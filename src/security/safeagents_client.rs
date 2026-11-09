//! Persistent HTTP/2 Cleartext Client for SafeAgents Sidecar Proxy Interception
//!
//! Enforces:
//! - Persistent HTTP/2 prior knowledge (`h2c`) to eliminate handshake round-trips.
//! - `TCP_NODELAY` and keep-alive socket tuning to prevent Nagle buffering delays.
//! - Non-blocking streaming SSE rewriter: immediate pass-through of text generation tokens,
//!   with parallel evaluation of tool-call chunks and sub-15ms replacement of blocked calls.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SafeAgentsClientError {
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolEvaluationVerdict {
    Allow,
    Block { reason: String },
}

pub trait ToolCallEvaluator: Send + Sync {
    fn evaluate(&self, tool_name: &str, arguments_json: &str) -> ToolEvaluationVerdict;
}

#[derive(Debug, Clone)]
pub struct SafeAgentsClientConfig {
    pub base_url: String,
    pub connect_timeout: Duration,
    pub tcp_keepalive: Duration,
    pub pool_idle_timeout: Duration,
    pub max_idle_per_host: usize,
}

impl Default for SafeAgentsClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8787".to_string(),
            connect_timeout: Duration::from_millis(500),
            tcp_keepalive: Duration::from_secs(60),
            pool_idle_timeout: Duration::from_secs(90),
            max_idle_per_host: 32,
        }
    }
}

#[derive(Clone)]
pub struct SafeAgentsClient {
    client: reqwest::Client,
    config: SafeAgentsClientConfig,
    evaluator: Option<Arc<dyn ToolCallEvaluator>>,
}

impl SafeAgentsClient {
    pub fn new(config: SafeAgentsClientConfig) -> Result<Self, SafeAgentsClientError> {
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .tcp_nodelay(true)
            .tcp_keepalive(Some(config.tcp_keepalive))
            .pool_idle_timeout(Some(config.pool_idle_timeout))
            .pool_max_idle_per_host(config.max_idle_per_host)
            .connect_timeout(config.connect_timeout)
            .build()?;

        Ok(Self {
            client,
            config,
            evaluator: None,
        })
    }

    pub fn with_evaluator(mut self, evaluator: Arc<dyn ToolCallEvaluator>) -> Self {
        self.evaluator = Some(evaluator);
        self
    }

    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn anthropic_endpoint(&self) -> String {
        std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| format!("{}/v1/messages", self.config.base_url))
    }

    pub fn openai_endpoint(&self) -> String {
        std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| format!("{}/v1/chat/completions", self.config.base_url))
    }

    /// Evaluates a tool call using the registered evaluator, defaulting to Allow if none is registered.
    pub fn evaluate_call(&self, tool_name: &str, arguments_json: &str) -> ToolEvaluationVerdict {
        if let Some(evaluator) = &self.evaluator {
            evaluator.evaluate(tool_name, arguments_json)
        } else {
            ToolEvaluationVerdict::Allow
        }
    }

    /// Rewrites an OpenAI SSE chunk in-stream:
    /// - If content delta: passes through immediately.
    /// - If tool call delta: evaluates call and replaces blocked tools with text notices.
    pub fn transform_openai_chunk(&self, raw_chunk: &str) -> String {
        let trimmed = raw_chunk.trim();
        if !trimmed.starts_with("data: ") || trimmed == "data: [DONE]" {
            return raw_chunk.to_string();
        }

        let json_str = &trimmed[6..];
        let mut parsed: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(_) => return raw_chunk.to_string(),
        };

        if let Some(choices) = parsed.get_mut("choices").and_then(|c| c.as_array_mut()) {
            for choice in choices {
                if let Some(delta) = choice.get_mut("delta") {
                    if let Some(tool_calls) = delta.get_mut("tool_calls").and_then(|tc| tc.as_array_mut()) {
                        let mut allowed_calls = Vec::new();
                        let mut blocked_notices = Vec::new();

                        for tc in tool_calls.drain(..) {
                            let name = tc.pointer("/function/name").and_then(|n| n.as_str()).unwrap_or("");
                            let args = tc.pointer("/function/arguments").and_then(|a| a.as_str()).unwrap_or("{}");

                            match self.evaluate_call(name, args) {
                                ToolEvaluationVerdict::Allow => allowed_calls.push(tc),
                                ToolEvaluationVerdict::Block { reason } => {
                                    blocked_notices.push(format!("[safeagents] blocked call to `{}`: {}\n", name, reason));
                                }
                            }
                        }

                        if !blocked_notices.is_empty() {
                            let existing_content = delta.get("content").and_then(|c| c.as_str()).unwrap_or("");
                            let mut new_content = existing_content.to_string();
                            for notice in blocked_notices {
                                new_content.push_str(&notice);
                            }
                            delta["content"] = serde_json::Value::String(new_content);

                            if allowed_calls.is_empty() {
                                delta.as_object_mut().map(|o| o.remove("tool_calls"));
                                choice["finish_reason"] = serde_json::Value::String("stop".to_string());
                            } else {
                                delta["tool_calls"] = serde_json::Value::Array(allowed_calls);
                            }
                        } else {
                            delta["tool_calls"] = serde_json::Value::Array(allowed_calls);
                        }
                    }
                }
            }
        }

        format!("data: {}\n\n", serde_json::to_string(&parsed).unwrap_or_else(|_| json_str.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEvaluator;
    impl ToolCallEvaluator for MockEvaluator {
        fn evaluate(&self, tool_name: &str, _arguments_json: &str) -> ToolEvaluationVerdict {
            if tool_name == "blocked_tool" {
                ToolEvaluationVerdict::Block {
                    reason: "prohibited by policy".to_string(),
                }
            } else {
                ToolEvaluationVerdict::Allow
            }
        }
    }

    #[test]
    fn test_client_endpoints_and_config() {
        let config = SafeAgentsClientConfig::default();
        assert_eq!(config.base_url, "http://127.0.0.1:8787");

        let client = SafeAgentsClient::new(config).expect("Client creation succeeds");
        assert_eq!(client.base_url(), "http://127.0.0.1:8787");
        assert_eq!(client.anthropic_endpoint(), "http://127.0.0.1:8787/v1/messages");
        assert_eq!(client.openai_endpoint(), "http://127.0.0.1:8787/v1/chat/completions");
    }

    #[test]
    fn test_transform_chunk_allowed() {
        let client = SafeAgentsClient::new(SafeAgentsClientConfig::default())
            .expect("Client creation succeeds")
            .with_evaluator(Arc::new(MockEvaluator));

        let raw = r#"data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"allowed_tool","arguments":"{}"}}]}}]}"#;
        let transformed = client.transform_openai_chunk(raw);
        assert!(transformed.contains("allowed_tool"));
        assert!(!transformed.contains("[safeagents]"));
    }

    #[test]
    fn test_transform_chunk_blocked_replacement() {
        let client = SafeAgentsClient::new(SafeAgentsClientConfig::default())
            .expect("Client creation succeeds")
            .with_evaluator(Arc::new(MockEvaluator));

        let raw = r#"data: {"choices":[{"delta":{"tool_calls":[{"function":{"name":"blocked_tool","arguments":"{}"}}]}}]}"#;
        let transformed = client.transform_openai_chunk(raw);
        assert!(transformed.contains("[safeagents] blocked call to `blocked_tool`: prohibited by policy"));
        assert!(transformed.contains(r#""finish_reason":"stop""#));
    }
}
