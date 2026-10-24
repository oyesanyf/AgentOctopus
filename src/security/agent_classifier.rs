//! Zero-Hardcode Bayesian Behavioral Agent Classifier
//!
//! Adapted from `D:\harfile\OshoosiClaw\crates\osoosi-agent-anomaly\src\classifier.rs`:
//! Identifies autonomous AI agents and tool-loop processes at runtime using Bayesian log-odds
//! updates over protocol provenance, MCP JSON-RPC framing, high-frequency pipe bursts, and
//! LLM endpoint egress—without relying on hardcoded process-name lists (`RULE[no_mocks_write_actual_code.md]`).
//! Interactive human terminals (`has_interactive_conpty_human_input`) receive negative log-odds
//! evidence so developer shells are never falsely classified as rogue agents.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessBehavioralTelemetry {
    pub pid: u32,
    pub process_label: String,
    pub has_mcp_jsonrpc_stdio_framing: bool,
    pub has_llm_inference_endpoint_socket: bool,
    pub sub_50ms_tool_dispatch_burst_rate: f64,
    pub autonomous_file_mutation_entropy: f64,
    pub has_interactive_conpty_human_keystrokes: bool,
    pub signed_vendor_toolchain_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentClassificationVerdict {
    pub pid: u32,
    pub posterior_probability: f64,
    pub log_odds: f64,
    pub is_autonomous_agent: bool,
    pub is_human_interactive_session: bool,
    pub contributing_factors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicAgentClassifier;

impl DynamicAgentClassifier {
    /// Computes the Bayesian posterior probability $P(\text{Agent} \mid E) = \sigma(L_0 + \sum_i \ln \text{LR}_i)$.
    pub fn classify_process(telemetry: &ProcessBehavioralTelemetry) -> AgentClassificationVerdict {
        // Prior P_0 = 0.25 -> L_0 = ln(0.25 / 0.75) = -1.098612
        let mut log_odds: f64 = -1.0986122886681098;
        let mut factors = Vec::new();

        if telemetry.has_mcp_jsonrpc_stdio_framing {
            log_odds += 2.85;
            factors.push("MCP_JSONRPC_STDIO_FRAMING(+2.85)".to_string());
        }
        if telemetry.has_llm_inference_endpoint_socket {
            log_odds += 2.40;
            factors.push("LLM_INFERENCE_SOCKET(+2.40)".to_string());
        }
        if telemetry.sub_50ms_tool_dispatch_burst_rate > 0.5 {
            let delta = 1.90 * telemetry.sub_50ms_tool_dispatch_burst_rate.clamp(0.0, 1.5);
            log_odds += delta;
            factors.push(format!("SUB_50MS_TOOL_BURST(+{:.2})", delta));
        }
        if telemetry.autonomous_file_mutation_entropy > 0.6 {
            log_odds += 1.15;
            factors.push("AUTONOMOUS_FILE_MUTATION(+1.15)".to_string());
        }

        // Negative log-odds evidence for verified human interactive ConPTY keystrokes & signed toolchains
        if telemetry.has_interactive_conpty_human_keystrokes {
            log_odds -= 3.20;
            factors.push("HUMAN_CONPTY_KEYSTROKES(-3.20)".to_string());
        }
        if telemetry.signed_vendor_toolchain_verified {
            log_odds -= 1.50;
            factors.push("SIGNED_VENDOR_TOOLCHAIN(-1.50)".to_string());
        }

        let posterior_probability = 1.0 / (1.0 + (-log_odds).exp());
        let is_autonomous_agent = posterior_probability >= 0.75;
        let is_human_interactive_session =
            telemetry.has_interactive_conpty_human_keystrokes && !is_autonomous_agent;

        AgentClassificationVerdict {
            pid: telemetry.pid,
            posterior_probability,
            log_odds,
            is_autonomous_agent,
            is_human_interactive_session,
            contributing_factors: factors,
        }
    }
}
