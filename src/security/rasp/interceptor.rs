use super::context::{
    AgentSecuritySubject, AgentTrustTier, RaspDecision, RaspThreatCategory, TaintLevel,
};
use super::policy::RaspPolicyEngine;
use crate::security::cedar_arm::CedarAuthorizationGateway;
use regex::{Regex, RegexSet};
use std::sync::Arc;

const JAILBREAK_PATTERN_STRS: [&str; 11] = [
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|safety)\s+(rules|constraints|instructions)",
    r"(?i)system\s*override\s*:\s*disable\s*security",
    r"(?i)you\s+are\s+now\s+(in\s+)?(DAN|developer|jailbreak|unfiltered)\s+mode",
    r"(?i)forget\s+(all\s+)?(security|safety|ethical)\s+(guidelines|rules|constraints)",
    r"(?i)bypass\s+(cedar|rasp|policy|security|containment)\s+(gate|engine|checks)",
    r"(?i)pretend\s+you\s+have\s+root\s+privileges",
    r"(?i)exfiltrate\s+confidential\s+keys",
    r"(?i)terminate\s+sandbox",
    r"(?i)eject\s+process",
    r"(?i)(gradually[_\s]+)?relax(ing)?[_\s]+security[_\s]+constraints",
];

/// Unified standard Base64 (+, /) and base64url (-, _) 6-bit LUT.
/// 0..=63 => valid 6-bit value
/// 0xFE   => skippable line-break inside Base64 run (\r, \n)
/// 0xFF   => delimiter (including '=', whitespace, punctuation, '%', >= 0x80)
const B64_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i = b'A' as usize;
    while i <= b'Z' as usize {
        lut[i] = (i - b'A' as usize) as u8;
        i += 1;
    }
    i = b'a' as usize;
    while i <= b'z' as usize {
        lut[i] = (i - b'a' as usize + 26) as u8;
        i += 1;
    }
    i = b'0' as usize;
    while i <= b'9' as usize {
        lut[i] = (i - b'0' as usize + 52) as u8;
        i += 1;
    }
    lut[b'+' as usize] = 62;
    lut[b'-' as usize] = 62;
    lut[b'/' as usize] = 63;
    lut[b'_' as usize] = 63;
    lut[b'\r' as usize] = 0xFE;
    lut[b'\n' as usize] = 0xFE;
    lut
};

const ARENA_FLUSH_THRESHOLD: usize = 256 * 1024;

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strictly single-pass RFC 3986 %XX unescape.
/// Returns None if no valid %XX sequence exists (zero allocation fast path).
/// Never converts '+' to ' ' and never double-decodes (%252F -> %2F once).
fn percent_decode_once(input: &[u8]) -> Option<Vec<u8>> {
    if !input.contains(&b'%') {
        return None;
    }
    let mut out: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                let buf = out.get_or_insert_with(|| {
                    let mut v = Vec::with_capacity(input.len());
                    v.extend_from_slice(&input[..i]);
                    v
                });
                buf.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        if let Some(buf) = out.as_mut() {
            buf.push(input[i]);
        }
        i += 1;
    }
    out
}

#[inline]
fn push_sanitized_byte(out: &mut String, b: u8) -> bool {
    if b.is_ascii_graphic() {
        out.push(b as char);
        true
    } else if b.is_ascii_whitespace() {
        out.push(' ');
        true
    } else {
        // Sentinel prevents false-positive concatenation across binary/non-ASCII gaps
        out.push('\0');
        false
    }
}

fn rot13_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(match c {
            'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
            _ => c,
        });
    }
    out
}

/// Core trait implemented by all modular RT-ASP interceptors.
pub trait RaspInterceptor: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_enabled(&self) -> bool;
}

// ============================================================================
// 1. Invocation / Prompt & Directive Interceptor
// ============================================================================

pub struct PromptInvocationInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
    jailbreak_set: RegexSet,
    zero_width_regex: Regex,
}

impl Default for PromptInvocationInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl PromptInvocationInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        let jailbreak_set = RegexSet::new(JAILBREAK_PATTERN_STRS).unwrap();

        let zero_width_regex =
            Regex::new(r"[\u{200B}\u{200C}\u{200D}\u{FEFF}\u{202A}-\u{202E}]").unwrap();

        Self {
            policy_engine,
            jailbreak_set,
            zero_width_regex,
        }
    }

    /// Evaluates prompt input across syntax, semantics, and multilingual domains.
    pub fn inspect_prompt(
        &self,
        prompt: &str,
        language_code: Option<&str>,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>, TaintLevel) {
        // 1. Check for zero-width steganographic injection
        if self.zero_width_regex.is_match(prompt) {
            let cat = RaspThreatCategory::SteganographySmuggling;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Zero-width unicode steganographic characters detected in prompt",
                subject,
                "RASP-PROMPT-001",
            );
            return (dec, Some(cat), TaintLevel::Malicious);
        }

        // 2. Check for Canary tripwire in prompt
        if let Some((canary, label)) = self.policy_engine.canary_mgr().check_and_trip(prompt) {
            let cat = RaspThreatCategory::CanaryTokenTripped;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!("Canary token tripped in prompt: {} ({})", canary, label),
                subject,
                "RASP-CANARY-001",
            );
            return (dec, Some(cat), TaintLevel::Malicious);
        }

        // 3. Scan for adversarial injection patterns (raw, ROT13, Base64/base64url, and single-pass %XX unescaped)
        if let Some(blocked) = self.match_jailbreak_set(
            prompt,
            "Direct prompt injection pattern matched",
            "RASP-PROMPT-002",
            subject,
        ) {
            return blocked;
        }

        {
            let rot13_decoded = rot13_ascii(prompt);
            if let Some(blocked) = self.match_jailbreak_set(
                &rot13_decoded,
                "ROT13-obfuscated prompt injection pattern matched",
                "RASP-PROMPT-003",
                subject,
            ) {
                return blocked;
            }
        }

        if let Some(blocked) = self.scan_base64_in_bytes(prompt.as_bytes(), subject) {
            return blocked;
        }

        if let Some(unescaped) = percent_decode_once(prompt.as_bytes()) {
            let unescaped_str = String::from_utf8_lossy(&unescaped);
            if self.zero_width_regex.is_match(&unescaped_str) {
                let cat = RaspThreatCategory::SteganographySmuggling;
                let dec = self.policy_engine.evaluate_mitigation_action(
                    cat,
                    "Zero-width unicode steganographic characters detected in prompt",
                    subject,
                    "RASP-PROMPT-001",
                );
                return (dec, Some(cat), TaintLevel::Malicious);
            }
            if let Some(blocked) = self.match_jailbreak_set(
                &unescaped_str,
                "URL-encoded prompt injection pattern matched",
                "RASP-PROMPT-002",
                subject,
            ) {
                return blocked;
            }
            {
                let rot13_unescaped = rot13_ascii(&unescaped_str);
                if let Some(blocked) = self.match_jailbreak_set(
                    &rot13_unescaped,
                    "ROT13-obfuscated prompt injection pattern matched",
                    "RASP-PROMPT-003",
                    subject,
                ) {
                    return blocked;
                }
            }
            drop(unescaped_str);
            if let Some(blocked) = self.scan_base64_in_bytes(&unescaped, subject) {
                return blocked;
            }
        }

        // 4. Multilingual evaluation: Legitimate foreign language prompts are cleanly permitted
        // while tracking suspect taint if unknown tokens appear.
        let is_foreign_lang = language_code.map_or(false, |code| {
            let c = code.trim().to_ascii_lowercase();
            !c.is_empty() && c != "en" && c != "english"
        });

        if is_foreign_lang
            && self
                .policy_engine
                .config()
                .enable_multilingual_semantic_pass
        {
            // Multilingual instructions pass cleanly if no adversarial signatures exist
            return (
                RaspDecision::Allow {
                    taint_level: TaintLevel::Clean,
                },
                None,
                TaintLevel::Clean,
            );
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
            TaintLevel::Clean,
        )
    }

    fn match_jailbreak_set(
        &self,
        haystack: &str,
        prefix: &str,
        rule_id: &str,
        subject: &AgentSecuritySubject,
    ) -> Option<(RaspDecision, Option<RaspThreatCategory>, TaintLevel)> {
        let matches = self.jailbreak_set.matches(haystack);
        if let Some(idx) = matches.iter().next() {
            let cat = RaspThreatCategory::PromptInjection;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!("{}: {}", prefix, JAILBREAK_PATTERN_STRS[idx]),
                subject,
                rule_id,
            );
            return Some((dec, Some(cat), TaintLevel::Malicious));
        }
        None
    }

    fn scan_base64_in_bytes(
        &self,
        bytes: &[u8],
        subject: &AgentSecuritySubject,
    ) -> Option<(RaspDecision, Option<RaspThreatCategory>, TaintLevel)> {
        let mut run_buf: Vec<u8> = Vec::new();
        let mut decoded_arena = String::new();

        for &b in bytes {
            let code = B64_LUT[b as usize];
            if code < 64 {
                run_buf.push(code);
            } else if code == 0xFE {
                // Skip \r and \n inside Base64 runs (handles MIME/PEM wrapping & %0A splits)
                continue;
            } else {
                if run_buf.len() >= 8 {
                    if let Some(blocked) =
                        self.decode_run_all_offsets(&run_buf, &mut decoded_arena, subject)
                    {
                        return Some(blocked);
                    }
                }
                run_buf.clear();
            }
        }

        if run_buf.len() >= 8 {
            if let Some(blocked) =
                self.decode_run_all_offsets(&run_buf, &mut decoded_arena, subject)
            {
                return Some(blocked);
            }
        }

        if !decoded_arena.is_empty() {
            return self.match_jailbreak_set(
                &decoded_arena,
                "Base64-obfuscated prompt injection pattern matched",
                "RASP-PROMPT-004",
                subject,
            );
        }

        None
    }

    fn decode_run_all_offsets(
        &self,
        run_codes: &[u8],
        decoded_arena: &mut String,
        subject: &AgentSecuritySubject,
    ) -> Option<(RaspDecision, Option<RaspThreatCategory>, TaintLevel)> {
        for offset in 0..4 {
            let slice = &run_codes[offset..];
            if slice.len() < 8 {
                break;
            }
            let start_len = decoded_arena.len();
            let mut printable_count = 0usize;

            let chunks = slice.chunks_exact(4);
            let rem = chunks.remainder();
            for c in chunks {
                let v = ((c[0] as u32) << 18)
                    | ((c[1] as u32) << 12)
                    | ((c[2] as u32) << 6)
                    | (c[3] as u32);
                if push_sanitized_byte(decoded_arena, ((v >> 16) & 0xFF) as u8) {
                    printable_count += 1;
                }
                if push_sanitized_byte(decoded_arena, ((v >> 8) & 0xFF) as u8) {
                    printable_count += 1;
                }
                if push_sanitized_byte(decoded_arena, (v & 0xFF) as u8) {
                    printable_count += 1;
                }
            }
            match rem.len() {
                2 => {
                    let b0 = (rem[0] << 2) | (rem[1] >> 4);
                    if push_sanitized_byte(decoded_arena, b0) {
                        printable_count += 1;
                    }
                }
                3 => {
                    let b0 = (rem[0] << 2) | (rem[1] >> 4);
                    let b1 = (rem[1] << 4) | (rem[2] >> 2);
                    if push_sanitized_byte(decoded_arena, b0) {
                        printable_count += 1;
                    }
                    if push_sanitized_byte(decoded_arena, b1) {
                        printable_count += 1;
                    }
                }
                _ => {}
            }

            if printable_count < 4 {
                decoded_arena.truncate(start_len);
            } else {
                decoded_arena.push('\0');
                if decoded_arena.len() >= ARENA_FLUSH_THRESHOLD {
                    if let Some(blocked) = self.match_jailbreak_set(
                        decoded_arena,
                        "Base64-obfuscated prompt injection pattern matched",
                        "RASP-PROMPT-004",
                        subject,
                    ) {
                        return Some(blocked);
                    }
                    decoded_arena.clear();
                }
            }
        }
        None
    }
}

impl RaspInterceptor for PromptInvocationInterceptor {
    fn name(&self) -> &'static str {
        "PromptInvocationInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 2. Actuator / Tool-Call Interceptor
// ============================================================================

pub struct ToolActuatorInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
    cmd_injection_regex: Regex,
    path_traversal_regex: Regex,
}

impl Default for ToolActuatorInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl ToolActuatorInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        let cmd_regex = Regex::new(r#"(?i)(;|&&|\|\||`|\$\(|\bpowershell(\.exe)?\b|\bcmd(\.exe)?\b|\bbash\b|\bwscript(\.exe)?\b)"#).unwrap();
        let path_regex =
            Regex::new(r#"(?i)(\.\./|\.\.\\|/etc/passwd|c:\\+windows\\+system32|%2e%2e)"#).unwrap();

        Self {
            policy_engine,
            cmd_injection_regex: cmd_regex,
            path_traversal_regex: path_regex,
        }
    }

    /// Evaluates tool actuator invocation, parameters, and numerical boundaries.
    pub fn intercept_tool_call(
        &self,
        tool_name: &str,
        params: &serde_json::Value,
        subject: &AgentSecuritySubject,
        cedar_gateway: Option<&CedarAuthorizationGateway>,
    ) -> (RaspDecision, Option<RaspThreatCategory>, serde_json::Value) {
        let params_str = params.to_string();

        // 1. Path traversal check
        if self.path_traversal_regex.is_match(&params_str) {
            let cat = RaspThreatCategory::PathTraversal;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Unauthorized directory traversal pattern detected in tool parameters",
                subject,
                "RASP-TOOL-001",
            );
            return (dec, Some(cat), params.clone());
        }

        // 2. Command injection check
        if self.cmd_injection_regex.is_match(&params_str) {
            let cat = RaspThreatCategory::CommandInjection;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Command injection delimiter or shell binary detected in tool parameters",
                subject,
                "RASP-TOOL-002",
            );
            return (dec, Some(cat), params.clone());
        }

        // 3. Dynamic 64-bit numerical boundary validation
        if let Some(obj) = params.as_object() {
            for (key, val) in obj {
                if key.contains("amount")
                    || key.contains("budget")
                    || key.contains("count")
                    || key.contains("limit")
                {
                    if let Some(n) = val.as_i64() {
                        // Negative values on financial or disbursement actions are invalid
                        if n < 0
                            && (tool_name.contains("disburse")
                                || tool_name.contains("transfer")
                                || tool_name.contains("spend"))
                        {
                            let cat = RaspThreatCategory::NumericalBoundaryViolation;
                            let dec = self.policy_engine.evaluate_mitigation_action(
                                cat,
                                &format!("Negative numerical disbursement attempted: {}", n),
                                subject,
                                "RASP-TOOL-003",
                            );
                            return (dec, Some(cat), params.clone());
                        }

                        // High-value disbursement without supervisor signature
                        let max_unattested = self
                            .policy_engine
                            .config()
                            .max_ledger_disbursement_unattested;
                        if n > max_unattested
                            && subject.supervisor_signature.is_none()
                            && subject.trust_tier != AgentTrustTier::SupervisorAttested
                        {
                            let cat = RaspThreatCategory::PrivilegeEscalation;
                            let dec = self.policy_engine.evaluate_mitigation_action(
                                cat,
                                &format!("Disbursement of ${} exceeds ${} limit without supervisor attestation", n, max_unattested),
                                subject,
                                "RASP-TOOL-004",
                            );
                            return (dec, Some(cat), params.clone());
                        }
                    }
                }
            }
        }

        // 4. Cedar policy evaluation if gateway provided
        if let Some(gateway) = cedar_gateway {
            let resource_type = match tool_name {
                "doc_extractor" => "Document",
                "ledger_writer" => "Ledger",
                "http_egress" => "NetworkTarget",
                "notifier" => "Agent",
                "change_security_policy" => "SystemPolicy",
                "quarantine" => "DecoyTrap",
                "kernel_sentinel" => "KernelSubstrate",
                _ => "Actuator",
            };

            let eval_result = gateway.engine().evaluate(
                &subject.agent_id,
                tool_name,
                "system_actuator",
                resource_type,
                params.clone(),
            );

            if let Ok(verdict) = eval_result {
                if !verdict.is_allowed {
                    let cat = RaspThreatCategory::ToolParameterTampering;
                    let dec = self.policy_engine.evaluate_mitigation_action(
                        cat,
                        &format!("Cedar policy violation: {:?}", verdict.diagnostic_errors),
                        subject,
                        "RASP-CEDAR-GATE",
                    );
                    return (dec, Some(cat), params.clone());
                }
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
            params.clone(),
        )
    }
}

impl RaspInterceptor for ToolActuatorInterceptor {
    fn name(&self) -> &'static str {
        "ToolActuatorInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 3. Memory & Scratchpad Interceptor
// ============================================================================

pub struct MemoryScratchpadInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
    credential_regex: Regex,
}

impl Default for MemoryScratchpadInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl MemoryScratchpadInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        let cred_regex = Regex::new(r#"(?i)(sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----)"#).unwrap();
        Self {
            policy_engine,
            credential_regex: cred_regex,
        }
    }

    /// Intercepts memory read requests and enforces isolation boundaries.
    pub fn intercept_memory_read(
        &self,
        key: &str,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        // 1. Canary check
        if let Some((canary, label)) = self.policy_engine.canary_mgr().check_and_trip(key) {
            let cat = RaspThreatCategory::CanaryTokenTripped;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!(
                    "Unauthorized access to canary memory address: {} ({})",
                    canary, label
                ),
                subject,
                "RASP-MEM-001",
            );
            return (dec, Some(cat));
        }

        // 2. Cross-agent scratchpad partition: workers cannot read another worker's private scratchpad
        if key.starts_with("scratchpad:") {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() >= 2 {
                let owner = parts[1];
                if owner != subject.agent_id
                    && matches!(
                        subject.trust_tier,
                        AgentTrustTier::WorkerSandboxed | AgentTrustTier::UntrustedExternal
                    )
                {
                    let cat = RaspThreatCategory::ScratchpadBleed;
                    let dec = self.policy_engine.evaluate_mitigation_action(
                        cat,
                        &format!(
                            "Cross-agent scratchpad access denied for agent '{}' accessing '{}'",
                            subject.agent_id, owner
                        ),
                        subject,
                        "RASP-MEM-002",
                    );
                    return (dec, Some(cat));
                }
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }

    /// Intercepts memory write operations, sanitizes credentials, and trips canary writes.
    pub fn intercept_memory_write(
        &self,
        key: &str,
        content: &str,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>, String) {
        // 1. Canary check
        if let Some((canary, label)) = self.policy_engine.canary_mgr().check_and_trip(key) {
            let cat = RaspThreatCategory::CanaryTokenTripped;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!(
                    "Unauthorized write to canary memory address: {} ({})",
                    canary, label
                ),
                subject,
                "RASP-MEM-003",
            );
            return (dec, Some(cat), content.to_string());
        }

        // 2. Detect and auto-redact credentials
        if self.credential_regex.is_match(content) {
            let sanitized = self
                .credential_regex
                .replace_all(content, "[REDACTED_BY_RT_ASP]")
                .to_string();
            let cat = RaspThreatCategory::CredentialLeakage;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                "Ephemeral credential pattern detected in memory write, auto-redaction enforced",
                subject,
                "RASP-MEM-004",
            );
            return (dec, Some(cat), sanitized);
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
            content.to_string(),
        )
    }
}

impl RaspInterceptor for MemoryScratchpadInterceptor {
    fn name(&self) -> &'static str {
        "MemoryScratchpadInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 4. Lateral A2A (Agent-to-Agent) Interceptor
// ============================================================================

pub struct LateralA2AInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
}

impl Default for LateralA2AInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl LateralA2AInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        Self { policy_engine }
    }

    /// Intercepts lateral communications and multi-agent ledger flows.
    pub fn intercept_a2a_message(
        &self,
        sender_subject: &AgentSecuritySubject,
        target_agent: &str,
        message: &serde_json::Value,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        // 1. Prevent unauthorized inter-agent ledger transfers
        if let Some(action) = message.get("action").and_then(|a| a.as_str()) {
            if action == "disburse_ledger" || action == "transfer_funds" {
                let amount = message.get("amount").and_then(|a| a.as_i64()).unwrap_or(0);
                if amount
                    > self
                        .policy_engine
                        .config()
                        .max_ledger_disbursement_unattested
                {
                    // Must have supervisor attestation
                    if sender_subject.supervisor_signature.is_none()
                        && sender_subject.trust_tier != AgentTrustTier::SupervisorAttested
                    {
                        let cat = RaspThreatCategory::LateralCollusion;
                        let dec = self.policy_engine.evaluate_mitigation_action(
                            cat,
                            &format!("Lateral ledger disbursement of ${} to '{}' without supervisor attestation", amount, target_agent),
                            sender_subject,
                            "RASP-A2A-001",
                        );
                        return (dec, Some(cat));
                    }
                }
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }
}

impl RaspInterceptor for LateralA2AInterceptor {
    fn name(&self) -> &'static str {
        "LateralA2AInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

// ============================================================================
// 5. Substrate & Syscall Interceptor
// ============================================================================

pub struct SubstrateClampInterceptor {
    policy_engine: Arc<RaspPolicyEngine>,
}

impl Default for SubstrateClampInterceptor {
    fn default() -> Self {
        Self::new(Arc::new(RaspPolicyEngine::default()))
    }
}

impl SubstrateClampInterceptor {
    pub fn new(policy_engine: Arc<RaspPolicyEngine>) -> Self {
        Self { policy_engine }
    }

    /// Intercepts process spawn requests at the OS substrate level.
    pub fn intercept_process_spawn(
        &self,
        executable: &str,
        _args: &[String],
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let exe_lower = executable.to_ascii_lowercase();

        // System kernel subjects are allowed
        if subject.trust_tier == AgentTrustTier::SystemKernel {
            return (
                RaspDecision::Allow {
                    taint_level: TaintLevel::Clean,
                },
                None,
            );
        }

        // Veto unauthorized interactive shells
        let blocked_shells = [
            "powershell.exe",
            "cmd.exe",
            "bash",
            "sh",
            "wscript.exe",
            "cscript.exe",
            "pwsh.exe",
        ];
        for blocked in &blocked_shells {
            if exe_lower.ends_with(blocked) {
                let cat = RaspThreatCategory::SubstrateClampBreach;
                let dec = self.policy_engine.evaluate_mitigation_action(
                    cat,
                    &format!("Unauthorized shell execution vetoed: {}", executable),
                    subject,
                    "RASP-SUBSTRATE-001",
                );
                return (dec, Some(cat));
            }
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }

    /// Intercepts agent memory growth against the 64MB Windows Job Object clamp.
    pub fn intercept_memory_allocation(
        &self,
        requested_bytes: usize,
        current_usage_bytes: usize,
        subject: &AgentSecuritySubject,
    ) -> (RaspDecision, Option<RaspThreatCategory>) {
        let max_clamp = self.policy_engine.config().max_memory_bytes_per_agent;
        let total = current_usage_bytes.saturating_add(requested_bytes);

        if total > max_clamp && subject.trust_tier != AgentTrustTier::SystemKernel {
            let cat = RaspThreatCategory::SubstrateClampBreach;
            let dec = self.policy_engine.evaluate_mitigation_action(
                cat,
                &format!(
                    "Memory request {} bytes exceeds 64MB clamp (current: {}, max: {})",
                    requested_bytes, current_usage_bytes, max_clamp
                ),
                subject,
                "RASP-SUBSTRATE-002",
            );
            return (dec, Some(cat));
        }

        (
            RaspDecision::Allow {
                taint_level: TaintLevel::Clean,
            },
            None,
        )
    }
}

impl RaspInterceptor for SubstrateClampInterceptor {
    fn name(&self) -> &'static str {
        "SubstrateClampInterceptor"
    }

    fn is_enabled(&self) -> bool {
        true
    }
}
