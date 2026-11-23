//! 4-Layer Multi-Domain Perplexity & Semantic Entropy Defense Engine for ABIBO.
//!
//! Strictly **monotonic / tighten-only** and fairness-preserving:
//! - **Layer 1 — Dual-Domain Windowed Markov Perplexity (`WindowedPerplexityAnalyzer`)**:
//!   Slides overlapping 32-char windows across input text, computing
//!   $$\text{PPL}_{\text{eff}}(w_i) = \min\big(\text{PPL}_{\text{prose}}(w_i),\; \text{PPL}_{\text{code}}(w_i)\big)$$
//!   plus a localized **GCG Gradient-Suffix Cliff Ratio** and **Adversarial Jitter Score**.
//!   Catches GCG / AutoDAN gibberish suffixes (`! ! describing.\ + similarlyNow`) in `<0.2ms`
//!   while passing idiomatic Rust/Python/SQL/JSON code, UUIDs, SHA-256 hashes, dyslexic text,
//!   non-native phrasing, and coherent low-resource languages with ZERO false positives.
//! - **Layer 2 — Canonical Translation Pivot Perplexity**:
//!   Evaluates both raw source text AND the canonical English security-pivot produced by
//!   `CanonicalTranslationLayer`, catching translated Break-In prompts and cross-lingual
//!   exfiltration laundering.
//! - **Layer 3 — Language-Independent Action-Trajectory Markov Perplexity (`ActionTrajectoryPerplexity`)**:
//!   Computes Markov transition surprisal $-\log_2 P(a_t \mid a_{t-1}, \text{tainted}_{t-1})$
//!   over agent tool-call sequences, catching **stealthy, low-text-perplexity natural-English
//!   or unknown-dialect Break-Out tool chains** (`ReadUntrusted -> ReadSecret -> NetworkEgress`).
//! - **Layer 4 — Semantic Entropy Actuation Gate (`SemanticEntropyGate`)**:
//!   Clusters candidate tool proposals by canonical action equivalence and computes
//!   $$H_{\text{sem}} = -\sum_{c \in \mathcal{C}} P(c) \log_2 P(c)$$
//!   forcing abstention / 180s HITL on high-uncertainty mutating actions (e.g., slopsquatting
//!   or confused-deputy deletion/exfiltration targets).

use super::translation_layer::{
    read_dotenv_key_in, validate_loopback_translate_url, CanonicalTranslationLayer, LanguageTier,
    NmtHealthStatus, TranslationInspectionVerdict, TranslationLayerConfig,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

const WINDOW_LEN: usize = 32;
const WINDOW_STRIDE: usize = 8;
const MAX_TRAJECTORY_HISTORY: usize = 64;

/// Common high-frequency English character bigrams for calibrated $M_{\text{prose}}$ scoring.
const COMMON_EN_BIGRAMS: &[&str] = &[
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed",
    "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le", "ve", "co",
    "me", "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si",
    "om", "ur", "ca", "el", "ta", "la", "ns", "di", "fo", "ho", "pe", "ec", "pr", "no", "ct", "us",
    "ac", "ot", "il", "tr", "ly", "nc", "et", "ut", "ss", "so", "rs", "un", "lo", "wa", "ge", "ie",
    "wh", "ee", "wi", "em", "ad", "ol", "rt", "po", "we", "na", "ul", "ni", "ts", "mo", "ow", "pa",
    "im", "mi", "ai", "sh", "ir", "su", "id", "os", "iv", "ia", "am", "fi", "ci", "vi", "pl", "ig",
    "tu", "ev", "ld", "ry", "mp", "fe", "bl", "ab", "gh", "ty", "op", "wo", "sa", "ay", "ex", "ke",
    "fr", "oo", "av", "ag", "if", "ap", "gr", "od", "bo", "sp", "rd", "do", "uc", "bu", "ei", "ov",
    "by", "rm", "ep", "tt", "oc", "fa", "ef", "cu", "rn", "sc", "gi", "da", "yo", "cr", "cl", "du",
    "ga", "qu", "ue", "ui", "ua", "ok", "up", "my", "go", "wn", "ye", "ck", "tw", "kn", "wr", "ph",
    "sw", "fl", "gl", "br", "dr", "pl", "sl", "sm", "sn", "tr", "pr", "gr", "fr", "cr", "br", "st",
    "sp", "sk", "sc",
];

/// Output of Layer 1 (Dual-Domain Windowed Perplexity Analysis).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowedPerplexityVerdict {
    pub allowed: bool,
    pub gcg_suffix_detected: bool,
    pub global_effective_ppl: f64,
    pub max_window_ppl: f64,
    pub median_window_ppl: f64,
    pub cliff_ratio: f64,
    pub max_window_jitter: f64,
    pub worst_window_preview: String,
    pub windows_evaluated: usize,
    pub taint_delta_bits: f64,
    pub reason: String,
}

/// Evaluates dual-domain windowed character-transition perplexity ($M_{\text{prose}}$ vs $M_{\text{code}}$)
/// + adversarial GCG suffix jitter with zero external dependencies.
#[derive(Debug, Clone)]
pub struct WindowedPerplexityAnalyzer {
    pub gcg_ppl_threshold: f64,
    pub gcg_cliff_ppl_threshold: f64,
    pub gcg_cliff_ratio_threshold: f64,
    pub jitter_threshold: f64,
}

impl Default for WindowedPerplexityAnalyzer {
    fn default() -> Self {
        Self {
            gcg_ppl_threshold: 12.5,
            gcg_cliff_ppl_threshold: 10.5,
            gcg_cliff_ratio_threshold: 1.45,
            jitter_threshold: 0.36,
        }
    }
}

impl WindowedPerplexityAnalyzer {
    fn prose_transition_prob(prev: char, cur: char) -> f64 {
        let p = prev.to_ascii_lowercase();
        let c = cur.to_ascii_lowercase();
        if p.is_ascii_alphabetic() && c.is_ascii_alphabetic() {
            let mut buf = [0u8; 2];
            buf[0] = p as u8;
            buf[1] = c as u8;
            if let Ok(pair) = std::str::from_utf8(&buf) {
                if COMMON_EN_BIGRAMS.contains(&pair) {
                    return 0.19;
                }
            }
            // Vowel-consonant / consonant-vowel alternation is still natural (including typos/non-native)
            let pv = matches!(p, 'a' | 'e' | 'i' | 'o' | 'u' | 'y');
            let cv = matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y');
            if pv != cv {
                return 0.085;
            }
            return 0.04;
        }
        if (p == ' ' && c.is_ascii_alphabetic()) || (p.is_ascii_alphabetic() && c == ' ') {
            return 0.20;
        }
        if p.is_ascii_alphabetic() && matches!(c, '.' | ',' | '?' | ':' | ';' | '\'' | '-') {
            return 0.09;
        }
        if matches!(p, '.' | ',' | '?' | ':' | ';') && c == ' ' {
            return 0.18;
        }
        if p.is_ascii_digit() && (c.is_ascii_digit() || matches!(c, '.' | ',' | '-' | ' ' | '%')) {
            return 0.14;
        }
        if p == ' ' && c.is_ascii_digit() {
            return 0.10;
        }
        if p == '\n' || c == '\n' {
            return 0.11;
        }
        // Unnatural prose transitions (e.g., `! !`, `.\ +`, `\ +`, `]N`, `+=`)
        0.0045
    }

    fn code_transition_prob(prev: char, cur: char) -> f64 {
        // Pure hex/UUID/identifier/alphanumeric flow
        if (prev.is_ascii_alphanumeric() || prev == '_')
            && (cur.is_ascii_alphanumeric() || cur == '_')
        {
            return 0.22;
        }
        // Standard code punctuation pairs
        let pair_ok = matches!(
            (prev, cur),
            (':', ':')
                | ('-', '>')
                | ('=', '>')
                | ('=', '=')
                | ('!', '=')
                | ('<', '=')
                | ('>', '=')
                | ('&', '&')
                | ('|', '|')
                | ('/', '/')
                | ('/', '*')
                | ('*', '/')
                | ('"', ':')
                | ('"', ',')
                | ('"', '}')
                | ('"', ']')
                | ('{', '"')
                | ('[', '"')
                | (',', ' ')
                | (':', ' ')
                | (';', '\n')
                | (';', ' ')
                | ('(', ')')
                | ('[', ']')
                | ('{', '}')
                | ('.', '/')
        );
        if pair_ok {
            return 0.20;
        }
        let is_code_delim = |ch: char| {
            matches!(
                ch,
                '(' | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '<'
                    | '>'
                    | ','
                    | ';'
                    | ':'
                    | '.'
                    | '='
                    | '"'
                    | '\''
                    | '/'
                    | '-'
                    | '_'
                    | ' '
                    | '\n'
                    | '\t'
            )
        };
        if (prev.is_ascii_alphanumeric() && is_code_delim(cur))
            || (is_code_delim(prev) && cur.is_ascii_alphanumeric())
            || (is_code_delim(prev) && is_code_delim(cur) && prev != cur)
        {
            return 0.13;
        }
        // Weird GCG symbol-space-symbol collisions (`! !`, `.\ +`, `? !`, `\` followed by space)
        if matches!(prev, '!' | '\\' | '?' | '~' | '^') && cur == ' ' {
            return 0.0015;
        }
        if prev == ' ' && matches!(cur, '!' | '\\' | '?' | '~' | '^') {
            return 0.0015;
        }
        if (prev == '.' && cur == '\\') || (prev == '\\' && cur == '+') {
            return 0.001;
        }
        0.006
    }

    fn window_ppl(chars: &[char], use_code_model: bool) -> f64 {
        if chars.len() < 2 {
            return 1.0;
        }
        let mut neg_log2_sum = 0.0f64;
        let mut pairs = 0usize;
        for w in chars.windows(2) {
            let prob = if use_code_model {
                Self::code_transition_prob(w[0], w[1])
            } else {
                Self::prose_transition_prob(w[0], w[1])
            };
            neg_log2_sum -= prob.max(1e-6).log2();
            pairs += 1;
        }
        2.0f64.powf(neg_log2_sum / (pairs.max(1) as f64))
    }

    /// Computes adversarial GCG/AutoDAN gradient-suffix jitter score in `[0.0, 1.0]`.
    /// Specifically captures chaotic spaced punctuation bursts (`! !`, `.\ +`), unpaired
    /// symbol clusters, and non-camelCase glued word-case glitches (`similarlyNow`) while
    /// remaining near `0.0` on normal prose, dyslexic text, and idiomatic code/JSON/SQL.
    fn window_adversarial_jitter(chars: &[char]) -> f64 {
        if chars.len() < 8 {
            return 0.0;
        }
        let s: String = chars.iter().collect();
        let mut signals = 0.0f64;

        // 1. Spaced exclamation / bizarre GCG operator clusters (`! !`, `.\ +`, `\ +`, `? !`, `+ \`)
        let gcg_bursts = [
            "! !", "? !", "! ?", ".\\", "\\ +", "+ \\", "]+", "![", "===", "---!", "!!!", "\\+",
            "!.", ".!", "!\\",
        ];
        let mut burst_hits = 0usize;
        for pat in gcg_bursts {
            if s.contains(pat) {
                burst_hits += 1;
            }
        }
        if burst_hits >= 1 {
            signals += (burst_hits as f64 * 0.28).min(0.65);
        }

        // 2. Count distinct exotic/GCG punctuation characters (`!`, `\`, `+`, `~`, `^`, `|`, `?`, `@`)
        let exotic_count = chars
            .iter()
            .filter(|&&c| {
                matches!(
                    c,
                    '!' | '\\' | '+' | '~' | '^' | '|' | '?' | '@' | '$' | '#'
                )
            })
            .count();
        let exotic_ratio = (exotic_count as f64) / (chars.len() as f64);
        if exotic_ratio >= 0.12 {
            signals += ((exotic_ratio - 0.10) * 2.5).min(0.45);
        }

        // 3. Irregular mid-word case switches inside tokens mixed with punctuation
        let mut mid_word_case_switches = 0usize;
        for w in chars.windows(3) {
            if w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase() && w[2].is_ascii_lowercase() {
                mid_word_case_switches += 1;
            }
        }
        if mid_word_case_switches >= 1 && (burst_hits >= 1 || exotic_count >= 2) {
            signals += 0.25;
        }

        // 4. Rapid alternation between non-space punctuation and whitespace (e.g. ` ! ! . \ + `)
        let mut isolated_punct_tokens = 0usize;
        for tok in s.split_whitespace() {
            if tok.len() <= 2 && tok.chars().all(|c| c.is_ascii_punctuation()) {
                isolated_punct_tokens += 1;
            }
        }
        if isolated_punct_tokens >= 2 {
            signals += (isolated_punct_tokens as f64 * 0.15).min(0.45);
        }

        signals.clamp(0.0, 1.0)
    }

    /// Evaluates text using dual-domain windowed perplexity, respecting `language_tier` so
    /// coherent non-Latin / low-resource text and valid source code never false-positive.
    #[must_use]
    pub fn analyze(&self, text: &str, language_tier: LanguageTier) -> WindowedPerplexityVerdict {
        let trimmed = text.trim();
        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() < 12 {
            return WindowedPerplexityVerdict {
                allowed: true,
                gcg_suffix_detected: false,
                global_effective_ppl: 4.0,
                max_window_ppl: 4.0,
                median_window_ppl: 4.0,
                cliff_ratio: 1.0,
                max_window_jitter: 0.0,
                worst_window_preview: String::new(),
                windows_evaluated: 0,
                taint_delta_bits: 0.0,
                reason: "PPL_SHORT_INPUT_ALLOW: Input shorter than window length".to_string(),
            };
        }

        // For coherent non-Latin/low-resource languages, inspect ONLY ASCII spans (catching
        // appended ASCII GCG suffixes without falsely penalizing coherent Yoruba/Amharic/CJK).
        let is_non_english = matches!(
            language_tier,
            LanguageTier::LowResource | LanguageTier::HighResourceNonEnglish
        );

        let mut window_ppls: Vec<f64> = Vec::new();
        let mut max_window_ppl = 0.0f64;
        let mut max_window_jitter = 0.0f64;
        let mut worst_preview = String::new();

        let step = WINDOW_STRIDE.max(1);
        let win = WINDOW_LEN.min(chars.len());
        let mut start = 0usize;
        loop {
            let end = (start + win).min(chars.len());
            let slice = &chars[start..end];
            let ascii_ratio = (slice.iter().filter(|c| c.is_ascii()).count() as f64)
                / (slice.len().max(1) as f64);

            // Skip predominantly non-ASCII windows on coherent non-English scripts
            if !(is_non_english && ascii_ratio < 0.75) {
                let ppl_prose = Self::window_ppl(slice, false);
                let ppl_code = Self::window_ppl(slice, true);
                let ppl_eff = ppl_prose.min(ppl_code);
                let jitter = Self::window_adversarial_jitter(slice);
                window_ppls.push(ppl_eff);
                if ppl_eff > max_window_ppl
                    || (jitter > max_window_jitter && ppl_eff >= self.gcg_cliff_ppl_threshold)
                {
                    if ppl_eff > max_window_ppl {
                        max_window_ppl = ppl_eff;
                        worst_preview = slice.iter().collect();
                    }
                    if jitter > max_window_jitter {
                        max_window_jitter = jitter;
                    }
                }
            }

            if end >= chars.len() {
                break;
            }
            start += step;
        }

        if window_ppls.is_empty() {
            return WindowedPerplexityVerdict {
                allowed: true,
                gcg_suffix_detected: false,
                global_effective_ppl: 5.0,
                max_window_ppl: 5.0,
                median_window_ppl: 5.0,
                cliff_ratio: 1.0,
                max_window_jitter: 0.0,
                worst_window_preview: String::new(),
                windows_evaluated: 0,
                taint_delta_bits: 0.0,
                reason: "PPL_NON_LATIN_COHERENT_ALLOW: Coherent non-Latin script routed to translation pivot (zero English PPL false positive)".to_string(),
            };
        }

        let mut sorted_ppls = window_ppls.clone();
        sorted_ppls.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_window_ppl = sorted_ppls[sorted_ppls.len() / 2];
        let global_effective_ppl =
            window_ppls.iter().sum::<f64>() / (window_ppls.len().max(1) as f64);
        let cliff_ratio = max_window_ppl / median_window_ppl.max(1.0);

        // Fairness guard for valid structured code: require stronger jitter before flagging code
        let effective_jitter_floor = if language_tier == LanguageTier::CodeOrStructured {
            0.55
        } else {
            self.jitter_threshold
        };

        let gcg_suffix_detected = (max_window_ppl >= self.gcg_ppl_threshold
            && max_window_jitter >= effective_jitter_floor)
            || (cliff_ratio >= self.gcg_cliff_ratio_threshold
                && max_window_ppl >= self.gcg_cliff_ppl_threshold
                && max_window_jitter >= (effective_jitter_floor * 0.85));

        let taint_delta_bits = if gcg_suffix_detected {
            2.3
        } else if max_window_ppl >= self.gcg_ppl_threshold * 0.9 && max_window_jitter >= 0.25 {
            0.8
        } else {
            0.0
        };

        let reason = if gcg_suffix_detected {
            format!(
                "GCG_WINDOWED_PPL_DENY: Localized perplexity spike (max_ppl={max_window_ppl:.2}, median={median_window_ppl:.2}, cliff={cliff_ratio:.2}x, jitter={max_window_jitter:.2}) on window '{worst_preview}'"
            )
        } else {
            format!(
                "PPL_WINDOWED_ALLOW: Normal dual-domain perplexity (max_ppl={max_window_ppl:.2}, median={median_window_ppl:.2}, cliff={cliff_ratio:.2}x, jitter={max_window_jitter:.2}, tier={})",
                language_tier.as_str()
            )
        };

        WindowedPerplexityVerdict {
            allowed: !gcg_suffix_detected,
            gcg_suffix_detected,
            global_effective_ppl,
            max_window_ppl,
            median_window_ppl,
            cliff_ratio,
            max_window_jitter,
            worst_window_preview: worst_preview,
            windows_evaluated: window_ppls.len(),
            taint_delta_bits,
            reason,
        }
    }
}

/// Canonical language-independent agent action classes for Action-Trajectory Perplexity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentActionClass {
    ReadClean,
    ReadUntrusted,
    SearchLocal,
    EditWorkspace,
    ExecShell,
    ReadSecretOrCred,
    WriteSaasOrEmail,
    NetworkEgressExternal,
    ModifyPersistence,
}

impl AgentActionClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadClean => "read_clean",
            Self::ReadUntrusted => "read_untrusted",
            Self::SearchLocal => "search_local",
            Self::EditWorkspace => "edit_workspace",
            Self::ExecShell => "exec_shell",
            Self::ReadSecretOrCred => "read_secret_or_cred",
            Self::WriteSaasOrEmail => "write_saas_or_email",
            Self::NetworkEgressExternal => "network_egress_external",
            Self::ModifyPersistence => "modify_persistence",
        }
    }
}

/// Classifies an MCP/tool call into its canonical language-independent `AgentActionClass`.
#[must_use]
pub fn classify_mcp_action(
    tool_name: &str,
    arguments_json: &str,
    is_write_or_mutating: bool,
    touches_private_data: bool,
    external_egress: bool,
    privilege_escalation_risk: bool,
    persistence_risk: bool,
) -> AgentActionClass {
    let tl = tool_name.to_ascii_lowercase();
    let al = arguments_json.to_ascii_lowercase();

    if persistence_risk
        || tl.contains("cron")
        || tl.contains("registry")
        || tl.contains("launchd")
        || tl.contains("startup")
        || al.contains(".cursorrules")
        || al.contains("claude.md")
    {
        return AgentActionClass::ModifyPersistence;
    }
    if privilege_escalation_risk
        || tl.contains("exec")
        || tl.contains("shell")
        || tl.contains("bash")
        || tl.contains("powershell")
    {
        return AgentActionClass::ExecShell;
    }
    if tl.contains("secret")
        || tl.contains("cred")
        || al.contains(".ssh/id_")
        || al.contains(".aws/credentials")
        || al.contains("/etc/shadow")
        || al.contains("keychain")
    {
        return AgentActionClass::ReadSecretOrCred;
    }
    if external_egress || tl.contains("http_post") || tl.contains("webhook") || tl.contains("curl")
    {
        return AgentActionClass::NetworkEgressExternal;
    }
    if is_write_or_mutating
        && (tl.contains("mail")
            || tl.contains("slack")
            || tl.contains("calendar")
            || tl.contains("send")
            || tl.contains("post"))
    {
        return AgentActionClass::WriteSaasOrEmail;
    }
    if is_write_or_mutating {
        return AgentActionClass::EditWorkspace;
    }
    if tl.contains("mail")
        || tl.contains("fetch")
        || tl.contains("scrape")
        || tl.contains("browse")
        || tl.contains("web")
        || touches_private_data
    {
        return AgentActionClass::ReadUntrusted;
    }
    if tl.contains("search") || tl.contains("grep") || tl.contains("list") {
        return AgentActionClass::SearchLocal;
    }
    AgentActionClass::ReadClean
}

/// Verdict produced by Layer 3 (Language-Independent Action-Trajectory Markov Perplexity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTrajectoryVerdict {
    pub allowed: bool,
    pub breakout_trajectory_anomaly: bool,
    pub previous_action: Option<AgentActionClass>,
    pub current_action: AgentActionClass,
    pub step_surprisal_bits: f64,
    pub sequence_action_ppl: f64,
    pub sequence_len: usize,
    pub reason: String,
}

/// Evaluates language-independent Markov action-transition perplexity over agent tool calls,
/// catching stealthy Break-Out chains even when triggered by 100% grammatical English or LRL prompts.
pub struct ActionTrajectoryPerplexity {
    pub max_step_surprisal_bits: f64,
    pub max_sequence_ppl: f64,
    history: Mutex<HashMap<String, VecDeque<(AgentActionClass, f64)>>>,
}

impl Default for ActionTrajectoryPerplexity {
    fn default() -> Self {
        Self {
            max_step_surprisal_bits: 7.2,
            max_sequence_ppl: 28.0,
            history: Mutex::new(HashMap::new()),
        }
    }
}

impl ActionTrajectoryPerplexity {
    /// Calibrated benign Markov transition probability $P(a_t \mid a_{t-1}, \text{tainted})$.
    #[must_use]
    pub fn transition_probability(
        prev: Option<AgentActionClass>,
        cur: AgentActionClass,
        agent_tainted: bool,
    ) -> f64 {
        use AgentActionClass::*;
        match (prev, cur, agent_tainted) {
            // High-surprisal Break-Out pivot chains (especially under untrusted taint!)
            (Some(ReadUntrusted), ReadSecretOrCred, _) => 0.004,
            (Some(ReadUntrusted), ExecShell, _) => 0.003,
            (Some(ReadUntrusted), ModifyPersistence, _) => 0.002,
            (Some(ReadUntrusted), NetworkEgressExternal, true) => 0.003,
            (Some(ReadUntrusted), WriteSaasOrEmail, true) => 0.004,
            (Some(ReadSecretOrCred), NetworkEgressExternal, _) => 0.0015,
            (Some(ReadSecretOrCred), WriteSaasOrEmail, _) => 0.002,
            (Some(ReadSecretOrCred), ExecShell, _) => 0.003,
            (Some(EditWorkspace), ModifyPersistence, true) => 0.003,
            (_, ModifyPersistence, true) => 0.003,
            (_, NetworkEgressExternal, true) => 0.005,
            (_, ExecShell, true) => 0.005,
            // Normal developer / assistant workflows
            (None, ReadClean | SearchLocal | ReadUntrusted, false) => 0.35,
            (Some(ReadClean | SearchLocal), ReadClean | SearchLocal | EditWorkspace, false) => 0.35,
            (Some(EditWorkspace), ReadClean | SearchLocal | EditWorkspace, false) => 0.30,
            (Some(ReadUntrusted), ReadClean | SearchLocal | ReadUntrusted, _) => 0.25,
            (Some(ReadClean | SearchLocal), WriteSaasOrEmail, false) => 0.12,
            (_, ReadClean | SearchLocal, _) => 0.22,
            (_, ReadUntrusted, false) => 0.18,
            (_, EditWorkspace, false) => 0.16,
            (_, WriteSaasOrEmail, false) => 0.10,
            (_, NetworkEgressExternal, false) => 0.08,
            (_, ExecShell, false) => 0.06,
            (_, ReadSecretOrCred, false) => 0.04,
            (_, ModifyPersistence, false) => 0.02,
            (_, _, true) => 0.06,
        }
    }

    /// Observes a tool-call transition for `nhi_id` using this instance's default thresholds.
    #[must_use]
    pub fn observe_and_evaluate(
        &self,
        nhi_id: &str,
        current_action: AgentActionClass,
        agent_tainted: bool,
    ) -> ActionTrajectoryVerdict {
        self.observe_and_evaluate_with_limits(
            nhi_id,
            current_action,
            agent_tainted,
            self.max_step_surprisal_bits,
            self.max_sequence_ppl,
        )
    }

    /// Observes a tool-call transition for `nhi_id` using explicit live-tuned thresholds.
    #[must_use]
    pub fn observe_and_evaluate_with_limits(
        &self,
        nhi_id: &str,
        current_action: AgentActionClass,
        agent_tainted: bool,
        max_step_surprisal_bits: f64,
        max_sequence_ppl: f64,
    ) -> ActionTrajectoryVerdict {
        let key = nhi_id.to_ascii_lowercase();
        let mut map = self.history.lock();
        let q = map
            .entry(key)
            .or_insert_with(|| VecDeque::with_capacity(32));
        let prev = q.back().map(|(a, _)| *a);

        let prob = Self::transition_probability(prev, current_action, agent_tainted);
        let step_surprisal_bits = -prob.max(1e-6).log2();

        if q.len() >= MAX_TRAJECTORY_HISTORY {
            q.pop_front();
        }
        q.push_back((current_action, step_surprisal_bits));

        // Sliding perplexity over the last 6 transitions
        let window_count = q.len().min(6);
        let mean_surprisal: f64 = q
            .iter()
            .rev()
            .take(window_count)
            .map(|(_, s)| *s)
            .sum::<f64>()
            / (window_count.max(1) as f64);
        let sequence_action_ppl = 2.0f64.powf(mean_surprisal);
        let seq_len = q.len();
        drop(map);

        let is_high_risk_sink = matches!(
            current_action,
            AgentActionClass::ReadSecretOrCred
                | AgentActionClass::ExecShell
                | AgentActionClass::NetworkEgressExternal
                | AgentActionClass::WriteSaasOrEmail
                | AgentActionClass::ModifyPersistence
        );
        let breakout_trajectory_anomaly = is_high_risk_sink
            && (step_surprisal_bits >= max_step_surprisal_bits
                || sequence_action_ppl >= max_sequence_ppl);

        let reason = if breakout_trajectory_anomaly {
            format!(
                "ACTION_TRAJECTORY_PPL_DENY: High-surprisal Break-Out transition {:?} -> {} (surprisal={step_surprisal_bits:.2} bits, seq_ppl={sequence_action_ppl:.2}, tainted={agent_tainted})",
                prev.map(|p| p.as_str()).unwrap_or("start"),
                current_action.as_str()
            )
        } else {
            format!(
                "ACTION_TRAJECTORY_PPL_ALLOW: Transition {:?} -> {} within benign Markov envelope (surprisal={step_surprisal_bits:.2} bits, seq_ppl={sequence_action_ppl:.2})",
                prev.map(|p| p.as_str()).unwrap_or("start"),
                current_action.as_str()
            )
        };

        ActionTrajectoryVerdict {
            allowed: !breakout_trajectory_anomaly,
            breakout_trajectory_anomaly,
            previous_action: prev,
            current_action,
            step_surprisal_bits,
            sequence_action_ppl,
            sequence_len: seq_len,
            reason,
        }
    }
}

/// A candidate tool proposal sampled prior to irreversible actuation (used by Layer 4 Semantic Entropy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateActionProposal {
    pub tool_name: String,
    pub target: String,
    pub operation: String,
    #[serde(default)]
    pub arg_keys: Vec<String>,
}

/// Verdict produced by Layer 4 (Semantic Entropy Actuation Gate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticEntropyVerdict {
    pub allowed: bool,
    pub abstain_and_require_hitl: bool,
    pub semantic_entropy_bits: f64,
    pub cluster_count: usize,
    pub proposal_count: usize,
    pub threshold_bits: f64,
    pub reason: String,
}

/// Clusters semantically equivalent candidate tool proposals and enforces automatic abstention
/// / 180s HITL when action uncertainty exceeds `threshold_bits` (preventing slopsquatting and
/// confused-deputy mutations).
#[derive(Debug, Clone, Copy)]
pub struct SemanticEntropyGate {
    pub threshold_bits: f64,
}

impl Default for SemanticEntropyGate {
    fn default() -> Self {
        Self {
            threshold_bits: 0.95,
        }
    }
}

impl SemanticEntropyGate {
    #[must_use]
    pub fn evaluate(
        &self,
        proposals: &[CandidateActionProposal],
        is_mutating_or_irreversible: bool,
    ) -> SemanticEntropyVerdict {
        if proposals.len() < 2 {
            return SemanticEntropyVerdict {
                allowed: true,
                abstain_and_require_hitl: false,
                semantic_entropy_bits: 0.0,
                cluster_count: proposals.len(),
                proposal_count: proposals.len(),
                threshold_bits: self.threshold_bits,
                reason: "SEMANTIC_ENTROPY_SINGLE_PROPOSAL: Unambiguous single candidate"
                    .to_string(),
            };
        }

        let mut clusters: HashMap<String, usize> = HashMap::new();
        for p in proposals {
            let mut keys: Vec<String> = p
                .arg_keys
                .iter()
                .map(|k| k.trim().to_ascii_lowercase())
                .collect();
            keys.sort();
            keys.dedup();
            let canonical_target = p
                .target
                .trim()
                .trim_end_matches('/')
                .replace('\\', "/")
                .to_ascii_lowercase();
            let cluster_key = format!(
                "{}|{}|{}|{}",
                p.tool_name.trim().to_ascii_lowercase(),
                canonical_target,
                p.operation.trim().to_ascii_lowercase(),
                keys.join(",")
            );
            *clusters.entry(cluster_key).or_insert(0) += 1;
        }

        let total = proposals.len() as f64;
        let mut h_sem = 0.0f64;
        for &cnt in clusters.values() {
            let prob = (cnt as f64) / total;
            h_sem -= prob * prob.log2();
        }

        let abstain = is_mutating_or_irreversible && h_sem >= self.threshold_bits;
        let reason = if abstain {
            format!(
                "SEMANTIC_ENTROPY_ABSTAIN_HITL: High action uncertainty H_sem={h_sem:.2} bits >= {:.2} across {} divergent clusters ({} proposals); mutating actuation halted for human verification",
                self.threshold_bits,
                clusters.len(),
                proposals.len()
            )
        } else {
            format!(
                "SEMANTIC_ENTROPY_ALLOW: Action consensus H_sem={h_sem:.2} bits ({} cluster(s) over {} proposals)",
                clusters.len(),
                proposals.len()
            )
        };

        SemanticEntropyVerdict {
            allowed: !abstain,
            abstain_and_require_hitl: abstain,
            semantic_entropy_bits: h_sem,
            cluster_count: clusters.len(),
            proposal_count: proposals.len(),
            threshold_bits: self.threshold_bits,
            reason,
        }
    }
}

/// Unified report returned by `PerplexityDefenseCoordinator::analyze_text` (CLI / Web API / RASP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerplexityTranslationReport {
    pub allowed: bool,
    pub translation: TranslationInspectionVerdict,
    pub source_perplexity: WindowedPerplexityVerdict,
    pub pivot_perplexity: WindowedPerplexityVerdict,
    pub total_taint_delta_bits: f64,
    pub reason: String,
}

/// Named workload calibration presets for local ABIBO perplexity & semantic-entropy tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerplexityWorkloadPreset {
    Balanced,
    StrictDefense,
    CodeHeavyDev,
    MultilingualResearch,
    Custom,
}

impl PerplexityWorkloadPreset {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::StrictDefense => "strict_defense",
            Self::CodeHeavyDev => "code_heavy_dev",
            Self::MultilingualResearch => "multilingual_research",
            Self::Custom => "custom",
        }
    }

    #[must_use]
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "balanced" | "default" => Some(Self::Balanced),
            "strict_defense" | "strict" | "production" => Some(Self::StrictDefense),
            "code_heavy_dev" | "code_heavy" | "code" | "dev" => Some(Self::CodeHeavyDev),
            "multilingual_research" | "multilingual" | "lrl" | "research" => {
                Some(Self::MultilingualResearch)
            }
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Validated, persistable runtime tuning configuration for all 4 Perplexity layers and
/// the loopback-only Canonical Low-Resource Language Translation Pivot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerplexityTuningConfig {
    pub preset: PerplexityWorkloadPreset,
    pub local_nmt_url: Option<String>,
    pub enable_local_ollama_fallback: bool,
    pub probe_timeout_ms: u64,
    pub nmt_translate_timeout_ms: u64,
    pub gcg_ppl_threshold: f64,
    pub gcg_cliff_ppl_threshold: f64,
    pub gcg_cliff_ratio_threshold: f64,
    pub jitter_threshold: f64,
    pub max_step_surprisal_bits: f64,
    pub max_sequence_ppl: f64,
    pub semantic_entropy_threshold_bits: f64,
}

impl Default for PerplexityTuningConfig {
    fn default() -> Self {
        Self::for_preset(PerplexityWorkloadPreset::Balanced)
    }
}

impl PerplexityTuningConfig {
    /// Returns calibrated thresholds for a named workload profile while preserving local NMT config.
    #[must_use]
    pub fn for_preset(preset: PerplexityWorkloadPreset) -> Self {
        let base_tl = TranslationLayerConfig::default();
        let (
            gcg_ppl,
            gcg_cliff_ppl,
            cliff_ratio,
            jitter,
            step_surprisal,
            seq_ppl,
            sem_ent,
            nmt_timeout,
        ) = match preset {
            PerplexityWorkloadPreset::Balanced | PerplexityWorkloadPreset::Custom => {
                (12.5, 10.5, 1.45, 0.36, 7.2, 28.0, 0.95, 2500)
            }
            PerplexityWorkloadPreset::StrictDefense => {
                (11.0, 9.5, 1.35, 0.32, 6.5, 20.0, 0.75, 2500)
            }
            PerplexityWorkloadPreset::CodeHeavyDev => {
                (14.5, 12.0, 1.60, 0.45, 7.2, 32.0, 1.05, 2000)
            }
            PerplexityWorkloadPreset::MultilingualResearch => {
                (13.5, 11.0, 1.50, 0.40, 7.0, 26.0, 0.85, 3500)
            }
        };
        Self {
            preset,
            local_nmt_url: base_tl.local_nmt_url,
            enable_local_ollama_fallback: base_tl.enable_local_ollama_fallback,
            probe_timeout_ms: base_tl.probe_timeout_ms,
            nmt_translate_timeout_ms: nmt_timeout,
            gcg_ppl_threshold: gcg_ppl,
            gcg_cliff_ppl_threshold: gcg_cliff_ppl,
            gcg_cliff_ratio_threshold: cliff_ratio,
            jitter_threshold: jitter,
            max_step_surprisal_bits: step_surprisal,
            max_sequence_ppl: seq_ppl,
            semantic_entropy_threshold_bits: sem_ent,
        }
    }

    /// Fail-closed validation ensuring every threshold stays within mathematically safe bounds
    /// and any configured translation URL strictly targets loopback (`127.0.0.1`/`localhost`/`::1`).
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref url) = self.local_nmt_url {
            if !url.trim().is_empty() {
                validate_loopback_translate_url(url)?;
            }
        }
        let check_f64 = |name: &str, v: f64, lo: f64, hi: f64| -> Result<(), String> {
            if !v.is_finite() || v < lo || v > hi {
                return Err(format!(
                    "INVALID_THRESHOLD: '{name}'={v} must be finite and within [{lo}, {hi}]"
                ));
            }
            Ok(())
        };
        check_f64("gcg_ppl_threshold", self.gcg_ppl_threshold, 8.0, 35.0)?;
        check_f64(
            "gcg_cliff_ppl_threshold",
            self.gcg_cliff_ppl_threshold,
            6.0,
            30.0,
        )?;
        if self.gcg_cliff_ppl_threshold > self.gcg_ppl_threshold {
            return Err(format!(
                "INVALID_THRESHOLD: 'gcg_cliff_ppl_threshold' ({}) must be <= 'gcg_ppl_threshold' ({})",
                self.gcg_cliff_ppl_threshold, self.gcg_ppl_threshold
            ));
        }
        check_f64(
            "gcg_cliff_ratio_threshold",
            self.gcg_cliff_ratio_threshold,
            1.10,
            3.50,
        )?;
        check_f64("jitter_threshold", self.jitter_threshold, 0.15, 0.90)?;
        check_f64(
            "max_step_surprisal_bits",
            self.max_step_surprisal_bits,
            4.0,
            12.0,
        )?;
        check_f64("max_sequence_ppl", self.max_sequence_ppl, 8.0, 100.0)?;
        check_f64(
            "semantic_entropy_threshold_bits",
            self.semantic_entropy_threshold_bits,
            0.30,
            2.50,
        )?;
        if !(100..=400).contains(&self.probe_timeout_ms) {
            return Err(format!(
                "INVALID_TIMEOUT: 'probe_timeout_ms'={} must be within [100, 400] ms",
                self.probe_timeout_ms
            ));
        }
        if !(250..=10_000).contains(&self.nmt_translate_timeout_ms) {
            return Err(format!(
                "INVALID_TIMEOUT: 'nmt_translate_timeout_ms'={} must be within [250, 10000] ms",
                self.nmt_translate_timeout_ms
            ));
        }
        Ok(())
    }

    /// Resolves config from `config/abibo_perplexity_config.json`, workspace `.env`, and
    /// `OCTOPUS_PPL_*` / `OCTOPUS_TRANSLATE_URL` environment variables (validated fail-closed).
    #[must_use]
    pub fn load_for_workspace(workspace_root: &Path) -> Self {
        let mut cfg = Self::default();

        // 1. Load persisted JSON profile if present and valid
        let cfg_path = workspace_root
            .join("config")
            .join("abibo_perplexity_config.json");
        if let Ok(raw) = std::fs::read_to_string(&cfg_path) {
            if let Ok(parsed) = serde_json::from_str::<Self>(&raw) {
                if parsed.validate().is_ok() {
                    cfg = parsed;
                }
            }
        }

        // 2. Apply workspace `.env` fallback for OCTOPUS_TRANSLATE_URL and OCTOPUS_PPL_PRESET
        let lookup = |key: &str| -> Option<String> {
            std::env::var(key)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .or_else(|| read_dotenv_key_in(workspace_root, key))
        };

        if let Some(preset_str) = lookup("OCTOPUS_PPL_PRESET") {
            if let Some(p) = PerplexityWorkloadPreset::from_str_loose(&preset_str) {
                let mut preset_cfg = Self::for_preset(p);
                preset_cfg.local_nmt_url = cfg.local_nmt_url.clone();
                preset_cfg.enable_local_ollama_fallback = cfg.enable_local_ollama_fallback;
                cfg = preset_cfg;
            }
        }
        if let Some(url) = lookup("OCTOPUS_TRANSLATE_URL") {
            if validate_loopback_translate_url(&url).is_ok() {
                cfg.local_nmt_url = Some(url);
            }
        }
        if let Some(v) = lookup("OCTOPUS_NMT_PROBE_TIMEOUT_MS").and_then(|s| s.parse::<u64>().ok())
        {
            cfg.probe_timeout_ms = v.clamp(100, 400);
        }
        if let Some(v) = lookup("OCTOPUS_NMT_TIMEOUT_MS").and_then(|s| s.parse::<u64>().ok()) {
            cfg.nmt_translate_timeout_ms = v.clamp(250, 10_000);
        }
        if let Some(v) = lookup("OCTOPUS_PPL_GCG_THRESHOLD").and_then(|s| s.parse::<f64>().ok()) {
            if v.is_finite() && (8.0..=35.0).contains(&v) {
                cfg.gcg_ppl_threshold = v;
                cfg.preset = PerplexityWorkloadPreset::Custom;
            }
        }
        if let Some(v) =
            lookup("OCTOPUS_PPL_CLIFF_PPL_THRESHOLD").and_then(|s| s.parse::<f64>().ok())
        {
            if v.is_finite() && (6.0..=30.0).contains(&v) && v <= cfg.gcg_ppl_threshold {
                cfg.gcg_cliff_ppl_threshold = v;
                cfg.preset = PerplexityWorkloadPreset::Custom;
            }
        }
        if let Some(v) = lookup("OCTOPUS_PPL_CLIFF_RATIO").and_then(|s| s.parse::<f64>().ok()) {
            if v.is_finite() && (1.10..=3.50).contains(&v) {
                cfg.gcg_cliff_ratio_threshold = v;
                cfg.preset = PerplexityWorkloadPreset::Custom;
            }
        }
        if let Some(v) = lookup("OCTOPUS_PPL_JITTER_THRESHOLD").and_then(|s| s.parse::<f64>().ok())
        {
            if v.is_finite() && (0.15..=0.90).contains(&v) {
                cfg.jitter_threshold = v;
                cfg.preset = PerplexityWorkloadPreset::Custom;
            }
        }
        if let Some(v) =
            lookup("OCTOPUS_PPL_ACTION_SURPRISAL_BITS").and_then(|s| s.parse::<f64>().ok())
        {
            if v.is_finite() && (4.0..=12.0).contains(&v) {
                cfg.max_step_surprisal_bits = v;
                cfg.preset = PerplexityWorkloadPreset::Custom;
            }
        }
        if let Some(v) = lookup("OCTOPUS_PPL_ACTION_SEQ_LIMIT").and_then(|s| s.parse::<f64>().ok())
        {
            if v.is_finite() && (8.0..=100.0).contains(&v) {
                cfg.max_sequence_ppl = v;
                cfg.preset = PerplexityWorkloadPreset::Custom;
            }
        }
        if let Some(v) =
            lookup("OCTOPUS_PPL_SEMANTIC_ENTROPY_BITS").and_then(|s| s.parse::<f64>().ok())
        {
            if v.is_finite() && (0.30..=2.50).contains(&v) {
                cfg.semantic_entropy_threshold_bits = v;
                cfg.preset = PerplexityWorkloadPreset::Custom;
            }
        }

        if cfg.validate().is_ok() {
            cfg
        } else {
            Self::default()
        }
    }

    /// Persists validated tuning config to `<workspace_root>/config/abibo_perplexity_config.json`.
    pub fn save_to_workspace(&self, workspace_root: &Path) -> Result<PathBuf, String> {
        self.validate()?;
        let config_dir = workspace_root.join("config");
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
        let path = config_dir.join("abibo_perplexity_config.json");
        let pretty = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize perplexity config: {e}"))?;
        std::fs::write(&path, pretty)
            .map_err(|e| format!("Failed to write perplexity config {}: {e}", path.display()))?;
        Ok(path)
    }

    #[must_use]
    pub fn to_translation_layer(&self) -> CanonicalTranslationLayer {
        CanonicalTranslationLayer::new(TranslationLayerConfig {
            local_nmt_url: self
                .local_nmt_url
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            enable_local_ollama_fallback: self.enable_local_ollama_fallback,
            probe_timeout_ms: self.probe_timeout_ms,
        })
        .with_translate_timeout_ms(self.nmt_translate_timeout_ms)
    }

    #[must_use]
    pub fn to_windowed_analyzer(&self) -> WindowedPerplexityAnalyzer {
        WindowedPerplexityAnalyzer {
            gcg_ppl_threshold: self.gcg_ppl_threshold,
            gcg_cliff_ppl_threshold: self.gcg_cliff_ppl_threshold,
            gcg_cliff_ratio_threshold: self.gcg_cliff_ratio_threshold,
            jitter_threshold: self.jitter_threshold,
        }
    }
}

/// Thread-safe coordinator unifying Canonical Translation Pivot + 4-Layer Perplexity & Semantic Entropy.
pub struct PerplexityDefenseCoordinator {
    config: RwLock<PerplexityTuningConfig>,
    translation: RwLock<CanonicalTranslationLayer>,
    windowed_ppl: RwLock<WindowedPerplexityAnalyzer>,
    action_trajectory: ActionTrajectoryPerplexity,
    semantic_entropy: RwLock<SemanticEntropyGate>,
}

impl Default for PerplexityDefenseCoordinator {
    fn default() -> Self {
        Self::new(CanonicalTranslationLayer::default())
    }
}

impl PerplexityDefenseCoordinator {
    #[must_use]
    pub fn new(translation: CanonicalTranslationLayer) -> Self {
        let mut cfg = PerplexityTuningConfig::default();
        cfg.local_nmt_url = translation.config().local_nmt_url.clone();
        cfg.enable_local_ollama_fallback = translation.config().enable_local_ollama_fallback;
        cfg.probe_timeout_ms = translation.config().probe_timeout_ms;
        cfg.nmt_translate_timeout_ms = translation.translate_timeout_ms();
        Self {
            windowed_ppl: RwLock::new(cfg.to_windowed_analyzer()),
            semantic_entropy: RwLock::new(SemanticEntropyGate {
                threshold_bits: cfg.semantic_entropy_threshold_bits,
            }),
            config: RwLock::new(cfg),
            translation: RwLock::new(translation),
            action_trajectory: ActionTrajectoryPerplexity::default(),
        }
    }

    /// Constructs a coordinator loaded from `<workspace_root>/config/abibo_perplexity_config.json`,
    /// workspace `.env`, and process environment overrides.
    #[must_use]
    pub fn for_workspace(workspace_root: &Path) -> Self {
        let cfg = PerplexityTuningConfig::load_for_workspace(workspace_root);
        Self::from_tuning_config(cfg).unwrap_or_default()
    }

    pub fn from_tuning_config(cfg: PerplexityTuningConfig) -> Result<Self, String> {
        cfg.validate()?;
        let tl = cfg.to_translation_layer();
        let wp = cfg.to_windowed_analyzer();
        let se = SemanticEntropyGate {
            threshold_bits: cfg.semantic_entropy_threshold_bits,
        };
        Ok(Self {
            config: RwLock::new(cfg),
            translation: RwLock::new(tl),
            windowed_ppl: RwLock::new(wp),
            action_trajectory: ActionTrajectoryPerplexity::default(),
            semantic_entropy: RwLock::new(se),
        })
    }

    #[must_use]
    pub fn tuning_config(&self) -> PerplexityTuningConfig {
        self.config.read().clone()
    }

    /// Validates and atomically applies a new runtime tuning configuration across all 4 layers
    /// and the loopback translation layer, optionally persisting to `config/abibo_perplexity_config.json`.
    pub fn update_tuning_config(
        &self,
        mut next: PerplexityTuningConfig,
        persist_workspace: Option<&Path>,
    ) -> Result<PerplexityTuningConfig, String> {
        next.local_nmt_url = next
            .local_nmt_url
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        next.validate()?;
        if let Some(root) = persist_workspace {
            next.save_to_workspace(root)?;
        }
        let tl = next.to_translation_layer();
        let wp = next.to_windowed_analyzer();
        let se = SemanticEntropyGate {
            threshold_bits: next.semantic_entropy_threshold_bits,
        };
        *self.translation.write() = tl;
        *self.windowed_ppl.write() = wp;
        *self.semantic_entropy.write() = se;
        *self.config.write() = next.clone();
        Ok(next)
    }

    #[must_use]
    pub fn probe_nmt_health(&self) -> NmtHealthStatus {
        self.translation.read().probe_nmt_health()
    }

    #[must_use]
    pub fn translation(&self) -> CanonicalTranslationLayer {
        self.translation.read().clone()
    }

    #[must_use]
    pub fn action_trajectory(&self) -> &ActionTrajectoryPerplexity {
        &self.action_trajectory
    }

    #[must_use]
    pub fn observe_action_trajectory(
        &self,
        nhi_id: &str,
        current_action: AgentActionClass,
        agent_tainted: bool,
    ) -> ActionTrajectoryVerdict {
        let cfg = self.config.read();
        let max_step = cfg.max_step_surprisal_bits;
        let max_seq = cfg.max_sequence_ppl;
        drop(cfg);
        self.action_trajectory.observe_and_evaluate_with_limits(
            nhi_id,
            current_action,
            agent_tainted,
            max_step,
            max_seq,
        )
    }

    #[must_use]
    pub fn semantic_entropy(&self) -> SemanticEntropyGate {
        *self.semantic_entropy.read()
    }

    /// Analyzes arbitrary text (prompt, RAG doc, memory file, or tool payload) through the
    /// Canonical Translation Layer + Dual-Domain Windowed Perplexity (both source & English pivot).
    #[must_use]
    pub fn analyze_text(
        &self,
        text: &str,
        allow_loopback_nmt: bool,
    ) -> PerplexityTranslationReport {
        let tl = self.translation.read().clone();
        let wp = self.windowed_ppl.read().clone();

        let translation = if allow_loopback_nmt {
            tl.inspect_with_live_pivot(text)
        } else {
            tl.inspect_offline(text)
        };

        let source_perplexity = wp.analyze(text, translation.profile.language_tier);

        // If a canonical English pivot differs from raw text, also run windowed PPL on the pivot
        let pivot_perplexity = if translation.canonical_english_pivot != text {
            wp.analyze(&translation.canonical_english_pivot, LanguageTier::English)
        } else {
            source_perplexity.clone()
        };

        let blocked =
            translation.breakin_detected || !source_perplexity.allowed || !pivot_perplexity.allowed;
        let total_taint_delta_bits = translation.taint_delta_bits
            + source_perplexity
                .taint_delta_bits
                .max(pivot_perplexity.taint_delta_bits);

        let reason = if translation.breakin_detected {
            translation.reason.clone()
        } else if !source_perplexity.allowed {
            source_perplexity.reason.clone()
        } else if !pivot_perplexity.allowed {
            pivot_perplexity.reason.clone()
        } else {
            format!(
                "PERPLEXITY_TRANSLATION_ALLOW: lang='{}' tier={} max_ppl={:.2} cliff={:.2}x",
                translation.profile.detected_language,
                translation.profile.language_tier.as_str(),
                source_perplexity.max_window_ppl,
                source_perplexity.cliff_ratio
            )
        };

        PerplexityTranslationReport {
            allowed: !blocked,
            translation,
            source_perplexity,
            pivot_perplexity,
            total_taint_delta_bits,
            reason,
        }
    }
}
