//! Rust <-> Lean 4 Formal Verification 1-to-1 Coupling & Invariant Integration Tests.
//!
//! Dynamically parses `formal/lean-toolchain`, `formal/lakefile.toml`,
//! `formal/AgentOctopusFormal.lean`, and all 10 modules under
//! `formal/AgentOctopusFormal/` (`CoreTypes`, `FsmContainment`, `HomologicalMesh`,
//! `EpochAutotomy`, `CageNoDirectBind`, `CedarAndTemporal`, `MandateAndQuorum`,
//! `IsolationAndPerimeter`, `NoBreachNoBreakout`, and `AxiomAudit`), verifying exact
//! structural/constant parity and exercising positive and negative runtime security boundaries.

use agent_octopus::containment_ring::sentinel as ring_sentinel;
use agent_octopus::containment_ring::{role_trust_tier, TrustTier, MAX_RELAY_HOPS};
use agent_octopus::security::cage_governance::{
    ActionReversibility, BfsPhase, CBF_EPSILON, CLOCK_DRIFT_TOLERANCE_SECS, ROUTING_SEAL_TTL_SECS,
    SR_26_2_CONFIDENCE_ALLOW_THRESHOLD, SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD,
};
use agent_octopus::security::cedar_arm::temporal::DecisionContext;
use agent_octopus::security::cedar_arm::{DogwoodTemporalEngine, OCTOPUS_CEDAR_SCHEMA_JSON};
use agent_octopus::security::{
    open_confined, TokenPosture, ALLOWED_SCHEMES, DANGEROUS_PRIVILEGES, INTEGRITY_HIGH,
    INTEGRITY_MEDIUM, MAX_DELEGATION_DEPTH,
};
use agent_octopus::sentinel_ring::{
    create_authenticated_heartbeat, EpochRegistry, SentinelAction, SentinelObservation,
    SentinelSupervisor, SentinelSystemState,
};
use agent_octopus::{
    evaluate_pre_resume_confinement_gate, is_restricted_rebinding_ip, validate_agent_egress_url,
    validate_mesh_uri, validate_sandbox_relative_path, verify_windows_confinement_invariants,
    ArmContainmentRing, ArmRole, ArmState, AttenuatedMandate, Authorizer, CbfSafetyEngine,
    CedarAuthorizer, CedarGate, CedarPolicyEngine, DebitLedger, DelegationScopeGuard,
    DeterministicLayer, DiracDeltaCapabilityTicket, FormalBfsModel, FsmTransitionGuard,
    HomologicalBoundaryAuditor, IndependentTrustBoundaryVerifier, KernelAttackSurface,
    KernelShieldPosture, LedgerError, MandateError, MeshGuard, MessageKind, Operation,
    PolicyAttestation, PolicyGuard, PolicyProposal, QuorumPolicyGuard, RingRequest,
    RoutingSealSigner, StrategicDirective, VerifiedInvoiceArtifact, VirtualPatchShieldStore,
    WindowsConfinementPolicy,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod lean_parser {
    use super::*;

    pub fn formal_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("formal")
    }

    pub fn read_formal_file(rel: &str) -> String {
        let p = formal_root().join(rel);
        fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("Failed to read formal file {}: {}", p.display(), e))
    }

    pub fn read_module(module_name: &str) -> String {
        read_formal_file(&format!("AgentOctopusFormal/{module_name}.lean"))
    }

    fn is_lean_ident_start(c: char) -> bool {
        c.is_alphabetic() || c == '_'
    }

    fn is_lean_ident_continue(c: char) -> bool {
        // Excludes '!' so `s!"..."`, `m!"..."`, `!"..."`, and `!=` split cleanly at '!'.
        c.is_alphanumeric() || c == '_' || c == '\'' || c == '?'
    }

    fn try_consume_lean_char_literal(src: &str, i: usize) -> Option<usize> {
        let bytes = src.as_bytes();
        if bytes.get(i) != Some(&b'\'') {
            return None;
        }
        let prev_is_ident = i > 0
            && src[..i]
                .chars()
                .next_back()
                .is_some_and(is_lean_ident_continue);
        if prev_is_ident {
            return None;
        }
        let rest = &src[i + 1..];
        if let Some(after_slash) = rest.strip_prefix('\\') {
            let esc = after_slash.chars().next()?;
            match esc {
                'n' | 'r' | 't' | '\\' | '"' | '\'' | '0' => {
                    let after_esc = &after_slash[esc.len_utf8()..];
                    if after_esc.starts_with('\'') {
                        return Some(i + 2 + esc.len_utf8() + 1);
                    }
                }
                'x' => {
                    let hex_part = &after_slash[1..];
                    if hex_part.len() >= 3
                        && hex_part.as_bytes()[0].is_ascii_hexdigit()
                        && hex_part.as_bytes()[1].is_ascii_hexdigit()
                        && hex_part.as_bytes()[2] == b'\''
                    {
                        return Some(i + 2 + 1 + 3);
                    }
                }
                'u' => {
                    let hex_part = &after_slash[1..];
                    if hex_part.len() >= 5
                        && hex_part.as_bytes()[..4].iter().all(u8::is_ascii_hexdigit)
                        && hex_part.as_bytes()[4] == b'\''
                    {
                        return Some(i + 2 + 1 + 5);
                    }
                }
                _ => {}
            }
            None
        } else {
            let ch = rest.chars().next()?;
            if ch != '\'' && ch != '\n' && ch != '\r' && rest[ch.len_utf8()..].starts_with('\'') {
                Some(i + 1 + ch.len_utf8() + 1)
            } else {
                None
            }
        }
    }

    fn try_consume_lean_raw_string(
        src: &str,
        i: usize,
        start_line: usize,
    ) -> Result<Option<(usize, usize)>, String> {
        let bytes = src.as_bytes();
        let n = bytes.len();
        if bytes.get(i) != Some(&b'r') {
            return Ok(None);
        }
        let prev_is_ident = i > 0
            && src[..i]
                .chars()
                .next_back()
                .is_some_and(is_lean_ident_continue);
        if prev_is_ident {
            return Ok(None);
        }
        let mut j = i + 1;
        while j < n && bytes[j] == b'#' {
            j += 1;
        }
        let hash_count = j - (i + 1);
        if bytes.get(j) != Some(&b'"') {
            return Ok(None);
        }

        let mut k = j + 1;
        let mut cur_line = start_line;
        while k < n {
            if bytes[k] == b'"'
                && k + 1 + hash_count <= n
                && bytes[k + 1..k + 1 + hash_count].iter().all(|&b| b == b'#')
            {
                return Ok(Some((k + 1 + hash_count, cur_line)));
            }
            let ch = src[k..].chars().next().unwrap();
            if ch == '\n' {
                cur_line += 1;
            }
            k += ch.len_utf8();
        }

        Err(format!(
            "Unclosed raw string literal starting at line {start_line}"
        ))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum LeanTokenKind {
        Ident(String),
        GuillemetIdent(String),
        Number(String),
        StringLit,
        CharLit,
        AtLBracket,
        Punct(char),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LeanToken {
        pub kind: LeanTokenKind,
        pub line: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum LexMode {
        Code {
            in_interpolation: bool,
            brace_depth: usize,
        },
        InterpString,
    }

    pub fn tokenize_lean_code(src: &str) -> Result<Vec<LeanToken>, String> {
        let bytes = src.as_bytes();
        let n = bytes.len();
        let mut i = 0usize;
        let mut line = 1usize;
        let mut stack = vec![LexMode::Code {
            in_interpolation: false,
            brace_depth: 0,
        }];
        let mut tokens = Vec::new();

        while i < n {
            match *stack.last().expect("lexer mode stack non-empty") {
                LexMode::InterpString => {
                    let b = bytes[i];
                    if b == b'\\' {
                        if i + 1 < n {
                            let esc = src[i + 1..].chars().next().unwrap();
                            if esc == '\n' {
                                line += 1;
                            }
                            i += 1 + esc.len_utf8();
                        } else {
                            return Err(format!(
                                "Trailing backslash in interpolated string at line {line}"
                            ));
                        }
                    } else if b == b'"' {
                        stack.pop();
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::StringLit,
                            line,
                        });
                        i += 1;
                    } else if b == b'{' {
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::Punct('{'),
                            line,
                        });
                        stack.push(LexMode::Code {
                            in_interpolation: true,
                            brace_depth: 0,
                        });
                        i += 1;
                    } else {
                        let ch = src[i..].chars().next().unwrap();
                        if ch == '\n' {
                            line += 1;
                        }
                        i += ch.len_utf8();
                    }
                }
                LexMode::Code {
                    in_interpolation,
                    brace_depth,
                } => {
                    let ch = src[i..].chars().next().unwrap();
                    if ch.is_whitespace() {
                        if ch == '\n' {
                            line += 1;
                        }
                        i += ch.len_utf8();
                        continue;
                    }

                    if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'-') {
                        i += 2;
                        while i < n && bytes[i] != b'\n' {
                            i += 1;
                        }
                        continue;
                    }

                    if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'-') {
                        let start_line = line;
                        let mut depth = 1usize;
                        i += 2;
                        while i < n && depth > 0 {
                            if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'-') {
                                depth += 1;
                                i += 2;
                            } else if bytes[i] == b'-' && bytes.get(i + 1) == Some(&b'/') {
                                depth -= 1;
                                i += 2;
                            } else {
                                let c = src[i..].chars().next().unwrap();
                                if c == '\n' {
                                    line += 1;
                                }
                                i += c.len_utf8();
                            }
                        }
                        if depth > 0 {
                            return Err(format!(
                                "Unclosed /- block comment starting at line {start_line}"
                            ));
                        }
                        continue;
                    }

                    if ch == '«' {
                        let start_line = line;
                        i += ch.len_utf8();
                        let start = i;
                        let mut closed = false;
                        while i < n {
                            let c = src[i..].chars().next().unwrap();
                            if c == '»' {
                                closed = true;
                                break;
                            }
                            if c == '\n' {
                                line += 1;
                            }
                            i += c.len_utf8();
                        }
                        if !closed {
                            return Err(format!(
                                "Unclosed guillemet identifier starting at line {start_line}"
                            ));
                        }
                        let inner = src[start..i].to_string();
                        i += '»'.len_utf8();
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::GuillemetIdent(inner),
                            line: start_line,
                        });
                        continue;
                    }

                    if bytes[i] == b'!' && bytes.get(i + 1) == Some(&b'"') {
                        stack.push(LexMode::InterpString);
                        i += 2;
                        continue;
                    }

                    if bytes[i] == b'r' {
                        if let Some((next_i, end_line)) = try_consume_lean_raw_string(src, i, line)?
                        {
                            tokens.push(LeanToken {
                                kind: LeanTokenKind::StringLit,
                                line,
                            });
                            line = end_line;
                            i = next_i;
                            continue;
                        }
                    }

                    if bytes[i] == b'"' {
                        let is_separated_interp = match tokens.as_slice() {
                            [.., LeanToken {
                                kind: LeanTokenKind::Ident(prefix),
                                ..
                            }, LeanToken {
                                kind: LeanTokenKind::Punct('!'),
                                ..
                            }] => {
                                let is_qualified = tokens.len() >= 3
                                    && matches!(
                                        tokens[tokens.len() - 3].kind,
                                        LeanTokenKind::Punct('.')
                                    );
                                !(prefix == "panic" && !is_qualified)
                            }
                            [.., LeanToken {
                                kind: LeanTokenKind::Ident(prefix),
                                ..
                            }] => prefix == "dbg_trace",
                            _ => false,
                        };
                        if is_separated_interp {
                            stack.push(LexMode::InterpString);
                            i += 1;
                            continue;
                        }
                        let start_line = line;
                        i += 1;
                        let mut closed = false;
                        while i < n {
                            if bytes[i] == b'\\' {
                                if i + 1 < n {
                                    let esc = src[i + 1..].chars().next().unwrap();
                                    if esc == '\n' {
                                        line += 1;
                                    }
                                    i += 1 + esc.len_utf8();
                                } else {
                                    return Err(format!(
                                        "Unclosed string escape at line {start_line}"
                                    ));
                                }
                            } else if bytes[i] == b'"' {
                                i += 1;
                                closed = true;
                                break;
                            } else {
                                let c = src[i..].chars().next().unwrap();
                                if c == '\n' {
                                    line += 1;
                                }
                                i += c.len_utf8();
                            }
                        }
                        if !closed {
                            return Err(format!(
                                "Unclosed string literal starting at line {start_line}"
                            ));
                        }
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::StringLit,
                            line: start_line,
                        });
                        continue;
                    }

                    if bytes[i] == b'\'' {
                        if let Some(next_i) = try_consume_lean_char_literal(src, i) {
                            tokens.push(LeanToken {
                                kind: LeanTokenKind::CharLit,
                                line,
                            });
                            i = next_i;
                        } else {
                            tokens.push(LeanToken {
                                kind: LeanTokenKind::Punct('\''),
                                line,
                            });
                            i += 1;
                        }
                        continue;
                    }

                    if bytes[i] == b'@' && bytes.get(i + 1) == Some(&b'[') {
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::AtLBracket,
                            line,
                        });
                        i += 2;
                        continue;
                    }

                    if bytes[i] == b'{' {
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::Punct('{'),
                            line,
                        });
                        if let Some(LexMode::Code { brace_depth: d, .. }) = stack.last_mut() {
                            *d += 1;
                        }
                        i += 1;
                        continue;
                    }

                    if bytes[i] == b'}' {
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::Punct('}'),
                            line,
                        });
                        i += 1;
                        if brace_depth > 0 {
                            if let Some(LexMode::Code { brace_depth: d, .. }) = stack.last_mut() {
                                *d -= 1;
                            }
                        } else if in_interpolation {
                            stack.pop();
                        }
                        continue;
                    }

                    if is_lean_ident_start(ch) {
                        let start = i;
                        i += ch.len_utf8();
                        while i < n {
                            let c = src[i..].chars().next().unwrap();
                            if is_lean_ident_continue(c) {
                                i += c.len_utf8();
                            } else {
                                break;
                            }
                        }
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::Ident(src[start..i].to_string()),
                            line,
                        });
                        continue;
                    }

                    if ch.is_ascii_digit() {
                        let start = i;
                        i += 1;
                        if ch == '0'
                            && i < n
                            && matches!(bytes[i], b'x' | b'X' | b'b' | b'B' | b'o' | b'O')
                        {
                            let radix = bytes[i];
                            i += 1;
                            while i < n {
                                let b = bytes[i];
                                let valid = match radix {
                                    b'x' | b'X' => b.is_ascii_hexdigit() || b == b'_',
                                    b'b' | b'B' => matches!(b, b'0' | b'1' | b'_'),
                                    b'o' | b'O' => matches!(b, b'0'..=b'7' | b'_'),
                                    _ => false,
                                };
                                if valid {
                                    i += 1;
                                } else {
                                    break;
                                }
                            }
                        } else {
                            while i < n && (bytes[i].is_ascii_digit() || bytes[i] == b'_') {
                                i += 1;
                            }
                        }
                        tokens.push(LeanToken {
                            kind: LeanTokenKind::Number(src[start..i].to_string()),
                            line,
                        });
                        continue;
                    }

                    tokens.push(LeanToken {
                        kind: LeanTokenKind::Punct(ch),
                        line,
                    });
                    i += ch.len_utf8();
                }
            }
        }

        if stack.len() != 1 {
            return Err("Unclosed interpolated string literal".to_string());
        }

        Ok(tokens)
    }

    /// Strips Lean `-- ...` line comments and nested `/- ... -/` block comments.
    /// When `strip_strings` is true, string literals `"..."` and char literals `'...'`
    /// are also blanked out while preserving token boundaries.
    pub fn strip_lean_comments(src: &str, strip_strings: bool) -> String {
        let bytes = src.as_bytes();
        let n = bytes.len();
        let mut out = Vec::with_capacity(n);
        let mut i = 0;
        let mut block_depth: usize = 0;
        let mut in_line_comment = false;
        let mut in_string = false;

        while i < n {
            let b = bytes[i];
            let next = if i + 1 < n { bytes[i + 1] } else { 0 };

            if in_line_comment {
                if b == b'\n' {
                    in_line_comment = false;
                    out.push(b);
                }
                i += 1;
            } else if block_depth > 0 {
                if b == b'/' && next == b'-' {
                    block_depth += 1;
                    i += 2;
                } else if b == b'-' && next == b'/' {
                    block_depth -= 1;
                    if block_depth == 0 {
                        out.push(b' ');
                    }
                    i += 2;
                } else {
                    if b == b'\n' {
                        out.push(b);
                    }
                    i += 1;
                }
            } else if in_string {
                if b == b'\\' && i + 1 < n {
                    let esc = src[i + 1..].chars().next().unwrap();
                    let adv = 1 + esc.len_utf8();
                    if !strip_strings {
                        out.extend_from_slice(&bytes[i..i + adv]);
                    }
                    i += adv;
                } else if b == b'"' {
                    in_string = false;
                    if strip_strings {
                        out.push(b' ');
                    } else {
                        out.push(b);
                    }
                    i += 1;
                } else {
                    if !strip_strings {
                        out.push(b);
                    }
                    i += 1;
                }
            } else if b == b'-' && next == b'-' {
                in_line_comment = true;
                i += 2;
            } else if b == b'/' && next == b'-' {
                block_depth = 1;
                i += 2;
            } else if b == b'r' {
                match try_consume_lean_raw_string(src, i, 1) {
                    Ok(Some((next_i, _))) => {
                        if strip_strings {
                            out.push(b' ');
                        } else {
                            out.extend_from_slice(&bytes[i..next_i]);
                        }
                        i = next_i;
                    }
                    Ok(None) => {
                        out.push(b);
                        i += 1;
                    }
                    Err(_) => {
                        if strip_strings {
                            out.push(b' ');
                        } else {
                            out.extend_from_slice(&bytes[i..]);
                        }
                        i = n;
                    }
                }
            } else if b == b'"' {
                in_string = true;
                if strip_strings {
                    out.push(b' ');
                } else {
                    out.push(b);
                }
                i += 1;
            } else if let Some(next_i) = try_consume_lean_char_literal(src, i) {
                if strip_strings {
                    out.push(b' ');
                } else {
                    out.extend_from_slice(&bytes[i..next_i]);
                }
                i = next_i;
            } else {
                out.push(b);
                i += 1;
            }
        }

        String::from_utf8(out).expect("Lean source must remain valid UTF-8")
    }

    pub fn parse_inductive_constructors(src: &str, type_name: &str) -> Vec<String> {
        let cleaned = strip_lean_comments(src, false);
        let lines: Vec<&str> = cleaned.lines().collect();
        let mut ctors = Vec::new();
        let mut capturing = false;

        for line in lines {
            let trimmed = line.trim();
            if !capturing {
                let mut tokens = trimmed.split_whitespace();
                let first = tokens.next();
                let second = tokens.next();
                let third = tokens.next();
                let matches_decl = match (first, second, third) {
                    (Some("inductive"), Some(name), _) => name == type_name,
                    (Some("private" | "protected"), Some("inductive"), Some(name)) => {
                        name == type_name
                    }
                    _ => false,
                };
                if matches_decl {
                    capturing = true;
                    if let Some(where_idx) = trimmed.find(" where") {
                        let rest = &trimmed[where_idx + " where".len()..];
                        for part in rest.split('|').skip(1) {
                            if let Some(cname) = part.split_whitespace().next() {
                                ctors.push(cname.to_string());
                            }
                        }
                    }
                }
                continue;
            }

            if trimmed.is_empty() {
                if !ctors.is_empty() {
                    break;
                }
                continue;
            }
            if trimmed.starts_with("deriving ")
                || trimmed.starts_with("end ")
                || trimmed.starts_with("def ")
                || trimmed.starts_with("theorem ")
                || trimmed.starts_with("inductive ")
                || trimmed.starts_with("structure ")
                || trimmed.starts_with("namespace ")
                || trimmed.starts_with("instance ")
            {
                break;
            }
            if let Some(after_bar) = trimmed.strip_prefix('|') {
                for part in after_bar.split('|') {
                    if let Some(raw_name) = part.split_whitespace().next() {
                        let name = raw_name.trim_end_matches(':');
                        if !name.is_empty() {
                            ctors.push(name.to_string());
                        }
                    }
                }
            } else if !ctors.is_empty() {
                break;
            }
        }

        ctors
    }

    pub fn parse_def_rhs(src: &str, def_name: &str) -> String {
        let cleaned = strip_lean_comments(src, false);
        let lines: Vec<&str> = cleaned.lines().collect();
        let mut collecting = false;
        let mut rhs_buf = String::new();

        for line in lines {
            let trimmed = line.trim();
            if !collecting {
                if let Some(after_def) = trimmed.strip_prefix("def ") {
                    let ident = after_def
                        .split(|c: char| c.is_whitespace() || c == ':')
                        .next()
                        .unwrap_or("");
                    if ident == def_name {
                        if let Some(pos) = trimmed.find(":=") {
                            rhs_buf.push_str(trimmed[pos + 2..].trim());
                            collecting = true;
                        }
                    }
                }
                continue;
            }

            let is_top_decl = trimmed.starts_with("def ")
                || trimmed.starts_with("theorem ")
                || trimmed.starts_with("private ")
                || trimmed.starts_with("inductive ")
                || trimmed.starts_with("structure ")
                || trimmed.starts_with("namespace ")
                || trimmed.starts_with("end ")
                || trimmed.starts_with("instance ");
            if is_top_decl {
                break;
            }
            if !trimmed.is_empty() {
                if !rhs_buf.is_empty() {
                    rhs_buf.push(' ');
                }
                rhs_buf.push_str(trimmed);
            } else if !rhs_buf.is_empty() {
                break;
            }
        }

        assert!(
            collecting && !rhs_buf.is_empty(),
            "Could not find Lean `def {def_name}`"
        );
        rhs_buf
    }

    fn eval_nat_token(tok: &str, env: &HashMap<String, u64>) -> u64 {
        let clean = tok.trim().replace('_', "");
        if let Some(hex_digits) = clean
            .strip_prefix("0x")
            .or_else(|| clean.strip_prefix("0X"))
        {
            u64::from_str_radix(hex_digits, 16)
                .unwrap_or_else(|e| panic!("Invalid hex Nat literal '{tok}': {e}"))
        } else if let Ok(v) = clean.parse::<u64>() {
            v
        } else if let Some(&v) = env.get(tok.trim()) {
            v
        } else {
            panic!("Unsupported Nat token '{tok}' in Lean expression");
        }
    }

    pub fn parse_def_nat(src: &str, def_name: &str, env: &HashMap<String, u64>) -> u64 {
        let rhs = parse_def_rhs(src, def_name);
        let mut prod: u64 = 1;
        for factor in rhs.split('*') {
            prod = prod
                .checked_mul(eval_nat_token(factor, env))
                .expect("Nat product overflow");
        }
        prod
    }

    pub fn parse_def_string(src: &str, def_name: &str) -> String {
        let rhs = parse_def_rhs(src, def_name);
        let trimmed = rhs.trim();
        let inner = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or_else(|| panic!("Expected string literal for `{def_name}`, got `{rhs}`"));
        inner.to_string()
    }

    pub fn parse_def_string_list(src: &str, def_name: &str) -> Vec<String> {
        let rhs = parse_def_rhs(src, def_name);
        let mut items = Vec::new();
        let bytes = rhs.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                items.push(rhs[start..i].to_string());
                i += 1;
            } else {
                i += 1;
            }
        }
        items
    }

    pub fn has_theorem(src: &str, theorem_name: &str) -> bool {
        let cleaned = strip_lean_comments(src, false);
        cleaned.lines().any(|line| {
            let trimmed = line.trim();
            let mut toks = trimmed.split_whitespace();
            match (toks.next(), toks.next(), toks.next()) {
                (Some("theorem"), Some(name), _) => name.trim_end_matches(':') == theorem_name,
                (Some("private" | "protected"), Some("theorem"), Some(name)) => {
                    name.trim_end_matches(':') == theorem_name
                }
                _ => false,
            }
        })
    }

    pub fn parse_role_trust_tier_map(src: &str) -> BTreeMap<String, String> {
        let cleaned = strip_lean_comments(src, false);
        let mut in_fn = false;
        let mut map = BTreeMap::new();
        for line in cleaned.lines() {
            let trimmed = line.trim();
            if !in_fn {
                if trimmed.starts_with("def roleTrustTier") {
                    in_fn = true;
                }
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with("theorem ") || trimmed.starts_with("def ")
            {
                break;
            }
            if let Some(after_bar) = trimmed.strip_prefix('|') {
                if let Some((lhs, rhs)) = after_bar.split_once("=>") {
                    let role_name = lhs.trim().trim_start_matches('.').to_string();
                    let tier_name = rhs.trim().trim_start_matches('.').to_string();
                    map.insert(role_name, tier_name);
                }
            }
        }
        map
    }
}

fn collect_lean_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir formal/") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.file_name().and_then(|s| s.to_str()) == Some(".lake") {
            continue;
        }
        if path.is_dir() {
            collect_lean_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("lean") {
            out.push(path);
        }
    }
}

fn check_lean_source_clean(rel_path: &str, content: &str) -> Result<(), String> {
    let tokens = lean_parser::tokenize_lean_code(content)
        .map_err(|e| format!("Lean lexical error in {rel_path}: {e}"))?;

    const FORBIDDEN_UNCONDITIONAL: &[&str] = &[
        "sorry",
        "sorryAx",
        "admit",
        "axiom",
        "opaque",
        "partial",
        "unsafe",
        "native_decide",
        "ofReduceBool",
        "trustCompiler",
        "syntax",
        "macro",
        "macro_rules",
        "elab",
        "elab_rules",
        "declare_syntax_cat",
        "interpolatedStr",
        "addDecl",
        "liftCoreM",
        "setImplementedBy",
        "CoreM",
        "MetaM",
        "TermElabM",
        "CommandElabM",
        "TacticM",
        "initialize",
        "builtin_initialize",
        "run_cmd",
        "run_tac",
        "run_elab",
        "by_elab",
        "Lean",
        "byAsSorry",
        "proofAsSorry",
        "terminalTacticsAsSorry",
        "idbg",
        "doIdbg",
        "modifyEnv",
    ];
    const FORBIDDEN_HASH_CMDS: &[&str] = &["eval", "reduce", "run_cmd", "run_elab"];

    for (idx, tok) in tokens.iter().enumerate() {
        match &tok.kind {
            lean_parser::LeanTokenKind::Ident(w)
            | lean_parser::LeanTokenKind::GuillemetIdent(w) => {
                if FORBIDDEN_UNCONDITIONAL.contains(&w.as_str()) {
                    return Err(format!(
                        "Forbidden `{w}` token found in {rel_path}:{}",
                        tok.line
                    ));
                }
                if matches!(&tok.kind, lean_parser::LeanTokenKind::Ident(id) if id == "import") {
                    let mut k = idx + 1;
                    if let Some(
                        lean_parser::LeanTokenKind::Ident(first)
                        | lean_parser::LeanTokenKind::GuillemetIdent(first),
                    ) = tokens.get(k).map(|t| &t.kind)
                    {
                        let mut parts = vec![first.clone()];
                        k += 1;
                        while k + 1 < tokens.len()
                            && matches!(tokens[k].kind, lean_parser::LeanTokenKind::Punct('.'))
                        {
                            if let lean_parser::LeanTokenKind::Ident(seg)
                            | lean_parser::LeanTokenKind::GuillemetIdent(seg) =
                                &tokens[k + 1].kind
                            {
                                parts.push(seg.clone());
                                k += 2;
                            } else {
                                break;
                            }
                        }
                        if parts[0] != "AgentOctopusFormal" {
                            return Err(format!(
                                "Forbidden external import `{}` found in {rel_path}:{}",
                                parts.join("."),
                                tok.line
                            ));
                        }
                    } else {
                        return Err(format!(
                            "Malformed `import` statement found in {rel_path}:{}",
                            tok.line
                        ));
                    }
                }
            }
            lean_parser::LeanTokenKind::Punct('#') => {
                if let Some(
                    lean_parser::LeanTokenKind::Ident(cmd)
                    | lean_parser::LeanTokenKind::GuillemetIdent(cmd),
                ) = tokens.get(idx + 1).map(|t| &t.kind)
                {
                    if FORBIDDEN_HASH_CMDS.contains(&cmd.as_str()) {
                        return Err(format!(
                            "Forbidden hash command `#{cmd}` found in {rel_path}:{}",
                            tok.line
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    // Scan all balanced `@[...]` and `(local|scoped)? attribute [...]` blocks.
    let mut i = 0;
    while i < tokens.len() {
        let attr_body_start = match &tokens[i].kind {
            lean_parser::LeanTokenKind::AtLBracket => Some(i + 1),
            lean_parser::LeanTokenKind::Ident(w) if w == "attribute" => {
                if matches!(
                    tokens.get(i + 1).map(|t| &t.kind),
                    Some(lean_parser::LeanTokenKind::Punct('['))
                ) {
                    Some(i + 2)
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(mut j) = attr_body_start {
            let mut depth: usize = 1;
            while j < tokens.len() && depth > 0 {
                match &tokens[j].kind {
                    lean_parser::LeanTokenKind::AtLBracket
                    | lean_parser::LeanTokenKind::Punct('[') => depth += 1,
                    lean_parser::LeanTokenKind::Punct(']') => depth -= 1,
                    lean_parser::LeanTokenKind::Ident(w)
                    | lean_parser::LeanTokenKind::GuillemetIdent(w) => {
                        if w == "extern" || w == "implemented_by" {
                            return Err(format!(
                                "Forbidden FFI/override attribute `{w}` found in {rel_path}:{}",
                                tokens[j].line
                            ));
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if depth > 0 {
                return Err(format!(
                    "Unclosed attribute `[...]` block in {rel_path}:{}",
                    tokens[i].line
                ));
            }
            i = j;
        } else {
            i += 1;
        }
    }

    Ok(())
}

fn assert_lean_module_soundness_clean(rel_path: &str, content: &str) -> Result<(), String> {
    check_lean_source_clean(rel_path, content)
}

#[test]
fn test_m1_lean_toolchain_manifest_and_zero_sorry_zero_axiom() {
    let toolchain = lean_parser::read_formal_file("lean-toolchain");
    assert_eq!(toolchain.trim(), "leanprover/lean4:v4.36.0");

    let lakefile = lean_parser::read_formal_file("lakefile.toml");
    assert!(lakefile.contains("name = \"AgentOctopusFormal\""));
    assert!(lakefile.contains("autoImplicit = false"));
    assert!(
        !lakefile.contains("[[require]]"),
        "formal/lakefile.toml must remain zero-dependency"
    );

    let root_lib = lean_parser::read_formal_file("AgentOctopusFormal.lean");
    let root_tokens = lean_parser::tokenize_lean_code(&root_lib)
        .expect("AgentOctopusFormal.lean must tokenize cleanly");
    let mut imported_mods: BTreeSet<String> = BTreeSet::new();
    let mut k = 0;
    while k < root_tokens.len() {
        if matches!(&root_tokens[k].kind, lean_parser::LeanTokenKind::Ident(w) if w == "import") {
            k += 1;
            if let Some(
                lean_parser::LeanTokenKind::Ident(first)
                | lean_parser::LeanTokenKind::GuillemetIdent(first),
            ) = root_tokens.get(k).map(|t| &t.kind)
            {
                let mut parts = vec![first.clone()];
                k += 1;
                while k + 1 < root_tokens.len()
                    && matches!(root_tokens[k].kind, lean_parser::LeanTokenKind::Punct('.'))
                {
                    if let lean_parser::LeanTokenKind::Ident(seg)
                    | lean_parser::LeanTokenKind::GuillemetIdent(seg) = &root_tokens[k + 1].kind
                    {
                        parts.push(seg.clone());
                        k += 2;
                    } else {
                        break;
                    }
                }
                imported_mods.insert(parts.join("."));
            }
        } else {
            k += 1;
        }
    }

    let formal_dir = lean_parser::formal_root();
    let pkg_dir = formal_dir.join("AgentOctopusFormal");
    let mut pkg_files = Vec::new();
    collect_lean_files(&pkg_dir, &mut pkg_files);
    let mut expected_mods: BTreeSet<String> = BTreeSet::new();
    for p in &pkg_files {
        let rel = p
            .strip_prefix(&formal_dir)
            .expect("path inside formal_dir")
            .with_extension("");
        let mod_name = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect::<Vec<_>>()
            .join(".");
        if mod_name == "AgentOctopusFormal.AxiomAudit" {
            continue;
        }
        expected_mods.insert(mod_name);
    }

    assert_eq!(
        imported_mods, expected_mods,
        "AgentOctopusFormal.lean imports must match all AgentOctopusFormal/*.lean modules (except AxiomAudit)"
    );

    let extra_root_lean: Vec<String> = fs::read_dir(&formal_dir)
        .expect("read_dir formal/")
        .filter_map(|e| e.ok().map(|ent| ent.path()))
        .filter(|p| {
            p.is_file()
                && p.extension().and_then(|s| s.to_str()) == Some("lean")
                && p.file_name().and_then(|s| s.to_str()) != Some("AgentOctopusFormal.lean")
        })
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        extra_root_lean.is_empty(),
        "Unexpected top-level .lean files under formal/: {extra_root_lean:?}"
    );

    let expected_submodules = [
        "CoreTypes",
        "FsmContainment",
        "HomologicalMesh",
        "EpochAutotomy",
        "CageNoDirectBind",
        "CedarAndTemporal",
        "MandateAndQuorum",
        "IsolationAndPerimeter",
        "NoBreachNoBreakout",
    ];
    for sub in expected_submodules {
        assert!(
            imported_mods.contains(&format!("AgentOctopusFormal.{sub}")),
            "AgentOctopusFormal.lean missing lexed import for {sub}"
        );
    }

    let axiom_audit = lean_parser::read_module("AxiomAudit");
    assert!(axiom_audit.contains("import AgentOctopusFormal.NoBreachNoBreakout"));
    assert!(axiom_audit.contains("#print axioms AgentOctopusFormal.no_breakout"));
    assert!(axiom_audit.contains("#print axioms AgentOctopusFormal.no_breach"));

    let mut lean_files = Vec::new();
    collect_lean_files(&formal_dir, &mut lean_files);
    assert_eq!(
        lean_files.len(),
        11,
        "Expected AgentOctopusFormal.lean + 10 submodules"
    );

    for path in &lean_files {
        let raw = fs::read_to_string(path).expect("read lean file");
        let rel = path.display().to_string();
        assert_lean_module_soundness_clean(&rel, &raw)
            .unwrap_or_else(|err| panic!("Lean soundness scan failed: {err}"));
    }
}

#[test]
fn test_m1_soundness_scanner_rejects_escape_patterns() {
    let escape_snippets = [
        ("sorry", "theorem evil : False := by sorry"),
        ("sorryAx", "theorem evil : False := sorryAx"),
        ("axiom_plain", "axiom cheat : False"),
        ("private_two_spaces_axiom", "private  axiom cheat : False"),
        ("axiom_tab", "axiom\tcheat : False"),
        ("protected_axiom", "protected axiom cheat : False"),
        ("noncomputable_axiom", "noncomputable axiom cheat : False"),
        ("scoped_axiom", "scoped axiom cheat : False"),
        ("local_axiom", "local axiom cheat : False"),
        ("unsafe_axiom", "unsafe axiom cheat : False"),
        ("unsafe_def", "unsafe def cheat : Nat := 0"),
        ("semicolon_axiom", "def ok : Nat := 1; axiom cheat : False"),
        ("attr_axiom", "@[simp] private  axiom cheat : False"),
        ("nospace_attr_axiom", "@[simp]axiom cheat : False"),
        (
            "nospace_attr_private_axiom",
            "@[simp]private axiom cheat : False",
        ),
        ("multiline_attr_axiom", "@[\n  simp\n] axiom cheat : False"),
        ("multiline_attr_opaque", "@[\n  simp\n] opaque bad : Nat"),
        (
            "same_line_no_semi_axiom",
            "def ok : Nat := 1 axiom cheat : False",
        ),
        (
            "num_adjacent_axiom",
            "def ok : Nat := 123axiom cheat : False",
        ),
        ("admit_tactic", "theorem evil : False := by admit"),
        ("native_decide", "theorem evil : True := by native_decide"),
        ("ofReduceBool", "def b : Bool := ofReduceBool true"),
        ("trustCompiler", "def c : Bool := trustCompiler true"),
        ("extern_attr", "@[extern \"c_fn\"] def f : Nat := 0"),
        (
            "implemented_by_attr",
            "@[implemented_by evil_impl] def f : Nat := 0",
        ),
        (
            "attribute_cmd_extern",
            "def f : Nat := 0\nattribute [extern \"c\"] f",
        ),
        (
            "attribute_cmd_impl",
            "def g : Nat := 0\ndef f : Nat := 0\nattribute [implemented_by g] f",
        ),
        (
            "local_attribute_extern",
            "def f : Nat := 0\nlocal attribute [extern \"c\"] f",
        ),
        (
            "scoped_attribute_impl",
            "def g : Nat := 0\ndef f : Nat := 0\nscoped attribute [implemented_by g] f",
        ),
        (
            "nested_bracket_attr_extern",
            "@[foo [bar], extern \"c\"] def f : Nat := 0",
        ),
        (
            "nested_bracket_attr_impl",
            "@[foo [bar], implemented_by g] def f : Nat := 0",
        ),
        (
            "interp_str_admit",
            "def s : String := s!\"{(by admit : Nat)}\"",
        ),
        (
            "interp_str_sorry",
            "def s : String := s!\"{(by sorry : Nat)}\"",
        ),
        ("interp_m_admit", "def s : String := m!\"{by admit}\""),
        (
            "interp_bang_sorry",
            "def s : String := !\"{(by sorry : Nat)}\"",
        ),
        (
            "interp_record_sorry",
            "def s : String := s!\"a {({ a := \"ok\", b := by sorry }).b}\"",
        ),
        ("guillemet_axiom", "axiom «cheat» : False"),
        ("guillemet_sorryAx", "def x : False := «sorryAx»"),
        (
            "guillemet_attr_extern",
            "def f : Nat := 0\nattribute [«extern» \"c\"] f",
        ),
        ("opaque_decl", "opaque bad : Nat"),
        ("private_opaque", "private  opaque bad : Nat"),
        (
            "block_comment_smuggle",
            "theorem sneaky : False := by/-c-/admit",
        ),
        ("char_literal_single_quote", "def c := '\\''; sorry"),
        ("char_literal_double_quote", "def c := '\"'; sorry"),
        (
            "escaped_string_quote",
            "def s := \"hello \\\"world\\\"\"; sorry",
        ),
        (
            "raw_str_1hash_swallow_axiom",
            "def decoy : String := r#\"not a real \" quote\"# axiom cheat : False",
        ),
        (
            "raw_str_paired_swallow_axiom",
            "def s1 : String := r#\"hello \"world\"#\naxiom cheat : False\ndef s2 : String := r#\"foo \"bar\"#",
        ),
        (
            "raw_str_2hash_sorry",
            "def decoy : String := r##\"foo \"# bar\"## sorry",
        ),
        (
            "raw_str_0hash_swallow_axiom",
            "def s1 : String := r\"hello\\\"\naxiom cheat : False\ndef s2 : String := r\"foo\\\"\"",
        ),
        ("raw_str_unclosed", "def bad : String := r#\"unclosed"),
        (
            "raw_str_unclosed_2hash",
            "def bad : String := r##\"almost\"# still open",
        ),
        (
            "interp_space_s_bang_sorry",
            "def s : String := s! \"{(by sorry : Nat)}\"",
        ),
        (
            "interp_newline_s_bang_sorry",
            "def s : String := s!\n\"{(by sorry : Nat)}\"",
        ),
        (
            "interp_comment_s_bang_admit",
            "def s : String := s! /-c-/ \"{(by admit : Nat)}\"",
        ),
        (
            "interp_line_comment_s_bang_sorry",
            "def s : String := s! -- c\n \"{(by sorry : Nat)}\"",
        ),
        (
            "interp_space_m_bang_sorry",
            "def m := m! \"{(by sorry : Nat)}\"",
        ),
        (
            "interp_space_f_bang_sorry",
            "def f := f! \"{(by sorry : Nat)}\"",
        ),
        (
            "partial_def",
            "partial def loop (n : Nat) : Nat := loop n",
        ),
        (
            "interp_space_q_bang_sorry",
            "def bad : String := q! \"{(by sorry : Nat)}\"",
        ),
        (
            "custom_syntax_q_bang_space_sorry",
            "import Lean\nsyntax \"q!\" interpolatedStr(term) : term\nmacro_rules | `(q! $s) => `(s! $s)\ndef bad : String := q! \"{(by sorry : Nat)}\"",
        ),
        (
            "interp_space_foo_q_bang_sorry",
            "def bad : String := Foo.q! \"{(by sorry : Nat)}\"",
        ),
        (
            "interp_space_foo_panic_bang_sorry",
            "def bad : String := Foo.panic! \"{(by sorry : Nat)}\"",
        ),
        (
            "interp_space_println_bang_sorry",
            "def bad : IO Unit := println! \"{(by sorry : Nat)}\"",
        ),
        (
            "interp_dbg_trace_sorry",
            "def bad : Nat := dbg_trace \"{(by sorry : Nat)}\"; 0",
        ),
        (
            "custom_syntax_q_pct_no_bang_sorry",
            "syntax \"q%\" interpolatedStr(term) : term\nmacro_rules | `(q% $s) => `(s! $s)\ndef bad : String := q% \"{(by sorry : Nat)}\"",
        ),
        (
            "custom_syntax_interp_word_no_bang_sorry",
            "syntax \"interp\" interpolatedStr(term) : term\nmacro_rules | `(interp $s) => `(s! $s)\ndef bad : String := interp \"{(by sorry : Nat)}\"",
        ),
        (
            "elab_token_pasting_sorry_ax",
            "elab \"sneaky\" : term => do let n := Lean.mkIdent (Lean.Name.mkSimple (\"sor\" ++ \"ryAx\")); pure n",
        ),
        (
            "elab_add_axiom_corem",
            "elab \"inject_ax\" : command => do Lean.Elab.Command.liftCoreM do Lean.addDecl (.axiomDecl { name := `evilAx, levelParams := [], type := .const `False [], isUnsafe := false })",
        ),
        (
            "eval_lift_corem_add_decl",
            "#eval show CommandElabM Unit from liftCoreM (addDecl (.axiomDecl { name := `evilAx, levelParams := [], type := .const `False [], isUnsafe := false }))",
        ),
        ("hash_eval_cmd", "#eval (1 + 1)"),
        ("hash_reduce_cmd", "#reduce (1 + 1)"),
        ("hash_run_cmd", "#run_cmd pure ()"),
        ("hash_run_elab", "#run_elab pure ()"),
        ("import_lean", "import Lean\ndef ok : Nat := 1"),
        ("import_std", "import Std\ndef ok : Nat := 1"),
        ("import_init", "import Init.Data.Nat\ndef ok : Nat := 1"),
        ("macro_sneaky", "macro \"sneaky\" : term => `(1)\ndef ok : Nat := 1"),
        ("syntax_decl", "syntax \"my_syn\" : term\ndef ok : Nat := 1"),
        (
            "declare_syntax_cat_decl",
            "declare_syntax_cat my_cat\ndef ok : Nat := 1",
        ),
        ("initialize_decl", "initialize x : IO.Ref Nat <- IO.mkRef 0"),
        ("set_implemented_by_direct", "def f := setImplementedBy"),
        (
            "by_as_sorry_option",
            "set_option byAsSorry true\ntheorem ok : True := by trivial",
        ),
        (
            "proof_as_sorry_option",
            "set_option proofAsSorry true\ntheorem ok : True := trivial",
        ),
        ("idbg_escape", "def sneaky : Nat := idbg 0"),
        ("modify_env_escape", "def sneaky := modifyEnv"),
    ];
    for (label, snippet) in escape_snippets {
        let res = check_lean_source_clean(label, snippet);
        assert!(
            res.is_err(),
            "Expected soundness scanner to reject `{label}` snippet: {snippet}"
        );
    }

    let clean_snippets = [
        (
            "line_comment",
            "-- sorry axiom cheat : False admit native_decide @[extern \"c\"] opaque bad\ndef ok : Nat := 1",
        ),
        (
            "nested_block_comment",
            "/- outer /- sorry axiom cheat : False -/ admit -/\ndef ok : Nat := 2",
        ),
        (
            "string_and_char_literals",
            "def msg : String := \"sorry axiom admit native_decide @[extern \\\"c\\\"] opaque\"\ndef q1 : Char := '\\''\ndef q2 : Char := '\"'\ndef axiom_free : Nat := 0\n#print axioms ok",
        ),
        ("primed_ident", "def x' (h' : Nat) : Nat := h'"),
        (
            "interp_benign_escaped_and_expr",
            "def s : String := s!\"hello {1 + 2} \\\"admit\\\" \\{- sorry -}\"",
        ),
        (
            "interp_escaped_brace",
            "def s : String := s!\"escaped \\{by sorry}\"",
        ),
        (
            "interp_record_string_literal",
            "def s : String := s!\"{({ a := \"admit\", b := 1 }).b}\"",
        ),
        (
            "interp_cage_label_like",
            "def tag (i : Nat) : String := s!\"direct_tier_{i}\"",
        ),
        (
            "raw_str_benign_keywords",
            "def ok := r#\"axiom sorry \"# ++ r##\"admit \"# opaque\"##",
        ),
        (
            "raw_str_0hash_benign",
            "def ok := r\"axiom sorry \\\" ++ r\"admit\"",
        ),
        (
            "interp_space_benign",
            "def s (ok : Nat) : String := s! \"benign {ok}\"",
        ),
        (
            "interp_comment_newline_benign",
            "def s (x : Nat) : String := s! /-c-/\n\"benign {x}\"",
        ),
        (
            "raw_str_inside_interp_benign",
            "def s : String := s! \"ok {r#\"axiom \" sorry\"#}\"",
        ),
        (
            "ident_ending_in_r_before_string",
            "def bar (s : String) : String := s\ndef ok := bar\"hello\"",
        ),
        (
            "panic_bang_sorry_literal",
            "def p : Nat := panic! \"sorry\"",
        ),
        (
            "panic_bang_braces_plain_string",
            "def p : Nat := panic! \"hello {by sorry}\"",
        ),
        (
            "dbg_trace_plain_literal",
            "def p : Nat := dbg_trace \"sorry\"; 0",
        ),
        (
            "dbg_trace_benign_interp",
            "def p (ok : Nat) : Nat := dbg_trace \"val {ok}\"; 0",
        ),
        (
            "inductive_prefix_ctor",
            "inductive PathComponent where | prefix (d : String)",
        ),
        (
            "import_agent_octopus_formal",
            "import AgentOctopusFormal.CoreTypes\n#print axioms ok",
        ),
    ];
    for (label, snippet) in clean_snippets {
        check_lean_source_clean(label, snippet)
            .unwrap_or_else(|err| panic!("Expected clean snippet `{label}` to pass, got: {err}"));
    }
}

#[test]
fn test_f2_core_types_arm_role_and_trust_tier_parity() {
    let core_src = lean_parser::read_module("CoreTypes");
    let lean_roles = lean_parser::parse_inductive_constructors(&core_src, "ArmRole");
    assert_eq!(lean_roles.len(), 18);

    let rust_all_roles = [
        ArmRole::UntrustedDocIngest,
        ArmRole::AccountingLedgerWrite,
        ArmRole::OutboundNotification,
        ArmRole::NetworkEgress,
        ArmRole::TarpitDecoyDefense,
        ArmRole::KernelLevelSentinel,
        ArmRole::CedarPolicyEvaluation,
        ArmRole::AtlasThreatIntelligence,
        ArmRole::AnomalyDetection,
        ArmRole::VulnerabilityResearch,
        ArmRole::ContinuousOssFuzz,
        ArmRole::ContinuousOsvScanner,
        ArmRole::DifferentialProtocolAnalyzer,
        ArmRole::AutonomousProtocolResearch,
        ArmRole::PostQuantumAttestation,
        ArmRole::EvolutionaryOptimizer,
        ArmRole::DreamRsiOptimizer,
        ArmRole::RecursiveHarnessOptimizer,
    ];
    let rust_role_names: Vec<String> = rust_all_roles
        .iter()
        .map(|r| match r {
            ArmRole::UntrustedDocIngest => "UntrustedDocIngest",
            ArmRole::AccountingLedgerWrite => "AccountingLedgerWrite",
            ArmRole::OutboundNotification => "OutboundNotification",
            ArmRole::NetworkEgress => "NetworkEgress",
            ArmRole::TarpitDecoyDefense => "TarpitDecoyDefense",
            ArmRole::KernelLevelSentinel => "KernelLevelSentinel",
            ArmRole::CedarPolicyEvaluation => "CedarPolicyEvaluation",
            ArmRole::AtlasThreatIntelligence => "AtlasThreatIntelligence",
            ArmRole::AnomalyDetection => "AnomalyDetection",
            ArmRole::VulnerabilityResearch => "VulnerabilityResearch",
            ArmRole::ContinuousOssFuzz => "ContinuousOssFuzz",
            ArmRole::ContinuousOsvScanner => "ContinuousOsvScanner",
            ArmRole::DifferentialProtocolAnalyzer => "DifferentialProtocolAnalyzer",
            ArmRole::AutonomousProtocolResearch => "AutonomousProtocolResearch",
            ArmRole::PostQuantumAttestation => "PostQuantumAttestation",
            ArmRole::EvolutionaryOptimizer => "EvolutionaryOptimizer",
            ArmRole::DreamRsiOptimizer => "DreamRsiOptimizer",
            ArmRole::RecursiveHarnessOptimizer => "RecursiveHarnessOptimizer",
        })
        .map(str::to_string)
        .collect();
    assert_eq!(lean_roles, rust_role_names);

    let lean_tiers = lean_parser::parse_inductive_constructors(&core_src, "TrustTier");
    assert_eq!(lean_tiers, vec!["Untrusted", "Worker", "PrivilegedSink"]);
    assert_eq!(TrustTier::Untrusted.potential(), 10);
    assert_eq!(TrustTier::Worker.potential(), 50);
    assert_eq!(TrustTier::PrivilegedSink.potential(), 100);
    assert!(core_src.contains("| .Untrusted => 10"));
    assert!(core_src.contains("| .Worker => 50"));
    assert!(core_src.contains("| .PrivilegedSink => 100"));

    let lean_role_tier_map = lean_parser::parse_role_trust_tier_map(&core_src);
    assert_eq!(lean_role_tier_map.len(), 18);
    assert!(lean_parser::has_theorem(&core_src, "roleTrustTier_total"));

    for (role, role_name) in rust_all_roles.iter().zip(rust_role_names.iter()) {
        let rust_tier_name = match role_trust_tier(role) {
            TrustTier::Untrusted => "Untrusted",
            TrustTier::Worker => "Worker",
            TrustTier::PrivilegedSink => "PrivilegedSink",
        };
        let lean_tier_name = lean_role_tier_map
            .get(role_name)
            .unwrap_or_else(|| panic!("Missing roleTrustTier entry for {role_name}"));
        assert_eq!(
            rust_tier_name, lean_tier_name,
            "TrustTier drift for ArmRole::{role_name}"
        );
    }
}

#[test]
fn test_f3_fsm_containment_and_policy_guard_parity() {
    let fsm_src = lean_parser::read_module("FsmContainment");
    let lean_states = lean_parser::parse_inductive_constructors(&fsm_src, "ArmState");
    let expected_states = [
        ArmState::Created,
        ArmState::DirectiveAccepted,
        ArmState::EnclaveDigesting,
        ArmState::MerkleSealed,
        ArmState::Completed,
        ArmState::Quarantined,
    ];
    let rust_state_names: Vec<String> = expected_states
        .iter()
        .map(|s| match s {
            ArmState::Created => "Created",
            ArmState::DirectiveAccepted => "DirectiveAccepted",
            ArmState::EnclaveDigesting => "EnclaveDigesting",
            ArmState::MerkleSealed => "MerkleSealed",
            ArmState::Completed => "Completed",
            ArmState::Quarantined => "Quarantined",
        })
        .map(str::to_string)
        .collect();
    assert_eq!(lean_states, rust_state_names);
    assert!(lean_parser::has_theorem(
        &fsm_src,
        "fsm_no_skip_to_completed"
    ));
    assert!(lean_parser::has_theorem(
        &fsm_src,
        "quarantined_is_absorbing"
    ));
    assert!(lean_parser::has_theorem(
        &fsm_src,
        "policy_guard_caps_enforced"
    ));

    let env = HashMap::new();
    let lean_max_amount = lean_parser::parse_def_nat(&fsm_src, "DEFAULT_MAX_AMOUNT_CENTS", &env);
    let lean_max_steps = lean_parser::parse_def_nat(&fsm_src, "DEFAULT_MAX_STEPS_PERMITTED", &env);
    let lean_currency = lean_parser::parse_def_string(&fsm_src, "DEFAULT_REQUIRED_CURRENCY");
    let lean_merkle_len = lean_parser::parse_def_nat(&fsm_src, "MERKLE_ROOT_LEN", &env);
    let lean_prefixes =
        lean_parser::parse_def_string_list(&fsm_src, "DEFAULT_ALLOWED_SOURCE_PREFIXES");

    let pg = PolicyGuard::default();
    assert_eq!(pg.max_amount_cents, lean_max_amount);
    assert_eq!(pg.max_steps_permitted as u64, lean_max_steps);
    assert_eq!(pg.required_currency, lean_currency);
    assert_eq!(lean_merkle_len, 64);
    assert_eq!(pg.allowed_source_prefixes, lean_prefixes);

    // Negative boundary 1: skipping directly from Created -> Completed must fail
    let mut fsm = FsmTransitionGuard::new();
    assert!(fsm.transition_to(ArmState::Completed).is_err());

    // Negative boundary 2: Quarantined is strictly absorbing
    assert!(fsm.transition_to(ArmState::Quarantined).is_ok());
    assert!(fsm.transition_to(ArmState::Completed).is_err());
    assert!(fsm.transition_to(ArmState::DirectiveAccepted).is_err());

    // Positive & Negative boundary 3: $100k exact cap (10_000_000 ok, 10_000_001 rejected)
    let mut layer = DeterministicLayer::new();
    let valid_dir = StrategicDirective {
        directive_id: "dir-coupling-1".to_string(),
        source_uri: "s3://invoices/2026/inv-01.pdf".to_string(),
        instruction: "Extract verified invoice totals".to_string(),
        raw_payload: None,
        max_step_budget: 5,
    };
    assert!(layer.accept_directive(&valid_dir).is_ok());
    assert!(layer.enter_enclave_digest().is_ok());
    let merkle_root = "a".repeat(64);
    assert!(layer.seal_merkle_trace(&merkle_root).is_ok());

    let over_cap = VerifiedInvoiceArtifact {
        invoice_id: "INV-OVER-CAP".to_string(),
        vendor_name: "Acme Corp".to_string(),
        amount_cents: 10_000_001,
        currency: "USD".to_string(),
        line_item_count: 1,
        sanitization_digest: "b".repeat(64),
        merkle_root: merkle_root.clone(),
        execution_step_count: 1,
    };
    assert!(pg.enforce_artifact(&over_cap).is_err());
    assert!(layer.finalize_artifact(&over_cap).is_err());

    let exact_cap = VerifiedInvoiceArtifact {
        amount_cents: 10_000_000,
        ..over_cap
    };
    assert!(pg.enforce_artifact(&exact_cap).is_ok());
    assert!(layer.finalize_artifact(&exact_cap).is_ok());
    assert_eq!(layer.state(), ArmState::Completed);
}

#[tokio::test]
async fn test_f4_homological_mesh_and_delegation_parity() {
    let mesh_src = lean_parser::read_module("HomologicalMesh");
    let env = HashMap::new();
    assert_eq!(
        lean_parser::parse_def_nat(&mesh_src, "MAX_RELAY_HOPS", &env) as usize,
        MAX_RELAY_HOPS
    );
    assert_eq!(
        lean_parser::parse_def_nat(&mesh_src, "MAX_DELEGATION_DEPTH", &env),
        2
    );
    assert_eq!(
        lean_parser::parse_def_nat(&mesh_src, "MAX_CORRELATION_ID_BYTES", &env) as usize,
        agent_octopus::neural_mesh::MAX_METADATA_BYTES
    );
    assert_eq!(
        lean_parser::parse_def_nat(&mesh_src, "MAX_MESH_PAYLOAD_BYTES", &env) as usize,
        agent_octopus::neural_mesh::MAX_CONTENT_BYTES
    );

    let lean_msg_kinds = lean_parser::parse_inductive_constructors(&mesh_src, "MessageKind");
    let rust_msg_kinds = [
        MessageKind::Finding,
        MessageKind::ThreatMapping,
        MessageKind::ChainCandidate,
        MessageKind::Alert,
    ];
    let rust_kind_names: Vec<String> = rust_msg_kinds
        .iter()
        .map(|k| match k {
            MessageKind::Finding => "Finding",
            MessageKind::ThreatMapping => "ThreatMapping",
            MessageKind::ChainCandidate => "ChainCandidate",
            MessageKind::Alert => "Alert",
        })
        .map(str::to_string)
        .collect();
    assert_eq!(lean_msg_kinds, rust_kind_names);
    assert!(lean_parser::has_theorem(&mesh_src, "no_proxy_laundering"));
    assert!(lean_parser::has_theorem(
        &mesh_src,
        "delegation_no_escalation"
    ));

    // Homological auditor rejects Untrusted -> Worker -> PrivilegedSink proxy laundering
    let audit = HomologicalBoundaryAuditor::audit_role_chain(&[
        ArmRole::UntrustedDocIngest,
        ArmRole::NetworkEgress,
        ArmRole::AccountingLedgerWrite,
    ]);
    assert!(!audit.allowed);
    assert!(audit.proxy_laundering_detected);

    // AutonomousProtocolResearch has empty delegation tool scope
    assert!(
        DelegationScopeGuard::permitted_tools_for_role(&ArmRole::AutonomousProtocolResearch)
            .is_empty()
    );
    let del_guard = DelegationScopeGuard::default();
    assert!(del_guard
        .validate_delegation(
            &ArmRole::UntrustedDocIngest,
            &[ArmRole::NetworkEgress],
            &ArmRole::AccountingLedgerWrite,
            "ledger_writer",
        )
        .is_err());

    // ArmContainmentRing + MeshGuard fail-closed checks
    let seed = b"LEAN_COUPLING_MESH_SEED_32_BYTES";
    let sender = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, seed);
    let sink = ArmContainmentRing::new(2, ArmRole::AccountingLedgerWrite, 1, seed);
    let msg_to_sink = sender
        .sign_mesh_message(2, 1, MessageKind::Finding, "corr-1", "payload")
        .await
        .expect("sign_mesh_message");
    assert!(sink.verify_incoming_message(&msg_to_sink).await.is_err());

    let worker_sender = ArmContainmentRing::new(3, ArmRole::NetworkEgress, 1, seed);
    let worker_recv = ArmContainmentRing::new(4, ArmRole::OutboundNotification, 1, seed);
    let msg_worker = worker_sender
        .sign_mesh_message(4, 1, MessageKind::Finding, "corr-2", "ok")
        .await
        .expect("sign worker msg");
    let verified = worker_recv
        .verify_incoming_message(&msg_worker)
        .await
        .expect("verified worker msg");

    let mesh_guard = MeshGuard::default();
    assert!(
        mesh_guard.validate_message(&verified).await.is_err(),
        "Empty MeshGuard route table must fail closed"
    );
    mesh_guard
        .allow_route(3, 4, Some(MessageKind::Finding))
        .await;
    assert!(mesh_guard.validate_message(&verified).await.is_ok());
}

#[tokio::test]
async fn test_f5_epoch_autotomy_dirac_and_three_layer_gate_parity() {
    let epoch_src = lean_parser::read_module("EpochAutotomy");
    let env = HashMap::new();
    let lean_dirac_max = lean_parser::parse_def_nat(&epoch_src, "DIRAC_MAX_WINDOW_US", &env);
    assert_eq!(lean_dirac_max, 5_000_000);
    for thm in [
        "epoch_strictly_monotonic",
        "revoked_epoch_never_valid",
        "dirac_single_use_no_replay",
        "three_layer_non_circular_gate",
    ] {
        assert!(
            lean_parser::has_theorem(&epoch_src, thm),
            "EpochAutotomy missing theorem {thm}"
        );
    }

    // EpochRegistry parity: arm 17 starts at gen 8, others at gen 1; monotonic advance
    let registry = EpochRegistry::new(20);
    assert!(registry.is_generation_active(17, 8).await.is_ok());
    assert!(registry.is_generation_active(1, 1).await.is_ok());
    let next_gen = registry
        .advance_generation(17)
        .await
        .expect("advance_generation");
    assert_eq!(next_gen, 9);
    assert!(registry.is_generation_active(17, 8).await.is_err());
    assert!(registry.is_generation_active(17, 9).await.is_ok());

    let ring = ArmContainmentRing::new(17, ArmRole::NetworkEgress, 8, b"SEED_32_BYTES_FOR_RING_17");
    let regen = ring.sever_and_regenerate().await;
    assert_eq!(regen, 9);
    assert!(ring.validate_epoch(8).await.is_err());
    assert!(ring.validate_epoch(9).await.is_ok());

    // Law 3 DiracDeltaCapabilityTicket clamping & single-use replay rejection
    let key = [0x42u8; 32];
    let mut ticket = DiracDeltaCapabilityTicket::issue(
        "arm-17",
        9,
        "http_egress",
        "https://www.google.com/",
        9_999_999,
        &key,
        None,
    );
    assert_eq!(ticket.window_us, lean_dirac_max);
    assert!(ticket
        .consume_once("http_egress", "https://www.google.com/", 9, &key, None)
        .is_ok());
    assert!(ticket
        .consume_once("http_egress", "https://www.google.com/", 9, &key, None)
        .is_err());

    // 3-layer orthogonal non-circular trust boundary verifier
    let verifier = IndependentTrustBoundaryVerifier::new(&key);
    let l1 = verifier.compute_layer1_token("arm-17", 1);
    let l2 = verifier.compute_layer2_token(&"c".repeat(64), 1);
    let l3 = verifier.compute_layer3_token("job-17", 1);

    let denied = verifier.evaluate_three_layer_gate(
        "arm-17",
        &"c".repeat(64),
        "job-17",
        &l1,
        &l2,
        &l3,
        false,
    );
    assert!(!denied.allowed);

    let allowed = verifier.evaluate_three_layer_gate(
        "arm-17",
        &"c".repeat(64),
        "job-17",
        &l1,
        &l2,
        &l3,
        true,
    );
    assert!(allowed.allowed);
}

#[test]
fn test_f6_cage_no_direct_bind_routing_seal_and_cbf_parity() {
    let cage_src = lean_parser::read_module("CageNoDirectBind");
    let env = HashMap::new();

    assert_eq!(
        lean_parser::parse_def_nat(&cage_src, "ROUTING_SEAL_TTL_SECS", &env),
        ROUTING_SEAL_TTL_SECS
    );
    assert_eq!(
        lean_parser::parse_def_nat(&cage_src, "CLOCK_DRIFT_TOLERANCE_SECS", &env),
        CLOCK_DRIFT_TOLERANCE_SECS
    );
    let gated_expected =
        lean_parser::parse_def_nat(&cage_src, "GATED_REACHABLE_COUNT", &env) as usize;
    let ungated_expected =
        lean_parser::parse_def_nat(&cage_src, "UNGATED_REACHABLE_COUNT", &env) as usize;
    let skipped_expected =
        lean_parser::parse_def_nat(&cage_src, "SKIPPED_TIER_REACHABLE_COUNT", &env) as usize;
    let allow_bps = lean_parser::parse_def_nat(&cage_src, "SR_26_2_ALLOW_BPS", &env);
    let approval_bps = lean_parser::parse_def_nat(&cage_src, "SR_26_2_APPROVAL_BPS", &env);
    let cbf_scale = lean_parser::parse_def_nat(&cage_src, "CBF_SCALE", &env);

    assert!((SR_26_2_CONFIDENCE_ALLOW_THRESHOLD - (allow_bps as f64 / 10_000.0)).abs() < 1e-12);
    assert!(
        (SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD - (approval_bps as f64 / 10_000.0)).abs() < 1e-12
    );
    assert!((CBF_EPSILON - (1.0 / (cbf_scale as f64))).abs() < 1e-18);

    let lean_bfs_phases = lean_parser::parse_inductive_constructors(&cage_src, "BfsPhase");
    let rust_bfs = [
        BfsPhase::Initial,
        BfsPhase::Checking,
        BfsPhase::NarrowEval,
        BfsPhase::NarrowPassed,
        BfsPhase::SealIssued,
        BfsPhase::Executed,
        BfsPhase::Denied,
    ];
    let rust_bfs_names: Vec<String> = rust_bfs
        .iter()
        .map(|p| match p {
            BfsPhase::Initial => "Initial",
            BfsPhase::Checking => "Checking",
            BfsPhase::NarrowEval => "NarrowEval",
            BfsPhase::NarrowPassed => "NarrowPassed",
            BfsPhase::SealIssued => "SealIssued",
            BfsPhase::Executed => "Executed",
            BfsPhase::Denied => "Denied",
        })
        .map(str::to_string)
        .collect();
    assert_eq!(lean_bfs_phases, rust_bfs_names);

    let lean_rev = lean_parser::parse_inductive_constructors(&cage_src, "ActionReversibility");
    let rust_rev = [
        ActionReversibility::ReadOnly,
        ActionReversibility::Reversible,
        ActionReversibility::Compensatable,
        ActionReversibility::ConditionalAutonomous,
        ActionReversibility::IrreversibleTerminal,
    ];
    let rust_rev_names: Vec<String> = rust_rev
        .iter()
        .map(|r| match r {
            ActionReversibility::ReadOnly => "ReadOnly",
            ActionReversibility::Reversible => "Reversible",
            ActionReversibility::Compensatable => "Compensatable",
            ActionReversibility::ConditionalAutonomous => "ConditionalAutonomous",
            ActionReversibility::IrreversibleTerminal => "IrreversibleTerminal",
        })
        .map(str::to_string)
        .collect();
    assert_eq!(lean_rev, rust_rev_names);

    let gated = FormalBfsModel::explore_gated_model();
    assert_eq!(gated.reachable_count, gated_expected);
    assert_eq!(gated.executed_count, 1);
    assert!(gated.violations.is_empty());
    assert!(gated.is_proven());

    let ungated = FormalBfsModel::explore_ungated_counterexample();
    assert_eq!(ungated.reachable_count, ungated_expected);
    assert!(!ungated.is_proven());

    let skipped = FormalBfsModel::explore_skipped_tier_model(0);
    assert_eq!(skipped.reachable_count, skipped_expected);
    assert_eq!(skipped.executed_count, 0);

    // RoutingSealSigner single-use & replay rejection
    let signer = RoutingSealSigner::new(b"cage-seal-secret-key", "0123456789abcdef");
    let action_digest = "a".repeat(64);
    let record_hash = "b".repeat(64);
    let now = 1_700_000_000u64;
    let seal = signer
        .issue_seal(&action_digest, &record_hash, now)
        .expect("issue_seal");
    assert!(signer
        .validate_and_consume(&seal, &action_digest, &record_hash, now + 1)
        .is_ok());
    assert!(signer
        .validate_and_consume(&seal, &action_digest, &record_hash, now + 2)
        .is_err());

    // CbfSafetyEngine & DebitLedger floor-breach rejection + LIFO conservation
    let cbf = CbfSafetyEngine::new(0.5, 100.0).expect("cbf");
    assert!(cbf.evaluate_step(150.0, 51.0, 50.0).is_err());
    assert!(cbf.evaluate_step(150.0, 20.0, 50.0).is_ok());

    let ledger = DebitLedger::new(200.0, 0.5, 100.0).expect("ledger");
    assert!(ledger.pre_reserve(101.0, "over-floor").is_err());
    assert_eq!(ledger.available_budget(), 200.0);
    ledger.pre_reserve(40.0, "d1").expect("d1");
    assert_eq!(ledger.available_budget(), 160.0);
    let (rolled_id, restored) = ledger.rollback_lifo().expect("rollback_lifo");
    assert_eq!(rolled_id, "d1");
    assert_eq!(restored, 200.0);
}

#[tokio::test]
async fn test_f7_cedar_parc_and_dogwood_temporal_parity() {
    let cedar_src = lean_parser::read_module("CedarAndTemporal");
    let fsm_src = lean_parser::read_module("FsmContainment");
    let fsm_env = HashMap::new();
    let default_max_amount =
        lean_parser::parse_def_nat(&fsm_src, "DEFAULT_MAX_AMOUNT_CENTS", &fsm_env);
    let mut env = HashMap::new();
    env.insert("DEFAULT_MAX_AMOUNT_CENTS".to_string(), default_max_amount);

    let entity_count =
        lean_parser::parse_def_nat(&cedar_src, "CEDAR_ENTITY_TYPE_COUNT", &env) as usize;
    let action_count = lean_parser::parse_def_nat(&cedar_src, "CEDAR_ACTION_COUNT", &env) as usize;
    let max_spend = lean_parser::parse_def_nat(&cedar_src, "CEDAR_MAX_SPEND_CENTS", &env);
    let lean_entity_names =
        lean_parser::parse_def_string_list(&cedar_src, "CEDAR_ENTITY_TYPE_NAMES");
    let lean_action_names = lean_parser::parse_def_string_list(&cedar_src, "CEDAR_ACTION_NAMES");

    assert_eq!(max_spend, default_max_amount);
    assert_eq!(max_spend, PolicyGuard::default().max_amount_cents);
    assert_eq!(lean_entity_names.len(), entity_count);
    assert_eq!(lean_action_names.len(), action_count);

    let schema_val: serde_json::Value =
        serde_json::from_str(OCTOPUS_CEDAR_SCHEMA_JSON).expect("valid OCTOPUS_CEDAR_SCHEMA_JSON");
    let rust_entities: BTreeSet<String> = schema_val["Octopus"]["entityTypes"]
        .as_object()
        .expect("entityTypes object")
        .keys()
        .cloned()
        .collect();
    let rust_actions: BTreeSet<String> = schema_val["Octopus"]["actions"]
        .as_object()
        .expect("actions object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        rust_entities,
        lean_entity_names.into_iter().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        rust_actions,
        lean_action_names.into_iter().collect::<BTreeSet<_>>()
    );

    let gate = Arc::new(CedarGate::new());
    // Over-budget spend rejected
    assert!(gate
        .evaluate_authorization(
            "ledger_arm",
            &ArmRole::AccountingLedgerWrite,
            "write",
            "acc-1",
            Some(10_000_001),
        )
        .await
        .is_err());
    // Principal spoofing rejected
    assert!(gate
        .evaluate_authorization(
            "ledger_arm",
            &ArmRole::UntrustedDocIngest,
            "extract",
            "doc-1",
            None,
        )
        .await
        .is_err());
    // rogue_adversary denied by @id("ALL") forbid rule
    assert!(gate
        .evaluate_authorization(
            "rogue_adversary",
            &ArmRole::NetworkEgress,
            "egress",
            "https://www.google.com/",
            None,
        )
        .await
        .is_err());

    // CedarAuthorizer denies unmapped role string fail-closed
    let authorizer = CedarAuthorizer::new(Arc::clone(&gate));
    let req = RingRequest {
        operation: Operation::DocumentRead,
        resource: "doc-1".to_string(),
        body: Vec::new(),
    };
    let unknown_res = authorizer
        .authorize("unknown-arm", "totally_unknown_role", &req)
        .await
        .expect("authorize call returns Ok(false)");
    assert!(!unknown_res);

    // Tighten-only policy engine rejects permit policy
    let engine = CedarPolicyEngine::new().expect("CedarPolicyEngine");
    let permit_attempt = engine.add_tighten_only_forbid_policy(
        Some("bad_permit"),
        "permit (principal, action == Octopus::Action::\"extract\", resource is Octopus::Document);",
    );
    assert!(permit_attempt.is_err());

    // Dogwood temporal engine fails closed on malformed clause
    let dogwood = DogwoodTemporalEngine::new_simulation();
    let dctx = DecisionContext {
        current_time_secs: 1000,
        principal: "document_arm".to_string(),
        resource: "doc-1".to_string(),
        context_fields: HashMap::new(),
    };
    assert!(dogwood.evaluate_policy("invalid((syntax", &dctx).is_err());
}

#[test]
fn test_f8_mandate_attenuation_and_quorum_parity() {
    let mq_src = lean_parser::read_module("MandateAndQuorum");
    let env = HashMap::new();
    let lean_depth =
        lean_parser::parse_def_nat(&mq_src, "MANDATE_MAX_DELEGATION_DEPTH", &env) as usize;
    let lean_schemes = lean_parser::parse_def_string_list(&mq_src, "ALLOWED_SCHEMES");
    assert_eq!(lean_depth, MAX_DELEGATION_DEPTH);
    assert_eq!(
        lean_schemes,
        ALLOWED_SCHEMES
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
    );

    // Invalid URIs rejected
    assert!(validate_mesh_uri("http://evil.example").is_err());
    assert!(validate_mesh_uri("mcp://169.254.169.254/latest").is_err());
    assert!(validate_mesh_uri("mcp://127.0.0.1:8080/calc").is_err());

    // Mandate chain parity hardening checks
    let k0 = SigningKey::generate(&mut OsRng);
    let k1 = SigningKey::generate(&mut OsRng);
    let k2 = SigningKey::generate(&mut OsRng);
    let root_vk = k0.verifying_key().to_bytes();

    let mut svc = BTreeSet::new();
    svc.insert("mcp://calc".to_string());
    let mut pub_set = BTreeSet::new();
    pub_set.insert("mcp://octopus/doc_extractor".to_string());

    let root = AttenuatedMandate::create_root(
        &k0,
        "spiffe://agentoctopus.local/root",
        "spiffe://agentoctopus.local/node1",
        k1.verifying_key().to_bytes(),
        svc.clone(),
        pub_set.clone(),
        1000,
        5000,
    )
    .expect("root mandate");

    // now == root_link.delegated_at must still be accepted
    assert!(root.verify_chain(&root_vk, 1000).is_ok());
    assert!(root.verify_chain(&root_vk, 999).is_err());

    let child = root
        .attenuate(
            &k1,
            "spiffe://agentoctopus.local/node2",
            k2.verifying_key().to_bytes(),
            svc.clone(),
            BTreeSet::new(),
            4000,
            1500,
        )
        .expect("child mandate");
    assert!(child.verify_chain(&root_vk, 1500).is_ok());

    // Tampered top-level allowed_services / allowed_publish / expires_at rejected
    let mut svc_tampered = child.clone();
    svc_tampered
        .allowed_services
        .insert("mcp://payroll".to_string());
    assert!(matches!(
        svc_tampered.verify_chain(&root_vk, 2000),
        Err(MandateError::PrivilegeEscalationService { .. })
    ));

    let mut pub_tampered = child.clone();
    pub_tampered
        .allowed_publish
        .insert("mcp://secret".to_string());
    assert!(matches!(
        pub_tampered.verify_chain(&root_vk, 2000),
        Err(MandateError::PrivilegeEscalationPublish { .. })
    ));

    let mut exp_tampered = child.clone();
    exp_tampered.expires_at = 9999;
    assert!(matches!(
        exp_tampered.verify_chain(&root_vk, 2000),
        Err(MandateError::MandateExpired { .. })
    ));

    // Tampered depth > MAX_DELEGATION_DEPTH rejected
    let mut depth_tampered = child.clone();
    depth_tampered.depth = MAX_DELEGATION_DEPTH + 1;
    assert!(matches!(
        depth_tampered.verify_chain(&root_vk, 2000),
        Err(MandateError::MaxDelegationDepthExceeded { .. })
    ));

    // Deserialized not_before earlier than root_link.delegated_at rejected
    let mut nbf_tampered = child.clone();
    nbf_tampered.not_before = 500;
    assert!(matches!(
        nbf_tampered.verify_chain(&root_vk, 500),
        Err(MandateError::MandateNotYetValid { .. })
    ));
    let mut now_before_leaf = child.clone();
    now_before_leaf.not_before = 1000;
    assert!(matches!(
        now_before_leaf.verify_chain(&root_vk, 1400),
        Err(MandateError::MandateNotYetValid { .. })
    ));

    // Deserialized chain with invalid URI in root_link rejected
    let mut bad_uri_services = BTreeSet::new();
    bad_uri_services.insert("http://evil.example".to_string());
    let mut forged_root = root.clone();
    forged_root.allowed_services = bad_uri_services.clone();
    forged_root.delegation_chain[0].attenuated_services = bad_uri_services;
    let payload0 = agent_octopus::DelegationLink::canonical_payload(
        forged_root.delegation_chain[0].depth,
        &forged_root.delegation_chain[0].delegator_spiffe_id,
        &forged_root.delegation_chain[0].delegator_verifying_key,
        &forged_root.delegation_chain[0].delegatee_spiffe_id,
        &forged_root.delegation_chain[0].delegatee_verifying_key,
        &forged_root.delegation_chain[0].attenuated_services,
        &forged_root.delegation_chain[0].attenuated_publish,
        forged_root.delegation_chain[0].delegated_at,
        forged_root.delegation_chain[0].expires_at,
    );
    use ed25519_dalek::Signer;
    forged_root.delegation_chain[0].signature = k0.sign(&payload0).to_bytes().to_vec();
    assert!(matches!(
        forged_root.verify_chain(&root_vk, 1500),
        Err(MandateError::InvalidUriScheme { .. })
    ));

    // Non-monotonic link.delegated_at rejected
    let mut non_mono = child.clone();
    non_mono.delegation_chain[1].delegated_at = 900;
    let payload1 = agent_octopus::DelegationLink::canonical_payload(
        non_mono.delegation_chain[1].depth,
        &non_mono.delegation_chain[1].delegator_spiffe_id,
        &non_mono.delegation_chain[1].delegator_verifying_key,
        &non_mono.delegation_chain[1].delegatee_spiffe_id,
        &non_mono.delegation_chain[1].delegatee_verifying_key,
        &non_mono.delegation_chain[1].attenuated_services,
        &non_mono.delegation_chain[1].attenuated_publish,
        non_mono.delegation_chain[1].delegated_at,
        non_mono.delegation_chain[1].expires_at,
    );
    non_mono.delegation_chain[1].signature = k1.sign(&payload1).to_bytes().to_vec();
    assert!(matches!(
        non_mono.verify_chain(&root_vk, 2000),
        Err(MandateError::MandateNotYetValid { .. })
    ));

    // QuorumPolicyGuard parity: zero threshold, Sybil duplicate, and insufficient attestations
    let auth1 = SigningKey::generate(&mut OsRng);
    let auth2 = SigningKey::generate(&mut OsRng);
    let proposal = PolicyProposal {
        proposal_id: "prop-1".to_string(),
        proposed_policy_hash: [0x11u8; 32],
        new_egress_domains: vec!["google.com".to_string()],
        timestamp_ms: 100,
    };

    let mut zero_guard = QuorumPolicyGuard::new(0, [0u8; 32]);
    assert_eq!(
        zero_guard.submit_and_commit_proposal(&proposal, &[]),
        Err(LedgerError::ZeroThreshold)
    );

    let mut guard = QuorumPolicyGuard::new(2, [0u8; 32]);
    guard.register_authority("auth1", auth1.verifying_key());
    guard.register_authority("auth2", auth2.verifying_key());

    let att1 = PolicyAttestation::create_and_sign(&proposal, "auth1", &auth1);
    let att2 = PolicyAttestation::create_and_sign(&proposal, "auth2", &auth2);

    assert_eq!(
        guard.submit_and_commit_proposal(&proposal, &[att1.clone(), att1.clone()]),
        Err(LedgerError::DuplicateAuthority("auth1".to_string()))
    );
    assert_eq!(
        guard.submit_and_commit_proposal(&proposal, &[att1.clone()]),
        Err(LedgerError::QuorumNotMet {
            required: 2,
            valid: 1
        })
    );
    assert!(guard
        .submit_and_commit_proposal(&proposal, &[att1, att2])
        .is_ok());
}

#[test]
fn test_f9_isolation_perimeter_shield_and_sentinel_parity() {
    let iso_src = lean_parser::read_module("IsolationAndPerimeter");
    let env = HashMap::new();

    assert_eq!(
        lean_parser::parse_def_nat(&iso_src, "INTEGRITY_MEDIUM", &env) as u32,
        INTEGRITY_MEDIUM
    );
    assert_eq!(
        lean_parser::parse_def_nat(&iso_src, "INTEGRITY_HIGH", &env) as u32,
        INTEGRITY_HIGH
    );
    assert_eq!(
        lean_parser::parse_def_nat(&iso_src, "MAX_WIN_MEMORY_BYTES", &env) as usize,
        512 * 1024 * 1024
    );
    let lean_privs = lean_parser::parse_def_string_list(&iso_src, "DANGEROUS_PRIVILEGES");
    assert_eq!(
        lean_privs,
        DANGEROUS_PRIVILEGES
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
    );

    let lean_sent_states =
        lean_parser::parse_inductive_constructors(&iso_src, "SentinelSystemState");
    let rust_sent_states = [
        SentinelSystemState::Healthy,
        SentinelSystemState::Degraded,
        SentinelSystemState::Quarantined,
        SentinelSystemState::Lockdown,
    ];
    let rust_sent_state_names: Vec<String> = rust_sent_states
        .iter()
        .map(|s| match s {
            SentinelSystemState::Healthy => "Healthy",
            SentinelSystemState::Degraded => "Degraded",
            SentinelSystemState::Quarantined => "Quarantined",
            SentinelSystemState::Lockdown => "Lockdown",
        })
        .map(str::to_string)
        .collect();
    assert_eq!(lean_sent_states, rust_sent_state_names);

    let lean_sent_actions = lean_parser::parse_inductive_constructors(&iso_src, "SentinelAction");
    let rust_sent_actions = [
        SentinelAction::Continue,
        SentinelAction::RevokeCapabilities,
        SentinelAction::IsolateArm(0),
        SentinelAction::TerminateArm(0),
        SentinelAction::LockdownSystem,
    ];
    let rust_sent_action_names: Vec<String> = rust_sent_actions
        .iter()
        .map(|a| match a {
            SentinelAction::Continue => "Continue",
            SentinelAction::RevokeCapabilities => "RevokeCapabilities",
            SentinelAction::IsolateArm(_) => "IsolateArm",
            SentinelAction::TerminateArm(_) => "TerminateArm",
            SentinelAction::LockdownSystem => "LockdownSystem",
        })
        .map(str::to_string)
        .collect();
    assert_eq!(lean_sent_actions, rust_sent_action_names);
    assert_eq!(KernelAttackSurface::baseline_proactive_surfaces().len(), 8);

    // Path confinement negative boundaries
    struct TempSandboxDir {
        path: PathBuf,
    }
    impl Drop for TempSandboxDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
    let unique_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sandbox_dir = std::env::temp_dir().join(format!(
        "agent_octopus_lean_coupling_sbx_{}_{}",
        std::process::id(),
        unique_ns
    ));
    fs::create_dir_all(&sandbox_dir).expect("create temp sandbox dir");
    let _sandbox_guard = TempSandboxDir {
        path: sandbox_dir.clone(),
    };
    for bad_rel in [
        "%2e%2e/x",
        "dir/%2f/x",
        "dir/%5c/x",
        "a\0b",
        "a%00b",
        "..",
        "../secret",
        r"C:\Windows\System32",
        r"\\unc\share\file",
        "foo.txt:ads",
    ] {
        assert!(
            validate_sandbox_relative_path(&sandbox_dir, bad_rel).is_err(),
            "Expected path rejection for {bad_rel:?}"
        );
        assert!(
            open_confined(&sandbox_dir, bad_rel, false).is_err(),
            "Expected open_confined rejection for {bad_rel:?}"
        );
    }

    // SSRF & non-standard IP encoding negative boundaries
    for restricted_ip in [
        "169.254.169.254",
        "168.63.129.16",
        "100.64.0.1",
        "192.0.0.192",
        "10.0.0.1",
        "::1",
        "::ffff:169.254.169.254",
    ] {
        let ip: IpAddr = restricted_ip.parse().expect("valid ip literal");
        assert!(
            is_restricted_rebinding_ip(&ip),
            "Expected restricted IP rejection for {restricted_ip}"
        );
    }
    assert!(!is_restricted_rebinding_ip(
        &"1.1.1.1".parse::<IpAddr>().unwrap()
    ));
    let allowed = vec!["1.1.1.1".to_string(), "www.google.com".to_string()];
    for bad_url in [
        "https://0x7f000001/",
        "https://0177.0.0.1/",
        "https://127.1/",
        "https://[::ffff:169.254.169.254]/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/",
    ] {
        assert!(
            validate_agent_egress_url(bad_url, &allowed).is_err(),
            "Expected SSRF URL block for {bad_url}"
        );
    }

    // TokenPosture & pre-resume confinement gate
    let unsafe_high = TokenPosture {
        elevated: true,
        integrity_rid: INTEGRITY_HIGH,
        admins_enabled: false,
        admins_deny_only: true,
        present_privileges: vec!["SeDebugPrivilege".to_string()],
        enabled_privileges: Vec::new(),
    };
    assert!(unsafe_high.verify_agent_safe().is_err());

    let safe_med = TokenPosture {
        elevated: false,
        integrity_rid: INTEGRITY_MEDIUM,
        admins_enabled: false,
        admins_deny_only: true,
        present_privileges: vec!["SeChangeNotifyPrivilege".to_string()],
        enabled_privileges: Vec::new(),
    };
    assert!(safe_med.verify_agent_safe().is_ok());

    let win_pol = WindowsConfinementPolicy::default();
    assert!(verify_windows_confinement_invariants(&win_pol).is_ok());
    assert!(evaluate_pre_resume_confinement_gate(&win_pol, false, true, true, true).is_err());
    assert!(evaluate_pre_resume_confinement_gate(&win_pol, true, true, true, false).is_err());
    assert!(evaluate_pre_resume_confinement_gate(&win_pol, true, true, true, true).is_ok());

    // VirtualPatchShieldStore latch monotonicity
    let store = VirtualPatchShieldStore::new(None);
    let mut locked = KernelShieldPosture::default_fail_closed();
    locked.reboot_pending = true;
    locked.shield_locked_until_reboot = true;
    locked.running_kernel = "6.8.0-generic".to_string();
    locked.finalize();
    assert!(store.apply_posture(locked).is_ok());

    let mut unlock_attempt = store.current();
    unlock_attempt.reboot_pending = false;
    unlock_attempt.shield_locked_until_reboot = false;
    unlock_attempt.finalize();
    assert!(store.apply_posture(unlock_attempt).is_err());
    assert!(store.confirm_reboot_cleared("6.8.0-generic", true).is_err());

    // SEC-RING-01 child PID verification & ring_sentinel::evaluate
    assert!(ArmContainmentRing::verify_terminable_child_pid(0).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(4).is_err());
    assert!(ArmContainmentRing::verify_terminable_child_pid(std::process::id()).is_err());

    let mut unhealthy_obs = ring_sentinel::SentinelObservation::healthy_baseline(17, 8);
    unhealthy_obs.supervisor_healthy = false;
    assert_eq!(
        ring_sentinel::evaluate(&unhealthy_obs),
        ring_sentinel::SentinelAction::LockdownSystem
    );
}

#[tokio::test]
async fn test_f9_f10_sentinel_lockdown_absorbing_and_master_theorems() {
    let master_src = lean_parser::read_module("NoBreachNoBreakout");
    assert!(lean_parser::has_theorem(&master_src, "no_breakout"));
    assert!(lean_parser::has_theorem(&master_src, "no_breach"));

    let seed = b"SENTINEL_LOCKDOWN_COUPLING_SEED_32";
    let sentinel = SentinelSupervisor::new(seed, 20);
    sentinel
        .trigger_lockdown("CouplingTest", "Verify Lockdown absorption")
        .await;
    let snap0 = sentinel.snapshot().await;
    assert_eq!(snap0.system_state, SentinelSystemState::Lockdown);
    assert!(snap0.is_locked_down);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Zombie worker observation would set Degraded if unguarded, must stay Lockdown
    let zombie_obs = SentinelObservation {
        arm_id: 3,
        generation: 1,
        worker_alive: true,
        authorization_healthy: true,
        sandbox_verified: true,
        unauthorized_egress_detected: false,
        supervisor_healthy: true,
        termination_deadline_exceeded: true,
        proxy_enforcement_intact: true,
        timestamp_secs: now,
    };
    let act1 = sentinel
        .evaluate_observation(&zombie_obs)
        .await
        .expect("zombie obs");
    assert_eq!(act1, SentinelAction::TerminateArm(3));
    let snap1 = sentinel.snapshot().await;
    assert_eq!(snap1.system_state, SentinelSystemState::Lockdown);
    assert!(snap1.is_locked_down);

    // Unauthorized egress observation would set Quarantined if unguarded, must stay Lockdown
    let egress_obs = SentinelObservation {
        arm_id: 4,
        generation: 1,
        worker_alive: true,
        authorization_healthy: true,
        sandbox_verified: true,
        unauthorized_egress_detected: true,
        supervisor_healthy: true,
        termination_deadline_exceeded: false,
        proxy_enforcement_intact: true,
        timestamp_secs: now,
    };
    let act2 = sentinel
        .evaluate_observation(&egress_obs)
        .await
        .expect("egress obs");
    assert_eq!(act2, SentinelAction::TerminateArm(4));
    let snap2 = sentinel.snapshot().await;
    assert_eq!(snap2.system_state, SentinelSystemState::Lockdown);
    assert!(snap2.is_locked_down);

    // Valid authenticated heartbeat must also keep Lockdown absorbing
    let hb = create_authenticated_heartbeat("supervisor_alpha", 1, 1, 1000, seed);
    assert!(sentinel.ingest_supervisor_heartbeat(hb).await.is_ok());
    let snap3 = sentinel.snapshot().await;
    assert_eq!(snap3.system_state, SentinelSystemState::Lockdown);
    assert!(snap3.is_locked_down);
}
