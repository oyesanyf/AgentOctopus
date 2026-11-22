use crate::cli::run::check_no_reparse_or_symlink;
use crate::cli::EXIT_PREFLIGHT_DENIED;
use crate::core::merkle::{MerkleLeaf, MerkleTree};
use crate::security::audit::SecurityAuditLog;
use crate::security::latent_shield::{
    load_cyclonedx_sbom_file, GuardVerdict, RuntimeTelemetry, SbomIntent, UnifiedSecurityShield,
    MAX_SBOM_JSON_BYTES, RUNTIME_ACTION_DIM,
};
use ndarray::Array1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomGuardSummary {
    pub domain: String,
    pub intent: String,
    pub surprise_score: f64,
    pub threshold: f64,
    pub block_execution: bool,
    pub reason: String,
    pub audit_merkle_root: String,
    pub audit_record_hash: String,
}

#[derive(Debug, Serialize)]
struct SubcommandJsonVerdict {
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    intent: Option<String>,
    surprise_score: f64,
    threshold: f64,
    block_execution: bool,
    reason: String,
    audit_merkle_root: String,
    audit_record_hash: String,
}

#[derive(Debug, Deserialize)]
struct TelemetryStepPayload {
    prev_state: RuntimeTelemetry,
    action: Vec<f64>,
    observed_state: RuntimeTelemetry,
}

fn finite_or_max(v: f64) -> f64 {
    if v.is_finite() {
        v
    } else {
        f64::MAX
    }
}

fn finite_threshold(v: f64) -> f64 {
    if v.is_finite() && v >= 0.0 {
        v
    } else {
        0.0
    }
}

pub(crate) fn load_shield_for_cli(
    latent_weights: Option<&Path>,
) -> Result<UnifiedSecurityShield, String> {
    if let Some(weights_path) = latent_weights {
        check_no_reparse_or_symlink(weights_path, "--latent-weights")?;
        UnifiedSecurityShield::from_weights_file(weights_path).map_err(|e| {
            format!(
                "failed to load --latent-weights '{}': {}",
                weights_path.display(),
                e
            )
        })
    } else {
        UnifiedSecurityShield::cached_default()
            .cloned()
            .map_err(|e| format!("failed to load embedded latent shield defaults: {}", e))
    }
}

fn compute_merkle_and_audit_receipt(
    event_type: &str,
    input_digest: &str,
    output_digest: &str,
    details: &str,
    block_execution: bool,
) -> (String, String) {
    let leaves = vec![
        MerkleLeaf::new(0, event_type, input_digest, output_digest),
        MerkleLeaf::new(
            1,
            if block_execution { "DENY" } else { "ALLOW" },
            output_digest,
            details,
        ),
    ];
    let tree = MerkleTree::from_leaves(leaves);
    let root_hex = tree.root_hex();
    let audit_log = SecurityAuditLog::new();
    let decision = if block_execution { "DENY" } else { "ALLOW" };
    let record_hash = audit_log.record_event(
        event_type,
        "octopus_latent_shield",
        &format!("{} merkle_root={}", details, root_hex),
        decision,
    );
    (root_hex, record_hash)
}

pub(crate) fn evaluate_gate1_sbom_pair(
    shield: &UnifiedSecurityShield,
    baseline_path: &Path,
    candidate_path: &Path,
    intent: SbomIntent,
) -> Result<SbomGuardSummary, String> {
    check_no_reparse_or_symlink(baseline_path, "--baseline-sbom")?;
    check_no_reparse_or_symlink(candidate_path, "--sbom")?;

    let baseline = load_cyclonedx_sbom_file(baseline_path).map_err(|e| {
        format!(
            "failed to load --baseline-sbom '{}': {}",
            baseline_path.display(),
            e
        )
    })?;
    let candidate = load_cyclonedx_sbom_file(candidate_path).map_err(|e| {
        format!(
            "failed to load --sbom '{}': {}",
            candidate_path.display(),
            e
        )
    })?;

    let action = intent.to_action_array();
    let verdict: GuardVerdict = shield
        .sbom_guard
        .evaluate_sbom_diff(&baseline, &action, &candidate);

    let baseline_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&baseline).unwrap_or_default(),
    ));
    let candidate_digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&candidate).unwrap_or_default(),
    ));
    let safe_surprise = finite_or_max(verdict.surprise_score);
    let safe_threshold = finite_threshold(verdict.threshold);
    let details = format!(
        "intent={} surprise={:.6} threshold={:.6} reason={}",
        intent.as_str(),
        safe_surprise,
        safe_threshold,
        verdict.reason
    );
    let (audit_merkle_root, audit_record_hash) = compute_merkle_and_audit_receipt(
        "SBOM_SUPPLY_CHAIN_GATE1",
        &baseline_digest,
        &candidate_digest,
        &details,
        verdict.block_execution,
    );

    Ok(SbomGuardSummary {
        domain: verdict.domain.to_string(),
        intent: intent.as_str().to_string(),
        surprise_score: safe_surprise,
        threshold: safe_threshold,
        block_execution: verdict.block_execution,
        reason: verdict.reason.to_string(),
        audit_merkle_root,
        audit_record_hash,
    })
}

pub fn print_sbom_guard_help() {
    println!(
        "octopus sbom-guard (alias: latent-shield) — Pure-Rust UnifiedSecurityShield Gate 1 & Gate 2 evaluator\n\n\
         USAGE:\n\
         \x20 octopus sbom-guard --baseline-sbom <PATH> --sbom <PATH> [--sbom-intent <patch|minor|refactor>] [--latent-weights <PATH>] [--json]\n\
         \x20 octopus sbom-guard --check-step --telemetry <PATH|-> [--latent-weights <PATH>] [--json]\n\n\
         OPTIONS:\n\
         \x20 --baseline-sbom <PATH>                Baseline CycloneDX SBOM JSON file (Mode 1)\n\
         \x20 --sbom <PATH>                         Candidate CycloneDX SBOM JSON file (Mode 1)\n\
         \x20 --sbom-intent, --intent <KIND>        Release intent: patch | minor | refactor (default: patch)\n\
         \x20 --check-step                          Evaluate a runtime telemetry transition step (Mode 2)\n\
         \x20 --telemetry <PATH|->                  Runtime telemetry JSON file or '-' for stdin (Mode 2)\n\
         \x20 --latent-weights <PATH>               Custom UnifiedSecurityShield JSON weights (default: embedded)\n\
         \x20 --json                                Emit structured GuardVerdict JSON output\n\
         \x20 -h, --help                            Print this help message\n\n\
         EXIT CODES:\n\
         \x20 0  Allowed (block_execution = false)\n\
         \x20 2  Blocked / fail-closed error (block_execution = true)"
    );
}

fn emit_subcommand_error(domain: &str, json_output: bool, msg: String) -> i32 {
    if json_output {
        let digest = hex::encode(Sha256::digest(msg.as_bytes()));
        let (audit_merkle_root, audit_record_hash) = compute_merkle_and_audit_receipt(
            "LATENT_SHIELD_FAIL_CLOSED",
            &digest,
            &digest,
            &msg,
            true,
        );
        let payload = SubcommandJsonVerdict {
            domain: domain.to_string(),
            intent: None,
            surprise_score: f64::MAX,
            threshold: 0.0,
            block_execution: true,
            reason: msg,
            audit_merkle_root,
            audit_record_hash,
        };
        if let Ok(text) = serde_json::to_string_pretty(&payload) {
            println!("{}", text);
        }
    } else {
        eprintln!("[octopus sbom-guard] DENY: {}", msg);
    }
    EXIT_PREFLIGHT_DENIED
}

fn read_bounded_telemetry_json(src: &str) -> Result<String, String> {
    if src == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .take(MAX_SBOM_JSON_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read --telemetry from stdin: {}", e))?;
        if buf.len() > MAX_SBOM_JSON_BYTES {
            return Err(format!(
                "stdin --telemetry payload exceeded {} byte cap",
                MAX_SBOM_JSON_BYTES
            ));
        }
        return String::from_utf8(buf)
            .map_err(|e| format!("stdin --telemetry is not valid UTF-8: {}", e));
    }

    let path = Path::new(src);
    check_no_reparse_or_symlink(path, "--telemetry")?;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("failed to stat --telemetry '{}': {}", path.display(), e))?;
    if !meta.is_file() {
        return Err(format!(
            "--telemetry '{}' is not a regular file",
            path.display()
        ));
    }
    if meta.len() > MAX_SBOM_JSON_BYTES as u64 {
        return Err(format!(
            "--telemetry '{}' ({} bytes) exceeds {} byte limit",
            path.display(),
            meta.len(),
            MAX_SBOM_JSON_BYTES
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|e| format!("failed to open --telemetry '{}': {}", path.display(), e))?;
    let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_SBOM_JSON_BYTES));
    file.take(MAX_SBOM_JSON_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("failed to read --telemetry '{}': {}", path.display(), e))?;
    if buf.len() > MAX_SBOM_JSON_BYTES {
        return Err(format!(
            "--telemetry '{}' exceeded {} byte read cap",
            path.display(),
            MAX_SBOM_JSON_BYTES
        ));
    }
    String::from_utf8(buf)
        .map_err(|e| format!("--telemetry '{}' is not valid UTF-8: {}", path.display(), e))
}

pub fn execute_sbom_guard_cli(sub_args: &[String]) -> i32 {
    if sub_args.iter().any(|a| a == "-h" || a == "--help") {
        print_sbom_guard_help();
        return 0;
    }

    let mut baseline_sbom: Option<PathBuf> = None;
    let mut candidate_sbom: Option<PathBuf> = None;
    let mut sbom_intent: Option<SbomIntent> = None;
    let mut latent_weights: Option<PathBuf> = None;
    let mut check_step = false;
    let mut telemetry_src: Option<String> = None;
    let mut json_output = sub_args.iter().any(|a| a == "--json");

    let mut i = 0usize;
    while i < sub_args.len() {
        let arg = sub_args[i].as_str();
        if arg == "--json" {
            json_output = true;
            i += 1;
        } else if arg == "--check-step" {
            check_step = true;
            i += 1;
        } else if arg == "--baseline-sbom" {
            let Some(val) = sub_args.get(i + 1) else {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "missing value for '--baseline-sbom'".to_string(),
                );
            };
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "'--baseline-sbom' value cannot be empty".to_string(),
                );
            }
            baseline_sbom = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--baseline-sbom=") {
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "'--baseline-sbom' value cannot be empty".to_string(),
                );
            }
            baseline_sbom = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--sbom" {
            let Some(val) = sub_args.get(i + 1) else {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "missing value for '--sbom'".to_string(),
                );
            };
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "'--sbom' value cannot be empty".to_string(),
                );
            }
            candidate_sbom = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--sbom=") {
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "'--sbom' value cannot be empty".to_string(),
                );
            }
            candidate_sbom = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--sbom-intent" || arg == "--intent" {
            let Some(val) = sub_args.get(i + 1) else {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    format!("missing value for '{}'", arg),
                );
            };
            match SbomIntent::parse(val) {
                Ok(parsed) => sbom_intent = Some(parsed),
                Err(e) => {
                    return emit_subcommand_error("SBOM_SUPPLY_CHAIN", json_output, e.to_string())
                }
            }
            i += 2;
        } else if let Some(val) = arg
            .strip_prefix("--sbom-intent=")
            .or_else(|| arg.strip_prefix("--intent="))
        {
            match SbomIntent::parse(val) {
                Ok(parsed) => sbom_intent = Some(parsed),
                Err(e) => {
                    return emit_subcommand_error("SBOM_SUPPLY_CHAIN", json_output, e.to_string())
                }
            }
            i += 1;
        } else if arg == "--latent-weights" {
            let Some(val) = sub_args.get(i + 1) else {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "missing value for '--latent-weights'".to_string(),
                );
            };
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "'--latent-weights' value cannot be empty".to_string(),
                );
            }
            latent_weights = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--latent-weights=") {
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "SBOM_SUPPLY_CHAIN",
                    json_output,
                    "'--latent-weights' value cannot be empty".to_string(),
                );
            }
            latent_weights = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--telemetry" {
            let Some(val) = sub_args.get(i + 1) else {
                return emit_subcommand_error(
                    "AGENT_OCTOPUS_RUNTIME",
                    json_output,
                    "missing value for '--telemetry'".to_string(),
                );
            };
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "AGENT_OCTOPUS_RUNTIME",
                    json_output,
                    "'--telemetry' value cannot be empty".to_string(),
                );
            }
            telemetry_src = Some(val.clone());
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--telemetry=") {
            if val.trim().is_empty() {
                return emit_subcommand_error(
                    "AGENT_OCTOPUS_RUNTIME",
                    json_output,
                    "'--telemetry' value cannot be empty".to_string(),
                );
            }
            telemetry_src = Some(val.to_string());
            i += 1;
        } else {
            return emit_subcommand_error(
                "SBOM_SUPPLY_CHAIN",
                json_output,
                format!("unknown option '{}'", arg),
            );
        }
    }

    let is_mode1 = baseline_sbom.is_some() || candidate_sbom.is_some() || sbom_intent.is_some();
    let is_mode2 = check_step || telemetry_src.is_some();

    if is_mode1 && is_mode2 {
        return emit_subcommand_error(
            "SBOM_SUPPLY_CHAIN",
            json_output,
            "cannot mix Mode 1 (--baseline-sbom/--sbom) and Mode 2 (--check-step/--telemetry)"
                .to_string(),
        );
    }
    if !is_mode1 && !is_mode2 {
        return emit_subcommand_error(
            "SBOM_SUPPLY_CHAIN",
            json_output,
            "specify Mode 1 (--baseline-sbom <PATH> --sbom <PATH>) or Mode 2 (--check-step --telemetry <PATH|->)"
                .to_string(),
        );
    }

    let shield = match load_shield_for_cli(latent_weights.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            let dom = if is_mode2 {
                "AGENT_OCTOPUS_RUNTIME"
            } else {
                "SBOM_SUPPLY_CHAIN"
            };
            return emit_subcommand_error(dom, json_output, e);
        }
    };

    if is_mode1 {
        let (Some(base_path), Some(cand_path)) =
            (baseline_sbom.as_deref(), candidate_sbom.as_deref())
        else {
            return emit_subcommand_error(
                "SBOM_SUPPLY_CHAIN",
                json_output,
                "both --baseline-sbom <PATH> and --sbom <PATH> are required".to_string(),
            );
        };
        let intent = sbom_intent.unwrap_or(SbomIntent::Patch);
        let summary = match evaluate_gate1_sbom_pair(&shield, base_path, cand_path, intent) {
            Ok(s) => s,
            Err(e) => return emit_subcommand_error("SBOM_SUPPLY_CHAIN", json_output, e),
        };
        if json_output {
            let payload = SubcommandJsonVerdict {
                domain: summary.domain.clone(),
                intent: Some(summary.intent.clone()),
                surprise_score: summary.surprise_score,
                threshold: summary.threshold,
                block_execution: summary.block_execution,
                reason: summary.reason.clone(),
                audit_merkle_root: summary.audit_merkle_root.clone(),
                audit_record_hash: summary.audit_record_hash.clone(),
            };
            if let Ok(text) = serde_json::to_string_pretty(&payload) {
                println!("{}", text);
            }
        } else if summary.block_execution {
            eprintln!(
                "[octopus sbom-guard] DENY {}: {} (surprise={:.6}, threshold={:.6}, merkle_root={})",
                summary.domain,
                summary.reason,
                summary.surprise_score,
                summary.threshold,
                summary.audit_merkle_root
            );
        } else {
            println!(
                "[octopus sbom-guard] ALLOW {}: {} (surprise={:.6}, threshold={:.6}, merkle_root={})",
                summary.domain,
                summary.reason,
                summary.surprise_score,
                summary.threshold,
                summary.audit_merkle_root
            );
        }
        return if summary.block_execution {
            EXIT_PREFLIGHT_DENIED
        } else {
            0
        };
    }

    // Mode 2: Runtime step check (--check-step --telemetry <PATH|->)
    let Some(tele_src) = telemetry_src.as_deref() else {
        return emit_subcommand_error(
            "AGENT_OCTOPUS_RUNTIME",
            json_output,
            "--check-step requires --telemetry <PATH|->".to_string(),
        );
    };
    let raw = match read_bounded_telemetry_json(tele_src) {
        Ok(r) => r,
        Err(e) => return emit_subcommand_error("AGENT_OCTOPUS_RUNTIME", json_output, e),
    };
    if raw.as_bytes().contains(&0) {
        return emit_subcommand_error(
            "AGENT_OCTOPUS_RUNTIME",
            json_output,
            "telemetry JSON contains embedded NUL byte".to_string(),
        );
    }
    let payload: TelemetryStepPayload = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            return emit_subcommand_error(
                "AGENT_OCTOPUS_RUNTIME",
                json_output,
                format!("invalid --telemetry JSON: {}", e),
            )
        }
    };
    if payload.action.len() != RUNTIME_ACTION_DIM {
        return emit_subcommand_error(
            "AGENT_OCTOPUS_RUNTIME",
            json_output,
            format!(
                "invalid telemetry action length: expected {}, got {}",
                RUNTIME_ACTION_DIM,
                payload.action.len()
            ),
        );
    }
    let action = Array1::from_vec(payload.action);
    let verdict =
        shield
            .runtime_guard
            .evaluate_step(&payload.prev_state, &action, &payload.observed_state);
    let safe_surprise = finite_or_max(verdict.surprise_score);
    let safe_threshold = finite_threshold(verdict.threshold);
    let input_digest = hex::encode(Sha256::digest(raw.as_bytes()));
    let details = format!(
        "surprise={:.6} threshold={:.6} reason={}",
        safe_surprise, safe_threshold, verdict.reason
    );
    let (audit_merkle_root, audit_record_hash) = compute_merkle_and_audit_receipt(
        "RUNTIME_TELEMETRY_GATE2_STEP",
        &input_digest,
        &input_digest,
        &details,
        verdict.block_execution,
    );

    if json_output {
        let json_verdict = SubcommandJsonVerdict {
            domain: verdict.domain.to_string(),
            intent: None,
            surprise_score: safe_surprise,
            threshold: safe_threshold,
            block_execution: verdict.block_execution,
            reason: verdict.reason.to_string(),
            audit_merkle_root: audit_merkle_root.clone(),
            audit_record_hash: audit_record_hash.clone(),
        };
        if let Ok(text) = serde_json::to_string_pretty(&json_verdict) {
            println!("{}", text);
        }
    } else if verdict.block_execution {
        eprintln!(
            "[octopus sbom-guard] DENY {}: {} (surprise={:.6}, threshold={:.6}, merkle_root={})",
            verdict.domain, verdict.reason, safe_surprise, safe_threshold, audit_merkle_root
        );
    } else {
        println!(
            "[octopus sbom-guard] ALLOW {}: {} (surprise={:.6}, threshold={:.6}, merkle_root={})",
            verdict.domain, verdict.reason, safe_surprise, safe_threshold, audit_merkle_root
        );
    }

    if verdict.block_execution {
        EXIT_PREFLIGHT_DENIED
    } else {
        0
    }
}
