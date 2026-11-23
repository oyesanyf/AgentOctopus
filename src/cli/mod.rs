pub mod latent_shield;
pub mod policy;
pub mod proxy;
pub mod run;
pub mod wasm_runner;

use crate::security::latent_shield::SbomIntent;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const EXIT_PREFLIGHT_DENIED: i32 = 2;
pub const EXIT_SANDBOX_FAILURE: i32 = 1;
pub const EXIT_TIMEOUT: i32 = 124;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SandboxMode {
    Standard,
    Strict,
    #[serde(rename = "wasm-strict")]
    WasmStrict,
}

impl SandboxMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxMode::Standard => "standard",
            SandboxMode::Strict => "strict",
            SandboxMode::WasmStrict => "wasm-strict",
        }
    }

    pub fn is_strict(&self) -> bool {
        matches!(self, SandboxMode::Strict | SandboxMode::WasmStrict)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OctopusRunArgs {
    pub policy_path: PathBuf,
    pub sandbox: SandboxMode,
    pub wasm_promote: bool,
    pub timeout_secs: Option<u64>,
    pub cwd: Option<PathBuf>,
    pub json_output: bool,
    pub baseline_sbom: Option<PathBuf>,
    pub sbom: Option<PathBuf>,
    pub sbom_intent: Option<SbomIntent>,
    pub latent_weights: Option<PathBuf>,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliParseResult {
    Help,
    RunHelp,
    Version,
    Run(OctopusRunArgs),
    Delegate(String),
    Invalid(String),
}

pub fn print_octopus_help() {
    println!(
        "octopus {} — Single-binary Rust deterministic agent containment runtime\n\
         (AWS Cedar v4.13, Wasmtime, OS kernel sandboxes, and RT-ASP sanitizers)\n\n\
         USAGE:\n\
         \x20 octopus run --policy <PATH> [OPTIONS] -- <COMMAND> [ARGS...]\n\
         \x20 octopus <SUBCOMMAND> [ARGS...]\n\n\
         SUBCOMMANDS:\n\
         \x20 run          Execute a command or .wasm/.wat guest inside deterministic containment\n\
         \x20 verify       Run 7-phase deterministic subsystem self-diagnostics\n\
         \x20 status       Show Host KillSwitch containment status (JSON)\n\
         \x20 protocols    Show Universal Protocol Catalog summary (JSON)\n\
         \x20 hook         Evaluate or install AI coding-agent RT-ASP hooks\n\
         \x20 mcp-proxy    Run stdio MCP JSON-RPC RT-ASP sanitizer proxy\n\
         \x20 siquery      Run relational EDR / process / socket audit query\n\
         \x20 sbom-guard   Run UnifiedSecurityShield Gate 1 SBOM or Gate 2 runtime step check (alias: latent-shield)\n\
         \x20 kernel-patch Scan kernel CVEs/KEVs, inspect livepatch/reboot shield, or apply OS patches\n\
         \x20 abibo        Run 7-Law Physics ABIBO containment, Artemis DFIR forensics & NewCore Grok simulator\n\
         \x20 isolate      Engage host-level network KillSwitch\n\
         \x20 restore      Disarm host-level network KillSwitch\n\
         \x20 service      Manage native OS background service\n\
         \x20 help         Print this help message\n\n\
         Run 'octopus run --help' for run-specific containment options.",
        env!("CARGO_PKG_VERSION")
    );
}

pub fn print_octopus_run_help() {
    println!(
        "octopus run — Execute a workload under deterministic Cedar + OS/Wasmtime + Egress Proxy containment\n\n\
         USAGE:\n\
         \x20 octopus run --policy <PATH> [--sandbox <strict|standard|wasm-strict>] [--wasm-promote] [--timeout <SECS>] [--cwd <DIR>] [--baseline-sbom <PATH> --sbom <PATH>] [--sbom-intent <patch|minor|refactor>] [--latent-weights <PATH>] [--json] -- <COMMAND> [ARGS...]\n\n\
         OPTIONS:\n\
         \x20 --policy <PATH>                        Path to .json or .cedar containment policy (required)\n\
         \x20 --sandbox <strict|standard|wasm-strict> OS/Wasmtime sandbox posture (default: standard; wasm-strict enforces Wasmtime when shield is active, else strict OS containment)\n\
         \x20 --wasm-promote                         Fail closed unless target is a .wasm/.wat guest when Virtual-Patch Shield is active\n\
         \x20 --timeout <SECS>                       Wall-clock timeout in seconds (0 disables timeout; default: policy or 60)\n\
         \x20 --cwd <DIR>                            Working directory for the contained workload\n\
         \x20 --baseline-sbom <PATH>                 Baseline CycloneDX SBOM JSON for pre-spawn Gate 1 diff\n\
         \x20 --sbom <PATH>                          Candidate CycloneDX SBOM JSON for pre-spawn Gate 1 diff\n\
         \x20 --sbom-intent <patch|minor|refactor>   Declared release intent for Gate 1 SBOM check (default: patch)\n\
         \x20 --latent-weights <PATH>                Custom UnifiedSecurityShield JSON weights file\n\
         \x20 --json                                 Emit a structured JSON containment summary\n\
         \x20 -h, --help                             Print this help message\n\n\
         NOTES:\n\
         \x20 - Fails closed with exit code 2 on missing/invalid policy, missing '--', or blocked pre-flight checks.\n\
         \x20 - Target .wasm / .wat files execute directly inside the Tier 1 Wasmtime sandbox."
    );
}

pub fn parse_octopus_cli(args: &[String]) -> CliParseResult {
    if args.len() <= 1 {
        return CliParseResult::Help;
    }

    let first = args[1].as_str();
    match first {
        "--help" | "-h" | "help" => return CliParseResult::Help,
        "--version" | "-V" => return CliParseResult::Version,
        "run" => {}
        "verify" | "--verify" | "--check" | "-v" | "status" | "protocols" | "hook"
        | "mcp-proxy" | "siquery" | "killswitch" | "isolate" | "engage" | "restore" | "disarm"
        | "service" | "--service" | "start" | "serve" | "ui" | "patch-kernel" | "kernel-patch"
        | "sbom-guard" | "latent-shield" | "abibo" => {
            return CliParseResult::Delegate(first.to_string())
        }
        other => {
            return CliParseResult::Invalid(format!("unknown subcommand or option '{}'", other));
        }
    }

    let rest = &args[2..];
    let sep_idx = rest.iter().position(|a| a == "--");
    let flag_slice = match sep_idx {
        Some(idx) => &rest[..idx],
        None => rest,
    };

    if flag_slice.iter().any(|a| a == "--help" || a == "-h") {
        return CliParseResult::RunHelp;
    }

    let mut policy_path: Option<PathBuf> = None;
    let mut sandbox = SandboxMode::Standard;
    let mut wasm_promote = false;
    let mut timeout_secs: Option<u64> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut json_output = false;
    let mut baseline_sbom: Option<PathBuf> = None;
    let mut sbom: Option<PathBuf> = None;
    let mut sbom_intent: Option<SbomIntent> = None;
    let mut latent_weights: Option<PathBuf> = None;

    let mut i = 0;
    while i < flag_slice.len() {
        let arg = flag_slice[i].as_str();
        if arg == "--policy" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--policy'".to_string());
            };
            if val.trim().is_empty() {
                return CliParseResult::Invalid("'--policy' value cannot be empty".to_string());
            }
            policy_path = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--policy=") {
            if val.trim().is_empty() {
                return CliParseResult::Invalid("'--policy' value cannot be empty".to_string());
            }
            policy_path = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--sandbox" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--sandbox'".to_string());
            };
            match parse_sandbox_mode(val) {
                Ok(mode) => sandbox = mode,
                Err(msg) => return CliParseResult::Invalid(msg),
            }
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--sandbox=") {
            match parse_sandbox_mode(val) {
                Ok(mode) => sandbox = mode,
                Err(msg) => return CliParseResult::Invalid(msg),
            }
            i += 1;
        } else if arg == "--timeout" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--timeout'".to_string());
            };
            match val.parse::<u64>() {
                Ok(secs) => timeout_secs = Some(secs),
                Err(_) => {
                    return CliParseResult::Invalid(format!(
                        "invalid '--timeout' value '{}': expected non-negative integer seconds",
                        val
                    ));
                }
            }
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--timeout=") {
            match val.parse::<u64>() {
                Ok(secs) => timeout_secs = Some(secs),
                Err(_) => {
                    return CliParseResult::Invalid(format!(
                        "invalid '--timeout' value '{}': expected non-negative integer seconds",
                        val
                    ));
                }
            }
            i += 1;
        } else if arg == "--cwd" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--cwd'".to_string());
            };
            if val.trim().is_empty() {
                return CliParseResult::Invalid("'--cwd' value cannot be empty".to_string());
            }
            cwd = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--cwd=") {
            if val.trim().is_empty() {
                return CliParseResult::Invalid("'--cwd' value cannot be empty".to_string());
            }
            cwd = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--baseline-sbom" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--baseline-sbom'".to_string());
            };
            if val.trim().is_empty() {
                return CliParseResult::Invalid(
                    "'--baseline-sbom' value cannot be empty".to_string(),
                );
            }
            baseline_sbom = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--baseline-sbom=") {
            if val.trim().is_empty() {
                return CliParseResult::Invalid(
                    "'--baseline-sbom' value cannot be empty".to_string(),
                );
            }
            baseline_sbom = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--sbom" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--sbom'".to_string());
            };
            if val.trim().is_empty() {
                return CliParseResult::Invalid("'--sbom' value cannot be empty".to_string());
            }
            sbom = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--sbom=") {
            if val.trim().is_empty() {
                return CliParseResult::Invalid("'--sbom' value cannot be empty".to_string());
            }
            sbom = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--sbom-intent" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--sbom-intent'".to_string());
            };
            match SbomIntent::parse(val) {
                Ok(intent) => sbom_intent = Some(intent),
                Err(e) => return CliParseResult::Invalid(e.to_string()),
            }
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--sbom-intent=") {
            match SbomIntent::parse(val) {
                Ok(intent) => sbom_intent = Some(intent),
                Err(e) => return CliParseResult::Invalid(e.to_string()),
            }
            i += 1;
        } else if arg == "--latent-weights" {
            let Some(val) = flag_slice.get(i + 1) else {
                return CliParseResult::Invalid("missing value for '--latent-weights'".to_string());
            };
            if val.trim().is_empty() {
                return CliParseResult::Invalid(
                    "'--latent-weights' value cannot be empty".to_string(),
                );
            }
            latent_weights = Some(PathBuf::from(val));
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--latent-weights=") {
            if val.trim().is_empty() {
                return CliParseResult::Invalid(
                    "'--latent-weights' value cannot be empty".to_string(),
                );
            }
            latent_weights = Some(PathBuf::from(val));
            i += 1;
        } else if arg == "--wasm-promote" {
            wasm_promote = true;
            i += 1;
        } else if arg == "--json" {
            json_output = true;
            i += 1;
        } else {
            return CliParseResult::Invalid(format!(
                "unknown or unexpected option '{}' before '--'",
                arg
            ));
        }
    }

    let Some(sep) = sep_idx else {
        return CliParseResult::Invalid(
            "missing '--' command separator before target <COMMAND>".to_string(),
        );
    };
    let Some(policy_path) = policy_path else {
        return CliParseResult::Invalid("missing required '--policy <PATH>' option".to_string());
    };
    let command: Vec<String> = rest[sep + 1..].to_vec();
    if command.is_empty() || command[0].trim().is_empty() {
        return CliParseResult::Invalid("missing target <COMMAND> after '--'".to_string());
    }

    CliParseResult::Run(OctopusRunArgs {
        policy_path,
        sandbox,
        wasm_promote,
        timeout_secs,
        cwd,
        json_output,
        baseline_sbom,
        sbom,
        sbom_intent,
        latent_weights,
        command,
    })
}

fn parse_sandbox_mode(val: &str) -> Result<SandboxMode, String> {
    match val.trim().to_ascii_lowercase().as_str() {
        "standard" => Ok(SandboxMode::Standard),
        "strict" => Ok(SandboxMode::Strict),
        "wasm-strict" => Ok(SandboxMode::WasmStrict),
        other => Err(format!(
            "invalid '--sandbox' value '{}': expected 'strict', 'standard', or 'wasm-strict'",
            other
        )),
    }
}

pub async fn dispatch_operational_subcommand(cli_args: &[String]) -> Option<i32> {
    if cli_args.len() < 2 {
        return None;
    }
    let first = cli_args[1].as_str();
    match first {
        "--verify" | "--check" | "-v" | "verify" => {
            println!("Executing 7-Phase Subsystem Self-Diagnostics (--verify)...");
            match crate::verify::SubsystemVerifier::run_all().await {
                Ok(report) => {
                    report.print_summary();
                    Some(0)
                }
                Err(e) => {
                    eprintln!("Verification failed: {}", e);
                    Some(1)
                }
            }
        }
        "status" => {
            let st = crate::security::global_host_killswitch().status();
            println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
            Some(0)
        }
        "protocols" => {
            let summary = crate::security::UniversalProtocolCatalog::catalog_json_summary();
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).unwrap_or_default()
            );
            Some(0)
        }
        "isolate" | "engage" => {
            match crate::security::global_host_killswitch()
                .engage("cli_operator", "Manual CLI host isolation")
            {
                Ok(st) => {
                    println!(
                        "Containment Engaged: {} (Level: {}, Hash: {})",
                        st.backend_engine, st.containment_level, st.state_hash
                    );
                    Some(0)
                }
                Err(e) => {
                    eprintln!("Containment Engagement Failed: {}", e);
                    Some(1)
                }
            }
        }
        "restore" | "disarm" => {
            match crate::security::global_host_killswitch()
                .disarm("cli_operator", "Manual CLI host restoration")
            {
                Ok(st) => {
                    println!(
                        "Disarm Successful (Level: {}, Hash: {})",
                        st.containment_level, st.state_hash
                    );
                    Some(0)
                }
                Err(e) => {
                    eprintln!("Disarm Failed: {}", e);
                    Some(1)
                }
            }
        }
        "service" | "--service" => {
            let action = cli_args.get(2).map(|s| s.as_str()).unwrap_or("status");
            match crate::service::handle_service_cli(action) {
                Ok(()) => Some(0),
                Err(_) => Some(1),
            }
        }
        "siquery" => {
            use crate::security::siquery::{SiqueryEngine, SiqueryOutputFormat};
            let query = cli_args.get(2).cloned().unwrap_or_else(|| {
                "SELECT pid, name, cmdline FROM processes LIMIT 10;".to_string()
            });
            match SiqueryEngine::new().execute_query_formatted(&query, SiqueryOutputFormat::Pretty)
            {
                Ok(out) => {
                    println!("{}", out);
                    Some(0)
                }
                Err(e) => {
                    eprintln!("Error executing query: {}", e);
                    Some(1)
                }
            }
        }
        "hook" => {
            if cli_args
                .iter()
                .skip(2)
                .any(|a| a == "--help" || a == "-h" || a == "help")
            {
                println!(
                    "octopus hook — Evaluate or install AI coding-agent RT-ASP hooks\n\n\
                     USAGE:\n\
                     \x20 octopus hook evaluate [--agent <claude|cursor|copilot|opencode|mcp>] [--event <NAME>] [--post]\n\
                     \x20 octopus hook install [--workspace <DIR>] [--agents <claude,cursor,copilot,opencode>]\n"
                );
                return Some(0);
            }
            let hook_sub = cli_args.get(2).map(|s| s.as_str()).unwrap_or("evaluate");
            if hook_sub == "install" {
                use crate::security::agent_hooks::{install_agent_hooks, SupportedAgentKind};
                let mut workspace_path =
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
                let mut agents = Vec::new();
                let mut i = 3;
                while i < cli_args.len() {
                    if cli_args[i] == "--workspace" || cli_args[i] == "-w" {
                        if let Some(w) = cli_args.get(i + 1) {
                            workspace_path = std::path::PathBuf::from(w);
                            i += 1;
                        }
                    } else if cli_args[i] == "--agents" || cli_args[i] == "-a" {
                        if let Some(a_list) = cli_args.get(i + 1) {
                            for a in a_list.split(',') {
                                if let Some(kind) = SupportedAgentKind::from_str(a.trim()) {
                                    agents.push(kind);
                                }
                            }
                            i += 1;
                        }
                    }
                    i += 1;
                }
                if agents.is_empty() {
                    agents = vec![
                        SupportedAgentKind::Claude,
                        SupportedAgentKind::Cursor,
                        SupportedAgentKind::Copilot,
                        SupportedAgentKind::OpenCode,
                    ];
                }
                let current_exe =
                    std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("octopus"));
                match install_agent_hooks(&workspace_path, &agents, &current_exe) {
                    Ok(configs) => {
                        println!(
                            "Installed AgentOctopus hooks across {} config(s):",
                            configs.len()
                        );
                        for c in configs {
                            println!("  - {}", c.display());
                        }
                        Some(0)
                    }
                    Err(e) => {
                        eprintln!("[octopus] error: failed to install agent hooks: {}", e);
                        Some(EXIT_SANDBOX_FAILURE)
                    }
                }
            } else if hook_sub == "evaluate" || hook_sub.starts_with('-') {
                use crate::security::agent_hooks::{
                    evaluate_hook_synchronously, format_claude_response, format_copilot_response,
                    format_cursor_response, format_mcp_error_response, format_opencode_response,
                    parse_claude_request, parse_copilot_request, parse_cursor_request,
                    parse_mcp_call_request, parse_opencode_request, SupportedAgentKind,
                };
                use std::io::{IsTerminal, Read};

                if cli_args.len() == 2 && std::io::stdin().is_terminal() {
                    println!(
                        "octopus hook — Evaluate or install AI coding-agent RT-ASP hooks\n\
                         Run 'octopus hook --help' for usage."
                    );
                    return Some(0);
                }

                let mut agent = SupportedAgentKind::Claude;
                let mut event_name = "PreToolUse".to_string();
                let mut is_post = false;
                let mut i = if hook_sub == "evaluate" { 3 } else { 2 };
                while i < cli_args.len() {
                    if cli_args[i] == "--agent" {
                        if let Some(a) = cli_args.get(i + 1) {
                            if let Some(k) = SupportedAgentKind::from_str(a) {
                                agent = k;
                            } else {
                                eprintln!(
                                    "[octopus] error: unknown hook agent '{}' (expected claude|cursor|copilot|opencode|mcp)",
                                    a
                                );
                                return Some(EXIT_PREFLIGHT_DENIED);
                            }
                            i += 1;
                        }
                    } else if cli_args[i] == "--event" {
                        if let Some(ev) = cli_args.get(i + 1) {
                            event_name = ev.clone();
                            if ev.eq_ignore_ascii_case("post")
                                || ev.to_ascii_lowercase().contains("after")
                            {
                                is_post = true;
                            }
                            i += 1;
                        }
                    } else if cli_args[i] == "--post" {
                        is_post = true;
                    }
                    i += 1;
                }

                let mut input = String::new();
                let _ = std::io::stdin().read_to_string(&mut input);

                let req = match agent {
                    SupportedAgentKind::Claude => parse_claude_request(&input, is_post),
                    SupportedAgentKind::Cursor => parse_cursor_request(&input, &event_name),
                    SupportedAgentKind::Copilot => parse_copilot_request(&input, &event_name),
                    SupportedAgentKind::OpenCode => parse_opencode_request(&input),
                    SupportedAgentKind::Mcp => parse_mcp_call_request(&input),
                };

                let req = match req {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[octopus] error parsing hook input: {}", e);
                        return Some(EXIT_SANDBOX_FAILURE);
                    }
                };

                let decision = evaluate_hook_synchronously(&req);
                let (exit_code, output) = match agent {
                    SupportedAgentKind::Claude => format_claude_response(&decision),
                    SupportedAgentKind::Cursor => format_cursor_response(&decision),
                    SupportedAgentKind::Copilot => format_copilot_response(&decision),
                    SupportedAgentKind::OpenCode => format_opencode_response(&decision),
                    SupportedAgentKind::Mcp => {
                        if decision.allowed {
                            (0, String::new())
                        } else {
                            let rpc_id = req.rpc_id.clone().unwrap_or(serde_json::Value::Null);
                            (0, format_mcp_error_response(&rpc_id, &decision))
                        }
                    }
                };

                if !output.is_empty() {
                    println!("{}", output);
                }
                Some(exit_code)
            } else {
                eprintln!(
                    "[octopus] error: unknown hook subcommand '{}'\nRun 'octopus hook --help' for usage.",
                    hook_sub
                );
                Some(EXIT_PREFLIGHT_DENIED)
            }
        }
        "killswitch" => {
            let sub = cli_args.get(2).map(|s| s.as_str()).unwrap_or("status");
            match sub {
                "--help" | "-h" | "help" => {
                    println!("USAGE: octopus killswitch [status|isolate|engage|restore|disarm|protocols]");
                    Some(0)
                }
                "status" => {
                    let st = crate::security::global_host_killswitch().status();
                    println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
                    Some(0)
                }
                "isolate" | "engage" => {
                    match crate::security::global_host_killswitch()
                        .engage("cli_operator", "Manual CLI host isolation")
                    {
                        Ok(st) => {
                            println!(
                                "Containment Engaged: {} (Level: {}, Hash: {})",
                                st.backend_engine, st.containment_level, st.state_hash
                            );
                            Some(0)
                        }
                        Err(e) => {
                            eprintln!("Containment Engagement Failed: {}", e);
                            Some(EXIT_SANDBOX_FAILURE)
                        }
                    }
                }
                "restore" | "disarm" => {
                    match crate::security::global_host_killswitch()
                        .disarm("cli_operator", "Manual CLI host restoration")
                    {
                        Ok(st) => {
                            println!(
                                "Disarm Successful (Level: {}, Hash: {})",
                                st.containment_level, st.state_hash
                            );
                            Some(0)
                        }
                        Err(e) => {
                            eprintln!("Disarm Failed: {}", e);
                            Some(EXIT_SANDBOX_FAILURE)
                        }
                    }
                }
                "protocols" => {
                    let summary = crate::security::UniversalProtocolCatalog::catalog_json_summary();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&summary).unwrap_or_default()
                    );
                    Some(0)
                }
                other => {
                    eprintln!(
                        "[octopus] error: unknown killswitch action '{}' (expected status|isolate|restore|protocols)",
                        other
                    );
                    Some(EXIT_PREFLIGHT_DENIED)
                }
            }
        }
        "start" | "serve" | "ui" => {
            if cli_args.iter().skip(2).any(|a| a == "--help" || a == "-h") {
                println!("USAGE: octopus {} [--port <PORT>] [--open-browser]", first);
                return Some(0);
            }
            let open_browser_requested = cli_args
                .iter()
                .any(|a| a == "--open-browser" || a == "--browser");
            let mut preferred_port: u16 = 3030;
            for i in 2..cli_args.len() {
                if (cli_args[i] == "--port" || cli_args[i] == "-p") && i + 1 < cli_args.len() {
                    if let Ok(p) = cli_args[i + 1].parse::<u16>() {
                        if p != 0 && p != 5000 {
                            preferred_port = p;
                        }
                    }
                } else if let Some(val) = cli_args[i].strip_prefix("--port=") {
                    if let Ok(p) = val.parse::<u16>() {
                        if p != 0 && p != 5000 {
                            preferred_port = p;
                        }
                    }
                }
            }
            let selected_port = crate::web::select_available_loopback_port(preferred_port);
            let addr = format!("127.0.0.1:{}", selected_port);
            if open_browser_requested {
                let bootstrap_nonce = crate::web::request_guard::issue_bootstrap_nonce();
                let url_for_browser = format!(
                    "http://127.0.0.1:{}/?bootstrap={}",
                    selected_port, bootstrap_nonce
                );
                tokio::spawn(async move {
                    tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
                    #[cfg(target_os = "windows")]
                    {
                        let mut explorer = std::process::Command::new("explorer");
                        explorer.arg(&url_for_browser);
                        let _ = crate::security::spawn_hidden(&mut explorer, "cli: open dashboard");
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        let _ = std::process::Command::new("xdg-open")
                            .arg(&url_for_browser)
                            .spawn();
                    }
                });
            }
            println!(
                "Starting AgentOctopus Web Dashboard on {} (headless: {})...",
                addr, !open_browser_requested
            );
            match crate::web::start_web_server(&addr).await {
                Ok(()) => Some(0),
                Err(e) => {
                    eprintln!("[octopus] Web server failed: {}", e);
                    Some(EXIT_SANDBOX_FAILURE)
                }
            }
        }
        "sbom-guard" | "latent-shield" => {
            let sub_args = cli_args.get(2..).unwrap_or(&[]);
            Some(crate::cli::latent_shield::execute_sbom_guard_cli(sub_args))
        }
        "patch-kernel" | "kernel-patch" => {
            let sub_args = cli_args.get(2..).unwrap_or(&[]);
            let parsed = match crate::security::kernel_patcher::parse_patch_kernel_args(sub_args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[octopus] error: {}", e);
                    return Some(EXIT_PREFLIGHT_DENIED);
                }
            };
            match crate::security::kernel_patcher::execute_patch_kernel_cli(&parsed).await {
                Ok(()) => Some(0),
                Err(e) => {
                    eprintln!("[octopus] error: {}", e);
                    Some(EXIT_SANDBOX_FAILURE)
                }
            }
        }
        "abibo" => {
            let sub_args = cli_args.get(2..).unwrap_or(&[]);
            Some(execute_abibo_cli(sub_args))
        }
        "mcp-proxy" => {
            use crate::security::abibo_physics::{
                AbiboMediationCoordinator, McpMediationRequest, NonHumanIdentityRecord,
            };
            use crate::security::agent_hooks::{
                evaluate_hook_synchronously, format_mcp_error_response, parse_mcp_call_request,
                HookEvaluationDecision,
            };
            use std::io::{BufRead, Write};

            let abibo = AbiboMediationCoordinator::default();
            abibo.register_nhi(NonHumanIdentityRecord {
                nhi_id: "mcp_stdio_session".to_string(),
                sponsor_human: "local_operator".to_string(),
                provider: "mcp_stdio_proxy".to_string(),
                allowed_tools: vec!["*".to_string()],
                write_capable: true,
                half_life_secs: Some(300),
                revoked: false,
                revoked_reason: None,
                created_at_unix: crate::security::artemis_dfir::unix_now_secs(),
            });

            let stdin = std::io::stdin();
            let mut stdout = std::io::stdout();
            for line in stdin.lock().lines() {
                let Ok(line) = line else {
                    break;
                };
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(req) = parse_mcp_call_request(&line) {
                    let decision = evaluate_hook_synchronously(&req);
                    if !decision.allowed {
                        let rpc_id = req.rpc_id.clone().unwrap_or(serde_json::Value::Null);
                        let resp = format_mcp_error_response(&rpc_id, &decision);
                        let _ = writeln!(stdout, "{}", resp);
                        let _ = stdout.flush();
                        continue;
                    }

                    let tool_name = req
                        .tool_name
                        .clone()
                        .unwrap_or_else(|| "unknown_tool".to_string());
                    let tool_lower = tool_name.to_ascii_lowercase();
                    let is_write = tool_lower.contains("write")
                        || tool_lower.contains("send")
                        || tool_lower.contains("delete")
                        || tool_lower.contains("post")
                        || tool_lower.contains("exec")
                        || tool_lower.contains("shell")
                        || tool_lower.contains("run")
                        || tool_lower.contains("modify");
                    let args_str = req
                        .arguments
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "{}".to_string());
                    let epoch = abibo.liveness().current_epoch();
                    let med = abibo.mediate(&McpMediationRequest {
                        nhi_id: req
                            .session_id
                            .clone()
                            .unwrap_or_else(|| "mcp_stdio_session".to_string()),
                        server_name: "mcp_stdio".to_string(),
                        tool_name,
                        arguments_json: args_str,
                        is_write_or_mutating: is_write,
                        touches_private_data: tool_lower.contains("mail")
                            || tool_lower.contains("calendar")
                            || tool_lower.contains("secret")
                            || tool_lower.contains("cred"),
                        external_egress: tool_lower.contains("http")
                            || tool_lower.contains("fetch")
                            || tool_lower.contains("send")
                            || tool_lower.contains("post"),
                        privilege_escalation_risk: tool_lower.contains("exec")
                            || tool_lower.contains("shell")
                            || tool_lower.contains("sudo"),
                        persistence_risk: tool_lower.contains("cron")
                            || tool_lower.contains("task")
                            || tool_lower.contains("registry")
                            || tool_lower.contains("memory"),
                        d_trust: if is_write { 1.5 } else { 0.5 },
                        request_epoch: epoch,
                        request_ts_unix: None,
                        capability_token: None,
                        tool_manifest: None,
                    });
                    if !med.allowed {
                        let rpc_id = req.rpc_id.clone().unwrap_or(serde_json::Value::Null);
                        let abibo_dec = HookEvaluationDecision {
                            allowed: false,
                            rationale: format!(
                                "[ABIBO 7-Law Physics Gateway: {}] {}",
                                med.decision.as_str(),
                                med.reason
                            ),
                            denied_by_layer: Some(med.triggered_laws.join(",")),
                            remediation: Some(
                                "Approve via out-of-band HITL queue or unlock human workstation session."
                                    .to_string(),
                            ),
                            duration_us: 0,
                        };
                        let resp = format_mcp_error_response(&rpc_id, &abibo_dec);
                        let _ = writeln!(stdout, "{}", resp);
                        let _ = stdout.flush();
                        continue;
                    }
                }
                let _ = writeln!(stdout, "{}", line);
                let _ = stdout.flush();
            }
            Some(0)
        }
        other => {
            eprintln!(
                "[octopus] error: unhandled subcommand '{}'\nRun 'octopus --help' for usage.",
                other
            );
            Some(EXIT_PREFLIGHT_DENIED)
        }
    }
}

/// Executes `octopus abibo <subcommand>` for 7-Law Physics ABIBO & Artemis DFIR operations.
pub fn execute_abibo_cli(sub_args: &[String]) -> i32 {
    use crate::security::abibo_physics::AbiboMediationCoordinator;

    let action = sub_args.first().map(|s| s.as_str()).unwrap_or("status");
    match action {
        "--help" | "-h" | "help" => {
            println!(
                "octopus abibo — 7-Law Physics ABIBO Containment & Artemis DFIR Forensics\n\n\
                 USAGE:\n\
                 \x20 octopus abibo status                      Show live 7-Law physics & liveness posture (JSON)\n\
                 \x20 octopus abibo scan-forensics              Run native cross-OS Artemis DFIR sweep + Cedar synthesis\n\
                 \x20 octopus abibo artemis-toml [--out <DIR>]  Print valid puffyCid/artemis v0.21 TOML recipe\n\
                 \x20 octopus abibo ingest-artemis <PATH>       Ingest Artemis v0.21 JSONL/JSON & compile Cedar forbid rules\n\
                 \x20 octopus abibo simulate-grok               Run NewCore 31-request overnight xAI Grok attack simulation\n\
                 \x20 octopus abibo analyze-perplexity --text <TEXT> Analyze text with 4-Layer Perplexity + LRL Translation Pivot\n\
                 \x20 octopus abibo perplexity-config           Show active perplexity/semantic-entropy thresholds & NMT health\n\
                 \x20 octopus abibo set-perplexity-preset <P>   Apply & save preset (balanced|strict-defense|code-heavy-dev|multilingual-research)\n\
                 \x20 octopus abibo probe-nmt                   Probe local loopback Seq2Seq NMT container (<=400ms)\n\
                 \x20 octopus abibo lock-workstation            Trigger Spacetime Event Horizon (epoch N -> N + 1)\n\
                 \x20 octopus abibo unlock-workstation          Unlock workstation under fresh human session epoch"
            );
            0
        }
        "status" => {
            let coord = AbiboMediationCoordinator::default();
            let snap = coord.status_snapshot();
            println!(
                "{}",
                serde_json::to_string_pretty(&snap).unwrap_or_default()
            );
            0
        }
        "scan-forensics" => {
            let coord = AbiboMediationCoordinator::default();
            let report = coord.artemis_engine().run_native_collection();
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            0
        }
        "artemis-toml" => {
            let out_dir = sub_args
                .windows(2)
                .find(|w| w[0] == "--out" || w[0] == "--out-dir")
                .map(|w| w[1].as_str())
                .unwrap_or("./artemis_abibo_out");
            let coord = AbiboMediationCoordinator::default();
            println!("{}", coord.artemis_engine().export_artemis_toml(out_dir));
            0
        }
        "ingest-artemis" => {
            let Some(path_str) = sub_args.get(1) else {
                eprintln!("[octopus] error: missing <PATH> for 'abibo ingest-artemis'");
                return EXIT_PREFLIGHT_DENIED;
            };
            let coord = AbiboMediationCoordinator::default();
            match coord
                .artemis_engine()
                .ingest_external_artemis_file(std::path::Path::new(path_str), &[])
            {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("[octopus] error ingesting Artemis export: {e}");
                    EXIT_SANDBOX_FAILURE
                }
            }
        }
        "simulate-grok" => {
            let report = AbiboMediationCoordinator::simulate_newcore_grok_overnight_attack();
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            0
        }
        "analyze-perplexity" => {
            let text = sub_args
                .windows(2)
                .find(|w| w[0] == "--text" || w[0] == "-t")
                .map(|w| w[1].clone())
                .or_else(|| sub_args.get(1).filter(|s| !s.starts_with('-')).cloned());
            let Some(payload) = text else {
                eprintln!("[octopus] error: missing --text <TEXT> for 'abibo analyze-perplexity'");
                return EXIT_PREFLIGHT_DENIED;
            };
            let coord = AbiboMediationCoordinator::default();
            let report = coord.perplexity_defense().analyze_text(&payload, true);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            if report.allowed {
                0
            } else {
                EXIT_PREFLIGHT_DENIED
            }
        }
        "perplexity-config" => {
            let coord = AbiboMediationCoordinator::default();
            let payload = serde_json::json!({
                "config": coord.perplexity_defense().tuning_config(),
                "nmt_health": coord.perplexity_defense().probe_nmt_health(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            0
        }
        "set-perplexity-preset" => {
            use crate::security::abibo_physics::{
                PerplexityTuningConfig, PerplexityWorkloadPreset,
            };
            let Some(preset_arg) = sub_args.get(1) else {
                eprintln!(
                    "[octopus] error: missing <PRESET> (balanced|strict-defense|code-heavy-dev|multilingual-research)"
                );
                return EXIT_PREFLIGHT_DENIED;
            };
            let Some(preset) = PerplexityWorkloadPreset::from_str_loose(preset_arg) else {
                eprintln!("[octopus] error: unknown perplexity preset '{preset_arg}'");
                return EXIT_PREFLIGHT_DENIED;
            };
            let coord = AbiboMediationCoordinator::default();
            let current = coord.perplexity_defense().tuning_config();
            let mut next = PerplexityTuningConfig::for_preset(preset);
            next.local_nmt_url = current.local_nmt_url;
            next.enable_local_ollama_fallback = current.enable_local_ollama_fallback;
            match coord
                .perplexity_defense()
                .update_tuning_config(next, Some(coord.workspace_root()))
            {
                Ok(saved) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&saved).unwrap_or_default()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("[octopus] error saving perplexity preset: {e}");
                    EXIT_SANDBOX_FAILURE
                }
            }
        }
        "probe-nmt" => {
            let coord = AbiboMediationCoordinator::default();
            let health = coord.perplexity_defense().probe_nmt_health();
            println!(
                "{}",
                serde_json::to_string_pretty(&health).unwrap_or_default()
            );
            if health.reachable {
                0
            } else {
                1
            }
        }
        "lock-workstation" => {
            let coord = AbiboMediationCoordinator::default();
            let snap = coord
                .liveness()
                .trigger_event_horizon("cli_manual_workstation_lock");
            println!(
                "{}",
                serde_json::to_string_pretty(&snap).unwrap_or_default()
            );
            0
        }
        "unlock-workstation" => {
            let coord = AbiboMediationCoordinator::default();
            let snap = coord.liveness().unlock_workstation();
            println!(
                "{}",
                serde_json::to_string_pretty(&snap).unwrap_or_default()
            );
            0
        }
        other => {
            eprintln!(
                "[octopus] error: unknown abibo subcommand '{}'\nRun 'octopus abibo --help' for usage.",
                other
            );
            EXIT_PREFLIGHT_DENIED
        }
    }
}
