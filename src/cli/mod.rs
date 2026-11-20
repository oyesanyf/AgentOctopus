pub mod policy;
pub mod proxy;
pub mod run;
pub mod wasm_runner;

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
}

impl SandboxMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxMode::Standard => "standard",
            SandboxMode::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OctopusRunArgs {
    pub policy_path: PathBuf,
    pub sandbox: SandboxMode,
    pub timeout_secs: Option<u64>,
    pub cwd: Option<PathBuf>,
    pub json_output: bool,
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
         \x20 octopus run --policy <PATH> [--sandbox <strict|standard>] [--timeout <SECS>] [--cwd <DIR>] [--json] -- <COMMAND> [ARGS...]\n\n\
         OPTIONS:\n\
         \x20 --policy <PATH>            Path to .json or .cedar containment policy (required)\n\
         \x20 --sandbox <strict|standard> OS sandbox posture (default: standard)\n\
         \x20 --timeout <SECS>           Wall-clock timeout in seconds (0 disables timeout; default: policy or 60)\n\
         \x20 --cwd <DIR>                Working directory for the contained workload\n\
         \x20 --json                     Emit a structured JSON containment summary\n\
         \x20 -h, --help                 Print this help message\n\n\
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
        | "service" | "--service" | "start" | "serve" | "ui" | "patch-kernel" | "kernel-patch" => {
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
    let mut timeout_secs: Option<u64> = None;
    let mut cwd: Option<PathBuf> = None;
    let mut json_output = false;

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
        timeout_secs,
        cwd,
        json_output,
        command,
    })
}

fn parse_sandbox_mode(val: &str) -> Result<SandboxMode, String> {
    match val.trim().to_ascii_lowercase().as_str() {
        "standard" => Ok(SandboxMode::Standard),
        "strict" => Ok(SandboxMode::Strict),
        other => Err(format!(
            "invalid '--sandbox' value '{}': expected 'strict' or 'standard'",
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
        "mcp-proxy" => {
            use crate::security::agent_hooks::{
                evaluate_hook_synchronously, format_mcp_error_response, parse_mcp_call_request,
            };
            use std::io::{BufRead, Write};
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
                }
                let _ = writeln!(stdout, "{}", line);
                let _ = stdout.flush();
            }
            Some(0)
        }
        _ => None,
    }
}
