use crate::cli::policy::LoadedOctopusPolicy;
use crate::cli::{EXIT_PREFLIGHT_DENIED, EXIT_SANDBOX_FAILURE, EXIT_TIMEOUT};
use crate::core::circuit_breaker::KillSwitch;
use crate::core::types::OctopusSecurityError;
use crate::security::wasm_tier1::{WasmExecutionReceipt, WasmSandboxLimits, WasmTier1Executor};
use std::io::{IsTerminal, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

pub fn is_wasm_or_wat_target(program: &str) -> bool {
    let lower = program.trim().to_ascii_lowercase();
    lower.ends_with(".wasm") || lower.ends_with(".wat")
}

pub struct WasmRunOutcome {
    pub exit_code: i32,
    pub timed_out: bool,
    pub receipt: Option<WasmExecutionReceipt>,
    pub diagnostic: Option<String>,
}

pub async fn execute_wasm_target(
    target_path: &Path,
    args: &[String],
    cwd: &Path,
    policy: &LoadedOctopusPolicy,
    timeout_secs: u64,
    json_output: bool,
) -> Result<WasmRunOutcome, (i32, String)> {
    if !target_path.is_file() {
        return Err((
            EXIT_PREFLIGHT_DENIED,
            format!(
                "blocked_by_octopus_policy: wasm/wat target '{}' does not exist",
                target_path.display()
            ),
        ));
    }

    let bytes = std::fs::read(target_path).map_err(|e| {
        (
            EXIT_PREFLIGHT_DENIED,
            format!(
                "blocked_by_octopus_policy: failed to read '{}': {}",
                target_path.display(),
                e
            ),
        )
    })?;

    let tool_name = target_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("wasm_guest")
        .to_string();

    let memory_bytes = policy
        .json_policy
        .limits
        .memory_mb
        .unwrap_or(64)
        .saturating_mul(1024 * 1024)
        .clamp(64 * 1024, 64 * 1024 * 1024);

    let fuel_budget = policy.json_policy.limits.wasm_fuel.unwrap_or(2_000_000);
    let allow_scratch_write = !policy.json_policy.filesystem.allow_write.is_empty();

    let limits = WasmSandboxLimits {
        fuel_budget,
        max_linear_memory_bytes: memory_bytes,
        scratchpad_root: cwd.to_path_buf(),
        allow_scratch_write,
        ..WasmSandboxLimits::default()
    };

    let args_vec = args.to_vec();

    let res = tokio::task::spawn_blocking(
        move || -> Result<WasmExecutionReceipt, OctopusSecurityError> {
            let cold_start_begin = Instant::now();
            let executor = WasmTier1Executor::try_new()?;
            let module = wasmtime::Module::new(executor.engine(), &bytes).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_COMPILE_REJECTED [{}]: {}",
                    tool_name, e
                ))
            })?;

            let needs_stdin = module.imports().any(|imp| {
                imp.module() == "octopus_wasi"
                    && (imp.name() == "input_len" || imp.name() == "read_input")
            });
            let has_forbidden_import = module.imports().any(|imp| imp.module() != "octopus_wasi");

            let deadline = if timeout_secs > 0 {
                Some(Instant::now() + Duration::from_secs(timeout_secs))
            } else {
                None
            };

            let input_bytes = if !args_vec.is_empty() {
                args_vec.join("\n").into_bytes()
            } else if !needs_stdin || has_forbidden_import || std::io::stdin().is_terminal() {
                Vec::new()
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>();
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = std::io::stdin().take(1024 * 1024).read_to_end(&mut buf);
                    let _ = tx.send(buf);
                });
                if let Some(dl) = deadline {
                    let remaining = dl.saturating_duration_since(Instant::now());
                    match rx.recv_timeout(remaining) {
                        Ok(buf) => buf,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            return Err(OctopusSecurityError::LimbKilled);
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => Vec::new(),
                    }
                } else {
                    rx.recv().unwrap_or_default()
                }
            };

            let ks = KillSwitch::new();
            executor.attach_killswitch(&ks);

            let done = Arc::new(AtomicBool::new(false));
            let timer_handle = deadline.map(|dl| {
                let ks_clone = ks.clone();
                let done_clone = done.clone();
                std::thread::spawn(move || {
                    let step = Duration::from_millis(20);
                    while Instant::now() < dl {
                        if done_clone.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(step);
                    }
                    if !done_clone.load(Ordering::Relaxed) {
                        ks_clone.trip();
                    }
                })
            });

            let exec_res = executor.execute_compiled_module_with_context(
                &tool_name,
                &module,
                &input_bytes,
                limits,
                None,
                cold_start_begin,
            );
            done.store(true, Ordering::Relaxed);
            if let Some(h) = timer_handle {
                let _ = h.join();
            }
            if ks.is_tripped() && exec_res.is_err() {
                return Err(OctopusSecurityError::LimbKilled);
            }
            exec_res
        },
    )
    .await
    .map_err(|e| {
        (
            EXIT_SANDBOX_FAILURE,
            format!("blocked_by_octopus_policy: Wasmtime worker panicked: {}", e),
        )
    })?;

    match res {
        Ok(receipt) => {
            if !json_output && !receipt.raw_output.is_empty() {
                print!("{}", receipt.raw_output);
            }
            Ok(WasmRunOutcome {
                exit_code: receipt.exit_code,
                timed_out: false,
                receipt: Some(receipt),
                diagnostic: None,
            })
        }
        Err(OctopusSecurityError::LimbKilled) => {
            let msg = format!(
                "blocked_by_octopus_policy: Wasmtime epoch KillSwitch terminated '{}' after {}s timeout",
                target_path.display(),
                timeout_secs
            );
            if !json_output {
                eprintln!("[octopus] DENY wasm: {}", msg);
            }
            Ok(WasmRunOutcome {
                exit_code: EXIT_TIMEOUT,
                timed_out: true,
                receipt: None,
                diagnostic: Some(msg),
            })
        }
        Err(e) => {
            let msg = format!(
                "blocked_by_octopus_policy: Wasmtime Tier 1 containment violation: {}",
                e
            );
            if !json_output {
                eprintln!("[octopus] DENY wasm: {}", msg);
            }
            Ok(WasmRunOutcome {
                exit_code: EXIT_SANDBOX_FAILURE,
                timed_out: false,
                receipt: None,
                diagnostic: Some(msg),
            })
        }
    }
}
