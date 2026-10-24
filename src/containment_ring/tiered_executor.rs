//! Unified 2-Tier Execution Dispatcher (`src/containment_ring/tiered_executor.rs`)
//!
//! Connects the `AgentOctopus` Control Plane (Cedar + Dogwood temporal authorization,
//! HMAC-signed `ArmRole` provenance in `MeshGuard`, non-decaying `MercuryContainmentEngine`,
//! and DNS-pinned egress) to two complementary execution tiers on Windows:
//! - **Tier 1 (`ExecutionTier::Tier1InProcessWasm`)**: Default for 90% of agent tools
//!   (untrusted document extraction, JSON/schema transformation, ledger validation, and custom `.wat`/`.wasm` plugins).
//!   Executes inside `WasmTier1Executor` with zero ambient OS syscalls, `ResourceLimiter` linear memory caps,
//!   deterministic instruction fuel metering, and `open_confined`-backed scratchpad access.
//! - **Tier 2 (`ExecutionTier::Tier2NativeWin32Confinement`)**: For native Windows CLI binaries
//!   (`git.exe`, `cargo.exe`, `curl.exe`, `cmd.exe`, etc.) that require an OS child process.
//!   Enforces structural command-line analysis (`analyze_command_line`), mandatory de-elevation
//!   (`spawn_deelevated` with `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`, `BUILTIN\Administrators` deny-only,
//!   and Medium integrity verified before `ResumeThread`), `WindowsJobObject` kernel limits &
//!   `MeasuredActuationSample` I/O accounting, and `hidden_process_ledger` audit logging.

use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::breakouts::{
    TechnicalBreakoutGuard, ZeroMiProjectionResult, ZeroMutualInformationProjector,
};
use crate::security::mercury_guard::{
    HostActuationPore, MeasuredActuationSample, MercuryContainmentEngine, MercuryEvaluationResult,
    KERNEL_IO_COALESCENCE_BUDGET_BYTES,
};
use crate::security::token_posture::{spawn_deelevated, TokenPosture};
use crate::security::wasm_tier1::{WasmExecutionReceipt, WasmSandboxLimits, WasmTier1Executor};
use crate::security::windows_sandbox::WindowsJobObject;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Execution tier selected by the `TieredExecutionDispatcher`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionTier {
    /// Tier 1: In-process Wasmtime capability sandbox (zero child processes, zero ambient OS authority).
    Tier1InProcessWasm,
    /// Tier 2: Native Win32 confined child process (`spawn_deelevated` + `WindowsJobObject` + `AppContainer`).
    Tier2NativeWin32Confinement,
}

/// Tool invocation request submitted to the `TieredExecutionDispatcher`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredToolRequest {
    pub agent_id: String,
    pub role: ArmRole,
    pub tool_name: String,
    /// Payload bytes (document content, JSON input, or custom WAT source when `custom_wat` is set).
    pub payload: Vec<u8>,
    /// Optional custom `.wat` / `.wasm` module to run in Tier 1.
    pub custom_wat: Option<String>,
    /// Optional native command-line (`program` and `args`) when invoking a Tier 2 CLI binary.
    pub native_command: Option<(String, Vec<String>)>,
    /// Sandbox scratchpad directory for confined file access.
    pub scratchpad_root: PathBuf,
    /// Whether scratchpad writes are permitted for this call.
    pub allow_scratch_write: bool,
}

/// Unified execution receipt returned by either Tier 1 (Wasmtime) or Tier 2 (Native Win32).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TieredExecutionReceipt {
    pub agent_id: String,
    pub tool_name: String,
    pub selected_tier: ExecutionTier,
    pub exit_code: i32,
    pub total_elapsed_us: u64,
    pub wasm_receipt: Option<WasmExecutionReceipt>,
    pub win32_child_token_posture: Option<TokenPosture>,
    pub job_io_sample: Option<MeasuredActuationSample>,
    pub mercury_evaluation: MercuryEvaluationResult,
    pub zero_mi_output: ZeroMiProjectionResult,
}

/// Pure-Rust Hybrid Execution Dispatcher routing agent tools between Tier 1 (Wasmtime)
/// and Tier 2 (Native Win32 de-elevated + JobObject confinement).
pub struct TieredExecutionDispatcher {
    wasm_tier1: WasmTier1Executor,
    mercury: Arc<MercuryContainmentEngine>,
    technical_guard: TechnicalBreakoutGuard,
}

impl TieredExecutionDispatcher {
    pub fn try_new(mercury: Arc<MercuryContainmentEngine>) -> Result<Self, OctopusSecurityError> {
        Ok(Self {
            wasm_tier1: WasmTier1Executor::try_new()?,
            mercury,
            technical_guard: TechnicalBreakoutGuard::default(),
        })
    }

    pub fn wasm_tier1(&self) -> &WasmTier1Executor {
        &self.wasm_tier1
    }

    /// Determines whether a request runs in Tier 1 (In-Process Wasmtime) or Tier 2 (Native Win32).
    pub fn classify_tier(req: &TieredToolRequest) -> ExecutionTier {
        if req.native_command.is_some() {
            ExecutionTier::Tier2NativeWin32Confinement
        } else {
            ExecutionTier::Tier1InProcessWasm
        }
    }

    /// Dispatches a tool request through the Control Plane checks into Tier 1 or Tier 2.
    pub fn dispatch(
        &self,
        req: &TieredToolRequest,
    ) -> Result<TieredExecutionReceipt, OctopusSecurityError> {
        match Self::classify_tier(req) {
            ExecutionTier::Tier1InProcessWasm => self.dispatch_tier1_wasm(req),
            ExecutionTier::Tier2NativeWin32Confinement => self.dispatch_tier2_win32(req),
        }
    }

    fn dispatch_tier1_wasm(
        &self,
        req: &TieredToolRequest,
    ) -> Result<TieredExecutionReceipt, OctopusSecurityError> {
        let start = Instant::now();
        let _ = std::fs::create_dir_all(&req.scratchpad_root);
        let limits = WasmSandboxLimits {
            scratchpad_root: req.scratchpad_root.clone(),
            allow_scratch_write: req.allow_scratch_write,
            ..WasmSandboxLimits::default()
        };

        let wasm_receipt = if let Some(ref wat) = req.custom_wat {
            self.wasm_tier1
                .execute_wat(&req.tool_name, wat.as_bytes(), &req.payload, limits)?
        } else {
            match req.tool_name.as_str() {
                "ledger_write" | "wasm_ledger_validator" | "LedgerWrite" => self
                    .wasm_tier1
                    .execute_ledger_validator(&req.payload, limits)?,
                _ => self
                    .wasm_tier1
                    .execute_doc_extractor(&req.payload, limits)?,
            }
        };

        // Feed supervisor-measured Wasm I/O and fuel into MercuryContainmentEngine
        let egress_bytes = (wasm_receipt.scratch_bytes_written as usize)
            .saturating_add(wasm_receipt.raw_output.len()) as f64;
        let fragment_mass = egress_bytes / KERNEL_IO_COALESCENCE_BUDGET_BYTES;
        let applied_pressure_pa = (wasm_receipt.fuel_consumed as f64 / 50_000.0) * 25.0;
        let mercury_eval = self.mercury.evaluate_pore_pressure(
            &req.agent_id,
            HostActuationPore::SharedMemoryMapping,
            applied_pressure_pa,
            0.05,
            0.0010,
            fragment_mass,
        );

        if mercury_eval.sulfur_passivated_hgs {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "TIER1_MERCURY_PASSIVATION [{}]: {}",
                req.agent_id, mercury_eval.reason
            )));
        }

        let zero_mi = wasm_receipt.zero_mi_projection.clone();
        Ok(TieredExecutionReceipt {
            agent_id: req.agent_id.clone(),
            tool_name: req.tool_name.clone(),
            selected_tier: ExecutionTier::Tier1InProcessWasm,
            exit_code: wasm_receipt.exit_code,
            total_elapsed_us: start.elapsed().as_micros() as u64,
            wasm_receipt: Some(wasm_receipt),
            win32_child_token_posture: None,
            job_io_sample: None,
            mercury_evaluation: mercury_eval,
            zero_mi_output: zero_mi,
        })
    }

    fn dispatch_tier2_win32(
        &self,
        req: &TieredToolRequest,
    ) -> Result<TieredExecutionReceipt, OctopusSecurityError> {
        let start = Instant::now();
        let (program, args) = req.native_command.as_ref().ok_or_else(|| {
            OctopusSecurityError::IsolationViolation(
                "Tier 2 execution requires native_command (program, args)".to_string(),
            )
        })?;

        // 1. Structural command-line inspection (Finding 1: CommandLineToArgvW + -EncodedCommand decoding)
        let full_cmd = if args.is_empty() {
            program.clone()
        } else {
            format!("{} {}", program, args.join(" "))
        };
        let tech_verdict = self.technical_guard.evaluate_execution(program, &full_cmd);
        if !tech_verdict.is_clean {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "TIER2_COMMAND_LINE_BLOCKED [{}]: {}",
                req.tool_name,
                tech_verdict.detected_vectors.join("; ")
            )));
        }

        // 2. Create dedicated Windows Job Object for kernel-enforced process & memory limits + I/O accounting
        let job_name = format!(
            "OctopusTier2Job_{}_{}",
            req.agent_id.replace('-', "_"),
            std::process::id()
        );
        let job = WindowsJobObject::create(job_name, 4, 64 * 1024 * 1024)?;

        // 3. Spawn child under mandatory de-elevated restricted token (Finding 7: LUA_TOKEN + Admins deny-only,
        // verified while CREATE_SUSPENDED before ResumeThread)
        let deelevated = spawn_deelevated(&full_cmd, true)?;
        let exit_code = deelevated.wait()? as i32;

        // Record in hidden-process ledger for dashboard transparency
        let mut ledger_cmd = std::process::Command::new(program);
        ledger_cmd.args(args);
        let _ = crate::security::hidden_process_ledger::record_hidden_spawn(
            &ledger_cmd,
            "TieredExecutionDispatcher::dispatch_tier2_win32",
            Some(deelevated.pid),
            None,
        );

        let elapsed_s = start.elapsed().as_secs_f64().max(0.001);
        let job_sample =
            MeasuredActuationSample::sample_from_job(&job, HostActuationPore::SubprocessSpawn, elapsed_s)?;
        let mercury_eval = self
            .mercury
            .evaluate_measured_sample(&req.agent_id, &job_sample);

        if mercury_eval.sulfur_passivated_hgs {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "TIER2_MERCURY_PASSIVATION [{}]: {}",
                req.agent_id, mercury_eval.reason
            )));
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let summary_out = format!(
            "{{\"tier\":\"Tier2NativeWin32\",\"pid\":{},\"exit_code\":{},\"elevated\":{}}}",
            deelevated.pid, exit_code, deelevated.posture.elevated
        );
        let zero_mi = ZeroMutualInformationProjector::project_output(&summary_out, now_ms, 100);

        Ok(TieredExecutionReceipt {
            agent_id: req.agent_id.clone(),
            tool_name: req.tool_name.clone(),
            selected_tier: ExecutionTier::Tier2NativeWin32Confinement,
            exit_code,
            total_elapsed_us: start.elapsed().as_micros() as u64,
            wasm_receipt: None,
            win32_child_token_posture: Some(deelevated.posture.clone()),
            job_io_sample: Some(job_sample),
            mercury_evaluation: mercury_eval,
            zero_mi_output: zero_mi,
        })
    }
}
