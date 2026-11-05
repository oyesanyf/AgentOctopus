//! Tier 1 In-Process Wasmtime Capability Sandbox (`src/security/wasm_tier1.rs`)
//!
//! Provides zero-ambient-authority WebAssembly tool execution inside `AgentOctopus`:
//! 1. **Zero Ambient Authority by Construction**:
//!    A `.wasm` / `.wat` guest module has no access to `CreateFileW`, `OpenProcessToken`,
//!    `AdjustTokenPrivileges`, `HKLM\SAM`, `\\.\PhysicalDrive0`, environment variables,
//!    network sockets, or subprocess creation (`CreateProcessW`).
//!    Any module that attempts to import `wasi_snapshot_preview1` process/socket/filesystem
//!    functions outside the explicit `"octopus_wasi"` host capability bridge fails instantiation.
//! 2. **Handle-Confined Scratchpad Bridge (`octopus_wasi::scratch_read` / `scratch_write`)**:
//!    The only filesystem operations available to the guest route exclusively through
//!    [`open_confined`](crate::security::breakouts::open_confined), which opens every path
//!    component with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects symlinks/junctions, rejects
//!    hardlinks (`nNumberOfLinks > 1`), and verifies `GetFinalPathNameByHandleW` prefix
//!    confinement before reading or writing a single byte.
//! 3. **Deterministic CPU & Memory Metering**:
//!    - `wasmtime::ResourceLimiter` (`WasmHostState`) enforces a strict linear memory ceiling
//!      (default `64 MiB`) and table element cap (`4,096`), trapping `memory.grow` overflows
//!      deterministically inside the Wasm runtime.
//!    - `Store::set_fuel` halts infinite loops (`(loop (br 0))`) after an exact instruction count.
//!    - `Config::epoch_interruption(true)` allows non-cooperative autotomy (`increment_epoch`)
//!      to interrupt running guests without OS thread termination races.

use crate::core::circuit_breaker::KillSwitch;
use crate::core::types::{ArmRole, OctopusSecurityError};
use crate::security::agentmesh::mandate_attenuation::validate_mesh_uri;
use crate::security::agentmesh::pep_bridge::AgentMeshPepBridge;
use crate::security::breakouts::{
    open_confined, ZeroMiProjectionResult, ZeroMutualInformationProjector,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use wasmtime::{Caller, Config, Engine, Linker, Module, ResourceLimiter, Store};

/// Error code returned to Wasm guests when `open_confined` or capability checks deny an operation.
pub const WASI_ERR_ACCESS_DENIED: i32 = -5;
/// Error code returned to Wasm guests when guest pointer/length bounds are invalid in linear memory.
pub const WASI_ERR_FAULT: i32 = -14;
/// Error code returned to Wasm guests when an I/O or UTF-8 failure occurs.
pub const WASI_ERR_IO: i32 = -29;

/// Maximum number of active virtual WASI stream descriptors per sandbox.
pub const MAX_VIRTUAL_MESH_STREAMS: usize = 16;

/// Virtual WASI stream descriptor representing an open mesh streaming channel (Weakness 6).
#[derive(Debug, Clone)]
pub struct VirtualMeshStream {
    pub fd: u32,
    pub uri: String,
    pub flags: i32,
    pub write_buffer: Vec<u8>,
    pub read_buffer: Vec<u8>,
    pub read_cursor: usize,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub dispatched: bool,
}

impl VirtualMeshStream {
    pub fn new(fd: u32, uri: String, flags: i32) -> Self {
        Self {
            fd,
            uri,
            flags,
            write_buffer: Vec::new(),
            read_buffer: Vec::new(),
            read_cursor: 0,
            total_bytes_read: 0,
            total_bytes_written: 0,
            dispatched: false,
        }
    }
}

/// Host-only bridge context passed to `Store<WasmHostState>`.
/// ZERO credentials, tokens, or private keys enter Wasm linear memory.
#[derive(Clone)]
pub struct WasmMeshBridgeContext {
    pub arm_id: String,
    pub generation_epoch: u64,
    pub role: ArmRole,
    pub killswitch: Option<KillSwitch>,
    pub pep_bridge: Arc<AgentMeshPepBridge>,
    pub max_mesh_calls: u32,
    pub max_mesh_bytes: usize,
}

impl std::fmt::Debug for WasmMeshBridgeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmMeshBridgeContext")
            .field("arm_id", &self.arm_id)
            .field("generation_epoch", &self.generation_epoch)
            .field("role", &self.role)
            .field("max_mesh_calls", &self.max_mesh_calls)
            .field("max_mesh_bytes", &self.max_mesh_bytes)
            .finish()
    }
}

impl WasmMeshBridgeContext {
    pub fn new(
        arm_id: impl Into<String>,
        generation_epoch: u64,
        role: ArmRole,
        pep_bridge: Arc<AgentMeshPepBridge>,
    ) -> Self {
        Self {
            arm_id: arm_id.into(),
            generation_epoch,
            role,
            killswitch: None,
            pep_bridge,
            max_mesh_calls: 100,
            max_mesh_bytes: 16 * 1024 * 1024, // 16 MiB default
        }
    }

    pub fn with_killswitch(mut self, killswitch: KillSwitch) -> Self {
        self.killswitch = Some(killswitch);
        self
    }

    pub fn is_tripped(&self) -> bool {
        if let Some(ref ks) = self.killswitch {
            if ks.is_tripped() {
                return true;
            }
        }
        self.pep_bridge.is_arm_tripped(&self.arm_id)
    }
}

/// Resource and capability limits applied to a single Tier 1 Wasm tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmSandboxLimits {
    /// Deterministic Wasm instruction fuel budget (default `2,000,000`).
    pub fuel_budget: u64,
    /// Maximum linear memory bytes across all memories in the store (default `64 MiB`).
    pub max_linear_memory_bytes: usize,
    /// Maximum table elements across all tables in the store (default `4,096`).
    pub max_table_elements: usize,
    /// Maximum bytes the guest may emit via `octopus_wasi::emit_output` (default `1 MiB`).
    pub max_output_bytes: usize,
    /// Pre-bound sandbox scratchpad directory accessed exclusively via `open_confined`.
    pub scratchpad_root: PathBuf,
    /// Whether the guest is authorized to call `octopus_wasi::scratch_write`.
    pub allow_scratch_write: bool,
    /// Optional host-bound AgentMesh bridge context.
    #[serde(skip)]
    pub mesh_context: Option<WasmMeshBridgeContext>,
}

impl Default for WasmSandboxLimits {
    fn default() -> Self {
        Self {
            fuel_budget: 2_000_000,
            max_linear_memory_bytes: 64 * 1024 * 1024, // 64 MiB
            max_table_elements: 4_096,
            max_output_bytes: 1024 * 1024, // 1 MiB
            scratchpad_root: std::env::temp_dir().join("octopus_wasm_scratchpad"),
            allow_scratch_write: false,
            mesh_context: None,
        }
    }
}

/// Cryptographic and resource telemetry receipt produced by a Tier 1 Wasm execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmExecutionReceipt {
    pub tool_name: String,
    pub exit_code: i32,
    pub cold_start_us: u64,
    pub execution_us: u64,
    pub fuel_budget: u64,
    pub fuel_consumed: u64,
    pub fuel_remaining: u64,
    pub peak_linear_memory_bytes: usize,
    pub max_linear_memory_bytes: usize,
    pub memory_limit_exceeded: bool,
    pub scratch_bytes_read: u64,
    pub scratch_bytes_written: u64,
    pub blocked_escape_attempts: Vec<String>,
    pub raw_output: String,
    pub zero_mi_projection: ZeroMiProjectionResult,
    // Milestone 2 AgentMesh Telemetry:
    pub mesh_calls_attempted: u64,
    pub mesh_calls_succeeded: u64,
    pub mesh_bytes_exchanged: u64,
    /// True when post-execution linear memory inspection confirms zero JWT/access-token/private-key bytes exist in guest memory.
    pub linear_memory_zero_secret_verified: bool,
}

fn verify_linear_memory_contains_no_secrets(mem_bytes: &[u8]) -> bool {
    const FORBIDDEN_MARKERS: &[&[u8]] = &[
        b"mesh_tok_",
        b"eyJhbGciOiJFUzI1NiI",
        b"BEGIN PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
    ];
    for marker in FORBIDDEN_MARKERS {
        if mem_bytes.windows(marker.len()).any(|w| w == *marker) {
            return false;
        }
    }
    true
}

/// Per-invocation host state owned by `wasmtime::Store<WasmHostState>`.
pub struct WasmHostState {
    pub limits: WasmSandboxLimits,
    pub input_bytes: Vec<u8>,
    pub output_buffer: Vec<u8>,
    pub peak_memory_bytes: usize,
    pub memory_limit_exceeded: bool,
    pub table_limit_exceeded: bool,
    pub scratch_bytes_read: u64,
    pub scratch_bytes_written: u64,
    pub blocked_escape_attempts: Vec<String>,
    // Milestone 2 additions:
    pub mesh_context: Option<WasmMeshBridgeContext>,
    pub mesh_calls_attempted: u64,
    pub mesh_calls_succeeded: u64,
    pub mesh_bytes_exchanged: u64,
    pub active_streams: HashMap<u32, VirtualMeshStream>,
    pub next_stream_fd: u32,
    pub stream_fallback_needed: bool,
}

impl WasmHostState {
    pub fn new(limits: WasmSandboxLimits, input_bytes: Vec<u8>) -> Self {
        let ctx = limits.mesh_context.clone();
        Self::with_context(limits, input_bytes, ctx)
    }

    pub fn with_context(
        limits: WasmSandboxLimits,
        input_bytes: Vec<u8>,
        mesh_context: Option<WasmMeshBridgeContext>,
    ) -> Self {
        let ctx = mesh_context.or_else(|| limits.mesh_context.clone());
        Self {
            limits,
            input_bytes,
            output_buffer: Vec::new(),
            peak_memory_bytes: 65_536, // 1 Wasm page initial baseline
            memory_limit_exceeded: false,
            table_limit_exceeded: false,
            scratch_bytes_read: 0,
            scratch_bytes_written: 0,
            blocked_escape_attempts: Vec::new(),
            mesh_context: ctx,
            mesh_calls_attempted: 0,
            mesh_calls_succeeded: 0,
            mesh_bytes_exchanged: 0,
            active_streams: HashMap::new(),
            next_stream_fd: 3, // Start virtual descriptors after 0, 1, 2
            stream_fallback_needed: false,
        }
    }
}

impl ResourceLimiter for WasmHostState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        if let Some(max) = maximum {
            if desired > max {
                self.memory_limit_exceeded = true;
                return Ok(false);
            }
        }
        if desired > self.limits.max_linear_memory_bytes {
            self.memory_limit_exceeded = true;
            return Ok(false);
        }
        if desired > self.peak_memory_bytes {
            self.peak_memory_bytes = desired;
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool, wasmtime::Error> {
        if let Some(max) = maximum {
            if desired > max {
                self.table_limit_exceeded = true;
                return Ok(false);
            }
        }
        if desired > self.limits.max_table_elements {
            self.table_limit_exceeded = true;
            return Ok(false);
        }
        Ok(true)
    }
}

/// Built-in WAT module for untrusted document ingestion & sanitization (`DocumentRead`).
/// Runs entirely inside Wasm linear memory with zero OS syscalls:
/// - Reads input bytes via `octopus_wasi::read_input`,
/// - Strips ASCII control characters (`< 0x20` except `\n` = 10 and `\t` = 9) and DEL (`0x7f`),
/// - Emits the sanitized document slice via `octopus_wasi::emit_output`.
pub const WASM_DOC_EXTRACTOR_WAT: &str = r#"
(module
    (import "octopus_wasi" "input_len" (func $input_len (result i32)))
    (import "octopus_wasi" "read_input" (func $read_input (param i32 i32) (result i32)))
    (import "octopus_wasi" "emit_output" (func $emit_output (param i32 i32) (result i32)))
    (memory (export "memory") 2 16)
    (func (export "octopus_run") (result i32)
        (local $len i32)
        (local $read i32)
        (local $i i32)
        (local $out_idx i32)
        (local $byte i32)
        (local.set $len (call $input_len))
        (if (i32.gt_s (local.get $len) (i32.const 32768))
            (then (local.set $len (i32.const 32768)))
        )
        (local.set $read (call $read_input (i32.const 0) (local.get $len)))
        (if (i32.lt_s (local.get $read) (i32.const 0))
            (then (return (local.get $read)))
        )
        (local.set $i (i32.const 0))
        (local.set $out_idx (i32.const 32768))
        (block $break
            (loop $scan
                (br_if $break (i32.ge_u (local.get $i) (local.get $read)))
                (local.set $byte (i32.load8_u (local.get $i)))
                ;; Keep printable bytes (>= 32 && != 127) plus '\n' (10) and '\t' (9)
                (if (i32.or
                        (i32.and
                            (i32.ge_u (local.get $byte) (i32.const 32))
                            (i32.ne (local.get $byte) (i32.const 127))
                        )
                        (i32.or
                            (i32.eq (local.get $byte) (i32.const 10))
                            (i32.eq (local.get $byte) (i32.const 9))
                        )
                    )
                    (then
                        (i32.store8 (local.get $out_idx) (local.get $byte))
                        (local.set $out_idx (i32.add (local.get $out_idx) (i32.const 1)))
                    )
                )
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)
            )
        )
        (call $emit_output
            (i32.const 32768)
            (i32.sub (local.get $out_idx) (i32.const 32768))
        )
    )
)
"#;

/// Built-in WAT module for accounting ledger entry validation (`LedgerWrite`).
/// Validates non-empty payload framing in Wasm linear memory and emits the verified bytes.
pub const WASM_LEDGER_VALIDATOR_WAT: &str = r#"
(module
    (import "octopus_wasi" "input_len" (func $input_len (result i32)))
    (import "octopus_wasi" "read_input" (func $read_input (param i32 i32) (result i32)))
    (import "octopus_wasi" "emit_output" (func $emit_output (param i32 i32) (result i32)))
    (memory (export "memory") 2 16)
    (func (export "octopus_run") (result i32)
        (local $len i32)
        (local $read i32)
        (local.set $len (call $input_len))
        (if (i32.le_s (local.get $len) (i32.const 0))
            (then (return (i32.const -5)))
        )
        (if (i32.gt_s (local.get $len) (i32.const 32768))
            (then (local.set $len (i32.const 32768)))
        )
        (local.set $read (call $read_input (i32.const 0) (local.get $len)))
        (if (i32.le_s (local.get $read) (i32.const 0))
            (then (return (i32.const -5)))
        )
        (call $emit_output (i32.const 0) (local.get $read))
    )
)
"#;

/// Built-in WAT module for outbound Tier 1 Wasm mesh pore execution (`octopus_wasi::mesh_call`).
/// Parses `URI\nPAYLOAD` framing in linear memory, calls `mesh_call`, and emits response bytes.
pub const WASM_MESH_CALLER_WAT: &str = r#"
(module
    (import "octopus_wasi" "input_len" (func $input_len (result i32)))
    (import "octopus_wasi" "read_input" (func $read_input (param i32 i32) (result i32)))
    (import "octopus_wasi" "emit_output" (func $emit_output (param i32 i32) (result i32)))
    (import "octopus_wasi" "mesh_call" (func $mesh_call (param i32 i32 i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 2 16)
    (func (export "octopus_run") (result i32)
        (local $len i32)
        (local $read i32)
        (local $i i32)
        (local $uri_len i32)
        (local $req_ptr i32)
        (local $req_len i32)
        (local $resp_len i32)
        (local $byte i32)

        (local.set $len (call $input_len))
        (if (i32.le_s (local.get $len) (i32.const 0))
            (then (return (i32.const -5)))
        )
        (if (i32.gt_s (local.get $len) (i32.const 16384))
            (then (local.set $len (i32.const 16384)))
        )
        (local.set $read (call $read_input (i32.const 0) (local.get $len)))
        (if (i32.le_s (local.get $read) (i32.const 0))
            (then (return (i32.const -5)))
        )

        ;; Scan for separator '\n' (byte 10) between URI and payload
        (local.set $i (i32.const 0))
        (local.set $uri_len (local.get $read))
        (local.set $req_ptr (i32.const 0))
        (local.set $req_len (i32.const 0))

        (block $scan_done
            (loop $scan
                (br_if $scan_done (i32.ge_u (local.get $i) (local.get $read)))
                (local.set $byte (i32.load8_u (local.get $i)))
                (if (i32.eq (local.get $byte) (i32.const 10))
                    (then
                        (local.set $uri_len (local.get $i))
                        (local.set $req_ptr (i32.add (local.get $i) (i32.const 1)))
                        (local.set $req_len (i32.sub (local.get $read) (local.get $req_ptr)))
                        (br $scan_done)
                    )
                )
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $scan)
            )
        )

        ;; Call mesh: uri at 0..uri_len, req at req_ptr..req_ptr+req_len, resp at 32768..32768+65536
        (local.set $resp_len
            (call $mesh_call
                (i32.const 0)
                (local.get $uri_len)
                (local.get $req_ptr)
                (local.get $req_len)
                (i32.const 32768)
                (i32.const 65536)
            )
        )

        ;; If mesh_call returned error (< 0), propagate error code as exit code
        (if (i32.lt_s (local.get $resp_len) (i32.const 0))
            (then (return (local.get $resp_len)))
        )

        ;; Emit the received response to output buffer
        (call $emit_output (i32.const 32768) (local.get $resp_len))
    )
)
"#;

/// Tier 1 In-Process Wasmtime Executor with pre-compiled built-in tool modules,
/// reusable `Linker`, SHA-256 compiled `Module` cache (`AO-FIND-10`),
/// fuel & epoch interruption, `ResourceLimiter`, and `open_confined`-backed scratchpad bridge.
#[derive(Clone)]
pub struct WasmTier1Executor {
    engine: Engine,
    linker: std::sync::Arc<Linker<WasmHostState>>,
    doc_extractor_module: Module,
    ledger_validator_module: Module,
    mesh_caller_module: Module,
    module_cache: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<[u8; 32], Module>>>,
}

impl WasmTier1Executor {
    pub fn try_new() -> Result<Self, OctopusSecurityError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);

        let engine = Engine::new(&config).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: WasmTier1Executor Engine initialization failed: {}",
                e
            ))
        })?;

        let mut linker: Linker<WasmHostState> = Linker::new(&engine);
        Self::bind_octopus_wasi_imports(&mut linker)?;

        let doc_extractor_module = Module::new(&engine, WASM_DOC_EXTRACTOR_WAT).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Failed to compile WASM_DOC_EXTRACTOR_WAT: {}",
                e
            ))
        })?;

        let ledger_validator_module =
            Module::new(&engine, WASM_LEDGER_VALIDATOR_WAT).map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "FAIL-CLOSED: Failed to compile WASM_LEDGER_VALIDATOR_WAT: {}",
                    e
                ))
            })?;

        let mesh_caller_module = Module::new(&engine, WASM_MESH_CALLER_WAT).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "FAIL-CLOSED: Failed to compile WASM_MESH_CALLER_WAT: {}",
                e
            ))
        })?;

        Ok(Self {
            engine,
            linker: std::sync::Arc::new(linker),
            doc_extractor_module,
            ledger_validator_module,
            mesh_caller_module,
            module_cache: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        })
    }

    /// Binds an engine epoch increment callback to the given KillSwitch.
    pub fn attach_killswitch(&self, killswitch: &KillSwitch) {
        let engine = self.engine.clone();
        killswitch.register_callback(Arc::new(move || {
            engine.increment_epoch();
        }));
    }

    /// Advances the Wasmtime engine epoch, immediately interrupting any running guest whose
    /// epoch deadline has expired (non-cooperative autotomy).
    pub fn increment_epoch(&self) {
        self.engine.increment_epoch();
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Compiles (with SHA-256 module caching, `AO-FIND-10`) and executes a `.wat` / `.wasm`
    /// module inside the Tier 1 capability sandbox with a fresh per-invocation `Store`.
    pub fn execute_wat(
        &self,
        tool_name: &str,
        wat_or_wasm: impl AsRef<[u8]>,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        let ctx = limits.mesh_context.clone();
        self.execute_wat_with_context(tool_name, wat_or_wasm, input_bytes, limits, ctx)
    }

    /// Executes a `.wat` / `.wasm` module with optional explicit host-only `WasmMeshBridgeContext`.
    pub fn execute_wat_with_context(
        &self,
        tool_name: &str,
        wat_or_wasm: impl AsRef<[u8]>,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
        mesh_context: Option<WasmMeshBridgeContext>,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        use sha2::{Digest, Sha256};

        let cold_start_begin = Instant::now();
        let bytes = wat_or_wasm.as_ref();
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(&Sha256::digest(bytes));

        let cached = self
            .module_cache
            .read()
            .ok()
            .and_then(|guard| guard.get(&digest_arr).cloned());

        let module = match cached {
            Some(m) => m,
            None => {
                let compiled = Module::new(&self.engine, bytes).map_err(|e| {
                    OctopusSecurityError::IsolationViolation(format!(
                        "TIER1_WASM_COMPILE_REJECTED [{}]: {}",
                        tool_name, e
                    ))
                })?;
                if let Ok(mut guard) = self.module_cache.write() {
                    if guard.len() >= 128 {
                        guard.clear();
                    }
                    guard.insert(digest_arr, compiled.clone());
                }
                compiled
            }
        };

        self.execute_compiled_module_with_context(
            tool_name,
            &module,
            input_bytes,
            limits,
            mesh_context,
            cold_start_begin,
        )
    }

    /// Executes a `.wat` / `.wasm` module without module caching or Linker reuse (baseline reference for benchmarking).
    pub fn execute_wat_uncached(
        &self,
        tool_name: &str,
        wat_or_wasm: impl AsRef<[u8]>,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        let cold_start_begin = Instant::now();
        let module = Module::new(&self.engine, wat_or_wasm).map_err(|e| {
            OctopusSecurityError::IsolationViolation(format!(
                "TIER1_WASM_COMPILE_REJECTED [{}]: {}",
                tool_name, e
            ))
        })?;
        for import in module.imports() {
            if import.module() != "octopus_wasi" {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_AMBIENT_IMPORT_FORBIDDEN [{}]: guest attempted to import '{}::{}' outside 'octopus_wasi'",
                    tool_name,
                    import.module(),
                    import.name()
                )));
            }
        }
        let fuel_budget = limits.fuel_budget;
        let max_linear_memory_bytes = limits.max_linear_memory_bytes;
        let host_state = WasmHostState::new(limits, input_bytes.to_vec());
        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        store.set_fuel(fuel_budget).map_err(|e| {
            OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Failed to configure Wasmtime fuel budget: {}",
                e
            ))
        })?;
        store.set_epoch_deadline(1);
        let mut uncached_linker: Linker<WasmHostState> = Linker::new(&self.engine);
        Self::bind_octopus_wasi_imports(&mut uncached_linker)?;
        let instance = uncached_linker
            .instantiate(&mut store, &module)
            .map_err(|e| {
                if store.data().memory_limit_exceeded {
                    OctopusSecurityError::ResourceQuotaExceeded(format!(
                    "TIER1_WASM_MEMORY_LIMIT_EXCEEDED [{}]: initial memory exceeds {} bytes ({})",
                    tool_name, max_linear_memory_bytes, e
                ))
                } else {
                    OctopusSecurityError::IsolationViolation(format!(
                        "TIER1_WASM_INSTANTIATE_FAILED [{}]: {}",
                        tool_name, e
                    ))
                }
            })?;
        let cold_start_us = cold_start_begin.elapsed().as_micros() as u64;
        let exec_begin = Instant::now();
        let run_fn = instance
            .get_typed_func::<(), i32>(&mut store, "octopus_run")
            .or_else(|_| instance.get_typed_func::<(), i32>(&mut store, "execute_step"))
            .map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_MISSING_ENTRYPOINT [{}]: {}",
                    tool_name, e
                ))
            })?;
        let exit_code = run_fn.call(&mut store, ()).map_err(|trap| {
            OctopusSecurityError::IsolationViolation(format!(
                "TIER1_WASM_RUNTIME_TRAP [{}]: {}",
                tool_name, trap
            ))
        })?;
        let execution_us = exec_begin.elapsed().as_micros() as u64;
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel_budget.saturating_sub(fuel_remaining);
        let linear_memory_zero_secret_verified = instance
            .get_memory(&mut store, "memory")
            .map(|mem| verify_linear_memory_contains_no_secrets(mem.data(&store)))
            .unwrap_or(true);
        let state = store.into_data();
        let raw_output = String::from_utf8_lossy(&state.output_buffer).to_string();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let zero_mi_projection =
            ZeroMutualInformationProjector::project_output(&raw_output, now_ms, 100);
        Ok(WasmExecutionReceipt {
            tool_name: tool_name.to_string(),
            exit_code,
            cold_start_us,
            execution_us,
            fuel_budget,
            fuel_consumed,
            fuel_remaining,
            peak_linear_memory_bytes: state.peak_memory_bytes,
            max_linear_memory_bytes: state.limits.max_linear_memory_bytes,
            memory_limit_exceeded: state.memory_limit_exceeded,
            scratch_bytes_read: state.scratch_bytes_read,
            scratch_bytes_written: state.scratch_bytes_written,
            blocked_escape_attempts: state.blocked_escape_attempts,
            raw_output,
            zero_mi_projection,
            mesh_calls_attempted: state.mesh_calls_attempted,
            mesh_calls_succeeded: state.mesh_calls_succeeded,
            mesh_bytes_exchanged: state.mesh_bytes_exchanged,
            linear_memory_zero_secret_verified,
        })
    }

    /// Executes the pre-compiled `WASM_DOC_EXTRACTOR_WAT` module in Tier 1.
    pub fn execute_doc_extractor(
        &self,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        self.execute_compiled_module(
            "wasm_doc_extractor",
            &self.doc_extractor_module,
            input_bytes,
            limits,
            Instant::now(),
        )
    }

    /// Executes the pre-compiled `WASM_LEDGER_VALIDATOR_WAT` module in Tier 1.
    pub fn execute_ledger_validator(
        &self,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        self.execute_compiled_module(
            "wasm_ledger_validator",
            &self.ledger_validator_module,
            input_bytes,
            limits,
            Instant::now(),
        )
    }

    /// Executes the pre-compiled `WASM_MESH_CALLER_WAT` module in Tier 1.
    pub fn execute_mesh_caller(
        &self,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
        mesh_context: WasmMeshBridgeContext,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        self.execute_compiled_module_with_context(
            "wasm_mesh_caller",
            &self.mesh_caller_module,
            input_bytes,
            limits,
            Some(mesh_context),
            Instant::now(),
        )
    }

    fn execute_compiled_module(
        &self,
        tool_name: &str,
        module: &Module,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
        cold_start_begin: Instant,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        let ctx = limits.mesh_context.clone();
        self.execute_compiled_module_with_context(
            tool_name,
            module,
            input_bytes,
            limits,
            ctx,
            cold_start_begin,
        )
    }

    pub fn execute_compiled_module_with_context(
        &self,
        tool_name: &str,
        module: &Module,
        input_bytes: &[u8],
        limits: WasmSandboxLimits,
        mesh_context: Option<WasmMeshBridgeContext>,
        cold_start_begin: Instant,
    ) -> Result<WasmExecutionReceipt, OctopusSecurityError> {
        // Reject any module importing namespaces outside "octopus_wasi" (zero ambient authority)
        for import in module.imports() {
            if import.module() != "octopus_wasi" {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_AMBIENT_IMPORT_FORBIDDEN [{}]: guest attempted to import '{}::{}' outside 'octopus_wasi'",
                    tool_name,
                    import.module(),
                    import.name()
                )));
            }
        }

        let fuel_budget = limits.fuel_budget;
        let max_linear_memory_bytes = limits.max_linear_memory_bytes;
        let host_state = WasmHostState::with_context(limits, input_bytes.to_vec(), mesh_context);

        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        store.set_fuel(fuel_budget).map_err(|e| {
            OctopusSecurityError::ResourceQuotaExceeded(format!(
                "Failed to configure Wasmtime fuel budget: {}",
                e
            ))
        })?;
        store.set_epoch_deadline(1);

        let instance = self.linker.instantiate(&mut store, module).map_err(|e| {
            let mem_exceeded = store.data().memory_limit_exceeded;
            if mem_exceeded {
                OctopusSecurityError::ResourceQuotaExceeded(format!(
                    "TIER1_WASM_MEMORY_LIMIT_EXCEEDED [{}]: initial memory exceeds {} bytes ({})",
                    tool_name, max_linear_memory_bytes, e
                ))
            } else {
                OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_INSTANTIATE_FAILED [{}]: {}",
                    tool_name, e
                ))
            }
        })?;

        let cold_start_us = cold_start_begin.elapsed().as_micros() as u64;
        let exec_begin = Instant::now();

        // Update peak memory from exported linear memory if present
        if let Some(mem) = instance.get_memory(&mut store, "memory") {
            let cur_size = mem.data_size(&store);
            if cur_size > store.data().peak_memory_bytes {
                store.data_mut().peak_memory_bytes = cur_size;
            }
        }

        let run_fn = instance
            .get_typed_func::<(), i32>(&mut store, "octopus_run")
            .or_else(|_| instance.get_typed_func::<(), i32>(&mut store, "execute_step"))
            .map_err(|e| {
                OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_MISSING_ENTRYPOINT [{}]: expected `(func (export \"octopus_run\") (result i32))`: {}",
                    tool_name, e
                ))
            })?;

        let exit_code = match run_fn.call(&mut store, ()) {
            Ok(code) => code,
            Err(trap) => {
                let fuel_left = store.get_fuel().unwrap_or(0);
                let mem_exceeded = store.data().memory_limit_exceeded;
                let is_tripped = store
                    .data()
                    .mesh_context
                    .as_ref()
                    .map_or(false, |c| c.is_tripped());

                if is_tripped || trap.to_string().contains("interrupt") {
                    return Err(OctopusSecurityError::LimbKilled);
                }
                if fuel_left == 0 {
                    return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                        "TIER1_WASM_OUT_OF_FUEL [{}]: exhausted {} instruction fuel units ({})",
                        tool_name, fuel_budget, trap
                    )));
                }
                if mem_exceeded {
                    return Err(OctopusSecurityError::ResourceQuotaExceeded(format!(
                        "TIER1_WASM_MEMORY_CAP_TRAPPED [{}]: exceeded {} byte linear memory ceiling ({})",
                        tool_name, max_linear_memory_bytes, trap
                    )));
                }
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "TIER1_WASM_RUNTIME_TRAP [{}]: {}",
                    tool_name, trap
                )));
            }
        };

        let mut linear_memory_zero_secret_verified = true;
        if let Some(mem) = instance.get_memory(&mut store, "memory") {
            let cur_size = mem.data_size(&store);
            linear_memory_zero_secret_verified =
                verify_linear_memory_contains_no_secrets(mem.data(&store));
            if cur_size > store.data().peak_memory_bytes {
                store.data_mut().peak_memory_bytes = cur_size;
            }
        }

        let execution_us = exec_begin.elapsed().as_micros() as u64;
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = fuel_budget.saturating_sub(fuel_remaining);

        let state = store.into_data();
        let raw_output = String::from_utf8_lossy(&state.output_buffer).to_string();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let zero_mi_projection =
            ZeroMutualInformationProjector::project_output(&raw_output, now_ms, 100);

        Ok(WasmExecutionReceipt {
            tool_name: tool_name.to_string(),
            exit_code,
            cold_start_us,
            execution_us,
            fuel_budget,
            fuel_consumed,
            fuel_remaining,
            peak_linear_memory_bytes: state.peak_memory_bytes,
            max_linear_memory_bytes: state.limits.max_linear_memory_bytes,
            memory_limit_exceeded: state.memory_limit_exceeded,
            scratch_bytes_read: state.scratch_bytes_read,
            scratch_bytes_written: state.scratch_bytes_written,
            blocked_escape_attempts: state.blocked_escape_attempts,
            raw_output,
            zero_mi_projection,
            mesh_calls_attempted: state.mesh_calls_attempted,
            mesh_calls_succeeded: state.mesh_calls_succeeded,
            mesh_bytes_exchanged: state.mesh_bytes_exchanged,
            linear_memory_zero_secret_verified,
        })
    }

    fn bind_octopus_wasi_imports(
        linker: &mut Linker<WasmHostState>,
    ) -> Result<(), OctopusSecurityError> {
        // 1. octopus_wasi::input_len() -> i32
        linker
            .func_wrap(
                "octopus_wasi",
                "input_len",
                |caller: Caller<'_, WasmHostState>| -> i32 {
                    caller.data().input_bytes.len() as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 2. octopus_wasi::read_input(dst_ptr: i32, dst_cap: i32) -> i32
        linker
            .func_wrap(
                "octopus_wasi",
                "read_input",
                |mut caller: Caller<'_, WasmHostState>, dst_ptr: i32, dst_cap: i32| -> i32 {
                    if dst_ptr < 0 || dst_cap < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let input = caller.data().input_bytes.clone();
                    let copy_len = input.len().min(dst_cap as usize);
                    let start = dst_ptr as usize;
                    let end = start.saturating_add(copy_len);
                    let data = mem.data_mut(&mut caller);
                    if end > data.len() {
                        return WASI_ERR_FAULT;
                    }
                    data[start..end].copy_from_slice(&input[..copy_len]);
                    copy_len as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 3. octopus_wasi::emit_output(src_ptr: i32, src_len: i32) -> i32
        linker
            .func_wrap(
                "octopus_wasi",
                "emit_output",
                |mut caller: Caller<'_, WasmHostState>, src_ptr: i32, src_len: i32| -> i32 {
                    if src_ptr < 0 || src_len < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let start = src_ptr as usize;
                    let len = src_len as usize;
                    let end = start.saturating_add(len);
                    let slice = {
                        let data = mem.data(&caller);
                        if end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        data[start..end].to_vec()
                    };
                    let max_out = caller.data().limits.max_output_bytes;
                    let state = caller.data_mut();
                    if state.output_buffer.len().saturating_add(slice.len()) > max_out {
                        return WASI_ERR_ACCESS_DENIED;
                    }
                    state.output_buffer.extend_from_slice(&slice);
                    slice.len() as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 4. octopus_wasi::scratch_read(path_ptr: i32, path_len: i32, dst_ptr: i32, dst_cap: i32) -> i32
        // Exclusively opens relative files inside `scratchpad_root` via Win32 handle-verified `open_confined`.
        linker
            .func_wrap(
                "octopus_wasi",
                "scratch_read",
                |mut caller: Caller<'_, WasmHostState>,
                 path_ptr: i32,
                 path_len: i32,
                 dst_ptr: i32,
                 dst_cap: i32|
                 -> i32 {
                    if path_ptr < 0 || path_len <= 0 || dst_ptr < 0 || dst_cap < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let rel_path = {
                        let data = mem.data(&caller);
                        let p_start = path_ptr as usize;
                        let p_end = p_start.saturating_add(path_len as usize);
                        if p_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        match std::str::from_utf8(&data[p_start..p_end]) {
                            Ok(s) => s.to_string(),
                            Err(_) => return WASI_ERR_IO,
                        }
                    };

                    let root = caller.data().limits.scratchpad_root.clone();
                    let mut file = match open_confined(&root, &rel_path, false) {
                        Ok(f) => f,
                        Err(e) => {
                            caller
                                .data_mut()
                                .blocked_escape_attempts
                                .push(format!("scratch_read('{}') blocked: {}", rel_path, e));
                            return WASI_ERR_ACCESS_DENIED;
                        }
                    };

                    let max_read = (dst_cap as usize)
                        .min(caller.data().limits.max_linear_memory_bytes)
                        .min(16 * 1024 * 1024);
                    let mut buf = Vec::with_capacity(max_read.min(65_536));
                    if (&mut file)
                        .take(max_read as u64)
                        .read_to_end(&mut buf)
                        .is_err()
                    {
                        return WASI_ERR_IO;
                    }
                    let copy_len = buf.len().min(dst_cap as usize);
                    let d_start = dst_ptr as usize;
                    let d_end = d_start.saturating_add(copy_len);
                    {
                        let data = mem.data_mut(&mut caller);
                        if d_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        data[d_start..d_end].copy_from_slice(&buf[..copy_len]);
                    }
                    caller.data_mut().scratch_bytes_read += copy_len as u64;
                    copy_len as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 5. octopus_wasi::scratch_write(path_ptr: i32, path_len: i32, src_ptr: i32, src_len: i32) -> i32
        // Exclusively opens relative files inside `scratchpad_root` via Win32 handle-verified `open_confined`.
        linker
            .func_wrap(
                "octopus_wasi",
                "scratch_write",
                |mut caller: Caller<'_, WasmHostState>,
                 path_ptr: i32,
                 path_len: i32,
                 src_ptr: i32,
                 src_len: i32|
                 -> i32 {
                    if !caller.data().limits.allow_scratch_write {
                        caller
                            .data_mut()
                            .blocked_escape_attempts
                            .push("scratch_write denied: allow_scratch_write=false".to_string());
                        return WASI_ERR_ACCESS_DENIED;
                    }
                    if path_ptr < 0 || path_len <= 0 || src_ptr < 0 || src_len < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let max_write_quota = caller.data().limits.max_output_bytes as u64;
                    let cur_written = caller.data().scratch_bytes_written;
                    if cur_written.saturating_add(src_len as u64) > max_write_quota {
                        caller.data_mut().blocked_escape_attempts.push(format!(
                            "scratch_write denied: write quota exceeded ({} + {} > {})",
                            cur_written, src_len, max_write_quota
                        ));
                        return WASI_ERR_ACCESS_DENIED;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let (rel_path, payload) = {
                        let data = mem.data(&caller);
                        let p_start = path_ptr as usize;
                        let p_end = p_start.saturating_add(path_len as usize);
                        let s_start = src_ptr as usize;
                        let s_end = s_start.saturating_add(src_len as usize);
                        if p_end > data.len() || s_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        let Ok(p_str) = std::str::from_utf8(&data[p_start..p_end]) else {
                            return WASI_ERR_IO;
                        };
                        (p_str.to_string(), data[s_start..s_end].to_vec())
                    };

                    let root = caller.data().limits.scratchpad_root.clone();
                    let mut file = match open_confined(&root, &rel_path, true) {
                        Ok(f) => f,
                        Err(e) => {
                            caller
                                .data_mut()
                                .blocked_escape_attempts
                                .push(format!("scratch_write('{}') blocked: {}", rel_path, e));
                            return WASI_ERR_ACCESS_DENIED;
                        }
                    };
                    if file.write_all(&payload).is_err() {
                        return WASI_ERR_IO;
                    }
                    caller.data_mut().scratch_bytes_written += payload.len() as u64;
                    payload.len() as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 6. octopus_wasi::mesh_call(uri_ptr, uri_len, req_ptr, req_len, resp_ptr, resp_cap) -> i32
        linker
            .func_wrap(
                "octopus_wasi",
                "mesh_call",
                |mut caller: Caller<'_, WasmHostState>,
                 uri_ptr: i32,
                 uri_len: i32,
                 req_ptr: i32,
                 req_len: i32,
                 resp_ptr: i32,
                 resp_cap: i32|
                 -> i32 {
                    caller.data_mut().mesh_calls_attempted += 1;

                    if uri_ptr < 0 || uri_len <= 0 || req_ptr < 0 || req_len < 0 || resp_ptr < 0 || resp_cap < 0 {
                        return WASI_ERR_FAULT;
                    }

                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };

                    // Bounds-checked extraction of URI and request payload from guest linear memory
                    let (uri_str, req_bytes) = {
                        let data = mem.data(&caller);
                        let u_start = uri_ptr as usize;
                        let u_end = u_start.saturating_add(uri_len as usize);
                        let r_start = req_ptr as usize;
                        let r_end = r_start.saturating_add(req_len as usize);
                        if u_end > data.len() || r_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        let Ok(uri_s) = std::str::from_utf8(&data[u_start..u_end]) else {
                            return WASI_ERR_IO;
                        };
                        (uri_s.trim().to_string(), data[r_start..r_end].to_vec())
                    };

                    // Strict URI scheme check (mcp://, a2a://, inference://, egress://)
                    if let Err(e) = validate_mesh_uri(&uri_str) {
                        caller.data_mut().blocked_escape_attempts.push(format!(
                            "mesh_call denied: invalid URI '{}': {}",
                            uri_str, e
                        ));
                        return WASI_ERR_ACCESS_DENIED;
                    }

                    // Extract host-only context from Store
                    let extracted = {
                        let state = caller.data();
                        match state.mesh_context {
                            None => Err("mesh_call denied: no WasmMeshBridgeContext configured in Store".to_string()),
                            Some(ref ctx) if ctx.is_tripped() => Err(format!(
                                "mesh_call denied: KillSwitch tripped for arm '{}'",
                                ctx.arm_id
                            )),
                            Some(ref ctx) if state.mesh_calls_attempted > ctx.max_mesh_calls as u64 => Err(format!(
                                "mesh_call denied: call limit exceeded ({}/{})",
                                state.mesh_calls_attempted, ctx.max_mesh_calls
                            )),
                            Some(ref ctx) => Ok((
                                ctx.arm_id.clone(),
                                ctx.generation_epoch,
                                ctx.role.clone(),
                                ctx.pep_bridge.clone(),
                            )),
                        }
                    };
                    let (arm_id, epoch, role, pep_bridge) = match extracted {
                        Ok(tuple) => tuple,
                        Err(msg) => {
                            caller.data_mut().blocked_escape_attempts.push(msg);
                            return WASI_ERR_ACCESS_DENIED;
                        }
                    };

                    // Dispatch out-of-sandbox via PEP bridge
                    match pep_bridge.dispatch_mesh_call_sync(&arm_id, epoch, &role, &uri_str, &req_bytes) {
                        Ok(sanitized_resp) => {
                            let copy_len = sanitized_resp.len().min(resp_cap as usize);
                            let d_start = resp_ptr as usize;
                            let d_end = d_start.saturating_add(copy_len);
                            {
                                let data = mem.data_mut(&mut caller);
                                if d_end > data.len() {
                                    return WASI_ERR_FAULT;
                                }
                                data[d_start..d_end].copy_from_slice(&sanitized_resp[..copy_len]);
                            }
                            let state = caller.data_mut();
                            state.mesh_calls_succeeded += 1;
                            state.mesh_bytes_exchanged = state
                                .mesh_bytes_exchanged
                                .saturating_add((req_bytes.len() + copy_len) as u64);

                            copy_len as i32
                        }
                        Err(crate::security::agentmesh::pep_bridge::MeshCallError::AccessDenied(msg)) => {
                            caller.data_mut().blocked_escape_attempts.push(format!(
                                "mesh_call policy 403 denied for '{}': {}",
                                uri_str, msg
                            ));
                            WASI_ERR_ACCESS_DENIED
                        }
                        Err(crate::security::agentmesh::pep_bridge::MeshCallError::KillSwitchTripped(arm)) => {
                            caller.data_mut().blocked_escape_attempts.push(format!(
                                "mesh_call aborted: KillSwitch tripped for arm '{}'",
                                arm
                            ));
                            WASI_ERR_ACCESS_DENIED
                        }
                        Err(e) => {
                            caller.data_mut().blocked_escape_attempts.push(format!(
                                "mesh_call failed for '{}': {}",
                                uri_str, e
                            ));
                            WASI_ERR_ACCESS_DENIED
                        }
                    }
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 7. octopus_wasi::mesh_stream_open(uri_ptr, uri_len, flags) -> fd (Weakness 6)
        linker
            .func_wrap(
                "octopus_wasi",
                "mesh_stream_open",
                |mut caller: Caller<'_, WasmHostState>,
                 uri_ptr: i32,
                 uri_len: i32,
                 flags: i32|
                 -> i32 {
                    if uri_ptr < 0 || uri_len <= 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let uri_str = {
                        let data = mem.data(&caller);
                        let u_start = uri_ptr as usize;
                        let u_end = u_start.saturating_add(uri_len as usize);
                        if u_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        match std::str::from_utf8(&data[u_start..u_end]) {
                            Ok(s) => s.trim().to_string(),
                            Err(_) => return WASI_ERR_IO,
                        }
                    };

                    if let Err(e) = validate_mesh_uri(&uri_str) {
                        caller.data_mut().blocked_escape_attempts.push(format!(
                            "mesh_stream_open denied: invalid URI '{}': {}",
                            uri_str, e
                        ));
                        return WASI_ERR_ACCESS_DENIED;
                    }

                    let state = caller.data();
                    let Some(ref ctx) = state.mesh_context else {
                        return WASI_ERR_ACCESS_DENIED;
                    };

                    if ctx.is_tripped() {
                        return WASI_ERR_ACCESS_DENIED;
                    }

                    if state.active_streams.len() >= MAX_VIRTUAL_MESH_STREAMS {
                        caller.data_mut().blocked_escape_attempts.push(format!(
                            "mesh_stream_open denied: active stream descriptor limit ({}) exceeded",
                            MAX_VIRTUAL_MESH_STREAMS
                        ));
                        return WASI_ERR_ACCESS_DENIED;
                    }

                    let state_mut = caller.data_mut();
                    let fd = state_mut.next_stream_fd;
                    state_mut.next_stream_fd = state_mut.next_stream_fd.wrapping_add(1).max(3);
                    let stream = VirtualMeshStream::new(fd, uri_str, flags);
                    state_mut.active_streams.insert(fd, stream);

                    fd as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 8. octopus_wasi::mesh_stream_write(fd, src_ptr, src_len) -> i32 (Weakness 6)
        linker
            .func_wrap(
                "octopus_wasi",
                "mesh_stream_write",
                |mut caller: Caller<'_, WasmHostState>,
                 fd: i32,
                 src_ptr: i32,
                 src_len: i32|
                 -> i32 {
                    if fd < 0 || src_ptr < 0 || src_len < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };
                    let chunk = {
                        let data = mem.data(&caller);
                        let s_start = src_ptr as usize;
                        let s_end = s_start.saturating_add(src_len as usize);
                        if s_end > data.len() {
                            return WASI_ERR_FAULT;
                        }
                        data[s_start..s_end].to_vec()
                    };

                    let state = caller.data_mut();
                    let Some(stream) = state.active_streams.get_mut(&(fd as u32)) else {
                        return WASI_ERR_FAULT;
                    };

                    let max_bytes = state.mesh_context.as_ref().map_or(16 * 1024 * 1024, |c| c.max_mesh_bytes);
                    if stream.write_buffer.len().saturating_add(chunk.len()) > max_bytes {
                        state.stream_fallback_needed = true;
                        state.blocked_escape_attempts.push(format!(
                            "mesh_stream_write: stream buffer capacity exceeded ({} bytes), flagging Tier 2 fallback",
                            max_bytes
                        ));
                        return WASI_ERR_ACCESS_DENIED;
                    }

                    stream.write_buffer.extend_from_slice(&chunk);
                    stream.total_bytes_written += chunk.len() as u64;
                    state.mesh_bytes_exchanged = state.mesh_bytes_exchanged.saturating_add(chunk.len() as u64);

                    chunk.len() as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 9. octopus_wasi::mesh_stream_read(fd, dst_ptr, dst_cap) -> i32 (Weakness 6)
        linker
            .func_wrap(
                "octopus_wasi",
                "mesh_stream_read",
                |mut caller: Caller<'_, WasmHostState>,
                 fd: i32,
                 dst_ptr: i32,
                 dst_cap: i32|
                 -> i32 {
                    if fd < 0 || dst_ptr < 0 || dst_cap < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let Some(wasmtime::Extern::Memory(mem)) = caller.get_export("memory") else {
                        return WASI_ERR_FAULT;
                    };

                    let needs_dispatch = {
                        let state = caller.data();
                        match state.active_streams.get(&(fd as u32)) {
                            Some(s) => !s.dispatched,
                            None => return WASI_ERR_FAULT,
                        }
                    };

                    if needs_dispatch {
                        let (arm_id, epoch, role, uri, payload, pep_bridge) = {
                            let state = caller.data();
                            let ctx = match state.mesh_context {
                                Some(ref c) => c,
                                None => return WASI_ERR_ACCESS_DENIED,
                            };
                            if ctx.is_tripped() {
                                return WASI_ERR_ACCESS_DENIED;
                            }
                            let stream = match state.active_streams.get(&(fd as u32)) {
                                Some(s) => s,
                                None => return WASI_ERR_FAULT,
                            };
                            (
                                ctx.arm_id.clone(),
                                ctx.generation_epoch,
                                ctx.role.clone(),
                                stream.uri.clone(),
                                stream.write_buffer.clone(),
                                ctx.pep_bridge.clone(),
                            )
                        };

                        caller.data_mut().mesh_calls_attempted += 1;
                        match pep_bridge.dispatch_mesh_call_sync(&arm_id, epoch, &role, &uri, &payload) {
                            Ok(resp) => {
                                let state = caller.data_mut();
                                if let Some(stream) = state.active_streams.get_mut(&(fd as u32)) {
                                    stream.read_buffer = resp;
                                    stream.dispatched = true;
                                }
                                state.mesh_calls_succeeded += 1;
                            }
                            Err(crate::security::agentmesh::pep_bridge::MeshCallError::AccessDenied(_)) => {
                                return WASI_ERR_ACCESS_DENIED;
                            }
                            Err(crate::security::agentmesh::pep_bridge::MeshCallError::KillSwitchTripped(_)) => {
                                return WASI_ERR_ACCESS_DENIED;
                            }
                            Err(_) => {
                                return WASI_ERR_IO;
                            }
                        }
                    }

                    let (copy_len, chunk) = {
                        let state = caller.data();
                        let stream = match state.active_streams.get(&(fd as u32)) {
                            Some(s) => s,
                            None => return WASI_ERR_FAULT,
                        };
                        let remaining = stream.read_buffer.len().saturating_sub(stream.read_cursor);
                        let len = remaining.min(dst_cap as usize);
                        let c = stream.read_buffer[stream.read_cursor..stream.read_cursor + len].to_vec();
                        (len, c)
                    };

                    if copy_len > 0 {
                        let d_start = dst_ptr as usize;
                        let d_end = d_start.saturating_add(copy_len);
                        {
                            let data = mem.data_mut(&mut caller);
                            if d_end > data.len() {
                                return WASI_ERR_FAULT;
                            }
                            data[d_start..d_end].copy_from_slice(&chunk);
                        }
                        let state = caller.data_mut();
                        if let Some(stream) = state.active_streams.get_mut(&(fd as u32)) {
                            stream.read_cursor += copy_len;
                            stream.total_bytes_read += copy_len as u64;
                        }
                        state.mesh_bytes_exchanged = state.mesh_bytes_exchanged.saturating_add(copy_len as u64);
                    }

                    copy_len as i32
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        // 10. octopus_wasi::mesh_stream_close(fd) -> i32 (Weakness 6)
        linker
            .func_wrap(
                "octopus_wasi",
                "mesh_stream_close",
                |mut caller: Caller<'_, WasmHostState>, fd: i32| -> i32 {
                    if fd < 0 {
                        return WASI_ERR_FAULT;
                    }
                    let state = caller.data_mut();
                    if state.active_streams.remove(&(fd as u32)).is_some() {
                        0
                    } else {
                        WASI_ERR_FAULT
                    }
                },
            )
            .map_err(|e| OctopusSecurityError::IsolationViolation(e.to_string()))?;

        Ok(())
    }
}
