//! # AgentOctopus (`agent_octopus`)
//!
//! **Single-Binary Rust Deterministic Agent Containment Runtime**
//!
//! > *`google/agentmesh` connects agents across machines; AgentOctopus is the single-binary Rust
//! > runtime that ensures a hijacked agent cannot own the host or exfiltrate secrets.*
//!
//! Every security allow/deny decision in `AgentOctopus` is enforced **100% deterministically** at
//! the host, binary, and process boundary. Any learned or statistical scoring module (including
//! [`security::latent_shield::UnifiedSecurityShield`] and the optional offline/advisory
//! [`security::rl_defense`] D3QN scorer) is strictly **monotonic / tighten-only** or **non-gating**
//! and can **never** weaken or override a deterministic deny.
//!
//! ---
//!
//! ## Core Architecture (Requirements R1–R8)
//!
//! 1. **The 4 Deterministic Containment Pillars**:
//!    - **RT-ASP Sanitizers** (`security::rasp`, `security::agent_hooks`, `security::sensitive_paths`,
//!      `security::atif_scan`): Unicode/Agentjacking/GhostJacking normalization, EchoLeak defanging,
//!      mandatory write-deny guards (`.ssh`, `.aws`, `.git/hooks`, `.mcp.json`, etc.), and `SemanticDlpEngine`.
//!    - **AWS Cedar v4.13 PARC Gate** (`security::cedar_arm`, `containment_ring::cedar_gate`):
//!      Default-deny authorization over **11 entity types** and **13 actions** (`exec`, `egress`,
//!      `inbound_perimeter`, `fs_read`, `fs_write`, `tool_call`, `write`, `extract`, `notify`,
//!      `change_security_policy`, `quarantine`, `kernel_enforce`, `evaluate`).
//!    - **Wasmtime v49.0.4 Tier-1 Sandbox** (`security::wasm_tier1`, `security::openshell`):
//!      Zero ambient WASI sockets/FS/env, `64 KiB..=64 MiB` `ResourceLimiter` cap, deterministic
//!      Cranelift fuel metering, `<1ms` epoch `KillSwitch` interruption, and confined `octopus_wasi` imports.
//!    - **Tier-2 OS Kernel Sandboxes & Loopback Policy Proxy** (`security::linux_sandbox`,
//!      `security::windows_sandbox`, `security::token_posture`, `security::macos_sandbox`,
//!      `security::bsd_sandbox`, `cli::proxy`, `security::host_network_isolation`):
//!      Linux Landlock + `seccomp-BPF` + `PR_SET_NO_NEW_PRIVS` + `RLIMIT_AS`, Windows Restricted Token /
//!      AppContainer + `WindowsJobObject`, macOS Seatbelt SBPL + `libproc`, BSD `unveil`/`pledge`/Capsicum,
//!      loopback HTTP/CONNECT proxy with DNS pinning, Cloud IMDS (`169.254.169.254`) block,
//!      `CredentialSentinelMasker` (`ao_mask_*`), and SHA-256 Merkle audit receipts (`core::merkle`).
//!
//! 2. **R6 — Multi-OS Kernel Patcher & Zero-Reboot Virtual-Patching Shield**
//!    (`security::kernel_patcher`, `security::virtual_patch_shield`, `arm::kernel_sentinel_arm`):
//!    - Discovers OS/kernel CPE 2.3 identifiers across **6 OS families** (`Windows`, `Linux`, `macOS`,
//!      `FreeBSD`, `OpenBSD`, `NetBSD`) and **17 Linux distributions**, queries NIST NVD 2.0 + CISA KEV,
//!      and orchestrates rebootless livepatching (`canonical-livepatch`, `kpatch`, `ksplice`/`uptrack`,
//!      `klp`/`kgraft`, Windows Hotpatch) or native OS patching without unsafe ring-0 code splicing.
//!    - Enforces **No Break-Out / No Break-In** zero-reboot containment: Tier-1 Wasmtime promotion
//!      (`--sandbox wasm-strict`, `--wasm-promote`), Linux `seccomp-BPF` EoP/escape syscall clamps,
//!      Windows `OsoosiDriver` BYOVD blocklists + process mitigations, macOS Seatbelt + BSD clamps,
//!      WFP/`nftables`/Netlink/`pfctl` inbound shields, and tighten-only Cedar `forbid(...)` hot-reload.
//!    - Enforces the 5 Foolproof Invariants including `shield_locked_until_reboot` and
//!      `telemetry_degraded_fail_closed`.
//!
//! 3. **R7 — Fast `<2ms` Pre-Spawn REA PE/ELF/Mach-O Binary Gate**
//!    (`security::rea_binary_gate`, `security::executable_identity`, `security::rate_limit_backoff`):
//!    - Bounds-checked, zero-panic pure-Rust pre-exec header and stub scanner running over TOCTOU-locked
//!      handles (`open_and_lock_executable_for_cli` / `BinarySource::LockedFile`) without heavy EDR
//!      disassembler or memory-carving bloat.
//!    - Detects packers (`UPX0`/`UPX1`/`UPX!`/`MPRESS`/`.vmp0`/`.themida`/`.aspack`), `W^X` sections/segments,
//!      packed Shannon entropy (`>= 6.4` + anomaly), Authenticode/`LC_CODE_SIGNATURE` presence, and
//!      Hell's/Halo's Gate or raw direct-syscall/`svc #0x80` stubs, bridged into `ReteEngine` (`ReaBinaryFact`).
//!
//! 4. **R8 — Pure-Rust `UnifiedSecurityShield`** (`security::latent_shield`, `cli::latent_shield`):
//!    - Pure-Rust (`ndarray` + `rand_distr`) shared `LatentWorldModel` (`latent_dim = 4`, `hidden = 32`)
//!      with embedded deterministic JSON weights (`DEFAULT_EMBEDDED_WEIGHTS_JSON`) and `--latent-weights <PATH>`.
//!    - **Gate 1 (`SbomSupplyChainGuard`)**: Pre-Wasmtime / pre-spawn CycloneDX SBOM transition check (`octopus run --baseline-sbom ... --sbom ...` or `octopus sbom-guard`).
//!    - **Gate 2 (`AgentRuntimeGuard` / `LiveRuntimeMonitor`)**: Microsecond Wasmtime & runtime telemetry step guard.
//!    - Strictly **tighten-only** and fail-closed on `NaN`/`Inf`, dimension mismatches, symlinks, or oversized JSON.
//!
//! 5. **Optional Offline / Advisory Telemetry (D3QN)** (`security::rl_defense`):
//!    - Disabled by default (`enabled: false`, `advisory_only: true`; opt-in via `OCTOPUS_ENABLE_RL_ADVISORY=1`).
//!    - Completely distinct from `UnifiedSecurityShield` and holds **zero** allow/deny authority.
//!
//! ---
//!
//! ## Crate Module Index
//!
//! | Module | Purpose |
//! |---|---|
//! | `cli` | `octopus` CLI parser, `run` orchestrator, loopback egress proxy, Wasm runner, SBOM guard CLI |
//! | `security::cedar_arm` | AWS Cedar v4.13 policy engine, 11-entity / 13-action schema, Dogwood temporal guard |
//! | `security::wasm_tier1` | Wasmtime v49.0.4 Tier-1 sandbox, fuel/epoch `KillSwitch`, `octopus_wasi` hostcalls |
//! | `security::rasp` | RT-ASP input/output sanitizers, EchoLeak, Agentjacking/GhostJacking, sensitive paths |
//! | `security::linux_sandbox`, `windows_sandbox`, `macos_sandbox`, `bsd_sandbox` | Tier-2 native OS kernel confinement |
//! | `security::kernel_patcher`, `security::virtual_patch_shield` | Multi-OS kernel CVE/KEV orchestrator and zero-reboot virtual-patch shield |
//! | `security::rea_binary_gate`, `security::executable_identity` | `<2ms` TOCTOU-locked PE/ELF/Mach-O/Wasm pre-spawn binary gate |
//! | `security::latent_shield` | Pure-Rust `UnifiedSecurityShield`, `LatentWorldModel`, `SbomSupplyChainGuard`, `AgentRuntimeGuard` |
//! | `security::host_network_isolation` | Zero-subprocess WFP, Netlink/SOCK_DESTROY, `nftables`, and `/dev/pf` host isolation |
//! | `security::agentmesh` | `google/agentmesh` OIDC/JWKS issuer, PEP bridge, Ed25519 mandate attenuation |
//! | `containment_ring` | Dual concentric containment rings, `CedarGate`, `EgressProxy`, `TieredExecutionDispatcher` |
//! | `arm`, `brain`, `enclave` | Multi-arm enclave runtime (`KernelSentinelArm` / `OsoosiDriver`, `TarpitArm`), central brain |
//! | `core::merkle`, `core::circuit_breaker` | RFC 6962 SHA-256 Merkle trees and sub-millisecond `KillSwitch` |
//! | `web` | Loopback Web Dashboard & authenticated REST API (`127.0.0.1:3030`) |
//! | `verify`, `service` | 7-phase self-diagnostics (`octopus verify`) and native OS service manager |
//! | `adversary` | `PromptInjectionEngine` and multi-category adversarial attack campaign evaluation |
//! | `conformal_jailbreak` | Multi-source conformal unseen jailbreak source detection (`Persist-3` & `SR-DKW`) |
//! | `deterministic` | `DeterministicLayer` unifying FSM transitions, `PolicyGuard`, and `SchemaGuard` |
//! | `edr_bench` | Two-gate `EdrBenchTask` verification harness (`FAIL_TO_PASS` / `PASS_TO_PASS`) for detection rules |
//! | `fprime_flight` | NASA JPL `F'` flight-software swarm backbone (`Fw::Comp`/`Port`, static arenas, `Svc::Health`, `CmdSequencer`) |
//! | `ledger` | Signed execution receipts, `QuorumPolicyGuard`, PQC attestation, and RFC 6962 transparency log |
//! | `neural_mesh` | Authenticated, anti-replay inter-arm `NeuralMessage` transport with dual capability grants |
//! | `quantum` | Swarm `AttackGraph`, `QuantumCircuit` simulator, quantum walk, and QUBO optimizer |
//! | `research_ingest` | Autonomous security research ingestion, 4-gate validation, and CVE `forbid(...)` hot-reload |
//! | `sentinel_ring` | Out-of-band Ring-4 Octopus Sentinel Ring (`SentinelSupervisor`, integrity, epoch revocation, emergency lockdown) |
//! | `swarm` | `SwarmManager` concurrent limb orchestrator with per-arm `KillSwitch` and cancellation tokens |
//! | `telemetry` | W3C TraceContext OpenTelemetry (`OtelSpan`), `AnomalyDetector`, and `WatchdogSupervisor` |
//! | `security::rl_defense` | Optional offline/advisory D3QN telemetry scorer (`enabled: false` by default) |
//!
//! ---
//!
//! ## Quickstart (CLI & Embedded Rust)
//!
//! Run any untrusted workload from the CLI:
//!
//! ```text
//! octopus run --policy examples/quickstart/policy.json -- python examples/quickstart/my_agent.py
//! ```
//!
//! Evaluate an AWS Cedar v4.13 policy directly from Rust:
//!
//! ```no_run
//! use agent_octopus::security::cedar_arm::CedarPolicyEngine;
//! use serde_json::json;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = CedarPolicyEngine::new()?;
//! let verdict = engine.evaluate(
//!     "ledger_arm",
//!     "write",
//!     "Ledger",
//!     "Ledger",
//!     json!({ "amount_cents": 50000, "approved": true }),
//! )?;
//! assert!(verdict.is_allowed);
//! # Ok(())
//! # }
//! ```

#![allow(
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::collapsible_if,
    clippy::collapsible_match,
    clippy::single_match,
    clippy::needless_range_loop,
    clippy::identity_op,
    clippy::unnecessary_map_or,
    clippy::to_string_trait_impl,
    clippy::new_without_default,
    clippy::useless_format,
    clippy::manual_contains,
    clippy::manual_pattern_char_comparison,
    clippy::manual_strip,
    clippy::manual_range_contains,
    clippy::manual_div_ceil,
    clippy::manual_is_multiple_of,
    clippy::manual_c_str_literals,
    clippy::chunks_exact_to_as_chunks,
    clippy::lines_filter_map_ok,
    clippy::double_ended_iterator_last,
    clippy::drain_collect,
    clippy::for_kv_map,
    clippy::if_same_then_else,
    clippy::len_without_is_empty,
    clippy::let_and_return,
    clippy::match_like_matches_macro,
    clippy::needless_bool,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::needless_late_init,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::redundant_closure,
    clippy::unnecessary_cast,
    clippy::unnecessary_lazy_evaluations,
    clippy::unnecessary_sort_by,
    clippy::unwrap_or_default,
    clippy::upper_case_acronyms,
    clippy::vec_init_then_push,
    clippy::comparison_to_empty,
    clippy::derivable_impls,
    clippy::doc_lazy_continuation,
    clippy::field_reassign_with_default,
    clippy::map_entry,
    clippy::collapsible_str_replace
)]

pub mod adversary;
pub mod arm;
pub mod brain;
pub mod cli;
pub mod conformal_jailbreak;
pub mod containment_ring;
pub mod core;
pub mod deterministic;
pub mod edr_bench;
pub mod enclave;
pub mod fprime_flight;
pub mod ledger;
pub mod neural_mesh;
pub mod quantum;
pub mod research_ingest;
pub mod security;
pub mod sentinel_ring;
pub mod service;
pub mod swarm;
pub mod telemetry;
pub mod verify;
pub mod web;

pub use service::{
    default_service_manager, execute_host_disarm_unauthenticated, handle_service_cli,
    NativeServiceManager, ServiceConfig, ServiceError, ServiceState, ServiceStatus,
    SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME,
};
pub use verify::{PhaseReport, SubsystemVerifier, VerificationReport};

pub use adversary::{
    AdversarialAttack, AttackCategory, AttackEvaluation, CampaignSummary, PromptInjectionEngine,
};
pub use arm::ArmRuntime;
pub use brain::CentralBrain;
pub use containment_ring::{
    ArmContainmentRing, ArmExecutionError, ArmRingConfig, ArmRingMeshMessage, ArmRingRegistry,
    AuditEvent, Authorizer, BoxFuture, BudgetQuota, CapabilityGate, CedarAuthorizer, CedarGate,
    ContainmentRing, EgressProxy, EgressRequest, EgressResponse, EgressSecurityLevel,
    EnclaveToolExecutor, IdentityGate, IsolationManager, MeshGuard, Operation,
    PolicyAttestationRecord, ResourceGuard, RingAttestation, RingAuditEntry, RingAuditLedger,
    RingConfig, RingController, RingDecision, RingError, RingOperationRequest, RingRequest,
    SandboxConstraints, ToolExecutor, TrustedArmHandle,
};
pub use core::circuit_breaker::KillSwitch;
pub use core::merkle::{
    hash_leaf, hash_nodes, verify_execution_step, DatasetMerkleTree, Direction,
    ExecutionMerkleTree, Hash32, MerkleLeaf, MerkleProof, MerkleTree, PolicyMerkleTree,
};
pub use core::types::*;
pub use deterministic::{
    ArmState, DeterministicLayer, FsmTransitionGuard, PolicyGuard, SchemaGuard,
};
pub use edr_bench::{
    resolve_fixture_path, BenchmarkReport, BenignBaselineAssertion, EdrBenchHarness, EdrBenchTask,
    ExpectedVerdict, HarnessBounds, ParsedYaraRule, StringPattern, TargetArch, TelemetryContext,
    ThreatAssertion,
};
pub use enclave::{HttpEgressGate, SafeDocumentExtractor, SafeLedgerWriter, SafeTool};
pub use fprime_flight::{
    create_port_pair, ArenaBinKind, ArenaSlotHandle, BftMeshConsensusComponent,
    BftQuorumPromotionProof, ComponentHealthVerdict, ContainmentDirective,
    EbpfPmuTelemetryComponent, FPrimeComponent, FPrimeError, FPrimeFlightRuntime,
    FPrimeOperatingMode, FPrimeTelemetrySnapshot, FPrimeTopology, InputPort, IsolationAck,
    OutputPort, PingToken, PongToken, PortConnectionDescriptor, PortEnvelope, PortQosLane,
    ReaInspectionVerdict, ReaMagikaInspectorComponent, RecoilAssessment,
    RecoilLikelihoodScorerComponent, SafeModeExecutionReport, SafeModePlaybook, SequencerOp,
    StaticArenaPool, SvcCmdSequencer, SvcHealthMonitor, TelemetryFrame, WatchdogStrokeReceipt,
    WfpNetworkIsolatorComponent,
};
pub use ledger::{
    InclusionProof, LedgerError, LogCheckpoint, PolicyAttestation, PolicyProposal,
    PostQuantumAttestation, PqcAlgorithm, PqcKeypair, ProofDirection, ProofSibling,
    QuorumPolicyGuard, SignedExecutionReceipt, TransparencyLog,
};
pub use neural_mesh::{
    ArmEndpoint, MeshCapabilityGrant, MeshError, MessageKind, NeuralMesh, NeuralMessage,
};
pub use quantum::{
    AgentNode, AttackEdge, AttackGraph, ChannelType, Complex, ExperimentComparisonReport,
    QuantumAnnealerConfig, QuantumCircuit, QuantumGate, QuantumWalkSimulator, QuboModel,
    QuboResult, SimulatedQuantumAnnealer, WalkComparison,
};
pub use research_ingest::{
    approve_ingested_research_rule, approve_pending_research_item, auto_correct_research_rule,
    canonical_research_rule_id, check_paper_to_code_semantic_domain_alignment,
    clear_all_ingested_research_rules, clear_or_restore_research_rules,
    compute_pending_item_priority, default_seeded_research_defense_rules,
    detect_verified_code_repo, evaluate_research_ingest, evaluate_research_novelty_check,
    execute_langgraph_research_swarm, get_pending_research_queue, get_research_schedule,
    get_research_status, is_canonical_m12_research_arxiv_id, is_current_research_arxiv_id,
    is_research_rule_operator_approved, is_research_rule_pinned, is_valid_technical_indicator,
    is_valid_verified_repo_url, list_ingested_research_rules, normalize_base_arxiv_id,
    parse_arxiv_year_month, pin_ingested_research_rule, register_ingested_research_rule,
    reject_pending_research_item, remove_ingested_research_rule, reset_research_defense_registry,
    restore_default_research_rules, run_live_regression_probe, run_paper2agent_accuracy_suite,
    safe_arxiv_abs_url, safe_arxiv_pdf_url, search_research_papers, synthesize_rust_guard_snippet,
    trim_pending_research_queue, update_research_schedule, validate_pending_research_item,
    validate_research_rule_acceptance, verify_generated_guard_code_accuracy,
    verify_rule_against_canary_benign_corpus, AgenticToolInvocation, GlmMultiModelFusionEvaluator,
    GroundedBreakoutExtraction, IngestedResearchDefenseRule, LangGraphEdge,
    LangGraphEdgeTransition, LangGraphNodeExecution, LangGraphSwarmRequest, LangGraphSwarmResponse,
    LiveRegressionProbeReport, LiveRegressionProbeResult, LlmFusionArmReport, LlmFusionConsensus,
    Paper2AgentAccuracySuiteResult, Paper2AgentCompiler, PaperNoveltyEvaluation,
    PendingResearchItem, ResearchAcceptanceVerdict, ResearchApprovalRequest,
    ResearchApprovalResponse, ResearchClearRequest, ResearchClearResponse, ResearchCoverageReport,
    ResearchExtractionItem, ResearchIngestRequest, ResearchIngestResponse, ResearchIngestStore,
    ResearchNoveltyCheckRequest, ResearchNoveltyCheckResponse, ResearchScheduleConfig,
    ResearchScheduleResponse, ResearchScheduleUpdateRequest, ResearchSearchRequest,
    ResearchSearchResponse, ResearchStatusResponse, ResearchValidationResponse, RingProbeVerdict,
    RuleAccuracyReport, VectorCoverageVerdict, ALREADY_IMPLEMENTED_ARXIV_IDS,
    CANARY_BENIGN_TELEMETRY_CORPUS, CODE_REPO_PRIORITY_BOOST, MIN_CURRENT_RESEARCH_ARXIV_YY,
};
pub use security::{
    hmac_sha256, AdaptiveMitigationTier, AgentIdentity, AgentRaspEngine, AgentSecuritySubject,
    AuditRecord, CapabilityToken, CedarAuthorizationGateway, CedarPolicyEngine, CedarSchema,
    DelegationScopeGuard, ExternalAuthorizationEngine, OpenShellConfig, OpenShellMode,
    RaspDecision, RaspThreatCategory, SandboxConfinementPolicy, SecurityAuditLog,
    SignedAgentMessage, WasmArmSandbox,
};
pub use swarm::{SwarmBatchSummary, SwarmManager};
pub use telemetry::{AnomalyDetector, WatchdogSupervisor};
pub use web::{start_web_server, static_files::INDEX_HTML};

pub use containment_ring::{
    is_restricted_rebinding_ip, now_micros, validate_agent_egress_url, AlgebraicTraceProof,
    DiracDeltaCapabilityTicket, HomologicalAuditReport, HomologicalBoundaryAuditor,
    IndependentTrustBoundaryVerifier, MeshWatchOutSignal, MultiLayerGateVerdict,
    PinnedToolObjectBinding, VanishingPolynomialTraceVerifier, ZeroCopyImmutableToolBuffer,
    MERSENNE_PRIME_127,
};
pub use security::{
    calibrate_glm_for_hardware, compute_hardened_console_mode,
    evaluate_pre_resume_confinement_gate, harden_windows_console, is_console_mode_hardened,
    probe_ollama_installed_tags_fast, validate_agent_filesystem_access,
    validate_sandbox_relative_path, verify_windows_confinement_invariants,
    AgentClassificationVerdict, AlignmentScanVerdict, ArtifactKey, ClassificationLattice,
    CommandConsoleExt, ConfidenceInterval95, CyberBattleBenchmarkReport, DlpBaggage,
    DlpLineageEngine, DynamicAgentClassifier, FileLineageRecord, FileLineageTracker,
    GlmFusionCalibrationReport, GlmHardwareSpec, GlmModelTier, HostActuationPore,
    LineageCheckVerdict, MercuryContainmentEngine, MercuryEvaluationResult,
    OrbWebContainmentEngine, OrbWebEvaluationResult, PolicyBenchmarkMetrics, PolicyLattice,
    ProcessBehavioralTelemetry, ProcessInstanceKey, RuntimeAlignmentScanner, SessionIntentContract,
    SilkRegime, ToolCallTraceStep, WindowsConfinementPolicy, ZeroMiProjectionResult,
    ZeroMutualInformationProjector,
};

pub use security::{
    CageGovernanceEngine, CageRoutingSeal, CbfSafetyEngine, CbfViolation, CommitReceipt,
    CompiledCagePolicy, DebitLedger, FormalBfsModel, FtraVerdict, GovernanceEvaluationResult,
    GovernanceRequest, GovernanceVerdict, PlanGraphAnalyzer, PlanStep, PolicyFormat,
    RoutingSealSigner, SealRejection, StreamVerificationReport, SubstrateTranslator,
    TheoremProofResult,
};

pub use security::{
    active_vpatch_wfp_filter_count, apply_virtual_patch_perimeter_shield,
    apply_virtual_patch_perimeter_shield_with_options, base64url_decode_no_pad,
    base64url_encode_no_pad, build_linux_blackhole_route_msg, build_linux_nft_vpatch_netlink_batch,
    build_virtual_patch_perimeter_spec, canonicalize_jcs, canonicalize_jcs_string,
    disarm_virtual_patch_perimeter_shield, discover_active_octopus_ports, freeze_process_by_pid,
    generate_bsd_darwin_pf_virtual_patch_rules, generate_linux_nftables_virtual_patch_rules,
    generate_macos_pf_quarantine_rules, global_host_killswitch, handle_wfp_kernel_apply_cli,
    has_live_active_vpatch_wfp_filters, has_live_active_wfp_filters, resolve_loopback_peer_pid,
    resume_process_by_pid, CageAttestationResponse, CageConformalBaselineResponse,
    CageConformalValidateRequest, CageConformalValidateResponse, CageKeyManifestResolver,
    CageQuarantineReceiptResponse, CageQuarantineReleaseReceiptResponse,
    CageQuarantineReleaseRequest, CageQuarantineRequest, CageSubstrateState, Cumulative24hTracker,
    HostIsolationError, HostIsolationReceipt, HostKillSwitchManager, HostKillSwitchStatus,
    JcsError, JournalData, JournalRecord, JwkKeyDto, JwksResponse, KernelIsolationBackend,
    KernelPerimeterPatchSpec, KeyedCumulative24hTracker, NonceReplayCache, OsiLayer,
    ProtocolDefinition, ProtocolDomain, ProtocolVectorType, QuarantineJournal, QuarantineLease,
    SealedJournalEnvelope, UniversalProtocolCatalog, VIRTUAL_PATCH_INBOUND_PORTS,
};

pub use security::{
    validate_mesh_uri, AgentMeshBindingDef, AgentMeshConfig, AgentMeshEngine,
    AgentMeshPolicyConfig, AgentMeshPolicyRoot, AgentMeshReferenceNode, AgentMeshRoleDef,
    AgentMeshServingNode, AgentMeshStatus, AsyncHttpWireClient, AttenuatedMandate, CachedMeshToken,
    ConformanceNodeStats, DelegationLink, EcJwk, ExchangedTokenMetadata, JwksDocument, JwsHeader,
    MandateError, MeshCallError, MeshCallReceipt, OctopusOidcActorIssuer, OidcError,
    OpenIdConfiguration, PepBridgeConfig, PepVaultTelemetry, ServingNodeStats, SyncHttpWireClient,
    WorkloadClaims,
};

pub use security::{
    apply_shield_posture, build_shield_receipt, build_shield_receipt_with_enforcement,
    current_shield_posture, global_shield_store, mark_shield_telemetry_degraded,
    KernelAttackSurface, KernelShieldPosture, VirtualPatchShieldReceipt, VirtualPatchShieldStore,
    ENV_SHIELD_POSTURE_PATH,
};
pub use security::{
    classify_mandatory_write_deny_path, classify_pinned_parent_for_write_deny,
    classify_sensitive_system_path, extract_hosts_from_text, global_cpu_pool,
    host_port_pattern_matches, init_global_cpu_pool, is_denied_resolved_ip,
    is_denied_resolved_ip_with_local, is_mandatory_write_deny_path, is_sensitive_credential_store,
    local_host_interface_ips, parse_and_validate_dynamic_policy, resolve_and_pin_allowed_host,
    spawn_cpu, validate_http_request_target, AtifScanner, AtifSeverity, AtifSignal, CpuPoolError,
    CpuThreadPool, CredentialSentinelMasker, DynamicNetworkPolicy, IpCidr, JournalEntry,
    JournalWatcherConfig, MandatoryWriteDenyKind, SafeAgentsClient, SafeAgentsClientConfig,
    SafeAgentsClientError, SafeAgentsHarnessEvaluator, SafeAgentsJournalWatcher,
    SafeAgentsJournalWatcherHandle, SensitiveCredentialStoreKind, ToolCallEvaluator,
    ToolEvaluationVerdict, ToolInvocationContext, ToolVerdict,
};
pub use security::{
    classify_mcp_action, detect_language_and_script, fold_confusables_and_diacritics,
    validate_loopback_translate_url, verify_translation_integrity, AbiboDirection,
    AbiboMediationCoordinator, AbiboMerkleAuditRecord, AbiboStatusSnapshot,
    ActionTrajectoryPerplexity, ActionTrajectoryVerdict, AgentActionClass, ArtemisCollectionReport,
    ArtemisDfirEngine, ArtemisForensicEvent, CandidateActionProposal, CanonicalTranslationLayer,
    ControlSynthesisKind, DefangedToolResponse, DetectedLanguageProfile, ForensicArtifactKind,
    ForensicControlCompiler, ForensicSeverity, GaussFluxCage, GaussFluxVerdict, HalfLifeVerdict,
    HamiltonianBarrierEngine, HamiltonianVerdict, HitlApprovalTicket, HitlTicketStatus,
    HumanWorkResetProof, LanguageTier, LivenessEventRecord, McpConnectorAuditEntry,
    McpMediationDecision, McpMediationReport, McpMediationRequest, McpToolManifest,
    McpToolSchemaPinRegistry, MemoryAttestationRecord, MemoryPlane, MemoryProvenanceGuard,
    MemoryProvenanceVerdict, NewCoreGrokSimulationReport, NonHumanIdentityRecord,
    PerplexityDefenseCoordinator, PerplexityTranslationReport, PersistenceArtifactFinding,
    PhaseSpaceState, PinnedToolSchemaRecord, QuantumZenoGuard, QuantumZenoVerdict,
    RadioactiveHalfLifeEngine, RelativityCausalityGate, RelativityConfig, RelativityVerdict,
    SchemaPinVerdict, ScriptFamily, SemanticEntropyGate, SemanticEntropyVerdict, SignedTaintHeader,
    SingleUseCapabilityToken, SleepLockWindow, SpectralBeaconDetector, SpectralBeaconVerdict,
    SynthesizedControlAction, ThermodynamicTaintEngine, ThermodynamicsVerdict, TranslationBackend,
    TranslationInspectionVerdict, TranslationLayerConfig, WindowedPerplexityAnalyzer,
    WindowedPerplexityVerdict, WindowsPrefetchHeader, WorkstationLivenessSnapshot,
    WorkstationLivenessTracker, DEFAULT_HITL_TTL_SECS,
};
pub use security::{
    extract_sbom_features, load_cyclonedx_sbom_file, parse_cyclonedx_sbom_bounded,
    validate_sbom_bounds, AgentRuntimeGuard, ComponentProperty, CycloneDxSbom, GuardVerdict,
    LatentShieldError, LatentWorldModel, LicenseChoice, LicenseDetail, LiveRuntimeMonitor,
    RuntimeEventKind, RuntimeGuardVerdictSummary, RuntimeTelemetry, SbomComponent, SbomDependency,
    SbomIntent, SbomSupplyChainGuard, UnifiedSecurityShield, DEFAULT_EMBEDDED_WEIGHTS_JSON,
    DEFAULT_LATENT_DIM, MAX_MODEL_DIM, MAX_SBOM_COMPONENTS, MAX_SBOM_DEPENDENCIES, MAX_SBOM_EDGES,
    MAX_SBOM_JSON_BYTES, MAX_SBOM_LICENSES_PER_COMPONENT, MAX_SBOM_PROPERTIES_PER_COMPONENT,
    MAX_SBOM_STRING_LEN, MAX_WEIGHTS_JSON_BYTES, RUNTIME_ACTION_DIM, RUNTIME_OBS_DIM,
    SBOM_ACTION_DIM, SBOM_OBS_DIM,
};
pub use security::{
    global_rete_engine, inspect_binary_bytes, inspect_locked_file,
    open_and_lock_executable_for_cli, BinaryFormat, BinaryIntegrityVerdict, ByteCursor,
    PreSpawnReaPolicy, PreSpawnReaVerdict, ReaBinaryFact, ReteEngine,
};
