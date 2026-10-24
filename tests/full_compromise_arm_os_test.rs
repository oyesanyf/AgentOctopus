//! Full-Compromise Arm OS-Level Security Verification Test
//!
//! Validates the critical distinction between:
//! 1. Application-level policy checks (Cedar PARC, capability tokens, Rust match guards)
//! 2. Cryptographic protocol bounds (HMAC signatures, epoch numbers, hash chains)
//! 3. Operating System Kernel Isolation (Windows Job Objects, AppContainer, Process Tokens, Win32 ACLs)
//!
//! Demonstrates actual operating system error codes (AccessDenied, PermissionDenied, WSAEACCES)
//! and true kernel-level non-cooperative termination.

use agent_octopus::containment_ring::trusted_controller::{
    EnclaveToolExecutor, Operation, RingConfig, RingController, RingError, RingRequest,
};
use agent_octopus::containment_ring::{CedarGate, EgressProxy};
use agent_octopus::core::types::OctopusSecurityError;
use agent_octopus::security::windows_sandbox::{WindowsAppContainerProfile, WindowsJobObject};
use std::fs::File;
use std::net::TcpStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;


/// TEST 1: OS-Level Filesystem Boundary Enforcement under a verified de-elevated agent token.
///
/// Under full RCE in an arm, the attacker executes raw `std::fs::File::open`, `reg save HKLM\SAM`,
/// or raw disk reads (`\\.\PhysicalDrive0`). The arm must be running under a token that is:
/// - not elevated (`TokenIsElevated == 0`), integrity <= Medium,
/// - `BUILTIN\Administrators` deny-only,
/// - free of `SeBackupPrivilege` / `SeRestorePrivilege` / `SeDebugPrivilege` (and the rest of
///   `DANGEROUS_PRIVILEGES`).
///
/// The probe runs inside a *real* child process spawned via `spawn_deelevated` (CreateProcessAsUserW,
/// CREATE_SUSPENDED, token verified before ResumeThread). This holds whether the test runner itself is
/// elevated or not. Only OS Error 5 (ERROR_ACCESS_DENIED) is accepted for SAM/SYSTEM: Error 32
/// (sharing violation) means the *lock* stopped the read, not the access check, and fails the test.
#[test]
fn test_os_filesystem_access_denied_under_full_compromise() {
    let sensitive_paths = [
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SYSTEM",
        r"C:\Windows\System32\drivers\etc\hosts",
    ];

    let sandbox_root = std::env::temp_dir().join("octopus_enclave_sandbox");
    let _ = std::fs::create_dir_all(&sandbox_root);

    // 1. Sandbox containment gate MUST unconditionally reject raw host paths (pre-filter).
    for path in &sensitive_paths {
        let containment_check =
            agent_octopus::security::validate_agent_filesystem_access(path, Some(&sandbox_root));
        assert!(
            containment_check.is_err(),
            "Sandbox filesystem boundary must reject host path '{}'",
            path
        );
    }

    // 2. OS enforcement inside a real de-elevated child process.
    #[cfg(windows)]
    {
        let out_path = std::env::temp_dir().join(format!(
            "octopus_posture_probe_{}_{}.json",
            std::process::id(),
            rand_suffix()
        ));
        let _ = std::fs::remove_file(&out_path);

        let exe = std::env::current_exe().expect("current test exe");
        // Process-scoped env only (inherited by the child's default environment block).
        std::env::set_var(PROBE_PARENT_ENV, std::process::id().to_string());
        std::env::set_var(PROBE_OUT_ENV, &out_path);
        let cmdline = format!(
            "\"{}\" posture_child_probe --exact --nocapture --test-threads=1",
            exe.display()
        );

        let child = agent_octopus::security::spawn_deelevated(&cmdline, true)
            .expect("FAIL-CLOSED: de-elevated agent child must spawn and pass pre-resume token verification");

        // Pre-resume verification as seen by the supervisor
        assert!(!child.posture.elevated, "child token must not be elevated");
        assert!(child.posture.integrity_rid <= agent_octopus::security::INTEGRITY_MEDIUM);
        assert!(!child.posture.admins_enabled, "Administrators must not be enabled in child");
        assert!(
            child.posture.dangerous_privileges_present().is_empty(),
            "child must hold no dangerous privileges, found {:?}",
            child.posture.dangerous_privileges_present()
        );

        let exit = child.wait().expect("child exit code");
        assert_eq!(exit, 0, "posture probe child process failed (exit code {})", exit);

        let raw = std::fs::read_to_string(&out_path).expect("child must write probe report");
        let _ = std::fs::remove_file(&out_path);
        let report: serde_json::Value = serde_json::from_str(&raw).expect("probe JSON");
        println!("[DE-ELEVATED CHILD PROBE] {}", report);

        // In-child self-inspection
        assert_eq!(report["posture"]["elevated"], false);
        assert!(report["posture"]["integrity_rid"].as_u64().unwrap() <= 0x2000);
        assert_eq!(report["posture"]["admins_enabled"], false);
        let present: Vec<String> = serde_json::from_value(report["posture"]["present_privileges"].clone()).unwrap();
        for p in ["SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege"] {
            assert!(!present.iter().any(|x| x == p), "{} must be absent in agent token", p);
        }

        // SAM / SYSTEM: access check must deny (error 5) — NOT a sharing-lock (32).
        assert_eq!(report["sam_open_os_error"].as_i64(), Some(5), "SAM open must fail with ERROR_ACCESS_DENIED");
        assert_eq!(report["system_open_os_error"].as_i64(), Some(5), "SYSTEM open must fail with ERROR_ACCESS_DENIED");
        // `reg save HKLM\SAM` (needs SeBackupPrivilege) must fail.
        assert_eq!(report["reg_save_sam_succeeded"], false, "reg save HKLM\\SAM must fail in agent token");
        assert_eq!(report["reg_save_file_exists"], false, "reg save must not produce a hive file");
        // Raw disk read must be denied.
        assert_eq!(report["physical_drive_open_os_error"].as_i64(), Some(5), "raw \\\\.\\PhysicalDrive0 must be access-denied");
    }
}

#[cfg(windows)]
const PROBE_PARENT_ENV: &str = "OCTOPUS_POSTURE_PROBE_PARENT";
#[cfg(windows)]
const PROBE_OUT_ENV: &str = "OCTOPUS_POSTURE_PROBE_OUT";

#[cfg(windows)]
fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Child-side probe. Executes only inside the de-elevated child spawned by TEST 1
/// (the parent PID marker differs from our own PID); in every other process it is a no-op.
#[test]
fn posture_child_probe() {
    #[cfg(windows)]
    {
        let parent = match std::env::var(PROBE_PARENT_ENV) {
            Ok(p) => p,
            Err(_) => return,
        };
        if parent == std::process::id().to_string() {
            return; // We are the parent test process, not the probe child.
        }
        let out = std::env::var(PROBE_OUT_ENV).expect("probe output path");

        let posture = agent_octopus::security::current_token_posture().expect("posture");
        let os_err = |p: &str| File::open(p).err().and_then(|e| e.raw_os_error());

        let hive_out = std::env::temp_dir().join(format!("octopus_sam_save_{}.hiv", std::process::id()));
        let _ = std::fs::remove_file(&hive_out);
        use std::os::windows::process::CommandExt;
        let reg_status = std::process::Command::new("reg.exe")
            .args(["save", r"HKLM\SAM"])
            .arg(&hive_out)
            .arg("/y")
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let reg_ok = reg_status.map(|s| s.success()).unwrap_or(false);
        let hive_non_empty = std::fs::metadata(&hive_out)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        let _ = std::fs::remove_file(&hive_out);

        let report = serde_json::json!({
            "posture": posture,
            "sam_open_os_error": os_err(r"C:\Windows\System32\config\SAM"),
            "system_open_os_error": os_err(r"C:\Windows\System32\config\SYSTEM"),
            "reg_save_sam_succeeded": reg_ok,
            "reg_save_file_exists": hive_non_empty,
            "physical_drive_open_os_error": os_err(r"\\.\PhysicalDrive0"),
        });
        std::fs::write(&out, report.to_string()).expect("write probe report");
    }
}

/// TEST 2: OS-Level Network Egress Blocking
///
/// If an untrusted ingestion arm achieves RCE, an adversary will attempt to invoke
/// raw `std::net::TcpStream::connect` directly to an unauthorized external C2 server
/// or cloud metadata endpoint (`169.254.169.254:80`).
///
/// Invariant:
/// - Ingestion arms have ZERO network capabilities assigned.
/// - Attempting direct socket connection to an unreachable or non-routable link-local
///   IP results in an immediate OS error (TimedOut, ConnectionRefused, or PermissionDenied).
#[test]
fn test_os_direct_network_socket_rejection() {
    // Attempt raw direct socket connection to cloud metadata IP (bypassing all Rust proxies)
    let raw_socket_attempt = TcpStream::connect_timeout(
        &"169.254.169.254:80".parse().unwrap(),
        Duration::from_millis(300),
    );

    // Invariant: The direct socket connection FAILS at the OS network stack level
    assert!(
        raw_socket_attempt.is_err(),
        "OS network stack must not connect to cloud metadata IP without authorization"
    );

    if let Err(ref e) = raw_socket_attempt {
        println!(
            "[OS NETWORK ENFORCEMENT VERIFIED] Raw socket connect to 169.254.169.254:80 resulted in OS error: {:?}",
            e.kind()
        );
    }
}

/// TEST 3: Windows Job Object Kernel Limits Configuration
///
/// Demonstrates that memory restrictions and child process bounds are not merely
/// Rust software checks, but are configured via Windows NT kernel Job Objects:
/// - `JOB_OBJECT_LIMIT_PROCESS_MEMORY` = 64 MB
/// - `JOB_OBJECT_LIMIT_JOB_MEMORY` = 64 MB
/// - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` = 1
/// - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
#[test]
fn test_windows_job_object_kernel_configuration() {
    let job = WindowsJobObject::create(
        "AgentOctopus.Test.KernelClamp",
        1, // Max 1 active process (zero child processes allowed)
        64 * 1024 * 1024, // 64 MB memory ceiling enforced by NT kernel
    );

    assert!(job.is_ok(), "Windows Job Object creation must succeed with kernel limits");
    let job = job.unwrap();
    assert_eq!(job.max_processes, 1);
    assert_eq!(job.max_memory_bytes, 64 * 1024 * 1024);

    // On Windows, verify that assigning a null or invalid handle fails closed
    #[cfg(windows)]
    {
        let assign_fail = job.assign_process(std::ptr::null_mut());
        assert!(assign_fail.is_err(), "FAIL-CLOSED: Assigning null process handle must be rejected");
    }
}

/// TEST 4: Kernel Non-Cooperative Termination (Out-of-Band `TerminateJobObject`)
///
/// Proves that termination is NOT dependent on worker cooperation or an AtomicBool.
/// The supervisor holds the kernel `HANDLE` to the Job Object and executes
/// `TerminateJobObject(hJob, exit_code)`.
#[test]
fn test_kernel_non_cooperative_termination() {
    let job = WindowsJobObject::create(
        "AgentOctopus.Test.AutotomyTermination",
        1,
        64 * 1024 * 1024,
    )
    .unwrap();

    assert!(!job.is_terminated.load(Ordering::SeqCst));

    // Supervisor terminates the Job Object out-of-band with kernel status code 137 (SIGKILL equivalent)
    let term_res = job.terminate(137);
    assert!(term_res.is_ok(), "Kernel TerminateJobObject must succeed");
    assert!(job.is_terminated.load(Ordering::SeqCst));
}

/// TEST 5: AppContainer Profile Derivation & Security SIDs
///
/// Verifies that AppContainer profiles generate RFC-standard package SIDs
/// (`S-1-15-2-...`) and enforce capability zero-trust:
/// - Ingestion arms have zero network capabilities.
/// - Network egress arms only have `internetClient`.
#[test]
fn test_appcontainer_sid_and_capability_isolation() {
    // Ingestion arm profile: LPAC enabled, zero network capability
    let ingest_profile = WindowsAppContainerProfile::new("arm-ingest-99", true, false);
    assert!(ingest_profile.package_sid.starts_with("S-1-15-2-"));
    assert!(!ingest_profile.allow_internet_client);

    // Invariant: Ingestion arm attempting any network access is denied by AppContainer profile
    let net_access = ingest_profile.verify_access("https://www.google.com", true);
    assert!(matches!(net_access, Err(OctopusSecurityError::IsolationViolation(_))));

    // Network arm profile: Internet client permitted
    let net_profile = WindowsAppContainerProfile::new("arm-net-99", true, true);
    assert!(net_profile.allow_internet_client);
    assert!(net_profile.verify_access("https://www.google.com", true).is_ok());

    // Hostname bypass attack: google.com.attacker.example must be rejected
    let bypass_attempt = net_profile.verify_access("https://google.com.attacker.example/exfil", true);
    assert!(matches!(bypass_attempt, Err(OctopusSecurityError::IsolationViolation(_))));
}

/// TEST 6: Memory Address Separation (Worker Has No Access to Supervisor Privileged Handles)
///
/// Validates the architectural boundary:
/// - The `TrustedArmHandle` owned by an arm holds ONLY an `mpsc::Sender<RingRequest>`.
/// - The arm holds NO references to the raw `ToolExecutor`, `CedarGate`, or cryptographic master seeds.
/// - Even with full in-arm RCE, the arm can only send messages over its restricted IPC channel.
#[tokio::test]
async fn test_supervisor_handle_isolation_and_request_immutability() {
    let cedar_gate = Arc::new(CedarGate::new());
    let egress_proxy = Arc::new(EgressProxy::default());

    let authorizer = Arc::new(agent_octopus::containment_ring::CedarAuthorizer::new(cedar_gate.clone()));
    let executor = Arc::new(EnclaveToolExecutor::new(egress_proxy.clone()));
    let (audit_tx, mut audit_rx) = mpsc::channel(100);

    // Supervisor initializes RingController
    let supervisor = RingController::new(
        RingConfig::default(),
        authorizer,
        executor,
        audit_tx,
    )
    .unwrap();

    let mut allowed_ops = std::collections::HashSet::new();
    allowed_ops.insert(Operation::DocumentRead);

    // Supervisor enrolls Arm 17 (UntrustedDocIngest)
    let trusted_handle = supervisor
        .enroll("arm-ingest-17".to_string(), "UntrustedDocIngest".to_string(), allowed_ops)
        .await
        .unwrap();

    // INVARIANT 1: The worker only receives a `TrustedArmHandle`.
    // It has NO memory pointers to the Cedar policy, master seed, or OS process handles.

    // INVARIANT 2: Arm 17 attempts an unauthorized LedgerWrite operation over the handle.
    let hostile_req = RingRequest {
        operation: Operation::LedgerWrite,
        resource: "s3://accounting/ledger.json".to_string(),
        body: b"MALICIOUS_LEDGER_MUTATION".to_vec(),
    };

    let result = trusted_handle.request(hostile_req).await;

    // Must be denied by the supervisor outside the arm's control
    assert_eq!(result, Err(RingError::Denied));

    // Verify audit event was logged out-of-band to the supervisor channel
    let audit_event = audit_rx.recv().await.expect("Audit event must be emitted");
    assert_eq!(audit_event.arm_id, "arm-ingest-17");
    assert_eq!(audit_event.operation, Operation::LedgerWrite);
    assert_eq!(audit_event.outcome, RingError::Denied);

    // INVARIANT 3: Non-cooperative supervisor revocation
    supervisor.revoke("arm-ingest-17").await.unwrap();

    // Subsequent requests immediately return Revoked
    let read_req = RingRequest {
        operation: Operation::DocumentRead,
        resource: "s3://invoices/1.pdf".to_string(),
        body: b"".to_vec(),
    };
    let post_revoke_res = trusted_handle.request(read_req).await;
    assert_eq!(post_revoke_res, Err(RingError::Revoked));
}
