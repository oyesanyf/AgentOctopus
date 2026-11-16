use agent_octopus::containment_ring::egress_proxy::is_restricted_rebinding_ip;
use agent_octopus::security::agent_hooks::{
    evaluate_hook_synchronously, HookEventType, NormalizedHookRequest, SupportedAgentKind,
};
use agent_octopus::security::linux_sandbox::{
    build_hardened_sandbox_bpf, evaluate_bpf_filter, AARCH64_BLOCKED_SANDBOX_ESCAPE_SYSCALLS,
    AARCH64_BLOCKED_SOCKET_SYSCALLS, AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, LINUX_EACCES,
    LINUX_ENOSYS, LINUX_EPERM, LINUX_SYS_CLONE3, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS, X86_64_BLOCKED_SANDBOX_ESCAPE_SYSCALLS,
    X86_64_BLOCKED_SOCKET_SYSCALLS,
};
use agent_octopus::security::SandboxConfinementPolicy;
use agent_octopus::{
    classify_mandatory_write_deny_path, classify_pinned_parent_for_write_deny,
    classify_sensitive_system_path, parse_and_validate_dynamic_policy,
    resolve_and_pin_allowed_host, validate_http_request_target, CredentialSentinelMasker, IpCidr,
    MandatoryWriteDenyKind, SensitiveCredentialStoreKind,
};
use std::net::IpAddr;

#[test]
fn test_e2e_srt_seccomp_bpf_closes_io_uring_and_mount_ns_escapes() {
    let x64_bpf = build_hardened_sandbox_bpf(AUDIT_ARCH_X86_64).expect("x64 BPF");
    let arm_bpf = build_hardened_sandbox_bpf(AUDIT_ARCH_AARCH64).expect("aarch64 BPF");

    for &nr in X86_64_BLOCKED_SOCKET_SYSCALLS {
        assert_eq!(
            evaluate_bpf_filter(&x64_bpf, AUDIT_ARCH_X86_64, nr),
            SECCOMP_RET_ERRNO | LINUX_EACCES
        );
    }
    for &nr in X86_64_BLOCKED_SANDBOX_ESCAPE_SYSCALLS {
        assert_eq!(
            evaluate_bpf_filter(&x64_bpf, AUDIT_ARCH_X86_64, nr),
            SECCOMP_RET_ERRNO | LINUX_EPERM
        );
    }
    for &nr in AARCH64_BLOCKED_SOCKET_SYSCALLS {
        assert_eq!(
            evaluate_bpf_filter(&arm_bpf, AUDIT_ARCH_AARCH64, nr),
            SECCOMP_RET_ERRNO | LINUX_EACCES
        );
    }
    for &nr in AARCH64_BLOCKED_SANDBOX_ESCAPE_SYSCALLS {
        assert_eq!(
            evaluate_bpf_filter(&arm_bpf, AUDIT_ARCH_AARCH64, nr),
            SECCOMP_RET_ERRNO | LINUX_EPERM
        );
    }

    assert_eq!(
        evaluate_bpf_filter(&x64_bpf, AUDIT_ARCH_X86_64, LINUX_SYS_CLONE3),
        SECCOMP_RET_ERRNO | LINUX_ENOSYS
    );
    assert_eq!(
        evaluate_bpf_filter(&arm_bpf, AUDIT_ARCH_AARCH64, LINUX_SYS_CLONE3),
        SECCOMP_RET_ERRNO | LINUX_ENOSYS
    );
    assert_eq!(
        evaluate_bpf_filter(&x64_bpf, AUDIT_ARCH_X86_64, 1),
        SECCOMP_RET_ALLOW
    );
    assert_eq!(
        evaluate_bpf_filter(&x64_bpf, AUDIT_ARCH_AARCH64, 1),
        SECCOMP_RET_KILL_PROCESS
    );
}

#[test]
fn test_e2e_srt_mandatory_write_deny_and_credential_catalog() {
    let mut policy = SandboxConfinementPolicy::default();
    policy.allow_host_filesystem = true;

    // 1. Credential stores remain blocked for read and write
    for cred_path in [
        "~/.aws/credentials",
        "/home/dev/.kube/config",
        r"C:\Users\dev\.cargo\credentials.toml",
        r"C:\Users\dev\NTUSER.DAT",
        r"C:\Users\dev\AppData\Local\Microsoft\Credentials\DFBE70A7",
        r"C:\Users\dev\AppData\Local\Programs\App\EBWebView\Cookies",
        "/home/dev/.config/1Password/settings.json",
    ] {
        assert!(classify_sensitive_system_path(cred_path).is_some());
        assert!(policy.validate_filesystem_confinement(cred_path).is_err());
    }
    assert_eq!(
        classify_sensitive_system_path("~/.config/gcloud/application_default_credentials.json"),
        Some(SensitiveCredentialStoreKind::CloudProviderCredentials)
    );

    // 2. Auto-protected workspace configs blocked on write and parent unlink
    for protected_write in [
        ".git/hooks/post-commit",
        ".git/config",
        ".githooks/pre-push",
        ".mcp.json",
        ".bashrc",
        ".zshrc",
        ".vscode/settings.json",
        ".claude/commands/shell.md",
    ] {
        assert!(classify_mandatory_write_deny_path(protected_write).is_some());
        assert!(policy
            .validate_filesystem_write_confinement(protected_write)
            .is_err());
    }
    assert_eq!(
        classify_pinned_parent_for_write_deny("repo/.git"),
        Some(MandatoryWriteDenyKind::GitHooksOrConfig)
    );
    assert!(policy
        .validate_directory_mutation_confinement("repo/.git")
        .is_err());

    // 3. Agent hooks enforce mandatory write-deny for mutating tools while allowing normal reads
    let edit_hook = NormalizedHookRequest {
        agent: SupportedAgentKind::Claude,
        event_type: HookEventType::PreToolUse,
        tool_name: Some("replace_file_content".into()),
        command: None,
        file_path: Some(".mcp.json".into()),
        arguments: None,
        exit_code: None,
        stderr: None,
        cwd: None,
        session_id: None,
        rpc_id: None,
    };
    let decision = evaluate_hook_synchronously(&edit_hook);
    assert!(!decision.allowed);
    assert_eq!(
        decision.denied_by_layer.as_deref(),
        Some("MandatoryWriteDenyGuard")
    );
}

#[test]
fn test_e2e_srt_egress_ssrf_masking_and_ambiguous_target_defense() {
    // Azure WireServer & Oracle/Alibaba/AWS IMDS + NAT64/6to4 all blocked globally
    for ip_str in [
        "168.63.129.16",
        "100.100.100.200",
        "192.0.0.192",
        "fd00:ec2::254",
        "64:ff9b::10.0.0.1",
        "2002:7f00:1::1",
    ] {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            is_restricted_rebinding_ip(&ip),
            "expected restricted IP for {}",
            ip_str
        );
    }

    // Single-lookup pinning rejects DNS rebinding to internal CIDR and pins public address
    let cidrs = vec![IpCidr::parse("10.0.0.0/8").unwrap()];
    assert!(resolve_and_pin_allowed_host(
        "api.github.com",
        443,
        &["api.github.com".to_string()],
        &[],
        &cidrs,
        Some(&["10.1.2.3".parse().unwrap()]),
    )
    .is_err());

    let pinned = resolve_and_pin_allowed_host(
        "api.github.com",
        443,
        &["api.github.com".to_string()],
        &[],
        &cidrs,
        Some(&["140.82.112.6".parse().unwrap()]),
    )
    .expect("public IP allowed");
    assert_eq!(pinned.len(), 1);

    // Sentinel credential masking + dynamic control update
    let masker = CredentialSentinelMasker::new();
    let sentinel = masker
        .register_masked_credential(
            "HF_TOKEN",
            "hf_real_live_secret_token",
            vec!["huggingface.co".to_string()],
            false,
        )
        .unwrap();
    let child_env = masker.sanitized_child_env(&[(
        "HF_TOKEN".to_string(),
        "hf_real_live_secret_token".to_string(),
    )]);
    assert_eq!(child_env[0].1, sentinel);

    let (unmasked, _) = masker
        .inject_on_egress(
            "https",
            "huggingface.co",
            443,
            &[("Authorization".to_string(), format!("Bearer {}", sentinel))],
            "",
        )
        .expect("approved https host unmasks sentinel");
    assert_eq!(unmasked[0].1, "Bearer hf_real_live_secret_token");
    assert!(masker
        .inject_on_egress(
            "http",
            "huggingface.co",
            80,
            &[("Authorization".to_string(), format!("Bearer {}", sentinel))],
            "",
        )
        .is_err());

    assert!(
        parse_and_validate_dynamic_policy(r#"{"denied_resolved_addresses":["invalid_cidr"]}"#)
            .is_err()
    );

    // Ambiguous target & Host/SNI enforcement
    assert_eq!(
        validate_http_request_target(
            "GET",
            "https://huggingface.co/public/../admin",
            Some("huggingface.co"),
            Some("huggingface.co:443"),
            Some("huggingface.co")
        )
        .unwrap_err()
        .0,
        400
    );
    assert_eq!(
        validate_http_request_target(
            "POST",
            "/v1/api",
            Some("evil.example.com"),
            Some("huggingface.co:443"),
            Some("huggingface.co")
        )
        .unwrap_err()
        .0,
        421
    );
}
