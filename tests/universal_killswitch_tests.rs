#[cfg(target_arch = "x86_64")]
use agent_octopus::security::FwpmFilter0;
use agent_octopus::security::{
    build_linux_blackhole_route_msg, discover_active_octopus_ports,
    generate_macos_pf_quarantine_rules, handle_wfp_kernel_apply_cli, HostIsolationError,
    HostKillSwitchManager, UniversalProtocolCatalog, BLOCKED_L2_ETHERTYPES, FORBIDDEN_PORT_5000,
};
use agent_octopus::web::api::{
    handle_killswitch_disarm, handle_killswitch_engage, handle_killswitch_protocols,
    handle_killswitch_status, WebState,
};
use agent_octopus::INDEX_HTML;

#[test]
fn test_universal_protocol_catalog_16_domains_218_protocols_and_256_iana_numbers() {
    let domains = UniversalProtocolCatalog::all_domains();
    assert_eq!(domains.len(), 16, "Must cover all 16 protocol domains");
    assert_eq!(
        UniversalProtocolCatalog::total_protocols_count(),
        218,
        "Must contain all 218 named protocols"
    );

    for ip_num in 0u8..=255u8 {
        assert!(UniversalProtocolCatalog::contains_iana_protocol(ip_num));
    }

    let all = UniversalProtocolCatalog::all_protocols();
    let has_id = |needle: &str| all.iter().any(|p| p.id.eq_ignore_ascii_case(needle));

    // Verify key protocols across Classical, PQC, Cryo/Hardware, and Quantum QKD/Networking
    assert!(has_id("TCP"));
    assert!(has_id("QUIC"));
    assert!(has_id("TLS-PQC"));
    assert!(has_id("WhiteRabbit"));
    assert!(has_id("BB84"));
    assert!(has_id("TF-QKD"));
    assert!(has_id("GG02"));
    assert!(has_id("Cascade"));

    // Verify all 4 Layer-2 hardware/quantum EtherTypes are explicitly guarded
    assert_eq!(BLOCKED_L2_ETHERTYPES, [0x88E5, 0x88F7, 0x8809, 0xAEFE]);
    for eth in BLOCKED_L2_ETHERTYPES {
        assert!(UniversalProtocolCatalog::contains_ethertype(eth));
    }
}

#[test]
fn test_fwpm_filter0_x64_abi_and_invalid_wfp_cli_action_rejected() {
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(std::mem::size_of::<FwpmFilter0>(), 200);
        assert_eq!(std::mem::align_of::<FwpmFilter0>(), 8);
    }

    let err = handle_wfp_kernel_apply_cli("drop-all-forever")
        .expect_err("Invalid --wfp-kernel-apply action must fail closed");
    assert!(matches!(err, HostIsolationError::InvalidAction(_)));
}

#[test]
fn test_octopus_port_discovery_and_cross_platform_zero_leak_quarantine_builders() {
    let ports = discover_active_octopus_ports();
    assert!(ports.contains(&5005));
    assert!(
        !ports.contains(&FORBIDDEN_PORT_5000),
        "Port 5000 must never be touched or allowlisted"
    );

    // Linux binary AF_NETLINK RTN_BLACKHOLE route messages (IPv4 & IPv6)
    let nl_v4 = build_linux_blackhole_route_msg(false, false, 10);
    let nl_v6 = build_linux_blackhole_route_msg(true, false, 10);
    assert_eq!(nl_v4.len(), 36);
    assert_eq!(nl_v6.len(), 36);
    // RtMsg starts at byte 16: rtm_family (16), rtm_table=RT_TABLE_MAIN(254) (20), rtm_type=RTN_BLACKHOLE(6) (23)
    assert_eq!(nl_v4[16], 2);
    assert_eq!(nl_v6[16], 10);
    assert_eq!(nl_v4[20], 254);
    assert_eq!(nl_v4[23], 6);

    // macOS /dev/pf anchor ruleset must preserve lo0 + 5005 and NEVER leak DNS 53 or DHCP 67/68
    let pf_lines = generate_macos_pf_quarantine_rules("agent_octopus", &[5005]);
    let joined = pf_lines.join("\n");
    assert!(joined.contains("pass quick on lo0 all keep state"));
    assert!(joined.contains("port 5005"));
    assert!(!joined.contains("port 53"));
    assert!(!joined.contains("port 67"));
    assert!(!joined.contains("port 68"));
    assert!(joined.contains("block drop in quick all"));
    assert!(joined.contains("block drop out quick all"));
}

#[test]
fn test_host_killswitch_manager_and_web_api_lifecycle() {
    let tmp_ledger =
        std::env::temp_dir().join(format!("octopus_ks_test_{}.json", std::process::id()));
    let _ = std::fs::remove_file(&tmp_ledger);

    let mgr = HostKillSwitchManager::new(Some(tmp_ledger.clone()));
    let s0 = mgr.status();
    assert!(!s0.isolated);
    assert_eq!(s0.universal_domains_count, 16);
    assert_eq!(s0.universal_protocols_count, 218);
    assert_eq!(s0.iana_ip_protocols_covered, 256);
    assert_eq!(s0.wfp_kernel_layers_enforced, 24);
    assert!(s0.zero_subprocess_enforced);

    let s1 = mgr
        .engage("integration_test", "Verify engage transition")
        .expect("Engage must succeed in test mode");
    assert!(s1.isolated);
    assert_eq!(s1.containment_level, "HermeticIsolation");
    assert_ne!(s1.state_hash, s0.state_hash);
    assert!(s1.active_receipt.is_some());

    let s2 = mgr
        .disarm("integration_test", "Verify disarm transition")
        .expect("Disarm must succeed in test mode");
    assert!(!s2.isolated);
    assert_eq!(s2.containment_level, "Disarmed");
    assert_ne!(s2.state_hash, s1.state_hash);

    let _ = std::fs::remove_file(&tmp_ledger);

    // Verify Web API endpoints and Dashboard UI wiring
    let web_state = WebState::default();
    let (code_proto, body_proto) = handle_killswitch_protocols();
    assert_eq!(code_proto, "200 OK");
    let parsed_proto: serde_json::Value = serde_json::from_str(&body_proto).unwrap();
    assert_eq!(parsed_proto["domains_covered"], 16);
    assert_eq!(parsed_proto["total_protocols"], 218);
    assert_eq!(parsed_proto["iana_ip_protocols_blocked"], 256);

    let (code_st, _) = handle_killswitch_status(&web_state);
    assert_eq!(code_st, "200 OK");

    let (code_bad, _) = handle_killswitch_engage(&web_state, "{broken_json");
    assert_eq!(code_bad, "400 Bad Request");
    let (code_bad2, _) = handle_killswitch_disarm(&web_state, "{broken_json");
    assert_eq!(code_bad2, "400 Bad Request");

    assert!(INDEX_HTML.contains("universal-killswitch"));
    assert!(INDEX_HTML.contains("engageHostKillSwitch()"));
    assert!(INDEX_HTML.contains("disarmHostKillSwitch()"));
}
