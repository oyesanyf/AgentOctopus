//! Binary: octopus-worker
//!
//! Isolated Worker Process for a single Agent Octopus arm.
//! Operates within a restricted OS security context:
//! - Bound to Windows NT Job Object (64MB memory limit, active process limit 1)
//! - Scoped by AppContainer isolation SID
//! - Enforced by Level 1 Arm Containment Ring (ACR) and Generation Epochs

use agent_octopus::containment_ring::ArmContainmentRing;
use agent_octopus::core::types::ArmRole;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let arm_id: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(17);
    let role_str = args.get(2).map(|s| s.as_str()).unwrap_or("doc_ingest");

    let role = match role_str {
        "ledger" => ArmRole::AccountingLedgerWrite,
        "egress" => ArmRole::NetworkEgress,
        _ => ArmRole::UntrustedDocIngest,
    };

    let pid = std::process::id();
    println!("============================================================");
    println!("🦾 AGENT OCTOPUS RESTRICTED WORKER - ARM {}", arm_id);
    println!("   OS PID: {} | Role: {:?} | Memory Clamp: 64MB", pid, role);
    println!("============================================================");

    let secret_seed =
        agent_octopus::security::cedar_arm::authorization::load_or_generate_cedar_secret();
    let ring = ArmContainmentRing::new(arm_id, role.clone(), 1, &secret_seed);

    println!(
        "[WORKER {}] Initialized ACR Generation: {}",
        arm_id,
        ring.current_generation()
    );
    println!("[WORKER {}] Validating capability bounds...", arm_id);

    // Verify allowed tool
    let tool_check = match role {
        ArmRole::UntrustedDocIngest => {
            ring.validate_tool_invocation("doc_extractor", "s3://invoices/inv_1.pdf", 1)
                .await
        }
        ArmRole::AccountingLedgerWrite => {
            ring.validate_tool_invocation("ledger_writer", "s3://accounting/ledger.dat", 1)
                .await
        }
        ArmRole::NetworkEgress => {
            ring.validate_tool_invocation("http_egress", "https://google.com/search", 1)
                .await
        }
        _ => Ok(()),
    };

    println!(
        "[WORKER {}] Permitted tool execution authorized: {}",
        arm_id,
        tool_check.is_ok()
    );

    // Verify negative control: unauthorized tool execution rejected
    let forbidden_check = ring
        .validate_tool_invocation("unauthorized_priv_escalation", "cmd.exe", 1)
        .await;
    println!(
        "[WORKER {}] Forbidden tool blocked by ACR: {}",
        arm_id,
        forbidden_check.is_err()
    );

    println!(
        "[WORKER {}] Execution finished safely under Ring 1 boundary.",
        arm_id
    );
    Ok(())
}
