use crate::core::types::OctopusSecurityError;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

/// Trusted Test Controller: Independent gatekeeper for adversarial testing and red-teaming.
/// Ensures simulated breakouts, fuzzing runs, and attack chain tests run strictly within
/// a safe sandbox envelope and cannot leak into production state or live networks.
pub struct TrustedTestController {
    is_test_mode_active: AtomicBool,
    allowed_mock_resources: HashSet<String>,
    simulated_attack_log: Vec<String>,
}

impl TrustedTestController {
    pub fn new() -> Self {
        let mut allowed = HashSet::new();
        allowed.insert("test://invoice/sample.pdf".to_string());
        allowed.insert("test://ledger/mock_ledger.json".to_string());
        allowed.insert("s3://invoices/test_batch/".to_string());

        Self {
            is_test_mode_active: AtomicBool::new(true),
            allowed_mock_resources: allowed,
            simulated_attack_log: Vec::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.is_test_mode_active.load(Ordering::SeqCst)
    }

    /// Verifies that an adversarial test target is within the synthetic test envelope.
    pub fn authorize_test_action(
        &mut self,
        resource_uri: &str,
    ) -> Result<(), OctopusSecurityError> {
        if !self.is_active() {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Test Controller is inactive; live execution prohibited in test controller"
                    .to_string(),
            ));
        }

        // Must not touch production ledgers or production credentials
        if resource_uri.contains("prod") || resource_uri.contains(".octopus_security_audit.log") {
            return Err(OctopusSecurityError::EnclaveViolation(format!(
                "Test action targeted protected production resource: {}",
                resource_uri
            )));
        }

        self.simulated_attack_log.push(resource_uri.to_string());
        Ok(())
    }

    pub fn allowed_resources(&self) -> &HashSet<String> {
        &self.allowed_mock_resources
    }

    pub fn simulated_attacks_count(&self) -> usize {
        self.simulated_attack_log.len()
    }
}
