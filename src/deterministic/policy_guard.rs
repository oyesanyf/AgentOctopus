use crate::core::types::{OctopusSecurityError, StrategicDirective, VerifiedInvoiceArtifact};

/// Pre-execution declarative policy engine operating outside the model context.
#[derive(Debug, Clone)]
pub struct PolicyGuard {
    pub max_amount_cents: u64,
    pub allowed_source_prefixes: Vec<String>,
    pub max_steps_permitted: usize,
    pub required_currency: String,
}

impl Default for PolicyGuard {
    fn default() -> Self {
        Self {
            max_amount_cents: 10_000_000, // $100,000.00 limit
            allowed_source_prefixes: vec![
                "s3://invoices/".to_string(),
                "https://www.google.com/".to_string(),
                "https://google.com/".to_string(),
                "s3://accounting/".to_string(),
            ],
            max_steps_permitted: 5,
            required_currency: "USD".to_string(),
        }
    }
}

impl PolicyGuard {
    pub fn new(
        max_amount_cents: u64,
        allowed_source_prefixes: Vec<String>,
        max_steps_permitted: usize,
    ) -> Self {
        Self {
            max_amount_cents,
            allowed_source_prefixes,
            max_steps_permitted,
            required_currency: "USD".to_string(),
        }
    }

    /// Enforces pre-execution policy on incoming high-level directives.
    pub fn enforce_directive(&self, directive: &StrategicDirective) -> Result<(), OctopusSecurityError> {
        // 1. Step budget policy check
        if directive.max_step_budget > self.max_steps_permitted {
            return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                "Requested step budget ({}) exceeds maximum allowable policy limit ({})",
                directive.max_step_budget, self.max_steps_permitted
            )));
        }

        // 2. Source URI allowlist check
        let is_allowed = self
            .allowed_source_prefixes
            .iter()
            .any(|prefix| directive.source_uri.starts_with(prefix));

        if !is_allowed {
            return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                "Directive source_uri '{}' violates allowable policy prefixes",
                directive.source_uri
            )));
        }

        Ok(())
    }

    /// Enforces post-extraction invariants on verified financial artifacts before commit.
    pub fn enforce_artifact(&self, artifact: &VerifiedInvoiceArtifact) -> Result<(), OctopusSecurityError> {
        // 1. Financial amount cap
        if artifact.amount_cents > self.max_amount_cents {
            return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                "Invoice amount (${:.2}) violates hard policy spending ceiling (${:.2})",
                artifact.amount_cents as f64 / 100.0,
                self.max_amount_cents as f64 / 100.0
            )));
        }

        // 2. Currency assertion
        if artifact.currency != self.required_currency {
            return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                "Currency '{}' violates required policy currency '{}'",
                artifact.currency, self.required_currency
            )));
        }

        // 3. Merkle root integrity check
        if artifact.merkle_root.len() != 64 {
            return Err(OctopusSecurityError::DeterministicLayerViolation(
                "Missing or non-conforming 32-byte Merkle root on verified artifact".to_string(),
            ));
        }

        Ok(())
    }
}
