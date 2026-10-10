use crate::core::types::OctopusSecurityError;
use regex::Regex;

/// Deterministic schema compiler and type assertion validator.
#[derive(Debug, Clone)]
pub struct SchemaGuard {
    invoice_id_regex: Regex,
    vendor_name_regex: Regex,
}

impl Default for SchemaGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SchemaGuard {
    pub fn new() -> Self {
        Self {
            invoice_id_regex: Regex::new(r"^[A-Z0-9-]{3,32}$").unwrap(),
            vendor_name_regex: Regex::new(r"^[A-Za-z0-9\s&.,-]{2,64}$").unwrap(),
        }
    }

    /// Verifies that extracted fields strictly conform to immutable lexical schemas.
    pub fn validate_fields(
        &self,
        invoice_id: &str,
        vendor_name: &str,
        amount_cents: u64,
    ) -> Result<(), OctopusSecurityError> {
        if !self.invoice_id_regex.is_match(invoice_id.trim()) {
            return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                "Invoice ID '{}' violates immutable lexical pattern '^[A-Z0-9-]{{3,32}}$'",
                invoice_id
            )));
        }

        if !self.vendor_name_regex.is_match(vendor_name.trim()) {
            return Err(OctopusSecurityError::DeterministicLayerViolation(format!(
                "Vendor name '{}' violates immutable lexical pattern",
                vendor_name
            )));
        }

        if amount_cents == 0 {
            return Err(OctopusSecurityError::DeterministicLayerViolation(
                "Zero transaction amounts are rejected by schema invariants".to_string(),
            ));
        }

        Ok(())
    }
}
