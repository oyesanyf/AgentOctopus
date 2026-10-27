use crate::core::types::OctopusSecurityError;
use crate::enclave::tool::SafeTool;
use regex::Regex;

pub struct SafeLedgerWriter {
    account_regex: Regex,
}

impl Default for SafeLedgerWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl SafeLedgerWriter {
    pub fn new() -> Self {
        Self {
            account_regex: Regex::new(r"^ACC-[0-9]{4}-[A-Z]{3}$").unwrap(),
        }
    }

    pub fn write_entry(
        &self,
        target_account: &str,
        amount_cents: u64,
    ) -> Result<String, OctopusSecurityError> {
        let trimmed = target_account.trim();
        if !self.account_regex.is_match(trimmed) {
            return Err(OctopusSecurityError::EnclaveViolation(format!(
                "Target account '{}' does not match immutable schema '^ACC-[0-9]{{4}}-[A-Z]{{3}}$'",
                target_account
            )));
        }

        if amount_cents == 0 {
            return Err(OctopusSecurityError::EnclaveViolation(
                "Refusing to write null transaction amount to ledger".to_string(),
            ));
        }

        Ok(format!(
            "Committed ledger entry for {} | Amount: ${:.2}",
            trimmed,
            amount_cents as f64 / 100.0
        ))
    }
}

impl SafeTool for SafeLedgerWriter {
    fn name(&self) -> &'static str {
        "ledger_writer"
    }

    fn execute(&self, raw_input: &str) -> Result<String, OctopusSecurityError> {
        // Enforce account regex verification
        let trimmed = raw_input.trim();
        if !self.account_regex.is_match(trimmed) {
            return Err(OctopusSecurityError::EnclaveViolation(format!(
                "Target account '{}' violates deterministic ledger format",
                trimmed
            )));
        }
        Ok(format!("Committed ledger entry for {}", trimmed))
    }
}
