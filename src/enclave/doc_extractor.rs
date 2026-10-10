use crate::core::types::{OctopusSecurityError, VerifiedInvoiceArtifact};
use crate::enclave::tool::SafeTool;
use regex::Regex;
use sha2::{Digest, Sha256};

pub struct SafeDocumentExtractor {
    injection_patterns: Vec<&'static str>,
    invoice_id_regex: Regex,
    vendor_regex: Regex,
    amount_regex: Regex,
}

impl Default for SafeDocumentExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl SafeDocumentExtractor {
    pub fn new() -> Self {
        Self {
            injection_patterns: vec![
                "ignore previous instructions",
                "system prompt",
                "curl ",
                "webhook",
                "base64",
                "<script>",
                "drop table",
                "exec(",
                "eval(",
                "/bin/sh",
                "bash -c",
                "powershell",
                "cmd.exe",
                "169.254.169.254",
                "bypass sandbox",
                "exfiltrate",
            ],
            invoice_id_regex: Regex::new(r"(?i)(?:INV|ID|INVOICE)[:\s#-]+([A-Z0-9-]+)").unwrap(),
            vendor_regex: Regex::new(r"(?i)vendor[:\s]+([A-Za-z0-9\s&.,-]+?)(?:\||\n|$)").unwrap(),
            amount_regex: Regex::new(r"(?i)(?:total|amount)[:\s]*\$?([0-9]+(?:\.[0-9]{2})?)").unwrap(),
        }
    }

    /// Primary defense: detect adversarial prompt injection attacks inside the arm's isolated scratchpad.
    pub fn scan_adversarial_signatures(&self, raw_input: &str) -> Result<(), OctopusSecurityError> {
        let lower = raw_input.to_lowercase();
        for signature in &self.injection_patterns {
            if lower.contains(signature) {
                return Err(OctopusSecurityError::BreakoutDetected(format!(
                    "Adversarial signature blocked in ingest sandbox: '{}'",
                    signature
                )));
            }
        }
        Ok(())
    }

    /// Extract strictly-typed invoice artifact from raw sanitized stream.
    /// Guarantees that raw text never travels to the central brain.
    pub fn extract_artifact(
        &self,
        raw_input: &str,
        merkle_root: String,
        execution_step_count: usize,
    ) -> Result<VerifiedInvoiceArtifact, OctopusSecurityError> {
        self.scan_adversarial_signatures(raw_input)?;

        let invoice_id = self
            .invoice_id_regex
            .captures(raw_input)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "INV-UNKNOWN".to_string());

        let vendor_name = self
            .vendor_regex
            .captures(raw_input)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_else(|| "Unknown Vendor".to_string());

        let amount_cents = self
            .amount_regex
            .captures(raw_input)
            .and_then(|cap| cap.get(1))
            .and_then(|m| m.as_str().parse::<f64>().ok())
            .map(|val| (val * 100.0).round() as u64)
            .unwrap_or(0);

        // Count line items or bullet points in raw document
        let line_item_count = raw_input
            .lines()
            .filter(|line| line.trim().starts_with('-') || line.trim().starts_with('*') || line.contains("ITEM"))
            .count()
            .max(1);

        // Compute authentic SHA-256 digest of input
        let mut hasher = Sha256::new();
        hasher.update(raw_input.as_bytes());
        let digest_bytes = hasher.finalize();
        let sanitization_digest = format!("sha256:{}", hex::encode(digest_bytes));

        Ok(VerifiedInvoiceArtifact {
            invoice_id,
            vendor_name,
            amount_cents,
            currency: "USD".to_string(),
            line_item_count,
            sanitization_digest,
            merkle_root,
            execution_step_count,
        })
    }
}

impl SafeTool for SafeDocumentExtractor {
    fn name(&self) -> &'static str {
        "doc_extractor"
    }

    fn execute(&self, raw_input: &str) -> Result<String, OctopusSecurityError> {
        let artifact = self.extract_artifact(raw_input, "sha256:unrooted".to_string(), 1)?;
        serde_json::to_string(&artifact).map_err(|e| {
            OctopusSecurityError::EnclaveViolation(format!("Serialization failure: {}", e))
        })
    }
}
