use super::policy_schema::CedarSchema;
use cedar_policy::{PolicySet, ValidationResult, Validator};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarValidationReport {
    pub is_valid: bool,
    pub validation_errors: Vec<String>,
    pub validation_warnings: Vec<String>,
}

/// Static policy analyzer and schema validator for Agent Octopus.
/// Ensures candidate policies conform to the authoritative Cedar schema before deployment.
pub struct CedarPolicyValidator {
    schema: CedarSchema,
}

impl Default for CedarPolicyValidator {
    fn default() -> Self {
        Self::new(CedarSchema::default())
    }
}

impl CedarPolicyValidator {
    pub fn new(schema: CedarSchema) -> Self {
        Self { schema }
    }

    /// Statically validates a policy string against the schema.
    pub fn validate_policy_text(&self, policy_text: &str) -> CedarValidationReport {
        let policy_set = match PolicySet::from_str(policy_text) {
            Ok(ps) => ps,
            Err(e) => {
                return CedarValidationReport {
                    is_valid: false,
                    validation_errors: vec![format!("Syntax/parse error: {}", e)],
                    validation_warnings: vec![],
                }
            }
        };

        self.validate_policy_set(&policy_set)
    }

    /// Validates an existing compiled PolicySet against the schema.
    pub fn validate_policy_set(&self, policy_set: &PolicySet) -> CedarValidationReport {
        let validator = Validator::new(self.schema.inner().clone());
        let result: ValidationResult =
            validator.validate(policy_set, cedar_policy::ValidationMode::Strict);

        let is_valid = result.validation_passed();
        let validation_errors = result.validation_errors().map(|e| e.to_string()).collect();
        let validation_warnings = result
            .validation_warnings()
            .map(|w| w.to_string())
            .collect();

        CedarValidationReport {
            is_valid,
            validation_errors,
            validation_warnings,
        }
    }
}
