use cedar_policy::Schema;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("Failed to parse Cedar schema: {0}")]
    ParseError(String),
}

/// Authoritative Cedar JSON schema definition for Agent Octopus.
/// Defines the Entity hierarchy, Actions, and Context attributes.
pub const OCTOPUS_CEDAR_SCHEMA_JSON: &str = r#"{
  "Octopus": {
    "entityTypes": {
      "Agent": {
        "shape": {
          "type": "Record",
          "attributes": {
            "role": { "type": "String", "required": false },
            "is_trusted_supervisor": { "type": "Boolean", "required": false }
          }
        }
      },
      "Document": {
        "shape": {
          "type": "Record",
          "attributes": {
            "uri": { "type": "String", "required": false }
          }
        }
      },
      "Ledger": {
        "shape": {
          "type": "Record",
          "attributes": {
            "account_id": { "type": "String", "required": false }
          }
        }
      },
      "NetworkTarget": {
        "shape": {
          "type": "Record",
          "attributes": {
            "domain": { "type": "String", "required": false }
          }
        }
      },
      "SystemPolicy": {
        "shape": {
          "type": "Record",
          "attributes": {
            "policy_id": { "type": "String", "required": false }
          }
        }
      },
      "DecoyTrap": {
        "shape": {
          "type": "Record",
          "attributes": {
            "trap_id": { "type": "String", "required": false }
          }
        }
      },
      "KernelSubstrate": {
        "shape": {
          "type": "Record",
          "attributes": {
            "substrate_id": { "type": "String", "required": false },
            "enforcement_tier": { "type": "String", "required": false }
          }
        }
      }
    },
    "actions": {
      "extract": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["Document"],
          "context": {
            "type": "Record",
            "attributes": {
              "delegation_depth": { "type": "Long", "required": false }
            }
          }
        }
      },
      "write": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["Ledger"],
          "context": {
            "type": "Record",
            "attributes": {
              "amount_cents": { "type": "Long", "required": true },
              "approved": { "type": "Boolean", "required": true }
            }
          }
        }
      },
      "egress": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["NetworkTarget"],
          "context": {
            "type": "Record",
            "attributes": {
              "destination_domain": { "type": "String", "required": true }
            }
          }
        }
      },
      "notify": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["Agent"],
          "context": {
            "type": "Record",
            "attributes": {}
          }
        }
      },
      "change_security_policy": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["SystemPolicy"],
          "context": {
            "type": "Record",
            "attributes": {
              "quorum_authorized": { "type": "Boolean", "required": false }
            }
          }
        }
      },
      "quarantine": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["DecoyTrap"],
          "context": {
            "type": "Record",
            "attributes": {
              "adversary_ip": { "type": "String", "required": false },
              "attack_type": { "type": "String", "required": false }
            }
          }
        }
      },
      "kernel_enforce": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["KernelSubstrate"],
          "context": {
            "type": "Record",
            "attributes": {
              "enforcement_tier": { "type": "String", "required": false },
              "target_pid": { "type": "Long", "required": false }
            }
          }
        }
      },
      "evaluate": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["NetworkTarget"],
          "context": {
            "type": "Record",
            "attributes": {
              "destination_host": { "type": "String", "required": true },
              "destination_port": { "type": "Long", "required": false }
            }
          }
        }
      }
    }
  }
}"#;

/// CedarSchema: Wrapper for the compiled, validated schema of Agent Octopus.
pub struct CedarSchema {
    schema: Schema,
}

impl Default for CedarSchema {
    fn default() -> Self {
        Self::load_default().expect("Authoritative Cedar schema failed to compile")
    }
}

impl CedarSchema {
    /// Loads and compiles the default Agent Octopus Cedar schema.
    pub fn load_default() -> Result<Self, SchemaError> {
        let schema = Schema::from_json_str(OCTOPUS_CEDAR_SCHEMA_JSON)
            .map_err(|e| SchemaError::ParseError(e.to_string()))?;
        Ok(Self { schema })
    }

    /// Loads a custom Cedar schema from a JSON string.
    pub fn from_json_str(json_str: &str) -> Result<Self, SchemaError> {
        let schema =
            Schema::from_json_str(json_str).map_err(|e| SchemaError::ParseError(e.to_string()))?;
        Ok(Self { schema })
    }

    pub fn inner(&self) -> &Schema {
        &self.schema
    }
}
