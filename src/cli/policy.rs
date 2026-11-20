use crate::security::cedar_arm::CedarPolicyEngine;
use crate::security::safeagents_client::IpCidr;
use crate::security::sensitive_paths::{
    classify_mandatory_write_deny_path, classify_pinned_parent_for_write_deny,
    classify_sensitive_system_path, scan_for_sensitive_system_path,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandPolicyConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub max_child_processes: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemPolicyConfig {
    #[serde(default)]
    pub allow_read: Vec<String>,
    #[serde(default)]
    pub allow_write: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialsPolicyConfig {
    #[serde(default)]
    pub mask_env: Vec<String>,
    #[serde(default)]
    pub inject_hosts: Vec<String>,
    #[serde(default)]
    pub allow_plaintext_inject: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitsPolicyConfig {
    #[serde(default)]
    pub memory_mb: Option<usize>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub wasm_fuel: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OctopusRunPolicy {
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub denied_domains: Vec<String>,
    #[serde(default)]
    pub denied_resolved_addresses: Vec<String>,
    #[serde(default)]
    pub commands: CommandPolicyConfig,
    #[serde(default)]
    pub filesystem: FilesystemPolicyConfig,
    #[serde(default)]
    pub credentials: CredentialsPolicyConfig,
    #[serde(default)]
    pub limits: LimitsPolicyConfig,
    #[serde(default)]
    pub cedar_policy: Option<String>,
    #[serde(default)]
    pub cedar_file: Option<String>,
}

pub struct LoadedOctopusPolicy {
    pub policy_path: PathBuf,
    pub is_standalone_cedar: bool,
    pub has_filesystem_section: bool,
    pub json_policy: OctopusRunPolicy,
    pub denied_cidrs: Vec<IpCidr>,
    pub cedar_engine: Option<CedarPolicyEngine>,
}

pub fn is_bare_or_port_wildcard(pattern: &str) -> bool {
    let trimmed = pattern.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed == "*:*" || trimmed == "*.*" {
        return true;
    }
    if let Some((host, _port)) = trimmed.split_once(':') {
        let h = host.trim();
        if h == "*" || h.is_empty() {
            return true;
        }
    }
    false
}

fn validate_domain_pattern(raw: &str, field_name: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("'{}' contains an empty domain entry", field_name));
    }
    if trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "'{}' entry '{}' contains whitespace or control characters",
            field_name, raw
        ));
    }
    if trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('@')
    {
        return Err(format!(
            "'{}' entry '{}' must be host or host:port without scheme, path, query, or userinfo",
            field_name, raw
        ));
    }
    if field_name == "allowed_domains" && is_bare_or_port_wildcard(trimmed) {
        return Err(format!(
            "'allowed_domains' forbids wildcard entry '{}'",
            raw
        ));
    }
    Ok(())
}

pub fn load_octopus_policy(path: &Path) -> Result<LoadedOctopusPolicy, String> {
    if !path.is_file() {
        return Err(format!(
            "policy file '{}' does not exist or is not a regular file",
            path.display()
        ));
    }
    let raw_text_owned = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read policy file '{}': {}", path.display(), e))?;
    let raw_text = raw_text_owned.trim_start_matches('\u{feff}');

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "cedar" => {
            let engine = CedarPolicyEngine::from_validated_policy_set(raw_text)
                .map_err(|e| format!("invalid Cedar policy '{}': {}", path.display(), e))?;
            Ok(LoadedOctopusPolicy {
                policy_path: path.to_path_buf(),
                is_standalone_cedar: true,
                has_filesystem_section: false,
                json_policy: OctopusRunPolicy::default(),
                denied_cidrs: Vec::new(),
                cedar_engine: Some(engine),
            })
        }
        "json" => {
            let raw_val: serde_json::Value = serde_json::from_str(raw_text)
                .map_err(|e| format!("invalid JSON in policy file '{}': {}", path.display(), e))?;
            let Some(obj) = raw_val.as_object() else {
                return Err(format!(
                    "policy file '{}' must contain a JSON object",
                    path.display()
                ));
            };
            let has_filesystem_section = obj.contains_key("filesystem");

            let policy: OctopusRunPolicy = serde_json::from_value(raw_val).map_err(|e| {
                format!(
                    "invalid Octopus policy schema in '{}': {}",
                    path.display(),
                    e
                )
            })?;

            for entry in &policy.allowed_domains {
                validate_domain_pattern(entry, "allowed_domains")?;
            }
            for entry in &policy.denied_domains {
                validate_domain_pattern(entry, "denied_domains")?;
            }

            let mut denied_cidrs = Vec::with_capacity(policy.denied_resolved_addresses.len());
            for cidr_raw in &policy.denied_resolved_addresses {
                let parsed = IpCidr::parse(cidr_raw).map_err(|e| {
                    format!(
                        "invalid CIDR '{}' in 'denied_resolved_addresses': {}",
                        cidr_raw, e
                    )
                })?;
                denied_cidrs.push(parsed);
            }

            for r in &policy.filesystem.allow_read {
                if r.trim().is_empty() {
                    return Err("'filesystem.allow_read' contains an empty path".to_string());
                }
                if let Some(kind) = classify_sensitive_system_path(r) {
                    return Err(format!(
                        "'filesystem.allow_read' entry '{}' targets protected sensitive path ({:?})",
                        r, kind
                    ));
                }
                if let Some((kind, needle)) = scan_for_sensitive_system_path(r) {
                    return Err(format!(
                        "'filesystem.allow_read' entry '{}' references sensitive path '{}' ({:?})",
                        r, needle, kind
                    ));
                }
            }

            for w in &policy.filesystem.allow_write {
                if w.trim().is_empty() {
                    return Err("'filesystem.allow_write' contains an empty path".to_string());
                }
                if let Some(kind) = classify_sensitive_system_path(w) {
                    return Err(format!(
                        "'filesystem.allow_write' entry '{}' targets protected sensitive path ({:?})",
                        w, kind
                    ));
                }
                if let Some((kind, needle)) = scan_for_sensitive_system_path(w) {
                    return Err(format!(
                        "'filesystem.allow_write' entry '{}' references sensitive path '{}' ({:?})",
                        w, needle, kind
                    ));
                }
                if let Some(kind) = classify_mandatory_write_deny_path(w) {
                    return Err(format!(
                        "'filesystem.allow_write' entry '{}' violates mandatory write-deny ({:?})",
                        w, kind
                    ));
                }
                if let Some(kind) = classify_pinned_parent_for_write_deny(w) {
                    return Err(format!(
                        "'filesystem.allow_write' entry '{}' targets protected pinned parent ({:?})",
                        w, kind
                    ));
                }
            }

            let mut cedar_chunks = Vec::new();
            if let Some(ref cfile) = policy.cedar_file {
                let resolved_cedar = if Path::new(cfile).is_absolute() {
                    PathBuf::from(cfile)
                } else {
                    match path.parent() {
                        Some(parent) => parent.join(cfile),
                        None => PathBuf::from(cfile),
                    }
                };
                let ctext = std::fs::read_to_string(&resolved_cedar).map_err(|e| {
                    format!(
                        "failed to read referenced cedar_file '{}': {}",
                        resolved_cedar.display(),
                        e
                    )
                })?;
                cedar_chunks.push(ctext);
            }
            if let Some(ref inline_cedar) = policy.cedar_policy {
                cedar_chunks.push(inline_cedar.clone());
            }
            let cedar_engine = if cedar_chunks.is_empty() {
                None
            } else {
                let combined = cedar_chunks.join("\n");
                let engine =
                    CedarPolicyEngine::from_validated_policy_set(&combined).map_err(|e| {
                        format!(
                            "invalid Cedar policy referenced by '{}': {}",
                            path.display(),
                            e
                        )
                    })?;
                Some(engine)
            };

            Ok(LoadedOctopusPolicy {
                policy_path: path.to_path_buf(),
                is_standalone_cedar: false,
                has_filesystem_section,
                json_policy: policy,
                denied_cidrs,
                cedar_engine,
            })
        }
        other => Err(format!(
            "unsupported policy extension '.{}' for '{}': expected '.json' or '.cedar'",
            other,
            path.display()
        )),
    }
}
