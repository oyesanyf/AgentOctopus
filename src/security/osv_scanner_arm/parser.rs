use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiscoveredDependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String, // "crates.io" or "PyPI"
    pub manifest_origin: String,
}

pub struct DependencyManifestParser;

impl DependencyManifestParser {
    /// Parses Cargo.lock and extracts all pinned crates and their semantic versions.
    pub fn parse_cargo_lock(lock_content: &str) -> Vec<DiscoveredDependency> {
        let mut deps = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;

        for line in lock_content.lines() {
            let trimmed = line.trim();
            if trimmed == "[[package]]" {
                if let (Some(n), Some(v)) = (current_name.take(), current_version.take()) {
                    deps.push(DiscoveredDependency {
                        name: n,
                        version: v,
                        ecosystem: "crates.io".to_string(),
                        manifest_origin: "Cargo.lock".to_string(),
                    });
                }
            } else if trimmed.starts_with("name = ") {
                let name = trimmed.trim_start_matches("name = ").trim_matches('"');
                current_name = Some(name.to_string());
            } else if trimmed.starts_with("version = ") {
                let ver = trimmed.trim_start_matches("version = ").trim_matches('"');
                current_version = Some(ver.to_string());
            }
        }

        if let (Some(n), Some(v)) = (current_name, current_version) {
            deps.push(DiscoveredDependency {
                name: n,
                version: v,
                ecosystem: "crates.io".to_string(),
                manifest_origin: "Cargo.lock".to_string(),
            });
        }

        deps
    }

    /// Parses Python requirements.txt and extracts package names and minimum pinned versions.
    pub fn parse_requirements_txt(req_content: &str, origin: &str) -> Vec<DiscoveredDependency> {
        let mut deps = Vec::new();
        for line in req_content.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if trimmed.is_empty() {
                continue;
            }
            let first_clause = trimmed.split(',').next().unwrap_or(trimmed).trim();
            for sep in ["==", ">=", "~=", ">"] {
                if let Some((pkg, ver)) = first_clause.split_once(sep) {
                    let name = pkg.trim().to_string();
                    let version = ver.trim().to_string();
                    if !name.is_empty() && !version.is_empty() {
                        deps.push(DiscoveredDependency {
                            name,
                            version,
                            ecosystem: "PyPI".to_string(),
                            manifest_origin: origin.to_string(),
                        });
                    }
                    break;
                }
            }
        }
        deps
    }

    /// Automatically scans the workspace root for Cargo.lock and Python requirements.txt files.
    pub fn scan_workspace_dependencies(workspace_dir: &str) -> Vec<DiscoveredDependency> {
        let mut all_deps = Vec::new();
        let root = Path::new(workspace_dir);

        let cargo_lock = root.join("Cargo.lock");
        if cargo_lock.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_lock) {
                all_deps.extend(Self::parse_cargo_lock(&content));
            }
        }

        let py_reqs = root.join("vendor").join("rfchunt").join("requirements.txt");
        if py_reqs.exists() {
            if let Ok(content) = std::fs::read_to_string(&py_reqs) {
                all_deps.extend(Self::parse_requirements_txt(&content, "vendor/rfchunt/requirements.txt"));
            }
        }

        all_deps
    }
}
