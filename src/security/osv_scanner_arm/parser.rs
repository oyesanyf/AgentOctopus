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

    /// Automatically scans the workspace root for Cargo.lock and dependency files.
    pub fn scan_workspace_dependencies(workspace_dir: &str) -> Vec<DiscoveredDependency> {
        let cargo_lock = Path::new(workspace_dir).join("Cargo.lock");
        if cargo_lock.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_lock) {
                return Self::parse_cargo_lock(&content);
            }
        }
        Vec::new()
    }
}
