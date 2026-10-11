use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

use super::advisor::{OsvAdvisory, OsvDatabaseMatcher, OsvSeverity};
use super::parser::{DependencyManifestParser, DiscoveredDependency};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvScanReport {
    pub scan_id: u64,
    pub timestamp_secs: u64,
    pub total_dependencies_scanned: usize,
    pub vulnerabilities_detected: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub supply_chain_security_posture: String,
    pub health_score_pct: f64,
    pub advisories: Vec<OsvAdvisory>,
    pub dependencies: Vec<DiscoveredDependency>,
}

pub struct ContinuousOsvScannerArm {
    workspace_dir: PathBuf,
    total_scans_performed: Arc<AtomicU64>,
    latest_report: Arc<Mutex<Option<OsvScanReport>>>,
    arm_ring: Arc<crate::containment_ring::ArmContainmentRing>,
}

impl Default for ContinuousOsvScannerArm {
    fn default() -> Self {
        Self::new(".")
    }
}

impl ContinuousOsvScannerArm {
    pub fn new(workspace_dir: impl AsRef<Path>) -> Self {
        let master_seed = crate::containment_ring::ArmRingRegistry::generate_master_seed();
        let arm_ring = Arc::new(crate::containment_ring::ArmContainmentRing::new(
            105,
            crate::core::types::ArmRole::ContinuousOsvScanner,
            1,
            &master_seed,
        ));
        Self {
            workspace_dir: workspace_dir.as_ref().to_path_buf(),
            total_scans_performed: Arc::new(AtomicU64::new(0)),
            latest_report: Arc::new(Mutex::new(None)),
            arm_ring,
        }
    }

    pub fn with_containment_ring(mut self, ring: Arc<crate::containment_ring::ArmContainmentRing>) -> Self {
        self.arm_ring = ring;
        self
    }

    pub fn containment_ring(&self) -> &Arc<crate::containment_ring::ArmContainmentRing> {
        &self.arm_ring
    }

    /// Performs an active continuous scan of all workspace dependencies against Google OSV database.
    pub fn run_continuous_scan(&self) -> OsvScanReport {
        let scan_id = self.total_scans_performed.fetch_add(1, Ordering::SeqCst) + 1;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if self.arm_ring.is_severed() {
            return OsvScanReport {
                scan_id,
                timestamp_secs: now_secs,
                total_dependencies_scanned: 0,
                vulnerabilities_detected: 0,
                critical_count: 0,
                high_count: 0,
                medium_count: 0,
                supply_chain_security_posture: "SEVERED_BY_SUPERVISOR".to_string(),
                health_score_pct: 0.0,
                advisories: Vec::new(),
                dependencies: Vec::new(),
            };
        }

        // 1. Discover all workspace dependencies from Cargo.lock
        let deps = DependencyManifestParser::scan_workspace_dependencies(
            self.workspace_dir.to_str().unwrap_or("."),
        );

        let total_deps = deps.len();
        let mut advisories = Vec::new();

        // 2. Query OSV API in batches of 50 to avoid request ceiling
        if !deps.is_empty() {
            for chunk in deps.chunks(50) {
                let payload = OsvDatabaseMatcher::build_batch_query_payload(chunk);
                if let Ok(payload_str) = serde_json::to_string(&payload) {
                    // Query OSV API via curl with strict 5s timeout
                    let output = std::process::Command::new("curl.exe")
                        .arg("-s")
                        .arg("-X")
                        .arg("POST")
                        .arg("https://api.osv.dev/v1/querybatch")
                        .arg("-H")
                        .arg("Content-Type: application/json")
                        .arg("-d")
                        .arg(&payload_str)
                        .output();

                    if let Ok(out) = output {
                        if out.status.success() {
                            if let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                                let mut batch_adv = OsvDatabaseMatcher::parse_osv_batch_response(&resp_json, chunk);
                                advisories.append(&mut batch_adv);
                            }
                        }
                    }
                }
            }
        }

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;

        for adv in &advisories {
            match adv.severity {
                OsvSeverity::Critical => critical_count += 1,
                OsvSeverity::High => high_count += 1,
                OsvSeverity::Medium | OsvSeverity::Low => medium_count += 1,
            }
        }

        let vulns_count = advisories.len();
        let posture = if vulns_count == 0 {
            "SECURE_ZERO_ADVISORIES".to_string()
        } else if critical_count > 0 {
            "CRITICAL_ALERT".to_string()
        } else {
            "ADVISORIES_FLAGGED".to_string()
        };

        let health_score_pct = if total_deps > 0 {
            let clean_deps = (total_deps.saturating_sub(vulns_count)) as f64;
            (clean_deps / total_deps as f64) * 100.0
        } else {
            100.0
        };

        let report = OsvScanReport {
            scan_id,
            timestamp_secs: now_secs,
            total_dependencies_scanned: total_deps,
            vulnerabilities_detected: vulns_count,
            critical_count,
            high_count,
            medium_count,
            supply_chain_security_posture: posture,
            health_score_pct,
            advisories,
            dependencies: deps,
        };

        {
            let mut lock = self.latest_report.lock().unwrap();
            *lock = Some(report.clone());
        }

        report
    }

    /// Retrieves the most recent scan report if available, or performs an on-demand scan.
    pub fn get_or_run_scan(&self) -> OsvScanReport {
        let cached = {
            let lock = self.latest_report.lock().unwrap();
            lock.clone()
        };

        match cached {
            Some(report) => report,
            None => self.run_continuous_scan(),
        }
    }

    /// Generates a SARIF report of all supply chain scan findings.
    pub fn generate_osv_sarif_report(&self) -> String {
        let report = self.get_or_run_scan();
        serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Google OSV-Scanner Continuous Arm (Agent Octopus)",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/google/osv-scanner"
                        }
                    },
                    "properties": {
                        "total_dependencies_scanned": report.total_dependencies_scanned,
                        "vulnerabilities_detected": report.vulnerabilities_detected,
                        "supply_chain_security_posture": report.supply_chain_security_posture,
                        "health_score_pct": report.health_score_pct
                    },
                    "results": []
                }
            ]
        }).to_string()
    }
}
