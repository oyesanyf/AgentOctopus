use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsvSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvAdvisory {
    pub advisory_id: String, // e.g. RUSTSEC-2024-0001, GHSA-..., CVE-...
    pub package_name: String,
    pub ecosystem: String,
    pub affected_version: String,
    pub fixed_version: Option<String>,
    pub severity: OsvSeverity,
    pub summary: String,
    pub details: String,
    pub reference_url: String,
}

pub struct OsvDatabaseMatcher;

impl OsvDatabaseMatcher {
    /// Formats a batch query payload for Google OSV API (https://api.osv.dev/v1/querybatch).
    pub fn build_batch_query_payload(
        deps: &[super::parser::DiscoveredDependency],
    ) -> serde_json::Value {
        let queries: Vec<_> = deps
            .iter()
            .map(|d| {
                serde_json::json!({
                    "package": {
                        "name": d.name,
                        "ecosystem": d.ecosystem
                    },
                    "version": d.version
                })
            })
            .collect();

        serde_json::json!({ "queries": queries })
    }

    /// Evaluates discovered dependencies against known vulnerabilities and OSV query responses.
    pub fn parse_osv_batch_response(
        response_json: &serde_json::Value,
        queried_deps: &[super::parser::DiscoveredDependency],
    ) -> Vec<OsvAdvisory> {
        let mut advisories = Vec::new();

        if let Some(results) = response_json.get("results").and_then(|r| r.as_array()) {
            for (idx, res) in results.iter().enumerate() {
                if let Some(dep) = queried_deps.get(idx) {
                    if let Some(vulns) = res.get("vulns").and_then(|v| v.as_array()) {
                        for v in vulns {
                            let adv_id = v
                                .get("id")
                                .and_then(|i| i.as_str())
                                .unwrap_or("OSV-UNKNOWN")
                                .to_string();
                            let summary = v
                                .get("summary")
                                .and_then(|s| s.as_str())
                                .unwrap_or("Supply chain vulnerability detected")
                                .to_string();
                            let details = v
                                .get("details")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_string();

                            // Parse severity
                            let mut severity = OsvSeverity::Medium;
                            if let Some(sev_arr) = v.get("severity").and_then(|s| s.as_array()) {
                                for s in sev_arr {
                                    if let Some(score_str) =
                                        s.get("score").and_then(|sc| sc.as_str())
                                    {
                                        if score_str.starts_with("CVSS:3")
                                            || score_str.starts_with("CVSS:4")
                                        {
                                            if score_str.contains("/S:C")
                                                || score_str.contains("/A:H")
                                            {
                                                severity = OsvSeverity::High;
                                            }
                                        }
                                    }
                                }
                            }
                            if summary.to_lowercase().contains("remote code execution")
                                || summary.to_lowercase().contains("arbitrary code")
                            {
                                severity = OsvSeverity::Critical;
                            }

                            let mut fixed_version = None;
                            if let Some(affected_arr) = v.get("affected").and_then(|a| a.as_array())
                            {
                                for aff in affected_arr {
                                    if let Some(ranges) =
                                        aff.get("ranges").and_then(|r| r.as_array())
                                    {
                                        for rng in ranges {
                                            if let Some(events) =
                                                rng.get("events").and_then(|e| e.as_array())
                                            {
                                                for ev in events {
                                                    if let Some(f) =
                                                        ev.get("fixed").and_then(|fx| fx.as_str())
                                                    {
                                                        fixed_version = Some(f.to_string());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            advisories.push(OsvAdvisory {
                                advisory_id: adv_id.clone(),
                                package_name: dep.name.clone(),
                                ecosystem: dep.ecosystem.clone(),
                                affected_version: dep.version.clone(),
                                fixed_version,
                                severity,
                                summary,
                                details,
                                reference_url: format!("https://osv.dev/vulnerability/{}", adv_id),
                            });
                        }
                    }
                }
            }
        }

        advisories
    }
}
