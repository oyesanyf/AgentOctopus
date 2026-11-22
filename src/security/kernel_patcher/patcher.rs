//! NVD API 2.0 vulnerability scanner and OS-native multi-distro patch orchestrator.

use serde_json::Value;
use std::process::Stdio;
use std::time::Duration;

use super::discovery::detect_host_posture_snapshot;
#[cfg(target_os = "linux")]
use super::discovery::linux::{classify_linux_distro, detect_linux_os_release};
use super::error::PatcherError;
use super::privilege::is_elevated;
use super::shield_state::global_kernel_shield;
use super::types::{
    HostKernelInfo, KernelVulnerability, LinuxDistro, OsFamily, PatchExecutionResult, PatchPlan,
    PatchStep, ScanOptions,
};
use super::validation::{
    apply_scrubbed_env, validate_cpe23, validate_cve_id, validate_package_name,
    verify_pinned_binary_path,
};

/// Abstraction for probing pinned system binary availability (real host vs cross-OS mock).
pub trait BinaryProbe {
    fn exists(&self, abs_path: &str) -> bool;
    fn arch(&self) -> &str;
}

/// Real host binary probe verifying pinned system prefixes and permissions.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostBinaryProbe;

impl BinaryProbe for HostBinaryProbe {
    fn exists(&self, abs_path: &str) -> bool {
        verify_pinned_binary_path(abs_path).is_ok()
    }

    fn arch(&self) -> &str {
        std::env::consts::ARCH
    }
}

/// Deterministic mock binary probe for cross-OS & 17-distro unit tests.
#[derive(Debug, Clone)]
pub struct MockBinaryProbe {
    pub present_paths: Vec<String>,
    pub cpu_arch: String,
}

impl MockBinaryProbe {
    #[must_use]
    pub fn with_paths(paths: &[&str], arch: &str) -> Self {
        Self {
            present_paths: paths.iter().map(|s| (*s).to_string()).collect(),
            cpu_arch: arch.to_string(),
        }
    }
}

impl BinaryProbe for MockBinaryProbe {
    fn exists(&self, abs_path: &str) -> bool {
        self.present_paths.iter().any(|p| p == abs_path)
    }

    fn arch(&self) -> &str {
        &self.cpu_arch
    }
}

/// Resolves an NVD API key strictly from explicit caller option or `NVD_API_KEY` env var.
/// Empty or whitespace-only values resolve to `None`.
#[must_use]
pub fn resolve_nvd_api_key(explicit: Option<&str>) -> Option<String> {
    explicit
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            std::env::var("NVD_API_KEY")
                .ok()
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
        })
}

/// Orchestrates OS kernel vulnerability scanning against NVD API 2.0 and native patch execution.
#[derive(Debug, Clone)]
pub struct KernelPatcher {
    base_url: String,
    client: reqwest::Client,
}

impl Default for KernelPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelPatcher {
    /// Constructs a patcher pointing to the official NIST NVD API 2.0 endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url("https://services.nvd.nist.gov/rest/json/cves/2.0")
    }

    /// Constructs a patcher pointing to a custom endpoint URL (useful for offline tests and mirrors).
    #[must_use]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Returns the configured NVD endpoint base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Queries NVD API 2.0 for vulnerabilities matching the target or detected kernel CPE,
    /// validating CPE/CVE syntax, extracting CVSS v3.1 & CISA KEV metadata, and ranking KEV-first.
    pub async fn scan_kernel_vulnerabilities(
        &self,
        options: &ScanOptions,
    ) -> Result<Vec<KernelVulnerability>, PatcherError> {
        let raw_cpe = match &options.cpe {
            Some(c) => c.clone(),
            None => HostKernelInfo::detect_host_kernel()?.cpe23,
        };
        let target_cpe = validate_cpe23(&raw_cpe)?;

        let separator = if self.base_url.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!("{}{}cpeName={}", self.base_url, separator, target_cpe);

        let mut req = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(options.timeout_secs.max(1)));

        // Secret Hygiene Invariant: NVD_API_KEY is read strictly from runtime env/options,
        // never accepted from CLI arguments so it never enters OS process tables.
        if let Some(key) = resolve_nvd_api_key(options.api_key.as_deref()) {
            req = req.header("apiKey", key);
        }

        let resp = req.send().await.map_err(PatcherError::Network)?;

        if resp.status().as_u16() == 429 {
            return Err(PatcherError::RateLimited);
        }

        if !resp.status().is_success() {
            return Err(PatcherError::NvdApiError(format!(
                "NVD API returned HTTP error: {}",
                resp.status()
            )));
        }

        let body_text = resp.text().await.map_err(PatcherError::Network)?;
        let parsed: Value =
            serde_json::from_str(&body_text).map_err(PatcherError::Serialization)?;

        let mut vulnerabilities = Vec::new();

        let vuln_items = parsed
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                PatcherError::NvdApiError(
                    "NVD API HTTP 200 response missing 'vulnerabilities' array".to_string(),
                )
            })?;

        for item in vuln_items {
            let Some(cve) = item.get("cve") else {
                continue;
            };
            let Some(raw_id) = cve.get("id").and_then(|i| i.as_str()) else {
                continue;
            };
            let Ok(id) = validate_cve_id(raw_id) else {
                continue;
            };

            // Description: English description preferred
            let mut description = String::new();
            if let Some(desc_array) = cve.get("descriptions").and_then(|d| d.as_array()) {
                for d in desc_array {
                    if d.get("lang").and_then(|l| l.as_str()) == Some("en") {
                        if let Some(v) = d.get("value").and_then(|s| s.as_str()) {
                            description = v.to_string();
                            break;
                        }
                    }
                }
                if description.is_empty() {
                    if let Some(first) = desc_array
                        .first()
                        .and_then(|d| d.get("value"))
                        .and_then(|s| s.as_str())
                    {
                        description = first.to_string();
                    }
                }
            }

            // CVSS v3.1 Metrics
            let mut cvss_score: Option<f32> = None;
            let mut cvss_severity: Option<String> = None;

            if let Some(v31_array) = cve
                .get("metrics")
                .and_then(|m| m.get("cvssMetricV31"))
                .and_then(|a| a.as_array())
            {
                if let Some(first_v31) = v31_array.first() {
                    if let Some(data) = first_v31.get("cvssData") {
                        cvss_score = data
                            .get("baseScore")
                            .and_then(|s| s.as_f64())
                            .map(|f| f as f32);
                        cvss_severity = data
                            .get("baseSeverity")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string());
                    }
                }
            }

            // CISA KEV Fields
            let cisa_exploit_add = cve
                .get("cisaExploitAdd")
                .and_then(|s| s.as_str())
                .map(ToString::to_string);
            let cisa_action_due = cve
                .get("cisaActionDue")
                .and_then(|s| s.as_str())
                .map(ToString::to_string);
            let cisa_required_action = cve
                .get("cisaRequiredAction")
                .and_then(|s| s.as_str())
                .map(ToString::to_string);
            let cisa_vulnerability_name = cve
                .get("cisaVulnerabilityName")
                .and_then(|s| s.as_str())
                .map(ToString::to_string);

            let is_cisa_kev = cisa_exploit_add.is_some()
                || cisa_action_due.is_some()
                || cisa_required_action.is_some()
                || cisa_vulnerability_name.is_some();

            // Threshold & KEV-only filters
            if options.kev_only && !is_cisa_kev {
                continue;
            }

            if let Some(min_score) = options.min_cvss_score {
                let score = cvss_score.unwrap_or(0.0);
                if score < min_score {
                    continue;
                }
            }

            vulnerabilities.push(KernelVulnerability {
                cve_id: id,
                description,
                cvss_v31_score: cvss_score,
                cvss_v31_severity: cvss_severity,
                is_cisa_kev,
                cisa_exploit_add,
                cisa_action_due,
                cisa_required_action,
                cisa_vulnerability_name,
            });
        }

        // Rank findings: CISA KEV entries first, descending by CVSS v3.1 base score
        vulnerabilities.sort_by(|a, b| match (a.is_cisa_kev, b.is_cisa_kev) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                let sa = a.cvss_v31_score.unwrap_or(-1.0);
                let sb = b.cvss_v31_score.unwrap_or(-1.0);
                sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
            }
        });

        Ok(vulnerabilities)
    }

    /// Executes or dry-runs the multi-step, pinned-binary OS-native kernel patch workflow.
    ///
    /// Non-dry-run operations require elevated privileges (`InsufficientPrivileges`), verify every
    /// pinned binary path (`UntrustedOrMissingBinary`), scrub dangerous env vars, execute via
    /// `spawn_hidden_tokio`, re-check `RebootPendingStatus` (latching `shield_locked_until_reboot`
    /// if a reboot is needed), and emit an RFC 6962 `PatchAuditReceipt`.
    pub async fn apply_os_kernel_patch(
        &self,
        dry_run: bool,
    ) -> Result<PatchExecutionResult, PatcherError> {
        if !dry_run && !is_elevated() {
            return Err(PatcherError::InsufficientPrivileges);
        }

        let snapshot = tokio::task::spawn_blocking(detect_host_posture_snapshot)
            .await
            .map_err(|e| PatcherError::DetectionFailed(e.to_string()))??;

        let Some(plan) = resolve_host_patch_plan(dry_run) else {
            return Err(PatcherError::UnsupportedPlatform(
                std::env::consts::OS.to_string(),
            ));
        };

        if dry_run {
            let preview_lines: Vec<String> = plan
                .steps
                .iter()
                .map(|s| format!("[DRY-RUN] [{}] {} {}", s.phase, s.command, s.args.join(" ")))
                .collect();
            let output = preview_lines.join("\n");
            let ephemeral_coordinator = super::shield_state::KernelShieldCoordinator::new();
            let receipt = ephemeral_coordinator.apply_post_patch_status(
                &snapshot.host_kernel.os_family,
                &snapshot.host_kernel.cpe23,
                &snapshot.reboot_pending,
            )?;

            return Ok(PatchExecutionResult {
                dry_run: true,
                command: plan.primary_command,
                args: plan.primary_args,
                success: true,
                output,
                os_subsystem: plan.os_subsystem,
                steps: plan.steps,
                step_outputs: preview_lines,
                reboot_pending: Some(snapshot.reboot_pending.clone()),
                shield_locked_until_reboot: receipt.shield_locked_until_reboot,
                audit_receipt: Some(receipt),
            });
        }

        let mut step_outputs = Vec::with_capacity(plan.steps.len());
        let mut combined_output = String::new();
        let mut all_ok = true;

        for step in &plan.steps {
            verify_pinned_binary_path(&step.command)?;
            let mut cmd = tokio::process::Command::new(&step.command);
            cmd.args(&step.args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let extra_env_refs: Vec<(&str, &str)> = step
                .env
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            apply_scrubbed_env(&mut cmd, &plan.os_family, &extra_env_refs)?;

            let child =
                crate::security::spawn_hidden_tokio(&mut cmd, "kernel_patcher: native OS patch")
                    .map_err(|e| PatcherError::ExecutionFailed(e.to_string()))?;
            let status = child
                .wait_with_output()
                .await
                .map_err(|e| PatcherError::ExecutionFailed(e.to_string()))?;

            let step_out = format!(
                "{}{}",
                String::from_utf8_lossy(&status.stdout),
                String::from_utf8_lossy(&status.stderr)
            );
            step_outputs.push(step_out.clone());
            if !combined_output.is_empty() {
                combined_output.push('\n');
            }
            combined_output.push_str(&format!("[{}] {}", step.os_subsystem, step_out));

            if !status.status.success() {
                all_ok = false;
                break;
            }
        }

        let post_snapshot = tokio::task::spawn_blocking(detect_host_posture_snapshot)
            .await
            .map_err(|e| PatcherError::DetectionFailed(e.to_string()))??;
        let receipt = global_kernel_shield().apply_post_patch_status(
            &post_snapshot.host_kernel.os_family,
            &post_snapshot.host_kernel.cpe23,
            &post_snapshot.reboot_pending,
        )?;

        Ok(PatchExecutionResult {
            dry_run: false,
            command: plan.primary_command,
            args: plan.primary_args,
            success: all_ok,
            output: combined_output,
            os_subsystem: plan.os_subsystem,
            steps: plan.steps,
            step_outputs,
            reboot_pending: Some(post_snapshot.reboot_pending),
            shield_locked_until_reboot: receipt.shield_locked_until_reboot,
            audit_receipt: Some(receipt),
        })
    }
}

fn resolve_host_patch_plan(dry_run: bool) -> Option<PatchPlan> {
    let probe = HostBinaryProbe;

    #[cfg(target_os = "windows")]
    {
        let _ = dry_run;
        plan_native_kernel_patch_with_probe(&OsFamily::Windows, None, &probe)
    }

    #[cfg(target_os = "linux")]
    {
        let os_rel = detect_linux_os_release();
        let distro = classify_linux_distro(&os_rel);
        plan_native_kernel_patch_with_probe_opts(&OsFamily::Linux, Some(&distro), &probe, dry_run)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = dry_run;
        plan_native_kernel_patch_with_probe(&OsFamily::MacOS, None, &probe)
    }

    #[cfg(target_os = "freebsd")]
    {
        plan_native_kernel_patch_with_probe_opts(&OsFamily::FreeBSD, None, &probe, dry_run)
    }

    #[cfg(target_os = "openbsd")]
    {
        plan_native_kernel_patch_with_probe_opts(&OsFamily::OpenBSD, None, &probe, dry_run)
    }

    #[cfg(target_os = "netbsd")]
    {
        plan_native_kernel_patch_with_probe_opts(&OsFamily::NetBSD, None, &probe, dry_run)
    }

    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (probe, dry_run);
        None
    }
}

/// Builds a pinned, argv-only `PatchPlan` for any supported OS / Linux distro using `probe`.
/// Never invokes `sh -c`, `cmd /c`, or `powershell -Command`.
#[must_use]
pub fn plan_native_kernel_patch_with_probe(
    os_family: &OsFamily,
    distro: Option<&LinuxDistro>,
    probe: &dyn BinaryProbe,
) -> Option<PatchPlan> {
    plan_native_kernel_patch_with_probe_opts(os_family, distro, probe, false)
}

/// Builds a pinned, argv-only `PatchPlan`, optionally adjusting check vs live flags (e.g. OpenBSD `syspatch -c` vs `syspatch`).
#[must_use]
pub fn plan_native_kernel_patch_with_probe_opts(
    os_family: &OsFamily,
    distro: Option<&LinuxDistro>,
    probe: &dyn BinaryProbe,
    dry_run: bool,
) -> Option<PatchPlan> {
    match os_family {
        OsFamily::Windows => {
            let uso = r"C:\Windows\System32\UsoClient.exe";
            let steps = vec![
                PatchStep {
                    command: uso.to_string(),
                    args: vec!["StartScan".to_string()],
                    env: Vec::new(),
                    os_subsystem: "UsoClient".to_string(),
                    phase: "scan".to_string(),
                },
                PatchStep {
                    command: uso.to_string(),
                    args: vec!["StartDownload".to_string()],
                    env: Vec::new(),
                    os_subsystem: "UsoClient".to_string(),
                    phase: "download".to_string(),
                },
                PatchStep {
                    command: uso.to_string(),
                    args: vec!["StartInstall".to_string()],
                    env: Vec::new(),
                    os_subsystem: "UsoClient".to_string(),
                    phase: "install".to_string(),
                },
            ];
            Some(PatchPlan {
                os_family: OsFamily::Windows,
                distro: None,
                primary_command: uso.to_string(),
                primary_args: vec!["StartInstall".to_string()],
                os_subsystem: "UsoClient".to_string(),
                steps,
                rebootless_livepatch_preferred: false,
                requires_elevation: true,
            })
        }
        OsFamily::MacOS => {
            let sw = "/usr/sbin/softwareupdate";
            let steps = vec![
                PatchStep {
                    command: sw.to_string(),
                    args: vec!["--list".to_string()],
                    env: Vec::new(),
                    os_subsystem: "softwareupdate".to_string(),
                    phase: "scan".to_string(),
                },
                PatchStep {
                    command: sw.to_string(),
                    args: vec![
                        "--install".to_string(),
                        "--recommended".to_string(),
                        "--agree-to-license".to_string(),
                    ],
                    env: Vec::new(),
                    os_subsystem: "softwareupdate".to_string(),
                    phase: "install".to_string(),
                },
            ];
            Some(PatchPlan {
                os_family: OsFamily::MacOS,
                distro: None,
                primary_command: sw.to_string(),
                primary_args: vec![
                    "--install".to_string(),
                    "--recommended".to_string(),
                    "--agree-to-license".to_string(),
                ],
                os_subsystem: "softwareupdate".to_string(),
                steps,
                rebootless_livepatch_preferred: false,
                requires_elevation: true,
            })
        }
        OsFamily::FreeBSD => {
            let bin = "/usr/sbin/freebsd-update";
            let args = vec![
                "--not-running-from-cron".to_string(),
                "fetch".to_string(),
                "install".to_string(),
            ];
            let step = PatchStep {
                command: bin.to_string(),
                args: args.clone(),
                env: Vec::new(),
                os_subsystem: "freebsd-update".to_string(),
                phase: "install".to_string(),
            };
            Some(PatchPlan {
                os_family: OsFamily::FreeBSD,
                distro: None,
                primary_command: bin.to_string(),
                primary_args: args,
                os_subsystem: "freebsd-update".to_string(),
                steps: vec![step],
                rebootless_livepatch_preferred: false,
                requires_elevation: true,
            })
        }
        OsFamily::OpenBSD => {
            let bin = "/usr/sbin/syspatch";
            let args = if dry_run {
                vec!["-c".to_string()]
            } else {
                Vec::new()
            };
            let step = PatchStep {
                command: bin.to_string(),
                args: args.clone(),
                env: Vec::new(),
                os_subsystem: "syspatch".to_string(),
                phase: if dry_run { "check" } else { "install" }.to_string(),
            };
            Some(PatchPlan {
                os_family: OsFamily::OpenBSD,
                distro: None,
                primary_command: bin.to_string(),
                primary_args: args,
                os_subsystem: "syspatch".to_string(),
                steps: vec![step],
                rebootless_livepatch_preferred: false,
                requires_elevation: true,
            })
        }
        OsFamily::NetBSD => {
            let (bin, args, subsys) =
                if probe.exists("/usr/sbin/sysupgrade") || !probe.exists("/usr/pkg/sbin/pkgin") {
                    (
                        "/usr/sbin/sysupgrade",
                        vec!["auto".to_string()],
                        "sysupgrade",
                    )
                } else {
                    (
                        "/usr/pkg/sbin/pkgin",
                        vec!["-y".to_string(), "full-upgrade".to_string()],
                        "pkgin",
                    )
                };
            let step = PatchStep {
                command: bin.to_string(),
                args: args.clone(),
                env: Vec::new(),
                os_subsystem: subsys.to_string(),
                phase: "install".to_string(),
            };
            Some(PatchPlan {
                os_family: OsFamily::NetBSD,
                distro: None,
                primary_command: bin.to_string(),
                primary_args: args,
                os_subsystem: subsys.to_string(),
                steps: vec![step],
                rebootless_livepatch_preferred: false,
                requires_elevation: true,
            })
        }
        OsFamily::Linux => plan_linux_distro_patch(distro, probe),
        OsFamily::Unknown(_) => None,
    }
}

fn first_existing<'a>(probe: &dyn BinaryProbe, candidates: &[&'a str]) -> Option<&'a str> {
    candidates.iter().copied().find(|p| probe.exists(p))
}

fn plan_linux_distro_patch(
    distro: Option<&LinuxDistro>,
    probe: &dyn BinaryProbe,
) -> Option<PatchPlan> {
    let effective_distro = distro.cloned().unwrap_or_else(|| {
        if probe.exists("/usr/bin/apt-get") {
            LinuxDistro::Ubuntu
        } else if probe.exists("/usr/bin/zypper") {
            LinuxDistro::Sles
        } else if probe.exists("/usr/bin/pacman") {
            LinuxDistro::Arch
        } else if probe.exists("/sbin/apk") || probe.exists("/usr/sbin/apk") {
            LinuxDistro::Alpine
        } else {
            LinuxDistro::Rhel
        }
    });

    let mut steps = Vec::new();
    let mut livepatch_preferred = false;

    match effective_distro {
        LinuxDistro::Ubuntu | LinuxDistro::Debian | LinuxDistro::Kali => {
            if let Some(lp_bin) = first_existing(
                probe,
                &[
                    "/usr/bin/canonical-livepatch",
                    "/snap/bin/canonical-livepatch",
                ],
            ) {
                livepatch_preferred = true;
                steps.push(PatchStep {
                    command: lp_bin.to_string(),
                    args: vec!["refresh".to_string()],
                    env: Vec::new(),
                    os_subsystem: "canonical-livepatch".to_string(),
                    phase: "livepatch".to_string(),
                });
            } else if probe.exists("/usr/bin/pro") {
                livepatch_preferred = true;
                steps.push(PatchStep {
                    command: "/usr/bin/pro".to_string(),
                    args: vec!["status".to_string(), "--wait".to_string()],
                    env: Vec::new(),
                    os_subsystem: "ubuntu-pro".to_string(),
                    phase: "livepatch".to_string(),
                });
            }

            let pkg = match effective_distro {
                LinuxDistro::Ubuntu => "linux-image-generic",
                LinuxDistro::Debian | LinuxDistro::Kali => {
                    if probe.arch().eq_ignore_ascii_case("aarch64") {
                        "linux-image-arm64"
                    } else {
                        "linux-image-amd64"
                    }
                }
                _ => "linux-image-generic",
            };
            let validated_pkg =
                validate_package_name(pkg).unwrap_or_else(|_| "linux-image-generic".to_string());
            steps.push(PatchStep {
                command: "/usr/bin/apt-get".to_string(),
                args: vec!["upgrade".to_string(), "-y".to_string(), validated_pkg],
                env: vec![("DEBIAN_FRONTEND".to_string(), "noninteractive".to_string())],
                os_subsystem: "apt-get".to_string(),
                phase: "upgrade".to_string(),
            });
        }
        LinuxDistro::Rhel
        | LinuxDistro::Fedora
        | LinuxDistro::Rocky
        | LinuxDistro::Alma
        | LinuxDistro::CentOS
        | LinuxDistro::AmazonLinux => {
            if let Some(kpatch_bin) =
                first_existing(probe, &["/usr/sbin/kpatch", "/usr/bin/kpatch"])
            {
                livepatch_preferred = true;
                steps.push(PatchStep {
                    command: kpatch_bin.to_string(),
                    args: vec!["load".to_string(), "--all".to_string()],
                    env: Vec::new(),
                    os_subsystem: "kpatch".to_string(),
                    phase: "livepatch".to_string(),
                });
            }
            if probe.exists("/usr/bin/dnf") || !probe.exists("/usr/bin/yum") {
                steps.push(PatchStep {
                    command: "/usr/bin/dnf".to_string(),
                    args: vec![
                        "upgrade".to_string(),
                        "--security".to_string(),
                        "-y".to_string(),
                        "kernel".to_string(),
                    ],
                    env: Vec::new(),
                    os_subsystem: "dnf".to_string(),
                    phase: "upgrade".to_string(),
                });
            } else {
                steps.push(PatchStep {
                    command: "/usr/bin/yum".to_string(),
                    args: vec![
                        "update".to_string(),
                        "--security".to_string(),
                        "-y".to_string(),
                        "kernel".to_string(),
                    ],
                    env: Vec::new(),
                    os_subsystem: "yum".to_string(),
                    phase: "upgrade".to_string(),
                });
            }
        }
        LinuxDistro::OracleLinux => {
            if let Some(uptrack_bin) = first_existing(
                probe,
                &["/usr/bin/uptrack-upgrade", "/usr/sbin/uptrack-upgrade"],
            ) {
                livepatch_preferred = true;
                steps.push(PatchStep {
                    command: uptrack_bin.to_string(),
                    args: vec!["-y".to_string()],
                    env: Vec::new(),
                    os_subsystem: "ksplice".to_string(),
                    phase: "livepatch".to_string(),
                });
            }
            if probe.exists("/usr/bin/dnf") || !probe.exists("/usr/bin/yum") {
                steps.push(PatchStep {
                    command: "/usr/bin/dnf".to_string(),
                    args: vec![
                        "upgrade".to_string(),
                        "--security".to_string(),
                        "-y".to_string(),
                        "kernel".to_string(),
                    ],
                    env: Vec::new(),
                    os_subsystem: "dnf".to_string(),
                    phase: "upgrade".to_string(),
                });
            } else {
                steps.push(PatchStep {
                    command: "/usr/bin/yum".to_string(),
                    args: vec![
                        "update".to_string(),
                        "--security".to_string(),
                        "-y".to_string(),
                        "kernel".to_string(),
                    ],
                    env: Vec::new(),
                    os_subsystem: "yum".to_string(),
                    phase: "upgrade".to_string(),
                });
            }
        }
        LinuxDistro::Sles | LinuxDistro::OpenSuse => {
            if let Some(klp_bin) = first_existing(
                probe,
                &[
                    "/usr/sbin/klp",
                    "/usr/bin/klp",
                    "/usr/sbin/kgr",
                    "/usr/bin/kgr",
                ],
            ) {
                livepatch_preferred = true;
                steps.push(PatchStep {
                    command: klp_bin.to_string(),
                    args: vec!["status".to_string()],
                    env: Vec::new(),
                    os_subsystem: "klp".to_string(),
                    phase: "livepatch".to_string(),
                });
            }
            steps.push(PatchStep {
                command: "/usr/bin/zypper".to_string(),
                args: vec![
                    "--non-interactive".to_string(),
                    "patch".to_string(),
                    "--category".to_string(),
                    "security".to_string(),
                ],
                env: Vec::new(),
                os_subsystem: "zypper".to_string(),
                phase: "upgrade".to_string(),
            });
        }
        LinuxDistro::Arch => {
            steps.push(PatchStep {
                command: "/usr/bin/pacman".to_string(),
                args: vec![
                    "-Syu".to_string(),
                    "--noconfirm".to_string(),
                    "linux".to_string(),
                ],
                env: Vec::new(),
                os_subsystem: "pacman".to_string(),
                phase: "upgrade".to_string(),
            });
        }
        LinuxDistro::Alpine => {
            let apk = first_existing(probe, &["/sbin/apk", "/usr/sbin/apk"]).unwrap_or("/sbin/apk");
            steps.push(PatchStep {
                command: apk.to_string(),
                args: vec![
                    "upgrade".to_string(),
                    "--no-cache".to_string(),
                    "linux-lts".to_string(),
                ],
                env: Vec::new(),
                os_subsystem: "apk".to_string(),
                phase: "upgrade".to_string(),
            });
        }
        LinuxDistro::NixOS => {
            steps.push(PatchStep {
                command: "/run/current-system/sw/bin/nixos-rebuild".to_string(),
                args: vec!["switch".to_string(), "--upgrade".to_string()],
                env: Vec::new(),
                os_subsystem: "nixos-rebuild".to_string(),
                phase: "upgrade".to_string(),
            });
        }
        LinuxDistro::Gentoo => {
            steps.push(PatchStep {
                command: "/usr/bin/emerge".to_string(),
                args: vec![
                    "--update".to_string(),
                    "--oneshot".to_string(),
                    "sys-kernel/gentoo-kernel".to_string(),
                ],
                env: Vec::new(),
                os_subsystem: "emerge".to_string(),
                phase: "upgrade".to_string(),
            });
        }
        LinuxDistro::Flatcar => {
            steps.push(PatchStep {
                command: "/usr/bin/update_engine_client".to_string(),
                args: vec!["-update".to_string()],
                env: Vec::new(),
                os_subsystem: "update_engine_client".to_string(),
                phase: "upgrade".to_string(),
            });
        }
        LinuxDistro::Unknown(_) => {
            if let Some(lp_bin) = first_existing(
                probe,
                &[
                    "/usr/bin/canonical-livepatch",
                    "/snap/bin/canonical-livepatch",
                ],
            ) {
                livepatch_preferred = true;
                steps.push(PatchStep {
                    command: lp_bin.to_string(),
                    args: vec!["refresh".to_string()],
                    env: Vec::new(),
                    os_subsystem: "canonical-livepatch".to_string(),
                    phase: "livepatch".to_string(),
                });
            }
            steps.push(PatchStep {
                command: "/usr/bin/dnf".to_string(),
                args: vec![
                    "upgrade".to_string(),
                    "--security".to_string(),
                    "-y".to_string(),
                    "kernel".to_string(),
                ],
                env: Vec::new(),
                os_subsystem: "dnf".to_string(),
                phase: "upgrade".to_string(),
            });
        }
    }

    let primary = steps.first()?.clone();
    Some(PatchPlan {
        os_family: OsFamily::Linux,
        distro: Some(effective_distro),
        primary_command: primary.command,
        primary_args: primary.args,
        os_subsystem: primary.os_subsystem,
        steps,
        rebootless_livepatch_preferred: livepatch_preferred,
        requires_elevation: true,
    })
}
