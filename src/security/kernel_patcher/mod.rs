//! OS Kernel Vulnerability Scanning & Native Patch Orchestration.
//!
//! Discovers the host operating system kernel (`Linux`, `Windows`, `macOS`), maps it to a
//! NIST IR 7695 CPE 2.3 identifier, queries NIST NVD API 2.0 / CISA KEV metadata, ranks
//! actively exploited CVEs first, and safely executes or dry-runs OS-native patch workflows.
//!
//! # Security Invariants
//! - Zero hardcoded secrets: `NVD_API_KEY` is read strictly from runtime `std::env::var("NVD_API_KEY")`.
//! - CLI `--api-key` / `--nvd-api-key` flags are explicitly rejected to prevent OS process-table leaks.
//! - Live patch execution fails closed (`InsufficientPrivileges`) when not elevated (`root` / Administrator).

pub mod cpe;
pub mod discovery;
pub mod error;
pub mod patcher;
pub mod privilege;
pub mod types;

pub use error::PatcherError;
pub use patcher::{resolve_nvd_api_key, KernelPatcher};
pub use privilege::is_elevated;
pub use types::{
    HostKernelInfo, KernelVulnerability, OsFamily, PatchExecutionResult, ScanOptions,
};

use serde::{Deserialize, Serialize};

/// Parsed CLI options for `agent_octopus patch-kernel`.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchKernelCliArgs {
    pub dry_run: bool,
    pub kev_only: bool,
    pub min_cvss: Option<f32>,
    pub cpe: Option<String>,
    pub apply: bool,
    pub json: bool,
    pub timeout_secs: u64,
    pub show_help: bool,
}

impl Default for PatchKernelCliArgs {
    fn default() -> Self {
        Self {
            dry_run: false,
            kev_only: false,
            min_cvss: None,
            cpe: None,
            apply: false,
            json: false,
            timeout_secs: 30,
            show_help: false,
        }
    }
}

/// Machine-readable report emitted by `agent_octopus patch-kernel --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchKernelCliReport {
    pub scan_status: String,
    pub scan_notice: Option<String>,
    pub host_kernel: HostKernelInfo,
    pub target_cpe: String,
    pub nvd_api_key_configured: bool,
    pub vulnerability_count: usize,
    pub cisa_kev_count: usize,
    pub vulnerabilities: Vec<KernelVulnerability>,
    pub patch_result: Option<PatchExecutionResult>,
}

/// Help banner for `agent_octopus patch-kernel`.
#[must_use]
pub fn format_patch_kernel_help() -> &'static str {
    "USAGE:\n  \
     agent_octopus patch-kernel [OPTIONS]\n\n\
     OPTIONS:\n  \
     --dry-run                Preview native OS patch command without mutating the kernel\n  \
     --apply, --execute       Execute native OS patch command (requires root/Administrator)\n  \
     --kev-only               Show only CISA Known Exploited Vulnerabilities\n  \
     --min-cvss <SCORE>       Minimum CVSS v3.1 base score filter (0.0 - 10.0)\n  \
     --cpe <CPE23>            Override auto-detected host kernel CPE 2.3 string\n  \
     --timeout-secs <SECS>    HTTP request timeout in seconds (default: 30)\n  \
     --json                   Emit machine-readable JSON output\n  \
     -h, --help               Show this help message\n\n\
     ENVIRONMENT:\n  \
     NVD_API_KEY              Optional NIST NVD API 2.0 key (CLI --api-key flags are forbidden)"
}

/// Parses arguments passed after `patch-kernel` / `kernel-patch`.
/// Rejects `--api-key` and `--nvd-api-key` to keep NVD credentials out of process argv tables.
pub fn parse_patch_kernel_args(args: &[String]) -> Result<PatchKernelCliArgs, String> {
    let mut parsed = PatchKernelCliArgs::default();
    let mut idx = 0;

    while idx < args.len() {
        let arg = args[idx].as_str();
        if arg == "--help" || arg == "-h" {
            parsed.show_help = true;
        } else if arg == "--dry-run" {
            parsed.dry_run = true;
        } else if arg == "--apply" || arg == "--execute" {
            parsed.apply = true;
        } else if arg == "--kev-only" {
            parsed.kev_only = true;
        } else if arg == "--json" {
            parsed.json = true;
        } else if arg == "--api-key"
            || arg.starts_with("--api-key=")
            || arg == "--nvd-api-key"
            || arg.starts_with("--nvd-api-key=")
        {
            return Err(
                "Passing NVD API keys via CLI arguments (--api-key/--nvd-api-key) is forbidden; set the NVD_API_KEY environment variable instead."
                    .to_string(),
            );
        } else if let Some(val) = arg.strip_prefix("--min-cvss=") {
            parsed.min_cvss = Some(parse_cvss_score(val)?);
        } else if arg == "--min-cvss" {
            idx += 1;
            let val = args
                .get(idx)
                .ok_or_else(|| "Missing value for --min-cvss".to_string())?;
            parsed.min_cvss = Some(parse_cvss_score(val)?);
        } else if let Some(val) = arg.strip_prefix("--cpe=") {
            if val.trim().is_empty() {
                return Err("--cpe value cannot be empty".to_string());
            }
            parsed.cpe = Some(val.trim().to_string());
        } else if arg == "--cpe" {
            idx += 1;
            let val = args
                .get(idx)
                .ok_or_else(|| "Missing value for --cpe".to_string())?;
            if val.trim().is_empty() {
                return Err("--cpe value cannot be empty".to_string());
            }
            parsed.cpe = Some(val.trim().to_string());
        } else if let Some(val) = arg.strip_prefix("--timeout-secs=") {
            parsed.timeout_secs = parse_timeout_secs(val)?;
        } else if arg == "--timeout-secs" {
            idx += 1;
            let val = args
                .get(idx)
                .ok_or_else(|| "Missing value for --timeout-secs".to_string())?;
            parsed.timeout_secs = parse_timeout_secs(val)?;
        } else {
            return Err(format!("Unknown patch-kernel option: {arg}"));
        }
        idx += 1;
    }

    Ok(parsed)
}

fn parse_cvss_score(raw: &str) -> Result<f32, String> {
    let score = raw
        .trim()
        .parse::<f32>()
        .map_err(|_| format!("Invalid --min-cvss score '{raw}': expected number 0.0..=10.0"))?;
    if !score.is_finite() || !(0.0..=10.0).contains(&score) {
        return Err(format!(
            "Invalid --min-cvss score '{raw}': must be within 0.0..=10.0"
        ));
    }
    Ok(score)
}

fn parse_timeout_secs(raw: &str) -> Result<u64, String> {
    let secs = raw
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("Invalid --timeout-secs value '{raw}': expected positive integer"))?;
    if secs == 0 {
        return Err("--timeout-secs must be at least 1".to_string());
    }
    Ok(secs)
}

/// Runs the `agent_octopus patch-kernel` CLI workflow and prints either human-readable
/// output or a structured JSON report.
pub async fn execute_patch_kernel_cli(args: &PatchKernelCliArgs) -> Result<(), PatcherError> {
    if args.show_help {
        println!("{}", format_patch_kernel_help());
        return Ok(());
    }

    let host_info = tokio::task::spawn_blocking(HostKernelInfo::detect_host_kernel)
        .await
        .map_err(|e| PatcherError::DetectionFailed(e.to_string()))??;

    let target_cpe = args
        .cpe
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&host_info.cpe23)
        .to_string();

    let api_key = resolve_nvd_api_key(None);
    let nvd_api_key_configured = api_key.is_some();

    let options = ScanOptions {
        cpe: Some(target_cpe.clone()),
        min_cvss_score: args.min_cvss,
        kev_only: args.kev_only,
        api_key,
        timeout_secs: args.timeout_secs.max(1),
    };

    let patcher = KernelPatcher::new();
    let (scan_status, scan_notice, vulnerabilities) =
        match patcher.scan_kernel_vulnerabilities(&options).await {
            Ok(vulns) => ("ok".to_string(), None, vulns),
            Err(PatcherError::RateLimited) => (
                "rate_limited".to_string(),
                Some(
                    "Rate limited by NIST NVD API 2.0; set NVD_API_KEY in runtime environment"
                        .to_string(),
                ),
                Vec::new(),
            ),
            Err(err) => ("unavailable".to_string(), Some(err.to_string()), Vec::new()),
        };

    let patch_result = if args.apply || args.dry_run {
        let is_dry_run = args.dry_run || !args.apply;
        Some(patcher.apply_os_kernel_patch(is_dry_run).await?)
    } else {
        None
    };

    let cisa_kev_count = vulnerabilities.iter().filter(|v| v.is_cisa_kev).count();

    if args.json {
        let report = PatchKernelCliReport {
            scan_status,
            scan_notice,
            host_kernel: host_info,
            target_cpe,
            nvd_api_key_configured,
            vulnerability_count: vulnerabilities.len(),
            cisa_kev_count,
            vulnerabilities,
            patch_result,
        };
        let serialized = serde_json::to_string_pretty(&report)?;
        println!("{serialized}");
        return Ok(());
    }

    println!("================================================================================");
    println!("AGENT OCTOPUS HOST KERNEL DISCOVERY & NVD VULNERABILITY SCANNER");
    println!("================================================================================");
    println!("  OS Family:        {}", host_info.os_family);
    println!("  OS Version:       {}", host_info.os_version);
    println!("  Kernel Release:   {}", host_info.kernel_release);
    println!("  Architecture:     {}", host_info.architecture);
    println!("  Target CPE 2.3:   {}", target_cpe);
    println!(
        "  NVD API Key:      {}",
        if nvd_api_key_configured {
            "Configured via NVD_API_KEY environment variable"
        } else {
            "None (public rate-limited mode)"
        }
    );
    if args.kev_only {
        println!("  Filter Mode:      CISA KEV Only");
    }
    if let Some(cvss) = args.min_cvss {
        println!("  Min CVSS Score:   {:.1}", cvss);
    }
    println!("================================================================================");

    if let Some(notice) = scan_notice {
        eprintln!("[KERNEL-PATCHER] NVD query notice ({scan_status}): {notice}");
    } else if vulnerabilities.is_empty() {
        println!("Zero vulnerabilities found matching the specified criteria.");
    } else {
        println!(
            "Found {} vulnerabilities affecting target kernel ({} CISA KEV):",
            vulnerabilities.len(),
            cisa_kev_count
        );
        for v in &vulnerabilities {
            let score_str = v
                .cvss_v31_score
                .map(|s| format!("{s:.1}"))
                .unwrap_or_else(|| "N/A".to_string());
            let sev_str = v.cvss_v31_severity.as_deref().unwrap_or("UNKNOWN");
            if v.is_cisa_kev {
                println!("  [CISA KEV] {} | CVSS v3.1: {} ({})", v.cve_id, score_str, sev_str);
                if let Some(ref action) = v.cisa_required_action {
                    println!("    Required Action: {action}");
                }
            } else {
                println!("  {} | CVSS v3.1: {} ({})", v.cve_id, score_str, sev_str);
            }
            if !v.description.is_empty() {
                println!("    Description: {}", v.description);
            }
        }
    }

    if let Some(exec_result) = patch_result {
        println!("  Target Subsystem: {}", exec_result.os_subsystem);
        println!(
            "  Mode:             {}",
            if exec_result.dry_run {
                "Dry-Run Simulation"
            } else {
                "Live Execution"
            }
        );
        println!(
            "  Command:          {} {}",
            exec_result.command,
            exec_result.args.join(" ")
        );
        println!("  Success:          {}", exec_result.success);
        println!("  Output:           {}", exec_result.output);
    } else {
        println!("Tip: Pass --dry-run to preview the OS-native patch command, or --apply with elevated privileges to execute.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cpe::*;
    use super::discovery::*;
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        request_line: String,
        headers_lower: String,
    }

    struct MockNvdServer {
        endpoint_url: String,
        recorded: Arc<Mutex<Vec<RecordedRequest>>>,
        handle: JoinHandle<()>,
    }

    impl MockNvdServer {
        async fn start(body: &'static str) -> Self {
            Self::start_with_status(200, body).await
        }

        async fn start_with_status(status_code: u16, body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral 127.0.0.1 listener");
            let addr = listener.local_addr().expect("local_addr");
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let recorded_clone = Arc::clone(&recorded);

            let reason = match status_code {
                200 => "OK",
                429 => "Too Many Requests",
                500 => "Internal Server Error",
                _ => "Status",
            };

            let handle = tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let rec = Arc::clone(&recorded_clone);
                    let body_bytes = body.as_bytes();
                    let header = format!(
                        "HTTP/1.1 {status_code} {reason}\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        body_bytes.len()
                    );

                    tokio::spawn(async move {
                        let mut buf = [0u8; 4096];
                        if let Ok(n) = socket.read(&mut buf).await {
                            let req_str = String::from_utf8_lossy(&buf[..n]);
                            let request_line = req_str.lines().next().unwrap_or("").to_string();
                            let headers_lower = req_str.to_ascii_lowercase();
                            if let Ok(mut guard) = rec.lock() {
                                guard.push(RecordedRequest {
                                    request_line,
                                    headers_lower,
                                });
                            }
                        }
                        let _ = socket.write_all(header.as_bytes()).await;
                        let _ = socket.write_all(body_bytes).await;
                    });
                }
            });

            Self {
                endpoint_url: format!("http://127.0.0.1:{}/rest/json/cves/2.0", addr.port()),
                recorded,
                handle,
            }
        }
    }

    impl Drop for MockNvdServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    const FIXTURE_MULTI_CVE_JSON: &str = r#"{
        "resultsPerPage": 4,
        "totalResults": 4,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": "Critical non-KEV flaw"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                        }]
                    }
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-1086",
                    "cisaExploitAdd": "2024-03-25",
                    "cisaActionDue": "2024-04-15",
                    "cisaRequiredAction": "Apply updates per vendor instructions.",
                    "cisaVulnerabilityName": "Linux Kernel netfilter Use-After-Free",
                    "descriptions": [
                        {"lang": "es", "value": "Descripcion en espanol"},
                        {"lang": "en", "value": "Linux kernel netfilter nf_tables privilege escalation"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 7.8, "baseSeverity": "HIGH"}
                        }]
                    }
                }
            },
            {
                "cve": {
                    "id": "CVE-2023-4567",
                    "cisaExploitAdd": "2023-11-01",
                    "descriptions": [{"lang": "en", "value": "Medium severity KEV flaw"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 5.5, "baseSeverity": "MEDIUM"}
                        }]
                    }
                }
            },
            {
                "cve": {
                    "id": "CVE-2022-1234",
                    "descriptions": [{"lang": "en", "value": "Low severity non-KEV flaw"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 3.3, "baseSeverity": "LOW"}
                        }]
                    }
                }
            }
        ]
    }"#;

    fn assert_valid_cpe23(cpe: &str) {
        assert!(
            cpe.starts_with("cpe:2.3:o:"),
            "CPE 2.3 must start with cpe:2.3:o:: got '{cpe}'"
        );
        let parts = split_unescaped_colons(cpe);
        assert_eq!(
            parts.len(),
            13,
            "CPE 2.3 formatted string must have 13 components, got {} in '{cpe}'",
            parts.len()
        );
    }

    #[test]
    fn test_cpe23_escaping_and_canonicalization() {
        assert_eq!(
            escape_cpe_attribute("Windows 11:Pro*Edition?"),
            r"windows_11\:pro\*edition\?"
        );
        assert_eq!(escape_cpe_attribute(""), "*");
        assert_eq!(escape_cpe_attribute("   "), "*");
        assert_eq!(escape_cpe_attribute("-"), "-");

        assert_eq!(canonicalize_linux_kernel_version("6.8.0-49-generic"), "6.8.0");
        assert_eq!(canonicalize_linux_kernel_version("5.15.167.4-microsoft-standard-WSL2"), "5.15.167");

        assert_eq!(
            canonicalize_windows_cpe(22631, false, Some("23H2")),
            ("windows_11", "23h2".to_string())
        );
        assert_eq!(
            canonicalize_windows_cpe(19045, false, Some("22H2")),
            ("windows_10", "22h2".to_string())
        );
        assert_eq!(
            canonicalize_windows_cpe(20348, true, None),
            ("windows_server_2022", "*".to_string())
        );
        assert_eq!(
            canonicalize_windows_cpe(26100, true, None),
            ("windows_server_2025", "*".to_string())
        );

        assert_eq!(canonicalize_macos_version("14.4.1 (a)"), "14.4.1");

        let cpe = Cpe23::new_os("microsoft", "windows_11", "24h2").to_formatted_string();
        assert_eq!(cpe, "cpe:2.3:o:microsoft:windows_11:24h2:*:*:*:*:*:*:*");
        assert_valid_cpe23(&cpe);
    }

    #[test]
    fn test_cross_platform_discovery_parsers() {
        let os_release = r#"
ID=ubuntu
VERSION_ID="24.04"
PRETTY_NAME="Ubuntu 24.04 LTS"
"#;
        let linux_info = parse_linux_kernel_info("6.8.0-49-generic", Some(os_release), "x86_64");
        assert_eq!(linux_info.os_family, OsFamily::Linux);
        assert_eq!(
            linux_info.cpe23,
            "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*"
        );
        assert_valid_cpe23(&linux_info.cpe23);

        let win_info = parse_windows_kernel_info(
            10,
            0,
            22631,
            Some(3880),
            Some("Windows 11 Enterprise"),
            Some("23H2"),
            "x86_64",
        );
        assert_eq!(win_info.os_family, OsFamily::Windows);
        assert_eq!(win_info.kernel_release, "10.0.22631.3880");
        assert_eq!(
            win_info.cpe23,
            "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*"
        );
        assert_valid_cpe23(&win_info.cpe23);

        let mac_info = parse_macos_kernel_info(Some("14.4.1"), "23.4.0", "aarch64");
        assert_eq!(mac_info.os_family, OsFamily::MacOS);
        assert_eq!(
            mac_info.cpe23,
            "cpe:2.3:o:apple:macos:14.4.1:*:*:*:*:*:*:*"
        );
        assert_valid_cpe23(&mac_info.cpe23);
    }

    #[test]
    fn test_host_kernel_detection_on_current_os() {
        let info = HostKernelInfo::detect_host_kernel().expect("host kernel detection must succeed");
        assert!(!info.kernel_release.is_empty());
        assert!(!info.architecture.is_empty());
        assert_valid_cpe23(&info.cpe23);
    }

    #[test]
    fn test_privilege_is_elevated_consistent_and_thread_safe() {
        let baseline = is_elevated();
        let handles: Vec<_> = (0..8).map(|_| std::thread::spawn(is_elevated)).collect();
        for h in handles {
            assert_eq!(h.join().expect("thread join"), baseline);
        }
    }

    #[tokio::test]
    async fn test_offline_nvd_kev_ranking_and_header_key() {
        let server = MockNvdServer::start(FIXTURE_MULTI_CVE_JSON).await;
        let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

        let opts = ScanOptions {
            cpe: Some("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string()),
            min_cvss_score: None,
            kev_only: false,
            api_key: Some("  unit_test_mock_header_token  ".to_string()),
            timeout_secs: 5,
        };

        let vulns = patcher
            .scan_kernel_vulnerabilities(&opts)
            .await
            .expect("NVD mock scan must succeed");

        assert_eq!(vulns.len(), 4);
        // CISA KEV entries rank strictly before non-KEV even when non-KEV has higher CVSS (9.8).
        assert_eq!(vulns[0].cve_id, "CVE-2024-1086");
        assert!(vulns[0].is_cisa_kev);
        assert_eq!(vulns[0].cvss_v31_score, Some(7.8));
        assert_eq!(
            vulns[0].description,
            "Linux kernel netfilter nf_tables privilege escalation"
        );
        assert_eq!(vulns[1].cve_id, "CVE-2023-4567");
        assert!(vulns[1].is_cisa_kev);
        assert_eq!(vulns[2].cve_id, "CVE-2024-9999");
        assert!(!vulns[2].is_cisa_kev);
        assert_eq!(vulns[3].cve_id, "CVE-2022-1234");
        assert!(!vulns[3].is_cisa_kev);

        let captured = server.recorded.lock().expect("lock recorded").clone();
        assert_eq!(captured.len(), 1);
        assert!(
            captured[0]
                .request_line
                .contains("cpeName=cpe:2.3:o:linux:linux_kernel:6.8.0"),
            "unexpected request line: {}",
            captured[0].request_line
        );
        assert!(
            captured[0]
                .headers_lower
                .contains("apikey: unit_test_mock_header_token"),
            "trimmed apiKey header missing in request: {}",
            captured[0].headers_lower
        );
    }

    #[tokio::test]
    async fn test_offline_nvd_filters_and_errors() {
        let server = MockNvdServer::start(FIXTURE_MULTI_CVE_JSON).await;
        let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

        // KEV-only filter
        let kev_only_opts = ScanOptions {
            cpe: Some("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string()),
            kev_only: true,
            ..Default::default()
        };
        let kev_vulns = patcher
            .scan_kernel_vulnerabilities(&kev_only_opts)
            .await
            .expect("KEV scan");
        assert_eq!(kev_vulns.len(), 2);
        assert!(kev_vulns.iter().all(|v| v.is_cisa_kev));

        // Min CVSS filter (>= 7.5)
        let cvss_opts = ScanOptions {
            cpe: Some("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string()),
            min_cvss_score: Some(7.5),
            ..Default::default()
        };
        let high_vulns = patcher
            .scan_kernel_vulnerabilities(&cvss_opts)
            .await
            .expect("CVSS scan");
        assert_eq!(high_vulns.len(), 2);
        assert_eq!(high_vulns[0].cve_id, "CVE-2024-1086");
        assert_eq!(high_vulns[1].cve_id, "CVE-2024-9999");

        // HTTP 429 rate limit handling
        let rl_server = MockNvdServer::start_with_status(429, "{}").await;
        let rl_patcher = KernelPatcher::with_base_url(&rl_server.endpoint_url);
        let rl_res = rl_patcher.scan_kernel_vulnerabilities(&kev_only_opts).await;
        assert!(matches!(rl_res, Err(PatcherError::RateLimited)));

        // Malformed JSON fails closed
        let bad_server = MockNvdServer::start("{not_valid_json").await;
        let bad_patcher = KernelPatcher::with_base_url(&bad_server.endpoint_url);
        let bad_res = bad_patcher
            .scan_kernel_vulnerabilities(&kev_only_opts)
            .await;
        assert!(matches!(bad_res, Err(PatcherError::Serialization(_))));
    }

    #[tokio::test]
    async fn test_patch_dry_run_and_non_privileged_fail_closed() {
        let patcher = KernelPatcher::new();
        let dry = patcher
            .apply_os_kernel_patch(true)
            .await
            .expect("dry run must succeed");
        assert!(dry.dry_run);
        assert!(dry.success);
        assert!(!dry.command.is_empty());
        assert!(!dry.args.is_empty());
        assert!(dry.output.contains("[DRY-RUN]"));

        if !is_elevated() {
            let live = patcher.apply_os_kernel_patch(false).await;
            assert!(
                matches!(live, Err(PatcherError::InsufficientPrivileges)),
                "non-elevated live patch must fail closed, got {live:?}"
            );
        }
    }

    #[test]
    fn test_cli_args_parser_and_api_key_hygiene() {
        let empty = parse_patch_kernel_args(&[]).expect("empty args ok");
        assert!(!empty.dry_run);
        assert!(!empty.apply);
        assert!(!empty.json);

        let full = parse_patch_kernel_args(&[
            "--json".to_string(),
            "--dry-run".to_string(),
            "--kev-only".to_string(),
            "--min-cvss".to_string(),
            "7.5".to_string(),
            "--cpe=cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string(),
            "--timeout-secs".to_string(),
            "15".to_string(),
        ])
        .expect("valid flags ok");
        assert!(full.json);
        assert!(full.dry_run);
        assert!(full.kev_only);
        assert_eq!(full.min_cvss, Some(7.5));
        assert_eq!(
            full.cpe.as_deref(),
            Some("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*")
        );
        assert_eq!(full.timeout_secs, 15);

        // Must reject CLI --api-key / --nvd-api-key flags
        for forbidden in [
            vec!["--api-key".to_string(), "val".to_string()],
            vec!["--api-key=val".to_string()],
            vec!["--nvd-api-key".to_string(), "val".to_string()],
            vec!["--nvd-api-key=val".to_string()],
        ] {
            let err = parse_patch_kernel_args(&forbidden)
                .expect_err("passing NVD API key on CLI must be rejected");
            assert!(err.contains("NVD_API_KEY"));
        }

        // Empty / whitespace keys normalize to None
        assert_eq!(resolve_nvd_api_key(Some("   ")), None);
        assert_eq!(
            resolve_nvd_api_key(Some("  trimmed  ")).as_deref(),
            Some("trimmed")
        );
    }
}
