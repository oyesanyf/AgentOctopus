use agent_octopus::security::cedar_arm::CedarPolicyEngine;
use agent_octopus::security::executable_identity::ExecutableIdentityVerifier;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "octopus_e2e_{}_{}_{}",
            prefix,
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn octopus_bin() -> &'static str {
    env!("CARGO_BIN_EXE_octopus")
}

fn find_python() -> String {
    for candidate in if cfg!(windows) {
        &["python", "python3"][..]
    } else {
        &["python3", "python"][..]
    } {
        if let Ok(out) = Command::new(candidate).arg("--version").output() {
            if out.status.success() {
                return candidate.to_string();
            }
        }
    }
    panic!("Python 3 interpreter not found on PATH for CLI E2E tests");
}

struct MockHttpServer {
    addr: String,
    hits: Arc<AtomicUsize>,
    last_auth: Arc<std::sync::Mutex<Option<String>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        listener.set_nonblocking(true).expect("set_nonblocking");
        let addr = listener.local_addr().unwrap().to_string();
        let hits = Arc::new(AtomicUsize::new(0));
        let last_auth = Arc::new(std::sync::Mutex::new(None));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let hits_c = hits.clone();
        let auth_c = last_auth.clone();
        let stop_c = stop.clone();

        let handle = thread::spawn(move || {
            while !stop_c.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = [0u8; 4096];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]).to_string();
                        hits_c.fetch_add(1, Ordering::SeqCst);
                        for line in req.lines() {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("authorization") {
                                    if let Ok(mut g) = auth_c.lock() {
                                        *g = Some(v.trim().to_string());
                                    }
                                }
                            }
                        }
                        let body = r#"{"ok":true}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            hits,
            last_auth,
            stop,
            handle: Some(handle),
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn last_authorization(&self) -> Option<String> {
        self.last_auth.lock().ok().and_then(|g| g.clone())
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn test_octopus_help_and_run_help() {
    for args in [&["--help"][..], &["-h"][..], &[][..]] {
        let out = Command::new(octopus_bin())
            .args(args)
            .output()
            .expect("run octopus help");
        assert!(out.status.success(), "help failed: {:?}", out);
        let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        assert!(stdout.contains("run"), "missing 'run' in help: {}", stdout);
        assert!(
            !stdout.contains("9-scenario"),
            "help must not run demo: {}",
            stdout
        );
    }

    let run_help = Command::new(octopus_bin())
        .args(["run", "--help"])
        .output()
        .expect("run octopus run --help");
    assert!(run_help.status.success());
    let text = String::from_utf8_lossy(&run_help.stdout).to_ascii_lowercase();
    for flag in ["--policy", "--sandbox", "--timeout", "--cwd", "--json"] {
        assert!(text.contains(flag), "missing {} in run --help", flag);
    }
}

#[test]
fn test_octopus_fail_closed_cli_inputs() {
    let ws = TempDirGuard::new("fail_closed");
    let bad_json = ws.path().join("bad.json");
    std::fs::write(&bad_json, "{not-json").unwrap();
    let wildcard_json = ws.path().join("wildcard.json");
    std::fs::write(&wildcard_json, r#"{"allowed_domains":["*"]}"#).unwrap();
    let bad_cedar = ws.path().join("bad.cedar");
    std::fs::write(&bad_cedar, "permit (").unwrap();
    let missing_policy = ws.path().join("does_not_exist.json");
    let py = find_python();

    let bad_cases: Vec<Vec<String>> = vec![
        vec![
            "run".into(),
            "--".into(),
            py.clone(),
            "-c".into(),
            "print(1)".into(),
        ],
        vec![
            "run".into(),
            "--policy".into(),
            missing_policy.display().to_string(),
            "--".into(),
            py.clone(),
            "-c".into(),
            "print(1)".into(),
        ],
        vec![
            "run".into(),
            "--policy".into(),
            bad_json.display().to_string(),
            "--".into(),
            py.clone(),
            "-c".into(),
            "print(1)".into(),
        ],
        vec![
            "run".into(),
            "--policy".into(),
            wildcard_json.display().to_string(),
            "--".into(),
            py.clone(),
            "-c".into(),
            "print(1)".into(),
        ],
        vec![
            "run".into(),
            "--policy".into(),
            bad_cedar.display().to_string(),
            "--".into(),
            py.clone(),
            "-c".into(),
            "print(1)".into(),
        ],
        vec![
            "run".into(),
            "--policy".into(),
            bad_json.display().to_string(),
            py.clone(),
        ],
        vec![
            "run".into(),
            "--policy".into(),
            bad_json.display().to_string(),
            "--".into(),
        ],
        vec![
            "run".into(),
            "--policy".into(),
            wildcard_json.display().to_string(),
            "--sandbox".into(),
            "bogus".into(),
            "--".into(),
            py,
            "-c".into(),
            "print(1)".into(),
        ],
    ];

    for case in bad_cases {
        let out = Command::new(octopus_bin())
            .args(&case)
            .output()
            .expect("invoke octopus");
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 for {:?}, got {:?}, stderr={}",
            case,
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn test_octopus_run_egress_allow_deny_and_imds_block() {
    let ws = TempDirGuard::new("egress");
    let allowed_srv = MockHttpServer::start();
    let denied_srv = MockHttpServer::start();
    let py = find_python();

    let policy_path = ws.path().join("policy.json");
    let policy_json = serde_json::json!({
        "allowed_domains": [allowed_srv.addr],
        "denied_domains": [denied_srv.addr],
        "denied_resolved_addresses": ["169.254.169.254/32"],
        "commands": {"allow": ["python", "python3"]},
        "filesystem": {"allow_read": [ws.path()], "allow_write": [ws.path()], "deny": []}
    });
    std::fs::write(&policy_path, policy_json.to_string()).unwrap();

    let probe_py = ws.path().join("probe.py");
    std::fs::write(
        &probe_py,
        format!(
            r#"import os, sys, urllib.error, urllib.request
proxy = os.environ["HTTP_PROXY"]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({{"http": proxy, "https": proxy}}))
with opener.open("http://{allowed}/ok", timeout=5) as r:
    assert r.status == 200
for url in ("http://{denied}/exfil", "http://169.254.169.254/latest/meta-data/"):
    try:
        opener.open(url, timeout=5)
        sys.exit(1)
    except urllib.error.HTTPError as e:
        assert e.code == 403, f"expected 403, got {{e.code}}"
        assert "blocked_by_octopus_policy" in e.read().decode()
print("EGRESS_E2E_OK")
"#,
            allowed = allowed_srv.addr,
            denied = denied_srv.addr,
        ),
    )
    .unwrap();

    let out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            &policy_path.display().to_string(),
            "--cwd",
            &ws.path().display().to_string(),
            "--",
            &py,
            &probe_py.display().to_string(),
        ])
        .output()
        .expect("run egress probe");
    assert!(
        out.status.success(),
        "egress probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("EGRESS_E2E_OK"));
    assert_eq!(allowed_srv.hits(), 1);
    assert_eq!(denied_srv.hits(), 0);

    // Tier 2 executable identity invariant must remain untouched
    assert!(ExecutableIdentityVerifier::default()
        .verify_and_lock("python", None)
        .is_err());
}

#[test]
fn test_octopus_run_preflight_forbidden_shell_and_sensitive_path() {
    let ws = TempDirGuard::new("preflight");
    let py = find_python();
    let policy_path = ws.path().join("policy.json");
    std::fs::write(
        &policy_path,
        r#"{"allowed_domains":[],"commands":{"allow":["python","python3"],"deny":["bash","sh","powershell","pwsh","cmd"]}}"#,
    )
    .unwrap();

    let shell_cmd = if cfg!(windows) {
        vec!["cmd", "/c", "echo FORBIDDEN_SHELL_RAN"]
    } else {
        vec!["sh", "-c", "echo FORBIDDEN_SHELL_RAN"]
    };
    let mut args = vec!["run", "--policy", policy_path.to_str().unwrap(), "--"];
    args.extend(shell_cmd);
    let out_shell = Command::new(octopus_bin()).args(&args).output().unwrap();
    assert_eq!(out_shell.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out_shell.stdout).contains("FORBIDDEN_SHELL_RAN"));

    let out_smuggle = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            &py,
            "-c",
            "print('SMUGGLED')",
            ";",
            "bash",
            "-c",
            "id",
        ])
        .output()
        .unwrap();
    assert_eq!(out_smuggle.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out_smuggle.stdout).contains("SMUGGLED"));

    let out_cred = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import pathlib; print(pathlib.Path('~/.aws/credentials').expanduser().read_text())",
        ])
        .output()
        .unwrap();
    assert_eq!(out_cred.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out_cred.stderr).contains("FileNotFoundError"));
}

#[test]
fn test_octopus_run_credential_masking_cwd_timeout_and_json() {
    let ws = TempDirGuard::new("creds_timeout_json");
    let sub = ws.path().join("sub_cwd");
    std::fs::create_dir_all(&sub).unwrap();
    let py = find_python();
    let srv = MockHttpServer::start();
    let secret = "sk-e2e-sentinel-mask-value-9876";

    let policy_path = ws.path().join("policy.json");
    std::fs::write(
        &policy_path,
        serde_json::json!({
            "allowed_domains": [srv.addr],
            "commands": {"allow": ["python", "python3"]},
            "credentials": {
                "mask_env": ["OPENAI_API_KEY"],
                "inject_hosts": [srv.addr],
                "allow_plaintext_inject": true
            }
        })
        .to_string(),
    )
    .unwrap();

    let script = ws.path().join("cred_check.py");
    std::fs::write(
        &script,
        format!(
            r#"import os, pathlib, urllib.request
val = os.environ["OPENAI_API_KEY"]
assert val.startswith("ao_mask_")
assert {secret:?} not in val
proxy = os.environ["HTTP_PROXY"]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({{"http": proxy}}))
req = urllib.request.Request("http://{addr}/auth", headers={{"Authorization": f"Bearer {{val}}"}})
with opener.open(req, timeout=5) as r:
    assert r.status == 200
print("CWD=" + os.path.realpath(os.getcwd()))
"#,
            secret = secret,
            addr = srv.addr
        ),
    )
    .unwrap();

    let out = Command::new(octopus_bin())
        .env("OPENAI_API_KEY", secret)
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            sub.to_str().unwrap(),
            "--json",
            "--",
            &py,
            script.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cred_check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(secret) && !stderr.contains(secret));
    assert_eq!(
        srv.last_authorization().as_deref(),
        Some("Bearer sk-e2e-sentinel-mask-value-9876")
    );
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid --json output");
    assert_eq!(parsed["exit_code"], 0);
    assert!(parsed["stdout"].as_str().unwrap_or("").contains("CWD="));

    // Timeout enforcement
    let t0 = Instant::now();
    let out_timeout = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--timeout",
            "1",
            "--",
            &py,
            "-c",
            "import time; time.sleep(20)",
        ])
        .output()
        .unwrap();
    assert!(!out_timeout.status.success());
    assert!(t0.elapsed() < Duration::from_secs(10));
}

#[test]
fn test_octopus_run_cedar_and_wasm_tier1() {
    let ws = TempDirGuard::new("cedar_wasm");
    let py = find_python();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cedar_path = repo_root
        .join("examples")
        .join("quickstart")
        .join("policy.cedar");
    let cedar_txt = std::fs::read_to_string(&cedar_path).expect("read quickstart policy.cedar");
    assert!(CedarPolicyEngine::from_validated_policy_set(&cedar_txt).is_ok());

    let ok_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            cedar_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "print('CEDAR_OK')",
        ])
        .output()
        .unwrap();
    assert!(ok_out.status.success());
    assert!(String::from_utf8_lossy(&ok_out.stdout).contains("CEDAR_OK"));

    let wat_policy = ws.path().join("wasm_policy.json");
    std::fs::write(&wat_policy, r#"{"allowed_domains":[]}"#).unwrap();

    let ok_wat = ws.path().join("ok.wat");
    std::fs::write(&ok_wat, r#"(module (func (export "_start")))"#).unwrap();
    let wat_res = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            wat_policy.to_str().unwrap(),
            "--",
            ok_wat.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(wat_res.status.success());

    let spin_wat = ws.path().join("spin.wat");
    std::fs::write(
        &spin_wat,
        r#"(module (func (export "_start") (loop $spin (br $spin))))"#,
    )
    .unwrap();
    let t0 = Instant::now();
    let spin_res = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            wat_policy.to_str().unwrap(),
            "--timeout",
            "2",
            "--",
            spin_wat.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!spin_res.status.success());
    assert!(t0.elapsed() < Duration::from_secs(10));
}

#[test]
fn test_octopus_run_quickstart_script() {
    let py = find_python();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let policy_path = repo_root
        .join("examples")
        .join("quickstart")
        .join("policy.json");
    let agent_path = repo_root
        .join("examples")
        .join("quickstart")
        .join("my_agent.py");

    let out = Command::new(octopus_bin())
        .current_dir(&repo_root)
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--",
            &py,
            agent_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "quickstart failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
    .to_ascii_lowercase();
    assert!(combined.contains("allow") && combined.contains("ok"));
    assert!(combined.contains("block") && combined.contains("403"));
}

#[test]
fn test_octopus_run_d3qn_default_off_invariance() {
    let ws = TempDirGuard::new("d3qn_off");
    let py = find_python();
    let policy_path = ws.path().join("policy.json");
    std::fs::write(
        &policy_path,
        r#"{"allowed_domains":[],"commands":{"allow":["python","python3"]}}"#,
    )
    .unwrap();

    for rl_opt in [None, Some("1")] {
        let mut cmd = Command::new(octopus_bin());
        cmd.args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "print('D3QN_INVARIANT')",
        ]);
        if let Some(v) = rl_opt {
            cmd.env("OCTOPUS_ENABLE_RL_ADVISORY", v);
        } else {
            cmd.env_remove("OCTOPUS_ENABLE_RL_ADVISORY");
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("D3QN_INVARIANT"));
    }

    assert!(!ws
        .path()
        .join("config")
        .join("rl_defense_policy.json")
        .exists());
    assert!(!ws.path().join("logs").exists());
}

#[test]
fn test_wasm_open_stdin_pipe_and_timeout_exit_124() {
    let ws = TempDirGuard::new("wasm_stdin_timeout");
    let wat_policy = ws.path().join("wasm_policy.json");
    std::fs::write(
        &wat_policy,
        r#"{"allowed_domains":[],"limits":{"wasm_fuel":1000000000000}}"#,
    )
    .unwrap();

    // (a1) Benign .wat without stdin imports completes promptly with open stdin pipe
    let ok_wat = ws.path().join("benign.wat");
    std::fs::write(&ok_wat, r#"(module (func (export "_start") nop))"#).unwrap();
    let t0 = Instant::now();
    let mut child = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            wat_policy.to_str().unwrap(),
            "--timeout",
            "2",
            "--",
            ok_wat.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn octopus wasm");
    let _kept_stdin_open = child.stdin.take();
    let out = child.wait_with_output().expect("wait wasm");
    drop(_kept_stdin_open);
    assert!(
        out.status.success(),
        "benign.wat with open stdin pipe failed: code={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        t0.elapsed() < Duration::from_secs(3),
        "benign.wat took {:?}, expected <3s",
        t0.elapsed()
    );

    // (a2) Infinite loop .wat with huge fuel trips KillSwitch on --timeout 1 -> exit 124
    let spin_wat = ws.path().join("spin.wat");
    std::fs::write(
        &spin_wat,
        r#"(module (func (export "_start") (loop $spin (br $spin))))"#,
    )
    .unwrap();
    let spin_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            wat_policy.to_str().unwrap(),
            "--timeout",
            "1",
            "--",
            spin_wat.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run spin.wat");
    assert_eq!(
        spin_out.status.code(),
        Some(124),
        "expected exit 124 on Wasm KillSwitch timeout, got {:?} stderr={}",
        spin_out.status.code(),
        String::from_utf8_lossy(&spin_out.stderr)
    );

    // (a3) Guest importing octopus_wasi::input_len with stalled stdin pipe respects --timeout 1 -> exit 124
    let stdin_wat = ws.path().join("needs_stdin.wat");
    std::fs::write(
        &stdin_wat,
        r#"(module
            (import "octopus_wasi" "input_len" (func $input_len (result i32)))
            (func (export "_start") (drop (call $input_len)))
        )"#,
    )
    .unwrap();
    let t1 = Instant::now();
    let mut stdin_child = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            wat_policy.to_str().unwrap(),
            "--timeout",
            "1",
            "--",
            stdin_wat.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stdin_wat");
    let _open_pipe = stdin_child.stdin.take();
    let stdin_out = stdin_child.wait_with_output().expect("wait stdin_wat");
    drop(_open_pipe);
    assert_eq!(
        stdin_out.status.code(),
        Some(124),
        "expected exit 124 on stalled stdin pipe, got {:?} stderr={}",
        stdin_out.status.code(),
        String::from_utf8_lossy(&stdin_out.stderr)
    );
    assert!(t1.elapsed() < Duration::from_secs(5));
}

#[test]
fn test_proxy_localhost_ipv4_fallback_non_standard_ip_and_duplicate_host() {
    let ws = TempDirGuard::new("proxy_hardening");
    let py = find_python();
    let srv = MockHttpServer::start();
    let port: u16 = srv
        .addr
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .expect("mock port");

    // (b) localhost:<port> allowlist reaches IPv4 127.0.0.1 listener
    let lh_policy = ws.path().join("localhost_policy.json");
    std::fs::write(
        &lh_policy,
        serde_json::json!({
            "allowed_domains": [format!("localhost:{}", port)],
            "commands": {"allow": ["python", "python3"]}
        })
        .to_string(),
    )
    .unwrap();
    let lh_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            lh_policy.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            &format!(
                "import os, urllib.request; op = urllib.request.build_opener(urllib.request.ProxyHandler({{'http': os.environ['HTTP_PROXY']}})); r = op.open('http://localhost:{}/lh_ok', timeout=15); assert r.status == 200; print('LOCALHOST_OK')",
                port
            ),
        ])
        .output()
        .expect("run localhost test");
    assert!(
        lh_out.status.success(),
        "localhost:<port> failed against 127.0.0.1 listener: stdout={} stderr={}",
        String::from_utf8_lossy(&lh_out.stdout),
        String::from_utf8_lossy(&lh_out.stderr)
    );
    assert!(String::from_utf8_lossy(&lh_out.stdout).contains("LOCALHOST_OK"));
    assert_eq!(srv.hits(), 1);

    // (c) Pre-canonicalization non-standard IP encodings and duplicate Host headers rejected
    let ip_policy = ws.path().join("ip_policy.json");
    std::fs::write(
        &ip_policy,
        serde_json::json!({
            "allowed_domains": [srv.addr],
            "commands": {"allow": ["python", "python3"]}
        })
        .to_string(),
    )
    .unwrap();
    let probe_py = ws.path().join("raw_proxy_probe.py");
    std::fs::write(
        &probe_py,
        format!(
            r#"import os, socket, urllib.parse

p = urllib.parse.urlparse(os.environ["HTTP_PROXY"])
host, port = p.hostname, p.port

def send_raw(req_bytes):
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(req_bytes)
        chunks = []
        while True:
            d = s.recv(4096)
            if not d:
                break
            chunks.append(d)
    return b"".join(chunks).decode("utf-8", errors="replace")

for bad_host in (
    f"0x7f000001:{tport}",
    f"2130706433:{tport}",
    f"0177.0.0.1:{tport}",
    f"127.1:{tport}",
):
    resp = send_raw(
        f"GET http://{{bad_host}}/ HTTP/1.1\r\nHost: {{bad_host}}\r\nConnection: close\r\n\r\n".encode()
    )
    assert "403 Forbidden" in resp and "non_standard_ip_encoding_blocked" in resp, f"failed for {{bad_host}}: {{resp}}"

resp_origin = send_raw(
    f"GET /origin_hex HTTP/1.1\r\nHost: 0x7f000001:{tport}\r\nConnection: close\r\n\r\n".encode()
)
assert "403 Forbidden" in resp_origin and "non_standard_ip_encoding_blocked" in resp_origin, resp_origin

resp_dup = send_raw(
    f"GET http://127.0.0.1:{tport}/dup HTTP/1.1\r\nHost: 127.0.0.1:{tport}\r\nHost: 169.254.169.254\r\nConnection: close\r\n\r\n".encode()
)
assert "400 Bad Request" in resp_dup and "duplicate_host_header_rejected" in resp_dup, resp_dup
print("PROXY_BYPASS_BLOCKED_OK")
"#,
            tport = port
        ),
    )
    .unwrap();
    let probe_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            ip_policy.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            probe_py.to_str().unwrap(),
        ])
        .output()
        .expect("run raw proxy probe");
    assert!(
        probe_out.status.success(),
        "raw proxy probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&probe_out.stdout),
        String::from_utf8_lossy(&probe_out.stderr)
    );
    assert!(String::from_utf8_lossy(&probe_out.stdout).contains("PROXY_BYPASS_BLOCKED_OK"));
    // Mock server should still only have the 1 legitimate hit from localhost test
    assert_eq!(srv.hits(), 1);
}

#[test]
fn test_python_isolation_flags_subprocess_bypass_ads_and_cwd_json() {
    let ws = TempDirGuard::new("py_guard_ads_cwd");
    let outside = TempDirGuard::new("py_guard_outside");
    let py = find_python();
    let policy_path = ws.path().join("policy.json");
    std::fs::write(
        &policy_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {"allow": ["python", "python3"], "deny": ["cmd", "bash", "sh"], "max_child_processes": 4},
            "filesystem": {"allow_read": [ws.path()], "allow_write": [ws.path()], "deny": []}
        })
        .to_string(),
    )
    .unwrap();

    // (d1) Direct Python -I / -E / -S / --isolated / combined short-flag clusters rejected pre-flight (exit 2)
    for bad_flag in ["-I", "-E", "-S", "--isolated", "-Es", "-uI", "-IS"] {
        let out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_path.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                bad_flag,
                "-c",
                "print('SHOULD_NOT_RUN')",
            ])
            .output()
            .expect("run bad python flag");
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 for Python flag {}, got {:?} stdout={} stderr={}",
            bad_flag,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!String::from_utf8_lossy(&out.stdout).contains("SHOULD_NOT_RUN"));
    }

    // (d2) Subprocess spawning [sys.executable, '-I', ...] or stripping PYTHONPATH blocked by audit hook
    std::fs::create_dir_all(ws.path().join(".git").join("hooks")).unwrap();
    let outside_file = outside.path().join("sub_escaped.txt");
    let sub_bypass_py = ws.path().join("sub_bypass.py");
    let inner_code = format!(
        "open('.git/hooks/pre-commit','w').write('pwn'); open({:?},'w').write('escaped')",
        outside_file.to_string_lossy().to_string()
    );
    std::fs::write(
        &sub_bypass_py,
        format!(
            "import subprocess, sys\nsubprocess.check_call([sys.executable, \"-I\", \"-c\", {inner:?}])\n",
            inner = inner_code
        ),
    )
    .unwrap();
    let sub_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            sub_bypass_py.to_str().unwrap(),
        ])
        .output()
        .expect("run subprocess -I probe");
    assert!(!sub_out.status.success(), "subprocess -I must be blocked");
    assert!(
        String::from_utf8_lossy(&sub_out.stderr).contains("blocked_by_octopus_policy"),
        "expected blocked_by_octopus_policy diagnostic, stderr={}",
        String::from_utf8_lossy(&sub_out.stderr)
    );
    assert!(!ws
        .path()
        .join(".git")
        .join("hooks")
        .join("pre-commit")
        .exists());
    assert!(!outside_file.exists());

    let env_strip_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import subprocess, sys; subprocess.check_call([sys.executable, '-c', 'pass'], env={})",
        ])
        .output()
        .expect("run env strip probe");
    assert!(
        !env_strip_out.status.success(),
        "subprocess env={{}} stripping PYTHONPATH must be blocked"
    );

    // (d3) NTFS Alternate Data Stream (.mcp.json:stream) blocked on Windows
    if cfg!(windows) {
        let ads_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_path.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                "-c",
                "open('.mcp.json:stream', 'w').write('pwn')",
            ])
            .output()
            .expect("run ADS probe");
        assert!(
            !ads_out.status.success(),
            "ADS write to .mcp.json:stream must be blocked"
        );
        assert!(
            !ws.path().join(".mcp.json").exists(),
            ".mcp.json must not be created via ADS"
        );
    }

    // (d4) --cwd nonexistent with --json emits JsonRunSummary on stdout and exits 2
    let bad_cwd = ws.path().join("does_not_exist_dir");
    let cwd_json_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            bad_cwd.to_str().unwrap(),
            "--json",
            "--",
            &py,
            "-c",
            "print(1)",
        ])
        .output()
        .expect("run bad cwd json");
    assert_eq!(cwd_json_out.status.code(), Some(2));
    let parsed: serde_json::Value =
        serde_json::from_slice(&cwd_json_out.stdout).expect("valid JSON summary for --cwd error");
    assert_eq!(parsed["status"], "denied_preflight");
    assert_eq!(parsed["exit_code"], 2);
}

#[test]
fn test_python_subprocess_winapi_createprocess_and_putenv_containment() {
    let ws = TempDirGuard::new("py_winapi_putenv");
    let outside = TempDirGuard::new("py_winapi_outside");
    let py = find_python();

    let policy_allow_py = ws.path().join("policy_allow_py.json");
    std::fs::write(
        &policy_allow_py,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {
                "allow": ["python", "python3"],
                "deny": ["cmd", "bash", "sh", "powershell", "pwsh"],
                "max_child_processes": 4
            },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": []
            }
        })
        .to_string(),
    )
    .unwrap();

    let policy_fs_only = ws.path().join("policy_fs_only.json");
    std::fs::write(
        &policy_fs_only,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {"allow": [], "deny": [], "max_child_processes": 4},
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": []
            }
        })
        .to_string(),
    )
    .unwrap();

    // (1) Normal allowed subprocess.check_call succeeds under both commands.allow=["python"] and commands.allow=[] with filesystem.allow_write
    for pol in [&policy_allow_py, &policy_fs_only] {
        let ok_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                "-c",
                "import subprocess, sys; subprocess.check_call([sys.executable, '-c', 'print(\"SUB_OK\")'])",
            ])
            .output()
            .expect("run normal subprocess.check_call");
        assert!(
            ok_out.status.success(),
            "normal subprocess.check_call failed for {:?}: code={:?} stdout={} stderr={}",
            pol,
            ok_out.status.code(),
            String::from_utf8_lossy(&ok_out.stdout),
            String::from_utf8_lossy(&ok_out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&ok_out.stdout).contains("SUB_OK"),
            "expected SUB_OK in stdout, got: {}",
            String::from_utf8_lossy(&ok_out.stdout)
        );
    }

    // (2) Direct _winapi.CreateProcess (-I and lpEnvironment={"PYTHONPATH": ""}) & Popen._execute_child bypass blocked on Windows
    std::fs::create_dir_all(ws.path().join(".git").join("hooks")).unwrap();
    let hook_file = ws.path().join(".git").join("hooks").join("pre-commit");
    let mcp_file = ws.path().join(".mcp.json");
    let outside_file = outside.path().join("winapi_escaped.txt");

    if cfg!(windows) {
        let winapi_iso_py = ws.path().join("winapi_iso.py");
        let inner = format!(
            "import os; open({hook:?},'w').write('pwn'); open({mcp:?},'w').write('pwn'); open({out:?},'w').write('escaped')",
            hook = hook_file.to_string_lossy().to_string(),
            mcp = mcp_file.to_string_lossy().to_string(),
            out = outside_file.to_string_lossy().to_string(),
        );
        std::fs::write(
            &winapi_iso_py,
            format!(
                "import _winapi, sys\ncmd = {cmd:?}\nhp, ht, pid, tid = _winapi.CreateProcess(sys.executable, cmd, None, None, False, 0, None, None, None)\n_winapi.WaitForSingleObject(hp, -1)\n",
                cmd = format!("python -I -c {:?}", inner)
            ),
        )
        .unwrap();
        let winapi_iso_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_allow_py.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                winapi_iso_py.to_str().unwrap(),
            ])
            .output()
            .expect("run _winapi.CreateProcess -I probe");
        assert!(
            !winapi_iso_out.status.success(),
            "direct _winapi.CreateProcess -I must be blocked"
        );
        assert!(
            String::from_utf8_lossy(&winapi_iso_out.stderr).contains("blocked_by_octopus_policy"),
            "stderr={}",
            String::from_utf8_lossy(&winapi_iso_out.stderr)
        );
        assert!(!hook_file.exists(), ".git/hooks/pre-commit must not exist");
        assert!(!mcp_file.exists(), ".mcp.json must not exist");
        assert!(!outside_file.exists(), "outside file must not exist");

        let winapi_env_py = ws.path().join("winapi_env.py");
        std::fs::write(
            &winapi_env_py,
            format!(
                "import _winapi, sys\nhp, ht, pid, tid = _winapi.CreateProcess(sys.executable, {cmd:?}, None, None, False, 0, {{\"PYTHONPATH\": \"\"}}, None, None)\n_winapi.WaitForSingleObject(hp, -1)\n",
                cmd = "python -c \"open('.mcp.json','w').write('pwn')\""
            ),
        )
        .unwrap();
        let winapi_env_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_allow_py.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                winapi_env_py.to_str().unwrap(),
            ])
            .output()
            .expect("run _winapi.CreateProcess lpEnvironment probe");
        assert!(
            !winapi_env_out.status.success(),
            "direct _winapi.CreateProcess lpEnvironment={{\"PYTHONPATH\":\"\"}} must be blocked"
        );
        assert!(
            String::from_utf8_lossy(&winapi_env_out.stderr).contains("blocked_by_octopus_policy"),
            "stderr={}",
            String::from_utf8_lossy(&winapi_env_out.stderr)
        );
        assert!(!mcp_file.exists(), ".mcp.json must not exist");

        // Direct Popen._execute_child skipping Popen.__init__
        let exec_child_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_allow_py.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                "-c",
                "import subprocess, sys; p = subprocess.Popen.__new__(subprocess.Popen); p._execute_child([sys.executable, '-c', 'open(\".mcp.json\",\"w\").write(\"pwn\")'], None, None, True, (), None, None, None, 0, False, -1, -1, -1, -1, -1, -1, False, None, None, None, -1, False, -1)",
            ])
            .output()
            .expect("run direct _execute_child probe");
        assert!(
            !exec_child_out.status.success(),
            "direct _execute_child skipping Popen.__init__ must be blocked"
        );
        assert!(!mcp_file.exists());

        // os.startfile blocked
        let startfile_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_allow_py.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                "-c",
                "import os; os.startfile('cmd.exe')",
            ])
            .output()
            .expect("run os.startfile probe");
        assert!(!startfile_out.status.success());
        assert!(
            String::from_utf8_lossy(&startfile_out.stderr).contains("blocked_by_octopus_policy"),
            "stderr={}",
            String::from_utf8_lossy(&startfile_out.stderr)
        );
    }

    // (3) os.putenv('PYTHONPATH', '') + subprocess.check_call and os.unsetenv('PYTHONPATH') blocked
    let putenv_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_allow_py.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import os, subprocess, sys; os.putenv('PYTHONPATH', ''); subprocess.check_call([sys.executable, '-c', 'open(\".mcp.json\",\"w\").write(\"putenv_pwn\")'])",
        ])
        .output()
        .expect("run os.putenv PYTHONPATH probe");
    assert!(
        !putenv_out.status.success(),
        "os.putenv('PYTHONPATH', '') must be blocked"
    );
    assert!(
        String::from_utf8_lossy(&putenv_out.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&putenv_out.stderr)
    );
    assert!(!mcp_file.exists(), ".mcp.json must not exist after putenv");

    let unsetenv_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_allow_py.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import os, subprocess, sys; os.unsetenv('PYTHONPATH'); subprocess.check_call([sys.executable, '-c', 'open(\".mcp.json\",\"w\").write(\"unsetenv_pwn\")'])",
        ])
        .output()
        .expect("run os.unsetenv PYTHONPATH probe");
    assert!(
        !unsetenv_out.status.success(),
        "os.unsetenv('PYTHONPATH') must be blocked"
    );
    assert!(
        String::from_utf8_lossy(&unsetenv_out.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&unsetenv_out.stderr)
    );
    assert!(
        !mcp_file.exists(),
        ".mcp.json must not exist after unsetenv"
    );

    // PYTHONHOME / PYTHONNOUSERSITE putenv tampering also blocked
    for env_key in ["PYTHONHOME", "PYTHONNOUSERSITE"] {
        let env_tamper_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_allow_py.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                "-c",
                &format!("import os; os.putenv({:?}, '1')", env_key),
            ])
            .output()
            .expect("run PYTHONHOME/PYTHONNOUSERSITE putenv probe");
        assert!(
            !env_tamper_out.status.success(),
            "os.putenv({}) must be blocked",
            env_key
        );
        assert!(
            String::from_utf8_lossy(&env_tamper_out.stderr).contains("blocked_by_octopus_policy")
        );
    }

    // os.rename of protected mandatory write-deny target blocked
    std::fs::write(&hook_file, "safe_placeholder").unwrap();
    let rename_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_allow_py.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import os; os.rename('.git/hooks/pre-commit', 'moved_hook')",
        ])
        .output()
        .expect("run os.rename protected source probe");
    assert!(!rename_out.status.success());
    assert!(hook_file.exists());
    assert!(!ws.path().join("moved_hook").exists());
}

#[test]
fn test_python_subprocess_sys_forgery_evildict_pythonpath_shadow_and_gc_immutability() {
    let ws = TempDirGuard::new("py_adv_remediation");
    let outside = TempDirGuard::new("py_adv_outside");
    let py = find_python();

    let policy_path = ws.path().join("policy.json");
    std::fs::write(
        &policy_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {
                "allow": ["python", "python3"],
                "deny": ["cmd", "bash", "sh", "powershell", "pwsh"],
                "max_child_processes": 4
            },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": []
            }
        })
        .to_string(),
    )
    .unwrap();

    std::fs::create_dir_all(ws.path().join(".git").join("hooks")).unwrap();
    let hook_file = ws.path().join(".git").join("hooks").join("pre-commit");
    std::fs::write(&hook_file, "safe_hook").unwrap();
    let mcp_file = ws.path().join(".mcp.json");
    let outside_file = outside.path().join("escaped.txt");

    // 1. subprocess.sys = FakeSys() bypass blocked
    let fake_sys_py = ws.path().join("fake_sys.py");
    let mcp_write_cmd = format!(
        "open({:?}, 'w').write('pwn')",
        mcp_file.to_string_lossy().to_string()
    );
    std::fs::write(
        &fake_sys_py,
        format!(
            r#"import subprocess, sys
class FakeSys:
    def audit(self, *a):
        return None
subprocess.sys = FakeSys()
subprocess.check_call([sys.executable, "-I", "-c", {cmd:?}])
"#,
            cmd = mcp_write_cmd
        ),
    )
    .unwrap();
    let out1 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            fake_sys_py.to_str().unwrap(),
        ])
        .output()
        .expect("run fake_sys probe");
    assert!(!out1.status.success(), "subprocess.sys swap must fail");
    assert!(
        String::from_utf8_lossy(&out1.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&out1.stderr)
    );
    assert!(!mcp_file.exists());

    // 2. types.FunctionType frame forgery (spawning python -I and cmd.exe) blocked
    let func_forge_py = ws.path().join("func_forge.py");
    let out_write_cmd = format!(
        "open({:?}, 'w').write('forged')",
        outside_file.to_string_lossy().to_string()
    );
    std::fs::write(
        &func_forge_py,
        format!(
            r#"import subprocess, sys, types
class FakeSys:
    def audit(self, *a):
        return None
fake_globals = dict(subprocess.Popen._execute_child.__globals__)
fake_globals["sys"] = FakeSys()
fake_exec = types.FunctionType(subprocess.Popen._execute_child.__code__, fake_globals)
fake_init = types.FunctionType(
    subprocess.Popen.__init__.__code__,
    fake_globals,
    argdefs=subprocess.Popen.__init__.__defaults__,
)
fake_init.__kwdefaults__ = subprocess.Popen.__init__.__kwdefaults__
class ForgedPopen(subprocess.Popen):
    _execute_child = fake_exec
    __init__ = fake_init
ForgedPopen([sys.executable, "-I", "-c", {cmd:?}]).wait()
"#,
            cmd = out_write_cmd
        ),
    )
    .unwrap();
    let out2 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            func_forge_py.to_str().unwrap(),
        ])
        .output()
        .expect("run FunctionType forgery probe");
    assert!(
        !out2.status.success(),
        "types.FunctionType frame forgery must fail"
    );
    assert!(
        String::from_utf8_lossy(&out2.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert!(!outside_file.exists());

    // 3. EvilDict(dict) env TOCTOU blocked
    let evil_dict_py = ws.path().join("evil_dict.py");
    let evildict_cmd = format!(
        "open({:?}, 'w').write('evildict')",
        mcp_file.to_string_lossy().to_string()
    );
    std::fs::write(
        &evil_dict_py,
        format!(
            r#"import os, subprocess, sys
class EvilDict(dict):
    def items(self):
        return [("PYTHONPATH", os.environ["PYTHONPATH"])]
subprocess.check_call(
    [sys.executable, "-c", {cmd:?}],
    env=EvilDict(),
)
"#,
            cmd = evildict_cmd
        ),
    )
    .unwrap();
    let out3 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            evil_dict_py.to_str().unwrap(),
        ])
        .output()
        .expect("run EvilDict probe");
    assert!(!out3.status.success(), "EvilDict(dict) env must fail");
    assert!(
        String::from_utf8_lossy(&out3.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&out3.stderr)
    );
    assert!(!mcp_file.exists());

    // 4a. PYTHONPATH prepend shadowing blocked
    let shadow_py = ws.path().join("pp_shadow.py");
    std::fs::write(
        &shadow_py,
        r#"import os, subprocess, sys
ws = os.getcwd()
env = dict(os.environ)
env["PYTHONPATH"] = ws + os.pathsep + env["PYTHONPATH"]
subprocess.check_call([sys.executable, "-c", "print('SHOULD_NOT_RUN')"], env=env)
"#,
    )
    .unwrap();
    let out4a = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            shadow_py.to_str().unwrap(),
        ])
        .output()
        .expect("run PYTHONPATH shadow probe");
    assert!(
        !out4a.status.success(),
        "PYTHONPATH prepend shadowing must fail"
    );
    assert!(
        String::from_utf8_lossy(&out4a.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&out4a.stderr)
    );
    assert!(!String::from_utf8_lossy(&out4a.stdout).contains("SHOULD_NOT_RUN"));

    // 4b. Writing sitecustomize.py, usercustomize.py, *.pth inside allow_write blocked
    for startup_name in [
        "sitecustomize.py",
        "SITECUSTOMIZE.PY.",
        "usercustomize.py",
        "evil.pth",
        "EVIL.PTH ",
    ] {
        let out4b = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_path.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                "-c",
                &format!("open({:?}, 'w').write('pwn')", startup_name),
            ])
            .output()
            .expect("run startup file write probe");
        assert!(
            !out4b.status.success(),
            "writing {} must be blocked",
            startup_name
        );
        assert!(
            String::from_utf8_lossy(&out4b.stderr).contains("blocked_by_octopus_policy"),
            "stderr for {}={}",
            startup_name,
            String::from_utf8_lossy(&out4b.stderr)
        );
    }
    assert!(!ws.path().join("sitecustomize.py").exists());
    assert!(!ws.path().join("usercustomize.py").exists());
    assert!(!ws.path().join("evil.pth").exists());

    // 5. gc.get_objects() is denied by audit hook and open outside allow_write remains blocked
    let gc_py = ws.path().join("gc_probe.py");
    std::fs::write(
        &gc_py,
        format!(
            r#"import gc
try:
    gc.get_objects()
    raise AssertionError("gc.get_objects() should have been denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)
print("GC_IMMUTABLE_OK")
open({out:?}, "w").write("should_fail")
"#,
            out = outside_file.to_string_lossy().to_string()
        ),
    )
    .unwrap();
    let out5 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            gc_py.to_str().unwrap(),
        ])
        .output()
        .expect("run gc immutability probe");
    assert!(
        !out5.status.success(),
        "write outside allow_write after gc probe must fail"
    );
    assert!(
        String::from_utf8_lossy(&out5.stdout).contains("GC_IMMUTABLE_OK"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out5.stdout),
        String::from_utf8_lossy(&out5.stderr)
    );
    assert!(!outside_file.exists());

    // 6. os.link mandatory write-deny protection on source (args[0])
    let out6 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import os; os.link('.git/hooks/pre-commit', 'hardlink_hook')",
        ])
        .output()
        .expect("run os.link mandatory write-deny probe");
    assert!(
        !out6.status.success(),
        "os.link from .git/hooks/pre-commit must be blocked"
    );
    assert!(
        String::from_utf8_lossy(&out6.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&out6.stderr)
    );
    assert!(!ws.path().join("hardlink_hook").exists());
}

#[test]
fn test_cedar_fs_read_write_runtime_and_proxy_framing() {
    let ws = TempDirGuard::new("cedar_fs_and_proxy_smuggle");
    let py = find_python();

    std::fs::write(ws.path().join("public_note.txt"), "CEDAR_PUBLIC_DATA").unwrap();
    std::fs::write(ws.path().join("secret_note.txt"), "CEDAR_SECRET_DATA").unwrap();

    // 1. Standalone .cedar fs_read (permit vs forbid vs default-deny) and fs_write (forbid)
    let cedar_policy = ws.path().join("test_actions_valid.cedar");
    std::fs::write(
        &cedar_policy,
        r#"
permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when { context has stem && (context.stem == "python" || context.stem == "python3") };
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when { context has path && context.path like "*public_note.txt" };
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when { context has path && context.path like "*secret_note.txt" };
forbid (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath);
"#,
    )
    .unwrap();

    let cedar_probe = ws.path().join("cedar_probe.py");
    std::fs::write(
        &cedar_probe,
        r#"import pathlib
pub = pathlib.Path("public_note.txt").read_text(encoding="utf-8")
assert pub == "CEDAR_PUBLIC_DATA", pub
try:
    pathlib.Path("secret_note.txt").read_text(encoding="utf-8")
    raise AssertionError("secret_note.txt read should be blocked")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)
try:
    pathlib.Path("forbid_write.txt").write_text("SHOULD_NOT_EXIST", encoding="utf-8")
    raise AssertionError("forbid_write.txt write should be blocked")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)
print("CEDAR_FS_STANDALONE_OK")
"#,
    )
    .unwrap();

    let out_cedar = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            cedar_policy.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            cedar_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run standalone cedar fs probe");
    assert!(
        out_cedar.status.success(),
        "standalone cedar fs probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_cedar.stdout),
        String::from_utf8_lossy(&out_cedar.stderr)
    );
    assert!(String::from_utf8_lossy(&out_cedar.stdout).contains("CEDAR_FS_STANDALONE_OK"));
    assert!(!ws.path().join("forbid_write.txt").exists());

    // 2. JSON + inline cedar_policy: Cedar forbid fs_write overrides JSON filesystem.allow_write=["."]
    let composed_json = ws.path().join("composed_forbid_write.json");
    std::fs::write(
        &composed_json,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {"allow": ["python", "python3"]},
            "filesystem": {"allow_read": ["."], "allow_write": ["."], "deny": []},
            "cedar_policy": "permit (principal, action == Octopus::Action::\"exec\", resource is Octopus::Command); forbid (principal, action == Octopus::Action::\"fs_write\", resource is Octopus::FilePath);"
        })
        .to_string(),
    )
    .unwrap();

    let composed_probe = ws.path().join("composed_probe.py");
    std::fs::write(
        &composed_probe,
        r#"import pathlib
assert pathlib.Path("public_note.txt").read_text(encoding="utf-8") == "CEDAR_PUBLIC_DATA"
try:
    pathlib.Path("jc_write.txt").write_text("SHOULD_NOT_WRITE", encoding="utf-8")
    raise AssertionError("jc_write.txt write should be blocked by Cedar forbid")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)
print("CEDAR_FS_COMPOSED_OK")
"#,
    )
    .unwrap();

    let out_comp = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            composed_json.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            composed_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run json+cedar fs probe");
    assert!(
        out_comp.status.success(),
        "json+cedar fs probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_comp.stdout),
        String::from_utf8_lossy(&out_comp.stderr)
    );
    assert!(String::from_utf8_lossy(&out_comp.stdout).contains("CEDAR_FS_COMPOSED_OK"));
    assert!(!ws.path().join("jc_write.txt").exists());

    // 3. Proxy HTTP smuggling hardening: TE+CL and duplicate Content-Length rejected with 400 Bad Request
    let srv = MockHttpServer::start();
    let proxy_pol = ws.path().join("proxy_smuggle_pol.json");
    std::fs::write(
        &proxy_pol,
        serde_json::json!({
            "allowed_domains": [srv.addr],
            "commands": {"allow": ["python", "python3"]}
        })
        .to_string(),
    )
    .unwrap();

    let smuggle_py = ws.path().join("smuggle_probe.py");
    std::fs::write(
        &smuggle_py,
        format!(
            r#"import os, socket, urllib.parse
p = urllib.parse.urlparse(os.environ["HTTP_PROXY"])
host, port = p.hostname, p.port
def send_raw(req):
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(req)
        chunks = []
        while True:
            d = s.recv(4096)
            if not d:
                break
            chunks.append(d)
    return b"".join(chunks).decode("utf-8", errors="replace")

r_te_cl = send_raw(
    b"POST http://{addr}/smug1 HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n"
)
assert "400 Bad Request" in r_te_cl and "conflicting_transfer_encoding_and_content_length" in r_te_cl, r_te_cl

r_dup_cl = send_raw(
    b"POST http://{addr}/smug2 HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 42\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
)
assert "400 Bad Request" in r_dup_cl and "duplicate_content_length_rejected" in r_dup_cl, r_dup_cl
print("PROXY_SMUGGLE_400_OK")
"#,
            addr = srv.addr
        ),
    )
    .unwrap();

    let out_smug = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            proxy_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            smuggle_py.to_str().unwrap(),
        ])
        .output()
        .expect("run proxy smuggle probe");
    assert!(
        out_smug.status.success(),
        "proxy smuggle probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_smug.stdout),
        String::from_utf8_lossy(&out_smug.stderr)
    );
    assert!(String::from_utf8_lossy(&out_smug.stdout).contains("PROXY_SMUGGLE_400_OK"));
    assert_eq!(srv.hits(), 0);
}

#[test]
fn test_iteration4_remediations_exact_types_cedar_exec_case_truncate_rename_sqlite_and_composed_forbid(
) {
    let ws = TempDirGuard::new("iter4_remediations");
    let outside = TempDirGuard::new("iter4_outside");
    let py = find_python();

    // 1. Exact-type enforcement (EvilStr / EvilList / os.spawnve) + pathlib.Path subprocess args passing
    let json_pol = ws.path().join("json_pol.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {
                "allow": ["python", "python3"],
                "deny": ["cmd", "bash", "sh", "powershell", "pwsh"],
                "max_child_processes": 4
            },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": [".mcp.json", ".git/hooks"]
            }
        })
        .to_string(),
    )
    .unwrap();

    // 1a. Legitimate pathlib.Path subprocess args pass
    let pathlike_ok = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import pathlib, subprocess, sys; subprocess.check_call([pathlib.Path(sys.executable), '-c', 'print(\"PATHLIKE_SUB_OK\")'])",
        ])
        .output()
        .expect("run pathlib.Path subprocess check");
    assert!(
        pathlike_ok.status.success(),
        "pathlib.Path subprocess args must pass: stdout={} stderr={}",
        String::from_utf8_lossy(&pathlike_ok.stdout),
        String::from_utf8_lossy(&pathlike_ok.stderr)
    );
    assert!(String::from_utf8_lossy(&pathlike_ok.stdout).contains("PATHLIKE_SUB_OK"));

    // 1b. EvilCmdLine (str subclass) in subprocess.Popen, EvilList (list subclass), and EvilCmd in os.spawnve blocked
    let out_str_flag = outside.path().join("evil_str_flag.txt");
    let out_str_cmd = outside.path().join("evil_str_cmd.txt");
    let out_list_sub = outside.path().join("evil_list_sub.txt");
    let evil_sub_py = ws.path().join("evil_subclasses.py");
    let shell_bin = if cfg!(windows) { "cmd.exe" } else { "/bin/sh" };
    let shell_flag = if cfg!(windows) { "/c" } else { "-c" };
    std::fs::write(
        &evil_sub_py,
        format!(
            r#"import os, subprocess, sys

class EvilCmdLine(str):
    def __len__(self): return 16
    def __getitem__(self, idx): return "python benign.py"[idx]
    def __iter__(self): return iter("python benign.py")
    def replace(self, *a): return "python benign.py"
    def lower(self): return "python"
    def strip(self, *a): return "python"
    def rstrip(self, *a): return "python"
    def rsplit(self, *a): return ["python"]

class EvilList(list):
    pass

out_flag_path = {out_flag:?}
out_list_path = {out_list:?}

# (i) str subclass in subprocess.Popen single-string cmdline (-I escape)
try:
    p = subprocess.Popen(EvilCmdLine(f'"{{sys.executable}}" -I -c "open({{repr(out_flag_path)}}, \'w\').write(\'PWN\')"'))
    p.wait()
    raise AssertionError("EvilCmdLine in subprocess.Popen should have been blocked")
except PermissionError as e:
    assert "non-exact string/bytes type denied" in str(e), str(e)

# (ii) str subclass in subprocess.Popen single-string denied shell command
try:
    p = subprocess.Popen(EvilCmdLine({shell_cmdline:?}))
    p.wait()
    raise AssertionError("EvilCmdLine shell command should have been blocked")
except PermissionError as e:
    assert "non-exact string/bytes type denied" in str(e), str(e)

# (iii) list subclass in os.spawnve (and subprocess.Popen on POSIX where args is not pre-flattened)
try:
    os.spawnve(os.P_WAIT, sys.executable, EvilList([sys.executable, "-c", f"open({{repr(out_list_path)}}, 'w').write('PWN')"]), os.environ.copy())
    raise AssertionError("EvilList in os.spawnve should have been blocked")
except PermissionError as e:
    assert "non-exact string/bytes type denied" in str(e), str(e)

if os.name != "nt":
    try:
        p = subprocess.Popen(EvilList([sys.executable, "-c", f"open({{repr(out_list_path)}}, 'w').write('PWN')"]))
        p.wait()
        raise AssertionError("EvilList in subprocess.Popen should have been blocked")
    except PermissionError as e:
        assert "non-exact string/bytes type denied" in str(e), str(e)

# (iv) str subclass in os.spawnve (both executable and argv[0])
try:
    os.spawnve(os.P_WAIT, EvilCmdLine({shell_bin:?}), [EvilCmdLine({shell_bin:?}), {shell_flag:?}, "echo PWN"], os.environ.copy())
    raise AssertionError("EvilCmdLine in os.spawnve should have been blocked")
except PermissionError as e:
    assert "non-exact string/bytes type denied" in str(e), str(e)

try:
    os.spawnve(os.P_WAIT, sys.executable, [EvilCmdLine(sys.executable), "-c", f"open({{repr(out_list_path)}}, 'w').write('PWN')"], os.environ.copy())
    raise AssertionError("EvilCmdLine element in os.spawnve argv should have been blocked")
except PermissionError as e:
    assert "non-exact string/bytes type denied" in str(e), str(e)

print("EXACT_TYPE_CHECKS_OK")
"#,
            out_flag = out_str_flag.to_string_lossy().to_string(),
            shell_cmdline = format!(
                "{} {} \"echo PWN > {}\"",
                shell_bin,
                shell_flag,
                out_str_cmd.to_string_lossy()
            ),
            out_list = out_list_sub.to_string_lossy().to_string(),
            shell_bin = shell_bin,
            shell_flag = shell_flag,
        ),
    )
    .unwrap();

    let out_evil = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            evil_sub_py.to_str().unwrap(),
        ])
        .output()
        .expect("run evil subclass probe");
    assert!(
        out_evil.status.success(),
        "evil subclass test script failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_evil.stdout),
        String::from_utf8_lossy(&out_evil.stderr)
    );
    assert!(String::from_utf8_lossy(&out_evil.stdout).contains("EXACT_TYPE_CHECKS_OK"));
    assert!(!out_str_flag.exists());
    assert!(!out_str_cmd.exists());
    assert!(!out_list_sub.exists());

    // 2. os.truncate(".git/hooks/pre-commit", 0) blocked and preserves file contents
    std::fs::create_dir_all(ws.path().join(".git").join("hooks")).unwrap();
    let hook_file = ws.path().join(".git").join("hooks").join("pre-commit");
    std::fs::write(&hook_file, "SAFE_HOOK_CONTENT").unwrap();
    let trunc_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import os; os.truncate('.git/hooks/pre-commit', 0)",
        ])
        .output()
        .expect("run os.truncate probe");
    assert!(
        !trunc_out.status.success(),
        "os.truncate on .git/hooks/pre-commit must be blocked"
    );
    assert!(
        String::from_utf8_lossy(&trunc_out.stderr).contains("blocked_by_octopus_policy"),
        "stderr={}",
        String::from_utf8_lossy(&trunc_out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&hook_file).unwrap(),
        "SAFE_HOOK_CONTENT"
    );

    // 3. Standalone .cedar: cmd/os.system blocked, Windows uppercase FORBID_WRITE.TXT blocked,
    //    os.rename on fs_read-forbidden source blocked, sqlite3.connect blocked under forbid fs_write
    std::fs::write(ws.path().join("secret_note.txt"), "CEDAR_SECRET_MOVE").unwrap();
    let cedar_pol = ws.path().join("strict_cedar.cedar");
    std::fs::write(
        &cedar_pol,
        r#"
permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when { context has stem && (context.stem == "python" || context.stem == "python3") };
forbid (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when { context has stem && (context.stem == "cmd" || context.stem == "sh" || context.stem == "bash") };
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath);
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when { context has path && context.path like "*secret_note.txt" };
permit (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath);
forbid (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when { context has path && (context.path like "*forbid_write.txt" || context.path like "*db_forbid.sqlite") };
"#,
    )
    .unwrap();

    let cedar_probe = ws.path().join("cedar_iter4_probe.py");
    let spawn_shell = if cfg!(windows) {
        r#"["cmd", "/c", "echo PWN > cmd_bypass.txt"]"#
    } else {
        r#"["sh", "-c", "echo PWN > cmd_bypass.txt"]"#
    };
    std::fs::write(
        &cedar_probe,
        format!(
            r#"import os, sqlite3, subprocess

# (a) Non-Python shell subprocess blocked under standalone .cedar
try:
    subprocess.run({spawn_shell}, check=True)
    raise AssertionError("shell subprocess should be blocked under standalone .cedar")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# (b) os.system blocked under standalone .cedar
try:
    os.system("echo PWN > os_system_bypass.txt")
    raise AssertionError("os.system should be blocked under standalone .cedar")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# (c) os.rename on fs_read-forbidden source blocked even though fs_write is permitted
try:
    os.rename("secret_note.txt", "public_moved.txt")
    raise AssertionError("os.rename on fs_read-forbidden file should be blocked")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# (d) sqlite3.connect(:memory:) permitted while disk sqlite target forbidden by Cedar fs_write
mem_conn = sqlite3.connect(":memory:")
mem_conn.execute("CREATE TABLE t(x INT)")
mem_conn.close()
try:
    sqlite3.connect("db_forbid.sqlite").execute("CREATE TABLE t(x INT)")
    raise AssertionError("sqlite3.connect to forbidden db_forbid.sqlite should be blocked")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# (e) Uppercase non-existent target FORBID_WRITE.TXT blocked on Windows against *forbid_write.txt
if os.name == "nt":
    try:
        open("FORBID_WRITE.TXT", "w").write("BYPASS")
        raise AssertionError("FORBID_WRITE.TXT should be blocked on Windows")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)

print("CEDAR_ITER4_REMEDIATIONS_OK")
"#,
            spawn_shell = spawn_shell,
        ),
    )
    .unwrap();

    let out_cedar4 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            cedar_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            cedar_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run cedar iter4 probe");
    assert!(
        out_cedar4.status.success(),
        "cedar iter4 probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_cedar4.stdout),
        String::from_utf8_lossy(&out_cedar4.stderr)
    );
    assert!(String::from_utf8_lossy(&out_cedar4.stdout).contains("CEDAR_ITER4_REMEDIATIONS_OK"));
    assert!(!ws.path().join("cmd_bypass.txt").exists());
    assert!(!ws.path().join("os_system_bypass.txt").exists());
    assert!(ws.path().join("secret_note.txt").exists());
    assert!(!ws.path().join("public_moved.txt").exists());
    assert!(!ws.path().join("db_forbid.sqlite").exists());
    assert!(!ws.path().join("FORBID_WRITE.TXT").exists());

    // 4. Composed .json + conditional forbid-only cedar_policy: matching path blocked, non-matching delegates to JSON allow_write
    let composed_cond_pol = ws.path().join("composed_cond_forbid.json");
    std::fs::write(
        &composed_cond_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {"allow": ["python", "python3"]},
            "filesystem": {"allow_read": ["."], "allow_write": ["."], "deny": []},
            "cedar_policy": "forbid (principal, action == Octopus::Action::\"fs_write\", resource is Octopus::FilePath) when { context has path && context.path like \"*cedar_blocked.txt\" };"
        })
        .to_string(),
    )
    .unwrap();
    let cond_probe = ws.path().join("cond_forbid_probe.py");
    std::fs::write(
        &cond_probe,
        r#"import pathlib
pathlib.Path("json_delegated_ok.txt").write_text("DELEGATED_OK", encoding="utf-8")
try:
    pathlib.Path("cedar_blocked.txt").write_text("SHOULD_FAIL", encoding="utf-8")
    raise AssertionError("cedar_blocked.txt should be blocked by Cedar forbid")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)
print("COMPOSED_COND_FORBID_OK")
"#,
    )
    .unwrap();
    let out_cond = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            composed_cond_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            cond_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run composed conditional forbid probe");
    assert!(
        out_cond.status.success(),
        "composed conditional forbid probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_cond.stdout),
        String::from_utf8_lossy(&out_cond.stderr)
    );
    assert!(String::from_utf8_lossy(&out_cond.stdout).contains("COMPOSED_COND_FORBID_OK"));
    assert_eq!(
        std::fs::read_to_string(ws.path().join("json_delegated_ok.txt")).unwrap(),
        "DELEGATED_OK"
    );
    assert!(!ws.path().join("cedar_blocked.txt").exists());
}

#[test]
fn test_iteration6_remediations_copyfile2_gc_tb_list2cmdline_spypath_sqlite_link_and_egress() {
    let ws = TempDirGuard::new("iter6_remediations");
    let outside = TempDirGuard::new("iter6_outside");
    let py = find_python();

    // Setup files for FS, CopyFile2, SpyPath, SQLite, and os.link tests
    std::fs::create_dir_all(ws.path().join(".git").join("hooks")).unwrap();
    let hook_file = ws.path().join(".git").join("hooks").join("pre-commit");
    std::fs::write(&hook_file, "SAFE_HOOK").unwrap();
    std::fs::write(ws.path().join("allowed_src.txt"), "SRC_OK").unwrap();
    std::fs::write(ws.path().join("secret_forbid.txt"), "TOP_SECRET_123").unwrap();
    std::fs::write(ws.path().join("secret_hl.txt"), "HARDLINK_SECRET").unwrap();

    // Create pre-populated SQLite DBs for fs_read / ATTACH tests using host python
    let setup_db = Command::new(&py)
        .current_dir(ws.path())
        .args([
            "-c",
            "import sqlite3; c = sqlite3.connect('secret_ro.sqlite'); c.execute('CREATE TABLE secrets(val TEXT)'); c.execute(\"INSERT INTO secrets VALUES ('TOP_SECRET_SQLITE')\"); c.commit(); c.close(); a = sqlite3.connect('allowed_attach.sqlite'); a.execute('CREATE TABLE pub(v TEXT)'); a.execute(\"INSERT INTO pub VALUES ('PUB_OK')\"); a.commit(); a.close()",
        ])
        .output()
        .expect("setup sqlite dbs");
    assert!(setup_db.status.success());

    // 1. JSON + Cedar fs_read/fs_write policy for CopyFile2, gc/traceback, list2cmdline, SpyPath, SQLite, os.link
    let json_cedar_pol = ws.path().join("iter6_pol.json");
    std::fs::write(
        &json_cedar_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {
                "allow": ["python", "python3"],
                "deny": ["cmd", "sh", "bash"],
                "max_child_processes": 4
            },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": ["secret_forbid.txt"]
            },
            "cedar_policy": r#"
permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when { context has stem && (context.stem == "python" || context.stem == "python3") };
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when { context has normalized_path && (context.normalized_path like "*secret_ro.sqlite*" || context.normalized_path like "*secret_hl.txt*" || context.normalized_path like "*secret_forbid.txt*") };
forbid (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when { context has normalized_path && context.normalized_path like "*forbid_db*.sqlite*" };
"#
        })
        .to_string(),
    )
    .unwrap();

    let probe_py = ws.path().join("iter6_probe.py");
    let outside_copy2 = outside.path().join("outside_copy2.txt");
    let outside_spypath = outside.path().join("outside_spypath.sqlite");
    std::fs::write(
        &probe_py,
        format!(
            r#"import gc, inspect, os, pathlib, shutil, sqlite3, subprocess, sys, warnings

# --- Fix 1: shutil.copy2 / _winapi.CopyFile2 ---
shutil.copy2("allowed_src.txt", "allowed_copy2.txt")
assert pathlib.Path("allowed_copy2.txt").read_text() == "SRC_OK"

for dst in (".mcp.json.", ".git/hooks/pre-commit", {out_copy2:?}):
    try:
        shutil.copy2("allowed_src.txt", dst)
        raise AssertionError(f"shutil.copy2 to {{dst}} should be blocked")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)

try:
    shutil.copy2("secret_forbid.txt", "exfil_copy2.txt")
    raise AssertionError("shutil.copy2 from secret_forbid.txt should be blocked")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

if os.name == "nt":
    import _winapi
    try:
        _winapi.CopyFile2("allowed_src.txt", ".git/hooks/pre-commit", 0)
        raise AssertionError("_winapi.CopyFile2 to .git/hooks/pre-commit should be blocked")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)

# --- Fix 2: gc / sys._current_frames / sys._getframe / PermissionError.__traceback__ ---
for fn in (gc.get_objects, lambda: gc.get_referrers({{}}), lambda: gc.get_referents({{}}), sys._current_frames):
    try:
        fn()
        raise AssertionError("introspection call should be denied")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)

with warnings.catch_warnings(record=True) as w:
    warnings.simplefilter("always")
    warnings.warn("user_warning_ok")
    assert len(w) == 1
assert inspect.currentframe() is not None

try:
    os.system("cmd /c echo PWN")
    raise AssertionError("os.system should be denied")
except PermissionError as e:
    tb = e.__traceback__
    frames = []
    while tb is not None:
        frames.append(tb.tb_frame)
        tb = tb.tb_next
    assert len(frames) == 2, f"expected 2 frames (module + _octopus_raise_gate), got {{len(frames)}}"
    audit_fr = frames[-1]
    assert audit_fr.f_code.co_name == "_octopus_raise_gate"
    assert e.__cause__ is None and e.__context__ is None
    for secret_local in ("_check_path", "_check_child_process", "_POPEN_TOKENS"):
        assert secret_local not in audit_fr.f_locals
    for secret_global in ("_check_path", "_CEDAR_TOKEN", "_POPEN_TOKENS", "_ORIG_SQLITE_CONN", "_AUDIT_GLOBALS"):
        assert secret_global not in audit_fr.f_globals
    try:
        audit_fr.f_globals["_GATE_PENDING"] = {{}}
        raise AssertionError("mutating gate f_globals should fail")
    except PermissionError as fe:
        assert "immutable audit globals" in str(fe), str(fe)

# --- Fix 3 & 4: subprocess.Popen list2cmdline exact types + exact pathlib types ---
class EvilStr(str):
    pass
class EvilBytes(bytes):
    pass
class EvilList(list):
    pass
class EvilTuple(tuple):
    pass
class EvilPathLike(os.PathLike):
    def __fspath__(self):
        return sys.executable
class DualStrPath(str, os.PathLike):
    def __fspath__(self):
        return sys.executable
class MySubPath(type(pathlib.Path("x"))):
    pass
class SpyPath(os.PathLike):
    def __init__(self):
        self.calls = 0
    def __fspath__(self):
        self.calls += 1
        return "allowed_spypath.sqlite" if self.calls == 1 else {out_spy:?}

for bad_arg in (
    [EvilStr(sys.executable), "-c", "print(1)"],
    [EvilBytes(sys.executable.encode()), b"-c", b"print(1)"],
    EvilList([sys.executable, "-c", "print(1)"]),
    EvilTuple([sys.executable, "-c", "print(1)"]),
    [EvilPathLike(), "-c", "print(1)"],
    [DualStrPath(sys.executable), "-c", "print(1)"],
    EvilBytes(sys.executable.encode()),
    EvilPathLike(),
    DualStrPath(sys.executable),
    MySubPath(sys.executable),
):
    try:
        p = subprocess.Popen(bad_arg)
        p.wait()
        raise AssertionError(f"Popen({{type(bad_arg)}}) should be denied")
    except PermissionError as e:
        assert "non-exact" in str(e), str(e)

# Positive controls with genuine stdlib pathlib.Path
subprocess.check_call([pathlib.Path(sys.executable), "-c", "pass"])
with open(pathlib.Path("pathlib_pos.txt"), "w") as pf:
    pf.write("POS_OK")
assert pathlib.Path("pathlib_pos.txt").read_text() == "POS_OK"

# SpyPath & MySubPath & DualStrPath denied on sqlite3.connect; DualStrPath & forbidden SpyPath denied on open
for bad_fs in (SpyPath(), DualStrPath("allowed_src.txt"), MySubPath("allowed_src.txt")):
    try:
        sqlite3.connect(bad_fs)
        raise AssertionError(f"sqlite3.connect({{type(bad_fs)}}) should be denied")
    except PermissionError as e:
        assert "non-exact" in str(e), str(e)
try:
    open(DualStrPath("allowed_src.txt"), "r")
    raise AssertionError("open(DualStrPath) should be denied")
except PermissionError as e:
    assert "non-exact" in str(e), str(e)
class SpyForbidWrite(os.PathLike):
    def __fspath__(self):
        return {out_spy:?}
try:
    open(SpyForbidWrite(), "w")
    raise AssertionError("open(SpyForbidWrite) outside allow_write should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# --- Fix 5: sqlite3.connect fs_read, mode= query-order/#fragment, and ATTACH DATABASE ---
for bad_conn_args in (
    ("secret_ro.sqlite", {{}}),
    ("file:secret_ro.sqlite?mode=rwc", {{"uri": True}}),
    ("file:forbid_db1.sqlite?mode=memory&mode=rwc", {{"uri": True}}),
    ("file:forbid_db1.sqlite?mode=rwc#?mode=memory", {{"uri": True}}),
):
    try:
        sqlite3.connect(bad_conn_args[0], **bad_conn_args[1])
        raise AssertionError(f"sqlite3.connect({{bad_conn_args}}) should be denied")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)

mem = sqlite3.connect(":memory:")
assert isinstance(mem, sqlite3.Connection)
mem2 = sqlite3.connect("file::memory:?cache=shared#frag", uri=True)
mem2.close()
try:
    mem.set_authorizer(None)
    raise AssertionError("set_authorizer(None) should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

for attach_sql in (
    "ATTACH DATABASE 'secret_ro.sqlite' AS s",
    "ATTACH DATABASE 'forbid_db2.sqlite' AS f",
    "ATTACH DATABASE 'file:forbid_db3.sqlite?mode=memory&mode=rwc' AS f2",
):
    try:
        mem.execute(attach_sql)
        raise AssertionError(f"ATTACH should be denied: {{attach_sql}}")
    except sqlite3.DatabaseError:
        pass

mem.execute("ATTACH DATABASE 'allowed_attach.sqlite' AS pub")
assert mem.execute("SELECT v FROM pub.pub").fetchall() == [("PUB_OK",)]
mem.close()

# --- Fix 6: os.link fs_read check on args[0] ---
try:
    os.link("secret_hl.txt", "public_hl.txt")
    raise AssertionError("os.link from fs_read-forbidden source should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

print("ITER6_FS_SUBPROCESS_SQLITE_OK")
"#,
            out_copy2 = outside_copy2.to_string_lossy().to_string(),
            out_spy = outside_spypath.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out_probe = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_cedar_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            probe_py.to_str().unwrap(),
        ])
        .output()
        .expect("run iter6 probe");
    assert!(
        out_probe.status.success(),
        "iter6 probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_probe.stdout),
        String::from_utf8_lossy(&out_probe.stderr)
    );
    assert!(String::from_utf8_lossy(&out_probe.stdout).contains("ITER6_FS_SUBPROCESS_SQLITE_OK"));
    assert_eq!(std::fs::read_to_string(&hook_file).unwrap(), "SAFE_HOOK");
    assert!(!ws.path().join(".mcp.json").exists());
    assert!(!ws.path().join("exfil_copy2.txt").exists());
    assert!(!ws.path().join("forbid_db1.sqlite").exists());
    assert!(!ws.path().join("forbid_db2.sqlite").exists());
    assert!(!ws.path().join("forbid_db3.sqlite").exists());
    assert!(!ws.path().join("public_hl.txt").exists());
    assert!(!outside_copy2.exists());
    assert!(!outside_spypath.exists());

    // Watchdog immediate termination on dict.__setitem__(fr.f_globals, ...)
    let watchdog_py = ws.path().join("watchdog_probe.py");
    std::fs::write(
        &watchdog_py,
        r#"import os
try:
    os.system("cmd /c echo x")
except PermissionError as e:
    tb = e.__traceback__
    while tb.tb_next is not None:
        tb = tb.tb_next
    dict.__setitem__(tb.tb_frame.f_globals, "_CMD_DENY", frozenset())
open("after_tamper.txt", "w").write("SHOULD_NOT_WRITE")
"#,
    )
    .unwrap();
    let out_wd = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_cedar_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            watchdog_py.to_str().unwrap(),
        ])
        .output()
        .expect("run watchdog probe");
    assert!(
        !out_wd.status.success(),
        "watchdog must terminate process on dict.__setitem__ tampering"
    );
    assert!(!ws.path().join("after_tamper.txt").exists());

    // Tampered subprocess.list2cmdline denied
    let l2c_tamper = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_cedar_pol.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import subprocess, sys; subprocess.list2cmdline = lambda seq: ' '.join(map(str, seq)); subprocess.Popen([sys.executable, '-c', 'pass']).wait()",
        ])
        .output()
        .expect("run tampered list2cmdline probe");
    assert!(!l2c_tamper.status.success());

    // --- Fix 7: Composed .json allowed_domains + forbid-only fs_write / conditional forbid-only egress delegation ---
    let srv = MockHttpServer::start();
    let composed_egress_pol1 = ws.path().join("composed_egress_fs.json");
    std::fs::write(
        &composed_egress_pol1,
        serde_json::json!({
            "allowed_domains": [srv.addr],
            "commands": {"allow": ["python", "python3"]},
            "cedar_policy": "forbid (principal, action == Octopus::Action::\"fs_write\", resource is Octopus::FilePath) when { context has path && context.path like \"*forbid*\" };"
        })
        .to_string(),
    )
    .unwrap();
    let out_eg1 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            composed_egress_pol1.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            &format!(
                "import os, urllib.request; op = urllib.request.build_opener(urllib.request.ProxyHandler({{'http': os.environ['HTTP_PROXY']}})); r = op.open('http://{}/ok', timeout=5); assert r.status == 200; print('COMP_EGRESS_1_OK')",
                srv.addr
            ),
        ])
        .output()
        .expect("run composed egress 1");
    assert!(
        out_eg1.status.success(),
        "composed json + forbid fs_write should permit JSON allowed_domains egress: stdout={} stderr={}",
        String::from_utf8_lossy(&out_eg1.stdout),
        String::from_utf8_lossy(&out_eg1.stderr)
    );
    assert!(String::from_utf8_lossy(&out_eg1.stdout).contains("COMP_EGRESS_1_OK"));

    let composed_egress_pol2 = ws.path().join("composed_egress_cond.json");
    std::fs::write(
        &composed_egress_pol2,
        serde_json::json!({
            "allowed_domains": [srv.addr],
            "commands": {"allow": ["python", "python3"]},
            "cedar_policy": "forbid (principal, action == Octopus::Action::\"egress\", resource is Octopus::NetworkTarget) when { context has path && context.path like \"*admin*\" };"
        })
        .to_string(),
    )
    .unwrap();
    let out_eg2 = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            composed_egress_pol2.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            &format!(
                r#"import os, urllib.error, urllib.request
op = urllib.request.build_opener(urllib.request.ProxyHandler({{"http": os.environ["HTTP_PROXY"]}}))
r = op.open("http://{addr}/ok", timeout=5)
assert r.status == 200
try:
    op.open("http://{addr}/admin", timeout=5)
    raise AssertionError("/admin should be blocked by Cedar forbid")
except urllib.error.HTTPError as e:
    assert e.code == 403
print("COMP_EGRESS_2_OK")
"#,
                addr = srv.addr
            ),
        ])
        .output()
        .expect("run composed egress 2");
    assert!(
        out_eg2.status.success(),
        "composed json + conditional forbid egress failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_eg2.stdout),
        String::from_utf8_lossy(&out_eg2.stderr)
    );
    assert!(String::from_utf8_lossy(&out_eg2.stdout).contains("COMP_EGRESS_2_OK"));
    assert_eq!(srv.hits(), 2);
}

#[test]
fn test_iteration7_3hook_stdlib_freeze_direntry_watchdog_and_sqlite_hardening() {
    let ws = TempDirGuard::new("iter7_hardening");
    let outside = TempDirGuard::new("iter7_outside");
    let py = find_python();

    std::fs::write(ws.path().join("allowed_doc.txt"), "DOC_OK").unwrap();
    std::fs::write(ws.path().join("secret_forbid.txt"), "FORBID_SECRET").unwrap();

    // Setup pre-populated SQLite DBs
    let setup_db = Command::new(&py)
        .current_dir(ws.path())
        .args([
            "-c",
            "import sqlite3; c = sqlite3.connect('secret_ro.sqlite'); c.execute('CREATE TABLE secrets(val TEXT)'); c.execute(\"INSERT INTO secrets VALUES ('DISK_SECRET')\"); c.commit(); c.close(); a = sqlite3.connect('allowed_pub.sqlite'); a.execute('CREATE TABLE pub(v TEXT)'); a.execute(\"INSERT INTO pub VALUES ('PUB_OK')\"); a.commit(); a.close()",
        ])
        .output()
        .expect("setup sqlite dbs");
    assert!(setup_db.status.success());

    let pol_path = ws.path().join("iter7_pol.json");
    std::fs::write(
        &pol_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {
                "allow": ["python", "python3"],
                "deny": ["cmd", "sh", "bash"]
            },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": ["secret_forbid.txt"]
            },
            "cedar_policy": r#"
permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when { context has stem && (context.stem == "python" || context.stem == "python3") };
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when { context has normalized_path && (context.normalized_path like "*secret_ro.sqlite*" || context.normalized_path like "*secret_forbid.txt*") };
forbid (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when { context has normalized_path && context.normalized_path like "*forbid_write*.sqlite*" };
"#
        })
        .to_string(),
    )
    .unwrap();

    // 1. Combined positive + negative security probe (3-hook traceback isolation, addaudithook,
    //    Boom() _getframe, stdlib monkeypatch immunity, os.DirEntry, SQLite URI/cursor/row_factory/
    //    setconfig/load_extension/ATTACH?, and positive SQLite controls)
    let probe_py = ws.path().join("iter7_probe.py");
    let outside_file = outside.path().join("escape.txt");
    let outside_db = outside.path().join("escape.sqlite");
    std::fs::write(
        &probe_py,
        format!(
            r#"import builtins, json, os, pathlib, socket, sqlite3, _sqlite3, subprocess, sys, weakref

# --- (a) sys.addaudithook denied ---
try:
    sys.addaudithook(lambda e, a: None)
    raise AssertionError("sys.addaudithook should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# --- (b) sys.audit('sys._getframe', Boom()) denied with stripped traceback in _GATE_GLOBALS ---
class Boom:
    def __getattr__(self, name):
        raise RuntimeError("boom_attr_" + name)

try:
    sys.audit("sys._getframe", Boom())
    raise AssertionError("sys._getframe with Boom() should be denied")
except PermissionError as e:
    assert e.__cause__ is None and e.__context__ is None, (e.__cause__, e.__context__)
    tb = e.__traceback__
    frames = []
    while tb is not None:
        frames.append(tb.tb_frame)
        tb = tb.tb_next
    assert len(frames) == 2, f"expected 2 frames, got {{len(frames)}}"
    gate_fr = frames[-1]
    assert gate_fr.f_code.co_name == "_octopus_raise_gate", gate_fr.f_code.co_name
    for forbidden in (
        "_AUDIT_GLOBALS", "_WATCHDOG_GLOBALS_REF", "_SQLITE_GLOBALS", "_LIST2CMD_GLOBALS",
        "_CEDAR_TOKEN", "_POPEN_TOKENS", "_ORIG_SQLITE_CONNECT", "_ORIG_SQLITE_CONN", "_check_path",
    ):
        assert forbidden not in gate_fr.f_globals, f"leaked {{forbidden}} in _GATE_GLOBALS"

try:
    try:
        1 / 0
    except ZeroDivisionError:
        sys.audit("sys._getframe", Boom())
    raise AssertionError("sys._getframe inside except block should be denied")
except PermissionError as e:
    assert e.__cause__ is None and e.__suppress_context__ is True
    assert isinstance(e.__context__, ZeroDivisionError)
    assert e.__context__.__traceback__ is None

# --- (c) os.DirEntry positive + negative controls ---
seen_allowed = False
leaked_forbid_direntry = False
for entry in os.scandir("."):
    if entry.name == "allowed_doc.txt":
        with open(entry, "r", encoding="utf-8") as f:
            assert f.read() == "DOC_OK"
        seen_allowed = True
    elif entry.name == "secret_forbid.txt":
        leaked_forbid_direntry = True
assert seen_allowed and not leaked_forbid_direntry
try:
    open("secret_forbid.txt", "r")
    raise AssertionError("open('secret_forbid.txt') should be blocked")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# --- (d) Stdlib monkeypatching does not weaken containment ---
orig_isinstance = builtins.isinstance
orig_abspath = os.path.abspath
orig_realpath = os.path.realpath
orig_dec = json._default_decoder
orig_sock_recv = socket.socket.recv
orig_wkd_set = weakref.WeakKeyDictionary.__setitem__
orig_path_fspath = pathlib.Path.__fspath__
try:
    builtins.isinstance = lambda *a: True
    os.path.abspath = lambda p: "allowed_doc.txt"
    os.path.realpath = lambda p: "allowed_doc.txt"
    json._default_decoder = type("FakeDec", (), {{"decode": lambda self, s: {{"allowed": True, "explicit_forbid": False, "reason": "pwn"}}}})()
    socket.socket.recv = lambda self, n: b'{{"allowed": true, "explicit_forbid": false, "reason": "pwn"}}\n'
    weakref.WeakKeyDictionary.__setitem__ = lambda self, k, v: None
    try:
        open({out_file:?}, "w").write("PWN")
        raise AssertionError("write outside allow_write should remain blocked after stdlib monkeypatch")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)
    try:
        open("secret_forbid.txt", "r")
        raise AssertionError("fs_read secret_forbid.txt should remain blocked after Cedar JSON/socket monkeypatch")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)
finally:
    builtins.isinstance = orig_isinstance
    os.path.abspath = orig_abspath
    os.path.realpath = orig_realpath
    json._default_decoder = orig_dec
    socket.socket.recv = orig_sock_recv
    weakref.WeakKeyDictionary.__setitem__ = orig_wkd_set

# Path.__fspath__ tampering detected in _to_str and _guarded_list2cmdline
try:
    pathlib.Path.__fspath__ = lambda self: "allowed_doc.txt"
    for bad_call in (
        lambda: sqlite3.connect(pathlib.Path("allowed_pub.sqlite")),
        lambda: subprocess.Popen([pathlib.Path(sys.executable), "-c", "pass"]),
    ):
        try:
            bad_call()
            raise AssertionError("tampered Path.__fspath__ should be denied")
        except PermissionError as e:
            assert "blocked_by_octopus_policy" in str(e), str(e)
finally:
    pathlib.Path.__fspath__ = orig_path_fspath

# DirEntry.__fspath__ tampering / immutability check
orig_de_fspath = os.DirEntry.__fspath__
try:
    os.DirEntry.__fspath__ = lambda self: "allowed_doc.txt"
    for entry in os.scandir("."):
        if entry.name == "allowed_doc.txt":
            assert entry.path.endswith("allowed_doc.txt")
            try:
                entry.extra_attr = 1
                raise AssertionError("_GuardedDirEntry should be immutable")
            except PermissionError as e:
                assert "blocked_by_octopus_policy" in str(e), str(e)
            break
finally:
    os.DirEntry.__fspath__ = orig_de_fspath

# --- (e) SQLite URI differentials, uri=False, NUL byte, ATTACH?, Cursor, row_factory, setconfig, load_extension ---
for secret_name in ("_ORIG_SQLITE_CONNECT", "_ORIG_SQLITE_CONN", "_ORIG_SQLITE_CURSOR", "_SQLITE_CONN_MAP", "_SQLITE_CURSOR_MAP"):
    assert secret_name not in sqlite3.connect.__globals__, f"{{secret_name}} leaked in _SQLITE_GLOBALS"

for bad_uri, kw in (
    ("file:secret_ro.sqlite?MODE=memory", {{"uri": True}}),
    ("file:secret_ro.sqlite? mode=memory", {{"uri": True}}),
    ("file:secret_ro.sqlite?%4dODE=memory", {{"uri": True}}),
    ("file:secret_ro.sqlite%00_ignored?mode=memory", {{"uri": True}}),
    ("file:forbid_write_uri.sqlite?mode=memory%00_ignored", {{"uri": True}}),
    ("file:forbid_write_uri.sqlite?MODE=ro", {{"uri": True}}),
    ("file:forbid_write_uri.sqlite? mode=ro", {{"uri": True}}),
    ("file:forbid_write_nouri.sqlite?mode=memory", {{}}),
    ("file:forbid_write_nouri.sqlite?mode=memory", {{"uri": False}}),
    ("file:{out_db_esc}?mode=memory", {{"uri": False}}),
):
    try:
        sqlite3.connect(bad_uri, **kw)
        raise AssertionError(f"sqlite3.connect({{bad_uri!r}}, {{kw}}) should be denied")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)

mem = sqlite3.connect(":memory:")
assert isinstance(mem, sqlite3.Connection)
assert isinstance(mem, _sqlite3.Connection)

# Bound method __self__ and iterdump generator frame isolation
assert getattr(mem.commit, "__self__", None) is None
dump_gen = mem.iterdump()
assert dump_gen.gi_frame.f_locals["connection"] is mem
list(dump_gen)

cur = mem.cursor()
assert isinstance(cur, sqlite3.Cursor)
assert isinstance(cur, _sqlite3.Cursor)
assert cur.connection is mem
assert getattr(cur.fetchone, "__self__", None) is cur
assert getattr(cur.close, "__self__", None) is None

cur2 = mem.execute("SELECT 1")
assert isinstance(cur2, sqlite3.Cursor)
assert cur2.connection is mem
try:
    cur2.connection.set_authorizer(None)
    raise AssertionError("cur2.connection.set_authorizer(None) should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)
cur2.close()
cur.close()

# row_factory denies sys._getframe(1) inspection and never exposes raw _sqlite3 objects
seen_rf = []
def inspect_rf(c, row):
    import warnings
    assert isinstance(c, sqlite3.Cursor)
    assert c.connection is mem
    warnings.warn("iter7_rf_warn", UserWarning)
    try:
        sys._getframe(1)
        raise AssertionError("sys._getframe(1) inside row_factory must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)
    seen_rf.append(row)
    return {{"v": row[0]}}

mem.row_factory = inspect_rf
assert mem.row_factory is inspect_rf
assert mem.execute("SELECT 42").fetchall() == [{{"v": 42}}]
assert seen_rf == [(42,)]
mem.row_factory = sqlite3.Row
row_obj = mem.execute("SELECT 7 AS num").fetchone()
assert row_obj["num"] == 7
mem.row_factory = None

# setconfig / enable_load_extension / load_extension blocked
if hasattr(sqlite3, "SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION"):
    try:
        mem.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, True)
        raise AssertionError("setconfig enable_load_extension should be denied")
    except PermissionError as e:
        assert "blocked_by_octopus_policy" in str(e), str(e)
try:
    mem.enable_load_extension(True)
    raise AssertionError("enable_load_extension(True) should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)
try:
    mem.load_extension("nonexistent_ext")
    raise AssertionError("load_extension should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# Parameterized ATTACH ?, expression ATTACH, and ?MODE=memory ATTACH denied
for attach_call in (
    lambda: mem.execute("ATTACH DATABASE ? AS s", ("secret_ro.sqlite",)),
    lambda: mem.execute("ATTACH DATABASE ('secret' || '_ro.sqlite') AS s"),
    lambda: mem.execute("ATTACH DATABASE 'file:secret_ro.sqlite?MODE=memory' AS s"),
):
    try:
        attach_call()
        raise AssertionError("ATTACH should be denied")
    except sqlite3.DatabaseError:
        pass

# Positive SQLite controls: VACUUM, for-loop iteration, Cursor(conn), SubCur, SubConn, backup()
mem.execute("CREATE TABLE items(x INT)")
mem.execute("INSERT INTO items VALUES (10), (20)")
mem.commit()
assert [r[0] for r in mem.execute("SELECT x FROM items ORDER BY x")] == [10, 20]
mem.execute("VACUUM")
assert list(mem.iterdump())[0] == "BEGIN TRANSACTION;"

c_direct = sqlite3.Cursor(mem)
assert c_direct.execute("SELECT COUNT(*) FROM items").fetchone() == (2,)

class SubCur(sqlite3.Cursor):
    tag = "subcur"
sc = mem.cursor(SubCur)
assert isinstance(sc, SubCur) and sc.tag == "subcur" and sc.connection is mem
assert sc.execute("SELECT SUM(x) FROM items").fetchone() == (30,)

class SubConn(sqlite3.Connection):
    tag = "subconn"
sub_c = sqlite3.connect(":memory:", factory=SubConn)
assert isinstance(sub_c, SubConn) and sub_c.tag == "subconn"
mem.backup(sub_c)
assert sub_c.execute("SELECT SUM(x) FROM items").fetchone() == (30,)
sub_c.close()
mem.close()

# uri=True legitimate in-memory URI positive control
mem_uri = sqlite3.connect("file:safe_mem.sqlite?mode=memory&cache=shared", uri=True)
mem_uri.execute("CREATE TABLE m(k INT)")
mem_uri.close()

print("ITER7_ALL_HARDENING_OK")
"#,
            out_file = outside_file.to_string_lossy().to_string(),
            out_db_esc = outside_db.to_string_lossy().replace('\\', "/"),
        ),
    )
    .unwrap();

    let out_probe = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            probe_py.to_str().unwrap(),
        ])
        .output()
        .expect("run iter7 probe");
    assert!(
        out_probe.status.success(),
        "iter7 probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_probe.stdout),
        String::from_utf8_lossy(&out_probe.stderr)
    );
    assert!(String::from_utf8_lossy(&out_probe.stdout).contains("ITER7_ALL_HARDENING_OK"));
    assert!(!outside_file.exists());
    assert!(!outside_db.exists());
    assert!(!ws.path().join("forbid_write_uri.sqlite").exists());
    assert!(!ws.path().join("forbid_write_nouri.sqlite").exists());
    assert!(!ws.path().join("safe_mem.sqlite").exists());

    // 2. Watchdog tamper tests on _GATE_GLOBALS, _SQLITE_GLOBALS & _LIST2CMD_GLOBALS (value change & extra-key injection)
    for (idx, tamper_expr) in [
        "import threading\ntry:\n    open('secret_forbid.txt')\nexcept PermissionError as e:\n    dict.__setitem__(e.__traceback__.tb_next.tb_frame.f_globals, '_GATE_TL', threading.local())\nopen('tamper1.txt', 'w').write('FAIL')",
        "try:\n    open('secret_forbid.txt')\nexcept PermissionError as e:\n    dict.__setitem__(e.__traceback__.tb_next.tb_frame.f_globals, '_EXTRA_KEY', 1)\nopen('tamper2.txt', 'w').write('FAIL')",
        "import sqlite3\ndict.__setitem__(sqlite3.connect.__globals__, '_SQLITE_WRAPPER_CLS', object)\nopen('tamper3.txt', 'w').write('FAIL')",
        "import sqlite3\ndict.__setitem__(sqlite3.connect.__globals__, '_EXTRA_SQ', 1)\nopen('tamper4.txt', 'w').write('FAIL')",
        "import subprocess\ndict.__setitem__(subprocess.list2cmdline.__globals__, '_EXACT_PATHLIB_TYPES', ())\nopen('tamper5.txt', 'w').write('FAIL')",
        "import subprocess\ndict.__setitem__(subprocess.list2cmdline.__globals__, '_EXTRA_L2C', 1)\nopen('tamper6.txt', 'w').write('FAIL')",
    ]
    .iter()
    .enumerate()
    {
        let wd_script = ws.path().join(format!("wd_tamper_{}.py", idx));
        std::fs::write(&wd_script, tamper_expr).unwrap();
        let out_wd = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_path.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                wd_script.to_str().unwrap(),
            ])
            .output()
            .expect("run watchdog tamper probe");
        assert!(
            !out_wd.status.success(),
            "watchdog tamper case {} must terminate immediately",
            idx
        );
        assert!(!ws.path().join(format!("tamper{}.txt", idx + 1)).exists());
    }
}

#[test]
fn test_iteration8_sqlite_trace_isolation_gate_tl_race_and_positional_connect() {
    let ws = TempDirGuard::new("iter8_hardening");
    let outside = TempDirGuard::new("iter8_outside");
    let py = find_python();

    std::fs::write(ws.path().join("allowed_doc.txt"), "DOC_OK").unwrap();
    std::fs::write(ws.path().join("secret_forbid.txt"), "FORBID_SECRET").unwrap();

    let pol_path = ws.path().join("iter8_pol.json");
    std::fs::write(
        &pol_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {
                "allow": ["python", "python3"],
                "deny": ["cmd", "sh", "bash"]
            },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": ["secret_forbid.txt"]
            },
            "cedar_policy": r#"
permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when { context has stem && (context.stem == "python" || context.stem == "python3") };
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when { context has normalized_path && context.normalized_path like "*secret_forbid.txt*" };
"#
        })
        .to_string(),
    )
    .unwrap();

    // 1. sys.settrace / sys.setprofile during SQLite connect, execute, row_factory, and GC cleanup
    let outside_db = outside.path().join("trace_escape.sqlite");
    let trace_script = ws.path().join("trace_sqlite_probe.py");
    std::fs::write(
        &trace_script,
        format!(
            r#"import gc, sqlite3, sys

captured_globals = []
def _tracer(frame, event, arg):
    fg = frame.f_globals
    for secret_k in (
        "_ORIG_SQLITE_CONNECT", "_ORIG_SQLITE_CONN", "_ORIG_SQLITE_CURSOR",
        "_PENDING_SQLITE_CONNS", "_AUDIT_GETFRAME_ACTIVE", "_CEDAR_TOKEN",
        "_AUDIT_DENY_ARMED", "_SQLITE_CONN_MAP", "_SQLITE_CURSOR_MAP",
    ):
        if secret_k in fg:
            captured_globals.append((frame.f_code.co_name, secret_k))
    return _tracer

def _profiler(frame, event, arg):
    fg = frame.f_globals
    for secret_k in ("_ORIG_SQLITE_CONNECT", "_CEDAR_TOKEN", "_AUDIT_DENY_ARMED"):
        if secret_k in fg:
            captured_globals.append(("prof:" + frame.f_code.co_name, secret_k))

for set_fn in (sys.settrace, sys.setprofile):
    cb = _tracer if set_fn is sys.settrace else _profiler
    set_fn(cb)
    try:
        conn = sqlite3.connect(":memory:")
        def rf(cur, row):
            assert isinstance(cur, sqlite3.Cursor)
            return row
        conn.row_factory = rf
        cur = conn.execute("SELECT 123")
        assert cur.fetchall() == [(123,)]
        del cur
        gc.collect()
        try:
            conn.execute("ATTACH DATABASE ? AS esc", ({out_db:?},))
            raise AssertionError("ATTACH DATABASE outside allow_write should fail")
        except sqlite3.DatabaseError:
            pass
        conn.close()
        del conn
        gc.collect()
    finally:
        set_fn(None)

assert not captured_globals, f"captured _AUDIT_GLOBALS keys via tracing: {{captured_globals}}"
print("TRACE_ISOLATION_OK")
"#,
            out_db = outside_db.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out_trace = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            trace_script.to_str().unwrap(),
        ])
        .output()
        .expect("run trace sqlite probe");
    assert!(
        out_trace.status.success(),
        "trace sqlite probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_trace.stdout),
        String::from_utf8_lossy(&out_trace.stderr)
    );
    assert!(String::from_utf8_lossy(&out_trace.stdout).contains("TRACE_ISOLATION_OK"));
    assert!(!outside_db.exists());

    // 2. _GATE_TL + 4th fail-closed hook GIL-switch race probe (5,000+ iterations)
    let outside_race_file = outside.path().join("race_pwn.txt");
    let race_script = ws.path().join("gate_tl_race_probe.py");
    std::fs::write(
        &race_script,
        format!(
            r#"import os, sys, threading

try:
    open("secret_forbid.txt", "r")
    raise AssertionError("initial denied open must raise PermissionError")
except PermissionError as e:
    gate_fg = e.__traceback__.tb_next.tb_frame.f_globals

assert "_GATE_PENDING" not in gate_fg, "_GATE_PENDING must be removed"
gate_tl = gate_fg["_GATE_TL"]
assert type(gate_tl) is type(threading.local())

stop = False
def hammer():
    while not stop:
        try:
            gate_tl.exc = None
        except Exception:
            pass
        try:
            del gate_tl.exc
        except Exception:
            pass

orig_sw = sys.getswitchinterval()
sys.setswitchinterval(1e-6)
t = threading.Thread(target=hammer, daemon=True)
t.start()
try:
    for i in range(1500):
        try:
            with open("secret_forbid.txt", "r") as f:
                raise AssertionError(f"denied read bypassed at iter {{i}}: {{f.read()}}")
        except PermissionError:
            pass
    for i in range(200):
        try:
            with open({out_race:?}, "w") as f:
                f.write("PWN")
            raise AssertionError(f"outside write bypassed at iter {{i}}")
        except PermissionError:
            pass
    for i in range(25):
        try:
            os.system("cmd /c echo PWN")
            raise AssertionError(f"denied os.system bypassed at iter {{i}}")
        except PermissionError:
            pass
finally:
    stop = True
    t.join(timeout=2.0)
    sys.setswitchinterval(orig_sw)

# Verify normal allowed call still works after 1,725+ caught denials
with open("allowed_doc.txt", "r", encoding="utf-8") as f:
    assert f.read() == "DOC_OK"
print("GATE_TL_RACE_RESISTANT_OK")
"#,
            out_race = outside_race_file.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out_race = Command::new(octopus_bin())
        .args([
            "run",
            "--timeout",
            "240",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            race_script.to_str().unwrap(),
        ])
        .output()
        .expect("run gate_tl race probe");
    assert!(
        out_race.status.success(),
        "gate_tl race probe failed (exit={:?}): stdout={} stderr={}",
        out_race.status.code(),
        String::from_utf8_lossy(&out_race.stdout),
        String::from_utf8_lossy(&out_race.stderr)
    );
    assert!(String::from_utf8_lossy(&out_race.stdout).contains("GATE_TL_RACE_RESISTANT_OK"));
    assert!(!outside_race_file.exists());

    // 3. Positional sqlite3.connect (>1 positional args) positive & negative controls + warningregistry resilience
    let pos_script = ws.path().join("pos_sqlite_probe.py");
    std::fs::write(
        &pos_script,
        r#"import sqlite3, warnings

c1 = sqlite3.connect(":memory:", 5.0)
c1.execute("CREATE TABLE t(v INT)")
c1.execute("INSERT INTO t VALUES (1)")
assert c1.execute("SELECT v FROM t").fetchone() == (1,)
c1.close()

c2 = sqlite3.connect("file:pos_ok.db?mode=memory", 5.0, 0, None, False, sqlite3.Connection, 128, True)
c2.execute("CREATE TABLE u(v TEXT)")
c2.execute("INSERT INTO u VALUES ('URI_POS_OK')")
assert c2.execute("SELECT v FROM u").fetchone() == ("URI_POS_OK",)
c2.close()

class SubConn(sqlite3.Connection):
    tag = "pos_subconn"

c3 = sqlite3.connect(":memory:", 5.0, 0, None, True, SubConn)
assert isinstance(c3, SubConn) and c3.tag == "pos_subconn"
assert c3.execute("SELECT 9").fetchone() == (9,)
c3.close()

# Negative positional uri=False check (file:...?mode=memory with positional args[7]=False must be rejected)
try:
    sqlite3.connect("file:forbid_pos_nouri.db?mode=memory", 5.0, 0, None, False, sqlite3.Connection, 128, False)
    raise AssertionError("positional uri=False should be denied")
except PermissionError as e:
    assert "blocked_by_octopus_policy" in str(e), str(e)

# >8 positional args and duplicate positional+keyword args preserve TypeError
for bad_call in (
    lambda: sqlite3.connect(":memory:", 5.0, 0, None, False, sqlite3.Connection, 128, True, "extra"),
    lambda: sqlite3.connect(":memory:", 5.0, timeout=5.0),
):
    try:
        bad_call()
        raise AssertionError("expected TypeError for invalid connect signature")
    except TypeError:
        pass

# Pre-seeded __warningregistry__ allows in-place warning recording without tripping watchdog
warnings.warn("test_pos_warn", DeprecationWarning)
assert isinstance(sqlite3.connect.__globals__.get("__warningregistry__"), dict)
dict.__setitem__(sqlite3.connect.__globals__["__warningregistry__"], ("k", DeprecationWarning, 1), 1)
assert open("allowed_doc.txt", "r", encoding="utf-8").read() == "DOC_OK"
print("POS_SQLITE_AND_WARNREG_OK")
"#,
    )
    .unwrap();

    let out_pos = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            pos_script.to_str().unwrap(),
        ])
        .output()
        .expect("run positional sqlite probe");
    assert!(
        out_pos.status.success(),
        "positional sqlite probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_pos.stdout),
        String::from_utf8_lossy(&out_pos.stderr)
    );
    assert!(String::from_utf8_lossy(&out_pos.stdout).contains("POS_SQLITE_AND_WARNREG_OK"));
    assert!(!ws.path().join("pos_ok.db").exists());
    assert!(!ws.path().join("forbid_pos_nouri.db").exists());

    // 4. Replacing __warningregistry__ with a different dict/non-dict MUST trip watchdog immediately
    let warn_tamper_script = ws.path().join("warnreg_tamper.py");
    std::fs::write(
        &warn_tamper_script,
        "import sqlite3\ndict.__setitem__(sqlite3.connect.__globals__, '__warningregistry__', {})\nopen('warn_tamper.txt', 'w').write('FAIL')\n",
    )
    .unwrap();
    let out_wt = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            warn_tamper_script.to_str().unwrap(),
        ])
        .output()
        .expect("run warnreg tamper probe");
    assert!(
        !out_wt.status.success(),
        "replacing __warningregistry__ must trip watchdog"
    );
    assert!(!ws.path().join("warn_tamper.txt").exists());
}

#[test]
fn test_iteration9_sqlite_traceback_and_signal_reentrancy_hardening() {
    let ws = TempDirGuard::new("iter9_hardening");
    let outside = TempDirGuard::new("iter9_outside");
    let py = find_python();

    std::fs::write(ws.path().join("allowed_doc.txt"), "DOC_OK").unwrap();
    std::fs::write(ws.path().join("secret_forbid.txt"), "FORBID_SECRET").unwrap();

    let pol_path = ws.path().join("iter9_pol.json");
    std::fs::write(
        &pol_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": {
                "allow": ["python", "python3"],
                "deny": ["cmd", "sh", "bash"]
            },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": ["secret_forbid.txt", outside.path()]
            },
            "cedar_policy": r#"
permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when { context has stem && (context.stem == "python" || context.stem == "python3") };
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when { context has normalized_path && context.normalized_path like "*secret_forbid.txt*" };
"#
        })
        .to_string(),
    )
    .unwrap();

    // 1. SQLite callback traceback isolation + denied synchronous callbacks + positive controls
    let outside_db = outside.path().join("tb_escape.sqlite");
    let sq_script = ws.path().join("iter9_sqlite_tb_probe.py");
    std::fs::write(
        &sq_script,
        format!(
            r#"import _sqlite3, sqlite3

captured = {{}}
def scan_tb(tag):
    try:
        1 / 0
    except ZeroDivisionError as e:
        f = e.__traceback__.tb_frame
        while f is not None:
            fg = f.f_globals
            if any(k in fg for k in (
                "_AUDIT_GLOBALS", "_ORIG_SQLITE_CONNECT", "_ORIG_SQLITE_CONN",
                "_ORIG_SQLITE_CURSOR", "_CEDAR_TOKEN", "_AUDIT_DENY_ARMED",
                "_PENDING_SQLITE_CONNS", "_WATCHDOG_GLOBALS_REF",
            )):
                captured[tag + "_audit_globals"] = True
            for loc_k in ("raw", "raw_cur"):
                if loc_k in f.f_locals:
                    captured[tag + "_" + loc_k] = type(f.f_locals[loc_k]).__name__
            f = f.f_back

class EvilFloat:
    def __float__(self):
        scan_tb("timeout_float")
        return 5.0

class EvilInt:
    def __index__(self):
        scan_tb("int_idx")
        return 0

class EvilBool:
    def __bool__(self):
        scan_tb("bool")
        return True

con = sqlite3.connect(
    ":memory:",
    timeout=EvilFloat(),
    detect_types=EvilInt(),
    check_same_thread=EvilBool(),
    cached_statements=EvilInt(),
    uri=False,
)
con.execute("CREATE TABLE t(x TEXT)")

def gen_rows():
    scan_tb("executemany_gen")
    yield ("a",)
    yield ("b",)
    yield ("c",)

con.executemany("INSERT INTO t VALUES (?)", gen_rows())

def rf_check(cur, row):
    assert isinstance(cur, sqlite3.Cursor)
    assert cur.connection is con
    scan_tb("row_factory")
    return {{"val": row[0]}}

con.row_factory = rf_check
assert con.execute("SELECT x FROM t ORDER BY x").fetchone() == {{"val": "a"}}
assert con.execute("SELECT x FROM t ORDER BY x").fetchmany(2) == [{{"val": "a"}}, {{"val": "b"}}]
assert con.execute("SELECT x FROM t ORDER BY x").fetchall() == [{{"val": "a"}}, {{"val": "b"}}, {{"val": "c"}}]
assert [r for r in con.execute("SELECT x FROM t ORDER BY x")] == [{{"val": "a"}}, {{"val": "b"}}, {{"val": "c"}}]

# sqlite3.Row compatibility preserved cleanly
con.row_factory = sqlite3.Row
row_c = con.execute("SELECT x AS col FROM t ORDER BY x").fetchone()
assert row_c["col"] == "a"
assert not hasattr(row_c, "cursor") and not hasattr(row_c, "connection")
con.row_factory = None

# Synchronous Python callback / adapter / text_factory / progress vectors denied
for label, call in (
    ("create_function", lambda: con.create_function("pwn", 0, lambda: 1)),
    ("create_aggregate", lambda: con.create_aggregate("agg", 1, object)),
    ("create_window_function", lambda: con.create_window_function("win", 1, object)),
    ("create_collation", lambda: con.create_collation("col", lambda a, b: 0)),
    ("set_progress_handler", lambda: con.set_progress_handler(lambda: 0, 1)),
    ("set_trace_callback", lambda: con.set_trace_callback(lambda s: None)),
    ("set_authorizer", lambda: con.set_authorizer(lambda *a: 0)),
    ("register_adapter", lambda: sqlite3.register_adapter(object, lambda o: "x")),
    ("register_converter", lambda: sqlite3.register_converter("X", lambda b: b)),
    ("raw_register_adapter", lambda: _sqlite3.register_adapter(object, lambda o: "x")),
    ("raw_register_converter", lambda: _sqlite3.register_converter("X", lambda b: b)),
    ("custom_text_factory", lambda: setattr(con, "text_factory", lambda b: b.decode())),
    ("backup_progress", lambda: con.backup(sqlite3.connect(":memory:"), progress=lambda s, r, t: None)),
):
    try:
        call()
        raise AssertionError(f"{{label}} must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

class EvilConform:
    def __conform__(self, proto):
        scan_tb("conform")
        return "pwn"

try:
    con.execute("SELECT ?", (EvilConform(),))
    raise AssertionError("__conform__ param must be denied")
except PermissionError as pe:
    assert "blocked_by_octopus_policy" in str(pe), str(pe)

# Safe text_factory & backup without progress still work
con.text_factory = bytes
assert con.execute("SELECT x FROM t LIMIT 1").fetchone() == (b"a",)
con.text_factory = str
con.commit()
bak = sqlite3.connect(":memory:")
con.backup(bak)
assert bak.execute("SELECT COUNT(*) FROM t").fetchone() == (3,)
bak.close()

# ATTACH DATABASE outside allow_write still blocked
try:
    con.execute("ATTACH DATABASE ? AS esc", ({out_db:?},))
    raise AssertionError("ATTACH outside allow_write must be denied")
except sqlite3.DatabaseError:
    pass

con.close()
assert captured == {{}}, f"traceback capture leaked internals: {{captured}}"
print("ITER9_SQLITE_TB_HARDENED_OK")
"#,
            out_db = outside_db.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out_sq = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            sq_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter9 sqlite traceback probe");
    assert!(
        out_sq.status.success(),
        "iter9 sqlite traceback probe failed (exit={:?}): stdout={} stderr={}",
        out_sq.status.code(),
        String::from_utf8_lossy(&out_sq.stdout),
        String::from_utf8_lossy(&out_sq.stderr)
    );
    assert!(String::from_utf8_lossy(&out_sq.stdout).contains("ITER9_SQLITE_TB_HARDENED_OK"));
    assert!(!outside_db.exists());

    // 2. Signal positive controls (user-frame handler, getsignal, default_int_handler)
    let sig_pos_script = ws.path().join("iter9_sig_pos.py");
    std::fs::write(
        &sig_pos_script,
        r#"import _signal, signal, sys, _thread, time

seen = []
def user_handler(signum, frame):
    assert signum == signal.SIGINT
    if frame is not None:
        assert "_AUDIT_GLOBALS" not in frame.f_globals
        assert "_CEDAR_TOKEN" not in frame.f_globals
    seen.append(signum)

old = signal.signal(signal.SIGINT, user_handler)
assert old is signal.default_int_handler
assert signal.getsignal(signal.SIGINT) is user_handler
assert _signal.getsignal(signal.SIGINT) is user_handler

t = _thread.start_new_thread(lambda: (time.sleep(0.05), _thread.interrupt_main()), ())
deadline = time.time() + 3.0
while not seen and time.time() < deadline:
    x = 0
    for _ in range(1000):
        x += 1

assert seen == [signal.SIGINT], f"expected SIGINT delivery, got {seen}"
assert signal.signal(signal.SIGINT, signal.default_int_handler) is user_handler
assert signal.getsignal(signal.SIGINT) is signal.default_int_handler

# Verify normal KeyboardInterrupt works with default_int_handler
try:
    _thread.interrupt_main()
    for _ in range(100000):
        pass
    raise AssertionError("expected KeyboardInterrupt")
except KeyboardInterrupt:
    pass

# Verify _signal.signal also works and wraps
old_raw = _signal.signal(_signal.SIGINT, signal.SIG_IGN)
assert old_raw is signal.default_int_handler
assert signal.getsignal(signal.SIGINT) is signal.SIG_IGN
_signal.signal(_signal.SIGINT, signal.default_int_handler)
print("ITER9_SIG_POSITIVE_OK")
"#,
    )
    .unwrap();

    let out_sig_pos = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            sig_pos_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter9 sig positive probe");
    assert!(
        out_sig_pos.status.success(),
        "iter9 sig positive probe failed (exit={:?}): stdout={} stderr={}",
        out_sig_pos.status.code(),
        String::from_utf8_lossy(&out_sig_pos.stdout),
        String::from_utf8_lossy(&out_sig_pos.stderr)
    );
    assert!(String::from_utf8_lossy(&out_sig_pos.stdout).contains("ITER9_SIG_POSITIVE_OK"));

    // 3. Signal reentrancy & frame exposure attack during denied open / os.system
    let outside_sig_file = outside.path().join("sig_pwn.txt");
    let sig_atk_script = ws.path().join("iter9_sig_attack.py");
    std::fs::write(
        &sig_atk_script,
        format!(
            r#"import os, signal, sys, threading, time, _thread

leaked = []
def atk_handler(signum, frame):
    f = frame
    while f is not None:
        fg = f.f_globals
        if any(k in fg for k in ("_AUDIT_GLOBALS", "_CEDAR_TOKEN", "_WD_ACTIVE", "_AUDIT_DENY_ARMED", "_GATE_TL")):
            leaked.append((f.f_code.co_name, list(fg.keys())[:5]))
        f = f.f_back
    try:
        sys.audit("benign.signal_ping")
        with open("allowed_doc.txt", "r", encoding="utf-8") as af:
            af.read(4)
    except Exception:
        pass

signal.signal(signal.SIGINT, atk_handler)
stop = False
def bomber():
    while not stop:
        try:
            _thread.interrupt_main()
        except Exception:
            pass
        time.sleep(0.0005)

t = threading.Thread(target=bomber, daemon=True)
t.start()
try:
    for i in range(600):
        try:
            with open("secret_forbid.txt", "r") as f:
                raise AssertionError(f"BYPASS_READ iter={{i}}: {{f.read()}}")
        except PermissionError:
            pass
    for i in range(150):
        try:
            with open({out_sig:?}, "w") as f:
                f.write("PWN_SIG")
            raise AssertionError(f"BYPASS_WRITE iter={{i}}")
        except PermissionError:
            pass
    for i in range(25):
        try:
            os.system("cmd /c echo PWN_SIG")
            raise AssertionError(f"BYPASS_SYS iter={{i}}")
        except PermissionError:
            pass
finally:
    stop = True
    t.join(timeout=2.0)

assert not leaked, f"LEAKED_INTERNAL_FRAMES: {{leaked}}"
print("ITER9_SIG_NO_BYPASS_OK")
"#,
            out_sig = outside_sig_file.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out_sig_atk = Command::new(octopus_bin())
        .args([
            "run",
            "--timeout",
            "120",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            sig_atk_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter9 sig attack probe");
    let sig_atk_stdout = String::from_utf8_lossy(&out_sig_atk.stdout);
    let sig_atk_stderr = String::from_utf8_lossy(&out_sig_atk.stderr);
    assert!(
        !outside_sig_file.exists(),
        "signal attack must never write outside allow_write"
    );
    assert!(
        !sig_atk_stdout.contains("LEAKED_INTERNAL_FRAMES")
            && !sig_atk_stderr.contains("LEAKED_INTERNAL_FRAMES")
            && !sig_atk_stderr.contains("BYPASS_"),
        "signal attack leaked or bypassed: exit={:?} stdout={} stderr={}",
        out_sig_atk.status.code(),
        sig_atk_stdout,
        sig_atk_stderr
    );
    assert!(
        out_sig_atk.status.success() && sig_atk_stdout.contains("ITER9_SIG_NO_BYPASS_OK"),
        "unexpected signal attack outcome: exit={:?} stdout={} stderr={}",
        out_sig_atk.status.code(),
        sig_atk_stdout,
        sig_atk_stderr
    );

    // 4. Watchdog tamper tests on _SIGNAL_GLOBALS and signal/_signal attributes
    for (idx, tamper_expr) in [
        "import signal\ndict.__setitem__(signal.signal.__globals__, '_INTERNAL_GLOBALS_IDS', frozenset())\nopen('sig_tamper1.txt', 'w').write('FAIL')",
        "import signal\ndict.__setitem__(signal.signal.__globals__, '_EXTRA_SIG', 1)\nopen('sig_tamper2.txt', 'w').write('FAIL')",
        "import signal\ndict.__setitem__(signal.signal.__globals__, '__warningregistry__', {})\nopen('sig_tamper3.txt', 'w').write('FAIL')",
        "import signal\nsignal.signal = lambda *a: None\nopen('sig_tamper4.txt', 'w').write('FAIL')",
        "import _signal\n_signal.signal = lambda *a: None\nopen('sig_tamper5.txt', 'w').write('FAIL')",
        "import signal\nsignal.getsignal = lambda *a: None\nopen('sig_tamper6.txt', 'w').write('FAIL')",
        "import _signal\n_signal.getsignal = lambda *a: None\nopen('sig_tamper7.txt', 'w').write('FAIL')",
    ]
    .iter()
    .enumerate()
    {
        let wd_script = ws.path().join(format!("sig_wd_tamper_{}.py", idx));
        std::fs::write(&wd_script, tamper_expr).unwrap();
        let out_wd = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_path.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                wd_script.to_str().unwrap(),
            ])
            .output()
            .expect("run signal watchdog tamper probe");
        assert!(
            !out_wd.status.success(),
            "signal watchdog tamper case {} must terminate immediately (exit={:?})",
            idx,
            out_wd.status.code()
        );
        assert!(!ws.path().join(format!("sig_tamper{}.txt", idx + 1)).exists());
    }
}

#[test]
fn test_iteration10_audit_and_sqlite_exact_type_hardening() {
    let py = find_python();
    let ws = TempDirGuard::new("iter10_hardening");
    let outside = TempDirGuard::new("iter10_outside");
    std::fs::write(ws.path().join("allowed.txt"), "ALLOWED_DATA\n").unwrap();
    std::fs::write(ws.path().join("secret_forbid.txt"), "TOP_SECRET\n").unwrap();

    let pol_path = ws.path().join("policy.json");
    std::fs::write(
        &pol_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "sh"] },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": ["secret_forbid.txt", outside.path()]
            }
        })
        .to_string(),
    )
    .unwrap();

    let outside_file = outside.path().join("iter10_escape.txt");
    let probe_script = ws.path().join("iter10_probe.py");
    std::fs::write(
        &probe_script,
        format!(
            r#"import os, sqlite3, sys

captured = {{}}
def scan_tb(tag):
    try:
        1 / 0
    except ZeroDivisionError as e:
        f = e.__traceback__.tb_frame
        while f is not None:
            fg = f.f_globals
            if any(k in fg for k in (
                "_AUDIT_GLOBALS", "_ORIG_SQLITE_CONNECT", "_ORIG_SQLITE_CONN",
                "_ORIG_SQLITE_CURSOR", "_CEDAR_TOKEN", "_AUDIT_DENY_ARMED",
                "_WATCHDOG_GLOBALS_REF", "_ORIG_SIGNAL_SIGNAL",
            )):
                captured[tag + "_audit_globals"] = True
            for loc_k in ("raw", "raw_cur"):
                if loc_k in f.f_locals:
                    captured[tag + "_" + loc_k] = type(f.f_locals[loc_k]).__name__
            f = f.f_back

class EvilMode(str):
    def __contains__(self, item):
        scan_tb("evil_mode")
        return False

class EvilFlags(int):
    def __and__(self, other):
        scan_tb("evil_flags")
        return 0

class EvilBool:
    def __bool__(self):
        scan_tb("evil_bool")
        return False

class FakePathObj:
    @property
    def __class__(self):
        scan_tb("fake_path_class")
        return str

class FakeTarget:
    @property
    def __class__(self):
        scan_tb("backup_target_class")
        return sqlite3.Connection

class EvilStr(str):
    def __eq__(self, other):
        scan_tb("evil_str_eq")
        return super().__eq__(other)
    def __hash__(self):
        scan_tb("evil_str_hash")
        return super().__hash__()

class EvilEq:
    def __eq__(self, other):
        scan_tb("evil_conv_eq")
        return False

class EvilMeta(type):
    def __eq__(self, other):
        scan_tb("evil_meta_eq")
        return False

class MetaObj(metaclass=EvilMeta):
    pass

# 1. sys.audit("open", ...) exact type checks
for label, call in (
    ("evil_mode", lambda: sys.audit("open", "allowed.txt", EvilMode("r"), 0)),
    ("evil_flags_int", lambda: sys.audit("open", "allowed.txt", 0, EvilFlags(0))),
    ("evil_flags_none_mode", lambda: sys.audit("open", "allowed.txt", None, EvilFlags(0))),
    ("evil_bool_load_ext", lambda: sys.audit("sqlite3.enable_load_extension", None, EvilBool())),
):
    try:
        call()
        raise AssertionError(f"{{label}} must raise PermissionError")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

# Non-string path with @property __class__ and metaclass __eq__ must not run dunders
sys.audit("open", FakePathObj(), "r", 0)
sys.audit("open", MetaObj(), "r", 0)

# 2. SQLite backup target @property __class__ and EvilStr attribute names
con = sqlite3.connect(":memory:")
con.execute("CREATE TABLE t(x INT)")
con.execute("INSERT INTO t VALUES (42)")
con.commit()
cur = con.cursor()

try:
    con.backup(FakeTarget())
    raise AssertionError("con.backup(FakeTarget()) must fail")
except TypeError:
    pass

for label, call in (
    ("con_getattr_evil_str", lambda: getattr(con, EvilStr("commit"))),
    ("cur_getattr_evil_str", lambda: getattr(cur, EvilStr("close"))),
    ("con_setattr_evil_str", lambda: setattr(con, EvilStr("row_factory"), None)),
    ("cur_setattr_evil_str", lambda: setattr(cur, EvilStr("arraysize"), 10)),
):
    try:
        call()
        raise AssertionError(f"{{label}} must raise PermissionError")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

# Positive controls: valid Connection subclass backup & normal sqlite3 ops still succeed
class SubConn(sqlite3.Connection):
    pass

sub_bak = sqlite3.connect(":memory:", factory=SubConn)
con.backup(sub_bak)
assert sub_bak.execute("SELECT x FROM t").fetchone() == (42,)
sub_bak.close()

# Tampering sqlite3.converters with EvilEq must fail closed without invoking __eq__ in _AUDIT_GLOBALS
orig_date_conv = sqlite3.converters.get("DATE")
try:
    sqlite3.converters["DATE"] = EvilEq()
    try:
        con.execute("SELECT 1")
        raise AssertionError("modified sqlite3.converters must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)
finally:
    if orig_date_conv is not None:
        sqlite3.converters["DATE"] = orig_date_conv

cur.close()
con.close()

# Policy containment still intact
try:
    with open({out_p:?}, "w") as wf:
        wf.write("ESCAPED")
    raise AssertionError("outside write must still be denied")
except PermissionError:
    pass

assert captured == {{}}, f"traceback capture leaked internals: {{captured}}"
print("ITER10_EXACT_TYPE_HARDENED_OK")
"#,
            out_p = outside_file.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            probe_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter10 probe");

    assert!(
        out.status.success(),
        "iter10 probe failed (exit={:?}): stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ITER10_EXACT_TYPE_HARDENED_OK"));
    assert!(!outside_file.exists());
}

#[test]
fn test_iteration11_pathlib_env_signal_and_getframe_hardening() {
    let py = find_python();
    let ws = TempDirGuard::new("iter11_hardening");
    let outside = TempDirGuard::new("iter11_outside");
    std::fs::write(ws.path().join("allowed.txt"), "ALLOWED_11\n").unwrap();
    std::fs::write(ws.path().join("secret_forbid.txt"), "TOP_SECRET_11\n").unwrap();
    std::fs::create_dir_all(ws.path().join("sub")).unwrap();

    let pol_path = ws.path().join("policy.json");
    std::fs::write(
        &pol_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "sh"] },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": ["secret_forbid.txt", outside.path()]
            }
        })
        .to_string(),
    )
    .unwrap();

    let outside_db = outside.path().join("iter11_pwned.db");
    let outside_txt = outside.path().join("iter11_pwned.txt");
    let probe_script = ws.path().join("iter11_probe.py");
    std::fs::write(
        &probe_script,
        format!(
            r#"import _signal, _thread, os, pathlib, signal, sqlite3, subprocess, sys, warnings

captured = {{}}
def scan_tb(tag):
    try:
        1 / 0
    except ZeroDivisionError as e:
        f = e.__traceback__.tb_frame
        while f is not None:
            fg = f.f_globals
            if any(k in fg for k in (
                "_AUDIT_GLOBALS", "_ORIG_SQLITE_CONNECT", "_ORIG_SQLITE_CONN",
                "_ORIG_SQLITE_CURSOR", "_CEDAR_TOKEN", "_AUDIT_DENY_ARMED",
                "_WATCHDOG_GLOBALS_REF", "_ORIG_SIGNAL_SIGNAL", "_ORIG_LIST2CMDLINE",
            )):
                captured[tag + "_globals"] = True
            f = f.f_back

# 1. Legitimate pathlib sqlite3 & open & list2cmdline work (single-arg, multi-arg, :memory:)
c_mem = sqlite3.connect(pathlib.Path(":memory:"))
c_mem.execute("CREATE TABLE m(x INT)")
c_mem.execute("INSERT INTO m VALUES (7)")
assert c_mem.execute("SELECT x FROM m").fetchone() == (7,)
c_mem.close()

c_sub = sqlite3.connect(pathlib.Path("sub", "multi.sqlite"))
c_sub.execute("CREATE TABLE t(v TEXT)")
c_sub.execute("INSERT INTO t VALUES ('MULTI_OK')")
c_sub.commit()
assert c_sub.execute("SELECT v FROM t").fetchone() == ("MULTI_OK",)
c_sub.close()

with open(pathlib.Path("allowed.txt"), "r", encoding="utf-8") as af:
    assert af.read().strip() == "ALLOWED_11"

cmd_str = subprocess.list2cmdline([pathlib.Path("sub", "multi.sqlite")])
assert "multi.sqlite" in cmd_str, cmd_str

# Outside pathlib sqlite3.connect still denied
try:
    sqlite3.connect(pathlib.Path({out_db:?}))
    raise AssertionError("outside pathlib sqlite3.connect must be denied")
except PermissionError as pe:
    assert "blocked_by_octopus_policy" in str(pe), str(pe)

# 2. EvilMetaDict (@property def __dict__) must not execute inside _AUDIT_GLOBALS
class EvilMetaDict(type):
    @property
    def __dict__(cls):
        scan_tb("evil_meta_dict")
        return {{}}

class TrapDictObj(metaclass=EvilMetaDict):
    pass

sys.audit("open", TrapDictObj(), "r", 0)
try:
    sqlite3.connect(TrapDictObj())
    raise AssertionError("sqlite3.connect(TrapDictObj()) must be denied")
except PermissionError as pe:
    assert "blocked_by_octopus_policy" in str(pe), str(pe)

# 3. FakeClsDict (EvilKey("__fspath__")) must not run __eq__ and must be denied
class EvilKey(str):
    def __eq__(self, other):
        scan_tb("evil_key_eq")
        return super().__eq__(other)
    def __hash__(self):
        return super().__hash__()

class FakeClsDict:
    locals()[EvilKey("__fspath__")] = lambda self: "secret_forbid.txt"

for fn in (
    lambda: sys.audit("open", FakeClsDict(), "r", 0),
    lambda: open(FakeClsDict(), "r"),
):
    try:
        fn()
        raise AssertionError("FakeClsDict must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

# 4. Path.__fspath__ = EvilDesc(), PurePath._format_parsed_parts monkeypatch, _raw_paths & _str tampering
class EvilPart:
    def replace(self, *a):
        scan_tb("evil_raw_part_replace")
        return "allowed.txt"

p_bad_raw = pathlib.Path("allowed.txt")
p_bad_raw._raw_paths = [EvilPart()]
for fn in (
    lambda: sys.audit("open", p_bad_raw, "r", 0),
    lambda: sqlite3.connect(p_bad_raw),
    lambda: subprocess.list2cmdline([p_bad_raw]),
):
    try:
        fn()
        raise AssertionError("tampered _raw_paths must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

p_bad_str = pathlib.Path("secret_forbid.txt")
p_bad_str._str = "allowed.txt"
for fn in (
    lambda: sys.audit("open", p_bad_str, "r", 0),
    lambda: sqlite3.connect(p_bad_str),
    lambda: subprocess.list2cmdline([p_bad_str]),
):
    try:
        fn()
        raise AssertionError("mismatched _str slot must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

p_bad_str2 = pathlib.Path("allowed.txt")
p_bad_str2._str = "secret_forbid.txt"
try:
    open(p_bad_str2, "r")
    raise AssertionError("open() with _str pointing to secret must be denied")
except PermissionError as pe:
    assert "blocked_by_octopus_policy" in str(pe), str(pe)

orig_fmt = pathlib.PurePath._format_parsed_parts
try:
    def trap_fmt(*a):
        scan_tb("purepath_fmt_trap")
        return "secret_forbid.txt"
    pathlib.PurePath._format_parsed_parts = classmethod(trap_fmt)
    for fn in (
        lambda: sys.audit("open", pathlib.Path("allowed.txt"), "r", 0),
        lambda: sqlite3.connect(pathlib.Path(":memory:")),
        lambda: open(pathlib.Path("allowed.txt"), "r"),
        lambda: subprocess.list2cmdline([pathlib.Path("allowed.txt")]),
    ):
        try:
            fn()
            raise AssertionError("patched PurePath._format_parsed_parts must be denied")
        except PermissionError as pe:
            assert "blocked_by_octopus_policy" in str(pe), str(pe)
finally:
    pathlib.PurePath._format_parsed_parts = orig_fmt

class EvilDesc:
    def __get__(self, obj, objtype=None):
        scan_tb("evil_path_desc")
        return "allowed.txt"

orig_path_fspath = pathlib.Path.__dict__.get("__fspath__")
try:
    pathlib.Path.__fspath__ = EvilDesc()
    for fn in (
        lambda: sys.audit("open", pathlib.Path("allowed.txt"), "r", 0),
        lambda: sqlite3.connect(pathlib.Path(":memory:")),
        lambda: subprocess.list2cmdline([pathlib.Path("allowed.txt")]),
    ):
        try:
            fn()
            raise AssertionError("tampered Path.__fspath__ descriptor must be denied")
        except PermissionError as pe:
            assert "blocked_by_octopus_policy" in str(pe), str(pe)
finally:
    if orig_path_fspath is None:
        delattr(pathlib.Path, "__fspath__")
    else:
        pathlib.Path.__fspath__ = orig_path_fspath

# 5. SubFloat & SneakyFloat timeout coercion
class SubFloat(float):
    pass

class SneakyFloat:
    def __float__(self):
        scan_tb("sneaky_float")
        return SubFloat(1.5)

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    c_flt = sqlite3.connect(":memory:", timeout=SneakyFloat())
    c_flt.close()

# 6. os.environ._data tampering (EvilMap & non-exact dict entries)
class EvilMap(dict):
    def __iter__(self):
        scan_tb("evil_env_iter")
        return super().__iter__()
    def __getitem__(self, k):
        scan_tb("evil_env_getitem")
        return super().__getitem__(k)

orig_env_data = os.environ._data
try:
    os.environ._data = EvilMap(orig_env_data)
    try:
        subprocess.run([sys.executable, "-c", "pass"], check=True)
        raise AssertionError("tampered os.environ._data must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)
finally:
    os.environ._data = orig_env_data

class EvilStr(str):
    def upper(self):
        scan_tb("evil_env_key_upper")
        return super().upper()

os.environ._data["OCTO_EVIL_VAL"] = EvilStr("bad")
try:
    try:
        subprocess.run([sys.executable, "-c", "pass"], check=True)
        raise AssertionError("non-exact os.environ._data value must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)
finally:
    os.environ._data.pop("OCTO_EVIL_VAL", None)

# 7. Caught PermissionError/ValueError -> signal/getsignal/_signal/interrupt_main storm must NOT crash
try:
    open({out_txt:?}, "r")
    raise AssertionError("outside read must be denied")
except PermissionError:
    pass

assert signal.getsignal(signal.SIGINT) is not None
assert _signal.getsignal(signal.SIGINT) is not None

sig_hits = []
def sig_handler(signum, frame):
    try:
        sys._getframe(1)
        captured["sig_getframe1"] = True
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)
    with open("allowed.txt", "r", encoding="utf-8") as af:
        sig_hits.append(af.read().strip())

prev_h = signal.signal(signal.SIGINT, sig_handler)
try:
    signal.signal(-999, sig_handler)
    raise AssertionError("invalid signal number must raise ValueError")
except ValueError:
    pass
assert signal.getsignal(signal.SIGINT) is sig_handler

try:
    open("secret_forbid.txt", "r")
    raise AssertionError("secret read must be denied")
except PermissionError:
    pass

_thread.interrupt_main()
for _ in range(200000):
    if sig_hits:
        break

for _ in range(20):
    try:
        open("secret_forbid.txt", "r")
    except PermissionError:
        pass
    _thread.interrupt_main()
    for _ in range(50000):
        pass

assert len(sig_hits) >= 1 and all(x == "ALLOWED_11" for x in sig_hits), sig_hits
assert _signal.signal(signal.SIGINT, prev_h) is sig_handler

# 8. sys._getframe(1) denied in row_factory (while warnings.warn works) & closed con.iterdump() safe
con_rf = sqlite3.connect(":memory:")
con_rf.execute("CREATE TABLE r(v INT)")
con_rf.execute("INSERT INTO r VALUES (99)")
def rf_chk(cur, row):
    warnings.warn("iter11_rf_warn", UserWarning)
    try:
        sys._getframe(1)
        captured["rf_getframe1"] = True
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)
    return row
con_rf.row_factory = rf_chk
assert con_rf.execute("SELECT v FROM r").fetchone() == (99,)
con_rf.close()

try:
    list(con_rf.iterdump())
    raise AssertionError("closed iterdump must raise ProgrammingError")
except sqlite3.ProgrammingError as pe:
    assert pe.__cause__ is None and pe.__context__ is None
    tb = pe.__traceback__
    while tb is not None:
        fg = tb.tb_frame.f_globals
        assert "_AUDIT_GLOBALS" not in fg and "_CEDAR_TOKEN" not in fg and "_ORIG_SQLITE_CONNECT" not in fg
        tb = tb.tb_next

assert captured == {{}}, f"captured leaks: {{captured}}"
print("ITER11_ALL_HARDENED_OK")
"#,
            out_db = outside_db.to_string_lossy().to_string(),
            out_txt = outside_txt.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            probe_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter11 probe");

    assert!(
        out.status.success(),
        "iter11 probe failed (exit={:?}): stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ITER11_ALL_HARDENED_OK"));
    assert!(!outside_db.exists());
    assert!(!outside_txt.exists());
}

#[test]
fn test_iteration12_expanduser_settrace_and_sig_hardening() {
    struct DirCleanup(std::path::PathBuf);
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let py = find_python();
    let ws = TempDirGuard::new("iter12_hardening");
    let outside = TempDirGuard::new("iter12_outside");
    std::fs::write(ws.path().join("allowed.txt"), "ALLOWED_12\n").unwrap();
    std::fs::write(ws.path().join("secret_forbid.txt"), "TOP_SECRET_12\n").unwrap();

    let home_dir = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .expect("USERPROFILE or HOME must be set");
    let tilde_rel = format!(
        "oct_iter12_tilde_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let tilde_abs = home_dir.join(&tilde_rel);
    std::fs::create_dir_all(&tilde_abs).unwrap();
    let _tilde_guard = DirCleanup(tilde_abs.clone());
    let tilde_secret = tilde_abs.join("secret.txt");
    std::fs::write(&tilde_secret, "TILDE_SECRET_12\n").unwrap();

    let pol_path = ws.path().join("policy.json");
    std::fs::write(
        &pol_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "sh"] },
            "filesystem": {
                "allow_read": [ws.path()],
                "allow_write": [ws.path()],
                "deny": ["secret_forbid.txt", format!("~/{}", tilde_rel), outside.path()]
            }
        })
        .to_string(),
    )
    .unwrap();

    let outside_db = outside.path().join("iter12_pwned.db");
    let outside_txt = outside.path().join("iter12_pwned.txt");
    let probe_script = ws.path().join("iter12_probe.py");
    std::fs::write(
        &probe_script,
        format!(
            r#"import _thread, os, pathlib, signal, sqlite3, sys

captured = {{}}
def scan_tb(tag):
    try:
        1 / 0
    except ZeroDivisionError as e:
        f = e.__traceback__.tb_frame
        while f is not None:
            fg = f.f_globals
            if fg.get("__name__", "").startswith("__octopus_") or any(k in fg for k in (
                "_AUDIT_GLOBALS", "_ORIG_SQLITE_CONNECT", "_ORIG_SQLITE_CONN",
                "_ORIG_SQLITE_CURSOR", "_CEDAR_TOKEN", "_AUDIT_DENY_ARMED",
                "_WATCHDOG_GLOBALS_REF", "_ORIG_SYS_SETTRACE",
            )):
                captured[tag + "_globals"] = fg.get("__name__", "unknown")
            f = f.f_back

# 1. filesystem.deny ~/... resists os.environ["USERPROFILE"] / os.environ["HOME"] tampering
tilde_secret = {tilde_sec:?}
for label in ("initial", "after_env_override"):
    if label == "after_env_override":
        os.environ["USERPROFILE"] = r"C:\fake_home_dir_999"
        os.environ["HOME"] = "/tmp/fake_home_dir_999"
    try:
        open(tilde_secret, "r").read()
        raise AssertionError(f"filesystem.deny ~/... bypassed ({{label}})")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

# 2. os.environ._data / encodekey / decodevalue tampering + open("~/...") never enters _AUDIT_GLOBALS
env_hits = []
class EvilEnvMap(dict):
    def __getitem__(self, k):
        env_hits.append(("getitem", k))
        scan_tb("evil_env_map")
        return super().__getitem__(k)

orig_ed = os.environ._data
orig_enc = getattr(os.environ, "encodekey", None)
orig_dec = getattr(os.environ, "decodevalue", None)
try:
    os.environ._data = EvilEnvMap(orig_ed)
    os.environ.encodekey = lambda k: (env_hits.append(("encodekey", k)), scan_tb("encodekey"), k)[2]
    os.environ.decodevalue = lambda v: (env_hits.append(("decodevalue", v)), scan_tb("decodevalue"), v)[2]
    for target in ("~/allowed.txt", pathlib.Path("~/allowed.txt")):
        try:
            open(target, "r")
        except (FileNotFoundError, PermissionError, OSError):
            pass
finally:
    os.environ._data = orig_ed
    if orig_enc is not None:
        os.environ.encodekey = orig_enc
    if orig_dec is not None:
        os.environ.decodevalue = orig_dec

assert env_hits == [], f"os.environ hooks executed during open(~/...): {{env_hits}}"

# Policy still blocks denied read/write/command after tilde probes
for call in (
    lambda: open("secret_forbid.txt", "r"),
    lambda: open({out_txt:?}, "w"),
    lambda: os.system("cmd /c echo PWN"),
):
    try:
        call()
        raise AssertionError("policy action must remain denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

# 3. sys.settrace / sys.setprofile / sys.monitoring isolation + PEP 667 FrameLocalsProxy SQLite protection
trace_internal_hits = []
conform_calls = []

class EvilConform:
    def __conform__(self, proto):
        conform_calls.append(proto)
        scan_tb("evil_conform")
        return "CONFORM_PWNED"

def tracer(frame, event, arg):
    f = frame
    while f is not None:
        fg = f.f_globals
        if fg.get("__name__", "").startswith("__octopus_") or any(
            k in fg for k in ("_AUDIT_GLOBALS", "_ORIG_SQLITE_CONNECT", "_CEDAR_TOKEN", "_ORIG_SYS_SETTRACE")
        ):
            trace_internal_hits.append((event, fg.get("__name__"), f.f_code.co_name))
        f = f.f_back
    if event == "line" and "clean_args" in frame.f_locals:
        frame.f_locals["clean_args"] = ("INSERT INTO t VALUES (?)", (EvilConform(),))
    return tracer

def profiler(frame, event, arg):
    f = frame
    while f is not None:
        fg = f.f_globals
        if fg.get("__name__", "").startswith("__octopus_"):
            trace_internal_hits.append(("prof:" + event, fg.get("__name__"), f.f_code.co_name))
        f = f.f_back

con = sqlite3.connect(":memory:")
con.execute("CREATE TABLE t(x TEXT)")

sys.settrace(tracer)
assert sys.gettrace() is tracer
try:
    con.execute("INSERT INTO t VALUES (?)", ("safe",))
finally:
    sys.settrace(None)
assert sys.gettrace() is None

sys.setprofile(profiler)
assert sys.getprofile() is profiler
try:
    con.execute("SELECT x FROM t").fetchall()
finally:
    sys.setprofile(None)
assert sys.getprofile() is None

# Monitoring callback also skips internal __octopus_*__ code objects
mon_internal_hits = []
tool_id = 3
sys.monitoring.use_tool_id(tool_id, "oct_probe12")
try:
    def mon_cb(code, offset):
        if "octopus" in (code.co_filename or "") or code.co_name in ("execute", "_guarded_sqlite_connect", "_octopus_audit_check"):
            mon_internal_hits.append((code.co_filename, code.co_name))
    prev_cb = sys.monitoring.register_callback(tool_id, sys.monitoring.events.PY_START, mon_cb)
    assert prev_cb is None
    sys.monitoring.set_events(tool_id, sys.monitoring.events.PY_START)
    try:
        con.execute("SELECT COUNT(*) FROM t").fetchone()
    finally:
        sys.monitoring.set_events(tool_id, 0)
        old_cb = sys.monitoring.register_callback(tool_id, sys.monitoring.events.PY_START, None)
        assert old_cb is mon_cb
finally:
    sys.monitoring.free_tool_id(tool_id)

assert trace_internal_hits == [], f"tracer/profiler observed internal frames: {{trace_internal_hits}}"
assert mon_internal_hits == [], f"sys.monitoring observed internal codes: {{mon_internal_hits}}"
assert conform_calls == [], f"EvilConform.__conform__ executed: {{conform_calls}}"

# Direct sys.audit("sys.settrace") forgery denied
for ev_name in ("sys.settrace", "sys.setprofile", "sys.monitoring.register_callback"):
    try:
        sys.audit(ev_name)
        raise AssertionError(f"direct sys.audit({{ev_name}}) must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

# 4. _thread.interrupt_main() inside row_factory suppresses internal f_back frames
sig_fback_leaks = []
sig_seen = []
def rf_sig_handler(signum, frame):
    sig_seen.append(signum)
    f = frame
    while f is not None:
        fg = f.f_globals
        if fg.get("__name__", "").startswith("__octopus_"):
            sig_fback_leaks.append((fg.get("__name__"), f.f_code.co_name))
        f = f.f_back

prev_sig = signal.signal(signal.SIGINT, rf_sig_handler)
def rf_interrupt(cur, row):
    _thread.interrupt_main()
    x = 0
    for _ in range(10000):
        x += 1
    return row
con.row_factory = rf_interrupt
try:
    con.execute("SELECT x FROM t").fetchall()
finally:
    con.row_factory = None
    signal.signal(signal.SIGINT, prev_sig)
assert sig_fback_leaks == [], f"signal handler observed internal f_back frames: {{sig_fback_leaks}}"

# 5. con.close(); list(con.iterdump()) strips cursor & _iterdump frames cleanly
con.close()
try:
    list(con.iterdump())
    raise AssertionError("closed iterdump must raise ProgrammingError")
except sqlite3.ProgrammingError as pe:
    assert pe.__cause__ is None and pe.__context__ is None
    tb_frames = []
    tb = pe.__traceback__
    while tb is not None:
        tb_frames.append((tb.tb_frame.f_globals.get("__name__"), tb.tb_frame.f_code.co_name))
        tb = tb.tb_next
    assert ("__octopus_sqlite__", "cursor") not in tb_frames, tb_frames
    assert ("sqlite3.dump", "_iterdump") not in tb_frames, tb_frames

# Outside DB write still denied
try:
    sqlite3.connect({out_db:?})
    raise AssertionError("outside sqlite3.connect must be denied")
except PermissionError as pe:
    assert "blocked_by_octopus_policy" in str(pe), str(pe)

assert captured == {{}}, f"captured leaks: {{captured}}"
print("ITER12_ALL_HARDENED_OK")
"#,
            tilde_sec = tilde_secret.to_string_lossy().to_string(),
            out_txt = outside_txt.to_string_lossy().to_string(),
            out_db = outside_db.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            probe_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter12 probe");

    assert!(
        out.status.success(),
        "iter12 probe failed (exit={:?}): stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ITER12_ALL_HARDENED_OK"));
    assert!(!outside_db.exists());
    assert!(!outside_txt.exists());

    // Watchdog tamper tests on sys.settrace/gettrace/setprofile/getprofile/monitoring & _TRACE_GLOBALS
    for (idx, tamper_expr) in [
        "import sys\nsys.settrace = lambda *a: None\nopen('tr_tamper1.txt', 'w').write('FAIL')",
        "import sys\nsys.gettrace = lambda: None\nopen('tr_tamper2.txt', 'w').write('FAIL')",
        "import sys\nsys.setprofile = lambda *a: None\nopen('tr_tamper3.txt', 'w').write('FAIL')",
        "import sys\nsys.monitoring.register_callback = lambda *a: None\nopen('tr_tamper4.txt', 'w').write('FAIL')",
        "import sys\ndict.__setitem__(sys.settrace.__globals__, '_INTERNAL_GLOBALS_IDS', frozenset())\nopen('tr_tamper5.txt', 'w').write('FAIL')",
    ]
    .iter()
    .enumerate()
    {
        let wd_script = ws.path().join(format!("tr_wd_tamper_{}.py", idx));
        std::fs::write(&wd_script, tamper_expr).unwrap();
        let out_wd = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_path.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                &py,
                wd_script.to_str().unwrap(),
            ])
            .output()
            .expect("run trace watchdog tamper probe");
        assert!(
            !out_wd.status.success(),
            "trace watchdog tamper case {} must terminate immediately (exit={:?})",
            idx,
            out_wd.status.code()
        );
        assert!(!ws.path().join(format!("tr_tamper{}.txt", idx + 1)).exists());
    }
}

#[test]
fn test_iteration13_verbatim_and_monitoring_hardening() {
    struct DirCleanup(std::path::PathBuf);
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let py = find_python();
    let parent_dir = TempDirGuard::new("iter13_root");
    let ws_dir = parent_dir.path().join("work");
    let rel_secret_dir = parent_dir.path().join("rel_secret");
    std::fs::create_dir_all(&ws_dir).unwrap();
    std::fs::create_dir_all(&rel_secret_dir).unwrap();
    let outside = TempDirGuard::new("iter13_outside");

    std::fs::write(ws_dir.join("allowed.txt"), "ALLOWED_13\n").unwrap();
    let rel_secret_file = rel_secret_dir.join("secret.txt");
    std::fs::write(&rel_secret_file, "REL_SECRET_13\n").unwrap();
    let outside_txt = outside.path().join("iter13_pwned.txt");
    let outside_db = outside.path().join("iter13_pwned.db");

    let home_dir = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .expect("USERPROFILE or HOME must be set");
    let tilde_rel = format!(
        "oct_iter13_tilde_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let tilde_abs = home_dir.join(&tilde_rel);
    std::fs::create_dir_all(&tilde_abs).unwrap();
    let _tilde_guard = DirCleanup(tilde_abs.clone());
    let tilde_secret = tilde_abs.join("secret.txt");
    std::fs::write(&tilde_secret, "TILDE_SECRET_13\n").unwrap();

    let pol_path = ws_dir.join("policy.json");
    std::fs::write(
        &pol_path,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "sh"] },
            "filesystem": {
                "allow_read": [&ws_dir],
                "allow_write": [&ws_dir],
                "deny": ["../rel_secret", format!("~/{}", tilde_rel), outside.path()]
            }
        })
        .to_string(),
    )
    .unwrap();

    let probe_script = ws_dir.join("iter13_probe.py");
    std::fs::write(
        &probe_script,
        format!(
            r#"import os, pathlib, sqlite3, subprocess, sys

captured = {{}}
def scan_tb(tag):
    try:
        1 / 0
    except ZeroDivisionError as e:
        f = e.__traceback__.tb_frame
        while f is not None:
            fg = f.f_globals
            if fg.get("__name__", "").startswith("__octopus_"):
                captured[tag + "_globals"] = fg.get("__name__")
            f = f.f_back

# 1. Windows \\?\ verbatim paths cannot bypass filesystem.deny (~/... and ../...) or allow_write
if os.name == "nt":
    tilde_verb = "\\\\?\\" + os.path.abspath({tilde_sec:?})
    rel_verb = "\\\\?\\" + os.path.abspath({rel_sec:?})
    out_verb = "\\\\?\\" + os.path.abspath({out_txt:?})
    out_db_verb = "\\\\?\\" + os.path.abspath({out_db:?})
    for label, call in (
        ("open_tilde_verb", lambda: open(tilde_verb, "r")),
        ("path_tilde_verb", lambda: open(pathlib.Path(tilde_verb), "r")),
        ("listdir_tilde_verb", lambda: os.listdir(os.path.dirname(tilde_verb))),
        ("open_rel_verb", lambda: open(rel_verb, "r")),
        ("listdir_rel_verb", lambda: os.listdir(os.path.dirname(rel_verb))),
        ("write_outside_verb", lambda: open(out_verb, "w")),
        ("sqlite_outside_verb", lambda: sqlite3.connect(out_db_verb)),
    ):
        try:
            call()
            raise AssertionError(f"{{label}} must be denied")
        except PermissionError as pe:
            assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

    # Allowed workspace verbatim write/read still works cleanly
    ok_verb = "\\\\?\\" + os.path.abspath("verb_allowed_out.txt")
    with open(ok_verb, "w", encoding="utf-8") as wf:
        wf.write("VERB_WRITE_OK")
    with open(ok_verb, "r", encoding="utf-8") as rf:
        assert rf.read() == "VERB_WRITE_OK"

# 2. _TRACE_GLOBALS does not expose raw _ORIG_SYS_* / _ORIG_MON_* callables
tg = sys.settrace.__globals__
for raw_k in (
    "_ORIG_SYS_SETTRACE", "_ORIG_SYS_GETTRACE", "_ORIG_SYS_SETPROFILE",
    "_ORIG_SYS_GETPROFILE", "_ORIG_SYS_SETTRACEALL", "_ORIG_SYS_SETPROFILEALL",
    "_ORIG_MON_REGISTER", "_ORIG_MON_SET_LOCAL",
):
    assert raw_k not in tg, f"{{raw_k}} must not be in _TRACE_GLOBALS"

# 3. LazyCallable in sys.monitoring.register_callback cannot bypass _MON_CB_CLS
E = sys.monitoring.events
M = sys.monitoring
lazy_hits = []
class LazyCallable:
    pass

lazy_obj = LazyCallable()
tid = 3
M.use_tool_id(tid, "oct_iter13_mon")
try:
    M.register_callback(tid, E.PY_START, lazy_obj)
    LazyCallable.__call__ = lambda self, code, offset: (
        lazy_hits.append((code.co_filename, code.co_name))
        if ((code.co_filename or "").startswith("<octopus") or code.co_name in ("_guarded_sqlite_connect", "_c_timeout", "<genexpr>"))
        else None
    )
    M.set_events(tid, E.PY_START)
    con_l = sqlite3.connect(":memory:", timeout=5.0)
    con_l.execute("SELECT ?", (1,)).fetchall()
    con_l.close()
    M.set_events(tid, 0)
    assert M.register_callback(tid, E.PY_START, None) is lazy_obj
    assert lazy_hits == [], f"LazyCallable observed internal codes: {{lazy_hits}}"

    # 4. EvilIndex.__index__ rejected with TypeError before entering _handle_trace_op
    idx_hits = []
    class EvilIndex:
        def __index__(self):
            idx_hits.append(True)
            scan_tb("evil_index")
            return tid

    for call in (
        lambda: M.register_callback(EvilIndex(), E.PY_START, None),
        lambda: M.register_callback(tid, EvilIndex(), None),
        lambda: M.set_local_events(EvilIndex(), (lambda: 1).__code__, E.PY_START),
        lambda: M.set_local_events(tid, (lambda: 1).__code__, EvilIndex()),
    ):
        try:
            call()
            raise AssertionError("EvilIndex must raise TypeError")
        except TypeError:
            pass
    assert idx_hits == [], f"EvilIndex.__index__ ran: {{idx_hits}}"

    # 5. Nested <genexpr> & nested helper codes are suppressed in sys.monitoring and blocked in set_local_events
    all_mon_hits = []
    def mon_all(code, *rest):
        if (code.co_filename or "").startswith("<octopus"):
            all_mon_hits.append((code.co_filename, code.co_name))

    for ev in (E.PY_START, E.LINE, E.CALL, E.PY_YIELD, E.PY_RESUME, E.PY_RETURN):
        M.register_callback(tid, ev, mon_all)
    M.set_events(tid, E.PY_START | E.LINE | E.CALL | E.PY_YIELD | E.PY_RESUME | E.PY_RETURN)
    con_m = sqlite3.connect(":memory:", timeout=5.0)
    con_m.execute("CREATE TABLE t(x INT)")
    con_m.execute("INSERT INTO t VALUES (?)", (42,))
    assert con_m.execute("SELECT x FROM t").fetchall() == [(42,)]
    con_m.close()
    subprocess.list2cmdline(["echo", "hi"])
    M.set_events(tid, 0)
    for ev in (E.PY_START, E.LINE, E.CALL, E.PY_YIELD, E.PY_RESUME, E.PY_RETURN):
        M.register_callback(tid, ev, None)
    assert all_mon_hits == [], f"sys.monitoring observed nested internal codes: {{all_mon_hits}}"

    # Find a nested <genexpr> code object from _ALL_INTERNAL_CODES and verify set_local_events denies it
    genexpr_code = next(
        c for c in tg["_ALL_INTERNAL_CODES"]
        if c.co_name == "<genexpr>" and c.co_filename == "<octopus_sqlite>"
    )
    try:
        M.set_local_events(tid, genexpr_code, E.PY_START)
        raise AssertionError("set_local_events on internal <genexpr> must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

    # 6. Non-disableable events (C_RETURN, PY_UNWIND, RAISE, EXCEPTION_HANDLED) do NOT crash sqlite3.connect
    non_dis_hits = []
    def mon_non_dis(*args):
        if args and hasattr(args[0], "co_filename") and (args[0].co_filename or "").startswith("<octopus"):
            non_dis_hits.append(args[0].co_name)

    for ev in (E.CALL, E.C_RETURN, E.C_RAISE, E.PY_UNWIND, E.RAISE, E.EXCEPTION_HANDLED):
        M.register_callback(tid, ev, mon_non_dis)
    M.set_events(tid, E.CALL | E.PY_UNWIND | E.RAISE | E.EXCEPTION_HANDLED)
    con_nd = sqlite3.connect(":memory:")
    con_nd.execute("SELECT 1").fetchall()
    con_nd.close()
    M.set_events(tid, 0)
    for ev in (E.CALL, E.C_RETURN, E.C_RAISE, E.PY_UNWIND, E.RAISE, E.EXCEPTION_HANDLED):
        M.register_callback(tid, ev, None)
    assert non_dis_hits == [], f"non-disableable monitoring observed internal codes: {{non_dis_hits}}"

    # 7. _MonCallbackWrapper strips __cause__/__context__ when user monitoring callback raises
    def mon_boom(code, offset):
        try:
            raise ValueError("inner_mon_ctx")
        except ValueError:
            raise RuntimeError("mon_boom_13")

    M.register_callback(tid, E.PY_START, mon_boom)
    M.set_events(tid, E.PY_START)
    try:
        (lambda: 123)()
        raise AssertionError("mon_boom must propagate RuntimeError")
    except RuntimeError as re_err:
        assert str(re_err) == "mon_boom_13"
        assert re_err.__cause__ is None and re_err.__context__ is None
    finally:
        M.set_events(tid, 0)
        M.register_callback(tid, E.PY_START, None)
finally:
    M.free_tool_id(tid)

# 8. sys.settrace (global & local) and sys.setprofile callback exceptions unwind cleanly without PermissionError mask
def target_unwind():
    x = 1
    return x + 1

def global_boom(frame, event, arg):
    raise RuntimeError("trace_global_boom")

sys.settrace(global_boom)
try:
    target_unwind()
    raise AssertionError("global_boom must propagate RuntimeError")
except RuntimeError as re_g:
    assert str(re_g) == "trace_global_boom"
    assert sys.gettrace() is None
finally:
    sys.settrace(None)

def local_boom(frame, event, arg):
    if event == "line":
        raise RuntimeError("trace_local_boom")
    return local_boom

def local_outer(frame, event, arg):
    return local_boom

sys.settrace(local_outer)
try:
    target_unwind()
    raise AssertionError("local_boom must propagate RuntimeError")
except RuntimeError as re_l:
    assert str(re_l) == "trace_local_boom"
    assert sys.gettrace() is None
finally:
    sys.settrace(None)

def prof_boom(frame, event, arg):
    raise RuntimeError("prof_boom_13")

sys.setprofile(prof_boom)
try:
    target_unwind()
    raise AssertionError("prof_boom must propagate RuntimeError")
except RuntimeError as re_p:
    assert str(re_p) == "prof_boom_13"
    assert sys.getprofile() is None
finally:
    sys.setprofile(None)

# Direct sys.audit spoofing remains blocked
for ev_name, ev_args in (
    ("sys.settrace", ()),
    ("sys.setprofile", ()),
    ("sys.monitoring.register_callback", ()),
    ("octopus.trace_unwind", ("sys.settrace",)),
    ("octopus.trace_op", ("settrace", None)),
):
    try:
        sys.audit(ev_name, *ev_args)
        raise AssertionError(f"spoofed sys.audit({{ev_name}}) must be denied")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), str(pe)

assert captured == {{}}, f"captured leaks: {{captured}}"
print("ITER13_ALL_HARDENED_OK")
"#,
            tilde_sec = tilde_secret.to_string_lossy().to_string(),
            rel_sec = rel_secret_file.to_string_lossy().to_string(),
            out_txt = outside_txt.to_string_lossy().to_string(),
            out_db = outside_db.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            pol_path.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            probe_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter13 probe");

    assert!(
        out.status.success(),
        "iter13 probe failed (exit={:?}): stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ITER13_ALL_HARDENED_OK"));
    assert!(!outside_txt.exists());
    assert!(!outside_db.exists());

    // Watchdog __new__ tamper tests for _TRACE_WRAPPER_CLS, _LOCAL_TRACE_CLS, _MON_CB_CLS, _SIGNAL_HANDLER_CLS, _SQLITE_WRAPPER_CLS
    for (idx, tamper_expr) in [
        "import sys\nsys.settrace.__globals__['_TRACE_WRAPPER_CLS'].__new__ = staticmethod(lambda cls, fn, p: fn)\nsys.settrace(lambda f, e, a: None)\nopen('new_tamper1.txt', 'w').write('FAIL')",
        "import sys\nsys.settrace.__globals__['_LOCAL_TRACE_CLS'].__new__ = staticmethod(lambda cls, fn: fn)\nsys.settrace(lambda f, e, a: (lambda f2, e2, a2: None))\n(lambda: 1)()\nopen('new_tamper2.txt', 'w').write('FAIL')",
        "import sys\nsys.settrace.__globals__['_MON_CB_CLS'].__new__ = staticmethod(lambda cls, fn, *a: fn)\nsys.monitoring.use_tool_id(4, 't')\nsys.monitoring.register_callback(4, sys.monitoring.events.PY_START, lambda *a: None)\nopen('new_tamper3.txt', 'w').write('FAIL')",
        "import signal\nsignal.signal.__globals__['_SIGNAL_HANDLER_CLS'].__new__ = staticmethod(lambda cls, fn: fn)\nsignal.signal(signal.SIGINT, lambda s, f: None)\nopen('new_tamper4.txt', 'w').write('FAIL')",
        "import sqlite3\nsqlite3.Connection.__new__ = staticmethod(lambda cls, *a, **kw: object.__new__(cls))\nopen('new_tamper5.txt', 'w').write('FAIL')",
    ]
    .iter()
    .enumerate()
    {
        let wd_script = ws_dir.join(format!("new_wd_tamper_{}.py", idx));
        std::fs::write(&wd_script, tamper_expr).unwrap();
        let out_wd = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_path.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
                wd_script.to_str().unwrap(),
            ])
            .output()
            .expect("run __new__ watchdog tamper probe");
        assert!(
            !out_wd.status.success(),
            "__new__ watchdog tamper case {} must fail closed (exit={:?})",
            idx,
            out_wd.status.code()
        );
        assert!(!ws_dir.join(format!("new_tamper{}.txt", idx + 1)).exists());
    }
}

#[test]
fn test_iteration14_unc_admin_share_and_stat_hardening() {
    struct DirCleanup(std::path::PathBuf);
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    let py = find_python();
    let parent_dir = TempDirGuard::new("iter14_root");
    let ws_dir = parent_dir.path().join("work");
    let rel_secret_dir = parent_dir.path().join("rel_secret");
    let abs_deny_dir = parent_dir.path().join("deny_abs");
    std::fs::create_dir_all(&ws_dir).unwrap();
    std::fs::create_dir_all(&rel_secret_dir).unwrap();
    std::fs::create_dir_all(&abs_deny_dir).unwrap();
    let outside = TempDirGuard::new("iter14_outside");

    std::fs::write(ws_dir.join("allowed.txt"), "ALLOWED_14\n").unwrap();
    let rel_secret_file = rel_secret_dir.join("secret.txt");
    std::fs::write(&rel_secret_file, "REL_SECRET_14\n").unwrap();
    let abs_secret_file = abs_deny_dir.join("abs_secret.txt");
    std::fs::write(&abs_secret_file, "ABS_SECRET_14\n").unwrap();
    let abs_secret_db = abs_deny_dir.join("secret.db");
    std::fs::write(&abs_secret_db, "").unwrap();
    let outside_txt = outside.path().join("iter14_pwned.txt");
    let outside_db = outside.path().join("iter14_pwned.db");

    let home_dir = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
        .expect("USERPROFILE or HOME must be set");
    let tilde_rel = format!(
        "oct_iter14_tilde_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let tilde_abs = home_dir.join(&tilde_rel);
    std::fs::create_dir_all(&tilde_abs).unwrap();
    let _tilde_guard = DirCleanup(tilde_abs.clone());
    let tilde_secret = tilde_abs.join("home_secret.txt");
    std::fs::write(&tilde_secret, "TILDE_SECRET_14\n").unwrap();

    let json_pol = ws_dir.join("policy_iter14.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "sh"] },
            "filesystem": {
                "allow_read": [&ws_dir],
                "allow_write": [&ws_dir],
                "deny": ["../rel_secret", format!("~/{}", tilde_rel), &abs_deny_dir, outside.path()]
            }
        })
        .to_string(),
    )
    .unwrap();

    let json_probe = ws_dir.join("iter14_json_probe.py");
    std::fs::write(
        &json_probe,
        format!(
            r#"import glob, os, pathlib, signal, sqlite3, sys

def expect_denied(label, fn):
    try:
        res = fn()
        raise AssertionError(f"{{label}} unexpectedly succeeded: {{res!r}}")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

targets = [
    ("rel", os.path.abspath({rel_sec:?})),
    ("abs", os.path.abspath({abs_sec:?})),
    ("tilde", os.path.abspath({tilde_sec:?})),
]

# 1. UNC admin-share variants (Windows)
if os.name == "nt":
    hosts = ["127.0.0.1", "localhost"]
    cn = os.environ.get("COMPUTERNAME")
    if cn:
        hosts.append(cn)
    for tname, tpath in targets:
        drv, rest = os.path.splitdrive(tpath)
        dl = drv[0]
        slash_rest = rest.replace("\\", "/")
        unc_variants = []
        for h in hosts:
            unc_variants.append((f"{{tname}}_{{h}}_bs", f"\\\\{{h}}\\{{dl}}${{rest}}"))
            unc_variants.append((f"{{tname}}_{{h}}_verb", f"\\\\?\\UNC\\{{h}}\\{{dl}}${{rest}}"))
        unc_variants.append((f"{{tname}}_fwd", f"//127.0.0.1/{{dl}}${{slash_rest}}"))
        unc_variants.append((f"{{tname}}_dot", f"\\\\127.0.0.1\\{{dl}}${{rest}}."))
        for vlabel, upath in unc_variants:
            expect_denied(vlabel + "_open", lambda p=upath: open(p, "r"))
            expect_denied(vlabel + "_path_open", lambda p=upath: pathlib.Path(p).open("r"))
            expect_denied(vlabel + "_os_open", lambda p=upath: os.open(p, os.O_RDONLY))
            expect_denied(vlabel + "_listdir", lambda p=os.path.dirname(upath): os.listdir(p))
            expect_denied(vlabel + "_scandir", lambda p=os.path.dirname(upath): os.scandir(p))
            expect_denied(vlabel + "_stat", lambda p=upath: os.stat(p))
            expect_denied(vlabel + "_lstat", lambda p=upath: os.lstat(p))
            expect_denied(vlabel + "_access", lambda p=upath: os.access(p, os.R_OK))
            expect_denied(vlabel + "_exists", lambda p=upath: os.path.exists(p))
            expect_denied(vlabel + "_isfile", lambda p=upath: os.path.isfile(p))
            expect_denied(vlabel + "_path_exists", lambda p=upath: pathlib.Path(p).exists())

    # ADMIN$ and IPC$ shares denied
    expect_denied("admin_share_read", lambda: open(r"\\127.0.0.1\ADMIN$\win.ini", "r"))
    expect_denied("admin_share_stat", lambda: os.stat(r"\\127.0.0.1\ADMIN$\win.ini"))
    expect_denied("ipc_share_stat", lambda: os.stat(r"\\127.0.0.1\IPC$\srvsvc"))

    # allow_write and sqlite3 via UNC admin share denied
    out_drv, out_rest = os.path.splitdrive(os.path.abspath({out_txt:?}))
    expect_denied("unc_write_outside", lambda: open(f"\\\\127.0.0.1\\{{out_drv[0]}}${{out_rest}}", "w"))
    db_drv, db_rest = os.path.splitdrive(os.path.abspath({out_db:?}))
    expect_denied("unc_sqlite_outside", lambda: sqlite3.connect(f"\\\\127.0.0.1\\{{db_drv[0]}}${{db_rest}}"))

    # Allowed workspace read/write via local UNC C$ still works
    ws_drv, ws_rest = os.path.splitdrive(os.path.abspath("allowed.txt"))
    with open(f"\\\\127.0.0.1\\{{ws_drv[0]}}${{ws_rest}}", "r", encoding="utf-8") as af:
        assert af.read().strip() == "ALLOWED_14"

# 2. os.stat / os.lstat / os.access / Path.stat / Path.exists / os.path.isfile / glob.glob on denied paths
for tname, tpath in targets:
    expect_denied(tname + "_os_stat", lambda p=tpath: os.stat(p))
    expect_denied(tname + "_os_lstat", lambda p=tpath: os.lstat(p))
    expect_denied(tname + "_os_access_f", lambda p=tpath: os.access(p, os.F_OK))
    expect_denied(tname + "_os_access_r", lambda p=tpath: os.access(p, os.R_OK))
    expect_denied(tname + "_os_access_w", lambda p=tpath: os.access(p, os.W_OK))
    expect_denied(tname + "_path_stat", lambda p=tpath: pathlib.Path(p).stat())
    expect_denied(tname + "_path_exists", lambda p=tpath: pathlib.Path(p).exists())
    expect_denied(tname + "_os_path_exists", lambda p=tpath: os.path.exists(p))
    expect_denied(tname + "_os_path_isfile", lambda p=tpath: os.path.isfile(p))
    expect_denied(tname + "_glob_exact", lambda p=tpath: glob.glob(p))

# TOCTOU / EvilPath / dir_fd checks
evil_ran = []
class EvilPath:
    def __fspath__(self):
        evil_ran.append(True)
        return "allowed.txt"
class EvilStr(str):
    pass
expect_denied("evil_path_stat", lambda: os.stat(EvilPath()))
expect_denied("evil_str_stat", lambda: os.stat(EvilStr("allowed.txt")))
expect_denied("evil_path_exists", lambda: os.path.exists(EvilPath()))
expect_denied("dir_fd_stat", lambda: os.stat("allowed.txt", dir_fd=1))
expect_denied("dir_fd_lstat", lambda: os.lstat("allowed.txt", dir_fd=1))
expect_denied("dir_fd_access", lambda: os.access("allowed.txt", os.R_OK, dir_fd=1))
assert evil_ran == [], f"EvilPath.__fspath__ ran: {{evil_ran}}"

# os.stat.__globals__ exposes no _ORIG_OS_* callables
for k in os.stat.__globals__:
    assert not k.startswith("_ORIG_"), f"raw {{k}} leaked into os.stat.__globals__"

# Allowed workspace stat/lstat/access/exists/glob work cleanly
assert os.stat("allowed.txt").st_size > 0
assert os.lstat("allowed.txt").st_size > 0
assert os.access("allowed.txt", os.R_OK | os.W_OK) is True
assert pathlib.Path("allowed.txt").exists() is True
assert os.path.isfile("allowed.txt") is True
assert "allowed.txt" in glob.glob("*.txt")
# Read-only sys.executable outside allow_write returns False for W_OK without crashing
assert os.access(sys.executable, os.W_OK) is False

# 3. _F_SIGNAL._enum_to_int / _int_to_enum in _ALL_INTERNAL_CODES & invisible to sys.monitoring
E = sys.monitoring.events
M = sys.monitoring
sig_mon_hits = []
tid = 5
M.use_tool_id(tid, "oct_iter14_sig")
try:
    def on_sig_start(code, offset):
        sig_mon_hits.append((code.co_filename, code.co_name))
    M.register_callback(tid, E.PY_START, on_sig_start)
    M.set_events(tid, E.PY_START)
    prev = signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGINT, prev)
    M.set_events(tid, 0)
    M.register_callback(tid, E.PY_START, None)
    assert all(
        not (fn.endswith("signal.py") and nm in ("_enum_to_int", "_int_to_enum"))
        and not fn.startswith("<octopus")
        for fn, nm in sig_mon_hits
    ), f"sys.monitoring observed signal internals: {{sig_mon_hits}}"
    for helper_name in ("_enum_to_int", "_int_to_enum"):
        hfn = getattr(signal, helper_name, None)
        if hfn is not None and hasattr(hfn, "__code__"):
            expect_denied(
                f"set_local_{{helper_name}}",
                lambda c=hfn.__code__: M.set_local_events(tid, c, E.PY_START),
            )
finally:
    M.free_tool_id(tid)

print("ITER14_JSON_HARDENED_OK")
"#,
            rel_sec = rel_secret_file.to_string_lossy().to_string(),
            abs_sec = abs_secret_file.to_string_lossy().to_string(),
            tilde_sec = tilde_secret.to_string_lossy().to_string(),
            out_txt = outside_txt.to_string_lossy().to_string(),
            out_db = outside_db.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out_json = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            json_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run iter14 json probe");
    assert!(
        out_json.status.success(),
        "iter14 json probe failed (exit={:?}): stdout={} stderr={}",
        out_json.status.code(),
        String::from_utf8_lossy(&out_json.stdout),
        String::from_utf8_lossy(&out_json.stderr)
    );
    assert!(String::from_utf8_lossy(&out_json.stdout).contains("ITER14_JSON_HARDENED_OK"));
    assert!(!outside_txt.exists());
    assert!(!outside_db.exists());

    // Cedar standalone policy covering UNC admin shares & os.stat/lstat/access/exists/glob
    let abs_deny_canon =
        std::fs::canonicalize(&abs_deny_dir).unwrap_or_else(|_| abs_deny_dir.clone());
    let abs_deny_raw = abs_deny_canon.to_string_lossy().replace('\\', "/");
    let abs_deny_cedar = abs_deny_raw
        .strip_prefix("//?/")
        .unwrap_or(&abs_deny_raw)
        .to_ascii_lowercase();
    let cedar_pol = ws_dir.join("policy_iter14.cedar");
    std::fs::write(
        &cedar_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath);
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{deny}*" }};
permit (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath);
forbid (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{deny}*" }};
"#,
            deny = abs_deny_cedar
        ),
    )
    .unwrap();

    let cedar_probe = ws_dir.join("iter14_cedar_probe.py");
    std::fs::write(
        &cedar_probe,
        format!(
            r#"import glob, os, pathlib, sqlite3

def expect_denied(label, fn):
    try:
        res = fn()
        raise AssertionError(f"{{label}} unexpectedly succeeded: {{res!r}}")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

abs_sec = os.path.abspath({abs_sec:?})
abs_db = os.path.abspath({abs_db:?})
expect_denied("cedar_stat", lambda: os.stat(abs_sec))
expect_denied("cedar_lstat", lambda: os.lstat(abs_sec))
expect_denied("cedar_access", lambda: os.access(abs_sec, os.R_OK))
expect_denied("cedar_path_exists", lambda: pathlib.Path(abs_sec).exists())
expect_denied("cedar_os_isfile", lambda: os.path.isfile(abs_sec))
expect_denied("cedar_glob", lambda: glob.glob(abs_sec))

if os.name == "nt":
    drv, rest = os.path.splitdrive(abs_sec)
    db_drv, db_rest = os.path.splitdrive(abs_db)
    dl = drv[0]
    slash_rest = rest.replace("\\", "/")
    hosts = ["127.0.0.1", "localhost"]
    cn = os.environ.get("COMPUTERNAME")
    if cn:
        hosts.append(cn)
    for h in hosts:
        for vlabel, upath in (
            (f"{{h}}_bs", f"\\\\{{h}}\\{{dl}}${{rest}}"),
            (f"{{h}}_verb", f"\\\\?\\UNC\\{{h}}\\{{dl}}${{rest}}"),
            (f"{{h}}_fwd", f"//{{h}}/{{dl}}${{slash_rest}}"),
        ):
            expect_denied(vlabel + "_read", lambda p=upath: open(p, "r"))
            expect_denied(vlabel + "_write", lambda p=upath + ".w": open(p, "w"))
            expect_denied(vlabel + "_listdir", lambda p=os.path.dirname(upath): os.listdir(p))
            expect_denied(vlabel + "_scandir", lambda p=os.path.dirname(upath): os.scandir(p))
            expect_denied(vlabel + "_stat", lambda p=upath: os.stat(p))
        db_unc = f"\\\\{{h}}\\{{db_drv[0]}}${{db_rest}}"
        expect_denied(f"{{h}}_sqlite", lambda p=db_unc: sqlite3.connect(p))

print("ITER14_CEDAR_HARDENED_OK")
"#,
            abs_sec = abs_secret_file.to_string_lossy().to_string(),
            abs_db = abs_secret_db.to_string_lossy().to_string(),
        ),
    )
    .unwrap();

    let out_cedar = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            cedar_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            cedar_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run iter14 cedar probe");
    assert!(
        out_cedar.status.success(),
        "iter14 cedar probe failed (exit={:?}): stdout={} stderr={}",
        out_cedar.status.code(),
        String::from_utf8_lossy(&out_cedar.stdout),
        String::from_utf8_lossy(&out_cedar.stderr)
    );
    assert!(String::from_utf8_lossy(&out_cedar.stdout).contains("ITER14_CEDAR_HARDENED_OK"));

    // Preflight Cedar CLI argument check on Windows UNC admin-share path
    #[cfg(windows)]
    {
        let abs_s = abs_secret_file.to_string_lossy();
        if abs_s.len() >= 3 && abs_s.as_bytes()[1] == b':' {
            let drv_ch = abs_s.as_bytes()[0] as char;
            let rest = &abs_s[2..];
            let unc_arg = format!(r"\\127.0.0.1\{}${}", drv_ch, rest);
            let out_pre = Command::new(octopus_bin())
                .args([
                    "run",
                    "--policy",
                    cedar_pol.to_str().unwrap(),
                    "--cwd",
                    ws_dir.to_str().unwrap(),
                    "--",
                    &py,
                    &unc_arg,
                ])
                .output()
                .expect("run iter14 preflight unc arg");
            assert!(
                !out_pre.status.success(),
                "preflight must reject UNC admin-share CLI arg to Cedar-forbidden file"
            );
            assert_eq!(out_pre.status.code(), Some(2));
        }
    }

    // Watchdog tamper probes on os.stat / os.path.exists
    for (idx, tamper_expr) in [
        "import os\nos.stat = lambda *a, **kw: None\nopen('st_tamper1.txt', 'w').write('FAIL')",
        "import os\nos.path.exists = lambda *a: False\nopen('st_tamper2.txt', 'w').write('FAIL')",
    ]
    .iter()
    .enumerate()
    {
        let wd_script = ws_dir.join(format!("st_wd_tamper_{}.py", idx));
        std::fs::write(&wd_script, tamper_expr).unwrap();
        let out_wd = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                json_pol.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
                wd_script.to_str().unwrap(),
            ])
            .output()
            .expect("run stat watchdog tamper probe");
        assert!(
            !out_wd.status.success(),
            "stat watchdog tamper case {} must terminate immediately (exit={:?})",
            idx,
            out_wd.status.code()
        );
        assert!(!ws_dir.join(format!("st_tamper{}.txt", idx + 1)).exists());
    }
}

#[test]
fn test_iteration15_strict_guard_scandir_and_latency() {
    let ws = TempDirGuard::new("iter15");
    let ws_dir = ws.path();
    let py = find_python();

    let allowed_dir = ws_dir.join("allowed");
    let denied_dir = ws_dir.join("denied");
    std::fs::create_dir_all(&allowed_dir).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();
    std::fs::write(allowed_dir.join("ok.txt"), "ALLOWED_15\n").unwrap();
    std::fs::write(allowed_dir.join("nested_secret.txt"), "NESTED_SECRET_15\n").unwrap();
    std::fs::write(denied_dir.join("inner.txt"), "INNER_SECRET_15\n").unwrap();
    std::fs::write(ws_dir.join("cwd_secret.txt"), "CWD_SECRET_15\n").unwrap();
    std::fs::write(ws_dir.join("strict_secret.txt"), "STRICT_SECRET_15\n").unwrap();

    #[cfg(windows)]
    {
        let _ = Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                denied_dir.join("junc_inside").to_str().unwrap(),
                allowed_dir.to_str().unwrap(),
            ])
            .output();
        let _ = Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                allowed_dir.join("junc_denied").to_str().unwrap(),
                denied_dir.to_str().unwrap(),
            ])
            .output();
    }
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(&allowed_dir, denied_dir.join("junc_inside"));
        let _ = std::os::unix::fs::symlink(&denied_dir, allowed_dir.join("junc_denied"));
    }

    let json_pol = ws_dir.join("policy_iter15.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": [] },
            "filesystem": {
                "allow_read": ["."],
                "allow_write": ["allowed"],
                "deny": [
                    "denied",
                    "allowed/nested_secret.txt",
                    "./strict_secret.txt",
                    "~/.ssh",
                    "~/.aws"
                ]
            }
        })
        .to_string(),
    )
    .unwrap();

    // 1. Latency check: import urllib.request must complete well under 5s
    let t0 = Instant::now();
    let lat_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            "-c",
            "import os, time, urllib.request; print('ACK_CLEAN', os.environ.get('OCTOPUS_PY_GUARD_ACK_FD'), os.environ.get('OCTOPUS_PY_GUARD_ACK_TOKEN'))",
        ])
        .output()
        .expect("run iter15 latency probe");
    let lat_elapsed = t0.elapsed();
    assert!(
        lat_out.status.success(),
        "latency probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&lat_out.stdout),
        String::from_utf8_lossy(&lat_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&lat_out.stdout).contains("ACK_CLEAN None None"),
        "ACK env vars must be popped before user code: {}",
        String::from_utf8_lossy(&lat_out.stdout)
    );
    assert!(
        lat_elapsed < Duration::from_secs(12),
        "import urllib.request under octopus took {:?}, expected < 12s",
        lat_elapsed
    );

    // 2. DirEntry / glob / Path.glob / os.chdir / os.readlink / Path.readlink under JSON
    let json_probe = ws_dir.join("iter15_json_probe.py");
    std::fs::write(
        &json_probe,
        r#"import glob, os, pathlib

def expect_denied(label, fn):
    try:
        res = fn()
        raise AssertionError(f"{label} unexpectedly succeeded: {res!r}")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{label}: {pe}"

entries = list(os.scandir("allowed"))
names = [e.name for e in entries]
assert "ok.txt" in names, names
assert "nested_secret.txt" not in names, names
assert "junc_denied" not in names, names
for e in entries:
    if e.name == "ok.txt":
        assert e.is_file() is True
        assert e.stat().st_size > 0
        assert e.inode() >= 0

assert glob.glob(os.path.join("allowed", "*secret*")) == []
assert list(pathlib.Path("allowed").glob("*secret*")) == []

expect_denied("chdir_denied", lambda: os.chdir("denied"))
expect_denied("chdir_denied_junc", lambda: os.chdir(os.path.join("denied", "junc_inside")))
expect_denied("readlink_denied_junc", lambda: os.readlink(os.path.join("denied", "junc_inside")))
expect_denied("readlink_junc_denied", lambda: os.readlink(os.path.join("allowed", "junc_denied")))
expect_denied("path_readlink_junc_denied", lambda: pathlib.Path("allowed", "junc_denied").readlink())

os.chdir("allowed")
assert any(e.name == "ok.txt" for e in os.scandir(None))
assert "ok.txt" in os.listdir(None)
assert "nested_secret.txt" not in [e.name for e in os.scandir()]
print("ITER15_JSON_OK")
"#,
    )
    .unwrap();
    let out_json = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            json_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run iter15 json probe");
    assert!(
        out_json.status.success(),
        "iter15 json probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_json.stdout),
        String::from_utf8_lossy(&out_json.stderr)
    );
    assert!(String::from_utf8_lossy(&out_json.stdout).contains("ITER15_JSON_OK"));

    // 3. Cedar standalone: DirEntry, glob, chdir, readlink, preflight ADMIN$, PYTHONPATH _path_stat
    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();
    let nested_cedar = format!("{}/nested_secret.txt", allowed_cedar);
    let cedar_pol = ws_dir.join("policy_iter15.cedar");
    std::fs::write(
        &cedar_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{allowed}*" }};
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{nested}*" }};
"#,
            allowed = allowed_cedar,
            nested = nested_cedar
        ),
    )
    .unwrap();

    #[cfg(windows)]
    {
        let pre_admin = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                cedar_pol.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
                "-c",
                "print('SHOULD_NOT_RUN')",
                r"\\127.0.0.1\ADMIN$\win.ini",
            ])
            .output()
            .expect("run iter15 preflight admin share probe");
        assert_eq!(
            pre_admin.status.code(),
            Some(2),
            "preflight must reject \\\\127.0.0.1\\ADMIN$\\win.ini: stdout={} stderr={}",
            String::from_utf8_lossy(&pre_admin.stdout),
            String::from_utf8_lossy(&pre_admin.stderr)
        );
        assert!(!String::from_utf8_lossy(&pre_admin.stdout).contains("SHOULD_NOT_RUN"));
    }

    let cedar_probe = ws_dir.join("iter15_cedar_probe.py");
    std::fs::write(
        &cedar_probe,
        r#"import _frozen_importlib_external, glob, os, pathlib

def expect_denied(label, fn):
    try:
        res = fn()
        raise AssertionError(f"{label} unexpectedly succeeded: {res!r}")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{label}: {pe}"

names = [e.name for e in os.scandir("allowed")]
assert "ok.txt" in names, names
assert "nested_secret.txt" not in names, names
assert "junc_denied" not in names, names
assert glob.glob(os.path.join("allowed", "*secret*")) == []
assert list(pathlib.Path("allowed").glob("*secret*")) == []
expect_denied("cedar_chdir_denied", lambda: os.chdir("denied"))
expect_denied("cedar_path_stat_cwd_secret", lambda: _frozen_importlib_external._path_stat("cwd_secret.txt"))
expect_denied("cedar_readlink_junc_denied", lambda: os.readlink(os.path.join("allowed", "junc_denied")))
expect_denied("cedar_path_readlink_junc_denied", lambda: pathlib.Path("allowed", "junc_denied").readlink())
print("ITER15_CEDAR_OK")
"#,
    )
    .unwrap();
    let out_cedar = Command::new(octopus_bin())
        .env("PYTHONPATH", ws_dir.to_str().unwrap())
        .args([
            "run",
            "--policy",
            cedar_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            cedar_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run iter15 cedar probe");
    assert!(
        out_cedar.status.success(),
        "iter15 cedar probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out_cedar.stdout),
        String::from_utf8_lossy(&out_cedar.stderr)
    );
    assert!(String::from_utf8_lossy(&out_cedar.stdout).contains("ITER15_CEDAR_OK"));

    // 4. Watchdog tamper on os.scandir / os.readlink
    for tamper_code in [
        "import os\nos.scandir = lambda *a, **kw: []\nos.stat('allowed/ok.txt')",
        "import os\nos.readlink = lambda *a, **kw: ''\nos.stat('allowed/ok.txt')",
    ] {
        let wd_out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                json_pol.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
                "-c",
                tamper_code,
            ])
            .output()
            .expect("run iter15 scandir/readlink tamper");
        assert!(
            !wd_out.status.success(),
            "watchdog tamper must terminate immediately"
        );
    }

    // 5. --sandbox strict verification (uses AppContainer-capable Python if available on host)
    #[allow(unused_mut)]
    let mut strict_py = py.clone();
    #[cfg(windows)]
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        let py314 = PathBuf::from(local_app)
            .join("Python")
            .join("pythoncore-3.14-64")
            .join("python.exe");
        if py314.is_file() {
            strict_py = py314.to_string_lossy().to_string();
        }
    }
    let strict_probe = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--sandbox",
            "strict",
            "--json",
            "--timeout",
            "30",
            "--",
            &strict_py,
            "-c",
            "import os, sqlite3, sys\nassert 'sitecustomize' in sys.modules\nfor lbl, fn in (('addaudithook', lambda: sys.addaudithook(lambda *a: None)), ('sqlite_udf', lambda: sqlite3.connect(':memory:').create_function('f', 0, lambda: 1)), ('stat_secret', lambda: os.stat('strict_secret.txt'))):\n    try:\n        fn()\n        raise AssertionError(lbl + ' unblocked')\n    except PermissionError as pe:\n        assert 'blocked_by_octopus_policy' in str(pe)\nprint('SC_IN_MODS True')\nopen('strict_secret.txt', 'r').read()",
        ])
        .output()
        .expect("run iter15 strict sandbox probe");
    let strict_json: serde_json::Value =
        serde_json::from_slice(&strict_out_or_empty(&strict_probe.stdout))
            .unwrap_or_else(|_| serde_json::json!({}));
    let strict_ec = strict_json["exit_code"].as_i64().unwrap_or(-1);
    let is_host_acl_err =
        strict_ec == (0xC000_0135u32 as i32) as i64 || strict_ec == (0xC000_0022u32 as i32) as i64;
    if !is_host_acl_err {
        let s_stdout = strict_json["stdout"].as_str().unwrap_or("");
        let s_stderr = strict_json["stderr"].as_str().unwrap_or("");
        assert_ne!(
            strict_ec, 0,
            "strict sandbox must block ./strict_secret.txt: json={}",
            strict_json
        );
        assert!(
            s_stdout.contains("SC_IN_MODS True"),
            "sitecustomize must load under --sandbox strict: json={}",
            strict_json
        );
        assert!(
            s_stderr.contains("blocked_by_octopus_policy"),
            "strict sandbox must enforce Python filesystem.deny: json={}",
            strict_json
        );
    }
}

fn strict_out_or_empty(b: &[u8]) -> Vec<u8> {
    if b.is_empty() {
        b"{}".to_vec()
    } else {
        b.to_vec()
    }
}

#[test]
fn test_iteration16_gc_reentrancy_lexical_and_preflight() {
    let ws = TempDirGuard::new("iter16");
    let ws_dir = ws.path();
    let py = find_python();

    let allowed_dir = ws_dir.join("allowed");
    let allowed_sub = allowed_dir.join("sub_ok");
    let sub_tilde_deny = allowed_dir.join("sub_tilde_deny");
    let denied_dir = ws_dir.join("denied");
    let rm_dir = allowed_dir.join("rm_me");
    std::fs::create_dir_all(&allowed_sub).unwrap();
    std::fs::create_dir_all(&sub_tilde_deny).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();
    std::fs::create_dir_all(&rm_dir).unwrap();
    std::fs::write(allowed_dir.join("ok.txt"), "ALLOWED_16\n").unwrap();
    std::fs::write(rm_dir.join("item.txt"), "RM_ITEM\n").unwrap();
    std::fs::write(denied_dir.join("secret.txt"), "SECRET_16\n").unwrap();
    std::fs::write(ws_dir.join("secret.txt"), "CWD_SECRET_16\n").unwrap();

    // Find Python's sys.prefix and a known readable file inside it (LICENSE.txt or similar).
    let py_info_out = Command::new(&py)
        .args([
            "-c",
            "import os, sys; cand = next((f for f in ('LICENSE.txt', 'LICENSE', 'NEWS.txt') if os.path.isfile(os.path.join(sys.prefix, f))), ''); print(sys.prefix); print(cand)",
        ])
        .output()
        .expect("query python sys.prefix");
    assert!(py_info_out.status.success());
    let py_info_str = String::from_utf8_lossy(&py_info_out.stdout);
    let mut py_lines = py_info_str.lines();
    let py_prefix = py_lines.next().unwrap_or("").trim().to_string();
    let py_file = py_lines.next().unwrap_or("").trim().to_string();
    assert!(!py_prefix.is_empty(), "python sys.prefix empty");

    #[cfg(windows)]
    {
        for (link_path, target_path) in [
            (denied_dir.join("junc_inside"), allowed_dir.as_path()),
            (denied_dir.join("junc_to_py"), Path::new(&py_prefix)),
            (
                allowed_dir.join("junc_allowed_to_py"),
                Path::new(&py_prefix),
            ),
            (sub_tilde_deny.join("junc_to_py"), Path::new(&py_prefix)),
        ] {
            let mk = Command::new("cmd")
                .args([
                    "/c",
                    "mklink",
                    "/J",
                    link_path.to_str().unwrap(),
                    target_path.to_str().unwrap(),
                ])
                .output()
                .expect("mklink /J");
            assert!(
                mk.status.success(),
                "mklink failed for {}: {}",
                link_path.display(),
                String::from_utf8_lossy(&mk.stderr)
            );
        }
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&allowed_dir, denied_dir.join("junc_inside")).unwrap();
        std::os::unix::fs::symlink(&py_prefix, denied_dir.join("junc_to_py")).unwrap();
        std::os::unix::fs::symlink(&py_prefix, allowed_dir.join("junc_allowed_to_py")).unwrap();
        std::os::unix::fs::symlink(&py_prefix, sub_tilde_deny.join("junc_to_py")).unwrap();
    }

    // Build a ~/... deny entry for allowed/sub_tilde_deny (and allowed/junc_allowed_to_py/<py_file>)
    // when ws_dir is inside home dir.
    let home_dir = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    let junc_allowed_to_py = allowed_dir.join("junc_allowed_to_py");
    let tilde_deny_sub = home_dir
        .as_ref()
        .and_then(|h| sub_tilde_deny.strip_prefix(h).ok())
        .map(|rel| format!("~/{}", rel.to_string_lossy().replace('\\', "/")))
        .unwrap_or_else(|| sub_tilde_deny.to_string_lossy().replace('\\', "/"));
    let tilde_deny_junc_file = if !py_file.is_empty() {
        let jf = junc_allowed_to_py.join(&py_file);
        home_dir
            .as_ref()
            .and_then(|h| jf.strip_prefix(h).ok())
            .map(|rel| format!("~/{}", rel.to_string_lossy().replace('\\', "/")))
            .unwrap_or_else(|| jf.to_string_lossy().replace('\\', "/"))
    } else {
        tilde_deny_sub.clone()
    };
    let tilde_deny_preflight = home_dir
        .as_ref()
        .and_then(|h| denied_dir.strip_prefix(h).ok())
        .map(|rel| format!("~/{}", rel.to_string_lossy().replace('\\', "/")));

    let json_pol = ws_dir.join("policy_iter16.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": [] },
            "filesystem": {
                "allow_read": ["."],
                "allow_write": ["allowed"],
                "deny": [
                    "denied",
                    "./secret.txt",
                    tilde_deny_sub,
                    tilde_deny_junc_file
                ]
            }
        })
        .to_string(),
    )
    .unwrap();

    // 1. Cyclic GC weakref finalizer reentrancy (os.scandir + sqlite3) & immediate rmdir/remove after del+gc.collect()
    let gc_script = ws_dir.join("gc_repro_iter16.py");
    std::fs::write(
        &gc_script,
        r#"import gc, os, sqlite3

for t in range(1, 35):
    gc.set_threshold(700, 10, 10)
    lst = [os.scandir("allowed")]
    lst.append(lst)
    del lst
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cyc = [con, cur]
    cyc.append(cyc)
    del cyc, cur, con
    try:
        os.stat("secret.txt")
    except PermissionError:
        pass
    gc.set_threshold(t, 1, 1)
    os.stat("allowed/ok.txt")

gc.set_threshold(700, 10, 10)

# Verify scandir raw handle is closed immediately on next audited call after GC
it = os.scandir("allowed/rm_me")
del it
gc.collect()
os.remove("allowed/rm_me/item.txt")
os.rmdir("allowed/rm_me")

# Verify sqlite file DB handle drops cleanly after del + gc.collect()
dbp = os.path.join("allowed", "gc_test.sqlite")
c2 = sqlite3.connect(dbp)
cur2 = c2.cursor()
cur2.execute("create table t(x int)")
c2.commit()
c2.close()
del cur2, c2
gc.collect()
os.remove(dbp)

# Unclosed sqlite file DB handle dropped cleanly via _drain_gc_cleanups() before os.remove
dbp2 = os.path.join("allowed", "gc_test_unclosed.sqlite")
c3 = sqlite3.connect(dbp2)
cur3 = c3.cursor()
cur3.execute("create table t(x int)")
c3.commit()
del cur3, c3
gc.collect()
os.remove(dbp2)
print("GC_REPRO_16_OK")
"#,
    )
    .unwrap();
    let gc_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--timeout",
            "20",
            "--",
            &py,
            gc_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter16 gc repro");
    assert!(
        gc_out.status.success(),
        "gc_repro_iter16 failed: code={:?} stdout={} stderr={}",
        gc_out.status.code(),
        String::from_utf8_lossy(&gc_out.stdout),
        String::from_utf8_lossy(&gc_out.stderr)
    );
    assert!(String::from_utf8_lossy(&gc_out.stdout).contains("GC_REPRO_16_OK"));

    // 2. Lexical / junction bypasses blocked under JSON (including ~/) across all FS ops
    let lex_probe = ws_dir.join("lex_probe_iter16.py");
    std::fs::write(
        &lex_probe,
        format!(
            r#"import glob, os, pathlib, sqlite3

PY_FILE = {py_file:?}

def expect_denied(label, fn):
    try:
        res = fn()
        raise AssertionError(f"{{label}} unexpectedly succeeded: {{res!r}}")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

# denied/junc_inside -> allowed across all ops
expect_denied("junc_inside_open", lambda: open(os.path.join("denied", "junc_inside", "ok.txt"), "r"))
expect_denied("junc_inside_stat", lambda: os.stat(os.path.join("denied", "junc_inside", "ok.txt")))
expect_denied("junc_inside_lstat", lambda: os.lstat(os.path.join("denied", "junc_inside", "ok.txt")))
expect_denied("junc_inside_scandir", lambda: list(os.scandir(os.path.join("denied", "junc_inside"))))
expect_denied("junc_inside_listdir", lambda: os.listdir(os.path.join("denied", "junc_inside")))
expect_denied("junc_inside_access", lambda: os.access(os.path.join("denied", "junc_inside", "ok.txt"), os.R_OK))
expect_denied("junc_inside_exists", lambda: os.path.exists(os.path.join("denied", "junc_inside", "ok.txt")))
expect_denied("junc_inside_chdir", lambda: os.chdir(os.path.join("denied", "junc_inside", "sub_ok")))
expect_denied("junc_inside_readlink", lambda: os.readlink(os.path.join("denied", "junc_inside")))
expect_denied("junc_inside_sqlite", lambda: sqlite3.connect(os.path.join("denied", "junc_inside", "db.sqlite")))
assert glob.glob(os.path.join("denied", "junc_inside", "*")) == []
assert list(pathlib.Path("denied", "junc_inside").glob("*")) == []

# denied/junc_to_py & allowed/sub_tilde_deny/junc_to_py (~/-denied) blocked across all ops
for base_lbl, jbase in (("junc_to_py", os.path.join("denied", "junc_to_py")), ("sub_tilde_junc_to_py", os.path.join("allowed", "sub_tilde_deny", "junc_to_py"))):
    expect_denied(base_lbl + "_scandir", lambda jb=jbase: list(os.scandir(jb)))
    expect_denied(base_lbl + "_listdir", lambda jb=jbase: os.listdir(jb))
    expect_denied(base_lbl + "_chdir", lambda jb=jbase: os.chdir(jb))
    expect_denied(base_lbl + "_readlink", lambda jb=jbase: os.readlink(jb))
    if PY_FILE:
        target = os.path.join(jbase, PY_FILE)
        expect_denied(base_lbl + "_open", lambda t=target: open(t, "r"))
        expect_denied(base_lbl + "_stat", lambda t=target: os.stat(t))
        expect_denied(base_lbl + "_lstat", lambda t=target: os.lstat(t))
        expect_denied(base_lbl + "_access", lambda t=target: os.access(t, os.R_OK))
        expect_denied(base_lbl + "_exists", lambda t=target: os.path.exists(t))

if PY_FILE:
    t_junc = os.path.join("allowed", "junc_allowed_to_py", PY_FILE)
    expect_denied("junc_allowed_to_py_file_open", lambda t=t_junc: open(t, "r"))
    expect_denied("junc_allowed_to_py_file_stat", lambda t=t_junc: os.stat(t))
    expect_denied("junc_allowed_to_py_file_lstat", lambda t=t_junc: os.lstat(t))

assert open(os.path.join("allowed", "ok.txt"), "r").read().strip() == "ALLOWED_16"
print("LEX_JSON_16_OK")
"#,
            py_file = py_file
        ),
    )
    .unwrap();
    let lex_json_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            lex_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run iter16 json lexical probe");
    assert!(
        lex_json_out.status.success(),
        "lex_probe_iter16 (JSON) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&lex_json_out.stdout),
        String::from_utf8_lossy(&lex_json_out.stderr)
    );
    assert!(String::from_utf8_lossy(&lex_json_out.stdout).contains("LEX_JSON_16_OK"));

    // 3. Cedar allowlist-only & Cedar explicit forbid on junctions into Python prefix + stdlib import urllib.request
    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();
    let junc_allowed_py_raw = junc_allowed_to_py.to_string_lossy().replace('\\', "/");
    let junc_allowed_py_cedar = junc_allowed_py_raw
        .strip_prefix("//?/")
        .unwrap_or(&junc_allowed_py_raw)
        .to_ascii_lowercase();
    let denied_canon = std::fs::canonicalize(&denied_dir).unwrap_or_else(|_| denied_dir.clone());
    let denied_raw = denied_canon.to_string_lossy().replace('\\', "/");
    let denied_cedar = denied_raw
        .strip_prefix("//?/")
        .unwrap_or(&denied_raw)
        .to_ascii_lowercase();

    let cedar_allowlist_pol = ws_dir.join("policy_allowlist_iter16.cedar");
    std::fs::write(
        &cedar_allowlist_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{allowed}/*" }};
"#,
            allowed = allowed_cedar
        ),
    )
    .unwrap();

    let cedar_forbid_pol = ws_dir.join("policy_forbid_iter16.cedar");
    std::fs::write(
        &cedar_forbid_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{allowed}*" }};
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && (context.normalized_path like "{denied}*" || context.normalized_path like "{junc_allowed_py}*") }};
"#,
            allowed = allowed_cedar,
            denied = denied_cedar,
            junc_allowed_py = junc_allowed_py_cedar,
        ),
    )
    .unwrap();

    let cedar_py_probe = ws_dir.join("cedar_py_probe_iter16.py");
    std::fs::write(
        &cedar_py_probe,
        format!(
            r#"import os, urllib.request

PY_FILE = {py_file:?}

def expect_denied(label, fn):
    try:
        res = fn()
        raise AssertionError(f"{{label}} unexpectedly succeeded: {{res!r}}")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{{label}}: {{pe}}"

for jbase in (os.path.join("denied", "junc_to_py"), os.path.join("allowed", "junc_allowed_to_py")):
    expect_denied("scandir_" + jbase, lambda jb=jbase: list(os.scandir(jb)))
    expect_denied("listdir_" + jbase, lambda jb=jbase: os.listdir(jb))
    if PY_FILE:
        t = os.path.join(jbase, PY_FILE)
        expect_denied("open_" + jbase, lambda p=t: open(p, "r"))
        expect_denied("stat_" + jbase, lambda p=t: os.stat(p))
        expect_denied("lstat_" + jbase, lambda p=t: os.lstat(p))

assert open(os.path.join("allowed", "ok.txt"), "r").read().strip() == "ALLOWED_16"
print("CEDAR_PY_16_OK")
"#,
            py_file = py_file
        ),
    )
    .unwrap();

    // Under Cedar allowlist-only: denied/junc_to_py is outside allowed/, while stdlib import urllib.request works.
    let cedar_allow_only_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            cedar_allowlist_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            "-c",
            &format!(
                "import os, urllib.request\ntry:\n    list(os.scandir('denied/junc_to_py'))\n    raise AssertionError('unblocked')\nexcept PermissionError as e:\n    assert 'blocked_by_octopus_policy' in str(e)\n{}\nprint('ALLOWLIST_16_OK')",
                if py_file.is_empty() {
                    String::new()
                } else {
                    format!(
                        "try:\n    open(os.path.join('denied', 'junc_to_py', {:?}), 'r')\n    raise AssertionError('unblocked')\nexcept PermissionError as e:\n    assert 'blocked_by_octopus_policy' in str(e)",
                        py_file
                    )
                }
            ),
        ])
        .output()
        .expect("run iter16 cedar allowlist probe");
    assert!(
        cedar_allow_only_out.status.success(),
        "cedar allowlist probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cedar_allow_only_out.stdout),
        String::from_utf8_lossy(&cedar_allow_only_out.stderr)
    );
    assert!(String::from_utf8_lossy(&cedar_allow_only_out.stdout).contains("ALLOWLIST_16_OK"));

    // Under Cedar explicit forbid: BOTH denied/junc_to_py AND allowed/junc_allowed_to_py are blocked.
    let cedar_forbid_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            cedar_forbid_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            cedar_py_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run iter16 cedar forbid probe");
    assert!(
        cedar_forbid_out.status.success(),
        "cedar forbid probe failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cedar_forbid_out.stdout),
        String::from_utf8_lossy(&cedar_forbid_out.stderr)
    );
    assert!(String::from_utf8_lossy(&cedar_forbid_out.stdout).contains("CEDAR_PY_16_OK"));

    // 4. Preflight \\127.0.0.1\C$\<denied> & ~/ & ../ under JSON and allowlist-only Cedar,
    // while \\127.0.0.1\C$\<allowed>, -c "print('a/b')", and https://example.com/a/b succeed.
    let dotdot_secret = "allowed/../denied/secret.txt";
    let mut json_denied_args: Vec<String> = vec![dotdot_secret.to_string()];
    #[cfg(windows)]
    {
        let denied_secret = denied_dir.join("secret.txt");
        let denied_s = denied_secret.to_string_lossy();
        if denied_s.len() >= 3 && denied_s.as_bytes()[1] == b':' {
            let drv = denied_s.chars().next().unwrap();
            let rest = &denied_s[3..];
            json_denied_args.push(format!(r"\\127.0.0.1\{}$\{}", drv, rest));
        }
        let allowed_ok = allowed_dir.join("ok.txt");
        let allowed_s = allowed_ok.to_string_lossy();
        if allowed_s.len() >= 3 && allowed_s.as_bytes()[1] == b':' {
            let drv = allowed_s.chars().next().unwrap();
            let rest = &allowed_s[3..];
            let unc_allowed = format!(r"\\127.0.0.1\{}$\{}", drv, rest);
            for pol in [&json_pol, &cedar_allowlist_pol] {
                let ok_out = Command::new(octopus_bin())
                    .args([
                        "run",
                        "--policy",
                        pol.to_str().unwrap(),
                        "--cwd",
                        ws_dir.to_str().unwrap(),
                        "--",
                        &py,
                        "-c",
                        "import sys; print('a/b', sys.argv[1])",
                        &unc_allowed,
                        "https://example.com/a/b",
                    ])
                    .output()
                    .expect("run preflight unc allowed");
                assert!(
                    ok_out.status.success(),
                    "preflight unc allowed failed ({}): stdout={} stderr={}",
                    pol.display(),
                    String::from_utf8_lossy(&ok_out.stdout),
                    String::from_utf8_lossy(&ok_out.stderr)
                );
            }
        }
    }
    if let Some(ref td) = tilde_deny_preflight {
        json_denied_args.push(format!("{}/secret.txt", td));
    }

    for pol in [&json_pol, &cedar_allowlist_pol] {
        for bad_arg in &json_denied_args {
            let pre_out = Command::new(octopus_bin())
                .args([
                    "run",
                    "--policy",
                    pol.to_str().unwrap(),
                    "--cwd",
                    ws_dir.to_str().unwrap(),
                    "--",
                    &py,
                    "-c",
                    "print('SHOULD_NOT_RUN')",
                    bad_arg,
                ])
                .output()
                .expect("run preflight denied arg");
            assert_eq!(
                pre_out.status.code(),
                Some(2),
                "preflight must exit 2 for '{}' under '{}': stdout={} stderr={}",
                bad_arg,
                pol.display(),
                String::from_utf8_lossy(&pre_out.stdout),
                String::from_utf8_lossy(&pre_out.stderr)
            );
            assert!(
                !String::from_utf8_lossy(&pre_out.stdout).contains("SHOULD_NOT_RUN"),
                "SHOULD_NOT_RUN printed for '{}' under '{}'",
                bad_arg,
                pol.display()
            );
        }
    }
}

#[test]
fn test_iteration17_async_signal_and_preflight_edge_cases() {
    let ws = TempDirGuard::new("iter17");
    let ws_dir = ws.path();
    let py = find_python();

    let allowed_dir = ws_dir.join("allowed");
    let denied_dir = ws_dir.join("denied");
    std::fs::create_dir_all(&allowed_dir).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();
    std::fs::write(allowed_dir.join("ok.txt"), "ALLOWED_17\n").unwrap();
    std::fs::write(allowed_dir.join("it's_ok.txt"), "ALLOWED_APOS_17\n").unwrap();
    std::fs::write(denied_dir.join("secret.txt"), "SECRET_17\n").unwrap();
    std::fs::write(denied_dir.join("it's_secret.txt"), "SECRET_APOS_17\n").unwrap();
    std::fs::write(ws_dir.join("allowed.txt"), "ROOT_ALLOWED_17\n").unwrap();
    std::fs::write(ws_dir.join("secret.txt"), "ROOT_SECRET_17\n").unwrap();

    let json_pol = ws_dir.join("policy_iter17.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": [] },
            "filesystem": {
                "allow_read": ["."],
                "allow_write": ["allowed"],
                "deny": ["denied", "./secret.txt"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();
    let denied_canon = std::fs::canonicalize(&denied_dir).unwrap_or_else(|_| denied_dir.clone());
    let denied_raw = denied_canon.to_string_lossy().replace('\\', "/");
    let denied_cedar = denied_raw
        .strip_prefix("//?/")
        .unwrap_or(&denied_raw)
        .to_ascii_lowercase();
    let ws_canon = std::fs::canonicalize(ws_dir).unwrap_or_else(|_| ws_dir.to_path_buf());
    let ws_raw = ws_canon.to_string_lossy().replace('\\', "/");
    let ws_cedar = ws_raw
        .strip_prefix("//?/")
        .unwrap_or(&ws_raw)
        .to_ascii_lowercase();
    let root_secret_cedar = format!("{}/secret.txt", ws_cedar);

    let cedar_allowlist_pol = ws_dir.join("policy_allowlist_iter17.cedar");
    std::fs::write(
        &cedar_allowlist_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{allowed}/*" }};
"#,
            allowed = allowed_cedar
        ),
    )
    .unwrap();

    let cedar_forbid_pol = ws_dir.join("policy_forbid_iter17.cedar");
    std::fs::write(
        &cedar_forbid_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{ws}/*" }};
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && (context.normalized_path like "{denied}*" || context.normalized_path == "{root_secret}") }};
"#,
            ws = ws_cedar,
            denied = denied_cedar,
            root_secret = root_secret_cedar
        ),
    )
    .unwrap();

    // 1. d200 (_thread.interrupt_main + SIGINT handler + open("secret.txt") PermissionError) under JSON & Cedar
    let d200_script = ws_dir.join("d200_iter17.py");
    std::fs::write(
        &d200_script,
        r#"import signal, threading, time, _thread

seen = 0
def h(s, f):
    global seen
    seen += 1

signal.signal(signal.SIGINT, h)
stop = False
def bomber():
    while not stop:
        try:
            _thread.interrupt_main()
        except Exception:
            pass
        time.sleep(0.0005)

t = threading.Thread(target=bomber, daemon=True)
t.start()
try:
    for _ in range(250):
        try:
            open("secret.txt", "r").close()
            raise AssertionError("secret.txt unexpectedly opened")
        except PermissionError as pe:
            assert "blocked_by_octopus_policy" in str(pe)
        assert open("allowed.txt", "r").read().strip() == "ROOT_ALLOWED_17"
finally:
    stop = True
    t.join(timeout=2.0)

assert seen > 0, f"expected seen > 0, got {seen}"
print("D200_ITER17_OK", seen)
"#,
    )
    .unwrap();
    for pol in [&json_pol, &cedar_forbid_pol] {
        let out = Command::new(octopus_bin())
            .args([
                "run",
                "--timeout",
                "60",
                "--policy",
                pol.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
                d200_script.to_str().unwrap(),
            ])
            .output()
            .expect("run d200_iter17");
        assert!(
            out.status.success(),
            "d200_iter17 failed under {}: exit={:?} stdout={} stderr={}",
            pol.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("D200_ITER17_OK"),
            "missing marker under {}: {}",
            pol.display(),
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).trim().is_empty(),
            "unexpected stderr under {}: {}",
            pol.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // 2. sig_deny_nogc (signal.raise_signal(SIGTERM) + os.stat("secret.txt") + os.stat("allowed.txt"))
    let sig_deny_nogc = ws_dir.join("sig_deny_nogc_iter17.py");
    std::fs::write(
        &sig_deny_nogc,
        r#"import os, signal, threading, time

seen = 0
def h(s, f):
    global seen
    seen += 1

signal.signal(signal.SIGTERM, h)
stop = False
def bomber():
    while not stop:
        try:
            signal.raise_signal(signal.SIGTERM)
        except Exception:
            pass
        time.sleep(0.0005)

deny_count = 0
allow_count = 0
iters = 0
_acc = 0
t = threading.Thread(target=bomber, daemon=True)
t.start()
try:
    while iters < 180 or (seen < 2 and iters < 600):
        iters += 1
        try:
            os.stat("secret.txt")
            raise AssertionError("os.stat(secret.txt) unexpectedly succeeded")
        except PermissionError as pe:
            assert "blocked_by_octopus_policy" in str(pe)
            deny_count += 1
        assert os.stat("allowed.txt").st_size > 0
        allow_count += 1
        _acc = 0
        for _k in range(25000):
            _acc += _k
finally:
    stop = True
    t.join(timeout=2.0)

assert deny_count == iters and deny_count >= 180
assert allow_count == iters and allow_count >= 180
assert _acc > 0
assert seen > 0, f"expected seen > 0, got {seen}"
print("SIG_DENY_NOGC_ITER17_OK", seen)
"#,
    )
    .unwrap();
    let out_nogc = Command::new(octopus_bin())
        .args([
            "run",
            "--timeout",
            "60",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            sig_deny_nogc.to_str().unwrap(),
        ])
        .output()
        .expect("run sig_deny_nogc_iter17");
    assert!(
        out_nogc.status.success(),
        "sig_deny_nogc_iter17 failed: exit={:?} stdout={} stderr={}",
        out_nogc.status.code(),
        String::from_utf8_lossy(&out_nogc.stdout),
        String::from_utf8_lossy(&out_nogc.stderr)
    );
    assert!(String::from_utf8_lossy(&out_nogc.stdout).contains("SIG_DENY_NOGC_ITER17_OK"));
    assert!(String::from_utf8_lossy(&out_nogc.stderr).trim().is_empty());

    // 3. d200_prof + sys.monitoring + default_int_handler + PermissionError + zero internal frame leaks
    let prof_mon_script = ws_dir.join("prof_mon_default_int_iter17.py");
    std::fs::write(
        &prof_mon_script,
        r#"import os, signal, sys, threading, time, _thread

leaked = []
seen = 0
def h(s, f):
    global seen
    seen += 1
    cur = f
    while cur is not None:
        fn = getattr(cur.f_code, "co_filename", "")
        if fn.startswith("<octopus"):
            leaked.append(fn)
        cur = cur.f_back

def prof(frame, event, arg):
    fn = getattr(frame.f_code, "co_filename", "")
    if fn.startswith("<octopus"):
        leaked.append(fn)

E = sys.monitoring.events
M = sys.monitoring
tid = 4
M.use_tool_id(tid, "oct_iter17_mon")
def mon_cb(*args):
    c = args[0]
    if hasattr(c, "co_filename") and c.co_filename.startswith("<octopus"):
        leaked.append(c.co_filename)
    return None

M.register_callback(tid, E.CALL, mon_cb)
M.register_callback(tid, E.C_RETURN, mon_cb)
M.register_callback(tid, E.C_RAISE, mon_cb)
M.register_callback(tid, E.RAISE, mon_cb)
M.set_events(tid, E.CALL | E.C_RETURN | E.C_RAISE | E.RAISE)

sys.setprofile(prof)
signal.signal(signal.SIGINT, h)
stop = False
def bomber():
    while not stop:
        try:
            _thread.interrupt_main()
        except Exception:
            pass
        time.sleep(0.001)

t = threading.Thread(target=bomber, daemon=True)
try:
    t.start()
    for _ in range(180):
        try:
            open("secret.txt", "r").close()
            raise AssertionError("open(secret.txt) unblocked")
        except PermissionError:
            pass
        try:
            os.stat("secret.txt")
            raise AssertionError("os.stat(secret.txt) unblocked")
        except PermissionError:
            pass
        _acc = 0
        for _k in range(25000):
            _acc += _k
finally:
    stop = True
    t.join(timeout=2.0)
    sys.setprofile(None)
    M.set_events(tid, 0)
    for ev in (E.CALL, E.C_RETURN, E.C_RAISE, E.RAISE):
        M.register_callback(tid, ev, None)
    M.free_tool_id(tid)

assert seen > 0, f"expected seen > 0, got {seen}"
assert not leaked, f"leaked internal frames: {leaked}"

# Verify default_int_handler raises KeyboardInterrupt normally in user code AND is wrapped safely across PermissionError
assert signal.signal(signal.SIGINT, signal.default_int_handler) is h
assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
try:
    _thread.interrupt_main()
    time.sleep(0.05)
    raise AssertionError("default_int_handler did not raise KeyboardInterrupt in user code")
except KeyboardInterrupt:
    pass

ki_count = 0
stop2 = False
def int_bomber():
    while not stop2:
        try:
            _thread.interrupt_main()
        except Exception:
            pass
        time.sleep(0.001)

t2 = threading.Thread(target=int_bomber, daemon=True)
try:
    try:
        t2.start()
    except KeyboardInterrupt:
        ki_count += 1
    for _ in range(150):
        try:
            open("secret.txt", "r").close()
        except PermissionError:
            pass
        except KeyboardInterrupt:
            ki_count += 1
except KeyboardInterrupt:
    ki_count += 1
finally:
    stop2 = True
    while True:
        try:
            t2.join(timeout=2.0)
            break
        except KeyboardInterrupt:
            ki_count += 1
    # Drain any pending signal before leaving try block
    try:
        time.sleep(0.02)
    except KeyboardInterrupt:
        ki_count += 1

print("PROF_MON_DEFAULT_INT_ITER17_OK", seen, ki_count)
"#,
    )
    .unwrap();
    let out_prof = Command::new(octopus_bin())
        .args([
            "run",
            "--timeout",
            "60",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            prof_mon_script.to_str().unwrap(),
        ])
        .output()
        .expect("run prof_mon_default_int_iter17");
    assert!(
        out_prof.status.success(),
        "prof_mon_default_int_iter17 failed: exit={:?} stdout={} stderr={}",
        out_prof.status.code(),
        String::from_utf8_lossy(&out_prof.stdout),
        String::from_utf8_lossy(&out_prof.stderr)
    );
    assert!(String::from_utf8_lossy(&out_prof.stdout).contains("PROF_MON_DEFAULT_INT_ITER17_OK"));

    // 4. Anti-spoof invariants for _AUDIT_GATE_WD_* and _INTERNAL_GLOBALS_*
    let spoof_script = ws_dir.join("spoof_check_iter17.py");
    std::fs::write(
        &spoof_script,
        r#"import os, signal, types

sg = signal.signal.__globals__
assert len(sg["_AUDIT_GATE_WD_IDS"]) == 3
assert len(sg["_INTERNAL_GLOBALS_IDS"]) >= 8
assert sg["_AUDIT_GATE_WD_IDS"].issubset(sg["_INTERNAL_GLOBALS_IDS"])
assert len(sg["_AUDIT_GATE_WD_HASHES"]) == 3
assert len(sg["_INTERNAL_GLOBALS_HASHES"]) == len(sg["_INTERNAL_GLOBALS_IDS"])
assert sg["_AUDIT_GATE_WD_HASHES"].issubset(sg["_INTERNAL_GLOBALS_HASHES"])

# Calling handler directly from a frame with os.stat.__globals__ (not in _AUDIT_GATE_WD_HASHES, IS in _INTERNAL_GLOBALS_HASHES)
# must NOT bypass via _AUDIT_GATE_WD_HASHES and must call user fn ONLY if not internal; since os.stat.__globals__ IS internal, it returns None after signal_guard.
seen_spoof = []
def user_h(s, f):
    seen_spoof.append((s, f))

# Wrap user_h via a fake globals dict created via type(sg)()
FakeDict = type(sg)
fake_d = FakeDict()
assert object.__hash__(fake_d) not in sg["_AUDIT_GATE_WD_HASHES"]
assert object.__hash__(fake_d) not in sg["_INTERNAL_GLOBALS_HASHES"]

def probe_from_fake():
    return True

# Function bound to os.stat.__globals__ cannot spoof _AUDIT_GATE_WD_HASHES
f_stat = types.FunctionType(probe_from_fake.__code__, os.stat.__globals__)
assert f_stat() is True

print("SPOOF_CHECK_ITER17_OK")
"#,
    )
    .unwrap();
    let out_spoof = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            json_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            spoof_script.to_str().unwrap(),
        ])
        .output()
        .expect("run spoof_check_iter17");
    assert!(
        out_spoof.status.success(),
        "spoof_check_iter17 failed: exit={:?} stdout={} stderr={}",
        out_spoof.status.code(),
        String::from_utf8_lossy(&out_spoof.stdout),
        String::from_utf8_lossy(&out_spoof.stderr)
    );
    assert!(String::from_utf8_lossy(&out_spoof.stdout).contains("SPOOF_CHECK_ITER17_OK"));

    // 5. Preflight edge cases (must exit 2 without printing SHOULD_NOT_RUN)
    #[allow(unused_mut)]
    let mut preflight_bad_args: Vec<String> = vec![
        "-f=allowed/../denied/secret.txt".to_string(),
        "\"-f=allowed/../denied/secret.txt\"".to_string(),
        "-o='allowed/../denied/secret.txt'".to_string(),
        "\"\"allowed/../denied/secret.txt\"\"".to_string(),
        "\"\\\"allowed/../denied/secret.txt\\\"\"".to_string(),
        "'allowed/../denied/secret.txt'".to_string(),
        "--flag=\"\\\"allowed/../denied/secret.txt\\\"\"".to_string(),
        "--flag='allowed/../denied/secret.txt'".to_string(),
        "-c=denied/secret.txt".to_string(),
        "denied/it's_secret.txt".to_string(),
        "-f=denied/it's_secret.txt".to_string(),
    ];
    #[cfg(windows)]
    {
        let denied_s = denied_dir.join("secret.txt").to_string_lossy().to_string();
        if denied_s.len() >= 3 && denied_s.as_bytes()[1] == b':' {
            let drv = denied_s.chars().next().unwrap();
            let rest = &denied_s[3..];
            let unc = format!(r"\\127.0.0.1\{}$\{}", drv, rest);
            preflight_bad_args.push(format!("-f={}", unc));
            preflight_bad_args.push(format!("\"-f={}\"", unc));
            preflight_bad_args.push(format!("\"\\\"{}\\\"\"", unc));
            preflight_bad_args.push(format!("'{}'", unc));
            preflight_bad_args.push(format!("--flag=\"\\\"{}\\\"\"", unc));
        }
        preflight_bad_args.push(r"-f=\\127.0.0.1\ADMIN$\win.ini".to_string());
        preflight_bad_args.push(r"'\\127.0.0.1\ADMIN$\win.ini'".to_string());
    }

    for pol in [&json_pol, &cedar_allowlist_pol, &cedar_forbid_pol] {
        for bad_arg in &preflight_bad_args {
            let pre_out = Command::new(octopus_bin())
                .args([
                    "run",
                    "--policy",
                    pol.to_str().unwrap(),
                    "--cwd",
                    ws_dir.to_str().unwrap(),
                    "--",
                    &py,
                    "-c",
                    "print('SHOULD_NOT_RUN')",
                    bad_arg,
                ])
                .output()
                .expect("run iter17 preflight bad arg");
            assert_eq!(
                pre_out.status.code(),
                Some(2),
                "preflight must exit 2 for '{}' under '{}': stdout={} stderr={}",
                bad_arg,
                pol.display(),
                String::from_utf8_lossy(&pre_out.stdout),
                String::from_utf8_lossy(&pre_out.stderr)
            );
            assert!(
                !String::from_utf8_lossy(&pre_out.stdout).contains("SHOULD_NOT_RUN"),
                "SHOULD_NOT_RUN printed for '{}' under '{}'",
                bad_arg,
                pol.display()
            );
        }
    }

    // 6. Positive controls for preflight + Cedar apostrophe EntityUid evaluation
    let positive_cases: Vec<Vec<&str>> = vec![
        vec!["-c", "print('POS_NONPATH')", "-f=json", "-f=123", "\"foo"],
        vec![
            "-W",
            "ignore",
            "-X",
            "utf8",
            "-X",
            "dev=1",
            "-cx=1/2; print('POS_ATTACHED', x)",
        ],
        vec!["-c\"x=1/2\""],
        vec![
            "-c",
            "import sys; print('POS_URL', sys.argv[1], sys.argv[2])",
            "\"https://example.com/a/b\"",
            "--url='https://example.com/a/b'",
        ],
        vec![
            "-c",
            "import sys; print('POS_ALLOWED_APOS', sys.argv[1])",
            "allowed/it's_ok.txt",
        ],
        vec![
            "-c",
            "import sys; print('POS_ALLOWED_FLAG', sys.argv[1])",
            "-f=allowed/ok.txt",
            "'allowed/ok.txt'",
            "--flag='allowed/ok.txt'",
        ],
    ];
    for pol in [&json_pol, &cedar_allowlist_pol, &cedar_forbid_pol] {
        for args_slice in &positive_cases {
            let mut full_args: Vec<&str> = vec![
                "run",
                "--policy",
                pol.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
            ];
            full_args.extend_from_slice(args_slice);
            let ok_out = Command::new(octopus_bin())
                .args(&full_args)
                .output()
                .expect("run iter17 positive preflight");
            assert!(
                ok_out.status.success(),
                "positive preflight {:?} failed under {}: exit={:?} stdout={} stderr={}",
                args_slice,
                pol.display(),
                ok_out.status.code(),
                String::from_utf8_lossy(&ok_out.stdout),
                String::from_utf8_lossy(&ok_out.stderr)
            );
        }
    }
}

#[test]
fn test_iteration19_ctypes_ffi_block_and_stdlib_compatibility() {
    let ws = TempDirGuard::new("iter19_ctypes");
    let ws_dir = ws.path();
    let py = find_python();

    let allowed_dir = ws_dir.join("allowed");
    let denied_dir = ws_dir.join("denied");
    std::fs::create_dir_all(&allowed_dir).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();
    std::fs::write(allowed_dir.join("ok.txt"), "ALLOWED_19\n").unwrap();
    std::fs::write(denied_dir.join("secret.txt"), "SECRET_19\n").unwrap();

    let minimal_pol = ws_dir.join("policy_minimal_iter19.json");
    std::fs::write(&minimal_pol, r#"{"allowed_domains":[]}"#).unwrap();

    let json_pol = ws_dir.join("policy_json_iter19.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "powershell", "bash"] },
            "filesystem": {
                "allow_read": ["allowed"],
                "allow_write": ["allowed"],
                "deny": ["denied"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();

    let cedar_allowlist_pol = ws_dir.join("policy_allowlist_iter19.cedar");
    std::fs::write(
        &cedar_allowlist_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{allowed}/*" }};
"#,
            allowed = allowed_cedar
        ),
    )
    .unwrap();

    let ctypes_block_script = ws_dir.join("ctypes_blocks.py");
    std::fs::write(
        &ctypes_block_script,
        r#"import importlib, os, sys

def expect_blocked(fn, label):
    try:
        fn()
        raise AssertionError(f"{label} unexpectedly succeeded")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{label} wrong msg: {pe}"

expect_blocked(lambda: __import__("ctypes"), "import ctypes")
expect_blocked(lambda: __import__("_ctypes"), "import _ctypes")
expect_blocked(lambda: importlib.import_module("ctypes.wintypes"), "import ctypes.wintypes")
expect_blocked(lambda: sys.audit("ctypes.dlopen", "kernel32"), "audit ctypes.dlopen")
expect_blocked(lambda: sys.audit("ctypes.cdata", 0), "audit ctypes.cdata")
expect_blocked(lambda: sys.audit("ctypes.call_function", 0, ()), "audit ctypes.call_function")
expect_blocked(lambda: sys.audit("import", "fake_ext", "~/.ssh/id_rsa.pyd", None, None, None), "audit import sensitive pyd")
expect_blocked(lambda: sys.audit("import", "fake_ext", "allowed/_ctypes.cp313-win_amd64.pyd", None, None, None), "audit import _ctypes pyd")
if os.environ.get("OCT_TEST_DENY_PYD") == "1":
    expect_blocked(lambda: sys.audit("import", "fake_ext", "denied/fake.pyd", None, None, None), "audit import denied pyd")

print("CTYPES_BLOCK_OK")
"#,
    )
    .unwrap();

    for (pol, has_fs) in [
        (&minimal_pol, false),
        (&json_pol, true),
        (&cedar_allowlist_pol, true),
    ] {
        let mut cmd = Command::new(octopus_bin());
        cmd.args([
            "run",
            "--policy",
            pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            ctypes_block_script.to_str().unwrap(),
        ]);
        if has_fs {
            cmd.env("OCT_TEST_DENY_PYD", "1");
        }
        let out = cmd.output().expect("run ctypes_block_script");
        assert!(
            out.status.success(),
            "ctypes_block_script failed under {}: exit={:?} stdout={} stderr={}",
            pol.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("CTYPES_BLOCK_OK"));
    }

    let stdlib_script = ws_dir.join("stdlib_smoke.py");
    std::fs::write(
        &stdlib_script,
        r#"import asyncio, getpass, hashlib, http.client, http.server, json, mimetypes, os, pathlib, platform, shutil, socket, sqlite3, ssl, subprocess, sys, tempfile, urllib.request, uuid
import multiprocessing.shared_memory

assert len(str(uuid.uuid4())) == 36
assert platform.platform()
conn = sqlite3.connect(":memory:")
assert conn.execute("select 1").fetchone()[0] == 1
conn.close()
ctx = ssl.create_default_context()
assert ctx is not None
s = socket.socket()
s.close()
asyncio.run(asyncio.sleep(0.001))
assert getpass.getuser()
if os.environ.get("OCT_TEST_MIMETYPES_FULL") == "1":
    assert mimetypes.guess_type("a.txt")[0] == "text/plain"
else:
    mimetypes.inited = True
    _mt = mimetypes.MimeTypes()
    _mt.read_windows_registry()
    assert _mt.guess_type("a.txt")[0] == "text/plain"
assert isinstance(urllib.request.getproxies(), dict)
p_out = subprocess.run([sys.executable, "-c", "print('SUB_OK')"], capture_output=True, text=True, check=True)
assert "SUB_OK" in p_out.stdout
print("STDLIB_SMOKE_OK")
"#,
    )
    .unwrap();

    for (pol, full_mime) in [(&json_pol, true), (&cedar_allowlist_pol, false)] {
        let mut cmd = Command::new(octopus_bin());
        cmd.args([
            "run",
            "--policy",
            pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            stdlib_script.to_str().unwrap(),
        ]);
        if full_mime {
            cmd.env("OCT_TEST_MIMETYPES_FULL", "1");
        }
        let out = cmd.output().expect("run stdlib_smoke");
        assert!(
            out.status.success(),
            "stdlib_smoke failed under {}: exit={:?} stdout={} stderr={}",
            pol.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("STDLIB_SMOKE_OK"));
    }
}

#[test]
fn test_iteration19_winapi_and_os_native_containment() {
    let ws = TempDirGuard::new("iter19_winapi");
    let ws_dir = ws.path();
    let py = find_python();

    let allowed_dir = ws_dir.join("allowed");
    let allowed_sub = allowed_dir.join("sub");
    let denied_dir = ws_dir.join("denied");
    let outside_dir = ws_dir.join("outside");
    std::fs::create_dir_all(&allowed_sub).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::fs::create_dir_all(allowed_dir.join(".git")).unwrap();
    std::fs::write(allowed_dir.join("ok.txt"), "ALLOWED_19\n").unwrap();
    std::fs::write(allowed_sub.join("sub.txt"), "SUB_19\n").unwrap();
    std::fs::write(denied_dir.join("secret.txt"), "SECRET_19\n").unwrap();

    let json_pol = ws_dir.join("policy_json_winapi.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "powershell", "bash"] },
            "filesystem": {
                "allow_read": ["allowed"],
                "allow_write": ["allowed"],
                "deny": ["denied"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();
    let denied_canon = std::fs::canonicalize(&denied_dir).unwrap_or_else(|_| denied_dir.clone());
    let denied_raw = denied_canon.to_string_lossy().replace('\\', "/");
    let denied_cedar = denied_raw
        .strip_prefix("//?/")
        .unwrap_or(&denied_raw)
        .to_ascii_lowercase();
    let ws_canon = std::fs::canonicalize(ws_dir).unwrap_or_else(|_| ws_dir.to_path_buf());
    let ws_raw = ws_canon.to_string_lossy().replace('\\', "/");
    let ws_cedar = ws_raw
        .strip_prefix("//?/")
        .unwrap_or(&ws_raw)
        .to_ascii_lowercase();

    let cedar_allowlist_pol = ws_dir.join("policy_allowlist_winapi.cedar");
    std::fs::write(
        &cedar_allowlist_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && (context.normalized_path == "{allowed}" || context.normalized_path like "{allowed}/*") }};
permit (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when {{
    context has normalized_path
    && context.normalized_path like "{allowed}/*"
    && !(context has is_mandatory_deny && context.is_mandatory_deny == true)
  }};
"#,
            allowed = allowed_cedar
        ),
    )
    .unwrap();

    let cedar_forbid_pol = ws_dir.join("policy_forbid_winapi.cedar");
    std::fs::write(
        &cedar_forbid_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{ws}/*" }};
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{denied}*" }};
permit (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when {{
    context has normalized_path
    && context.normalized_path like "{allowed}/*"
    && !(context has is_mandatory_deny && context.is_mandatory_deny == true)
  }};
forbid (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{denied}*" }};
"#,
            ws = ws_cedar,
            allowed = allowed_cedar,
            denied = denied_cedar
        ),
    )
    .unwrap();

    let winapi_script = ws_dir.join("winapi_probe.py");
    std::fs::write(
        &winapi_script,
        r#"import asyncio, mimetypes, multiprocessing.connection, os, platform, shutil, sys, urllib.request

def expect_blocked(fn, label):
    try:
        fn()
        raise AssertionError(f"{label} unexpectedly succeeded")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{label} wrong msg: {pe}"

class EvilStr(str):
    def __str__(self):
        return "allowed"

# Cross-platform shutil defense-in-depth
expect_blocked(lambda: shutil.copytree("denied", "allowed/ct_denied"), "shutil.copytree denied")
expect_blocked(lambda: shutil.move("denied/secret.txt", "allowed/moved.txt"), "shutil.move denied")
expect_blocked(lambda: shutil.make_archive("denied/arch", "zip", "allowed"), "shutil.make_archive denied")
dst_copy = "allowed/sub_copy_" + str(os.getpid())
if os.path.exists(dst_copy):
    shutil.rmtree(dst_copy)
shutil.copytree("allowed/sub", dst_copy)
assert os.path.isfile(os.path.join(dst_copy, "sub.txt"))

if sys.platform == "win32":
    import _winapi, nt, winreg

    # 1. _winapi.CreateJunction blocks
    expect_blocked(lambda: _winapi.CreateJunction("allowed", "denied/j_in_denied"), "CreateJunction in denied")
    expect_blocked(lambda: _winapi.CreateJunction("denied", "allowed/j_to_denied"), "CreateJunction to denied")
    expect_blocked(lambda: _winapi.CreateJunction("denied", "outside/j_outside"), "CreateJunction outside")
    expect_blocked(lambda: _winapi.CreateJunction("allowed", "allowed/.git/hooks"), "CreateJunction .git/hooks")
    expect_blocked(lambda: _winapi.CreateJunction(EvilStr("denied"), "allowed/j_evil"), "CreateJunction EvilStr")
    expect_blocked(lambda: sys.audit("_winapi.CreateJunction", EvilStr("allowed"), "allowed/j_evil"), "audit CreateJunction EvilStr")

    j_ok = "allowed/j_ok_" + str(os.getpid())
    if os.path.exists(j_ok):
        os.rmdir(j_ok)
    _winapi.CreateJunction(os.path.abspath("allowed/sub"), j_ok)
    assert os.path.isjunction(j_ok)
    assert open(os.path.join(j_ok, "sub.txt"), "r").read().strip() == "SUB_19"
    os.rmdir(j_ok)

    # 2. _winapi.CreateFile blocks + self-PID pipe positive controls
    expect_blocked(lambda: _winapi.CreateFile("denied/secret.txt", 0x80000000, 3, 0, 3, 0, 0), "CreateFile read denied")
    expect_blocked(lambda: _winapi.CreateFile("allowed/.git/hooks/pre-commit", 0x40000000, 0, 0, 2, 0, 0), "CreateFile write .git/hooks")
    expect_blocked(lambda: _winapi.CreateFile("outside/pwn.txt", 0x40000000, 0, 0, 2, 0, 0), "CreateFile write outside")
    pipe_trav = "\\\\.\\pipe\\python-pipe-" + str(os.getpid()) + "-x\\..\\..\\denied\\secret.txt"
    expect_blocked(lambda: _winapi.CreateFile(pipe_trav, 0x80000000, 3, 0, 3, 0, 0), "CreateFile pipe traversal")

    h_ok = _winapi.CreateFile("allowed/cf_ok_" + str(os.getpid()) + ".txt", 0x40000000, 0, 0, 2, 0, 0)
    _winapi.WriteFile(h_ok, b"CF_OK")
    _winapi.CloseHandle(h_ok)

    c1, c2 = multiprocessing.connection.Pipe()
    c1.send("ping")
    assert c2.recv() == "ping"
    c1.close()
    c2.close()

    async def run_sub():
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "print('ASYNC_SUB_OK')",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, _ = await proc.communicate()
        assert proc.returncode == 0 and b"ASYNC_SUB_OK" in out
    asyncio.run(run_sub())

    # 3. nt._findfirstfile, os.add_dll_directory, winreg.*
    expect_blocked(lambda: nt._findfirstfile("denied/*"), "nt._findfirstfile denied")
    assert nt._findfirstfile("allowed/*")
    expect_blocked(lambda: os.add_dll_directory(os.path.abspath("denied")), "os.add_dll_directory denied")
    expect_blocked(lambda: winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\__OctIter19Test__"), "winreg.CreateKey")
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software")
    winreg.CloseKey(k)
    if os.environ.get("OCT_TEST_MIMETYPES_FULL") == "1":
        assert mimetypes.guess_type("a.txt")[0] == "text/plain"
    else:
        mimetypes.inited = True
        _mt = mimetypes.MimeTypes()
        _mt.read_windows_registry()
        assert _mt.guess_type("a.txt")[0] == "text/plain"
    assert isinstance(urllib.request.getproxies(), dict)
    assert platform.platform()

print("WINAPI_CONTAINMENT_OK")
"#,
    )
    .unwrap();

    for (pol, full_mime) in [
        (&json_pol, true),
        (&cedar_allowlist_pol, false),
        (&cedar_forbid_pol, false),
    ] {
        let mut cmd = Command::new(octopus_bin());
        cmd.args([
            "run",
            "--policy",
            pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &py,
            winapi_script.to_str().unwrap(),
        ]);
        if full_mime {
            cmd.env("OCT_TEST_MIMETYPES_FULL", "1");
        }
        let out = cmd.output().expect("run winapi_script");
        assert!(
            out.status.success(),
            "winapi_script failed under {}: exit={:?} stdout={} stderr={}",
            pol.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("WINAPI_CONTAINMENT_OK"));
    }
}

#[test]
fn test_iteration19_preflight_dotdot_and_colon_flags() {
    let ws = TempDirGuard::new("iter19_preflight");
    let ws_dir = ws.path();
    let py = find_python();

    let allowed_dir = ws_dir.join("allowed");
    let denied_dir = ws_dir.join("denied");
    std::fs::create_dir_all(&allowed_dir).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();
    std::fs::write(allowed_dir.join("ok.txt"), "ALLOWED_19\n").unwrap();
    // Note: intentionally keep denied_dir empty so denied/nonexistent.txt does NOT exist on disk!

    let json_pol = ws_dir.join("policy_preflight_iter19.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": [] },
            "filesystem": {
                "allow_read": ["."],
                "allow_write": ["allowed"],
                "deny": ["denied", ".git"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();
    let denied_canon = std::fs::canonicalize(&denied_dir).unwrap_or_else(|_| denied_dir.clone());
    let denied_raw = denied_canon.to_string_lossy().replace('\\', "/");
    let denied_cedar = denied_raw
        .strip_prefix("//?/")
        .unwrap_or(&denied_raw)
        .to_ascii_lowercase();
    let ws_canon = std::fs::canonicalize(ws_dir).unwrap_or_else(|_| ws_dir.to_path_buf());
    let ws_raw = ws_canon.to_string_lossy().replace('\\', "/");
    let ws_cedar = ws_raw
        .strip_prefix("//?/")
        .unwrap_or(&ws_raw)
        .to_ascii_lowercase();
    let git_cedar = format!("{}/.git", ws_cedar);

    let cedar_allowlist_pol = ws_dir.join("policy_preflight_allowlist.cedar");
    std::fs::write(
        &cedar_allowlist_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{allowed}/*" }};
"#,
            allowed = allowed_cedar
        ),
    )
    .unwrap();

    let cedar_forbid_pol = ws_dir.join("policy_preflight_forbid.cedar");
    std::fs::write(
        &cedar_forbid_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{ws}/*" }};
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && (context.normalized_path like "{denied}*" || context.normalized_path like "{git}*") }};
"#,
            ws = ws_cedar,
            denied = denied_cedar,
            git = git_cedar
        ),
    )
    .unwrap();

    #[allow(unused_mut)]
    let mut bad_args: Vec<String> = vec![
        "allowed/../denied/nonexistent.txt".to_string(),
        "allowed/./../denied/nonexistent.txt".to_string(),
        "-f=allowed/../denied/nonexistent.txt".to_string(),
        "-f:allowed/../denied/nonexistent.txt".to_string(),
        "allowed/..:stream/denied/nonexistent.txt".to_string(),
        "allowed/../.git/hooks/pre-commit".to_string(),
        "denied./nonexistent.txt.".to_string(),
        "denied../nonexistent.txt".to_string(),
        "-f:denied/nonexistent.txt".to_string(),
        "--file:denied/nonexistent.txt".to_string(),
        "-f:\"denied/nonexistent.txt\"".to_string(),
        "\"-f:denied/nonexistent.txt\"".to_string(),
    ];

    #[cfg(windows)]
    {
        let ws_clean = ws_raw
            .strip_prefix("//?/")
            .unwrap_or(&ws_raw)
            .replace('/', "\\");
        if ws_clean.len() >= 3 && ws_clean.as_bytes()[1] == b':' {
            let drv = ws_clean.chars().next().unwrap();
            let rest = &ws_clean[3..];
            bad_args.push(format!(
                r"\\127.0.0.1\{}$\{}\allowed\..\denied\nonexistent.txt",
                drv, rest
            ));
            bad_args.push(format!(
                r"\\?\{}\allowed\..\denied\nonexistent.txt",
                ws_clean
            ));
            bad_args.push(format!("{}:allowed/../denied/nonexistent.txt", drv));
            bad_args.push(format!(
                r"-o:\\127.0.0.1\{}$\{}\denied\nonexistent.txt",
                drv, rest
            ));
            bad_args.push(format!(r"-f:{}\denied\nonexistent.txt", ws_clean));
        }
        bad_args.push(r"-f:\\127.0.0.1\ADMIN$\win.ini".to_string());
    }

    for pol in [&json_pol, &cedar_allowlist_pol, &cedar_forbid_pol] {
        for bad_arg in &bad_args {
            let out = Command::new(octopus_bin())
                .args([
                    "run",
                    "--policy",
                    pol.to_str().unwrap(),
                    "--cwd",
                    ws_dir.to_str().unwrap(),
                    "--",
                    &py,
                    "-c",
                    "print('SHOULD_NOT_RUN')",
                    bad_arg,
                ])
                .output()
                .expect("run iter19 preflight bad arg");
            assert_eq!(
                out.status.code(),
                Some(2),
                "preflight must exit 2 for '{}' under '{}': stdout={} stderr={}",
                bad_arg,
                pol.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains("SHOULD_NOT_RUN"),
                "SHOULD_NOT_RUN printed for '{}' under '{}'",
                bad_arg,
                pol.display()
            );
        }
    }

    let positive_cases: Vec<Vec<&str>> = vec![
        vec![
            "-c",
            "import sys; print('POS_COLON', len(sys.argv))",
            "-f:allowed/ok.txt",
            "--file:allowed/ok.txt",
            "-f:json",
            "-f:123",
            "foo:bar",
            "https://example.com/foo",
            "--url:https://example.com/foo",
            "--url=https://example.com/foo",
        ],
        vec![
            "-c",
            "import sys; print('POS_WX', len(sys.argv))",
            "-W:ignore",
            "-X:utf8",
            "-X:dev=1",
            "-W:default::DeprecationWarning",
        ],
        vec![
            "-c",
            "import sys; print('POS_DOTSPACE', sys.argv[1], sys.argv[2])",
            "allowed/.. /denied/nonexistent.txt",
            "allowed/.../denied/nonexistent.txt",
        ],
    ];
    for pol in [&json_pol, &cedar_allowlist_pol, &cedar_forbid_pol] {
        for args_slice in &positive_cases {
            let mut full_args: Vec<&str> = vec![
                "run",
                "--policy",
                pol.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
            ];
            full_args.extend_from_slice(args_slice);
            let ok_out = Command::new(octopus_bin())
                .args(&full_args)
                .output()
                .expect("run iter19 positive preflight");
            assert!(
                ok_out.status.success(),
                "positive preflight {:?} failed under {}: exit={:?} stdout={} stderr={}",
                args_slice,
                pol.display(),
                ok_out.status.code(),
                String::from_utf8_lossy(&ok_out.stdout),
                String::from_utf8_lossy(&ok_out.stderr)
            );
        }
    }
}

#[test]
fn test_iteration20_pinned_parent_protection() {
    let ws = TempDirGuard::new("iter20_pinned");
    let ws_dir = ws.path();
    let py = find_python();

    let allowed_dir = ws_dir.join("allowed");
    let denied_dir = ws_dir.join("denied");
    std::fs::create_dir_all(allowed_dir.join("repo_real/.git/hooks")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("repo_real/.claude/commands")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("empty_git/.git")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("empty_claude/.claude")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("parent_with_git/nested/.git/hooks")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("evil/hooks")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("evil_claude/commands")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("sub")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("normal_dir")).unwrap();
    std::fs::create_dir_all(allowed_dir.join("new_repo")).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();

    std::fs::write(
        allowed_dir.join("repo_real/.git/HEAD"),
        "ref: refs/heads/main\n",
    )
    .unwrap();
    std::fs::write(
        allowed_dir.join("repo_real/.git/hooks/pre-commit"),
        "#!/bin/sh\necho ORIGINAL_HOOK\n",
    )
    .unwrap();
    std::fs::write(
        allowed_dir.join("repo_real/.claude/commands/safe.md"),
        "SAFE_CMD\n",
    )
    .unwrap();
    std::fs::write(
        allowed_dir.join("parent_with_git/keep.txt"),
        "KEEP_PARENT\n",
    )
    .unwrap();
    std::fs::write(
        allowed_dir.join("parent_with_git/nested/.git/hooks/pre-commit"),
        "#!/bin/sh\necho NESTED_ORIG\n",
    )
    .unwrap();
    std::fs::write(
        allowed_dir.join("evil/hooks/pre-commit"),
        "#!/bin/sh\necho PWNED\n",
    )
    .unwrap();
    std::fs::write(
        allowed_dir.join("evil_claude/commands/evil.md"),
        "PWN_CLAUDE\n",
    )
    .unwrap();
    std::fs::write(allowed_dir.join("sub/sub.txt"), "SUB_20\n").unwrap();
    std::fs::write(allowed_dir.join("normal_dir/item.txt"), "NORMAL_20\n").unwrap();
    std::fs::write(denied_dir.join("secret.txt"), "SECRET_20\n").unwrap();

    let json_pol = ws_dir.join("policy_pinned.json");
    std::fs::write(
        &json_pol,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": ["python", "python3"], "deny": ["cmd", "powershell", "bash"] },
            "filesystem": {
                "allow_read": ["allowed"],
                "allow_write": ["allowed"],
                "deny": ["denied"]
            }
        })
        .to_string(),
    )
    .unwrap();

    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();
    let denied_canon = std::fs::canonicalize(&denied_dir).unwrap_or_else(|_| denied_dir.clone());
    let denied_raw = denied_canon.to_string_lossy().replace('\\', "/");
    let denied_cedar = denied_raw
        .strip_prefix("//?/")
        .unwrap_or(&denied_raw)
        .to_ascii_lowercase();

    let cedar_permissive = ws_dir.join("policy_pinned_permissive.cedar");
    std::fs::write(
        &cedar_permissive,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && (context.normalized_path == "{allowed}" || context.normalized_path like "{allowed}/*") }};
permit (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{allowed}/*" }};
"#,
            allowed = allowed_cedar
        ),
    )
    .unwrap();

    let cedar_forbid = ws_dir.join("policy_pinned_forbid.cedar");
    std::fs::write(
        &cedar_forbid,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && (context.normalized_path == "{allowed}" || context.normalized_path like "{allowed}/*") }};
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{denied}*" }};
permit (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when {{
    context has normalized_path
    && context.normalized_path like "{allowed}/*"
    && !(context has is_mandatory_deny && context.is_mandatory_deny == true)
  }};
"#,
            allowed = allowed_cedar,
            denied = denied_cedar
        ),
    )
    .unwrap();

    let probe_script = ws_dir.join("pinned_probe.py");
    std::fs::write(
        &probe_script,
        r##"import os, shutil, sys, zipfile

def expect_blocked(fn, label):
    try:
        fn()
        raise AssertionError(f"{label} unexpectedly succeeded")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{label} wrong msg: {pe}"

evil_zip = "allowed/evil_pkg.zip"
if not os.path.exists(evil_zip):
    with zipfile.ZipFile(evil_zip, "w") as zf:
        zf.writestr("hooks/pre-commit", "#!/bin/sh\necho PWN_ZIP\n")

# 1. Existing pinned parents must not be moved, replaced, or deleted
expect_blocked(lambda: os.rename("allowed/repo_real/.git", "allowed/old_git"), "rename existing .git")
expect_blocked(lambda: os.replace("allowed/repo_real/.git", "allowed/old_git"), "replace existing .git")
expect_blocked(lambda: shutil.move("allowed/repo_real/.git", "allowed/old_git"), "shutil.move existing .git")
expect_blocked(lambda: shutil.rmtree("allowed/repo_real/.git"), "rmtree existing .git")
expect_blocked(lambda: os.rmdir("allowed/empty_git/.git"), "rmdir empty .git")
expect_blocked(lambda: os.rmdir("allowed/empty_claude/.claude"), "rmdir empty .claude")
expect_blocked(lambda: os.unlink("allowed/repo_real/.git"), "unlink .git")
expect_blocked(lambda: os.remove("allowed/repo_real/.claude"), "remove .claude")

# 2. Planting new .git / .claude via open, rename, copytree, unpack_archive, symlink, junctions
expect_blocked(lambda: open("allowed/new_repo/.git", "w").write("gitdir: ../evil\n"), "open .git gitdir")
expect_blocked(lambda: open("allowed/new_repo/.claude", "w").write("x"), "open .claude write")
expect_blocked(lambda: os.rename("allowed/evil", "allowed/new_repo/.git"), "rename plant .git")
expect_blocked(lambda: os.replace("allowed/evil_claude", "allowed/new_repo/.claude"), "replace plant .claude")
expect_blocked(lambda: shutil.move("allowed/evil", "allowed/new_repo/.git"), "shutil.move plant .git")
expect_blocked(lambda: shutil.copytree("allowed/evil", "allowed/new_repo/.git"), "copytree plant .git")
expect_blocked(lambda: shutil.unpack_archive(evil_zip, "allowed/new_repo/.git"), "unpack_archive plant .git")
expect_blocked(lambda: os.symlink(os.path.abspath("allowed/evil"), "allowed/new_repo/.git"), "symlink plant .git")

# 3. Ancestor directory moves/deletes containing .git
expect_blocked(lambda: os.rename("allowed/parent_with_git", "allowed/parent_moved"), "rename parent_with_git")
expect_blocked(lambda: os.replace("allowed/parent_with_git", "allowed/parent_moved"), "replace parent_with_git")
expect_blocked(lambda: shutil.move("allowed/parent_with_git", "allowed/parent_moved"), "shutil.move parent_with_git")
expect_blocked(lambda: shutil.rmtree("allowed/parent_with_git"), "rmtree parent_with_git")
assert os.path.isfile("allowed/parent_with_git/keep.txt")
assert "NESTED_ORIG" in open("allowed/parent_with_git/nested/.git/hooks/pre-commit").read()

if sys.platform == "win32":
    import _winapi
    expect_blocked(lambda: _winapi.CreateJunction(os.path.abspath("allowed/evil"), "allowed/new_repo/.git"), "CreateJunction plant .git")
    expect_blocked(lambda: _winapi.CreateJunction(os.path.abspath("allowed/evil_claude"), "allowed/new_repo/.claude"), "CreateJunction plant .claude")
    expect_blocked(lambda: _winapi.CreateJunction(os.path.abspath("allowed/evil"), "allowed/new_repo/.git."), "CreateJunction plant .git.")
    expect_blocked(lambda: _winapi.CreateJunction(os.path.abspath("allowed/parent_with_git"), "allowed/alias_parent"), "CreateJunction parent_with_git")
    expect_blocked(lambda: _winapi.CreateFile("allowed/repo_real/.git", 0x00010000, 0, 0, 3, 0x06000000, 0), "CreateFile delete .git")

# 4. Zero false positives
work_claude = "allowed/work_claude_" + str(os.getpid())
os.makedirs(os.path.join(work_claude, ".claude"), exist_ok=True)
cfg_path = os.path.join(work_claude, ".claude", "config.json")
with open(cfg_path, "w", encoding="utf-8") as f:
    f.write('{"ok": true}')
assert open(cfg_path, "r", encoding="utf-8").read() == '{"ok": true}'

assert "refs/heads/main" in open("allowed/repo_real/.git/HEAD").read()
notes_p = "allowed/repo_real/.git/notes_ok_" + str(os.getpid()) + ".txt"
with open(notes_p, "w", encoding="utf-8") as f:
    f.write("NOTES_OK")
assert open(notes_p, "r", encoding="utf-8").read() == "NOTES_OK"

norm_src = "allowed/norm_src_" + str(os.getpid())
norm_dst = "allowed/norm_dst_" + str(os.getpid())
os.makedirs(norm_src, exist_ok=True)
with open(os.path.join(norm_src, "a.txt"), "w") as f:
    f.write("OK")
os.rename(norm_src, norm_dst)
shutil.rmtree(norm_dst)

if sys.platform == "win32":
    import _winapi
    j_ok = "allowed/j_ok20_" + str(os.getpid())
    if os.path.exists(j_ok):
        os.rmdir(j_ok)
    _winapi.CreateJunction(os.path.abspath("allowed/sub"), j_ok)
    assert open(os.path.join(j_ok, "sub.txt")).read().strip() == "SUB_20"
    os.rmdir(j_ok)

print("PINNED_PARENT_ALL_OK")
"##,
    )
    .unwrap();

    for pol in [&json_pol, &cedar_permissive, &cedar_forbid] {
        let out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol.to_str().unwrap(),
                "--cwd",
                ws_dir.to_str().unwrap(),
                "--",
                &py,
                probe_script.to_str().unwrap(),
            ])
            .output()
            .expect("run iter20 pinned_probe");
        assert!(
            out.status.success(),
            "pinned_probe failed under {}: exit={:?} stdout={} stderr={}",
            pol.display(),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("PINNED_PARENT_ALL_OK"));
    }

    // Also test --sandbox strict with AppContainer-capable Python (e.g., Py 3.14 on Windows)
    #[allow(unused_mut)]
    let mut strict_py = py.clone();
    #[cfg(windows)]
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        let py314 = PathBuf::from(local_app)
            .join("Python")
            .join("pythoncore-3.14-64")
            .join("python.exe");
        if py314.is_file() {
            strict_py = py314.to_string_lossy().to_string();
        }
    }
    let strict_out = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            cedar_permissive.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--sandbox",
            "strict",
            "--json",
            "--timeout",
            "20",
            "--",
            &strict_py,
            probe_script.to_str().unwrap(),
        ])
        .output()
        .expect("run iter20 strict pinned_probe");
    let strict_json: serde_json::Value =
        serde_json::from_slice(&strict_out_or_empty(&strict_out.stdout))
            .unwrap_or_else(|_| serde_json::json!({}));
    let strict_ec = strict_json["exit_code"].as_i64().unwrap_or(-1);
    let is_host_acl_err =
        strict_ec == (0xC000_0135u32 as i32) as i64 || strict_ec == (0xC000_0022u32 as i32) as i64;
    if !is_host_acl_err {
        assert_eq!(
            strict_ec, 0,
            "strict pinned_probe failed: json={}",
            strict_json
        );
        assert!(
            strict_json["stdout"]
                .as_str()
                .unwrap_or("")
                .contains("PINNED_PARENT_ALL_OK"),
            "missing PINNED_PARENT_ALL_OK under strict: json={}",
            strict_json
        );
    }

    // Verify original .git/hooks/pre-commit remained untouched across all runs
    let hook_after =
        std::fs::read_to_string(allowed_dir.join("repo_real/.git/hooks/pre-commit")).unwrap();
    assert!(hook_after.contains("ORIGINAL_HOOK"));
}

#[test]
fn test_iteration20_strict_appcontainer_cedar_and_proxy() {
    let py = find_python();
    #[allow(unused_mut)]
    let mut strict_py = py;
    #[cfg(windows)]
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        let py314 = PathBuf::from(local_app)
            .join("Python")
            .join("pythoncore-3.14-64")
            .join("python.exe");
        if py314.is_file() {
            strict_py = py314.to_string_lossy().to_string();
        }
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let quickstart_dir = root.join("examples").join("quickstart");
    let quickstart_cedar = quickstart_dir.join("policy.cedar");
    let quickstart_json = quickstart_dir.join("policy.json");
    let quickstart_agent = quickstart_dir.join("my_agent.py");

    // 1. Quickstart policy.cedar + inline script under --sandbox strict (must not timeout)
    let cedar_hello = Command::new(octopus_bin())
        .args([
            "run",
            "--timeout",
            "30",
            "--sandbox",
            "strict",
            "--json",
            "--policy",
            quickstart_cedar.to_str().unwrap(),
            "--cwd",
            quickstart_dir.to_str().unwrap(),
            "--",
            &strict_py,
            "-c",
            "print('HELLO_STRICT_CEDAR')",
        ])
        .output()
        .expect("run strict cedar hello");
    let hello_json: serde_json::Value =
        serde_json::from_slice(&strict_out_or_empty(&cedar_hello.stdout))
            .unwrap_or_else(|_| serde_json::json!({}));
    let hello_ec = hello_json["exit_code"].as_i64().unwrap_or(-1);
    let is_host_acl_err =
        hello_ec == (0xC000_0135u32 as i32) as i64 || hello_ec == (0xC000_0022u32 as i32) as i64;
    if is_host_acl_err {
        return;
    }
    assert_eq!(
        hello_ec, 0,
        "strict cedar hello failed (must not timeout 124): json={}",
        hello_json
    );
    assert!(!hello_json["timed_out"].as_bool().unwrap_or(true));
    assert!(hello_json["stdout"]
        .as_str()
        .unwrap_or("")
        .contains("HELLO_STRICT_CEDAR"));

    // 2. Quickstart my_agent.py under both policy.json and policy.cedar with --sandbox strict
    for pol in [&quickstart_json, &quickstart_cedar] {
        let out = Command::new(octopus_bin())
            .args([
                "run",
                "--timeout",
                "30",
                "--sandbox",
                "strict",
                "--json",
                "--policy",
                pol.to_str().unwrap(),
                "--cwd",
                quickstart_dir.to_str().unwrap(),
                "--",
                &strict_py,
                quickstart_agent.to_str().unwrap(),
            ])
            .output()
            .expect("run strict quickstart my_agent.py");
        let j: serde_json::Value = serde_json::from_slice(&strict_out_or_empty(&out.stdout))
            .unwrap_or_else(|_| serde_json::json!({}));
        assert_eq!(
            j["exit_code"].as_i64(),
            Some(0),
            "strict quickstart failed under {}: json={}",
            pol.display(),
            j
        );
        assert_eq!(j["timed_out"].as_bool(), Some(false));
        let stdout_s = j["stdout"].as_str().unwrap_or("");
        assert!(
            stdout_s.contains("[ALLOW]") && stdout_s.contains("[BLOCKED]"),
            "expected [ALLOW] and [BLOCKED] under {}: json={}",
            pol.display(),
            j
        );
    }

    // 3. Dedicated strict Cedar IPC, asyncio/socketpair, IMDS fast-fail, and direct pipe block checks
    let ws = TempDirGuard::new("iter20_strict_cedar");
    let ws_dir = ws.path();
    let allowed_dir = ws_dir.join("allowed");
    let denied_dir = ws_dir.join("denied");
    std::fs::create_dir_all(&allowed_dir).unwrap();
    std::fs::create_dir_all(&denied_dir).unwrap();
    std::fs::write(allowed_dir.join("ok.txt"), "STRICT_CEDAR_OK\n").unwrap();
    std::fs::write(denied_dir.join("secret.txt"), "STRICT_SECRET\n").unwrap();

    let allowed_canon = std::fs::canonicalize(&allowed_dir).unwrap_or_else(|_| allowed_dir.clone());
    let allowed_raw = allowed_canon.to_string_lossy().replace('\\', "/");
    let allowed_cedar = allowed_raw
        .strip_prefix("//?/")
        .unwrap_or(&allowed_raw)
        .to_ascii_lowercase();
    let denied_canon = std::fs::canonicalize(&denied_dir).unwrap_or_else(|_| denied_dir.clone());
    let denied_raw = denied_canon.to_string_lossy().replace('\\', "/");
    let denied_cedar = denied_raw
        .strip_prefix("//?/")
        .unwrap_or(&denied_raw)
        .to_ascii_lowercase();

    let strict_cedar_pol = ws_dir.join("strict_policy.cedar");
    std::fs::write(
        &strict_cedar_pol,
        format!(
            r#"permit (principal, action == Octopus::Action::"exec", resource is Octopus::Command)
  when {{ context has stem && (context.stem == "python" || context.stem == "python3") }};
permit (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && (context.normalized_path == "{allowed}" || context.normalized_path like "{allowed}/*") }};
forbid (principal, action == Octopus::Action::"fs_read", resource is Octopus::FilePath)
  when {{ context has normalized_path && context.normalized_path like "{denied}*" }};
permit (principal, action == Octopus::Action::"fs_write", resource is Octopus::FilePath)
  when {{
    context has normalized_path
    && context.normalized_path like "{allowed}/*"
    && !(context has is_mandatory_deny && context.is_mandatory_deny == true)
  }};
"#,
            allowed = allowed_cedar,
            denied = denied_cedar
        ),
    )
    .unwrap();

    let strict_probe = ws_dir.join("strict_probe.py");
    std::fs::write(
        &strict_probe,
        r#"import asyncio, gc, os, socket, subprocess, sys, time

# 1. Cedar fs_read allow + forbid + fs_write allow + exec forbid
assert open("allowed/ok.txt", "r", encoding="utf-8").read().strip() == "STRICT_CEDAR_OK"
with open("allowed/written.txt", "w", encoding="utf-8") as f:
    f.write("WROTE_OK")

for label, fn in (
    ("read_denied", lambda: open("denied/secret.txt", "r")),
    ("write_denied", lambda: open("denied/pwn.txt", "w")),
    ("exec_cmd", lambda: subprocess.run(["cmd", "/c", "echo", "hi"])),
):
    try:
        fn()
        raise AssertionError(label + " unexpectedly succeeded")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe), f"{label}: {pe}"

# 2. Direct access to Cedar IPC named pipe must be blocked
if sys.platform == "win32":
    import _winapi
    fake_pipe = r"\\.\pipe\octopus-cedar-1234-deadbeef"
    try:
        _winapi.CreateFile(fake_pipe, 0x80000000, 0, 0, 3, 0, 0)
        raise AssertionError("direct CreateFile on octopus-cedar pipe unexpectedly allowed")
    except PermissionError as pe:
        assert "blocked_by_octopus_policy" in str(pe)

# 3. Intra-AppContainer socketpair and asyncio.run must work
s1, s2 = socket.socketpair()
s1.sendall(b"ping")
assert s2.recv(4) == b"ping"
s1.close()
s2.close()
asyncio.run(asyncio.sleep(0.01))

# 4. Direct non-proxied IMDS socket connect must fail fast (never hang)
t0 = time.monotonic()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
try:
    s.connect(("169.254.169.254", 80))
    raise AssertionError("IMDS connect unexpectedly succeeded")
except (PermissionError, OSError, TimeoutError):
    pass
finally:
    s.close()
assert (time.monotonic() - t0) < 2.5

gc.collect()
print("STRICT_CEDAR_AND_PROXY_OK")
"#,
    )
    .unwrap();

    let probe_out = Command::new(octopus_bin())
        .args([
            "run",
            "--timeout",
            "30",
            "--sandbox",
            "strict",
            "--json",
            "--policy",
            strict_cedar_pol.to_str().unwrap(),
            "--cwd",
            ws_dir.to_str().unwrap(),
            "--",
            &strict_py,
            strict_probe.to_str().unwrap(),
        ])
        .output()
        .expect("run strict_probe");
    let probe_json: serde_json::Value =
        serde_json::from_slice(&strict_out_or_empty(&probe_out.stdout))
            .unwrap_or_else(|_| serde_json::json!({}));
    assert_eq!(
        probe_json["exit_code"].as_i64(),
        Some(0),
        "strict_probe failed: json={}",
        probe_json
    );
    assert!(probe_json["stdout"]
        .as_str()
        .unwrap_or("")
        .contains("STRICT_CEDAR_AND_PROXY_OK"));
}

#[test]
fn test_octopus_run_pre_spawn_rea_binary_gate() {
    let ws = TempDirGuard::new("rea_gate_e2e");
    let py = find_python();

    // Build a minimal synthetic PE64 with UPX0/W^X/Hell's Gate direct-syscall stub
    let build_hostile_pe = |wx: bool, upx: bool, hells_gate: bool| -> Vec<u8> {
        let lfanew = 0x80usize;
        let opt_size = 240usize;
        let sec_off = lfanew + 4 + 20 + opt_size;
        let raw_off = 0x400usize;
        let mut code = vec![0x90u8; 64];
        if upx {
            code[0..4].copy_from_slice(b"UPX!");
        }
        if hells_gate {
            code[8..18]
                .copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05]);
        }
        let mut buf = vec![0u8; raw_off + code.len()];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
        buf[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
        let coff = lfanew + 4;
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

        let sec_name = if upx { b"UPX0\0\0\0\0" } else { b".text\0\0\0" };
        buf[sec_off..sec_off + 8].copy_from_slice(sec_name);
        buf[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec_off + 16..sec_off + 20].copy_from_slice(&(code.len() as u32).to_le_bytes());
        buf[sec_off + 20..sec_off + 24].copy_from_slice(&(raw_off as u32).to_le_bytes());
        let chars: u32 = if wx { 0xE000_0020 } else { 0x6000_0020 };
        buf[sec_off + 36..sec_off + 40].copy_from_slice(&chars.to_le_bytes());
        buf[raw_off..raw_off + code.len()].copy_from_slice(&code);
        buf
    };

    let policy_default = ws.path().join("rea_default.json");
    std::fs::write(
        &policy_default,
        serde_json::json!({
            "allowed_domains": [],
            "commands": { "allow": [], "deny": [] },
            "binary_integrity": {
                "enabled": true,
                "require_signed_binaries": false,
                "block_packed": true,
                "block_wx_sections": true,
                "block_direct_syscalls": true
            }
        })
        .to_string(),
    )
    .unwrap();

    // 1. Packed / W^X / Hell's Gate binaries MUST be denied pre-spawn (exit 2, status=denied_preflight)
    for (fname, bytes, expected_diag) in [
        (
            "packed_upx.exe",
            build_hostile_pe(false, true, false),
            "packed",
        ),
        (
            "wx_only.exe",
            build_hostile_pe(true, false, false),
            "wx_memory_section",
        ),
        (
            "hells_gate.exe",
            build_hostile_pe(false, false, true),
            "direct_syscall",
        ),
    ] {
        let bin_path = ws.path().join(fname);
        std::fs::write(&bin_path, bytes).unwrap();
        let out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_default.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--json",
                "--",
                bin_path.to_str().unwrap(),
            ])
            .output()
            .expect("invoke octopus on hostile binary");
        assert_eq!(
            out.status.code(),
            Some(2),
            "hostile binary {} must exit 2, got {:?} stdout={} stderr={}",
            fname,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("valid JSON preflight denial");
        assert_eq!(parsed["status"], "denied_preflight");
        assert!(
            parsed["diagnostic"]
                .as_str()
                .unwrap_or("")
                .contains(expected_diag),
            "expected '{}' in diagnostic for {}: {:?}",
            expected_diag,
            fname,
            parsed
        );
    }

    // 2. Clean unsigned binary fails pre-spawn when require_signed_binaries == true
    let clean_unsigned = ws.path().join("clean_unsigned.exe");
    std::fs::write(&clean_unsigned, build_hostile_pe(false, false, false)).unwrap();
    let policy_signed = ws.path().join("rea_signed.json");
    std::fs::write(
        &policy_signed,
        serde_json::json!({
            "allowed_domains": [],
            "binary_integrity": {
                "enabled": true,
                "require_signed_binaries": true
            }
        })
        .to_string(),
    )
    .unwrap();
    let out_unsigned = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_signed.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--json",
            "--",
            clean_unsigned.to_str().unwrap(),
        ])
        .output()
        .expect("invoke octopus with require_signed_binaries");
    assert_eq!(out_unsigned.status.code(), Some(2));
    let parsed_u: serde_json::Value =
        serde_json::from_slice(&out_unsigned.stdout).expect("valid JSON unsigned denial");
    assert_eq!(parsed_u["status"], "denied_preflight");
    assert!(parsed_u["diagnostic"]
        .as_str()
        .unwrap_or("")
        .contains("unsigned_binary_rejected"));

    // 3. Invalid entropy_threshold (> 8.0 or negative) fails policy validation with exit 2
    let bad_ent_pol = ws.path().join("bad_entropy.json");
    std::fs::write(
        &bad_ent_pol,
        r#"{"allowed_domains":[],"binary_integrity":{"entropy_threshold":9.5}}"#,
    )
    .unwrap();
    let out_bad_pol = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            bad_ent_pol.to_str().unwrap(),
            "--",
            &py,
            "-c",
            "print('NO')",
        ])
        .output()
        .unwrap();
    assert_eq!(out_bad_pol.status.code(), Some(2));

    // 4. Legitimate python & shell binaries pass with zero false positives
    let out_py = Command::new(octopus_bin())
        .args([
            "run",
            "--policy",
            policy_default.to_str().unwrap(),
            "--cwd",
            ws.path().to_str().unwrap(),
            "--",
            &py,
            "-c",
            "print('REA_PY_OK')",
        ])
        .output()
        .unwrap();
    assert!(
        out_py.status.success(),
        "benign python failed REA gate: stderr={}",
        String::from_utf8_lossy(&out_py.stderr)
    );
    assert!(String::from_utf8_lossy(&out_py.stdout).contains("REA_PY_OK"));

    #[cfg(windows)]
    {
        // System32 cmd.exe passes even under require_signed_binaries: true (via Windows Catalog)
        let out_cmd = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                policy_signed.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                "cmd",
                "/c",
                "echo",
                "REA_CMD_CATALOG_OK",
            ])
            .output()
            .unwrap();
        assert!(
            out_cmd.status.success(),
            "signed cmd.exe failed require_signed_binaries: stderr={}",
            String::from_utf8_lossy(&out_cmd.stderr)
        );
        assert!(String::from_utf8_lossy(&out_cmd.stdout).contains("REA_CMD_CATALOG_OK"));
    }
}

#[test]
fn test_r7_iter2_remediations_forged_cert_syscall_variants_anomalies_cedar_and_o1_latency() {
    let ws = TempDirGuard::new("r7_iter2");

    fn build_pe64(sections: &[(&str, u32, u32, &[u8], bool)], with_dummy_cert: bool) -> Vec<u8> {
        let lfanew = 0x80usize;
        let opt_size = 240usize;
        let sec_table_off = lfanew + 4 + 20 + opt_size;
        let headers_end = sec_table_off + sections.len() * 40;
        let first_sec_off = headers_end.div_ceil(0x200) * 0x200;

        let mut raw_offsets = Vec::with_capacity(sections.len());
        let mut cur_off = first_sec_off;
        for &(_, _, _, data, force_zero) in sections {
            raw_offsets.push(cur_off);
            if !force_zero && !data.is_empty() {
                cur_off += data.len().div_ceil(0x200) * 0x200;
            }
        }

        let cert_off = cur_off;
        let cert_len = if with_dummy_cert { 64usize } else { 0usize };
        let mut buf = vec![0u8; cert_off + cert_len];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&(lfanew as u32).to_le_bytes());
        buf[lfanew..lfanew + 4].copy_from_slice(b"PE\0\0");
        let coff = lfanew + 4;
        buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        buf[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        let opt = coff + 20;
        buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        let ep_rva = sections.first().map(|s| s.1).unwrap_or(0x1000);
        buf[opt + 16..opt + 20].copy_from_slice(&ep_rva.to_le_bytes());
        buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        if with_dummy_cert {
            buf[opt + 144..opt + 148].copy_from_slice(&(cert_off as u32).to_le_bytes());
            buf[opt + 148..opt + 152].copy_from_slice(&(cert_len as u32).to_le_bytes());
            buf[cert_off..cert_off + 4].copy_from_slice(&64u32.to_le_bytes());
            buf[cert_off + 4..cert_off + 6].copy_from_slice(&0x0200u16.to_le_bytes());
            buf[cert_off + 6..cert_off + 8].copy_from_slice(&0x0002u16.to_le_bytes());
        }

        for (i, &(name, va, chars, data, force_zero)) in sections.iter().enumerate() {
            let sh = sec_table_off + i * 40;
            let nb = name.as_bytes();
            let clen = nb.len().min(8);
            buf[sh..sh + clen].copy_from_slice(&nb[..clen]);
            let vsz = (data.len() as u32).max(0x1000);
            buf[sh + 8..sh + 12].copy_from_slice(&vsz.to_le_bytes());
            buf[sh + 12..sh + 16].copy_from_slice(&va.to_le_bytes());
            let rsz = if force_zero { 0u32 } else { data.len() as u32 };
            let rptr = if force_zero || data.is_empty() {
                0u32
            } else {
                raw_offsets[i] as u32
            };
            buf[sh + 16..sh + 20].copy_from_slice(&rsz.to_le_bytes());
            buf[sh + 20..sh + 24].copy_from_slice(&rptr.to_le_bytes());
            buf[sh + 36..sh + 40].copy_from_slice(&chars.to_le_bytes());
            if !force_zero && !data.is_empty() {
                let off = raw_offsets[i];
                buf[off..off + data.len()].copy_from_slice(data);
            }
        }
        buf
    }

    let pol_default = ws.path().join("pol_default.json");
    std::fs::write(
        &pol_default,
        serde_json::json!({
            "allowed_domains": [],
            "binary_integrity": { "enabled": true }
        })
        .to_string(),
    )
    .unwrap();

    let pol_signed = ws.path().join("pol_signed.json");
    std::fs::write(
        &pol_signed,
        serde_json::json!({
            "allowed_domains": [],
            "binary_integrity": { "enabled": true, "require_signed_binaries": true }
        })
        .to_string(),
    )
    .unwrap();

    // 1. Forged dummy WIN_CERTIFICATE fails require_signed_binaries=true on Windows
    #[cfg(windows)]
    {
        let forged_bin = ws.path().join("forged_win_cert.exe");
        std::fs::write(
            &forged_bin,
            build_pe64(&[(".text", 0x1000, 0x6000_0020, &[0xC3], false)], true),
        )
        .unwrap();
        let out_forged = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_signed.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--json",
                "--",
                forged_bin.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(out_forged.status.code(), Some(2));
        let parsed: serde_json::Value = serde_json::from_slice(&out_forged.stdout).unwrap();
        assert_eq!(parsed["status"], "denied_preflight");
        assert!(parsed["diagnostic"]
            .as_str()
            .unwrap_or("")
            .contains("unsigned_binary_rejected"));

        // Standalone .cedar checking context.is_authenticode_signed allows Catalog-signed cmd.exe
        let cedar_sig = ws.path().join("sig_check.cedar");
        std::fs::write(
            &cedar_sig,
            r#"permit(principal, action == Octopus::Action::"exec", resource is Octopus::Command)
when { context has is_authenticode_signed && context.is_authenticode_signed };"#,
        )
        .unwrap();
        let out_cedar_cmd = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                cedar_sig.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--",
                "cmd",
                "/c",
                "echo",
                "CEDAR_CATALOG_CMD_OK",
            ])
            .output()
            .unwrap();
        assert!(
            out_cedar_cmd.status.success(),
            "Catalog-signed cmd.exe must satisfy standalone Cedar is_authenticode_signed: stderr={}",
            String::from_utf8_lossy(&out_cedar_cmd.stderr)
        );
        assert!(String::from_utf8_lossy(&out_cedar_cmd.stdout).contains("CEDAR_CATALOG_CMD_OK"));

        let out_cedar_forged = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                cedar_sig.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--json",
                "--",
                forged_bin.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(out_cedar_forged.status.code(), Some(2));
    }

    // 2. Direct-syscall variants, low-entropy EP-in-writable/hollow_exec, and 3rd .evil section -> exit 2
    let mut halos_24 = vec![0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00];
    halos_24.extend(std::iter::repeat_n(0x90u8, 24));
    halos_24.extend_from_slice(&[0x0F, 0x05]);

    let nop_256k = vec![0x90u8; 256 * 1024];
    let cases: [(&str, Vec<u8>); 6] = [
        (
            "alt_nops.exe",
            build_pe64(
                &[(
                    ".text",
                    0x1000,
                    0x6000_0020,
                    &[
                        0x49, 0x89, 0xCA, 0xB8, 0x1A, 0x00, 0x00, 0x00, 0x90, 0x90, 0x0F, 0x05,
                    ],
                    false,
                )],
                false,
            ),
        ),
        (
            "alt_int2e.exe",
            build_pe64(
                &[(
                    ".text",
                    0x1000,
                    0x6000_0020,
                    &[0x49, 0x89, 0xCA, 0xB8, 0x1B, 0x00, 0x00, 0x00, 0xCD, 0x2E],
                    false,
                )],
                false,
            ),
        ),
        (
            "halos_24nops.exe",
            build_pe64(&[(".text", 0x1000, 0x6000_0020, &halos_24, false)], false),
        ),
        (
            "ep_in_data.exe",
            build_pe64(
                &[(
                    ".data",
                    0x1000,
                    0xC000_0040,
                    &[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05],
                    false,
                )],
                false,
            ),
        ),
        (
            "hollow_exec.exe",
            build_pe64(
                &[(".text", 0x1000, 0x6000_0020, &[0x90; 8192], true)],
                false,
            ),
        ),
        (
            "evil_3rd_sec.exe",
            build_pe64(
                &[
                    (".text0", 0x1000, 0x6000_0020, &nop_256k, false),
                    (".text1", 0x50000, 0x6000_0020, &nop_256k, false),
                    (
                        ".evil",
                        0xA0000,
                        0x6000_0020,
                        &[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05],
                        false,
                    ),
                ],
                false,
            ),
        ),
    ];

    for (name, bytes) in cases {
        let p = ws.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        let out = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_default.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--json",
                "--",
                p.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "{} must deny preflight with exit 2: stdout={} stderr={}",
            name,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // 3. 55 MiB W^X PE denies in O(1) constant time (<2ms parser SLA + O(1) prefix-read invariance)
    let tiny_pe = build_pe64(&[(".text", 0x1000, 0xE000_0020, &[0x90; 8], false)], false);
    let tiny_pe_path = ws.path().join("tiny_4kb_wx.exe");
    std::fs::write(&tiny_pe_path, &tiny_pe).unwrap();

    let rsrc_55mb = vec![0x41u8; 55 * 1024 * 1024];
    let pe_55mb = build_pe64(
        &[
            (".text", 0x1000, 0xE000_0020, &[0x90; 8], false),
            (".rsrc", 0x10000, 0x4000_0040, &rsrc_55mb, false),
        ],
        false,
    );
    let pe_55mb_path = ws.path().join("big_55mb_wx.exe");
    std::fs::write(&pe_55mb_path, &pe_55mb).unwrap();
    // Pre-read once to let OS page cache / Windows Defender settle on freshly written 55 MiB .exe
    if let Ok(mut f) = std::fs::File::open(&pe_55mb_path) {
        let mut hdr = [0u8; 64];
        let _ = f.read(&mut hdr);
    }

    // Strict <2ms parser SLA directly on the locked 55 MiB PE handle
    let mut best_parser_us = u64::MAX;
    for _ in 0..5 {
        let mut locked_55 =
            agent_octopus::security::executable_identity::open_and_lock_executable_for_cli(
                &pe_55mb_path,
                "big_55mb_wx",
            )
            .expect("lock 55 MiB PE");
        let v_55 = agent_octopus::security::rea_binary_gate::inspect_locked_file(
            &mut locked_55.locked_file,
            &pe_55mb_path,
            locked_55.metadata.file_size,
            "big_55mb_wx",
            false,
        )
        .expect("inspect 55 MiB PE");
        assert!(v_55.has_wx_violation);
        best_parser_us = best_parser_us.min(v_55.inspection_micros);
    }
    assert!(
        best_parser_us < 2_000,
        "55 MiB W^X PE REA parser best {}us exceeded strict 2000us SLA",
        best_parser_us
    );

    // Subprocess O(1) scaling comparison vs tiny 4 KiB W^X PE (resilient to 34-way debug Cargo jitter)
    let mut best_tiny_ms = u64::MAX;
    for _ in 0..3 {
        let out_tiny = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_default.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--json",
                "--",
                tiny_pe_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(out_tiny.status.code(), Some(2));
        let parsed_tiny: serde_json::Value = serde_json::from_slice(&out_tiny.stdout).unwrap();
        assert_eq!(parsed_tiny["status"], "denied_preflight");
        best_tiny_ms = best_tiny_ms.min(parsed_tiny["duration_ms"].as_u64().unwrap_or(u64::MAX));
    }

    let mut best_55_ms = u64::MAX;
    for _ in 0..3 {
        let out_55 = Command::new(octopus_bin())
            .args([
                "run",
                "--policy",
                pol_default.to_str().unwrap(),
                "--cwd",
                ws.path().to_str().unwrap(),
                "--json",
                "--",
                pe_55mb_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(out_55.status.code(), Some(2));
        let parsed_55: serde_json::Value = serde_json::from_slice(&out_55.stdout).unwrap();
        assert_eq!(parsed_55["status"], "denied_preflight");
        best_55_ms = best_55_ms.min(parsed_55["duration_ms"].as_u64().unwrap_or(u64::MAX));
    }
    let o1_cap_ms = best_tiny_ms.saturating_add(250).max(500);
    assert!(
        best_55_ms < o1_cap_ms && best_55_ms < 1_000,
        "55 MiB W^X PE preflight best duration {}ms exceeded O(1) bound (tiny={}ms, cap={}ms)",
        best_55_ms,
        best_tiny_ms,
        o1_cap_ms
    );
}
