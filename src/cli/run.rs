use crate::cli::policy::{load_octopus_policy, LoadedOctopusPolicy};
use crate::cli::proxy::{start_loopback_proxy, EgressEventRecord};
use crate::cli::wasm_runner::{execute_wasm_target, is_wasm_or_wat_target};
use crate::cli::{
    parse_octopus_cli, CliParseResult, OctopusRunArgs, SandboxMode, EXIT_PREFLIGHT_DENIED,
    EXIT_SANDBOX_FAILURE, EXIT_TIMEOUT,
};
use crate::security::breakouts::TechnicalBreakoutGuard;
use crate::security::cedar_arm::CedarPolicyEngine;
use crate::security::semantic_command::{parse_semantic_command, DynamicBinaryMetadataProbe};
use crate::security::sensitive_paths::{
    classify_mandatory_write_deny_path, classify_pinned_parent_for_write_deny,
    classify_sensitive_system_path, scan_for_sensitive_system_path,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[derive(Serialize)]
struct JsonRunSummary {
    status: String,
    exit_code: i32,
    timed_out: bool,
    sandbox: String,
    backend: String,
    pid: Option<u32>,
    duration_ms: u64,
    stdout: String,
    stderr: String,
    egress_events: Vec<EgressEventRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<String>,
}

struct TempGuardDir(PathBuf);

impl Drop for TempGuardDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(windows)]
fn is_local_unc_host(host: &str) -> bool {
    let mut h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    if h.starts_with('[') && h.ends_with(']') && h.len() >= 2 {
        h = h[1..h.len() - 1].to_string();
    }
    if let Some((addr_only, _zone)) = h.split_once('%') {
        h = addr_only.to_string();
    }
    if matches!(
        h.as_str(),
        "localhost" | "localhost.localdomain" | "0.0.0.0" | "::1" | "0:0:0:0:0:0:0:1"
    ) {
        return true;
    }
    if let Ok(ip4) = h.parse::<std::net::Ipv4Addr>() {
        if ip4.is_loopback() || ip4.is_unspecified() {
            return true;
        }
    }
    if h.starts_with("127.") && h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return true;
    }
    if let Ok(ip6) = h.parse::<std::net::Ipv6Addr>() {
        if ip6.is_loopback()
            || ip6.is_unspecified()
            || ip6
                .to_ipv4_mapped()
                .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        {
            return true;
        }
    }
    if let Some(prefix) = h.strip_suffix(".ipv6-literal.net") {
        if matches!(prefix, "0--1" | "0-0-0-0-0-0-0-1" | "0-0-0-0-0-0-0-0") {
            return true;
        }
    }
    for env_key in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(val) = std::env::var(env_key) {
            let norm = val.trim().trim_end_matches('.').to_ascii_lowercase();
            if !norm.is_empty() && h == norm {
                return true;
            }
        }
    }
    if let (Ok(cn), Ok(dns)) = (
        std::env::var("COMPUTERNAME"),
        std::env::var("USERDNSDOMAIN"),
    ) {
        let cn = cn.trim().trim_end_matches('.');
        let dns = dns.trim().trim_end_matches('.');
        if !cn.is_empty() && !dns.is_empty() {
            let fqdn = format!("{}.{}", cn, dns).to_ascii_lowercase();
            if h == fqdn {
                return true;
            }
        }
    }
    false
}

#[cfg(windows)]
fn strip_win_verbatim_and_local_unc_str(raw: &str) -> String {
    let mut t = raw.replace('\\', "/");
    let mut tl = t.to_ascii_lowercase();
    if tl.starts_with("//?/global/") || tl.starts_with("//./global/") {
        t = format!("//{}{}", &t[2..4], &t[11..]);
        tl = t.to_ascii_lowercase();
    }
    if tl.starts_with("//?/unc/") || tl.starts_with("//./unc/") {
        t = format!("//{}", &t[8..]);
    } else if tl.starts_with("//?/") {
        t = t[4..].to_string();
    } else if tl.starts_with("//./") {
        let bytes = t.as_bytes();
        if bytes.len() >= 6 && bytes[4].is_ascii_alphabetic() && bytes[5] == b':' {
            t = t[4..].to_string();
        }
    }
    if let Some(rest) = t.strip_prefix("//") {
        let mut parts = rest.splitn(3, '/');
        let host = parts.next().unwrap_or("");
        let share = parts.next().unwrap_or("");
        let tail = parts.next().unwrap_or("");
        if !host.is_empty() && is_local_unc_host(host) {
            let sb = share.as_bytes();
            if sb.len() == 2 && sb[0].is_ascii_alphabetic() && sb[1] == b'$' {
                return if tail.is_empty() {
                    format!("{}:/", sb[0] as char)
                } else {
                    format!("{}:/{}", sb[0] as char, tail)
                };
            }
            if share.eq_ignore_ascii_case("admin$") {
                let sys_root = std::env::var("SystemRoot")
                    .or_else(|_| std::env::var("WINDIR"))
                    .unwrap_or_else(|_| "C:/Windows".to_string())
                    .replace('\\', "/")
                    .trim_end_matches('/')
                    .to_string();
                return if tail.is_empty() {
                    sys_root
                } else {
                    format!("{}/{}", sys_root, tail)
                };
            }
        }
    }
    t
}

#[cfg(windows)]
fn is_raw_admin_or_ipc_share_str(raw: &str) -> bool {
    let mut t = raw.trim().replace('\\', "/");
    let mut tl = t.to_ascii_lowercase();
    if tl.starts_with("//?/global/unc/") || tl.starts_with("//./global/unc/") {
        t = format!("//{}", &t[15..]);
    } else {
        if tl.starts_with("//?/global/") || tl.starts_with("//./global/") {
            t = format!("//{}{}", &t[2..4], &t[11..]);
            tl = t.to_ascii_lowercase();
        }
        if tl.starts_with("//?/unc/") || tl.starts_with("//./unc/") {
            t = format!("//{}", &t[8..]);
        }
    }
    let Some(rest) = t.strip_prefix("//") else {
        return false;
    };
    let mut parts = rest.splitn(3, '/');
    let _host = parts.next().unwrap_or("");
    let share = parts.next().unwrap_or("").trim_end_matches(['.', ' ']);
    share.eq_ignore_ascii_case("admin$") || share.eq_ignore_ascii_case("ipc$")
}

#[cfg(windows)]
fn is_unc_admin_share_str(raw: &str) -> bool {
    let t = raw.trim().replace('\\', "/");
    let Some(rest) = t.strip_prefix("//") else {
        return false;
    };
    let mut parts = rest.splitn(3, '/');
    let _host = parts.next().unwrap_or("");
    let share = parts.next().unwrap_or("").trim_end_matches(['.', ' ']);
    !share.is_empty() && share.ends_with('$')
}

fn strip_win_verbatim_prefix(p: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let s = p.to_string_lossy().to_string();
        let rewritten = strip_win_verbatim_and_local_unc_str(&s);
        let pb = PathBuf::from(rewritten.replace('/', "\\"));
        if rewritten != s.replace('\\', "/") {
            if let Ok(canon) = std::fs::canonicalize(&pb) {
                let cs = canon.to_string_lossy().to_string();
                let cs_clean = strip_win_verbatim_and_local_unc_str(&cs);
                return PathBuf::from(cs_clean.replace('/', "\\"));
            }
        }
        pb
    }
    #[cfg(not(windows))]
    p
}

fn quote_arg_for_analysis(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c.is_whitespace() || c == '"' || c == '\'')
    {
        return arg.to_string();
    }
    format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
}

fn build_joined_cmdline(program: &str, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote_arg_for_analysis(program));
    for a in args {
        parts.push(quote_arg_for_analysis(a));
    }
    parts.join(" ")
}

fn normalized_command_aliases(raw: &str) -> Vec<String> {
    let fname = Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    let mut aliases = Vec::new();
    let mut push_uniq = |val: String| {
        if !val.is_empty() && !aliases.contains(&val) {
            aliases.push(val);
        }
    };
    push_uniq(fname.clone());
    let no_ext = fname
        .strip_suffix(".exe")
        .or_else(|| fname.strip_suffix(".cmd"))
        .or_else(|| fname.strip_suffix(".bat"))
        .or_else(|| fname.strip_suffix(".com"))
        .unwrap_or(&fname)
        .to_string();
    push_uniq(no_ext.clone());

    if let Some(rest) = no_ext.strip_prefix("python") {
        if rest.is_empty()
            || rest
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == 'w')
        {
            if let Some(major) = rest.chars().next().filter(|c| c.is_ascii_digit()) {
                push_uniq(format!("python{}", major));
            }
            push_uniq("python".to_string());
        }
    }
    aliases
}

fn resolve_executable_on_path(program: &str, cwd: &Path) -> Option<PathBuf> {
    let p = Path::new(program);
    if p.is_absolute() || p.components().count() > 1 {
        let candidate = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };
        if candidate.is_file() {
            return Some(strip_win_verbatim_prefix(
                std::fs::canonicalize(&candidate).unwrap_or(candidate),
            ));
        }
        #[cfg(windows)]
        if candidate.extension().is_none() {
            let with_exe = candidate.with_extension("exe");
            if with_exe.is_file() {
                return Some(strip_win_verbatim_prefix(
                    std::fs::canonicalize(&with_exe).unwrap_or(with_exe),
                ));
            }
        }
        return None;
    }

    if let Ok(path_env) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let candidate = dir.join(program);
            if candidate.is_file() {
                return Some(strip_win_verbatim_prefix(
                    std::fs::canonicalize(&candidate).unwrap_or(candidate),
                ));
            }
            #[cfg(windows)]
            if candidate.extension().is_none() {
                let with_exe = candidate.with_extension("exe");
                if with_exe.is_file() {
                    return Some(strip_win_verbatim_prefix(
                        std::fs::canonicalize(&with_exe).unwrap_or(with_exe),
                    ));
                }
            }
        }
    }
    None
}

fn is_python_aliases(aliases: &[String]) -> bool {
    aliases.iter().any(|a| {
        matches!(
            a.as_str(),
            "python" | "python3" | "python2" | "pythonw" | "py"
        )
    })
}

fn find_forbidden_python_flag(cmd_args: &[String]) -> Option<String> {
    let mut i = 0;
    while i < cmd_args.len() {
        let tok = cmd_args[i].trim();
        if tok == "--" || tok == "-" {
            break;
        }
        if tok.starts_with("--") {
            if tok == "--isolated" || tok.starts_with("--isolated=") {
                return Some(tok.to_string());
            }
            if tok == "--check-hash-based-pycs" {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if tok.starts_with('-') && tok.len() > 1 {
            let mut stop_after_tok = false;
            let mut skip_next = false;
            let mut chars = tok[1..].chars();
            while let Some(ch) = chars.next() {
                if ch == '=' {
                    break;
                }
                if ch == 'I' || ch == 'E' || ch == 'S' {
                    return Some(tok.to_string());
                }
                if ch == 'c' || ch == 'm' {
                    stop_after_tok = true;
                    break;
                }
                if ch == 'W' || ch == 'X' {
                    if chars.next().is_none() {
                        skip_next = true;
                    }
                    break;
                }
            }
            if stop_after_tok {
                break;
            }
            if skip_next {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        break;
    }
    None
}

fn has_ntfs_ads_suffix(tok: &str) -> bool {
    let trimmed = tok.trim().trim_matches(['"', '\'', '`']);
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return false;
    }
    let mut rest = trimmed.replace('\\', "/");
    for prefix in [
        "//?/global/unc/",
        "//./global/unc/",
        "//?/unc/",
        "//./unc/",
        "//?/global/",
        "//./global/",
        "//?/",
        "//./",
    ] {
        if rest.len() >= prefix.len() && rest[..prefix.len()].eq_ignore_ascii_case(prefix) {
            rest = rest[prefix.len()..].to_string();
            break;
        }
    }
    let after_drive = if rest.len() >= 2
        && rest.as_bytes()[0].is_ascii_alphabetic()
        && rest.as_bytes()[1] == b':'
    {
        &rest[2..]
    } else {
        &rest
    };
    after_drive.contains(':')
}

fn is_python_startup_guard_path(tok: &str) -> bool {
    let trimmed = tok.trim().trim_matches(['"', '\'', '`']);
    if trimmed.is_empty() {
        return false;
    }
    let normalized = trimmed.replace('\\', "/");
    let after_drive = if normalized.len() >= 2
        && normalized.as_bytes()[0].is_ascii_alphabetic()
        && normalized.as_bytes()[1] == b':'
    {
        &normalized[2..]
    } else {
        &normalized
    };
    let last_seg = after_drive
        .rsplit('/')
        .next()
        .unwrap_or(after_drive)
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches(['.', ' '])
        .to_ascii_lowercase();
    last_seg == "sitecustomize.py" || last_seg == "usercustomize.py" || last_seg.ends_with(".pth")
}

fn strip_win_ads_and_trailing_dots_for_cedar(raw: &str) -> String {
    #[cfg(windows)]
    let replaced = strip_win_verbatim_and_local_unc_str(raw.trim());
    #[cfg(not(windows))]
    let replaced = raw.trim().replace('\\', "/");
    let (prefix, rest) = if replaced.len() >= 2
        && replaced.as_bytes()[0].is_ascii_alphabetic()
        && replaced.as_bytes()[1] == b':'
    {
        (&replaced[..2], &replaced[2..])
    } else {
        ("", replaced.as_str())
    };
    let segs: Vec<String> = rest
        .split('/')
        .map(|seg| {
            let no_ads = seg.split(':').next().unwrap_or(seg);
            if cfg!(windows) {
                if no_ads == "." || no_ads == ".." {
                    no_ads.to_string()
                } else {
                    let trimmed = no_ads.trim_end_matches(['.', ' ']);
                    if trimmed.is_empty() && !no_ads.is_empty() {
                        no_ads.to_string()
                    } else {
                        trimmed.to_string()
                    }
                }
            } else {
                no_ads.to_string()
            }
        })
        .collect();
    format!("{}{}", prefix, segs.join("/"))
}

fn expand_tilde_for_preflight(raw: &str) -> Option<PathBuf> {
    let rest = if raw == "~" {
        ""
    } else if let Some(r) = raw.strip_prefix("~/") {
        r
    } else if cfg!(windows) {
        raw.strip_prefix("~\\")?
    } else {
        return None;
    };
    let home = if cfg!(windows) {
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| {
                let hp = std::env::var_os("HOMEPATH")?;
                let mut base = std::env::var_os("HOMEDRIVE")
                    .map(PathBuf::from)
                    .unwrap_or_default();
                base.push(hp);
                Some(base)
            })
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }?;
    if rest.is_empty() {
        Some(home)
    } else {
        Some(home.join(rest))
    }
}

fn lexical_collapse_slashes(clean: &str) -> String {
    let s = clean.replace('\\', "/");
    let (prefix, rest) = if let Some(after_unc) = s.strip_prefix("//") {
        let mut it = after_unc.splitn(3, '/');
        let host = it.next().unwrap_or("");
        let share = it.next().unwrap_or("");
        let tail = it.next().unwrap_or("");
        if !host.is_empty() && !share.is_empty() {
            (format!("//{}/{}/", host, share), tail.to_string())
        } else if !host.is_empty() {
            (format!("//{}/", host), String::new())
        } else {
            ("//".to_string(), after_unc.to_string())
        }
    } else if s.len() >= 2 && s.as_bytes()[0].is_ascii_alphabetic() && s.as_bytes()[1] == b':' {
        let after = s[2..].trim_start_matches('/');
        (format!("{}/", &s[..2]), after.to_string())
    } else if let Some(after_root) = s.strip_prefix('/') {
        ("/".to_string(), after_root.to_string())
    } else {
        (String::new(), s.clone())
    };

    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if !stack.is_empty() && !(prefix.is_empty() && stack.last() == Some(&"..")) {
                stack.pop();
            } else if prefix.is_empty() {
                stack.push("..");
            }
            continue;
        }
        stack.push(seg);
    }
    if stack.is_empty() {
        if prefix.starts_with("//") && prefix.ends_with('/') {
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.matches('/').count() >= 3 {
                return trimmed.to_string();
            }
        }
        if prefix.is_empty() {
            ".".to_string()
        } else {
            prefix
        }
    } else {
        format!("{}{}", prefix, stack.join("/"))
    }
}

fn norm_cmp_path(s: &str) -> String {
    let mut t = s.replace('\\', "/");
    if t.len() > 1 && !(t.len() == 3 && t.as_bytes()[1] == b':' && t.ends_with('/')) {
        t = t.trim_end_matches('/').to_string();
    }
    if cfg!(windows) {
        t.to_ascii_lowercase()
    } else {
        t
    }
}

fn under_dir_norm(target: &str, base: &str) -> bool {
    let t = norm_cmp_path(target);
    let b = norm_cmp_path(base);
    if b.is_empty() {
        return false;
    }
    if t == b {
        return true;
    }
    if b.ends_with('/') {
        t.starts_with(&b)
    } else {
        t.starts_with(&format!("{}/", b))
    }
}

fn compile_policy_cedar_engine(
    policy: &LoadedOctopusPolicy,
) -> Result<Option<CedarPolicyEngine>, String> {
    if policy.cedar_engine.is_none() {
        return Ok(None);
    }
    if policy.is_standalone_cedar {
        let txt = std::fs::read_to_string(&policy.policy_path)
            .map_err(|e| format!("failed to reload Cedar policy: {}", e))?;
        Ok(Some(
            CedarPolicyEngine::from_validated_policy_set(&txt)
                .map_err(|e| format!("failed to compile Cedar policy: {}", e))?,
        ))
    } else {
        let mut chunks = Vec::new();
        if let Some(ref cf) = policy.json_policy.cedar_file {
            let p = if Path::new(cf).is_absolute() {
                PathBuf::from(cf)
            } else {
                policy
                    .policy_path
                    .parent()
                    .map(|par| par.join(cf))
                    .unwrap_or_else(|| PathBuf::from(cf))
            };
            chunks.push(
                std::fs::read_to_string(&p)
                    .map_err(|e| format!("failed to read cedar_file '{}': {}", p.display(), e))?,
            );
        }
        if let Some(ref inline) = policy.json_policy.cedar_policy {
            chunks.push(inline.clone());
        }
        if chunks.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                CedarPolicyEngine::from_validated_policy_set(&chunks.join("\n"))
                    .map_err(|e| format!("failed to compile Cedar policy: {}", e))?,
            ))
        }
    }
}

struct CedarFsControlHandle {
    port: u16,
    pipe_name: Option<String>,
    token: String,
    has_fs_read_forbid: bool,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl CedarFsControlHandle {
    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(jh) = self.join_handle.take() {
            let _ = tokio::time::timeout(Duration::from_millis(500), jh).await;
        }
    }
}

struct CedarFsServerState {
    engine: CedarPolicyEngine,
    is_standalone_cedar: bool,
    has_exec_permit_rule: bool,
    has_fs_read_permit_rule: bool,
    has_fs_write_permit_rule: bool,
    cwd: String,
    sandbox_mode: String,
    auth_token: String,
}

#[derive(Deserialize)]
struct CedarFsIpcRequest {
    token: String,
    action: String,
    path: String,
    #[serde(default)]
    raw_path: Option<String>,
    #[serde(default)]
    args_joined: Option<String>,
    #[serde(default)]
    check_pinned_parent: bool,
}

#[derive(Serialize)]
struct CedarFsIpcResponse {
    allowed: bool,
    explicit_forbid: bool,
    reason: String,
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn evaluate_cedar_fs_request(
    state: &CedarFsServerState,
    req: &CedarFsIpcRequest,
) -> CedarFsIpcResponse {
    if !constant_time_eq(&req.token, &state.auth_token) {
        return CedarFsIpcResponse {
            allowed: false,
            explicit_forbid: true,
            reason: "unauthorized_cedar_ipc_token".to_string(),
        };
    }

    let action = req.action.as_str();
    if action == "exec" {
        let prog_aliases = normalized_command_aliases(&req.path);
        let canonical_stem = prog_aliases
            .last()
            .cloned()
            .unwrap_or_else(|| req.path.to_ascii_lowercase());
        let args_joined = req.args_joined.as_deref().unwrap_or(&req.path);
        let ctx = serde_json::json!({
            "executable": req.path,
            "stem": canonical_stem,
            "args_joined": args_joined,
            "cwd": state.cwd,
            "sandbox_mode": state.sandbox_mode,
            "is_wasm": false,
        });
        let verdict =
            match state
                .engine
                .evaluate("cli_runner", "exec", &canonical_stem, "Command", ctx)
            {
                Ok(v) => v,
                Err(e) => {
                    return CedarFsIpcResponse {
                        allowed: false,
                        explicit_forbid: true,
                        reason: format!("cedar_exec_evaluation_error: {}", e),
                    };
                }
            };
        if verdict.is_allowed {
            return CedarFsIpcResponse {
                allowed: true,
                explicit_forbid: false,
                reason: "cedar_allow".to_string(),
            };
        }
        if !verdict.determining_policies.is_empty() {
            return CedarFsIpcResponse {
                allowed: false,
                explicit_forbid: true,
                reason: "cedar_exec_forbid".to_string(),
            };
        }
        return if state.is_standalone_cedar || state.has_exec_permit_rule {
            CedarFsIpcResponse {
                allowed: false,
                explicit_forbid: false,
                reason: "cedar_exec_denied".to_string(),
            }
        } else {
            CedarFsIpcResponse {
                allowed: true,
                explicit_forbid: false,
                reason: "cedar_no_action_rule_json_delegated".to_string(),
            }
        };
    }

    if action != "fs_read" && action != "fs_write" {
        return CedarFsIpcResponse {
            allowed: false,
            explicit_forbid: true,
            reason: format!("unsupported_cedar_fs_action: {}", action),
        };
    }

    #[cfg(windows)]
    if is_raw_admin_or_ipc_share_str(&req.path)
        || req
            .raw_path
            .as_deref()
            .is_some_and(is_raw_admin_or_ipc_share_str)
    {
        return CedarFsIpcResponse {
            allowed: false,
            explicit_forbid: true,
            reason: "windows_admin_share_denied".to_string(),
        };
    }

    let normalize_for_cedar = |raw: &str| -> String {
        let clean = strip_win_ads_and_trailing_dots_for_cedar(raw);
        if clean.is_empty() {
            clean
        } else {
            lexical_collapse_slashes(&clean)
        }
    };
    let mut candidates = Vec::with_capacity(2);
    let clean_primary = normalize_for_cedar(&req.path);
    candidates.push(clean_primary.clone());
    if let Some(ref raw) = req.raw_path {
        let clean_raw = normalize_for_cedar(raw);
        if !clean_raw.is_empty() && clean_raw != clean_primary {
            candidates.push(clean_raw);
        }
    }

    #[cfg(windows)]
    if candidates.iter().any(|c| is_unc_admin_share_str(c)) {
        return CedarFsIpcResponse {
            allowed: false,
            explicit_forbid: true,
            reason: "windows_admin_share_denied".to_string(),
        };
    }

    let has_permit_action_rule = if action == "fs_read" {
        state.has_fs_read_permit_rule
    } else {
        state.has_fs_write_permit_rule
    };

    let mut all_allowed = true;
    for cand in &candidates {
        let is_sensitive = classify_sensitive_system_path(cand).is_some();
        let is_pinned_parent = action == "fs_write"
            && req.check_pinned_parent
            && classify_pinned_parent_for_write_deny(cand).is_some();
        let is_mandatory_deny = if action == "fs_write" {
            classify_mandatory_write_deny_path(cand).is_some()
                || is_python_startup_guard_path(cand)
                || is_pinned_parent
        } else {
            false
        };

        if action == "fs_write" && is_mandatory_deny {
            return CedarFsIpcResponse {
                allowed: false,
                explicit_forbid: true,
                reason: if is_pinned_parent {
                    "mandatory_write_deny_pinned_parent".to_string()
                } else {
                    "mandatory_write_deny".to_string()
                },
            };
        }

        #[cfg(windows)]
        let norm_path = cand.to_ascii_lowercase();
        #[cfg(not(windows))]
        let norm_path = cand.clone();

        let make_ctx = |path_val: &str| {
            if action == "fs_read" {
                serde_json::json!({
                    "path": path_val,
                    "normalized_path": norm_path,
                    "is_sensitive": is_sensitive,
                })
            } else {
                serde_json::json!({
                    "path": path_val,
                    "normalized_path": norm_path,
                    "is_mandatory_deny": is_mandatory_deny,
                })
            }
        };

        let verdict =
            match state
                .engine
                .evaluate("cli_runner", action, cand, "FilePath", make_ctx(cand))
            {
                Ok(v) => v,
                Err(e) => {
                    return CedarFsIpcResponse {
                        allowed: false,
                        explicit_forbid: true,
                        reason: format!("cedar_{}_evaluation_error: {}", action, e),
                    };
                }
            };

        if !verdict.is_allowed && !verdict.determining_policies.is_empty() {
            return CedarFsIpcResponse {
                allowed: false,
                explicit_forbid: true,
                reason: format!("cedar_{}_forbid", action),
            };
        }

        #[allow(unused_mut)]
        let mut cand_allowed = verdict.is_allowed;
        #[cfg(windows)]
        {
            let lower_cand = cand.to_ascii_lowercase();
            if lower_cand != *cand {
                let verdict_lower = match state.engine.evaluate(
                    "cli_runner",
                    action,
                    &lower_cand,
                    "FilePath",
                    make_ctx(&lower_cand),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        return CedarFsIpcResponse {
                            allowed: false,
                            explicit_forbid: true,
                            reason: format!("cedar_{}_evaluation_error: {}", action, e),
                        };
                    }
                };
                if !verdict_lower.is_allowed && !verdict_lower.determining_policies.is_empty() {
                    return CedarFsIpcResponse {
                        allowed: false,
                        explicit_forbid: true,
                        reason: format!("cedar_{}_forbid", action),
                    };
                }
                cand_allowed = cand_allowed || verdict_lower.is_allowed;
            }
        }

        if !cand_allowed {
            all_allowed = false;
        }
    }

    if all_allowed {
        return CedarFsIpcResponse {
            allowed: true,
            explicit_forbid: false,
            reason: "cedar_allow".to_string(),
        };
    }

    if state.is_standalone_cedar || has_permit_action_rule {
        CedarFsIpcResponse {
            allowed: false,
            explicit_forbid: false,
            reason: format!("cedar_{}_denied", action),
        }
    } else {
        CedarFsIpcResponse {
            allowed: true,
            explicit_forbid: false,
            reason: "cedar_no_action_rule_json_delegated".to_string(),
        }
    }
}

#[cfg(windows)]
fn create_cedar_pipe_instance(
    pipe_name: &str,
    sddl: &str,
    first_instance: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, String> {
    use crate::security::windows_sandbox::win32::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, LocalFree,
    };

    struct OwnedSecurityDescriptor(*mut std::ffi::c_void);
    impl Drop for OwnedSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct PipeSecurityAttributes {
        nLength: u32,
        lpSecurityDescriptor: *mut std::ffi::c_void,
        bInheritHandle: i32,
    }

    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            1,
            &mut sd_ptr,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || sd_ptr.is_null() {
        return Err(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed for Cedar IPC pipe '{}'",
            pipe_name
        ));
    }
    let _sd_guard = OwnedSecurityDescriptor(sd_ptr);
    let mut sa = PipeSecurityAttributes {
        nLength: std::mem::size_of::<PipeSecurityAttributes>() as u32,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };
    let mut opts = tokio::net::windows::named_pipe::ServerOptions::new();
    opts.reject_remote_clients(true);
    if first_instance {
        opts.first_pipe_instance(true);
    }
    unsafe {
        opts.create_with_security_attributes_raw(
            pipe_name,
            &mut sa as *mut _ as *mut std::ffi::c_void,
        )
    }
    .map_err(|e| {
        format!(
            "failed to create Cedar FS control pipe '{}': {}",
            pipe_name, e
        )
    })
}

async fn handle_cedar_ipc_connection<R, W>(
    read_half: R,
    mut write_half: W,
    st: Arc<CedarFsServerState>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let resp = match serde_json::from_str::<CedarFsIpcRequest>(trimmed) {
                    Ok(req) => evaluate_cedar_fs_request(&st, &req),
                    Err(e) => CedarFsIpcResponse {
                        allowed: false,
                        explicit_forbid: true,
                        reason: format!("invalid_cedar_ipc_request: {}", e),
                    },
                };
                let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| {
                    "{\"allowed\":false,\"explicit_forbid\":true,\"reason\":\"serialize_error\"}"
                        .to_string()
                });
                out.push('\n');
                if write_half.write_all(out.as_bytes()).await.is_err() {
                    break;
                }
                let _ = write_half.flush().await;
            }
        }
    }
}

async fn start_cedar_fs_control_server(
    policy: &LoadedOctopusPolicy,
    cwd: &Path,
    sandbox_mode: SandboxMode,
    appcontainer_sid: Option<&str>,
) -> Result<Option<CedarFsControlHandle>, String> {
    let Some(engine) = compile_policy_cedar_engine(policy)? else {
        return Ok(None);
    };
    let has_exec_permit_rule = engine.has_permit_action_policy("exec");
    let has_fs_read_permit_rule = engine.has_permit_action_policy("fs_read");
    let has_fs_write_permit_rule = engine.has_permit_action_policy("fs_write");
    let has_fs_read_forbid_rule = engine.has_forbid_action_policy("fs_read");
    let token_bytes: [u8; 32] = rand::random();
    let auth_token: String = token_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    let state = Arc::new(CedarFsServerState {
        engine,
        is_standalone_cedar: policy.is_standalone_cedar,
        has_exec_permit_rule,
        has_fs_read_permit_rule,
        has_fs_write_permit_rule,
        cwd: cwd.to_string_lossy().to_string(),
        sandbox_mode: sandbox_mode.as_str().to_string(),
        auth_token: auth_token.clone(),
    });

    #[cfg(windows)]
    if let Some(ac_sid) = appcontainer_sid {
        let pipe_name = format!(
            r"\\.\pipe\octopus-cedar-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        );
        let sddl = format!(
            "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;GRGW;;;{})",
            ac_sid
        );
        let mut server = create_cedar_pipe_instance(&pipe_name, &sddl, true)?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let pipe_name_loop = pipe_name.clone();
        let join_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    conn_res = server.connect() => {
                        match conn_res {
                            Ok(()) => {
                                let connected = server;
                                let next_server = match create_cedar_pipe_instance(&pipe_name_loop, &sddl, false) {
                                    Ok(ns) => ns,
                                    Err(_) => break,
                                };
                                server = next_server;
                                let st = state.clone();
                                tokio::spawn(async move {
                                    let (read_half, write_half) = tokio::io::split(connected);
                                    handle_cedar_ipc_connection(read_half, write_half, st).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        return Ok(Some(CedarFsControlHandle {
            port: 0,
            pipe_name: Some(pipe_name),
            token: auth_token,
            has_fs_read_forbid: has_fs_read_forbid_rule,
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        }));
    }

    #[cfg(not(windows))]
    let _ = appcontainer_sid;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("failed to bind Cedar FS control IPC on 127.0.0.1:0: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("failed to inspect Cedar FS control addr: {}", e))?
        .port();

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let st = state.clone();
                            tokio::spawn(async move {
                                let (read_half, write_half) = stream.into_split();
                                handle_cedar_ipc_connection(read_half, write_half, st).await;
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    Ok(Some(CedarFsControlHandle {
        port,
        pipe_name: None,
        token: auth_token,
        has_fs_read_forbid: has_fs_read_forbid_rule,
        shutdown_tx: Some(shutdown_tx),
        join_handle: Some(join_handle),
    }))
}

fn has_shell_smuggling_in_args(args: &[String], deny_cmds: &[String]) -> Option<String> {
    let mut expect_inline_code = false;
    for (idx, tok) in args.iter().enumerate() {
        let trimmed = tok.trim();
        if matches!(trimmed, ";" | "&&" | "||" | "|" | "&" | "`") {
            return Some(format!(
                "shell chaining/smuggling operator '{}' in argv[{}]",
                trimmed, idx
            ));
        }
        if expect_inline_code {
            expect_inline_code = false;
            if trimmed.contains('`') || trimmed.contains("$(") {
                return Some(
                    "command substitution backtick/$() in inline script payload".to_string(),
                );
            }
            continue;
        }
        if trimmed == "-c" || trimmed == "-e" {
            expect_inline_code = true;
            continue;
        }
        let aliases = normalized_command_aliases(trimmed);
        for shell_tok in ["bash", "sh", "zsh", "dash", "powershell", "pwsh", "cmd"] {
            if aliases.iter().any(|a| a == shell_tok) {
                return Some(format!(
                    "smuggled shell token '{}' in argv[{}]",
                    trimmed, idx
                ));
            }
        }
        for denied in deny_cmds {
            let d_aliases = normalized_command_aliases(denied);
            if aliases.iter().any(|a| d_aliases.contains(a)) {
                return Some(format!(
                    "denied command token '{}' in argv[{}]",
                    trimmed, idx
                ));
            }
        }
    }
    None
}

fn strip_matching_outer_quotes(mut s: &str) -> &str {
    loop {
        let t = s.trim();
        if t.len() >= 2
            && ((t.starts_with('"') && t.ends_with('"'))
                || (t.starts_with('\'') && t.ends_with('\'')))
        {
            s = &t[1..t.len() - 1];
        } else if t.len() >= 4
            && ((t.starts_with("\\\"") && t.ends_with("\\\""))
                || (t.starts_with("\\'") && t.ends_with("\\'")))
        {
            s = &t[2..t.len() - 2];
        } else {
            return t;
        }
    }
}

fn extract_preflight_arg_candidate(unquoted_tok: &str) -> Option<&str> {
    if !unquoted_tok.starts_with('-') {
        return Some(unquoted_tok);
    }
    let sep_pos = match (unquoted_tok.find('='), unquoted_tok.find(':')) {
        (Some(e), Some(c)) => Some(e.min(c)),
        (Some(e), None) => Some(e),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }?;
    let lhs = unquoted_tok[..sep_pos].trim();
    if lhs.trim_start_matches('-').is_empty() {
        return None;
    }
    let cand = strip_matching_outer_quotes(&unquoted_tok[sep_pos + 1..]);
    if cand.is_empty() {
        None
    } else {
        Some(cand)
    }
}

fn run_preflight_gate(
    args: &OctopusRunArgs,
    policy: &LoadedOctopusPolicy,
    cwd: &Path,
    is_wasm: bool,
) -> Result<(String, Option<PathBuf>), String> {
    let program = &args.command[0];
    let cmd_args = &args.command[1..];

    if program.chars().any(|c| c == '\0' || c < ' ')
        || cmd_args.iter().any(|a| {
            a.chars()
                .any(|c| c == '\0' || (c < ' ' && c != '\n' && c != '\r' && c != '\t'))
        })
    {
        return Err("command or arguments contain NUL or invalid control characters".to_string());
    }

    let joined = build_joined_cmdline(program, cmd_args);
    let tech = TechnicalBreakoutGuard::default().evaluate_execution(program, &joined);
    if !tech.is_clean {
        return Err(format!(
            "TechnicalBreakoutGuard blocked execution: {}",
            tech.detected_vectors.join("; ")
        ));
    }

    let sem = parse_semantic_command(&joined);
    if sem.privilege_class.is_privileged_execution() {
        return Err(format!(
            "SemanticCommand AST blocked privileged execution ({:?})",
            sem.privilege_class
        ));
    }

    let resolved_exe = if is_wasm {
        let p = Path::new(program);
        let cand = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };
        if !cand.is_file() {
            return Err(format!("wasm/wat file '{}' does not exist", cand.display()));
        }
        Some(strip_win_verbatim_prefix(
            std::fs::canonicalize(&cand).unwrap_or(cand),
        ))
    } else {
        let resolved = resolve_executable_on_path(program, cwd);
        if let Some(ref exe_path) = resolved {
            if let Ok(probe) = DynamicBinaryMetadataProbe::probe_path(exe_path) {
                if probe.is_privileged_target() {
                    return Err(format!(
                        "DynamicBinaryMetadataProbe blocked privileged executable '{}'",
                        exe_path.display()
                    ));
                }
            }
        }
        resolved
    };

    if let Some(reason) = has_shell_smuggling_in_args(cmd_args, &policy.json_policy.commands.deny) {
        return Err(format!("RT-ASP command smuggling guard: {}", reason));
    }

    let check_rtasp_token = |val: &str, orig_tok: &str| -> Result<(), String> {
        #[cfg(windows)]
        if is_raw_admin_or_ipc_share_str(val) {
            return Err(format!(
                "Windows administrative UNC share argument '{}' is denied",
                orig_tok
            ));
        }
        if let Some(kind) = classify_sensitive_system_path(val) {
            return Err(format!(
                "SensitiveSystemPathGuard blocked argument '{}' ({:?})",
                orig_tok, kind
            ));
        }
        if let Some((kind, needle)) = scan_for_sensitive_system_path(val) {
            return Err(format!(
                "SensitiveSystemPathGuard blocked reference to '{}' ({:?})",
                needle, kind
            ));
        }
        if has_ntfs_ads_suffix(val) {
            if let Some(kind) = classify_pinned_parent_for_write_deny(val) {
                return Err(format!(
                    "MandatoryWriteDenyGuard blocked NTFS alternate data stream argument '{}' ({:?})",
                    orig_tok, kind
                ));
            }
            if is_python_startup_guard_path(val) {
                return Err(format!(
                    "MandatoryWriteDenyGuard blocked NTFS alternate data stream Python startup target '{}'",
                    orig_tok
                ));
            }
        }
        Ok(())
    };
    for tok in &args.command {
        check_rtasp_token(tok, tok)?;
        let unquoted = strip_matching_outer_quotes(tok.trim());
        if let Some(cand) = extract_preflight_arg_candidate(unquoted) {
            if cand != tok {
                check_rtasp_token(cand, tok)?;
            }
        }
    }

    let prog_aliases = normalized_command_aliases(program);
    let canonical_stem = prog_aliases
        .last()
        .cloned()
        .unwrap_or_else(|| program.to_ascii_lowercase());
    let is_python = !is_wasm && is_python_aliases(&prog_aliases);

    let mut skip_arg_indices = std::collections::HashSet::<usize>::new();
    let mut entry_script_idx: Option<usize> = None;
    if is_python {
        let mut i = 0;
        while i < cmd_args.len() {
            let tok = cmd_args[i].trim();
            if tok == "--" {
                if i + 1 < cmd_args.len() {
                    entry_script_idx = Some(i + 1);
                }
                break;
            }
            if tok == "-" {
                break;
            }
            if tok.starts_with("--") {
                if tok == "--check-hash-based-pycs" && i + 1 < cmd_args.len() {
                    skip_arg_indices.insert(i + 1);
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if tok.starts_with('-') && tok.len() > 1 {
                let mut has_c = false;
                let mut has_m = false;
                let mut skip_next = false;
                let mut chars = tok[1..].chars();
                while let Some(ch) = chars.next() {
                    if ch == '=' {
                        break;
                    }
                    if ch == 'c' {
                        has_c = true;
                        if let Some(next_ch) = chars.next() {
                            if next_ch != '=' {
                                skip_arg_indices.insert(i);
                            }
                        } else if i + 1 < cmd_args.len() {
                            skip_arg_indices.insert(i + 1);
                        }
                        break;
                    }
                    if ch == 'm' {
                        has_m = true;
                        if let Some(next_ch) = chars.next() {
                            if next_ch != '=' {
                                skip_arg_indices.insert(i);
                            }
                        } else if i + 1 < cmd_args.len() {
                            skip_arg_indices.insert(i + 1);
                        }
                        break;
                    }
                    if ch == 'W' || ch == 'X' {
                        if chars.next().is_none() && i + 1 < cmd_args.len() {
                            skip_arg_indices.insert(i + 1);
                            skip_next = true;
                        }
                        break;
                    }
                }
                if has_c || has_m {
                    break;
                }
                if skip_next {
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            entry_script_idx = Some(i);
            break;
        }
    } else {
        let mut i = 0;
        while i < cmd_args.len() {
            let tok = cmd_args[i].trim();
            if matches!(tok, "-c" | "-e")
                || (cfg!(windows)
                    && (tok.eq_ignore_ascii_case("/c") || tok.eq_ignore_ascii_case("/k")))
            {
                if i + 1 < cmd_args.len() {
                    skip_arg_indices.insert(i + 1);
                }
                break;
            }
            i += 1;
        }
    }

    let mut json_deny_paths: Vec<String> = Vec::new();
    if !policy.is_standalone_cedar {
        for raw in &policy.json_policy.filesystem.deny {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            let abs = if let Some(exp) = expand_tilde_for_preflight(t) {
                exp
            } else {
                let p = Path::new(t);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    cwd.join(p)
                }
            };
            let lex_raw = strip_win_ads_and_trailing_dots_for_cedar(&abs.to_string_lossy());
            let lex_clean = lexical_collapse_slashes(&lex_raw);
            if !lex_clean.is_empty() && !json_deny_paths.contains(&lex_clean) {
                json_deny_paths.push(lex_clean);
            }
            if let Ok(canon_pb) = std::fs::canonicalize(&abs) {
                let canon_stripped = strip_win_verbatim_prefix(canon_pb);
                let canon_raw =
                    strip_win_ads_and_trailing_dots_for_cedar(&canon_stripped.to_string_lossy());
                let canon_clean = lexical_collapse_slashes(&canon_raw);
                if !canon_clean.is_empty() && !json_deny_paths.contains(&canon_clean) {
                    json_deny_paths.push(canon_clean);
                }
            }
        }
    }

    if !policy.is_standalone_cedar || policy.cedar_engine.is_some() {
        for (idx, tok) in cmd_args.iter().enumerate() {
            if skip_arg_indices.contains(&idx) {
                continue;
            }
            let trimmed = tok.trim();
            if trimmed.is_empty() {
                continue;
            }
            let unquoted_tok = strip_matching_outer_quotes(trimmed);
            if unquoted_tok.is_empty() {
                continue;
            }
            let Some(candidate_tok) = extract_preflight_arg_candidate(unquoted_tok) else {
                continue;
            };

            let lower_tok = candidate_tok.to_ascii_lowercase();
            if lower_tok.starts_with("http://")
                || lower_tok.starts_with("https://")
                || lower_tok.starts_with("ws://")
                || lower_tok.starts_with("wss://")
                || lower_tok.starts_with("ftp://")
            {
                continue;
            }
            #[cfg(windows)]
            if candidate_tok.starts_with('/')
                && !candidate_tok.starts_with("//")
                && !candidate_tok[1..].contains(['/', '\\'])
                && candidate_tok.len() <= 8
                && !Path::new(candidate_tok).exists()
            {
                continue;
            }

            let p = Path::new(candidate_tok);
            let is_tilde = candidate_tok == "~"
                || candidate_tok.starts_with("~/")
                || (cfg!(windows) && candidate_tok.starts_with("~\\"));
            let is_win_drive = cfg!(windows)
                && candidate_tok.len() >= 2
                && candidate_tok.as_bytes()[0].is_ascii_alphabetic()
                && candidate_tok.as_bytes()[1] == b':';
            let is_path_candidate = is_tilde
                || is_win_drive
                || p.is_absolute()
                || candidate_tok.contains('/')
                || candidate_tok.contains('\\')
                || cwd.join(p).exists();
            if !is_path_candidate {
                continue;
            }

            let abs = if let Some(exp) = expand_tilde_for_preflight(candidate_tok) {
                exp
            } else if is_win_drive && !candidate_tok[2..].starts_with(['/', '\\']) {
                let cwd_s = cwd.to_string_lossy();
                let cwd_clean = cwd_s.strip_prefix(r"\\?\").unwrap_or(&cwd_s);
                let cwd_bytes = cwd_clean.as_bytes();
                if cwd_bytes.len() >= 2
                    && cwd_bytes[1] == b':'
                    && cwd_bytes[0].eq_ignore_ascii_case(&candidate_tok.as_bytes()[0])
                {
                    let rel = &candidate_tok[2..];
                    if rel.is_empty() {
                        cwd.to_path_buf()
                    } else {
                        cwd.join(rel)
                    }
                } else {
                    p.to_path_buf()
                }
            } else if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd.join(p)
            };

            #[cfg(windows)]
            if is_raw_admin_or_ipc_share_str(candidate_tok) {
                return Err(format!(
                    "Windows administrative UNC share argument '{}' is denied",
                    tok
                ));
            }
            let lex_raw = strip_win_ads_and_trailing_dots_for_cedar(&abs.to_string_lossy());
            #[cfg(windows)]
            if is_unc_admin_share_str(&lex_raw) {
                return Err(format!(
                    "Windows administrative UNC share argument '{}' is denied",
                    tok
                ));
            }
            let lex_clean = lexical_collapse_slashes(&lex_raw);
            let mut check_paths = vec![lex_clean.clone()];
            if let Ok(canon_pb) = std::fs::canonicalize(&abs) {
                let canon_stripped = strip_win_verbatim_prefix(canon_pb);
                let canon_raw =
                    strip_win_ads_and_trailing_dots_for_cedar(&canon_stripped.to_string_lossy());
                #[cfg(windows)]
                if is_unc_admin_share_str(&canon_raw) {
                    return Err(format!(
                        "Windows administrative UNC share argument '{}' is denied",
                        tok
                    ));
                }
                let canon_clean = lexical_collapse_slashes(&canon_raw);
                if canon_clean != lex_clean {
                    check_paths.push(canon_clean);
                }
            }

            if !policy.is_standalone_cedar {
                for cp in &check_paths {
                    if json_deny_paths.iter().any(|dp| under_dir_norm(cp, dp)) {
                        return Err(format!(
                            "argument '{}' is blocked by policy filesystem.deny",
                            tok
                        ));
                    }
                }
            }

            if !is_python
                && !is_wasm
                && matches!(
                    canonical_stem.as_str(),
                    "rm" | "rmdir"
                        | "unlink"
                        | "mv"
                        | "move"
                        | "ren"
                        | "rename"
                        | "del"
                        | "erase"
                        | "rd"
                        | "mklink"
                        | "ln"
                )
            {
                for cp in &check_paths {
                    if let Some(kind) = classify_pinned_parent_for_write_deny(cp) {
                        return Err(format!(
                            "MandatoryWriteDenyGuard blocked '{}' targeting protected path '{}' ({:?})",
                            canonical_stem, tok, kind
                        ));
                    }
                }
            }

            if let Some(ref cedar) = policy.cedar_engine {
                let is_entry_script = entry_script_idx == Some(idx);
                let enforce_default_deny = !is_entry_script
                    && (policy.is_standalone_cedar || cedar.has_permit_action_policy("fs_read"));
                let mut all_allowed = true;

                for cand in &check_paths {
                    let is_sensitive = classify_sensitive_system_path(cand).is_some();
                    #[cfg(windows)]
                    let norm_path = cand.to_ascii_lowercase();
                    #[cfg(not(windows))]
                    let norm_path = cand.clone();

                    let verdict = cedar
                        .evaluate(
                            "cli_runner",
                            "fs_read",
                            cand,
                            "FilePath",
                            serde_json::json!({
                                "path": cand,
                                "normalized_path": norm_path,
                                "is_sensitive": is_sensitive,
                            }),
                        )
                        .map_err(|e| format!("Cedar fs_read evaluation failed: {}", e))?;
                    if !verdict.is_allowed && !verdict.determining_policies.is_empty() {
                        return Err(format!(
                            "Cedar policy explicitly forbids fs_read for argument '{}'",
                            tok
                        ));
                    }
                    let mut cand_allowed = verdict.is_allowed;
                    #[cfg(windows)]
                    if norm_path != *cand {
                        let verdict_lower = cedar
                            .evaluate(
                                "cli_runner",
                                "fs_read",
                                &norm_path,
                                "FilePath",
                                serde_json::json!({
                                    "path": norm_path,
                                    "normalized_path": norm_path,
                                    "is_sensitive": is_sensitive,
                                }),
                            )
                            .map_err(|e| format!("Cedar fs_read evaluation failed: {}", e))?;
                        if !verdict_lower.is_allowed
                            && !verdict_lower.determining_policies.is_empty()
                        {
                            return Err(format!(
                                "Cedar policy explicitly forbids fs_read for argument '{}'",
                                tok
                            ));
                        }
                        cand_allowed = cand_allowed || verdict_lower.is_allowed;
                    }
                    if !cand_allowed {
                        all_allowed = false;
                    }
                }

                if !all_allowed && enforce_default_deny {
                    return Err(format!(
                        "Cedar policy denied fs_read for argument '{}'",
                        tok
                    ));
                }
            }
        }
    }

    if is_python {
        if let Some(bad_flag) = find_forbidden_python_flag(cmd_args) {
            return Err(format!(
                "Python isolation/site-bypass flag '{}' is forbidden under Octopus containment",
                bad_flag
            ));
        }
    }

    if !is_wasm && !policy.is_standalone_cedar {
        for denied in &policy.json_policy.commands.deny {
            let d_aliases = normalized_command_aliases(denied);
            if prog_aliases.iter().any(|a| d_aliases.contains(a)) {
                return Err(format!(
                    "command '{}' is blocked by policy commands.deny ('{}')",
                    program, denied
                ));
            }
        }
        if !policy.json_policy.commands.allow.is_empty() {
            let allowed = policy.json_policy.commands.allow.iter().any(|al| {
                let a_aliases = normalized_command_aliases(al);
                prog_aliases.iter().any(|a| a_aliases.contains(a))
            });
            if !allowed {
                return Err(format!(
                    "command '{}' is not in policy commands.allow",
                    program
                ));
            }
        }
    }

    if let Some(ref cedar) = policy.cedar_engine {
        let verdict = cedar
            .evaluate(
                "cli_runner",
                "exec",
                &canonical_stem,
                "Command",
                serde_json::json!({
                    "executable": program,
                    "stem": canonical_stem,
                    "args_joined": joined,
                    "cwd": cwd.to_string_lossy().to_string(),
                    "sandbox_mode": args.sandbox.as_str(),
                    "is_wasm": is_wasm,
                }),
            )
            .map_err(|e| format!("Cedar exec evaluation failed: {}", e))?;
        if !verdict.is_allowed
            && (policy.is_standalone_cedar
                || !verdict.determining_policies.is_empty()
                || cedar.has_permit_action_policy("exec"))
        {
            return Err(format!(
                "Cedar policy denied exec for '{}' (stem='{}')",
                program, canonical_stem
            ));
        }
    }

    Ok((canonical_stem, resolved_exe))
}
fn create_python_audit_guard(
    policy: &LoadedOctopusPolicy,
    cwd: &Path,
    cedar_ipc: Option<(u16, Option<&str>, &str, bool)>,
    win_ac_blocked_proxy_port: Option<u16>,
) -> Result<TempGuardDir, String> {
    let dir = std::env::temp_dir().join(format!(
        "octopus_py_guard_{}_{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("failed to create ephemeral python guard dir: {}", e))?;

    let resolve_list = |items: &[String]| -> Vec<String> {
        items
            .iter()
            .filter_map(|raw| {
                let t = raw.trim();
                if t.is_empty() {
                    return None;
                }
                if t.starts_with('~') {
                    return Some(t.replace('\\', "/"));
                }
                let p = Path::new(t);
                let abs = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    cwd.join(p)
                };
                let canon = strip_win_verbatim_prefix(std::fs::canonicalize(&abs).unwrap_or(abs));
                Some(canon.to_string_lossy().replace('\\', "/"))
            })
            .collect()
    };

    let allow_write = resolve_list(&policy.json_policy.filesystem.allow_write);
    let deny_resolved = resolve_list(&policy.json_policy.filesystem.deny);
    let deny_raw: Vec<String> = policy
        .json_policy
        .filesystem
        .deny
        .iter()
        .map(|s| s.trim().replace('\\', "/").to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let has_cedar_fs = policy.is_standalone_cedar
        || policy
            .cedar_engine
            .as_ref()
            .is_some_and(|e| e.has_action_policy("fs_read") || e.has_action_policy("fs_write"));
    let has_fs_restrictions = policy.has_filesystem_section
        || !policy.json_policy.filesystem.allow_read.is_empty()
        || !policy.json_policy.filesystem.allow_write.is_empty()
        || !policy.json_policy.filesystem.deny.is_empty()
        || has_cedar_fs;
    let mut commands_allow: Vec<String> = Vec::new();
    for entry in &policy.json_policy.commands.allow {
        for alias in normalized_command_aliases(entry) {
            if !commands_allow.contains(&alias) {
                commands_allow.push(alias);
            }
        }
    }
    let mut commands_deny: Vec<String> = Vec::new();
    for entry in &policy.json_policy.commands.deny {
        for alias in normalized_command_aliases(entry) {
            if !commands_deny.contains(&alias) {
                commands_deny.push(alias);
            }
        }
    }

    let mut local_hosts: std::collections::BTreeSet<String> = [
        "localhost",
        "localhost.",
        "localhost.localdomain",
        "127.0.0.1",
        "::1",
        "[::1]",
        "0:0:0:0:0:0:0:1",
        "0.0.0.0",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for env_k in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(ev) = std::env::var(env_k) {
            let el = ev.trim().trim_end_matches('.').to_ascii_lowercase();
            if !el.is_empty() {
                local_hosts.insert(format!("{}.", el));
                local_hosts.insert(el);
            }
        }
    }
    if let (Ok(cn), Ok(udns)) = (
        std::env::var("COMPUTERNAME"),
        std::env::var("USERDNSDOMAIN"),
    ) {
        let cn = cn.trim().trim_end_matches('.');
        let udns = udns.trim().trim_end_matches('.');
        if !cn.is_empty() && !udns.is_empty() {
            let fq = format!("{}.{}", cn, udns).to_ascii_lowercase();
            local_hosts.insert(format!("{}.", fq));
            local_hosts.insert(fq);
        }
    }
    let host_probes: Vec<String> = local_hosts
        .iter()
        .map(|h| h.trim_end_matches('.').to_string())
        .filter(|h| !h.is_empty() && h.chars().any(|c| c.is_ascii_alphabetic()))
        .collect();
    for h in host_probes {
        if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(h.as_str(), 0)) {
            for sa in addrs {
                let ip_s = sa.ip().to_string().to_ascii_lowercase();
                if ip_s.contains(':') {
                    local_hosts.insert(format!("[{}]", ip_s));
                }
                local_hosts.insert(ip_s);
            }
        }
    }
    let local_hosts_vec: Vec<String> = local_hosts.into_iter().collect();

    let cfg_json = serde_json::json!({
        "enforce_allow_write": policy.has_filesystem_section,
        "has_fs_restrictions": has_fs_restrictions,
        "allow_write": allow_write,
        "deny_resolved": deny_resolved,
        "deny_raw": deny_raw,
        "commands_allow": commands_allow,
        "commands_deny": commands_deny,
        "guard_dir": dir.to_string_lossy().replace('\\', "/"),
        "cedar_ipc_port": cedar_ipc.and_then(|(p, _, _, _)| if p > 0 { Some(p) } else { None }),
        "cedar_ipc_pipe": cedar_ipc.and_then(|(_, pipe, _, _)| pipe),
        "cedar_ipc_token": cedar_ipc.map(|(_, _, t, _)| t),
        "cedar_has_fs_read_forbid": cedar_ipc.is_some_and(|(_, _, _, f)| f),
        "win_ac_blocked_proxy_port": win_ac_blocked_proxy_port,
        "local_hosts": local_hosts_vec,
    })
    .to_string();

    let cfg_literal = serde_json::to_string(&cfg_json).unwrap_or_else(|_| "\"{}\"".to_string());
    let sitecustomize_template = r##"def _install_octopus_audit():
    import builtins, errno, genericpath, json, ntpath, operator, os, pathlib, posixpath, signal, _signal, socket, _socket, sqlite3, sqlite3.dump, _sqlite3, stat, sys, threading, types, _weakref
    try:
        import _json
    except ImportError:
        _json = None

    _OCTOPUS_CFG = json.loads(__OCTOPUS_CFG_LITERAL__)
    _IS_WIN = (os.name == "nt")

    _OS_EXIT = os._exit
    _INSTALL_CODE = sys._getframe(0).f_code
    _SYS_MOD = sys
    _SYS_AUDIT = sys.audit
    _SYS_GETFRAME = sys._getframe
    _SYS_IS_FINALIZING = sys.is_finalizing
    _FRAME_TYPE = types.FrameType
    _CODE_TYPE = type(_INSTALL_CODE)

    def _collect_nested_codes(root_codes):
        out = set()
        stack = [c for c in root_codes if type(c) is _CODE_TYPE]
        while stack:
            c = stack.pop()
            if c in out:
                continue
            out.add(c)
            for const in c.co_consts:
                if type(const) is _CODE_TYPE and const not in out:
                    stack.append(const)
        return frozenset(out)
    _GET_IDENT = threading.get_ident
    _THREADING_LOCAL = threading.local
    _THREADING_LOCAL_TYPE = type(threading.local())
    _LOCK_TYPE = type(threading.Lock())
    _TYPE_DICT_GET = type.__dict__["__dict__"].__get__
    _TYPE_MRO_GET = type.__dict__["__mro__"].__get__
    _MP_ITEMS = type(object.__dict__).items
    _OBJECT_GETATTR = object.__getattribute__
    _MISSING = object()
    _DICT_GET = dict.get
    _DICT_POP = dict.pop
    _DICT_LEN = dict.__len__
    _DICT_GETITEM = dict.__getitem__
    _LIST_APPEND = list.append
    _LIST_POP = list.pop
    _stat_gc_queue = []
    _sqlite_gc_queue = []
    _OBJECT_NEW = object.__new__
    _OBJ_HASH = object.__hash__
    _WEAKREF = _weakref.ref
    _OP_INDEX = operator.index
    _EXC_TB_SET = BaseException.__traceback__.__set__
    _EXC_CAUSE_SET = BaseException.__cause__.__set__
    _EXC_CTX_SET = BaseException.__context__.__set__

    _OS_PATHLIKE = getattr(os, "PathLike", None)
    _OS_FSPATH = getattr(os, "fspath", None)
    _OS_DIRENTRY = getattr(os, "DirEntry", None)
    _OS_DIRENTRY_FSPATH = getattr(_OS_DIRENTRY, "__fspath__", None)
    _OS_DIRENTRY_PATH_DESC = getattr(_OS_DIRENTRY, "path", None)
    _EXACT_PATHLIB_TYPES = tuple(
        t for t in (
            getattr(pathlib, n, None)
            for n in ("Path", "PurePath", "PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath")
        )
        if t is not None
    )
    _PUREPATH_CLS = getattr(pathlib, "PurePath", None)
    _PUREPATH_RAW_PATHS_DESC = _PUREPATH_CLS.__dict__.get("_raw_paths") if _PUREPATH_CLS is not None else None
    _PUREPATH_STR_DESC = _PUREPATH_CLS.__dict__.get("_str") if _PUREPATH_CLS is not None else None
    _PUREPATH_DRV_DESC = _PUREPATH_CLS.__dict__.get("_drv") if _PUREPATH_CLS is not None else None
    _PUREPATH_ROOT_DESC = _PUREPATH_CLS.__dict__.get("_root") if _PUREPATH_CLS is not None else None
    _PUREPATH_TAIL_DESC = _PUREPATH_CLS.__dict__.get("_tail_cached") if _PUREPATH_CLS is not None else None
    _POSIX_PATHLIB_TYPES = tuple(
        t for t in (
            getattr(pathlib, "PurePosixPath", None),
            getattr(pathlib, "PosixPath", None),
        )
        if t is not None
    )
    _PATHLIB_CHECK_ATTRS = (
        "__fspath__", "__str__", "_str", "_raw_paths", "_drv", "_root", "_tail_cached",
        "_format_parsed_parts", "_parse_path", "_raw_path", "drive", "root", "_tail", "parser",
    )

    def _setup_raw_mro_attr(cls, aname):
        for _b in _TYPE_MRO_GET(cls):
            _bd = _TYPE_DICT_GET(_b)
            for _k, _v in _MP_ITEMS(_bd):
                if type(_k) is str and _k == aname:
                    return _v
        return _MISSING

    _PATHLIB_META_MAP = tuple(
        (
            _pt,
            (_pt in _POSIX_PATHLIB_TYPES),
            tuple((_an, _setup_raw_mro_attr(_pt, _an)) for _an in _PATHLIB_CHECK_ATTRS),
        )
        for _pt in _EXACT_PATHLIB_TYPES
    )
    _SOCK_CLS = _socket.socket
    _AF_INET = _socket.AF_INET
    _SOCK_STREAM = _socket.SOCK_STREAM
    _JSON_C_ENC = (
        _json.make_encoder(None, None, _json.encode_basestring_ascii, None, ": ", ", ", False, None, True)
        if _json is not None
        else None
    )
    _JSON_C_SCAN = _json.make_scanner(json.JSONDecoder()) if _json is not None else None
    _JSON_DUMPS = json.dumps
    _JSON_LOADS = json.loads

    class _FrozenDict(dict):
        __slots__ = ()

        def _deny(self, *a, **kw):
            raise PermissionError("blocked_by_octopus_policy: immutable audit globals")

        __setitem__ = _deny
        __delitem__ = _deny
        clear = _deny
        pop = _deny
        popitem = _deny
        setdefault = _deny
        update = _deny
        __ior__ = _deny
        copy = _deny

        def keys(self):
            return ()

        def values(self):
            return ()

        def items(self):
            return ()

        def __iter__(self):
            return iter(())

        def __repr__(self):
            return "<FrozenAuditGlobals>"

    class _FrozenModule:
        __slots__ = ("__dict__", "__name__")

        def __init__(self, name, frozen_dict):
            object.__setattr__(self, "__name__", name)
            object.__setattr__(self, "__dict__", frozen_dict)

        def __setattr__(self, *a, **kw):
            raise PermissionError("blocked_by_octopus_policy: immutable audit module")

        def __delattr__(self, *a, **kw):
            raise PermissionError("blocked_by_octopus_policy: immutable audit module")

        def __repr__(self):
            return "<FrozenAuditModule>"

    _FROZEN_DENY_FN = _FrozenDict._deny
    _FROZEN_DENY_CODE = _FROZEN_DENY_FN.__code__
    _FROZEN_MOD_SETATTR_FN = _FrozenModule.__setattr__
    _FROZEN_MOD_SETATTR_CODE = _FROZEN_MOD_SETATTR_FN.__code__
    _FROZEN_MOD_DELATTR_FN = _FrozenModule.__delattr__
    _FROZEN_MOD_DELATTR_CODE = _FROZEN_MOD_DELATTR_FN.__code__

    _FROZEN_BUILTINS = _FrozenDict(builtins.__dict__)
    _EXPECTED_BUILTINS_ITEMS = tuple(dict.items(_FROZEN_BUILTINS))
    _EXPECTED_BUILTINS_LEN = dict.__len__(_FROZEN_BUILTINS)

    def _freeze_mod(mod, overrides):
        d = dict(mod.__dict__)
        d.update(overrides)
        d["__warningregistry__"] = {}
        fd = _FrozenDict(d)
        for k, v in list(d.items()):
            if isinstance(v, types.FunctionType):
                nf = types.FunctionType(v.__code__, fd, v.__name__, v.__defaults__, v.__closure__)
                if v.__kwdefaults__ is not None:
                    nf.__kwdefaults__ = dict(v.__kwdefaults__)
                dict.__setitem__(fd, k, nf)
        return _FrozenModule(mod.__name__, fd)

    _F_SYS = _FrozenModule("sys", _FrozenDict(sys.__dict__))
    _F_STAT = _freeze_mod(stat, {"__builtins__": _FROZEN_BUILTINS})
    _F_ERRNO = _freeze_mod(errno, {"__builtins__": _FROZEN_BUILTINS})
    _F_GENERICPATH = _freeze_mod(genericpath, {"__builtins__": _FROZEN_BUILTINS, "stat": _F_STAT})
    _F_POSIXPATH = _freeze_mod(
        posixpath,
        {
            "__builtins__": _FROZEN_BUILTINS,
            "sys": _F_SYS,
            "stat": _F_STAT,
            "genericpath": _F_GENERICPATH,
            "errno": _F_ERRNO,
        },
    )
    _F_NTPATH = _freeze_mod(
        ntpath,
        {
            "__builtins__": _FROZEN_BUILTINS,
            "sys": _F_SYS,
            "stat": _F_STAT,
            "genericpath": _F_GENERICPATH,
            "errno": _F_ERRNO,
        },
    )
    _F_OSPATH = _F_NTPATH if os.path is ntpath else (
        _F_POSIXPATH if os.path is posixpath else _freeze_mod(
            os.path,
            {
                "__builtins__": _FROZEN_BUILTINS,
                "sys": _F_SYS,
                "stat": _F_STAT,
                "genericpath": _F_GENERICPATH,
                "errno": _F_ERRNO,
            },
        )
    )
    _F_OS = _freeze_mod(
        os,
        {
            "__builtins__": _FROZEN_BUILTINS,
            "sys": _F_SYS,
            "stat": _F_STAT,
            "path": _F_OSPATH,
            "environ": _FrozenDict(),
            "environb": _FrozenDict(),
        },
    )
    dict.__setitem__(_F_GENERICPATH.__dict__, "os", _F_OS)
    dict.__setitem__(_F_POSIXPATH.__dict__, "os", _F_OS)
    dict.__setitem__(_F_NTPATH.__dict__, "os", _F_OS)
    dict.__setitem__(_F_OSPATH.__dict__, "os", _F_OS)

    _POSIX_PARSER_CFG = (_F_POSIXPATH.join, _F_POSIXPATH.splitroot, _F_POSIXPATH.splitdrive, _F_POSIXPATH.sep, _F_POSIXPATH.altsep)
    _NT_PARSER_CFG = (_F_NTPATH.join, _F_NTPATH.splitroot, _F_NTPATH.splitdrive, _F_NTPATH.sep, _F_NTPATH.altsep)

    _F_OSPATH_JOIN = _F_OSPATH.join
    _F_OSPATH_BASENAME = _F_OSPATH.basename
    _F_OSPATH_DIRNAME = _F_OSPATH.dirname
    _OS_PATH_ISABS = _F_OSPATH.isabs
    _OS_PATH_ABSPATH = _F_OSPATH.abspath
    _OS_PATH_REALPATH = _F_OSPATH.realpath
    _OS_PATH_NORMPATH = _F_OSPATH.normpath
    _OS_PATH_NORMCASE = _F_OSPATH.normcase
    _STAT_S_ISDIR = _F_STAT.S_ISDIR
    _OS_PATHSEP = os.pathsep
    if _IS_WIN:
        import _winapi as _raw_winapi
        _WINAPI_CREATEFILE = _raw_winapi.CreateFile
        _WINAPI_READFILE = _raw_winapi.ReadFile
        _WINAPI_WRITEFILE = _raw_winapi.WriteFile
        _WINAPI_CLOSEHANDLE = _raw_winapi.CloseHandle
        _WINAPI_WAITNAMEDPIPE = getattr(_raw_winapi, "WaitNamedPipe", None)
        _WINAPI_GENERIC_RW = _raw_winapi.GENERIC_READ | _raw_winapi.GENERIC_WRITE
        _WINAPI_OPEN_EXISTING = _raw_winapi.OPEN_EXISTING
    else:
        _WINAPI_CREATEFILE = None
        _WINAPI_READFILE = None
        _WINAPI_WRITEFILE = None
        _WINAPI_CLOSEHANDLE = None
        _WINAPI_WAITNAMEDPIPE = None
        _WINAPI_GENERIC_RW = 0
        _WINAPI_OPEN_EXISTING = 3
    _OS_ENVIRON = os.environ
    _OS_ENVIRON_TYPE = type(os.environ)
    _OS_ENVIRON_DATA = _OBJECT_GETATTR(os.environ, "_data")
    if type(_OS_ENVIRON_DATA) is not dict:
        raise RuntimeError("unexpected os.environ._data type")

    def _setup_env_ci(target_name):
        for _k, _v in dict.items(_OS_ENVIRON_DATA):
            if type(_k) is str and type(_v) is str:
                if _k == target_name or (_IS_WIN and _k.upper() == target_name):
                    return _v
        return None

    _INIT_HOME_DIR = None
    _INIT_USERNAME = _setup_env_ci("USERNAME")
    _INIT_PWD_HOMES = _FrozenDict()
    if _IS_WIN:
        _up = _setup_env_ci("USERPROFILE")
        if _up is not None:
            _INIT_HOME_DIR = _up
        else:
            _hp = _setup_env_ci("HOMEPATH")
            if _hp is not None:
                _hd = _setup_env_ci("HOMEDRIVE") or ""
                _INIT_HOME_DIR = _F_NTPATH.join(_hd, _hp)
    else:
        _INIT_HOME_DIR = _setup_env_ci("HOME")
        try:
            import pwd as _setup_pwd
            _pwd_map = {}
            for _pe in _setup_pwd.getpwall():
                _pn = getattr(_pe, "pw_name", None)
                _pd = getattr(_pe, "pw_dir", None)
                if type(_pn) is str and type(_pd) is str:
                    _pwd_map[_pn] = _pd
            if _INIT_HOME_DIR is None:
                _INIT_HOME_DIR = _setup_pwd.getpwuid(os.getuid()).pw_dir
            _INIT_PWD_HOMES = _FrozenDict(_pwd_map)
        except Exception:
            pass
    _O_RDONLY = getattr(os, "O_RDONLY", 0)
    _O_WRONLY = getattr(os, "O_WRONLY", 1)
    _O_RDWR = getattr(os, "O_RDWR", 2)
    _O_CREAT = getattr(os, "O_CREAT", 0)
    _O_TRUNC = getattr(os, "O_TRUNC", 0)
    _O_APPEND = getattr(os, "O_APPEND", 0)

    _SP_GLOBALS = None
    _POPEN_INIT_CODE = None
    _POPEN_EXEC_CODE = None
    _SUBPROCESS_FILE = None
    _ORIG_LIST2CMDLINE = None
    try:
        import subprocess as _sp
        _SP_GLOBALS = _sp.__dict__
        _POPEN_INIT_CODE = getattr(getattr(_sp.Popen, "__init__", None), "__code__", None)
        _POPEN_EXEC_CODE = getattr(getattr(_sp.Popen, "_execute_child", None), "__code__", None)
        _ORIG_LIST2CMDLINE = getattr(_sp, "list2cmdline", None)
        _sp_file = getattr(_sp, "__file__", None)
        if _sp_file:
            _SUBPROCESS_FILE = _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(_sp_file))
    except Exception:
        _sp = None

    _IMPORTLIB_EXT_GLOBALS = None
    _IMPORTLIB_FILL_CACHE_CODE = None
    _IMPORTLIB_PATH_STAT_CODE = None
    try:
        _imp_ext = sys.modules.get("_frozen_importlib_external")
        if _imp_ext is not None:
            _IMPORTLIB_EXT_GLOBALS = _imp_ext.__dict__
            _ff = getattr(_imp_ext, "FileFinder", None)
            _IMPORTLIB_FILL_CACHE_CODE = getattr(getattr(_ff, "_fill_cache", None), "__code__", None)
            _IMPORTLIB_PATH_STAT_CODE = getattr(getattr(_imp_ext, "_path_stat", None), "__code__", None)
    except Exception:
        pass

    _ZIPIMPORT_GLOBALS = None
    _ZIPIMPORT_READ_DIR_CODE = None
    try:
        _zip_mod = sys.modules.get("zipimport")
        if _zip_mod is not None:
            _ZIPIMPORT_GLOBALS = _zip_mod.__dict__
            _ZIPIMPORT_READ_DIR_CODE = getattr(getattr(_zip_mod, "_read_directory", None), "__code__", None)
    except Exception:
        pass

    _SQLITE_MOD = sqlite3
    _RAW_SQLITE_MOD = _sqlite3
    _ORIG_SQLITE_CONNECT = _sqlite3.connect
    _ORIG_SQLITE_CONN = _sqlite3.Connection
    _ORIG_SQLITE_CURSOR = _sqlite3.Cursor
    _ORIG_SQLITE_ROW = _sqlite3.Row
    _SQLITE_CONVERTERS = _sqlite3.converters
    _EXPECTED_SQLITE_CONVERTERS = tuple(dict.items(_SQLITE_CONVERTERS))
    _SQLITE_ADAPTERS = _sqlite3.adapters
    _EXPECTED_SQLITE_ADAPTERS = tuple(dict.items(_SQLITE_ADAPTERS))
    _SQLITE_OPT_UNICODE = getattr(sqlite3, "OptimizedUnicode", None)
    _SQLITE_LEGACY_TC = getattr(sqlite3, "LEGACY_TRANSACTION_CONTROL", -1)
    _SQLITE_ITERDUMP = sqlite3.dump._iterdump
    _SQLITE_ATTACH = getattr(sqlite3, "SQLITE_ATTACH", 24)
    _SQLITE_FUNCTION = getattr(sqlite3, "SQLITE_FUNCTION", 31)
    _SQLITE_OK = getattr(sqlite3, "SQLITE_OK", 0)
    _SQLITE_DENY = getattr(sqlite3, "SQLITE_DENY", 1)
    _SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION = getattr(_sqlite3, "SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION", 1005)

    _SIGNAL_MOD = signal
    _RAW_SIGNAL_MOD = _signal
    _ORIG_SIGNAL_SIGNAL = _signal.signal
    _ORIG_SIGNAL_GETSIGNAL = _signal.getsignal
    _SIG_DFL = signal.SIG_DFL
    _SIG_IGN = signal.SIG_IGN
    _DEFAULT_INT_HANDLER = signal.default_int_handler
    _F_RAW_SIGNAL = _freeze_mod(
        _signal,
        {
            "__builtins__": _FROZEN_BUILTINS,
            "signal": None,
            "getsignal": None,
        },
    )
    _F_SIGNAL = _freeze_mod(
        signal,
        {
            "__builtins__": _FROZEN_BUILTINS,
            "_signal": _F_RAW_SIGNAL,
            "signal": None,
            "getsignal": None,
        },
    )

    _LIST2CMD_GLOBALS = None
    _GUARDED_LIST2CMDLINE = None
    _GUARDED_LIST2CMD_CODE = None
    _L2C_WARNREG_REF = None
    _EXPECTED_L2C_ITEMS = ()
    _EXPECTED_L2C_LEN = 0
    _EXPECTED_L2C_FUNCS = ()
    _L2C_CODES = ()
    if _SP_GLOBALS is not None and _ORIG_LIST2CMDLINE is not None:
        _l2c_plain = {
            "__builtins__": _FROZEN_BUILTINS,
            "__name__": "__octopus_list2cmdline__",
            "__warningregistry__": {},
            "_TYPE": type,
            "_TYPE_DICT_GET": _TYPE_DICT_GET,
            "_TYPE_MRO_GET": _TYPE_MRO_GET,
            "_MP_ITEMS": _MP_ITEMS,
            "_MISSING": _MISSING,
            "_ORIG_LIST2CMDLINE": _ORIG_LIST2CMDLINE,
            "_EXACT_PATHLIB_TYPES": _EXACT_PATHLIB_TYPES,
            "_PATHLIB_META_MAP": _PATHLIB_META_MAP,
            "_PUREPATH_RAW_PATHS_DESC": _PUREPATH_RAW_PATHS_DESC,
            "_PUREPATH_STR_DESC": _PUREPATH_STR_DESC,
            "_PUREPATH_DRV_DESC": _PUREPATH_DRV_DESC,
            "_PUREPATH_ROOT_DESC": _PUREPATH_ROOT_DESC,
            "_PUREPATH_TAIL_DESC": _PUREPATH_TAIL_DESC,
            "_POSIX_PARSER_CFG": _POSIX_PARSER_CFG,
            "_NT_PARSER_CFG": _NT_PARSER_CFG,
            "_OS_DIRENTRY": _OS_DIRENTRY,
            "_OS_DIRENTRY_FSPATH": _OS_DIRENTRY_FSPATH,
            "_OS_DIRENTRY_PATH_DESC": _OS_DIRENTRY_PATH_DESC,
            "_GUARDED_DIRENTRY_CLS": None,
            "_DIRENTRY_MAP": None,
            "_DICT_GET": _DICT_GET,
            "_EXC_TB_SET": _EXC_TB_SET,
            "_EXC_CAUSE_SET": _EXC_CAUSE_SET,
            "_EXC_CTX_SET": _EXC_CTX_SET,
            "_extract_pathlib_str": None,
        }
        _l2c_src = '''
def _extract_pathlib_str(x, t):
    _meta = None
    for _item in _PATHLIB_META_MAP:
        if t is _item[0]:
            _meta = _item
            break
    if _meta is None:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    _is_posix = _meta[1]
    _exp_attrs = _meta[2]
    for _b in _TYPE_MRO_GET(t):
        _bd = _TYPE_DICT_GET(_b)
        for _k in _bd:
            if _TYPE(_k) is not str:
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    for _aname, _exp_v in _exp_attrs:
        _found = _MISSING
        for _b in _TYPE_MRO_GET(t):
            _bd = _TYPE_DICT_GET(_b)
            for _k, _v in _MP_ITEMS(_bd):
                if _TYPE(_k) is str and _k == _aname:
                    _found = _v
                    break
            if _found is not _MISSING:
                break
        if _found is not _exp_v:
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    if _PUREPATH_RAW_PATHS_DESC is None:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    try:
        _raw_paths = _PUREPATH_RAW_PATHS_DESC.__get__(x)
    except AttributeError:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied") from None
    if _TYPE(_raw_paths) is not list:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    for _el in list.__iter__(_raw_paths):
        if _TYPE(_el) is not str:
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    _p_join, _p_splitroot, _p_splitdrive, _p_sep, _p_altsep = _POSIX_PARSER_CFG if _is_posix else _NT_PARSER_CFG
    _n = list.__len__(_raw_paths)
    if _n == 0:
        _raw_p = ""
    elif _n == 1:
        _raw_p = _raw_paths[0]
    else:
        _raw_p = _p_join(*_raw_paths)
    if _TYPE(_raw_p) is not str:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if not _raw_p:
        _drv, _root, _tail = "", "", []
    else:
        if _p_altsep:
            _raw_p = _raw_p.replace(_p_altsep, _p_sep)
        _drv, _root, _rel = _p_splitroot(_raw_p)
        if not _root and _drv.startswith(_p_sep) and not _drv.endswith(_p_sep):
            _drv_parts = _drv.split(_p_sep)
            if len(_drv_parts) == 4 and _drv_parts[2] not in "?.":
                _root = _p_sep
            elif len(_drv_parts) == 6:
                _root = _p_sep
        _tail = [_seg for _seg in _rel.split(_p_sep) if _seg and _seg != "."]
    if _drv or _root:
        _res = _drv + _root + _p_sep.join(_tail)
    elif _tail and _p_splitdrive(_tail[0])[0]:
        _res = _p_sep.join(["."] + _tail)
    else:
        _res = _p_sep.join(_tail)
    _computed = _res or "."
    if _PUREPATH_STR_DESC is not None:
        try:
            _s_val = _PUREPATH_STR_DESC.__get__(x)
        except AttributeError:
            _s_val = _MISSING
        if _s_val is not _MISSING:
            if _TYPE(_s_val) is not str or _s_val != _computed:
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_DRV_DESC is not None:
        try:
            _d_val = _PUREPATH_DRV_DESC.__get__(x)
        except AttributeError:
            _d_val = _MISSING
        if _d_val is not _MISSING and (_TYPE(_d_val) is not str or _d_val != _drv):
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_ROOT_DESC is not None:
        try:
            _r_val = _PUREPATH_ROOT_DESC.__get__(x)
        except AttributeError:
            _r_val = _MISSING
        if _r_val is not _MISSING and (_TYPE(_r_val) is not str or _r_val != _root):
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_TAIL_DESC is not None:
        try:
            _t_val = _PUREPATH_TAIL_DESC.__get__(x)
        except AttributeError:
            _t_val = _MISSING
        if _t_val is not _MISSING:
            if _TYPE(_t_val) is not list or list.__len__(_t_val) != len(_tail):
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
            for _idx, _tv in enumerate(list.__iter__(_t_val)):
                if _TYPE(_tv) is not str or _tv != _tail[_idx]:
                    raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    return _computed

def _guarded_list2cmdline(seq):
    try:
        _seq_t = _TYPE(seq)
        if _seq_t is not list and _seq_t is not tuple:
            raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
        it = list.__iter__(seq) if _seq_t is list else tuple.__iter__(seq)
        clean = []
        for item in it:
            t = _TYPE(item)
            if t is str or t is bytes:
                clean.append(item)
            elif _OS_DIRENTRY is not None and t is _OS_DIRENTRY:
                if t.__fspath__ is not _OS_DIRENTRY_FSPATH or t.path is not _OS_DIRENTRY_PATH_DESC:
                    raise PermissionError("blocked_by_octopus_policy: tampered DirEntry descriptor denied")
                v = _OS_DIRENTRY_FSPATH(item)
                _vt = _TYPE(v)
                if _vt is not str and _vt is not bytes:
                    raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
                clean.append(v)
            elif _GUARDED_DIRENTRY_CLS is not None and t is _GUARDED_DIRENTRY_CLS:
                _de = _DICT_GET(_DIRENTRY_MAP, id(item)) if _DIRENTRY_MAP is not None else None
                if _de is None or _de[0]() is not item:
                    raise PermissionError("blocked_by_octopus_policy: invalid DirEntry object")
                v = _de[3]
                _vt = _TYPE(v)
                if _vt is not str and _vt is not bytes:
                    raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
                clean.append(v)
            elif any(t is _pt for _pt in _EXACT_PATHLIB_TYPES):
                v = _extract_pathlib_str(item, t)
                clean.append(v)
            else:
                raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
        return _ORIG_LIST2CMDLINE(clean)
    except BaseException as exc:
        seen = set()
        stack = [exc]
        while stack:
            cur = stack.pop()
            if cur is None or id(cur) in seen:
                continue
            seen.add(id(cur))
            try:
                _EXC_TB_SET(cur, None)
                nxt_cause = cur.__cause__
                nxt_ctx = cur.__context__
                _EXC_CAUSE_SET(cur, None)
                _EXC_CTX_SET(cur, None)
            except Exception:
                continue
            if nxt_cause is not None and id(nxt_cause) not in seen:
                stack.append(nxt_cause)
            if nxt_ctx is not None and id(nxt_ctx) not in seen:
                stack.append(nxt_ctx)
        raise exc from None
'''
        exec(compile(_l2c_src, "<octopus_list2cmdline>", "exec"), _l2c_plain)
        _LIST2CMD_GLOBALS = _FrozenDict(_l2c_plain)
        _L2C_WARNREG_REF = dict.__getitem__(_LIST2CMD_GLOBALS, "__warningregistry__")
        _l2c_ext_orig = _l2c_plain["_extract_pathlib_str"]
        _l2c_ext_fn = types.FunctionType(
            _l2c_ext_orig.__code__,
            _LIST2CMD_GLOBALS,
            "_extract_pathlib_str",
            None,
            None,
        )
        dict.__setitem__(_LIST2CMD_GLOBALS, "_extract_pathlib_str", _l2c_ext_fn)
        _l2c_fn = _l2c_plain["_guarded_list2cmdline"]
        _GUARDED_LIST2CMD_CODE = _l2c_fn.__code__
        _GUARDED_LIST2CMDLINE = types.FunctionType(
            _GUARDED_LIST2CMD_CODE,
            _LIST2CMD_GLOBALS,
            "_guarded_list2cmdline",
            None,
            None,
        )
        dict.__setitem__(_LIST2CMD_GLOBALS, "_guarded_list2cmdline", _GUARDED_LIST2CMDLINE)
        _EXPECTED_L2C_ITEMS = tuple(
            (k, v) for k, v in dict.items(_LIST2CMD_GLOBALS) if k != "__warningregistry__"
        )
        _EXPECTED_L2C_LEN = dict.__len__(_LIST2CMD_GLOBALS)
        _EXPECTED_L2C_FUNCS = (
            (_l2c_ext_fn, _l2c_ext_fn.__code__, _l2c_ext_fn.__defaults__, _l2c_ext_fn.__kwdefaults__),
        )
        _L2C_CODES = _collect_nested_codes((_GUARDED_LIST2CMD_CODE, _l2c_ext_fn.__code__))
        _sp.list2cmdline = _GUARDED_LIST2CMDLINE

    _gate_tl = _THREADING_LOCAL()
    _gate_getattr = getattr
    _gate_setattr = setattr
    _gate_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_gate__",
        "__warningregistry__": {},
        "_GATE_TL": _gate_tl,
        "_GATE_GETATTR": _gate_getattr,
        "_GATE_SETATTR": _gate_setattr,
    }
    _gate_src = '''
def _octopus_raise_gate(event, args):
    exc = _GATE_GETATTR(_GATE_TL, "exc", None)
    if exc is not None:
        _GATE_SETATTR(_GATE_TL, "exc", None)
        _tok = _GATE_GETATTR(_GATE_TL, "tok", None)
        _GATE_SETATTR(_GATE_TL, "disarmed", _tok)
        del event, args, _tok
        raise exc from None
'''
    exec(compile(_gate_src, "<octopus_gate>", "exec"), _gate_plain)
    _GATE_GLOBALS = _FrozenDict(_gate_plain)
    _GATE_WARNREG_REF = dict.__getitem__(_GATE_GLOBALS, "__warningregistry__")
    _gate_orig_fn = _gate_plain["_octopus_raise_gate"]
    _GATE_CODE = _gate_orig_fn.__code__
    _GATE_HOOK = types.FunctionType(_GATE_CODE, _GATE_GLOBALS, "_octopus_raise_gate", None, None)
    dict.__setitem__(_GATE_GLOBALS, "_octopus_raise_gate", _GATE_HOOK)
    _EXPECTED_GATE_ITEMS = tuple(
        (k, v) for k, v in dict.items(_GATE_GLOBALS) if k not in ("_GATE_TL", "__warningregistry__")
    )
    _EXPECTED_GATE_LEN = dict.__len__(_GATE_GLOBALS)

    _addhook_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_addaudithook__",
        "__warningregistry__": {},
        "_SYS_AUDIT": _SYS_AUDIT,
    }
    exec(
        compile("def _guarded_addaudithook(hook):\n    _SYS_AUDIT('sys.addaudithook')\n", "<octopus_addhook>", "exec"),
        _addhook_plain,
    )
    _ADDHOOK_GLOBALS = _FrozenDict(_addhook_plain)
    _ADDHOOK_WARNREG_REF = dict.__getitem__(_ADDHOOK_GLOBALS, "__warningregistry__")
    _addhook_orig = _addhook_plain["_guarded_addaudithook"]
    _ADDHOOK_CODE = _addhook_orig.__code__
    _GUARDED_ADDAUDITHOOK = types.FunctionType(_ADDHOOK_CODE, _ADDHOOK_GLOBALS, "_guarded_addaudithook", None, None)
    dict.__setitem__(_ADDHOOK_GLOBALS, "_guarded_addaudithook", _GUARDED_ADDAUDITHOOK)
    _EXPECTED_ADDHOOK_ITEMS = tuple(
        (k, v) for k, v in dict.items(_ADDHOOK_GLOBALS) if k != "__warningregistry__"
    )
    _EXPECTED_ADDHOOK_LEN = dict.__len__(_ADDHOOK_GLOBALS)

    _SQLITE_CONNECT_POS_NAMES = (
        "database",
        "timeout",
        "detect_types",
        "isolation_level",
        "check_same_thread",
        "factory",
        "cached_statements",
        "uri",
    )

    _sq_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_sqlite__",
        "__warningregistry__": {},
        "_TYPE": type,
        "_TYPE_MRO_GET": type.__dict__["__mro__"].__get__,
        "_SYS_AUDIT": _SYS_AUDIT,
        "_SYS_IS_FINALIZING": _SYS_IS_FINALIZING,
        "_LIST_APPEND": _LIST_APPEND,
        "_SQLITE_GC_QUEUE": _sqlite_gc_queue,
        "_SQLITE_ITERDUMP": _SQLITE_ITERDUMP,
        "_SQLITE_CONNECT_POS_NAMES": _SQLITE_CONNECT_POS_NAMES,
        "_OP_INDEX": _OP_INDEX,
        "_ORIG_SQLITE_ROW": _ORIG_SQLITE_ROW,
        "_SQLITE_OPT_UNICODE": _SQLITE_OPT_UNICODE,
        "_SQLITE_LEGACY_TC": _SQLITE_LEGACY_TC,
        "_OBJECT_SETATTR": object.__setattr__,
        "_OBJECT_NEW": _OBJECT_NEW,
        "_EXC_TB_SET": _EXC_TB_SET,
        "_EXC_CAUSE_SET": _EXC_CAUSE_SET,
        "_EXC_CTX_SET": _EXC_CTX_SET,
        "_SQLITE_WRAPPER_CLS": None,
        "_SQLITE_CURSOR_CLS": None,
        "_SQLITE_METHOD_CLS": None,
        "_SQLITE_CLEANUP_CLS": None,
        "_CONN_RF_SLOT": None,
        "_CUR_RF_SLOT": None,
        "_has_mro_base": None,
        "_strip_sq_exc": None,
        "_coerce_sqlite_connect_args": None,
        "_sanitize_sq_param": None,
        "_sanitize_sq_params": None,
        "_sanitize_sq_exec_args": None,
        "_sanitize_sq_call_val": None,
        "_guarded_sqlite_connect": None,
        "_guarded_sqlite_denied_reg": None,
    }
    _sq_src = '''
def _has_mro_base(obj, cls):
    for _b in _TYPE_MRO_GET(_TYPE(obj)):
        if _b is cls:
            return True
    return False

def _strip_sq_exc(exc):
    seen = set()
    stack = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        try:
            _EXC_TB_SET(cur, None)
            nxt_cause = cur.__cause__
            nxt_ctx = cur.__context__
            _EXC_CAUSE_SET(cur, None)
            _EXC_CTX_SET(cur, None)
        except Exception:
            continue
        if nxt_cause is not None and id(nxt_cause) not in seen:
            stack.append(nxt_cause)
        if nxt_ctx is not None and id(nxt_ctx) not in seen:
            stack.append(nxt_ctx)

def _coerce_sqlite_connect_args(args, kwargs, strip_factory=False):
    if len(args) > 8:
        raise TypeError("connect() takes at most 8 positional arguments (" + str(len(args)) + " given)")
    if len(args) == 0 and "database" not in kwargs:
        raise TypeError("connect() missing required argument 'database' (pos 1)")
    clean_args = list(args)
    clean_kw = {}
    for k, v in dict.items(kwargs):
        if type(k) is not str:
            raise TypeError("keywords must be strings")
        if k not in _SQLITE_CONNECT_POS_NAMES and k != "autocommit":
            raise TypeError("connect() got an unexpected keyword argument '" + k + "'")
        clean_kw[k] = v
    for idx in range(len(clean_args)):
        pname = _SQLITE_CONNECT_POS_NAMES[idx]
        if pname in clean_kw:
            raise TypeError("connect() got multiple values for argument '" + pname + "'")

    def _c_timeout(val):
        if _has_mro_base(val, str) or _has_mro_base(val, bytes):
            raise TypeError("must be real number, not " + _TYPE(val).__name__)
        _vt = _TYPE(val)
        if _vt is int or _vt is float:
            return val
        if _has_mro_base(val, float):
            return float.__float__(val)
        fval = float(val)
        if _TYPE(fval) is float:
            return fval
        if _has_mro_base(fval, float):
            return float.__float__(fval)
        raise TypeError("must be real number, not " + _TYPE(val).__name__)

    def _c_int_idx(val):
        if _TYPE(val) is int:
            return val
        iv = _OP_INDEX(val)
        if _TYPE(iv) is int:
            return iv
        if _has_mro_base(iv, int):
            return int.__index__(iv)
        return int(iv)

    def _c_iso(val):
        if val is None:
            return None
        if not _has_mro_base(val, str):
            raise TypeError("isolation_level must be str or None")
        if _TYPE(val) is str:
            return val
        return str.__str__(val)

    def _c_bool(val):
        if _TYPE(val) is bool:
            return val
        return bool(val)

    def _c_autocommit(val):
        if val is True or val is False:
            return val
        if _has_mro_base(val, int):
            return int.__index__(val)
        raise ValueError("autocommit must be True, False, or sqlite3.LEGACY_TRANSACTION_CONTROL")

    if len(clean_args) > 1:
        clean_args[1] = _c_timeout(clean_args[1])
    elif "timeout" in clean_kw:
        clean_kw["timeout"] = _c_timeout(clean_kw["timeout"])

    if len(clean_args) > 2:
        clean_args[2] = _c_int_idx(clean_args[2])
    elif "detect_types" in clean_kw:
        clean_kw["detect_types"] = _c_int_idx(clean_kw["detect_types"])

    if len(clean_args) > 3:
        clean_args[3] = _c_iso(clean_args[3])
    elif "isolation_level" in clean_kw:
        clean_kw["isolation_level"] = _c_iso(clean_kw["isolation_level"])

    if len(clean_args) > 4:
        clean_args[4] = _c_bool(clean_args[4])
    elif "check_same_thread" in clean_kw:
        clean_kw["check_same_thread"] = _c_bool(clean_kw["check_same_thread"])

    if strip_factory:
        if len(clean_args) > 5:
            clean_args[5] = _SQLITE_WRAPPER_CLS
        clean_kw.pop("factory", None)

    if len(clean_args) > 6:
        clean_args[6] = _c_int_idx(clean_args[6])
    elif "cached_statements" in clean_kw:
        clean_kw["cached_statements"] = _c_int_idx(clean_kw["cached_statements"])

    if len(clean_args) > 7:
        clean_args[7] = _c_bool(clean_args[7])
    elif "uri" in clean_kw:
        clean_kw["uri"] = _c_bool(clean_kw["uri"])

    if "autocommit" in clean_kw:
        clean_kw["autocommit"] = _c_autocommit(clean_kw["autocommit"])

    return tuple(clean_args), clean_kw

def _sanitize_sq_param(v):
    if v is None:
        return None
    t = _TYPE(v)
    if t is bool or t is int or t is float or t is str or t is bytes or t is bytearray:
        return v
    if t is memoryview:
        return bytes(v)
    if _has_mro_base(v, bool):
        return bool(v)
    if _has_mro_base(v, int):
        return int.__index__(v)
    if _has_mro_base(v, float):
        return float.__float__(v)
    if _has_mro_base(v, str):
        return str.__str__(v)
    if _has_mro_base(v, bytes) or _has_mro_base(v, bytearray):
        return bytes(v)
    raise PermissionError("blocked_by_octopus_policy: non-primitive sqlite3 parameter denied")

def _sanitize_sq_params(params):
    if _has_mro_base(params, dict):
        out = {}
        it = dict.items(params) if _TYPE(params) is dict else params.items()
        for k, v in it:
            if _TYPE(k) is str:
                sk = k
            elif _has_mro_base(k, str):
                sk = str.__str__(k)
            else:
                raise PermissionError("blocked_by_octopus_policy: non-string sqlite3 parameter key denied")
            out[sk] = _sanitize_sq_param(v)
        return out
    if hasattr(params, "keys") and hasattr(params, "__getitem__"):
        out = {}
        for k in params.keys():
            if _TYPE(k) is str:
                sk = k
            elif _has_mro_base(k, str):
                sk = str.__str__(k)
            else:
                raise PermissionError("blocked_by_octopus_policy: non-string sqlite3 parameter key denied")
            out[sk] = _sanitize_sq_param(params[k])
        return out
    return tuple(_sanitize_sq_param(x) for x in params)

def _sanitize_sq_exec_args(mname, args, kwargs):
    if kwargs:
        raise TypeError(mname + "() takes no keyword arguments")
    if mname == "executescript":
        if len(args) != 1:
            raise TypeError("executescript() takes exactly 1 argument (" + str(len(args)) + " given)")
        sql = args[0]
        if _TYPE(sql) is str:
            return (sql,)
        if _has_mro_base(sql, str):
            return (str.__str__(sql),)
        raise TypeError("must be str, not " + _TYPE(sql).__name__)
    if mname == "execute":
        if not (1 <= len(args) <= 2):
            raise TypeError("execute() takes 1 or 2 arguments (" + str(len(args)) + " given)")
        sql = args[0]
        if _TYPE(sql) is not str:
            if _has_mro_base(sql, str):
                sql = str.__str__(sql)
            else:
                raise TypeError("must be str, not " + _TYPE(sql).__name__)
        if len(args) == 1:
            return (sql,)
        return (sql, _sanitize_sq_params(args[1]))
    if len(args) != 2:
        raise TypeError("executemany() takes exactly 2 arguments (" + str(len(args)) + " given)")
    sql = args[0]
    if _TYPE(sql) is not str:
        if _has_mro_base(sql, str):
            sql = str.__str__(sql)
        else:
            raise TypeError("must be str, not " + _TYPE(sql).__name__)
    seq = [_sanitize_sq_params(item) for item in args[1]]
    return (sql, seq)

def _sanitize_sq_call_val(v):
    if v is None:
        return None
    t = _TYPE(v)
    if t is bool or t is int or t is float or t is str or t is bytes or t is bytearray:
        return v
    if t is memoryview:
        return bytes(v)
    if _has_mro_base(v, bool):
        return bool(v)
    if _has_mro_base(v, int):
        return int.__index__(v)
    if _has_mro_base(v, float):
        return float.__float__(v)
    if _has_mro_base(v, str):
        return str.__str__(v)
    if _has_mro_base(v, bytes) or _has_mro_base(v, bytearray):
        return bytes(v)
    if hasattr(t, "__index__"):
        iv = _OP_INDEX(v)
        return iv if _TYPE(iv) is int else (int.__index__(iv) if _has_mro_base(iv, int) else int(iv))
    raise PermissionError("blocked_by_octopus_policy: non-primitive sqlite3 method argument denied")

class _SqWeakrefCleanup:
    __slots__ = ("_op", "_id1", "_id2")

    def __new__(cls, op, id1, id2=0):
        if cls is not _SQLITE_CLEANUP_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable sqlite cleanup")
        return _OBJECT_NEW(cls)

    def __init__(self, op, id1, id2=0):
        _OBJECT_SETATTR(self, "_op", op)
        _OBJECT_SETATTR(self, "_id1", id1)
        _OBJECT_SETATTR(self, "_id2", id2)

    def __call__(self, wr):
        if not _SYS_IS_FINALIZING():
            try:
                _LIST_APPEND(_SQLITE_GC_QUEUE, (self._op, self._id1, self._id2))
            except BaseException:
                pass

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable sqlite cleanup")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable sqlite cleanup")

class _GuardedSQLiteMethod:
    __slots__ = ("_obj", "_name", "_op")

    def __new__(cls, obj, name, op):
        if cls is not _SQLITE_METHOD_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable sqlite method")
        return _OBJECT_NEW(cls)

    def __init__(self, obj, name, op):
        _OBJECT_SETATTR(self, "_obj", obj)
        _OBJECT_SETATTR(self, "_name", name)
        _OBJECT_SETATTR(self, "_op", op)

    def __call__(self, *args, **kwargs):
        try:
            clean_args = tuple(_sanitize_sq_call_val(a) for a in args)
            clean_kw = {}
            for k, v in dict.items(kwargs):
                if type(k) is not str:
                    raise TypeError("keywords must be strings")
                clean_kw[k] = _sanitize_sq_call_val(v)
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", self._op, self._obj, self._name, clean_args, clean_kw, box)
            return box[0]
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable sqlite method")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable sqlite method")

    def __repr__(self):
        return "<GuardedSQLiteMethod " + self._name + ">"

class _GuardedSQLiteCursor:
    __slots__ = ("__weakref__", "_oct_rf")

    def __new__(cls, *args, **kwargs):
        return _OBJECT_NEW(cls)

    def __init__(self, connection):
        try:
            if not _has_mro_base(connection, _SQLITE_WRAPPER_CLS):
                raise TypeError("connection must be sqlite3.Connection")
            _CUR_RF_SLOT.__set__(self, _CONN_RF_SLOT.__get__(connection))
            _SYS_AUDIT("octopus.sqlite_op", "cursor_init", self, connection)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    @property
    def connection(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "cursor_connection", self, box)
            return box[0]
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    @property
    def row_factory(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "cursor_get_rf", self, box)
            return _CUR_RF_SLOT.__get__(self)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    @row_factory.setter
    def row_factory(self, value):
        try:
            _SYS_AUDIT("octopus.sqlite_op", "cursor_set_rf", self, value is _ORIG_SQLITE_ROW)
            _CUR_RF_SLOT.__set__(self, value)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def execute(self, *args, **kwargs):
        try:
            clean_args = _sanitize_sq_exec_args("execute", args, kwargs)
            _SYS_AUDIT("octopus.sqlite_op", "cursor_exec", self, "execute", clean_args, {})
            return self
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def executemany(self, *args, **kwargs):
        try:
            clean_args = _sanitize_sq_exec_args("executemany", args, kwargs)
            _SYS_AUDIT("octopus.sqlite_op", "cursor_exec", self, "executemany", clean_args, {})
            return self
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def executescript(self, *args, **kwargs):
        try:
            clean_args = _sanitize_sq_exec_args("executescript", args, kwargs)
            _SYS_AUDIT("octopus.sqlite_op", "cursor_exec", self, "executescript", clean_args, {})
            return self
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def fetchone(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "cursor_call", self, "fetchone", (), {}, box)
            row = box[0]
            if row is None:
                return None
            rf = _CUR_RF_SLOT.__get__(self)
            if rf is not None and rf is not _ORIG_SQLITE_ROW:
                return rf(self, row)
            return row
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def fetchmany(self, *args, **kwargs):
        try:
            if kwargs:
                for _k in dict.keys(kwargs):
                    if _TYPE(_k) is not str:
                        raise TypeError("keywords must be strings")
                if len(kwargs) > 1 or "size" not in kwargs or args:
                    raise TypeError("fetchmany() got unexpected keyword arguments")
                clean_args = (int(_OP_INDEX(kwargs["size"])),)
            elif args:
                if len(args) > 1:
                    raise TypeError("fetchmany() takes at most 1 positional argument (" + str(len(args)) + " given)")
                clean_args = (int(_OP_INDEX(args[0])),)
            else:
                clean_args = ()
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "cursor_call", self, "fetchmany", clean_args, {}, box)
            rows = box[0]
            rf = _CUR_RF_SLOT.__get__(self)
            if rf is not None and rf is not _ORIG_SQLITE_ROW:
                return [rf(self, r) for r in rows]
            return rows
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def fetchall(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "cursor_call", self, "fetchall", (), {}, box)
            rows = box[0]
            rf = _CUR_RF_SLOT.__get__(self)
            if rf is not None and rf is not _ORIG_SQLITE_ROW:
                return [rf(self, r) for r in rows]
            return rows
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __iter__(self):
        return self

    def __next__(self):
        try:
            box = [False, None]
            _SYS_AUDIT("octopus.sqlite_op", "cursor_next", self, box)
            if not box[0]:
                raise StopIteration
            row = box[1]
            rf = _CUR_RF_SLOT.__get__(self)
            if rf is not None and rf is not _ORIG_SQLITE_ROW:
                return rf(self, row)
            return row
        except StopIteration:
            raise
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __getattr__(self, name):
        try:
            if _TYPE(name) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
            box = [False, None]
            _SYS_AUDIT("octopus.sqlite_op", "cursor_getattr", self, name, box)
            if box[0]:
                return _SQLITE_METHOD_CLS(self, name, "cursor_call")
            return box[1]
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __setattr__(self, name, value):
        try:
            if _TYPE(name) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
            if name == "row_factory":
                _SYS_AUDIT("octopus.sqlite_op", "cursor_set_rf", self, value is _ORIG_SQLITE_ROW)
                _CUR_RF_SLOT.__set__(self, value)
                return
            if name == "arraysize":
                clean_sz = int(_OP_INDEX(value))
                _SYS_AUDIT("octopus.sqlite_op", "cursor_setattr", self, name, clean_sz)
                return
            if name in ("_oct_rf", "connection", "execute", "executemany", "executescript", "fetchone", "fetchmany", "fetchall", "__iter__", "__next__"):
                raise PermissionError("blocked_by_octopus_policy: sqlite3 cursor attribute cannot be modified")
            _OBJECT_SETATTR(self, name, value)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __delattr__(self, name):
        try:
            if _TYPE(name) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
            if name in ("_oct_rf", "connection", "row_factory", "arraysize", "execute", "executemany", "executescript", "fetchone", "fetchmany", "fetchall", "__iter__", "__next__"):
                raise PermissionError("blocked_by_octopus_policy: sqlite3 cursor attribute cannot be deleted")
            object.__delattr__(self, name)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

class _GuardedSQLiteConnection:
    __slots__ = ("__weakref__", "_oct_rf")

    def __new__(cls, *args, **kwargs):
        return _OBJECT_NEW(cls)

    def __init__(self, *args, **kwargs):
        try:
            _CONN_RF_SLOT.__set__(self, None)
            clean_args, clean_kw = _coerce_sqlite_connect_args(args, kwargs, strip_factory=True)
            _SYS_AUDIT("octopus.sqlite_op", "conn_init", self, clean_args, clean_kw)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def cursor(self, factory=None):
        try:
            if factory is None or factory is _SQLITE_CURSOR_CLS:
                box = [None]
                _SYS_AUDIT("octopus.sqlite_op", "conn_cursor", self, box)
                cur_w = box[0]
                _CUR_RF_SLOT.__set__(cur_w, _CONN_RF_SLOT.__get__(self))
                return cur_w
            if _has_mro_base(factory, type) and any(_b is _SQLITE_CURSOR_CLS for _b in _TYPE_MRO_GET(factory)):
                return factory(self)
            raise TypeError("factory must be subclass of Cursor")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def execute(self, *args, **kwargs):
        try:
            clean_args = _sanitize_sq_exec_args("execute", args, kwargs)
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "conn_exec", self, "execute", clean_args, {}, box)
            cur_w = box[0]
            _CUR_RF_SLOT.__set__(cur_w, _CONN_RF_SLOT.__get__(self))
            return cur_w
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def executemany(self, *args, **kwargs):
        try:
            clean_args = _sanitize_sq_exec_args("executemany", args, kwargs)
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "conn_exec", self, "executemany", clean_args, {}, box)
            cur_w = box[0]
            _CUR_RF_SLOT.__set__(cur_w, _CONN_RF_SLOT.__get__(self))
            return cur_w
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def executescript(self, *args, **kwargs):
        try:
            clean_args = _sanitize_sq_exec_args("executescript", args, kwargs)
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "conn_exec", self, "executescript", clean_args, {}, box)
            cur_w = box[0]
            _CUR_RF_SLOT.__set__(cur_w, _CONN_RF_SLOT.__get__(self))
            return cur_w
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    @property
    def row_factory(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "conn_get_rf", self, box)
            return _CONN_RF_SLOT.__get__(self)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    @row_factory.setter
    def row_factory(self, value):
        try:
            _SYS_AUDIT("octopus.sqlite_op", "conn_set_rf", self, value is _ORIG_SQLITE_ROW)
            _CONN_RF_SLOT.__set__(self, value)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def iterdump(self, *, filter=None):
        try:
            _SYS_AUDIT("octopus.sqlite_op", "conn_check_open", self)
            return _SQLITE_ITERDUMP(self, filter=filter)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def create_function(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 create_function denied")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def create_aggregate(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 create_aggregate denied")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def create_window_function(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 create_window_function denied")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def create_collation(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 create_collation denied")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def set_progress_handler(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 set_progress_handler denied")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def set_trace_callback(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 set_trace_callback denied")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def set_authorizer(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 set_authorizer cannot be modified")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def setconfig(self, op, enable=True, /):
        try:
            clean_op = int(_OP_INDEX(op))
            clean_en = bool(enable)
            box = [None]
            _SYS_AUDIT("octopus.sqlite_op", "conn_setconfig", self, clean_op, clean_en, box)
            return box[0]
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def enable_load_extension(self, enabled, /):
        try:
            clean_en = bool(enabled)
            _SYS_AUDIT("octopus.sqlite_op", "conn_enable_load_ext", self, clean_en)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def load_extension(self, *args, **kwargs):
        try:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 load_extension denied")
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def backup(self, target, *, pages=-1, progress=None, name="main", sleep=0.25):
        try:
            if not _has_mro_base(target, _SQLITE_WRAPPER_CLS):
                raise TypeError("target must be sqlite3.Connection")
            if progress is not None:
                raise PermissionError("blocked_by_octopus_policy: sqlite3 backup progress callback denied")
            clean_pages = int(_OP_INDEX(pages))
            if _has_mro_base(sleep, str) or _has_mro_base(sleep, bytes):
                raise TypeError("must be real number, not " + _TYPE(sleep).__name__)
            clean_sleep = float(sleep)
            if _TYPE(name) is str:
                clean_name = name
            elif _has_mro_base(name, str):
                clean_name = str.__str__(name)
            else:
                raise TypeError("name must be str")
            _SYS_AUDIT(
                "octopus.sqlite_op",
                "conn_backup",
                self,
                target,
                (),
                {"pages": clean_pages, "progress": None, "name": clean_name, "sleep": clean_sleep},
            )
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __enter__(self):
        try:
            _SYS_AUDIT("octopus.sqlite_op", "conn_enter", self)
            return self
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __exit__(self, *exc):
        try:
            box = [False]
            _SYS_AUDIT("octopus.sqlite_op", "conn_exit", self, exc, box)
            return box[0]
        except BaseException as e:
            _strip_sq_exc(e)
            raise e from None

    def __getattr__(self, name):
        try:
            if _TYPE(name) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
            if name in (
                "set_authorizer", "load_extension",
                "create_function", "create_aggregate", "create_window_function",
                "create_collation", "set_progress_handler", "set_trace_callback",
            ):
                raise PermissionError("blocked_by_octopus_policy: sqlite3 " + name + " cannot be accessed")
            box = [False, None]
            _SYS_AUDIT("octopus.sqlite_op", "conn_getattr", self, name, box)
            if box[0]:
                return _SQLITE_METHOD_CLS(self, name, "conn_call")
            return box[1]
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __setattr__(self, name, value):
        try:
            if _TYPE(name) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
            if name in (
                "_oct_rf",
                "set_authorizer", "load_extension", "enable_load_extension",
                "create_function", "create_aggregate", "create_window_function",
                "create_collation", "set_progress_handler", "set_trace_callback",
                "setconfig", "cursor", "execute", "executemany", "executescript",
                "backup", "iterdump",
            ):
                raise PermissionError("blocked_by_octopus_policy: sqlite3 attribute cannot be modified")
            if name == "row_factory":
                _SYS_AUDIT("octopus.sqlite_op", "conn_set_rf", self, value is _ORIG_SQLITE_ROW)
                _CONN_RF_SLOT.__set__(self, value)
                return
            if name == "text_factory":
                if not (
                    value is None
                    or value is str
                    or value is bytes
                    or value is bytearray
                    or (_SQLITE_OPT_UNICODE is not None and value is _SQLITE_OPT_UNICODE)
                ):
                    raise PermissionError("blocked_by_octopus_policy: sqlite3 custom text_factory denied")
                _SYS_AUDIT("octopus.sqlite_op", "conn_setattr", self, name, value)
                return
            if name == "isolation_level":
                if value is not None:
                    if not _has_mro_base(value, str):
                        raise TypeError("isolation_level must be str or None")
                    if _TYPE(value) is not str:
                        value = str.__str__(value)
                _SYS_AUDIT("octopus.sqlite_op", "conn_setattr", self, name, value)
                return
            if name == "autocommit":
                if value is True or value is False:
                    pass
                elif _has_mro_base(value, int):
                    value = int.__index__(value)
                else:
                    raise ValueError("autocommit must be True, False, or sqlite3.LEGACY_TRANSACTION_CONTROL")
                _SYS_AUDIT("octopus.sqlite_op", "conn_setattr", self, name, value)
                return
            _OBJECT_SETATTR(self, name, value)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

    def __delattr__(self, name):
        try:
            if _TYPE(name) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
            if name in (
                "_oct_rf",
                "set_authorizer", "load_extension", "enable_load_extension",
                "create_function", "create_aggregate", "create_window_function",
                "create_collation", "set_progress_handler", "set_trace_callback",
                "setconfig", "cursor", "execute", "executemany", "executescript",
                "backup", "iterdump", "row_factory", "text_factory",
                "isolation_level", "autocommit",
            ):
                raise PermissionError("blocked_by_octopus_policy: sqlite3 attribute cannot be deleted")
            object.__delattr__(self, name)
        except BaseException as exc:
            _strip_sq_exc(exc)
            raise exc from None

def _guarded_sqlite_connect(*args, **kwargs):
    try:
        clean_args, clean_kw = _coerce_sqlite_connect_args(args, kwargs, strip_factory=False)
        fac = None
        if len(clean_args) > 5:
            fac = clean_args[5]
            c_list = list(clean_args)
            c_list[5] = _SQLITE_WRAPPER_CLS
            clean_args = tuple(c_list)
        elif "factory" in clean_kw:
            fac = clean_kw.pop("factory")
        if fac is None or fac is _SQLITE_WRAPPER_CLS:
            return _SQLITE_WRAPPER_CLS(*clean_args, **clean_kw)
        if _has_mro_base(fac, type) and any(_b is _SQLITE_WRAPPER_CLS for _b in _TYPE_MRO_GET(fac)):
            return fac(*clean_args, **clean_kw)
        raise TypeError("factory must be subclass of Connection")
    except BaseException as exc:
        _strip_sq_exc(exc)
        raise exc from None

def _guarded_sqlite_denied_reg(*args, **kwargs):
    try:
        raise PermissionError("blocked_by_octopus_policy: sqlite3 adapter/converter registration denied")
    except BaseException as exc:
        _strip_sq_exc(exc)
        raise exc from None
'''
    exec(compile(_sq_src, "<octopus_sqlite>", "exec"), _sq_plain)
    _SQLITE_GLOBALS = _FrozenDict(_sq_plain)
    _SQLITE_WARNREG_REF = dict.__getitem__(_SQLITE_GLOBALS, "__warningregistry__")
    _SQLITE_WRAPPER_CLS = _sq_plain["_GuardedSQLiteConnection"]
    _SQLITE_CURSOR_CLS = _sq_plain["_GuardedSQLiteCursor"]
    _SQLITE_METHOD_CLS = _sq_plain["_GuardedSQLiteMethod"]
    _SQLITE_CLEANUP_CLS = _sq_plain["_SqWeakrefCleanup"]
    _CONN_RF_SLOT = _SQLITE_WRAPPER_CLS.__dict__["_oct_rf"]
    _CUR_RF_SLOT = _SQLITE_CURSOR_CLS.__dict__["_oct_rf"]

    def _rebind_sq_fn(fn):
        nf = types.FunctionType(fn.__code__, _SQLITE_GLOBALS, fn.__name__, fn.__defaults__, None)
        if fn.__kwdefaults__ is not None:
            nf.__kwdefaults__ = dict(fn.__kwdefaults__)
        return nf

    _expected_sqlite_funcs = []
    _expected_sqlite_cls_attrs = [
        (_SQLITE_WRAPPER_CLS, "_oct_rf", _CONN_RF_SLOT),
        (_SQLITE_CURSOR_CLS, "_oct_rf", _CUR_RF_SLOT),
    ]
    _sqlite_op_codes = []

    for _hname in (
        "_has_mro_base",
        "_strip_sq_exc",
        "_coerce_sqlite_connect_args",
        "_sanitize_sq_param",
        "_sanitize_sq_params",
        "_sanitize_sq_exec_args",
        "_sanitize_sq_call_val",
    ):
        _hfn = _rebind_sq_fn(_sq_plain[_hname])
        dict.__setitem__(_SQLITE_GLOBALS, _hname, _hfn)
        _expected_sqlite_funcs.append((_hfn, _hfn.__code__, _hfn.__defaults__, _hfn.__kwdefaults__))

    for _scls in (_SQLITE_CLEANUP_CLS, _SQLITE_METHOD_CLS, _SQLITE_CURSOR_CLS, _SQLITE_WRAPPER_CLS):
        _snew_sm = _scls.__dict__["__new__"]
        _snew_fn = _rebind_sq_fn(_snew_sm.__func__)
        _snew_bound = staticmethod(_snew_fn)
        setattr(_scls, "__new__", _snew_bound)
        _expected_sqlite_funcs.append((_snew_fn, _snew_fn.__code__, _snew_fn.__defaults__, _snew_fn.__kwdefaults__))
        _expected_sqlite_cls_attrs.append((_scls, "__new__", _snew_bound))

    for _mname in ("__init__", "__call__", "__setattr__", "__delattr__"):
        _mfn = _rebind_sq_fn(_SQLITE_CLEANUP_CLS.__dict__[_mname])
        setattr(_SQLITE_CLEANUP_CLS, _mname, _mfn)
        _expected_sqlite_funcs.append((_mfn, _mfn.__code__, _mfn.__defaults__, _mfn.__kwdefaults__))
        _expected_sqlite_cls_attrs.append((_SQLITE_CLEANUP_CLS, _mname, _mfn))

    for _mname in ("__init__", "__call__", "__setattr__", "__delattr__", "__repr__"):
        _mfn = _rebind_sq_fn(_SQLITE_METHOD_CLS.__dict__[_mname])
        setattr(_SQLITE_METHOD_CLS, _mname, _mfn)
        _expected_sqlite_funcs.append((_mfn, _mfn.__code__, _mfn.__defaults__, _mfn.__kwdefaults__))
        _expected_sqlite_cls_attrs.append((_SQLITE_METHOD_CLS, _mname, _mfn))
        if _mname == "__call__":
            _sqlite_op_codes.append(_mfn.__code__)

    for _mname in (
        "__init__", "execute", "executemany", "executescript",
        "fetchone", "fetchmany", "fetchall",
        "__iter__", "__next__", "__getattr__", "__setattr__", "__delattr__",
    ):
        _mfn = _rebind_sq_fn(_SQLITE_CURSOR_CLS.__dict__[_mname])
        setattr(_SQLITE_CURSOR_CLS, _mname, _mfn)
        _expected_sqlite_funcs.append((_mfn, _mfn.__code__, _mfn.__defaults__, _mfn.__kwdefaults__))
        _expected_sqlite_cls_attrs.append((_SQLITE_CURSOR_CLS, _mname, _mfn))
        if _mname in (
            "__init__", "execute", "executemany", "executescript",
            "fetchone", "fetchmany", "fetchall",
            "__next__", "__getattr__", "__setattr__",
        ):
            _sqlite_op_codes.append(_mfn.__code__)

    for _pname in ("connection", "row_factory"):
        _prop = _SQLITE_CURSOR_CLS.__dict__[_pname]
        _fget = _rebind_sq_fn(_prop.fget)
        _fset = _rebind_sq_fn(_prop.fset) if _prop.fset is not None else None
        _new_prop = property(_fget, _fset, _prop.fdel, _prop.__doc__)
        setattr(_SQLITE_CURSOR_CLS, _pname, _new_prop)
        _expected_sqlite_funcs.append((_fget, _fget.__code__, _fget.__defaults__, _fget.__kwdefaults__))
        _sqlite_op_codes.append(_fget.__code__)
        if _fset is not None:
            _expected_sqlite_funcs.append((_fset, _fset.__code__, _fset.__defaults__, _fset.__kwdefaults__))
            _sqlite_op_codes.append(_fset.__code__)
        _expected_sqlite_cls_attrs.append((_SQLITE_CURSOR_CLS, _pname, _new_prop))

    for _mname in (
        "__init__", "cursor", "execute", "executemany", "executescript",
        "iterdump", "create_function", "create_aggregate", "create_window_function",
        "create_collation", "set_progress_handler", "set_trace_callback",
        "set_authorizer", "setconfig", "enable_load_extension",
        "load_extension", "backup", "__enter__", "__exit__",
        "__getattr__", "__setattr__", "__delattr__",
    ):
        _mfn = _rebind_sq_fn(_SQLITE_WRAPPER_CLS.__dict__[_mname])
        setattr(_SQLITE_WRAPPER_CLS, _mname, _mfn)
        _expected_sqlite_funcs.append((_mfn, _mfn.__code__, _mfn.__defaults__, _mfn.__kwdefaults__))
        _expected_sqlite_cls_attrs.append((_SQLITE_WRAPPER_CLS, _mname, _mfn))
        if _mname in (
            "__init__", "cursor", "execute", "executemany", "executescript",
            "iterdump", "setconfig", "enable_load_extension", "backup", "__enter__", "__exit__",
            "__getattr__", "__setattr__",
        ):
            _sqlite_op_codes.append(_mfn.__code__)

    _conn_rf_prop = _SQLITE_WRAPPER_CLS.__dict__["row_factory"]
    _conn_rf_get = _rebind_sq_fn(_conn_rf_prop.fget)
    _conn_rf_set = _rebind_sq_fn(_conn_rf_prop.fset)
    _conn_rf_new = property(_conn_rf_get, _conn_rf_set, _conn_rf_prop.fdel, _conn_rf_prop.__doc__)
    setattr(_SQLITE_WRAPPER_CLS, "row_factory", _conn_rf_new)
    _expected_sqlite_funcs.append((_conn_rf_get, _conn_rf_get.__code__, _conn_rf_get.__defaults__, _conn_rf_get.__kwdefaults__))
    _expected_sqlite_funcs.append((_conn_rf_set, _conn_rf_set.__code__, _conn_rf_set.__defaults__, _conn_rf_set.__kwdefaults__))
    _sqlite_op_codes.append(_conn_rf_get.__code__)
    _sqlite_op_codes.append(_conn_rf_set.__code__)
    _expected_sqlite_cls_attrs.append((_SQLITE_WRAPPER_CLS, "row_factory", _conn_rf_new))

    _GUARDED_SQLITE_CONNECT = _rebind_sq_fn(_sq_plain["_guarded_sqlite_connect"])
    _expected_sqlite_funcs.append((_GUARDED_SQLITE_CONNECT, _GUARDED_SQLITE_CONNECT.__code__, _GUARDED_SQLITE_CONNECT.__defaults__, _GUARDED_SQLITE_CONNECT.__kwdefaults__))
    _GUARDED_SQLITE_DENIED_REG = _rebind_sq_fn(_sq_plain["_guarded_sqlite_denied_reg"])
    _expected_sqlite_funcs.append((_GUARDED_SQLITE_DENIED_REG, _GUARDED_SQLITE_DENIED_REG.__code__, _GUARDED_SQLITE_DENIED_REG.__defaults__, _GUARDED_SQLITE_DENIED_REG.__kwdefaults__))

    dict.__setitem__(_SQLITE_GLOBALS, "_SQLITE_WRAPPER_CLS", _SQLITE_WRAPPER_CLS)
    dict.__setitem__(_SQLITE_GLOBALS, "_SQLITE_CURSOR_CLS", _SQLITE_CURSOR_CLS)
    dict.__setitem__(_SQLITE_GLOBALS, "_SQLITE_METHOD_CLS", _SQLITE_METHOD_CLS)
    dict.__setitem__(_SQLITE_GLOBALS, "_SQLITE_CLEANUP_CLS", _SQLITE_CLEANUP_CLS)
    dict.__setitem__(_SQLITE_GLOBALS, "_CONN_RF_SLOT", _CONN_RF_SLOT)
    dict.__setitem__(_SQLITE_GLOBALS, "_CUR_RF_SLOT", _CUR_RF_SLOT)
    dict.__setitem__(_SQLITE_GLOBALS, "_guarded_sqlite_connect", _GUARDED_SQLITE_CONNECT)
    dict.__setitem__(_SQLITE_GLOBALS, "_guarded_sqlite_denied_reg", _GUARDED_SQLITE_DENIED_REG)
    _EXPECTED_SQLITE_ITEMS = tuple(
        (k, v) for k, v in dict.items(_SQLITE_GLOBALS) if k != "__warningregistry__"
    )
    _EXPECTED_SQLITE_LEN = dict.__len__(_SQLITE_GLOBALS)
    _SQLITE_OP_CODES = frozenset(_sqlite_op_codes)
    _SQLITE_ALL_CODES = _collect_nested_codes(_fn.__code__ for _fn, _, _, _ in _expected_sqlite_funcs)

    _SQLITE_MOD.connect = _GUARDED_SQLITE_CONNECT
    _SQLITE_MOD.Connection = _SQLITE_WRAPPER_CLS
    _SQLITE_MOD.Cursor = _SQLITE_CURSOR_CLS
    _SQLITE_MOD.register_adapter = _GUARDED_SQLITE_DENIED_REG
    _SQLITE_MOD.register_converter = _GUARDED_SQLITE_DENIED_REG
    _RAW_SQLITE_MOD.connect = _GUARDED_SQLITE_CONNECT
    _RAW_SQLITE_MOD.Connection = _SQLITE_WRAPPER_CLS
    _RAW_SQLITE_MOD.Cursor = _SQLITE_CURSOR_CLS
    _RAW_SQLITE_MOD.register_adapter = _GUARDED_SQLITE_DENIED_REG
    _RAW_SQLITE_MOD.register_converter = _GUARDED_SQLITE_DENIED_REG

    _sig_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_signal__",
        "__warningregistry__": {},
        "_SYS_AUDIT": _SYS_AUDIT,
        "_TYPE": type,
        "_OBJ_HASH": _OBJ_HASH,
        "_FROZEN_DICT_CLS": _FrozenDict,
        "_FRAME_TYPE": _FRAME_TYPE,
        "_ENUM_TO_INT": _F_SIGNAL._enum_to_int,
        "_INT_TO_ENUM": _F_SIGNAL._int_to_enum,
        "_HANDLERS_ENUM": _F_SIGNAL.Handlers,
        "_SIG_DFL": _SIG_DFL,
        "_SIG_IGN": _SIG_IGN,
        "_DEFAULT_INT_HANDLER": _DEFAULT_INT_HANDLER,
        "_OBJECT_SETATTR": object.__setattr__,
        "_OBJECT_GETATTR": object.__getattribute__,
        "_OBJECT_NEW": _OBJECT_NEW,
        "_EXC_TB_SET": _EXC_TB_SET,
        "_EXC_CAUSE_SET": _EXC_CAUSE_SET,
        "_EXC_CTX_SET": _EXC_CTX_SET,
        "_INTERNAL_GLOBALS_IDS": (),
        "_AUDIT_GATE_WD_IDS": (),
        "_INTERNAL_GLOBALS_HASHES": (),
        "_AUDIT_GATE_WD_HASHES": (),
        "_SIGNAL_GLOBALS_HASH": 0,
        "_SIG_CALL_CODE": None,
        "_SIGNAL_HANDLER_CLS": None,
        "_strip_sig_exc": None,
        "_guarded_signal": None,
        "_guarded_getsignal": None,
        "_guarded_raw_signal": None,
        "_guarded_raw_getsignal": None,
    }
    _sig_src = '''
def _strip_sig_exc(exc):
    seen = set()
    stack = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        try:
            _EXC_TB_SET(cur, None)
            nxt_cause = cur.__cause__
            nxt_ctx = cur.__context__
            _EXC_CAUSE_SET(cur, None)
            _EXC_CTX_SET(cur, None)
        except Exception:
            continue
        if nxt_cause is not None and id(nxt_cause) not in seen:
            stack.append(nxt_cause)
        if nxt_ctx is not None and id(nxt_ctx) not in seen:
            stack.append(nxt_ctx)

class _GuardedSigHandler:
    __slots__ = ("_fn",)

    def __new__(cls, fn):
        if cls is not _SIGNAL_HANDLER_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable signal handler wrapper")
        return _OBJECT_NEW(cls)

    def __init__(self, fn):
        _OBJECT_SETATTR(self, "_fn", fn)

    def __call__(self, signum, frame):
        if frame is not None and frame.f_code is _SIG_CALL_CODE and _TYPE(frame.f_globals) is _FROZEN_DICT_CLS and _OBJ_HASH(frame.f_globals) == _SIGNAL_GLOBALS_HASH:
            return
        _saw_internal = False
        _first_user = None
        _cur = frame
        while _TYPE(_cur) is _FRAME_TYPE:
            fg = _cur.f_globals
            if _TYPE(fg) is _FROZEN_DICT_CLS:
                _fg_h = _OBJ_HASH(fg)
                if _fg_h in _AUDIT_GATE_WD_HASHES:
                    return
                if _fg_h in _INTERNAL_GLOBALS_HASHES:
                    _saw_internal = True
                    _first_user = None
                elif _first_user is None:
                    _first_user = _cur
            elif _first_user is None:
                _first_user = _cur
            _cur = _cur.f_back
        if _saw_internal:
            _SYS_AUDIT("octopus.signal_guard", signum)
            return
        return _OBJECT_GETATTR(self, "_fn")(signum, _first_user)

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable signal handler wrapper")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable signal handler wrapper")

def _guarded_raw_signal(signalnum, handler):
    try:
        sig_i = signalnum if type(signalnum) is int else _ENUM_TO_INT(signalnum)
        if type(sig_i) is not int:
            raise TypeError("'signalnum' must be an integer")
        h_norm = _ENUM_TO_INT(handler)
        if type(h_norm) is int:
            pass
        elif callable(handler):
            h_norm = _SIGNAL_HANDLER_CLS(handler)
            if type(h_norm) is not _SIGNAL_HANDLER_CLS:
                raise PermissionError("blocked_by_octopus_policy: tampered signal handler wrapper")
        else:
            raise TypeError("signal handler must be signal.SIG_IGN, signal.SIG_DFL, or a callable object")
        box = [None]
        _SYS_AUDIT("octopus.signal_op", "signal", sig_i, h_norm, handler, box)
        return box[0]
    except BaseException as exc:
        _strip_sig_exc(exc)
        raise exc from None

def _guarded_raw_getsignal(signalnum):
    try:
        sig_i = signalnum if type(signalnum) is int else _ENUM_TO_INT(signalnum)
        if type(sig_i) is not int:
            raise TypeError("'signalnum' must be an integer")
        box = [None]
        _SYS_AUDIT("octopus.signal_op", "getsignal", sig_i, box)
        return box[0]
    except BaseException as exc:
        _strip_sig_exc(exc)
        raise exc from None

def _guarded_signal(signalnum, handler):
    try:
        sig_i = _ENUM_TO_INT(signalnum)
        if type(sig_i) is not int:
            raise TypeError("'signalnum' must be an integer")
        h_norm = _ENUM_TO_INT(handler)
        if type(h_norm) is int:
            pass
        elif callable(handler):
            h_norm = _SIGNAL_HANDLER_CLS(handler)
            if type(h_norm) is not _SIGNAL_HANDLER_CLS:
                raise PermissionError("blocked_by_octopus_policy: tampered signal handler wrapper")
        else:
            raise TypeError("signal handler must be signal.SIG_IGN, signal.SIG_DFL, or a callable object")
        box = [None]
        _SYS_AUDIT("octopus.signal_op", "signal", sig_i, h_norm, handler, box)
        return _INT_TO_ENUM(box[0], _HANDLERS_ENUM)
    except BaseException as exc:
        _strip_sig_exc(exc)
        raise exc from None

def _guarded_getsignal(signalnum):
    try:
        sig_i = _ENUM_TO_INT(signalnum)
        if type(sig_i) is not int:
            raise TypeError("'signalnum' must be an integer")
        box = [None]
        _SYS_AUDIT("octopus.signal_op", "getsignal", sig_i, box)
        return _INT_TO_ENUM(box[0], _HANDLERS_ENUM)
    except BaseException as exc:
        _strip_sig_exc(exc)
        raise exc from None
'''
    exec(compile(_sig_src, "<octopus_signal>", "exec"), _sig_plain)
    _SIGNAL_GLOBALS = _FrozenDict(_sig_plain)
    _SIGNAL_WARNREG_REF = dict.__getitem__(_SIGNAL_GLOBALS, "__warningregistry__")
    _SIGNAL_HANDLER_CLS = _sig_plain["_GuardedSigHandler"]

    def _rebind_sig_fn(fn):
        nf = types.FunctionType(fn.__code__, _SIGNAL_GLOBALS, fn.__name__, fn.__defaults__, None)
        if fn.__kwdefaults__ is not None:
            nf.__kwdefaults__ = dict(fn.__kwdefaults__)
        return nf

    _expected_signal_funcs = []
    _expected_signal_cls_attrs = []
    _signal_op_codes = []

    _strip_sig_exc_fn = _rebind_sig_fn(_sig_plain["_strip_sig_exc"])
    dict.__setitem__(_SIGNAL_GLOBALS, "_strip_sig_exc", _strip_sig_exc_fn)
    _expected_signal_funcs.append((_strip_sig_exc_fn, _strip_sig_exc_fn.__code__, _strip_sig_exc_fn.__defaults__, _strip_sig_exc_fn.__kwdefaults__))

    _signew_sm = _SIGNAL_HANDLER_CLS.__dict__["__new__"]
    _signew_fn = _rebind_sig_fn(_signew_sm.__func__)
    _signew_bound = staticmethod(_signew_fn)
    setattr(_SIGNAL_HANDLER_CLS, "__new__", _signew_bound)
    _expected_signal_funcs.append((_signew_fn, _signew_fn.__code__, _signew_fn.__defaults__, _signew_fn.__kwdefaults__))
    _expected_signal_cls_attrs.append((_SIGNAL_HANDLER_CLS, "__new__", _signew_bound))

    for _mname in ("__init__", "__call__", "__setattr__", "__delattr__"):
        _mfn = _rebind_sig_fn(_SIGNAL_HANDLER_CLS.__dict__[_mname])
        setattr(_SIGNAL_HANDLER_CLS, _mname, _mfn)
        _expected_signal_funcs.append((_mfn, _mfn.__code__, _mfn.__defaults__, _mfn.__kwdefaults__))
        _expected_signal_cls_attrs.append((_SIGNAL_HANDLER_CLS, _mname, _mfn))

    _GUARDED_SIGNAL = _rebind_sig_fn(_sig_plain["_guarded_signal"])
    _GUARDED_GETSIGNAL = _rebind_sig_fn(_sig_plain["_guarded_getsignal"])
    _GUARDED_RAW_SIGNAL = _rebind_sig_fn(_sig_plain["_guarded_raw_signal"])
    _GUARDED_RAW_GETSIGNAL = _rebind_sig_fn(_sig_plain["_guarded_raw_getsignal"])
    for _sfn_name, _sfn in (
        ("_guarded_signal", _GUARDED_SIGNAL),
        ("_guarded_getsignal", _GUARDED_GETSIGNAL),
        ("_guarded_raw_signal", _GUARDED_RAW_SIGNAL),
        ("_guarded_raw_getsignal", _GUARDED_RAW_GETSIGNAL),
    ):
        dict.__setitem__(_SIGNAL_GLOBALS, _sfn_name, _sfn)
        _expected_signal_funcs.append((_sfn, _sfn.__code__, _sfn.__defaults__, _sfn.__kwdefaults__))
        _signal_op_codes.append(_sfn.__code__)

    dict.__setitem__(_SIGNAL_GLOBALS, "_SIGNAL_HANDLER_CLS", _SIGNAL_HANDLER_CLS)
    _SIGNAL_OP_CODES = frozenset(_signal_op_codes)
    _signal_helper_codes = [
        getattr(_fn, "__code__", None)
        for _fn in (
            getattr(_F_SIGNAL, "_enum_to_int", None),
            getattr(_F_SIGNAL, "_int_to_enum", None),
        )
    ]
    _SIGNAL_ALL_CODES = _collect_nested_codes(
        [_fn.__code__ for _fn, _, _, _ in _expected_signal_funcs]
        + [c for c in _signal_helper_codes if type(c) is _CODE_TYPE]
    )

    _SIGNAL_MOD.signal = _GUARDED_SIGNAL
    _SIGNAL_MOD.getsignal = _GUARDED_GETSIGNAL
    _RAW_SIGNAL_MOD.signal = _GUARDED_RAW_SIGNAL
    _RAW_SIGNAL_MOD.getsignal = _GUARDED_RAW_GETSIGNAL

    _ORIG_SYS_SETTRACE = sys.settrace
    _ORIG_SYS_GETTRACE = sys.gettrace
    _ORIG_SYS_SETPROFILE = sys.setprofile
    _ORIG_SYS_GETPROFILE = sys.getprofile
    _ORIG_SYS_SETTRACEALL = getattr(sys, "_settraceallthreads", None)
    _ORIG_SYS_SETPROFILEALL = getattr(sys, "_setprofileallthreads", None)
    _SYS_MON_MOD = getattr(sys, "monitoring", None)
    _SYS_MON_EVENTS = getattr(_SYS_MON_MOD, "events", None) if _SYS_MON_MOD is not None else None
    _ORIG_MON_REGISTER = getattr(_SYS_MON_MOD, "register_callback", None) if _SYS_MON_MOD is not None else None
    _ORIG_MON_SET_LOCAL = getattr(_SYS_MON_MOD, "set_local_events", None) if _SYS_MON_MOD is not None else None
    _MON_DISABLE = getattr(_SYS_MON_MOD, "DISABLE", None) if _SYS_MON_MOD is not None else None
    _MON_NON_DISABLEABLE_EVENTS = frozenset(
        getattr(_SYS_MON_EVENTS, _ev_name)
        for _ev_name in (
            "C_RETURN",
            "C_RAISE",
            "PY_UNWIND",
            "RAISE",
            "RERAISE",
            "EXCEPTION_HANDLED",
            "PY_THROW",
        )
        if _SYS_MON_EVENTS is not None and hasattr(_SYS_MON_EVENTS, _ev_name)
    )

    _trace_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_trace__",
        "__warningregistry__": {},
        "_SYS_AUDIT": _SYS_AUDIT,
        "_TYPE": type,
        "_OBJ_HASH": _OBJ_HASH,
        "_FROZEN_DICT_CLS": _FrozenDict,
        "_FRAME_TYPE": _FRAME_TYPE,
        "_CODE_TYPE": _CODE_TYPE,
        "_OBJECT_SETATTR": object.__setattr__,
        "_OBJECT_GETATTR": object.__getattribute__,
        "_OBJECT_NEW": _OBJECT_NEW,
        "_EXC_TB_SET": _EXC_TB_SET,
        "_EXC_CAUSE_SET": _EXC_CAUSE_SET,
        "_EXC_CTX_SET": _EXC_CTX_SET,
        "_MON_DISABLE": _MON_DISABLE,
        "_MON_NON_DISABLEABLE_EVENTS": _MON_NON_DISABLEABLE_EVENTS,
        "_INTERNAL_GLOBALS_IDS": (),
        "_INTERNAL_GLOBALS_HASHES": (),
        "_ALL_INTERNAL_CODES": (),
        "_TRACE_WRAPPER_CLS": None,
        "_LOCAL_TRACE_CLS": None,
        "_MON_CB_CLS": None,
        "_strip_trace_exc": None,
        "_is_internal_frame": None,
        "_guarded_settrace": None,
        "_guarded_gettrace": None,
        "_guarded_setprofile": None,
        "_guarded_getprofile": None,
        "_guarded_settraceall": None,
        "_guarded_setprofileall": None,
        "_guarded_mon_register": None,
        "_guarded_mon_set_local": None,
    }
    _trace_src = '''
def _strip_trace_exc(exc):
    seen = set()
    stack = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        try:
            _EXC_TB_SET(cur, None)
            nxt_cause = cur.__cause__
            nxt_ctx = cur.__context__
            _EXC_CAUSE_SET(cur, None)
            _EXC_CTX_SET(cur, None)
        except Exception:
            continue
        if nxt_cause is not None and id(nxt_cause) not in seen:
            stack.append(nxt_cause)
        if nxt_ctx is not None and id(nxt_ctx) not in seen:
            stack.append(nxt_ctx)

def _is_internal_frame(frame):
    f = frame
    while _TYPE(f) is _FRAME_TYPE:
        fg = f.f_globals
        if (_TYPE(fg) is _FROZEN_DICT_CLS and _OBJ_HASH(fg) in _INTERNAL_GLOBALS_HASHES) or f.f_code in _ALL_INTERNAL_CODES:
            return True
        f = f.f_back
    return False

class _LocalTraceWrapper:
    __slots__ = ("_fn",)

    def __new__(cls, fn):
        if cls is not _LOCAL_TRACE_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable trace wrapper")
        return _OBJECT_NEW(cls)

    def __init__(self, fn):
        _OBJECT_SETATTR(self, "_fn", fn)

    def __call__(self, frame, event, arg):
        try:
            if _is_internal_frame(frame):
                return None
            fn = _OBJECT_GETATTR(self, "_fn")
            res = fn(frame, event, arg)
            if res is None:
                return None
            if res is fn:
                return self
            lw = _LOCAL_TRACE_CLS(res)
            if _TYPE(lw) is not _LOCAL_TRACE_CLS:
                raise PermissionError("blocked_by_octopus_policy: tampered local trace wrapper")
            return lw
        except BaseException as exc:
            _strip_trace_exc(exc)
            _SYS_AUDIT("octopus.trace_unwind", "sys.settrace")
            raise exc from None

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable trace wrapper")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable trace wrapper")

class _TraceWrapper:
    __slots__ = ("_fn", "_is_prof")

    def __new__(cls, fn, is_prof):
        if cls is not _TRACE_WRAPPER_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable trace wrapper")
        return _OBJECT_NEW(cls)

    def __init__(self, fn, is_prof):
        _OBJECT_SETATTR(self, "_fn", fn)
        _OBJECT_SETATTR(self, "_is_prof", is_prof)

    def __call__(self, frame, event, arg):
        is_prof = _OBJECT_GETATTR(self, "_is_prof")
        try:
            if _is_internal_frame(frame):
                return None
            fn = _OBJECT_GETATTR(self, "_fn")
            if is_prof:
                fn(frame, event, arg)
                return None
            res = fn(frame, event, arg)
            if res is None:
                return None
            if res is fn:
                return self
            lw = _LOCAL_TRACE_CLS(res)
            if _TYPE(lw) is not _LOCAL_TRACE_CLS:
                raise PermissionError("blocked_by_octopus_policy: tampered local trace wrapper")
            return lw
        except BaseException as exc:
            _strip_trace_exc(exc)
            _SYS_AUDIT("octopus.trace_unwind", "sys.setprofile" if is_prof else "sys.settrace")
            raise exc from None

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable trace wrapper")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable trace wrapper")

class _MonCallbackWrapper:
    __slots__ = ("_fn", "_can_disable")

    def __new__(cls, fn, can_disable=True):
        if cls is not _MON_CB_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable monitoring wrapper")
        return _OBJECT_NEW(cls)

    def __init__(self, fn, can_disable=True):
        _OBJECT_SETATTR(self, "_fn", fn)
        _OBJECT_SETATTR(self, "_can_disable", bool(can_disable))

    def __call__(self, *args):
        if args and _TYPE(args[0]) is _CODE_TYPE and args[0] in _ALL_INTERNAL_CODES:
            return _MON_DISABLE if _OBJECT_GETATTR(self, "_can_disable") else None
        try:
            return _OBJECT_GETATTR(self, "_fn")(*args)
        except BaseException as exc:
            _strip_trace_exc(exc)
            raise exc from None

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable monitoring wrapper")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable monitoring wrapper")

def _guarded_settrace(func):
    try:
        if func is None:
            _SYS_AUDIT("octopus.trace_op", "settrace", None)
            return None
        w = _TRACE_WRAPPER_CLS(func, False)
        if _TYPE(w) is not _TRACE_WRAPPER_CLS:
            raise PermissionError("blocked_by_octopus_policy: tampered trace wrapper")
        _SYS_AUDIT("octopus.trace_op", "settrace", w)
        return None
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None

def _guarded_gettrace():
    try:
        box = [None]
        _SYS_AUDIT("octopus.trace_op", "gettrace", box)
        cur = box[0]
        if _TYPE(cur) is _TRACE_WRAPPER_CLS:
            return _OBJECT_GETATTR(cur, "_fn")
        return cur
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None

def _guarded_setprofile(func):
    try:
        if func is None:
            _SYS_AUDIT("octopus.trace_op", "setprofile", None)
            return None
        w = _TRACE_WRAPPER_CLS(func, True)
        if _TYPE(w) is not _TRACE_WRAPPER_CLS:
            raise PermissionError("blocked_by_octopus_policy: tampered profile wrapper")
        _SYS_AUDIT("octopus.trace_op", "setprofile", w)
        return None
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None

def _guarded_getprofile():
    try:
        box = [None]
        _SYS_AUDIT("octopus.trace_op", "getprofile", box)
        cur = box[0]
        if _TYPE(cur) is _TRACE_WRAPPER_CLS:
            return _OBJECT_GETATTR(cur, "_fn")
        return cur
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None

def _guarded_settraceall(func):
    try:
        if func is None:
            _SYS_AUDIT("octopus.trace_op", "settraceall", None)
            return None
        w = _TRACE_WRAPPER_CLS(func, False)
        if _TYPE(w) is not _TRACE_WRAPPER_CLS:
            raise PermissionError("blocked_by_octopus_policy: tampered trace wrapper")
        _SYS_AUDIT("octopus.trace_op", "settraceall", w)
        return None
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None

def _guarded_setprofileall(func):
    try:
        if func is None:
            _SYS_AUDIT("octopus.trace_op", "setprofileall", None)
            return None
        w = _TRACE_WRAPPER_CLS(func, True)
        if _TYPE(w) is not _TRACE_WRAPPER_CLS:
            raise PermissionError("blocked_by_octopus_policy: tampered profile wrapper")
        _SYS_AUDIT("octopus.trace_op", "setprofileall", w)
        return None
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None

def _guarded_mon_register(tool_id, event, func):
    try:
        if _TYPE(tool_id) is not int or _TYPE(event) is not int:
            raise TypeError("tool_id and event must be exact int")
        if func is None:
            cb = None
        else:
            cb = _MON_CB_CLS(func, event not in _MON_NON_DISABLEABLE_EVENTS)
            if _TYPE(cb) is not _MON_CB_CLS:
                raise PermissionError("blocked_by_octopus_policy: tampered monitoring wrapper")
        box = [None]
        _SYS_AUDIT("octopus.trace_op", "mon_register", tool_id, event, cb, box)
        prev = box[0]
        if _TYPE(prev) is _MON_CB_CLS:
            return _OBJECT_GETATTR(prev, "_fn")
        return prev
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None

def _guarded_mon_set_local(tool_id, code, event_set):
    try:
        if _TYPE(tool_id) is not int or _TYPE(event_set) is not int:
            raise TypeError("tool_id and event_set must be exact int")
        if _TYPE(code) is _CODE_TYPE and code in _ALL_INTERNAL_CODES:
            raise PermissionError("blocked_by_octopus_policy: monitoring internal guard code denied")
        box = [None]
        _SYS_AUDIT("octopus.trace_op", "mon_set_local", tool_id, code, event_set, box)
        return box[0]
    except BaseException as exc:
        _strip_trace_exc(exc)
        raise exc from None
'''
    exec(compile(_trace_src, "<octopus_trace>", "exec"), _trace_plain)
    _TRACE_GLOBALS = _FrozenDict(_trace_plain)
    _TRACE_WARNREG_REF = dict.__getitem__(_TRACE_GLOBALS, "__warningregistry__")
    _TRACE_WRAPPER_CLS = _trace_plain["_TraceWrapper"]
    _LOCAL_TRACE_CLS = _trace_plain["_LocalTraceWrapper"]
    _MON_CB_CLS = _trace_plain["_MonCallbackWrapper"]

    def _rebind_tr_fn(fn):
        nf = types.FunctionType(fn.__code__, _TRACE_GLOBALS, fn.__name__, fn.__defaults__, None)
        if fn.__kwdefaults__ is not None:
            nf.__kwdefaults__ = dict(fn.__kwdefaults__)
        return nf

    _expected_trace_funcs = []
    _expected_trace_cls_attrs = []
    _trace_op_codes = []

    for _th_name in ("_strip_trace_exc", "_is_internal_frame"):
        _th_fn = _rebind_tr_fn(_trace_plain[_th_name])
        dict.__setitem__(_TRACE_GLOBALS, _th_name, _th_fn)
        _expected_trace_funcs.append((_th_fn, _th_fn.__code__, _th_fn.__defaults__, _th_fn.__kwdefaults__))

    for _tcls in (_TRACE_WRAPPER_CLS, _LOCAL_TRACE_CLS, _MON_CB_CLS):
        _tnew_sm = _tcls.__dict__["__new__"]
        _tnew_fn = _rebind_tr_fn(_tnew_sm.__func__)
        _tnew_bound = staticmethod(_tnew_fn)
        setattr(_tcls, "__new__", _tnew_bound)
        _expected_trace_funcs.append((_tnew_fn, _tnew_fn.__code__, _tnew_fn.__defaults__, _tnew_fn.__kwdefaults__))
        _expected_trace_cls_attrs.append((_tcls, "__new__", _tnew_bound))
        for _mname in ("__init__", "__call__", "__setattr__", "__delattr__"):
            _mfn = _rebind_tr_fn(_tcls.__dict__[_mname])
            setattr(_tcls, _mname, _mfn)
            _expected_trace_funcs.append((_mfn, _mfn.__code__, _mfn.__defaults__, _mfn.__kwdefaults__))
            _expected_trace_cls_attrs.append((_tcls, _mname, _mfn))

    _GUARDED_SETTRACE = _rebind_tr_fn(_trace_plain["_guarded_settrace"])
    _GUARDED_GETTRACE = _rebind_tr_fn(_trace_plain["_guarded_gettrace"])
    _GUARDED_SETPROFILE = _rebind_tr_fn(_trace_plain["_guarded_setprofile"])
    _GUARDED_GETPROFILE = _rebind_tr_fn(_trace_plain["_guarded_getprofile"])
    _GUARDED_SETTRACEALL = _rebind_tr_fn(_trace_plain["_guarded_settraceall"]) if _ORIG_SYS_SETTRACEALL is not None else None
    _GUARDED_SETPROFILEALL = _rebind_tr_fn(_trace_plain["_guarded_setprofileall"]) if _ORIG_SYS_SETPROFILEALL is not None else None
    _GUARDED_MON_REGISTER = _rebind_tr_fn(_trace_plain["_guarded_mon_register"]) if _ORIG_MON_REGISTER is not None else None
    _GUARDED_MON_SET_LOCAL = _rebind_tr_fn(_trace_plain["_guarded_mon_set_local"]) if _ORIG_MON_SET_LOCAL is not None else None

    for _tfn_name, _tfn, _is_op in (
        ("_guarded_settrace", _GUARDED_SETTRACE, True),
        ("_guarded_gettrace", _GUARDED_GETTRACE, True),
        ("_guarded_setprofile", _GUARDED_SETPROFILE, True),
        ("_guarded_getprofile", _GUARDED_GETPROFILE, True),
        ("_guarded_settraceall", _GUARDED_SETTRACEALL, True),
        ("_guarded_setprofileall", _GUARDED_SETPROFILEALL, True),
        ("_guarded_mon_register", _GUARDED_MON_REGISTER, True),
        ("_guarded_mon_set_local", _GUARDED_MON_SET_LOCAL, True),
    ):
        if _tfn is not None:
            dict.__setitem__(_TRACE_GLOBALS, _tfn_name, _tfn)
            _expected_trace_funcs.append((_tfn, _tfn.__code__, _tfn.__defaults__, _tfn.__kwdefaults__))
            if _is_op:
                _trace_op_codes.append(_tfn.__code__)
        else:
            _rebound_unused = _rebind_tr_fn(_trace_plain[_tfn_name])
            dict.__setitem__(_TRACE_GLOBALS, _tfn_name, _rebound_unused)
            _expected_trace_funcs.append((_rebound_unused, _rebound_unused.__code__, _rebound_unused.__defaults__, _rebound_unused.__kwdefaults__))

    dict.__setitem__(_TRACE_GLOBALS, "_TRACE_WRAPPER_CLS", _TRACE_WRAPPER_CLS)
    dict.__setitem__(_TRACE_GLOBALS, "_LOCAL_TRACE_CLS", _LOCAL_TRACE_CLS)
    dict.__setitem__(_TRACE_GLOBALS, "_MON_CB_CLS", _MON_CB_CLS)
    _TRACE_OP_CODES = frozenset(_trace_op_codes)
    _TRACE_UNWIND_CODES = frozenset((
        _TRACE_WRAPPER_CLS.__dict__["__call__"].__code__,
        _LOCAL_TRACE_CLS.__dict__["__call__"].__code__,
    ))
    _TRACE_ALL_CODES = _collect_nested_codes(_fn.__code__ for _fn, _, _, _ in _expected_trace_funcs)

    _local_hosts = {
        "localhost", "localhost.", "localhost.localdomain",
        "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1", "0.0.0.0",
    }
    for _lh in (_OCTOPUS_CFG.get("local_hosts") or ()):
        if type(_lh) is str and _lh:
            _local_hosts.add(_lh)
    for _env_k in ("COMPUTERNAME", "HOSTNAME"):
        _ev = _setup_env_ci(_env_k)
        if _ev:
            _el = _ev.strip().lower().rstrip(".")
            if _el:
                _local_hosts.add(_el)
                _local_hosts.add(_el + ".")
    _cn_env = _setup_env_ci("COMPUTERNAME")
    _udns_env = _setup_env_ci("USERDNSDOMAIN")
    if _cn_env and _udns_env:
        _fq_env = (_cn_env.strip() + "." + _udns_env.strip()).lower().rstrip(".")
        if _fq_env:
            _local_hosts.add(_fq_env)
            _local_hosts.add(_fq_env + ".")
    try:
        _hn = socket.gethostname()
        if type(_hn) is str and _hn.strip():
            _hl = _hn.strip().lower().rstrip(".")
            _local_hosts.add(_hl)
            _local_hosts.add(_hl + ".")
    except Exception:
        pass
    _LOCAL_HOSTS = frozenset(_local_hosts)
    _WIN_SYS_ROOT = (_setup_env_ci("SystemRoot") or _setup_env_ci("WINDIR") or "C:\\Windows").replace("\\", "/").rstrip("/")

    _OS_MOD = os
    _RAW_OS_MOD = sys.modules.get(os.name)
    _OS_PATH_MOD = os.path
    _ORIG_OS_STAT = _RAW_OS_MOD.stat if _RAW_OS_MOD is not None else os.stat
    _ORIG_OS_LSTAT = _RAW_OS_MOD.lstat if _RAW_OS_MOD is not None else os.lstat
    _ORIG_OS_ACCESS = _RAW_OS_MOD.access if _RAW_OS_MOD is not None else os.access
    _ORIG_OS_SCANDIR = _RAW_OS_MOD.scandir if _RAW_OS_MOD is not None else os.scandir
    _ORIG_OS_READLINK = getattr(_RAW_OS_MOD, "readlink", None) if _RAW_OS_MOD is not None else getattr(os, "readlink", None)
    _GLOB_MOD = sys.modules.get("glob")
    _OS_W_OK = getattr(os, "W_OK", 2)
    _ORIG_NT_PATH_EXISTS = getattr(_RAW_OS_MOD, "_path_exists", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None
    _ORIG_NT_PATH_LEXISTS = getattr(_RAW_OS_MOD, "_path_lexists", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None
    _ORIG_NT_PATH_ISFILE = getattr(_RAW_OS_MOD, "_path_isfile", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None
    _ORIG_NT_PATH_ISDIR = getattr(_RAW_OS_MOD, "_path_isdir", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None
    _ORIG_NT_PATH_ISLINK = getattr(_RAW_OS_MOD, "_path_islink", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None
    _ORIG_NT_PATH_ISJUNCTION = getattr(_RAW_OS_MOD, "_path_isjunction", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None
    _ORIG_NT_GETFINALPATHNAME = getattr(_RAW_OS_MOD, "_getfinalpathname", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None
    _ORIG_NT_FINDFIRSTFILE = getattr(_RAW_OS_MOD, "_findfirstfile", None) if (_IS_WIN and _RAW_OS_MOD is not None) else None

    _stat_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_stat__",
        "__warningregistry__": {},
        "_SYS_AUDIT": _SYS_AUDIT,
        "_SYS_IS_FINALIZING": _SYS_IS_FINALIZING,
        "_LIST_APPEND": _LIST_APPEND,
        "_STAT_GC_QUEUE": _stat_gc_queue,
        "_TYPE": type,
        "_TYPE_DICT_GET": _TYPE_DICT_GET,
        "_TYPE_MRO_GET": _TYPE_MRO_GET,
        "_MP_ITEMS": _MP_ITEMS,
        "_MISSING": _MISSING,
        "_OBJECT_NEW": _OBJECT_NEW,
        "_OBJECT_SETATTR": object.__setattr__,
        "_OS_PATHLIKE": _OS_PATHLIKE,
        "_OS_DIRENTRY": _OS_DIRENTRY,
        "_OS_DIRENTRY_FSPATH": _OS_DIRENTRY_FSPATH,
        "_OS_DIRENTRY_PATH_DESC": _OS_DIRENTRY_PATH_DESC,
        "_EXACT_PATHLIB_TYPES": _EXACT_PATHLIB_TYPES,
        "_PATHLIB_META_MAP": _PATHLIB_META_MAP,
        "_PUREPATH_RAW_PATHS_DESC": _PUREPATH_RAW_PATHS_DESC,
        "_PUREPATH_STR_DESC": _PUREPATH_STR_DESC,
        "_PUREPATH_DRV_DESC": _PUREPATH_DRV_DESC,
        "_PUREPATH_ROOT_DESC": _PUREPATH_ROOT_DESC,
        "_PUREPATH_TAIL_DESC": _PUREPATH_TAIL_DESC,
        "_POSIX_PARSER_CFG": _POSIX_PARSER_CFG,
        "_NT_PARSER_CFG": _NT_PARSER_CFG,
        "_EXC_TB_SET": _EXC_TB_SET,
        "_EXC_CAUSE_SET": _EXC_CAUSE_SET,
        "_EXC_CTX_SET": _EXC_CTX_SET,
        "_STAT_CLEANUP_CLS": None,
        "_GUARDED_DIRENTRY_CLS": None,
        "_SCANDIR_ITER_CLS": None,
        "_has_mro_base": None,
        "_strip_stat_exc": None,
        "_extract_pathlib_str": None,
        "_coerce_stat_path": None,
        "_coerce_exact_bool": None,
        "_guarded_os_stat": None,
        "_guarded_os_lstat": None,
        "_guarded_os_access": None,
        "_guarded_os_scandir": None,
        "_guarded_os_readlink": None,
        "_guarded_nt_path_exists": None,
        "_guarded_nt_path_lexists": None,
        "_guarded_nt_path_isfile": None,
        "_guarded_nt_path_isdir": None,
        "_guarded_nt_path_islink": None,
        "_guarded_nt_path_isjunction": None,
        "_guarded_nt_getfinalpathname": None,
        "_guarded_nt_findfirstfile": None,
    }
    _stat_src = '''
def _has_mro_base(obj, cls):
    for _b in _TYPE_MRO_GET(_TYPE(obj)):
        if _b is cls:
            return True
    return False

def _strip_stat_exc(exc):
    seen = set()
    stack = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        try:
            _EXC_TB_SET(cur, None)
            nxt_cause = cur.__cause__
            nxt_ctx = cur.__context__
            _EXC_CAUSE_SET(cur, None)
            _EXC_CTX_SET(cur, None)
        except Exception:
            continue
        if nxt_cause is not None and id(nxt_cause) not in seen:
            stack.append(nxt_cause)
        if nxt_ctx is not None and id(nxt_ctx) not in seen:
            stack.append(nxt_ctx)

def _extract_pathlib_str(x, t):
    _meta = None
    for _item in _PATHLIB_META_MAP:
        if t is _item[0]:
            _meta = _item
            break
    if _meta is None:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    _is_posix = _meta[1]
    _exp_attrs = _meta[2]
    for _b in _TYPE_MRO_GET(t):
        _bd = _TYPE_DICT_GET(_b)
        for _k in _bd:
            if _TYPE(_k) is not str:
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    for _aname, _exp_v in _exp_attrs:
        _found = _MISSING
        for _b in _TYPE_MRO_GET(t):
            _bd = _TYPE_DICT_GET(_b)
            for _k, _v in _MP_ITEMS(_bd):
                if _TYPE(_k) is str and _k == _aname:
                    _found = _v
                    break
            if _found is not _MISSING:
                break
        if _found is not _exp_v:
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    if _PUREPATH_RAW_PATHS_DESC is None:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    try:
        _raw_paths = _PUREPATH_RAW_PATHS_DESC.__get__(x)
    except AttributeError:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied") from None
    if _TYPE(_raw_paths) is not list:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    for _el in list.__iter__(_raw_paths):
        if _TYPE(_el) is not str:
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    _p_join, _p_splitroot, _p_splitdrive, _p_sep, _p_altsep = _POSIX_PARSER_CFG if _is_posix else _NT_PARSER_CFG
    _n = list.__len__(_raw_paths)
    if _n == 0:
        _raw_p = ""
    elif _n == 1:
        _raw_p = _raw_paths[0]
    else:
        _raw_p = _p_join(*_raw_paths)
    if _TYPE(_raw_p) is not str:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if not _raw_p:
        _drv, _root, _tail = "", "", []
    else:
        if _p_altsep:
            _raw_p = _raw_p.replace(_p_altsep, _p_sep)
        _drv, _root, _rel = _p_splitroot(_raw_p)
        if not _root and _drv.startswith(_p_sep) and not _drv.endswith(_p_sep):
            _drv_parts = _drv.split(_p_sep)
            if len(_drv_parts) == 4 and _drv_parts[2] not in "?.":
                _root = _p_sep
            elif len(_drv_parts) == 6:
                _root = _p_sep
        _tail = [_seg for _seg in _rel.split(_p_sep) if _seg and _seg != "."]
    if _drv or _root:
        _res = _drv + _root + _p_sep.join(_tail)
    elif _tail and _p_splitdrive(_tail[0])[0]:
        _res = _p_sep.join(["."] + _tail)
    else:
        _res = _p_sep.join(_tail)
    _computed = _res or "."
    if _PUREPATH_STR_DESC is not None:
        try:
            _s_val = _PUREPATH_STR_DESC.__get__(x)
        except AttributeError:
            _s_val = _MISSING
        if _s_val is not _MISSING:
            if _TYPE(_s_val) is not str or _s_val != _computed:
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_DRV_DESC is not None:
        try:
            _d_val = _PUREPATH_DRV_DESC.__get__(x)
        except AttributeError:
            _d_val = _MISSING
        if _d_val is not _MISSING and (_TYPE(_d_val) is not str or _d_val != _drv):
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_ROOT_DESC is not None:
        try:
            _r_val = _PUREPATH_ROOT_DESC.__get__(x)
        except AttributeError:
            _r_val = _MISSING
        if _r_val is not _MISSING and (_TYPE(_r_val) is not str or _r_val != _root):
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_TAIL_DESC is not None:
        try:
            _t_val = _PUREPATH_TAIL_DESC.__get__(x)
        except AttributeError:
            _t_val = _MISSING
        if _t_val is not _MISSING:
            if _TYPE(_t_val) is not list or list.__len__(_t_val) != len(_tail):
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
            for _idx, _tv in enumerate(list.__iter__(_t_val)):
                if _TYPE(_tv) is not str or _tv != _tail[_idx]:
                    raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    return _computed

def _coerce_stat_path(p):
    t = _TYPE(p)
    if t is str or t is bytes:
        return p
    if _has_mro_base(p, str) or _has_mro_base(p, bytes):
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    if _OS_DIRENTRY is not None and t is _OS_DIRENTRY:
        if t.__fspath__ is not _OS_DIRENTRY_FSPATH or t.path is not _OS_DIRENTRY_PATH_DESC:
            raise PermissionError("blocked_by_octopus_policy: tampered DirEntry descriptor denied")
        v = _OS_DIRENTRY_FSPATH(p)
        vt = _TYPE(v)
        if vt is str or vt is bytes:
            return v
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    if _GUARDED_DIRENTRY_CLS is not None and t is _GUARDED_DIRENTRY_CLS:
        v = p.path
        vt = _TYPE(v)
        if vt is str or vt is bytes:
            return v
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    if any(t is _pt for _pt in _EXACT_PATHLIB_TYPES):
        return _extract_pathlib_str(p, t)
    if _OS_PATHLIKE is not None and _has_mro_base(p, _OS_PATHLIKE):
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    for _b in _TYPE_MRO_GET(t):
        _bd = _TYPE_DICT_GET(_b)
        for _k in _bd:
            if _TYPE(_k) is not str or _k == "__fspath__":
                raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    raise TypeError("stat: path should be string, bytes or os.PathLike, not " + t.__name__)

def _coerce_exact_bool(val, name):
    vt = _TYPE(val)
    if vt is bool:
        return val
    if vt is int:
        return bool(val)
    raise PermissionError("blocked_by_octopus_policy: non-exact " + name + " type denied")

def _guarded_os_stat(path, *, dir_fd=None, follow_symlinks=True):
    try:
        if dir_fd is not None:
            raise PermissionError("blocked_by_octopus_policy: os.stat dir_fd denied")
        fsym = _coerce_exact_bool(follow_symlinks, "follow_symlinks")
        clean_path = path if _TYPE(path) is int else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "stat", clean_path, fsym, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_os_lstat(path, *, dir_fd=None):
    try:
        if dir_fd is not None:
            raise PermissionError("blocked_by_octopus_policy: os.lstat dir_fd denied")
        clean_path = _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "lstat", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_os_access(path, mode, *, dir_fd=None, effective_ids=False, follow_symlinks=True):
    try:
        if dir_fd is not None:
            raise PermissionError("blocked_by_octopus_policy: os.access dir_fd denied")
        if _TYPE(mode) is not int:
            raise TypeError("an integer is required (got type " + _TYPE(mode).__name__ + ")")
        eids = _coerce_exact_bool(effective_ids, "effective_ids")
        fsym = _coerce_exact_bool(follow_symlinks, "follow_symlinks")
        clean_path = path if _TYPE(path) is int else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "access", clean_path, mode, eids, fsym, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_path_exists(path):
    try:
        clean_path = path if _TYPE(path) is int else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "path_exists", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_path_lexists(path):
    try:
        clean_path = path if _TYPE(path) is int else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "path_lexists", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_path_isfile(path):
    try:
        clean_path = path if _TYPE(path) is int else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "path_isfile", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_path_isdir(s):
    try:
        clean_path = s if _TYPE(s) is int else _coerce_stat_path(s)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "path_isdir", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_path_islink(path):
    try:
        clean_path = path if _TYPE(path) is int else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "path_islink", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_path_isjunction(path):
    try:
        clean_path = path if _TYPE(path) is int else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "path_isjunction", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_getfinalpathname(path, /):
    try:
        clean_path = _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "getfinalpathname", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_nt_findfirstfile(path, /):
    try:
        clean_path = _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "findfirstfile", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

class _StatWeakrefCleanup:
    __slots__ = ("_op", "_obj_id")

    def __new__(cls, op, obj_id):
        if cls is not _STAT_CLEANUP_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable stat cleanup")
        return _OBJECT_NEW(cls)

    def __init__(self, op, obj_id):
        _OBJECT_SETATTR(self, "_op", op)
        _OBJECT_SETATTR(self, "_obj_id", obj_id)

    def __call__(self, wr):
        if not _SYS_IS_FINALIZING():
            try:
                _LIST_APPEND(_STAT_GC_QUEUE, (self._op, self._obj_id))
            except BaseException:
                pass

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable stat cleanup")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable stat cleanup")

class _GuardedDirEntry:
    __slots__ = ("__weakref__",)

    def __new__(cls, *a, **kw):
        raise TypeError("cannot create 'DirEntry' instances")

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable DirEntry")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable DirEntry")

    @property
    def name(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_attr", self, "name", box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    @property
    def path(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_attr", self, "path", box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def __fspath__(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_attr", self, "path", box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def stat(self, *, follow_symlinks=True):
        try:
            fsym = _coerce_exact_bool(follow_symlinks, "follow_symlinks")
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_op", self, "stat", fsym, box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def is_file(self, *, follow_symlinks=True):
        try:
            fsym = _coerce_exact_bool(follow_symlinks, "follow_symlinks")
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_op", self, "is_file", fsym, box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def is_dir(self, *, follow_symlinks=True):
        try:
            fsym = _coerce_exact_bool(follow_symlinks, "follow_symlinks")
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_op", self, "is_dir", fsym, box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def is_symlink(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_op", self, "is_symlink", True, box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def is_junction(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_op", self, "is_junction", True, box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def inode(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "direntry_op", self, "inode", True, box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def __repr__(self):
        return "<DirEntry " + repr(self.name) + ">"

class _GuardedScandirIter:
    __slots__ = ("__weakref__",)

    def __new__(cls, *a, **kw):
        raise TypeError("cannot create 'ScandirIterator' instances")

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable ScandirIterator")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable ScandirIterator")

    def __iter__(self):
        return self

    def __next__(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "scandir_next", self, box)
            res = box[0]
            if res is None:
                raise StopIteration
            return res
        except StopIteration:
            raise
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def close(self):
        try:
            box = [None]
            _SYS_AUDIT("octopus.stat_op", "scandir_close", self, box)
            return box[0]
        except BaseException as exc:
            _strip_stat_exc(exc)
            raise exc from None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

def _guarded_os_scandir(path=None):
    try:
        if _TYPE(path) is int:
            raise PermissionError("blocked_by_octopus_policy: os.scandir fd denied")
        clean_path = "." if path is None else _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "scandir", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None

def _guarded_os_readlink(path, *, dir_fd=None):
    try:
        if dir_fd is not None:
            raise PermissionError("blocked_by_octopus_policy: os.readlink dir_fd denied")
        clean_path = _coerce_stat_path(path)
        box = [None]
        _SYS_AUDIT("octopus.stat_op", "readlink", clean_path, box)
        return box[0]
    except BaseException as exc:
        _strip_stat_exc(exc)
        raise exc from None
'''
    exec(compile(_stat_src, "<octopus_stat>", "exec"), _stat_plain)
    _STAT_GLOBALS = _FrozenDict(_stat_plain)
    _STAT_WARNREG_REF = dict.__getitem__(_STAT_GLOBALS, "__warningregistry__")
    _STAT_CLEANUP_CLS = _stat_plain["_StatWeakrefCleanup"]
    _GUARDED_DIRENTRY_CLS = _stat_plain["_GuardedDirEntry"]
    _SCANDIR_ITER_CLS = _stat_plain["_GuardedScandirIter"]

    def _rebind_st_fn(fn):
        nf = types.FunctionType(fn.__code__, _STAT_GLOBALS, fn.__name__, fn.__defaults__, None)
        if fn.__kwdefaults__ is not None:
            nf.__kwdefaults__ = dict(fn.__kwdefaults__)
        return nf

    _expected_stat_funcs = []
    _expected_stat_cls_attrs = []
    _stat_op_codes = []
    for _st_name, _st_is_op in (
        ("_has_mro_base", False),
        ("_strip_stat_exc", False),
        ("_extract_pathlib_str", False),
        ("_coerce_stat_path", False),
        ("_coerce_exact_bool", False),
        ("_guarded_os_stat", True),
        ("_guarded_os_lstat", True),
        ("_guarded_os_access", True),
        ("_guarded_os_scandir", True),
        ("_guarded_os_readlink", True),
        ("_guarded_nt_path_exists", True),
        ("_guarded_nt_path_lexists", True),
        ("_guarded_nt_path_isfile", True),
        ("_guarded_nt_path_isdir", True),
        ("_guarded_nt_path_islink", True),
        ("_guarded_nt_path_isjunction", True),
        ("_guarded_nt_getfinalpathname", True),
        ("_guarded_nt_findfirstfile", True),
    ):
        _st_fn = _rebind_st_fn(_stat_plain[_st_name])
        dict.__setitem__(_STAT_GLOBALS, _st_name, _st_fn)
        _expected_stat_funcs.append((_st_fn, _st_fn.__code__, _st_fn.__defaults__, _st_fn.__kwdefaults__))
        if _st_is_op:
            _stat_op_codes.append(_st_fn.__code__)

    for _st_cls, _st_methods, _st_op_methods in (
        (_STAT_CLEANUP_CLS, ("__init__", "__call__", "__setattr__", "__delattr__"), ()),
        (
            _GUARDED_DIRENTRY_CLS,
            ("__setattr__", "__delattr__", "__fspath__", "stat", "is_file", "is_dir", "is_symlink", "is_junction", "inode", "__repr__"),
            ("__fspath__", "stat", "is_file", "is_dir", "is_symlink", "is_junction", "inode"),
        ),
        (
            _SCANDIR_ITER_CLS,
            ("__setattr__", "__delattr__", "__iter__", "__next__", "close", "__enter__", "__exit__"),
            ("__next__", "close"),
        ),
    ):
        _snew_sm = _st_cls.__dict__["__new__"]
        _snew_fn = _rebind_st_fn(_snew_sm.__func__)
        _snew_bound = staticmethod(_snew_fn)
        setattr(_st_cls, "__new__", _snew_bound)
        _expected_stat_funcs.append((_snew_fn, _snew_fn.__code__, _snew_fn.__defaults__, _snew_fn.__kwdefaults__))
        _expected_stat_cls_attrs.append((_st_cls, "__new__", _snew_bound))
        for _mname in _st_methods:
            _mfn = _rebind_st_fn(_st_cls.__dict__[_mname])
            setattr(_st_cls, _mname, _mfn)
            _expected_stat_funcs.append((_mfn, _mfn.__code__, _mfn.__defaults__, _mfn.__kwdefaults__))
            _expected_stat_cls_attrs.append((_st_cls, _mname, _mfn))
            if _mname in _st_op_methods:
                _stat_op_codes.append(_mfn.__code__)

    for _de_pname in ("name", "path"):
        _de_prop = _GUARDED_DIRENTRY_CLS.__dict__[_de_pname]
        _de_get = _rebind_st_fn(_de_prop.fget)
        _de_new_prop = property(_de_get, None, None, _de_prop.__doc__)
        setattr(_GUARDED_DIRENTRY_CLS, _de_pname, _de_new_prop)
        _expected_stat_funcs.append((_de_get, _de_get.__code__, _de_get.__defaults__, _de_get.__kwdefaults__))
        _stat_op_codes.append(_de_get.__code__)
        _expected_stat_cls_attrs.append((_GUARDED_DIRENTRY_CLS, _de_pname, _de_new_prop))

    dict.__setitem__(_STAT_GLOBALS, "_STAT_CLEANUP_CLS", _STAT_CLEANUP_CLS)
    dict.__setitem__(_STAT_GLOBALS, "_GUARDED_DIRENTRY_CLS", _GUARDED_DIRENTRY_CLS)
    dict.__setitem__(_STAT_GLOBALS, "_SCANDIR_ITER_CLS", _SCANDIR_ITER_CLS)

    _GUARDED_OS_STAT = dict.__getitem__(_STAT_GLOBALS, "_guarded_os_stat")
    _GUARDED_OS_LSTAT = dict.__getitem__(_STAT_GLOBALS, "_guarded_os_lstat")
    _GUARDED_OS_ACCESS = dict.__getitem__(_STAT_GLOBALS, "_guarded_os_access")
    _GUARDED_OS_SCANDIR = dict.__getitem__(_STAT_GLOBALS, "_guarded_os_scandir")
    _GUARDED_OS_READLINK = dict.__getitem__(_STAT_GLOBALS, "_guarded_os_readlink") if _ORIG_OS_READLINK is not None else None
    _GUARDED_NT_PATH_EXISTS = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_path_exists") if _ORIG_NT_PATH_EXISTS is not None else None
    _GUARDED_NT_PATH_LEXISTS = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_path_lexists") if _ORIG_NT_PATH_LEXISTS is not None else None
    _GUARDED_NT_PATH_ISFILE = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_path_isfile") if _ORIG_NT_PATH_ISFILE is not None else None
    _GUARDED_NT_PATH_ISDIR = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_path_isdir") if _ORIG_NT_PATH_ISDIR is not None else None
    _GUARDED_NT_PATH_ISLINK = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_path_islink") if _ORIG_NT_PATH_ISLINK is not None else None
    _GUARDED_NT_PATH_ISJUNCTION = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_path_isjunction") if _ORIG_NT_PATH_ISJUNCTION is not None else None
    _GUARDED_NT_GETFINALPATHNAME = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_getfinalpathname") if _ORIG_NT_GETFINALPATHNAME is not None else None
    _GUARDED_NT_FINDFIRSTFILE = dict.__getitem__(_STAT_GLOBALS, "_guarded_nt_findfirstfile") if _ORIG_NT_FINDFIRSTFILE is not None else None

    _EXPECTED_STAT_ITEMS = tuple(
        (k, v) for k, v in dict.items(_STAT_GLOBALS) if k != "__warningregistry__"
    )
    _EXPECTED_STAT_LEN = dict.__len__(_STAT_GLOBALS)
    _STAT_OP_CODES = frozenset(_stat_op_codes)
    _STAT_ALL_CODES = _collect_nested_codes(_fn.__code__ for _fn, _, _, _ in _expected_stat_funcs)

    _pending_sqlite_conns = []
    _popen_lock = threading.Lock()
    _gc_map_lock = threading.Lock()
    _popen_tokens = {}
    _cedar_tl = threading.local()
    _sqlite_conn_map = {}
    _sqlite_cursor_map = {}
    _sqlite_raw_to_cursor = {}
    _sqlite_connect_pending = {}
    _scandir_map = {}
    _direntry_map = {}
    if _LIST2CMD_GLOBALS is not None:
        dict.__setitem__(_LIST2CMD_GLOBALS, "_GUARDED_DIRENTRY_CLS", _GUARDED_DIRENTRY_CLS)
        dict.__setitem__(_LIST2CMD_GLOBALS, "_DIRENTRY_MAP", _direntry_map)
        _EXPECTED_L2C_ITEMS = tuple(
            (k, v) for k, v in dict.items(_LIST2CMD_GLOBALS) if k != "__warningregistry__"
        )
    _audit_getframe_active = {}
    _audit_stack_check_active = {}
    _audit_deny_armed = {}
    _trace_unwind_armed = {}
    _signal_sig_map = {}

    _audit_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_audit__",
        "__warningregistry__": {},
        "_TYPE": type,
        "_TYPE_DICT_GET": _TYPE_DICT_GET,
        "_TYPE_MRO_GET": _TYPE_MRO_GET,
        "_MP_ITEMS": _MP_ITEMS,
        "_OBJECT_GETATTR": _OBJECT_GETATTR,
        "_MISSING": _MISSING,
        "_IS_WIN": _IS_WIN,
        "_OS_EXIT": _OS_EXIT,
        "_SYS_MOD": _SYS_MOD,
        "_SYS_AUDIT": _SYS_AUDIT,
        "_SYS_GETFRAME": _SYS_GETFRAME,
        "_FRAME_TYPE": _FRAME_TYPE,
        "_CODE_TYPE": _CODE_TYPE,
        "_GET_IDENT": _GET_IDENT,
        "_DICT_GET": _DICT_GET,
        "_DICT_POP": _DICT_POP,
        "_DICT_LEN": _DICT_LEN,
        "_DICT_GETITEM": _DICT_GETITEM,
        "_OBJECT_NEW": _OBJECT_NEW,
        "_OBJECT_SETATTR": object.__setattr__,
        "_WEAKREF": _WEAKREF,
        "_EXC_TB_SET": _EXC_TB_SET,
        "_EXC_CAUSE_SET": _EXC_CAUSE_SET,
        "_EXC_CTX_SET": _EXC_CTX_SET,
        "_OS_PATHLIKE": _OS_PATHLIKE,
        "_OS_DIRENTRY": _OS_DIRENTRY,
        "_OS_DIRENTRY_FSPATH": _OS_DIRENTRY_FSPATH,
        "_OS_DIRENTRY_PATH_DESC": _OS_DIRENTRY_PATH_DESC,
        "_EXACT_PATHLIB_TYPES": _EXACT_PATHLIB_TYPES,
        "_PATHLIB_META_MAP": _PATHLIB_META_MAP,
        "_PUREPATH_RAW_PATHS_DESC": _PUREPATH_RAW_PATHS_DESC,
        "_PUREPATH_STR_DESC": _PUREPATH_STR_DESC,
        "_PUREPATH_DRV_DESC": _PUREPATH_DRV_DESC,
        "_PUREPATH_ROOT_DESC": _PUREPATH_ROOT_DESC,
        "_PUREPATH_TAIL_DESC": _PUREPATH_TAIL_DESC,
        "_POSIX_PARSER_CFG": _POSIX_PARSER_CFG,
        "_NT_PARSER_CFG": _NT_PARSER_CFG,
        "_F_OSPATH_JOIN": _F_OSPATH_JOIN,
        "_F_OSPATH_BASENAME": _F_OSPATH_BASENAME,
        "_F_OSPATH_DIRNAME": _F_OSPATH_DIRNAME,
        "_OS_PATH_ISABS": _OS_PATH_ISABS,
        "_INIT_HOME_DIR": _INIT_HOME_DIR,
        "_INIT_USERNAME": _INIT_USERNAME,
        "_INIT_PWD_HOMES": _INIT_PWD_HOMES,
        "_OS_PATH_ABSPATH": _OS_PATH_ABSPATH,
        "_OS_PATH_REALPATH": _OS_PATH_REALPATH,
        "_OS_PATH_NORMPATH": _OS_PATH_NORMPATH,
        "_OS_PATH_NORMCASE": _OS_PATH_NORMCASE,
        "_STAT_S_ISDIR": _STAT_S_ISDIR,
        "_OS_PATHSEP": _OS_PATHSEP,
        "_OS_ENVIRON": _OS_ENVIRON,
        "_OS_ENVIRON_TYPE": _OS_ENVIRON_TYPE,
        "_OS_ENVIRON_DATA": _OS_ENVIRON_DATA,
        "_O_RDONLY": _O_RDONLY,
        "_O_WRONLY": _O_WRONLY,
        "_O_RDWR": _O_RDWR,
        "_O_CREAT": _O_CREAT,
        "_O_TRUNC": _O_TRUNC,
        "_O_APPEND": _O_APPEND,
        "_SOCK_CLS": _SOCK_CLS,
        "_AF_INET": _AF_INET,
        "_SOCK_STREAM": _SOCK_STREAM,
        "_JSON_C_ENC": _JSON_C_ENC,
        "_JSON_C_SCAN": _JSON_C_SCAN,
        "_JSON_DUMPS": _JSON_DUMPS,
        "_JSON_LOADS": _JSON_LOADS,
        "_SP_GLOBALS": _SP_GLOBALS,
        "_POPEN_INIT_CODE": _POPEN_INIT_CODE,
        "_POPEN_EXEC_CODE": _POPEN_EXEC_CODE,
        "_SUBPROCESS_FILE": _SUBPROCESS_FILE,
        "_LIST2CMD_GLOBALS": _LIST2CMD_GLOBALS,
        "_GUARDED_LIST2CMDLINE": _GUARDED_LIST2CMDLINE,
        "_L2C_CODES": _L2C_CODES,
        "_ADDHOOK_GLOBALS": _ADDHOOK_GLOBALS,
        "_ADDHOOK_CODE": _ADDHOOK_CODE,
        "_IMPORTLIB_EXT_GLOBALS": _IMPORTLIB_EXT_GLOBALS,
        "_IMPORTLIB_FILL_CACHE_CODE": _IMPORTLIB_FILL_CACHE_CODE,
        "_IMPORTLIB_PATH_STAT_CODE": _IMPORTLIB_PATH_STAT_CODE,
        "_LOCAL_HOSTS": _LOCAL_HOSTS,
        "_WIN_SYS_ROOT": _WIN_SYS_ROOT,
        "_STAT_GLOBALS_REF": _STAT_GLOBALS,
        "_STAT_CLEANUP_CLS_REF": _STAT_CLEANUP_CLS,
        "_GUARDED_DIRENTRY_CLS_REF": _GUARDED_DIRENTRY_CLS,
        "_SCANDIR_ITER_CLS_REF": _SCANDIR_ITER_CLS,
        "_SCANDIR_MAP": _scandir_map,
        "_DIRENTRY_MAP": _direntry_map,
        "_STAT_OP_CODES": _STAT_OP_CODES,
        "_STAT_CODES": _STAT_ALL_CODES,
        "_OS_W_OK": _OS_W_OK,
        "_ORIG_OS_STAT": _ORIG_OS_STAT,
        "_ORIG_OS_LSTAT": _ORIG_OS_LSTAT,
        "_ORIG_OS_ACCESS": _ORIG_OS_ACCESS,
        "_ORIG_OS_SCANDIR": _ORIG_OS_SCANDIR,
        "_ORIG_OS_READLINK": _ORIG_OS_READLINK,
        "_ORIG_NT_PATH_EXISTS": _ORIG_NT_PATH_EXISTS,
        "_ORIG_NT_PATH_LEXISTS": _ORIG_NT_PATH_LEXISTS,
        "_ORIG_NT_PATH_ISFILE": _ORIG_NT_PATH_ISFILE,
        "_ORIG_NT_PATH_ISDIR": _ORIG_NT_PATH_ISDIR,
        "_ORIG_NT_PATH_ISLINK": _ORIG_NT_PATH_ISLINK,
        "_ORIG_NT_PATH_ISJUNCTION": _ORIG_NT_PATH_ISJUNCTION,
        "_ORIG_NT_GETFINALPATHNAME": _ORIG_NT_GETFINALPATHNAME,
        "_ORIG_NT_FINDFIRSTFILE": _ORIG_NT_FINDFIRSTFILE,
        "_CUR_PID_STR": str(os.getpid()),
        "_ZIPIMPORT_GLOBALS": _ZIPIMPORT_GLOBALS,
        "_ZIPIMPORT_READ_DIR_CODE": _ZIPIMPORT_READ_DIR_CODE,
        "_SQLITE_ATTACH": _SQLITE_ATTACH,
        "_SQLITE_FUNCTION": _SQLITE_FUNCTION,
        "_SQLITE_OK": _SQLITE_OK,
        "_SQLITE_DENY": _SQLITE_DENY,
        "_SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION": _SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION,
        "_SQLITE_CONNECT_POS_NAMES": _SQLITE_CONNECT_POS_NAMES,
        "_ORIG_SQLITE_CONNECT": _ORIG_SQLITE_CONNECT,
        "_ORIG_SQLITE_CONN": _ORIG_SQLITE_CONN,
        "_ORIG_SQLITE_CURSOR": _ORIG_SQLITE_CURSOR,
        "_ORIG_SQLITE_ROW": _ORIG_SQLITE_ROW,
        "_SQLITE_CONVERTERS": _SQLITE_CONVERTERS,
        "_EXPECTED_SQLITE_CONVERTERS": _EXPECTED_SQLITE_CONVERTERS,
        "_SQLITE_ADAPTERS": _SQLITE_ADAPTERS,
        "_EXPECTED_SQLITE_ADAPTERS": _EXPECTED_SQLITE_ADAPTERS,
        "_SQLITE_OPT_UNICODE": _SQLITE_OPT_UNICODE,
        "_SQLITE_GLOBALS": _SQLITE_GLOBALS,
        "_SQLITE_WRAPPER_CLS": _SQLITE_WRAPPER_CLS,
        "_SQLITE_CURSOR_CLS": _SQLITE_CURSOR_CLS,
        "_SQLITE_CLEANUP_CLS": _SQLITE_CLEANUP_CLS,
        "_SQLITE_OP_CODES": _SQLITE_OP_CODES,
        "_SQLITE_CODES": _SQLITE_ALL_CODES,
        "_SQLITE_CONN_MAP": _sqlite_conn_map,
        "_SQLITE_CURSOR_MAP": _sqlite_cursor_map,
        "_SQLITE_RAW_TO_CURSOR": _sqlite_raw_to_cursor,
        "_SQLITE_CONNECT_PENDING": _sqlite_connect_pending,
        "_SIGNAL_GLOBALS_REF": _SIGNAL_GLOBALS,
        "_SIGNAL_HANDLER_CLS_REF": _SIGNAL_HANDLER_CLS,
        "_SIGNAL_OP_CODES": _SIGNAL_OP_CODES,
        "_SIGNAL_CODES": _SIGNAL_ALL_CODES,
        "_SIGNAL_SIG_MAP": _signal_sig_map,
        "_ORIG_SIGNAL_SIGNAL": _ORIG_SIGNAL_SIGNAL,
        "_ORIG_SIGNAL_GETSIGNAL": _ORIG_SIGNAL_GETSIGNAL,
        "_DEFAULT_INT_HANDLER": _DEFAULT_INT_HANDLER,
        "_TRACE_GLOBALS_REF": _TRACE_GLOBALS,
        "_TRACE_WRAPPER_CLS_REF": _TRACE_WRAPPER_CLS,
        "_MON_CB_CLS_REF": _MON_CB_CLS,
        "_TRACE_OP_CODES": _TRACE_OP_CODES,
        "_TRACE_UNWIND_CODES": _TRACE_UNWIND_CODES,
        "_TRACE_CODES": _TRACE_ALL_CODES,
        "_ALL_INTERNAL_CODES_REF": (),
        "_ORIG_SYS_SETTRACE": _ORIG_SYS_SETTRACE,
        "_ORIG_SYS_GETTRACE": _ORIG_SYS_GETTRACE,
        "_ORIG_SYS_SETPROFILE": _ORIG_SYS_SETPROFILE,
        "_ORIG_SYS_GETPROFILE": _ORIG_SYS_GETPROFILE,
        "_ORIG_SYS_SETTRACEALL": _ORIG_SYS_SETTRACEALL,
        "_ORIG_SYS_SETPROFILEALL": _ORIG_SYS_SETPROFILEALL,
        "_ORIG_MON_REGISTER": _ORIG_MON_REGISTER,
        "_ORIG_MON_SET_LOCAL": _ORIG_MON_SET_LOCAL,
        "_HANDLE_TRACE_OP_CODE": None,
        "_HANDLE_STAT_OP_CODE": None,
        "_AUDIT_GETFRAME_ACTIVE": _audit_getframe_active,
        "_AUDIT_STACK_CHECK_ACTIVE": _audit_stack_check_active,
        "_AUDIT_DENY_ARMED": _audit_deny_armed,
        "_TRACE_UNWIND_ARMED": _trace_unwind_armed,
        "_GATE_GLOBALS_REF": _GATE_GLOBALS,
        "_GATE_HOOK_REF": _GATE_HOOK,
        "_GATE_CODE_REF": _GATE_CODE,
        "_GATE_TL": _gate_tl,
        "_GATE_GETATTR": _gate_getattr,
        "_GATE_SETATTR": _gate_setattr,
        "_INSTALL_CODE": _INSTALL_CODE,
        "_WATCHDOG_GLOBALS_REF": None,
        "_WATCHDOG_CODE_REF": None,
        "_PENDING_SQLITE_CONNS": _pending_sqlite_conns,
        "_POPEN_LOCK": _popen_lock,
        "_GC_MAP_LOCK": _gc_map_lock,
        "_LIST_POP": _LIST_POP,
        "_STAT_GC_QUEUE_REF": _stat_gc_queue,
        "_SQLITE_GC_QUEUE_REF": _sqlite_gc_queue,
        "_POPEN_TOKENS": _popen_tokens,
        "_CEDAR_PORT": _OCTOPUS_CFG.get("cedar_ipc_port"),
        "_CEDAR_PIPE": _OCTOPUS_CFG.get("cedar_ipc_pipe") or "",
        "_CEDAR_PIPE_NORM": (_OCTOPUS_CFG.get("cedar_ipc_pipe") or "").replace("\\", "/").lower(),
        "_CEDAR_ACTIVE": bool(_OCTOPUS_CFG.get("cedar_ipc_port") or _OCTOPUS_CFG.get("cedar_ipc_pipe")),
        "_WIN_AC_BLOCKED_PROXY_PORT": _OCTOPUS_CFG.get("win_ac_blocked_proxy_port"),
        "_QUERY_CEDAR_IPC_CODE": None,
        "_CHECK_PINNED_SUBTREE_CODE": None,
        "_CEDAR_PIPE_CLS": None,
        "_WINAPI_CREATEFILE": _WINAPI_CREATEFILE,
        "_WINAPI_READFILE": _WINAPI_READFILE,
        "_WINAPI_WRITEFILE": _WINAPI_WRITEFILE,
        "_WINAPI_CLOSEHANDLE": _WINAPI_CLOSEHANDLE,
        "_WINAPI_WAITNAMEDPIPE": _WINAPI_WAITNAMEDPIPE,
        "_WINAPI_GENERIC_RW": _WINAPI_GENERIC_RW,
        "_WINAPI_OPEN_EXISTING": _WINAPI_OPEN_EXISTING,
        "_CEDAR_TOKEN": _OCTOPUS_CFG.get("cedar_ipc_token") or "",
        "_CEDAR_HAS_FS_READ_FORBID": bool(_OCTOPUS_CFG.get("cedar_has_fs_read_forbid", False)),
        "_CEDAR_TL": _cedar_tl,
        "_ALLOW_WRITE": (),
        "_DENY_RESOLVED": (),
        "_DENY_RAW": tuple(_OCTOPUS_CFG["deny_raw"]),
        "_DENY_RAW_PATTERNS": (),
        "_ENFORCE_WRITE": bool(_OCTOPUS_CFG["enforce_allow_write"]),
        "_HAS_FS_RESTRICTIONS": bool(_OCTOPUS_CFG["has_fs_restrictions"]),
        "_CMD_ALLOW": frozenset(_OCTOPUS_CFG["commands_allow"]),
        "_CMD_DENY": frozenset(_OCTOPUS_CFG["commands_deny"]),
        "_GUARD_DIR": "",
        "_GUARD_DIR_LEX": "",
        "_PY_PREFIXES": (),
        "_INIT_SYS_PATH": (),
        "_ENTRY_SCRIPT_PATHS": (),
        "_INIT_PYTHONHOME": None,
        "_INIT_PYTHONNOUSERSITE": None,
        "_AUDIT_GLOBALS": None,
        "_AUDIT_CODES": (),
        "_SENSITIVE_NEEDLES": (
            "/.ssh/", "/.ssh", "/.aws/", "/.aws", "/.kube/config", "/.config/gcloud",
            "/.azure/", "/.cargo/credentials", "/.netrc", "/.git-credentials",
            "/.npmrc", "/.pypirc", "/.vault-token", "/.terraformrc", "/.databrickscfg",
            "/.pgpass", "/etc/shadow", "/etc/sudoers", "ntuser.dat", "usrclass.dat",
            "docker.sock", "pipe/docker_engine", "pipe/octopus-cedar-", "microsoft/credentials", "microsoft/protect",
            "ebwebview", "/system32/config/sam", "/system32/config/system", "/system32/config/security",
        ),
    }

    _audit_src = '''
def _has_mro_base(obj, cls):
    for _b in _TYPE_MRO_GET(_TYPE(obj)):
        if _b is cls:
            return True
    return False

def _sq_key_eq(k, ek):
    if k is ek:
        return True
    kt = _TYPE(k)
    ekt = _TYPE(ek)
    if kt is not ekt:
        return False
    if kt is str:
        return k == ek
    if kt is tuple and len(k) == len(ek):
        for i in range(len(k)):
            if not _sq_key_eq(k[i], ek[i]):
                return False
        return True
    return False

def _get_env_ci(env_map, target_name):
    if env_map is _OS_ENVIRON:
        if (
            _TYPE(_OS_ENVIRON) is not _OS_ENVIRON_TYPE
            or _OBJECT_GETATTR(_OS_ENVIRON, "_data") is not _OS_ENVIRON_DATA
            or _TYPE(_OS_ENVIRON_DATA) is not dict
        ):
            raise PermissionError("blocked_by_octopus_policy: tampered os.environ._data denied")
        for k, v in dict.items(_OS_ENVIRON_DATA):
            _kt = _TYPE(k)
            _vt = _TYPE(v)
            if (_kt is not str and _kt is not bytes) or (_vt is not str and _vt is not bytes):
                raise PermissionError("blocked_by_octopus_policy: non-exact os.environ key/value type denied")
            ks = _to_str(k)
            if ks and (ks == target_name or (_IS_WIN and str.upper(ks) == target_name)):
                return _to_str(v)
        return None
    if _TYPE(env_map) is not dict:
        raise PermissionError("blocked_by_octopus_policy: custom env mapping type denied")
    for k, v in dict.items(env_map):
        _kt = _TYPE(k)
        _vt = _TYPE(v)
        if (_kt is not str and _kt is not bytes) or (_vt is not str and _vt is not bytes):
            raise PermissionError("blocked_by_octopus_policy: non-exact env key/value type denied")
        ks = _to_str(k)
        if ks and (ks == target_name or (_IS_WIN and str.upper(ks) == target_name)):
            return _to_str(v)
    return None

def _extract_pathlib_str(x, t):
    _meta = None
    for _item in _PATHLIB_META_MAP:
        if t is _item[0]:
            _meta = _item
            break
    if _meta is None:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    _is_posix = _meta[1]
    _exp_attrs = _meta[2]
    for _b in _TYPE_MRO_GET(t):
        _bd = _TYPE_DICT_GET(_b)
        for _k in _bd:
            if _TYPE(_k) is not str:
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    for _aname, _exp_v in _exp_attrs:
        _found = _MISSING
        for _b in _TYPE_MRO_GET(t):
            _bd = _TYPE_DICT_GET(_b)
            for _k, _v in _MP_ITEMS(_bd):
                if _TYPE(_k) is str and _k == _aname:
                    _found = _v
                    break
            if _found is not _MISSING:
                break
        if _found is not _exp_v:
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike descriptor denied")
    if _PUREPATH_RAW_PATHS_DESC is None:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    try:
        _raw_paths = _PUREPATH_RAW_PATHS_DESC.__get__(x)
    except AttributeError:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied") from None
    if _TYPE(_raw_paths) is not list:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    for _el in list.__iter__(_raw_paths):
        if _TYPE(_el) is not str:
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    _p_join, _p_splitroot, _p_splitdrive, _p_sep, _p_altsep = _POSIX_PARSER_CFG if _is_posix else _NT_PARSER_CFG
    _n = list.__len__(_raw_paths)
    if _n == 0:
        _raw_p = ""
    elif _n == 1:
        _raw_p = _raw_paths[0]
    else:
        _raw_p = _p_join(*_raw_paths)
    if _TYPE(_raw_p) is not str:
        raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if not _raw_p:
        _drv, _root, _tail = "", "", []
    else:
        if _p_altsep:
            _raw_p = _raw_p.replace(_p_altsep, _p_sep)
        _drv, _root, _rel = _p_splitroot(_raw_p)
        if not _root and _drv.startswith(_p_sep) and not _drv.endswith(_p_sep):
            _drv_parts = _drv.split(_p_sep)
            if len(_drv_parts) == 4 and _drv_parts[2] not in "?.":
                _root = _p_sep
            elif len(_drv_parts) == 6:
                _root = _p_sep
        _tail = [_seg for _seg in _rel.split(_p_sep) if _seg and _seg != "."]
    if _drv or _root:
        _res = _drv + _root + _p_sep.join(_tail)
    elif _tail and _p_splitdrive(_tail[0])[0]:
        _res = _p_sep.join(["."] + _tail)
    else:
        _res = _p_sep.join(_tail)
    _computed = _res or "."
    if _PUREPATH_STR_DESC is not None:
        try:
            _s_val = _PUREPATH_STR_DESC.__get__(x)
        except AttributeError:
            _s_val = _MISSING
        if _s_val is not _MISSING:
            if _TYPE(_s_val) is not str or _s_val != _computed:
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_DRV_DESC is not None:
        try:
            _d_val = _PUREPATH_DRV_DESC.__get__(x)
        except AttributeError:
            _d_val = _MISSING
        if _d_val is not _MISSING and (_TYPE(_d_val) is not str or _d_val != _drv):
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_ROOT_DESC is not None:
        try:
            _r_val = _PUREPATH_ROOT_DESC.__get__(x)
        except AttributeError:
            _r_val = _MISSING
        if _r_val is not _MISSING and (_TYPE(_r_val) is not str or _r_val != _root):
            raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    if _PUREPATH_TAIL_DESC is not None:
        try:
            _t_val = _PUREPATH_TAIL_DESC.__get__(x)
        except AttributeError:
            _t_val = _MISSING
        if _t_val is not _MISSING:
            if _TYPE(_t_val) is not list or list.__len__(_t_val) != len(_tail):
                raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
            for _idx, _tv in enumerate(list.__iter__(_t_val)):
                if _TYPE(_tv) is not str or _tv != _tail[_idx]:
                    raise PermissionError("blocked_by_octopus_policy: tampered PathLike object denied")
    return _computed

def _to_str(x):
    t = _TYPE(x)
    if t is str:
        return x
    if t is bytes:
        return bytes.decode(x, "utf-8", errors="replace")
    if _has_mro_base(x, str) or _has_mro_base(x, bytes):
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    if _OS_DIRENTRY is not None and t is _OS_DIRENTRY:
        if t.__fspath__ is not _OS_DIRENTRY_FSPATH or t.path is not _OS_DIRENTRY_PATH_DESC:
            raise PermissionError("blocked_by_octopus_policy: tampered DirEntry descriptor denied")
        v = _OS_DIRENTRY_FSPATH(x)
        vt = _TYPE(v)
        if vt is str:
            return v
        if vt is bytes:
            return bytes.decode(v, "utf-8", errors="replace")
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    if _GUARDED_DIRENTRY_CLS_REF is not None and t is _GUARDED_DIRENTRY_CLS_REF:
        _de = _DICT_GET(_DIRENTRY_MAP, id(x))
        if _de is None or _de[0]() is not x:
            raise PermissionError("blocked_by_octopus_policy: invalid DirEntry object")
        v = _de[3]
        vt = _TYPE(v)
        if vt is str:
            return v
        if vt is bytes:
            return bytes.decode(v, "utf-8", errors="replace")
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    if any(t is _pt for _pt in _EXACT_PATHLIB_TYPES):
        return _extract_pathlib_str(x, t)
    if _OS_PATHLIKE is not None and _has_mro_base(x, _OS_PATHLIKE):
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    for _b in _TYPE_MRO_GET(t):
        _bd = _TYPE_DICT_GET(_b)
        for _k in _bd:
            if _TYPE(_k) is not str or _k == "__fspath__":
                raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    return None

def _pct_unquote(s):
    if "%" not in s:
        return s
    out = bytearray()
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "%" and i + 2 < n:
            hx = s[i + 1:i + 3]
            try:
                out.append(int(hx, 16))
                i += 3
                continue
            except ValueError:
                pass
        out.extend(s[i].encode("utf-8"))
        i += 1
    return out.decode("utf-8", errors="replace")

def _safe_expanduser(p):
    if _TYPE(p) is not str or not p.startswith("~"):
        return p
    if _IS_WIN:
        i, n = 1, len(p)
        while i < n and p[i] not in (chr(92), "/"):
            i += 1
        if _INIT_HOME_DIR is None:
            return p
        userhome = _INIT_HOME_DIR
        if i != 1:
            target_user = p[1:i]
            if target_user != _INIT_USERNAME:
                if _INIT_USERNAME != _F_OSPATH_BASENAME(userhome):
                    return p
                userhome = _F_OSPATH_JOIN(_F_OSPATH_DIRNAME(userhome), target_user)
        return userhome + p[i:]
    i = p.find("/", 1)
    if i < 0:
        i = len(p)
    if i == 1:
        if _INIT_HOME_DIR is None:
            return p
        userhome = _INIT_HOME_DIR
    else:
        target_user = p[1:i]
        userhome = _DICT_GET(_INIT_PWD_HOMES, target_user)
        if userhome is None:
            return p
    userhome = userhome.rstrip("/")
    return (userhome + p[i:]) or "/"

def _is_local_unc_host(host):
    if _TYPE(host) is not str:
        return False
    h = host.strip().lower().rstrip(".")
    if not h:
        return False
    if h.startswith("[") and h.endswith("]") and len(h) >= 2:
        h = h[1:-1]
    if "%" in h:
        h = h.split("%", 1)[0]
    if h in _LOCAL_HOSTS or (h + ".") in _LOCAL_HOSTS:
        return True
    if h.startswith("127.") and all(c.isdigit() or c == "." for c in h):
        return True
    if h.startswith("::ffff:127.") and all(c.isdigit() or c == "." for c in h[7:]):
        return True
    if h.endswith(".ipv6-literal.net"):
        pfx = h[:-len(".ipv6-literal.net")]
        if pfx in ("0--1", "0-0-0-0-0-0-0-1", "0-0-0-0-0-0-0-0"):
            return True
    return False

def _is_unc_admin_share(s):
    if not _IS_WIN or _TYPE(s) is not str or not s.startswith("//"):
        return False
    parts = s[2:].split("/", 2)
    if len(parts) < 2:
        return False
    share = parts[1].rstrip(". ")
    return bool(share) and share.endswith("$")

def _is_raw_admin_or_ipc_share(s):
    if not _IS_WIN or _TYPE(s) is not str:
        return False
    t = s.replace("\\\\", "/")
    tl = t.lower()
    if tl.startswith("//?/unc/") or tl.startswith("//./unc/"):
        t = "//" + t[8:]
    if not t.startswith("//"):
        return False
    parts = t[2:].split("/", 2)
    if len(parts) < 2:
        return False
    share = parts[1].rstrip(". ").lower()
    return share in ("admin$", "ipc$")

def _strip_win_verbatim(s):
    if not _IS_WIN or _TYPE(s) is not str:
        return s
    t = s.replace("\\\\", "/")
    tl = t.lower()
    for gp in ("//?/global/", "//./global/"):
        if tl.startswith(gp):
            t = "//" + gp[2:4] + t[len(gp):]
            tl = t.lower()
            break
    if tl.startswith("//?/unc/") or tl.startswith("//./unc/"):
        t = "//" + t[8:]
    elif tl.startswith("//?/"):
        t = t[4:]
    elif tl.startswith("//./") and len(t) >= 6 and t[4].isalpha() and t[5] == ":":
        t = t[4:]
    if t.startswith("//"):
        parts = t[2:].split("/", 2)
        if len(parts) >= 2 and _is_local_unc_host(parts[0]):
            share = parts[1]
            tail = parts[2] if len(parts) >= 3 else ""
            if len(share) == 2 and share[0].isalpha() and share[1] == "$":
                return share[0] + ":/" + tail
            if share.lower() == "admin$":
                return _WIN_SYS_ROOT + ("/" + tail if tail else "")
    return t

def _norm_pair(p):
    p = _to_str(p)
    if _TYPE(p) is not str:
        return None, None
    expanded = _safe_expanduser(p)
    try:
        abs_p = _OS_PATH_ABSPATH(expanded)
    except Exception:
        abs_p = expanded
    if _IS_WIN:
        abs_s = abs_p.replace("\\\\", "/")
        pre = _strip_win_verbatim(abs_s)
        if ".." in pre or "/." in pre or "//" in pre or pre.endswith("/") or pre != abs_s:
            try:
                lex_raw = _OS_PATH_NORMPATH(pre)
            except Exception:
                lex_raw = pre
            lex_p = _strip_win_verbatim(lex_raw.replace("\\\\", "/")).lower()
        else:
            lex_p = pre.lower()
        try:
            real_arg = abs_p if pre == abs_s else _OS_PATH_ABSPATH(pre)
            real = _OS_PATH_REALPATH(real_arg)
        except Exception:
            real = pre
        norm_p = _strip_win_verbatim(real.replace("\\\\", "/")).lower()
        return norm_p, lex_p
    try:
        real = _OS_PATH_REALPATH(abs_p)
    except Exception:
        real = abs_p
    return real, abs_p

def _norm(p):
    norm_p, _ = _norm_pair(p)
    return norm_p

def _full_lex_norm(p):
    p = _to_str(p)
    if _TYPE(p) is not str:
        return None
    expanded = _safe_expanduser(p)
    try:
        abs_p = _OS_PATH_ABSPATH(expanded)
    except Exception:
        abs_p = expanded
    if _IS_WIN:
        abs_s = abs_p.replace("\\\\", "/")
        pre = _strip_win_verbatim(abs_s)
        if ".." in pre or "/." in pre or "//" in pre or pre.endswith("/") or pre != abs_s:
            try:
                pre = _OS_PATH_NORMPATH(pre)
            except Exception:
                pass
        return _strip_win_verbatim(pre.replace("\\\\", "/")).lower()
    return abs_p

def _cedar_path(p, use_realpath):
    p = _to_str(p)
    if _TYPE(p) is not str:
        return None
    expanded = _safe_expanduser(p)
    try:
        abs_p = _OS_PATH_ABSPATH(expanded)
    except Exception:
        abs_p = expanded
    if _IS_WIN:
        abs_s = abs_p.replace("\\\\", "/")
        pre = _strip_win_verbatim(abs_s)
        if use_realpath:
            try:
                real_arg = abs_p if pre == abs_s else _OS_PATH_ABSPATH(pre)
                real = _OS_PATH_REALPATH(real_arg)
            except Exception:
                real = pre
            return _strip_win_verbatim(real.replace("\\\\", "/"))
        if ".." in pre or "/." in pre or "//" in pre or pre.endswith("/") or pre != abs_s:
            try:
                pre = _OS_PATH_NORMPATH(pre)
            except Exception:
                pass
        return _strip_win_verbatim(pre.replace("\\\\", "/"))
    if use_realpath:
        try:
            return _OS_PATH_REALPATH(abs_p)
        except Exception:
            return abs_p
    return abs_p

def _raw_norm(p):
    p = _to_str(p)
    if _TYPE(p) is not str:
        return ""
    return p.replace("\\\\", "/").lower()

def _strip_win_prefix_for_ads(s):
    t = s.replace("\\\\", "/")
    tl = t.lower()
    for pfx in ("//?/global/unc/", "//./global/unc/", "//?/unc/", "//./unc/", "//?/global/", "//./global/", "//?/", "//./"):
        if tl.startswith(pfx):
            t = t[len(pfx):]
            break
    if len(t) >= 2 and t[0].isalpha() and t[1] == ":":
        t = t[2:]
    return t

def _has_ntfs_ads(raw_or_norm):
    if not _IS_WIN or _TYPE(raw_or_norm) is not str:
        return False
    return ":" in _strip_win_prefix_for_ads(raw_or_norm)

def _strip_ads_segments(norm_path):
    if not _IS_WIN or _TYPE(norm_path) is not str:
        return norm_path
    drive = ""
    rest = norm_path
    if len(rest) >= 2 and rest[0].isalpha() and rest[1] == ":":
        drive = rest[:2]
        rest = rest[2:]
    segs = []
    for s in rest.split("/"):
        no_ads = s.split(":", 1)[0]
        if no_ads in (".", ".."):
            segs.append(no_ads)
        else:
            tr = no_ads.rstrip(". ")
            segs.append(no_ads if (not tr and no_ads) else tr)
    return drive + "/".join(segs)

def _under_dir(target, base):
    b = base.rstrip("/")
    if not b:
        return target == "/"
    return target == b or target.startswith(b + "/")

def _is_mandatory_write_deny(norm_path):
    clean = _strip_ads_segments(norm_path)
    segs = [s.split(":", 1)[0].rstrip(". ").lower() for s in clean.split("/") if s]
    if not segs:
        return False
    base = segs[-1]
    if base in (
        ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
        ".gitconfig", ".gitmodules", ".mcp.json", ".ripgreprc",
        "sitecustomize.py", "usercustomize.py",
    ) or base.endswith(".pth"):
        return True
    for i in range(len(segs)):
        if segs[i] in (".githooks", ".vscode", ".idea"):
            return True
        if i + 1 < len(segs) and segs[i] == ".git" and segs[i + 1] in ("hooks", "config", "modules"):
            return True
        if i + 1 < len(segs) and segs[i] == ".claude" and segs[i + 1] in ("commands", "agents"):
            return True
    return False

def _is_pinned_parent_write_deny(norm_path):
    if _is_mandatory_write_deny(norm_path):
        return True
    clean = _strip_ads_segments(norm_path)
    segs = [s.split(":", 1)[0].rstrip(". ").lower() for s in clean.split("/") if s]
    if not segs:
        return False
    return segs[-1] in (".git", ".githooks", ".vscode", ".idea", ".claude")

def _is_pinned_entry_name(name):
    n = name.split(":", 1)[0].rstrip(". ").lower()
    return (
        n in (
            ".git", ".githooks", ".vscode", ".idea", ".claude",
            ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
            ".gitconfig", ".gitmodules", ".mcp.json", ".ripgreprc",
            "sitecustomize.py", "usercustomize.py",
        )
        or n.endswith(".pth")
    )

def _check_pinned_subtree(raw_target, base_dir=None):
    if _TYPE(raw_target) is int:
        return
    norm_p, lex_p = _norm_pair(raw_target)
    if norm_p is None:
        return
    if _is_pinned_parent_write_deny(norm_p) or (lex_p and _is_pinned_parent_write_deny(lex_p)):
        raise PermissionError("blocked_by_octopus_policy: mandatory write-deny pinned parent protected")
    s = _to_str(raw_target)
    if _TYPE(s) is not str or not s:
        return
    expanded = _safe_expanduser(s)
    candidates = []
    if base_dir is not None and not _OS_PATH_ISABS(expanded):
        joined = _F_OSPATH_JOIN(base_dir, expanded)
        jn, jl = _norm_pair(joined)
        if (jn and _is_pinned_parent_write_deny(jn)) or (jl and _is_pinned_parent_write_deny(jl)):
            raise PermissionError("blocked_by_octopus_policy: mandatory write-deny pinned parent protected")
        candidates.append(joined)
    try:
        abs_p = _OS_PATH_ABSPATH(expanded)
    except Exception:
        abs_p = expanded
    if abs_p not in candidates:
        candidates.append(abs_p)
    try:
        real_p = _OS_PATH_REALPATH(abs_p)
        if real_p not in candidates:
            candidates.append(real_p)
    except Exception:
        pass
    for root_p in candidates:
        try:
            st = _ORIG_OS_LSTAT(root_p)
        except OSError:
            continue
        if not _STAT_S_ISDIR(st.st_mode):
            continue
        if _IS_WIN and ((getattr(st, "st_file_attributes", 0) & 0x0400) != 0):
            continue
        queue = [root_p]
        qi = 0
        visited = 0
        while qi < len(queue):
            cur = queue[qi]
            qi += 1
            try:
                it = _ORIG_OS_SCANDIR(cur)
            except OSError:
                continue
            try:
                for ent in it:
                    visited += 1
                    if _is_pinned_entry_name(ent.name):
                        raise PermissionError("blocked_by_octopus_policy: directory contains mandatory write-deny pinned parent")
                    try:
                        if ent.is_dir(follow_symlinks=False):
                            if _IS_WIN and hasattr(ent, "is_junction") and ent.is_junction():
                                continue
                            if not ent.is_symlink() and visited < 50000:
                                queue.append(ent.path)
                    except OSError:
                        pass
            finally:
                try:
                    it.close()
                except Exception:
                    pass

class _CedarPipeHandle:
    __slots__ = ("_box",)

    def __new__(cls, h):
        if cls is not _CEDAR_PIPE_CLS:
            raise PermissionError("blocked_by_octopus_policy: immutable Cedar pipe handle")
        return _OBJECT_NEW(cls)

    def __init__(self, h):
        _OBJECT_SETATTR(self, "_box", [h])

    def close(self):
        box = _OBJECT_GETATTR(self, "_box")
        h = box[0]
        if h is not None:
            box[0] = None
            try:
                _WINAPI_CLOSEHANDLE(h)
            except Exception:
                pass

    def __del__(self):
        try:
            box = _OBJECT_GETATTR(self, "_box")
            h = box[0]
            if h is not None:
                box[0] = None
                _WINAPI_CLOSEHANDLE(h)
        except Exception:
            pass

    def __setattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable Cedar pipe handle")

    def __delattr__(self, *a, **kw):
        raise PermissionError("blocked_by_octopus_policy: immutable Cedar pipe handle")

def _query_cedar_ipc(action, path_real, path_lex=None, args_joined=None, check_pinned_parent=False):
    if not _CEDAR_ACTIVE or not _CEDAR_TOKEN:
        return True, False, "cedar_inactive"
    req_obj = dict(
        token=_CEDAR_TOKEN,
        action=action,
        path=path_real,
    )
    if path_lex is not None:
        req_obj["raw_path"] = path_lex
    if args_joined is not None:
        req_obj["args_joined"] = args_joined
    if check_pinned_parent:
        req_obj["check_pinned_parent"] = True
    encoded = "".join(_JSON_C_ENC(req_obj, 0)) if _JSON_C_ENC is not None else _JSON_DUMPS(req_obj)
    payload = (encoded + "\\n").encode("utf-8")

    if _CEDAR_PIPE:
        for attempt in range(2):
            ph = getattr(_CEDAR_TL, "pipe", None)
            if _TYPE(ph) is not _CEDAR_PIPE_CLS:
                ph = None
            if ph is not None:
                h = _OBJECT_GETATTR(ph, "_box")[0]
                if h is None:
                    ph = None
            if ph is None:
                try:
                    h = None
                    for _w in range(5):
                        try:
                            h = _WINAPI_CREATEFILE(_CEDAR_PIPE, _WINAPI_GENERIC_RW, 0, 0, _WINAPI_OPEN_EXISTING, 0, 0)
                            break
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == 231 and _WINAPI_WAITNAMEDPIPE is not None and _w < 4:
                                _WINAPI_WAITNAMEDPIPE(_CEDAR_PIPE, 1000)
                                continue
                            raise
                    ph = _CEDAR_PIPE_CLS(h)
                    _CEDAR_TL.pipe = ph
                except Exception as exc:
                    _CEDAR_TL.pipe = None
                    if attempt == 1:
                        raise PermissionError("blocked_by_octopus_policy: Cedar IPC pipe evaluation unavailable: " + str(exc)) from None
                    continue
            else:
                h = _OBJECT_GETATTR(ph, "_box")[0]
            try:
                off = 0
                while off < len(payload):
                    written, _ = _WINAPI_WRITEFILE(h, payload[off:])
                    if not written:
                        raise OSError("cedar IPC pipe short write")
                    off += written
                chunks = []
                while True:
                    data, _ = _WINAPI_READFILE(h, 4096)
                    if not data:
                        raise OSError("cedar IPC pipe EOF")
                    nl = data.find(b"\\n")
                    if nl != -1:
                        chunks.append(data[:nl])
                        break
                    chunks.append(data)
                resp_txt = b"".join(chunks).decode("utf-8")
                resp = _JSON_C_SCAN(resp_txt, 0)[0] if _JSON_C_SCAN is not None else _JSON_LOADS(resp_txt)
                return bool(resp.get("allowed", False)), bool(resp.get("explicit_forbid", False)), str(resp.get("reason", "cedar_denied"))
            except Exception as exc:
                try:
                    ph.close()
                except Exception:
                    pass
                _CEDAR_TL.pipe = None
                if attempt == 1:
                    raise PermissionError("blocked_by_octopus_policy: Cedar IPC pipe evaluation failed: " + str(exc)) from None
        raise PermissionError("blocked_by_octopus_policy: Cedar IPC pipe evaluation failed")

    peer_target = ("127.0.0.1", int(_CEDAR_PORT))

    for attempt in range(2):
        sock = getattr(_CEDAR_TL, "sock", None)
        if sock is not None:
            if type(sock) is not _SOCK_CLS:
                sock = None
            else:
                try:
                    if _SOCK_CLS.getpeername(sock) != peer_target:
                        _SOCK_CLS.close(sock)
                        sock = None
                except Exception:
                    try:
                        _SOCK_CLS.close(sock)
                    except Exception:
                        pass
                    sock = None
        if sock is None:
            try:
                sock = _SOCK_CLS(_AF_INET, _SOCK_STREAM)
                _SOCK_CLS.settimeout(sock, 5.0)
                _SOCK_CLS.connect(sock, peer_target)
                _CEDAR_TL.sock = sock
            except Exception as exc:
                _CEDAR_TL.sock = None
                if attempt == 1:
                    raise PermissionError("blocked_by_octopus_policy: Cedar IPC evaluation unavailable: " + str(exc)) from None
                continue
        try:
            _SOCK_CLS.sendall(sock, payload)
            chunks = []
            while True:
                data = _SOCK_CLS.recv(sock, 4096)
                if not data:
                    raise OSError("cedar IPC EOF")
                nl = data.find(b"\\n")
                if nl != -1:
                    chunks.append(data[:nl])
                    break
                chunks.append(data)
            resp_txt = b"".join(chunks).decode("utf-8")
            resp = _JSON_C_SCAN(resp_txt, 0)[0] if _JSON_C_SCAN is not None else _JSON_LOADS(resp_txt)
            return bool(resp.get("allowed", False)), bool(resp.get("explicit_forbid", False)), str(resp.get("reason", "cedar_denied"))
        except Exception as exc:
            try:
                _SOCK_CLS.close(sock)
            except Exception:
                pass
            _CEDAR_TL.sock = None
            if attempt == 1:
                raise PermissionError("blocked_by_octopus_policy: Cedar IPC evaluation failed: " + str(exc)) from None
    raise PermissionError("blocked_by_octopus_policy: Cedar IPC evaluation failed")

def _query_cedar_fs(action, path_real, path_lex, check_pinned_parent=False):
    return _query_cedar_ipc(action, path_real, path_lex, None, check_pinned_parent)

def _check_path(raw_target, is_write, is_read=None, only_explicit_cedar_forbid=False, check_lexical=True, pre_norm=None, pre_lex=None, check_pinned_parent=False):
    if type(raw_target) is int:
        return
    if is_read is None:
        is_read = not is_write
    raw_l = _raw_norm(raw_target)
    if raw_l in ("nul", "/dev/null", "//./nul", "\\\\\\\\.\\\\nul"):
        return
    if pre_norm is not None:
        norm_p = pre_norm
        lex_p = pre_lex if pre_lex is not None else (_full_lex_norm(raw_target) or norm_p)
    else:
        norm_p, lex_p = _norm_pair(raw_target)
    if norm_p is None:
        return
    if lex_p is None:
        lex_p = norm_p
    if norm_p in ("/dev/null", "//./nul") or norm_p.endswith("/nul"):
        return
    if _IS_WIN and (_is_unc_admin_share(norm_p) or _is_raw_admin_or_ipc_share(raw_l) or _is_unc_admin_share(lex_p)):
        raise PermissionError("blocked_by_octopus_policy: Windows administrative UNC share denied")
    norm_no_ads = _strip_ads_segments(norm_p)
    raw_no_ads = _strip_ads_segments(raw_l)
    lex_no_ads = _strip_ads_segments(lex_p)
    for needle in _SENSITIVE_NEEDLES:
        if (
            norm_p.endswith(needle.rstrip("/"))
            or needle in norm_p
            or needle in raw_l
            or norm_no_ads.endswith(needle.rstrip("/"))
            or needle in norm_no_ads
            or needle in raw_no_ads
            or lex_p.endswith(needle.rstrip("/"))
            or needle in lex_p
            or lex_no_ads.endswith(needle.rstrip("/"))
            or needle in lex_no_ads
        ):
            raise PermissionError("blocked_by_octopus_policy: sensitive credential path access denied")
    for d in _DENY_RESOLVED:
        if (
            _under_dir(norm_p, d)
            or _under_dir(norm_no_ads, d)
            or _under_dir(lex_p, d)
            or _under_dir(lex_no_ads, d)
        ):
            raise PermissionError("blocked_by_octopus_policy: filesystem.deny path blocked")
    for d_raw in _DENY_RAW_PATTERNS:
        if (
            d_raw in norm_p
            or d_raw in raw_l
            or d_raw in norm_no_ads
            or d_raw in raw_no_ads
            or d_raw in lex_p
            or d_raw in lex_no_ads
        ):
            raise PermissionError("blocked_by_octopus_policy: filesystem.deny pattern blocked")
    if is_write:
        if _is_mandatory_write_deny(norm_p) or _is_mandatory_write_deny(lex_p):
            raise PermissionError("blocked_by_octopus_policy: mandatory write-deny target protected")
        if check_pinned_parent and (_is_pinned_parent_write_deny(norm_p) or _is_pinned_parent_write_deny(lex_p)):
            raise PermissionError("blocked_by_octopus_policy: mandatory write-deny pinned parent protected")
        if _has_ntfs_ads(norm_p) or _has_ntfs_ads(raw_l) or _has_ntfs_ads(lex_p):
            raise PermissionError("blocked_by_octopus_policy: NTFS alternate data stream denied")
        if _GUARD_DIR and (_under_dir(norm_p, _GUARD_DIR) or _under_dir(lex_p, _GUARD_DIR) or (_GUARD_DIR_LEX and _under_dir(lex_p, _GUARD_DIR_LEX))):
            raise PermissionError("blocked_by_octopus_policy: write to Octopus guard directory denied")
        if _ENFORCE_WRITE:
            _allowed_w = False
            for aw in _ALLOW_WRITE:
                if _under_dir(norm_p, aw):
                    _allowed_w = True
                    break
            if not _allowed_w:
                raise PermissionError("blocked_by_octopus_policy: write outside filesystem.allow_write denied")
    if _CEDAR_ACTIVE:
        is_clean_runtime_read = (not is_write) and (
            (
                _GUARD_DIR
                and _under_dir(norm_p, _GUARD_DIR)
                and (_under_dir(lex_p, _GUARD_DIR) or (_GUARD_DIR_LEX and _under_dir(lex_p, _GUARD_DIR_LEX)))
            )
            or (
                any(_under_dir(norm_p, px) for px in _PY_PREFIXES)
                and any(_under_dir(lex_p, px) for px in _PY_PREFIXES)
            )
        )
        if is_clean_runtime_read and not _CEDAR_HAS_FS_READ_FORBID:
            return
        effective_only_explicit = only_explicit_cedar_forbid or is_clean_runtime_read
        cedar_real = _cedar_path(raw_target, True) or norm_p
        cedar_lex = _cedar_path(raw_target, False) or cedar_real
        if is_write:
            allowed, explicit_forbid, reason = _query_cedar_fs("fs_write", cedar_real, cedar_lex, check_pinned_parent)
            if not allowed and (explicit_forbid or not only_explicit_cedar_forbid):
                raise PermissionError("blocked_by_octopus_policy: Cedar fs_write denied (" + reason + ")")
        if is_read:
            allowed, explicit_forbid, reason = _query_cedar_fs("fs_read", cedar_real, cedar_lex, False)
            if explicit_forbid or (not allowed and not effective_only_explicit):
                raise PermissionError("blocked_by_octopus_policy: Cedar fs_read denied (" + reason + ")")

def _check_sqlite_target(raw_target, uri_enabled=False):
    db_str = _to_str(raw_target)
    if db_str is None:
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    nul = chr(0)
    if nul in db_str:
        raise PermissionError("blocked_by_octopus_policy: null byte in sqlite target denied")
    if db_str == ":memory:":
        return db_str
    if uri_enabled and db_str.startswith("file:"):
        body = db_str[5:].split("#", 1)[0]
        path_part, _sep, query = body.partition("?")
        if path_part.startswith("//"):
            if path_part.startswith("///"):
                raw_path_part = path_part[3:] if _IS_WIN else path_part[2:]
            elif path_part.startswith("//localhost/"):
                raw_path_part = path_part[12:] if _IS_WIN else path_part[11:]
            else:
                raise PermissionError("blocked_by_octopus_policy: invalid sqlite uri authority")
        else:
            raw_path_part = path_part
        db_path = _pct_unquote(raw_path_part)
        if nul in db_path:
            raise PermissionError("blocked_by_octopus_policy: null byte in sqlite uri path denied")
        if _IS_WIN and len(db_path) >= 3 and db_path[0] == "/" and db_path[1].isalpha() and db_path[2] == ":":
            db_path = db_path[1:]
        if not path_part.startswith("//") and db_path == ":memory:":
            return db_str
        last_mode = None
        if query:
            for q in query.split("&"):
                if not q:
                    continue
                k_raw, eq, v_raw = q.partition("=")
                if not eq:
                    continue
                k = _pct_unquote(k_raw)
                v = _pct_unquote(v_raw)
                if nul in k or nul in v:
                    raise PermissionError("blocked_by_octopus_policy: null byte in sqlite uri query denied")
                if k == "mode":
                    last_mode = v
        if last_mode == "memory":
            return db_str
        is_ro = (last_mode == "ro")
        _check_path(db_path, not is_ro, True)
    else:
        _check_path(db_str, True, True)
    return db_str

def _sqlite_authorizer_check(action_code, arg1, arg2, uri_enabled):
    if action_code == _SQLITE_ATTACH:
        if type(arg1) is not str:
            return _SQLITE_DENY
        if arg1 == "":
            return _SQLITE_OK
        try:
            _check_sqlite_target(arg1, uri_enabled)
        except Exception:
            return _SQLITE_DENY
    elif action_code == _SQLITE_FUNCTION:
        if type(arg2) is str and arg2.lower() == "load_extension":
            return _SQLITE_DENY
    return _SQLITE_OK

def _sqlite_authorizer_uri(action_code, arg1, arg2, db_name, trigger_name):
    return _sqlite_authorizer_check(action_code, arg1, arg2, True)

def _sqlite_authorizer_no_uri(action_code, arg1, arg2, db_name, trigger_name):
    return _sqlite_authorizer_check(action_code, arg1, arg2, False)

def _drain_pending_sqlite_conns():
    if not _PENDING_SQLITE_CONNS:
        return
    keep = []
    while _PENDING_SQLITE_CONNS:
        item = _PENDING_SQLITE_CONNS.pop()
        if type(item) is tuple and len(item) == 2:
            c, u = item
        else:
            c, u = item, False
        if type(c) is not _ORIG_SQLITE_CONN:
            continue
        try:
            c.set_authorizer(_sqlite_authorizer_uri if u else _sqlite_authorizer_no_uri)
        except Exception:
            keep.append((c, u))
    if keep:
        _PENDING_SQLITE_CONNS.extend(keep[-64:])

def _drain_gc_cleanups():
    if not _STAT_GC_QUEUE_REF and not _SQLITE_GC_QUEUE_REF:
        return
    to_close = []
    dropped = []
    while _STAT_GC_QUEUE_REF or _SQLITE_GC_QUEUE_REF:
        while _STAT_GC_QUEUE_REF:
            try:
                item = _LIST_POP(_STAT_GC_QUEUE_REF)
            except IndexError:
                break
            if _TYPE(item) is not tuple or len(item) != 2:
                continue
            op, obj_id = item
            if _TYPE(op) is not str or _TYPE(obj_id) is not int:
                continue
            if op == "scandir_gc":
                with _GC_MAP_LOCK:
                    ent = _DICT_GET(_SCANDIR_MAP, obj_id)
                    if ent is not None and ent[0]() is None:
                        dropped_ent = _DICT_POP(_SCANDIR_MAP, obj_id, None)
                        if dropped_ent is not None:
                            to_close.append(dropped_ent[1])
                            dropped.append(dropped_ent)
            elif op == "direntry_gc":
                with _GC_MAP_LOCK:
                    ent = _DICT_GET(_DIRENTRY_MAP, obj_id)
                    if ent is not None and ent[0]() is None:
                        _DICT_POP(_DIRENTRY_MAP, obj_id, None)
        while _SQLITE_GC_QUEUE_REF:
            try:
                item = _LIST_POP(_SQLITE_GC_QUEUE_REF)
            except IndexError:
                break
            if _TYPE(item) is not tuple or len(item) != 3:
                continue
            op, id1, id2 = item
            if _TYPE(op) is not str or _TYPE(id1) is not int or _TYPE(id2) is not int:
                continue
            if op == "conn_cleanup":
                with _GC_MAP_LOCK:
                    e = _DICT_GET(_SQLITE_CONN_MAP, id1)
                    if e is not None and e[0]() is None:
                        dropped_e = _DICT_POP(_SQLITE_CONN_MAP, id1, None)
                        if dropped_e is not None:
                            to_close.append(dropped_e[1])
                            dropped.append(dropped_e)
            elif op == "cursor_cleanup":
                with _GC_MAP_LOCK:
                    e = _DICT_GET(_SQLITE_CURSOR_MAP, id1)
                    if e is not None and e[0]() is None:
                        dropped_e = _DICT_POP(_SQLITE_CURSOR_MAP, id1, None)
                        if dropped_e is not None:
                            dropped.append(dropped_e)
                    ce = _DICT_GET(_SQLITE_RAW_TO_CURSOR, id2)
                    if ce is not None and ce[0]() is None:
                        dropped_ce = _DICT_POP(_SQLITE_RAW_TO_CURSOR, id2, None)
                        if dropped_ce is not None:
                            dropped.append(dropped_ce)
        ent = dropped_ent = e = dropped_e = ce = dropped_ce = None
        dropped.clear()
        for raw_it in to_close:
            try:
                raw_it.close()
            except Exception:
                pass
        to_close.clear()

def _audit_check_sq_prim(v):
    t = _TYPE(v)
    if v is None or t is bool or t is int or t is float or t is str or t is bytes or t is bytearray:
        return
    raise PermissionError("blocked_by_octopus_policy: non-primitive sqlite3 parameter denied")

def _audit_check_sq_params(p):
    pt = _TYPE(p)
    if pt is dict:
        for k, v in dict.items(p):
            if _TYPE(k) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 parameter key denied")
            _audit_check_sq_prim(v)
        return
    if pt is tuple:
        for v in tuple.__iter__(p):
            _audit_check_sq_prim(v)
        return
    if pt is list:
        for v in list.__iter__(p):
            _audit_check_sq_prim(v)
        return
    raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 parameters denied")

def _parse_sqlite_connect_args(args, kwargs):
    if _TYPE(args) is not tuple or _TYPE(kwargs) is not dict:
        raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 connect args")
    if len(args) > 8:
        raise TypeError("connect() takes at most 8 positional arguments (" + str(len(args)) + " given)")
    if len(args) == 0 and "database" not in kwargs:
        raise TypeError("connect() missing required argument 'database' (pos 1)")
    clean_kw = {}
    for k, v in dict.items(kwargs):
        if _TYPE(k) is not str:
            raise TypeError("keywords must be strings")
        if k not in _SQLITE_CONNECT_POS_NAMES and k != "autocommit":
            raise PermissionError("blocked_by_octopus_policy: unexpected sqlite3 connect kwarg denied")
        clean_kw[k] = v
    for idx in range(len(args)):
        pname = _SQLITE_CONNECT_POS_NAMES[idx]
        if pname in clean_kw:
            raise TypeError("connect() got multiple values for argument '" + pname + "'")
        if idx > 0:
            clean_kw[pname] = args[idx]
    if len(args) > 0:
        db_arg = args[0]
        clean_args = (db_arg,)
    else:
        db_arg = clean_kw["database"]
        clean_args = ()
    clean_kw["factory"] = _ORIG_SQLITE_CONN
    if "timeout" in clean_kw:
        _tv = clean_kw["timeout"]
        if _TYPE(_tv) is not int and _TYPE(_tv) is not float:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 timeout denied")
    if "detect_types" in clean_kw and _TYPE(clean_kw["detect_types"]) is not int:
        raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 detect_types denied")
    if "isolation_level" in clean_kw:
        _iv = clean_kw["isolation_level"]
        if _iv is not None and _TYPE(_iv) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 isolation_level denied")
    if "check_same_thread" in clean_kw and _TYPE(clean_kw["check_same_thread"]) is not bool:
        raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 check_same_thread denied")
    if "cached_statements" in clean_kw and _TYPE(clean_kw["cached_statements"]) is not int:
        raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 cached_statements denied")
    if "autocommit" in clean_kw:
        _av = clean_kw["autocommit"]
        if _TYPE(_av) is not bool and _TYPE(_av) is not int:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 autocommit denied")
    if "uri" in clean_kw:
        if _TYPE(clean_kw["uri"]) is not bool:
            raise PermissionError("blocked_by_octopus_policy: non-bool sqlite3 uri denied")
        uri_enabled = clean_kw["uri"]
    else:
        uri_enabled = False
    return clean_args, clean_kw, db_arg, uri_enabled

def _get_sqlite_conn_entry(conn_wrapper):
    wid = id(conn_wrapper)
    with _GC_MAP_LOCK:
        entry = _DICT_GET(_SQLITE_CONN_MAP, wid)
    if entry is None or entry[0]() is not conn_wrapper:
        raise PermissionError("blocked_by_octopus_policy: invalid or unmapped sqlite3 Connection")
    return entry

def _get_sqlite_cursor_entry(cur_wrapper):
    cid = id(cur_wrapper)
    with _GC_MAP_LOCK:
        entry = _DICT_GET(_SQLITE_CURSOR_MAP, cid)
    if entry is None or entry[0]() is not cur_wrapper:
        raise PermissionError("blocked_by_octopus_policy: invalid or unmapped sqlite3 Cursor")
    return entry

def _wrap_sqlite_cursor(raw_cur, conn_wrapper):
    if _TYPE(raw_cur) is not _ORIG_SQLITE_CURSOR:
        raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 Cursor type denied")
    cur_w = _OBJECT_NEW(_SQLITE_CURSOR_CLS)
    cid = id(cur_w)
    rc_id = id(raw_cur)
    wr = _WEAKREF(cur_w, _SQLITE_CLEANUP_CLS("cursor_cleanup", cid, rc_id))
    with _GC_MAP_LOCK:
        _SQLITE_CURSOR_MAP[cid] = (wr, raw_cur, conn_wrapper)
        _SQLITE_RAW_TO_CURSOR[rc_id] = (wr, raw_cur)
    return cur_w

def _check_sqlite_conv_adapt():
    if (
        _DICT_LEN(_SQLITE_CONVERTERS) != len(_EXPECTED_SQLITE_CONVERTERS)
        or _DICT_LEN(_SQLITE_ADAPTERS) != len(_EXPECTED_SQLITE_ADAPTERS)
    ):
        raise PermissionError("blocked_by_octopus_policy: modified sqlite3 converters/adapters denied")
    for _idx, (_k, _v) in enumerate(dict.items(_SQLITE_CONVERTERS)):
        _ek, _ev = _EXPECTED_SQLITE_CONVERTERS[_idx]
        if not _sq_key_eq(_k, _ek) or _v is not _ev:
            raise PermissionError("blocked_by_octopus_policy: modified sqlite3 converters/adapters denied")
    for _idx, (_k, _v) in enumerate(dict.items(_SQLITE_ADAPTERS)):
        _ek, _ev = _EXPECTED_SQLITE_ADAPTERS[_idx]
        if not _sq_key_eq(_k, _ek) or _v is not _ev:
            raise PermissionError("blocked_by_octopus_policy: modified sqlite3 converters/adapters denied")

def _handle_sqlite_op(args):
    if _TYPE(args) is not tuple or not args:
        raise PermissionError("blocked_by_octopus_policy: malformed sqlite_op")
    op = args[0]
    if _TYPE(op) is not str:
        raise PermissionError("blocked_by_octopus_policy: non-exact sqlite_op")
    if op == "conn_init":
        _, conn_w, c_args, c_kwargs = args
        if not _has_mro_base(conn_w, _SQLITE_WRAPPER_CLS):
            raise TypeError("Connection must be subclass of sqlite3.Connection")
        wid = id(conn_w)
        with _GC_MAP_LOCK:
            existing = _DICT_GET(_SQLITE_CONN_MAP, wid)
        if existing is not None and existing[0]() is conn_w:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 Connection already initialized")
        clean_args, clean_kw, db_arg, uri_enabled = _parse_sqlite_connect_args(c_args, c_kwargs)
        db_str = _check_sqlite_target(db_arg, uri_enabled)
        db_norm = db_arg if _TYPE(db_arg) is bytes else db_str
        if clean_args:
            clean_args = (db_norm,) + clean_args[1:]
        else:
            clean_kw["database"] = db_norm
        tid = _GET_IDENT()
        _SQLITE_CONNECT_PENDING[tid] = (db_norm, uri_enabled)
        try:
            raw = _ORIG_SQLITE_CONNECT(*clean_args, **clean_kw)
        finally:
            _DICT_POP(_SQLITE_CONNECT_PENDING, tid, None)
        if _TYPE(raw) is not _ORIG_SQLITE_CONN:
            raise PermissionError("blocked_by_octopus_policy: unexpected sqlite3 Connection type")
        raw.set_authorizer(_sqlite_authorizer_uri if uri_enabled else _sqlite_authorizer_no_uri)
        if _PENDING_SQLITE_CONNS:
            _PENDING_SQLITE_CONNS[:] = [x for x in _PENDING_SQLITE_CONNS if (x[0] if _TYPE(x) is tuple else x) is not raw]
        wr = _WEAKREF(conn_w, _SQLITE_CLEANUP_CLS("conn_cleanup", wid, 0))
        with _GC_MAP_LOCK:
            _SQLITE_CONN_MAP[wid] = (wr, raw, uri_enabled)
    elif op == "conn_check_open":
        _, conn_w = args
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        _ = raw.total_changes
    elif op == "conn_cursor":
        _, conn_w, box = args
        if _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 cursor box")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        raw_cur = raw.cursor()
        box[0] = _wrap_sqlite_cursor(raw_cur, conn_w)
    elif op == "conn_exec":
        _, conn_w, mname, c_args, c_kwargs, box = args
        if _TYPE(mname) is not str or mname not in ("execute", "executemany", "executescript"):
            raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 exec method")
        if _TYPE(c_args) is not tuple or _TYPE(c_kwargs) is not dict or _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 exec args")
        if _DICT_LEN(c_kwargs) != 0:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 exec kwargs denied")
        if mname == "executescript":
            if len(c_args) != 1 or _TYPE(c_args[0]) is not str:
                raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 executescript args")
        elif mname == "execute":
            if not (1 <= len(c_args) <= 2) or _TYPE(c_args[0]) is not str:
                raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 execute args")
            if len(c_args) == 2:
                _audit_check_sq_params(c_args[1])
        else:
            if len(c_args) != 2 or _TYPE(c_args[0]) is not str or _TYPE(c_args[1]) is not list:
                raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 executemany args")
            for _sq_row in list.__iter__(c_args[1]):
                _audit_check_sq_params(_sq_row)
        _check_sqlite_conv_adapt()
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        raw_cur = getattr(raw, mname)(*c_args, **c_kwargs)
        box[0] = _wrap_sqlite_cursor(raw_cur, conn_w)
    elif op == "conn_get_rf":
        _, conn_w, box = args
        _get_sqlite_conn_entry(conn_w)
    elif op == "conn_set_rf":
        _, conn_w, use_c_row = args
        if _TYPE(use_c_row) is not bool:
            raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 row_factory flag")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        raw.row_factory = _ORIG_SQLITE_ROW if use_c_row else None
    elif op == "conn_setconfig":
        _, conn_w, cfg_op, enable, box = args
        if _TYPE(cfg_op) is not int or _TYPE(enable) is not bool or _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 setconfig args")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        if cfg_op == _SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION and enable:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 load_extension denied")
        box[0] = raw.setconfig(cfg_op, enable)
    elif op == "conn_enable_load_ext":
        _, conn_w, enabled = args
        if _TYPE(enabled) is not bool or enabled:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 load_extension denied")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        raw.enable_load_extension(False)
    elif op == "conn_backup":
        _, conn_w, target, b_args, b_kwargs = args
        if _TYPE(b_args) is not tuple or len(b_args) != 0 or _TYPE(b_kwargs) is not dict:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 backup args")
        for _bk, _bv in dict.items(b_kwargs):
            if _TYPE(_bk) is not str or _bk not in ("pages", "progress", "name", "sleep"):
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 backup kwarg denied")
            if _bk == "progress" and _bv is not None:
                raise PermissionError("blocked_by_octopus_policy: sqlite3 backup progress callback denied")
            if _bk == "pages" and _TYPE(_bv) is not int:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 backup pages denied")
            if _bk == "name" and _TYPE(_bv) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 backup name denied")
            if _bk == "sleep" and _TYPE(_bv) is not int and _TYPE(_bv) is not float:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 backup sleep denied")
        if not _has_mro_base(target, _SQLITE_WRAPPER_CLS):
            raise TypeError("target must be sqlite3.Connection")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        _, target_raw, _ = _get_sqlite_conn_entry(target)
        raw.backup(target_raw, *b_args, **b_kwargs)
    elif op == "conn_enter":
        _, conn_w = args
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        raw.__enter__()
    elif op == "conn_exit":
        _, conn_w, exc_args, box = args
        if _TYPE(exc_args) is not tuple or len(exc_args) != 3 or _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 exit args")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        box[0] = raw.__exit__(*exc_args)
    elif op == "conn_getattr":
        _, conn_w, name, box = args
        if _TYPE(name) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
        if _TYPE(box) is not list or len(box) != 2:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 getattr box")
        if name in (
            "set_authorizer", "load_extension", "enable_load_extension", "setconfig",
            "create_function", "create_aggregate", "create_window_function",
            "create_collation", "set_progress_handler", "set_trace_callback",
        ):
            raise PermissionError("blocked_by_octopus_policy: sqlite3 " + name + " cannot be accessed")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        val = getattr(raw, name)
        if _TYPE(val) is type:
            box[0] = False
            box[1] = val
        elif callable(val):
            box[0] = True
            box[1] = None
        else:
            if val is raw or getattr(val, "__self__", None) is raw:
                raise PermissionError("blocked_by_octopus_policy: raw sqlite3 object access denied")
            box[0] = False
            box[1] = val
    elif op == "conn_call":
        _, conn_w, name, c_args, c_kwargs, box = args
        if _TYPE(name) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
        if _TYPE(c_args) is not tuple or _TYPE(c_kwargs) is not dict or _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 call args")
        if name in (
            "set_authorizer", "load_extension", "enable_load_extension",
            "setconfig", "cursor", "execute", "executemany", "executescript",
            "backup", "iterdump",
            "create_function", "create_aggregate", "create_window_function",
            "create_collation", "set_progress_handler", "set_trace_callback",
        ):
            raise PermissionError("blocked_by_octopus_policy: sqlite3 " + name + " cannot be called directly")
        for _ca in tuple.__iter__(c_args):
            _audit_check_sq_prim(_ca)
        for _ck, _cv in dict.items(c_kwargs):
            if _TYPE(_ck) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 call kwarg denied")
            _audit_check_sq_prim(_cv)
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        res = getattr(raw, name)(*c_args, **c_kwargs)
        if res is raw:
            res = conn_w
        elif _TYPE(res) is _ORIG_SQLITE_CURSOR:
            res = _wrap_sqlite_cursor(res, conn_w)
        box[0] = res
    elif op == "conn_setattr":
        _, conn_w, name, val = args
        if _TYPE(name) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
        if name not in ("text_factory", "isolation_level", "autocommit"):
            raise PermissionError("blocked_by_octopus_policy: sqlite3 attribute cannot be modified")
        if name == "text_factory" and not (
            val is None
            or val is str
            or val is bytes
            or val is bytearray
            or (_SQLITE_OPT_UNICODE is not None and val is _SQLITE_OPT_UNICODE)
        ):
            raise PermissionError("blocked_by_octopus_policy: sqlite3 custom text_factory denied")
        if name == "isolation_level" and val is not None and _TYPE(val) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 isolation_level denied")
        if name == "autocommit" and not (val is True or val is False or _TYPE(val) is int):
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 autocommit denied")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        setattr(raw, name, val)
    elif op == "cursor_init":
        _, cur_w, conn_w = args
        if not _has_mro_base(cur_w, _SQLITE_CURSOR_CLS):
            raise TypeError("Cursor must be subclass of sqlite3.Cursor")
        cid = id(cur_w)
        with _GC_MAP_LOCK:
            existing = _DICT_GET(_SQLITE_CURSOR_MAP, cid)
        if existing is not None and existing[0]() is cur_w:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 Cursor already initialized")
        if not _has_mro_base(conn_w, _SQLITE_WRAPPER_CLS):
            raise TypeError("connection must be sqlite3.Connection")
        _, raw, _ = _get_sqlite_conn_entry(conn_w)
        raw_cur = raw.cursor()
        rc_id = id(raw_cur)
        wr = _WEAKREF(cur_w, _SQLITE_CLEANUP_CLS("cursor_cleanup", cid, rc_id))
        with _GC_MAP_LOCK:
            _SQLITE_CURSOR_MAP[cid] = (wr, raw_cur, conn_w)
            _SQLITE_RAW_TO_CURSOR[rc_id] = (wr, raw_cur)
    elif op == "cursor_connection":
        _, cur_w, box = args
        if _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 cursor box")
        _, _, conn_w = _get_sqlite_cursor_entry(cur_w)
        box[0] = conn_w
    elif op == "cursor_get_rf":
        _, cur_w, box = args
        _get_sqlite_cursor_entry(cur_w)
    elif op == "cursor_set_rf":
        _, cur_w, use_c_row = args
        if _TYPE(use_c_row) is not bool:
            raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 row_factory flag")
        _, raw_cur, _ = _get_sqlite_cursor_entry(cur_w)
        raw_cur.row_factory = _ORIG_SQLITE_ROW if use_c_row else None
    elif op == "cursor_exec":
        _, cur_w, mname, c_args, c_kwargs = args
        if _TYPE(mname) is not str or mname not in ("execute", "executemany", "executescript"):
            raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 cursor exec method")
        if _TYPE(c_args) is not tuple or _TYPE(c_kwargs) is not dict:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 cursor exec args")
        if _DICT_LEN(c_kwargs) != 0:
            raise PermissionError("blocked_by_octopus_policy: sqlite3 cursor exec kwargs denied")
        if mname == "executescript":
            if len(c_args) != 1 or _TYPE(c_args[0]) is not str:
                raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 executescript args")
        elif mname == "execute":
            if not (1 <= len(c_args) <= 2) or _TYPE(c_args[0]) is not str:
                raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 execute args")
            if len(c_args) == 2:
                _audit_check_sq_params(c_args[1])
        else:
            if len(c_args) != 2 or _TYPE(c_args[0]) is not str or _TYPE(c_args[1]) is not list:
                raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 executemany args")
            for _sq_row in list.__iter__(c_args[1]):
                _audit_check_sq_params(_sq_row)
        _check_sqlite_conv_adapt()
        _, raw_cur, _ = _get_sqlite_cursor_entry(cur_w)
        getattr(raw_cur, mname)(*c_args, **c_kwargs)
    elif op == "cursor_next":
        _, cur_w, box = args
        if _TYPE(box) is not list or len(box) != 2:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 cursor box")
        _check_sqlite_conv_adapt()
        _, raw_cur, _ = _get_sqlite_cursor_entry(cur_w)
        try:
            box[1] = next(raw_cur)
            box[0] = True
        except StopIteration:
            box[0] = False
            box[1] = None
    elif op == "cursor_getattr":
        _, cur_w, name, box = args
        if _TYPE(name) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
        if _TYPE(box) is not list or len(box) != 2:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 cursor getattr box")
        if name == "connection":
            _, _, conn_w = _get_sqlite_cursor_entry(cur_w)
            box[0] = False
            box[1] = conn_w
            return
        _, raw_cur, _ = _get_sqlite_cursor_entry(cur_w)
        val = getattr(raw_cur, name)
        if callable(val):
            box[0] = True
            box[1] = None
        else:
            if val is raw_cur or getattr(val, "__self__", None) is raw_cur:
                raise PermissionError("blocked_by_octopus_policy: raw sqlite3 cursor object access denied")
            box[0] = False
            box[1] = val
    elif op == "cursor_call":
        _, cur_w, name, c_args, c_kwargs, box = args
        if _TYPE(name) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
        if _TYPE(c_args) is not tuple or _TYPE(c_kwargs) is not dict or _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed sqlite3 cursor call args")
        if name in ("execute", "executemany", "executescript", "row_factory"):
            raise PermissionError("blocked_by_octopus_policy: invalid sqlite3 cursor call")
        for _ca in tuple.__iter__(c_args):
            _audit_check_sq_prim(_ca)
        for _ck, _cv in dict.items(c_kwargs):
            if _TYPE(_ck) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 cursor call kwarg denied")
            _audit_check_sq_prim(_cv)
        _check_sqlite_conv_adapt()
        _, raw_cur, _ = _get_sqlite_cursor_entry(cur_w)
        res = getattr(raw_cur, name)(*c_args, **c_kwargs)
        if res is raw_cur:
            res = cur_w
        box[0] = res
    elif op == "cursor_setattr":
        _, cur_w, name, val = args
        if _TYPE(name) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact sqlite3 attribute name denied")
        if name != "arraysize":
            raise PermissionError("blocked_by_octopus_policy: sqlite3 cursor attribute cannot be modified")
        if _TYPE(val) is not int:
            raise TypeError("arraysize must be int")
        _, raw_cur, _ = _get_sqlite_cursor_entry(cur_w)
        raw_cur.arraysize = val
    else:
        raise PermissionError("blocked_by_octopus_policy: unknown sqlite_op")

def _handle_signal_op(args):
    if _TYPE(args) is not tuple or not args:
        raise PermissionError("blocked_by_octopus_policy: malformed signal_op")
    op = args[0]
    if _TYPE(op) is not str:
        raise PermissionError("blocked_by_octopus_policy: non-exact signal_op")
    if op == "signal":
        _, sig_i, h_norm, orig_h, box = args
        if _TYPE(sig_i) is not int:
            raise TypeError("'signalnum' must be an integer")
        _ht = _TYPE(h_norm)
        if not (_ht is int or _ht is _SIGNAL_HANDLER_CLS_REF):
            raise PermissionError("blocked_by_octopus_policy: invalid signal handler wrapper")
        old_entry = _DICT_GET(_SIGNAL_SIG_MAP, sig_i)
        prev = _ORIG_SIGNAL_SIGNAL(sig_i, h_norm)
        if type(h_norm) is _SIGNAL_HANDLER_CLS_REF:
            _SIGNAL_SIG_MAP[sig_i] = (h_norm, orig_h)
        else:
            _DICT_POP(_SIGNAL_SIG_MAP, sig_i, None)
        if old_entry is not None and prev is old_entry[0]:
            prev = old_entry[1]
        elif _TYPE(prev) is _SIGNAL_HANDLER_CLS_REF:
            prev = _OBJECT_GETATTR(prev, "_fn")
        box[0] = prev
    elif op == "getsignal":
        _, sig_i, box = args
        if type(sig_i) is not int:
            raise TypeError("'signalnum' must be an integer")
        cur = _ORIG_SIGNAL_GETSIGNAL(sig_i)
        entry = _DICT_GET(_SIGNAL_SIG_MAP, sig_i)
        if entry is not None and cur is entry[0]:
            cur = entry[1]
        elif _TYPE(cur) is _SIGNAL_HANDLER_CLS_REF:
            cur = _OBJECT_GETATTR(cur, "_fn")
        box[0] = cur
    else:
        raise PermissionError("blocked_by_octopus_policy: unknown signal_op")

def _handle_trace_op(args):
    if _TYPE(args) is not tuple or not args:
        raise PermissionError("blocked_by_octopus_policy: malformed trace_op")
    op = args[0]
    if _TYPE(op) is not str:
        raise PermissionError("blocked_by_octopus_policy: non-exact trace_op")
    if op == "settrace":
        _, w = args
        if w is not None and _TYPE(w) is not _TRACE_WRAPPER_CLS_REF:
            raise PermissionError("blocked_by_octopus_policy: invalid trace wrapper")
        _ORIG_SYS_SETTRACE(w)
    elif op == "gettrace":
        _, box = args
        if _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed trace box")
        box[0] = _ORIG_SYS_GETTRACE()
    elif op == "setprofile":
        _, w = args
        if w is not None and _TYPE(w) is not _TRACE_WRAPPER_CLS_REF:
            raise PermissionError("blocked_by_octopus_policy: invalid profile wrapper")
        _ORIG_SYS_SETPROFILE(w)
    elif op == "getprofile":
        _, box = args
        if _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed profile box")
        box[0] = _ORIG_SYS_GETPROFILE()
    elif op == "settraceall":
        _, w = args
        if _ORIG_SYS_SETTRACEALL is None:
            raise PermissionError("blocked_by_octopus_policy: _settraceallthreads unavailable")
        if w is not None and _TYPE(w) is not _TRACE_WRAPPER_CLS_REF:
            raise PermissionError("blocked_by_octopus_policy: invalid trace wrapper")
        _ORIG_SYS_SETTRACEALL(w)
    elif op == "setprofileall":
        _, w = args
        if _ORIG_SYS_SETPROFILEALL is None:
            raise PermissionError("blocked_by_octopus_policy: _setprofileallthreads unavailable")
        if w is not None and _TYPE(w) is not _TRACE_WRAPPER_CLS_REF:
            raise PermissionError("blocked_by_octopus_policy: invalid profile wrapper")
        _ORIG_SYS_SETPROFILEALL(w)
    elif op == "mon_register":
        _, tool_id, event, cb, box = args
        if _ORIG_MON_REGISTER is None:
            raise PermissionError("blocked_by_octopus_policy: sys.monitoring unavailable")
        if _TYPE(tool_id) is not int or _TYPE(event) is not int:
            raise TypeError("tool_id and event must be exact int")
        if cb is not None and _TYPE(cb) is not _MON_CB_CLS_REF:
            raise PermissionError("blocked_by_octopus_policy: invalid monitoring wrapper")
        if _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed monitoring box")
        box[0] = _ORIG_MON_REGISTER(tool_id, event, cb)
    elif op == "mon_set_local":
        _, tool_id, code, event_set, box = args
        if _ORIG_MON_SET_LOCAL is None:
            raise PermissionError("blocked_by_octopus_policy: sys.monitoring unavailable")
        if _TYPE(tool_id) is not int or _TYPE(event_set) is not int:
            raise TypeError("tool_id and event_set must be exact int")
        if _TYPE(code) is _CODE_TYPE and code in _ALL_INTERNAL_CODES_REF:
            raise PermissionError("blocked_by_octopus_policy: monitoring internal guard code denied")
        if _TYPE(box) is not list or len(box) != 1:
            raise PermissionError("blocked_by_octopus_policy: malformed monitoring box")
        box[0] = _ORIG_MON_SET_LOCAL(tool_id, code, event_set)
    else:
        raise PermissionError("blocked_by_octopus_policy: unknown trace_op")

def _handle_stat_op(args, caller_frame):
    if _TYPE(args) is not tuple or len(args) < 3:
        raise PermissionError("blocked_by_octopus_policy: malformed stat_op")
    op = args[0]
    if _TYPE(op) is not str:
        raise PermissionError("blocked_by_octopus_policy: non-exact stat_op")
    box = args[-1]
    if _TYPE(box) is not list or len(box) != 1:
        raise PermissionError("blocked_by_octopus_policy: malformed stat box")
    if op == "scandir_next":
        if len(args) != 3:
            raise PermissionError("blocked_by_octopus_policy: malformed scandir_next stat_op")
        it_w = args[1]
        if _TYPE(it_w) is not _SCANDIR_ITER_CLS_REF:
            raise PermissionError("blocked_by_octopus_policy: invalid scandir iterator")
        it_id = id(it_w)
        with _GC_MAP_LOCK:
            ent = _DICT_GET(_SCANDIR_MAP, it_id)
        if ent is None or ent[0]() is not it_w:
            box[0] = None
            return
        raw_it = ent[1]
        while True:
            try:
                raw_entry = next(raw_it)
            except StopIteration:
                box[0] = None
                return
            try:
                _check_path(raw_entry.path, False, True, check_lexical=True)
            except PermissionError:
                continue
            ew = _OBJECT_NEW(_GUARDED_DIRENTRY_CLS_REF)
            ew_id = id(ew)
            ew_wr = _WEAKREF(ew, _STAT_CLEANUP_CLS_REF("direntry_gc", ew_id))
            e_name = raw_entry.name
            e_path = raw_entry.path
            with _GC_MAP_LOCK:
                _DIRENTRY_MAP[ew_id] = (ew_wr, raw_entry, e_name, e_path)
            box[0] = ew
            return
    elif op == "scandir_close":
        if len(args) != 3:
            raise PermissionError("blocked_by_octopus_policy: malformed scandir_close stat_op")
        it_w = args[1]
        if _TYPE(it_w) is not _SCANDIR_ITER_CLS_REF:
            raise PermissionError("blocked_by_octopus_policy: invalid scandir iterator")
        it_id = id(it_w)
        with _GC_MAP_LOCK:
            ent = _DICT_POP(_SCANDIR_MAP, it_id, None)
        if ent is not None and ent[0]() is it_w:
            ent[1].close()
        box[0] = None
        return
    elif op == "direntry_attr":
        if len(args) != 4:
            raise PermissionError("blocked_by_octopus_policy: malformed direntry_attr stat_op")
        ew = args[1]
        attr = args[2]
        if _TYPE(ew) is not _GUARDED_DIRENTRY_CLS_REF or _TYPE(attr) is not str:
            raise PermissionError("blocked_by_octopus_policy: invalid DirEntry object")
        ew_id = id(ew)
        with _GC_MAP_LOCK:
            ent = _DICT_GET(_DIRENTRY_MAP, ew_id)
        if ent is None or ent[0]() is not ew:
            raise PermissionError("blocked_by_octopus_policy: invalid DirEntry object")
        if attr == "name":
            box[0] = ent[2]
            return
        if attr == "path":
            box[0] = ent[3]
            return
        raise PermissionError("blocked_by_octopus_policy: invalid DirEntry attribute")
    elif op == "direntry_op":
        if len(args) != 5:
            raise PermissionError("blocked_by_octopus_policy: malformed direntry_op stat_op")
        ew = args[1]
        dop = args[2]
        fsym = args[3]
        if _TYPE(ew) is not _GUARDED_DIRENTRY_CLS_REF or _TYPE(dop) is not str or _TYPE(fsym) is not bool:
            raise PermissionError("blocked_by_octopus_policy: invalid DirEntry operation")
        ew_id = id(ew)
        with _GC_MAP_LOCK:
            ent = _DICT_GET(_DIRENTRY_MAP, ew_id)
        if ent is None or ent[0]() is not ew:
            raise PermissionError("blocked_by_octopus_policy: invalid DirEntry object")
        raw_entry = ent[1]
        _check_path(ent[3], False, True, check_lexical=True)
        if dop == "stat":
            box[0] = raw_entry.stat(follow_symlinks=fsym)
        elif dop == "is_file":
            box[0] = raw_entry.is_file(follow_symlinks=fsym)
        elif dop == "is_dir":
            box[0] = raw_entry.is_dir(follow_symlinks=fsym)
        elif dop == "is_symlink":
            box[0] = raw_entry.is_symlink()
        elif dop == "is_junction":
            box[0] = raw_entry.is_junction()
        elif dop == "inode":
            box[0] = raw_entry.inode()
        else:
            raise PermissionError("blocked_by_octopus_policy: unknown direntry_op")
        return
    clean_path = args[1]
    pt = _TYPE(clean_path)
    if pt is not int and pt is not str and pt is not bytes:
        raise PermissionError("blocked_by_octopus_policy: non-exact stat path type denied")
    if pt is not int:
        if clean_path == "" or clean_path == b"":
            if op in ("path_exists", "path_lexists", "path_isfile", "path_isdir", "path_islink", "path_isjunction"):
                box[0] = False
                return
        else:
            only_explicit = False
            norm_t = None
            lex_t = None
            if (
                _CEDAR_ACTIVE
                and _IMPORTLIB_PATH_STAT_CODE is not None
                and caller_frame is not None
                and type(caller_frame) is _FRAME_TYPE
                and caller_frame.f_code is _IMPORTLIB_PATH_STAT_CODE
                and caller_frame.f_globals is _IMPORTLIB_EXT_GLOBALS
            ):
                norm_t, lex_t = _norm_pair(clean_path)
                if norm_t and lex_t:
                    for sp in _INIT_SYS_PATH:
                        if _under_dir(norm_t, sp) and _under_dir(lex_t, sp):
                            only_explicit = True
                            break
            _check_path(clean_path, False, True, only_explicit, check_lexical=True, pre_norm=norm_t, pre_lex=lex_t)
            if op == "access":
                if len(args) != 6 or _TYPE(args[2]) is not int:
                    raise PermissionError("blocked_by_octopus_policy: malformed access stat_op")
                if (args[2] & _OS_W_OK) != 0:
                    try:
                        _check_path(clean_path, True, False, only_explicit, check_lexical=True, pre_norm=norm_t, pre_lex=lex_t)
                    except PermissionError:
                        box[0] = False
                        return
    if op == "stat":
        if len(args) != 4 or _TYPE(args[2]) is not bool:
            raise PermissionError("blocked_by_octopus_policy: malformed stat args")
        box[0] = _ORIG_OS_STAT(clean_path, follow_symlinks=args[2])
    elif op == "lstat":
        if len(args) != 3 or pt is int:
            raise PermissionError("blocked_by_octopus_policy: malformed lstat args")
        box[0] = _ORIG_OS_LSTAT(clean_path)
    elif op == "access":
        if len(args) != 6 or _TYPE(args[2]) is not int or _TYPE(args[3]) is not bool or _TYPE(args[4]) is not bool:
            raise PermissionError("blocked_by_octopus_policy: malformed access args")
        box[0] = _ORIG_OS_ACCESS(clean_path, args[2], effective_ids=args[3], follow_symlinks=args[4])
    elif op == "scandir":
        if len(args) != 3 or pt is int or _ORIG_OS_SCANDIR is None:
            raise PermissionError("blocked_by_octopus_policy: scandir unavailable")
        raw_it = _ORIG_OS_SCANDIR(clean_path)
        iter_w = _OBJECT_NEW(_SCANDIR_ITER_CLS_REF)
        it_id = id(iter_w)
        it_wr = _WEAKREF(iter_w, _STAT_CLEANUP_CLS_REF("scandir_gc", it_id))
        stale_it = None
        with _GC_MAP_LOCK:
            old_ent = _DICT_GET(_SCANDIR_MAP, it_id)
            if old_ent is not None and old_ent[0]() is None:
                stale_it = old_ent[1]
            _SCANDIR_MAP[it_id] = (it_wr, raw_it)
        if stale_it is not None:
            try:
                stale_it.close()
            except Exception:
                pass
        box[0] = iter_w
    elif op == "readlink":
        if len(args) != 3 or pt is int or _ORIG_OS_READLINK is None:
            raise PermissionError("blocked_by_octopus_policy: readlink unavailable")
        target = _ORIG_OS_READLINK(clean_path)
        if target:
            target_s = _to_str(target)
            if target_s:
                clean_s = _to_str(clean_path)
                link_dir = _F_OSPATH_DIRNAME(_OS_PATH_ABSPATH(clean_s))
                resolved_target = _F_OSPATH_JOIN(link_dir, target_s)
                _check_path(resolved_target, False, True, check_lexical=True)
        box[0] = target
    elif op == "path_exists":
        if len(args) != 3 or _ORIG_NT_PATH_EXISTS is None:
            raise PermissionError("blocked_by_octopus_policy: path_exists unavailable")
        box[0] = _ORIG_NT_PATH_EXISTS(clean_path)
    elif op == "path_lexists":
        if len(args) != 3 or _ORIG_NT_PATH_LEXISTS is None:
            raise PermissionError("blocked_by_octopus_policy: path_lexists unavailable")
        box[0] = _ORIG_NT_PATH_LEXISTS(clean_path)
    elif op == "path_isfile":
        if len(args) != 3 or _ORIG_NT_PATH_ISFILE is None:
            raise PermissionError("blocked_by_octopus_policy: path_isfile unavailable")
        box[0] = _ORIG_NT_PATH_ISFILE(clean_path)
    elif op == "path_isdir":
        if len(args) != 3 or _ORIG_NT_PATH_ISDIR is None:
            raise PermissionError("blocked_by_octopus_policy: path_isdir unavailable")
        box[0] = _ORIG_NT_PATH_ISDIR(clean_path)
    elif op == "path_islink":
        if len(args) != 3 or _ORIG_NT_PATH_ISLINK is None:
            raise PermissionError("blocked_by_octopus_policy: path_islink unavailable")
        box[0] = _ORIG_NT_PATH_ISLINK(clean_path)
    elif op == "path_isjunction":
        if len(args) != 3 or _ORIG_NT_PATH_ISJUNCTION is None:
            raise PermissionError("blocked_by_octopus_policy: path_isjunction unavailable")
        box[0] = _ORIG_NT_PATH_ISJUNCTION(clean_path)
    elif op == "getfinalpathname":
        if len(args) != 3 or pt is int or _ORIG_NT_GETFINALPATHNAME is None:
            raise PermissionError("blocked_by_octopus_policy: getfinalpathname unavailable")
        box[0] = _ORIG_NT_GETFINALPATHNAME(clean_path)
    elif op == "findfirstfile":
        if len(args) != 3 or pt is int or _ORIG_NT_FINDFIRSTFILE is None:
            raise PermissionError("blocked_by_octopus_policy: findfirstfile unavailable")
        box[0] = _ORIG_NT_FINDFIRSTFILE(clean_path)
    else:
        raise PermissionError("blocked_by_octopus_policy: unknown stat_op")

def _split_cmdline(s):
    tokens = []
    cur = []
    in_quote = None
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if in_quote is not None:
            if ch == in_quote:
                in_quote = None
            elif ch == "\\\\" and not _IS_WIN and i + 1 < n:
                i += 1
                cur.append(s[i])
            else:
                cur.append(ch)
        else:
            if ch in ('"', "'"):
                in_quote = ch
            elif ch.isspace():
                if cur:
                    tokens.append("".join(cur))
                    cur = []
            elif ch == "\\\\" and not _IS_WIN and i + 1 < n:
                i += 1
                cur.append(s[i])
            else:
                cur.append(ch)
        i += 1
    if cur:
        tokens.append("".join(cur))
    return tokens

def _cmd_aliases(raw):
    s = _to_str(raw)
    if not s:
        return []
    fname = s.replace("\\\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().lower()
    if not fname:
        return []
    aliases = [fname]
    no_ext = fname
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if no_ext.endswith(ext):
            no_ext = no_ext[:-len(ext)]
            break
    if no_ext and no_ext not in aliases:
        aliases.append(no_ext)
    if no_ext.startswith("python"):
        rest = no_ext[len("python"):]
        _all_py_chars = True
        for c in rest:
            if not (c.isdigit() or c in (".", "w")):
                _all_py_chars = False
                break
        if not rest or _all_py_chars:
            if rest and rest[0].isdigit():
                maj = "python" + rest[0]
                if maj not in aliases:
                    aliases.append(maj)
            if "python" not in aliases:
                aliases.append("python")
    return aliases

def _is_python_aliases(aliases):
    for a in aliases:
        if a in ("python", "python3", "python2", "pythonw", "py"):
            return True
    return False

def _check_python_child_flags(flag_tokens):
    i = 0
    while i < len(flag_tokens):
        tok = flag_tokens[i].strip()
        if tok == "--" or tok == "-":
            break
        if tok.startswith("--"):
            if tok == "--isolated" or tok.startswith("--isolated="):
                raise PermissionError("blocked_by_octopus_policy: Python child isolation flag '--isolated' denied")
            if tok == "--check-hash-based-pycs":
                i += 2
                continue
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            stop_after = False
            skip_next = False
            for idx, ch in enumerate(tok[1:]):
                if ch in ("I", "E", "S"):
                    raise PermissionError("blocked_by_octopus_policy: Python child isolation flag '" + tok + "' denied")
                if ch in ("c", "m"):
                    stop_after = True
                    break
                if ch in ("W", "X"):
                    if idx + 1 == len(tok[1:]):
                        skip_next = True
                    break
            if stop_after:
                break
            if skip_next:
                i += 2
                continue
            i += 1
            continue
        break

def _has_guard_in_pythonpath(pp_val):
    if not _GUARD_DIR or _TYPE(pp_val) is not str or not pp_val.strip():
        return False
    g = _GUARD_DIR.rstrip("/")
    raw_entries = pp_val.split(_OS_PATHSEP)
    if not raw_entries or not raw_entries[0].strip():
        return False
    entries = [e for e in raw_entries if e.strip()]
    if not entries:
        return False
    first_norm = _norm(entries[0])
    return bool(first_norm and first_norm.rstrip("/") == g)

def _check_child_env(env):
    if not _GUARD_DIR:
        return
    pp = None
    if env is None or env is _OS_ENVIRON:
        pp = _to_str(_get_env_ci(_OS_ENVIRON, "PYTHONPATH"))
        ph = _to_str(_get_env_ci(_OS_ENVIRON, "PYTHONHOME"))
        pns = _to_str(_get_env_ci(_OS_ENVIRON, "PYTHONNOUSERSITE"))
        if not _has_guard_in_pythonpath(pp):
            raise PermissionError("blocked_by_octopus_policy: child process PYTHONPATH must preserve Octopus guard directory")
        if ph is not None and ph != _INIT_PYTHONHOME:
            raise PermissionError("blocked_by_octopus_policy: child process PYTHONHOME override denied")
        if pns is not None and pns != _INIT_PYTHONNOUSERSITE:
            raise PermissionError("blocked_by_octopus_policy: child process PYTHONNOUSERSITE override denied")
        return
    if _TYPE(env) is not dict:
        raise PermissionError("blocked_by_octopus_policy: custom env mapping type denied")
    for k, v in dict.items(env):
        _kt = _TYPE(k)
        _vt = _TYPE(v)
        if (_kt is not str and _kt is not bytes) or (_vt is not str and _vt is not bytes):
            raise PermissionError("blocked_by_octopus_policy: non-exact env key/value type denied")
        ks = _to_str(k)
        if not ks:
            continue
        ku = str.upper(ks) if _IS_WIN else ks
        if ku == "PYTHONPATH":
            val = _to_str(v)
            if not _has_guard_in_pythonpath(val):
                raise PermissionError("blocked_by_octopus_policy: child process PYTHONPATH must preserve Octopus guard directory")
            pp = val
        elif ku == "PYTHONHOME":
            if _to_str(v) != _INIT_PYTHONHOME:
                raise PermissionError("blocked_by_octopus_policy: child process PYTHONHOME override denied")
        elif ku == "PYTHONNOUSERSITE":
            if _to_str(v) != _INIT_PYTHONNOUSERSITE:
                raise PermissionError("blocked_by_octopus_policy: child process PYTHONNOUSERSITE override denied")
    if not _has_guard_in_pythonpath(pp):
        raise PermissionError("blocked_by_octopus_policy: child process PYTHONPATH must preserve Octopus guard directory")

def _check_child_process(executable, raw_args, env, has_env):
    if executable is not None:
        exe_str = _to_str(executable)
        if exe_str is None:
            raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
    else:
        exe_str = None

    tokens = []
    _rt = _TYPE(raw_args)
    if raw_args is None:
        pass
    elif _rt is str or _rt is bytes:
        s = _to_str(raw_args)
        if s:
            tokens = _split_cmdline(s)
    elif _rt is list or _rt is tuple:
        it = list.__iter__(raw_args) if _rt is list else tuple.__iter__(raw_args)
        for item in it:
            s = _to_str(item)
            if s is None:
                raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
            tokens.append(s)
    elif any(_rt is _pt for _pt in _EXACT_PATHLIB_TYPES) or (_OS_DIRENTRY is not None and _rt is _OS_DIRENTRY) or (_GUARDED_DIRENTRY_CLS_REF is not None and _rt is _GUARDED_DIRENTRY_CLS_REF):
        s = _to_str(raw_args)
        if s is None:
            raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
        if s:
            tokens = [s]
    else:
        raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")

    candidates = []
    if exe_str:
        candidates.append(exe_str)
    if tokens:
        if not exe_str or not tokens[0].startswith("-"):
            if tokens[0] not in candidates:
                candidates.append(tokens[0])
    if not candidates:
        raise PermissionError("blocked_by_octopus_policy: empty child command denied")

    all_aliases = []
    for c in candidates:
        for a in _cmd_aliases(c):
            if a not in all_aliases:
                all_aliases.append(a)

    for a in all_aliases:
        if a in _CMD_DENY:
            raise PermissionError("blocked_by_octopus_policy: child command blocked by commands.deny")

    json_explicitly_allowed = False
    if _CMD_ALLOW:
        for a in all_aliases:
            if a in _CMD_ALLOW:
                json_explicitly_allowed = True
                break
        if not json_explicitly_allowed:
            raise PermissionError("blocked_by_octopus_policy: child command not in commands.allow")

    cedar_explicitly_allowed = False
    if _CEDAR_ACTIVE:
        args_joined = " ".join(tokens) if tokens else (exe_str or "")
        all_cedar_explicit = True
        for cand_cmd in candidates:
            allowed, _exp_forbid, reason = _query_cedar_ipc("exec", cand_cmd, None, args_joined)
            if not allowed:
                raise PermissionError("blocked_by_octopus_policy: Cedar exec denied (" + reason + ")")
            if reason != "cedar_allow":
                all_cedar_explicit = False
        cedar_explicitly_allowed = all_cedar_explicit

    explicitly_allowed = json_explicitly_allowed or (not _CMD_ALLOW and cedar_explicitly_allowed)

    is_py = _is_python_aliases(all_aliases)
    if not is_py:
        if _HAS_FS_RESTRICTIONS and not explicitly_allowed:
            raise PermissionError("blocked_by_octopus_policy: non-Python child process blocked while filesystem restrictions are active")
    else:
        flag_slice = tokens if (exe_str and (not tokens or (tokens[0].startswith("-") and not _is_python_aliases(_cmd_aliases(tokens[0]))))) else tokens[1:]
        _check_python_child_flags(flag_slice)

    if has_env:
        _check_child_env(env)
    else:
        _check_child_env(None)

def _has_valid_subprocess_frames(caller_frame):
    if (
        _SP_GLOBALS is None
        or _POPEN_INIT_CODE is None
        or _POPEN_EXEC_CODE is None
        or not _SUBPROCESS_FILE
    ):
        return False
    if _DICT_GET(_SP_GLOBALS, "sys") is not _SYS_MOD or getattr(_SYS_MOD, "audit", None) is not _SYS_AUDIT:
        return False
    if _GUARDED_LIST2CMDLINE is not None and _DICT_GET(_SP_GLOBALS, "list2cmdline") is not _GUARDED_LIST2CMDLINE:
        return False
    if caller_frame is None or type(caller_frame) is not _FRAME_TYPE:
        return False
    exec_code = caller_frame.f_code
    if exec_code is not _POPEN_EXEC_CODE or caller_frame.f_globals is not _SP_GLOBALS:
        return False
    exec_file = getattr(exec_code, "co_filename", None)
    if not exec_file:
        return False
    try:
        exec_norm = _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(exec_file))
    except Exception:
        return False
    if exec_norm != _SUBPROCESS_FILE:
        return False
    frame = caller_frame.f_back
    while type(frame) is _FRAME_TYPE:
        code = frame.f_code
        co_file = getattr(code, "co_filename", None)
        if co_file and code is _POPEN_INIT_CODE and frame.f_globals is _SP_GLOBALS:
            try:
                fn = _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(co_file))
            except Exception:
                fn = ""
            if fn == _SUBPROCESS_FILE:
                return True
        frame = frame.f_back
    return False

def _is_audited_popen_createprocess(caller_frame):
    if not _has_valid_subprocess_frames(caller_frame):
        return False
    tok = (_GET_IDENT(), id(caller_frame))
    with _POPEN_LOCK:
        return _POPEN_TOKENS.pop(tok, None) is not None

def _strip_exc(exc):
    seen = set()
    stack = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        try:
            _EXC_TB_SET(cur, None)
            nxt_cause = cur.__cause__
            nxt_ctx = cur.__context__
            _EXC_CAUSE_SET(cur, None)
            _EXC_CTX_SET(cur, None)
        except Exception:
            continue
        if nxt_cause is not None and id(nxt_cause) not in seen:
            stack.append(nxt_cause)
        if nxt_ctx is not None and id(nxt_ctx) not in seen:
            stack.append(nxt_ctx)

def _internal_getframe(depth):
    _tid = _GET_IDENT()
    _AUDIT_GETFRAME_ACTIVE[_tid] = True
    try:
        return _SYS_GETFRAME(depth)
    except Exception:
        return None
    finally:
        _DICT_POP(_AUDIT_GETFRAME_ACTIVE, _tid, None)

def _dispatch_audit(event, args):
    _unwind_ev = _DICT_POP(_TRACE_UNWIND_ARMED, _GET_IDENT(), None)
    if event not in ("builtins.id", "sys._getframe", "object.__getattr__"):
        _drain_pending_sqlite_conns()
        _drain_gc_cleanups()
    if event == "open":
        if not args:
            raise PermissionError("blocked_by_octopus_policy: malformed open audit event")
        path = args[0]
        mode = args[1] if len(args) > 1 else "r"
        flags = args[2] if len(args) > 2 else 0
        if mode is not None and _TYPE(mode) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact open mode denied")
        if flags is not None and _TYPE(flags) is not int:
            raise PermissionError("blocked_by_octopus_policy: non-exact open flags denied")
        is_w = False
        is_r = True
        if mode is not None:
            for c in ("w", "a", "x", "+"):
                if c in mode:
                    is_w = True
                    break
            is_r = (not is_w) or ("r" in mode) or ("+" in mode)
        elif flags is not None:
            w_mask = _O_WRONLY | _O_RDWR | _O_CREAT | _O_TRUNC | _O_APPEND
            if (flags & w_mask) != 0:
                is_w = True
            acc = flags & (_O_RDONLY | _O_WRONLY | _O_RDWR)
            is_r = (not is_w) or (acc == _O_RDONLY) or (acc == _O_RDWR)
        only_explicit = False
        norm_t = None
        lex_t = None
        if not is_w and _CEDAR_ACTIVE and _ENTRY_SCRIPT_PATHS:
            norm_t, lex_t = _norm_pair(path)
            if norm_t and norm_t in _ENTRY_SCRIPT_PATHS and lex_t and lex_t in _ENTRY_SCRIPT_PATHS:
                cf = _internal_getframe(3)
                if cf is None:
                    only_explicit = True
                elif (
                    type(cf) is _FRAME_TYPE
                    and _ZIPIMPORT_READ_DIR_CODE is not None
                    and cf.f_code is _ZIPIMPORT_READ_DIR_CODE
                    and cf.f_globals is _ZIPIMPORT_GLOBALS
                ):
                    only_explicit = True
        _check_path(path, is_w, is_r, only_explicit, check_lexical=True, pre_norm=norm_t, pre_lex=lex_t, check_pinned_parent=is_w)
    elif event == "os.mkdir":
        if args and _TYPE(args[0]) is not int:
            _check_path(args[0], True, check_pinned_parent=False)
    elif event in ("os.rmdir", "os.remove", "os.unlink", "os.chmod", "os.chown", "os.utime", "os.truncate", "os.chflags", "os.setxattr", "os.removexattr", "shutil.rmtree"):
        if args and _TYPE(args[0]) is not int:
            _check_path(args[0], True, check_pinned_parent=True)
            if event in ("os.rmdir", "shutil.rmtree"):
                _check_pinned_subtree(args[0])
    elif event in ("os.rename", "os.replace", "os.link"):
        if len(args) >= 1:
            _check_path(args[0], True, True, check_pinned_parent=True)
            if event != "os.link":
                _check_pinned_subtree(args[0])
        if len(args) >= 2:
            _check_path(args[1], True, check_pinned_parent=True)
            if event != "os.link":
                _check_pinned_subtree(args[1])
    elif event == "_winapi.CopyFile2":
        if len(args) >= 1:
            _check_path(args[0], False, True)
        if len(args) >= 2:
            _check_path(args[1], True, check_pinned_parent=True)
    elif event == "_winapi.CreateJunction":
        if len(args) < 2:
            raise PermissionError("blocked_by_octopus_policy: malformed _winapi.CreateJunction audit event")
        if _TYPE(args[0]) is not str or _TYPE(args[1]) is not str:
            raise PermissionError("blocked_by_octopus_policy: non-exact _winapi.CreateJunction path type denied")
        _check_path(args[0], False, True, check_lexical=True)
        _check_pinned_subtree(args[0])
        _check_path(args[1], True, False, check_lexical=True, check_pinned_parent=True)
    elif event == "_winapi.CreateFile":
        if len(args) < 5 or _TYPE(args[0]) is not str or _TYPE(args[1]) is not int or _TYPE(args[2]) is not int or _TYPE(args[3]) is not int or _TYPE(args[4]) is not int:
            raise PermissionError("blocked_by_octopus_policy: malformed _winapi.CreateFile audit event")
        _cf_raw = _raw_norm(args[0])
        if _CEDAR_PIPE and _cf_raw == _CEDAR_PIPE_NORM:
            _cpf = _internal_getframe(3)
            if (
                _cpf is not None
                and type(_cpf) is _FRAME_TYPE
                and _cpf.f_globals is _AUDIT_GLOBALS
                and _cpf.f_code is _QUERY_CEDAR_IPC_CODE
            ):
                return
            raise PermissionError("blocked_by_octopus_policy: direct Cedar IPC pipe access denied")
        _cf_access = args[1]
        _cf_disp = args[3]
        _cf_flags = args[4]
        _cf_w = ((_cf_access & 0x520D0156) != 0) or (_cf_disp in (1, 2, 4, 5)) or ((_cf_flags & 0x04000000) != 0)
        _cf_r = (not _cf_w) or ((_cf_access & 0xB2000089) != 0)
        _cf_is_self_pipe = (
            ".." not in _cf_raw
            and (
                _cf_raw.startswith("//./pipe/python-pipe-" + _CUR_PID_STR + "-")
                or _cf_raw.startswith("//./pipe/pyc-" + _CUR_PID_STR + "-")
            )
            and "/" not in _cf_raw[9:]
            and ":" not in _cf_raw[9:]
        )
        if not _cf_is_self_pipe:
            _check_path(args[0], _cf_w, _cf_r, check_lexical=True, check_pinned_parent=_cf_w)
    elif event == "os.add_dll_directory":
        if args:
            _check_path(args[0], False, True, check_lexical=True)
    elif event in ("os.getxattr", "os.listxattr"):
        if args and _TYPE(args[0]) is not int:
            _check_path(args[0], False, True, check_lexical=True)
    elif event in ("shutil.copytree", "shutil.copymode", "shutil.copystat"):
        if len(args) >= 1:
            _check_path(args[0], False, True, check_lexical=True)
        if len(args) >= 2:
            _check_path(args[1], True, False, check_lexical=True, check_pinned_parent=True)
    elif event == "shutil.move":
        if len(args) >= 1:
            _check_path(args[0], True, True, check_lexical=True, check_pinned_parent=True)
            _check_pinned_subtree(args[0])
        if len(args) >= 2:
            _check_path(args[1], True, False, check_lexical=True, check_pinned_parent=True)
            _check_pinned_subtree(args[1])
    elif event == "shutil.chown":
        if args:
            _check_path(args[0], True, False, check_lexical=True, check_pinned_parent=True)
    elif event == "shutil.make_archive":
        if len(args) >= 1 and args[0] is not None:
            _check_path(args[0], True, False, check_lexical=True, check_pinned_parent=True)
        if len(args) >= 3 and args[2] is not None:
            _check_path(args[2], False, True, check_lexical=True)
        if len(args) >= 4 and args[3] is not None:
            if args[2] is None:
                _check_path(args[3], False, True, check_lexical=True)
            else:
                _ma_root = _to_str(args[2])
                _ma_base = _to_str(args[3])
                if _ma_root is not None and _ma_base is not None:
                    _check_path(_F_OSPATH_JOIN(_ma_root, _ma_base), False, True, check_lexical=True)
    elif event == "shutil.unpack_archive":
        if len(args) >= 1 and args[0] is not None:
            _check_path(args[0], False, True, check_lexical=True)
        if len(args) >= 2 and args[1] is not None:
            _check_path(args[1], True, False, check_lexical=True, check_pinned_parent=True)
    elif event == "winreg.SaveKey":
        if len(args) >= 2:
            _check_path(args[1], True, False, check_lexical=True, check_pinned_parent=True)
        if _HAS_FS_RESTRICTIONS or _CMD_ALLOW or _CMD_DENY or _CEDAR_ACTIVE:
            raise PermissionError("blocked_by_octopus_policy: winreg.SaveKey denied")
    elif event == "winreg.LoadKey":
        if len(args) >= 3:
            _check_path(args[2], False, True, check_lexical=True)
        if _HAS_FS_RESTRICTIONS or _CMD_ALLOW or _CMD_DENY or _CEDAR_ACTIVE:
            raise PermissionError("blocked_by_octopus_policy: winreg.LoadKey denied")
    elif event in ("winreg.CreateKey", "winreg.SetValue", "winreg.DeleteKey", "winreg.DeleteValue", "winreg.ConnectRegistry"):
        if _HAS_FS_RESTRICTIONS or _CMD_ALLOW or _CMD_DENY or _CEDAR_ACTIVE:
            raise PermissionError("blocked_by_octopus_policy: " + event + " denied")
    elif event == "import":
        if args:
            _mod_name = args[0]
            if _TYPE(_mod_name) is not str:
                raise PermissionError("blocked_by_octopus_policy: non-exact import module name denied")
            if _mod_name == "_ctypes" or _mod_name == "ctypes" or str.startswith(_mod_name, "ctypes.") or str.startswith(_mod_name, "_ctypes."):
                raise PermissionError("blocked_by_octopus_policy: ctypes FFI import denied")
            if len(args) > 1 and args[1] is not None:
                _imp_file = _to_str(args[1])
                if _imp_file is not None:
                    _imp_norm = _strip_win_prefix_for_ads(_imp_file) if _IS_WIN else _imp_file.replace("\\\\", "/")
                    _imp_base = _imp_norm.rsplit("/", 1)[-1]
                    if _IS_WIN:
                        _imp_base = _imp_base.split(":", 1)[0].rstrip(". ")
                    _imp_base = _imp_base.lower()
                    if _imp_base == "_ctypes" or str.startswith(_imp_base, "_ctypes."):
                        raise PermissionError("blocked_by_octopus_policy: _ctypes extension load denied")
                _check_path(args[1], False, True, check_lexical=True)
    elif event == "octopus.sqlite_op":
        cf = _internal_getframe(3)
        if (
            cf is None
            or type(cf) is not _FRAME_TYPE
            or cf.f_globals is not _SQLITE_GLOBALS
            or cf.f_code not in _SQLITE_OP_CODES
        ):
            raise PermissionError("blocked_by_octopus_policy: unauthorized sqlite_op")
        _handle_sqlite_op(args)
    elif event == "octopus.signal_op":
        cf = _internal_getframe(3)
        if (
            cf is None
            or type(cf) is not _FRAME_TYPE
            or cf.f_globals is not _SIGNAL_GLOBALS_REF
            or cf.f_code not in _SIGNAL_OP_CODES
        ):
            raise PermissionError("blocked_by_octopus_policy: unauthorized signal_op")
        _handle_signal_op(args)
    elif event == "octopus.signal_guard":
        return
    elif event == "sqlite3.connect":
        if args:
            uri_flag = False
            pending = _DICT_GET(_SQLITE_CONNECT_PENDING, _GET_IDENT())
            if pending is not None and pending[0] is args[0]:
                uri_flag = bool(pending[1])
            _check_sqlite_target(args[0], uri_flag)
    elif event == "sqlite3.connect/handle":
        if args:
            uri_flag = False
            pending = _DICT_GET(_SQLITE_CONNECT_PENDING, _GET_IDENT())
            if pending is not None:
                uri_flag = bool(pending[1])
            if len(_PENDING_SQLITE_CONNS) >= 64:
                _PENDING_SQLITE_CONNS.pop(0)
            _PENDING_SQLITE_CONNS.append((args[0], uri_flag))
    elif event in ("sqlite3.enable_load_extension", "sqlite3.load_extension"):
        if event == "sqlite3.load_extension":
            raise PermissionError("blocked_by_octopus_policy: sqlite3 load_extension denied")
        if len(args) >= 2:
            _en_arg = args[1]
            _en_t = _TYPE(_en_arg)
            if (_en_t is not bool and _en_t is not int) or _en_arg:
                raise PermissionError("blocked_by_octopus_policy: sqlite3 load_extension denied")
    elif event in ("os.symlink", "shutil.copyfile"):
        if len(args) >= 1:
            _check_path(args[0], False)
            if event == "os.symlink":
                _sym_base = None
                if len(args) >= 2:
                    _sym_dst = _to_str(args[1])
                    if _TYPE(_sym_dst) is str and _sym_dst:
                        _sym_base = _F_OSPATH_DIRNAME(_OS_PATH_ABSPATH(_sym_dst))
                _check_pinned_subtree(args[0], _sym_base)
        if len(args) >= 2:
            _check_path(args[1], True, check_pinned_parent=True)
    elif event == "socket.connect":
        if _WIN_AC_BLOCKED_PROXY_PORT is not None and len(args) >= 2:
            _sc_addr = args[1]
            if (
                _TYPE(_sc_addr) is tuple
                and len(_sc_addr) >= 2
                and _TYPE(_sc_addr[0]) is str
                and _TYPE(_sc_addr[1]) is int
                and _is_local_unc_host(_sc_addr[0])
                and _sc_addr[1] == _WIN_AC_BLOCKED_PROXY_PORT
            ):
                raise PermissionError(
                    "blocked_by_octopus_policy: Windows AppContainer loopback proxy unavailable unprivileged (use --sandbox standard or run elevated)"
                )
    elif event in ("os.listdir", "os.scandir"):
        if args:
            if event == "os.scandir":
                _scf = _internal_getframe(3)
                if (
                    _scf is not None
                    and type(_scf) is _FRAME_TYPE
                    and _scf.f_globals is _AUDIT_GLOBALS
                    and (_scf.f_code is _HANDLE_STAT_OP_CODE or _scf.f_code is _CHECK_PINNED_SUBTREE_CODE)
                ):
                    return
            if _TYPE(args[0]) is int:
                raise PermissionError("blocked_by_octopus_policy: " + event + " fd denied")
            _dir_target = "." if args[0] is None else args[0]
            only_explicit = False
            norm_dir = None
            lex_dir = None
            if _CEDAR_ACTIVE and _IMPORTLIB_FILL_CACHE_CODE is not None:
                cf = _internal_getframe(3)
                if (
                    cf is not None
                    and type(cf) is _FRAME_TYPE
                    and cf.f_code is _IMPORTLIB_FILL_CACHE_CODE
                    and cf.f_globals is _IMPORTLIB_EXT_GLOBALS
                ):
                    norm_dir, lex_dir = _norm_pair(_dir_target)
                    if norm_dir and lex_dir:
                        for sp in _INIT_SYS_PATH:
                            if _under_dir(norm_dir, sp) and _under_dir(lex_dir, sp):
                                only_explicit = True
                                break
            _check_path(_dir_target, False, True, only_explicit, check_lexical=True, pre_norm=norm_dir, pre_lex=lex_dir)
    elif event == "os.chdir":
        if not args:
            raise PermissionError("blocked_by_octopus_policy: malformed os.chdir audit event")
        if _TYPE(args[0]) is int:
            if _IS_WIN:
                raise PermissionError("blocked_by_octopus_policy: os.chdir fd denied on Windows")
        else:
            _check_path(args[0], False, True, check_lexical=True)
    elif event == "os.unsetenv":
        if args:
            _t0 = _TYPE(args[0])
            if _t0 is not str and _t0 is not bytes:
                raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
            k = _to_str(args[0])
            if k is not None:
                ku = str.upper(k) if _IS_WIN else k
                if ku in ("PYTHONPATH", "PYTHONHOME", "PYTHONNOUSERSITE"):
                    raise PermissionError("blocked_by_octopus_policy: unsetting protected Python containment env var denied")
    elif event == "os.putenv":
        if len(args) >= 2:
            _t0 = _TYPE(args[0])
            _t1 = _TYPE(args[1])
            if (_t0 is not str and _t0 is not bytes) or (_t1 is not str and _t1 is not bytes):
                raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
            k = _to_str(args[0])
            v = _to_str(args[1])
            if k is not None:
                ku = str.upper(k) if _IS_WIN else k
                if ku == "PYTHONPATH":
                    if not _has_guard_in_pythonpath(v):
                        raise PermissionError("blocked_by_octopus_policy: os.putenv PYTHONPATH must preserve Octopus guard directory")
                elif ku in ("PYTHONHOME", "PYTHONNOUSERSITE"):
                    raise PermissionError("blocked_by_octopus_policy: modifying protected Python containment env var denied")
    elif event == "subprocess.Popen":
        executable, p_args, _cwd, p_env = (args + (None, None, None, None))[:4]
        _check_child_process(executable, p_args, p_env, True)
        caller = _internal_getframe(3)
        if not _has_valid_subprocess_frames(caller):
            raise PermissionError("blocked_by_octopus_policy: forged subprocess.Popen frame or tampered subprocess.sys/list2cmdline denied")
        tok = (_GET_IDENT(), id(caller))
        with _POPEN_LOCK:
            if len(_POPEN_TOKENS) >= 512:
                try:
                    _POPEN_TOKENS.pop(next(iter(_POPEN_TOKENS)))
                except Exception:
                    _POPEN_TOKENS.clear()
            _POPEN_TOKENS[tok] = True
    elif event == "os.system":
        cmd_str = _to_str(args[0]) if args else ""
        if args and cmd_str is None:
            raise PermissionError("blocked_by_octopus_policy: non-exact string/bytes type denied")
        shell_name = "cmd" if _IS_WIN else "sh"
        if shell_name in _CMD_DENY:
            raise PermissionError("blocked_by_octopus_policy: os.system blocked by commands.deny")
        if _CMD_ALLOW and shell_name not in _CMD_ALLOW:
            raise PermissionError("blocked_by_octopus_policy: os.system not in commands.allow")
        cedar_shell_allowed = False
        if _CEDAR_ACTIVE:
            allowed, _exp_forbid, reason = _query_cedar_ipc("exec", shell_name, None, cmd_str or shell_name)
            if not allowed:
                raise PermissionError("blocked_by_octopus_policy: os.system Cedar exec denied (" + reason + ")")
            cedar_shell_allowed = (reason == "cedar_allow")
        if _HAS_FS_RESTRICTIONS and not ((_CMD_ALLOW and shell_name in _CMD_ALLOW) or (not _CMD_ALLOW and cedar_shell_allowed)):
            raise PermissionError("blocked_by_octopus_policy: os.system blocked while filesystem restrictions are active")
        _check_child_env(None)
    elif event == "os.spawn":
        _mode, sp_path, sp_args, sp_env = (args + (None, None, None, None))[:4]
        _check_child_process(sp_path, sp_args, sp_env, True)
    elif event in ("os.posix_spawn", "os.exec"):
        ex_path, ex_args, ex_env = (args + (None, None, None))[:3]
        _check_child_process(ex_path, ex_args, ex_env, True)
    elif event == "_winapi.CreateProcess":
        caller = _internal_getframe(3)
        if not _is_audited_popen_createprocess(caller):
            raise PermissionError("blocked_by_octopus_policy: direct _winapi.CreateProcess denied; use audited subprocess.Popen")
    elif event == "os.startfile":
        raise PermissionError("blocked_by_octopus_policy: os.startfile denied")
    elif event == "pty.spawn":
        _check_child_process(None, args[0] if args else None, None, False)
    elif event == "octopus.trace_op":
        cf = _internal_getframe(3)
        if (
            cf is None
            or type(cf) is not _FRAME_TYPE
            or cf.f_globals is not _TRACE_GLOBALS_REF
            or cf.f_code not in _TRACE_OP_CODES
        ):
            raise PermissionError("blocked_by_octopus_policy: unauthorized trace_op")
        _handle_trace_op(args)
    elif event == "octopus.stat_op":
        cf = _internal_getframe(3)
        if (
            cf is None
            or type(cf) is not _FRAME_TYPE
            or cf.f_globals is not _STAT_GLOBALS_REF
            or cf.f_code not in _STAT_OP_CODES
        ):
            raise PermissionError("blocked_by_octopus_policy: unauthorized stat_op")
        _handle_stat_op(args, cf.f_back)
    elif event == "octopus.trace_unwind":
        cf = _internal_getframe(3)
        if (
            cf is None
            or type(cf) is not _FRAME_TYPE
            or cf.f_globals is not _TRACE_GLOBALS_REF
            or cf.f_code not in _TRACE_UNWIND_CODES
        ):
            raise PermissionError("blocked_by_octopus_policy: unauthorized trace_unwind")
        if not args or _TYPE(args[0]) is not str or args[0] not in ("sys.settrace", "sys.setprofile"):
            raise PermissionError("blocked_by_octopus_policy: invalid trace_unwind")
        _TRACE_UNWIND_ARMED[_GET_IDENT()] = args[0]
        return
    elif event in ("sys.settrace", "sys.setprofile", "sys.monitoring.register_callback"):
        if _unwind_ev == event and not args:
            return
        cf = _internal_getframe(3)
        if (
            cf is None
            or type(cf) is not _FRAME_TYPE
            or cf.f_globals is not _AUDIT_GLOBALS
            or cf.f_code is not _HANDLE_TRACE_OP_CODE
        ):
            raise PermissionError("blocked_by_octopus_policy: unauthorized " + event)
    elif event == "sys.addaudithook":
        _ok_gate = False
        _cf = _internal_getframe(3)
        if _cf is not None and type(_cf) is _FRAME_TYPE and _cf.f_code is _INSTALL_CODE:
            _ok_gate = True
        if not _ok_gate:
            raise PermissionError("blocked_by_octopus_policy: sys.addaudithook denied")
    elif event in (
        "gc.get_objects",
        "gc.get_referrers",
        "gc.get_referents",
        "sys._current_frames",
        "sys._current_exceptions",
    ):
        raise PermissionError("blocked_by_octopus_policy: audit introspection denied")
    elif _TYPE(event) is str and (event == "ctypes" or str.startswith(event, "ctypes.")):
        raise PermissionError("blocked_by_octopus_policy: " + event + " FFI denied")
    elif event == "sys._getframe":
        if _DICT_GET(_AUDIT_GETFRAME_ACTIVE, _GET_IDENT(), False):
            return
        _f = args[0] if args else None
        if _f is not None and type(_f) is not _FRAME_TYPE:
            raise PermissionError("blocked_by_octopus_policy: audit frame inspection denied")
        while _f is not None:
            _fg = _f.f_globals
            _fc = _f.f_code
            if (
                _fg is _AUDIT_GLOBALS
                or _fg is _WATCHDOG_GLOBALS_REF
                or _fg is _GATE_GLOBALS_REF
                or _fg is _SQLITE_GLOBALS
                or _fg is _SIGNAL_GLOBALS_REF
                or _fg is _ADDHOOK_GLOBALS
                or _fg is _TRACE_GLOBALS_REF
                or _fg is _STAT_GLOBALS_REF
                or (_LIST2CMD_GLOBALS is not None and _fg is _LIST2CMD_GLOBALS)
                or _fc in _AUDIT_CODES
                or _fc is _WATCHDOG_CODE_REF
                or _fc is _GATE_CODE_REF
                or _fc in _SQLITE_CODES
                or _fc in _SIGNAL_CODES
                or _fc is _ADDHOOK_CODE
                or _fc in _TRACE_CODES
                or _fc in _STAT_CODES
                or _fc in _L2C_CODES
            ):
                raise PermissionError("blocked_by_octopus_policy: audit frame inspection denied")
            _f = _f.f_back

def _octopus_audit_check(event, args):
    if (
        event == "object.__getattr__"
        and len(args) >= 2
        and type(args[1]) is str
        and args[1] in ("f_code", "__code__", "__defaults__", "__kwdefaults__")
    ):
        return
    _tid = _GET_IDENT()
    if _DICT_GET(_AUDIT_STACK_CHECK_ACTIVE, _tid, False):
        if (
            event == "sys._getframe"
            and args
            and type(args[0]) is _FRAME_TYPE
            and args[0].f_globals is _AUDIT_GLOBALS
        ):
            return
        _OS_EXIT(1)
    _armed_tok = _DICT_GET(_AUDIT_DENY_ARMED, _tid, None)
    if _armed_tok is not None:
        _AUDIT_STACK_CHECK_ACTIVE[_tid] = True
        _DICT_POP(_AUDIT_DENY_ARMED, _tid, None)
        try:
            _disarmed_tok = _GATE_GETATTR(_GATE_TL, "disarmed", None)
            if _disarmed_tok is not _armed_tok or _GATE_GETATTR(_GATE_TL, "exc", None) is not None:
                _OS_EXIT(1)
            _cf = _SYS_GETFRAME(0).f_back
            _has_audit_hook = False
            while type(_cf) is _FRAME_TYPE:
                _fg = _cf.f_globals
                if (
                    _fg is _AUDIT_GLOBALS
                    or _fg is _GATE_GLOBALS_REF
                    or _fg is _WATCHDOG_GLOBALS_REF
                ):
                    _has_audit_hook = True
                    break
                _cf = _cf.f_back
            if _has_audit_hook:
                _OS_EXIT(1)
        except BaseException:
            _OS_EXIT(1)
        finally:
            _DICT_POP(_AUDIT_STACK_CHECK_ACTIVE, _tid, None)
    elif event == "octopus.signal_op":
        _AUDIT_STACK_CHECK_ACTIVE[_tid] = True
        try:
            _cf = _SYS_GETFRAME(0).f_back
            while type(_cf) is _FRAME_TYPE:
                _fg = _cf.f_globals
                if (
                    _fg is _AUDIT_GLOBALS
                    or _fg is _GATE_GLOBALS_REF
                    or _fg is _WATCHDOG_GLOBALS_REF
                ):
                    _OS_EXIT(1)
                _cf = _cf.f_back
        except BaseException:
            _OS_EXIT(1)
        finally:
            _DICT_POP(_AUDIT_STACK_CHECK_ACTIVE, _tid, None)
    _GATE_SETATTR(_GATE_TL, "exc", None)
    _GATE_SETATTR(_GATE_TL, "tok", None)
    _GATE_SETATTR(_GATE_TL, "disarmed", None)
    try:
        _dispatch_audit(event, args)
    except BaseException as exc:
        _strip_exc(exc)
        _tok = _OBJECT_NEW(object)
        _GATE_SETATTR(_GATE_TL, "tok", _tok)
        _GATE_SETATTR(_GATE_TL, "disarmed", None)
        _GATE_SETATTR(_GATE_TL, "exc", exc)
        _AUDIT_DENY_ARMED[_tid] = _tok
    else:
        _GATE_SETATTR(_GATE_TL, "exc", None)
        _GATE_SETATTR(_GATE_TL, "tok", None)
        _GATE_SETATTR(_GATE_TL, "disarmed", None)
        _DICT_POP(_AUDIT_DENY_ARMED, _tid, None)

def _octopus_failclosed_guard(event, args, _os_exit=_OS_EXIT):
    if (
        event == "object.__getattr__"
        and len(args) >= 2
        and type(args[1]) is str
        and args[1] in ("f_code", "__code__", "__defaults__", "__kwdefaults__")
    ):
        return
    _tid = _GET_IDENT()
    _armed_tok = _DICT_GET(_AUDIT_DENY_ARMED, _tid, None)
    if _armed_tok is not None:
        if _GATE_GETATTR(_GATE_TL, "disarmed", None) is not _armed_tok:
            _os_exit(1)
        _DICT_POP(_AUDIT_DENY_ARMED, _tid, None)
'''
    exec(compile(_audit_src, "<octopus_audit>", "exec"), _audit_plain)

    _tmp_norm = _audit_plain["_norm"]
    _tmp_full_lex = _audit_plain["_full_lex_norm"]
    _tmp_norm_pair = _audit_plain["_norm_pair"]
    _tmp_env_ci = _audit_plain["_get_env_ci"]
    _tmp_under_dir = _audit_plain["_under_dir"]
    _audit_plain["_ALLOW_WRITE"] = tuple((_tmp_norm(x) or x.lower()) for x in _OCTOPUS_CFG["allow_write"])
    _deny_res_list = []
    for _dx in _OCTOPUS_CFG["deny_resolved"]:
        _dn = _tmp_norm(_dx) or _dx.lower()
        if _dn and _dn not in _deny_res_list:
            _deny_res_list.append(_dn)
    _deny_raw_patterns = []
    for _dr in _OCTOPUS_CFG["deny_raw"]:
        if _dr == "~" or _dr.startswith("~/"):
            _dn_tilde = _tmp_norm(_dr)
            if _dn_tilde and _dn_tilde not in _deny_res_list:
                _deny_res_list.append(_dn_tilde)
            try:
                _lex_tilde = _tmp_full_lex(_dr)
                if _lex_tilde and _lex_tilde not in _deny_res_list:
                    _deny_res_list.append(_lex_tilde)
            except Exception:
                pass
        else:
            _deny_raw_patterns.append(_dr)
    _audit_plain["_DENY_RESOLVED"] = tuple(_deny_res_list)
    _audit_plain["_DENY_RAW_PATTERNS"] = tuple(_deny_raw_patterns)
    _audit_plain["_GUARD_DIR"] = _tmp_norm(_OCTOPUS_CFG["guard_dir"]) or ""
    _audit_plain["_GUARD_DIR_LEX"] = _tmp_full_lex(_OCTOPUS_CFG["guard_dir"]) or ""
    _py_pfx_list = []
    for _raw_px in (
        sys.prefix,
        sys.base_prefix,
        sys.exec_prefix,
        getattr(sys, "base_exec_prefix", ""),
    ):
        if _raw_px:
            _pn, _pl = _tmp_norm_pair(_raw_px)
            if _pn and _pn not in _py_pfx_list:
                _py_pfx_list.append(_pn)
            if _pl and _pl not in _py_pfx_list:
                _py_pfx_list.append(_pl)
    _py_pfx = tuple(_py_pfx_list)
    _audit_plain["_PY_PREFIXES"] = _py_pfx
    _init_sp_list = []
    for _x in sys.path:
        _sn, _sl = _tmp_norm_pair(_x)
        if _sn and _sl and any(_tmp_under_dir(_sn, px) for px in _py_pfx) and any(_tmp_under_dir(_sl, px) for px in _py_pfx):
            if _sn not in _init_sp_list:
                _init_sp_list.append(_sn)
            if _sl not in _init_sp_list:
                _init_sp_list.append(_sl)
    _audit_plain["_INIT_SYS_PATH"] = tuple(_init_sp_list)
    _audit_plain["_INIT_PYTHONHOME"] = _tmp_env_ci(os.environ, "PYTHONHOME")
    _audit_plain["_INIT_PYTHONNOUSERSITE"] = _tmp_env_ci(os.environ, "PYTHONNOUSERSITE")

    _entry_candidates = []
    if sys.argv and isinstance(sys.argv[0], str) and sys.argv[0] not in ("", "-c", "-m"):
        _en_real = _tmp_norm(sys.argv[0])
        if _en_real:
            _entry_candidates.append(_en_real)
        try:
            _en_abs = _tmp_full_lex(sys.argv[0])
            if _en_abs and _en_abs not in _entry_candidates:
                _entry_candidates.append(_en_abs)
        except Exception:
            pass
    _audit_plain["_ENTRY_SCRIPT_PATHS"] = tuple(_entry_candidates)

    _AUDIT_GLOBALS = _FrozenDict(_audit_plain)
    _audit_fn_names = (
        "_has_mro_base",
        "_sq_key_eq",
        "_get_env_ci",
        "_extract_pathlib_str",
        "_to_str",
        "_pct_unquote",
        "_safe_expanduser",
        "_is_local_unc_host",
        "_is_unc_admin_share",
        "_is_raw_admin_or_ipc_share",
        "_strip_win_verbatim",
        "_norm_pair",
        "_norm",
        "_full_lex_norm",
        "_cedar_path",
        "_raw_norm",
        "_strip_win_prefix_for_ads",
        "_has_ntfs_ads",
        "_strip_ads_segments",
        "_under_dir",
        "_is_mandatory_write_deny",
        "_is_pinned_parent_write_deny",
        "_is_pinned_entry_name",
        "_check_pinned_subtree",
        "_query_cedar_ipc",
        "_query_cedar_fs",
        "_check_path",
        "_check_sqlite_target",
        "_sqlite_authorizer_check",
        "_sqlite_authorizer_uri",
        "_sqlite_authorizer_no_uri",
        "_drain_pending_sqlite_conns",
        "_drain_gc_cleanups",
        "_audit_check_sq_prim",
        "_audit_check_sq_params",
        "_parse_sqlite_connect_args",
        "_get_sqlite_conn_entry",
        "_get_sqlite_cursor_entry",
        "_wrap_sqlite_cursor",
        "_check_sqlite_conv_adapt",
        "_handle_sqlite_op",
        "_handle_signal_op",
        "_handle_trace_op",
        "_handle_stat_op",
        "_split_cmdline",
        "_cmd_aliases",
        "_is_python_aliases",
        "_check_python_child_flags",
        "_has_guard_in_pythonpath",
        "_check_child_env",
        "_check_child_process",
        "_has_valid_subprocess_frames",
        "_is_audited_popen_createprocess",
        "_strip_exc",
        "_internal_getframe",
        "_dispatch_audit",
        "_octopus_audit_check",
        "_octopus_failclosed_guard",
    )
    _audit_codes = []
    _expected_audit_funcs = []
    for _fn_name in _audit_fn_names:
        _orig_fn = _audit_plain[_fn_name]
        _rebound_fn = types.FunctionType(
            _orig_fn.__code__,
            _AUDIT_GLOBALS,
            _orig_fn.__name__,
            _orig_fn.__defaults__,
            None,
        )
        if _orig_fn.__kwdefaults__ is not None:
            _rebound_fn.__kwdefaults__ = dict(_orig_fn.__kwdefaults__)
        dict.__setitem__(_AUDIT_GLOBALS, _fn_name, _rebound_fn)
        _audit_codes.append(_orig_fn.__code__)
        _expected_audit_funcs.append((_rebound_fn, _orig_fn.__code__, _orig_fn.__defaults__, _rebound_fn.__kwdefaults__))

    _CEDAR_PIPE_CLS = _audit_plain["_CedarPipeHandle"]
    _expected_audit_cls_attrs = []
    _cpipe_new_sm = _CEDAR_PIPE_CLS.__dict__["__new__"]
    _cpipe_new_fn = types.FunctionType(
        _cpipe_new_sm.__func__.__code__,
        _AUDIT_GLOBALS,
        _cpipe_new_sm.__func__.__name__,
        _cpipe_new_sm.__func__.__defaults__,
        None,
    )
    _cpipe_new_bound = staticmethod(_cpipe_new_fn)
    setattr(_CEDAR_PIPE_CLS, "__new__", _cpipe_new_bound)
    _audit_codes.append(_cpipe_new_fn.__code__)
    _expected_audit_funcs.append((_cpipe_new_fn, _cpipe_new_fn.__code__, _cpipe_new_fn.__defaults__, None))
    _expected_audit_cls_attrs.append((_CEDAR_PIPE_CLS, "__new__", _cpipe_new_bound))
    for _cmname in ("__init__", "close", "__del__", "__setattr__", "__delattr__"):
        _cmorig = _CEDAR_PIPE_CLS.__dict__[_cmname]
        _cmfn = types.FunctionType(
            _cmorig.__code__,
            _AUDIT_GLOBALS,
            _cmorig.__name__,
            _cmorig.__defaults__,
            None,
        )
        if _cmorig.__kwdefaults__ is not None:
            _cmfn.__kwdefaults__ = dict(_cmorig.__kwdefaults__)
        setattr(_CEDAR_PIPE_CLS, _cmname, _cmfn)
        _audit_codes.append(_cmfn.__code__)
        _expected_audit_funcs.append((_cmfn, _cmfn.__code__, _cmfn.__defaults__, _cmfn.__kwdefaults__))
        _expected_audit_cls_attrs.append((_CEDAR_PIPE_CLS, _cmname, _cmfn))

    _audit_codes_set = _collect_nested_codes(_audit_codes)
    dict.__setitem__(_AUDIT_GLOBALS, "_AUDIT_GLOBALS", _AUDIT_GLOBALS)
    dict.__setitem__(_AUDIT_GLOBALS, "_AUDIT_CODES", _audit_codes_set)
    dict.__setitem__(_AUDIT_GLOBALS, "_CEDAR_PIPE_CLS", _CEDAR_PIPE_CLS)
    dict.__setitem__(_AUDIT_GLOBALS, "_QUERY_CEDAR_IPC_CODE", dict.__getitem__(_AUDIT_GLOBALS, "_query_cedar_ipc").__code__)
    dict.__setitem__(_AUDIT_GLOBALS, "_CHECK_PINNED_SUBTREE_CODE", dict.__getitem__(_AUDIT_GLOBALS, "_check_pinned_subtree").__code__)
    dict.__setitem__(_AUDIT_GLOBALS, "_HANDLE_TRACE_OP_CODE", dict.__getitem__(_AUDIT_GLOBALS, "_handle_trace_op").__code__)
    dict.__setitem__(_AUDIT_GLOBALS, "_HANDLE_STAT_OP_CODE", dict.__getitem__(_AUDIT_GLOBALS, "_handle_stat_op").__code__)

    _FAILCLOSED_HOOK = dict.__getitem__(_AUDIT_GLOBALS, "_octopus_failclosed_guard")
    _FAILCLOSED_CODE = _FAILCLOSED_HOOK.__code__

    _audit_mutable_keys = {
        "__warningregistry__": dict,
        "_AUDIT_DENY_ARMED": dict,
        "_TRACE_UNWIND_ARMED": dict,
        "_AUDIT_STACK_CHECK_ACTIVE": dict,
        "_GATE_TL": _THREADING_LOCAL_TYPE,
        "_PENDING_SQLITE_CONNS": list,
        "_POPEN_LOCK": _LOCK_TYPE,
        "_GC_MAP_LOCK": _LOCK_TYPE,
        "_STAT_GC_QUEUE_REF": list,
        "_SQLITE_GC_QUEUE_REF": list,
        "_POPEN_TOKENS": dict,
        "_CEDAR_TL": _THREADING_LOCAL_TYPE,
        "_SQLITE_CONN_MAP": dict,
        "_SQLITE_CURSOR_MAP": dict,
        "_SQLITE_RAW_TO_CURSOR": dict,
        "_SQLITE_CONNECT_PENDING": dict,
        "_SIGNAL_SIG_MAP": dict,
        "_AUDIT_GETFRAME_ACTIVE": dict,
        "_SCANDIR_MAP": dict,
        "_DIRENTRY_MAP": dict,
    }
    _expected_audit_mutable = tuple(
        (k, dict.__getitem__(_AUDIT_GLOBALS, k), exp_t) for k, exp_t in _audit_mutable_keys.items()
    )

    _expected_win_path_attrs = []
    if _IS_WIN and _RAW_OS_MOD is not None:
        for _raw_attr, _path_attr, _gfn in (
            ("_path_exists", "exists", _GUARDED_NT_PATH_EXISTS),
            ("_path_lexists", "lexists", _GUARDED_NT_PATH_LEXISTS),
            ("_path_isfile", "isfile", _GUARDED_NT_PATH_ISFILE),
            ("_path_isdir", "isdir", _GUARDED_NT_PATH_ISDIR),
            ("_path_islink", "islink", _GUARDED_NT_PATH_ISLINK),
            ("_path_isjunction", "isjunction", _GUARDED_NT_PATH_ISJUNCTION),
            ("_getfinalpathname", "_getfinalpathname", _GUARDED_NT_GETFINALPATHNAME),
            ("_findfirstfile", None, _GUARDED_NT_FINDFIRSTFILE),
        ):
            if _gfn is not None:
                _expected_win_path_attrs.append((_raw_attr, _path_attr if (_path_attr is not None and hasattr(_OS_PATH_MOD, _path_attr)) else None, _gfn))
    _EXPECTED_WIN_PATH_ATTRS = tuple(_expected_win_path_attrs)

    _glob_sg_cls = getattr(_GLOB_MOD, "_StringGlobber", None) if _GLOB_MOD is not None else None
    _expected_glob_sg_attrs_list = []
    _orig_ospath_lexists = getattr(_OS_PATH_MOD, "lexists", None)
    if _glob_sg_cls is not None:
        _sg_sc = _glob_sg_cls.__dict__.get("scandir")
        if isinstance(_sg_sc, staticmethod) and _sg_sc.__func__ is _ORIG_OS_SCANDIR:
            _new_sg_sc = staticmethod(_GUARDED_OS_SCANDIR)
            _glob_sg_cls.scandir = _new_sg_sc
            _expected_glob_sg_attrs_list.append(("scandir", _new_sg_sc))
        _sg_ls = _glob_sg_cls.__dict__.get("lstat")
        if isinstance(_sg_ls, staticmethod) and _sg_ls.__func__ is _ORIG_OS_LSTAT:
            _new_sg_ls = staticmethod(_GUARDED_OS_LSTAT)
            _glob_sg_cls.lstat = _new_sg_ls
            _expected_glob_sg_attrs_list.append(("lstat", _new_sg_ls))
        _sg_lx = _glob_sg_cls.__dict__.get("lexists")
        if (
            isinstance(_sg_lx, staticmethod)
            and _GUARDED_NT_PATH_LEXISTS is not None
            and (_sg_lx.__func__ is _ORIG_NT_PATH_LEXISTS or _sg_lx.__func__ is _orig_ospath_lexists)
        ):
            _new_sg_lx = staticmethod(_GUARDED_NT_PATH_LEXISTS)
            _glob_sg_cls.lexists = _new_sg_lx
            _expected_glob_sg_attrs_list.append(("lexists", _new_sg_lx))
    _expected_glob_sg_attrs = tuple(_expected_glob_sg_attrs_list)
    _exp_nt_readlink = (_GUARDED_OS_READLINK is not None and getattr(ntpath, "_nt_readlink", None) is _ORIG_OS_READLINK)
    _wd_tick = [0]
    _wd_fast_events = frozenset((
        "octopus.stat_op",
        "sys._getframe",
        "import",
        "exec",
        "marshal.loads",
        "compile",
        "sys._getframemodulename",
    ))

    _wd_active = {}
    _wd_plain = {
        "__builtins__": _FROZEN_BUILTINS,
        "__name__": "__octopus_watchdog__",
        "__warningregistry__": {},
        "_OS_EXIT": _OS_EXIT,
        "_SYS_IS_FINALIZING": _SYS_IS_FINALIZING,
        "_GET_IDENT": _GET_IDENT,
        "_FRAME_TYPE": _FRAME_TYPE,
        "_THREADING_LOCAL_TYPE_REF": _THREADING_LOCAL_TYPE,
        "_DICT_GET": _DICT_GET,
        "_DICT_POP": _DICT_POP,
        "_DICT_LEN": _DICT_LEN,
        "_DICT_GETITEM": _DICT_GETITEM,
        "_WD_ACTIVE": _wd_active,
        "_FROZEN_DICT_CLS": _FrozenDict,
        "_FROZEN_MOD_CLS": _FrozenModule,
        "_FROZEN_DENY_FN": _FROZEN_DENY_FN,
        "_FROZEN_DENY_CODE": _FROZEN_DENY_CODE,
        "_FROZEN_MOD_SETATTR_FN": _FROZEN_MOD_SETATTR_FN,
        "_FROZEN_MOD_SETATTR_CODE": _FROZEN_MOD_SETATTR_CODE,
        "_FROZEN_MOD_DELATTR_FN": _FROZEN_MOD_DELATTR_FN,
        "_FROZEN_MOD_DELATTR_CODE": _FROZEN_MOD_DELATTR_CODE,
        "_FROZEN_BUILTINS_REF": _FROZEN_BUILTINS,
        "_EXPECTED_BUILTINS_ITEMS": _EXPECTED_BUILTINS_ITEMS,
        "_EXPECTED_BUILTINS_LEN": _EXPECTED_BUILTINS_LEN,
        "_AUDIT_GLOBALS_REF": _AUDIT_GLOBALS,
        "_EXPECTED_AUDIT_ITEMS": None,
        "_EXPECTED_AUDIT_MUTABLE": _expected_audit_mutable,
        "_EXPECTED_AUDIT_LEN": 0,
        "_EXPECTED_AUDIT_FUNCS": tuple(_expected_audit_funcs),
        "_EXPECTED_AUDIT_CLS_ATTRS": tuple(_expected_audit_cls_attrs),
        "_FAILCLOSED_HOOK_REF": _FAILCLOSED_HOOK,
        "_FAILCLOSED_CODE_REF": _FAILCLOSED_CODE,
        "_GATE_GLOBALS_REF": _GATE_GLOBALS,
        "_GATE_HOOK_REF": _GATE_HOOK,
        "_GATE_CODE_REF": _GATE_CODE,
        "_GATE_TL_REF": _gate_tl,
        "_GATE_WARNREG_REF": _GATE_WARNREG_REF,
        "_EXPECTED_GATE_ITEMS": _EXPECTED_GATE_ITEMS,
        "_EXPECTED_GATE_LEN": _EXPECTED_GATE_LEN,
        "_LIST2CMD_GLOBALS_REF": _LIST2CMD_GLOBALS,
        "_GUARDED_LIST2CMDLINE_REF": _GUARDED_LIST2CMDLINE,
        "_GUARDED_LIST2CMD_CODE": _GUARDED_LIST2CMD_CODE,
        "_L2C_WARNREG_REF": _L2C_WARNREG_REF,
        "_EXPECTED_L2C_ITEMS": _EXPECTED_L2C_ITEMS,
        "_EXPECTED_L2C_LEN": _EXPECTED_L2C_LEN,
        "_EXPECTED_L2C_FUNCS": _EXPECTED_L2C_FUNCS,
        "_SQLITE_GLOBALS_REF": _SQLITE_GLOBALS,
        "_SQLITE_WRAPPER_CLS_REF": _SQLITE_WRAPPER_CLS,
        "_SQLITE_CURSOR_CLS_REF": _SQLITE_CURSOR_CLS,
        "_SQLITE_METHOD_CLS_REF": _SQLITE_METHOD_CLS,
        "_SQLITE_CLEANUP_CLS_REF": _SQLITE_CLEANUP_CLS,
        "_GUARDED_SQLITE_CONNECT_REF": _GUARDED_SQLITE_CONNECT,
        "_GUARDED_SQLITE_DENIED_REG_REF": _GUARDED_SQLITE_DENIED_REG,
        "_SQLITE_WARNREG_REF": _SQLITE_WARNREG_REF,
        "_EXPECTED_SQLITE_ITEMS": _EXPECTED_SQLITE_ITEMS,
        "_EXPECTED_SQLITE_LEN": _EXPECTED_SQLITE_LEN,
        "_EXPECTED_SQLITE_FUNCS": tuple(_expected_sqlite_funcs),
        "_EXPECTED_SQLITE_CLS_ATTRS": tuple(_expected_sqlite_cls_attrs),
        "_ORIG_SQLITE_ROW_REF": _ORIG_SQLITE_ROW,
        "_SQLITE_MOD_REF": _SQLITE_MOD,
        "_RAW_SQLITE_MOD_REF": _RAW_SQLITE_MOD,
        "_SIGNAL_GLOBALS_REF": _SIGNAL_GLOBALS,
        "_SIGNAL_HANDLER_CLS_REF": _SIGNAL_HANDLER_CLS,
        "_GUARDED_SIGNAL_REF": _GUARDED_SIGNAL,
        "_GUARDED_GETSIGNAL_REF": _GUARDED_GETSIGNAL,
        "_GUARDED_RAW_SIGNAL_REF": _GUARDED_RAW_SIGNAL,
        "_GUARDED_RAW_GETSIGNAL_REF": _GUARDED_RAW_GETSIGNAL,
        "_SIGNAL_WARNREG_REF": _SIGNAL_WARNREG_REF,
        "_EXPECTED_SIGNAL_ITEMS": None,
        "_EXPECTED_SIGNAL_LEN": 0,
        "_EXPECTED_SIGNAL_FUNCS": tuple(_expected_signal_funcs),
        "_EXPECTED_SIGNAL_CLS_ATTRS": tuple(_expected_signal_cls_attrs),
        "_SIGNAL_MOD_REF": _SIGNAL_MOD,
        "_RAW_SIGNAL_MOD_REF": _RAW_SIGNAL_MOD,
        "_SYS_MOD_REF": _SYS_MOD,
        "_ADDHOOK_GLOBALS_REF": _ADDHOOK_GLOBALS,
        "_GUARDED_ADDAUDITHOOK_REF": _GUARDED_ADDAUDITHOOK,
        "_ADDHOOK_CODE_REF": _ADDHOOK_CODE,
        "_ADDHOOK_WARNREG_REF": _ADDHOOK_WARNREG_REF,
        "_EXPECTED_ADDHOOK_ITEMS": _EXPECTED_ADDHOOK_ITEMS,
        "_EXPECTED_ADDHOOK_LEN": _EXPECTED_ADDHOOK_LEN,
        "_TRACE_GLOBALS_REF": _TRACE_GLOBALS,
        "_TRACE_WARNREG_REF": _TRACE_WARNREG_REF,
        "_EXPECTED_TRACE_ITEMS": None,
        "_EXPECTED_TRACE_LEN": 0,
        "_EXPECTED_TRACE_FUNCS": tuple(_expected_trace_funcs),
        "_EXPECTED_TRACE_CLS_ATTRS": tuple(_expected_trace_cls_attrs),
        "_GUARDED_SETTRACE_REF": _GUARDED_SETTRACE,
        "_GUARDED_GETTRACE_REF": _GUARDED_GETTRACE,
        "_GUARDED_SETPROFILE_REF": _GUARDED_SETPROFILE,
        "_GUARDED_GETPROFILE_REF": _GUARDED_GETPROFILE,
        "_GUARDED_SETTRACEALL_REF": _GUARDED_SETTRACEALL,
        "_GUARDED_SETPROFILEALL_REF": _GUARDED_SETPROFILEALL,
        "_SYS_MON_MOD_REF": _SYS_MON_MOD,
        "_GUARDED_MON_REGISTER_REF": _GUARDED_MON_REGISTER,
        "_GUARDED_MON_SET_LOCAL_REF": _GUARDED_MON_SET_LOCAL,
        "_STAT_GLOBALS_REF": _STAT_GLOBALS,
        "_STAT_WARNREG_REF": _STAT_WARNREG_REF,
        "_EXPECTED_STAT_ITEMS": _EXPECTED_STAT_ITEMS,
        "_EXPECTED_STAT_LEN": _EXPECTED_STAT_LEN,
        "_EXPECTED_STAT_FUNCS": tuple(_expected_stat_funcs),
        "_EXPECTED_STAT_CLS_ATTRS": tuple(_expected_stat_cls_attrs),
        "_OS_MOD_REF": _OS_MOD,
        "_RAW_OS_MOD_REF": _RAW_OS_MOD,
        "_OS_PATH_MOD_REF": _OS_PATH_MOD,
        "_NTPATH_MOD_REF": ntpath,
        "_EXP_NT_READLINK": _exp_nt_readlink,
        "_GLOB_SG_CLS": _glob_sg_cls,
        "_EXPECTED_GLOB_SG_ATTRS": _expected_glob_sg_attrs,
        "_GUARDED_OS_STAT_REF": _GUARDED_OS_STAT,
        "_GUARDED_OS_LSTAT_REF": _GUARDED_OS_LSTAT,
        "_GUARDED_OS_ACCESS_REF": _GUARDED_OS_ACCESS,
        "_GUARDED_OS_SCANDIR_REF": _GUARDED_OS_SCANDIR,
        "_GUARDED_OS_READLINK_REF": _GUARDED_OS_READLINK,
        "_EXPECTED_WIN_PATH_ATTRS": _EXPECTED_WIN_PATH_ATTRS,
        "_WD_TICK": _wd_tick,
        "_WD_FAST_EVENTS": _wd_fast_events,
        "_WATCHDOG_GLOBALS_REF": None,
        "_WATCHDOG_CODE": None,
        "_WATCHDOG_HOOK_REF": None,
        "_WD_WARNREG_REF": None,
        "_EXPECTED_WD_ITEMS": None,
        "_EXPECTED_WD_LEN": 0,
    }
    _wd_src = '''
def _watchdog_audit(event, args, _os_exit=_OS_EXIT):
    if (
        event == "object.__getattr__"
        and len(args) >= 2
        and type(args[1]) is str
        and args[1] in ("f_code", "__code__", "__defaults__", "__kwdefaults__")
    ):
        return
    _tid = _GET_IDENT()
    _set_active = False
    try:
        if _DICT_GET(_WD_ACTIVE, _tid, False):
            return
        _WD_ACTIVE[_tid] = True
        _set_active = True
        if event == "sys._getframe":
            _f = args[0] if args else None
            while type(_f) is _FRAME_TYPE:
                if _f.f_globals is _WATCHDOG_GLOBALS_REF or _f.f_code is _WATCHDOG_CODE:
                    _os_exit(1)
                _f = _f.f_back
        if (
            _FROZEN_DICT_CLS.__setitem__ is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.__delitem__ is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.update is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.clear is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.pop is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.popitem is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.setdefault is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.__ior__ is not _FROZEN_DENY_FN
            or _FROZEN_DICT_CLS.copy is not _FROZEN_DENY_FN
            or _FROZEN_DENY_FN.__code__ is not _FROZEN_DENY_CODE
            or _FROZEN_DENY_FN.__closure__ is not None
            or _FROZEN_MOD_CLS.__setattr__ is not _FROZEN_MOD_SETATTR_FN
            or _FROZEN_MOD_SETATTR_FN.__code__ is not _FROZEN_MOD_SETATTR_CODE
            or _FROZEN_MOD_CLS.__delattr__ is not _FROZEN_MOD_DELATTR_FN
            or _FROZEN_MOD_DELATTR_FN.__code__ is not _FROZEN_MOD_DELATTR_CODE
        ):
            _os_exit(1)
        if (
            type(_WATCHDOG_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_WATCHDOG_GLOBALS_REF) != _EXPECTED_WD_LEN
            or _DICT_GETITEM(_WATCHDOG_GLOBALS_REF, "_EXPECTED_WD_ITEMS") is not _EXPECTED_WD_ITEMS
            or _DICT_GETITEM(_WATCHDOG_GLOBALS_REF, "__warningregistry__") is not _WD_WARNREG_REF
            or type(_WD_WARNREG_REF) is not dict
            or type(_WD_ACTIVE) is not dict
            or type(_WD_TICK) is not list
            or len(_WD_TICK) != 1
            or type(_WD_TICK[0]) is not int
            or _WATCHDOG_HOOK_REF.__code__ is not _WATCHDOG_CODE
            or _WATCHDOG_HOOK_REF.__globals__ is not _WATCHDOG_GLOBALS_REF
            or _WATCHDOG_HOOK_REF.__closure__ is not None
            or len(_WATCHDOG_HOOK_REF.__defaults__) != 1
            or _WATCHDOG_HOOK_REF.__defaults__[0] is not _OS_EXIT
        ):
            _os_exit(1)
        if (
            type(_AUDIT_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_AUDIT_GLOBALS_REF) != _EXPECTED_AUDIT_LEN
            or type(_GATE_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_GATE_GLOBALS_REF) != _EXPECTED_GATE_LEN
            or type(_STAT_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_STAT_GLOBALS_REF) != _EXPECTED_STAT_LEN
        ):
            _os_exit(1)
        _fin = _SYS_IS_FINALIZING()
        if (
            not (_SYS_MOD_REF.addaudithook is _GUARDED_ADDAUDITHOOK_REF or (_fin and getattr(_SYS_MOD_REF, "addaudithook", None) is None))
            or not (_OS_MOD_REF.stat is _GUARDED_OS_STAT_REF or (_fin and getattr(_OS_MOD_REF, "stat", None) is None))
            or not (_OS_MOD_REF.lstat is _GUARDED_OS_LSTAT_REF or (_fin and getattr(_OS_MOD_REF, "lstat", None) is None))
            or not (_OS_MOD_REF.access is _GUARDED_OS_ACCESS_REF or (_fin and getattr(_OS_MOD_REF, "access", None) is None))
            or not (_OS_MOD_REF.scandir is _GUARDED_OS_SCANDIR_REF or (_fin and getattr(_OS_MOD_REF, "scandir", None) is None))
            or (_GUARDED_OS_READLINK_REF is not None and not (_OS_MOD_REF.readlink is _GUARDED_OS_READLINK_REF or (_fin and getattr(_OS_MOD_REF, "readlink", None) is None)))
            or (_RAW_OS_MOD_REF is not None and not (_RAW_OS_MOD_REF.stat is _GUARDED_OS_STAT_REF or (_fin and getattr(_RAW_OS_MOD_REF, "stat", None) is None)))
            or (_RAW_OS_MOD_REF is not None and not (_RAW_OS_MOD_REF.lstat is _GUARDED_OS_LSTAT_REF or (_fin and getattr(_RAW_OS_MOD_REF, "lstat", None) is None)))
            or (_RAW_OS_MOD_REF is not None and not (_RAW_OS_MOD_REF.access is _GUARDED_OS_ACCESS_REF or (_fin and getattr(_RAW_OS_MOD_REF, "access", None) is None)))
            or (_RAW_OS_MOD_REF is not None and not (_RAW_OS_MOD_REF.scandir is _GUARDED_OS_SCANDIR_REF or (_fin and getattr(_RAW_OS_MOD_REF, "scandir", None) is None)))
            or (_RAW_OS_MOD_REF is not None and _GUARDED_OS_READLINK_REF is not None and hasattr(_RAW_OS_MOD_REF, "readlink") and not (_RAW_OS_MOD_REF.readlink is _GUARDED_OS_READLINK_REF or (_fin and getattr(_RAW_OS_MOD_REF, "readlink", None) is None)))
            or (_EXP_NT_READLINK and not (_NTPATH_MOD_REF._nt_readlink is _GUARDED_OS_READLINK_REF or (_fin and getattr(_NTPATH_MOD_REF, "_nt_readlink", None) is None)))
        ):
            _os_exit(1)
        if _GLOB_SG_CLS is not None and not _fin:
            _sg_d = _GLOB_SG_CLS.__dict__
            for _ga, _gsm in _EXPECTED_GLOB_SG_ATTRS:
                if _sg_d.get(_ga) is not _gsm:
                    _os_exit(1)
        for _raw_attr, _path_attr, _gfn in _EXPECTED_WIN_PATH_ATTRS:
            if _RAW_OS_MOD_REF is not None and not (getattr(_RAW_OS_MOD_REF, _raw_attr, None) is _gfn or (_fin and getattr(_RAW_OS_MOD_REF, _raw_attr, None) is None)):
                _os_exit(1)
            if _path_attr is not None and not (getattr(_OS_PATH_MOD_REF, _path_attr, None) is _gfn or (_fin and getattr(_OS_PATH_MOD_REF, _path_attr, None) is None)):
                _os_exit(1)
        if event in _WD_FAST_EVENTS:
            _tval = (_WD_TICK[0] + 1) & 63
            _WD_TICK[0] = _tval
            if _tval != 0:
                return
        if type(_FROZEN_BUILTINS_REF) is not _FROZEN_DICT_CLS or _DICT_LEN(_FROZEN_BUILTINS_REF) != _EXPECTED_BUILTINS_LEN:
            _os_exit(1)
        for _k, _exp_v in _EXPECTED_BUILTINS_ITEMS:
            if _DICT_GETITEM(_FROZEN_BUILTINS_REF, _k) is not _exp_v:
                _os_exit(1)
        for _k, _exp_v in _EXPECTED_WD_ITEMS:
            if _DICT_GETITEM(_WATCHDOG_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        for _k, _exp_v in _EXPECTED_AUDIT_ITEMS:
            if _DICT_GETITEM(_AUDIT_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        for _k, _exp_obj, _exp_t in _EXPECTED_AUDIT_MUTABLE:
            _cur_obj = _DICT_GETITEM(_AUDIT_GLOBALS_REF, _k)
            if _cur_obj is not _exp_obj or type(_cur_obj) is not _exp_t:
                _os_exit(1)
        for _fn, _exp_code, _exp_defs, _exp_kwdefs in _EXPECTED_AUDIT_FUNCS:
            if (
                _fn.__code__ is not _exp_code
                or _fn.__globals__ is not _AUDIT_GLOBALS_REF
                or _fn.__closure__ is not None
                or _fn.__defaults__ != _exp_defs
                or _fn.__kwdefaults__ != _exp_kwdefs
            ):
                _os_exit(1)
        for _cls, _aname, _exp_attr in _EXPECTED_AUDIT_CLS_ATTRS:
            if _cls.__dict__[_aname] is not _exp_attr:
                _os_exit(1)
        if (
            _FAILCLOSED_HOOK_REF.__code__ is not _FAILCLOSED_CODE_REF
            or _FAILCLOSED_HOOK_REF.__globals__ is not _AUDIT_GLOBALS_REF
            or _FAILCLOSED_HOOK_REF.__closure__ is not None
            or len(_FAILCLOSED_HOOK_REF.__defaults__) != 1
            or _FAILCLOSED_HOOK_REF.__defaults__[0] is not _OS_EXIT
        ):
            _os_exit(1)
        if (
            type(_GATE_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_GATE_GLOBALS_REF) != _EXPECTED_GATE_LEN
            or _DICT_GETITEM(_GATE_GLOBALS_REF, "_GATE_TL") is not _GATE_TL_REF
            or type(_GATE_TL_REF) is not _THREADING_LOCAL_TYPE_REF
            or _DICT_GETITEM(_GATE_GLOBALS_REF, "__warningregistry__") is not _GATE_WARNREG_REF
            or type(_GATE_WARNREG_REF) is not dict
            or _GATE_HOOK_REF.__code__ is not _GATE_CODE_REF
            or _GATE_HOOK_REF.__globals__ is not _GATE_GLOBALS_REF
            or _GATE_HOOK_REF.__closure__ is not None
            or _GATE_HOOK_REF.__defaults__ is not None
        ):
            _os_exit(1)
        for _k, _exp_v in _EXPECTED_GATE_ITEMS:
            if _DICT_GETITEM(_GATE_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        if _GUARDED_LIST2CMDLINE_REF is not None:
            if (
                type(_LIST2CMD_GLOBALS_REF) is not _FROZEN_DICT_CLS
                or _DICT_LEN(_LIST2CMD_GLOBALS_REF) != _EXPECTED_L2C_LEN
                or _DICT_GETITEM(_LIST2CMD_GLOBALS_REF, "__warningregistry__") is not _L2C_WARNREG_REF
                or type(_L2C_WARNREG_REF) is not dict
                or _GUARDED_LIST2CMDLINE_REF.__code__ is not _GUARDED_LIST2CMD_CODE
                or _GUARDED_LIST2CMDLINE_REF.__globals__ is not _LIST2CMD_GLOBALS_REF
                or _GUARDED_LIST2CMDLINE_REF.__closure__ is not None
                or _GUARDED_LIST2CMDLINE_REF.__defaults__ is not None
            ):
                _os_exit(1)
            for _k, _exp_v in _EXPECTED_L2C_ITEMS:
                if _DICT_GETITEM(_LIST2CMD_GLOBALS_REF, _k) is not _exp_v:
                    _os_exit(1)
            for _fn, _exp_code, _exp_defs, _exp_kwdefs in _EXPECTED_L2C_FUNCS:
                if (
                    _fn.__code__ is not _exp_code
                    or _fn.__globals__ is not _LIST2CMD_GLOBALS_REF
                    or _fn.__closure__ is not None
                    or _fn.__defaults__ != _exp_defs
                    or _fn.__kwdefaults__ != _exp_kwdefs
                ):
                    _os_exit(1)
        if (
            type(_SQLITE_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_SQLITE_GLOBALS_REF) != _EXPECTED_SQLITE_LEN
            or _DICT_GETITEM(_SQLITE_GLOBALS_REF, "__warningregistry__") is not _SQLITE_WARNREG_REF
            or type(_SQLITE_WARNREG_REF) is not dict
        ):
            _os_exit(1)
        for _k, _exp_v in _EXPECTED_SQLITE_ITEMS:
            if _DICT_GETITEM(_SQLITE_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        for _fn, _exp_code, _exp_defs, _exp_kwdefs in _EXPECTED_SQLITE_FUNCS:
            if (
                _fn.__code__ is not _exp_code
                or _fn.__globals__ is not _SQLITE_GLOBALS_REF
                or _fn.__closure__ is not None
                or _fn.__defaults__ != _exp_defs
                or _fn.__kwdefaults__ != _exp_kwdefs
            ):
                _os_exit(1)
        for _cls, _aname, _exp_attr in _EXPECTED_SQLITE_CLS_ATTRS:
            if _cls.__dict__[_aname] is not _exp_attr:
                _os_exit(1)
        if (
            type(_SIGNAL_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_SIGNAL_GLOBALS_REF) != _EXPECTED_SIGNAL_LEN
            or _DICT_GETITEM(_SIGNAL_GLOBALS_REF, "__warningregistry__") is not _SIGNAL_WARNREG_REF
            or type(_SIGNAL_WARNREG_REF) is not dict
        ):
            _os_exit(1)
        for _k, _exp_v in _EXPECTED_SIGNAL_ITEMS:
            if _DICT_GETITEM(_SIGNAL_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        for _fn, _exp_code, _exp_defs, _exp_kwdefs in _EXPECTED_SIGNAL_FUNCS:
            if (
                _fn.__code__ is not _exp_code
                or _fn.__globals__ is not _SIGNAL_GLOBALS_REF
                or _fn.__closure__ is not None
                or _fn.__defaults__ != _exp_defs
                or _fn.__kwdefaults__ != _exp_kwdefs
            ):
                _os_exit(1)
        for _cls, _aname, _exp_attr in _EXPECTED_SIGNAL_CLS_ATTRS:
            if _cls.__dict__[_aname] is not _exp_attr:
                _os_exit(1)
        if (
            type(_TRACE_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_TRACE_GLOBALS_REF) != _EXPECTED_TRACE_LEN
            or _DICT_GETITEM(_TRACE_GLOBALS_REF, "__warningregistry__") is not _TRACE_WARNREG_REF
            or type(_TRACE_WARNREG_REF) is not dict
        ):
            _os_exit(1)
        for _k, _exp_v in _EXPECTED_TRACE_ITEMS:
            if _DICT_GETITEM(_TRACE_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        for _fn, _exp_code, _exp_defs, _exp_kwdefs in _EXPECTED_TRACE_FUNCS:
            if (
                _fn.__code__ is not _exp_code
                or _fn.__globals__ is not _TRACE_GLOBALS_REF
                or _fn.__closure__ is not None
                or _fn.__defaults__ != _exp_defs
                or _fn.__kwdefaults__ != _exp_kwdefs
            ):
                _os_exit(1)
        for _cls, _aname, _exp_attr in _EXPECTED_TRACE_CLS_ATTRS:
            if _cls.__dict__[_aname] is not _exp_attr:
                _os_exit(1)
        if (
            type(_STAT_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_STAT_GLOBALS_REF) != _EXPECTED_STAT_LEN
            or _DICT_GETITEM(_STAT_GLOBALS_REF, "__warningregistry__") is not _STAT_WARNREG_REF
            or type(_STAT_WARNREG_REF) is not dict
        ):
            _os_exit(1)
        for _k, _exp_v in _EXPECTED_STAT_ITEMS:
            if _DICT_GETITEM(_STAT_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        for _fn, _exp_code, _exp_defs, _exp_kwdefs in _EXPECTED_STAT_FUNCS:
            if (
                _fn.__code__ is not _exp_code
                or _fn.__globals__ is not _STAT_GLOBALS_REF
                or _fn.__closure__ is not None
                or _fn.__defaults__ != _exp_defs
                or _fn.__kwdefaults__ != _exp_kwdefs
            ):
                _os_exit(1)
        for _cls, _aname, _exp_attr in _EXPECTED_STAT_CLS_ATTRS:
            if _cls.__dict__[_aname] is not _exp_attr:
                _os_exit(1)
        if (
            type(_ADDHOOK_GLOBALS_REF) is not _FROZEN_DICT_CLS
            or _DICT_LEN(_ADDHOOK_GLOBALS_REF) != _EXPECTED_ADDHOOK_LEN
            or _DICT_GETITEM(_ADDHOOK_GLOBALS_REF, "__warningregistry__") is not _ADDHOOK_WARNREG_REF
            or type(_ADDHOOK_WARNREG_REF) is not dict
            or _GUARDED_ADDAUDITHOOK_REF.__code__ is not _ADDHOOK_CODE_REF
            or _GUARDED_ADDAUDITHOOK_REF.__globals__ is not _ADDHOOK_GLOBALS_REF
            or _GUARDED_ADDAUDITHOOK_REF.__closure__ is not None
            or _GUARDED_ADDAUDITHOOK_REF.__defaults__ is not None
        ):
            _os_exit(1)
        for _k, _exp_v in _EXPECTED_ADDHOOK_ITEMS:
            if _DICT_GETITEM(_ADDHOOK_GLOBALS_REF, _k) is not _exp_v:
                _os_exit(1)
        if (
            not (_SQLITE_MOD_REF.connect is _GUARDED_SQLITE_CONNECT_REF or (_fin and getattr(_SQLITE_MOD_REF, "connect", None) is None))
            or not (_RAW_SQLITE_MOD_REF.connect is _GUARDED_SQLITE_CONNECT_REF or (_fin and getattr(_RAW_SQLITE_MOD_REF, "connect", None) is None))
            or not (_SQLITE_MOD_REF.Connection is _SQLITE_WRAPPER_CLS_REF or (_fin and getattr(_SQLITE_MOD_REF, "Connection", None) is None))
            or not (_RAW_SQLITE_MOD_REF.Connection is _SQLITE_WRAPPER_CLS_REF or (_fin and getattr(_RAW_SQLITE_MOD_REF, "Connection", None) is None))
            or not (_SQLITE_MOD_REF.Cursor is _SQLITE_CURSOR_CLS_REF or (_fin and getattr(_SQLITE_MOD_REF, "Cursor", None) is None))
            or not (_RAW_SQLITE_MOD_REF.Cursor is _SQLITE_CURSOR_CLS_REF or (_fin and getattr(_RAW_SQLITE_MOD_REF, "Cursor", None) is None))
            or not (_SQLITE_MOD_REF.Row is _ORIG_SQLITE_ROW_REF or (_fin and getattr(_SQLITE_MOD_REF, "Row", None) is None))
            or not (_RAW_SQLITE_MOD_REF.Row is _ORIG_SQLITE_ROW_REF or (_fin and getattr(_RAW_SQLITE_MOD_REF, "Row", None) is None))
            or not (_SQLITE_MOD_REF.register_adapter is _GUARDED_SQLITE_DENIED_REG_REF or (_fin and getattr(_SQLITE_MOD_REF, "register_adapter", None) is None))
            or not (_RAW_SQLITE_MOD_REF.register_adapter is _GUARDED_SQLITE_DENIED_REG_REF or (_fin and getattr(_RAW_SQLITE_MOD_REF, "register_adapter", None) is None))
            or not (_SQLITE_MOD_REF.register_converter is _GUARDED_SQLITE_DENIED_REG_REF or (_fin and getattr(_SQLITE_MOD_REF, "register_converter", None) is None))
            or not (_RAW_SQLITE_MOD_REF.register_converter is _GUARDED_SQLITE_DENIED_REG_REF or (_fin and getattr(_RAW_SQLITE_MOD_REF, "register_converter", None) is None))
            or not (_SIGNAL_MOD_REF.signal is _GUARDED_SIGNAL_REF or (_fin and getattr(_SIGNAL_MOD_REF, "signal", None) is None))
            or not (_RAW_SIGNAL_MOD_REF.signal is _GUARDED_RAW_SIGNAL_REF or (_fin and getattr(_RAW_SIGNAL_MOD_REF, "signal", None) is None))
            or not (_SIGNAL_MOD_REF.getsignal is _GUARDED_GETSIGNAL_REF or (_fin and getattr(_SIGNAL_MOD_REF, "getsignal", None) is None))
            or not (_RAW_SIGNAL_MOD_REF.getsignal is _GUARDED_RAW_GETSIGNAL_REF or (_fin and getattr(_RAW_SIGNAL_MOD_REF, "getsignal", None) is None))
            or not (_SYS_MOD_REF.settrace is _GUARDED_SETTRACE_REF or (_fin and getattr(_SYS_MOD_REF, "settrace", None) is None))
            or not (_SYS_MOD_REF.gettrace is _GUARDED_GETTRACE_REF or (_fin and getattr(_SYS_MOD_REF, "gettrace", None) is None))
            or not (_SYS_MOD_REF.setprofile is _GUARDED_SETPROFILE_REF or (_fin and getattr(_SYS_MOD_REF, "setprofile", None) is None))
            or not (_SYS_MOD_REF.getprofile is _GUARDED_GETPROFILE_REF or (_fin and getattr(_SYS_MOD_REF, "getprofile", None) is None))
            or (_GUARDED_SETTRACEALL_REF is not None and not (_SYS_MOD_REF._settraceallthreads is _GUARDED_SETTRACEALL_REF or (_fin and getattr(_SYS_MOD_REF, "_settraceallthreads", None) is None)))
            or (_GUARDED_SETPROFILEALL_REF is not None and not (_SYS_MOD_REF._setprofileallthreads is _GUARDED_SETPROFILEALL_REF or (_fin and getattr(_SYS_MOD_REF, "_setprofileallthreads", None) is None)))
            or (_GUARDED_MON_REGISTER_REF is not None and not (_SYS_MON_MOD_REF.register_callback is _GUARDED_MON_REGISTER_REF or (_fin and getattr(_SYS_MON_MOD_REF, "register_callback", None) is None)))
            or (_GUARDED_MON_SET_LOCAL_REF is not None and not (_SYS_MON_MOD_REF.set_local_events is _GUARDED_MON_SET_LOCAL_REF or (_fin and getattr(_SYS_MON_MOD_REF, "set_local_events", None) is None)))
        ):
            _os_exit(1)
    except BaseException:
        _os_exit(1)
    finally:
        if _set_active:
            _DICT_POP(_WD_ACTIVE, _tid, None)
'''
    exec(compile(_wd_src, "<octopus_watchdog>", "exec"), _wd_plain)
    _WATCHDOG_GLOBALS = _FrozenDict(_wd_plain)
    _WD_WARNREG_REF = dict.__getitem__(_WATCHDOG_GLOBALS, "__warningregistry__")
    _wd_orig = _wd_plain["_watchdog_audit"]
    _WATCHDOG_CODE = _wd_orig.__code__
    _WATCHDOG_HOOK = types.FunctionType(
        _WATCHDOG_CODE,
        _WATCHDOG_GLOBALS,
        "_watchdog_audit",
        (_OS_EXIT,),
        None,
    )
    _frozen_helper_codes = (
        _FROZEN_DENY_CODE,
        _FROZEN_MOD_SETATTR_CODE,
        _FROZEN_MOD_DELATTR_CODE,
        _FrozenDict.keys.__code__,
        _FrozenDict.values.__code__,
        _FrozenDict.items.__code__,
        _FrozenDict.__iter__.__code__,
        _FrozenDict.__repr__.__code__,
        _FrozenModule.__init__.__code__,
        _FrozenModule.__repr__.__code__,
        _GATE_CODE,
        _WATCHDOG_CODE,
        _ADDHOOK_CODE,
        _FAILCLOSED_CODE,
    )
    _all_internal_codes_set = frozenset().union(
        _audit_codes_set,
        _collect_nested_codes(_frozen_helper_codes),
        _SQLITE_ALL_CODES,
        _SIGNAL_ALL_CODES,
        _TRACE_ALL_CODES,
        _STAT_ALL_CODES,
        _L2C_CODES,
    )
    dict.__setitem__(_AUDIT_GLOBALS, "_WATCHDOG_GLOBALS_REF", _WATCHDOG_GLOBALS)
    dict.__setitem__(_AUDIT_GLOBALS, "_WATCHDOG_CODE_REF", _WATCHDOG_CODE)
    dict.__setitem__(_AUDIT_GLOBALS, "_ALL_INTERNAL_CODES_REF", _all_internal_codes_set)
    _expected_audit_items = tuple(
        (k, v) for k, v in dict.items(_AUDIT_GLOBALS) if k not in _audit_mutable_keys
    )
    _expected_audit_len = dict.__len__(_AUDIT_GLOBALS)

    _internal_dicts = [
        _AUDIT_GLOBALS,
        _GATE_GLOBALS,
        _WATCHDOG_GLOBALS,
        _SQLITE_GLOBALS,
        _ADDHOOK_GLOBALS,
        _SIGNAL_GLOBALS,
        _TRACE_GLOBALS,
        _STAT_GLOBALS,
    ]
    if _LIST2CMD_GLOBALS is not None:
        _internal_dicts.append(_LIST2CMD_GLOBALS)
    _internal_ids_frozen = frozenset(id(g) for g in _internal_dicts)
    _internal_hashes_frozen = frozenset(_OBJ_HASH(g) for g in _internal_dicts)
    _audit_gate_wd_hashes = frozenset((_OBJ_HASH(_AUDIT_GLOBALS), _OBJ_HASH(_GATE_GLOBALS), _OBJ_HASH(_WATCHDOG_GLOBALS)))
    dict.__setitem__(_SIGNAL_GLOBALS, "_INTERNAL_GLOBALS_IDS", _internal_ids_frozen)
    dict.__setitem__(
        _SIGNAL_GLOBALS,
        "_AUDIT_GATE_WD_IDS",
        frozenset((id(_AUDIT_GLOBALS), id(_GATE_GLOBALS), id(_WATCHDOG_GLOBALS))),
    )
    dict.__setitem__(_SIGNAL_GLOBALS, "_INTERNAL_GLOBALS_HASHES", _internal_hashes_frozen)
    dict.__setitem__(_SIGNAL_GLOBALS, "_AUDIT_GATE_WD_HASHES", _audit_gate_wd_hashes)
    dict.__setitem__(_SIGNAL_GLOBALS, "_SIGNAL_GLOBALS_HASH", _OBJ_HASH(_SIGNAL_GLOBALS))
    dict.__setitem__(_SIGNAL_GLOBALS, "_SIG_CALL_CODE", _SIGNAL_HANDLER_CLS.__dict__["__call__"].__code__)
    _expected_signal_items = tuple(
        (k, v) for k, v in dict.items(_SIGNAL_GLOBALS) if k != "__warningregistry__"
    )
    _expected_signal_len = dict.__len__(_SIGNAL_GLOBALS)

    dict.__setitem__(_TRACE_GLOBALS, "_INTERNAL_GLOBALS_IDS", _internal_ids_frozen)
    dict.__setitem__(_TRACE_GLOBALS, "_INTERNAL_GLOBALS_HASHES", _internal_hashes_frozen)
    dict.__setitem__(_TRACE_GLOBALS, "_ALL_INTERNAL_CODES", _all_internal_codes_set)
    _expected_trace_items = tuple(
        (k, v) for k, v in dict.items(_TRACE_GLOBALS) if k != "__warningregistry__"
    )
    _expected_trace_len = dict.__len__(_TRACE_GLOBALS)

    dict.__setitem__(_WATCHDOG_GLOBALS, "_watchdog_audit", _WATCHDOG_HOOK)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_WATCHDOG_GLOBALS_REF", _WATCHDOG_GLOBALS)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_WATCHDOG_CODE", _WATCHDOG_CODE)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_WATCHDOG_HOOK_REF", _WATCHDOG_HOOK)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_WD_WARNREG_REF", _WD_WARNREG_REF)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_AUDIT_ITEMS", _expected_audit_items)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_AUDIT_LEN", _expected_audit_len)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_SIGNAL_ITEMS", _expected_signal_items)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_SIGNAL_LEN", _expected_signal_len)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_TRACE_ITEMS", _expected_trace_items)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_TRACE_LEN", _expected_trace_len)
    _expected_wd_len = dict.__len__(_WATCHDOG_GLOBALS)
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_WD_LEN", _expected_wd_len)
    _expected_wd_items = tuple(
        (k, v) for k, v in dict.items(_WATCHDOG_GLOBALS) if k not in ("_EXPECTED_WD_ITEMS", "__warningregistry__")
    )
    dict.__setitem__(_WATCHDOG_GLOBALS, "_EXPECTED_WD_ITEMS", _expected_wd_items)

    sys.settrace = _GUARDED_SETTRACE
    sys.gettrace = _GUARDED_GETTRACE
    sys.setprofile = _GUARDED_SETPROFILE
    sys.getprofile = _GUARDED_GETPROFILE
    if _GUARDED_SETTRACEALL is not None:
        sys._settraceallthreads = _GUARDED_SETTRACEALL
    if _GUARDED_SETPROFILEALL is not None:
        sys._setprofileallthreads = _GUARDED_SETPROFILEALL
    if _SYS_MON_MOD is not None:
        if _GUARDED_MON_REGISTER is not None:
            _SYS_MON_MOD.register_callback = _GUARDED_MON_REGISTER
        if _GUARDED_MON_SET_LOCAL is not None:
            _SYS_MON_MOD.set_local_events = _GUARDED_MON_SET_LOCAL

    _OS_MOD.stat = _GUARDED_OS_STAT
    _OS_MOD.lstat = _GUARDED_OS_LSTAT
    _OS_MOD.access = _GUARDED_OS_ACCESS
    _OS_MOD.scandir = _GUARDED_OS_SCANDIR
    if _GUARDED_OS_READLINK is not None:
        _OS_MOD.readlink = _GUARDED_OS_READLINK
    if _exp_nt_readlink:
        ntpath._nt_readlink = _GUARDED_OS_READLINK
    if _RAW_OS_MOD is not None:
        _RAW_OS_MOD.stat = _GUARDED_OS_STAT
        _RAW_OS_MOD.lstat = _GUARDED_OS_LSTAT
        _RAW_OS_MOD.access = _GUARDED_OS_ACCESS
        _RAW_OS_MOD.scandir = _GUARDED_OS_SCANDIR
        if _GUARDED_OS_READLINK is not None and hasattr(_RAW_OS_MOD, "readlink"):
            _RAW_OS_MOD.readlink = _GUARDED_OS_READLINK
        for _raw_attr, _path_attr, _gfn in _EXPECTED_WIN_PATH_ATTRS:
            setattr(_RAW_OS_MOD, _raw_attr, _gfn)
            if _path_attr is not None:
                setattr(_OS_PATH_MOD, _path_attr, _gfn)

    for _init_sname in ("SIGINT", "SIGBREAK"):
        _init_sig = getattr(_SIGNAL_MOD, _init_sname, None)
        if _init_sig is not None:
            _init_h = _ORIG_SIGNAL_GETSIGNAL(_init_sig)
            if callable(_init_h) and type(_init_h) is not _SIGNAL_HANDLER_CLS:
                _wrapped_init_h = _SIGNAL_HANDLER_CLS(_init_h)
                _ORIG_SIGNAL_SIGNAL(_init_sig, _wrapped_init_h)
                _signal_sig_map[int(_init_sig)] = (_wrapped_init_h, _init_h)

    _OCTOPUS_HOOK = dict.__getitem__(_AUDIT_GLOBALS, "_octopus_audit_check")
    _orig_addaudithook = sys.addaudithook
    sys.addaudithook = _GUARDED_ADDAUDITHOOK
    _orig_addaudithook(_WATCHDOG_HOOK)
    _orig_addaudithook(_OCTOPUS_HOOK)
    _orig_addaudithook(_GATE_HOOK)
    _orig_addaudithook(_FAILCLOSED_HOOK)

    _ack_fd_s = os.environ.pop("OCTOPUS_PY_GUARD_ACK_FD", None)
    _ack_tok = os.environ.pop("OCTOPUS_PY_GUARD_ACK_TOKEN", None)
    if _ack_fd_s and _ack_tok:
        _ack_val = int(_ack_fd_s)
        if _IS_WIN:
            import msvcrt as _msvcrt
            _ack_crt_fd = _msvcrt.open_osfhandle(_ack_val, 0)
        else:
            _ack_crt_fd = _ack_val
        _ack_payload = (_ack_tok + "\n").encode("ascii")
        _ack_off = 0
        while _ack_off < len(_ack_payload):
            _ack_written = os.write(_ack_crt_fd, _ack_payload[_ack_off:])
            if _ack_written <= 0:
                raise OSError("short write on python guard ack pipe")
            _ack_off += _ack_written
        os.close(_ack_crt_fd)

try:
    _install_octopus_audit()
except BaseException as _oct_init_err:
    import os as _oct_os, sys as _oct_sys
    try:
        _oct_sys.stderr.write("blocked_by_octopus_policy: audit guard initialization failed: " + repr(_oct_init_err) + "\n")
        _oct_sys.stderr.flush()
    except BaseException:
        pass
    _oct_os._exit(1)
del _install_octopus_audit
"##;
    let sitecustomize = sitecustomize_template.replace("__OCTOPUS_CFG_LITERAL__", &cfg_literal);

    std::fs::write(dir.join("sitecustomize.py"), sitecustomize)
        .map_err(|e| format!("failed to write ephemeral sitecustomize.py: {}", e))?;
    Ok(TempGuardDir(dir))
}

fn emit_json_summary(summary: &JsonRunSummary) {
    if let Ok(json_str) = serde_json::to_string(summary) {
        println!("{}", json_str);
    }
}

pub async fn execute_from_args(args: &[String]) -> i32 {
    match parse_octopus_cli(args) {
        CliParseResult::Run(run_args) => execute_octopus_run(run_args).await,
        CliParseResult::RunHelp => {
            crate::cli::print_octopus_run_help();
            0
        }
        CliParseResult::Help => {
            crate::cli::print_octopus_help();
            0
        }
        CliParseResult::Version => {
            println!("octopus {}", env!("CARGO_PKG_VERSION"));
            0
        }
        CliParseResult::Invalid(msg) => {
            eprintln!(
                "[octopus] error: {}\nRun 'octopus run --help' for usage.",
                msg
            );
            EXIT_PREFLIGHT_DENIED
        }
        CliParseResult::Delegate(_) => EXIT_PREFLIGHT_DENIED,
    }
}

fn emit_preflight_denial(args: &OctopusRunArgs, start: Instant, label: &str, msg: String) -> i32 {
    if args.json_output {
        emit_json_summary(&JsonRunSummary {
            status: "denied_preflight".to_string(),
            exit_code: EXIT_PREFLIGHT_DENIED,
            timed_out: false,
            sandbox: args.sandbox.as_str().to_string(),
            backend: "preflight".to_string(),
            pid: None,
            duration_ms: start.elapsed().as_millis() as u64,
            stdout: String::new(),
            stderr: msg.clone(),
            egress_events: Vec::new(),
            diagnostic: Some(msg),
        });
    } else {
        eprintln!("[octopus] DENY {}: {}", label, msg);
    }
    EXIT_PREFLIGHT_DENIED
}

pub async fn execute_octopus_run(args: OctopusRunArgs) -> i32 {
    let start = Instant::now();
    let policy = match load_octopus_policy(&args.policy_path) {
        Ok(p) => p,
        Err(msg) => {
            return emit_preflight_denial(&args, start, "policy", msg);
        }
    };

    let raw_cwd = match args.cwd {
        Some(ref c) => c.clone(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                return emit_preflight_denial(
                    &args,
                    start,
                    "cwd",
                    format!("failed to determine current_dir: {}", e),
                );
            }
        },
    };
    if !raw_cwd.is_dir() {
        let msg = format!(
            "--cwd '{}' does not exist or is not a directory",
            raw_cwd.display()
        );
        return emit_preflight_denial(&args, start, "cwd", msg);
    }
    let cwd = strip_win_verbatim_prefix(std::fs::canonicalize(&raw_cwd).unwrap_or(raw_cwd));
    let cwd_str = cwd.to_string_lossy().to_string();
    if let Some(kind) = classify_sensitive_system_path(&cwd_str) {
        return emit_preflight_denial(
            &args,
            start,
            "cwd",
            format!(
                "--cwd '{}' targets protected sensitive path ({:?})",
                cwd_str, kind
            ),
        );
    }
    if let Some((kind, needle)) = scan_for_sensitive_system_path(&cwd_str) {
        return emit_preflight_denial(
            &args,
            start,
            "cwd",
            format!(
                "--cwd '{}' references sensitive path '{}' ({:?})",
                cwd_str, needle, kind
            ),
        );
    }

    let is_wasm = is_wasm_or_wat_target(&args.command[0]);
    let (canonical_stem, resolved_exe) = match run_preflight_gate(&args, &policy, &cwd, is_wasm) {
        Ok(v) => v,
        Err(reason) => {
            return emit_preflight_denial(&args, start, "preflight", reason);
        }
    };

    let timeout_secs = args
        .timeout_secs
        .unwrap_or_else(|| policy.json_policy.limits.timeout_secs.unwrap_or(60));

    if is_wasm {
        let target_path = resolved_exe.unwrap_or_else(|| PathBuf::from(&args.command[0]));
        return match execute_wasm_target(
            &target_path,
            &args.command[1..],
            &cwd,
            &policy,
            timeout_secs,
            args.json_output,
        )
        .await
        {
            Ok(outcome) => {
                if args.json_output {
                    let stdout = outcome
                        .receipt
                        .as_ref()
                        .map(|r| r.raw_output.clone())
                        .unwrap_or_default();
                    let status = if outcome.timed_out {
                        "timeout"
                    } else if outcome.exit_code == 0 {
                        "ok"
                    } else {
                        "error"
                    };
                    emit_json_summary(&JsonRunSummary {
                        status: status.to_string(),
                        exit_code: outcome.exit_code,
                        timed_out: outcome.timed_out,
                        sandbox: args.sandbox.as_str().to_string(),
                        backend: "wasmtime-tier1".to_string(),
                        pid: None,
                        duration_ms: start.elapsed().as_millis() as u64,
                        stdout,
                        stderr: outcome.diagnostic.clone().unwrap_or_default(),
                        egress_events: Vec::new(),
                        diagnostic: outcome.diagnostic,
                    });
                }
                outcome.exit_code
            }
            Err((code, msg)) => {
                if args.json_output {
                    emit_json_summary(&JsonRunSummary {
                        status: "wasm_error".to_string(),
                        exit_code: code,
                        timed_out: code == EXIT_TIMEOUT,
                        sandbox: args.sandbox.as_str().to_string(),
                        backend: "wasmtime-tier1".to_string(),
                        pid: None,
                        duration_ms: start.elapsed().as_millis() as u64,
                        stdout: String::new(),
                        stderr: msg.clone(),
                        egress_events: Vec::new(),
                        diagnostic: Some(msg),
                    });
                } else {
                    eprintln!("[octopus] DENY wasm: {}", msg);
                }
                code
            }
        };
    }

    #[cfg(windows)]
    let mut ac_profile: Option<crate::security::windows_sandbox::PreparedAppContainerProfile> =
        if args.sandbox == SandboxMode::Strict {
            match crate::security::windows_sandbox::PreparedAppContainerProfile::prepare_appcontainer_profile() {
                Ok(p) => Some(p),
                Err(e) => {
                    let msg = format!("ERROR preparing Windows AppContainer strict sandbox: {}", e);
                    if args.json_output {
                        emit_json_summary(&JsonRunSummary {
                            status: "sandbox_error".to_string(),
                            exit_code: EXIT_SANDBOX_FAILURE,
                            timed_out: false,
                            sandbox: args.sandbox.as_str().to_string(),
                            backend: "windows-appcontainer".to_string(),
                            pid: None,
                            duration_ms: start.elapsed().as_millis() as u64,
                            stdout: String::new(),
                            stderr: msg.clone(),
                            egress_events: Vec::new(),
                            diagnostic: Some(msg),
                        });
                    } else {
                        eprintln!("[octopus] {}", msg);
                    }
                    return EXIT_SANDBOX_FAILURE;
                }
            }
        } else {
            None
        };
    #[cfg(windows)]
    let ac_loopback_ok = {
        let wants_egress_proxy =
            !policy.json_policy.allowed_domains.is_empty() || policy.is_standalone_cedar;
        if let Some(ref mut p) = ac_profile {
            if wants_egress_proxy {
                p.try_enable_loopback_exemption()
            } else {
                false
            }
        } else {
            false
        }
    };
    #[cfg(windows)]
    let ac_sid_opt: Option<&str> = ac_profile.as_ref().map(|p| p.sid_str.as_str());
    #[cfg(not(windows))]
    let ac_sid_opt: Option<&str> = None;

    let cedar_fs_handle =
        match start_cedar_fs_control_server(&policy, &cwd, args.sandbox, ac_sid_opt).await {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("ERROR starting Cedar FS control IPC: {}", e);
                if args.json_output {
                    emit_json_summary(&JsonRunSummary {
                        status: "sandbox_error".to_string(),
                        exit_code: EXIT_SANDBOX_FAILURE,
                        timed_out: false,
                        sandbox: args.sandbox.as_str().to_string(),
                        backend: "cedar-fs-ipc".to_string(),
                        pid: None,
                        duration_ms: start.elapsed().as_millis() as u64,
                        stdout: String::new(),
                        stderr: msg.clone(),
                        egress_events: Vec::new(),
                        diagnostic: Some(msg),
                    });
                } else {
                    eprintln!("[octopus] {}", msg);
                }
                return EXIT_SANDBOX_FAILURE;
            }
        };
    let cedar_ipc_port = cedar_fs_handle.as_ref().and_then(|h| {
        if h.pipe_name.is_none() && h.port > 0 {
            Some(h.port)
        } else {
            None
        }
    });

    let proxy = match start_loopback_proxy(&policy, args.json_output, cedar_ipc_port).await {
        Ok(p) => p,
        Err(e) => {
            if let Some(h) = cedar_fs_handle {
                h.shutdown().await;
            }
            let msg = format!("ERROR starting loopback policy proxy: {}", e);
            if args.json_output {
                emit_json_summary(&JsonRunSummary {
                    status: "sandbox_error".to_string(),
                    exit_code: EXIT_SANDBOX_FAILURE,
                    timed_out: false,
                    sandbox: args.sandbox.as_str().to_string(),
                    backend: "loopback-proxy".to_string(),
                    pid: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    stdout: String::new(),
                    stderr: msg.clone(),
                    egress_events: Vec::new(),
                    diagnostic: Some(msg),
                });
            } else {
                eprintln!("[octopus] {}", msg);
            }
            return EXIT_SANDBOX_FAILURE;
        }
    };

    #[cfg(windows)]
    let win_ac_blocked_proxy_port = if args.sandbox == SandboxMode::Strict && !ac_loopback_ok {
        Some(proxy.port)
    } else {
        None
    };
    #[cfg(not(windows))]
    let win_ac_blocked_proxy_port: Option<u16> = None;

    let mut child_env = proxy.child_env.clone();
    let mut _py_guard_dir: Option<TempGuardDir> = None;
    let prog_aliases_exec = normalized_command_aliases(&args.command[0]);
    if is_python_aliases(&prog_aliases_exec)
        || matches!(
            canonical_stem.as_str(),
            "python" | "python3" | "python2" | "pythonw" | "py"
        )
    {
        let cedar_ipc_ref = cedar_fs_handle.as_ref().map(|h| {
            (
                h.port,
                h.pipe_name.as_deref(),
                h.token.as_str(),
                h.has_fs_read_forbid,
            )
        });
        match create_python_audit_guard(&policy, &cwd, cedar_ipc_ref, win_ac_blocked_proxy_port) {
            Ok(guard_dir) => {
                let guard_str = guard_dir.0.to_string_lossy().to_string();
                let mut existing_py_path: Option<String> = None;
                child_env.retain(|(k, v)| {
                    if k.eq_ignore_ascii_case("PYTHONPATH") {
                        existing_py_path = Some(v.clone());
                        false
                    } else {
                        !k.eq_ignore_ascii_case("PYTHONDONTWRITEBYTECODE")
                    }
                });
                let new_py_path = match existing_py_path {
                    Some(prev) if !prev.is_empty() => {
                        let sep = if cfg!(windows) { ";" } else { ":" };
                        format!("{}{}{}", guard_str, sep, prev)
                    }
                    _ => guard_str,
                };
                child_env.push(("PYTHONPATH".to_string(), new_py_path));
                child_env.push(("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string()));
                _py_guard_dir = Some(guard_dir);
            }
            Err(e) => {
                proxy.shutdown().await;
                if let Some(h) = cedar_fs_handle {
                    h.shutdown().await;
                }
                let msg = format!("ERROR initializing python audit hook: {}", e);
                if args.json_output {
                    emit_json_summary(&JsonRunSummary {
                        status: "sandbox_error".to_string(),
                        exit_code: EXIT_SANDBOX_FAILURE,
                        timed_out: false,
                        sandbox: args.sandbox.as_str().to_string(),
                        backend: "python-audit-guard".to_string(),
                        pid: None,
                        duration_ms: start.elapsed().as_millis() as u64,
                        stdout: String::new(),
                        stderr: msg.clone(),
                        egress_events: Vec::new(),
                        diagnostic: Some(msg),
                    });
                } else {
                    eprintln!("[octopus] {}", msg);
                }
                return EXIT_SANDBOX_FAILURE;
            }
        }
    }

    if _py_guard_dir.is_none() && win_ac_blocked_proxy_port.is_some() {
        child_env.retain(|(k, _)| {
            !matches!(
                k.to_ascii_uppercase().as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
            )
        });
    }

    let exec_target = resolved_exe
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| args.command[0].clone());
    let child_args = &args.command[1..];
    let timeout_opt = if timeout_secs > 0 {
        Some(Duration::from_secs(timeout_secs))
    } else {
        None
    };

    let py_guard_path = _py_guard_dir.as_ref().map(|g| g.0.as_path());
    let run_res = run_os_confined_child(
        &exec_target,
        child_args,
        &cwd,
        &child_env,
        &policy,
        args.sandbox,
        proxy.port,
        py_guard_path,
        cedar_ipc_port,
        timeout_opt,
        args.json_output,
        #[cfg(windows)]
        ac_profile,
    )
    .await;

    let egress_events = proxy.events_snapshot();
    proxy.shutdown().await;
    if let Some(h) = cedar_fs_handle {
        h.shutdown().await;
    }
    drop(_py_guard_dir);

    match run_res {
        Ok(res) => {
            if args.json_output {
                let status = if res.timed_out {
                    "timeout"
                } else if res.exit_code == 0 {
                    "ok"
                } else {
                    "exited_nonzero"
                };
                emit_json_summary(&JsonRunSummary {
                    status: status.to_string(),
                    exit_code: res.exit_code,
                    timed_out: res.timed_out,
                    sandbox: args.sandbox.as_str().to_string(),
                    backend: res.backend,
                    pid: res.pid,
                    duration_ms: start.elapsed().as_millis() as u64,
                    stdout: res.stdout,
                    stderr: res.stderr,
                    egress_events,
                    diagnostic: res.diagnostic,
                });
            }
            res.exit_code
        }
        Err(e) => {
            if args.json_output {
                emit_json_summary(&JsonRunSummary {
                    status: "sandbox_error".to_string(),
                    exit_code: EXIT_SANDBOX_FAILURE,
                    timed_out: false,
                    sandbox: args.sandbox.as_str().to_string(),
                    backend: "os-sandbox".to_string(),
                    pid: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    stdout: String::new(),
                    stderr: e.clone(),
                    egress_events,
                    diagnostic: Some(e),
                });
            } else {
                eprintln!("[octopus] DENY sandbox: {}", e);
            }
            EXIT_SANDBOX_FAILURE
        }
    }
}
struct ChildRunOutcome {
    exit_code: i32,
    timed_out: bool,
    backend: String,
    pid: Option<u32>,
    stdout: String,
    stderr: String,
    diagnostic: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_os_confined_child(
    program: &str,
    args: &[String],
    cwd: &Path,
    env_pairs: &[(String, String)],
    policy: &LoadedOctopusPolicy,
    sandbox: SandboxMode,
    proxy_port: u16,
    py_guard_dir: Option<&Path>,
    cedar_ipc_port: Option<u16>,
    timeout: Option<Duration>,
    pipe_stdio: bool,
    #[cfg(windows)] ac_profile: Option<
        crate::security::windows_sandbox::PreparedAppContainerProfile,
    >,
) -> Result<ChildRunOutcome, String> {
    #[cfg(windows)]
    {
        use crate::security::token_posture::spawn_deelevated_in_job_with_io;
        use crate::security::windows_sandbox::{
            build_windows_command_line, spawn_appcontainer_in_job_with_io_prepared,
            WindowsJobObject,
        };
        use std::io::Read;
        use std::os::windows::io::{FromRawHandle, RawHandle};

        #[repr(C)]
        #[allow(non_snake_case)]
        struct AckPipeSecAttr {
            nLength: u32,
            lpSecurityDescriptor: *mut std::ffi::c_void,
            bInheritHandle: i32,
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn CreatePipe(
                hReadPipe: *mut *mut std::ffi::c_void,
                hWritePipe: *mut *mut std::ffi::c_void,
                lpPipeAttributes: *const AckPipeSecAttr,
                nSize: u32,
            ) -> i32;
            fn SetHandleInformation(
                hObject: *mut std::ffi::c_void,
                dwMask: u32,
                dwFlags: u32,
            ) -> i32;
            fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        }

        let program = program.to_string();
        let args = args.to_vec();
        let cwd = cwd.to_path_buf();
        let mut env_pairs = env_pairs.to_vec();
        let mandatory_ro_dirs: Vec<PathBuf> = py_guard_dir
            .map(|p| vec![p.to_path_buf()])
            .unwrap_or_default();
        let require_py_guard_ack = py_guard_dir.is_some();
        let max_procs = policy
            .json_policy
            .commands
            .max_child_processes
            .unwrap_or(16)
            .max(1);
        let mem_bytes = policy
            .json_policy
            .limits
            .memory_mb
            .unwrap_or(512)
            .clamp(64, 4096)
            .saturating_mul(1024 * 1024);

        let resolve_dirs = |raws: &[String]| -> Vec<PathBuf> {
            raws.iter()
                .filter_map(|r| {
                    let t = r.trim();
                    if t.is_empty() || t.starts_with('~') {
                        return None;
                    }
                    let p = Path::new(t);
                    Some(if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        cwd.join(p)
                    })
                })
                .collect()
        };
        let ro_dirs = resolve_dirs(&policy.json_policy.filesystem.allow_read);
        let mut rw_dirs = resolve_dirs(&policy.json_policy.filesystem.allow_write);
        if policy.is_standalone_cedar
            && rw_dirs.is_empty()
            && py_guard_dir.is_some()
            && policy
                .cedar_engine
                .as_ref()
                .is_some_and(|e| e.has_permit_action_policy("fs_write"))
        {
            rw_dirs.push(cwd.clone());
        }
        let allow_net_cap = (!policy.json_policy.allowed_domains.is_empty()
            || policy.is_standalone_cedar)
            && ac_profile
                .as_ref()
                .is_some_and(|p| p.loopback_exempt_active());

        let _ = (proxy_port, cedar_ipc_port);
        tokio::task::spawn_blocking(move || -> Result<ChildRunOutcome, String> {
            let job_name = format!(
                "OctopusRunJob_{}_{:08x}",
                std::process::id(),
                rand::random::<u32>()
            );
            let job = WindowsJobObject::create(job_name, max_procs, mem_bytes)
                .map_err(|e| format!("failed to create WindowsJobObject: {}", e))?;

            let spawn_read_thread = |file_opt: Option<std::fs::File>| {
                file_opt.map(|mut f| {
                    std::thread::spawn(move || {
                        let mut buf = Vec::new();
                        let _ = f.read_to_end(&mut buf);
                        String::from_utf8_lossy(&buf).to_string()
                    })
                })
            };

            let (ack_expected_token, ack_read_file, mut ack_write_handle) = if require_py_guard_ack {
                let mut ack_read: *mut std::ffi::c_void = std::ptr::null_mut();
                let mut ack_write: *mut std::ffi::c_void = std::ptr::null_mut();
                let sa = AckPipeSecAttr {
                    nLength: std::mem::size_of::<AckPipeSecAttr>() as u32,
                    lpSecurityDescriptor: std::ptr::null_mut(),
                    bInheritHandle: 1,
                };
                if unsafe { CreatePipe(&mut ack_read, &mut ack_write, &sa, 0) } == 0 {
                    return Err("failed to create Python audit guard ACK pipe".to_string());
                }
                unsafe { SetHandleInformation(ack_read, 1, 0) };
                let mut tok = String::with_capacity(64);
                for _ in 0..32 {
                    tok.push_str(&format!("{:02x}", rand::random::<u8>()));
                }
                env_pairs.retain(|(k, _)| {
                    !k.eq_ignore_ascii_case("OCTOPUS_PY_GUARD_ACK_FD")
                        && !k.eq_ignore_ascii_case("OCTOPUS_PY_GUARD_ACK_TOKEN")
                });
                env_pairs.push((
                    "OCTOPUS_PY_GUARD_ACK_FD".to_string(),
                    (ack_write as usize).to_string(),
                ));
                env_pairs.push(("OCTOPUS_PY_GUARD_ACK_TOKEN".to_string(), tok.clone()));
                let rf = unsafe { std::fs::File::from_raw_handle(ack_read as RawHandle) };
                (Some(tok), Some(rf), Some(ack_write))
            } else {
                (None, None, None)
            };

            if sandbox == SandboxMode::Strict {
                let spawn_res = spawn_appcontainer_in_job_with_io_prepared(
                    &program,
                    &args,
                    &cwd,
                    &env_pairs,
                    allow_net_cap,
                    &ro_dirs,
                    &rw_dirs,
                    &mandatory_ro_dirs,
                    pipe_stdio,
                    &job,
                    ac_profile,
                );
                if let Some(hw) = ack_write_handle.take() {
                    unsafe { CloseHandle(hw) };
                }
                let (child, out_f, err_f) = spawn_res
                    .map_err(|e| format!("Windows AppContainer strict sandbox failed: {}", e))?;

                let out_thr = spawn_read_thread(out_f);
                let err_thr = spawn_read_thread(err_f);
                let ack_thr = spawn_read_thread(ack_read_file);
                let pid = child.pid;
                let wait_res = child
                    .wait_with_timeout(timeout)
                    .map_err(|e| format!("wait on AppContainer child failed: {}", e))?;

                let (exit_code, timed_out, diagnostic) = match wait_res {
                    Some(code) => {
                        let diag = if code == 0xC000_0135 || code == 0xC000_0022 {
                            let exe_parent = Path::new(&program)
                                .parent()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| program.clone());
                            let msg = format!(
                                "AppContainer strict child exited with 0x{:08X} ({}); '{}' may lack ALL APPLICATION PACKAGES (S-1-15-2-1) (RX) ACLs",
                                code, code as i32, exe_parent
                            );
                            if !pipe_stdio {
                                eprintln!("[octopus] {}", msg);
                            }
                            Some(msg)
                        } else {
                            None
                        };
                        (code as i32, false, diag)
                    }
                    None => {
                        let _ = job.terminate(EXIT_TIMEOUT as u32);
                        (
                            EXIT_TIMEOUT,
                            true,
                            Some("process terminated by WindowsJobObject timeout".to_string()),
                        )
                    }
                };
                let stdout = out_thr.and_then(|h| h.join().ok()).unwrap_or_default();
                let mut stderr = err_thr.and_then(|h| h.join().ok()).unwrap_or_default();
                let ack_received = ack_thr.and_then(|h| h.join().ok()).unwrap_or_default();
                if let Some(ref exp_tok) = ack_expected_token {
                    let is_init_acl_err = exit_code == 0xC000_0135u32 as i32
                        || exit_code == 0xC000_0022u32 as i32;
                    if !timed_out && !is_init_acl_err && ack_received.trim() != exp_tok {
                        let err_tail = stderr.trim();
                        return Err(if err_tail.is_empty() {
                            "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox".to_string()
                        } else {
                            format!(
                                "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox: {}",
                                err_tail
                            )
                        });
                    }
                }
                if let Some(ref diag_msg) = diagnostic {
                    if !timed_out && stderr.is_empty() {
                        stderr = diag_msg.clone();
                    }
                }

                Ok(ChildRunOutcome {
                    exit_code,
                    timed_out,
                    backend: "windows-appcontainer+job".to_string(),
                    pid: Some(pid),
                    stdout,
                    stderr,
                    diagnostic,
                })
            } else {
                let cmdline = build_windows_command_line(&program, &args);
                let spawn_res = spawn_deelevated_in_job_with_io(
                    Some(&program),
                    &cmdline,
                    Some(&cwd),
                    Some(&env_pairs),
                    pipe_stdio,
                    false,
                    &job,
                );
                if let Some(hw) = ack_write_handle.take() {
                    unsafe { CloseHandle(hw) };
                }
                let (child, out_f, err_f) = spawn_res
                    .map_err(|e| format!("Windows de-elevated JobObject sandbox failed: {}", e))?;

                let out_thr = spawn_read_thread(out_f);
                let err_thr = spawn_read_thread(err_f);
                let ack_thr = spawn_read_thread(ack_read_file);
                let pid = child.pid;
                let wait_res = child
                    .wait_with_timeout(timeout)
                    .map_err(|e| format!("wait on de-elevated child failed: {}", e))?;

                let (exit_code, timed_out, diagnostic) = match wait_res {
                    Some(code) => (code as i32, false, None),
                    None => {
                        let _ = job.terminate(EXIT_TIMEOUT as u32);
                        (
                            EXIT_TIMEOUT,
                            true,
                            Some("process terminated by WindowsJobObject timeout".to_string()),
                        )
                    }
                };
                let stdout = out_thr.and_then(|h| h.join().ok()).unwrap_or_default();
                let stderr = err_thr.and_then(|h| h.join().ok()).unwrap_or_default();
                let ack_received = ack_thr.and_then(|h| h.join().ok()).unwrap_or_default();
                if let Some(ref exp_tok) = ack_expected_token {
                    if !timed_out && ack_received.trim() != exp_tok {
                        let err_tail = stderr.trim();
                        return Err(if err_tail.is_empty() {
                            "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox".to_string()
                        } else {
                            format!(
                                "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox: {}",
                                err_tail
                            )
                        });
                    }
                }

                Ok(ChildRunOutcome {
                    exit_code,
                    timed_out,
                    backend: "windows-deelevated+job".to_string(),
                    pid: Some(pid),
                    stdout,
                    stderr,
                    diagnostic,
                })
            }
        })
        .await
        .map_err(|e| format!("blocking sandbox worker panicked: {}", e))?
    }

    #[cfg(target_os = "linux")]
    {
        use crate::security::linux_sandbox::apply_cli_pre_exec_confinement;
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let program = program.to_string();
        let args = args.to_vec();
        let cwd = cwd.to_path_buf();
        let mut env_pairs = env_pairs.to_vec();
        let mandatory_ro_dirs: Vec<PathBuf> = py_guard_dir
            .map(|p| vec![p.to_path_buf()])
            .unwrap_or_default();
        let require_py_guard_ack = py_guard_dir.is_some();
        let mem_bytes = (policy
            .json_policy
            .limits
            .memory_mb
            .unwrap_or(512)
            .clamp(64, 4096)
            * 1024
            * 1024) as u64;
        let block_all_sockets = sandbox == SandboxMode::Strict
            && policy.json_policy.allowed_domains.is_empty()
            && !policy.is_standalone_cedar
            && cedar_ipc_port.is_none();
        let strict_fail_closed = sandbox == SandboxMode::Strict;
        let _ = proxy_port;

        let resolve_dirs = |raws: &[String]| -> Vec<PathBuf> {
            raws.iter()
                .filter_map(|r| {
                    let t = r.trim();
                    if t.is_empty() || t.starts_with('~') {
                        return None;
                    }
                    let p = Path::new(t);
                    Some(if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        cwd.join(p)
                    })
                })
                .collect()
        };
        let mut ro_dirs = resolve_dirs(&policy.json_policy.filesystem.allow_read);
        if let Some(gd) = py_guard_dir {
            ro_dirs.push(gd.to_path_buf());
        }
        let mut rw_dirs = resolve_dirs(&policy.json_policy.filesystem.allow_write);
        if policy.is_standalone_cedar
            && rw_dirs.is_empty()
            && py_guard_dir.is_some()
            && policy
                .cedar_engine
                .as_ref()
                .is_some_and(|e| e.has_permit_action_policy("fs_write"))
        {
            rw_dirs.push(cwd.clone());
        }

        tokio::task::spawn_blocking(move || -> Result<ChildRunOutcome, String> {
            let (ack_expected_token, ack_read_file, mut ack_write_fd) = if require_py_guard_ack {
                let mut fds = [0i32; 2];
                if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                    return Err("failed to create Python audit guard ACK pipe".to_string());
                }
                unsafe {
                    libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fds[1], libc::F_SETFD, 0);
                }
                let mut tok = String::with_capacity(64);
                for _ in 0..32 {
                    tok.push_str(&format!("{:02x}", rand::random::<u8>()));
                }
                env_pairs.retain(|(k, _)| {
                    !k.eq_ignore_ascii_case("OCTOPUS_PY_GUARD_ACK_FD")
                        && !k.eq_ignore_ascii_case("OCTOPUS_PY_GUARD_ACK_TOKEN")
                });
                env_pairs.push(("OCTOPUS_PY_GUARD_ACK_FD".to_string(), fds[1].to_string()));
                env_pairs.push(("OCTOPUS_PY_GUARD_ACK_TOKEN".to_string(), tok.clone()));
                let rf = unsafe { std::fs::File::from_raw_fd(fds[0]) };
                (Some(tok), Some(rf), Some(fds[1]))
            } else {
                (None, None, None)
            };

            let mut cmd = Command::new(&program);
            cmd.args(&args)
                .env_clear()
                .envs(env_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .current_dir(&cwd);
            if pipe_stdio {
                cmd.stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            } else {
                cmd.stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
            }

            let bin_path = PathBuf::from(&program);
            let cwd_c = cwd.clone();
            unsafe {
                cmd.pre_exec(move || {
                    apply_cli_pre_exec_confinement(
                        &bin_path,
                        &cwd_c,
                        &ro_dirs,
                        &rw_dirs,
                        &mandatory_ro_dirs,
                        mem_bytes,
                        block_all_sockets,
                        strict_fail_closed,
                    )
                });
            }

            let spawn_res = cmd.spawn();
            if let Some(wfd) = ack_write_fd.take() {
                unsafe { libc::close(wfd) };
            }
            let mut child = spawn_res.map_err(|e| {
                format!("failed to spawn Linux sandboxed child '{}': {}", program, e)
            })?;
            let pid = child.id();

            let out_thr = child.stdout.take().map(|mut s| {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).to_string()
                })
            });
            let err_thr = child.stderr.take().map(|mut s| {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).to_string()
                })
            });
            let ack_thr = ack_read_file.map(|mut s| {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).to_string()
                })
            });

            let deadline = timeout.map(|d| Instant::now() + d);
            let mut timed_out = false;
            let exit_code = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code().unwrap_or(1),
                    Ok(None) => {
                        if let Some(dl) = deadline {
                            if Instant::now() >= dl {
                                timed_out = true;
                                unsafe {
                                    libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                                }
                                let _ = child.kill();
                                let _ = child.wait();
                                break EXIT_TIMEOUT;
                            }
                        }
                        std::thread::sleep(Duration::from_millis(15));
                    }
                    Err(e) => {
                        let _ = child.kill();
                        return Err(format!("error waiting on Linux child: {}", e));
                    }
                }
            };

            let stdout = out_thr.and_then(|h| h.join().ok()).unwrap_or_default();
            let stderr = err_thr.and_then(|h| h.join().ok()).unwrap_or_default();
            let ack_received = ack_thr.and_then(|h| h.join().ok()).unwrap_or_default();
            if let Some(ref exp_tok) = ack_expected_token {
                if !timed_out && ack_received.trim() != exp_tok {
                    let err_tail = stderr.trim();
                    return Err(if err_tail.is_empty() {
                        "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox".to_string()
                    } else {
                        format!(
                            "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox: {}",
                            err_tail
                        )
                    });
                }
            }

            Ok(ChildRunOutcome {
                exit_code,
                timed_out,
                backend: "linux-landlock+seccomp".to_string(),
                pid: Some(pid),
                stdout,
                stderr,
                diagnostic: if timed_out {
                    Some("process terminated by Linux timeout".to_string())
                } else {
                    None
                },
            })
        })
        .await
        .map_err(|e| format!("blocking Linux worker panicked: {}", e))?
    }

    #[cfg(target_os = "macos")]
    {
        use crate::security::macos_sandbox::{
            kill_macos_process_subtree, spawn_macos_seatbelt_process_with_stdio,
            SandboxedMacosConfig,
        };
        use std::io::Read;
        use std::os::unix::io::FromRawFd;

        let resolve_dirs = |raws: &[String]| -> Vec<PathBuf> {
            raws.iter()
                .filter_map(|r| {
                    let t = r.trim();
                    if t.is_empty() || t.starts_with('~') {
                        return None;
                    }
                    let p = Path::new(t);
                    Some(if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        cwd.join(p)
                    })
                })
                .collect()
        };
        let mut ro_dirs = resolve_dirs(&policy.json_policy.filesystem.allow_read);
        if let Some(gd) = py_guard_dir {
            ro_dirs.push(gd.to_path_buf());
        }
        if let Some(parent) = Path::new(program).parent() {
            ro_dirs.push(parent.to_path_buf());
        }
        let mut rw_dirs = resolve_dirs(&policy.json_policy.filesystem.allow_write);
        rw_dirs.push(std::env::temp_dir());

        let mut control_ports = vec![proxy_port];
        if let Some(cp) = cedar_ipc_port {
            control_ports.push(cp);
        }

        let cfg = SandboxedMacosConfig {
            program: PathBuf::from(program),
            args: args.to_vec(),
            read_only_dirs: ro_dirs,
            read_write_dirs: rw_dirs,
            working_dir: Some(cwd.to_path_buf()),
            allow_loopback: !policy.json_policy.allowed_domains.is_empty()
                || policy.is_standalone_cedar
                || cedar_ipc_port.is_some(),
            control_ports,
        };
        let mut env_pairs = env_pairs.to_vec();
        let require_py_guard_ack = py_guard_dir.is_some();

        tokio::task::spawn_blocking(move || -> Result<ChildRunOutcome, String> {
            let (ack_expected_token, ack_read_file, mut ack_write_fd) = if require_py_guard_ack {
                let mut fds = [0i32; 2];
                if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                    return Err("failed to create Python audit guard ACK pipe".to_string());
                }
                unsafe {
                    libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fds[1], libc::F_SETFD, 0);
                }
                let mut tok = String::with_capacity(64);
                for _ in 0..32 {
                    tok.push_str(&format!("{:02x}", rand::random::<u8>()));
                }
                env_pairs.retain(|(k, _)| {
                    !k.eq_ignore_ascii_case("OCTOPUS_PY_GUARD_ACK_FD")
                        && !k.eq_ignore_ascii_case("OCTOPUS_PY_GUARD_ACK_TOKEN")
                });
                env_pairs.push(("OCTOPUS_PY_GUARD_ACK_FD".to_string(), fds[1].to_string()));
                env_pairs.push(("OCTOPUS_PY_GUARD_ACK_TOKEN".to_string(), tok.clone()));
                let rf = unsafe { std::fs::File::from_raw_fd(fds[0]) };
                (Some(tok), Some(rf), Some(fds[1]))
            } else {
                (None, None, None)
            };

            let spawn_res = spawn_macos_seatbelt_process_with_stdio(&cfg, &env_pairs, pipe_stdio);
            if let Some(wfd) = ack_write_fd.take() {
                unsafe { libc::close(wfd) };
            }
            let mut proc_handle =
                spawn_res.map_err(|e| format!("macOS Seatbelt spawn failed: {}", e))?;
            let pid = proc_handle.root_pid;
            let mut child = proc_handle
                .take_child()
                .ok_or_else(|| "missing macOS child handle".to_string())?;

            let out_thr = child.stdout.take().map(|mut s| {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).to_string()
                })
            });
            let err_thr = child.stderr.take().map(|mut s| {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).to_string()
                })
            });
            let ack_thr = ack_read_file.map(|mut s| {
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let _ = s.read_to_end(&mut buf);
                    String::from_utf8_lossy(&buf).to_string()
                })
            });

            let deadline = timeout.map(|d| Instant::now() + d);
            let mut timed_out = false;
            let exit_code = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code().unwrap_or(1),
                    Ok(None) => {
                        if let Some(dl) = deadline {
                            if Instant::now() >= dl {
                                timed_out = true;
                                let _ = kill_macos_process_subtree(pid);
                                let _ = child.kill();
                                let _ = child.wait();
                                break EXIT_TIMEOUT;
                            }
                        }
                        std::thread::sleep(Duration::from_millis(15));
                    }
                    Err(e) => {
                        let _ = kill_macos_process_subtree(pid);
                        return Err(format!("error waiting on macOS child: {}", e));
                    }
                }
            };

            let stdout = out_thr.and_then(|h| h.join().ok()).unwrap_or_default();
            let stderr = err_thr.and_then(|h| h.join().ok()).unwrap_or_default();
            let ack_received = ack_thr.and_then(|h| h.join().ok()).unwrap_or_default();
            if let Some(ref exp_tok) = ack_expected_token {
                if !timed_out && ack_received.trim() != exp_tok {
                    let err_tail = stderr.trim();
                    return Err(if err_tail.is_empty() {
                        "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox".to_string()
                    } else {
                        format!(
                            "Python audit guard (sitecustomize.py) failed to load or verify inside sandbox: {}",
                            err_tail
                        )
                    });
                }
            }

            Ok(ChildRunOutcome {
                exit_code,
                timed_out,
                backend: "macos-seatbelt-sbpl".to_string(),
                pid: Some(pid),
                stdout,
                stderr,
                diagnostic: if timed_out {
                    Some("process terminated by macOS Seatbelt timeout".to_string())
                } else {
                    None
                },
            })
        })
        .await
        .map_err(|e| format!("blocking macOS worker panicked: {}", e))?
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            program,
            args,
            cwd,
            env_pairs,
            policy,
            sandbox,
            proxy_port,
            py_guard_dir,
            cedar_ipc_port,
            timeout,
            pipe_stdio,
        );
        Err("OS sandbox containment unsupported on this target OS".to_string())
    }
}

#[cfg(test)]
mod iter19_path_norm_tests {
    use super::*;

    #[test]
    fn strip_win_ads_preserves_dot_and_dotdot_segments_before_collapse() {
        let cases = [
            (
                "allowed/../denied/nonexistent.txt",
                "denied/nonexistent.txt",
            ),
            (
                "allowed/./../denied/nonexistent.txt",
                "denied/nonexistent.txt",
            ),
            (
                "allowed/..:stream/denied/nonexistent.txt",
                "denied/nonexistent.txt",
            ),
            ("allowed/../.git/hooks/pre-commit", ".git/hooks/pre-commit"),
            (
                "C:/ws/allowed/../denied/nonexistent.txt",
                "C:/ws/denied/nonexistent.txt",
            ),
            (
                "C:\\ws\\allowed\\..\\denied\\nonexistent.txt",
                "C:/ws/denied/nonexistent.txt",
            ),
        ];
        for (input, expected) in cases {
            let stripped = strip_win_ads_and_trailing_dots_for_cedar(input);
            let collapsed = lexical_collapse_slashes(&stripped);
            assert_eq!(collapsed, expected, "input={}", input);
        }

        #[cfg(windows)]
        {
            for (input, expected) in [
                (
                    r"\\?\C:\ws\allowed\..\denied\nonexistent.txt",
                    "C:/ws/denied/nonexistent.txt",
                ),
                (
                    r"\\127.0.0.1\C$\ws\allowed\..\denied\nonexistent.txt",
                    "C:/ws/denied/nonexistent.txt",
                ),
                (
                    "allowed/.. /denied/nonexistent.txt",
                    "allowed/.. /denied/nonexistent.txt",
                ),
                (
                    "allowed/.../denied/nonexistent.txt",
                    "allowed/.../denied/nonexistent.txt",
                ),
                (
                    "allowed/denied../nonexistent.txt",
                    "allowed/denied/nonexistent.txt",
                ),
                ("allowed/denied./secret.txt.", "allowed/denied/secret.txt"),
            ] {
                let stripped = strip_win_ads_and_trailing_dots_for_cedar(input);
                let collapsed = lexical_collapse_slashes(&stripped);
                assert_eq!(collapsed, expected, "windows input={}", input);
            }
        }
    }

    #[test]
    fn extract_preflight_arg_candidate_handles_equals_and_colons_without_false_positives() {
        assert_eq!(
            extract_preflight_arg_candidate("allowed/ok.txt"),
            Some("allowed/ok.txt")
        );
        assert_eq!(
            extract_preflight_arg_candidate("-f=denied/nonexistent.txt"),
            Some("denied/nonexistent.txt")
        );
        assert_eq!(
            extract_preflight_arg_candidate("-f:denied/nonexistent.txt"),
            Some("denied/nonexistent.txt")
        );
        assert_eq!(
            extract_preflight_arg_candidate("--file:denied/a=b.txt"),
            Some("denied/a=b.txt")
        );
        assert_eq!(
            extract_preflight_arg_candidate("--url=https://example.com/foo"),
            Some("https://example.com/foo")
        );
        assert_eq!(
            extract_preflight_arg_candidate("--url:https://example.com/foo"),
            Some("https://example.com/foo")
        );
        assert_eq!(
            extract_preflight_arg_candidate(r"-f:C:\ws\denied\secret.txt"),
            Some(r"C:\ws\denied\secret.txt")
        );
        assert_eq!(
            extract_preflight_arg_candidate(r#"-f:"denied/secret.txt""#),
            Some("denied/secret.txt")
        );
        assert_eq!(extract_preflight_arg_candidate("-f:"), None);
        assert_eq!(extract_preflight_arg_candidate("--:"), None);
        assert_eq!(extract_preflight_arg_candidate("-I"), None);
    }

    #[test]
    fn evaluate_cedar_fs_request_collapses_dotdot_traversal() {
        let cedar_src = r#"
permit (
    principal,
    action == Octopus::Action::"fs_read",
    resource is Octopus::FilePath
) when {
    context has normalized_path && context.normalized_path like "c:/ws/allowed/*"
};
forbid (
    principal,
    action == Octopus::Action::"fs_read",
    resource is Octopus::FilePath
) when {
    context has normalized_path && context.normalized_path like "c:/ws/denied/*"
};
"#;
        let engine = CedarPolicyEngine::from_custom_policy_set(cedar_src).expect("cedar parse");
        let state = CedarFsServerState {
            engine,
            is_standalone_cedar: true,
            has_exec_permit_rule: false,
            has_fs_read_permit_rule: true,
            has_fs_write_permit_rule: false,
            cwd: "C:/ws".to_string(),
            sandbox_mode: "standard".to_string(),
            auth_token: "tok123".to_string(),
        };
        let deny_req = CedarFsIpcRequest {
            token: "tok123".to_string(),
            action: "fs_read".to_string(),
            path: "C:/ws/allowed/../denied/nonexistent.txt".to_string(),
            raw_path: Some("C:\\ws\\allowed\\..\\denied\\nonexistent.txt".to_string()),
            args_joined: None,
            check_pinned_parent: false,
        };
        let resp = evaluate_cedar_fs_request(&state, &deny_req);
        assert!(
            !resp.allowed,
            "traversal to denied must be denied: {}",
            resp.reason
        );
        assert!(
            resp.explicit_forbid,
            "expected explicit_forbid: {}",
            resp.reason
        );

        let allow_req = CedarFsIpcRequest {
            token: "tok123".to_string(),
            action: "fs_read".to_string(),
            path: "C:/ws/allowed/sub/../ok.txt".to_string(),
            raw_path: None,
            args_joined: None,
            check_pinned_parent: false,
        };
        let ok_resp = evaluate_cedar_fs_request(&state, &allow_req);
        assert!(
            ok_resp.allowed,
            "expected allowed/ok.txt permitted: {}",
            ok_resp.reason
        );
    }

    #[test]
    fn evaluate_cedar_fs_request_enforces_pinned_parent_write_deny() {
        let cedar_src = r#"
permit (
    principal,
    action == Octopus::Action::"fs_write",
    resource is Octopus::FilePath
);
"#;
        let engine = CedarPolicyEngine::from_custom_policy_set(cedar_src).expect("cedar parse");
        let state = CedarFsServerState {
            engine,
            is_standalone_cedar: true,
            has_exec_permit_rule: false,
            has_fs_read_permit_rule: false,
            has_fs_write_permit_rule: true,
            cwd: "C:/ws".to_string(),
            sandbox_mode: "standard".to_string(),
            auth_token: "tok123".to_string(),
        };

        for pinned in [
            "C:/ws/allowed/.git",
            "C:/ws/allowed/.claude",
            "C:/ws/allowed/.git.",
            "C:/ws/allowed/.git:stream",
            "C:/ws/allowed/sub/../.git",
            "C:/ws/allowed/.githooks",
            "C:/ws/allowed/.vscode",
            "C:/ws/allowed/.idea",
        ] {
            let req = CedarFsIpcRequest {
                token: "tok123".to_string(),
                action: "fs_write".to_string(),
                path: pinned.to_string(),
                raw_path: None,
                args_joined: None,
                check_pinned_parent: true,
            };
            let resp = evaluate_cedar_fs_request(&state, &req);
            assert!(
                !resp.allowed && resp.explicit_forbid,
                "pinned parent '{}' must be unconditionally forbidden: allowed={}, explicit_forbid={}, reason={}",
                pinned, resp.allowed, resp.explicit_forbid, resp.reason
            );
        }

        for ok_child in [
            "C:/ws/allowed/.git/index",
            "C:/ws/allowed/.claude/config.json",
        ] {
            let req = CedarFsIpcRequest {
                token: "tok123".to_string(),
                action: "fs_write".to_string(),
                path: ok_child.to_string(),
                raw_path: None,
                args_joined: None,
                check_pinned_parent: false,
            };
            let resp = evaluate_cedar_fs_request(&state, &req);
            assert!(
                resp.allowed,
                "non-mandatory child '{}' with check_pinned_parent=false should be allowed: {}",
                ok_child, resp.reason
            );
        }

        let hook_req = CedarFsIpcRequest {
            token: "tok123".to_string(),
            action: "fs_write".to_string(),
            path: "C:/ws/allowed/.git/hooks/pre-commit".to_string(),
            raw_path: None,
            args_joined: None,
            check_pinned_parent: false,
        };
        let hook_resp = evaluate_cedar_fs_request(&state, &hook_req);
        assert!(
            !hook_resp.allowed
                && hook_resp.explicit_forbid
                && hook_resp.reason == "mandatory_write_deny",
            "mandatory write-deny '.git/hooks/pre-commit' must be unconditionally forbidden: {}",
            hook_resp.reason
        );
    }
}
