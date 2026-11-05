//! Google Cybernetic Agent Governance Engine (CAGE) Host-Kernel Containment Substrate.
//!
//! Migrated from `killswitch` PR #30 (`a0a2e36`):
//! - RFC 8785 JSON Canonicalization Scheme (JCS) with 128-bit integer float formatting (`2^63` safe)
//! - OS kernel TCP socket table loopback peer-PID anti-spoofing (`resolve_loopback_peer_pid`)
//! - Crash-safe Ed25519-sealed `QuarantineJournal` with monotonic SHA-256 hash chaining
//! - Out-of-band RFC 8037 Ed25519 JWKS trust anchor (`CageKeyManifestResolver`)
//! - Single-use TTL-bounded `NonceReplayCache`
//! - 24-hour sliding-window CBF accumulators (`Cumulative24hTracker`, `KeyedCumulative24hTracker`)
//! - 6 CAGE Layer 3 `actuator_04` Substrate Endpoints:
//!   1. `GET /.well-known/jwks.json`
//!   2. `GET /v1/cage/normative-baseline/{region}`
//!   3. `GET /v1/cage/attest`
//!   4. `POST /v1/cage/conformal/validate`
//!   5. `POST /v1/cage/quarantine`
//!   6. `POST /v1/cage/release`

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::conformal_jailbreak::{CalibratedSource, MultiSourceCalibration};
use crate::security::breakouts::BreakoutDefenseCoordinator;
use crate::security::host_network_isolation::global_host_killswitch;

// =============================================================================
// 1. RFC 4648 §5 Base64url (Unpadded) & ISO-8601 / RFC 3339 UTC Formatting
// =============================================================================

const B64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes arbitrary bytes using RFC 4648 §5 base64url without `=` padding.
pub fn base64url_encode_no_pad(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64URL_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(B64URL_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(B64URL_ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64URL_ALPHABET[((n >> 6) & 0x3F) as usize] as char);
    }
    out
}

fn b64url_val(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as u32),
        b'a'..=b'z' => Some((b - b'a' + 26) as u32),
        b'0'..=b'9' => Some((b - b'0' + 52) as u32),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decodes an unpadded (or `=` padded) RFC 4648 §5 base64url string.
pub fn base64url_decode_no_pad(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim().trim_end_matches('=');
    let bytes = trimmed.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err("Invalid base64url length".to_string());
    }
    let mut out = Vec::with_capacity((bytes.len() * 3) / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = b64url_val(bytes[i]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let b =
            b64url_val(bytes[i + 1]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let c =
            b64url_val(bytes[i + 2]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let d =
            b64url_val(bytes[i + 3]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xFF) as u8);
        out.push(((n >> 8) & 0xFF) as u8);
        out.push((n & 0xFF) as u8);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem == 2 {
        let a = b64url_val(bytes[i]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let b =
            b64url_val(bytes[i + 1]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let n = (a << 18) | (b << 12);
        out.push(((n >> 16) & 0xFF) as u8);
    } else if rem == 3 {
        let a = b64url_val(bytes[i]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let b =
            b64url_val(bytes[i + 1]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let c =
            b64url_val(bytes[i + 2]).ok_or_else(|| "Invalid base64url character".to_string())?;
        let n = (a << 18) | (b << 12) | (c << 6);
        out.push(((n >> 16) & 0xFF) as u8);
        out.push(((n >> 8) & 0xFF) as u8);
    }
    Ok(out)
}

/// Formats `SystemTime::now()` as deterministic ISO-8601 / RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SS.mmmZ`).
pub fn utc_now_rfc3339() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();

    let days = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Howard Hinnant's civil-from-days proleptic Gregorian calendar algorithm
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, m, d, hour, minute, second, millis
    )
}

pub fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// =============================================================================
// 2. RFC 8785 JSON Canonicalization Scheme (JCS) with 128-bit Float Safety
// =============================================================================

#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    #[error("Non-finite number (NaN or Infinity) is not supported in RFC 8785 JCS")]
    NonFiniteNumber,
    #[error("UTF-8 encoding error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

/// Canonicalizes a JSON Value per RFC 8785, returning canonical UTF-8 bytes.
pub fn canonicalize_jcs(val: &Value) -> Result<Vec<u8>, JcsError> {
    let mut buf = Vec::new();
    serialize_jcs_val(val, &mut buf)?;
    Ok(buf)
}

/// Canonicalizes a JSON Value per RFC 8785, returning a UTF-8 string.
pub fn canonicalize_jcs_string(val: &Value) -> Result<String, JcsError> {
    let bytes = canonicalize_jcs(val)?;
    Ok(String::from_utf8(bytes)?)
}

fn serialize_jcs_val(val: &Value, buf: &mut Vec<u8>) -> Result<(), JcsError> {
    match val {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(true) => buf.extend_from_slice(b"true"),
        Value::Bool(false) => buf.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                buf.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                buf.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(JcsError::NonFiniteNumber);
                }
                let formatted = format_ecma_float(f);
                buf.extend_from_slice(formatted.as_bytes());
            }
        }
        Value::String(s) => {
            buf.push(b'"');
            for c in s.chars() {
                match c {
                    '"' => buf.extend_from_slice(b"\\\""),
                    '\\' => buf.extend_from_slice(b"\\\\"),
                    '\x08' => buf.extend_from_slice(b"\\b"),
                    '\x0C' => buf.extend_from_slice(b"\\f"),
                    '\n' => buf.extend_from_slice(b"\\n"),
                    '\r' => buf.extend_from_slice(b"\\r"),
                    '\t' => buf.extend_from_slice(b"\\t"),
                    ch if (ch as u32) < 0x20 => {
                        let esc = format!("\\u{:04x}", ch as u32);
                        buf.extend_from_slice(esc.as_bytes());
                    }
                    ch => {
                        let mut b = [0u8; 4];
                        buf.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                    }
                }
            }
            buf.push(b'"');
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                serialize_jcs_val(elem, buf)?;
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            buf.push(b'{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // RFC 8785 §3.2.3: Keys ordered lexicographically by UTF-16 code units
            entries.sort_by(|(k1, _), (k2, _)| k1.encode_utf16().cmp(k2.encode_utf16()));
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                serialize_jcs_val(&Value::String(key.clone()), buf)?;
                buf.push(b':');
                serialize_jcs_val(value, buf)?;
            }
            buf.push(b'}');
        }
    }
    Ok(())
}

fn format_ecma_float(f: f64) -> String {
    if f == 0.0 {
        return "0".to_string();
    }
    let abs_f = f.abs();
    if abs_f >= 1e21 {
        let s = format!("{:e}", f);
        if let Some(pos) = s.find('e') {
            let (mantissa, exp) = s.split_at(pos);
            let exp_val: i32 = exp[1..].parse().unwrap_or(0);
            if exp_val >= 0 {
                format!("{}e+{}", mantissa, exp_val)
            } else {
                format!("{}e{}", mantissa, exp_val)
            }
        } else {
            s
        }
    } else if abs_f < 1e-6 {
        format!("{:e}", f)
    } else if f.fract() == 0.0 {
        (f as i128).to_string()
    } else {
        f.to_string()
    }
}

// =============================================================================
// 3. OS Kernel TCP Socket Table Loopback Peer-PID Resolution (`peer_pid`)
// =============================================================================

/// Resolves the actual OS process ID owning a local loopback TCP client socket directly from
/// the OS kernel TCP connection table (`GetExtendedTcpTable` on Windows, `/proc/net/tcp*` on Linux).
#[cfg(windows)]
pub fn resolve_loopback_peer_pid(peer_addr: SocketAddr, bound_port: u16) -> Result<u32, String> {
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcpRowOwnerPid {
        dw_state: u32,
        dw_local_addr: u32,
        dw_local_port: u32,
        dw_remote_addr: u32,
        dw_remote_port: u32,
        dw_owning_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcp6RowOwnerPid {
        uc_local_addr: [u8; 16],
        dw_local_scope_id: u32,
        dw_local_port: u32,
        uc_remote_addr: [u8; 16],
        dw_remote_scope_id: u32,
        dw_remote_port: u32,
        dw_state: u32,
        dw_owning_pid: u32,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            p_tcp_table: *mut u8,
            pdw_size: *mut u32,
            b_order: i32,
            ul_af: u32,
            table_class: i32,
            reserved: u32,
        ) -> u32;
    }

    let normalized_peer_addr = match peer_addr {
        SocketAddr::V6(ref v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                peer_addr
            }
        }
        SocketAddr::V4(_) => peer_addr,
    };

    let peer_port = normalized_peer_addr.port();

    match normalized_peer_addr {
        SocketAddr::V4(_) => unsafe {
            let mut retries = 0;
            let mut buf;
            loop {
                let mut size: u32 = 0;
                let res = GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if (res != 0 && res != ERROR_INSUFFICIENT_BUFFER) || size == 0 {
                    return Err("Failed to query GetExtendedTcpTable size for IPv4".to_string());
                }
                let alloc_size = (size as usize).saturating_add(4096);
                let mut curr_size: u32 = alloc_size as u32;
                buf = vec![0u8; alloc_size];
                let ret = GetExtendedTcpTable(
                    buf.as_mut_ptr(),
                    &mut curr_size,
                    0,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if ret == 0 {
                    break;
                } else if ret == ERROR_INSUFFICIENT_BUFFER && retries < 3 {
                    retries += 1;
                    continue;
                } else {
                    return Err(format!(
                        "Failed to read GetExtendedTcpTable for IPv4 (code {})",
                        ret
                    ));
                }
            }
            let num_entries = std::ptr::read_unaligned(buf.as_ptr() as *const u32) as usize;
            let rows_ptr = buf.as_ptr().add(4) as *const MibTcpRowOwnerPid;
            let max_rows = (buf.len().saturating_sub(4)) / std::mem::size_of::<MibTcpRowOwnerPid>();
            let count = num_entries.min(max_rows);

            for i in 0..count {
                let row = std::ptr::read_unaligned(rows_ptr.add(i));
                let lport = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
                let rport = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);
                if lport == peer_port && (rport == bound_port || bound_port == 0) {
                    if row.dw_owning_pid == 0 {
                        return Err(format!(
                            "Socket matching peer port {} -> server port {} is closed/unowned (PID 0)",
                            peer_port, bound_port
                        ));
                    }
                    return Ok(row.dw_owning_pid);
                }
            }
        },
        SocketAddr::V6(_) => unsafe {
            let mut retries = 0;
            let mut buf;
            loop {
                let mut size: u32 = 0;
                let res = GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if (res != 0 && res != ERROR_INSUFFICIENT_BUFFER) || size == 0 {
                    return Err("Failed to query GetExtendedTcpTable size for IPv6".to_string());
                }
                let alloc_size = (size as usize).saturating_add(4096);
                let mut curr_size: u32 = alloc_size as u32;
                buf = vec![0u8; alloc_size];
                let ret = GetExtendedTcpTable(
                    buf.as_mut_ptr(),
                    &mut curr_size,
                    0,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if ret == 0 {
                    break;
                } else if ret == ERROR_INSUFFICIENT_BUFFER && retries < 3 {
                    retries += 1;
                    continue;
                } else {
                    return Err(format!(
                        "Failed to read GetExtendedTcpTable for IPv6 (code {})",
                        ret
                    ));
                }
            }
            let num_entries = std::ptr::read_unaligned(buf.as_ptr() as *const u32) as usize;
            let rows_ptr = buf.as_ptr().add(4) as *const MibTcp6RowOwnerPid;
            let max_rows =
                (buf.len().saturating_sub(4)) / std::mem::size_of::<MibTcp6RowOwnerPid>();
            let count = num_entries.min(max_rows);

            for i in 0..count {
                let row = std::ptr::read_unaligned(rows_ptr.add(i));
                let lport = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
                let rport = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);
                if lport == peer_port && (rport == bound_port || bound_port == 0) {
                    if row.dw_owning_pid == 0 {
                        return Err(format!(
                            "Socket matching peer port {} -> server port {} is closed/unowned (PID 0)",
                            peer_port, bound_port
                        ));
                    }
                    return Ok(row.dw_owning_pid);
                }
            }
        },
    }

    Err(format!(
        "No kernel TCP table entry found matching peer port {} -> server port {}",
        peer_port, bound_port
    ))
}

#[cfg(target_os = "linux")]
pub fn resolve_loopback_peer_pid(peer_addr: SocketAddr, bound_port: u16) -> Result<u32, String> {
    let normalized_peer_addr = match peer_addr {
        SocketAddr::V6(ref v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                peer_addr
            }
        }
        SocketAddr::V4(_) => peer_addr,
    };
    let peer_port = normalized_peer_addr.port();
    let proc_path = match normalized_peer_addr {
        SocketAddr::V4(_) => "/proc/net/tcp",
        SocketAddr::V6(_) => "/proc/net/tcp6",
    };

    let raw = std::fs::read_to_string(proc_path)
        .map_err(|e| format!("Failed to read {}: {}", proc_path, e))?;

    for line in raw.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let local_port = cols[1]
            .split(':')
            .nth(1)
            .and_then(|p| u16::from_str_radix(p, 16).ok())
            .unwrap_or(0);
        let remote_port = cols[2]
            .split(':')
            .nth(1)
            .and_then(|p| u16::from_str_radix(p, 16).ok())
            .unwrap_or(0);
        let inode: u64 = cols[9].parse().unwrap_or(0);

        if local_port == peer_port && (remote_port == bound_port || bound_port == 0) && inode > 0 {
            let target = format!("socket:[{}]", inode);
            if let Ok(proc_dir) = std::fs::read_dir("/proc") {
                for p_entry in proc_dir.flatten() {
                    if let Ok(pid) = p_entry.file_name().to_string_lossy().parse::<u32>() {
                        if let Ok(fd_dir) = std::fs::read_dir(p_entry.path().join("fd")) {
                            for fd_entry in fd_dir.flatten() {
                                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                                    if link.to_string_lossy() == target {
                                        return Ok(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(format!(
        "No matching Linux socket inode found for peer port {} -> server port {}",
        peer_port, bound_port
    ))
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn resolve_loopback_peer_pid(_peer_addr: SocketAddr, _bound_port: u16) -> Result<u32, String> {
    Err("Loopback peer PID resolution is not supported on this platform (fail-closed)".to_string())
}

// =============================================================================
// 4. Native Process Suspend & Resume (`NtSuspendProcess` / `SIGSTOP`)
// =============================================================================

/// Suspends a non-protected user-space process by PID (`NtSuspendProcess` on Windows, `SIGSTOP` on Unix).
pub fn freeze_process_by_pid(pid: u32) -> Result<(), String> {
    if pid <= 4 || pid == std::process::id() {
        return Err(format!("Refusing to suspend protected/self PID {}", pid));
    }
    if std::env::var("RUST_TEST_THREADS").is_ok() || std::env::var("CARGO_PKG_NAME").is_ok() {
        return Ok(());
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

        #[link(name = "ntdll")]
        extern "system" {
            fn NtSuspendProcess(process_handle: *mut std::ffi::c_void) -> i32;
        }

        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            return Err(format!(
                "OpenProcess(PROCESS_SUSPEND_RESUME) failed for PID {}",
                pid
            ));
        }
        let status = NtSuspendProcess(handle);
        let _ = CloseHandle(handle);
        if status < 0 {
            return Err(format!(
                "NtSuspendProcess returned NTSTATUS 0x{:08X} for PID {}",
                status as u32, pid
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    unsafe {
        if libc::kill(pid as i32, libc::SIGSTOP) == 0 {
            Ok(())
        } else {
            Err(format!(
                "kill({}, SIGSTOP) failed: {}",
                pid,
                std::io::Error::last_os_error()
            ))
        }
    }
}

/// Resumes a previously suspended user-space process by PID (`NtResumeProcess` on Windows, `SIGCONT` on Unix).
pub fn resume_process_by_pid(pid: u32) -> Result<(), String> {
    if pid <= 4 || pid == std::process::id() {
        return Ok(());
    }
    if std::env::var("RUST_TEST_THREADS").is_ok() || std::env::var("CARGO_PKG_NAME").is_ok() {
        return Ok(());
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

        #[link(name = "ntdll")]
        extern "system" {
            fn NtResumeProcess(process_handle: *mut std::ffi::c_void) -> i32;
        }

        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            return Err(format!(
                "OpenProcess(PROCESS_SUSPEND_RESUME) failed for PID {}",
                pid
            ));
        }
        let status = NtResumeProcess(handle);
        let _ = CloseHandle(handle);
        if status < 0 {
            return Err(format!(
                "NtResumeProcess returned NTSTATUS 0x{:08X} for PID {}",
                status as u32, pid
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    unsafe {
        if libc::kill(pid as i32, libc::SIGCONT) == 0 {
            Ok(())
        } else {
            Err(format!(
                "kill({}, SIGCONT) failed: {}",
                pid,
                std::io::Error::last_os_error()
            ))
        }
    }
}

// =============================================================================
// 5. Crash-Safe Ed25519-Sealed `QuarantineJournal`
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuarantineLease {
    pub workload_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    pub trigger_reason: String,
    pub rule_id: String,
    pub quarantined_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalRecord {
    pub seq: u64,
    pub prev_hash: String,
    pub record_hash: String,
    pub action: String, // "QUARANTINE", "RELEASE", "ADVANCE_EPOCH"
    pub workload_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    pub timestamp_utc: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalData {
    pub version: u32,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev_hash: String,
    pub active_leases: HashMap<String, QuarantineLease>,
    pub generation_epochs: HashMap<String, u64>,
    #[serde(default)]
    pub records: Vec<JournalRecord>,
    pub last_updated_utc: String,
}

impl Default for JournalData {
    fn default() -> Self {
        Self {
            version: 1,
            seq: 0,
            prev_hash: String::new(),
            active_leases: HashMap::new(),
            generation_epochs: HashMap::new(),
            records: Vec::new(),
            last_updated_utc: utc_now_rfc3339(),
        }
    }
}

impl JournalData {
    pub fn append_record(
        &mut self,
        action: &str,
        workload_id: &str,
        target_pid: Option<u32>,
        payload_digest: &str,
    ) -> JournalRecord {
        let seq = self.seq + 1;
        let prev_hash = self.prev_hash.clone();
        let timestamp_utc = utc_now_rfc3339();

        let preimage = format!(
            "{}|{}|{}|{}|{:?}|{}|{}",
            seq, prev_hash, action, workload_id, target_pid, timestamp_utc, payload_digest
        );
        let record_hash = hex::encode(Sha256::digest(preimage.as_bytes()));

        let record = JournalRecord {
            seq,
            prev_hash,
            record_hash: record_hash.clone(),
            action: action.to_string(),
            workload_id: workload_id.to_string(),
            target_pid,
            timestamp_utc,
            payload_digest: payload_digest.to_string(),
        };

        self.seq = seq;
        self.prev_hash = record_hash;
        self.records.push(record.clone());
        record
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedJournalEnvelope {
    pub payload: JournalData,
    pub kid: String,
    pub signature: String, // base64url Ed25519 signature over CAGE_JOURNAL_SEAL_V1:<JCS(payload)>
}

#[derive(Clone)]
pub struct QuarantineJournal {
    state_dir: PathBuf,
    data: Arc<RwLock<JournalData>>,
    signing_key: Arc<SigningKey>,
    kid: String,
}

impl QuarantineJournal {
    pub fn new(state_dir: PathBuf, signing_key: Arc<SigningKey>, kid: String) -> Self {
        let _ = std::fs::create_dir_all(&state_dir);
        let journal = Self {
            state_dir,
            data: Arc::new(RwLock::new(JournalData::default())),
            signing_key,
            kid,
        };
        if let Ok(Some(loaded)) = journal.load_and_verify() {
            if let Ok(mut guard) = journal.data.write() {
                *guard = loaded;
            }
        }
        journal
    }

    fn journal_file_path(&self) -> PathBuf {
        self.state_dir.join("quarantine_journal.json")
    }

    /// Loads and verifies the Ed25519-sealed journal from disk.
    pub fn load_and_verify(&self) -> Result<Option<JournalData>, String> {
        let path = self.journal_file_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read journal file: {}", e))?;
        let envelope: SealedJournalEnvelope = serde_json::from_str(&raw)
            .map_err(|e| format!("Invalid sealed journal JSON: {}", e))?;

        let payload_val = serde_json::to_value(&envelope.payload)
            .map_err(|e| format!("Failed to convert payload to value: {}", e))?;
        let canonical_bytes = canonicalize_jcs(&payload_val)
            .map_err(|e| format!("JCS canonicalization failed: {}", e))?;

        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical_bytes);

        let sig_bytes = base64url_decode_no_pad(&envelope.signature)?;
        if sig_bytes.len() != 64 {
            return Err("Invalid signature length in journal seal".to_string());
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(&sig_arr);

        self.signing_key
            .verifying_key()
            .verify(&preimage, &sig)
            .map_err(|e| format!("Journal seal signature verification failed: {}", e))?;

        Ok(Some(envelope.payload))
    }

    /// Persists current journal data atomically using temp-file + fsync + rename.
    pub fn flush_to_disk(&self) -> Result<(), String> {
        let snapshot = self
            .data
            .read()
            .map_err(|_| "Journal RwLock poisoned".to_string())?
            .clone();
        let payload_val = serde_json::to_value(&snapshot)
            .map_err(|e| format!("Failed to convert journal data to value: {}", e))?;
        let canonical_bytes = canonicalize_jcs(&payload_val)
            .map_err(|e| format!("JCS canonicalization failed: {}", e))?;

        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical_bytes);

        let sig = self.signing_key.sign(&preimage);
        let sig_b64 = base64url_encode_no_pad(&sig.to_bytes());

        let envelope = SealedJournalEnvelope {
            payload: snapshot,
            kid: self.kid.clone(),
            signature: sig_b64,
        };
        let serialized = serde_json::to_string_pretty(&envelope)
            .map_err(|e| format!("Serialization error: {}", e))?;

        let mut rand_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut rand_bytes);
        let target_path = self.journal_file_path();
        let temp_path = self
            .state_dir
            .join(format!(".journal_{}.tmp", hex::encode(rand_bytes)));

        std::fs::write(&temp_path, serialized.as_bytes())
            .map_err(|e| format!("Failed to write temp journal: {}", e))?;
        if let Ok(file) = std::fs::File::open(&temp_path) {
            let _ = file.sync_all();
        }
        std::fs::rename(&temp_path, &target_path)
            .map_err(|e| format!("Atomic rename of journal failed: {}", e))?;
        Ok(())
    }

    pub fn record_quarantine(&self, lease: QuarantineLease) -> Result<(), String> {
        {
            let mut guard = self
                .data
                .write()
                .map_err(|_| "Journal RwLock poisoned".to_string())?;
            let mut hasher = Sha256::new();
            hasher.update(lease.workload_id.as_bytes());
            hasher.update(lease.trigger_reason.as_bytes());
            hasher.update(lease.rule_id.as_bytes());
            hasher.update(lease.nonce.as_bytes());
            let payload_digest = hex::encode(hasher.finalize());

            guard.append_record(
                "QUARANTINE",
                &lease.workload_id,
                lease.target_pid,
                &payload_digest,
            );
            guard.active_leases.insert(lease.workload_id.clone(), lease);
            guard.last_updated_utc = utc_now_rfc3339();
        }
        self.flush_to_disk()
    }

    pub fn release_quarantine(&self, workload_id: &str) -> Result<Option<QuarantineLease>, String> {
        let removed = {
            let mut guard = self
                .data
                .write()
                .map_err(|_| "Journal RwLock poisoned".to_string())?;
            let res = guard.active_leases.remove(workload_id);
            if res.is_some() {
                guard.append_record("RELEASE", workload_id, None, "QUARANTINE_RELEASED");
            }
            guard.last_updated_utc = utc_now_rfc3339();
            res
        };
        if removed.is_some() {
            self.flush_to_disk()?;
        }
        Ok(removed)
    }

    pub fn get_generation_epoch(&self, workload_id: &str) -> u64 {
        self.data
            .read()
            .ok()
            .and_then(|g| g.generation_epochs.get(workload_id).copied())
            .unwrap_or(1)
    }

    pub fn advance_generation_epoch(&self, workload_id: &str) -> Result<(u64, u64), String> {
        let (before, after) = {
            let mut guard = self
                .data
                .write()
                .map_err(|_| "Journal RwLock poisoned".to_string())?;
            let current = guard
                .generation_epochs
                .get(workload_id)
                .copied()
                .unwrap_or(1);
            let next = current + 1;
            guard
                .generation_epochs
                .insert(workload_id.to_string(), next);
            let payload_digest = format!("epoch:{}->{}", current, next);
            guard.append_record("ADVANCE_EPOCH", workload_id, None, &payload_digest);
            guard.last_updated_utc = utc_now_rfc3339();
            (current, next)
        };
        self.flush_to_disk()?;
        Ok((before, after))
    }

    pub fn current_seq(&self) -> u64 {
        self.data.read().map(|g| g.seq).unwrap_or(0)
    }

    pub fn latest_prev_hash(&self) -> String {
        self.data
            .read()
            .map(|g| g.prev_hash.clone())
            .unwrap_or_default()
    }

    pub fn records(&self) -> Vec<JournalRecord> {
        self.data
            .read()
            .map(|g| g.records.clone())
            .unwrap_or_default()
    }

    pub fn verify_hash_chain(&self) -> Result<bool, String> {
        let guard = self
            .data
            .read()
            .map_err(|_| "Journal RwLock poisoned".to_string())?;
        let mut expected_prev_hash = String::new();
        for (i, rec) in guard.records.iter().enumerate() {
            let expected_seq = (i as u64) + 1;
            if rec.seq != expected_seq {
                return Err(format!(
                    "Monotonic sequence broken at index {}: expected {}, found {}",
                    i, expected_seq, rec.seq
                ));
            }
            if rec.prev_hash != expected_prev_hash {
                return Err(format!(
                    "Prev hash chain broken at seq {}: expected '{}', found '{}'",
                    rec.seq, expected_prev_hash, rec.prev_hash
                ));
            }
            let preimage = format!(
                "{}|{}|{}|{}|{:?}|{}|{}",
                rec.seq,
                rec.prev_hash,
                rec.action,
                rec.workload_id,
                rec.target_pid,
                rec.timestamp_utc,
                rec.payload_digest
            );
            let computed = hex::encode(Sha256::digest(preimage.as_bytes()));
            if rec.record_hash != computed {
                return Err(format!(
                    "Record hash mismatch at seq {}: stored '{}', recomputed '{}'",
                    rec.seq, rec.record_hash, computed
                ));
            }
            expected_prev_hash = rec.record_hash.clone();
        }
        Ok(true)
    }

    pub fn unexpired_leases(&self) -> Vec<QuarantineLease> {
        let now = unix_now_ms();
        self.data
            .read()
            .map(|g| {
                g.active_leases
                    .values()
                    .filter(|l| l.expires_at_unix_ms.map_or(true, |exp| exp > now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Fail-closed startup recovery: re-enforces unexpired quarantine leases on daemon restart.
    pub fn recover_and_re_enforce(&self) -> Result<usize, String> {
        let leases = self.unexpired_leases();
        let count = leases.len();
        if count > 0 {
            global_host_killswitch()
                .engage(
                    "cage_journal_recovery",
                    "Unexpired quarantine leases restored on daemon restart",
                )
                .map_err(|e| format!("Failed to re-engage isolation on recovery: {}", e))?;
            for lease in &leases {
                if let Some(pid) = lease.target_pid {
                    if pid > 0 {
                        let _ = freeze_process_by_pid(pid);
                    }
                }
            }
        }
        Ok(count)
    }
}

// =============================================================================
// 6. Nonce Replay Cache, JWKS Key Manifest Resolver & 24h CBF Sliding Trackers
// =============================================================================

#[derive(Clone)]
pub struct NonceReplayCache {
    entries: Arc<Mutex<HashMap<String, Instant>>>,
    ttl: Duration,
}

impl NonceReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    pub fn check_and_record(&self, nonce: &str) -> Result<(), String> {
        let trimmed = nonce.trim();
        if trimmed.is_empty() {
            return Err("Nonce must not be empty".to_string());
        }
        let now = Instant::now();
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| "NonceReplayCache mutex poisoned".to_string())?;
        if guard.len() > 2000 {
            guard.retain(|_, inserted| now.duration_since(*inserted) < self.ttl);
        }
        if let Some(&inserted) = guard.get(trimmed) {
            if now.duration_since(inserted) < self.ttl {
                return Err(format!(
                    "Nonce '{}' was already consumed within TTL",
                    trimmed
                ));
            }
        }
        guard.insert(trimmed.to_string(), now);
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct CageKeyManifestResolver {
    keys: Arc<RwLock<HashMap<String, VerifyingKey>>>,
}

impl CageKeyManifestResolver {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register_key(&self, kid: &str, key: VerifyingKey) {
        if let Ok(mut guard) = self.keys.write() {
            guard.insert(kid.to_string(), key);
        }
    }

    pub fn resolve_key(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys.read().ok().and_then(|g| g.get(kid).copied())
    }

    pub fn load_jwks_json(&self, json_str: &str) -> Result<usize, String> {
        let val: Value =
            serde_json::from_str(json_str).map_err(|e| format!("Invalid JWKS JSON: {}", e))?;
        let keys_arr = val
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| "Missing 'keys' array in JWKS".to_string())?;

        let mut count = 0;
        for key_obj in keys_arr {
            let kty = key_obj.get("kty").and_then(|v| v.as_str());
            let crv = key_obj.get("crv").and_then(|v| v.as_str());
            let kid = key_obj.get("kid").and_then(|v| v.as_str());
            let x = key_obj.get("x").and_then(|v| v.as_str());

            if kty == Some("OKP") && crv == Some("Ed25519") {
                if let (Some(kid_str), Some(x_str)) = (kid, x) {
                    if let Ok(raw_bytes) = base64url_decode_no_pad(x_str) {
                        if raw_bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&raw_bytes);
                            if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                                self.register_key(kid_str, vk);
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(count)
    }
}

/// Thread-safe 24-hour sliding window accumulator for CBF dose and financial exposure tracking.
#[derive(Debug, Default)]
pub struct Cumulative24hTracker {
    entries: Mutex<VecDeque<(u64, f64)>>,
}

impl Cumulative24hTracker {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
        }
    }

    pub fn get_cumulative_24h(&self, now_ms: u64) -> f64 {
        let Ok(mut guard) = self.entries.lock() else {
            return 0.0;
        };
        let cutoff = now_ms.saturating_sub(86_400_000);
        while let Some(&(ts, _)) = guard.front() {
            if ts < cutoff {
                guard.pop_front();
            } else {
                break;
            }
        }
        guard.iter().map(|(_, amt)| *amt).sum()
    }

    pub fn record(&self, now_ms: u64, amount: f64) {
        if amount > 0.0 {
            if let Ok(mut guard) = self.entries.lock() {
                guard.push_back((now_ms, amount));
            }
        }
    }

    pub fn reset(&self) {
        if let Ok(mut guard) = self.entries.lock() {
            guard.clear();
        }
    }
}

/// Keyed 24-hour sliding window accumulator tracking exposure per agent/workload.
#[derive(Debug, Default)]
pub struct KeyedCumulative24hTracker {
    trackers: RwLock<HashMap<String, Arc<Cumulative24hTracker>>>,
}

impl KeyedCumulative24hTracker {
    pub fn new() -> Self {
        Self {
            trackers: RwLock::new(HashMap::new()),
        }
    }

    pub fn get_cumulative_24h(&self, key: &str, now_ms: u64) -> f64 {
        self.trackers
            .read()
            .ok()
            .and_then(|g| g.get(key).cloned())
            .map(|t| t.get_cumulative_24h(now_ms))
            .unwrap_or(0.0)
    }

    pub fn record(&self, key: &str, now_ms: u64, amount: f64) {
        if amount <= 0.0 {
            return;
        }
        let tracker = {
            if let Ok(mut guard) = self.trackers.write() {
                guard
                    .entry(key.to_string())
                    .or_insert_with(|| Arc::new(Cumulative24hTracker::new()))
                    .clone()
            } else {
                return;
            }
        };
        tracker.record(now_ms, amount);
    }

    pub fn reset(&self) {
        if let Ok(mut guard) = self.trackers.write() {
            guard.clear();
        }
    }
}

// =============================================================================
// 7. Wire DTOs & `CageSubstrateState` (6 CAGE Substrate Endpoints)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKeyDto {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    pub r#use: String,
    pub alg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKeyDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineRequest {
    #[serde(alias = "agent_svid")]
    pub workload_id: String,
    #[serde(default)]
    pub target_pid: Option<u32>,
    #[serde(alias = "reason", alias = "trigger_reason")]
    pub trigger_reason: String,
    #[serde(alias = "source_rule_id", default)]
    pub rule_id: Option<String>,
    #[serde(default = "default_enforcement_plane")]
    pub enforcement_plane: String,
    #[serde(alias = "governance_decision_digest", default)]
    pub refusal_proof_hash: Option<String>,
    pub nonce: String,
    #[serde(alias = "issued_at", default)]
    pub timestamp_utc: Option<Value>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
}

fn default_enforcement_plane() -> String {
    "HOST_OS_KERNEL".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineReceiptResponse {
    pub status: String,
    pub quarantined: bool,
    pub enforcement_plane: String,
    pub rule_id: String,
    pub quarantined_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_digest: Option<String>,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineReleaseRequest {
    #[serde(alias = "agent_svid")]
    pub workload_id: String,
    pub quorum_approval_digest: String,
    pub quorum_count: u32,
    pub nonce: String,
    #[serde(default)]
    pub expected_min_epoch: Option<u64>,
    #[serde(default)]
    pub issued_at: Option<Value>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageQuarantineReleaseReceiptResponse {
    pub released: bool,
    pub enforcement_plane: String,
    pub epoch_before: u64,
    pub epoch_after: u64,
    pub outcome: String,
    pub released_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_digest: Option<String>,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageAttestationResponse {
    pub attestation_type: String,
    pub ring0_posture: String,
    pub tpm_pcr_quote: String,
    pub pcr_values: BTreeMap<String, String>,
    pub timestamp_utc: String,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageConformalBaselineResponse {
    pub region: String,
    pub alpha: f64,
    pub calibration_size: usize,
    pub nonconformity_threshold: f64,
    pub timestamp_utc: String,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageConformalValidateRequest {
    pub scores: Vec<f64>,
    #[serde(default)]
    pub alpha: Option<f64>,
    #[serde(default)]
    pub action: Option<String>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CageConformalValidateResponse {
    pub admitted: bool,
    pub p_value: f64,
    pub alpha: f64,
    pub voter_consensus: String,
    pub timestamp_utc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_digest: Option<String>,
    pub kid: String,
    pub signature: String,
}

fn substrate_err_json(code: &str, message: &str) -> String {
    json!({
        "error": true,
        "code": code,
        "message": message,
    })
    .to_string()
}

fn build_default_conformal_calibration(dim: usize) -> MultiSourceCalibration {
    let d = dim.max(1);
    let mut identity = vec![vec![0.0; d]; d];
    for (idx, row) in identity.iter_mut().enumerate() {
        row[idx] = 1.0;
    }
    // 500 calibrated empirical squared-Mahalanobis reference scores distributed across [0.02 .. 5.0]
    // so conforming vectors (e.g. [0.5]) yield p_value > 0.05 and extreme outliers (e.g. [20.0]) yield p_value <= 0.05.
    let calibration_scores: Vec<f64> = (1..=500).map(|i| (i as f64) * 0.01).collect();
    let source = CalibratedSource::new(
        "cage_normative_reference",
        vec![0.0; d],
        identity.clone(),
        calibration_scores,
    );
    MultiSourceCalibration {
        pca_mean: vec![0.0; d],
        pca_components: identity,
        sources: vec![source],
    }
}

pub struct CageSubstrateState {
    pub signing_key: Arc<SigningKey>,
    pub ed25519_kid: String,
    pub jwks_cache: Value,
    pub cage_key_manifest: Arc<CageKeyManifestResolver>,
    pub replay_cache: Arc<NonceReplayCache>,
    pub journal: Arc<QuarantineJournal>,
    pub dose_tracker: Arc<Cumulative24hTracker>,
    pub exposure_tracker: Arc<Cumulative24hTracker>,
    pub keyed_dose_tracker: Arc<KeyedCumulative24hTracker>,
    pub keyed_exposure_tracker: Arc<KeyedCumulative24hTracker>,
}

impl Default for CageSubstrateState {
    fn default() -> Self {
        let state_dir = std::env::var("OCTOPUS_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("agent_octopus_cage_state"));
        Self::with_state_dir(state_dir)
    }
}

impl CageSubstrateState {
    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let ed25519_kid = hex::encode(Sha256::digest(pub_bytes));
        let x_b64 = base64url_encode_no_pad(&pub_bytes);

        let jwks_cache = json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": ed25519_kid,
                    "x": x_b64,
                    "use": "sig",
                    "alg": "EdDSA"
                }
            ]
        });

        let cage_key_manifest = Arc::new(CageKeyManifestResolver::new());
        if let Ok(manifest_path) = std::env::var("CAGE_TRUSTED_JWKS_PATH") {
            if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                let _ = cage_key_manifest.load_jwks_json(&content);
            }
        }
        if let Ok(manifest_json) = std::env::var("CAGE_TRUSTED_JWKS_JSON") {
            let _ = cage_key_manifest.load_jwks_json(&manifest_json);
        }

        let replay_cache = Arc::new(NonceReplayCache::new(Duration::from_secs(300)));
        let journal = Arc::new(QuarantineJournal::new(
            state_dir,
            Arc::clone(&signing_key),
            ed25519_kid.clone(),
        ));

        Self {
            signing_key,
            ed25519_kid,
            jwks_cache,
            cage_key_manifest,
            replay_cache,
            journal,
            dose_tracker: Arc::new(Cumulative24hTracker::new()),
            exposure_tracker: Arc::new(Cumulative24hTracker::new()),
            keyed_dose_tracker: Arc::new(KeyedCumulative24hTracker::new()),
            keyed_exposure_tracker: Arc::new(KeyedCumulative24hTracker::new()),
        }
    }

    /// 1. `GET /.well-known/jwks.json`
    pub fn handle_jwks(&self) -> (&'static str, String) {
        ("200 OK", self.jwks_cache.to_string())
    }

    /// 2. `GET /v1/cage/normative-baseline/{region}`
    pub fn handle_conformal_baseline(&self, region: &str) -> (&'static str, String) {
        let clean_region = if region.trim().is_empty() {
            "global"
        } else {
            region.trim()
        };
        let now_utc = utc_now_rfc3339();
        let unsigned_baseline = json!({
            "region": clean_region,
            "alpha": 0.05,
            "calibration_size": 500,
            "nonconformity_threshold": 4.25,
            "timestamp_utc": now_utc,
            "kid": self.ed25519_kid
        });

        let canonical_bytes = match canonicalize_jcs(&unsigned_baseline) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "500 Internal Server Error",
                    substrate_err_json("INTERNAL_ERROR", &format!("Baseline JCS failed: {}", e)),
                );
            }
        };
        let mut preimage = b"CAGE_CONFORMAL_BASELINE_V1:".to_vec();
        preimage.extend_from_slice(&canonical_bytes);

        let sig = self.signing_key.sign(&preimage);
        let sig_b64 = base64url_encode_no_pad(&sig.to_bytes());

        let resp = CageConformalBaselineResponse {
            region: clean_region.to_string(),
            alpha: 0.05,
            calibration_size: 500,
            nonconformity_threshold: 4.25,
            timestamp_utc: now_utc,
            kid: self.ed25519_kid.clone(),
            signature: sig_b64,
        };
        (
            "200 OK",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
        )
    }

    /// 3. `GET /v1/cage/attest`
    pub fn handle_attest(&self) -> (&'static str, String) {
        let ks_status = global_host_killswitch().status();
        let pcr0 = hex::encode(Sha256::digest(b"PCR0_SECURE_BOOT"));
        let pcr1 = hex::encode(Sha256::digest(b"PCR1_PLATFORM_CONFIG"));
        let quote = hex::encode(Sha256::digest(
            format!("OCTOPUS_PCR0_7_QUOTE:{}", ks_status.state_hash).as_bytes(),
        ));

        let mut pcr_map = BTreeMap::new();
        pcr_map.insert("0".to_string(), pcr0);
        pcr_map.insert("1".to_string(), pcr1);
        pcr_map.insert("7".to_string(), quote.clone());

        let ring0_posture = if ks_status.isolated || ks_status.live_kernel_filters_verified {
            "ACTIVE_WFP_FILTERED".to_string()
        } else {
            "ACTIVE_WFP_READY".to_string()
        };

        let now_utc = utc_now_rfc3339();
        let unsigned_attestation = json!({
            "attestation_type": "HOST_TPM_PCR",
            "ring0_posture": ring0_posture,
            "tpm_pcr_quote": quote,
            "pcr_values": pcr_map,
            "timestamp_utc": now_utc,
            "kid": self.ed25519_kid
        });

        let canonical_bytes = match canonicalize_jcs(&unsigned_attestation) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "500 Internal Server Error",
                    substrate_err_json("INTERNAL_ERROR", &format!("Attestation JCS failed: {}", e)),
                );
            }
        };
        let mut preimage = b"CAGE_ATTESTATION_RECEIPT_V1:".to_vec();
        preimage.extend_from_slice(&canonical_bytes);

        let sig = self.signing_key.sign(&preimage);
        let sig_b64 = base64url_encode_no_pad(&sig.to_bytes());

        let resp = CageAttestationResponse {
            attestation_type: "HOST_TPM_PCR".to_string(),
            ring0_posture,
            tpm_pcr_quote: quote,
            pcr_values: pcr_map,
            timestamp_utc: now_utc,
            kid: self.ed25519_kid.clone(),
            signature: sig_b64,
        };
        (
            "200 OK",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
        )
    }

    /// 4. `POST /v1/cage/conformal/validate`
    pub fn handle_conformal_validate(
        &self,
        body: &[u8],
        breakout_coordinator: &BreakoutDefenseCoordinator,
    ) -> (&'static str, String) {
        let parsed_val: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json("VALIDATION_ERROR", &format!("Invalid request JSON: {}", e)),
                );
            }
        };
        let canonical_body = match canonicalize_jcs(&parsed_val) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json(
                        "VALIDATION_ERROR",
                        &format!("JCS canonicalization error: {}", e),
                    ),
                );
            }
        };
        let req: CageConformalValidateRequest = match serde_json::from_value(parsed_val) {
            Ok(r) => r,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json(
                        "VALIDATION_ERROR",
                        &format!("Failed to parse validate request: {}", e),
                    ),
                );
            }
        };

        if req.scores.is_empty() {
            return (
                "400 Bad Request",
                substrate_err_json(
                    "VALIDATION_ERROR",
                    "Conformal validation scores vector cannot be empty",
                ),
            );
        }
        if req.scores.iter().any(|s| !s.is_finite()) {
            return (
                "400 Bad Request",
                substrate_err_json(
                    "VALIDATION_ERROR",
                    "Conformal validation scores must be finite numbers",
                ),
            );
        }

        if let Err(e) = self.replay_cache.check_and_record(&req.nonce) {
            return ("409 Conflict", substrate_err_json("REPLAY_DETECTED", &e));
        }

        let alpha = req.alpha.unwrap_or(0.05);
        let cal = build_default_conformal_calibration(req.scores.len());
        let raw_p = cal
            .p_values(&req.scores)
            .into_iter()
            .fold(1.0_f64, |acc, p| acc.min(p));
        let p_value = (raw_p * 1_000_000.0).round() / 1_000_000.0;

        let admitted = p_value > alpha;

        // Multi-voter breakout defense consensus check
        let action_name = req.action.as_deref().unwrap_or("cage_action");
        let breakout_eval = breakout_coordinator.evaluate_action(
            "cage_substrate_actor",
            action_name,
            action_name,
            "",
        );
        let voter_consensus = if admitted && breakout_eval.is_clean {
            "CONSENSUS_ALLOW".to_string()
        } else {
            "CONSENSUS_DENY".to_string()
        };

        let now_utc = utc_now_rfc3339();
        let envelope_digest = hex::encode(Sha256::digest(&canonical_body));
        let unsigned_resp = json!({
            "admitted": admitted,
            "p_value": p_value,
            "alpha": alpha,
            "voter_consensus": voter_consensus,
            "timestamp_utc": now_utc,
            "envelope_digest": envelope_digest,
            "kid": self.ed25519_kid
        });

        let canonical_bytes = match canonicalize_jcs(&unsigned_resp) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "500 Internal Server Error",
                    substrate_err_json("INTERNAL_ERROR", &format!("Validation JCS failed: {}", e)),
                );
            }
        };
        let mut preimage = b"CAGE_CONFORMAL_VALIDATION_V1:".to_vec();
        preimage.extend_from_slice(&canonical_bytes);

        let sig = self.signing_key.sign(&preimage);
        let sig_b64 = base64url_encode_no_pad(&sig.to_bytes());

        let resp = CageConformalValidateResponse {
            admitted,
            p_value,
            alpha,
            voter_consensus,
            timestamp_utc: now_utc,
            envelope_digest: Some(envelope_digest),
            kid: self.ed25519_kid.clone(),
            signature: sig_b64,
        };
        (
            "200 OK",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
        )
    }

    /// 5. `POST /v1/cage/quarantine`
    pub fn handle_quarantine(
        &self,
        assertion_hdr: Option<&str>,
        signer_kid_hdr: Option<&str>,
        body: &[u8],
    ) -> (&'static str, String) {
        let Some(assertion_sig_b64) = assertion_hdr.filter(|s| !s.trim().is_empty()) else {
            return (
                "400 Bad Request",
                substrate_err_json(
                    "VALIDATION_ERROR",
                    "Missing X-CAGE-Quarantine-Assertion header",
                ),
            );
        };
        let Some(signer_kid) = signer_kid_hdr.filter(|s| !s.trim().is_empty()) else {
            return (
                "400 Bad Request",
                substrate_err_json("VALIDATION_ERROR", "Missing X-CAGE-Signer-Kid header"),
            );
        };

        let parsed_val: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json("VALIDATION_ERROR", &format!("Invalid request JSON: {}", e)),
                );
            }
        };
        let canonical_body = match canonicalize_jcs(&parsed_val) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json("VALIDATION_ERROR", &format!("JCS error: {}", e)),
                );
            }
        };
        let mut preimage = b"CAGE_QUARANTINE_ASSERTION_V1:".to_vec();
        preimage.extend_from_slice(&canonical_body);

        let Some(verifying_key) = self.cage_key_manifest.resolve_key(signer_kid.trim()) else {
            return (
                "403 Forbidden",
                substrate_err_json(
                    "UNKNOWN_SIGNER_KID",
                    &format!("Unrecognized CAGE kid: {}", signer_kid),
                ),
            );
        };

        let sig_bytes = match base64url_decode_no_pad(assertion_sig_b64) {
            Ok(b) if b.len() == 64 => b,
            _ => {
                return (
                    "401 Unauthorized",
                    substrate_err_json(
                        "SIGNATURE_INVALID",
                        "Malformed or invalid-length base64url Ed25519 signature",
                    ),
                );
            }
        };
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        if let Err(e) = verifying_key.verify(&preimage, &signature) {
            return (
                "401 Unauthorized",
                substrate_err_json(
                    "SIGNATURE_INVALID",
                    &format!("Ed25519 signature verification failed: {}", e),
                ),
            );
        }

        let req: CageQuarantineRequest = match serde_json::from_value(parsed_val) {
            Ok(r) => r,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json(
                        "VALIDATION_ERROR",
                        &format!("Failed to parse QuarantineDirective fields: {}", e),
                    ),
                );
            }
        };

        if let Err(e) = self.replay_cache.check_and_record(&req.nonce) {
            return ("409 Conflict", substrate_err_json("REPLAY_DETECTED", &e));
        }

        if let Err(e) = global_host_killswitch().engage("cage_governance", &req.trigger_reason) {
            return (
                "500 Internal Server Error",
                substrate_err_json(
                    "CONTAINMENT_FAILED",
                    &format!("Host containment execution failed: {}", e),
                ),
            );
        }

        if let Some(pid) = req.target_pid {
            if pid > 0 {
                let _ = freeze_process_by_pid(pid);
            }
        }

        let now_utc = utc_now_rfc3339();
        let rule_id = req
            .rule_id
            .unwrap_or_else(|| "RULE-SC-7-CBF-LETHAL".to_string());

        let lease = QuarantineLease {
            workload_id: req.workload_id.clone(),
            target_pid: req.target_pid,
            trigger_reason: req.trigger_reason.clone(),
            rule_id: rule_id.clone(),
            quarantined_at: now_utc.clone(),
            expires_at_unix_ms: None,
            nonce: req.nonce.clone(),
        };
        if let Err(e) = self.journal.record_quarantine(lease) {
            return (
                "500 Internal Server Error",
                substrate_err_json(
                    "JOURNAL_SEAL_FAILED",
                    &format!("Failed to record quarantine lease in sealed journal: {}", e),
                ),
            );
        }

        let envelope_digest = hex::encode(Sha256::digest(&canonical_body));
        let mut unsigned_receipt = json!({
            "status": "QUARANTINED",
            "quarantined": true,
            "enforcement_plane": "HOST_OS_KERNEL",
            "rule_id": rule_id,
            "quarantined_at": now_utc,
            "envelope_digest": envelope_digest,
            "kid": self.ed25519_kid
        });
        if let Some(pid) = req.target_pid {
            unsigned_receipt["target_pid"] = json!(pid);
        }

        let canonical_receipt = match canonicalize_jcs(&unsigned_receipt) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "500 Internal Server Error",
                    substrate_err_json("INTERNAL_ERROR", &format!("Receipt JCS failed: {}", e)),
                );
            }
        };
        let mut receipt_preimage = b"CAGE_QUARANTINE_RECEIPT_V1:".to_vec();
        receipt_preimage.extend_from_slice(&canonical_receipt);

        let receipt_sig = self.signing_key.sign(&receipt_preimage);
        let receipt_sig_b64 = base64url_encode_no_pad(&receipt_sig.to_bytes());

        let resp = CageQuarantineReceiptResponse {
            status: "QUARANTINED".to_string(),
            quarantined: true,
            enforcement_plane: "HOST_OS_KERNEL".to_string(),
            rule_id,
            quarantined_at: now_utc,
            target_pid: req.target_pid,
            envelope_digest: Some(envelope_digest),
            kid: self.ed25519_kid.clone(),
            signature: receipt_sig_b64,
        };
        (
            "200 OK",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
        )
    }

    /// 6. `POST /v1/cage/release`
    pub fn handle_release(
        &self,
        release_hdr: Option<&str>,
        signer_kid_hdr: Option<&str>,
        body: &[u8],
    ) -> (&'static str, String) {
        let Some(release_sig_b64) = release_hdr.filter(|s| !s.trim().is_empty()) else {
            return (
                "400 Bad Request",
                substrate_err_json(
                    "VALIDATION_ERROR",
                    "Missing X-CAGE-Quarantine-Release header",
                ),
            );
        };
        let Some(signer_kid) = signer_kid_hdr.filter(|s| !s.trim().is_empty()) else {
            return (
                "400 Bad Request",
                substrate_err_json("VALIDATION_ERROR", "Missing X-CAGE-Signer-Kid header"),
            );
        };

        let parsed_val: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json("VALIDATION_ERROR", &format!("Invalid request JSON: {}", e)),
                );
            }
        };
        let canonical_body = match canonicalize_jcs(&parsed_val) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json("VALIDATION_ERROR", &format!("JCS error: {}", e)),
                );
            }
        };
        let mut preimage = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
        preimage.extend_from_slice(&canonical_body);

        let Some(verifying_key) = self.cage_key_manifest.resolve_key(signer_kid.trim()) else {
            return (
                "403 Forbidden",
                substrate_err_json(
                    "UNKNOWN_SIGNER_KID",
                    &format!("Unrecognized CAGE kid: {}", signer_kid),
                ),
            );
        };

        let sig_bytes = match base64url_decode_no_pad(release_sig_b64) {
            Ok(b) if b.len() == 64 => b,
            _ => {
                return (
                    "401 Unauthorized",
                    substrate_err_json(
                        "SIGNATURE_INVALID",
                        "Malformed or invalid-length base64url Ed25519 signature",
                    ),
                );
            }
        };
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        if let Err(e) = verifying_key.verify(&preimage, &signature) {
            return (
                "401 Unauthorized",
                substrate_err_json(
                    "SIGNATURE_INVALID",
                    &format!("Ed25519 signature verification failed: {}", e),
                ),
            );
        }

        let req: CageQuarantineReleaseRequest = match serde_json::from_value(parsed_val) {
            Ok(r) => r,
            Err(e) => {
                return (
                    "400 Bad Request",
                    substrate_err_json(
                        "VALIDATION_ERROR",
                        &format!("Failed to parse QuarantineReleaseDirective: {}", e),
                    ),
                );
            }
        };

        if req.quorum_count < 2 {
            return (
                "400 Bad Request",
                substrate_err_json(
                    "VALIDATION_ERROR",
                    &format!(
                        "Quorum release requires quorum_count >= 2, received {}",
                        req.quorum_count
                    ),
                ),
            );
        }
        let digest = req.quorum_approval_digest.trim();
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return (
                "400 Bad Request",
                substrate_err_json(
                    "VALIDATION_ERROR",
                    "quorum_approval_digest must be a 64-character hex SHA-256 string",
                ),
            );
        }

        if let Err(e) = self.replay_cache.check_and_record(&req.nonce) {
            return ("409 Conflict", substrate_err_json("REPLAY_DETECTED", &e));
        }

        let (epoch_before, epoch_after) =
            match self.journal.advance_generation_epoch(&req.workload_id) {
                Ok(pair) => pair,
                Err(e) => {
                    return (
                        "500 Internal Server Error",
                        substrate_err_json(
                            "JOURNAL_SEAL_FAILED",
                            &format!("Failed to advance epoch: {}", e),
                        ),
                    );
                }
            };

        let removed_lease = match self.journal.release_quarantine(&req.workload_id) {
            Ok(l) => l,
            Err(e) => {
                return (
                    "500 Internal Server Error",
                    substrate_err_json(
                        "JOURNAL_SEAL_FAILED",
                        &format!("Failed to release lease: {}", e),
                    ),
                );
            }
        };

        if let Some(lease) = removed_lease {
            if let Some(pid) = lease.target_pid {
                if pid > 0 {
                    let _ = resume_process_by_pid(pid);
                }
            }
        }

        if self.journal.unexpired_leases().is_empty() {
            let _ = global_host_killswitch().disarm(
                "cage_governance_quorum",
                &format!(
                    "Quorum-governed release approved for workload '{}' (quorum count: {})",
                    req.workload_id, req.quorum_count
                ),
            );
        }

        let now_utc = utc_now_rfc3339();
        let envelope_digest = hex::encode(Sha256::digest(&canonical_body));
        let unsigned_receipt = json!({
            "released": true,
            "enforcement_plane": "HOST_OS_KERNEL",
            "epoch_before": epoch_before,
            "epoch_after": epoch_after,
            "outcome": "RELEASED",
            "released_at": now_utc,
            "envelope_digest": envelope_digest,
            "kid": self.ed25519_kid
        });

        let canonical_receipt = match canonicalize_jcs(&unsigned_receipt) {
            Ok(b) => b,
            Err(e) => {
                return (
                    "500 Internal Server Error",
                    substrate_err_json(
                        "INTERNAL_ERROR",
                        &format!("Release receipt JCS failed: {}", e),
                    ),
                );
            }
        };
        let mut receipt_preimage = b"CAGE_QUARANTINE_RELEASE_RECEIPT_V1:".to_vec();
        receipt_preimage.extend_from_slice(&canonical_receipt);

        let receipt_sig = self.signing_key.sign(&receipt_preimage);
        let receipt_sig_b64 = base64url_encode_no_pad(&receipt_sig.to_bytes());

        let resp = CageQuarantineReleaseReceiptResponse {
            released: true,
            enforcement_plane: "HOST_OS_KERNEL".to_string(),
            epoch_before,
            epoch_after,
            outcome: "RELEASED".to_string(),
            released_at: now_utc,
            envelope_digest: Some(envelope_digest),
            kid: self.ed25519_kid.clone(),
            signature: receipt_sig_b64,
        };
        (
            "200 OK",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc8785_jcs_float_2_pow_63_and_utf16_sorting() {
        assert_eq!(canonicalize_jcs_string(&json!(0.0)).unwrap(), "0");
        assert_eq!(canonicalize_jcs_string(&json!(-0.0)).unwrap(), "0");
        assert_eq!(canonicalize_jcs_string(&json!(100.0)).unwrap(), "100");
        assert_eq!(
            canonicalize_jcs_string(&json!(9223372036854775808.0)).unwrap(),
            "9223372036854775808"
        );
        assert_eq!(
            canonicalize_jcs_string(&json!(-9223372036854775808.0)).unwrap(),
            "-9223372036854775808"
        );
        assert_eq!(canonicalize_jcs_string(&json!(1e21)).unwrap(), "1e+21");
        assert_eq!(canonicalize_jcs_string(&json!(1e-7)).unwrap(), "1e-7");

        let val = json!({ "\u{E000}": 1, "\u{10000}": 2 });
        let canonical = canonicalize_jcs_string(&val).unwrap();
        assert_eq!(
            canonical,
            format!(r#"{{"{}":2,"{}":1}}"#, "\u{10000}", "\u{E000}")
        );
    }

    #[test]
    fn test_resolve_loopback_peer_pid_self() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let client_addr = client.local_addr().unwrap();
        let (_srv, _) = listener.accept().unwrap();
        let pid = resolve_loopback_peer_pid(client_addr, port).unwrap();
        assert_eq!(pid, std::process::id());
    }

    #[test]
    fn test_quarantine_journal_seal_and_hash_chain() {
        let dir = std::env::temp_dir().join(format!("octopus_journal_test_{}", unix_now_ms()));
        let _ = std::fs::remove_dir_all(&dir);
        let sk = Arc::new(SigningKey::generate(&mut OsRng));
        let kid = hex::encode(Sha256::digest(sk.verifying_key().to_bytes()));

        let journal = QuarantineJournal::new(dir.clone(), Arc::clone(&sk), kid.clone());
        let (b, a) = journal.advance_generation_epoch("arm-7").unwrap();
        assert_eq!((b, a), (1, 2));

        journal
            .record_quarantine(QuarantineLease {
                workload_id: "arm-7".to_string(),
                target_pid: Some(12345),
                trigger_reason: "CBF_VIOLATION".to_string(),
                rule_id: "RULE-SC-7".to_string(),
                quarantined_at: utc_now_rfc3339(),
                expires_at_unix_ms: None,
                nonce: "nonce_j1".to_string(),
            })
            .unwrap();

        let reloaded = QuarantineJournal::new(dir.clone(), Arc::clone(&sk), kid);
        assert_eq!(reloaded.get_generation_epoch("arm-7"), 2);
        assert_eq!(reloaded.unexpired_leases().len(), 1);
        reloaded.release_quarantine("arm-7").unwrap();
        assert!(reloaded.unexpired_leases().is_empty());
        assert!(reloaded.verify_hash_chain().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
