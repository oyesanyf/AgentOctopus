//! Multi-Model HTTP Parser Behavioral Profiles for Differential Protocol Analysis.
//! Evaluates raw HTTP stream interpretations across distinct protocol profiles to uncover
//! semantic gaps, desync vectors, and 0-day HTTP request smuggling exploits.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Resulting interpretation of a raw HTTP request stream from a single parser profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParsedProfileInterpretation {
    pub profile_name: String,
    pub method: Option<String>,
    pub target_uri: Option<String>,
    pub normalized_path: String,
    pub version: Option<String>,
    pub headers: HashMap<String, String>,
    pub raw_header_count: usize,
    pub content_length: Option<usize>,
    pub is_chunked: bool,
    pub has_ambiguous_framing: bool,
    pub detected_anomalies: Vec<String>,
    pub header_end_offset: usize,
}

impl ParsedProfileInterpretation {
    pub fn empty(name: &str) -> Self {
        Self {
            profile_name: name.to_string(),
            method: None,
            target_uri: None,
            normalized_path: String::new(),
            version: None,
            headers: HashMap::new(),
            raw_header_count: 0,
            content_length: None,
            is_chunked: false,
            has_ambiguous_framing: false,
            detected_anomalies: Vec::new(),
            header_end_offset: 0,
        }
    }
}

/// Profile A: Strict RFC 7230 / HTTP 1.1 Invariant Model
pub struct StrictRfc7230Parser;

impl StrictRfc7230Parser {
    pub fn parse(raw: &[u8]) -> ParsedProfileInterpretation {
        let mut interp = ParsedProfileInterpretation::empty("Strict-RFC-7230");

        let header_pos = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(p) => p,
            None => {
                interp.detected_anomalies.push("MISSING_CRLF_CRLF_BOUNDARY".to_string());
                return interp;
            }
        };
        interp.header_end_offset = header_pos + 4;
        let header_bytes = &raw[..header_pos];

        // Reject NUL or bare LF without CR
        if header_bytes.contains(&0) {
            interp.detected_anomalies.push("NUL_BYTE_IN_HEADERS".to_string());
        }
        for (i, &b) in header_bytes.iter().enumerate() {
            if b == b'\n' && (i == 0 || header_bytes[i - 1] != b'\r') {
                interp.detected_anomalies.push("BARE_LF_DETECTED".to_string());
                break;
            }
        }

        let lines: Vec<&[u8]> = header_bytes.split(|&b| b == b'\n').collect();
        if lines.is_empty() {
            interp.detected_anomalies.push("EMPTY_REQUEST_HEADER".to_string());
            return interp;
        }

        // Request line
        let req_line = lines[0].strip_suffix(b"\r").unwrap_or(lines[0]);
        let parts: Vec<&[u8]> = req_line.split(|&b| b == b' ').collect();
        if parts.len() == 3 {
            interp.method = String::from_utf8(parts[0].to_vec()).ok();
            let uri_str = String::from_utf8_lossy(parts[1]).to_string();
            interp.normalized_path = normalize_path_strict(&uri_str);
            interp.target_uri = Some(uri_str);
            interp.version = String::from_utf8(parts[2].to_vec()).ok();
        } else {
            interp.detected_anomalies.push("MALFORMED_REQUEST_LINE".to_string());
        }

        // Headers
        let mut cl_count = 0;
        let mut te_present = false;

        for line_raw in &lines[1..] {
            let line = line_raw.strip_suffix(b"\r").unwrap_or(line_raw);
            if line.is_empty() {
                continue;
            }
            interp.raw_header_count += 1;

            // Strict: no leading whitespace (obs-fold forbidden)
            if line[0] == b' ' || line[0] == b'\t' {
                interp.detected_anomalies.push("OBS_FOLD_DETECTED".to_string());
                continue;
            }

            let colon_idx = match line.iter().position(|&b| b == b':') {
                Some(idx) => idx,
                None => {
                    interp.detected_anomalies.push("HEADER_MISSING_COLON".to_string());
                    continue;
                }
            };

            // Strict: whitespace before colon is illegal
            if colon_idx > 0 && (line[colon_idx - 1] == b' ' || line[colon_idx - 1] == b'\t') {
                interp.detected_anomalies.push("WHITESPACE_BEFORE_COLON".to_string());
            }

            let key = String::from_utf8_lossy(&line[..colon_idx]).to_ascii_lowercase();
            let val = String::from_utf8_lossy(&line[colon_idx + 1..]).trim().to_string();

            if key == "content-length" {
                cl_count += 1;
                if let Ok(cl) = val.parse::<usize>() {
                    interp.content_length = Some(cl);
                } else {
                    interp.detected_anomalies.push("NON_DIGIT_CONTENT_LENGTH".to_string());
                }
            }

            if key == "transfer-encoding" {
                te_present = true;
                if val.to_ascii_lowercase().contains("chunked") {
                    interp.is_chunked = true;
                }
            }

            if key == "content-type" && val.to_ascii_lowercase().contains("multipart/byteranges") {
                interp.has_ambiguous_framing = true;
                interp.detected_anomalies.push("SHARED_PARSER_CONFUSION_MULTIPART_BYTERANGES".to_string());
            }
            if key == "content-range" {
                interp.detected_anomalies.push("SHARED_PARSER_CONFUSION_CONTENT_RANGE".to_string());
            }
            if key == "location" {
                interp.detected_anomalies.push("SHARED_PARSER_CONFUSION_LOCATION".to_string());
            }
            if key == "set-cookie" {
                interp.detected_anomalies.push("SHARED_PARSER_CONFUSION_SET_COOKIE".to_string());
            }
            if key == "early-data" {
                interp.detected_anomalies.push("NOVEL_DESYNC_TRIGGER_EARLY_DATA".to_string());
            }

            interp.headers.insert(key, val);
        }

        if cl_count > 1 {
            interp.has_ambiguous_framing = true;
            interp.detected_anomalies.push("DUPLICATE_CONTENT_LENGTH".to_string());
        }
        if te_present && cl_count > 0 {
            interp.has_ambiguous_framing = true;
            interp.detected_anomalies.push("CL_TE_SMUGGLING_CONFLICT".to_string());
        }

        interp
    }
}

/// Profile B: Permissive Legacy Behavioral Model (Apache / IIS / Node.js permissive parsers)
pub struct PermissiveLegacyParser;

impl PermissiveLegacyParser {
    pub fn parse(raw: &[u8]) -> ParsedProfileInterpretation {
        let mut interp = ParsedProfileInterpretation::empty("Permissive-Legacy");

        // Accepts either \r\n\r\n or \n\n
        let (header_bytes, header_len) = if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            (&raw[..p], p + 4)
        } else if let Some(p) = raw.windows(2).position(|w| w == b"\n\n") {
            (&raw[..p], p + 2)
        } else {
            interp.detected_anomalies.push("NO_HEADER_TERMINATOR".to_string());
            return interp;
        };
        interp.header_end_offset = header_len;

        let lines: Vec<&[u8]> = header_bytes.split(|&b| b == b'\n').collect();
        if lines.is_empty() {
            return interp;
        }

        // Request line tolerant splitting
        let req_line = lines[0].strip_suffix(b"\r").unwrap_or(lines[0]);
        let mut parts = req_line.split(|&b| b == b' ' || b == b'\t').filter(|s| !s.is_empty());
        if let Some(m) = parts.next() {
            interp.method = String::from_utf8(m.to_vec()).ok();
        }
        if let Some(u) = parts.next() {
            let uri_str = String::from_utf8_lossy(u).to_string();
            // Permissive: unnormalized or path traversal retained
            interp.normalized_path = uri_str.clone();
            interp.target_uri = Some(uri_str);
        }
        if let Some(v) = parts.next() {
            interp.version = String::from_utf8(v.to_vec()).ok();
        }

        // Permissive headers: strips whitespace before colon and handles obs-fold
        let mut cl_first: Option<usize> = None;
        let mut te_chunked = false;

        for line_raw in &lines[1..] {
            let line = line_raw.strip_suffix(b"\r").unwrap_or(line_raw);
            if line.is_empty() {
                continue;
            }
            interp.raw_header_count += 1;

            if let Some(colon_idx) = line.iter().position(|&b| b == b':') {
                // Strips trailing whitespace from key (tolerating "Content-Length : 10")
                let key_raw = &line[..colon_idx];
                let key = String::from_utf8_lossy(key_raw).trim().to_ascii_lowercase();
                let val = String::from_utf8_lossy(&line[colon_idx + 1..]).trim().to_string();

                if key == "content-length" && cl_first.is_none() {
                    if let Ok(num) = val.parse::<usize>() {
                        cl_first = Some(num);
                    }
                }

                if key == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                    te_chunked = true;
                }

                // Permissive/Legacy flaw: Transfer-Encoding: gzip causes server to ignore Content-Length (F5 Big-IP bug)
                if key == "transfer-encoding" && val.to_ascii_lowercase().contains("gzip") {
                    te_chunked = true;
                }

                // Permissive/Legacy flaw: multipart/byteranges in request causes server to ignore Content-Length (CL.0 desync)
                if key == "content-type" && val.to_ascii_lowercase().contains("multipart/byteranges") {
                    cl_first = Some(0);
                }

                // Permissive: first header wins or preserves last
                interp.headers.entry(key).or_insert(val);
            }
        }

        interp.is_chunked = te_chunked;
        // In legacy parsers, Transfer-Encoding overrides Content-Length
        if te_chunked {
            interp.content_length = None;
        } else {
            interp.content_length = cl_first;
        }

        interp
    }
}

/// Profile C: CDN & Reverse Proxy Behavioral Model (Cloudflare / NGINX / AWS ALB)
pub struct CdnProxyParser;

impl CdnProxyParser {
    pub fn parse(raw: &[u8]) -> ParsedProfileInterpretation {
        let mut interp = ParsedProfileInterpretation::empty("CDN-ReverseProxy");

        let header_pos = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(p) => p,
            None => return interp,
        };
        interp.header_end_offset = header_pos + 4;
        let header_bytes = &raw[..header_pos];

        let lines: Vec<&[u8]> = header_bytes.split(|&b| b == b'\n').collect();
        if lines.is_empty() {
            return interp;
        }

        let req_line = lines[0].strip_suffix(b"\r").unwrap_or(lines[0]);
        let parts: Vec<&[u8]> = req_line.split(|&b| b == b' ').collect();
        if parts.len() >= 2 {
            interp.method = String::from_utf8(parts[0].to_vec()).ok();
            let uri_str = String::from_utf8_lossy(parts[1]).to_string();
            // CDN normalizes: collapses duplicate slashes and decodes percent-escapes
            interp.normalized_path = normalize_path_cdn(&uri_str);
            interp.target_uri = Some(uri_str);
            if parts.len() >= 3 {
                interp.version = String::from_utf8(parts[2].to_vec()).ok();
            }
        }

        // CDN Header processing: Last header wins, removes hop-by-hop
        let mut last_cl = None;
        let mut has_te = false;

        for line_raw in &lines[1..] {
            let line = line_raw.strip_suffix(b"\r").unwrap_or(line_raw);
            if let Some(colon_idx) = line.iter().position(|&b| b == b':') {
                let key = String::from_utf8_lossy(&line[..colon_idx]).trim().to_ascii_lowercase();
                let val = String::from_utf8_lossy(&line[colon_idx + 1..]).trim().to_string();

                if key == "content-length" {
                    if let Ok(c) = val.parse::<usize>() {
                        last_cl = Some(c);
                    }
                }
                if key == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                    has_te = true;
                }

                // Last header wins in many CDN internal representations
                interp.headers.insert(key, val);
            }
        }

        interp.is_chunked = has_te;
        interp.content_length = last_cl;
        interp
    }
}

/// Profile D: Asynchronous Microservice Parser (Go net/http, Netty)
pub struct AsyncMicroserviceParser;

impl AsyncMicroserviceParser {
    pub fn parse(raw: &[u8]) -> ParsedProfileInterpretation {
        let mut interp = ParsedProfileInterpretation::empty("Async-Microservice");

        let header_pos = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(p) => p,
            None => return interp,
        };
        interp.header_end_offset = header_pos + 4;
        let header_bytes = &raw[..header_pos];

        let lines: Vec<&[u8]> = header_bytes.split(|&b| b == b'\n').collect();
        if lines.is_empty() {
            return interp;
        }

        let req_line = lines[0].strip_suffix(b"\r").unwrap_or(lines[0]);
        let parts: Vec<&[u8]> = req_line.split(|&b| b == b' ').collect();
        if parts.len() == 3 {
            interp.method = String::from_utf8(parts[0].to_vec()).ok();
            let uri_str = String::from_utf8_lossy(parts[1]).to_string();
            interp.normalized_path = uri_str.split('?').next().unwrap_or(&uri_str).to_string();
            interp.target_uri = Some(uri_str);
            interp.version = String::from_utf8(parts[2].to_vec()).ok();
        }

        for line_raw in &lines[1..] {
            let line = line_raw.strip_suffix(b"\r").unwrap_or(line_raw);
            if let Some(colon_idx) = line.iter().position(|&b| b == b':') {
                let key = String::from_utf8_lossy(&line[..colon_idx]).to_ascii_lowercase();
                let val = String::from_utf8_lossy(&line[colon_idx + 1..]).trim().to_string();

                if key == "content-length" {
                    if let Ok(c) = val.parse::<usize>() {
                        interp.content_length = Some(c);
                    }
                }
                if key == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                    interp.is_chunked = true;
                }

                // Microservices often aggregate multiple headers into comma-delimited strings
                interp.headers.entry(key)
                    .and_modify(|existing| {
                        existing.push_str(", ");
                        existing.push_str(&val);
                    })
                    .or_insert(val);
            }
        }

        interp
    }
}

fn normalize_path_strict(path: &str) -> String {
    let p = path.split('?').next().unwrap_or(path);
    // Strict dot-segment normalization
    let mut segments = Vec::new();
    for seg in p.split('/') {
        if seg == "" || seg == "." {
            continue;
        } else if seg == ".." {
            segments.pop();
        } else {
            segments.push(seg);
        }
    }
    format!("/{}", segments.join("/"))
}

fn normalize_path_cdn(path: &str) -> String {
    let mut normalized = path.split('?').next().unwrap_or(path).to_string();
    // Collapse duplicate slashes
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    // Percent decoding for standard path characters
    normalized = normalized.replace("%2f", "/").replace("%2F", "/");
    normalized
}
