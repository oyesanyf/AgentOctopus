//! Fail-closed HTTP/1.1 framing, protocol anomaly detection, and novel attack defense.
//! Neutralizes the complete arsenal of HTTP Terminator vectors (PortSwigger Research, Black Hat/DEF CON 2026):
//! - Shared-Parser Confusion (multipart/byteranges, Content-Range, Location, Set-Cookie in requests)
//! - Dual-matching & integer overflow Content-Length (Citrix NetScaler / SSO desync)
//! - The Dangling-Byte Technique (Autonomous RQP weaponization)
//! - Novel desync triggers (Transfer-Encoding: gzip, Early-Data, Max-Forwards CVE-2026-63078)
//! - Status-line injection (protocol token mutation e.g. COW<)
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    DuplicateContentLength,
    TransferEncodingPresent,
    InvalidContentLength,
    InvalidHeaderSyntax,
    InvalidRequestLine,
    UnexpectedBody,
    UnexpectedTrailingBytes,
    UnsupportedProtocol,
    SuspiciousHeader,
    SharedParserConfusion,
    NovelDesyncTrigger,
    AsteriskUriAnomaly,
}

impl Signal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DuplicateContentLength => "duplicate_content_length",
            Self::TransferEncodingPresent => "transfer_encoding_present",
            Self::InvalidContentLength => "invalid_content_length",
            Self::InvalidHeaderSyntax => "invalid_header_syntax",
            Self::InvalidRequestLine => "invalid_request_line",
            Self::UnexpectedBody => "unexpected_body",
            Self::UnexpectedTrailingBytes => "unexpected_trailing_bytes",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::SuspiciousHeader => "suspicious_header",
            Self::SharedParserConfusion => "shared_parser_confusion",
            Self::NovelDesyncTrigger => "novel_desync_trigger",
            Self::AsteriskUriAnomaly => "asterisk_uri_anomaly",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Reject {
    pub signal: Signal,
    pub details: &'static str,
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.signal.code(), self.details)
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub content_length: usize,
    pub signals: Vec<Signal>,
}

fn fail(signal: Signal, details: &'static str) -> Reject {
    Reject { signal, details }
}

fn token(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

/// Validates raw header bytes without lossy UTF-8 conversion.
/// Rejects ambiguous or unsupported protocol forms and novel desync triggers.
pub fn validate_header(raw: &[u8]) -> Result<Frame, Reject> {
    if raw.len() > 16 * 1024 {
        return Err(fail(Signal::InvalidHeaderSyntax, "headers too large"));
    }

    if raw.contains(&0)
        || raw.iter().any(|b| *b == b'\n')
            && raw
                .windows(2)
                .filter(|x| x[1] == b'\n')
                .any(|x| x[0] != b'\r')
    {
        return Err(fail(
            Signal::InvalidHeaderSyntax,
            "invalid line termination or NUL",
        ));
    }

    let mut lines = raw.split(|b| *b == b'\n');

    let first = lines
        .next()
        .ok_or_else(|| fail(Signal::InvalidRequestLine, "missing request line"))?;

    let first = first
        .strip_suffix(b"\r")
        .ok_or_else(|| fail(Signal::InvalidRequestLine, "request line missing CR"))?;

    let fields: Vec<_> = first.split(|b| *b == b' ').collect();

    // Defense against status-line injection (e.g. GET / COW< HTTP/1.1) and non-canonical requests
    if fields.len() != 3
        || !token(fields[0])
        || fields[1].is_empty()
        || fields[1].iter().any(|b| b.is_ascii_control() || *b >= 127)
    {
        return Err(fail(
            Signal::InvalidRequestLine,
            "noncanonical request line",
        ));
    }

    // Defense against OPTIONS *? early-response gadgets from HTTP Terminator
    if fields[1].starts_with(b"*") {
        return Err(fail(
            Signal::AsteriskUriAnomaly,
            "asterisk request target is forbidden on this service",
        ));
    }

    // Standard paths must begin with /
    if fields[1][0] != b'/' {
        return Err(fail(
            Signal::InvalidRequestLine,
            "request-target must begin with slash",
        ));
    }

    // Defense against protocol token tampering (e.g. GET / COW< or HTTP/1.0 desync)
    if fields[2] != b"HTTP/1.1" {
        return Err(fail(Signal::UnsupportedProtocol, "HTTP/1.1 required"));
    }

    let method = fields[0];

    if method != b"GET" && method != b"HEAD" && method != b"POST" && method != b"OPTIONS" {
        return Err(fail(Signal::InvalidRequestLine, "method not allowed"));
    }

    let mut host_count = 0;
    let mut cl = None;
    let mut header_count = 0usize;
    let mut signals = Vec::new();

    let all_lines: Vec<_> = lines.collect();

    for (i, raw_line) in all_lines.iter().enumerate() {
        let line = if i + 1 == all_lines.len() {
            *raw_line
        } else {
            raw_line
                .strip_suffix(b"\r")
                .ok_or_else(|| fail(Signal::InvalidHeaderSyntax, "header missing CR"))?
        };

        if line.is_empty() {
            return Err(fail(Signal::InvalidHeaderSyntax, "unexpected blank header"));
        }

        if line[0] == b' ' || line[0] == b'\t' {
            return Err(fail(Signal::InvalidHeaderSyntax, "obsolete folded header"));
        }

        let split = line
            .iter()
            .position(|b| *b == b':')
            .ok_or_else(|| fail(Signal::InvalidHeaderSyntax, "header lacks colon"))?;

        let name = &line[..split];

        if !token(name) {
            return Err(fail(Signal::InvalidHeaderSyntax, "invalid header name"));
        }

        let value = &line[split + 1..];

        if value
            .iter()
            .any(|b| *b == b'\r' || *b == 0 || (*b < 32 && *b != b'\t') || *b == 127)
        {
            return Err(fail(Signal::InvalidHeaderSyntax, "invalid header value"));
        }

        header_count += 1;

        if header_count > 100 {
            return Err(fail(Signal::InvalidHeaderSyntax, "too many headers"));
        }

        if name.eq_ignore_ascii_case(b"host") {
            host_count += 1;

            if value.iter().all(|b| b.is_ascii_whitespace()) || value.contains(&b',') {
                return Err(fail(Signal::InvalidHeaderSyntax, "invalid host"));
            }
        }

        // Novel Attack Defense 1: Transfer-Encoding (chunked, gzip, identity, deflate)
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err(fail(
                Signal::TransferEncodingPresent,
                "transfer encoding is unsupported on this endpoint",
            ));
        }

        // Novel Attack Defense 2: Dual Content-Length (including dual matching CL and integer overflow)
        if name.eq_ignore_ascii_case(b"content-length") {
            if cl.is_some() {
                return Err(fail(
                    Signal::DuplicateContentLength,
                    "multiple Content-Length headers",
                ));
            }

            let value = value.strip_prefix(b" ").unwrap_or(value);

            if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(fail(
                    Signal::InvalidContentLength,
                    "content length must be ASCII digits",
                ));
            }

            let length = std::str::from_utf8(value)
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .ok_or_else(|| {
                    fail(
                        Signal::InvalidContentLength,
                        "invalid or overflowing content length",
                    )
                })?;

            cl = Some(length);
        }

        // Novel Attack Defense 3: Shared-Parser Confusion (multipart/byteranges, Content-Range, Location, Set-Cookie in requests)
        if name.eq_ignore_ascii_case(b"content-type") {
            let val_lower = value.to_ascii_lowercase();
            let pattern = b"multipart/byteranges";
            if val_lower.windows(pattern.len()).any(|w| w == pattern) {
                return Err(fail(
                    Signal::SharedParserConfusion,
                    "multipart/byteranges is a response-only content type: request rejected (Shared-Parser Confusion defense)",
                ));
            }
        }

        if name.eq_ignore_ascii_case(b"content-range") {
            return Err(fail(
                Signal::SharedParserConfusion,
                "Content-Range header is forbidden in client requests (Shared-Parser Confusion defense)",
            ));
        }

        if name.eq_ignore_ascii_case(b"location") {
            return Err(fail(
                Signal::SharedParserConfusion,
                "Location header is forbidden in client requests (Shared-Parser Confusion defense)",
            ));
        }

        if name.eq_ignore_ascii_case(b"set-cookie") {
            return Err(fail(
                Signal::SharedParserConfusion,
                "Set-Cookie header is forbidden in client requests (Shared-Parser Confusion defense)",
            ));
        }

        // Novel Attack Defense 4: Early-Data and Max-Forwards Triggers
        if name.eq_ignore_ascii_case(b"early-data") {
            return Err(fail(
                Signal::NovelDesyncTrigger,
                "Early-Data header rejected without TLS pre-shared key (RFC 8446 desync defense)",
            ));
        }

        if name.eq_ignore_ascii_case(b"max-forwards") && method != b"OPTIONS" {
            return Err(fail(
                Signal::NovelDesyncTrigger,
                "Max-Forwards forbidden on non-OPTIONS methods (CVE-2026-63078 defense)",
            ));
        }

        if name.eq_ignore_ascii_case(b"content-location") || name.eq_ignore_ascii_case(b"range") {
            signals.push(Signal::SuspiciousHeader);
        }
    }

    if host_count != 1 {
        return Err(fail(
            Signal::InvalidHeaderSyntax,
            "exactly one Host required",
        ));
    }

    let content_length = cl.unwrap_or(0);

    if method != b"POST" && content_length != 0 {
        return Err(fail(
            Signal::UnexpectedBody,
            "request body not allowed for this method",
        ));
    }

    Ok(Frame {
        content_length,
        signals,
    })
}

pub fn validate_complete_body(buffered_body: usize, expected: usize) -> Result<(), Reject> {
    if buffered_body != expected {
        return Err(fail(
            Signal::UnexpectedTrailingBytes,
            "request has incomplete or trailing body data",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(s: &str) -> Result<Frame, Reject> {
        validate_header(s.as_bytes())
    }

    #[test]
    fn normal_requests() {
        assert_eq!(
            check("GET / HTTP/1.1\r\nHost: localhost")
                .unwrap()
                .content_length,
            0
        );

        assert_eq!(
            check("POST /api/test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3")
                .unwrap()
                .content_length,
            3
        );
    }

    #[test]
    fn reject_ambiguous_framing() {
        let cases = [
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3",
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked",
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: junk",
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 184467440737095516161111",
            "POST / HTTP/1.1\r\nHost: x\r\n Content-Length: 1",
            "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 4",
            "GET / HTTP/1.1\r\nHost: x\r\nHost: y",
            "GET / HTTP/1.0\r\nHost: x",
            "TRACE / HTTP/1.1\r\nHost: x",
            "GET / HTTP/1.1\r\nHost : x",
        ];

        for case in cases {
            assert!(check(case).is_err(), "accepted: {case:?}");
        }
    }

    #[test]
    fn reject_shared_parser_confusion_attacks() {
        // multipart/byteranges in request Content-Type
        let byterange_req = "POST /api/data HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/byteranges; boundary=BOUND\r\nContent-Length: 10";
        let res = check(byterange_req);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().signal, Signal::SharedParserConfusion);

        // Content-Range in client request
        let cr_req = "POST /api/data HTTP/1.1\r\nHost: x\r\nContent-Range: bytes 0-5/100\r\nContent-Length: 5";
        let res_cr = check(cr_req);
        assert!(res_cr.is_err());
        assert_eq!(res_cr.unwrap_err().signal, Signal::SharedParserConfusion);

        // Location in request
        let loc_req = "GET /api/data HTTP/1.1\r\nHost: x\r\nLocation: http://attacker.com/";
        let res_loc = check(loc_req);
        assert!(res_loc.is_err());
        assert_eq!(res_loc.unwrap_err().signal, Signal::SharedParserConfusion);

        // Set-Cookie in request
        let sc_req = "GET /api/data HTTP/1.1\r\nHost: x\r\nSet-Cookie: session=evil";
        let res_sc = check(sc_req);
        assert!(res_sc.is_err());
        assert_eq!(res_sc.unwrap_err().signal, Signal::SharedParserConfusion);
    }

    #[test]
    fn reject_novel_desync_triggers() {
        // Transfer-Encoding: gzip (F5 Big-IP trigger)
        let gzip_te = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\nContent-Length: 5";
        assert_eq!(
            check(gzip_te).unwrap_err().signal,
            Signal::TransferEncodingPresent
        );

        // Early-Data (Azure/Akamai desync)
        let early_data =
            "POST / HTTP/1.1\r\nHost: x\r\nEarly-Data: experimental\r\nContent-Length: 5";
        assert_eq!(
            check(early_data).unwrap_err().signal,
            Signal::NovelDesyncTrigger
        );

        // Max-Forwards on non-OPTIONS (Apache Traffic Server CVE-2026-63078 defense)
        let max_forwards = "POST /foo HTTP/1.1\r\nHost: x\r\nMax-Forwards: 0\r\nContent-Length: 0";
        assert_eq!(
            check(max_forwards).unwrap_err().signal,
            Signal::NovelDesyncTrigger
        );

        // Asterisk request target (OPTIONS *?xyz early-response gadget)
        let asterisk = "OPTIONS *?xyz HTTP/1.1\r\nHost: x";
        assert_eq!(
            check(asterisk).unwrap_err().signal,
            Signal::AsteriskUriAnomaly
        );

        // Status-line injection attempt
        let status_inj = "GET / COW< HTTP/1.1\r\nHost: x";
        assert_eq!(
            check(status_inj).unwrap_err().signal,
            Signal::InvalidRequestLine
        );

        // Dual matching Content-Length (Citrix NetScaler / SSO exploit)
        let dual_matching =
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 28\r\nContent-Length: 28";
        assert_eq!(
            check(dual_matching).unwrap_err().signal,
            Signal::DuplicateContentLength
        );
    }

    #[test]
    fn reject_request_pipelining() {
        assert!(validate_complete_body(40, 0).is_err());
        assert!(validate_complete_body(2, 3).is_err());
        assert!(validate_complete_body(3, 3).is_ok());
    }

    #[test]
    fn detect_unusual_but_nonfatal_headers() {
        let frame = check("GET / HTTP/1.1\r\nHost: x\r\nRange: bytes=1-2").unwrap();

        assert!(frame.signals.contains(&Signal::SuspiciousHeader));
    }
}
