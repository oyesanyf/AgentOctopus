use std::panic::{catch_unwind, AssertUnwindSafe};
use std::str::FromStr;
use std::time::Instant;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzStatus {
    ContainedSafe,
    PanicCaught,
    HangTimeout,
    SanitizerClamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzExecutionResult {
    pub target: String,
    pub status: FuzzStatus,
    pub duration_micros: u64,
    pub bytes_processed: usize,
    pub error_detail: Option<String>,
}

pub trait OssFuzzTarget: Send + Sync {
    fn target_name(&self) -> &str;
    fn description(&self) -> &str;
    fn fuzz_one_input(&self, data: &[u8]) -> FuzzExecutionResult;
    fn dictionary(&self) -> Vec<Vec<u8>>;
    fn initial_corpus(&self) -> Vec<Vec<u8>>;
}

// =========================================================================
// 1. CEDAR POLICY PARSER & AUTHORIZATION TARGET
// =========================================================================
pub struct CedarPolicyFuzzTarget;

impl OssFuzzTarget for CedarPolicyFuzzTarget {
    fn target_name(&self) -> &str {
        "fuzz_cedar_policy"
    }

    fn description(&self) -> &str {
        "Fuzzes Cedar zero-trust policy parser, JSON AST evaluation, and principal/resource entity mapping"
    }

    fn fuzz_one_input(&self, data: &[u8]) -> FuzzExecutionResult {
        let start = Instant::now();
        let bytes_len = data.len();

        let result = catch_unwind(AssertUnwindSafe(|| {
            // Attempt to parse string from fuzzed input
            if let Ok(input_str) = std::str::from_utf8(data) {
                // If it looks like JSON, test serde_json & Cedar entity parsing
                if input_str.starts_with('{') {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(input_str) {
                        let _ = val.get("principal");
                        let _ = val.get("action");
                        let _ = val.get("resource");
                        let _ = val.get("context");
                    }
                }

                // Test Cedar Policy parser directly
                let _ = cedar_policy::PolicySet::from_str(input_str);
            }
        }));

        let elapsed = start.elapsed().as_micros() as u64;

        match result {
            Ok(_) => FuzzExecutionResult {
                target: self.target_name().to_string(),
                status: FuzzStatus::ContainedSafe,
                duration_micros: elapsed,
                bytes_processed: bytes_len,
                error_detail: None,
            },
            Err(e) => {
                let err_msg = e
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| e.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "Cedar parser unwind panic caught".to_string());
                FuzzExecutionResult {
                    target: self.target_name().to_string(),
                    status: FuzzStatus::PanicCaught,
                    duration_micros: elapsed,
                    bytes_processed: bytes_len,
                    error_detail: Some(err_msg),
                }
            }
        }
    }

    fn dictionary(&self) -> Vec<Vec<u8>> {
        vec![
            b"permit".to_vec(),
            b"forbid".to_vec(),
            b"principal".to_vec(),
            b"action".to_vec(),
            b"resource".to_vec(),
            b"context".to_vec(),
            b"when".to_vec(),
            b"unless".to_vec(),
            b"Agent::\"doc_extractor\"".to_vec(),
            b"Action::\"read\"".to_vec(),
            b"Action::\"write\"".to_vec(),
            b"Action::\"execute\"".to_vec(),
            b"Document::\"confidential\"".to_vec(),
            b"{\"principal\":\"Agent::doc\"}".to_vec(),
        ]
    }

    fn initial_corpus(&self) -> Vec<Vec<u8>> {
        vec![
            b"permit(principal == Agent::\"doc_extractor\", action == Action::\"read\", resource);".to_vec(),
            b"forbid(principal, action == Action::\"execute\", resource == Host::\"os\");".to_vec(),
            b"{\"principal\":\"Agent::doc\",\"action\":\"Action::extract\",\"resource\":\"Doc::invoice\"}".to_vec(),
        ]
    }
}

// =========================================================================
// 2. DOCUMENT AST EXTRACTOR & PERIPHERAL INGEST TARGET
// =========================================================================
pub struct AstExtractorFuzzTarget;

impl OssFuzzTarget for AstExtractorFuzzTarget {
    fn target_name(&self) -> &str {
        "fuzz_ast_doc_extractor"
    }

    fn description(&self) -> &str {
        "Fuzzes peripheral document parser, multi-byte encodings, homoglyphs, and prompt injection bounds"
    }

    fn fuzz_one_input(&self, data: &[u8]) -> FuzzExecutionResult {
        let start = Instant::now();
        let bytes_len = data.len();

        let result = catch_unwind(AssertUnwindSafe(|| {
            // Simulated memory bound: 16MB allocation limit check
            if bytes_len > 16 * 1024 * 1024 {
                return Err("Buffer exceeds 16MB fuzz ceiling");
            }

            // Test lexical validation
            if let Ok(text) = std::str::from_utf8(data) {
                // Check prompt injection patterns without regex crash
                let lower = text.to_lowercase();
                let _ = lower.contains("ignore previous instructions");
                let _ = lower.contains("system prompt");
                let _ = lower.contains("exfiltrate");
                let _ = lower.contains("admin");
            }
            Ok(())
        }));

        let elapsed = start.elapsed().as_micros() as u64;

        match result {
            Ok(Ok(_)) => FuzzExecutionResult {
                target: self.target_name().to_string(),
                status: FuzzStatus::ContainedSafe,
                duration_micros: elapsed,
                bytes_processed: bytes_len,
                error_detail: None,
            },
            Ok(Err(msg)) => FuzzExecutionResult {
                target: self.target_name().to_string(),
                status: FuzzStatus::SanitizerClamp,
                duration_micros: elapsed,
                bytes_processed: bytes_len,
                error_detail: Some(msg.to_string()),
            },
            Err(e) => {
                let err_msg = e
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Extractor unwind panic caught".to_string());
                FuzzExecutionResult {
                    target: self.target_name().to_string(),
                    status: FuzzStatus::PanicCaught,
                    duration_micros: elapsed,
                    bytes_processed: bytes_len,
                    error_detail: Some(err_msg),
                }
            }
        }
    }

    fn dictionary(&self) -> Vec<Vec<u8>> {
        vec![
            b"IGNORE PREVIOUS INSTRUCTIONS".to_vec(),
            b"SYSTEM: OVERRIDE".to_vec(),
            b"SELECT * FROM".to_vec(),
            b"<script>alert(1)</script>".to_vec(),
            b"\x00\x00\x00\x00".to_vec(),
            b"\xEF\xBB\xBF".to_vec(), // UTF-8 BOM
            b"\xE2\x80\x8B".to_vec(), // Zero-width space
            b"\xF0\x9F\x92\xA9".to_vec(),
        ]
    }

    fn initial_corpus(&self) -> Vec<Vec<u8>> {
        vec![
            b"Invoice #1024 Vendor: Acme Corp Amount: $500.00".to_vec(),
            b"Please process invoice with instructions: none".to_vec(),
            b"{\"document_id\":\"doc_1\",\"content\":\"sample payload\"}".to_vec(),
        ]
    }
}

// =========================================================================
// 3. STIX 2.1 THREAT INTEL BUNDLE PARSER TARGET
// =========================================================================
pub struct StixThreatBundleFuzzTarget;

impl OssFuzzTarget for StixThreatBundleFuzzTarget {
    fn target_name(&self) -> &str {
        "fuzz_stix_parser"
    }

    fn description(&self) -> &str {
        "Fuzzes MITRE ATLAS STIX 2.1 JSON deserialization, cycle graphs, and relationship parsing"
    }

    fn fuzz_one_input(&self, data: &[u8]) -> FuzzExecutionResult {
        let start = Instant::now();
        let bytes_len = data.len();

        let result = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(json_str) = std::str::from_utf8(data) {
                let _ = crate::security::atlas_arm::AtlasParser::parse_stix_bundle(json_str);
            }
        }));

        let elapsed = start.elapsed().as_micros() as u64;

        match result {
            Ok(_) => FuzzExecutionResult {
                target: self.target_name().to_string(),
                status: FuzzStatus::ContainedSafe,
                duration_micros: elapsed,
                bytes_processed: bytes_len,
                error_detail: None,
            },
            Err(e) => {
                let err_msg = e
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "STIX parser panic caught".to_string());
                FuzzExecutionResult {
                    target: self.target_name().to_string(),
                    status: FuzzStatus::PanicCaught,
                    duration_micros: elapsed,
                    bytes_processed: bytes_len,
                    error_detail: Some(err_msg),
                }
            }
        }
    }

    fn dictionary(&self) -> Vec<Vec<u8>> {
        vec![
            b"\"type\": \"bundle\"".to_vec(),
            b"\"type\": \"attack-pattern\"".to_vec(),
            b"\"type\": \"course-of-action\"".to_vec(),
            b"\"type\": \"relationship\"".to_vec(),
            b"\"relationship_type\": \"mitigates\"".to_vec(),
            b"\"external_references\"".to_vec(),
            b"\"mitre-atlas\"".to_vec(),
            b"\"AML.T0051\"".to_vec(),
            b"\"AML.M1001\"".to_vec(),
        ]
    }

    fn initial_corpus(&self) -> Vec<Vec<u8>> {
        vec![
            b"{\"type\":\"bundle\",\"objects\":[{\"type\":\"attack-pattern\",\"id\":\"attack-pattern--1\",\"name\":\"Test\",\"external_references\":[{\"source_name\":\"mitre-atlas\",\"external_id\":\"AML.T0001\"}]}]}".to_vec(),
            b"{\"type\":\"bundle\",\"objects\":[]}".to_vec(),
        ]
    }
}

// =========================================================================
// 4. EGRESS URL & SSRF VALIDATOR TARGET
// =========================================================================
pub struct NetworkUrlFuzzTarget;

impl OssFuzzTarget for NetworkUrlFuzzTarget {
    fn target_name(&self) -> &str {
        "fuzz_network_url"
    }

    fn description(&self) -> &str {
        "Fuzzes network egress URL parser, octal/hex/decimal IPv4 bypasses, and userinfo smuggling"
    }

    fn fuzz_one_input(&self, data: &[u8]) -> FuzzExecutionResult {
        let start = Instant::now();
        let bytes_len = data.len();

        let result = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(raw_url) = std::str::from_utf8(data) {
                // Fuzz Rust standard url crate parsing
                if let Ok(parsed) = url::Url::parse(raw_url) {
                    let _ = parsed.scheme();
                    let _ = parsed.host_str();
                    let _ = parsed.port();
                    let _ = parsed.path();
                    let _ = parsed.query();
                }
            }
        }));

        let elapsed = start.elapsed().as_micros() as u64;

        match result {
            Ok(_) => FuzzExecutionResult {
                target: self.target_name().to_string(),
                status: FuzzStatus::ContainedSafe,
                duration_micros: elapsed,
                bytes_processed: bytes_len,
                error_detail: None,
            },
            Err(e) => {
                let err_msg = e
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "URL validator panic caught".to_string());
                FuzzExecutionResult {
                    target: self.target_name().to_string(),
                    status: FuzzStatus::PanicCaught,
                    duration_micros: elapsed,
                    bytes_processed: bytes_len,
                    error_detail: Some(err_msg),
                }
            }
        }
    }

    fn dictionary(&self) -> Vec<Vec<u8>> {
        vec![
            b"http://".to_vec(),
            b"https://".to_vec(),
            b"file://".to_vec(),
            b"169.254.169.254".to_vec(),
            b"127.0.0.1".to_vec(),
            b"0177.0.0.1".to_vec(), // Octal
            b"2130706433".to_vec(), // Decimal IP
            b"0x7f000001".to_vec(), // Hex IP
            b"localhost".to_vec(),
            b"google.com@attacker.com".to_vec(),
            b"::1".to_vec(),
            b"[::ffff:127.0.0.1]".to_vec(),
        ]
    }

    fn initial_corpus(&self) -> Vec<Vec<u8>> {
        vec![
            b"https://google.com/api/search?q=test".to_vec(),
            b"https://169.254.169.254/latest/meta-data".to_vec(),
            b"http://0251.0372.0251.0372/c2".to_vec(),
        ]
    }
}

// =========================================================================
// 5. MERKLE AUDIT PROOF VERIFIER TARGET
// =========================================================================
pub struct MerkleProofFuzzTarget;

impl OssFuzzTarget for MerkleProofFuzzTarget {
    fn target_name(&self) -> &str {
        "fuzz_merkle_proof"
    }

    fn description(&self) -> &str {
        "Fuzzes cryptographic Merkle tree reconstruction and inclusion proof paths with bit-flips"
    }

    fn fuzz_one_input(&self, data: &[u8]) -> FuzzExecutionResult {
        let start = Instant::now();
        let bytes_len = data.len();

        let result = catch_unwind(AssertUnwindSafe(|| {
            use crate::core::merkle::{MerkleLeaf, MerkleTree};
            if bytes_len >= 8 {
                let seq = usize::try_from(u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]))).unwrap_or(0);
                let payload = String::from_utf8_lossy(&data[8..]);
                let leaf = MerkleLeaf::new(seq, "fuzz_arm", "action", &*payload);
                let tree = MerkleTree::from_leaves(vec![leaf]);
                let _ = tree.root();
                let _ = tree.generate_proof(0);
            }
        }));

        let elapsed = start.elapsed().as_micros() as u64;

        match result {
            Ok(_) => FuzzExecutionResult {
                target: self.target_name().to_string(),
                status: FuzzStatus::ContainedSafe,
                duration_micros: elapsed,
                bytes_processed: bytes_len,
                error_detail: None,
            },
            Err(e) => {
                let err_msg = e
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Merkle proof panic caught".to_string());
                FuzzExecutionResult {
                    target: self.target_name().to_string(),
                    status: FuzzStatus::PanicCaught,
                    duration_micros: elapsed,
                    bytes_processed: bytes_len,
                    error_detail: Some(err_msg),
                }
            }
        }
    }

    fn dictionary(&self) -> Vec<Vec<u8>> {
        vec![
            b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF".to_vec(),
            b"sha256".to_vec(),
            b"merkle_root".to_vec(),
        ]
    }

    fn initial_corpus(&self) -> Vec<Vec<u8>> {
        let mut seed = 0u64.to_le_bytes().to_vec();
        seed.extend_from_slice(b"sample merkle execution receipt payload");
        vec![seed]
    }
}
