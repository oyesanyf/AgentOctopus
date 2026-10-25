use super::types::{CandidateProbeDto, RfcChunkDto};
use crate::security::console_defense::CommandConsoleExt;
use crate::security::hidden_process_ledger::LedgeredCommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// RfcKnowledgeBase: Encapsulates Agent Octopus's dedicated, isolated Protocol Research database.
/// Strictly decoupled from external engines, storing ingested RFC knowledge, probes, and evaluations.
pub struct RfcKnowledgeBase {
    db_path: PathBuf,
}

impl Default for RfcKnowledgeBase {
    fn default() -> Self {
        Self::new()
    }
}

impl RfcKnowledgeBase {
    /// Creates a `sqlite3` command pre-configured with `CREATE_NO_WINDOW (0x0800_0000)`
    /// (`EDR-VEC-23`) so it never spawns a visible console prompt window on Windows.
    fn sqlite_cmd(&self) -> Command {
        let mut cmd = Command::new("sqlite3");
        cmd.enforce_no_window();
        cmd.arg(&self.db_path);
        cmd
    }

    /// Creates a new RfcKnowledgeBase pointing to Octopus's private data store.
    pub fn new() -> Self {
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let db_path = base_dir.join("data").join("protocol_research.db");
        
        let kb = Self { db_path };
        kb.ensure_initialized();
        kb
    }

    /// Initializes from an explicit file path (e.g. for testing isolated instances).
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        let kb = Self { db_path: path.into() };
        kb.ensure_initialized();
        kb
    }

    /// Path to Octopus's private protocol research database.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Verifies that the database directory and required schema exist.
    pub fn ensure_initialized(&self) {
        if let Some(parent) = self.db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let schema_sql = "
            CREATE TABLE IF NOT EXISTS rfcs (
                rfc_number INTEGER PRIMARY KEY,
                title TEXT,
                published_date TEXT,
                status TEXT
            );
            CREATE TABLE IF NOT EXISTS fragments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rfc_number INTEGER,
                title TEXT,
                chunk_index INTEGER,
                content TEXT,
                is_normative INTEGER
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_fragments_unique ON fragments (rfc_number, chunk_index);
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS probes (
                id TEXT PRIMARY KEY,
                rfc_number INTEGER,
                raw_request TEXT,
                mutation_type TEXT,
                hypothesis TEXT,
                status TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS evaluations (
                id TEXT PRIMARY KEY,
                probe_id TEXT,
                target_host TEXT,
                target_port INTEGER,
                is_anomalous INTEGER,
                finding_status TEXT,
                details TEXT,
                baseline_subtracted INTEGER,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS arm106_validations (
                id TEXT PRIMARY KEY,
                evaluation_id TEXT,
                divergence_tier TEXT,
                parser_consensus TEXT,
                requires_rule_promotion INTEGER,
                verified_at TEXT
            );
        ";

        let _ = self.sqlite_cmd()
            .arg(schema_sql)
            .output_logged("rfc knowledge base: sqlite3");
    }

    /// Returns aggregate telemetry: (rfc_count, fragment_count, probe_count, evaluations_count).
    pub fn read_untrusted_data(&self) -> (usize, usize, usize) {
        let (rfcs, frags, probes, _) = self.get_full_counts();
        (rfcs, frags, probes)
    }

    /// Returns all counts including recorded evaluations.
    pub fn get_full_counts(&self) -> (usize, usize, usize, usize) {
        let query = "SELECT (SELECT COUNT(*) FROM rfcs), (SELECT COUNT(*) FROM fragments), (SELECT COUNT(*) FROM probes), (SELECT COUNT(*) FROM evaluations);";
        let output = self.sqlite_cmd()
            .arg(query)
            .output_logged("rfc knowledge base: sqlite3");

        if let Ok(out) = output {
            let result_str = String::from_utf8_lossy(&out.stdout);
            let parts: Vec<&str> = result_str.trim().split('|').collect();
            if parts.len() >= 4 {
                let rfcs: usize = parts[0].parse().unwrap_or(0);
                let fragments: usize = parts[1].parse().unwrap_or(0);
                let probes: usize = parts[2].parse().unwrap_or(0);
                let evals: usize = parts[3].parse().unwrap_or(0);
                return (rfcs, fragments, probes, evals);
            }
        }
        (0, 0, 0, 0)
    }

    /// Sanitizes an arbitrary string before interpolation into a SQLite single-quoted string literal (`CWE-89` mitigation).
    #[inline]
    fn sanitize_sql_literal(input: &str) -> String {
        input
            .chars()
            .filter(|&c| c != '\0')
            .collect::<String>()
            .replace('\'', "''")
    }

    /// Queries RFC fragments matching a specific protocol token or header.
    pub fn search_fragments(&self, keyword: &str, limit: usize) -> Vec<RfcChunkDto> {
        let sanitized = Self::sanitize_sql_literal(keyword)
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let query = format!(
            "SELECT id, rfc_number, title, chunk_index, content, is_normative FROM fragments WHERE content LIKE '%{}%' ESCAPE '\\' LIMIT {};",
            sanitized, limit
        );

        let mut results = Vec::new();
        let output = self.sqlite_cmd()
            .arg("-separator")
            .arg("<|OCT_SEP|>")
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let fields: Vec<&str> = line.split("<|OCT_SEP|>").collect();
                if fields.len() >= 6 {
                    results.push(RfcChunkDto {
                        id: fields[0].parse().unwrap_or(0),
                        rfc_number: fields[1].parse().unwrap_or(0),
                        title: fields[2].to_string(),
                        chunk_index: fields[3].parse().unwrap_or(0),
                        content: fields[4].to_string(),
                        is_normative: fields[5] == "1",
                    });
                }
            }
        }
        results
    }

    /// Fetches candidate probes from the research knowledge base.
    pub fn get_candidate_probes(&self, limit: usize) -> Vec<CandidateProbeDto> {
        let query = format!(
            "SELECT id, rfc_number, raw_request, mutation_type, hypothesis, status FROM probes LIMIT {};",
            limit
        );

        let mut probes = Vec::new();
        let output = self.sqlite_cmd()
            .arg("-separator")
            .arg("<|OCT_SEP|>")
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let fields: Vec<&str> = line.split("<|OCT_SEP|>").collect();
                if fields.len() >= 6 {
                    probes.push(CandidateProbeDto {
                        id: fields[0].to_string(),
                        rfc_number: fields[1].parse().unwrap_or(0),
                        raw_request: fields[2].to_string(),
                        mutation_type: fields[3].to_string(),
                        hypothesis: fields[4].to_string(),
                        status: fields[5].to_string(),
                    });
                }
            }
        }
        probes
    }

    /// Records an evaluation finding into Octopus's private research store.
    pub fn record_evaluation(
        &self,
        finding_id: &str,
        probe_id: &str,
        target_host: &str,
        target_port: u16,
        is_anomalous: bool,
        finding_status: &str,
        details: &str,
        baseline_subtracted: bool,
    ) {
        let clean_finding_id = Self::sanitize_sql_literal(finding_id);
        let clean_probe_id = Self::sanitize_sql_literal(probe_id);
        let clean_target_host = Self::sanitize_sql_literal(target_host);
        let clean_status = Self::sanitize_sql_literal(finding_status);
        let clean_details = Self::sanitize_sql_literal(details);
        let query = format!(
            "INSERT OR REPLACE INTO evaluations (id, probe_id, target_host, target_port, is_anomalous, finding_status, details, baseline_subtracted, created_at) VALUES ('{}', '{}', '{}', {}, {}, '{}', '{}', {}, datetime('now'));",
            clean_finding_id,
            clean_probe_id,
            clean_target_host,
            target_port,
            if is_anomalous { 1 } else { 0 },
            clean_status,
            clean_details,
            if baseline_subtracted { 1 } else { 0 }
        );

        let _ = self.sqlite_cmd()
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");
    }

    /// Records an Arm 106 differential cross-validation outcome.
    pub fn record_arm106_validation(
        &self,
        validation_id: &str,
        evaluation_id: &str,
        divergence_tier: &str,
        parser_consensus: &str,
        requires_rule_promotion: bool,
    ) {
        let clean_validation_id = Self::sanitize_sql_literal(validation_id);
        let clean_evaluation_id = Self::sanitize_sql_literal(evaluation_id);
        let clean_tier = Self::sanitize_sql_literal(divergence_tier);
        let clean_consensus = Self::sanitize_sql_literal(parser_consensus);
        let query = format!(
            "INSERT OR REPLACE INTO arm106_validations (id, evaluation_id, divergence_tier, parser_consensus, requires_rule_promotion, verified_at) VALUES ('{}', '{}', '{}', '{}', {}, datetime('now'));",
            clean_validation_id,
            clean_evaluation_id,
            clean_tier,
            clean_consensus,
            if requires_rule_promotion { 1 } else { 0 }
        );

        let _ = self.sqlite_cmd()
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");
    }

    /// Inserts or updates an RFC metadata record in the database.
    pub fn insert_or_update_rfc(&self, rfc_number: u32, title: &str, published_date: &str, status: &str) {
        let clean_title = Self::sanitize_sql_literal(title);
        let clean_date = Self::sanitize_sql_literal(published_date);
        let clean_status = Self::sanitize_sql_literal(status);
        let query = format!(
            "INSERT OR REPLACE INTO rfcs (rfc_number, title, published_date, status) VALUES ({}, '{}', '{}', '{}');",
            rfc_number, clean_title, clean_date, clean_status
        );
        let _ = self.sqlite_cmd()
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");
    }

    /// Inserts a chunk/normative fragment for an RFC with deduplication.
    pub fn insert_fragment(&self, rfc_number: u32, title: &str, chunk_index: usize, content: &str, is_normative: bool) {
        let clean_title = Self::sanitize_sql_literal(title);
        let clean_content = Self::sanitize_sql_literal(content);
        let query = format!(
            "INSERT OR REPLACE INTO fragments (rfc_number, title, chunk_index, content, is_normative) VALUES ({}, '{}', {}, '{}', {});",
            rfc_number, clean_title, chunk_index, clean_content, if is_normative { 1 } else { 0 }
        );
        let _ = self.sqlite_cmd()
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");
    }

    /// Retrieves all fragments/chunks belonging to a specific RFC.
    pub fn get_fragments_for_rfc(&self, rfc_number: u32) -> Vec<RfcChunkDto> {
        let query = format!(
            "SELECT id, rfc_number, title, chunk_index, content, is_normative FROM fragments WHERE rfc_number = {} ORDER BY chunk_index ASC;",
            rfc_number
        );
        let mut results = Vec::new();
        let output = self.sqlite_cmd()
            .arg("-separator")
            .arg("<|OCT_SEP|>")
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let fields: Vec<&str> = line.split("<|OCT_SEP|>").collect();
                if fields.len() >= 6 {
                    results.push(RfcChunkDto {
                        id: fields[0].parse().unwrap_or(0),
                        rfc_number: fields[1].parse().unwrap_or(0),
                        title: fields[2].to_string(),
                        chunk_index: fields[3].parse().unwrap_or(0),
                        content: fields[4].to_string(),
                        is_normative: fields[5] == "1",
                    });
                }
            }
        }
        results
    }

    /// Returns the total chunk count for an RFC.
    pub fn get_chunk_count_for_rfc(&self, rfc_number: u32) -> usize {
        let query = format!("SELECT COUNT(*) FROM fragments WHERE rfc_number = {};", rfc_number);
        if let Ok(out) = self.sqlite_cmd().arg(&query).output_logged("rfc knowledge base: sqlite3") {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            text.parse().unwrap_or(0)
        } else {
            0
        }
    }

    /// Inserts a batch of structured chunks for an RFC.
    pub fn insert_fragments_batch(&self, rfc_number: u32, title: &str, chunks: &[(usize, String, bool)]) {
        let mut cmds = Vec::with_capacity(chunks.len());
        let clean_title = Self::sanitize_sql_literal(title);
        for (idx, content, is_norm) in chunks {
            let clean_content = Self::sanitize_sql_literal(content);
            cmds.push(format!(
                "INSERT OR REPLACE INTO fragments (rfc_number, title, chunk_index, content, is_normative) VALUES ({}, '{}', {}, '{}', {});",
                rfc_number, clean_title, idx, clean_content, if *is_norm { 1 } else { 0 }
            ));
        }
        self.execute_batch(&cmds);
    }

    /// Retrieves synchronization metadata by key (e.g. etag, last_sync).
    pub fn get_metadata(&self, key: &str) -> Option<String> {
        let clean_key = Self::sanitize_sql_literal(key);
        let query = format!("SELECT value FROM sync_metadata WHERE key = '{}';", clean_key);
        let output = self.sqlite_cmd()
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3")
            .ok()?;
        let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if val.is_empty() {
            None
        } else {
            Some(val)
        }
    }

    /// Updates or inserts synchronization metadata.
    pub fn set_metadata(&self, key: &str, value: &str) {
        let clean_key = Self::sanitize_sql_literal(key);
        let clean_val = Self::sanitize_sql_literal(value);
        let query = format!(
            "INSERT OR REPLACE INTO sync_metadata (key, value, updated_at) VALUES ('{}', '{}', datetime('now'));",
            clean_key, clean_val
        );
        let _ = self.sqlite_cmd()
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");
    }

    /// Deletes all fragments for a given RFC number for transactional updates.
    pub fn delete_rfc_fragments(&self, rfc_number: u32) {
        let query = format!("DELETE FROM fragments WHERE rfc_number = {};", rfc_number);
        let _ = self.sqlite_cmd()
            .arg(&query)
            .output_logged("rfc knowledge base: sqlite3");
    }

    /// Executes a batch of SQL statements wrapped in a single transaction for high-performance synchronization.
    pub fn execute_batch(&self, sql_commands: &[String]) {
        if sql_commands.is_empty() {
            return;
        }

        use std::io::Write;
        let mut child = match self.sqlite_cmd()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn_logged("rfc knowledge base: sqlite3 (stdin import)")
        {
            Ok(c) => c,
            Err(_) => return,
        };

        if let Some(mut stdin) = child.stdin.take() {
            let _ = writeln!(stdin, "BEGIN TRANSACTION;");
            for cmd in sql_commands {
                let _ = writeln!(stdin, "{}", cmd);
            }
            let _ = writeln!(stdin, "COMMIT;");
        }
        let _ = child.wait();
    }
}
