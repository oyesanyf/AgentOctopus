"""
Database persistence layer for HTTP Terminator.
Uses SQLite to store RFCs, micro-fragments, generated probes,
evaluations, anomalies, and discovery cascade hypotheses.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class Database:
    def __init__(self, db_path: str = "terminator.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS rfcs (
                    rfc_id TEXT PRIMARY KEY,
                    title TEXT,
                    source_url TEXT,
                    doc_path TEXT,
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS fragments (
                    fragment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rfc_id TEXT,
                    content TEXT NOT NULL,
                    keywords TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(rfc_id) REFERENCES rfcs(rfc_id)
                );

                CREATE TABLE IF NOT EXISTS probes (
                    probe_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fragment_id INTEGER,
                    rationale TEXT NOT NULL,
                    raw_request TEXT NOT NULL,
                    is_clean BOOLEAN DEFAULT 0,
                    source_type TEXT DEFAULT 'llm', -- 'llm', 'permuted', 'cascade'
                    parent_probe_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(fragment_id) REFERENCES fragments(fragment_id)
                );

                CREATE TABLE IF NOT EXISTS evaluations (
                    finding_status TEXT DEFAULT 'UNVERIFIED',
                    eval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id INTEGER NOT NULL,
                    target_host TEXT NOT NULL,
                    target_port INTEGER NOT NULL,
                    is_vulnerable BOOLEAN NOT NULL,
                    desync_class TEXT,
                    details TEXT,
                    raw_evidence TEXT,
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(probe_id) REFERENCES probes(probe_id)
                );

                CREATE TABLE IF NOT EXISTS anomalies (
                    anomaly_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    eval_id INTEGER,
                    anomaly_type TEXT NOT NULL, -- 'text_binary_blend', 'double_html', 'inline_headers', 'clean_dual_response'
                    description TEXT,
                    raw_response BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(eval_id) REFERENCES evaluations(eval_id)
                );

                CREATE TABLE IF NOT EXISTS cascade_hypotheses (
                    hypothesis_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trigger_eval_id INTEGER,
                    category TEXT NOT NULL, -- 'shared_parser_confusion', 'range_cache_poisoning', 'status_line_injection', 'general'
                    hypothesis_text TEXT NOT NULL,
                    suggested_probes_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(trigger_eval_id) REFERENCES evaluations(eval_id)
                );
            """)

    def save_rfc(self, rfc_id: str, title: str, source_url: str, doc_path: str) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO rfcs (rfc_id, title, source_url, doc_path)
                VALUES (?, ?, ?, ?)
                """,
                (rfc_id, title, source_url, doc_path),
            )

    def save_fragments(self, rfc_id: str, fragments: List[Tuple[str, str]]) -> int:
        count = 0
        with self.conn:
            for content, keywords in fragments:
                self.conn.execute(
                    """
                    INSERT INTO fragments (rfc_id, content, keywords)
                    VALUES (?, ?, ?)
                    """,
                    (rfc_id, content, keywords),
                )
                count += 1
        return count

    def get_ingested_rfc_ids(self) -> List[str]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT rfc_id FROM fragments")
        return [row[0] for row in cursor.fetchall() if row[0]]

    def get_scanned_rfc_nums(self) -> List[int]:
        ids = self.get_ingested_rfc_ids()
        nums = []
        for rid in ids:
            if rid.upper() == "RFC-MCP":
                nums.append(0)
            elif rid.upper().startswith("RFC"):
                try:
                    nums.append(int(rid[3:]))
                except ValueError:
                    pass
        return nums

    def get_unprocessed_fragments(self, limit: int = 50) -> List[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT f.fragment_id, f.rfc_id, f.content
            FROM fragments f
            LEFT JOIN probes p ON f.fragment_id = p.fragment_id
            WHERE p.probe_id IS NULL
            LIMIT ?
            """,
            (limit,),
        )
        return cursor.fetchall()

    def save_probe(
        self,
        fragment_id: Optional[int],
        rationale: str,
        raw_request: str,
        is_clean: bool = False,
        source_type: str = "llm",
        parent_probe_id: Optional[int] = None,
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO probes (fragment_id, rationale, raw_request, is_clean, source_type, parent_probe_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (fragment_id, rationale, raw_request, 1 if is_clean else 0, source_type, parent_probe_id),
            )
            return cursor.lastrowid

    def get_pending_probes(self, target_host: str, limit: int = 50) -> List[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT p.probe_id, p.rationale, p.raw_request, p.is_clean, p.source_type
            FROM probes p
            LEFT JOIN evaluations e ON p.probe_id = e.probe_id AND e.target_host = ?
            WHERE e.eval_id IS NULL
            LIMIT ?
            """,
            (target_host, limit),
        )
        return cursor.fetchall()

    def record_evaluation(
        self,
        probe_id: int,
        target_host: str,
        target_port: int,
        is_vulnerable: bool,
        desync_class: Optional[str],
        details: str,
        raw_evidence: str,
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO evaluations (probe_id, target_host, target_port, is_vulnerable, desync_class, details, raw_evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (probe_id, target_host, target_port, 1 if is_vulnerable else 0, desync_class, details, raw_evidence),
            )
            return cursor.lastrowid

    def record_anomaly(
        self,
        eval_id: Optional[int],
        anomaly_type: str,
        description: str,
        raw_response: bytes,
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO anomalies (eval_id, anomaly_type, description, raw_response)
                VALUES (?, ?, ?, ?)
                """,
                (eval_id, anomaly_type, description, raw_response),
            )
            return cursor.lastrowid

    def save_cascade_hypothesis(
        self,
        trigger_eval_id: Optional[int],
        category: str,
        hypothesis_text: str,
        suggested_probes: List[Dict[str, Any]],
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO cascade_hypotheses (trigger_eval_id, category, hypothesis_text, suggested_probes_json)
                VALUES (?, ?, ?, ?)
                """,
                (trigger_eval_id, category, hypothesis_text, json.dumps(suggested_probes)),
            )
            return cursor.lastrowid

    def get_confirmed_findings(self) -> List[sqlite3.Row]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT e.eval_id, e.probe_id, e.target_host, e.desync_class, e.details, e.raw_evidence,
                   p.rationale, p.raw_request, f.content AS rfc_fragment
            FROM evaluations e
            JOIN probes p ON e.probe_id = p.probe_id
            LEFT JOIN fragments f ON p.fragment_id = f.fragment_id
            WHERE e.is_vulnerable = 1
            """
        )
        return cursor.fetchall()
