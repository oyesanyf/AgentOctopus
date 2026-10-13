"""
RFC Ingestion Engine: Automatically fetches canonical and recent RFC documents
from the IETF / RFC Editor (https://www.rfc-editor.org).
Provides local caching and discovery of recent HTTP, framing, and transport RFCs.
"""

import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional
import httpx

from database import Database
from engine.terminator_rfc_selector import TerminatorRFCSelector, TERMINATOR_CORE_RFCS


# Canonical core modern and historic protocol RFCs for HTTP Terminators
DEFAULT_CORE_RFCS = [
    {"id": "RFC9112", "num": 9112, "title": "HTTP/1.1 (Message Syntax and Framing - Primary Line Terminator Spec)"},
    {"id": "RFC9110", "num": 9110, "title": "HTTP Semantics (Intermediaries, Gateways, and Connection Management)"},
    {"id": "RFC7230", "num": 7230, "title": "Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing"},
    {"id": "RFC2616", "num": 2616, "title": "Hypertext Transfer Protocol -- HTTP/1.1 (Historic Discrepancies & Multipart/Byteranges)"},
    {"id": "RFC9113", "num": 9113, "title": "HTTP/2 (Section 8: Intermediary Gateway Translation to HTTP/1.1)"},
    {"id": "RFC7540", "num": 7540, "title": "Hypertext Transfer Protocol Version 2 (HTTP/2 - Legacy Framing)"},
    {"id": "RFC9114", "num": 9114, "title": "HTTP/3 (QUIC Gateway Termination & Mapping)"},
    {"id": "RFC8446", "num": 8446, "title": "The Transport Layer Security (TLS) Protocol Version 1.3"},
    {"id": "RFC3986", "num": 3986, "title": "Uniform Resource Identifier (URI): Generic Syntax (Path & NUL Byte Normalization)"},
    {"id": "RFC6265", "num": 6265, "title": "HTTP State Management Mechanism (Cookies)"},
    {"id": "RFC9111", "num": 9111, "title": "HTTP Caching"},
    {"id": "RFC1945", "num": 1945, "title": "Hypertext Transfer Protocol -- HTTP/1.0"},
    {"id": "RFC9218", "num": 9218, "title": "Extensible Prioritization Scheme for HTTP"},
    {"id": "RFC9204", "num": 9204, "title": "QPACK: Field Compression for HTTP/3"},
]

# Ancillary specifications (opt-in via --rfc MCP or explicit selector)
ANCILLARY_PROTOCOL_RFCS = [
    {"id": "RFC-MCP", "num": 0, "title": "Model Context Protocol Architecture and Transport Specification"},
]

RFC_EDITOR_BASE = "https://www.rfc-editor.org/rfc"
RFC_INDEX_URL = "https://www.rfc-editor.org/rfc-index.txt"


class RFCFetcher:
    def __init__(self, cache_dir: str = "rfcs", db: Optional[Database] = None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db = db or Database()
        self.client = httpx.Client(
            headers={"User-Agent": "HTTPTerminator-ResearchBot/1.0 (Academic/RFC-Analysis)"},
            timeout=15.0,
            follow_redirects=True,
        )

    def fetch_rfc_by_number(self, rfc_number: int, title: Optional[str] = None) -> Optional[str]:
        """
        Fetches an RFC document by its number (e.g. 0 for MCP, 9112 for HTTP/1.1).
        Checks local cache first; if missing, downloads from rfc-editor.org.
        """
        if rfc_number == 0 or str(rfc_number).upper() in ("0", "MCP"):
            rfc_id = "RFC-MCP"
            mcp_file = self.cache_dir / "rfc_mcp_spec.txt"
            if mcp_file.exists():
                text = mcp_file.read_text(encoding="utf-8", errors="ignore")
                self.db.save_rfc(rfc_id, "Model Context Protocol Specification", "https://spec.modelcontextprotocol.io", str(mcp_file))
                print(f"[+] Loaded canonical {rfc_id}: Model Context Protocol Specification")
                return text

        rfc_id = f"RFC{rfc_number}"
        cached_file = self.cache_dir / f"rfc{rfc_number}.txt"

        if cached_file.exists():
            text = cached_file.read_text(encoding="utf-8", errors="ignore")
            if title is None:
                title = self._extract_title_from_text(text) or rfc_id
            self.db.save_rfc(rfc_id, title, f"{RFC_EDITOR_BASE}/rfc{rfc_number}.txt", str(cached_file))
            return text

        url = f"{RFC_EDITOR_BASE}/rfc{rfc_number}.txt"
        try:
            resp = self.client.get(url)
            if resp.status_code == 200:
                text = resp.text
                cached_file.write_text(text, encoding="utf-8")
                if title is None:
                    title = self._extract_title_from_text(text) or rfc_id
                self.db.save_rfc(rfc_id, title, url, str(cached_file))
                print(f"[+] Successfully fetched and cached {rfc_id}: {title}")
                return text
            else:
                print(f"[-] HTTP {resp.status_code} fetching {url}")
                return None
        except Exception as e:
            print(f"[!] Network error fetching {url}: {e}")
            return None

    def fetch_core_rfcs(self, limit: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Fetches the primary suite of HTTP, TLS, and framing RFCs.
        """
        results = []
        target_list = DEFAULT_CORE_RFCS[:limit] if limit else DEFAULT_CORE_RFCS
        for item in target_list:
            text = self.fetch_rfc_by_number(item["num"], item["title"])
            if text:
                results.append({"rfc_id": item["id"], "title": item["title"], "content": text})
            # Respectful rate limiting
            time.sleep(0.2)
        return results

    def get_rfc_index_content(self, refresh_cache: bool = False) -> str:
        """
        Retrieves the full rfc-index.txt, caching it locally to avoid repeated large downloads.
        """
        index_cache = self.cache_dir / "rfc-index.txt"
        # Refresh if missing, explicitly requested, or older than 24h
        if not refresh_cache and index_cache.exists():
            try:
                mtime = index_cache.stat().st_mtime
                if (time.time() - mtime) < 86400:
                    return index_cache.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        print("[*] Downloading latest RFC Editor index from https://www.rfc-editor.org/rfc-index.txt...")
        try:
            resp = self.client.get(RFC_INDEX_URL)
            if resp.status_code == 200:
                content = resp.text
                index_cache.write_text(content, encoding="utf-8")
                return content
            elif index_cache.exists():
                return index_cache.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            if index_cache.exists():
                print(f"[!] Network error fetching RFC index ({e}); using existing cache.")
                return index_cache.read_text(encoding="utf-8", errors="ignore")
            print(f"[!] Failed to fetch RFC index: {e}")
        return ""

    def get_all_active_rfcs(
        self,
        keywords: Optional[List[str]] = None,
        max_rfcs: Optional[int] = None,
        refresh_cache: bool = False,
        reverse: bool = True,
    ) -> List[int]:
        """
        Parses the complete RFC Editor index to discover ALL active (non-obsoleted, non-historic)
        RFC documents. Supports filtering by protocol/framing keywords or scanning all active RFCs.
        """
        content = self.get_rfc_index_content(refresh_cache=refresh_cache)
        if not content:
            return []

        pattern = re.compile(r"^(\d{4,5})\s+(.*?)(?=\n\n|\r\n\r\n|\Z)", re.MULTILINE | re.DOTALL)
        matches = pattern.findall(content)

        active_rfcs: List[int] = []
        iterable = reversed(matches) if reverse else matches

        for num_str, entry_text in iterable:
            entry_lower = entry_text.lower()

            # Filter out obsoleted, historic, or withdrawn RFCs
            if "obsoleted by" in entry_lower:
                continue
            if "(status: historic)" in entry_lower or "(status: unknown)" in entry_lower:
                continue

            # Optional keyword filtering
            if keywords:
                if not any(kw.lower() in entry_lower for kw in keywords):
                    continue

            rfc_num = int(num_str)
            active_rfcs.append(rfc_num)

            if max_rfcs and len(active_rfcs) >= max_rfcs:
                break

        return active_rfcs

    def discover_active_protocol_rfcs(
        self,
        include_tier2: bool = True,
        max_rfcs: Optional[int] = None,
        unrestricted: bool = False,
    ) -> List[int]:
        """
        Discovers all active (non-obsoleted, non-historic) RFCs from the RFC Editor index.
        Ranks by protocol relevance:
        - Tier 1: Active HTTP Semantics, Message Syntax, Framing, Caching, Chunking, Query/Methods (170 RFCs)
        - Tier 2: Active Web Protocols, TLS, WebSockets, QUIC, URIs, Cookies, Proxies (1080+ RFCs)
        - Unrestricted: All 7,600+ active RFCs in the registry
        """
        content = self.get_rfc_index_content()
        if not content:
            return [9112, 9110, 9111, 9113, 9114, 8446, 7230, 2616]

        pattern = re.compile(r"^(\d{4,5})\s+(.*?)(?=\n\n|\r\n\r\n|\Z)", re.MULTILINE | re.DOTALL)
        matches = pattern.findall(content)

        tier1: List[int] = []
        tier2: List[int] = []
        tier3: List[int] = []
        seen = set()

        # Canonical mandatory HTTP/1.1 and framing standards
        core_standards = [9112, 9110, 9111, 9113, 9114, 8446, 7230, 7540, 6585, 6265, 6455, 3986, 2817]

        t1_keywords = [
            'http', 'hypertext transfer', 'transfer-encoding', 'content-length',
            'request smuggling', 'chunked', 'message syntax', 'caching', 'status code',
            'incremental forwarding', 'query method', 'cache groups'
        ]
        t2_keywords = [
            'websocket', 'quic', 'tls', 'proxy', 'uri', 'cookie', 'token',
            'sse', 'multiplex', 'gateway', 'mime', 'alpn', 'cross-device'
        ]

        for num_str, entry in reversed(matches):
            entry_l = entry.lower()
            if 'obsoleted by' in entry_l or '(status: historic)' in entry_l or '(status: unknown)' in entry_l:
                continue

            num = int(num_str)
            if num in seen:
                continue

            if any(k in entry_l for k in t1_keywords):
                seen.add(num)
                tier1.append(num)
            elif any(k in entry_l for k in t2_keywords):
                seen.add(num)
                tier2.append(num)
            else:
                seen.add(num)
                tier3.append(num)

        # Ensure core standards are in tier 1
        for cs in core_standards:
            if cs not in tier1:
                tier1.append(cs)

        print(f"[+] Active RFC Registry Analysis:")
        print(f"    - Tier 1 (Core HTTP & Framing): {len(tier1)} active RFCs")
        print(f"    - Tier 2 (Web Protocols & TLS): {len(tier2)} active RFCs")
        if unrestricted:
            print(f"    - Tier 3 (General Internet Specs): {len(tier3)} active RFCs")

        if unrestricted:
            ordered = tier1 + tier2 + tier3
        elif include_tier2:
            ordered = tier1 + tier2
        else:
            ordered = tier1

        if max_rfcs and max_rfcs > 0:
            ordered = ordered[:max_rfcs]

        return ordered

    def get_kettle_corpus(self, max_rfcs: int = 138) -> List[int]:
        """
        Retrieves James Kettle's curated research corpus of 138 HTTP and SMTP specifications.
        Prioritizes core HTTP message syntax, semantics, framing, and caching RFCs,
        alongside canonical SMTP message formats, MIME structures, pipelining, and transport extensions.
        """
        content = self.get_rfc_index_content()
        if not content:
            return [9112, 9110, 9111, 9113, 9114, 7230, 2616, 5321, 5322, 2045, 2046, 3030]

        core_kettle_prio = [
            # Core HTTP Message Syntax, Semantics, Framing & Extensions
            9112, 9110, 9111, 9113, 9114, 7230, 7231, 7232, 7233, 7234, 7235,
            2616, 1945, 7540, 7541, 8446, 6585, 6265, 6455, 3986, 2817, 2818,
            8297, 8941, 9651, 7538, 8187, 8246, 9218, 7617, 7616, 9297, 9204,
            # Core SMTP, Internet Message Format, MIME, Chunking & Pipelining
            5321, 5322, 2045, 2046, 2047, 3030, 2920, 3207, 1870, 2034, 4954,
            6531, 6532, 7504, 3461, 1830, 2821, 2822, 821, 822
        ]

        pattern = re.compile(r"^(\d{4,5})\s+(.*?)(?=\n\n|\r\n\r\n|\Z)", re.MULTILINE | re.DOTALL)
        matches = pattern.findall(content)

        corpus: List[int] = []
        seen = set()

        for num in core_kettle_prio:
            if num not in seen:
                seen.add(num)
                corpus.append(num)

        for num_str, entry in reversed(matches):
            entry_l = entry.lower()
            if 'obsoleted by' in entry_l or '(status: historic)' in entry_l or '(status: unknown)' in entry_l:
                continue
            if any(ex in entry_l for ex in ['anti-spam', 'reputation', 'pki', 'on-demand mail', 'dns ncache', 'x.25', 'postal', 'radius']):
                continue
            is_http = any(k in entry_l for k in ['http', 'hypertext transfer', 'transfer-encoding', 'content-length', 'caching'])
            is_smtp = any(k in entry_l for k in ['smtp', 'simple mail transfer', 'mail submission', 'email message', 'mime'])
            if is_http or is_smtp:
                n = int(num_str)
                if n not in seen:
                    seen.add(n)
                    corpus.append(n)

            if len(corpus) >= max_rfcs:
                break

        final_corpus = corpus[:max_rfcs]
        print(f"[+] James Kettle Research Corpus Initialized:")
        print(f"    - Protocol Scope: HTTP & SMTP Specifications")
        print(f"    - Total Curated Specifications: {len(final_corpus)} RFCs")
        return final_corpus

    def discover_recent_rfcs(self, max_discover: int = 10, keywords: Optional[List[str]] = None) -> List[int]:
        """
        Scans the RFC Editor index to discover the highest-numbered (most recent) RFCs
        related to HTTP, transport, caching, framing, or proxies.
        """
        if keywords is None:
            return self.discover_active_protocol_rfcs(max_rfcs=max_discover)

        print("[*] Querying RFC Editor index for recent protocol specifications...")
        found_rfcs = self.get_all_active_rfcs(keywords=keywords, max_rfcs=max_discover, reverse=True)
        print(f"[+] Discovered {len(found_rfcs)} recent relevant RFCs: {found_rfcs[:10]}{'...' if len(found_rfcs) > 10 else ''}")
        return found_rfcs

    def _extract_title_from_text(self, text: str) -> Optional[str]:
        # Typically on the first page after the author block
        lines = [line.strip() for line in text.splitlines()[:50] if line.strip()]
        for line in lines:
            if any(term in line.lower() for term in ["protocol", "http", "semantics", "caching", "framing", "extension"]):
                return line
        return None

    def check_new_rfcs_from_index(self) -> List[int]:
        # automated continuous RFC monitoring
        existing = self.db.get_scanned_rfc_nums()
        active = self.discover_active_protocol_rfcs(unrestricted=True)
        new_rfcs = [r for r in active if r not in existing]
        for num in new_rfcs:
            self.fetch_rfc_by_number(num)
            # trigger hypotheses
        return new_rfcs

    def get_pqc_corpus(self, max_rfcs: int = 25) -> List[int]:
        """
        Retrieves active Post-Quantum Cryptography (PQC), Hybrid Key Exchange,
        and Quantum-Resistant Transport specifications from the IETF registry.
        """
        core_pqc = [9980, 9958, 9954, 9370, 9180, 8937, 8554, 8446, 8391]
        discovered = self.get_all_active_rfcs(
            keywords=['quantum', 'post-quantum', 'kem', 'hpke', 'hash-based', 'lattice', 'hybrid key', 'merkle'],
            max_rfcs=max_rfcs,
            reverse=True
        )
        seen = set(discovered)
        for rfc in core_pqc:
            if rfc not in seen:
                discovered.append(rfc)
                seen.add(rfc)
        print(f"[+] Post-Quantum Cryptography (PQC) Research Corpus Initialized:")
        print(f"    - Protocol Scope: Post-Quantum KEM, Hybrid Key Exchange, ML-KEM, HPKE, & Quantum-Resistant TLS")
        print(f"    - Total Curated Specifications: {len(discovered)} RFCs")
        return discovered

    def get_terminator_corpus(self, max_rfcs: Optional[int] = None) -> List[int]:
        """
        Retrieves the curated Terminator RFC suite (RFC 9112, 9110, 7230, 2616, 9113, etc.)
        specifically prioritized for finding desync, framing, and line-terminator discrepancies.
        """
        return TerminatorRFCSelector.get_terminator_corpus(max_rfcs=max_rfcs)

    def ensure_terminator_rfcs_cached(self) -> Dict[str, Any]:
        """
        Guarantees that all canonical Terminator RFCs are downloaded and cached locally
        for offline, zero-network execution.
        """
        cached_count = 0
        fetched_count = 0
        failed_count = 0

        specs = TerminatorRFCSelector.get_terminator_specs()
        for spec in specs:
            fpath = self.cache_dir / f"rfc{spec.num}.txt"
            if fpath.exists() and fpath.stat().st_size > 1000:
                cached_count += 1
            else:
                txt = self.fetch_rfc_by_number(spec.num, title=spec.title)
                if txt and len(txt) > 1000:
                    fetched_count += 1
                else:
                    failed_count += 1

        return {
            "total_specs": len(specs),
            "cached": cached_count,
            "fetched": fetched_count,
            "failed": failed_count,
            "ready": (failed_count == 0),
        }

