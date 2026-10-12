"""
RFC Micro-Inspiration Chunker: Slices RFC documents into 1-3 sentence micro-fragments.
Solves context-contamination and LLM over-anchoring by isolating operative requirements.
"""

import re
from typing import List, Tuple


OPERATIVE_KEYWORDS = [
    "must", "must not", "should", "should not", "may",
    "stream", "header", "length", "framing", "cache",
    "transfer-encoding", "content-length", "content-type",
    "range", "multipart", "early data", "expect", "trailer",
    "upgrade", "connect", "tunnel", "chunked", "boundary",
    "status line", "request line", "whitespace", "delimit",
    "response", "status code", "pipelining", "bdat",
    "folding", "dot-stuffing", "bare lf", "mail from", "rcpt to"
]


class RFCChunker:
    """
    Slices raw RFC documents into small 1-3 sentence micro-fragments to avoid
    context contamination, LLM over-anchoring, and semantic regression.
    """

    @staticmethod
    def clean_text(rfc_text: str) -> str:
        # Strip Byte Order Mark (BOM)
        cleaned = rfc_text.lstrip("\ufeff")
        # 1. Strip ASCII document headers, footers, page breaks, and form feeds
        # Example: [Page 12] or RFC 9112 HTTP/1.1 June 2022
        cleaned = re.sub(r"\n\s*RFC\s+\d+.*?\n", "\n", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\[Page\s+\d+\]", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\f", "\n", cleaned)
        cleaned = re.sub(r"[-=]{4,}", " ", cleaned)
        # Normalize whitespace
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    @classmethod
    def chunk_document(
        cls, rfc_text: str, sentences_per_chunk: int = 2, min_sentence_len: int = 25
    ) -> List[Tuple[str, str]]:
        """
        Chunks the document into micro-inspiration fragments.
        Returns a list of tuples: (fragment_text, matched_keywords_csv).
        """
        cleaned_text = cls.clean_text(rfc_text)

        # Split into sentences using punctuation boundaries
        # Lookbehind for punctuation, lookahead for Capital letter or number
        sentence_end = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'])")
        raw_sentences = [
            s.strip() for s in sentence_end.split(cleaned_text) if len(s.strip()) >= min_sentence_len
        ]

        chunks: List[Tuple[str, str]] = []
        for i in range(0, len(raw_sentences), sentences_per_chunk):
            chunk = " ".join(raw_sentences[i : i + sentences_per_chunk])

            # Check for operative protocol requirements or state language
            chunk_lower = chunk.lower()
            matched = [k for k in OPERATIVE_KEYWORDS if k in chunk_lower]

            if matched:
                # Anti-anchor: ensure words like 'smuggling' or 'desync' do not exist in the source inspiration
                sanitized_chunk = re.sub(r"\b(desync|smuggling|vulnerability|exploit)\b", "boundary condition", chunk, flags=re.IGNORECASE)
                chunks.append((sanitized_chunk, ",".join(matched[:5])))

        return chunks
