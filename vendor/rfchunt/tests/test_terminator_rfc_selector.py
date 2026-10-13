"""
Unit and integration tests for Terminator RFC Selector and Build Pipeline components.
"""

from engine.terminator_rfc_selector import TerminatorRFCSelector, TERMINATOR_CORE_RFCS
from rfc_chunker import RFCChunker
from rfc_fetcher import DEFAULT_CORE_RFCS, RFCFetcher
from build_all import build_step_syntax_check, build_step_dependencies, build_step_database


def test_terminator_core_rfcs_priority():
    """Verifies that RFC 9112 is guaranteed at position 0 and RFC-MCP is not in the default terminator queue."""
    corpus = TerminatorRFCSelector.get_terminator_corpus()
    assert len(corpus) >= 10
    assert corpus[0] == 9112, "RFC 9112 (HTTP/1.1 Message Syntax & Framing) MUST be position 0"
    assert corpus[1] == 9110, "RFC 9110 (HTTP Semantics & Intermediaries) MUST be position 1"
    assert corpus[2] == 7230, "RFC 7230 (Predecessor Proxy Standard) MUST be position 2"
    assert corpus[3] == 2616, "RFC 2616 (Historic Baseline) MUST be position 3"
    assert corpus[4] == 9113, "RFC 9113 (HTTP/2 Gateway Translation) MUST be position 4"

    # Ensure RFC-MCP (num 0) is excluded from the core Terminator RFC suite
    assert 0 not in corpus, "RFC-MCP (num 0) must not be in the HTTP Terminator corpus"

    # Check specs dictionary
    specs = TerminatorRFCSelector.get_terminator_specs()
    assert specs[0].num == 9112
    assert "Line Terminators" in specs[0].key_sections[0]


def test_terminator_scoring_engine():
    """Verifies that text with line terminators, CRLF, and Transfer-Encoding receives high scores."""
    terminator_text = (
        "Although the line terminator for the start-line and fields is the sequence CRLF, "
        "a recipient MUST recognize a single LF as a line terminator and ignore any preceding CR. "
        "If a message is received with both a Transfer-Encoding and a Content-Length header field, "
        "the Transfer-Encoding overrides the Content-Length for an intermediary gateway."
    )
    score, matched = TerminatorRFCSelector.score_text_for_terminator(terminator_text)
    assert score > 15.0
    assert "line terminator" in matched
    assert "crlf" in matched
    assert "transfer-encoding" in matched
    assert "intermediary" in matched

    benign_text = "This document describes the format of astronomical telemetry coordinates for satellite downlinks."
    benign_score, benign_matched = TerminatorRFCSelector.score_text_for_terminator(benign_text)
    assert benign_score == 0.0
    assert len(benign_matched) == 0


def test_rfc_fetcher_terminator_corpus():
    """Verifies that RFCFetcher prioritizes RFC 9112 and provides terminator corpus methods."""
    fetcher = RFCFetcher()
    corpus = fetcher.get_terminator_corpus()
    assert corpus[0] == 9112

    # Verifies DEFAULT_CORE_RFCS has RFC 9112 at position 0
    assert DEFAULT_CORE_RFCS[0]["num"] == 9112
    assert DEFAULT_CORE_RFCS[0]["id"] == "RFC9112"


def test_chunker_terminator_keywords_and_ranking():
    """Verifies that RFCChunker extracts and ranks terminator-specific chunks."""
    doc_text = """
    RFC 9112 HTTP/1.1 June 2022
    Section 2.2: Although the line terminator for fields is the sequence CRLF, a recipient MUST recognize a single LF as a line terminator.
    Section 3.1: The astronomical observatory monitors satellite positioning across equatorial sectors.
    Section 6.1: An intermediary gateway receiving both Transfer-Encoding and Content-Length MUST treat the message body as chunked.
    """
    scored_chunks = RFCChunker.chunk_document_for_terminator(doc_text, sentences_per_chunk=1)
    assert len(scored_chunks) >= 2

    # Top-ranked chunk should be terminator-related
    top_chunk, top_keywords, top_score = scored_chunks[0]
    assert top_score > 0
    assert any(term in top_keywords.lower() for term in ["terminator", "crlf", "transfer-encoding", "must"])


def test_build_pipeline_syntax_and_db():
    """Verifies build pipeline syntax checking, dependency auditing, and database schema integrity."""
    ok_syntax, msg_syntax = build_step_syntax_check()
    assert ok_syntax is True, msg_syntax

    ok_deps, msg_deps = build_step_dependencies()
    assert ok_deps is True, msg_deps

    ok_db, msg_db = build_step_database()
    assert ok_db is True, msg_db
