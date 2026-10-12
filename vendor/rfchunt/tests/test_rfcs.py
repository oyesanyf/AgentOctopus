"""
Unit tests for RFC Fetcher and Micro-Inspiration Chunker.
"""

import os
from pathlib import Path
import shutil
import tempfile
import pytest

from database import Database
from rfc_chunker import RFCChunker
from rfc_fetcher import RFCFetcher


@pytest.fixture
def temp_env():
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    db = Database(db_path)
    yield temp_dir, db
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_chunker_micro_fragmentation():
    sample_text = """
    RFC 9112               HTTP/1.1 Message Syntax               June 2022

    A client MUST NOT send a Transfer-Encoding header field in any request that contains a Content-Length header field.
    A server or client that receives an HTTP/1.0 message containing a Transfer-Encoding header field MUST treat the message
    as if the framing is faulty, even if a Content-Length is present.

    [Page 15]

    This is an irrelevant historical note about protocol history with no operative requirements.
    Another line that discusses general background information without keywords.
    """

    chunks = RFCChunker.chunk_document(sample_text, sentences_per_chunk=1)

    # Must find operative sentences containing MUST and Transfer-Encoding
    assert len(chunks) >= 2
    for chunk, keywords in chunks:
        assert "[Page" not in chunk
        assert "RFC 9112" not in chunk
        assert any(k in keywords for k in ["must", "transfer-encoding", "content-length", "framing"])


def test_chunker_anti_anchoring():
    sample_text = "A proxy must handle potential smuggling or desync vulnerabilities by closing the connection."
    chunks = RFCChunker.chunk_document(sample_text, sentences_per_chunk=1)
    assert len(chunks) == 1
    # Check that buzzwords 'smuggling' and 'desync' are sanitized to 'boundary condition'
    assert "smuggling" not in chunks[0][0].lower()
    assert "desync" not in chunks[0][0].lower()
    assert "boundary condition" in chunks[0][0].lower()


def test_rfc_fetcher_caching(temp_env):
    temp_dir, db = temp_env
    cache_dir = os.path.join(temp_dir, "rfcs")
    os.makedirs(cache_dir, exist_ok=True)

    # Pre-populate a fake RFC file in cache to verify offline retrieval
    fake_rfc = os.path.join(cache_dir, "rfc9999.txt")
    with open(fake_rfc, "w", encoding="utf-8") as f:
        f.write("A client MUST NOT send dual headers.\n")

    fetcher = RFCFetcher(cache_dir=cache_dir, db=db)
    content = fetcher.fetch_rfc_by_number(9999, title="Test RFC 9999")
    assert content is not None
    assert "MUST NOT send dual headers" in content

    # Verify recorded in DB
    cursor = db.conn.cursor()
    cursor.execute("SELECT rfc_id, title FROM rfcs WHERE rfc_id = 'RFC9999'")
    row = cursor.fetchone()
    assert row is not None
    assert row["title"] == "Test RFC 9999"


def test_rfc_mcp_ingestion(temp_env):
    temp_dir, db = temp_env
    # Point fetcher to real rfcs dir where rfc_mcp_spec.txt lives
    rfcs_dir = Path(__file__).resolve().parent.parent / "rfcs"
    fetcher = RFCFetcher(cache_dir=str(rfcs_dir), db=db)
    mcp_text = fetcher.fetch_rfc_by_number(0)
    assert mcp_text is not None
    assert "Model Context Protocol" in mcp_text
    assert "JSON-RPC" in mcp_text

    # Verify chunking operative keywords on MCP spec
    chunks = RFCChunker.chunk_document(mcp_text, sentences_per_chunk=2)
    assert len(chunks) > 5
    assert any("must" in kw for _, kw in chunks)


def test_rfc_fetcher_all_active(temp_env):
    temp_dir, db = temp_env
    cache_dir = os.path.join(temp_dir, "rfcs")
    os.makedirs(cache_dir, exist_ok=True)

    # Mock an rfc-index.txt with active and obsoleted entries
    mock_index = """
1001 Active Protocol Spec. Author. Jan 2026. (Format: TXT) (Status: PROPOSED STANDARD)

1002 Old Obsoleted Spec. Author. Jan 2020. (Format: TXT) (Obsoleted by RFC1001) (Status: PROPOSED STANDARD)

1003 Historic Protocol. Author. Jan 2010. (Format: TXT) (Status: HISTORIC)

1004 Active Framing Extension. Author. Feb 2026. (Format: TXT) (Status: INTERNET STANDARD)
"""
    index_file = os.path.join(cache_dir, "rfc-index.txt")
    with open(index_file, "w", encoding="utf-8") as f:
        f.write(mock_index)

    fetcher = RFCFetcher(cache_dir=cache_dir, db=db)
    active = fetcher.get_all_active_rfcs(keywords=None)
    # 1002 is obsoleted, 1003 is historic; only 1004 and 1001 are active
    assert active == [1004, 1001]

    # Keyword filter for "framing"
    framing_active = fetcher.get_all_active_rfcs(keywords=["framing"])
    assert framing_active == [1004]


def test_kettle_corpus(temp_env):
    temp_dir, db = temp_env
    # Real cache dir with rfc-index.txt
    real_cache = Path(__file__).resolve().parent.parent / "rfcs"
    fetcher = RFCFetcher(cache_dir=str(real_cache), db=db)
    corpus = fetcher.get_kettle_corpus(max_rfcs=138)
    assert len(corpus) <= 138
    assert len(corpus) > 20
    # Core HTTP standards must be present
    assert 9112 in corpus
    assert 7230 in corpus
    # Core SMTP standards must be present
    assert 5321 in corpus
    assert 5322 in corpus


def test_explain_vulnerability_concept():
    from fusion_engine import FusionArbiter
    arbiter = FusionArbiter(db=None)

    # Test heuristic fallback and concept synthesis for Response Rule Inversion
    analysis = arbiter.explain_vulnerability_concept(
        rfc_fragment="A server MUST NOT send a body in a 304 (Not Modified) response.",
        probe_request="GET / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 5\r\n\r\nhello$PAYLOAD",
        baseline_resp="HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n1234567890",
        probe_resp="HTTP/1.1 400 Bad Request\r\n\r\n",
        retest_resp="CONNECTION_CLOSED",
        anomalies=[],
        details="Differential response triggering Connection Close on Conn A",
    )

    assert "concept_name" in analysis and len(analysis["concept_name"]) > 0
    assert "architectural_explanation" in analysis and len(analysis["architectural_explanation"]) > 0
    assert "rfc_clue_connection" in analysis and len(analysis["rfc_clue_connection"]) > 0
    assert "generalization" in analysis and len(analysis["generalization"]) > 0
    assert isinstance(analysis["validation_steps"], list) and len(analysis["validation_steps"]) > 0
