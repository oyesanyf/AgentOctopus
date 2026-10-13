"""
Unit test for LangGraph Protocol Research Swarm Agent (rfc_hunt_swarm.py).
Verifies:
1. Swarm graph construction, compilation, and state schema.
2. Node definitions (fetch, generate, execute, triage, cascade/publish).
3. Conditional routing decisions.
"""

import pytest
from pathlib import Path
import sys

# Ensure vendor/rfchunt is in python path
rfchunt_dir = Path(__file__).resolve().parent.parent
if str(rfchunt_dir) not in sys.path:
    sys.path.insert(0, str(rfchunt_dir))

from rfc_hunt_swarm import ProtocolResearchSwarm, ResearchState


def test_swarm_agent_graph_build(tmp_path):
    test_db = str(tmp_path / "test_swarm.db")
    swarm = ProtocolResearchSwarm(host="127.0.0.1", port=5006, db_path=test_db)
    graph = swarm.build_graph()

    assert graph is not None
    # Verify graph nodes exist
    nodes = graph.nodes
    assert "fetch_and_chunk_agent" in nodes
    assert "llm_generator_agent" in nodes
    assert "execution_oracle_agent" in nodes
    assert "triage_debugger_agent" in nodes
    assert "cascade_and_publish_agent" in nodes


def test_swarm_agent_routing_logic(tmp_path):
    test_db = str(tmp_path / "test_swarm.db")
    swarm = ProtocolResearchSwarm(host="127.0.0.1", port=5006, db_path=test_db)

    # Test route_after_generation
    empty_state = {"generated_candidates": [], "fragments": []}
    assert swarm.route_after_generation(empty_state) == "__end__"

    state_with_frags = {"generated_candidates": [], "fragments": ["some fragment"]}
    assert swarm.route_after_generation(state_with_frags) == "llm_generator_agent"

    state_with_cands = {"generated_candidates": [{"raw_request": b"GET / HTTP/1.1\r\n\r\n"}]}
    assert swarm.route_after_generation(state_with_cands) == "execution_oracle_agent"

    # Test route_after_execution
    from engine.taxonomy import ImplementationAnomaly, AnomalyCategory
    anom = ImplementationAnomaly(
        anomaly_id="ANOM-TEST",
        target_engine="127.0.0.1:5006",
        category=AnomalyCategory.PARSER_DIVERGENCE,
        observed_behavior="divergence",
        expected_behavior="standard",
        raw_probe=b"TEST",
        raw_response=b"RESP",
    )
    assert swarm.route_after_execution({"current_anomaly": anom}) == "triage_debugger_agent"
    assert swarm.route_after_execution({"current_anomaly": None, "generated_candidates": [1]}) == "execution_oracle_agent"
    assert swarm.route_after_execution({"current_anomaly": None, "generated_candidates": [], "cycle_count": 5, "max_cycles": 3}) == "__end__"
