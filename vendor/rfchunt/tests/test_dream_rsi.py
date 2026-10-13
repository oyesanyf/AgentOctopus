"""
Comprehensive Verification Tests for Open Dream-RSI (Modules 13-15).

Tests:
1. ProtocolWorldModel state ingestion from SQLite and trajectory reconstruction.
2. Fast in-memory simulation fidelity across structural mutations.
3. DreamRSIOptimizer off-policy fitness evaluation and evolutionary RSI gain.
4. DreamPolicyStore persistence and summary telemetry.
5. AdaptiveBanditScheduler hot-reloading of evolved policies.
6. ProtocolResearchSwarm LangGraph state machine integration with Agent 13 (dream_rsi_agent).
"""

import sqlite3
import pytest
from pathlib import Path

from engine.bandit_scheduler import AdaptiveBanditScheduler
from engine.dream_world_model import ProtocolWorldModel, SimulatedResponse
from engine.dream_rsi_optimizer import DreamRSIOptimizer, DreamPolicy
from engine.dream_policy_store import DreamPolicyStore
from rfc_hunt_swarm import ProtocolResearchSwarm


def test_world_model_ingestion(tmp_path):
    """Verifies that ProtocolWorldModel ingests historical runs and populates trajectories."""
    db_file = tmp_path / "test_sim.db"
    conn = sqlite3.connect(str(db_file))
    with conn:
        conn.executescript("""
            CREATE TABLE probes (
                probe_id INTEGER PRIMARY KEY,
                raw_request TEXT
            );
            CREATE TABLE evaluations (
                eval_id INTEGER PRIMARY KEY,
                probe_id INTEGER,
                is_vulnerable BOOLEAN,
                desync_class TEXT,
                details TEXT
            );
            INSERT INTO probes VALUES (1, 'POST / HTTP/1.1\\r\\nHost: target.local\\r\\nContent-Length: 5\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n');
            INSERT INTO evaluations VALUES (1, 1, 1, 'CL_TE_DESYNCHRONIZATION', 'Dual framing detected');
            INSERT INTO probes VALUES (2, 'GET / HTTP/1.1\\r\\nHost: target.local\\r\\n\\r\\n');
            INSERT INTO evaluations VALUES (2, 2, 0, NULL, 'Standard request');
        """)
    conn.close()

    model = ProtocolWorldModel(target_host="127.0.0.1", target_port=8080)
    loaded = model.ingest_history_from_db(str(db_file))
    assert loaded == 2
    assert len(model.trajectories) == 2
    assert "CL_TE_DESYNCHRONIZATION" in model.known_anomaly_patterns


def test_world_model_simulation_fidelity():
    """Verifies simulation rules for conforming and non-conforming protocol triggers."""
    model = ProtocolWorldModel(target_host="127.0.0.1", target_port=8080)

    # 1. Dual-CL probe
    dual_cl_probe = (
        b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
    )
    sim_dual = model.simulate_probe(dual_cl_probe)
    assert sim_dual.status_code == 400
    assert sim_dual.is_anomaly is True
    assert sim_dual.anomaly_category == "DUAL_HEADER_CONFLICT"

    # 2. CL.TE conflicting framing
    cl_te_probe = (
        b"POST / HTTP/1.1\r\nHost: target.local\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    )
    sim_clte = model.simulate_probe(cl_te_probe)
    assert sim_clte.status_code == 200
    assert sim_clte.is_vulnerability is True
    assert sim_clte.anomaly_category == "CL_TE_DESYNCHRONIZATION"

    # 3. Un-framed client body (RFC 9112 Section 6.1)
    unframed_probe = b"POST / HTTP/1.1\r\nHost: target.local\r\n\r\n{'unframed': true}"
    sim_unframed = model.simulate_probe(unframed_probe)
    assert sim_unframed.status_code == 400
    assert sim_unframed.is_anomaly is False  # Not an anomaly, expected server behavior
    assert "framing omission" in sim_unframed.details.lower()

    # 4. Standard clean GET
    clean_get = b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n"
    sim_clean = model.simulate_probe(clean_get)
    assert sim_clean.status_code == 200
    assert sim_clean.is_anomaly is False


def test_dream_rsi_optimizer_evolution():
    """Verifies off-policy dreaming rollouts and policy evolution generation."""
    model = ProtocolWorldModel(target_host="127.0.0.1", target_port=8080)
    optimizer = DreamRSIOptimizer(model)

    assert optimizer.current_generation == 0
    assert optimizer.active_policy is not None

    # Evaluate baseline fitness
    f0 = optimizer.evaluate_policy_fitness(optimizer.active_policy, rollouts=100)
    assert isinstance(f0, float)

    # Evolve 2 generations
    gen1 = optimizer.evolve_policy_generation(rollouts_per_candidate=100, population_size=4)
    assert gen1.generation == 1
    assert len(gen1.mutator_weights) > 0
    assert round(sum(gen1.mutator_weights.values()), 2) == 1.0

    gen2 = optimizer.evolve_policy_generation(rollouts_per_candidate=100, population_size=4)
    assert gen2.generation == 2


def test_dream_policy_store(tmp_path):
    """Verifies persistence, retrieval, and telemetry export from DreamPolicyStore."""
    store_file = tmp_path / "policies.json"
    store = DreamPolicyStore(storage_path=str(store_file))

    p1 = DreamPolicy(
        generation=1,
        mutator_weights={"TE_CL_DUAL_HEADER": 0.6, "PATH_NUL_EARLY_RESPONSE": 0.4},
        fitness_score=150.0,
        rsi_gain=0.25,
        simulated_yield=0.35,
    )
    store.save_policy(p1)

    # Reload from disk
    store2 = DreamPolicyStore(storage_path=str(store_file))
    latest = store2.get_latest_policy()
    assert latest is not None
    assert latest.generation == 1
    assert latest.fitness_score == 150.0
    assert latest.mutator_weights["TE_CL_DUAL_HEADER"] == 0.6

    summary = store2.export_summary()
    assert summary["total_generations"] == 1
    assert summary["latest_fitness"] == 150.0


def test_bandit_hot_reload_with_dream_policy():
    """Verifies that AdaptiveBanditScheduler biases sampling towards dream-evolved mutator weights."""
    scheduler = AdaptiveBanditScheduler()

    # Pre-dream state
    assert "TE_CL_DUAL_HEADER" in scheduler.arms

    # Apply policy heavily favoring TE_CL_DUAL_HEADER
    dream_policy = DreamPolicy(
        generation=2,
        mutator_weights={
            "TE_CL_DUAL_HEADER": 0.95,
            "PATH_NUL_EARLY_RESPONSE": 0.05,
        },
    )
    scheduler.apply_dream_policy(dream_policy)

    # Check arm reward boost
    arm = scheduler.arms["TE_CL_DUAL_HEADER"]
    assert arm.total_reward > 0
    assert arm.pulls >= 2


def test_swarm_graph_contains_dream_rsi_agent():
    """Verifies that ProtocolResearchSwarm LangGraph state machine includes dream_rsi_agent."""
    swarm = ProtocolResearchSwarm(host="127.0.0.1", port=5006)
    graph = swarm.build_graph()

    # Check node presence in the compiled LangGraph runnable
    nodes = list(graph.nodes.keys())
    assert "dream_rsi_agent" in nodes
    assert "fetch_and_chunk_agent" in nodes
    assert "execution_oracle_agent" in nodes
    assert "cascade_and_publish_agent" in nodes
