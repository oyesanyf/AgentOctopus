import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
import pytest
from vendor.dream_rsi_worker.trajectory_buffer import TrajectoryBuffer
from vendor.dream_rsi_worker.world_model import WorldModel
from vendor.dream_rsi_worker.policy_agent import PolicyAgent

def test_trajectory_buffer():
    tb = TrajectoryBuffer()
    tb.add_event({
        "event_id": "test-1",
        "rfc_number": 9112,
        "mutation_type": "abnf_delimiter",
        "is_anomalous": True,
        "divergence_score": 0.9,
        "reproducibility_rate": 1.0,
    })
    assert len(tb) == 1
    events = tb.get_events()
    assert events[0]["rfc_number"] == 9112
    assert events[0]["is_anomalous"] is True

def test_world_model_priors_and_prediction():
    wm = WorldModel()
    pred = wm.predict(9112, "abnf_delimiter")
    assert "predicted_divergence" in pred
    assert 0.0 < pred["predicted_divergence"] < 1.0
    assert pred["information_entropy"] > 0.0

def test_world_model_training_from_events():
    wm = WorldModel()
    initial_pred = wm.predict(9112, "abnf_delimiter")["predicted_divergence"]

    events = [
        {"rfc_number": 9112, "mutation_type": "abnf_delimiter", "is_anomalous": True, "reproducibility_rate": 1.0},
        {"rfc_number": 9112, "mutation_type": "abnf_delimiter", "is_anomalous": True, "reproducibility_rate": 1.0},
    ]
    wm.train_from_events(events)
    updated_pred = wm.predict(9112, "abnf_delimiter")["predicted_divergence"]
    # With 2 extra anomalous samples, divergence prediction should increase
    assert updated_pred > initial_pred

def test_policy_agent_rollout_and_training():
    wm = WorldModel()
    agent = PolicyAgent(wm)
    rollout = agent.simulate_rollout(agent.policy, steps=200)
    assert rollout["simulated_steps"] == 200
    assert "fitness" in rollout

    trained = agent.train_policy(generations=3, steps_per_gen=100)
    assert trained["generation"] >= 1

    plan = agent.generate_plan()
    assert len(plan["prioritized_rfcs"]) > 0
    assert len(plan["prioritized_mutations"]) > 0
