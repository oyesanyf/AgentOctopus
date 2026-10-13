#!/usr/bin/env python3
"""
CLI entrypoint for Open Dream-RSI Worker.
Operates strictly offline without socket access.
"""

import argparse
import json
import sys
import os

from trajectory_buffer import TrajectoryBuffer
from world_model import WorldModel
from policy_agent import PolicyAgent

def main():
    parser = argparse.ArgumentParser(description="Open Dream-RSI Worker")
    parser.add_argument("--mode", choices=["status", "train", "rollout", "recommend"], default="status")
    parser.add_argument("--trajectories", default="data/protocol_research/evaluation_history.jsonl")
    parser.add_argument("--generations", type=int, default=10)
    parser.add_argument("--steps", type=int, default=1000)
    args = parser.parse_args()

    # Strict Process-Scoped Offline Safety Guard
    os.environ["DREAM_RSI_OFFLINE"] = "1"

    tb = TrajectoryBuffer()
    if os.path.exists(args.trajectories):
        loaded = tb.load_from_file(args.trajectories)
    else:
        loaded = 0

    wm = WorldModel()
    if tb.get_events():
        wm.train_from_events(tb.get_events())

    agent = PolicyAgent(wm)

    if args.mode == "status":
        res = {
            "status": "OPERATIONAL_OFFLINE",
            "historical_trajectories": loaded,
            "world_model_states": len(wm.transitions),
            "policy_generation": agent.policy["generation"],
        }
        print(json.dumps(res, indent=2))

    elif args.mode == "train":
        evolved = agent.train_policy(generations=args.generations, steps_per_gen=args.steps)
        plan = agent.generate_plan()
        res = {
            "status": "TRAINED",
            "evolved_policy": evolved,
            "experiment_plan": plan,
        }
        print(json.dumps(res, indent=2))

    elif args.mode == "rollout":
        rep = agent.simulate_rollout(agent.policy, steps=args.steps)
        print(json.dumps(rep, indent=2))

    elif args.mode == "recommend":
        plan = agent.generate_plan()
        print(json.dumps(plan, indent=2))

if __name__ == "__main__":
    main()
