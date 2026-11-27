"""Opaque-box 4-tier E2E verification suite for AgentOctopus Lean 4 formal verification."""

from __future__ import annotations

__version__ = "0.1.0"

TIER_NAMES = {
    1: "Tier 1: Feature Behavior (Category-Partition)",
    2: "Tier 2: Boundary & Negative Cases (BVA)",
    3: "Tier 3: Pairwise Feature Combinations",
    4: "Tier 4: Real-World End-to-End Scenarios",
}

FEATURE_INVENTORY = {
    "F1": "Lean 4 Toolchain & Lake Project",
    "F2": "Core Types & Trust Tier Total Map",
    "F3": "Deterministic 6-State Arm FSM & PolicyGuard",
    "F4": "Homological Mesh & Delegation Guards",
    "F5": "Epoch Autotomy & Dirac/3-Layer Gates",
    "F6": "CAGE NoDirectBind BFS, Routing Seal & CBF",
    "F7": "Cedar PARC & Dogwood Temporal MFOTL",
    "F8": "AgentMesh Mandate Attenuation & M-of-N Quorum",
    "F9": "Path/Sandbox, SSRF, TokenPosture, Shield & Sentinel",
    "F10": "Master no_breakout & no_breach Theorems + Axiom Audit",
    "F11": "Rust-to-Lean 1-to-1 Consistency Tests",
    "F12": "Lean Verification CI Workflow",
    "F13": "Opaque-Box E2E Verification Suite Self-Integrity",
    "F14": "Final Shipping Readiness, Packaging & Repo Hygiene",
}
