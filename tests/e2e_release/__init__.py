"""Opaque-box 4-tier release E2E verification suite for AgentOctopus."""

__version__ = "0.1.0"

TIER_NAMES = {
    1: "Tier 1: Feature Behavior (Category-Partition)",
    2: "Tier 2: Boundary & Negative Cases (BVA)",
    3: "Tier 3: Pairwise Feature Combinations",
    4: "Tier 4: Real-World Scenarios & Release Gates",
    5: "Tier 5: Adversarial Hardening & Regression Probes",
}

FEATURE_AREAS = {
    "F1": "Deterministic Containment & Policy Enforcement",
    "F2": "D3QN Default-Off & Non-Interference Invariants",
    "F3": "CLI UX, Subcommands, Flags & Exit Codes",
    "F4": "Repo Hygiene & History Preservation",
    "F5": "Positioning, Docs & Quickstart Parity",
    "F6": "Workspace Boundaries, Sibling Immutability & GitHub Metadata",
}
