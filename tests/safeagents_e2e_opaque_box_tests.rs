//! ==============================================================================
//! [AGENT OCTOPUS] SAFEAGENTS E2E OPAQUE-BOX TEST BATTERY (TIERS 1 - 4)
//! ==============================================================================
//! Comprehensive end-to-end opaque-box test runner validating all features
//! across Tier 1 (Feature Coverage), Tier 2 (Boundary & Corner Cases),
//! Tier 3 (Cross-Feature Combinations), and Tier 4 (Real-World Scenarios).
//! ==============================================================================

#[path = "safeagents_e2e/contract.rs"]
pub mod contract;

#[path = "safeagents_e2e/tier1.rs"]
pub mod tier1_feature_coverage;

#[path = "safeagents_e2e/tier2.rs"]
pub mod tier2_boundary_corner;

#[path = "safeagents_e2e/tier3.rs"]
pub mod tier3_combinations;

#[path = "safeagents_e2e/tier4.rs"]
pub mod tier4_real_world;
