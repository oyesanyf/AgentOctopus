use serde::{Deserialize, Serialize};

/// Discrete Progressive Action Space (A_t) for Autonomous Active Defense (inspired by OshoosiClaw EDR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AdaptiveDefenseAction {
    /// Level 0: Default telemetry logging, passive monitoring.
    PassiveObserve = 0,
    /// Level 1: Verbose tool parameter tracing, AST verification, and capability verification.
    TraceElevation = 1,
    /// Level 2: In-memory scratchpad scan, cross-agent state audit, environment token leak detection.
    MemoryIntrospection = 2,
    /// Level 3: Dynamic tarpit delay injection, drop unapproved sockets, suspend suspicious execution threads.
    MicroContainment = 3,
    /// Level 4: Hardware autotomy kill-switch, Windows Job Object termination, permanent capability revocation.
    HardMitigation = 4,
}

impl AdaptiveDefenseAction {
    pub const ALL_ACTIONS: [AdaptiveDefenseAction; 5] = [
        AdaptiveDefenseAction::PassiveObserve,
        AdaptiveDefenseAction::TraceElevation,
        AdaptiveDefenseAction::MemoryIntrospection,
        AdaptiveDefenseAction::MicroContainment,
        AdaptiveDefenseAction::HardMitigation,
    ];

    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::PassiveObserve,
            1 => Self::TraceElevation,
            2 => Self::MemoryIntrospection,
            3 => Self::MicroContainment,
            4 => Self::HardMitigation,
            _ => Self::PassiveObserve,
        }
    }

    pub fn to_index(self) -> usize {
        self as usize
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PassiveObserve => "PassiveObserve",
            Self::TraceElevation => "TraceElevation",
            Self::MemoryIntrospection => "MemoryIntrospection",
            Self::MicroContainment => "MicroContainment",
            Self::HardMitigation => "HardMitigation",
        }
    }

    pub fn is_containment(self) -> bool {
        matches!(self, Self::MicroContainment | Self::HardMitigation)
    }

    pub fn is_inspection(self) -> bool {
        matches!(self, Self::TraceElevation | Self::MemoryIntrospection)
    }

    pub fn tier_description(self) -> &'static str {
        match self {
            Self::PassiveObserve => "Tier 0: Passive telemetry & zero friction monitoring",
            Self::TraceElevation => "Tier 1: Deep parameter schema & AST tracing",
            Self::MemoryIntrospection => "Tier 2: Scratchpad & cross-agent memory inspection",
            Self::MicroContainment => "Tier 3: Active tarpit throttle & network socket suspension",
            Self::HardMitigation => "Tier 4: Immediate process autotomy & hardware kill-switch",
        }
    }
}
