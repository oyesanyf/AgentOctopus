"""
Protocol Research Engine package for HTTP Terminator and Agent Octopus.
"""

from engine.taxonomy import (
    AnomalyCategory,
    Arm106DefensiveRule,
    Arm107RegressionTest,
    ImpactClass,
    ImplementationAnomaly,
    NovelTechnique,
    ReproducibleVulnerability,
    RFCRequirement,
    RequirementType,
)
from engine.caldera_bridge import CalderaBridge
from engine.terminator_rfc_selector import TerminatorRFCSelector, TERMINATOR_CORE_RFCS

__all__ = [
    "AnomalyCategory",
    "Arm106DefensiveRule",
    "Arm107RegressionTest",
    "CalderaBridge",
    "ImpactClass",
    "ImplementationAnomaly",
    "NovelTechnique",
    "ReproducibleVulnerability",
    "RFCRequirement",
    "RequirementType",
    "TerminatorRFCSelector",
    "TERMINATOR_CORE_RFCS",
]

