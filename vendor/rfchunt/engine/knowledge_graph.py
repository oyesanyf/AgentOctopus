"""
Module 11: Coverage and Research Knowledge Graph (P1).

Maintains a bipartite knowledge graph of RFC specifications, ABNF grammar tokens,
normative requirements, discovered anomalies, and novel techniques to uncover
untested specification blind spots.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class GraphNode:
    node_id: str
    node_type: str  # 'RFC', 'SECTION', 'GRAMMAR', 'REQUIREMENT', 'ANOMALY', 'VULNERABILITY', 'TECHNIQUE'
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str  # 'CONTAINS', 'DEFINES', 'TESTED_BY', 'PROVES_VULN', 'GENERALIZED_TO'


class ResearchKnowledgeGraph:
    """
    Maintains graph relationships and identifies coverage gaps across RFC specifications.
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_adjacency: Dict[str, Set[str]] = defaultdict(set)

    def add_node(self, node_id: str, node_type: str, label: str, attributes: Optional[Dict[str, Any]] = None) -> GraphNode:
        node = GraphNode(node_id=node_id, node_type=node_type, label=label, attributes=attributes or {})
        self.nodes[node_id] = node
        return node

    def add_edge(self, source_id: str, target_id: str, relationship: str) -> None:
        self.edges.append(GraphEdge(source_id=source_id, target_id=target_id, relationship=relationship))
        self.adjacency[source_id].add(target_id)
        self.reverse_adjacency[target_id].add(source_id)

    def record_testing_event(self, requirement_id: str, outcome_node_id: str, is_vulnerability: bool = False):
        """Connects a test outcome to an RFC requirement node."""
        rel = "PROVES_VULN" if is_vulnerability else "TESTED_BY"
        self.add_edge(requirement_id, outcome_node_id, rel)

    def calculate_specification_coverage(self) -> Dict[str, Any]:
        """
        Calculates test coverage across extracted specification requirements
        and returns unvisited 'blind spots'.
        """
        requirements = [n for n in self.nodes.values() if n.node_type == "REQUIREMENT"]
        if not requirements:
            return {"coverage_percent": 0.0, "total_requirements": 0, "tested_count": 0, "blind_spots": []}

        tested = []
        untested = []

        for req in requirements:
            # Check if this node has outgoing edges to tests/anomalies/probes
            targets = self.adjacency.get(req.node_id, set())
            if targets:
                tested.append(req.node_id)
            else:
                untested.append(req.node_id)

        pct = (len(tested) / len(requirements)) * 100.0 if requirements else 0.0

        return {
            "coverage_percent": round(pct, 2),
            "total_requirements": len(requirements),
            "tested_count": len(tested),
            "untested_count": len(untested),
            "blind_spots": untested[:20],  # Return up to 20 immediate gaps
        }

    def get_lineage_trace(self, vuln_id: str) -> List[Dict[str, str]]:
        """Traces a confirmed vulnerability back to its originating RFC and section."""
        trace = []
        current = vuln_id

        # Trace backwards along reverse adjacency
        visited = set()
        while current and current not in visited:
            visited.add(current)
            node = self.nodes.get(current)
            if node:
                trace.append({"node_id": node.node_id, "type": node.node_type, "label": node.label})
            parents = self.reverse_adjacency.get(current, set())
            current = list(parents)[0] if parents else None

        return trace
