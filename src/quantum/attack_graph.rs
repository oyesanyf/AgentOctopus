use crate::core::types::ArmRole;
use std::collections::{HashMap, VecDeque};

/// Type of communication or delegation channel connecting two agents in the swarm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChannelType {
    /// Direct Inter-Process Communication channel.
    DirectIpc,
    /// HMAC-signed capability delegation channel.
    DelegatedCapability,
    /// Shared filesystem or artifact drop zone.
    SharedArtifactDrop,
    /// Shared memory segment or named pipe.
    NamedPipe,
    /// External network egress bridge.
    ExternalNetworkEgress,
}

/// A node in the 50-agent swarm attack graph.
#[derive(Debug, Clone)]
pub struct AgentNode {
    pub id: usize,
    pub name: String,
    pub role: ArmRole,
    pub privilege_level: u8,
    pub capabilities: Vec<String>,
    pub is_target: bool,
    pub is_entry_point: bool,
}

/// A directed edge representing an interaction or delegation channel between two agents.
#[derive(Debug, Clone)]
pub struct AttackEdge {
    pub from: usize,
    pub to: usize,
    pub channel_type: ChannelType,
    /// Cost of traversing or exploiting this channel (lower = easier).
    pub cost: f64,
    /// Probability of successful lateral exploitation.
    pub exploit_probability: f64,
    /// Whether this transition violates least-privilege or segregation policies.
    pub is_unauthorized_transition: bool,
}

/// Attack graph representation of the 50-agent swarm.
/// Maps agent roles, delegation channels, and permitted interactions.
#[derive(Debug, Clone)]
pub struct AttackGraph {
    pub nodes: Vec<AgentNode>,
    pub edges: Vec<AttackEdge>,
    adj_list: HashMap<usize, Vec<usize>>,
}

impl AttackGraph {
    /// Creates a new empty attack graph.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            adj_list: HashMap::new(),
        }
    }

    /// Adds an agent node to the graph.
    pub fn add_node(&mut self, node: AgentNode) {
        self.adj_list.entry(node.id).or_default();
        self.nodes.push(node);
    }

    /// Adds a directed edge to the graph.
    pub fn add_edge(&mut self, edge: AttackEdge) {
        let edge_idx = self.edges.len();
        self.adj_list.entry(edge.from).or_default().push(edge_idx);
        self.edges.push(edge);
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn get_node(&self, id: usize) -> Option<&AgentNode> {
        self.nodes.get(id)
    }

    pub fn get_edges_from(&self, from_id: usize) -> Vec<&AttackEdge> {
        if let Some(edge_indices) = self.adj_list.get(&from_id) {
            edge_indices.iter().map(|&idx| &self.edges[idx]).collect()
        } else {
            Vec::new()
        }
    }

    /// Constructs a realistic, comprehensive 50-agent swarm topology:
    /// - Nodes 0..15: Untrusted Document Ingestion workers (Entry Points, privilege 1)
    /// - Nodes 16..30: Intermediate Data Transformers & Aggregators (privilege 2)
    /// - Nodes 31..42: Specialized Verification & Tool Exec Arms (privilege 3)
    /// - Nodes 43..47: Protected Ledger Writers & Egress Gates (privilege 4)
    /// - Nodes 48..49: Central Brain Supervisors (High-Value Targets, privilege 5)
    pub fn new_50_agent_swarm() -> Self {
        let mut graph = Self::new();

        for i in 0..50 {
            let (role, priv_level, caps, is_target, is_entry) = match i {
                0..=15 => (
                    ArmRole::UntrustedDocIngest,
                    1,
                    vec!["doc_extractor".to_string(), "pdf_parse".to_string()],
                    false,
                    true,
                ),
                16..=30 => (
                    ArmRole::OutboundNotification,
                    2,
                    vec!["normalize_data".to_string(), "token_counter".to_string()],
                    false,
                    false,
                ),
                31..=42 => (
                    ArmRole::UntrustedDocIngest,
                    3,
                    vec!["schema_guard".to_string(), "policy_check".to_string()],
                    false,
                    false,
                ),
                43..=45 => (
                    ArmRole::AccountingLedgerWrite,
                    4,
                    vec!["ledger_writer".to_string(), "append_receipt".to_string()],
                    true,
                    false,
                ),
                46..=47 => (
                    ArmRole::NetworkEgress,
                    4,
                    vec!["http_gate".to_string(), "google_egress".to_string()],
                    true,
                    false,
                ),
                _ => (
                    ArmRole::AccountingLedgerWrite,
                    5,
                    vec![
                        "master_auth".to_string(),
                        "circuit_breaker".to_string(),
                        "revoke_token".to_string(),
                    ],
                    true,
                    false,
                ),
            };

            graph.add_node(AgentNode {
                id: i,
                name: format!("arm-worker-{:02}", i),
                role,
                privilege_level: priv_level,
                capabilities: caps,
                is_target,
                is_entry_point: is_entry,
            });
        }

        // 1. Legitimate pipeline edges: Ingest (0..15) -> Transformers (16..30)
        for ingest in 0..16 {
            let target_transformer = 16 + (ingest % 15);
            graph.add_edge(AttackEdge {
                from: ingest,
                to: target_transformer,
                channel_type: ChannelType::SharedArtifactDrop,
                cost: 2.0,
                exploit_probability: 0.25,
                is_unauthorized_transition: false,
            });
        }

        // 2. Transformer (16..30) -> Verification (31..42)
        for trans in 16..31 {
            let target_verify = 31 + (trans % 12);
            graph.add_edge(AttackEdge {
                from: trans,
                to: target_verify,
                channel_type: ChannelType::DirectIpc,
                cost: 2.5,
                exploit_probability: 0.20,
                is_unauthorized_transition: false,
            });
        }

        // 3. Verification (31..42) -> Protected Ledger Writers (43..45) & Egress (46..47)
        for verif in 31..43 {
            let target_ledger = 43 + (verif % 3);
            graph.add_edge(AttackEdge {
                from: verif,
                to: target_ledger,
                channel_type: ChannelType::DelegatedCapability,
                cost: 4.0,
                exploit_probability: 0.15,
                is_unauthorized_transition: false,
            });
        }

        // 4. Subtle / Lateral Escalation Channels (Confused Deputy & Over-Delegation Vulnerabilities)
        // Agent 5 (Ingest) has an accidental direct named pipe to Agent 20 (Transformer)
        graph.add_edge(AttackEdge {
            from: 5,
            to: 20,
            channel_type: ChannelType::NamedPipe,
            cost: 1.0,
            exploit_probability: 0.85,
            is_unauthorized_transition: false,
        });

        // Agent 20 has a dangerous cross-delegation capability to Ledger Writer 44
        graph.add_edge(AttackEdge {
            from: 20,
            to: 44,
            channel_type: ChannelType::DelegatedCapability,
            cost: 1.5,
            exploit_probability: 0.75,
            is_unauthorized_transition: true, // Bypasses verification arm!
        });

        // Agent 11 (Ingest) shares an unpartitioned memory ring with Agent 38
        graph.add_edge(AttackEdge {
            from: 11,
            to: 38,
            channel_type: ChannelType::DirectIpc,
            cost: 1.2,
            exploit_probability: 0.80,
            is_unauthorized_transition: true, // Direct jump from Ingest to Verification!
        });

        // Agent 38 has an unauthorized debug bridge to Supervisor Brain 48
        graph.add_edge(AttackEdge {
            from: 38,
            to: 48,
            channel_type: ChannelType::NamedPipe,
            cost: 1.8,
            exploit_probability: 0.65,
            is_unauthorized_transition: true, // Privilege escalation to Supervisor!
        });

        // Agent 8 -> Agent 46 (Direct egress leak attempt)
        graph.add_edge(AttackEdge {
            from: 8,
            to: 46,
            channel_type: ChannelType::ExternalNetworkEgress,
            cost: 3.5,
            exploit_probability: 0.30,
            is_unauthorized_transition: true,
        });

        // Inter-worker peer communication among transformers
        for i in 16..30 {
            graph.add_edge(AttackEdge {
                from: i,
                to: i + 1,
                channel_type: ChannelType::DirectIpc,
                cost: 3.0,
                exploit_probability: 0.10,
                is_unauthorized_transition: false,
            });
        }

        graph
    }

    /// Computes the graph adjacency matrix where A[i][j] is the weight/exploit probability.
    pub fn adjacency_matrix(&self) -> Vec<Vec<f64>> {
        let n = self.nodes.len();
        let mut matrix = vec![vec![0.0; n]; n];

        for edge in &self.edges {
            if edge.from < n && edge.to < n {
                matrix[edge.from][edge.to] = edge.exploit_probability;
            }
        }

        matrix
    }

    /// Computes the unnormalized graph Laplacian matrix: L = D - A
    pub fn laplacian_matrix(&self) -> Vec<Vec<f64>> {
        let n = self.nodes.len();
        let adj = self.adjacency_matrix();
        let mut laplacian = vec![vec![0.0; n]; n];

        for i in 0..n {
            let mut degree = 0.0;
            for j in 0..n {
                if adj[i][j] > 0.0 {
                    degree += adj[i][j];
                    laplacian[i][j] = -adj[i][j];
                }
            }
            laplacian[i][i] = degree;
        }

        laplacian
    }

    /// Checks if a traversal path includes unauthorized privilege transitions.
    pub fn is_path_unauthorized(&self, path: &[usize]) -> bool {
        if path.len() < 2 {
            return false;
        }

        for window in path.windows(2) {
            let from = window[0];
            let to = window[1];

            // If edge is flagged unauthorized
            for edge in self.get_edges_from(from) {
                if edge.to == to && edge.is_unauthorized_transition {
                    return true;
                }
            }

            // Or if privilege gap jumps by >= 2 levels without proper verification
            if let (Some(n1), Some(n2)) = (self.get_node(from), self.get_node(to)) {
                if n2.privilege_level > n1.privilege_level + 1 {
                    return true;
                }
            }
        }

        false
    }

    /// Classical Breadth-First Search (BFS) finding shortest hop path.
    pub fn classical_bfs(&self, start: usize, target: usize) -> Option<Vec<usize>> {
        if start == target {
            return Some(vec![start]);
        }

        let mut queue = VecDeque::new();
        let mut visited = HashMap::new();

        queue.push_back(start);
        visited.insert(start, None);

        while let Some(current) = queue.pop_front() {
            if current == target {
                let mut path = Vec::new();
                let mut curr_node = Some(target);
                while let Some(node) = curr_node {
                    path.push(node);
                    curr_node = visited.get(&node).copied().flatten();
                }
                path.reverse();
                return Some(path);
            }

            for edge in self.get_edges_from(current) {
                if !visited.contains_key(&edge.to) {
                    visited.insert(edge.to, Some(current));
                    queue.push_back(edge.to);
                }
            }
        }

        None
    }

    /// Classical Dijkstra shortest-cost pathfinder.
    pub fn classical_dijkstra(&self, start: usize, target: usize) -> Option<(Vec<usize>, f64)> {
        let n = self.nodes.len();
        let mut dist = vec![f64::INFINITY; n];
        let mut prev = vec![None; n];
        let mut visited = vec![false; n];

        dist[start] = 0.0;

        for _ in 0..n {
            let mut u = None;
            let mut min_d = f64::INFINITY;

            for i in 0..n {
                if !visited[i] && dist[i] < min_d {
                    min_d = dist[i];
                    u = Some(i);
                }
            }

            let u = match u {
                Some(idx) => idx,
                None => break,
            };

            visited[u] = true;
            if u == target {
                break;
            }

            for edge in self.get_edges_from(u) {
                let alt = dist[u] + edge.cost;
                if alt < dist[edge.to] {
                    dist[edge.to] = alt;
                    prev[edge.to] = Some(u);
                }
            }
        }

        if dist[target].is_infinite() {
            return None;
        }

        let mut path = Vec::new();
        let mut curr = Some(target);
        while let Some(u) = curr {
            path.push(u);
            curr = prev[u];
        }
        path.reverse();

        Some((path, dist[target]))
    }

    /// Discovers all paths up to max_depth using depth-limited search.
    pub fn find_all_paths(&self, start: usize, target: usize, max_depth: usize) -> Vec<Vec<usize>> {
        let mut all_paths = Vec::new();
        let mut current_path = vec![start];
        let mut visited = vec![false; self.nodes.len()];
        visited[start] = true;

        self.dfs_paths(
            start,
            target,
            max_depth,
            &mut current_path,
            &mut visited,
            &mut all_paths,
        );
        all_paths
    }

    fn dfs_paths(
        &self,
        current: usize,
        target: usize,
        max_depth: usize,
        current_path: &mut Vec<usize>,
        visited: &mut [bool],
        all_paths: &mut Vec<Vec<usize>>,
    ) {
        if current == target {
            all_paths.push(current_path.clone());
            return;
        }

        if current_path.len() > max_depth {
            return;
        }

        for edge in self.get_edges_from(current) {
            let next = edge.to;
            if !visited[next] {
                visited[next] = true;
                current_path.push(next);
                self.dfs_paths(next, target, max_depth, current_path, visited, all_paths);
                current_path.pop();
                visited[next] = false;
            }
        }
    }
}
