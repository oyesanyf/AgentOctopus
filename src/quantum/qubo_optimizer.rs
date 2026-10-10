use crate::quantum::attack_graph::AttackGraph;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;

/// Quadratic Unconstrained Binary Optimization (QUBO) model:
/// E(x) = sum_i a_i * x_i + sum_{i < j} b_{ij} * x_i * x_j
/// where x_i in {0, 1}.
#[derive(Debug, Clone)]
pub struct QuboModel {
    pub num_variables: usize,
    /// Linear coefficients a_i
    pub linear: Vec<f64>,
    /// Quadratic interaction matrix b_{ij} where i < j
    pub quadratic: HashMap<(usize, usize), f64>,
    /// Mapping of variable index to edge in the attack graph (from, to)
    pub var_to_edge: Vec<(usize, usize)>,
}

impl QuboModel {
    pub fn new(num_variables: usize) -> Self {
        Self {
            num_variables,
            linear: vec![0.0; num_variables],
            quadratic: HashMap::new(),
            var_to_edge: Vec::new(),
        }
    }

    /// Evaluates the objective energy of a binary assignment:
    /// E(x) = sum_i a_i * x_i + sum_{i < j} b_{ij} * x_i * x_j
    pub fn energy(&self, x: &[bool]) -> f64 {
        assert_eq!(x.len(), self.num_variables, "State size must match num_variables");
        let mut total = 0.0;

        for (i, &xi) in x.iter().enumerate() {
            if xi {
                total += self.linear[i];
            }
        }

        for (&(i, j), &bij) in &self.quadratic {
            if x[i] && x[j] {
                total += bij;
            }
        }

        total
    }

    /// Constructs a QUBO model from an attack graph to discover unauthorized privilege escalation paths
    /// from a designated entry node to a target node.
    pub fn from_attack_graph(graph: &AttackGraph, start: usize, target: usize) -> Self {
        let edge_count = graph.edges.len();
        let mut model = Self::new(edge_count);
        model.var_to_edge = graph.edges.iter().map(|e| (e.from, e.to)).collect();

        // Penalty multipliers for constraints
        let penalty_flow = 18.0;
        let penalty_branch = 12.0;

        // 1. Objective: minimize traversal cost and reward unauthorized privilege escalation discovery
        for (i, edge) in graph.edges.iter().enumerate() {
            let mut cost = edge.cost;

            // Significant negative energy bonus for reaching the sensitive target
            if edge.to == target {
                cost -= 30.0;
            }

            // Reward discovering subtle unauthorized escalation edges
            if edge.is_unauthorized_transition {
                cost -= 15.0;
            }

            model.linear[i] += cost;
        }

        // 2. Start node constraint: exactly one outgoing edge from start must be active
        // Penalty: P * (sum_{e in out(start)} x_e - 1)^2
        // = P * [ sum x_e + 2 * sum_{i < j} x_i * x_j - 2 * sum x_e + 1 ]
        // = P * [ - sum x_e + 2 * sum_{i < j} x_i * x_j + 1 ]
        let start_out: Vec<usize> = graph
            .edges
            .iter()
            .enumerate()
            .filter(|(_, e)| e.from == start)
            .map(|(i, _)| i)
            .collect();

        for &i in &start_out {
            model.linear[i] -= penalty_flow;
        }
        for (idx, &i) in start_out.iter().enumerate() {
            for &j in &start_out[idx + 1..] {
                let pair = if i < j { (i, j) } else { (j, i) };
                *model.quadratic.entry(pair).or_default() += 2.0 * penalty_flow;
            }
        }

        // 3. Target node constraint: exactly one incoming edge into target must be active
        // Penalty: P * (sum_{e in in(target)} x_e - 1)^2
        let target_in: Vec<usize> = graph
            .edges
            .iter()
            .enumerate()
            .filter(|(_, e)| e.to == target)
            .map(|(i, _)| i)
            .collect();

        for &i in &target_in {
            model.linear[i] -= penalty_flow;
        }
        for (idx, &i) in target_in.iter().enumerate() {
            for &j in &target_in[idx + 1..] {
                let pair = if i < j { (i, j) } else { (j, i) };
                *model.quadratic.entry(pair).or_default() += 2.0 * penalty_flow;
            }
        }

        // 4. Flow conservation at intermediate nodes:
        // For each node v != start && v != target:
        // sum_{e in in(v)} x_e == sum_{e in out(v)} x_e
        // Penalty: P * (sum_{in} x_i - sum_{out} x_j)^2
        for node in &graph.nodes {
            if node.id == start || node.id == target {
                continue;
            }

            let in_edges: Vec<usize> = graph
                .edges
                .iter()
                .enumerate()
                .filter(|(_, e)| e.to == node.id)
                .map(|(i, _)| i)
                .collect();

            let out_edges: Vec<usize> = graph
                .edges
                .iter()
                .enumerate()
                .filter(|(_, e)| e.from == node.id)
                .map(|(i, _)| i)
                .collect();

            if in_edges.is_empty() || out_edges.is_empty() {
                continue;
            }

            // x_i^2 = x_i
            for &i in &in_edges {
                model.linear[i] += penalty_flow;
            }
            for &j in &out_edges {
                model.linear[j] += penalty_flow;
            }

            // +2 * x_i * x_j for pairs in the same group (in-in and out-out)
            for (idx, &i) in in_edges.iter().enumerate() {
                for &j in &in_edges[idx + 1..] {
                    let pair = if i < j { (i, j) } else { (j, i) };
                    *model.quadratic.entry(pair).or_default() += 2.0 * penalty_flow;
                }
            }
            for (idx, &i) in out_edges.iter().enumerate() {
                for &j in &out_edges[idx + 1..] {
                    let pair = if i < j { (i, j) } else { (j, i) };
                    *model.quadratic.entry(pair).or_default() += 2.0 * penalty_flow;
                }
            }

            // -2 * x_i * x_j for cross terms (in-out)
            for &i in &in_edges {
                for &j in &out_edges {
                    let pair = if i < j { (i, j) } else { (j, i) };
                    *model.quadratic.entry(pair).or_default() -= 2.0 * penalty_flow;
                }
            }

            // 5. Anti-branching: prevent nodes from emitting multiple outgoing steps
            for (idx, &i) in out_edges.iter().enumerate() {
                for &j in &out_edges[idx + 1..] {
                    let pair = if i < j { (i, j) } else { (j, i) };
                    *model.quadratic.entry(pair).or_default() += penalty_branch;
                }
            }
        }

        model
    }

    /// Reconstructs valid node paths from the binary edge assignment.
    pub fn extract_paths(&self, state: &[bool], start: usize, target: usize) -> Vec<Vec<usize>> {
        let mut active_edges: Vec<(usize, usize)> = Vec::new();
        for (i, &active) in state.iter().enumerate() {
            if active && i < self.var_to_edge.len() {
                active_edges.push(self.var_to_edge[i]);
            }
        }

        let mut paths = Vec::new();
        let mut visited_edges = vec![false; active_edges.len()];

        for (idx, &(from, to)) in active_edges.iter().enumerate() {
            if from == start && !visited_edges[idx] {
                visited_edges[idx] = true;
                let mut path = vec![from, to];
                let mut current = to;

                while current != target {
                    let mut extended = false;
                    for (next_idx, &(n_from, n_to)) in active_edges.iter().enumerate() {
                        if n_from == current && !visited_edges[next_idx] {
                            visited_edges[next_idx] = true;
                            path.push(n_to);
                            current = n_to;
                            extended = true;
                            break;
                        }
                    }
                    if !extended {
                        break;
                    }
                }

                if current == target {
                    paths.push(path);
                }
            }
        }

        paths
    }
}

/// Configuration parameters for Quantum Annealing with Transverse-Field Tunneling.
#[derive(Debug, Clone)]
pub struct QuantumAnnealerConfig {
    pub num_steps: usize,
    /// Number of Trotter replicas in Path-Integral Monte Carlo
    pub trotter_slices: usize,
    /// Initial transverse field strength Gamma_0
    pub initial_gamma: f64,
    pub final_gamma: f64,
    /// Temperature schedule
    pub initial_temp: f64,
    pub final_temp: f64,
    pub seed: u64,
}

impl Default for QuantumAnnealerConfig {
    fn default() -> Self {
        Self {
            num_steps: 1200,
            trotter_slices: 8,
            initial_gamma: 3.5,
            final_gamma: 0.01,
            initial_temp: 2.0,
            final_temp: 0.05,
            seed: 42,
        }
    }
}

/// Result returned by the Simulated Quantum Annealing engine.
#[derive(Debug, Clone)]
pub struct QuboResult {
    pub best_state: Vec<bool>,
    pub best_energy: f64,
    pub paths_discovered: Vec<Vec<usize>>,
    pub iterations: usize,
    pub tunneling_events: usize,
}

/// Simulated Quantum Annealer implementing Path-Integral Monte Carlo (PIMC)
/// with transverse field quantum tunneling across Trotter slices.
pub struct SimulatedQuantumAnnealer {
    config: QuantumAnnealerConfig,
}

impl SimulatedQuantumAnnealer {
    pub fn new(config: QuantumAnnealerConfig) -> Self {
        Self { config }
    }

    /// Solves the QUBO problem using Simulated Quantum Annealing (SQA).
    pub fn solve(&self, model: &QuboModel, start: usize, target: usize) -> QuboResult {
        let n = model.num_variables;
        let m = self.config.trotter_slices;
        let mut rng = StdRng::seed_from_u64(self.config.seed);

        // M Trotter replicas (slices) initialized randomly
        let mut replicas: Vec<Vec<bool>> = (0..m)
            .map(|_| (0..n).map(|_| rng.gen_bool(0.1)).collect())
            .collect();

        let mut best_state = replicas[0].clone();
        let mut best_energy = model.energy(&best_state);
        let mut tunneling_events = 0;

        for step in 0..self.config.num_steps {
            let progress = step as f64 / self.config.num_steps as f64;

            // Annealing schedules: Gamma(t) drops to 0, Temp drops to final_temp
            let gamma = self.config.initial_gamma * (1.0 - progress) + self.config.final_gamma * progress;
            let temp = self.config.initial_temp * (1.0 - progress) + self.config.final_temp * progress;

            // Inter-slice quantum coupling: J_perp = -0.5 * T * ln(tanh(Gamma / (M * T)))
            let arg = (gamma / (m as f64 * temp.max(1e-4))).clamp(1e-6, 15.0);
            let j_perp = -0.5 * temp * arg.tanh().ln().clamp(-20.0, 0.0);

            // Update each Trotter slice
            for slice in 0..m {
                let prev_slice = (slice + m - 1) % m;
                let next_slice = (slice + 1) % m;

                for bit in 0..n {
                    // 1. Classical energy difference for flipping bit in this slice
                    let mut flipped = replicas[slice].clone();
                    flipped[bit] = !flipped[bit];

                    let current_e = model.energy(&replicas[slice]);
                    let flipped_e = model.energy(&flipped);
                    let delta_classical = (flipped_e - current_e) / m as f64;

                    // 2. Quantum transverse coupling penalty along imaginary time
                    let s_curr = if replicas[slice][bit] { 1.0 } else { -1.0 };
                    let s_flip = -s_curr;
                    let s_prev = if replicas[prev_slice][bit] { 1.0 } else { -1.0 };
                    let s_next = if replicas[next_slice][bit] { 1.0 } else { -1.0 };

                    let quantum_coupling_before = -j_perp * s_curr * (s_prev + s_next);
                    let quantum_coupling_after = -j_perp * s_flip * (s_prev + s_next);
                    let delta_quantum = quantum_coupling_after - quantum_coupling_before;

                    let total_delta = delta_classical + delta_quantum;

                    // Metropolis-Hastings acceptance criterion
                    let accept = if total_delta <= 0.0 {
                        true
                    } else {
                        let p = (-total_delta / temp.max(1e-4)).exp();
                        rng.gen::<f64>() < p
                    };

                    if accept {
                        replicas[slice][bit] = flipped[bit];

                        // Quantum tunneling check: flip accepted even if delta_classical > 0
                        if delta_classical > 1.5 && total_delta <= 0.0 {
                            tunneling_events += 1;
                        }

                        let slice_energy = model.energy(&replicas[slice]);
                        if slice_energy < best_energy {
                            best_energy = slice_energy;
                            best_state = replicas[slice].clone();
                        }
                    }
                }
            }
        }

        let paths_discovered = model.extract_paths(&best_state, start, target);

        QuboResult {
            best_state,
            best_energy,
            paths_discovered,
            iterations: self.config.num_steps,
            tunneling_events,
        }
    }

    /// Solves the QUBO model using classical Simulated Annealing (single replica, zero tunneling).
    pub fn solve_classical_baseline(&self, model: &QuboModel, start: usize, target: usize) -> QuboResult {
        let n = model.num_variables;
        let mut rng = StdRng::seed_from_u64(self.config.seed);

        let mut current_state: Vec<bool> = (0..n).map(|_| rng.gen_bool(0.1)).collect();
        let mut best_state = current_state.clone();
        let mut best_energy = model.energy(&best_state);

        for step in 0..self.config.num_steps {
            let progress = step as f64 / self.config.num_steps as f64;
            let temp = self.config.initial_temp * (1.0 - progress) + self.config.final_temp * progress;

            for bit in 0..n {
                let mut candidate = current_state.clone();
                candidate[bit] = !candidate[bit];

                let cur_e = model.energy(&current_state);
                let cand_e = model.energy(&candidate);
                let delta = cand_e - cur_e;

                let accept = if delta <= 0.0 {
                    true
                } else {
                    let p = (-delta / temp.max(1e-4)).exp();
                    rng.gen::<f64>() < p
                };

                if accept {
                    current_state = candidate;
                    if cand_e < best_energy {
                        best_energy = cand_e;
                        best_state = current_state.clone();
                    }
                }
            }
        }

        let paths_discovered = model.extract_paths(&best_state, start, target);

        QuboResult {
            best_state,
            best_energy,
            paths_discovered,
            iterations: self.config.num_steps,
            tunneling_events: 0,
        }
    }
}
