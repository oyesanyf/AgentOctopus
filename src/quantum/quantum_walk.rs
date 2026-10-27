use crate::quantum::attack_graph::AttackGraph;

/// Complex number structure for pure-Rust quantum state manipulations.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

impl Complex {
    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    pub fn zero() -> Self {
        Self { re: 0.0, im: 0.0 }
    }

    pub fn norm_sq(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }

    pub fn add(&self, other: &Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }

    pub fn mul(&self, other: &Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }

    pub fn scale(&self, s: f64) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }
}

/// Comparison metrics between quantum walk and classical random walk lateral spread.
#[derive(Debug, Clone)]
pub struct WalkComparison {
    pub quantum_probabilities: Vec<f64>,
    pub classical_probabilities: Vec<f64>,
    pub quantum_entropy: f64,
    pub classical_entropy: f64,
    pub ballistic_spread_speedup: f64,
}

/// Quantum Walk Simulator across the 50-agent swarm adjacency network.
/// Simulates both Continuous-Time Quantum Walks (CTQW) via graph Hamiltonian evolution
/// and Discrete-Time Quantum Walks (DTQW) with coin operators.
#[derive(Debug, Clone)]
pub struct QuantumWalkSimulator {
    pub num_nodes: usize,
    pub hamiltonian: Vec<Vec<f64>>,
    pub adjacency: Vec<Vec<f64>>,
}

impl QuantumWalkSimulator {
    /// Constructs a new simulator from a swarm AttackGraph using the Hermitian graph Laplacian.
    pub fn from_attack_graph(graph: &AttackGraph) -> Self {
        let n = graph.nodes.len();
        let adj = graph.adjacency_matrix();
        let mut sym_adj = vec![vec![0.0; n]; n];
        let mut hamiltonian = vec![vec![0.0; n]; n];

        for i in 0..n {
            for j in 0..n {
                let weight = (adj[i][j] + adj[j][i]) * 0.5;
                if weight > 0.0 {
                    sym_adj[i][j] = weight;
                }
            }
        }

        for i in 0..n {
            let mut deg = 0.0;
            for j in 0..n {
                if sym_adj[i][j] > 0.0 {
                    deg += sym_adj[i][j];
                    hamiltonian[i][j] = -sym_adj[i][j];
                }
            }
            hamiltonian[i][i] = deg;
        }

        Self {
            num_nodes: n,
            hamiltonian,
            adjacency: adj,
        }
    }

    /// Simulates a Continuous-Time Quantum Walk (CTQW):
    /// |psi(t)> = exp(-i * H * t) |psi(0)>
    /// Returns the probability distribution P(j) = |<j|psi(t)>|^2 over all 50 agent nodes.
    pub fn simulate_continuous_walk(
        &self,
        start_node: usize,
        total_time: f64,
        steps: usize,
    ) -> Vec<f64> {
        let n = self.num_nodes;
        assert!(start_node < n, "start_node out of bounds");

        // Initial state: localized at start_node |psi(0)> = |start>
        let mut state = vec![Complex::zero(); n];
        state[start_node] = Complex::new(1.0, 0.0);

        let dt = total_time / steps.max(1) as f64;

        for _ in 0..steps {
            state = self.propagate_step_taylor(&state, dt);
        }

        // Compute probability distribution
        let mut probs: Vec<f64> = state.iter().map(|c| c.norm_sq()).collect();
        let sum: f64 = probs.iter().sum();
        if sum > 0.0 {
            for p in &mut probs {
                *p /= sum;
            }
        }

        probs
    }

    /// Unitary time step propagation via 6th-order Taylor series expansion:
    /// exp(-i * H * dt) |psi> = sum_{k=0}^6 ((-i * dt)^k / k!) * H^k |psi>
    fn propagate_step_taylor(&self, state: &[Complex], dt: f64) -> Vec<Complex> {
        let n = self.num_nodes;
        let mut result = state.to_vec();
        let mut current_term = state.to_vec();

        let mut factorial = 1.0;
        for k in 1..=6 {
            factorial *= k as f64;

            // Multiply H * current_term
            let mut h_term = vec![Complex::zero(); n];
            for i in 0..n {
                let mut sum = Complex::zero();
                for j in 0..n {
                    let h_ij = self.hamiltonian[i][j];
                    if h_ij.abs() > 1e-9 {
                        sum = sum.add(&current_term[j].scale(h_ij));
                    }
                }
                h_term[i] = sum;
            }

            // Factor (-i * dt)^k / k!
            // Note: (-i)^1 = -i, (-i)^2 = -1, (-i)^3 = +i, (-i)^4 = +1
            let coeff = match k % 4 {
                1 => Complex::new(0.0, -dt.powi(k as i32) / factorial),
                2 => Complex::new(-dt.powi(k as i32) / factorial, 0.0),
                3 => Complex::new(0.0, dt.powi(k as i32) / factorial),
                _ => Complex::new(dt.powi(k as i32) / factorial, 0.0),
            };

            for i in 0..n {
                let step_addition = h_term[i].mul(&coeff);
                result[i] = result[i].add(&step_addition);
            }

            current_term = h_term;
        }

        // Re-normalize state vector to maintain strict unitarity
        let norm: f64 = result.iter().map(|c| c.norm_sq()).sum::<f64>().sqrt();
        if norm > 1e-12 {
            for c in &mut result {
                *c = c.scale(1.0 / norm);
            }
        }

        result
    }

    /// Classical Markov Random Walk lateral spread simulation:
    /// p(t+1) = M * p(t)
    pub fn simulate_classical_walk(&self, start_node: usize, steps: usize) -> Vec<f64> {
        let n = self.num_nodes;
        let mut p = vec![0.0; n];
        p[start_node] = 1.0;

        // Transition probability matrix M_ij = A_ij / deg(j)
        let mut m = vec![vec![0.0; n]; n];
        for j in 0..n {
            let deg: f64 = (0..n).map(|i| self.adjacency[j][i]).sum();
            if deg > 0.0 {
                for i in 0..n {
                    m[i][j] = self.adjacency[j][i] / deg;
                }
            } else {
                m[j][j] = 1.0; // Absorbing state
            }
        }

        for _ in 0..steps {
            let mut next_p = vec![0.0; n];
            for i in 0..n {
                let mut sum = 0.0;
                for j in 0..n {
                    sum += m[i][j] * p[j];
                }
                next_p[i] = sum;
            }
            p = next_p;
        }

        p
    }

    /// Compares lateral movement propagation speed between Quantum Walk and Classical Walk.
    pub fn compare_spread(&self, start_node: usize, time_or_steps: usize) -> WalkComparison {
        let quantum_probs =
            self.simulate_continuous_walk(start_node, time_or_steps as f64 * 0.4, 25);
        let classical_probs = self.simulate_classical_walk(start_node, time_or_steps);

        let q_entropy = shannon_entropy(&quantum_probs);
        let c_entropy = shannon_entropy(&classical_probs);

        let speedup = if c_entropy > 1e-6 {
            q_entropy / c_entropy
        } else {
            1.0
        };

        WalkComparison {
            quantum_probabilities: quantum_probs,
            classical_probabilities: classical_probs,
            quantum_entropy: q_entropy,
            classical_entropy: c_entropy,
            ballistic_spread_speedup: speedup,
        }
    }

    /// Identifies critical lateral movement chokepoints:
    /// Nodes that accumulate disproportionate quantum probability mass when initialized from entry points.
    pub fn identify_critical_lateral_chokepoints(
        &self,
        entry_points: &[usize],
        prob_threshold: f64,
    ) -> Vec<(usize, f64)> {
        let n = self.num_nodes;
        let mut aggregate_probs = vec![0.0; n];

        for &entry in entry_points {
            let probs = self.simulate_continuous_walk(entry, 2.5, 30);
            for (i, &p) in probs.iter().enumerate() {
                aggregate_probs[i] += p / entry_points.len().max(1) as f64;
            }
        }

        let mut chokepoints = Vec::new();
        for (i, &p) in aggregate_probs.iter().enumerate() {
            // Exclude starting entry points to highlight target and transit bottlenecks
            if !entry_points.contains(&i) && p >= prob_threshold {
                chokepoints.push((i, p));
            }
        }

        chokepoints.sort_by(|a, b| b.1.total_cmp(&a.1));
        chokepoints
    }
}

fn shannon_entropy(probs: &[f64]) -> f64 {
    let mut ent = 0.0;
    for &p in probs {
        if p > 1e-12 {
            ent -= p * p.ln();
        }
    }
    ent
}
