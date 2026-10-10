use crate::quantum::attack_graph::AttackGraph;
use crate::quantum::qubo_optimizer::{QuboModel, QuantumAnnealerConfig, SimulatedQuantumAnnealer};
use std::collections::HashSet;
use std::time::Instant;

/// Comparative metrics evaluating Quantum-Inspired Optimization vs Classical Pathfinding (BFS / Dijkstra).
#[derive(Debug, Clone)]
pub struct ExperimentComparisonReport {
    /// Number of unauthorized privilege escalation paths discovered by Quantum-Inspired Annealing
    pub quantum_unauthorized_paths_discovered: usize,
    /// Number of unauthorized privilege escalation paths discovered by Classical BFS / Dijkstra
    pub classical_unauthorized_paths_discovered: usize,
    /// Novel unauthorized paths discovered exclusively by quantum tunneling that classical search missed
    pub novel_paths_discovered_by_quantum: usize,
    /// Total execution time for the quantum-inspired optimizer in milliseconds
    pub quantum_execution_time_ms: f64,
    /// Total execution time for classical BFS / Dijkstra in milliseconds
    pub classical_execution_time_ms: f64,
    /// Graph exploration coverage percentage for quantum-inspired search
    pub quantum_coverage_pct: f64,
    /// Graph exploration coverage percentage for classical search
    pub classical_coverage_pct: f64,
    /// Rate of benign / invalid candidate paths generated (false alarms)
    pub false_alarm_rate: f64,
    /// Number of quantum tunneling barrier-penetration events observed during SQA
    pub tunneling_events_observed: usize,
    /// Detailed list of valid unauthorized paths discovered
    pub discovered_unauthorized_paths: Vec<Vec<usize>>,
    pub summary: String,
}

/// Runs a reproducible comparative experiment on the swarm attack graph.
pub fn run_comparative_experiment(
    graph: &AttackGraph,
    start_node: usize,
    target_node: usize,
    seed: u64,
) -> ExperimentComparisonReport {
    // 1. Classical Baseline: BFS & Dijkstra
    let classical_start = Instant::now();
    let mut classical_paths = Vec::new();
    let mut classical_visited_edges = HashSet::new();

    if let Some(bfs_path) = graph.classical_bfs(start_node, target_node) {
        for w in bfs_path.windows(2) {
            classical_visited_edges.insert((w[0], w[1]));
        }
        classical_paths.push(bfs_path);
    }

    if let Some((dijkstra_path, _)) = graph.classical_dijkstra(start_node, target_node) {
        for w in dijkstra_path.windows(2) {
            classical_visited_edges.insert((w[0], w[1]));
        }
        if !classical_paths.contains(&dijkstra_path) {
            classical_paths.push(dijkstra_path);
        }
    }

    let classical_duration = classical_start.elapsed().as_secs_f64() * 1000.0;
    let classical_unauthorized: Vec<Vec<usize>> = classical_paths
        .into_iter()
        .filter(|p| graph.is_path_unauthorized(p))
        .collect();

    // 2. Quantum-Inspired Adversarial Defense Optimization (QUBO + SQA)
    let quantum_start = Instant::now();
    let qubo_model = QuboModel::from_attack_graph(graph, start_node, target_node);

    let config = QuantumAnnealerConfig {
        num_steps: 1500,
        trotter_slices: 8,
        initial_gamma: 4.0,
        final_gamma: 0.01,
        initial_temp: 2.5,
        final_temp: 0.05,
        seed,
    };

    let annealer = SimulatedQuantumAnnealer::new(config);
    let qubo_res = annealer.solve(&qubo_model, start_node, target_node);
    let quantum_duration = quantum_start.elapsed().as_secs_f64() * 1000.0;

    let mut quantum_visited_edges = HashSet::new();
    for (i, &active) in qubo_res.best_state.iter().enumerate() {
        if active && i < qubo_model.var_to_edge.len() {
            quantum_visited_edges.insert(qubo_model.var_to_edge[i]);
        }
    }

    let mut valid_quantum_paths = Vec::new();
    let mut false_alarms = 0;

    for path in qubo_res.paths_discovered {
        if path.first() == Some(&start_node) && path.last() == Some(&target_node) {
            valid_quantum_paths.push(path);
        } else {
            false_alarms += 1;
        }
    }

    let quantum_unauthorized: Vec<Vec<usize>> = valid_quantum_paths
        .into_iter()
        .filter(|p| graph.is_path_unauthorized(p))
        .collect();

    // Count novel paths found by quantum search that classical missed
    let mut novel_count = 0;
    for qp in &quantum_unauthorized {
        if !classical_unauthorized.contains(qp) {
            novel_count += 1;
        }
    }

    let total_edges = graph.edges.len().max(1) as f64;
    let classical_coverage = (classical_visited_edges.len() as f64 / total_edges) * 100.0;
    let quantum_coverage = (quantum_visited_edges.len() as f64 / total_edges) * 100.0;

    let total_candidates = (quantum_unauthorized.len() + false_alarms).max(1);
    let false_alarm_rate = false_alarms as f64 / total_candidates as f64;

    let summary = format!(
        "Quantum-Inspired Adversarial Defense Evaluation: Discovered {} unauthorized paths ({} novel vs classical), \
        with {} tunneling events in {:.2}ms (Classical: {} paths in {:.2}ms). Quantum Coverage: {:.1}%, False Alarm Rate: {:.2}%.",
        quantum_unauthorized.len(),
        novel_count,
        qubo_res.tunneling_events,
        quantum_duration,
        classical_unauthorized.len(),
        classical_duration,
        quantum_coverage,
        false_alarm_rate
    );

    ExperimentComparisonReport {
        quantum_unauthorized_paths_discovered: quantum_unauthorized.len(),
        classical_unauthorized_paths_discovered: classical_unauthorized.len(),
        novel_paths_discovered_by_quantum: novel_count,
        quantum_execution_time_ms: quantum_duration,
        classical_execution_time_ms: classical_duration,
        quantum_coverage_pct: quantum_coverage,
        classical_coverage_pct: classical_coverage,
        false_alarm_rate,
        tunneling_events_observed: qubo_res.tunneling_events,
        discovered_unauthorized_paths: quantum_unauthorized,
        summary,
    }
}
