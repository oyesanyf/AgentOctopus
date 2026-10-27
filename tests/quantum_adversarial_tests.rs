use agent_octopus::quantum::{
    run_comparative_experiment, AttackGraph, Complex, QuantumAnnealerConfig, QuantumCircuit,
    QuantumGate, QuantumWalkSimulator, QuboModel, SimulatedQuantumAnnealer,
};
use agent_octopus::ArmRole;

#[test]
fn test_50_agent_attack_graph_construction_and_topology() {
    let graph = AttackGraph::new_50_agent_swarm();

    // Verify 50 nodes
    assert_eq!(graph.node_count(), 50);
    assert!(graph.edge_count() >= 50);

    // Verify entry nodes (0..15)
    for i in 0..16 {
        let node = graph.get_node(i).expect("Node should exist");
        assert!(node.is_entry_point);
        assert_eq!(node.privilege_level, 1);
        assert_eq!(node.role, ArmRole::UntrustedDocIngest);
    }

    // Verify target nodes (Ledger writers and Brains)
    let node_44 = graph.get_node(44).expect("Node 44 should exist");
    assert!(node_44.is_target);
    assert_eq!(node_44.privilege_level, 4);

    let node_48 = graph.get_node(48).expect("Node 48 should exist");
    assert!(node_48.is_target);
    assert_eq!(node_48.privilege_level, 5);

    // Verify Adjacency matrix properties
    let adj = graph.adjacency_matrix();
    assert_eq!(adj.len(), 50);
    assert_eq!(adj[0].len(), 50);

    // Verify Laplacian matrix properties: sum of each row in L should be ~0.0
    let lap = graph.laplacian_matrix();
    for row in &lap {
        let row_sum: f64 = row.iter().sum();
        assert!(
            row_sum.abs() < 1e-6,
            "Laplacian row sum must be 0, got {}",
            row_sum
        );
    }

    // Verify unauthorized path detection
    let legitimate_path = vec![0, 16, 31, 43];
    assert!(!graph.is_path_unauthorized(&legitimate_path));

    let sneaky_escalation = vec![5, 20, 44];
    assert!(graph.is_path_unauthorized(&sneaky_escalation));

    let memory_ring_escalation = vec![11, 38, 48];
    assert!(graph.is_path_unauthorized(&memory_ring_escalation));
}

#[test]
fn test_qubo_model_formulation_and_energy_evaluation() {
    let graph = AttackGraph::new_50_agent_swarm();
    let start = 5;
    let target = 44;

    let model = QuboModel::from_attack_graph(&graph, start, target);
    assert_eq!(model.num_variables, graph.edges.len());

    // All-zero state
    let zero_state = vec![false; model.num_variables];
    let zero_energy = model.energy(&zero_state);
    assert_eq!(zero_energy, 0.0);

    // A state that connects start (5) -> 20 -> 44
    let mut valid_escalation_state = vec![false; model.num_variables];
    for (i, edge) in graph.edges.iter().enumerate() {
        if (edge.from == 5 && edge.to == 20) || (edge.from == 20 && edge.to == 44) {
            valid_escalation_state[i] = true;
        }
    }

    let escalation_energy = model.energy(&valid_escalation_state);
    // Target reward and escalation bonus should drive the energy negative
    assert!(
        escalation_energy < 0.0,
        "Valid unauthorized path reaching target must have negative energy, got {}",
        escalation_energy
    );

    // Path extraction
    let paths = model.extract_paths(&valid_escalation_state, start, target);
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], vec![5, 20, 44]);
}

#[test]
fn test_simulated_quantum_annealing_discovers_unauthorized_paths() {
    let graph = AttackGraph::new_50_agent_swarm();
    let start = 5;
    let target = 44;

    let model = QuboModel::from_attack_graph(&graph, start, target);
    let config = QuantumAnnealerConfig {
        num_steps: 1200,
        trotter_slices: 8,
        initial_gamma: 3.5,
        final_gamma: 0.01,
        initial_temp: 2.0,
        final_temp: 0.05,
        seed: 42,
    };

    let annealer = SimulatedQuantumAnnealer::new(config);
    let result = annealer.solve(&model, start, target);

    // Verify quantum annealing executed iterations
    assert_eq!(result.iterations, 1200);

    // Verify quantum tunneling events occurred through transverse field fluctuations
    assert!(
        result.tunneling_events > 0,
        "Expected quantum tunneling events across Trotter slices, got {}",
        result.tunneling_events
    );

    // Low energy found
    assert!(result.best_energy < 0.0);

    // Verify paths discovered contains the unauthorized escalation path
    let contains_escalation = result.paths_discovered.iter().any(|p| {
        p.first() == Some(&start) && p.last() == Some(&target) && graph.is_path_unauthorized(p)
    });
    assert!(
        contains_escalation,
        "SQA must discover the unauthorized escalation path: {:?}",
        result.paths_discovered
    );
}

#[test]
fn test_continuous_time_quantum_walk_lateral_movement_simulation() {
    let graph = AttackGraph::new_50_agent_swarm();
    let simulator = QuantumWalkSimulator::from_attack_graph(&graph);

    let start_node = 0;
    let probs = simulator.simulate_continuous_walk(start_node, 3.0, 30);

    assert_eq!(probs.len(), 50);

    // Strictly verify probability distribution normalizes to 1.0
    let total_prob: f64 = probs.iter().sum();
    assert!(
        (total_prob - 1.0).abs() < 1e-5,
        "Total probability must equal 1.0, got {}",
        total_prob
    );

    // Verify probability has spread beyond start node
    assert!(probs[start_node] < 0.99);

    // Compare with classical walk spread
    let comparison = simulator.compare_spread(start_node, 10);
    assert_eq!(comparison.quantum_probabilities.len(), 50);
    assert_eq!(comparison.classical_probabilities.len(), 50);
    assert!(comparison.quantum_entropy > 0.0);

    // Critical lateral chokepoint detection
    let chokepoints = simulator.identify_critical_lateral_chokepoints(&[0, 5, 11], 0.02);
    assert!(!chokepoints.is_empty(), "Should identify chokepoints");
    for &(node_id, prob) in &chokepoints {
        assert!(prob >= 0.02);
        assert!(node_id < 50);
    }
}

#[test]
fn test_quantum_circuit_state_vector_simulation_and_gates() {
    let mut circuit = QuantumCircuit::new(2);
    assert_eq!(circuit.state.len(), 4);
    assert_eq!(circuit.state[0], Complex::new(1.0, 0.0));

    // Create Bell state |Phi+> = (|00> + |11>) / sqrt(2)
    circuit.apply_gate(&QuantumGate::Hadamard(0));
    circuit.apply_gate(&QuantumGate::CNOT {
        control: 0,
        target: 1,
    });

    let probs = circuit.basis_probabilities();
    let inv2 = 0.5;
    assert!((probs[0] - inv2).abs() < 1e-6); // |00> prob ~ 0.5
    assert!(probs[1].abs() < 1e-6); // |01> prob ~ 0
    assert!(probs[2].abs() < 1e-6); // |10> prob ~ 0
    assert!((probs[3] - inv2).abs() < 1e-6); // |11> prob ~ 0.5

    // Pauli-Z expectation values
    let z0 = circuit.expectation_z(0);
    let z1 = circuit.expectation_z(1);
    assert!(z0.abs() < 1e-6); // Equal superposition gives <Z> = 0
    assert!(z1.abs() < 1e-6);

    // Test Pauli-X
    let mut x_circuit = QuantumCircuit::new(1);
    x_circuit.apply_gate(&QuantumGate::PauliX(0));
    assert_eq!(x_circuit.expectation_z(0), -1.0); // State is |1>, <Z> = -1
}

#[test]
fn test_quantum_feature_encoding_and_anomaly_detection() {
    let mut circuit = QuantumCircuit::new(4);

    // Benign execution baseline features (normalized between 0.0 and 1.0)
    let baseline_trace = vec![0.12, 0.15, 0.20, 0.10];
    circuit.encode_features(&baseline_trace);
    let baseline_state = circuit.state.clone();

    // Trace identical to baseline -> fidelity must be 1.0
    let fidelity_self = QuantumCircuit::compute_kernel_fidelity(&baseline_state, &baseline_state);
    assert!(
        (fidelity_self - 1.0).abs() < 1e-6,
        "Self fidelity must be 1.0, got {}",
        fidelity_self
    );

    // Minor normal variation
    let normal_trace = vec![0.13, 0.16, 0.21, 0.11];
    circuit.encode_features(&normal_trace);
    let normal_state = circuit.state.clone();
    let fidelity_normal = QuantumCircuit::compute_kernel_fidelity(&baseline_state, &normal_state);
    assert!(
        fidelity_normal > 0.90,
        "Normal variation should maintain high fidelity > 0.90, got {}",
        fidelity_normal
    );

    // Anomalous breakout attempt trace (high syscall rate, memory surge, prompt injection spike)
    let anomalous_trace = vec![0.95, 0.90, 0.88, 0.98];
    circuit.encode_features(&anomalous_trace);
    let anomalous_state = circuit.state.clone();
    let fidelity_anomaly =
        QuantumCircuit::compute_kernel_fidelity(&baseline_state, &anomalous_state);
    assert!(
        fidelity_anomaly < 0.35,
        "Anomalous trace must yield low quantum fidelity < 0.35, got {}",
        fidelity_anomaly
    );
}

#[test]
fn test_comparative_experiment_metrics_quantum_vs_classical() {
    let graph = AttackGraph::new_50_agent_swarm();
    let start_node = 5;
    let target_node = 44;

    let report = run_comparative_experiment(&graph, start_node, target_node, 101);

    // Verify metrics structure
    assert!(report.quantum_execution_time_ms > 0.0);
    assert!(report.quantum_coverage_pct > 0.0);
    assert!(report.tunneling_events_observed > 0);

    // Verify paths discovered
    assert!(
        report.quantum_unauthorized_paths_discovered >= 1,
        "Quantum optimization should discover unauthorized path"
    );
    assert!(!report.discovered_unauthorized_paths.is_empty());

    for path in &report.discovered_unauthorized_paths {
        assert_eq!(path.first(), Some(&start_node));
        assert_eq!(path.last(), Some(&target_node));
        assert!(graph.is_path_unauthorized(path));
    }

    assert!(report
        .summary
        .contains("Quantum-Inspired Adversarial Defense"));
}
