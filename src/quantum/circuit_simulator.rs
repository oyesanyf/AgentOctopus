use crate::quantum::quantum_walk::Complex;

/// Gate operations supported by the state-vector simulator.
#[derive(Debug, Clone, PartialEq)]
pub enum QuantumGate {
    Hadamard(usize),
    PauliX(usize),
    PauliY(usize),
    PauliZ(usize),
    RotationY(usize, f64),
    RotationZ(usize, f64),
    CNOT { control: usize, target: usize },
    CZ { control: usize, target: usize },
    Swap(usize, usize),
}

/// Lightweight state-vector quantum circuit simulator for quantum-assisted anomaly feature encoding.
#[derive(Debug, Clone)]
pub struct QuantumCircuit {
    pub num_qubits: usize,
    pub state: Vec<Complex>,
}

impl QuantumCircuit {
    /// Creates a new circuit initialized to state |00...0>.
    pub fn new(num_qubits: usize) -> Self {
        assert!(
            num_qubits >= 1 && num_qubits <= 14,
            "num_qubits must be between 1 and 14"
        );
        let dim = 1 << num_qubits;
        let mut state = vec![Complex::zero(); dim];
        state[0] = Complex::new(1.0, 0.0);

        Self { num_qubits, state }
    }

    /// Resets the quantum state back to |00...0>.
    pub fn reset(&mut self) {
        self.state.fill(Complex::zero());
        self.state[0] = Complex::new(1.0, 0.0);
    }

    /// Applies a quantum gate to the state vector.
    pub fn apply_gate(&mut self, gate: &QuantumGate) {
        match *gate {
            QuantumGate::Hadamard(q) => self.apply_hadamard(q),
            QuantumGate::PauliX(q) => self.apply_pauli_x(q),
            QuantumGate::PauliY(q) => self.apply_pauli_y(q),
            QuantumGate::PauliZ(q) => self.apply_pauli_z(q),
            QuantumGate::RotationY(q, theta) => self.apply_rotation_y(q, theta),
            QuantumGate::RotationZ(q, theta) => self.apply_rotation_z(q, theta),
            QuantumGate::CNOT { control, target } => self.apply_cnot(control, target),
            QuantumGate::CZ { control, target } => self.apply_cz(control, target),
            QuantumGate::Swap(q1, q2) => self.apply_swap(q1, q2),
        }
    }

    fn apply_hadamard(&mut self, qubit: usize) {
        let inv_sqrt2 = 1.0 / std::f64::consts::SQRT_2;
        let bit = 1 << qubit;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & bit) == 0 {
                let j = i | bit;
                let u = self.state[i];
                let v = self.state[j];
                self.state[i] = u.add(&v).scale(inv_sqrt2);
                self.state[j] = u.sub(&v).scale(inv_sqrt2);
            }
        }
    }

    fn apply_pauli_x(&mut self, qubit: usize) {
        let bit = 1 << qubit;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & bit) == 0 {
                let j = i | bit;
                self.state.swap(i, j);
            }
        }
    }

    fn apply_pauli_y(&mut self, qubit: usize) {
        let bit = 1 << qubit;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & bit) == 0 {
                let j = i | bit;
                let u = self.state[i];
                let v = self.state[j];
                // Y * |0> = i|1>, Y * |1> = -i|0>
                self.state[i] = Complex::new(v.im, -v.re);
                self.state[j] = Complex::new(-u.im, u.re);
            }
        }
    }

    fn apply_pauli_z(&mut self, qubit: usize) {
        let bit = 1 << qubit;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & bit) != 0 {
                self.state[i] = self.state[i].scale(-1.0);
            }
        }
    }

    fn apply_rotation_y(&mut self, qubit: usize, theta: f64) {
        let cos = (theta / 2.0).cos();
        let sin = (theta / 2.0).sin();
        let bit = 1 << qubit;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & bit) == 0 {
                let j = i | bit;
                let u = self.state[i];
                let v = self.state[j];
                self.state[i] = Complex::new(cos * u.re - sin * v.re, cos * u.im - sin * v.im);
                self.state[j] = Complex::new(sin * u.re + cos * v.re, sin * u.im + cos * v.im);
            }
        }
    }

    fn apply_rotation_z(&mut self, qubit: usize, theta: f64) {
        let half = theta / 2.0;
        let cos = half.cos();
        let sin = half.sin();
        let exp_neg = Complex::new(cos, -sin);
        let exp_pos = Complex::new(cos, sin);
        let bit = 1 << qubit;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & bit) == 0 {
                self.state[i] = self.state[i].mul(&exp_neg);
            } else {
                self.state[i] = self.state[i].mul(&exp_pos);
            }
        }
    }

    fn apply_cnot(&mut self, control: usize, target: usize) {
        assert_ne!(control, target, "Control and target qubits must differ");
        let c_bit = 1 << control;
        let t_bit = 1 << target;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & c_bit) != 0 && (i & t_bit) == 0 {
                let j = i | t_bit;
                self.state.swap(i, j);
            }
        }
    }

    fn apply_cz(&mut self, control: usize, target: usize) {
        let c_bit = 1 << control;
        let t_bit = 1 << target;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            if (i & c_bit) != 0 && (i & t_bit) != 0 {
                self.state[i] = self.state[i].scale(-1.0);
            }
        }
    }

    fn apply_swap(&mut self, q1: usize, q2: usize) {
        let bit1 = 1 << q1;
        let bit2 = 1 << q2;
        let dim = 1 << self.num_qubits;

        for i in 0..dim {
            let b1 = (i & bit1) != 0;
            let b2 = (i & bit2) != 0;
            if b1 && !b2 {
                let j = (i ^ bit1) | bit2;
                self.state.swap(i, j);
            }
        }
    }

    /// Measures the probability distribution across all 2^n computational basis states.
    pub fn basis_probabilities(&self) -> Vec<f64> {
        self.state.iter().map(|c| c.norm_sq()).collect()
    }

    /// Computes the Pauli-Z expectation value <Z_i> for a given qubit:
    /// <Z_i> = P(qubit=0) - P(qubit=1), ranging in [-1.0, +1.0].
    pub fn expectation_z(&self, qubit: usize) -> f64 {
        let bit = 1 << qubit;
        let mut sum_zero = 0.0;
        let mut sum_one = 0.0;

        for (i, c) in self.state.iter().enumerate() {
            let prob = c.norm_sq();
            if (i & bit) == 0 {
                sum_zero += prob;
            } else {
                sum_one += prob;
            }
        }

        sum_zero - sum_one
    }

    /// Quantum Feature Encoding:
    /// Encodes a continuous telemetry / execution trace vector x into an entangled quantum state:
    /// 1. Hadamard layer creates uniform superposition.
    /// 2. Rotation layer R_y(pi * x_i) encodes normalized features.
    /// 3. Entanglement layer (circular CNOT chain) models high-order feature correlations.
    /// 4. Second rotation layer R_z(pi * x_i).
    pub fn encode_features(&mut self, features: &[f64]) {
        self.reset();
        let num_features = features.len().min(self.num_qubits);

        // 1. Hadamard layer
        for q in 0..self.num_qubits {
            self.apply_gate(&QuantumGate::Hadamard(q));
        }

        // 2. Feature angle encoding via R_y
        for q in 0..num_features {
            let angle = features[q] * std::f64::consts::PI;
            self.apply_gate(&QuantumGate::RotationY(q, angle));
        }

        // 3. Circular CNOT entangling ladder
        for q in 0..self.num_qubits {
            let next_q = (q + 1) % self.num_qubits;
            self.apply_gate(&QuantumGate::CNOT {
                control: q,
                target: next_q,
            });
        }

        // 4. Feature phase encoding via R_z
        for q in 0..num_features {
            let angle = features[q] * std::f64::consts::PI * 0.5;
            self.apply_gate(&QuantumGate::RotationZ(q, angle));
        }
    }

    /// Computes the quantum kernel fidelity K(A, B) = |<psi(A)|psi(B)>|^2
    /// between two encoded agent execution traces.
    pub fn compute_kernel_fidelity(state_a: &[Complex], state_b: &[Complex]) -> f64 {
        assert_eq!(state_a.len(), state_b.len());
        let mut inner_product = Complex::zero();

        for (ca, cb) in state_a.iter().zip(state_b.iter()) {
            // Conjugate(ca) * cb = (ca.re - i*ca.im) * (cb.re + i*cb.im)
            let conj_ca = Complex::new(ca.re, -ca.im);
            inner_product = inner_product.add(&conj_ca.mul(cb));
        }

        inner_product.norm_sq()
    }
}
