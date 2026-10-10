use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Hash32 = [u8; 32];

/// Computes a leaf hash with RFC 6962 domain separation prefix 0x00
pub fn hash_leaf(data: &[u8]) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // Leaf prefix to prevent second preimage attacks
    hasher.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Computes an internal node hash with RFC 6962 domain separation prefix 0x01
pub fn hash_nodes(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut hasher = Sha256::new();
    hasher.update([0x01]); // Internal node prefix
    hasher.update(left);
    hasher.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Left,
    Right,
}

/// Represents an individual discrete execution step inside an arm enclave.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleLeaf {
    pub step_index: usize,
    pub tool_name: String,
    pub input_digest: String,
    pub output_digest: String,
    pub timestamp_epoch_ms: u64,
}

impl MerkleLeaf {
    pub fn new(
        step_index: usize,
        tool_name: impl Into<String>,
        input_digest: impl Into<String>,
        output_digest: impl Into<String>,
    ) -> Self {
        let timestamp_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            step_index,
            tool_name: tool_name.into(),
            input_digest: input_digest.into(),
            output_digest: output_digest.into(),
            timestamp_epoch_ms,
        }
    }

    /// Computes the cryptographic leaf hash with domain separation prefix 0x00
    pub fn hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update([0x00]); // Leaf domain separation prefix
        hasher.update((self.step_index as u64).to_be_bytes());
        hasher.update(self.tool_name.as_bytes());
        hasher.update(self.input_digest.as_bytes());
        hasher.update(self.output_digest.as_bytes());
        hasher.update(self.timestamp_epoch_ms.to_be_bytes());

        let result = hasher.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result);
        output
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }
}

/// Compact cryptographic proof showing that a specific step is included in the Merkle Tree.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_hash: Hash32,
    pub audit_path: Vec<(Direction, Hash32)>,
}

impl MerkleProof {
    /// Verifies that this proof hashes upward to the expected Merkle Root.
    pub fn verify(&self, expected_root: &Hash32) -> bool {
        let mut current_hash = self.leaf_hash;

        for (direction, sibling_hash) in &self.audit_path {
            current_hash = match direction {
                Direction::Left => hash_nodes(sibling_hash, &current_hash),
                Direction::Right => hash_nodes(&current_hash, sibling_hash),
            };
        }

        &current_hash == expected_root
    }
}

/// Immutable Binary Merkle Tree constructed over all execution steps in an arm scratchpad.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<MerkleLeaf>,
    layers: Vec<Vec<Hash32>>,
}

impl MerkleTree {
    /// Builds a Merkle Tree from an ordered sequence of execution step leaves.
    pub fn from_leaves(leaves: Vec<MerkleLeaf>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves: vec![],
                layers: vec![vec![[0u8; 32]]],
            };
        }

        let mut base_layer: Vec<Hash32> = leaves.iter().map(|l| l.hash()).collect();
        let mut layers = vec![base_layer.clone()];

        while base_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity((base_layer.len() + 1) / 2);
            for chunk in base_layer.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                next_layer.push(hash_nodes(&left, &right));
            }
            layers.push(next_layer.clone());
            base_layer = next_layer;
        }

        Self { leaves, layers }
    }

    pub fn root(&self) -> Hash32 {
        self.layers
            .last()
            .and_then(|layer| layer.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let leaf_hash = self.leaves[leaf_index].hash();
        let mut audit_path = Vec::new();
        let mut idx = leaf_index;

        for layer in &self.layers[0..self.layers.len() - 1] {
            let is_right_child = idx % 2 == 1;
            let sibling_idx = if is_right_child {
                idx - 1
            } else if idx + 1 < layer.len() {
                idx + 1
            } else {
                idx
            };

            let sibling_hash = layer[sibling_idx];
            let direction = if is_right_child {
                Direction::Left
            } else {
                Direction::Right
            };

            audit_path.push((direction, sibling_hash));
            idx /= 2;
        }

        Some(MerkleProof {
            leaf_hash,
            audit_path,
        })
    }
}

// ============================================================================
// 1. Direct In-Memory Trace Merkle Tree & Inclusion Proof Verification
// ============================================================================

/// In-memory Merkle Tree built over an Arm's discrete string execution trace.
/// Padded to power of 2 for balanced binary structure.
#[derive(Debug, Clone)]
pub struct ExecutionMerkleTree {
    pub raw_steps: Vec<String>,
    pub leaves: Vec<Hash32>,
    pub layers: Vec<Vec<Hash32>>,
}

impl ExecutionMerkleTree {
    pub fn build(raw_steps: &[String]) -> Self {
        if raw_steps.is_empty() {
            return Self {
                raw_steps: vec![],
                leaves: vec![[0u8; 32]],
                layers: vec![vec![[0u8; 32]]],
            };
        }

        let mut current_layer: Vec<Hash32> = raw_steps
            .iter()
            .map(|step| hash_leaf(step.as_bytes()))
            .collect();

        // Pad to power of 2 for balanced binary tree structure
        while current_layer.len() > 1 && (current_layer.len() & (current_layer.len() - 1)) != 0 {
            current_layer.push(*current_layer.last().unwrap());
        }

        let leaves = current_layer.clone();
        let mut layers = vec![current_layer.clone()];

        while current_layer.len() > 1 {
            let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
            for chunk in current_layer.chunks(2) {
                let left = &chunk[0];
                let right = if chunk.len() > 1 { &chunk[1] } else { left };
                next_layer.push(hash_nodes(left, right));
            }
            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        Self {
            raw_steps: raw_steps.to_vec(),
            leaves,
            layers,
        }
    }

    pub fn root(&self) -> Hash32 {
        self.layers.last().map(|l| l[0]).unwrap_or([0u8; 32])
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Generate an inclusion proof for leaf at index.
    /// Returns vector of (sibling_hash, is_right_sibling).
    pub fn generate_proof(&self, mut index: usize) -> Vec<(Hash32, bool)> {
        let mut proof = Vec::new();
        if self.layers.is_empty() || index >= self.leaves.len() {
            return proof;
        }

        for layer in &self.layers[..self.layers.len() - 1] {
            let is_right_sibling = index % 2 == 0;
            let sibling_index = if is_right_sibling { index + 1 } else { index - 1 };

            if sibling_index < layer.len() {
                proof.push((layer[sibling_index], is_right_sibling));
            }
            index /= 2;
        }
        proof
    }
}

/// Out-of-band verification performed by Central Brain or Supervisory Watchdog.
/// Validates in O(log N) that raw_step was executed at the claimed position without reading scratchpad.
pub fn verify_execution_step(
    root: &Hash32,
    raw_step: &str,
    proof: &[(Hash32, bool)],
) -> bool {
    let mut current_hash = hash_leaf(raw_step.as_bytes());

    for (sibling, is_right) in proof {
        current_hash = if *is_right {
            hash_nodes(&current_hash, sibling)
        } else {
            hash_nodes(sibling, &current_hash)
        };
    }

    &current_hash == root
}

// ============================================================================
// 2. Proof of Tool Integrity & Policy Allowlist Enforcement
// ============================================================================

/// Pre-authorized tool action capability tree.
/// Before executing any tool, the arm's local enclave must produce an inclusion proof
/// demonstrating that the invoked action schema is present in the policy tree signed by the brain.
#[derive(Debug, Clone)]
pub struct PolicyMerkleTree {
    allowed_schemas: Vec<String>,
    tree: ExecutionMerkleTree,
}

impl PolicyMerkleTree {
    pub fn build(allowed_schemas: &[&str]) -> Self {
        let schemas_vec: Vec<String> = allowed_schemas.iter().map(|s| s.to_string()).collect();
        let tree = ExecutionMerkleTree::build(&schemas_vec);
        Self {
            allowed_schemas: schemas_vec,
            tree,
        }
    }

    pub fn policy_root(&self) -> Hash32 {
        self.tree.root()
    }

    pub fn policy_root_hex(&self) -> String {
        self.tree.root_hex()
    }

    /// Prove that action exists in the authorized policy tree
    pub fn prove_action(&self, action_signature: &str) -> Option<Vec<(Hash32, bool)>> {
        self.allowed_schemas
            .iter()
            .position(|s| s == action_signature)
            .map(|idx| self.tree.generate_proof(idx))
    }

    /// Host-level enclave gate: verifies that action signature is cryptographically permitted
    pub fn verify_action(policy_root: &Hash32, action_signature: &str, proof: &[(Hash32, bool)]) -> bool {
        verify_execution_step(policy_root, action_signature, proof)
    }
}

// ============================================================================
// 3. Microsegmented Cross-Arm Artifact Handoffs (Data Slice Verification)
// ============================================================================

/// Slices a complex multi-field artifact into verified Merkle leaves.
/// Downstream arms can request and verify individual data slices (e.g., amount, vendor)
/// without ingesting the untrusted source document or unneeded fields.
#[derive(Debug, Clone)]
pub struct DatasetMerkleTree {
    slices: Vec<String>,
    tree: ExecutionMerkleTree,
}

impl DatasetMerkleTree {
    pub fn build(key_values: &[(&str, &str)]) -> Self {
        let slices: Vec<String> = key_values
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        let tree = ExecutionMerkleTree::build(&slices);
        Self { slices, tree }
    }

    pub fn dataset_root(&self) -> Hash32 {
        self.tree.root()
    }

    pub fn prove_slice(&self, key: &str, value: &str) -> Option<Vec<(Hash32, bool)>> {
        let target = format!("{}={}", key, value);
        self.slices
            .iter()
            .position(|s| s == &target)
            .map(|idx| self.tree.generate_proof(idx))
    }

    pub fn verify_slice(dataset_root: &Hash32, key: &str, value: &str, proof: &[(Hash32, bool)]) -> bool {
        let target = format!("{}={}", key, value);
        verify_execution_step(dataset_root, &target, proof)
    }
}
