use rand::Rng;

pub struct OssFuzzMutator {
    dictionary: Vec<Vec<u8>>,
}

impl OssFuzzMutator {
    pub fn new(dictionary: Vec<Vec<u8>>) -> Self {
        Self { dictionary }
    }

    /// Mutates an input buffer using standard coverage-guided fuzzing strategies.
    pub fn mutate(&self, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        if data.is_empty() {
            return b"test_fuzz_seed".to_vec();
        }

        let mut mutated = data.to_vec();
        let strategy = rng.gen_range(0..6);

        match strategy {
            0 => {
                // 1. Bit flip (1 or 2 bits)
                let idx = rng.gen_range(0..mutated.len());
                let bit = 1 << rng.gen_range(0..8);
                mutated[idx] ^= bit;
            }
            1 => {
                // 2. Byte overwrite with random byte
                let idx = rng.gen_range(0..mutated.len());
                mutated[idx] = rng.gen();
            }
            2 => {
                // 3. Insert dictionary token
                if !self.dictionary.is_empty() {
                    let dict_idx = rng.gen_range(0..self.dictionary.len());
                    let token = &self.dictionary[dict_idx];
                    let insert_pos = rng.gen_range(0..=mutated.len());
                    mutated.splice(insert_pos..insert_pos, token.iter().cloned());
                }
            }
            3 => {
                // 4. Random byte insertion / deletion
                if mutated.len() > 4 && rng.gen_bool(0.5) {
                    let del_idx = rng.gen_range(0..mutated.len());
                    mutated.remove(del_idx);
                } else if mutated.len() < 8192 {
                    let ins_idx = rng.gen_range(0..=mutated.len());
                    mutated.insert(ins_idx, rng.gen());
                }
            }
            4 => {
                // 5. Boundary value injection
                let boundary_values: [u8; 8] = [0x00, 0xFF, 0x7F, 0x80, 0x0A, 0x0D, b'\'', b'"'];
                let b_val = boundary_values[rng.gen_range(0..boundary_values.len())];
                let idx = rng.gen_range(0..mutated.len());
                mutated[idx] = b_val;
            }
            _ => {
                // 6. Byte swap / shuffle
                if mutated.len() >= 2 {
                    let i = rng.gen_range(0..mutated.len());
                    let j = rng.gen_range(0..mutated.len());
                    mutated.swap(i, j);
                }
            }
        }

        // Clamp max size to 32KB to prevent memory exhaustion in fuzzer
        if mutated.len() > 32768 {
            mutated.truncate(32768);
        }

        mutated
    }

    /// Splices two seeds together (crossover mutation).
    pub fn crossover(&self, parent1: &[u8], parent2: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        if parent1.is_empty() {
            return parent2.to_vec();
        }
        if parent2.is_empty() {
            return parent1.to_vec();
        }

        let cut1 = rng.gen_range(0..parent1.len());
        let cut2 = rng.gen_range(0..parent2.len());

        let mut child = Vec::with_capacity(cut1 + (parent2.len() - cut2));
        child.extend_from_slice(&parent1[..cut1]);
        child.extend_from_slice(&parent2[cut2..]);
        child
    }
}
