pub struct AnomalyDetector {
    entropy_threshold: f64,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new(5.5) // bits per byte threshold for plain text/payloads
    }
}

impl AnomalyDetector {
    pub fn new(entropy_threshold: f64) -> Self {
        Self { entropy_threshold }
    }

    /// Computes true Shannon Entropy of a string or byte slice:
    /// H(X) = -sum( P(x) * log2(P(x)) )
    pub fn compute_shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len_f64 = data.len() as f64;
        let mut entropy = 0.0;

        for &count in counts.iter() {
            if count > 0 {
                let p = count as f64 / len_f64;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Checks if a payload exhibits anomalous entropy (e.g. encrypted exfiltration, packed shellcode)
    pub fn is_entropy_anomalous(&self, data: &[u8]) -> bool {
        // Only evaluate if payload is sufficiently large to be statistically meaningful
        if data.len() < 32 {
            return false;
        }
        Self::compute_shannon_entropy(data) > self.entropy_threshold
    }

    /// Checks for unauthorized lateral movement or cloud metadata access targets
    pub fn is_lateral_pivot_attempt(target: &str) -> bool {
        let lower = target.to_lowercase();
        lower.contains("169.254.169.254")
            || lower.contains("metadata.google.internal")
            || lower.contains("127.0.0.1")
            || lower.contains("localhost")
            || lower.contains("internal.net")
            || lower.contains("corp.local")
            || lower.contains(".aws/credentials")
            || lower.contains("/etc/shadow")
            || lower.contains("id_rsa")
    }
}
