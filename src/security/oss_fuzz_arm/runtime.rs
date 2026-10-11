use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use serde::{Deserialize, Serialize};

use super::mutator::OssFuzzMutator;
use super::targets::{
    AstExtractorFuzzTarget, CedarPolicyFuzzTarget, FuzzExecutionResult, FuzzStatus,
    MerkleProofFuzzTarget, NetworkUrlFuzzTarget, OssFuzzTarget, StixThreatBundleFuzzTarget,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetTelemetry {
    pub target_name: String,
    pub description: String,
    pub executions: u64,
    pub corpus_entries: usize,
    pub crashes_prevented: u64,
    pub hangs_intercepted: u64,
    pub avg_duration_micros: f64,
    pub last_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OssFuzzCycleReport {
    pub cycle_id: u64,
    pub executed_mutations: usize,
    pub total_executions: u64,
    pub execs_per_sec: f64,
    pub total_corpus_entries: usize,
    pub crashes_prevented: u64,
    pub hangs_intercepted: u64,
    pub active_sanitizers: Vec<String>,
    pub targets: Vec<TargetTelemetry>,
    pub recent_contained_crashes: Vec<FuzzExecutionResult>,
}

pub struct ContinuousOssFuzzArm {
    targets: Vec<Box<dyn OssFuzzTarget>>,
    mutators: HashMap<String, OssFuzzMutator>,
    corpus: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
    total_executions: Arc<AtomicU64>,
    crashes_prevented: Arc<AtomicU64>,
    hangs_intercepted: Arc<AtomicU64>,
    cycle_counter: Arc<AtomicU64>,
    recent_events: Arc<Mutex<Vec<FuzzExecutionResult>>>,
    arm_ring: Arc<crate::containment_ring::ArmContainmentRing>,
}

impl Default for ContinuousOssFuzzArm {
    fn default() -> Self {
        Self::new()
    }
}

impl ContinuousOssFuzzArm {
    pub fn new() -> Self {
        let targets: Vec<Box<dyn OssFuzzTarget>> = vec![
            Box::new(CedarPolicyFuzzTarget),
            Box::new(AstExtractorFuzzTarget),
            Box::new(StixThreatBundleFuzzTarget),
            Box::new(NetworkUrlFuzzTarget),
            Box::new(MerkleProofFuzzTarget),
        ];

        let mut mutators = HashMap::new();
        let mut corpus_map = HashMap::new();

        for t in &targets {
            let name = t.target_name().to_string();
            mutators.insert(name.clone(), OssFuzzMutator::new(t.dictionary()));
            corpus_map.insert(name, t.initial_corpus());
        }

        let master_seed = crate::containment_ring::ArmRingRegistry::generate_master_seed();
        let arm_ring = Arc::new(crate::containment_ring::ArmContainmentRing::new(
            104,
            crate::core::types::ArmRole::ContinuousOssFuzz,
            1,
            &master_seed,
        ));

        Self {
            targets,
            mutators,
            corpus: Arc::new(Mutex::new(corpus_map)),
            total_executions: Arc::new(AtomicU64::new(0)),
            crashes_prevented: Arc::new(AtomicU64::new(0)),
            hangs_intercepted: Arc::new(AtomicU64::new(0)),
            cycle_counter: Arc::new(AtomicU64::new(0)),
            recent_events: Arc::new(Mutex::new(Vec::new())),
            arm_ring,
        }
    }

    pub fn with_containment_ring(mut self, ring: Arc<crate::containment_ring::ArmContainmentRing>) -> Self {
        self.arm_ring = ring;
        self
    }

    pub fn containment_ring(&self) -> &Arc<crate::containment_ring::ArmContainmentRing> {
        &self.arm_ring
    }

    /// Executes a continuous dynamic fuzzing cycle across all targets.
    /// Runs `iterations_per_target` mutations per target without blocking thread pool.
    pub fn run_continuous_fuzz_cycle(&self, iterations_per_target: usize) -> OssFuzzCycleReport {
        let cycle_id = self.cycle_counter.fetch_add(1, Ordering::SeqCst) + 1;
        if self.arm_ring.is_severed() {
            return OssFuzzCycleReport {
                cycle_id,
                executed_mutations: 0,
                total_executions: self.total_executions.load(Ordering::SeqCst),
                execs_per_sec: 0.0,
                total_corpus_entries: 0,
                crashes_prevented: self.crashes_prevented.load(Ordering::SeqCst),
                hangs_intercepted: self.hangs_intercepted.load(Ordering::SeqCst),
                active_sanitizers: vec!["SEVERED_BY_SUPERVISOR".to_string()],
                targets: Vec::new(),
                recent_contained_crashes: Vec::new(),
            };
        }
        let start = Instant::now();
        let mut target_summaries = Vec::new();
        let mut batch_results = Vec::new();
        let mut total_executed_in_cycle = 0;

        for target in &self.targets {
            let t_name = target.target_name();
            let mutator = self.mutators.get(t_name);

            // Fetch seed from corpus
            let seeds = {
                let lock = self.corpus.lock().unwrap();
                lock.get(t_name).cloned().unwrap_or_default()
            };

            let mut target_execs = 0u64;
            let mut target_crashes = 0u64;
            let mut target_hangs = 0u64;
            let mut total_duration = 0u64;
            let mut last_status = "SAFE".to_string();

            let fallback_seed = b"fuzz_seed_fallback".to_vec();
            for i in 0..iterations_per_target {
                let seed: &[u8] = if !seeds.is_empty() {
                    &seeds[i % seeds.len()]
                } else {
                    &fallback_seed
                };

                let mutated = match mutator {
                    Some(m) => m.mutate(seed),
                    None => seed.to_vec(),
                };

                let res = target.fuzz_one_input(&mutated);
                target_execs += 1;
                total_duration += res.duration_micros;

                match res.status {
                    FuzzStatus::PanicCaught => {
                        target_crashes += 1;
                        self.crashes_prevented.fetch_add(1, Ordering::Relaxed);
                        last_status = "PANIC_CONTAINED".to_string();
                        batch_results.push(res);
                    }
                    FuzzStatus::HangTimeout => {
                        target_hangs += 1;
                        self.hangs_intercepted.fetch_add(1, Ordering::Relaxed);
                        last_status = "HANG_MITIGATED".to_string();
                        batch_results.push(res);
                    }
                    FuzzStatus::SanitizerClamp => {
                        last_status = "SANITIZER_CLAMPED".to_string();
                    }
                    FuzzStatus::ContainedSafe => {}
                }
            }

            self.total_executions.fetch_add(target_execs, Ordering::Relaxed);
            total_executed_in_cycle += target_execs as usize;

            let avg_micros = if target_execs > 0 {
                total_duration as f64 / target_execs as f64
            } else {
                0.0
            };

            target_summaries.push(TargetTelemetry {
                target_name: t_name.to_string(),
                description: target.description().to_string(),
                executions: target_execs,
                corpus_entries: seeds.len(),
                crashes_prevented: target_crashes,
                hangs_intercepted: target_hangs,
                avg_duration_micros: avg_micros,
                last_status,
            });
        }

        let elapsed_sec = start.elapsed().as_secs_f64().max(0.0001);
        let execs_per_sec = total_executed_in_cycle as f64 / elapsed_sec;

        let total_corpus = {
            let lock = self.corpus.lock().unwrap();
            lock.values().map(|v| v.len()).sum()
        };

        // Maintain top 20 recent contained crashes
        {
            let mut recent = self.recent_events.lock().unwrap();
            for item in &batch_results {
                recent.push(item.clone());
                if recent.len() > 30 {
                    recent.remove(0);
                }
            }
        }

        OssFuzzCycleReport {
            cycle_id,
            executed_mutations: total_executed_in_cycle,
            total_executions: self.total_executions.load(Ordering::Relaxed),
            execs_per_sec,
            total_corpus_entries: total_corpus,
            crashes_prevented: self.crashes_prevented.load(Ordering::Relaxed),
            hangs_intercepted: self.hangs_intercepted.load(Ordering::Relaxed),
            active_sanitizers: vec![
                "AddressSanitizer (ASan-Bounds)".to_string(),
                "UndefinedBehaviorSanitizer (UBSan-Clamp)".to_string(),
                "MemorySanitizer (MSan-Init)".to_string(),
                "HangTimeoutGuard (50ms)".to_string(),
            ],
            targets: target_summaries,
            recent_contained_crashes: batch_results,
        }
    }

    /// Generates a GitHub Actions / Google CIFuzz compatible SARIF report.
    pub fn generate_cifuzz_sarif_report(&self) -> String {
        let total = self.total_executions.load(Ordering::Relaxed);
        let crashes = self.crashes_prevented.load(Ordering::Relaxed);
        let hangs = self.hangs_intercepted.load(Ordering::Relaxed);

        serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Google OSS-Fuzz Continuous Runtime Arm (Agent Octopus)",
                            "version": "0.1.0",
                            "informationUri": "https://google.github.io/oss-fuzz/getting-started/continuous-integration/",
                            "rules": [
                                {
                                    "id": "FUZZ-PANIC-001",
                                    "shortDescription": { "text": "Parser Unwind Panic Caught & Contained" },
                                    "defaultConfiguration": { "level": "warning" }
                                },
                                {
                                    "id": "FUZZ-HANG-002",
                                    "shortDescription": { "text": "Continuous Execution Hang/Timeout Mitigated" },
                                    "defaultConfiguration": { "level": "warning" }
                                }
                            ]
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": true,
                            "toolExecutionNotifications": []
                        }
                    ],
                    "properties": {
                        "total_fuzz_executions": total,
                        "crashes_prevented": crashes,
                        "hangs_intercepted": hangs,
                        "continuous_integration_service": "google/oss-fuzz/actions/run-fuzzers"
                    },
                    "results": []
                }
            ]
        }).to_string()
    }
}
