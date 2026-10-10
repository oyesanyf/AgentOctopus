use crate::core::circuit_breaker::KillSwitch;
use crate::core::types::{ArmRole, TelemetryPacket};
use crate::telemetry::detector::AnomalyDetector;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct WatchdogSupervisor {
    kill_switches: HashMap<ArmRole, KillSwitch>,
    detector: AnomalyDetector,
}

impl WatchdogSupervisor {
    pub fn new(kill_switches: HashMap<ArmRole, KillSwitch>) -> Self {
        Self {
            kill_switches,
            detector: AnomalyDetector::default(),
        }
    }

    /// Spawns the independent out-of-band monitoring loop.
    pub fn spawn(self, mut telemetry_rx: mpsc::Receiver<TelemetryPacket>) -> JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(packet) = telemetry_rx.recv().await {
                // Real-time telemetry monitoring log
                println!(
                    "[SUPERVISOR] Heartbeat | Arm: {:?} | Directive: {} | Tool: {} | Target: {} | Entropy: {:.2}",
                    packet.arm_role, packet.directive_id, packet.tool_invoked, packet.raw_target, packet.entropy_bits
                );

                if let Some(ref root) = packet.incremental_merkle_root {
                    println!(
                        "[SUPERVISOR MERKLE] Incremental Root Sealed | Arm: {:?} | Step {}: {}",
                        packet.arm_role, packet.step_index, root
                    );
                }

                // 1. Check for lateral pivot, cloud metadata, or internal scanning
                if AnomalyDetector::is_lateral_pivot_attempt(&packet.raw_target) {
                    eprintln!(
                        "[CRITICAL SUPERVISORY ALERT] Lateral pivot / metadata breach attempt detected from arm {:?}! Tripping autotomy circuit breaker.",
                        packet.arm_role
                    );
                    if let Some(kill_switch) = self.kill_switches.get(&packet.arm_role) {
                        kill_switch.trip();
                    }
                    continue;
                }

                // 2. Check for anomalous high entropy indicating encrypted payload exfiltration or packed shellcode
                if self.detector.is_entropy_anomalous(packet.raw_target.as_bytes()) {
                    eprintln!(
                        "[CRITICAL SUPERVISORY ALERT] High-entropy payload anomaly ({:.2} bits/byte) detected from arm {:?}! Tripping autotomy circuit breaker.",
                        packet.entropy_bits, packet.arm_role
                    );
                    if let Some(kill_switch) = self.kill_switches.get(&packet.arm_role) {
                        kill_switch.trip();
                    }
                    continue;
                }
            }
        })
    }
}
