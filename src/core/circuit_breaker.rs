use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Atomic hardware-style circuit breaker allowing the supervisory task
/// or central brain to sever limb execution instantly.
#[derive(Debug, Clone)]
pub struct KillSwitch {
    flag: Arc<AtomicBool>,
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_tripped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn trip(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn reset(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }

    pub fn inner(&self) -> Arc<AtomicBool> {
        self.flag.clone()
    }
}
