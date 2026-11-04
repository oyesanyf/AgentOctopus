use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Atomic hardware-style circuit breaker allowing the supervisory task
/// or central brain to sever limb execution instantly.
#[derive(Clone)]
pub struct KillSwitch {
    flag: Arc<AtomicBool>,
    callbacks: Arc<std::sync::RwLock<Vec<Arc<dyn Fn() + Send + Sync>>>>,
}

impl std::fmt::Debug for KillSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KillSwitch")
            .field("is_tripped", &self.is_tripped())
            .finish()
    }
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
            callbacks: Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    pub fn is_tripped(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn trip(&self) {
        self.flag.store(true, Ordering::SeqCst);
        if let Ok(cbs) = self.callbacks.read() {
            for cb in cbs.iter() {
                cb();
            }
        }
    }

    pub fn register_callback(&self, cb: Arc<dyn Fn() + Send + Sync>) {
        if let Ok(mut cbs) = self.callbacks.write() {
            cbs.push(cb);
        }
    }

    pub fn reset(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }

    pub fn inner(&self) -> Arc<AtomicBool> {
        self.flag.clone()
    }
}
