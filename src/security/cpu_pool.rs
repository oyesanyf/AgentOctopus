//! Rayon CPU Threadpool Dispatcher for AgentOctopus
//!
//! Offloads compute-heavy JSON/ATIF serialization, deserialization, AST parsing,
//! and batch pattern matching from Tokio async reactor threads onto a dedicated
//! work-stealing Rayon threadpool.
//!
//! Complies with high-performance multithreading invariants:
//! - Non-blocking Tokio worker integration via `tokio::sync::oneshot` channels.
//! - Dynamically bounded thread pool sized to hardware parallelism.
//! - Priority isolation: heavy background work never blocks interactive token streaming.

use rayon::{ThreadPool, ThreadPoolBuilder};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::OnceLock;
use thiserror::Error;
use tokio::sync::oneshot;

/// Errors arising from CPU threadpool operations.
#[derive(Debug, Error)]
pub enum CpuPoolError {
    #[error("CPU worker task was cancelled or the threadpool thread panicked")]
    TaskCancelled,

    #[error("JSON serialization or deserialization failed: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    #[error("Threadpool initialization failed: {0}")]
    InitError(String),
}

/// Dedicated CPU threadpool manager wrapping Rayon.
pub struct CpuThreadPool {
    pool: ThreadPool,
}

static GLOBAL_CPU_POOL: OnceLock<CpuThreadPool> = OnceLock::new();

impl CpuThreadPool {
    /// Creates a new `CpuThreadPool` with the specified number of worker threads.
    /// If `num_threads` is None, sizes dynamically to `std::thread::available_parallelism()`.
    pub fn new(num_threads: Option<usize>) -> Result<Self, CpuPoolError> {
        let threads = num_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .clamp(2, 32)
        });

        let pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|idx| format!("octopus-cpu-worker-{idx}"))
            .build()
            .map_err(|e| CpuPoolError::InitError(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Access the global shared `CpuThreadPool`. Initializes with default thread count if uninitialized.
    pub fn global() -> &'static Self {
        GLOBAL_CPU_POOL
            .get_or_init(|| Self::new(None).expect("Failed to initialize global CpuThreadPool"))
    }

    /// Initialize the global `CpuThreadPool` with custom parameters before first use.
    pub fn init_global(num_threads: Option<usize>) -> Result<&'static Self, CpuPoolError> {
        let pool = Self::new(num_threads)?;
        let _ = GLOBAL_CPU_POOL.set(pool);
        Ok(Self::global())
    }

    /// Spawns a synchronous computation onto the Rayon pool and awaits its result
    /// via a Tokio oneshot channel without blocking the Tokio reactor thread.
    pub async fn spawn_cpu<F, T>(&self, op: F) -> Result<T, CpuPoolError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.pool.spawn(move || {
            let res = op();
            let _ = tx.send(res);
        });

        rx.await.map_err(|_| CpuPoolError::TaskCancelled)
    }

    /// Asynchronously serializes a value to a JSON string using the Rayon pool.
    pub async fn serialize_json<T: Serialize + Send + 'static>(
        value: T,
    ) -> Result<String, CpuPoolError> {
        Self::global()
            .spawn_cpu(move || serde_json::to_string(&value))
            .await?
            .map_err(CpuPoolError::JsonSerialization)
    }

    /// Asynchronously serializes a value to pretty-printed JSON using the Rayon pool.
    pub async fn serialize_json_pretty<T: Serialize + Send + 'static>(
        value: T,
    ) -> Result<String, CpuPoolError> {
        Self::global()
            .spawn_cpu(move || serde_json::to_string_pretty(&value))
            .await?
            .map_err(CpuPoolError::JsonSerialization)
    }

    /// Asynchronously deserializes a JSON string into a structured type using the Rayon pool.
    pub async fn deserialize_json<T: DeserializeOwned + Send + 'static>(
        json_str: String,
    ) -> Result<T, CpuPoolError> {
        Self::global()
            .spawn_cpu(move || serde_json::from_str::<T>(&json_str))
            .await?
            .map_err(CpuPoolError::JsonSerialization)
    }

    /// Asynchronously parses a JSON string into a `serde_json::Value` using the Rayon pool.
    pub async fn parse_json_value(json_str: String) -> Result<serde_json::Value, CpuPoolError> {
        Self::global()
            .spawn_cpu(move || serde_json::from_str::<serde_json::Value>(&json_str))
            .await?
            .map_err(CpuPoolError::JsonSerialization)
    }

    /// Executes parallel batch processing across elements in Rayon's threadpool,
    /// returning the mapped results without blocking Tokio worker threads.
    pub async fn par_map<T, R, F>(items: Vec<T>, op: F) -> Result<Vec<R>, CpuPoolError>
    where
        T: Send + 'static,
        R: Send + 'static,
        F: Fn(T) -> R + Send + Sync + 'static,
    {
        use rayon::prelude::*;
        Self::global()
            .spawn_cpu(move || items.into_par_iter().map(op).collect())
            .await
    }
}

/// Shorthand helper to execute a synchronous closure on the global CPU pool from an async task.
pub async fn spawn_cpu<F, T>(op: F) -> Result<T, CpuPoolError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    CpuThreadPool::global().spawn_cpu(op).await
}

/// Shorthand helper to access the global CPU pool reference.
pub fn global_cpu_pool() -> &'static CpuThreadPool {
    CpuThreadPool::global()
}

/// Shorthand helper to initialize the global CPU pool.
pub fn init_global_cpu_pool(
    num_threads: Option<usize>,
) -> Result<&'static CpuThreadPool, CpuPoolError> {
    CpuThreadPool::init_global(num_threads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct SampleTask {
        id: u64,
        command: String,
        flags: Vec<String>,
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_spawn_cpu_computation() {
        let result = spawn_cpu(|| {
            let mut sum: u64 = 0;
            for i in 1..=1000 {
                sum += i;
            }
            sum
        })
        .await
        .expect("spawn_cpu should complete");

        assert_eq!(result, 500500);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_json_roundtrip() {
        let original = SampleTask {
            id: 42,
            command: "atif-scan /proc/1/environ".to_string(),
            flags: vec!["--strict".to_string(), "--block-on-detect".to_string()],
        };

        let serialized = CpuThreadPool::serialize_json(original.clone())
            .await
            .expect("serialization should succeed");
        assert!(serialized.contains("atif-scan"));

        let deserialized: SampleTask = CpuThreadPool::deserialize_json(serialized)
            .await
            .expect("deserialization should succeed");
        assert_eq!(deserialized, original);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_par_map_batch() {
        let numbers: Vec<u64> = (1..=50).collect();
        let squares = CpuThreadPool::par_map(numbers, |n| n * n)
            .await
            .expect("par_map should succeed");

        assert_eq!(squares.len(), 50);
        assert_eq!(squares[0], 1);
        assert_eq!(squares[49], 2500);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_tokio_to_rayon_fanout() {
        use tokio::task::JoinSet;

        let mut set = JoinSet::new();
        for i in 0..50 {
            set.spawn(async move { spawn_cpu(move || i * 2).await });
        }

        let mut count = 0;
        while let Some(res) = set.join_next().await {
            let val = res
                .expect("join should succeed")
                .expect("cpu task should succeed");
            assert_eq!(val % 2, 0);
            count += 1;
        }
        assert_eq!(count, 50);
    }
}
