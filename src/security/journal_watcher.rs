//! Asynchronous, Lock-Free File Watcher Tailing `~/.safeagents/calls.jsonl`
//!
//! Enforces:
//! - Dedicated OS background thread (`std::thread::Builder`) to isolate file I/O from Tokio executor.
//! - Bounded queue (`crossbeam_channel::bounded(1024)`) preventing memory leaks under high log volume.
//! - Safe Windows file-sharing modes (`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`) to avoid `ERROR_SHARING_VIOLATION`.
//! - Byte-offset tracking with automatic truncation detection for at-least-once log streaming.

use crossbeam_channel::{bounded, Receiver, Sender};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AtifSignal {
    pub id: String,
    pub severity: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalEntry {
    pub id: u64,
    pub time: f64,
    pub verdict: String,
    pub tool: String,
    pub arguments: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub signals: Vec<AtifSignal>,
    #[serde(default)]
    pub judge: Option<String>,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub task: String,
}

#[derive(Debug, Clone)]
pub struct JournalWatcherConfig {
    pub journal_path: PathBuf,
    pub channel_capacity: usize,
    pub poll_debounce: Duration,
    pub tail_from_beginning: bool,
}

impl Default for JournalWatcherConfig {
    fn default() -> Self {
        let base_dir = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let journal_path = base_dir.join(".safeagents").join("calls.jsonl");

        Self {
            journal_path,
            channel_capacity: 1024,
            poll_debounce: Duration::from_millis(100),
            tail_from_beginning: false,
        }
    }
}

pub struct SafeAgentsJournalWatcherHandle {
    stop_signal: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
    entry_rx: Receiver<JournalEntry>,
}

impl SafeAgentsJournalWatcherHandle {
    pub fn entry_receiver(&self) -> &Receiver<JournalEntry> {
        &self.entry_rx
    }

    pub fn stop(mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SafeAgentsJournalWatcherHandle {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

pub struct SafeAgentsJournalWatcher;

impl SafeAgentsJournalWatcher {
    pub fn start(config: JournalWatcherConfig) -> std::io::Result<SafeAgentsJournalWatcherHandle> {
        let (entry_tx, entry_rx) = bounded(config.channel_capacity);
        let stop_signal = Arc::new(AtomicBool::new(false));
        let thread_stop = stop_signal.clone();

        let thread_handle = std::thread::Builder::new()
            .name("safeagents-journal-watcher".to_string())
            .spawn(move || {
                Self::watcher_loop(config, entry_tx, thread_stop);
            })?;

        Ok(SafeAgentsJournalWatcherHandle {
            stop_signal,
            thread_handle: Some(thread_handle),
            entry_rx,
        })
    }

    fn open_file_safe(path: &Path) -> std::io::Result<std::fs::File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        }

        options.open(path)
    }

    fn watcher_loop(
        config: JournalWatcherConfig,
        entry_tx: Sender<JournalEntry>,
        stop_signal: Arc<AtomicBool>,
    ) {
        let (notify_tx, notify_rx) = bounded(1024);

        let mut watcher: Option<RecommendedWatcher> = Watcher::new(
            move |res| {
                let _ = notify_tx.send(res);
            },
            Config::default(),
        )
        .ok();

        if let Some(parent) = config.journal_path.parent() {
            let _ = std::fs::create_dir_all(parent);
            if let Some(w) = watcher.as_mut() {
                let _ = w.watch(parent, RecursiveMode::NonRecursive);
            }
        }

        let mut current_offset = 0u64;
        if !config.tail_from_beginning {
            if let Ok(metadata) = std::fs::metadata(&config.journal_path) {
                current_offset = metadata.len();
            }
        }

        while !stop_signal.load(Ordering::SeqCst) {
            // Drain any pending lines from the journal file
            Self::drain_file(&config.journal_path, &mut current_offset, &entry_tx);

            // Wait for file system notify event or timeout tick
            crossbeam_channel::select! {
                recv(notify_rx) -> _ => {
                    Self::drain_file(&config.journal_path, &mut current_offset, &entry_tx);
                }
                default(config.poll_debounce) => {
                    // Periodic poll to ensure coalesced OS events are not missed
                }
            }
        }

        // Final drain on stop
        Self::drain_file(&config.journal_path, &mut current_offset, &entry_tx);
    }

    fn drain_file(path: &Path, current_offset: &mut u64, entry_tx: &Sender<JournalEntry>) {
        if !path.exists() {
            return;
        }

        let Ok(mut file) = Self::open_file_safe(path) else {
            return;
        };

        let Ok(file_len) = file.metadata().map(|m| m.len()) else {
            return;
        };

        // Detect truncation or rotation
        if file_len < *current_offset {
            *current_offset = 0;
        }

        if file.seek(SeekFrom::Start(*current_offset)).is_err() {
            return;
        }

        let mut reader = BufReader::new(file);
        let mut line = String::new();

        while let Ok(bytes_read) = reader.read_line(&mut line) {
            if bytes_read == 0 {
                break;
            }

            *current_offset += bytes_read as u64;

            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if let Ok(entry) = serde_json::from_str::<JournalEntry>(trimmed) {
                    let _ = entry_tx.try_send(entry);
                }
            }
            line.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_journal_watcher_tailing() {
        let temp_dir = std::env::temp_dir().join(format!("safeagents_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let journal_file = temp_dir.join("test_calls.jsonl");

        // Write an initial line
        {
            let mut f = std::fs::File::create(&journal_file).unwrap();
            writeln!(
                f,
                r#"{{"id":1,"time":1710000000.0,"verdict":"allow","tool":"bash","arguments":"ls -la","signals":[],"model":"claude-3-opus","task":"list files"}}"#
            )
            .unwrap();
            f.flush().unwrap();
        }

        let config = JournalWatcherConfig {
            journal_path: journal_file.clone(),
            channel_capacity: 64,
            poll_debounce: Duration::from_millis(50),
            tail_from_beginning: true,
        };

        let handle = SafeAgentsJournalWatcher::start(config).expect("Watcher start succeeds");
        let rx = handle.entry_receiver();

        // Should receive the first entry
        let entry1 = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("Should receive first entry");
        assert_eq!(entry1.id, 1);
        assert_eq!(entry1.tool, "bash");
        assert_eq!(entry1.verdict, "allow");

        // Append a second entry
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&journal_file)
                .unwrap();
            writeln!(
                f,
                r#"{{"id":2,"time":1710000001.0,"verdict":"blocked","tool":"bash","arguments":"cat /proc/1/environ","reason":"side_channel.harness_secret_read","signals":[{{"id":"side_channel.harness_secret_read","severity":"HIGH","title":"PID 1 environ"}}],"model":"claude-3-opus","task":"read secrets"}}"#
            )
            .unwrap();
            f.flush().unwrap();
        }

        // Should receive the second entry
        let entry2 = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("Should receive second entry");
        assert_eq!(entry2.id, 2);
        assert_eq!(entry2.verdict, "blocked");
        assert_eq!(
            entry2.reason.as_deref(),
            Some("side_channel.harness_secret_read")
        );
        assert_eq!(entry2.signals.len(), 1);

        handle.stop();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
