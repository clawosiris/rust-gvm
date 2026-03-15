//! Command history recording for inspection.

use std::sync::{Arc, Mutex};
use std::time::Instant;

/// A recorded GMP command.
#[derive(Debug, Clone)]
pub struct CommandRecord {
    /// The command name (e.g., "get_tasks").
    command_name: String,
    /// The raw XML bytes received.
    raw_xml: Vec<u8>,
    /// When the command was received.
    timestamp: Instant,
    /// Session identifier.
    session_id: u64,
}

impl CommandRecord {
    /// Create a new command record.
    pub fn new(command_name: String, raw_xml: Vec<u8>, session_id: u64) -> Self {
        Self {
            command_name,
            raw_xml,
            timestamp: Instant::now(),
            session_id,
        }
    }

    /// Get the command name.
    pub fn command_name(&self) -> &str {
        &self.command_name
    }

    /// Get the raw XML bytes.
    pub fn raw_xml(&self) -> &[u8] {
        &self.raw_xml
    }

    /// Get the session ID.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> Instant {
        self.timestamp
    }
}

/// Thread-safe command history store.
#[derive(Debug, Clone)]
pub struct CommandHistory {
    records: Arc<Mutex<Vec<CommandRecord>>>,
}

impl CommandHistory {
    /// Create a new empty history.
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record a command.
    pub fn record(&self, command_name: String, raw_xml: Vec<u8>, session_id: u64) {
        let record = CommandRecord::new(command_name, raw_xml, session_id);
        self.records
            .lock()
            .expect("history lock poisoned")
            .push(record);
    }

    /// Get all recorded commands.
    pub fn all(&self) -> Vec<CommandRecord> {
        self.records.lock().expect("history lock poisoned").clone()
    }

    /// Get the number of recorded commands.
    pub fn len(&self) -> usize {
        self.records.lock().expect("history lock poisoned").len()
    }

    /// Check if the history is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear the history.
    pub fn clear(&self) {
        self.records.lock().expect("history lock poisoned").clear();
    }
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new()
    }
}
