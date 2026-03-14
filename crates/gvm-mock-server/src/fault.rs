//! Error injection / fault engine for testing error handling paths.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A fault that can be injected into the mock server.
#[derive(Debug, Clone)]
pub struct Fault {
    /// When this fault triggers.
    pub trigger: FaultTrigger,
    /// What kind of fault to inject.
    pub kind: FaultKind,
}

/// When a fault triggers.
#[derive(Debug, Clone)]
pub enum FaultTrigger {
    /// Trigger on every command.
    Always,
    /// Trigger only once, then disable.
    Once,
    /// Trigger after N commands have been processed.
    AfterCommands(usize),
    /// Trigger only for a specific command name.
    OnCommand(String),
}

/// What kind of fault to inject.
#[derive(Debug, Clone)]
pub enum FaultKind {
    /// Return a 500 Internal Server Error.
    ServerError500,
    /// Return a specific error status code and message.
    ErrorStatus { code: u16, message: String },
    /// Delay the response by the specified duration.
    Delay(Duration),
    /// Return malformed (non-XML) data.
    MalformedXml,
    /// Return a truncated response (cut off mid-XML).
    TruncatedResponse,
    /// Drop the connection (close without response).
    Disconnect,
}

/// Manages fault injection state.
#[derive(Debug, Clone)]
pub struct FaultEngine {
    faults: Arc<Vec<FaultEntry>>,
}

#[derive(Debug)]
struct FaultEntry {
    fault: Fault,
    fired: AtomicUsize,
}

impl FaultEngine {
    /// Create a new fault engine with the given faults.
    pub fn new(faults: Vec<Fault>) -> Self {
        Self {
            faults: Arc::new(
                faults
                    .into_iter()
                    .map(|f| FaultEntry {
                        fault: f,
                        fired: AtomicUsize::new(0),
                    })
                    .collect(),
            ),
        }
    }

    /// Create an empty fault engine (no faults).
    pub fn none() -> Self {
        Self {
            faults: Arc::new(Vec::new()),
        }
    }

    /// Create a new fault engine with the same faults but fresh counters.
    pub fn fork(&self) -> FaultEngine {
        FaultEngine::new(self.faults.iter().map(|entry| entry.fault.clone()).collect())
    }

    /// Check all faults that should fire for this command.
    pub fn check_all(&self, command_name: &str, total_commands: usize) -> Vec<FaultAction> {
        let mut out = Vec::new();
        for entry in self.faults.iter() {
            if self.should_trigger(entry, command_name, total_commands) {
                entry.fired.fetch_add(1, Ordering::Relaxed);
                out.push(self.to_action(&entry.fault.kind));
            }
        }
        out
    }

    /// Compatibility helper: returns the first matching fault action, if any.
    pub fn check(&self, command_name: &str, total_commands: usize) -> Option<FaultAction> {
        self.check_all(command_name, total_commands).into_iter().next()
    }

    fn should_trigger(&self, entry: &FaultEntry, command_name: &str, total_commands: usize) -> bool {
        match &entry.fault.trigger {
            FaultTrigger::Always => true,
            FaultTrigger::Once => entry.fired.load(Ordering::Relaxed) == 0,
            FaultTrigger::AfterCommands(n) => total_commands >= *n,
            FaultTrigger::OnCommand(name) => command_name == name,
        }
    }

    fn to_action(&self, kind: &FaultKind) -> FaultAction {
        match kind {
            FaultKind::ServerError500 => FaultAction::ErrorResponse {
                status: 500,
                message: "Internal Server Error".to_string(),
            },
            FaultKind::ErrorStatus { code, message } => FaultAction::ErrorResponse {
                status: *code,
                message: message.clone(),
            },
            FaultKind::Delay(d) => FaultAction::Delay(*d),
            FaultKind::MalformedXml => FaultAction::MalformedResponse,
            FaultKind::TruncatedResponse => FaultAction::TruncatedResponse,
            FaultKind::Disconnect => FaultAction::Disconnect,
        }
    }

    /// Check if there are any faults configured.
    pub fn has_faults(&self) -> bool {
        !self.faults.is_empty()
    }
}

/// Action the handler should take when a fault fires.
#[derive(Debug, Clone)]
pub enum FaultAction {
    /// Return an error response with the given status and message.
    ErrorResponse { status: u16, message: String },
    /// Delay before sending the normal response.
    Delay(Duration),
    /// Send malformed (non-XML) bytes.
    MalformedResponse,
    /// Send a truncated XML response.
    TruncatedResponse,
    /// Close the connection immediately.
    Disconnect,
}

impl Fault {
    /// Create a fault that always triggers.
    pub fn always(kind: FaultKind) -> Self {
        Self {
            trigger: FaultTrigger::Always,
            kind,
        }
    }

    /// Create a fault that triggers once.
    pub fn once(kind: FaultKind) -> Self {
        Self {
            trigger: FaultTrigger::Once,
            kind,
        }
    }

    /// Create a fault that triggers after N commands.
    pub fn after_commands(n: usize, kind: FaultKind) -> Self {
        Self {
            trigger: FaultTrigger::AfterCommands(n),
            kind,
        }
    }

    /// Create a fault that triggers on a specific command.
    pub fn on_command(name: &str, kind: FaultKind) -> Self {
        Self {
            trigger: FaultTrigger::OnCommand(name.to_string()),
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_always_fault() {
        let engine = FaultEngine::new(vec![Fault::always(FaultKind::ServerError500)]);
        let action = engine.check("get_tasks", 0);
        assert!(action.is_some());
        assert!(matches!(action.unwrap(), FaultAction::ErrorResponse { status: 500, .. }));
    }

    #[test]
    fn test_once_fault() {
        let engine = FaultEngine::new(vec![Fault::once(FaultKind::ServerError500)]);
        assert!(engine.check("get_tasks", 0).is_some());
        assert!(engine.check("get_tasks", 1).is_none());
    }

    #[test]
    fn test_after_commands_fault() {
        let engine = FaultEngine::new(vec![Fault::after_commands(3, FaultKind::ServerError500)]);
        assert!(engine.check("get_tasks", 0).is_none());
        assert!(engine.check("get_tasks", 2).is_none());
        assert!(engine.check("get_tasks", 3).is_some());
        assert!(engine.check("get_tasks", 5).is_some());
    }

    #[test]
    fn test_on_command_fault() {
        let engine = FaultEngine::new(vec![Fault::on_command("get_reports", FaultKind::ServerError500)]);
        assert!(engine.check("get_tasks", 0).is_none());
        assert!(engine.check("get_reports", 0).is_some());
    }

    #[test]
    fn test_no_faults() {
        let engine = FaultEngine::none();
        assert!(engine.check("get_tasks", 0).is_none());
        assert!(!engine.has_faults());
    }

    #[test]
    fn test_delay_fault() {
        let engine = FaultEngine::new(vec![Fault::always(FaultKind::Delay(Duration::from_secs(1)))]);
        let action = engine.check("get_tasks", 0);
        assert!(matches!(action, Some(FaultAction::Delay(_))));
    }

    #[test]
    fn test_disconnect_fault() {
        let engine = FaultEngine::new(vec![Fault::always(FaultKind::Disconnect)]);
        let action = engine.check("get_tasks", 0);
        assert!(matches!(action, Some(FaultAction::Disconnect)));
    }

    #[test]
    fn test_malformed_fault() {
        let engine = FaultEngine::new(vec![Fault::always(FaultKind::MalformedXml)]);
        let action = engine.check("get_tasks", 0);
        assert!(matches!(action, Some(FaultAction::MalformedResponse)));
    }

    #[test]
    fn test_error_status_fault() {
        let engine = FaultEngine::new(vec![Fault::always(FaultKind::ErrorStatus {
            code: 409,
            message: "Conflict".to_string(),
        })]);
        let action = engine.check("get_tasks", 0).unwrap();
        match action {
            FaultAction::ErrorResponse { status, message } => {
                assert_eq!(status, 409);
                assert_eq!(message, "Conflict");
            }
            _ => panic!("expected ErrorResponse"),
        }
    }

    #[test]
    fn test_fork_resets_counters() {
        let engine = FaultEngine::new(vec![Fault::once(FaultKind::ServerError500)]);
        assert!(engine.check("get_tasks", 0).is_some());
        assert!(engine.check("get_tasks", 1).is_none());

        let forked = engine.fork();
        assert!(forked.check("get_tasks", 0).is_some());
        assert!(forked.check("get_tasks", 1).is_none());
    }
}
