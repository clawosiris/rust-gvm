//! GMP session handler — processes commands and generates responses.

use crate::command_parser::parse_command;
use crate::fixtures::FixtureStore;
use crate::history::CommandHistory;
use crate::response_gen::{echo_response, error_response};
use crate::version::GmpVersion;
use crate::ServerMode;

/// Handles GMP commands for a single session.
pub struct SessionHandler {
    mode: ServerMode,
    version: GmpVersion,
    history: CommandHistory,
    session_id: u64,
    fixtures: Option<FixtureStore>,
}

impl SessionHandler {
    /// Create a new session handler.
    pub fn new(
        mode: ServerMode,
        version: GmpVersion,
        history: CommandHistory,
        session_id: u64,
        fixtures: Option<FixtureStore>,
    ) -> Self {
        Self {
            mode,
            version,
            history,
            session_id,
            fixtures,
        }
    }

    /// Process a complete GMP XML command and return a response.
    pub fn handle_command(&self, xml: &[u8]) -> Vec<u8> {
        let Some(cmd) = parse_command(xml) else {
            return error_response("unknown", 400, "Could not parse command");
        };

        // Record in history
        self.history
            .record(cmd.name.clone(), xml.to_vec(), self.session_id);

        match self.mode {
            ServerMode::Echo => echo_response(&cmd.name, self.version.as_str()),
            ServerMode::Fixture => self.handle_fixture(&cmd.name),
        }
    }

    fn handle_fixture(&self, command_name: &str) -> Vec<u8> {
        if let Some(ref store) = self.fixtures {
            if let Some(fixture) = store.get(command_name) {
                return fixture.into_bytes();
            }
        }
        // Fall back to echo for commands without fixtures
        echo_response(command_name, self.version.as_str())
    }
}
