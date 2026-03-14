//! GMP session handler — processes commands and generates responses.

use std::sync::atomic::{AtomicUsize, Ordering};

use uuid::Uuid;

use crate::command_parser::{parse_command, parse_element_text, ParsedCommand};
use crate::fault::{FaultAction, FaultEngine};
use crate::fixtures::FixtureStore;
use crate::history::CommandHistory;
use crate::response_gen::{echo_response, error_response};
use crate::store::{Resource, ResourceStore, TaskStatus};
use crate::version::GmpVersion;
use crate::ServerMode;

/// Handles GMP commands for a single session.
pub struct SessionHandler {
    mode: ServerMode,
    version: GmpVersion,
    history: CommandHistory,
    session_id: u64,
    fixtures: Option<FixtureStore>,
    store: Option<ResourceStore>,
    fault_engine: FaultEngine,
    command_count: AtomicUsize,
}

impl SessionHandler {
    /// Create a new session handler.
    pub fn new(
        mode: ServerMode,
        version: GmpVersion,
        history: CommandHistory,
        session_id: u64,
        fixtures: Option<FixtureStore>,
        store: Option<ResourceStore>,
        fault_engine: FaultEngine,
    ) -> Self {
        Self {
            mode,
            version,
            history,
            session_id,
            fixtures,
            store,
            fault_engine,
            command_count: AtomicUsize::new(0),
        }
    }

    /// Process a complete GMP XML command and return a response.
    ///
    /// Returns `None` if the fault engine signals a disconnect.
    pub fn handle_command(&self, xml: &[u8]) -> Option<Vec<u8>> {
        let Some(cmd) = parse_command(xml) else {
            return Some(error_response("unknown", 400, "Could not parse command"));
        };

        let count = self.command_count.fetch_add(1, Ordering::Relaxed);

        // Record in history
        self.history
            .record(cmd.name.clone(), xml.to_vec(), self.session_id);

        // Check fault engine
        if self.fault_engine.has_faults() {
            if let Some(action) = self.fault_engine.check(&cmd.name, count) {
                return match action {
                    FaultAction::ErrorResponse { status, message } => {
                        Some(error_response(&cmd.name, status, &message))
                    }
                    FaultAction::MalformedResponse => {
                        Some(b"THIS IS NOT XML <<<<".to_vec())
                    }
                    FaultAction::TruncatedResponse => {
                        // Return partial XML
                        Some(format!("<{}_response status=\"200\"", cmd.name).into_bytes())
                    }
                    FaultAction::Disconnect => None, // Signal to close connection
                    FaultAction::Delay(_duration) => {
                        // Note: actual delay must be handled at the async level
                        // For now, just return the normal response
                        // TODO: wire delay into async handler
                        Some(self.normal_response(&cmd, xml))
                    }
                };
            }
        }

        Some(self.normal_response(&cmd, xml))
    }

    fn normal_response(&self, cmd: &ParsedCommand, xml: &[u8]) -> Vec<u8> {
        match self.mode {
            ServerMode::Echo => echo_response(&cmd.name, self.version.as_str()),
            ServerMode::Fixture => self.handle_fixture(&cmd.name),
            ServerMode::Stateful => self.handle_stateful(cmd, xml),
        }
    }

    fn handle_fixture(&self, command_name: &str) -> Vec<u8> {
        if let Some(ref store) = self.fixtures {
            if let Some(fixture) = store.get(command_name) {
                return fixture.into_bytes();
            }
        }
        echo_response(command_name, self.version.as_str())
    }

    fn handle_stateful(&self, cmd: &ParsedCommand, raw_xml: &[u8]) -> Vec<u8> {
        let store = match &self.store {
            Some(s) => s,
            None => return error_response(&cmd.name, 500, "No resource store"),
        };

        // get_version is always allowed (pre-auth)
        if cmd.name == "get_version" {
            return crate::response_gen::version_response(self.version.as_str());
        }

        // authenticate
        if cmd.name == "authenticate" {
            return self.handle_authenticate(cmd, raw_xml, store);
        }

        // All other commands require authentication
        if !store.is_authenticated(self.session_id) {
            return error_response(&cmd.name, 401, "Not authenticated");
        }

        // Route to specific handlers
        match cmd.name.as_str() {
            // Create commands
            name if name.starts_with("create_") => self.handle_create(cmd, raw_xml, store),
            // Get commands
            name if name.starts_with("get_") => self.handle_get(cmd, store),
            // Modify commands
            name if name.starts_with("modify_") => self.handle_modify(cmd, raw_xml, store),
            // Delete commands
            name if name.starts_with("delete_") => self.handle_delete(cmd, store),
            // Task actions
            "start_task" => self.handle_start_task(cmd, store),
            "stop_task" => self.handle_stop_task(cmd, store),
            "resume_task" => self.handle_resume_task(cmd, store),
            // Trashcan
            "empty_trashcan" => {
                store.empty_trashcan();
                format!(
                    "<empty_trashcan_response status=\"200\" status_text=\"OK\"/>"
                )
                .into_bytes()
            }
            "restore" => self.handle_restore(cmd, store),
            // Help
            "help" => echo_response("help", self.version.as_str()),
            // Everything else
            _ => echo_response(&cmd.name, self.version.as_str()),
        }
    }

    fn handle_authenticate(
        &self,
        cmd: &ParsedCommand,
        raw_xml: &[u8],
        store: &ResourceStore,
    ) -> Vec<u8> {
        // Extract username/password from nested XML
        let username = parse_element_text(raw_xml, "username").unwrap_or_default();
        let password = parse_element_text(raw_xml, "password").unwrap_or_default();

        if store.authenticate(self.session_id, &username, &password) {
            "<authenticate_response status=\"200\" status_text=\"OK\">\
             <role>Admin</role>\
             <timezone>UTC</timezone>\
             </authenticate_response>"
                .as_bytes()
                .to_vec()
        } else {
            error_response(&cmd.name, 400, "Authentication failed")
        }
    }

    fn handle_create(
        &self,
        cmd: &ParsedCommand,
        raw_xml: &[u8],
        store: &ResourceStore,
    ) -> Vec<u8> {
        let resource_type = cmd.name.strip_prefix("create_").unwrap_or("unknown");

        // Check for clone (copy element)
        if let Some(copy_id) = parse_element_text(raw_xml, "copy") {
            if let Ok(uuid) = Uuid::parse_str(&copy_id) {
                if let Some(new_id) = store.clone_resource(&uuid) {
                    return format!(
                        "<{}_response status=\"201\" \
                         status_text=\"OK, resource created\" \
                         id=\"{new_id}\"/>",
                        cmd.name
                    )
                    .into_bytes();
                }
            }
            return error_response(&cmd.name, 404, "Resource to clone not found");
        }

        // Extract name
        let name = parse_element_text(raw_xml, "name").unwrap_or_default();
        if name.is_empty() && resource_type != "port_range" {
            return error_response(&cmd.name, 400, "Missing required element: name");
        }

        let mut resource = Resource::new(resource_type, &name);

        // Extract comment
        if let Some(comment) = parse_element_text(raw_xml, "comment") {
            resource.comment = comment;
        }

        // Task-specific: extract references
        if resource_type == "task" {
            if let Some(target_id) = cmd.child_attr("target", "id") {
                resource.set_attr("target_id", target_id);
            }
            if let Some(config_id) = cmd.child_attr("config", "id") {
                resource.set_attr("config_id", config_id);
            }
            if let Some(scanner_id) = cmd.child_attr("scanner", "id") {
                resource.set_attr("scanner_id", scanner_id);
            }
            resource.set_attr("status", TaskStatus::New.as_str());
        }

        // Target-specific
        if resource_type == "target" {
            if let Some(hosts) = parse_element_text(raw_xml, "hosts") {
                resource.set_attr("hosts", &hosts);
            }
        }

        let id = store.create(resource);
        format!(
            "<{}_response status=\"201\" \
             status_text=\"OK, resource created\" \
             id=\"{id}\"/>",
            cmd.name
        )
        .into_bytes()
    }

    fn handle_get(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let resource_type = cmd
            .name
            .strip_prefix("get_")
            .unwrap_or("unknown")
            .trim_end_matches('s');

        // Special: get_version handled above
        // Special: get_feeds, get_info, etc. → echo for now
        let _plural = cmd.name.strip_prefix("get_").unwrap_or("unknown");

        // Check for single resource by ID
        let id_attr = format!("{resource_type}_id");
        if let Some(id_str) = cmd.attr(&id_attr) {
            if let Ok(uuid) = Uuid::parse_str(id_str) {
                if let Some(resource) = store.get(&uuid) {
                    let xml = resource.to_xml();
                    return format!(
                        "<{}_response status=\"200\" status_text=\"OK\">\
                         {xml}\
                         </{}_response>",
                        cmd.name, cmd.name
                    )
                    .into_bytes();
                }
            }
            return error_response(&cmd.name, 404, "Resource not found");
        }

        // List all
        let trash = cmd.attr("trash") == Some("1");
        let resources = if trash {
            store.list_trashed(resource_type)
        } else {
            store.list(resource_type)
        };

        let count = resources.len();
        let items: String = resources.iter().map(|r| r.to_xml()).collect();

        format!(
            "<{name}_response status=\"200\" status_text=\"OK\">\
             {items}\
             <{resource_type}_count>{count}<filtered>{count}</filtered></{resource_type}_count>\
             </{name}_response>",
            name = cmd.name,
        )
        .into_bytes()
    }

    fn handle_modify(
        &self,
        cmd: &ParsedCommand,
        raw_xml: &[u8],
        store: &ResourceStore,
    ) -> Vec<u8> {
        let resource_type = cmd.name.strip_prefix("modify_").unwrap_or("unknown");
        let id_attr = format!("{resource_type}_id");

        let Some(id_str) = cmd.attr(&id_attr) else {
            return error_response(&cmd.name, 400, "Missing required attribute: id");
        };

        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        let new_name = parse_element_text(raw_xml, "name");
        let new_comment = parse_element_text(raw_xml, "comment");

        let modified = store.modify(&uuid, |r| {
            if let Some(ref name) = new_name {
                r.name.clone_from(name);
            }
            if let Some(ref comment) = new_comment {
                r.comment.clone_from(comment);
            }
        });

        if modified {
            format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
        } else {
            error_response(&cmd.name, 404, "Resource not found")
        }
    }

    fn handle_delete(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let resource_type = cmd.name.strip_prefix("delete_").unwrap_or("unknown");
        let id_attr = format!("{resource_type}_id");

        let Some(id_str) = cmd.attr(&id_attr) else {
            return error_response(&cmd.name, 400, "Missing required attribute: id");
        };

        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        let ultimate = cmd.attr("ultimate") == Some("1");

        if store.delete(&uuid, ultimate) {
            format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
        } else {
            error_response(&cmd.name, 404, "Resource not found")
        }
    }

    fn handle_start_task(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("task_id") else {
            return error_response(&cmd.name, 400, "Missing task_id");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        // Check current status
        let current_status = store
            .get(&uuid)
            .and_then(|r| r.attr("status").map(String::from));

        match current_status.as_deref() {
            Some("New") | Some("Stopped") | Some("Done") => {
                let report_id = Uuid::new_v4();
                store.modify(&uuid, |r| {
                    r.set_attr("status", TaskStatus::Running.as_str());
                    r.set_attr("report_id", &report_id.to_string());
                });
                format!(
                    "<start_task_response status=\"202\" status_text=\"OK\">\
                     <report_id>{report_id}</report_id>\
                     </start_task_response>"
                )
                .into_bytes()
            }
            Some("Running") | Some("Requested") => {
                error_response(&cmd.name, 409, "Task is already running")
            }
            None => error_response(&cmd.name, 404, "Task not found"),
            _ => error_response(&cmd.name, 409, "Task cannot be started in current state"),
        }
    }

    fn handle_stop_task(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("task_id") else {
            return error_response(&cmd.name, 400, "Missing task_id");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        let current_status = store
            .get(&uuid)
            .and_then(|r| r.attr("status").map(String::from));

        match current_status.as_deref() {
            Some("Running") | Some("Requested") => {
                store.modify(&uuid, |r| {
                    r.set_attr("status", TaskStatus::Stopped.as_str());
                });
                format!("<stop_task_response status=\"200\" status_text=\"OK\"/>").into_bytes()
            }
            Some("Stopped") => error_response(&cmd.name, 409, "Task is already stopped"),
            None => error_response(&cmd.name, 404, "Task not found"),
            _ => error_response(&cmd.name, 409, "Task cannot be stopped in current state"),
        }
    }

    fn handle_resume_task(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("task_id") else {
            return error_response(&cmd.name, 400, "Missing task_id");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        let current_status = store
            .get(&uuid)
            .and_then(|r| r.attr("status").map(String::from));

        match current_status.as_deref() {
            Some("Stopped") => {
                let report_id = Uuid::new_v4();
                store.modify(&uuid, |r| {
                    r.set_attr("status", TaskStatus::Running.as_str());
                    r.set_attr("report_id", &report_id.to_string());
                });
                format!(
                    "<resume_task_response status=\"202\" status_text=\"OK\">\
                     <report_id>{report_id}</report_id>\
                     </resume_task_response>"
                )
                .into_bytes()
            }
            Some("Running") => error_response(&cmd.name, 409, "Task is already running"),
            None => error_response(&cmd.name, 404, "Task not found"),
            _ => error_response(&cmd.name, 409, "Task can only be resumed from Stopped state"),
        }
    }

    fn handle_restore(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("id") else {
            return error_response("restore", 400, "Missing id attribute");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response("restore", 400, "Invalid UUID");
        };

        if store.restore(&uuid) {
            "<restore_response status=\"200\" status_text=\"OK\"/>"
                .as_bytes()
                .to_vec()
        } else {
            error_response("restore", 404, "Resource not found in trashcan")
        }
    }
}
