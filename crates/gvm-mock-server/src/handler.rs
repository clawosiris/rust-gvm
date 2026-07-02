// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP session handler — processes commands and generates responses.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use uuid::Uuid;

use crate::command_parser::{parse_command, parse_element_text, ParsedCommand};
use crate::fault::{FaultAction, FaultEngine};
use crate::fixtures::FixtureStore;
use crate::history::CommandHistory;
use crate::response_gen::{
    echo_response, error_response, generate_binary_report_export, generate_large_report,
    generate_xml_report_export, LargeReportConfig, REPORT_EXPORT_XML_FORMAT_ID,
};
use crate::scenario::{ScenarioEngine, ScenarioMode, ScenarioOutcome, ScenarioStep};
use crate::store::{Resource, ResourceStore, TaskStatus};
use crate::util::xml_escape;
use crate::version::{command_available, GmpVersion};
use crate::ServerMode;

/// Handles GMP commands for a single session.
pub struct SessionHandler {
    mode: ServerMode,
    version: GmpVersion,
    history: CommandHistory,
    session_id: u64,
    fixtures: Option<FixtureStore>,
    store: Option<ResourceStore>,
    scenario_engine: Option<Mutex<ScenarioEngine>>,
    large_report: Option<LargeReportConfig>,
    fault_engine: FaultEngine,
    command_count: AtomicUsize,
}

/// Command handling result for the transport layer.
pub enum HandleResult {
    /// Send a response (optionally after delay).
    Respond {
        /// Response bytes to send.
        bytes: Vec<u8>,
        /// Optional delay before sending.
        delay: Option<Duration>,
    },
    /// Close the connection immediately (fault injection).
    Disconnect,
}

impl SessionHandler {
    /// Create a new session handler.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: ServerMode,
        version: GmpVersion,
        history: CommandHistory,
        session_id: u64,
        fixtures: Option<FixtureStore>,
        store: Option<ResourceStore>,
        scenario_config: Option<(ScenarioMode, Vec<ScenarioStep>)>,
        large_report: Option<LargeReportConfig>,
        fault_engine: FaultEngine,
    ) -> Self {
        Self {
            mode,
            version,
            history,
            session_id,
            fixtures,
            store,
            scenario_engine: scenario_config
                .map(|(mode, steps)| Mutex::new(ScenarioEngine::new(mode, steps))),
            large_report,
            fault_engine,
            command_count: AtomicUsize::new(0),
        }
    }

    /// Process a complete GMP XML command and return response/disconnect behavior.
    pub fn handle_command(&self, xml: &[u8]) -> HandleResult {
        let Some(cmd) = parse_command(xml) else {
            return HandleResult::Respond {
                bytes: error_response("unknown", 400, "Could not parse command"),
                delay: None,
            };
        };

        let count = self.command_count.fetch_add(1, Ordering::Relaxed);

        // Record in history
        self.history
            .record(cmd.name.clone(), xml.to_vec(), self.session_id);

        let mut delay: Option<Duration> = None;
        let mut override_response: Option<Vec<u8>> = None;

        // Check fault engine (compose all matching faults)
        if self.fault_engine.has_faults() {
            for action in self.fault_engine.check_all(&cmd.name, count) {
                match action {
                    FaultAction::Disconnect => return HandleResult::Disconnect,
                    FaultAction::MalformedResponse => {
                        override_response = Some(b"THIS IS NOT XML <<<<".to_vec());
                    }
                    FaultAction::TruncatedResponse => {
                        override_response =
                            Some(format!("<{}_response status=\"200\"", cmd.name).into_bytes());
                    }
                    FaultAction::ErrorResponse { status, message } => {
                        override_response = Some(error_response(&cmd.name, status, &message));
                    }
                    FaultAction::Delay(d) => {
                        delay = Some(delay.map_or(d, |cur| cur.max(d)));
                    }
                }
            }
        }

        let bytes = override_response.unwrap_or_else(|| self.normal_response(&cmd, xml));
        HandleResult::Respond { bytes, delay }
    }

    fn normal_response(&self, cmd: &ParsedCommand, xml: &[u8]) -> Vec<u8> {
        match self.mode {
            ServerMode::Echo => echo_response(&cmd.name, self.version.as_str()),
            ServerMode::Fixture => self.handle_fixture(&cmd.name),
            ServerMode::Stateful => self.handle_stateful(cmd, xml),
            ServerMode::Scenario => self.handle_scenario(cmd),
        }
    }

    fn handle_scenario(&self, cmd: &ParsedCommand) -> Vec<u8> {
        let Some(engine) = &self.scenario_engine else {
            return error_response(&cmd.name, 500, "No scenario engine");
        };

        let outcome = match engine.lock() {
            Ok(mut guard) => guard.next_for_command(&cmd.name),
            Err(_) => return error_response(&cmd.name, 500, "Scenario engine lock poisoned"),
        };

        match outcome {
            ScenarioOutcome::Scripted(xml) => xml.into_bytes(),
            ScenarioOutcome::Fallback => echo_response(&cmd.name, self.version.as_str()),
            ScenarioOutcome::StrictMismatch { expected, got } => error_response(
                &cmd.name,
                400,
                &format!("Unexpected command: got {got}, expected {expected}"),
            ),
            ScenarioOutcome::Exhausted => error_response(&cmd.name, 400, "Scenario exhausted"),
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

        if !command_available(&cmd.name, self.version) {
            return crate::response_gen::error_response(
                &cmd.name,
                400,
                &format!(
                    "Command '{}' is not available in GMP {}",
                    cmd.name, self.version
                ),
            );
        }

        // Route to specific handlers
        match cmd.name.as_str() {
            "get_features" => {
                "<get_features_response status=\"200\" status_text=\"OK\"></get_features_response>"
                    .as_bytes()
                    .to_vec()
            }
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
                b"<empty_trashcan_response status=\"200\" status_text=\"OK\"/>".to_vec()
            }
            "restore" => self.handle_restore(cmd, store),
            // Help
            "help" => render_help_response(cmd.attr("format")),
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

    fn handle_create(&self, cmd: &ParsedCommand, raw_xml: &[u8], store: &ResourceStore) -> Vec<u8> {
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

        let name = match resource_type {
            "note" | "override" => parse_element_text(raw_xml, "text")
                .or_else(|| parse_element_text(raw_xml, "name"))
                .unwrap_or_default(),
            _ => parse_element_text(raw_xml, "name").unwrap_or_default(),
        };
        let requires_name = !matches!(
            resource_type,
            "note" | "override" | "ticket" | "port_range" | "report"
        );
        if name.is_empty() && requires_name {
            return error_response(&cmd.name, 400, "Missing required element: name");
        }

        let mut resource = Resource::new(resource_type, &name);

        // Extract comment
        if let Some(comment) = parse_element_text(raw_xml, "comment") {
            resource.comment = comment;
        }
        if let Some(scheduler_cron_time) = parse_element_text(raw_xml, "scheduler_cron_time") {
            resource.set_attr("scheduler_cron_time", &scheduler_cron_time);
        }

        if matches!(resource_type, "config" | "task") {
            if let Some(usage_type) = parse_element_text(raw_xml, "usage_type") {
                resource.set_attr("usage_type", &usage_type);
            }
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

        if resource_type == "report" {
            if let Some(task_id) = cmd.child_attr("task", "id") {
                resource.set_attr("task_id", task_id);
                if let Ok(task_uuid) = Uuid::parse_str(task_id) {
                    if let Some(task) = store.get(&task_uuid) {
                        if let Some(usage_type) = task.attr("usage_type") {
                            resource.set_attr("usage_type", usage_type);
                        }
                    }
                }
            }
        }

        // Target-specific
        if resource_type == "target" {
            if let Some(hosts) = parse_element_text(raw_xml, "hosts") {
                resource.set_attr("hosts", &hosts);
            }
        }

        if resource_type == "asset" {
            let asset_type = cmd
                .attr("asset_type")
                .map(str::to_string)
                .or_else(|| cmd.attr("type").map(str::to_string))
                .or_else(|| parse_element_text(raw_xml, "type"))
                .unwrap_or_default();
            if !asset_type.is_empty() {
                resource.set_attr("asset_type", &asset_type);
                resource.set_attr("type", &asset_type);
            }
        }

        if matches!(resource_type, "note" | "override") {
            if let Some(nvt_oid) = parse_element_text(raw_xml, "nvt_oid")
                .or_else(|| cmd.child_attr("nvt", "oid").map(str::to_string))
            {
                resource.set_attr("nvt_oid", &nvt_oid);
            }
            if let Some(hosts) = parse_element_text(raw_xml, "hosts") {
                resource.set_attr("hosts", &hosts);
            }
            if let Some(port) = parse_element_text(raw_xml, "port") {
                resource.set_attr("port", &port);
            }
            if let Some(severity) = parse_element_text(raw_xml, "severity") {
                resource.set_attr("severity", &severity);
            }
            if let Some(new_severity) = parse_element_text(raw_xml, "new_severity") {
                resource.set_attr("new_severity", &new_severity);
            }
            if let Some(active) = parse_element_text(raw_xml, "active") {
                resource.set_attr("active", &active);
            }
            if let Some(result_id) = cmd.child_attr("result", "id") {
                resource.set_attr("result_id", result_id);
            }
            if let Some(task_id) = cmd.child_attr("task", "id") {
                resource.set_attr("task_id", task_id);
            }
        }

        if resource_type == "ticket" {
            if let Some(result_id) = parse_element_text(raw_xml, "result_id")
                .or_else(|| cmd.child_attr("result", "id").map(str::to_string))
            {
                resource.set_attr("result_id", &result_id);
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
        match cmd.name.as_str() {
            "get_feeds" => return render_feeds_response(),
            "get_aggregates" => return render_aggregates_response(cmd),
            "get_system_reports" => return render_system_reports_response(),
            "get_info" => return render_secinfo_response(cmd),
            "get_report_hosts"
            | "get_report_ports"
            | "get_report_applications"
            | "get_report_operating_systems"
            | "get_report_cves"
            | "get_report_vulns"
            | "get_report_tls_certificates"
            | "get_report_errors"
            | "get_report_closed_cves" => return self.render_report_detail_response(cmd, store),
            "get_timezones" | "get_credential_stores" => {
                return FixtureStore::new(self.version)
                    .get(&cmd.name)
                    .expect("built-in fixture present")
                    .into_bytes();
            }
            _ => {}
        }

        let resource_type =
            singularize_resource_type(cmd.name.strip_prefix("get_").unwrap_or("unknown"));
        let requested_usage_type = cmd.attr("usage_type");

        // Special: get_version handled above
        // Check for single resource by ID
        let id_attr = format!("{resource_type}_id");
        if let Some(id_str) = cmd.attr(&id_attr) {
            if let Ok(uuid) = Uuid::parse_str(id_str) {
                if let Some(resource) = store.get(&uuid) {
                    if !usage_type_matches(&resource, requested_usage_type) {
                        return error_response(&cmd.name, 404, "Resource not found");
                    }
                    if cmd.name == "get_reports" {
                        return self.render_single_report_response(cmd, &resource, store);
                    }
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

        // List (with optional filter)
        let trash = cmd.attr("trash") == Some("1");
        let filter = cmd.attr("filter");
        let mut resources = if trash {
            store.list_trashed(resource_type)
        } else if let Some(filter_str) = filter {
            store.list_filtered(resource_type, filter_str)
        } else {
            store.list(resource_type)
        };

        if cmd.name == "get_assets" {
            if let Some(asset_type) = cmd.attr("asset_type").or_else(|| cmd.attr("type")) {
                resources.retain(|resource| resource.attr("asset_type") == Some(asset_type));
            }
        }

        if let Some(usage_type) = requested_usage_type {
            resources.retain(|resource| resource.attr("usage_type") == Some(usage_type));
        }

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

    fn handle_modify(&self, cmd: &ParsedCommand, raw_xml: &[u8], store: &ResourceStore) -> Vec<u8> {
        let resource_type = cmd.name.strip_prefix("modify_").unwrap_or("unknown");
        let id_attr = format!("{resource_type}_id");

        let id_str = if cmd.name == "modify_integration_config" {
            let Some(id) = cmd.attr("uuid") else {
                return error_response(&cmd.name, 400, "Missing required attribute: uuid");
            };
            id
        } else {
            let Some(id) = cmd.attr(&id_attr) else {
                let message = format!("Missing required attribute: {id_attr}");
                return error_response(&cmd.name, 400, &message);
            };
            id
        };

        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        let new_name = parse_element_text(raw_xml, "name");
        let new_text = parse_element_text(raw_xml, "text");
        let new_comment = parse_element_text(raw_xml, "comment");
        let new_host = parse_element_text(raw_xml, "host");
        let new_hosts = parse_element_text(raw_xml, "hosts");
        let new_status = parse_element_text(raw_xml, "status");
        let new_scheduler_cron_time = parse_element_text(raw_xml, "scheduler_cron_time");
        let new_nvt_oid = parse_element_text(raw_xml, "nvt_oid")
            .or_else(|| cmd.child_attr("nvt", "oid").map(str::to_string));
        let new_result_id = parse_element_text(raw_xml, "result_id")
            .or_else(|| cmd.child_attr("result", "id").map(str::to_string));
        let new_task_id = cmd.child_attr("task", "id").map(str::to_string);
        let new_port = parse_element_text(raw_xml, "port");
        let new_severity = parse_element_text(raw_xml, "severity");
        let new_new_severity = parse_element_text(raw_xml, "new_severity");
        let new_active = parse_element_text(raw_xml, "active");
        let new_usage_type = parse_element_text(raw_xml, "usage_type");
        let new_value = parse_element_text(raw_xml, "value");
        let (
            new_service_url,
            new_service_cacert,
            new_oidc_provider_url,
            new_oidc_client_id,
            new_oidc_client_secret,
        ) = if resource_type == "integration_config" {
            (
                nested_child_text(cmd, &["service", "url"]),
                nested_child_text(cmd, &["service", "cacert"]),
                nested_child_text(cmd, &["oidc", "oidc_provider_url"]),
                nested_child_text(cmd, &["oidc", "client", "id"]),
                nested_child_text(cmd, &["oidc", "client", "secret"]),
            )
        } else {
            (None, None, None, None, None)
        };

        let modified = store.modify(&uuid, |r| {
            if matches!(resource_type, "note" | "override") {
                if let Some(ref text) = new_text {
                    r.name.clone_from(text);
                }
            } else if let Some(ref name) = new_name {
                r.name.clone_from(name);
            }
            if let Some(ref comment) = new_comment {
                r.comment.clone_from(comment);
            }
            if let Some(ref host) = new_host {
                r.set_attr("host", host);
            }
            if let Some(ref hosts) = new_hosts {
                r.set_attr("hosts", hosts);
            }
            if let Some(ref nvt_oid) = new_nvt_oid {
                r.set_attr("nvt_oid", nvt_oid);
            }
            if let Some(ref result_id) = new_result_id {
                r.set_attr("result_id", result_id);
            }
            if let Some(ref task_id) = new_task_id {
                r.set_attr("task_id", task_id);
            }
            if let Some(ref port) = new_port {
                r.set_attr("port", port);
            }
            if let Some(ref severity) = new_severity {
                r.set_attr("severity", severity);
            }
            if let Some(ref new_severity) = new_new_severity {
                r.set_attr("new_severity", new_severity);
            }
            if let Some(ref active) = new_active {
                r.set_attr("active", active);
            }
            if let Some(ref usage_type) = new_usage_type {
                r.set_attr("usage_type", usage_type);
            }
            if let Some(ref value) = new_value {
                r.set_attr("value", value);
            }
            if let Some(ref service_url) = new_service_url {
                r.set_attr("service_url", service_url);
            }
            if let Some(ref service_cacert) = new_service_cacert {
                r.set_attr("service_cacert", service_cacert);
            }
            if let Some(ref oidc_provider_url) = new_oidc_provider_url {
                r.set_attr("oidc_provider_url", oidc_provider_url);
            }
            if let Some(ref oidc_client_id) = new_oidc_client_id {
                r.set_attr("oidc_provider_client_id", oidc_client_id);
            }
            if let Some(ref oidc_client_secret) = new_oidc_client_secret {
                r.set_attr("oidc_provider_client_secret", oidc_client_secret);
            }
            if let Some(ref scheduler_cron_time) = new_scheduler_cron_time {
                r.set_attr("scheduler_cron_time", scheduler_cron_time);
            }
            if resource_type == "ticket" {
                if let Some(ref status) = new_status {
                    r.set_attr("status", status);
                }
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

        let (current_status, task_name) = store
            .get(&uuid)
            .map(|r| (r.attr("status").map(String::from), r.name))
            .unwrap_or((None, "Task Report".to_string()));

        match current_status.as_deref() {
            Some("New") | Some("Stopped") | Some("Done") => {
                let report_id = Uuid::new_v4();
                let mut report =
                    Resource::with_id("report", &format!("Report for {task_name}"), report_id);
                report.set_attr("task_id", &uuid.to_string());
                let _ = store.create(report);
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
                b"<stop_task_response status=\"200\" status_text=\"OK\"/>".to_vec()
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

        let (current_status, task_name) = store
            .get(&uuid)
            .map(|r| (r.attr("status").map(String::from), r.name))
            .unwrap_or((None, "Task Report".to_string()));

        match current_status.as_deref() {
            Some("Stopped") => {
                let report_id = Uuid::new_v4();
                let mut report =
                    Resource::with_id("report", &format!("Report for {task_name}"), report_id);
                report.set_attr("task_id", &uuid.to_string());
                let _ = store.create(report);
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
            _ => error_response(
                &cmd.name,
                409,
                "Task can only be resumed from Stopped state",
            ),
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

    fn render_single_report_response(
        &self,
        cmd: &ParsedCommand,
        report: &Resource,
        store: &ResourceStore,
    ) -> Vec<u8> {
        if let Some(format_id) = cmd.attr("format_id") {
            let format_uuid = Uuid::parse_str(format_id)
                .unwrap_or(crate::response_gen::REPORT_EXPORT_BINARY_FORMAT_ID);
            if format_uuid == REPORT_EXPORT_XML_FORMAT_ID {
                return generate_xml_report_export(report.id, format_uuid).into_bytes();
            }
            return generate_binary_report_export(report.id, format_uuid).into_bytes();
        }

        if let Some(config) = self.large_report {
            if report.attr("task_id").is_some() {
                return generate_large_report(report.id, &config).into_bytes();
            }
        }

        let report_id = report.id.to_string();
        let results: Vec<Resource> = store
            .list("result")
            .into_iter()
            .filter(|resource| resource.attr("report_id") == Some(report_id.as_str()))
            .collect();
        let count = results.len();
        let results_xml: String = results.iter().map(render_report_result_xml).collect();

        format!(
            "<{name}_response status=\"200\" status_text=\"OK\">\
             <report id=\"{id}\">\
             <name>{report_name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{creation_time}</creation_time>\
             <modification_time>{modification_time}</modification_time>\
             <report id=\"{id}\">\
             <results max=\"100\" start=\"1\">{results_xml}</results>\
             <result_count><full>{count}</full><filtered>{count}</filtered></result_count>\
             </report>\
             </report>\
             </{name}_response>",
            name = cmd.name,
            id = report.id,
            report_name = xml_escape(&report.name),
            comment = xml_escape(&report.comment),
            creation_time = report.creation_time,
            modification_time = report.modification_time,
        )
        .into_bytes()
    }

    fn render_report_detail_response(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(report_id) = cmd.attr("report_id") else {
            return error_response(&cmd.name, 400, "Missing required attribute: report_id");
        };

        let Ok(report_uuid) = Uuid::parse_str(report_id) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        if store.get(&report_uuid).is_none() {
            return error_response(&cmd.name, 404, "Resource not found");
        }

        let (element_name, items) = match cmd.name.as_str() {
            "get_report_hosts" => (
                "host",
                vec![
                    "<host id=\"host-1\"><name>192.0.2.10</name><severity>7.5</severity></host>"
                        .to_string(),
                    "<host id=\"host-2\"><name>192.0.2.20</name><severity>5.0</severity></host>"
                        .to_string(),
                ],
            ),
            "get_report_ports" => (
                "port",
                vec![
                    "<port id=\"port-1\"><name>22/tcp</name><severity>6.5</severity></port>"
                        .to_string(),
                    "<port id=\"port-2\"><name>443/tcp</name><severity>4.2</severity></port>"
                        .to_string(),
                ],
            ),
            "get_report_applications" => (
                "application",
                vec![
                    "<application id=\"app-1\"><name>OpenSSH</name><severity>6.5</severity></application>"
                        .to_string(),
                    "<application id=\"app-2\"><name>nginx</name><severity>4.0</severity></application>"
                        .to_string(),
                ],
            ),
            "get_report_operating_systems" => (
                "operating_system",
                vec![
                    "<operating_system id=\"os-1\"><name>Debian</name><severity>5.5</severity></operating_system>"
                        .to_string(),
                    "<operating_system id=\"os-2\"><name>Ubuntu</name><severity>3.1</severity></operating_system>"
                        .to_string(),
                ],
            ),
            "get_report_cves" => (
                "cve",
                vec![
                    "<cve id=\"cve-1\"><name>CVE-2026-0001</name><severity>8.0</severity></cve>"
                        .to_string(),
                    "<cve id=\"cve-2\"><name>CVE-2026-0002</name><severity>6.0</severity></cve>"
                        .to_string(),
                ],
            ),
            "get_report_vulns" => (
                "vuln",
                vec![
                    "<vuln id=\"vuln-1\"><name>OpenSSL Vulnerability</name><host>192.0.2.10</host><port>443/tcp</port><threat>High</threat><severity>8.2</severity><family>General</family><cve>CVE-2026-0001</cve></vuln>"
                        .to_string(),
                ],
            ),
            "get_report_tls_certificates" => (
                "tls_certificate",
                vec![
                    "<tls_certificate id=\"tls-1\"><name>example.com</name><host>192.0.2.10</host><port>443/tcp</port><subject>CN=example.com</subject><issuer>CN=Example CA</issuer><serial>01</serial><expiration_time>2027-01-01T00:00:00Z</expiration_time></tls_certificate>"
                        .to_string(),
                ],
            ),
            "get_report_errors" => (
                "error",
                vec![
                    "<error id=\"err-1\"><name>Host dead</name><host>192.0.2.20</host><port>general/tcp</port><description>Could not reach host.</description><nvt><name>Ping Host</name></nvt></error>"
                        .to_string(),
                ],
            ),
            "get_report_closed_cves" => (
                "closed_cve",
                vec![
                    "<closed_cve id=\"closed-1\"><name>CVE-2025-9999</name><host>192.0.2.30</host><severity>5.0</severity></closed_cve>"
                        .to_string(),
                ],
            ),
            _ => return error_response(&cmd.name, 400, "Unsupported report detail command"),
        };

        let count = items.len();
        let items = items.join("");
        format!(
            "<{name}_response status=\"200\" status_text=\"OK\">{items}<{element_name}_count>{count}<filtered>{count}</filtered></{element_name}_count></{name}_response>",
            name = cmd.name,
        )
        .into_bytes()
    }
}

fn render_report_result_xml(result: &Resource) -> String {
    let mut xml = format!(
        "<result id=\"{id}\"><name>{name}</name>",
        id = result.id,
        name = xml_escape(&result.name),
    );

    if let Some(host) = result.attr("host") {
        xml.push_str(&format!("<host>{}</host>", xml_escape(host)));
    }
    if let Some(port) = result.attr("port") {
        xml.push_str(&format!("<port>{}</port>", xml_escape(port)));
    }
    if let Some(threat) = result.attr("threat") {
        xml.push_str(&format!("<threat>{}</threat>", xml_escape(threat)));
    }
    if let Some(severity) = result.attr("severity") {
        xml.push_str(&format!("<severity>{}</severity>", xml_escape(severity)));
    }

    xml.push_str("</result>");
    xml
}

fn usage_type_matches(resource: &Resource, requested_usage_type: Option<&str>) -> bool {
    match requested_usage_type {
        Some(usage_type) => resource.attr("usage_type") == Some(usage_type),
        None => true,
    }
}

fn render_help_response(format: Option<&str>) -> Vec<u8> {
    let body = match format {
        Some("brief") => "<commands><command>get_feeds</command><command>get_tasks</command><command>get_configs</command></commands>",
        _ => "<commands><command>get_feeds</command><command>get_tasks</command><command>get_configs</command><command>get_reports</command><command>get_info</command><command>get_settings</command></commands>",
    };
    format!("<help_response status=\"200\" status_text=\"OK\">{body}</help_response>").into_bytes()
}

fn render_feeds_response() -> Vec<u8> {
    "<get_feeds_response status=\"200\" status_text=\"OK\">\
     <feed><type>NVT</type><name>Network Vulnerability Tests</name><version>2026031801</version><status>current</status></feed>\
     <feed><type>SCAP</type><name>SCAP Data</name><version>2026031701</version><status>current</status></feed>\
     <feed><type>CERT</type><name>CERT Advisories</name><version>2026031601</version><status>current</status></feed>\
     <feed_count>3<filtered>3</filtered></feed_count>\
     </get_feeds_response>"
        .as_bytes()
        .to_vec()
}

fn render_aggregates_response(cmd: &ParsedCommand) -> Vec<u8> {
    let resource_type = cmd.attr("type").unwrap_or("task");
    let group_column = cmd.attr("group_column").unwrap_or("severity");
    format!(
        "<get_aggregates_response status=\"200\" status_text=\"OK\">\
         <type>{resource_type}</type>\
         <group_column>{group_column}</group_column>\
         <aggregate><text>High</text><value>3</value></aggregate>\
         <aggregate><text>Medium</text><value>5</value></aggregate>\
         </get_aggregates_response>"
    )
    .into_bytes()
}

fn render_system_reports_response() -> Vec<u8> {
    "<get_system_reports_response status=\"200\" status_text=\"OK\">\
     <system_report id=\"system-report-1\">\
     <name>GVMD Performance Snapshot</name>\
     <comment>Mock system report</comment>\
     <created>2026-03-18T00:00:00Z</created>\
     <duration>15m</duration>\
     </system_report>\
     <system_report_count>1<filtered>1</filtered></system_report_count>\
     </get_system_reports_response>"
        .as_bytes()
        .to_vec()
}

fn render_secinfo_response(cmd: &ParsedCommand) -> Vec<u8> {
    let info_type = cmd.attr("type").unwrap_or("cve");
    let (element, entries) = match info_type {
        "CPE" | "cpe" => (
            "cpe",
            vec![
                ("cpe:/a:greenbone:gvm", "Greenbone GVM"),
                ("cpe:/o:debian:debian_linux:12", "Debian 12"),
            ],
        ),
        "CVE" | "cve" => (
            "cve",
            vec![
                ("CVE-2026-1000", "Mock CVE one"),
                ("CVE-2026-1001", "Mock CVE two"),
            ],
        ),
        "CERT_BUND_ADV" | "cert_bund_adv" => (
            "cert_bund_adv",
            vec![
                ("CB-K26/001", "CERT-Bund advisory one"),
                ("CB-K26/002", "CERT-Bund advisory two"),
            ],
        ),
        "DFN_CERT_ADV" | "dfn_cert_adv" => (
            "dfn_cert_adv",
            vec![
                ("DFN-2026-001", "DFN-CERT advisory one"),
                ("DFN-2026-002", "DFN-CERT advisory two"),
            ],
        ),
        "os" => (
            "os",
            vec![("os-1", "Debian GNU/Linux"), ("os-2", "Ubuntu Linux")],
        ),
        "vuln" => (
            "vuln",
            vec![
                ("vuln-1", "Outdated package"),
                ("vuln-2", "Weak configuration"),
            ],
        ),
        _ => ("info", vec![("info-1", "Generic info entry")]),
    };

    let info_id = cmd.attr("info_id");
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|(id, _)| info_id.is_none_or(|wanted| wanted == *id))
        .collect();
    let count = entries.len();
    let items: String = entries
        .into_iter()
        .map(|(id, name)| format!("<{element} id=\"{id}\"><name>{name}</name></{element}>"))
        .collect();
    format!(
        "<get_info_response status=\"200\" status_text=\"OK\">{items}<{element}_count>{count}<filtered>{count}</filtered></{element}_count></get_info_response>"
    )
    .into_bytes()
}

fn nested_child_text(cmd: &ParsedCommand, path: &[&str]) -> Option<String> {
    let (first, rest) = path.split_first()?;
    let mut element = cmd.children.iter().find(|child| child.name == *first)?;
    for name in rest {
        element = element.children.iter().find(|child| child.name == **name)?;
    }
    Some(element.text.clone().unwrap_or_default())
}

fn singularize_resource_type(plural: &str) -> &str {
    match plural {
        "nvts" => "nvt",
        "assets" => "asset",
        "results" => "result",
        s if s.ends_with('s') => &s[..s.len() - 1],
        s => s,
    }
}
