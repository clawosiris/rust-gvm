// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP session handler — processes commands and generates responses.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use uuid::Uuid;

use crate::command_parser::{parse_command, parse_element_text, ParsedCommand, ParsedElement};
use crate::fault::{FaultAction, FaultEngine};
use crate::fixtures::FixtureStore;
use crate::history::CommandHistory;
use crate::response_gen::{
    echo_response, error_response, generate_binary_report_export, generate_large_report,
    generate_xml_report_export, is_known_command, LargeReportConfig, REPORT_EXPORT_XML_FORMAT_ID,
};
use crate::scenario::{ScenarioEngine, ScenarioMode, ScenarioOutcome, ScenarioStep};
use crate::store::{
    AssetInputProfile, DeleteAssetResult, Resource, ResourceStore, SpecializedTaskTarget,
    StoreError, TaskReferenceUpdates, TaskReferences, TaskStatus, DEFAULT_CONFIG_ID,
    DEFAULT_SCANNER_ID,
};
use crate::util::{xml_escape, xml_escape_attr};
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

fn asset_sort_value<'a>(resource: &'a Resource, field: &str) -> &'a str {
    match field {
        "name" => &resource.name,
        "comment" => &resource.comment,
        "type" => resource.asset_type().unwrap_or_default(),
        _ => resource.attr(field).unwrap_or_default(),
    }
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
            ServerMode::Fixture if cmd.name == "get_info" => render_secinfo_response(cmd),
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

        if !is_known_command(&cmd.name) {
            return error_response(&cmd.name, 400, "Unknown command");
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
        if cmd.name == "modify_credential"
            && has_credential_store_credential_modify_field(cmd)
            && self.version != GmpVersion::V22_8
        {
            return error_response(
                &cmd.name,
                400,
                "Credential-store-backed credentials require GMP 22.8",
            );
        }

        // Route to specific handlers
        match cmd.name.as_str() {
            "get_features" => render_features_response(),
            "get_agent_installer_instruction" => render_agent_installer_instruction_response(cmd),
            "get_agent_support_bundle" => render_agent_support_bundle_response(cmd),
            "create_asset" => self.handle_create_asset(cmd, store),
            "get_assets" => self.handle_get_assets(cmd, store),
            "modify_asset" => self.handle_modify_asset(cmd, store),
            "delete_asset" => self.handle_delete_asset(cmd, store),
            // Create commands
            name if name.starts_with("create_") => self.handle_create(cmd, raw_xml, store),
            // Get commands
            name if name.starts_with("get_") => self.handle_get(cmd, store),
            "modify_agent" => handle_agent_set_action(cmd),
            "modify_agent_control_scan_config" => handle_modify_agent_control_scan_config(cmd),
            "modify_auth" => self.handle_modify_auth(cmd),
            "modify_credential_store" => handle_modify_credential_store(cmd),
            "modify_license" => self.handle_modify_license(cmd),
            // Modify commands
            name if name.starts_with("modify_") => self.handle_modify(cmd, raw_xml, store),
            "verify_credential_store" => handle_verify_credential_store(cmd),
            "delete_agent" => handle_agent_set_action(cmd),
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
            "help" => render_help_response(cmd),
            "sync_agents" => b"<sync_agents_response status=\"200\" status_text=\"OK\"/>".to_vec(),
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

    fn handle_create_asset(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let profile = store.asset_input_profile();
        let canonical = cmd.children.iter().find(|child| child.name == "asset");

        let parsed = canonical.and_then(|asset| {
            let asset_type = element_child_text(asset, "type")?;
            let name = element_child_text(asset, "name")?;
            let comment = asset
                .children
                .iter()
                .find(|child| child.name == "comment")
                .map(|child| child.text.as_deref().unwrap_or_default())
                .unwrap_or_default();
            Some((
                asset_type.to_string(),
                name.to_string(),
                comment.to_string(),
                false,
            ))
        });

        let parsed = parsed.or_else(|| {
            (profile == AssetInputProfile::LegacyFlatCompatibility).then(|| {
                let asset_type = cmd
                    .attr("asset_type")
                    .or_else(|| cmd.child_text("asset_type"))
                    .or_else(|| cmd.attr("type"))
                    .or_else(|| cmd.child_text("type"))?
                    .to_string();
                let name = cmd
                    .child_text("name")
                    .or_else(|| cmd.child_text("value"))?
                    .to_string();
                let comment = cmd.child_text("comment").unwrap_or_default().to_string();
                Some((asset_type, name, comment, true))
            })?
        });

        let Some((asset_type, name, comment, legacy_flat)) = parsed else {
            return error_response(
                &cmd.name,
                400,
                "Missing required nested asset/type/name elements",
            );
        };
        if asset_type.is_empty() || name.is_empty() {
            return error_response(&cmd.name, 400, "Asset type and name must not be empty");
        }

        let asset_type = asset_type.to_ascii_lowercase();
        if asset_type != "host"
            && !(legacy_flat
                && profile == AssetInputProfile::LegacyFlatCompatibility
                && asset_type == "os")
        {
            return error_response(
                &cmd.name,
                400,
                "Direct asset creation supports only host assets",
            );
        }

        if asset_type == "host" && !legacy_flat && name.parse::<IpAddr>().is_err() {
            return error_response(
                &cmd.name,
                400,
                "Host asset name must be a valid IPv4 or IPv6 address",
            );
        }

        let mut resource = Resource::new("asset", &name);
        resource.comment = comment;
        resource.set_attr("type", &asset_type);
        if legacy_flat {
            resource.set_attr("asset_type", &asset_type);
            resource.set_attr("value", &name);
        }

        let id = store.create(resource);
        format!(
            "<create_asset_response status=\"201\" status_text=\"OK, resource created\" id=\"{id}\"/>"
        )
        .into_bytes()
    }

    fn handle_get_assets(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let profile = store.asset_input_profile();
        let asset_type = cmd.attr("type").or_else(|| {
            (profile == AssetInputProfile::LegacyFlatCompatibility)
                .then(|| cmd.attr("asset_type"))
                .flatten()
        });
        let Some(asset_type) = asset_type else {
            return error_response(&cmd.name, 400, "Missing required attribute: type");
        };
        let asset_type = asset_type.to_ascii_lowercase();
        if !matches!(asset_type.as_str(), "host" | "os") {
            return error_response(
                &cmd.name,
                404,
                &format!("Failed to find type '{asset_type}'"),
            );
        }

        if cmd
            .attr("filt_id")
            .is_some_and(|filter_id| filter_id != "0")
        {
            return error_response(&cmd.name, 404, "Saved filter not found");
        }

        let trash = matches!(cmd.attr("trash"), Some("1" | "true"));
        let mut resources: Vec<Resource> = if trash {
            store.list_trashed("asset")
        } else {
            store.list("asset")
        }
        .into_iter()
        .filter(|resource| resource.asset_type() == Some(asset_type.as_str()))
        .collect();
        let total = resources.len();

        if let Some(id) = cmd.attr("asset_id") {
            let Ok(id) = Uuid::parse_str(id) else {
                return error_response(&cmd.name, 400, "Invalid UUID");
            };
            let Some(resource) = resources.into_iter().find(|resource| resource.id == id) else {
                return error_response(&cmd.name, 404, "Resource not found");
            };
            return format!(
                "<get_assets_response status=\"200\" status_text=\"OK\">{}\
                 <asset_count>{total}<filtered>1</filtered><page>1</page></asset_count>\
                 </get_assets_response>",
                resource.to_asset_xml(),
            )
            .into_bytes();
        }

        let mut first = 1usize;
        let mut rows = None;
        let mut sort_field = "name";
        let mut reverse = false;
        if let Some(filter) = cmd.attr("filter") {
            for predicate in filter.split_whitespace() {
                let Some((key, value)) = predicate.split_once('=') else {
                    continue;
                };
                match key {
                    "first" => {
                        first = value
                            .parse::<isize>()
                            .ok()
                            .map_or(1, |value| value.max(0) as usize);
                    }
                    "rows" => {
                        rows = value
                            .parse::<isize>()
                            .ok()
                            .and_then(|value| (value > 0).then_some(value as usize));
                    }
                    "sort" => sort_field = value,
                    "sort-reverse" => {
                        sort_field = value;
                        reverse = true;
                    }
                    "permission" | "owner" | "min_qod" => {}
                    "name" => resources.retain(|resource| resource.name == value),
                    "comment" => resources.retain(|resource| resource.comment == value),
                    "uuid" | "id" => {
                        resources.retain(|resource| resource.id.to_string() == value);
                    }
                    "type" => {
                        resources.retain(|resource| resource.asset_type() == Some(value));
                    }
                    _ => resources.retain(|resource| resource.attr(key) == Some(value)),
                }
            }
        }
        resources.sort_by(|left, right| {
            let left = asset_sort_value(left, sort_field);
            let right = asset_sort_value(right, sort_field);
            if reverse {
                right.cmp(left)
            } else {
                left.cmp(right)
            }
        });

        let filtered = resources.len();
        if !matches!(cmd.attr("ignore_pagination"), Some("1" | "true")) {
            let start = first.saturating_sub(1).min(resources.len());
            let end = rows.map_or(resources.len(), |rows| {
                start.saturating_add(rows).min(resources.len())
            });
            resources = resources[start..end].to_vec();
        }

        let page = resources.len();
        let items: String = resources.iter().map(Resource::to_asset_xml).collect();
        format!(
            "<get_assets_response status=\"200\" status_text=\"OK\">\
             {items}\
             <asset_count>{total}<filtered>{filtered}</filtered><page>{page}</page></asset_count>\
             </get_assets_response>"
        )
        .into_bytes()
    }

    fn handle_modify_asset(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id) = cmd.attr("asset_id") else {
            return error_response(&cmd.name, 400, "Missing required attribute: asset_id");
        };
        let Ok(id) = Uuid::parse_str(id) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };
        let comment = cmd
            .children
            .iter()
            .find(|child| child.name == "comment")
            .and_then(|comment| comment.text.as_deref())
            .unwrap_or_default();

        if store.modify_host_asset_comment(&id, comment) {
            b"<modify_asset_response status=\"200\" status_text=\"OK\"/>".to_vec()
        } else {
            error_response(&cmd.name, 404, "Host asset not found")
        }
    }

    fn handle_delete_asset(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id) = cmd.attr("asset_id") else {
            let message = if cmd.attr("report_id").is_some() {
                "Report-based bulk asset deletion is not implemented by the stateful mock"
            } else {
                "Missing required attribute: asset_id"
            };
            return error_response(&cmd.name, 400, message);
        };
        let Ok(id) = Uuid::parse_str(id) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        match store.delete_asset_permanently(&id) {
            DeleteAssetResult::Deleted => {
                b"<delete_asset_response status=\"200\" status_text=\"OK\"/>".to_vec()
            }
            DeleteAssetResult::InUse => error_response(&cmd.name, 400, "Asset is in use"),
            DeleteAssetResult::NotFound => error_response(&cmd.name, 404, "Asset not found"),
        }
    }

    fn handle_create(&self, cmd: &ParsedCommand, raw_xml: &[u8], store: &ResourceStore) -> Vec<u8> {
        let resource_type = cmd.name.strip_prefix("create_").unwrap_or("unknown");
        let has_config_import_payload = resource_type == "config" && has_config_import_payload(cmd);
        let imported_config = if resource_type == "config" {
            imported_config_element(cmd)
        } else {
            None
        };

        // Check for clone (copy element)
        if let Some(copy_id) = parse_element_text(raw_xml, "copy") {
            if let Ok(uuid) = Uuid::parse_str(&copy_id) {
                match store.clone_typed(&uuid, resource_type) {
                    Ok(new_id) => {
                        return format!(
                            "<{}_response status=\"201\" \
                             status_text=\"OK, resource created\" \
                             id=\"{new_id}\"/>",
                            cmd.name
                        )
                        .into_bytes();
                    }
                    Err(error) => return store_error_response(&cmd.name, error),
                }
            }
            return error_response(&cmd.name, 404, "Resource to clone not found");
        }

        let asset_type = if resource_type == "asset" {
            cmd.attr("asset_type")
                .map(str::to_string)
                .or_else(|| parse_element_text(raw_xml, "asset_type"))
                .or_else(|| cmd.attr("type").map(str::to_string))
                .or_else(|| parse_element_text(raw_xml, "type"))
        } else {
            None
        };
        let asset_value = if resource_type == "asset" {
            parse_element_text(raw_xml, "value")
        } else {
            None
        };

        let name = match resource_type {
            "note" | "override" => parse_element_text(raw_xml, "text")
                .or_else(|| parse_element_text(raw_xml, "name"))
                .unwrap_or_default(),
            "asset" => parse_element_text(raw_xml, "name")
                .or_else(|| asset_value.clone())
                .or_else(|| asset_type.as_ref().map(|ty| format!("{ty} asset")))
                .unwrap_or_else(|| "asset".to_string()),
            "config" if has_config_import_payload => imported_config
                .and_then(|config| element_child_text(config, "name").map(ToOwned::to_owned))
                .unwrap_or_default(),
            "config" => parse_element_text(raw_xml, "name").unwrap_or_default(),
            _ => parse_element_text(raw_xml, "name").unwrap_or_default(),
        };
        let requires_name = !matches!(
            resource_type,
            "asset" | "note" | "override" | "ticket" | "port_range" | "report"
        );
        if name.is_empty() && requires_name {
            return error_response(&cmd.name, 400, "Missing required element: name");
        }
        let credential_store_type = if resource_type == "credential" {
            parse_element_text(raw_xml, "type")
                .filter(|credential_type| is_credential_store_credential_type(credential_type))
        } else {
            None
        };
        if credential_store_type.is_some() && self.version != GmpVersion::V22_8 {
            return error_response(
                &cmd.name,
                400,
                "Credential-store-backed credentials require GMP 22.8",
            );
        }
        if credential_store_type.is_some()
            && parse_element_text(raw_xml, "vault_id").is_none_or(|value| value.trim().is_empty())
        {
            return error_response(&cmd.name, 400, "Missing required element: vault_id");
        }
        if credential_store_type.is_some()
            && parse_element_text(raw_xml, "host_identifier")
                .is_none_or(|value| value.trim().is_empty())
        {
            return error_response(&cmd.name, 400, "Missing required element: host_identifier");
        }
        let (ticket_result_id, ticket_assignee_id, ticket_open_note) = if resource_type == "ticket"
        {
            let Some(result_id) = cmd.child_attr("result", "id") else {
                return error_response(&cmd.name, 400, "Missing required element: result");
            };
            let Some(assignee_id) = nested_child_attr(cmd, &["assigned_to", "user"], "id") else {
                return error_response(
                    &cmd.name,
                    400,
                    "Missing required element: assigned_to/user",
                );
            };
            let Some(open_note) =
                parse_element_text(raw_xml, "open_note").filter(|note| !note.trim().is_empty())
            else {
                return error_response(&cmd.name, 400, "Missing required element: open_note");
            };
            (
                Some(result_id.to_string()),
                Some(assignee_id),
                Some(open_note),
            )
        } else {
            (None, None, None)
        };

        let mut resource = Resource::new(resource_type, &name);

        // Extract comment
        let comment = if has_config_import_payload {
            imported_config
                .and_then(|config| element_child_text(config, "comment").map(ToOwned::to_owned))
        } else {
            parse_element_text(raw_xml, "comment")
        };
        if let Some(comment) = comment {
            resource.comment = comment;
        }
        if let Some(scheduler_cron_time) = parse_element_text(raw_xml, "scheduler_cron_time") {
            resource.set_attr("scheduler_cron_time", &scheduler_cron_time);
        }
        if resource_type == "filter" {
            if let Some(term) = parse_element_text(raw_xml, "term") {
                resource.set_attr("term", &term);
            }
        }
        if resource_type == "ticket" {
            if let Some(result_id) = ticket_result_id {
                resource.set_attr("result_id", &result_id);
            }
            if let Some(assignee_id) = ticket_assignee_id {
                resource.set_attr("assigned_to_id", &assignee_id);
            }
            if let Some(open_note) = ticket_open_note {
                resource.set_attr("open_note", &open_note);
            }
        }
        if resource_type == "oci_image_target" {
            if let Some(image_references) = parse_element_text(raw_xml, "image_references") {
                resource.set_attr("image_references", &image_references);
            }
            if let Some(credential_id) = cmd.child_attr("credential", "id") {
                resource.set_attr("credential_id", credential_id);
            }
        }
        if resource_type == "web_application_target" {
            if let Some(urls) = parse_element_text(raw_xml, "urls") {
                resource.set_attr("urls", &urls);
            }
            if let Some(exclude_urls) = parse_element_text(raw_xml, "exclude_urls") {
                resource.set_attr("exclude_urls", &exclude_urls);
            }
            if let Some(credential_id) = cmd.child_attr("credential", "id") {
                resource.set_attr("credential_id", credential_id);
            }
        }
        if resource_type == "scanner" {
            for field in ["host", "port", "type", "ca_pub"] {
                if let Some(value) = parse_element_text(raw_xml, field) {
                    resource.set_attr(field, &value);
                }
            }
            if let Some(credential_id) = cmd.child_attr("credential", "id") {
                resource.set_attr("credential_id", credential_id);
            }
        }
        if resource_type == "alert" {
            set_alert_fields(&mut resource, cmd);
        }

        if matches!(resource_type, "config" | "task") {
            let usage_type = if has_config_import_payload {
                imported_config.and_then(|config| {
                    element_child_text(config, "usage_type").map(ToOwned::to_owned)
                })
            } else {
                parse_element_text(raw_xml, "usage_type")
            };
            if let Some(usage_type) = usage_type {
                resource.set_attr("usage_type", &usage_type);
            }
        }
        if resource_type == "credential" {
            if let Some(credential_type) = parse_element_text(raw_xml, "type") {
                resource.set_attr("type", &credential_type);
            }
            if let Some(credential_store_id) = parse_element_text(raw_xml, "credential_store_id") {
                resource.set_attr("credential_store_id", &credential_store_id);
            }
            if let Some(vault_id) = parse_element_text(raw_xml, "vault_id") {
                resource.set_attr("vault_id", &vault_id);
            }
            if let Some(host_identifier) = parse_element_text(raw_xml, "host_identifier") {
                resource.set_attr("host_identifier", &host_identifier);
            }
        }
        if resource_type == "permission" {
            set_permission_references(&mut resource, cmd);
        }

        // Task-specific: extract references
        if resource_type == "task" {
            let has_web_application_target = cmd
                .children
                .iter()
                .any(|child| child.name == "web_application_target");
            if has_web_application_target && !matches!(self.version, GmpVersion::V22_8) {
                return error_response(
                    &cmd.name,
                    400,
                    &format!(
                        "Web application target tasks are not available in GMP {}",
                        self.version
                    ),
                );
            }
            if has_web_application_target
                && cmd
                    .child_attr("web_application_target", "id")
                    .is_none_or(str::is_empty)
            {
                return error_response(
                    &cmd.name,
                    400,
                    "Missing required attribute: web_application_target id",
                );
            }
            if let Some(target_id) = cmd.child_attr("target", "id") {
                resource.set_attr("target_id", target_id);
            }
            if let Some(agent_group_id) = cmd.child_attr("agent_group", "id") {
                resource.set_attr("agent_group_id", agent_group_id);
            }
            if let Some(oci_image_target_id) = cmd.child_attr("oci_image_target", "id") {
                resource.set_attr("oci_image_target_id", oci_image_target_id);
            }
            if let Some(web_application_target_id) = cmd.child_attr("web_application_target", "id")
            {
                resource.set_attr("web_application_target_id", web_application_target_id);
            }
            if let Some(config_id) = cmd.child_attr("config", "id") {
                resource.set_attr("config_id", config_id);
            }
            if let Some(scanner_id) = cmd.child_attr("scanner", "id") {
                resource.set_attr("scanner_id", scanner_id);
            }
            resource.set_attr("status", TaskStatus::New.as_str());
        }

        let report_task_id = if resource_type == "report" {
            match optional_child_uuid(cmd, "task") {
                Ok(task_id) => task_id,
                Err(message) => return error_response(&cmd.name, 400, message),
            }
        } else {
            None
        };

        if resource_type == "report" {
            if let Some(task_id) = report_task_id {
                if let Some(task) = store.get_typed(&task_id, "task") {
                    if let Some(usage_type) = task.attr("usage_type") {
                        resource.set_attr("usage_type", usage_type);
                    }
                }
            }
            if let Some(in_assets) = cmd.child_text("in_assets") {
                resource.set_attr("in_assets", in_assets);
            }
        }

        // Target-specific
        if resource_type == "target" {
            if let Some(hosts) = parse_element_text(raw_xml, "hosts") {
                resource.set_attr("hosts", &hosts);
            }
        }

        if resource_type == "asset" {
            if let Some(asset_type) = asset_type.as_ref().filter(|value| !value.is_empty()) {
                resource.set_attr("asset_type", asset_type);
                resource.set_attr("type", asset_type);
            }
            if let Some(value) = asset_value.as_ref().filter(|value| !value.is_empty()) {
                resource.set_attr("value", value);
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

        let id = match resource_type {
            "task" => {
                let references = match task_references(cmd) {
                    Ok(references) => references,
                    Err(message) => return error_response(&cmd.name, 400, message),
                };
                match store.create_task(resource, references) {
                    Ok(id) => id,
                    Err(error) => return store_error_response(&cmd.name, error),
                }
            }
            "report" => match store.create_linked_report(resource, report_task_id) {
                Ok(id) => id,
                Err(error) => return store_error_response(&cmd.name, error),
            },
            _ => store.create(resource),
        };
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
            "get_feeds" => return render_feeds_response(cmd),
            "get_aggregates" => return render_aggregates_response(cmd),
            "get_audit_report" => return self.render_audit_report_response(cmd, store),
            "get_audit_report_hosts" => {
                return self.render_audit_report_hosts_response(cmd, store);
            }
            "get_scan_report" => return self.render_scan_report_response(cmd, store),
            "get_system_reports" => return render_system_reports_response(cmd, store),
            "get_info" => return render_secinfo_response(cmd),
            "get_vulns" => return render_vulnerabilities_response(cmd),
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
            let Ok(uuid) = Uuid::parse_str(id_str) else {
                return error_response(&cmd.name, 400, "Invalid UUID");
            };
            if let Some(resource) = store.get_typed(&uuid, resource_type) {
                if !usage_type_matches(&resource, requested_usage_type) {
                    return error_response(&cmd.name, 404, "Resource not found");
                }
                if cmd.name == "get_reports" {
                    return self.render_single_report_response(cmd, &resource, store);
                }
                let xml = if cmd.name == "get_integration_configs" {
                    resource.to_integration_config_xml(cmd.attr("details") == Some("1"))
                } else {
                    resource.to_xml()
                };
                return format!(
                    "<{}_response status=\"200\" status_text=\"OK\">\
                     {xml}\
                     </{}_response>",
                    cmd.name, cmd.name
                )
                .into_bytes();
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

        if cmd.name == "get_nvts" {
            if let Some(nvt_oid) = cmd.attr("nvt_oid") {
                resources.retain(|resource| {
                    resource.attr("oid") == Some(nvt_oid)
                        || resource.attr("nvt_oid") == Some(nvt_oid)
                        || resource.id.to_string() == nvt_oid
                });
            }
            if let Some(config_id) = cmd.attr("config_id") {
                resources.retain(|resource| resource.attr("config_id") == Some(config_id));
            }
            if let Some(preferences_config_id) = cmd.attr("preferences_config_id") {
                resources.retain(|resource| {
                    resource.attr("preferences_config_id") == Some(preferences_config_id)
                });
            }
            if let Some(family) = cmd.attr("family") {
                resources.retain(|resource| resource.attr("family") == Some(family));
            }
        }

        if let Some(usage_type) = requested_usage_type {
            resources.retain(|resource| resource.attr("usage_type") == Some(usage_type));
        }

        let count = resources.len();
        let items: String = if cmd.name == "get_integration_configs" {
            let details = cmd.attr("details") == Some("1");
            resources
                .iter()
                .map(|resource| resource.to_integration_config_xml(details))
                .collect()
        } else {
            resources.iter().map(|resource| resource.to_xml()).collect()
        };

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

        let new_name = if resource_type == "user" {
            parse_element_text(raw_xml, "new_name")
        } else if resource_type == "alert" {
            cmd.child_text("name").map(str::to_string)
        } else {
            parse_element_text(raw_xml, "name")
        };
        let new_text = parse_element_text(raw_xml, "text");
        let new_comment = parse_element_text(raw_xml, "comment");
        let new_host = parse_element_text(raw_xml, "host");
        let new_hosts = parse_element_text(raw_xml, "hosts");
        let new_image_references = parse_element_text(raw_xml, "image_references");
        let new_urls = parse_element_text(raw_xml, "urls");
        let new_exclude_urls = parse_element_text(raw_xml, "exclude_urls");
        let new_status = parse_element_text(raw_xml, "status");
        let new_open_note = parse_element_text(raw_xml, "open_note");
        let new_fixed_note = parse_element_text(raw_xml, "fixed_note");
        let new_closed_note = parse_element_text(raw_xml, "closed_note");
        let new_scheduler_cron_time = parse_element_text(raw_xml, "scheduler_cron_time");
        let new_nvt_oid = parse_element_text(raw_xml, "nvt_oid")
            .or_else(|| cmd.child_attr("nvt", "oid").map(str::to_string));
        let new_result_id = parse_element_text(raw_xml, "result_id")
            .or_else(|| cmd.child_attr("result", "id").map(str::to_string));
        let new_task_id = cmd.child_attr("task", "id").map(str::to_string);
        let new_credential_id = cmd.child_attr("credential", "id").map(str::to_string);
        let new_assignee_id = nested_child_attr(cmd, &["assigned_to", "user"], "id");
        let new_port = parse_element_text(raw_xml, "port");
        let new_type = parse_element_text(raw_xml, "type");
        let new_ca_pub = parse_element_text(raw_xml, "ca_pub");
        let new_severity = parse_element_text(raw_xml, "severity");
        let new_new_severity = parse_element_text(raw_xml, "new_severity");
        let new_active = parse_element_text(raw_xml, "active");
        let new_usage_type = parse_element_text(raw_xml, "usage_type");
        let new_value = parse_element_text(raw_xml, "value");
        let new_value = if resource_type == "setting" {
            let Some(value) = new_value else {
                return error_response(&cmd.name, 400, "Missing required element: value");
            };
            let decoded = match base64::engine::general_purpose::STANDARD.decode(value.as_bytes()) {
                Ok(decoded) => decoded,
                Err(_) => {
                    return error_response(&cmd.name, 400, "Value cannot be decoded to valid UTF-8")
                }
            };
            match String::from_utf8(decoded) {
                Ok(value) => Some(value),
                Err(_) => {
                    return error_response(&cmd.name, 400, "Value cannot be decoded to valid UTF-8")
                }
            }
        } else {
            new_value
        };
        let new_term = parse_element_text(raw_xml, "term");
        let new_credential_store_id = parse_element_text(raw_xml, "credential_store_id");
        let new_vault_id = parse_element_text(raw_xml, "vault_id");
        let new_host_identifier = parse_element_text(raw_xml, "host_identifier");
        let task_reference_updates = if resource_type == "task" {
            match task_reference_updates(cmd) {
                Ok(references) => references,
                Err(message) => return error_response(&cmd.name, 400, message),
            }
        } else {
            TaskReferenceUpdates::default()
        };
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
                nested_child_text(cmd, &["oidc", "url"]),
                nested_child_text(cmd, &["oidc", "client", "id"]),
                nested_child_text(cmd, &["oidc", "client", "secret"]),
            )
        } else {
            (None, None, None, None, None)
        };

        if resource_type == "integration_config" {
            for (value, field) in [
                (&new_service_url, "service <url>"),
                (&new_oidc_provider_url, "oidc <url>"),
                (&new_oidc_client_id, "oidc client <id>"),
                (&new_oidc_client_secret, "oidc client <secret>"),
            ] {
                if value.is_none() {
                    return error_response(
                        &cmd.name,
                        400,
                        &format!("Invalid arguments: missing {field}"),
                    );
                }
            }

            let all_empty = [
                new_service_url.as_deref(),
                new_service_cacert.as_deref(),
                new_oidc_provider_url.as_deref(),
                new_oidc_client_id.as_deref(),
                new_oidc_client_secret.as_deref(),
            ]
            .into_iter()
            .all(|value| value.is_none_or(|value| value.trim().is_empty()));
            if !all_empty {
                for (value, field) in [
                    (new_service_url.as_deref(), "service <url>"),
                    (new_oidc_provider_url.as_deref(), "oidc <url>"),
                    (new_oidc_client_id.as_deref(), "oidc client <id>"),
                    (new_oidc_client_secret.as_deref(), "oidc client <secret>"),
                ] {
                    if value.is_none_or(|value| value.trim().is_empty()) {
                        return error_response(
                            &cmd.name,
                            400,
                            &format!("Invalid arguments: missing {field}"),
                        );
                    }
                }
            }
        }

        let update_resource = |r: &mut Resource| {
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
            if resource_type == "oci_image_target" {
                if let Some(ref image_references) = new_image_references {
                    r.set_attr("image_references", image_references);
                }
            }
            if resource_type == "web_application_target" {
                if let Some(ref urls) = new_urls {
                    r.set_attr("urls", urls);
                }
                if let Some(ref exclude_urls) = new_exclude_urls {
                    r.set_attr("exclude_urls", exclude_urls);
                }
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
            if matches!(
                resource_type,
                "oci_image_target" | "web_application_target" | "scanner"
            ) {
                if let Some(ref credential_id) = new_credential_id {
                    r.set_attr("credential_id", credential_id);
                }
            }
            if let Some(ref port) = new_port {
                r.set_attr("port", port);
            }
            if resource_type == "scanner" {
                if let Some(ref scanner_type) = new_type {
                    r.set_attr("type", scanner_type);
                }
                if let Some(ref ca_pub) = new_ca_pub {
                    r.set_attr("ca_pub", ca_pub);
                }
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
            if resource_type == "filter" {
                if let Some(ref term) = new_term {
                    r.set_attr("term", term);
                }
            }
            if resource_type == "alert" {
                set_alert_fields(r, cmd);
            }
            if resource_type == "credential" {
                if let Some(ref credential_store_id) = new_credential_store_id {
                    r.set_attr("credential_store_id", credential_store_id);
                }
                if let Some(ref vault_id) = new_vault_id {
                    r.set_attr("vault_id", vault_id);
                }
                if let Some(ref host_identifier) = new_host_identifier {
                    r.set_attr("host_identifier", host_identifier);
                }
            }
            if resource_type == "permission" {
                set_permission_references(r, cmd);
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
                if let Some(ref assignee_id) = new_assignee_id {
                    r.set_attr("assigned_to_id", assignee_id);
                }
                for (value, field) in [
                    (&new_open_note, "open_note"),
                    (&new_fixed_note, "fixed_note"),
                    (&new_closed_note, "closed_note"),
                ] {
                    if let Some(value) = value {
                        r.set_attr(field, value);
                    }
                }
            }
        };

        if resource_type == "task" {
            return match store.modify_task(&uuid, task_reference_updates, update_resource) {
                Ok(()) => format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name)
                    .into_bytes(),
                Err(error) => store_error_response(&cmd.name, error),
            };
        }

        let modified = store.modify_typed(&uuid, resource_type, update_resource);

        if modified {
            format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
        } else {
            error_response(&cmd.name, 404, "Resource not found")
        }
    }

    fn handle_modify_auth(&self, cmd: &ParsedCommand) -> Vec<u8> {
        match cmd.attr("enabled") {
            Some("0" | "1") => {
                format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
            }
            Some(_) => error_response(&cmd.name, 400, "Invalid enabled value"),
            None => error_response(&cmd.name, 400, "Missing required attribute: enabled"),
        }
    }

    fn handle_modify_license(&self, cmd: &ParsedCommand) -> Vec<u8> {
        format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
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

        match store.delete_typed(&uuid, resource_type, ultimate) {
            Ok(()) => {
                format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
            }
            Err(error) => store_error_response(&cmd.name, error),
        }
    }

    fn handle_start_task(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("task_id") else {
            return error_response(&cmd.name, 400, "Missing task_id");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        match store.start_task(&uuid) {
            Ok(report_id) => format!(
                "<start_task_response status=\"202\" status_text=\"OK\">\
                     <report_id>{report_id}</report_id>\
                     </start_task_response>"
            )
            .into_bytes(),
            Err(error) => store_error_response(&cmd.name, error),
        }
    }

    fn handle_stop_task(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("task_id") else {
            return error_response(&cmd.name, 400, "Missing task_id");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        match store.stop_task(&uuid) {
            Ok(()) => b"<stop_task_response status=\"200\" status_text=\"OK\"/>".to_vec(),
            Err(error) => store_error_response(&cmd.name, error),
        }
    }

    fn handle_resume_task(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("task_id") else {
            return error_response(&cmd.name, 400, "Missing task_id");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };

        match store.resume_task(&uuid) {
            Ok(report_id) => format!(
                "<resume_task_response status=\"202\" status_text=\"OK\">\
                     <report_id>{report_id}</report_id>\
                     </resume_task_response>"
            )
            .into_bytes(),
            Err(error) => store_error_response(&cmd.name, error),
        }
    }

    fn handle_restore(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(id_str) = cmd.attr("id") else {
            return error_response("restore", 400, "Missing id attribute");
        };
        let Ok(uuid) = Uuid::parse_str(id_str) else {
            return error_response("restore", 400, "Invalid UUID");
        };

        match store.restore_checked(&uuid) {
            Ok(()) => "<restore_response status=\"200\" status_text=\"OK\"/>"
                .as_bytes()
                .to_vec(),
            Err(error) => store_error_response("restore", error),
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
        let report_metadata: String = ["task_id", "status", "usage_type"]
            .into_iter()
            .filter_map(|key| {
                report
                    .attr(key)
                    .map(|value| format!("<{key}>{}</{key}>", xml_escape(value)))
            })
            .collect();

        format!(
            "<{name}_response status=\"200\" status_text=\"OK\">\
             <report id=\"{id}\">\
             <name>{report_name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{creation_time}</creation_time>\
             <modification_time>{modification_time}</modification_time>\
             {report_metadata}\
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

    fn render_scan_report_response(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(report_id) = cmd.attr("scan_report_id") else {
            return error_response(&cmd.name, 400, "Missing required attribute: scan_report_id");
        };
        let Ok(report_id) = Uuid::parse_str(report_id) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };
        let Some(report) = store.get_typed(&report_id, "report") else {
            return error_response(&cmd.name, 404, "Resource not found");
        };
        if report.attr("usage_type") == Some("audit") {
            return error_response(
                &cmd.name,
                400,
                "Audit and compliance reports are not supported",
            );
        }

        let (filter_id, filter) = match cmd.attr("filt_id") {
            Some(filter_id) => {
                let Ok(filter_id) = Uuid::parse_str(filter_id) else {
                    return error_response(&cmd.name, 400, "Invalid filter UUID");
                };
                let Some(saved_filter) = store.get_typed(&filter_id, "filter") else {
                    return error_response(&cmd.name, 400, "Saved filter not found");
                };
                (
                    filter_id.to_string(),
                    saved_filter.attr("term").unwrap_or_default().to_string(),
                )
            }
            None => (
                String::new(),
                cmd.attr("filter").unwrap_or_default().to_string(),
            ),
        };

        let filter = resolve_scan_report_filter(&filter);
        let (sort_field, sort_order) = scan_report_sort(&filter);
        let report_id_text = report_id.to_string();
        let results: Vec<Resource> = store
            .list("result")
            .into_iter()
            .filter(|result| result.attr("report_id") == Some(report_id_text.as_str()))
            .collect();
        let filtered_results: Vec<&Resource> = results
            .iter()
            .filter(|result| scan_report_result_matches(result, &filter))
            .collect();
        let full_counts = ScanReportResultCounts::from_results(results.iter());
        let filtered_counts =
            ScanReportResultCounts::from_results(filtered_results.iter().copied());

        let task = report
            .attr("task_id")
            .and_then(|task_id| Uuid::parse_str(task_id).ok())
            .and_then(|task_id| store.get_typed(&task_id, "task"));
        let task_xml = task.as_ref().map_or_else(
            || "<task/>".to_string(),
            |task| render_scan_report_task(task, store),
        );
        let status = report.attr("status").unwrap_or("Done");
        let scan_end = if matches!(status, "Done" | "Stopped" | "Interrupted") {
            report.modification_time.as_str()
        } else {
            ""
        };
        let filter_keywords = render_scan_report_filter_keywords(&filter);

        format!(
            "<get_scan_report_response status=\"200\" status_text=\"OK\">\
             <report id=\"{report_id}\">\
             <owner><name>admin</name></owner>\
             <name>{report_name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{creation_time}</creation_time>\
             <modification_time>{modification_time}</modification_time>\
             <writable>0</writable><in_use>0</in_use>\
             <scan_run_status>{status}</scan_run_status>\
             <hosts><count>{hosts}</count></hosts>\
             <closed_cves><count>0</count></closed_cves>\
             <cves><count>0</count></cves>\
             <vulns><count>{vulns}</count></vulns>\
             <os><count>0</count></os>\
             <apps><count>0</count></apps>\
             <ssl_certs><count>0</count></ssl_certs>\
             <ports><count>{ports}</count></ports>\
             <errors><count>{errors}</count></errors>\
             {task_xml}\
             <timestamp>{creation_time}</timestamp>\
             <scan_start>{creation_time}</scan_start>\
             <timezone>UTC</timezone><timezone_abbrev>UTC</timezone_abbrev>\
             {result_count_xml}\
             <severity><full>{full_severity:.1}</full><filtered>{filtered_severity:.1}</filtered></severity>\
             <scan_end>{scan_end}</scan_end>\
             </report>\
             <filters id=\"{filter_id}\"><term>{filter}</term><keywords>{filter_keywords}</keywords></filters>\
             <sort><field>{sort_field}<order>{sort_order}</order></field></sort>\
             <scan_report start=\"1\" max=\"1\"/>\
             <scan_report_count>1<filtered>1</filtered><page>0</page></scan_report_count>\
             </get_scan_report_response>",
            report_id = report.id,
            report_name = xml_escape(&report.name),
            comment = xml_escape(&report.comment),
            creation_time = xml_escape(&report.creation_time),
            modification_time = xml_escape(&report.modification_time),
            status = xml_escape(status),
            hosts = full_counts.hosts,
            vulns = full_counts.total,
            ports = full_counts.ports,
            errors = full_counts.errors,
            result_count_xml = render_scan_report_result_counts(&full_counts, &filtered_counts),
            full_severity = full_counts.max_severity,
            filtered_severity = filtered_counts.max_severity,
            filter_id = xml_escape_attr(&filter_id),
            filter = xml_escape(&filter),
            scan_end = xml_escape(scan_end),
            sort_field = xml_escape(&sort_field),
        )
        .into_bytes()
    }

    fn render_audit_report_response(&self, cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
        let Some(report_id) = cmd.attr("audit_report_id") else {
            return error_response(&cmd.name, 400, "Missing audit_report_id attribute");
        };
        let Ok(report_id) = Uuid::parse_str(report_id) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };
        let Some(report) = store.get_typed(&report_id, "report") else {
            return error_response(&cmd.name, 404, "Resource not found");
        };
        if report.attr("usage_type") != Some("audit") {
            return error_response(&cmd.name, 400, "Report type is not supported");
        }

        let (filter_id, filter) = match audit_filter_from_command(cmd, store) {
            Ok(filter) => filter,
            Err(message) => return error_response(&cmd.name, 400, message),
        };
        let filter = match AuditFilter::parse(&filter, audit_rows_per_page(store)) {
            Ok(filter) => filter,
            Err(message) => return error_response(&cmd.name, 400, message),
        };
        let report_id_text = report_id.to_string();
        let results: Vec<Resource> = store
            .list("result")
            .into_iter()
            .filter(|result| result.attr("report_id") == Some(report_id_text.as_str()))
            .collect();
        let filtered_results: Vec<&Resource> = results
            .iter()
            .filter(|result| filter.result_matches(result))
            .collect();
        let full_counts = AuditComplianceCounts::from_results(results.iter());
        let filtered_counts = AuditComplianceCounts::from_results(filtered_results.iter().copied());
        let hosts = results
            .iter()
            .filter_map(|result| result.attr("host"))
            .collect::<BTreeSet<_>>()
            .len();
        let ports = results
            .iter()
            .filter_map(|result| result.attr("port"))
            .filter(|port| !port.is_empty() && !port.starts_with("general/"))
            .collect::<BTreeSet<_>>()
            .len();
        let applications = results
            .iter()
            .filter_map(|result| result.attr("application"))
            .collect::<BTreeSet<_>>()
            .len();
        let errors = results
            .iter()
            .filter(|result| result.attr("threat") == Some("Error"))
            .count();
        let task = report
            .attr("task_id")
            .and_then(|task_id| Uuid::parse_str(task_id).ok())
            .and_then(|task_id| store.get_typed(&task_id, "task"));
        let task_xml = task.as_ref().map_or_else(
            || "<task/>".to_string(),
            |task| render_scan_report_task(task, store),
        );
        let status = report.attr("status").unwrap_or("Done");
        let scan_end = if matches!(status, "Done" | "Stopped" | "Interrupted") {
            report.modification_time.as_str()
        } else {
            ""
        };
        let filter_keywords = render_scan_report_filter_keywords(&filter.raw);
        let (sort_field, sort_order) = filter.sort_metadata("type", "descending");

        format!(
            "<get_audit_report_response status=\"200\" status_text=\"OK\">\
             <report id=\"{report_id}\">\
             <owner><name>admin</name></owner>\
             <name>{report_name}</name><comment>{comment}</comment>\
             <creation_time>{creation_time}</creation_time>\
             <modification_time>{modification_time}</modification_time>\
             <writable>0</writable><in_use>0</in_use>\
             <scan_run_status>{status}</scan_run_status>\
             <hosts><count>{hosts}</count></hosts>\
             <closed_cves><count>0</count></closed_cves>\
             <cves><count>0</count></cves>\
             <vulns><count>{vulns}</count></vulns>\
             <os><count>0</count></os>\
             <apps><count>{applications}</count></apps>\
             <ssl_certs><count>0</count></ssl_certs>\
             <ports><count>{ports}</count></ports>\
             <errors><count>{errors}</count></errors>\
             {task_xml}\
             <timestamp>{creation_time}</timestamp><scan_start>{creation_time}</scan_start>\
             <timezone>UTC</timezone><timezone_abbrev>UTC</timezone_abbrev>\
             {compliance_count_xml}\
             <compliance><full>{full_compliance}</full><filtered>{filtered_compliance}</filtered></compliance>\
             <scan_end>{scan_end}</scan_end>\
             </report>\
             <filters id=\"{filter_id}\"><term>{filter_term}</term><keywords>{filter_keywords}</keywords></filters>\
             <sort><field>{sort_field}<order>{sort_order}</order></field></sort>\
             <audit_report start=\"1\" max=\"1\"/>\
             <audit_report_count>1<filtered>1</filtered><page>0</page></audit_report_count>\
             </get_audit_report_response>",
            report_id = report.id,
            report_name = xml_escape(&report.name),
            comment = xml_escape(&report.comment),
            creation_time = xml_escape(&report.creation_time),
            modification_time = xml_escape(&report.modification_time),
            status = xml_escape(status),
            vulns = results.len(),
            compliance_count_xml =
                render_audit_compliance_counts(&full_counts, &filtered_counts),
            full_compliance = full_counts.compliance(),
            filtered_compliance = filtered_counts.compliance(),
            filter_id = xml_escape_attr(&filter_id),
            filter_term = xml_escape(&filter.raw),
            sort_field = xml_escape(sort_field),
            scan_end = xml_escape(scan_end),
        )
        .into_bytes()
    }

    fn render_audit_report_hosts_response(
        &self,
        cmd: &ParsedCommand,
        store: &ResourceStore,
    ) -> Vec<u8> {
        let Some(report_id) = cmd.attr("report_id") else {
            return error_response(&cmd.name, 400, "Missing report_id attribute");
        };
        let Ok(report_id) = Uuid::parse_str(report_id) else {
            return error_response(&cmd.name, 400, "Invalid UUID");
        };
        let Some(report) = store.get_typed(&report_id, "report") else {
            return error_response(&cmd.name, 404, "Resource not found");
        };
        if report.attr("usage_type") != Some("audit") {
            return error_response(&cmd.name, 400, "Report is not an audit report");
        }

        let (filter_id, filter) = match audit_filter_from_command(cmd, store) {
            Ok(filter) => filter,
            Err(message) => return error_response(&cmd.name, 400, message),
        };
        let filter = match AuditFilter::parse(&filter, audit_rows_per_page(store)) {
            Ok(filter) => filter,
            Err(message) => return error_response(&cmd.name, 400, message),
        };
        let report_id_text = report_id.to_string();
        let results: Vec<Resource> = store
            .list("result")
            .into_iter()
            .filter(|result| result.attr("report_id") == Some(report_id_text.as_str()))
            .collect();
        let mut hosts = audit_hosts_from_results(&results, &filter);
        let total = results
            .iter()
            .filter_map(|result| result.attr("host"))
            .collect::<BTreeSet<_>>()
            .len();
        let filtered = hosts.len();
        hosts.sort_by(|left, right| filter.compare_hosts(left, right));

        let start = filter.first.saturating_sub(1).min(hosts.len());
        let end = filter.rows.page_end(start, hosts.len());
        let page_hosts = &hosts[start..end];
        let page = page_hosts.len();
        let details = matches!(cmd.attr("details"), Some("1" | "true"));
        let lean = matches!(cmd.attr("lean"), Some("1" | "true"));
        let items = if details {
            page_hosts
                .iter()
                .map(|host| host.to_xml(lean))
                .collect::<String>()
        } else {
            String::new()
        };
        let max = filter.rows;
        let filter_keywords = render_scan_report_filter_keywords(&filter.raw);
        let (sort_field, sort_order) = filter.sort_metadata("ip", "ascending");

        format!(
            "<get_audit_report_hosts_response status=\"200\" status_text=\"OK\">\
             {items}\
             <filters id=\"{filter_id}\"><term>{filter_term}</term><keywords>{filter_keywords}</keywords></filters>\
             <sort><field>{sort_field}<order>{sort_order}</order></field></sort>\
             <audit_report_hosts start=\"{first}\" max=\"{max}\"/>\
             <audit_report_host_count>{total}<filtered>{filtered}</filtered><page>{page}</page></audit_report_host_count>\
             </get_audit_report_hosts_response>",
            filter_id = xml_escape_attr(&filter_id),
            filter_term = xml_escape(&filter.raw),
            sort_field = xml_escape(sort_field),
            first = filter.first,
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

        if store.get_typed(&report_uuid, "report").is_none() {
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
                    "<vuln><nvt oid=\"1.3.6.1.4.1.25623.1.0.117761\"><name>SSL/TLS Renegotiation Vulnerability</name></nvt><cves><cve>CVE-2011-1473</cve><cve>CVE-2011-5094</cve></cves><hosts_count>2</hosts_count><occurrences>3</occurrences><severity>5.0</severity><threat>Medium</threat></vuln>"
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
                    "<closed_cve><host>192.0.2.30</host><cve>CVE-2025-9999</cve><nvt oid=\"1.3.6.1.4.1.25623.1.0.100000\"><name>Closed vulnerability check</name></nvt><severity>5.0</severity><threat>Medium</threat></closed_cve>"
                        .to_string(),
                ],
            ),
            _ => return error_response(&cmd.name, 400, "Unsupported report detail command"),
        };

        let count = items.len();
        let items = items.join("");
        let details = match cmd.name.as_str() {
            "get_report_vulns" => format!(
                "<vulns>{items}</vulns><report_vuln_count>{count}<filtered>{count}</filtered></report_vuln_count>"
            ),
            "get_report_closed_cves" => format!(
                "<closed_cves>{items}</closed_cves><report_closed_cve_count>{count}<filtered>{count}</filtered></report_closed_cve_count>"
            ),
            _ => format!(
                "{items}<{element_name}_count>{count}<filtered>{count}</filtered></{element_name}_count>"
            ),
        };
        format!(
            "<{name}_response status=\"200\" status_text=\"OK\">{details}</{name}_response>",
            name = cmd.name,
        )
        .into_bytes()
    }
}

fn render_features_response() -> Vec<u8> {
    const FEATURE_NAMES: [&str; 8] = [
        "ENABLE_OPENVASD",
        "ENABLE_CONTAINER_SCANNING",
        "ENABLE_AGENTS",
        "ENABLE_CREDENTIAL_STORES",
        "FEED_VT_METADATA",
        "ENABLE_SECURITY_INTELLIGENCE_EXPORT",
        "ENABLE_JWT_AUTH",
        "ENABLE_WEB_APPLICATION_SCANNING",
    ];

    let mut xml = String::from("<get_features_response status=\"200\" status_text=\"OK\">");
    for name in FEATURE_NAMES {
        xml.push_str("<feature compiled_in=\"0\" enabled=\"0\"><name>");
        xml.push_str(name);
        xml.push_str("</name></feature>");
    }
    xml.push_str("</get_features_response>");
    xml.into_bytes()
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

fn audit_filter_from_command(
    cmd: &ParsedCommand,
    store: &ResourceStore,
) -> Result<(String, String), &'static str> {
    let (filter_id, filter) = match cmd.attr("filt_id") {
        Some(filter_id) => {
            let filter_id = Uuid::parse_str(filter_id).map_err(|_| "Invalid filter UUID")?;
            let saved_filter = store
                .get_typed(&filter_id, "filter")
                .ok_or("Failed to find filter")?;
            (
                filter_id.to_string(),
                saved_filter.attr("term").unwrap_or_default().to_string(),
            )
        }
        None => (
            String::new(),
            cmd.attr("filter").unwrap_or_default().to_string(),
        ),
    };
    Ok((filter_id, resolve_audit_filter(&filter)))
}

fn resolve_audit_filter(filter: &str) -> String {
    let mut resolved = filter.trim().to_string();
    let has_keyword = |filter: &str, expected: &str| {
        filter.split_whitespace().any(|predicate| {
            predicate
                .split_once('=')
                .is_some_and(|(key, _)| key == expected)
        })
    };
    if !has_keyword(&resolved, "min_qod") {
        resolved = format!("min_qod=70 {resolved}").trim_end().to_string();
    }
    if !has_keyword(&resolved, "apply_overrides") {
        resolved = format!("apply_overrides=0 {resolved}")
            .trim_end()
            .to_string();
    }
    resolved
}

fn audit_rows_per_page(store: &ResourceStore) -> usize {
    store
        .list("setting")
        .into_iter()
        .find(|setting| setting.name == "rows_per_page")
        .and_then(|setting| {
            setting
                .attr("value")
                .and_then(|value| value.parse::<i32>().ok())
                .and_then(|value| usize::try_from(value).ok())
        })
        .filter(|rows| *rows > 0)
        .unwrap_or(1)
}

#[derive(Clone, Copy, Debug)]
enum AuditPageSize {
    Unlimited,
    Limited(usize),
}

impl AuditPageSize {
    fn page_end(&self, start: usize, available: usize) -> usize {
        match self {
            Self::Unlimited => available,
            Self::Limited(rows) => start.saturating_add(*rows).min(available),
        }
    }
}

impl std::fmt::Display for AuditPageSize {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlimited => formatter.write_str("-1"),
            Self::Limited(rows) => rows.fmt(formatter),
        }
    }
}

#[derive(Debug)]
struct AuditFilter {
    raw: String,
    first: usize,
    rows: AuditPageSize,
    sort_field: Option<String>,
    reverse: bool,
    compliance_levels: Option<String>,
    minimum_qod: u32,
    result_hosts_only: bool,
    ip: Option<String>,
    asset_id: Option<String>,
    host_id: Option<String>,
    start: Option<String>,
    end: Option<String>,
    severity: Option<String>,
}

impl AuditFilter {
    fn parse(raw: &str, rows_per_page: usize) -> Result<Self, &'static str> {
        let mut parsed = Self {
            raw: raw.to_string(),
            first: 1,
            rows: AuditPageSize::Limited(rows_per_page.max(1)),
            sort_field: None,
            reverse: false,
            compliance_levels: None,
            minimum_qod: 0,
            result_hosts_only: false,
            ip: None,
            asset_id: None,
            host_id: None,
            start: None,
            end: None,
            severity: None,
        };

        for predicate in raw.split_whitespace() {
            let Some((key, value)) = predicate.split_once('=') else {
                return Err("Malformed filter");
            };
            if key.is_empty() || value.is_empty() {
                return Err("Malformed filter");
            }
            match key {
                "first" => {
                    let value = value
                        .parse::<i32>()
                        .map_err(|_| "Invalid first filter value")?;
                    parsed.first = if value <= 0 {
                        1
                    } else {
                        usize::try_from(value).map_err(|_| "Invalid first filter value")?
                    };
                }
                "rows" => {
                    let value = value
                        .parse::<i32>()
                        .map_err(|_| "Invalid rows filter value")?;
                    parsed.rows = match value {
                        -2 => AuditPageSize::Limited(rows_per_page.max(1)),
                        -1 => AuditPageSize::Unlimited,
                        value if value < -2 => AuditPageSize::Unlimited,
                        value => AuditPageSize::Limited(
                            usize::try_from(value.max(1))
                                .map_err(|_| "Invalid rows filter value")?,
                        ),
                    };
                }
                "sort" => {
                    parsed.sort_field = Some(value.to_string());
                    parsed.reverse = false;
                }
                "sort-reverse" => {
                    parsed.sort_field = Some(value.to_string());
                    parsed.reverse = true;
                }
                "compliance_levels" | "levels" => {
                    if !value.chars().all(|level| "yniu".contains(level)) {
                        return Err("Invalid compliance levels");
                    }
                    parsed.compliance_levels = Some(value.to_string());
                }
                "min_qod" => {
                    parsed.minimum_qod = value
                        .parse::<u32>()
                        .map_err(|_| "Invalid min_qod filter value")?;
                }
                "apply_overrides" => {
                    parse_filter_bool(value).ok_or("Invalid apply_overrides filter value")?;
                }
                "result_hosts_only" => {
                    parsed.result_hosts_only =
                        parse_filter_bool(value).ok_or("Invalid result_hosts_only filter value")?;
                }
                "ip" => parsed.ip = Some(value.to_string()),
                "asset_id" => parsed.asset_id = Some(value.to_string()),
                "uuid" => parsed.host_id = Some(value.to_string()),
                "start" => parsed.start = Some(value.to_string()),
                "end" => parsed.end = Some(value.to_string()),
                "severity" => parsed.severity = Some(value.to_string()),
                // Current gvmd accepts a broad result-filter vocabulary. The
                // mock validates syntax while deliberately emulating only the
                // audit fields represented by its stateful result resources.
                _ => {}
            }
        }
        Ok(parsed)
    }

    fn result_matches(&self, result: &Resource) -> bool {
        if let Some(levels) = &self.compliance_levels {
            let level = audit_compliance_level(result);
            if !levels.contains(level) {
                return false;
            }
        }
        let qod = result
            .attr("qod")
            .and_then(|qod| qod.parse::<u32>().ok())
            .unwrap_or(100);
        if qod < self.minimum_qod {
            return false;
        }
        if self
            .ip
            .as_deref()
            .is_some_and(|ip| result.attr("host") != Some(ip))
        {
            return false;
        }
        if self
            .asset_id
            .as_deref()
            .is_some_and(|id| result.attr("asset_id") != Some(id))
        {
            return false;
        }
        true
    }

    fn host_matches(&self, host: &AuditHost) -> bool {
        self.ip.as_deref().is_none_or(|ip| ip == host.ip)
            && self
                .asset_id
                .as_deref()
                .is_none_or(|id| host.asset_id.as_deref() == Some(id))
            && self
                .host_id
                .as_deref()
                .is_none_or(|id| host.host_id.as_deref() == Some(id))
            && self
                .start
                .as_deref()
                .is_none_or(|start| host.start.as_deref() == Some(start))
            && self
                .end
                .as_deref()
                .is_none_or(|end| host.end.as_deref() == Some(end))
            && self.severity.as_deref().is_none_or(|severity| {
                severity
                    .parse::<f64>()
                    .is_ok_and(|severity| host.severity == severity)
            })
    }

    fn compare_hosts(&self, left: &AuditHost, right: &AuditHost) -> std::cmp::Ordering {
        let field = self.sort_field.as_deref().unwrap_or("ip");
        let order = match field {
            "severity" => left.severity.total_cmp(&right.severity),
            "asset_id" => left.asset_id.cmp(&right.asset_id),
            "start" => left.start.cmp(&right.start),
            "end" => left.end.cmp(&right.end),
            _ => left.ip.cmp(&right.ip),
        }
        .then_with(|| left.ip.cmp(&right.ip));
        if self.reverse {
            order.reverse()
        } else {
            order
        }
    }

    fn sort_metadata<'a>(
        &'a self,
        default_field: &'a str,
        default_order: &'a str,
    ) -> (&'a str, &'a str) {
        (
            self.sort_field.as_deref().unwrap_or(default_field),
            if self.sort_field.is_some() {
                if self.reverse {
                    "descending"
                } else {
                    "ascending"
                }
            } else {
                default_order
            },
        )
    }
}

fn parse_filter_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct AuditComplianceCounts {
    yes: usize,
    no: usize,
    incomplete: usize,
    undefined: usize,
}

impl AuditComplianceCounts {
    fn from_results<'a>(results: impl Iterator<Item = &'a Resource>) -> Self {
        let mut counts = Self::default();
        for result in results {
            match result
                .attr("compliance")
                .unwrap_or("undefined")
                .to_ascii_lowercase()
                .as_str()
            {
                "yes" => counts.yes += 1,
                "no" => counts.no += 1,
                "incomplete" => counts.incomplete += 1,
                _ => counts.undefined += 1,
            }
        }
        counts
    }

    fn total(self) -> usize {
        self.yes + self.no + self.incomplete + self.undefined
    }

    fn compliance(self) -> &'static str {
        if self.no > 0 {
            "no"
        } else if self.incomplete > 0 {
            "incomplete"
        } else if self.yes > 0 {
            "yes"
        } else {
            "undefined"
        }
    }
}

fn audit_compliance_level(result: &Resource) -> char {
    match result
        .attr("compliance")
        .unwrap_or("undefined")
        .to_ascii_lowercase()
        .as_str()
    {
        "yes" => 'y',
        "no" => 'n',
        "incomplete" => 'i',
        _ => 'u',
    }
}

fn render_audit_compliance_counts(
    full: &AuditComplianceCounts,
    filtered: &AuditComplianceCounts,
) -> String {
    format!(
        "<compliance_count>{total}\
         <full>{total}</full><filtered>{filtered_total}</filtered>\
         <yes><full>{yes}</full><filtered>{filtered_yes}</filtered></yes>\
         <no><full>{no}</full><filtered>{filtered_no}</filtered></no>\
         <incomplete><full>{incomplete}</full><filtered>{filtered_incomplete}</filtered></incomplete>\
         <undefined><full>{undefined}</full><filtered>{filtered_undefined}</filtered></undefined>\
         </compliance_count>",
        total = full.total(),
        filtered_total = filtered.total(),
        yes = full.yes,
        filtered_yes = filtered.yes,
        no = full.no,
        filtered_no = filtered.no,
        incomplete = full.incomplete,
        filtered_incomplete = filtered.incomplete,
        undefined = full.undefined,
        filtered_undefined = filtered.undefined,
    )
}

#[derive(Debug)]
struct AuditHost {
    ip: String,
    host_id: Option<String>,
    asset_id: Option<String>,
    asset_snapshot_key: Option<String>,
    start: Option<String>,
    end: Option<String>,
    hostname: Option<String>,
    port_count: usize,
    application_count: usize,
    counts: AuditComplianceCounts,
    severity: f64,
    details: Vec<AuditHostDetail>,
}

#[derive(Debug)]
struct AuditHostDetail {
    name: String,
    value: String,
    source_type: Option<String>,
    source_name: String,
    source_description: Option<String>,
    extra: Option<String>,
}

impl AuditHost {
    fn to_xml(&self, lean: bool) -> String {
        let mut xml = format!("<host><ip>{}</ip>", xml_escape(&self.ip));
        match &self.asset_id {
            Some(asset_id) => xml.push_str(&format!(
                "<asset asset_id=\"{}\"/>",
                xml_escape_attr(asset_id)
            )),
            None if !lean => xml.push_str("<asset asset_id=\"\"/>"),
            None => {}
        }
        if let Some(asset_key) = &self.asset_snapshot_key {
            xml.push_str(&format!(
                "<asset_snapshot asset_key=\"{}\"/>",
                xml_escape_attr(asset_key)
            ));
        }
        xml.push_str(&format!(
            "<start>{start}</start><end>{end}</end>\
             <port_count><page>{ports}</page></port_count>\
             <compliance_count><page>{total}</page>\
             <yes><page>{yes}</page></yes><no><page>{no}</page></no>\
             <incomplete><page>{incomplete}</page></incomplete>\
             <undefined><page>{undefined}</page></undefined></compliance_count>\
             <host_compliance>{compliance}</host_compliance>\
             <app_count><page>{applications}</page></app_count>",
            start = xml_escape(self.start.as_deref().unwrap_or_default()),
            end = xml_escape(self.end.as_deref().unwrap_or_default()),
            ports = self.port_count,
            total = self.counts.total(),
            yes = self.counts.yes,
            no = self.counts.no,
            incomplete = self.counts.incomplete,
            undefined = self.counts.undefined,
            compliance = self.counts.compliance(),
            applications = self.application_count,
        ));
        match &self.hostname {
            Some(hostname) if !hostname.is_empty() => {
                xml.push_str(&format!("<hostname>{}</hostname>", xml_escape(hostname)));
            }
            _ if !lean => xml.push_str("<hostname></hostname>"),
            _ => {}
        }
        for detail in &self.details {
            if lean
                && matches!(
                    detail.name.as_str(),
                    "EXIT_CODE"
                        | "scanned_with_scanner"
                        | "scanned_with_feedtype"
                        | "scanned_with_feedversion"
                        | "OS"
                        | "traceroute"
                )
            {
                continue;
            }
            xml.push_str(&format!(
                "<detail><name>{}</name><value>{}</value><source>",
                xml_escape(&detail.name),
                xml_escape(&detail.value),
            ));
            if !lean {
                xml.push_str(&format!(
                    "<type>{}</type>",
                    xml_escape(detail.source_type.as_deref().unwrap_or_default())
                ));
            }
            xml.push_str(&format!("<name>{}</name>", xml_escape(&detail.source_name)));
            match &detail.source_description {
                Some(description) if !description.is_empty() => xml.push_str(&format!(
                    "<description>{}</description>",
                    xml_escape(description)
                )),
                _ if !lean => xml.push_str("<description></description>"),
                _ => {}
            }
            xml.push_str("</source>");
            match &detail.extra {
                Some(extra) if !extra.is_empty() => {
                    xml.push_str(&format!("<extra>{}</extra>", xml_escape(extra)));
                }
                _ if !lean => xml.push_str("<extra></extra>"),
                _ => {}
            }
            xml.push_str("</detail>");
        }
        xml.push_str("</host>");
        xml
    }
}

fn audit_hosts_from_results(results: &[Resource], filter: &AuditFilter) -> Vec<AuditHost> {
    let mut full_by_host: BTreeMap<&str, Vec<&Resource>> = BTreeMap::new();
    let mut filtered_by_host: BTreeMap<&str, Vec<&Resource>> = BTreeMap::new();
    for result in results {
        let Some(host) = result.attr("host") else {
            continue;
        };
        full_by_host.entry(host).or_default().push(result);
        if filter.result_matches(result) {
            filtered_by_host.entry(host).or_default().push(result);
        }
    }

    full_by_host
        .into_iter()
        .filter_map(|(ip, full_results)| {
            let filtered_results = filtered_by_host.remove(ip).unwrap_or_default();
            if filter.result_hosts_only && filtered_results.is_empty() {
                return None;
            }
            let representative = full_results[0];
            let counts = AuditComplianceCounts::from_results(filtered_results.iter().copied());
            let ports = filtered_results
                .iter()
                .filter_map(|result| result.attr("port"))
                .filter(|port| !port.is_empty() && !port.starts_with("general/"))
                .collect::<BTreeSet<_>>()
                .len();
            let applications = filtered_results
                .iter()
                .filter_map(|result| result.attr("application"))
                .collect::<BTreeSet<_>>()
                .len();
            let severity = filtered_results
                .iter()
                .map(|result| scan_report_result_severity(result))
                .fold(0.0, f64::max);
            let details = filtered_results
                .iter()
                .filter_map(|result| {
                    Some(AuditHostDetail {
                        name: result.attr("detail_name")?.to_string(),
                        value: result.attr("detail_value")?.to_string(),
                        source_type: result.attr("detail_source_type").map(ToString::to_string),
                        source_name: result
                            .attr("detail_source_name")
                            .unwrap_or("mock-audit")
                            .to_string(),
                        source_description: result
                            .attr("detail_source_description")
                            .map(ToString::to_string),
                        extra: result.attr("detail_extra").map(ToString::to_string),
                    })
                })
                .collect();
            let host = AuditHost {
                ip: ip.to_string(),
                host_id: representative.attr("host_id").map(ToString::to_string),
                asset_id: representative.attr("asset_id").map(ToString::to_string),
                asset_snapshot_key: representative
                    .attr("asset_snapshot_key")
                    .map(ToString::to_string),
                start: representative.attr("host_start").map(ToString::to_string),
                end: representative.attr("host_end").map(ToString::to_string),
                hostname: representative.attr("hostname").map(ToString::to_string),
                port_count: ports,
                application_count: applications,
                counts,
                severity,
                details,
            };
            filter.host_matches(&host).then_some(host)
        })
        .collect()
}

#[derive(Default)]
struct ScanReportResultCounts {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    log: usize,
    false_positive: usize,
    errors: usize,
    hosts: usize,
    ports: usize,
    max_severity: f64,
}

impl ScanReportResultCounts {
    fn from_results<'a>(results: impl Iterator<Item = &'a Resource>) -> Self {
        let mut counts = Self::default();
        let mut hosts = BTreeSet::new();
        let mut ports = BTreeSet::new();
        for result in results {
            counts.total += 1;
            let severity = scan_report_result_severity(result);
            counts.max_severity = counts.max_severity.max(severity);
            if result.attr("false_positive") == Some("1") {
                counts.false_positive += 1;
            } else if severity >= 9.0 {
                counts.critical += 1;
            } else if severity >= 7.0 {
                counts.high += 1;
            } else if severity >= 4.0 {
                counts.medium += 1;
            } else if severity > 0.0 {
                counts.low += 1;
            } else {
                counts.log += 1;
            }
            if result.attr("threat") == Some("Error") {
                counts.errors += 1;
            }
            if let Some(host) = result.attr("host") {
                hosts.insert(host);
            }
            if let Some(port) = result.attr("port") {
                ports.insert(port);
            }
        }
        counts.hosts = hosts.len();
        counts.ports = ports.len();
        counts
    }
}

fn scan_report_result_severity(result: &Resource) -> f64 {
    result
        .attr("severity")
        .and_then(|severity| severity.parse().ok())
        .unwrap_or_default()
}

fn scan_report_result_matches(result: &Resource, filter: &str) -> bool {
    let severity = scan_report_result_severity(result);
    for predicate in filter.split_whitespace() {
        let Some((key, value)) = predicate.split_once('=') else {
            continue;
        };
        match key {
            "levels" => {
                let level = if result.attr("false_positive") == Some("1") {
                    'f'
                } else if severity >= 9.0 {
                    'c'
                } else if severity >= 7.0 {
                    'h'
                } else if severity >= 4.0 {
                    'm'
                } else if severity > 0.0 {
                    'l'
                } else {
                    'g'
                };
                if !value.contains(level) {
                    return false;
                }
            }
            "min_qod" => {
                let minimum = value.parse::<u32>().unwrap_or_default();
                let qod = result
                    .attr("qod")
                    .and_then(|qod| qod.parse().ok())
                    .unwrap_or(100);
                if qod < minimum {
                    return false;
                }
            }
            "first" | "rows" | "sort" | "sort-reverse" | "apply_overrides"
            | "result_hosts_only" => {}
            _ => {}
        }
    }
    true
}

fn resolve_scan_report_filter(filter: &str) -> String {
    let mut resolved = filter.trim().to_string();
    let has_keyword = |filter: &str, expected: &str| {
        filter.split_whitespace().any(|predicate| {
            predicate
                .split_once('=')
                .is_some_and(|(key, _)| key == expected)
        })
    };
    if !has_keyword(&resolved, "min_qod") {
        resolved = format!("min_qod=70 {resolved}").trim_end().to_string();
    }
    if !has_keyword(&resolved, "apply_overrides") {
        resolved = format!("apply_overrides=0 {resolved}")
            .trim_end()
            .to_string();
    }
    resolved
}

fn scan_report_sort(filter: &str) -> (String, &'static str) {
    for predicate in filter.split_whitespace() {
        match predicate.split_once('=') {
            Some(("sort", field)) => return (field.to_string(), "ascending"),
            Some(("sort-reverse", field)) => return (field.to_string(), "descending"),
            _ => {}
        }
    }
    ("name".to_string(), "ascending")
}

fn render_scan_report_result_counts(
    full: &ScanReportResultCounts,
    filtered: &ScanReportResultCounts,
) -> String {
    format!(
        "<result_count>{total}\
         <full>{total}</full><filtered>{filtered_total}</filtered>\
         <critical><full>{critical}</full><filtered>{filtered_critical}</filtered></critical>\
         <hole deprecated=\"1\"><full>{high}</full><filtered>{filtered_high}</filtered></hole>\
         <high><full>{high}</full><filtered>{filtered_high}</filtered></high>\
         <info deprecated=\"1\"><full>{low}</full><filtered>{filtered_low}</filtered></info>\
         <low><full>{low}</full><filtered>{filtered_low}</filtered></low>\
         <log><full>{log}</full><filtered>{filtered_log}</filtered></log>\
         <warning deprecated=\"1\"><full>{medium}</full><filtered>{filtered_medium}</filtered></warning>\
         <medium><full>{medium}</full><filtered>{filtered_medium}</filtered></medium>\
         <false_positive><full>{false_positive}</full><filtered>{filtered_false_positive}</filtered></false_positive>\
         </result_count>",
        total = full.total,
        filtered_total = filtered.total,
        critical = full.critical,
        filtered_critical = filtered.critical,
        high = full.high,
        filtered_high = filtered.high,
        low = full.low,
        filtered_low = filtered.low,
        log = full.log,
        filtered_log = filtered.log,
        medium = full.medium,
        filtered_medium = filtered.medium,
        false_positive = full.false_positive,
        filtered_false_positive = filtered.false_positive,
    )
}

fn render_scan_report_task(task: &Resource, store: &ResourceStore) -> String {
    let target = [
        ("target_id", "target"),
        ("agent_group_id", "agent_group"),
        ("oci_image_target_id", "oci_image_target"),
        ("web_application_target_id", "web_application_target"),
    ]
    .into_iter()
    .find_map(|(attribute, resource_type)| {
        task.attr(attribute)
            .and_then(|id| Uuid::parse_str(id).ok())
            .and_then(|id| store.get_typed(&id, resource_type))
            .map(|target| {
                let target_type = resource_type
                    .strip_suffix("_target")
                    .unwrap_or(resource_type);
                format!(
                    "<target id=\"{id}\"><trash>0</trash><name>{name}</name>\
                     <comment>{comment}</comment><target_type>{target_type}</target_type></target>",
                    id = target.id,
                    name = xml_escape(&target.name),
                    comment = xml_escape(&target.comment),
                )
            })
    })
    .unwrap_or_else(|| "<target/>".to_string());
    let progress = if task.attr("status") == Some("Done") {
        100
    } else {
        0
    };
    format!(
        "<task id=\"{id}\"><name>{name}</name><comment>{comment}</comment>\
         {target}<progress>{progress}</progress></task>",
        id = task.id,
        name = xml_escape(&task.name),
        comment = xml_escape(&task.comment),
    )
}

fn render_scan_report_filter_keywords(filter: &str) -> String {
    filter
        .split_whitespace()
        .filter_map(|predicate| predicate.split_once('='))
        .map(|(column, value)| {
            format!(
                "<keyword><column>{}</column><relation>=</relation><value>{}</value></keyword>",
                xml_escape(column),
                xml_escape(value),
            )
        })
        .collect()
}

fn render_agent_installer_instruction_response(cmd: &ParsedCommand) -> Vec<u8> {
    if cmd.attr("scanner_id").is_none() {
        return error_response(&cmd.name, 400, "Missing required attribute: scanner_id");
    }
    let Some(language) = cmd.attr("language") else {
        return error_response(&cmd.name, 400, "Missing required attribute: language");
    };
    if !matches!(language, "en" | "de") {
        return error_response(&cmd.name, 400, "Unsupported language");
    }
    if cmd.attr("origin_url").is_none_or(str::is_empty) {
        return error_response(&cmd.name, 400, "Missing required attribute: origin_url");
    }

    format!(
        "<get_agent_installer_instruction_response status=\"200\" status_text=\"OK\">\
         <language>{language}</language>\
         <instruction>Install the mock agent and connect it to the requested manager.</instruction>\
         </get_agent_installer_instruction_response>"
    )
    .into_bytes()
}

fn render_agent_support_bundle_response(cmd: &ParsedCommand) -> Vec<u8> {
    if cmd.attr("agent_uuid").is_none() {
        return error_response(&cmd.name, 400, "Missing required attribute: agent_uuid");
    }
    if let Some(days) = cmd.attr("days") {
        if days.parse::<u32>().is_err() {
            return error_response(&cmd.name, 400, "Invalid days value");
        }
    }

    b"<get_agent_support_bundle_response status=\"200\" status_text=\"OK\">\
      <file>\
      <name>mock-agent-support-bundle.tar.gz</name>\
      <content_type>application/octet-stream</content_type>\
      <size>10</size>\
      <content encoding=\"base64\">aGVsbG8tbW9jaw==</content>\
      </file>\
      </get_agent_support_bundle_response>"
        .to_vec()
}

fn handle_agent_set_action(cmd: &ParsedCommand) -> Vec<u8> {
    if !has_agent_ids(cmd) {
        return error_response(&cmd.name, 400, "Missing required element: agents");
    }
    format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
}

fn handle_modify_agent_control_scan_config(cmd: &ParsedCommand) -> Vec<u8> {
    if cmd.attr("agent_control_id").is_none() {
        return error_response(
            &cmd.name,
            400,
            "Missing required attribute: agent_control_id",
        );
    }
    if !cmd
        .children
        .iter()
        .any(|child| child.name == "config_defaults")
    {
        return error_response(&cmd.name, 400, "Missing required element: config_defaults");
    }
    format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
}

fn handle_modify_credential_store(cmd: &ParsedCommand) -> Vec<u8> {
    if cmd.attr("credential_store_id").is_none() {
        return error_response(
            &cmd.name,
            400,
            "Missing required attribute: credential_store_id",
        );
    }
    format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
}

fn handle_verify_credential_store(cmd: &ParsedCommand) -> Vec<u8> {
    if cmd.attr("credential_store_id").is_none() {
        return error_response(
            &cmd.name,
            400,
            "Missing required attribute: credential_store_id",
        );
    }
    format!("<{}_response status=\"200\" status_text=\"OK\"/>", cmd.name).into_bytes()
}

fn is_credential_store_credential_type(credential_type: &str) -> bool {
    matches!(
        credential_type,
        "cs_cc" | "cs_snmp" | "cs_up" | "cs_usk" | "cs_smime" | "cs_pgp" | "cs_pw"
    )
}

fn has_credential_store_credential_modify_field(cmd: &ParsedCommand) -> bool {
    cmd.children.iter().any(|child| {
        matches!(
            child.name.as_str(),
            "credential_store_id" | "vault_id" | "host_identifier"
        )
    })
}

fn has_agent_ids(cmd: &ParsedCommand) -> bool {
    cmd.children
        .iter()
        .find(|child| child.name == "agents")
        .is_some_and(|agents| {
            agents
                .children
                .iter()
                .any(|agent| agent.name == "agent" && agent.attributes.contains_key("id"))
        })
}

fn has_config_import_payload(cmd: &ParsedCommand) -> bool {
    cmd.children
        .iter()
        .any(|child| child.name == "get_configs_response")
}

fn imported_config_element(cmd: &ParsedCommand) -> Option<&ParsedElement> {
    let mut configs = cmd
        .children
        .iter()
        .find(|child| child.name == "get_configs_response")
        .into_iter()
        .flat_map(|response| response.children.iter())
        .filter(|child| child.name == "config");
    let config = configs.next()?;
    configs.next().is_none().then_some(config)
}

fn element_child_text<'a>(element: &'a ParsedElement, name: &str) -> Option<&'a str> {
    element
        .children
        .iter()
        .find(|child| child.name == name)
        .and_then(|child| child.text.as_deref())
}

fn usage_type_matches(resource: &Resource, requested_usage_type: Option<&str>) -> bool {
    match requested_usage_type {
        Some(usage_type) => resource.attr("usage_type") == Some(usage_type),
        None => true,
    }
}

fn optional_child_uuid(
    cmd: &ParsedCommand,
    child_name: &'static str,
) -> Result<Option<Uuid>, &'static str> {
    let Some(child) = cmd.children.iter().find(|child| child.name == child_name) else {
        return Ok(None);
    };
    let Some(id) = child.attributes.get("id") else {
        return Err(match child_name {
            "target" => "Missing target id",
            "config" => "Missing config id",
            "scanner" => "Missing scanner id",
            "task" => "Missing task id",
            _ => "Missing resource id",
        });
    };
    Uuid::parse_str(id).map(Some).map_err(|_| match child_name {
        "target" => "Invalid target UUID",
        "config" => "Invalid config UUID",
        "scanner" => "Invalid scanner UUID",
        "task" => "Invalid task UUID",
        _ => "Invalid resource UUID",
    })
}

fn task_references(cmd: &ParsedCommand) -> Result<TaskReferences, &'static str> {
    let target = cmd.children.iter().find(|child| child.name == "target");
    let target_id = target.and_then(|child| child.attributes.get("id"));
    let specialized_target = specialized_task_target(cmd)?;
    if target_id.map(String::as_str) == Some("0") {
        if specialized_target.is_some() {
            return Err("A task cannot have multiple target types");
        }
        return Ok(TaskReferences {
            target: None,
            specialized_target: None,
            config: None,
            scanner: None,
        });
    }
    if let Some(specialized_target) = specialized_target {
        if target.is_some() {
            return Err("A task cannot have multiple target types");
        }
        return Ok(TaskReferences {
            target: None,
            specialized_target: Some(specialized_target),
            config: optional_child_uuid(cmd, "config")?,
            scanner: Some(optional_child_uuid(cmd, "scanner")?.ok_or("A scanner is required")?),
        });
    }
    let target = optional_child_uuid(cmd, "target")?.ok_or("A target is required")?;
    let config = optional_child_uuid(cmd, "config")?.unwrap_or(DEFAULT_CONFIG_ID);
    let scanner = optional_child_uuid(cmd, "scanner")?.unwrap_or(DEFAULT_SCANNER_ID);
    Ok(TaskReferences {
        target: Some(target),
        specialized_target: None,
        config: Some(config),
        scanner: Some(scanner),
    })
}

fn task_reference_updates(cmd: &ParsedCommand) -> Result<TaskReferenceUpdates, &'static str> {
    let target = optional_child_uuid(cmd, "target")?;
    let specialized_target = specialized_task_target(cmd)?;
    if target.is_some() && specialized_target.is_some() {
        return Err("A task cannot have multiple target types");
    }
    Ok(TaskReferenceUpdates {
        target,
        specialized_target,
        config: optional_child_uuid(cmd, "config")?,
        scanner: optional_child_uuid(cmd, "scanner")?,
    })
}

fn specialized_task_target(
    cmd: &ParsedCommand,
) -> Result<Option<SpecializedTaskTarget>, &'static str> {
    let mut targets = cmd.children.iter().filter_map(|child| {
        let kind = match child.name.as_str() {
            "agent_group" => SpecializedTaskTarget::AgentGroup,
            "oci_image_target" => SpecializedTaskTarget::OciImageTarget,
            "web_application_target" => SpecializedTaskTarget::WebApplicationTarget,
            _ => return None,
        };
        Some((child, kind))
    });
    let Some((child, kind)) = targets.next() else {
        return Ok(None);
    };
    if targets.next().is_some() {
        return Err("A task cannot have multiple specialized targets");
    }
    let id = child
        .attributes
        .get("id")
        .filter(|id| !id.is_empty())
        .ok_or("Missing specialized target id")?;
    let id = Uuid::parse_str(id).map_err(|_| "Invalid specialized target UUID")?;
    Ok(Some(kind(id)))
}

fn store_error_response(command_name: &str, error: StoreError) -> Vec<u8> {
    match error {
        StoreError::NotFound(resource_type) => {
            error_response(command_name, 404, &format!("{resource_type} not found"))
        }
        StoreError::InUse(resource_type) => {
            error_response(command_name, 409, &format!("{resource_type} is in use"))
        }
        StoreError::InvalidState(message) => error_response(command_name, 409, message),
        StoreError::Inconsistent(resource_type) => error_response(
            command_name,
            409,
            &format!("Task graph is inconsistent: {resource_type}"),
        ),
    }
}

fn render_help_response(cmd: &ParsedCommand) -> Vec<u8> {
    const COMMANDS: [(&str, &str); 6] = [
        ("get_configs", "Get scan configurations"),
        ("get_feeds", "Get feed information"),
        ("get_info", "Get security information"),
        ("get_reports", "Get reports"),
        ("get_settings", "Get settings"),
        ("get_tasks", "Get tasks"),
    ];

    let format = cmd.attr("format").map(str::to_ascii_lowercase);
    let help_type = cmd.attr("type").unwrap_or_default();
    if !matches!(help_type, "" | "brief") {
        return error_response("help", 400, "Help type must be blank or 'brief'");
    }
    if help_type == "brief" && format.as_deref() != Some("xml") {
        return error_response("help", 400, "Brief help requires XML format");
    }

    if format.as_deref().is_none_or(|value| value == "text") {
        let mut body = String::new();
        for (name, summary) in COMMANDS {
            body.push_str(name);
            body.push_str(" - ");
            body.push_str(summary);
            body.push('\n');
        }
        return format!("<help_response status=\"200\" status_text=\"OK\">{body}</help_response>")
            .into_bytes();
    }

    if help_type == "brief" {
        let mut body = String::new();
        for (name, summary) in COMMANDS {
            body.push_str("<command><name>");
            body.push_str(name);
            body.push_str("</name><summary>");
            body.push_str(summary);
            body.push_str("</summary></command>");
        }
        return format!(
            "<help_response status=\"200\" status_text=\"OK\"><schema format=\"XML\" extension=\"xml\" content_type=\"text/xml\">{body}</schema></help_response>"
        )
        .into_bytes();
    }

    match format.as_deref().unwrap_or_default() {
        "xml" => {
            let mut commands = String::new();
            for (name, summary) in COMMANDS {
                commands.push_str("<command><name>");
                commands.push_str(name);
                commands.push_str("</name><summary>");
                commands.push_str(summary);
                commands.push_str("</summary></command>");
            }
            format!(
                "<help_response status=\"200\" status_text=\"OK\"><schema format=\"xml\" extension=\"xml\" content_type=\"text/xml\"><protocol><name>Greenbone Management Protocol</name>{commands}</protocol></schema></help_response>"
            )
            .into_bytes()
        }
        "html" => b"<help_response status=\"200\" status_text=\"OK\"><schema format=\"html\" extension=\"html\" content_type=\"text/html\">PGh0bWw+PGJvZHk+R01QPC9ib2R5PjwvaHRtbD4=</schema></help_response>".to_vec(),
        "rnc" => b"<help_response status=\"200\" status_text=\"OK\"><schema format=\"rnc\" extension=\"rnc\" content_type=\"application/relax-ng-compact-syntax\">c3RhcnQgPSBlbGVtZW50IGhlbHAgeyB0ZXh0IH0=</schema></help_response>".to_vec(),
        other => error_response("help", 404, &format!("Unknown help format '{other}'")),
    }
}

fn render_feeds_response(cmd: &ParsedCommand) -> Vec<u8> {
    const FEEDS: [(&str, &str, &str, &str); 4] = [
        (
            "NVT",
            "Greenbone Security Feed",
            "2026031801",
            "Network vulnerability tests",
        ),
        (
            "SCAP",
            "Greenbone SCAP Feed",
            "2026031701",
            "Security content automation data",
        ),
        (
            "CERT",
            "Greenbone CERT Feed",
            "2026031601",
            "CERT advisories",
        ),
        (
            "GVMD_DATA",
            "Greenbone Data Objects Feed",
            "2026031501",
            "Manager data objects",
        ),
    ];
    let selected_type = cmd.attr("type");
    let mut feeds = String::new();
    for (feed_type, name, version, description) in FEEDS {
        if selected_type.is_some_and(|selected| !selected.eq_ignore_ascii_case(feed_type)) {
            continue;
        }
        feeds.push_str("<feed><type>");
        feeds.push_str(feed_type);
        feeds.push_str("</type><name>");
        feeds.push_str(name);
        feeds.push_str("</name><version>");
        feeds.push_str(version);
        feeds.push_str("</version><description>");
        feeds.push_str(description);
        feeds.push_str("</description>");
        if feed_type == "SCAP" {
            feeds.push_str(
                "<currently_syncing><timestamp>2026-03-18T00:00:00Z</timestamp></currently_syncing>",
            );
        } else if feed_type == "CERT" {
            feeds.push_str(
                "<sync_not_available><error>Feed synchronization is unavailable</error></sync_not_available>",
            );
        }
        feeds.push_str("</feed>");
    }
    format!(
        "<get_feeds_response status=\"200\" status_text=\"OK\">\
         <feed_owner_set>1</feed_owner_set>\
         <feed_roles_set>1</feed_roles_set>\
         <feed_resources_access>1</feed_resources_access>\
         {feeds}</get_feeds_response>"
    )
    .into_bytes()
}

fn render_aggregates_response(cmd: &ParsedCommand) -> Vec<u8> {
    let Some(resource_type) = cmd.attr("type") else {
        return error_response("get_aggregates", 400, "A 'type' attribute is required");
    };
    let group_column = cmd.attr("group_column");
    let subgroup_column = cmd.attr("subgroup_column");
    if subgroup_column.is_some() && group_column.is_none() {
        return error_response(
            "get_aggregates",
            400,
            "A 'group_column' attribute is required when 'subgroup_column' is given",
        );
    }
    if cmd
        .attr("mode")
        .is_some_and(|mode| mode.eq_ignore_ascii_case("word_counts"))
    {
        let Some(group_column) = group_column else {
            return error_response(
                "get_aggregates",
                400,
                "A 'group_column' attribute is required for word_counts mode",
            );
        };
        let filter_id = cmd.attr("filt_id").unwrap_or_default();
        let filter_term = cmd.attr("filter").unwrap_or_default();
        return format!(
            "<get_aggregates_response status=\"200\" status_text=\"OK\">\
             <aggregate><data_type>{}</data_type><group_column>{}</group_column>\
             <group><value>security</value><count>3</count></group>\
             <group><value>update</value><count>5</count></group>\
             <column_info><aggregate_column><name>value</name><stat>value</stat>\
             <type>{}</type><column>{}</column><data_type>text</data_type>\
             </aggregate_column><aggregate_column><name>count</name><stat>count</stat>\
             <type>{}</type><column></column><data_type>integer</data_type>\
             </aggregate_column></column_info></aggregate>\
             <filters id=\"{}\"><term>{}</term><keywords/></filters>\
             </get_aggregates_response>",
            xml_escape(resource_type),
            xml_escape(group_column),
            xml_escape(resource_type),
            xml_escape(group_column),
            xml_escape(resource_type),
            xml_escape_attr(filter_id),
            xml_escape(filter_term)
        )
        .into_bytes();
    }

    let mut data_columns: Vec<&str> = cmd
        .children
        .iter()
        .filter(|child| child.name == "data_column")
        .filter_map(|child| child.text.as_deref())
        .collect();
    if data_columns.is_empty() {
        if let Some(data_column) = cmd.attr("data_column") {
            if !data_column.is_empty() {
                data_columns.push(data_column);
            }
        } else if let Some(legacy_columns) = cmd.attr("data_columns") {
            data_columns.extend(
                legacy_columns
                    .split(',')
                    .map(str::trim)
                    .filter(|column| !column.is_empty()),
            );
        }
    }
    let mut text_columns: Vec<&str> = cmd
        .children
        .iter()
        .filter(|child| child.name == "text_column")
        .filter_map(|child| child.text.as_deref())
        .collect();
    if text_columns.is_empty() {
        if let Some(legacy_columns) = cmd.attr("text_columns") {
            text_columns.extend(
                legacy_columns
                    .split(',')
                    .map(str::trim)
                    .filter(|column| !column.is_empty()),
            );
        }
    }

    let mut aggregate = format!(
        "<aggregate><data_type>{}</data_type>",
        xml_escape(resource_type)
    );
    for data_column in &data_columns {
        aggregate.push_str(&format!(
            "<data_column>{}</data_column>",
            xml_escape(data_column)
        ));
    }
    for text_column in &text_columns {
        aggregate.push_str(&format!(
            "<text_column>{}</text_column>",
            xml_escape(text_column)
        ));
    }
    if let Some(group_column) = group_column {
        aggregate.push_str(&format!(
            "<group_column>{}</group_column>",
            xml_escape(group_column)
        ));
    }
    if let Some(subgroup_column) = subgroup_column {
        aggregate.push_str(&format!(
            "<subgroup_column>{}</subgroup_column>",
            xml_escape(subgroup_column)
        ));
    }

    let append_statistics = |xml: &mut String, count: u32, cumulative: u32| {
        for data_column in &data_columns {
            xml.push_str(&format!(
                "<stats column=\"{}\"><min>1</min><max>{count}</max>\
                 <mean>2</mean><sum>{count}</sum><c_sum>{cumulative}</c_sum></stats>",
                xml_escape_attr(data_column)
            ));
        }
    };
    let append_text = |xml: &mut String, value: &str| {
        for text_column in &text_columns {
            xml.push_str(&format!(
                "<text column=\"{}\">{}</text>",
                xml_escape_attr(text_column),
                xml_escape(value)
            ));
        }
    };

    if group_column.is_none() {
        aggregate.push_str("<overall><count>8</count><c_count>8</c_count>");
        append_statistics(&mut aggregate, 8, 8);
        append_text(&mut aggregate, "All");
        aggregate.push_str("</overall>");
    } else if subgroup_column.is_some() {
        aggregate.push_str("<group><value>High</value>");
        aggregate.push_str("<subgroup><value>Primary</value><count>3</count><c_count>3</c_count>");
        append_statistics(&mut aggregate, 3, 3);
        aggregate.push_str("</subgroup><count>3</count><c_count>3</c_count>");
        append_statistics(&mut aggregate, 3, 3);
        append_text(&mut aggregate, "High");
        aggregate.push_str("</group><group><value>Medium</value>");
        aggregate
            .push_str("<subgroup><value>Secondary</value><count>5</count><c_count>5</c_count>");
        append_statistics(&mut aggregate, 5, 5);
        aggregate.push_str("</subgroup><count>5</count><c_count>8</c_count>");
        append_statistics(&mut aggregate, 5, 8);
        append_text(&mut aggregate, "Medium");
        aggregate.push_str(
            "</group><subgroups><value>Primary</value><value>Secondary</value></subgroups>",
        );
    } else {
        aggregate.push_str("<group><value>High</value><count>3</count><c_count>3</c_count>");
        append_statistics(&mut aggregate, 3, 3);
        append_text(&mut aggregate, "High");
        aggregate
            .push_str("</group><group><value>Medium</value><count>5</count><c_count>8</c_count>");
        append_statistics(&mut aggregate, 5, 8);
        append_text(&mut aggregate, "Medium");
        aggregate.push_str("</group>");
    }

    aggregate.push_str("<column_info>");
    if let Some(group_column) = group_column {
        aggregate.push_str(&format!(
            "<aggregate_column><name>value</name><stat>value</stat>\
             <type>{}</type><column>{}</column><data_type>text</data_type></aggregate_column>",
            xml_escape(resource_type),
            xml_escape(group_column)
        ));
    }
    if let Some(subgroup_column) = subgroup_column {
        aggregate.push_str(&format!(
            "<aggregate_column><name>subgroup_value</name><stat>value</stat>\
             <type>{}</type><column>{}</column><data_type>text</data_type></aggregate_column>",
            xml_escape(resource_type),
            xml_escape(subgroup_column)
        ));
    }
    aggregate.push_str(&format!(
        "<aggregate_column><name>count</name><stat>count</stat>\
         <type>{}</type><column></column><data_type>integer</data_type></aggregate_column>\
         <aggregate_column><name>c_count</name><stat>c_count</stat>\
         <type>{}</type><column></column><data_type>integer</data_type></aggregate_column>",
        xml_escape(resource_type),
        xml_escape(resource_type)
    ));
    for data_column in &data_columns {
        for statistic in ["min", "max", "mean", "sum", "c_sum"] {
            aggregate.push_str(&format!(
                "<aggregate_column><name>{}_{statistic}</name><stat>{statistic}</stat>\
                 <type>{}</type><column>{}</column><data_type>number</data_type>\
                 </aggregate_column>",
                xml_escape(data_column),
                xml_escape(resource_type),
                xml_escape(data_column)
            ));
        }
    }
    for text_column in &text_columns {
        aggregate.push_str(&format!(
            "<aggregate_column><name>{}</name><stat>text</stat>\
             <type>{}</type><column>{}</column><data_type>text</data_type></aggregate_column>",
            xml_escape(text_column),
            xml_escape(resource_type),
            xml_escape(text_column)
        ));
    }
    aggregate.push_str("</column_info></aggregate>");

    let filter_id = cmd.attr("filt_id").unwrap_or_default();
    let filter_term = cmd.attr("filter").unwrap_or_default();
    format!(
        "<get_aggregates_response status=\"200\" status_text=\"OK\">{aggregate}\
         <filters id=\"{}\"><term>{}</term><keywords/></filters>\
         </get_aggregates_response>",
        xml_escape_attr(filter_id),
        xml_escape(filter_term)
    )
    .into_bytes()
}

fn render_system_reports_response(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    const REPORTS: [(&str, &str); 2] = [("proc", "Processes"), ("load", "System Load")];
    let selected_name = cmd.attr("name");
    let brief = match cmd.attr("brief") {
        None | Some("0") | Some("false") => false,
        Some("1") | Some("true") => true,
        Some(_) => return error_response("get_system_reports", 400, "Invalid brief value"),
    };
    let duration = match cmd.attr("duration") {
        Some(value) => match value.parse::<u64>() {
            Ok(duration) => Some(duration),
            Err(_) => return error_response("get_system_reports", 400, "Invalid duration"),
        },
        None => None,
    };
    if selected_name.is_some_and(|selected| {
        !REPORTS
            .iter()
            .any(|(name, _)| selected.eq_ignore_ascii_case(name))
    }) {
        return error_response("get_system_reports", 404, "System report not found");
    }
    if let Some(slave_id) = cmd.attr("slave_id") {
        let Ok(slave_id) = Uuid::parse_str(slave_id) else {
            return error_response("get_system_reports", 400, "Invalid slave ID");
        };
        if store
            .get(&slave_id)
            .is_none_or(|resource| resource.resource_type != "scanner")
        {
            return error_response("get_system_reports", 404, "Slave not found");
        }
    }
    let start_time = cmd.attr("start_time").unwrap_or_default();
    let end_time = cmd.attr("end_time").unwrap_or_default();
    let duration = duration.map(|value| value.to_string()).unwrap_or_else(|| {
        if !start_time.is_empty() && !end_time.is_empty() {
            String::new()
        } else {
            "86400".to_string()
        }
    });
    let mut reports = String::new();

    for (name, title) in REPORTS {
        if selected_name.is_some_and(|selected| !selected.eq_ignore_ascii_case(name)) {
            continue;
        }
        reports.push_str("<system_report><name>");
        reports.push_str(name);
        reports.push_str("</name><title>");
        reports.push_str(title);
        reports.push_str("</title>");
        if !brief {
            reports.push_str("<report format=\"png\" start_time=\"");
            reports.push_str(&xml_escape_attr(start_time));
            reports.push_str("\" end_time=\"");
            reports.push_str(&xml_escape_attr(end_time));
            reports.push_str("\" duration=\"");
            reports.push_str(&duration);
            reports.push_str("\">iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB</report>");
        }
        reports.push_str("</system_report>");
    }

    format!(
        "<get_system_reports_response status=\"200\" status_text=\"OK\">{reports}</get_system_reports_response>"
    )
    .into_bytes()
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
        "NVT" | "nvt" => (
            "nvt",
            vec![
                ("1.3.6.1.4.1.25623.1", "Mock NVT one"),
                ("1.3.6.1.4.1.25623.2", "Mock NVT two"),
            ],
        ),
        "OVALDEF" | "ovaldef" => (
            "ovaldef",
            vec![
                ("oval:org.example:def:1", "Mock OVAL definition one"),
                ("oval:org.example:def:2", "Mock OVAL definition two"),
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
    let name = cmd.attr("name");
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|(id, _)| info_id.is_none_or(|wanted| wanted == *id))
        .filter(|(id, entry_name)| name.is_none_or(|wanted| wanted == *id || wanted == *entry_name))
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

fn render_vulnerabilities_response(cmd: &ParsedCommand) -> Vec<u8> {
    let entries = [
        ("vuln-1", "Outdated package"),
        ("vuln-2", "Weak configuration"),
    ];
    let vuln_id = cmd.attr("vuln_id");
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|(id, _)| vuln_id.is_none_or(|wanted| wanted == *id))
        .collect();
    let count = entries.len();
    let items: String = entries
        .into_iter()
        .map(|(id, name)| format!("<vuln id=\"{id}\"><name>{name}</name></vuln>"))
        .collect();
    format!(
        "<get_vulns_response status=\"200\" status_text=\"OK\">{items}<vuln_count>{count}<filtered>{count}</filtered></vuln_count></get_vulns_response>"
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

fn set_alert_fields(resource: &mut Resource, cmd: &ParsedCommand) {
    for field in ["event", "condition", "method"] {
        let Some(element) = cmd.children.iter().find(|child| child.name == field) else {
            continue;
        };
        resource.set_attr(field, element.text.as_deref().unwrap_or_default());
        let data_prefix = format!("{field}_data:");
        resource
            .attrs
            .retain(|key, _| !key.starts_with(&data_prefix));
        for data in element.children.iter().filter(|child| child.name == "data") {
            let Some(name) = element_child_text(data, "name") else {
                continue;
            };
            resource.set_attr(
                &format!("{data_prefix}{name}"),
                data.text.as_deref().unwrap_or_default(),
            );
        }
    }
    if let Some(filter_id) = cmd.child_attr("filter", "id") {
        resource.set_attr("filter_id", filter_id);
    }
}

fn nested_child_attr(cmd: &ParsedCommand, path: &[&str], attr: &str) -> Option<String> {
    let (first, rest) = path.split_first()?;
    let mut element = cmd.children.iter().find(|child| child.name == *first)?;
    for name in rest {
        element = element.children.iter().find(|child| child.name == **name)?;
    }
    element.attributes.get(attr).cloned()
}

fn set_permission_references(resource: &mut Resource, cmd: &ParsedCommand) {
    for (element, id_key, type_key) in [
        ("subject", "subject_id", "subject_type"),
        ("resource", "resource_id", "resource_type"),
    ] {
        if let Some(id) = cmd
            .child_attr(element, "id")
            .filter(|value| !value.is_empty())
        {
            resource.set_attr(id_key, id);
        }
        if let Some(reference_type) =
            nested_child_text(cmd, &[element, "type"]).filter(|value| !value.is_empty())
        {
            resource.set_attr(type_key, &reference_type);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_parser::parse_command;

    #[test]
    fn permission_references_ignore_empty_ids_and_types() {
        let command = parse_command(
            br#"<create_permission>
                <subject id=""><type>role</type></subject>
                <resource id="target-1"><type/></resource>
            </create_permission>"#,
        )
        .expect("parse permission command");
        let mut permission = Resource::new("permission", "get_targets");

        set_permission_references(&mut permission, &command);

        assert_eq!(permission.attr("subject_id"), None);
        assert_eq!(permission.attr("subject_type"), Some("role"));
        assert_eq!(permission.attr("resource_id"), Some("target-1"));
        assert_eq!(permission.attr("resource_type"), None);
        let xml = permission.to_xml();
        assert!(!xml.contains("<subject"));
        assert!(xml.contains(r#"<resource id="target-1"><name></name></resource>"#));
        assert!(!xml.contains("<type>"));
    }

    #[test]
    fn optional_child_uuid_reports_specific_missing_and_invalid_ids() {
        for (child_name, missing_message, invalid_message) in [
            ("target", "Missing target id", "Invalid target UUID"),
            ("config", "Missing config id", "Invalid config UUID"),
            ("scanner", "Missing scanner id", "Invalid scanner UUID"),
            ("task", "Missing task id", "Invalid task UUID"),
            ("resource", "Missing resource id", "Invalid resource UUID"),
        ] {
            let missing = parse_command(format!("<command><{child_name}/></command>").as_bytes())
                .expect("parse missing-id command");
            assert_eq!(
                optional_child_uuid(&missing, child_name),
                Err(missing_message)
            );

            let invalid = parse_command(
                format!("<command><{child_name} id=\"not-a-uuid\"/></command>").as_bytes(),
            )
            .expect("parse invalid-id command");
            assert_eq!(
                optional_child_uuid(&invalid, child_name),
                Err(invalid_message)
            );
        }
    }

    #[test]
    fn task_reference_parsing_rejects_competing_target_shapes() {
        let target_id = Uuid::new_v4();
        let agent_group_id = Uuid::new_v4();
        let oci_target_id = Uuid::new_v4();

        let import_and_specialized = parse_command(
            format!(
                "<create_task><target id=\"0\"/><agent_group id=\"{agent_group_id}\"/></create_task>"
            )
            .as_bytes(),
        )
        .expect("parse import and specialized targets");
        assert_eq!(
            task_references(&import_and_specialized),
            Err("A task cannot have multiple target types")
        );

        let regular_and_specialized = parse_command(
            format!(
                "<create_task><target id=\"{target_id}\"/><agent_group id=\"{agent_group_id}\"/></create_task>"
            )
            .as_bytes(),
        )
        .expect("parse regular and specialized targets");
        assert_eq!(
            task_references(&regular_and_specialized),
            Err("A task cannot have multiple target types")
        );
        assert_eq!(
            task_reference_updates(&regular_and_specialized),
            Err("A task cannot have multiple target types")
        );

        let empty_regular_and_specialized = parse_command(
            format!("<create_task><target/><agent_group id=\"{agent_group_id}\"/></create_task>")
                .as_bytes(),
        )
        .expect("parse empty regular and specialized targets");
        assert_eq!(
            task_references(&empty_regular_and_specialized),
            Err("A task cannot have multiple target types")
        );

        let multiple_specialized = parse_command(
            format!(
                "<create_task><agent_group id=\"{agent_group_id}\"/><oci_image_target id=\"{oci_target_id}\"/></create_task>"
            )
            .as_bytes(),
        )
        .expect("parse multiple specialized targets");
        assert_eq!(
            task_references(&multiple_specialized),
            Err("A task cannot have multiple specialized targets")
        );
    }

    #[test]
    fn inconsistent_store_errors_are_rendered_as_conflicts() {
        let response = store_error_response("start_task", StoreError::Inconsistent("task report"));
        let response = String::from_utf8(response).expect("UTF-8 response");
        assert!(response.contains("status=\"409\""));
        assert!(response.contains("Task graph is inconsistent: task report"));
    }

    #[test]
    fn scan_report_task_renders_running_specialized_target() {
        let store = ResourceStore::new();
        let target = Resource::new("oci_image_target", "Container Target");
        let target_id = target.id;
        store.seed(target);

        let mut task = Resource::new("task", "Container Task");
        task.set_attr("oci_image_target_id", &target_id.to_string());
        task.set_attr("status", "Running");

        let xml = render_scan_report_task(&task, &store);
        assert!(xml.contains("<target_type>oci_image</target_type>"));
        assert!(xml.contains("<progress>0</progress>"));
    }

    #[test]
    fn scan_report_task_renders_empty_target_when_unlinked() {
        let store = ResourceStore::new();
        let task = Resource::new("task", "Import Task");

        let xml = render_scan_report_task(&task, &store);
        assert!(xml.contains("<target/>"));
        assert!(xml.contains("<progress>0</progress>"));
    }
}
