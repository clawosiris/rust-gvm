// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! In-memory resource store for Stateful mode.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use chrono::DateTime;
use gvm_gmp::AliveTest;
use uuid::Uuid;

use crate::util::{now_iso, xml_escape, xml_escape_attr};

/// Input profile for stateful asset commands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssetInputProfile {
    /// Require the asset command shapes accepted by current gvmd.
    #[default]
    GvmdStrict,
    /// Accept the historical flat mock inputs (`asset_type`, `<asset_type>`, and `<value>`).
    ///
    /// This profile exists only for consumers that explicitly need compatibility
    /// with the mock's former, non-canonical asset command surface.
    LegacyFlatCompatibility,
}

/// Result of an atomic permanent asset deletion.
pub(crate) enum DeleteAssetResult {
    /// The asset was deleted.
    Deleted,
    /// The operating-system asset is still referenced.
    InUse,
    /// No live asset with the requested ID exists.
    NotFound,
}

pub(crate) const DEFAULT_CONFIG_ID: Uuid =
    Uuid::from_u128(0xdaba_56c8_73ec_11df_a475_0022_6476_4cea);
pub(crate) const DEFAULT_SCANNER_ID: Uuid =
    Uuid::from_u128(0x08b6_9003_5fc2_4037_a479_93b4_4021_1c73);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoreError {
    NotFound(String),
    InUse(&'static str),
    InvalidArgument(&'static str),
    InvalidState(&'static str),
    Inconsistent(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecializedTaskTarget {
    AgentGroup(Uuid),
    OciImageTarget(Uuid),
    WebApplicationTarget(Uuid),
}

impl SpecializedTaskTarget {
    fn resource_type(self) -> &'static str {
        match self {
            Self::AgentGroup(_) => "agent_group",
            Self::OciImageTarget(_) => "oci_image_target",
            Self::WebApplicationTarget(_) => "web_application_target",
        }
    }

    fn attr_name(self) -> &'static str {
        match self {
            Self::AgentGroup(_) => "agent_group_id",
            Self::OciImageTarget(_) => "oci_image_target_id",
            Self::WebApplicationTarget(_) => "web_application_target_id",
        }
    }

    fn id(self) -> Uuid {
        match self {
            Self::AgentGroup(id) | Self::OciImageTarget(id) | Self::WebApplicationTarget(id) => id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskReferences {
    pub target: Option<Uuid>,
    pub specialized_target: Option<SpecializedTaskTarget>,
    pub config: Option<Uuid>,
    pub scanner: Option<Uuid>,
    pub schedule: Option<Uuid>,
    pub schedule_periods: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum TaskScheduleUpdate {
    #[default]
    Omitted,
    Set(Uuid),
    Clear,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TaskReferenceUpdates {
    pub target: Option<Uuid>,
    pub specialized_target: Option<SpecializedTaskTarget>,
    pub config: Option<Uuid>,
    pub scanner: Option<Uuid>,
    pub schedule: TaskScheduleUpdate,
    pub schedule_periods: Option<u32>,
}

impl TaskReferenceUpdates {
    fn changes_scan_definition(self) -> bool {
        self.target.is_some()
            || self.specialized_target.is_some()
            || self.config.is_some()
            || self.scanner.is_some()
    }
}

/// Task status in the lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    /// Newly created, not yet started.
    New,
    /// Start requested.
    Requested,
    /// Waiting for scanner capacity.
    Queued,
    /// Currently running.
    Running,
    /// Stop requested.
    StopRequested,
    /// Delete requested while processing is still active.
    DeleteRequested,
    /// Ultimate deletion requested while processing is still active.
    UltimateDeleteRequested,
    /// Stopped by user.
    Stopped,
    /// Completed successfully.
    Done,
    /// Interrupted before completion and eligible for resumption.
    Interrupted,
    /// Report data is being processed.
    Processing,
}

impl TaskStatus {
    /// Return the GMP status string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Requested => "Requested",
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::StopRequested => "Stop Requested",
            Self::DeleteRequested => "Delete Requested",
            Self::UltimateDeleteRequested => "Ultimate Delete Requested",
            Self::Stopped => "Stopped",
            Self::Done => "Done",
            Self::Interrupted => "Interrupted",
            Self::Processing => "Processing",
        }
    }
}

/// A stored GMP resource (generic for all resource types).
#[derive(Debug, Clone)]
pub struct Resource {
    /// Resource UUID.
    pub id: Uuid,
    /// Resource type name (e.g., "task", "target").
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Optional comment.
    pub comment: String,
    /// Creation timestamp (ISO 8601).
    pub creation_time: String,
    /// Modification timestamp (ISO 8601).
    pub modification_time: String,
    /// Additional type-specific attributes.
    pub attrs: BTreeMap<String, String>,
    /// Whether this resource is in the trashcan.
    pub trashed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AuditComplianceCounts {
    pub(crate) yes: usize,
    pub(crate) no: usize,
    pub(crate) incomplete: usize,
    pub(crate) undefined: usize,
}

impl AuditComplianceCounts {
    pub(crate) fn from_results<'a>(results: impl Iterator<Item = &'a Resource>) -> Self {
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

    pub(crate) fn total(self) -> usize {
        self.yes + self.no + self.incomplete + self.undefined
    }

    pub(crate) fn compliance(self) -> &'static str {
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

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScanReportResultCounts {
    pub(crate) total: usize,
    pub(crate) critical: usize,
    pub(crate) high: usize,
    pub(crate) medium: usize,
    pub(crate) low: usize,
    pub(crate) log: usize,
    pub(crate) false_positive: usize,
    pub(crate) errors: usize,
    pub(crate) hosts: usize,
    pub(crate) ports: usize,
    pub(crate) max_severity: f64,
}

impl ScanReportResultCounts {
    pub(crate) fn from_results<'a>(results: impl Iterator<Item = &'a Resource>) -> Self {
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

pub(crate) fn scan_report_result_severity(result: &Resource) -> f64 {
    result
        .attr("severity")
        .and_then(|severity| severity.parse().ok())
        .unwrap_or_default()
}

impl Resource {
    /// Create a new resource with auto-generated UUID and timestamps.
    pub fn new(resource_type: &str, name: &str) -> Self {
        let now = now_iso();
        Self {
            id: Uuid::new_v4(),
            resource_type: resource_type.to_string(),
            name: name.to_string(),
            comment: String::new(),
            creation_time: now.clone(),
            modification_time: now,
            attrs: BTreeMap::new(),
            trashed: false,
        }
    }

    /// Create with a specific UUID.
    pub fn with_id(resource_type: &str, name: &str, id: Uuid) -> Self {
        let mut r = Self::new(resource_type, name);
        r.id = id;
        r
    }

    /// Set an attribute.
    pub fn set_attr(&mut self, key: &str, value: &str) {
        self.attrs.insert(key.to_string(), value.to_string());
    }

    /// Remove an attribute.
    pub fn remove_attr(&mut self, key: &str) {
        self.attrs.remove(key);
    }

    /// Get an attribute.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(String::as_str)
    }

    /// Return the canonical asset type, including legacy seeded resources.
    pub(crate) fn asset_type(&self) -> Option<&str> {
        self.attr("type").or_else(|| self.attr("asset_type"))
    }

    /// Generate the canonical gvmd asset representation used by `get_assets`.
    pub(crate) fn to_asset_xml(&self) -> String {
        let asset_type = self.asset_type().unwrap_or_default();
        let writable = if asset_type == "os" { "0" } else { "1" };
        let in_use = if asset_type == "os"
            && self
                .attr("installs")
                .and_then(|value| value.parse::<u32>().ok())
                .is_some_and(|count| count > 0)
        {
            "1"
        } else {
            "0"
        };
        let common = format!(
            "<asset id=\"{id}\">\
             <owner><name>admin</name></owner>\
             <name>{name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>\
             <writable>{writable}</writable>\
             <in_use>{in_use}</in_use>\
             <permissions><permission><name>Everything</name></permission></permissions>",
            id = self.id,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
            writable = writable,
            in_use = in_use,
        );

        match asset_type {
            "host" => {
                let severity = self.attr("severity").unwrap_or_default();
                format!(
                    "{common}\
                     <identifiers><identifier id=\"{id}\">\
                     <name>ip</name><value>{name}</value>\
                     <creation_time>{ct}</creation_time>\
                     <modification_time>{mt}</modification_time>\
                     <source><type>User</type><data></data><deleted>0</deleted><name>admin</name></source>\
                     </identifier></identifiers>\
                     <type>host</type>\
                     <host><severity><value>{severity}</value></severity></host>\
                     </asset>",
                    id = self.id,
                    name = xml_escape(&self.name),
                    ct = self.creation_time,
                    mt = self.modification_time,
                    severity = xml_escape(severity),
                )
            }
            "os" => {
                let title = self.attr("title").unwrap_or(&self.name);
                let installs = self.attr("installs").unwrap_or("0");
                let all_installs = self.attr("all_installs").unwrap_or(installs);
                let latest = self.attr("latest_severity").unwrap_or_default();
                let highest = self.attr("highest_severity").unwrap_or_default();
                let average = self.attr("average_severity").unwrap_or_default();
                format!(
                    "{common}\
                     <type>os</type>\
                     <os>\
                     <latest_severity><value>{latest}</value></latest_severity>\
                     <highest_severity><value>{highest}</value></highest_severity>\
                     <average_severity><value>{average}</value></average_severity>\
                     <title>{title}</title>\
                     <installs>{installs}</installs>\
                     <all_installs>{all_installs}</all_installs>\
                     <hosts>{installs}</hosts>\
                     </os>\
                     </asset>",
                    latest = xml_escape(latest),
                    highest = xml_escape(highest),
                    average = xml_escape(average),
                    title = xml_escape(title),
                    installs = xml_escape(installs),
                    all_installs = xml_escape(all_installs),
                )
            }
            _ => format!("{common}<type>{}</type></asset>", xml_escape(asset_type)),
        }
    }

    /// Generate XML representation for get responses.
    pub fn to_xml(&self) -> String {
        self.to_xml_with_details(false)
    }

    /// Generate XML representation for get responses with command detail semantics.
    pub(crate) fn to_xml_with_details(&self, details: bool) -> String {
        self.to_xml_with_task_reports(None, None, &[], details)
    }

    fn to_xml_with_task_reports(
        &self,
        current_report: Option<&Resource>,
        last_report: Option<&Resource>,
        last_report_results: &[&Resource],
        details: bool,
    ) -> String {
        // Notes and overrides use <text> instead of <name>
        let name_tag = if self.resource_type == "note" || self.resource_type == "override" {
            "text"
        } else {
            "name"
        };
        let oid_attr = if self.resource_type == "nvt" {
            self.attr("oid")
                .or_else(|| self.attr("nvt_oid"))
                .map(|oid| format!(" oid=\"{}\"", xml_escape_attr(oid)))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let mut xml = format!(
            "<{type} id=\"{id}\"{oid_attr}>\
             <{name_tag}>{name}</{name_tag}>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>",
            type = self.resource_type,
            id = self.id,
            oid_attr = oid_attr,
            name_tag = name_tag,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
        );
        if self.resource_type == "permission" {
            for (element, id_key, type_key) in [
                ("subject", "subject_id", "subject_type"),
                ("resource", "resource_id", "resource_type"),
            ] {
                if let Some(id) = self.attr(id_key).filter(|value| !value.is_empty()) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name>",
                        xml_escape_attr(id),
                    ));
                    if let Some(reference_type) =
                        self.attr(type_key).filter(|value| !value.is_empty())
                    {
                        xml.push_str(&format!("<type>{}</type>", xml_escape(reference_type)));
                    }
                    xml.push_str(&format!("</{element}>"));
                }
            }
        }
        if self.resource_type == "task" {
            if self.attr("observers").is_some() || self.attr("observer_group_ids").is_some() {
                xml.push_str("<observers>");
                if let Some(observers) = self.attr("observers") {
                    xml.push_str(&xml_escape(observers));
                }
                if let Some(group_ids) = self.attr("observer_group_ids") {
                    for group_id in group_ids.split(',').filter(|id| !id.is_empty()) {
                        xml.push_str(&format!(
                            "<group id=\"{}\"><name>{}</name></group>",
                            xml_escape_attr(group_id),
                            xml_escape(group_id),
                        ));
                    }
                }
                xml.push_str("</observers>");
            }
            if self.attr("target_id").is_none() {
                xml.push_str("<target id=\"\"><name></name></target>");
            }
            for (attribute, element) in [
                ("target_id", "target"),
                ("agent_group_id", "agent_group"),
                ("oci_image_target_id", "oci_image_target"),
                ("web_application_target_id", "web_application_target"),
                ("config_id", "config"),
                ("scanner_id", "scanner"),
                ("schedule_id", "schedule"),
            ] {
                if let Some(id) = self.attr(attribute) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name></{element}>",
                        xml_escape_attr(id),
                    ));
                }
            }
            xml.push_str(&format!(
                "<schedule_periods>{}</schedule_periods>",
                xml_escape(self.attr("schedule_periods").unwrap_or("0")),
            ));
            if let Some(report) = current_report {
                xml.push_str(&task_report_reference_xml("current_report", report, &[]));
            }
            if let Some(report) = last_report {
                xml.push_str(&task_report_reference_xml(
                    "last_report",
                    report,
                    last_report_results,
                ));
            }
        }
        if self.resource_type == "user" {
            if let Some(role_ids) = self.attr("role_ids") {
                for role_id in role_ids.split(',').filter(|role_id| !role_id.is_empty()) {
                    let role_id_attr = xml_escape_attr(role_id);
                    let role_id = xml_escape(role_id);
                    xml.push_str(&format!(
                        "<role id=\"{role_id_attr}\"><name>{role_id}</name></role>"
                    ));
                }
            }
        }
        if self.resource_type == "target" {
            let alive_test = self
                .attr("alive_test")
                .unwrap_or(AliveTest::ScanConfigDefault.as_target_name());
            xml.push_str(&format!(
                "<alive_tests>{}</alive_tests>",
                xml_escape(alive_test),
            ));
            if let Some(port_list_id) = self.attr("port_list_id") {
                xml.push_str(&format!(
                    "<port_list id=\"{}\"><name></name></port_list>",
                    xml_escape_attr(port_list_id),
                ));
            }
            if details {
                if let Some(port_range) = self.attr("port_range") {
                    xml.push_str(&format!(
                        "<port_range>{}</port_range>",
                        xml_escape(port_range),
                    ));
                }
            }
            if let Some(id) = self.attr("ssh_credential_id") {
                xml.push_str(&format!(
                    "<ssh_credential id=\"{}\"><name></name>",
                    xml_escape_attr(id),
                ));
                if let Some(port) = self.attr("ssh_credential_port") {
                    xml.push_str(&format!("<port>{}</port>", xml_escape(port)));
                }
                xml.push_str("</ssh_credential>");
            } else {
                xml.push_str("<ssh_credential id=\"\"><name></name><port></port></ssh_credential>");
            }
            if let Some(id) = self.attr("smb_credential_id") {
                xml.push_str(&format!(
                    "<smb_credential id=\"{}\"><name></name></smb_credential>",
                    xml_escape_attr(id),
                ));
            } else {
                xml.push_str("<smb_credential id=\"\"><name></name></smb_credential>");
            }
            for (attribute, element) in [
                ("ssh_elevate_credential_id", "ssh_elevate_credential"),
                ("krb5_credential_id", "krb5_credential"),
                ("esxi_credential_id", "esxi_credential"),
                ("snmp_credential_id", "snmp_credential"),
            ] {
                if let Some(id) = self.attr(attribute) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name></{element}>",
                        xml_escape_attr(id),
                    ));
                } else {
                    xml.push_str(&format!("<{element} id=\"\"><name></name></{element}>"));
                }
            }
        }
        // Add type-specific attributes
        if self.resource_type == "alert" {
            for field in ["event", "condition", "method"] {
                if let Some(value) = self.attr(field) {
                    xml.push_str(&format!("<{field}>{}", xml_escape(value)));
                    let data_prefix = format!("{field}_data:");
                    for (key, data_value) in self.attrs.iter().filter_map(|(key, value)| {
                        key.strip_prefix(&data_prefix).map(|name| (name, value))
                    }) {
                        xml.push_str(&format!(
                            "<data>{}<name>{}</name></data>",
                            xml_escape(data_value),
                            xml_escape(key),
                        ));
                    }
                    xml.push_str(&format!("</{field}>"));
                }
            }
            if let Some(filter_id) = self.attr("filter_id") {
                xml.push_str(&format!(
                    "<filter id=\"{}\"><name></name></filter>",
                    xml_escape_attr(filter_id),
                ));
            }
        }
        if self.resource_type == "ticket" {
            for (field, element) in [
                ("assigned_to_id", "assigned_to"),
                ("result_id", "result"),
                ("task_id", "task"),
            ] {
                if let Some(id) = self.attr(field) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name></{element}>",
                        xml_escape_attr(id),
                    ));
                }
            }
        }
        for (k, v) in &self.attrs {
            if self.resource_type == "scanner" && k == "credential_id" {
                xml.push_str(&format!(
                    "<credential id=\"{}\"><name></name></credential>",
                    xml_escape_attr(v),
                ));
                continue;
            }
            if self.resource_type == "alert"
                && (matches!(k.as_str(), "event" | "condition" | "method" | "filter_id")
                    || k.starts_with("event_data:")
                    || k.starts_with("condition_data:")
                    || k.starts_with("method_data:"))
            {
                continue;
            }
            if self.resource_type == "ticket"
                && matches!(k.as_str(), "assigned_to_id" | "result_id" | "task_id")
            {
                continue;
            }
            if self.resource_type == "permission"
                && matches!(
                    k.as_str(),
                    "subject_id" | "subject_type" | "resource_id" | "resource_type"
                )
            {
                continue;
            }
            if self.resource_type == "user" && k == "role_ids" {
                continue;
            }
            if self.resource_type == "target"
                && matches!(
                    k.as_str(),
                    "port_list_id"
                        | "alive_test"
                        | "port_range"
                        | "asset_hosts_filter"
                        | "ssh_credential_id"
                        | "ssh_credential_port"
                        | "smb_credential_id"
                        | "ssh_elevate_credential_id"
                        | "krb5_credential_id"
                        | "esxi_credential_id"
                        | "snmp_credential_id"
                )
            {
                continue;
            }
            if self.resource_type == "nvt"
                && matches!(
                    k.as_str(),
                    "oid" | "nvt_oid" | "config_id" | "preferences_config_id"
                )
            {
                continue;
            }
            if self.resource_type == "task"
                && matches!(
                    k.as_str(),
                    "target_id"
                        | "agent_group_id"
                        | "oci_image_target_id"
                        | "web_application_target_id"
                        | "config_id"
                        | "scanner_id"
                        | "schedule_id"
                        | "schedule_periods"
                        | "report_id"
                )
            {
                continue;
            }
            xml.push_str(&format!("<{k}>{}</{k}>", xml_escape(v)));
        }
        xml.push_str(&format!("</{}>", self.resource_type));
        xml
    }

    /// Generate the canonical gvmd representation for an integration configuration.
    pub(crate) fn to_integration_config_xml(&self, details: bool) -> String {
        let mut xml = format!(
            "<integration_config id=\"{id}\">\
             <owner><name>admin</name></owner>\
             <name>{name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>\
             <writable>1</writable>\
             <in_use>0</in_use>\
             <permissions><permission><name>Everything</name></permission></permissions>",
            id = self.id,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
        );
        if details {
            xml.push_str(&format!(
                "<service><url>{service_url}</url></service>\
                 <oidc><url>{oidc_url}</url><client><id>{client_id}</id></client></oidc>",
                service_url = xml_escape(self.attr("service_url").unwrap_or_default()),
                oidc_url = xml_escape(self.attr("oidc_provider_url").unwrap_or_default()),
                client_id = xml_escape(self.attr("oidc_provider_client_id").unwrap_or_default()),
            ));
        }
        xml.push_str("</integration_config>");
        xml
    }
}

fn task_report_reference_xml(field: &str, report: &Resource, results: &[&Resource]) -> String {
    let timestamp = report.attr("timestamp").unwrap_or(&report.creation_time);
    let scan_start = report.attr("scan_start").unwrap_or(&report.creation_time);
    let scan_end = report.attr("scan_end").unwrap_or_else(|| {
        if report.attr("status") == Some(TaskStatus::Done.as_str()) {
            &report.modification_time
        } else {
            ""
        }
    });
    let mut xml = format!(
        "<{field}><report id=\"{}\"><timestamp>{}</timestamp>\
         <scan_start>{}</scan_start><scan_end>{}</scan_end>",
        xml_escape_attr(&report.id.to_string()),
        xml_escape(timestamp),
        xml_escape(scan_start),
        xml_escape(scan_end),
    );
    if field == "last_report" {
        if report.attr("usage_type") == Some("audit") {
            let counts = AuditComplianceCounts::from_results(results.iter().copied());
            xml.push_str(&format!(
                "<compliance_count><yes>{}</yes><no>{}</no><incomplete>{}</incomplete>\
                 </compliance_count>",
                counts.yes, counts.no, counts.incomplete,
            ));
        } else {
            let counts = ScanReportResultCounts::from_results(results.iter().copied());
            xml.push_str(&format!(
                "<result_count><critical>{critical}</critical>\
                 <hole deprecated=\"1\">{high}</hole><high>{high}</high>\
                 <info deprecated=\"1\">{low}</info><low>{low}</low><log>{log}</log>\
                 <warning deprecated=\"1\">{medium}</warning><medium>{medium}</medium>\
                 <false_positive>{false_positive}</false_positive></result_count>\
                 <severity>{severity:.1}</severity>",
                critical = counts.critical,
                high = counts.high,
                low = counts.low,
                log = counts.log,
                medium = counts.medium,
                false_positive = counts.false_positive,
                severity = counts.max_severity,
            ));
        }
    }
    xml.push_str(&format!("</report></{field}>"));
    xml
}

/// Thread-safe resource store.
#[derive(Debug, Clone)]
pub struct ResourceStore {
    inner: Arc<RwLock<StoreInner>>,
}

#[derive(Debug)]
struct StoreInner {
    resources: HashMap<Uuid, Resource>,
    insertion_order: HashMap<Uuid, u64>,
    next_insertion_order: u64,
    /// Stateful asset request parsing profile.
    asset_input_profile: AssetInputProfile,
    /// Authenticated sessions.
    authenticated_sessions: std::collections::HashSet<u64>,
    /// Configured credentials.
    username: String,
    password: String,
}

fn default_resources() -> HashMap<Uuid, Resource> {
    let mut resources = HashMap::new();

    let mut timezone = Resource::with_id(
        "setting",
        "timezone",
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("valid uuid"),
    );
    timezone.comment = "User timezone".to_string();
    timezone.set_attr("value", "UTC");
    resources.insert(timezone.id, timezone);

    let mut rows_per_page = Resource::with_id(
        "setting",
        "rows_per_page",
        Uuid::parse_str("00000000-0000-0000-0000-000000000002").expect("valid uuid"),
    );
    rows_per_page.comment = "Default rows per page".to_string();
    rows_per_page.set_attr("value", "100");
    resources.insert(rows_per_page.id, rows_per_page);

    let mut integration_config = Resource::with_id(
        "integration_config",
        "Default Integration Config",
        Uuid::parse_str("00000000-0000-0000-0000-000000000100").expect("valid uuid"),
    );
    integration_config.comment = "Mock integration config".to_string();
    integration_config.set_attr("service_url", "https://service.example.invalid");
    integration_config.set_attr("service_cacert", "MOCK-CA-CERT");
    integration_config.set_attr("oidc_provider_url", "https://oidc.example.invalid");
    integration_config.set_attr("oidc_provider_client_id", "mock-client-id");
    integration_config.set_attr("oidc_provider_client_secret", "mock-client-secret");
    resources.insert(integration_config.id, integration_config);

    let mut config = Resource::with_id("config", "Full and fast", DEFAULT_CONFIG_ID);
    config.comment = "Mock default scan config".to_string();
    config.set_attr("usage_type", "scan");
    resources.insert(config.id, config);

    let mut scanner = Resource::with_id("scanner", "OpenVAS Default", DEFAULT_SCANNER_ID);
    scanner.comment = "Mock default scanner".to_string();
    scanner.set_attr("type", "OpenVAS");
    resources.insert(scanner.id, scanner);

    resources
}

fn active_typed_resource<'a>(
    inner: &'a StoreInner,
    id: &Uuid,
    resource_type: &'static str,
) -> Result<&'a Resource, StoreError> {
    inner
        .resources
        .get(id)
        .filter(|resource| !resource.trashed && resource.resource_type == resource_type)
        .ok_or_else(|| StoreError::NotFound(resource_type.to_string()))
}

fn validate_task_reference(
    inner: &StoreInner,
    id: &Uuid,
    resource_type: &'static str,
) -> Result<(), StoreError> {
    active_typed_resource(inner, id, resource_type).map(|_| ())
}

fn stored_task_reference(
    task: &Resource,
    key: &'static str,
    resource_type: &'static str,
) -> Result<Uuid, StoreError> {
    task.attr(key)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(StoreError::Inconsistent(resource_type))
}

fn validate_stored_task_references(inner: &StoreInner, task: &Resource) -> Result<(), StoreError> {
    if let Some(schedule_id) = task.attr("schedule_id") {
        let schedule_id =
            Uuid::parse_str(schedule_id).map_err(|_| StoreError::Inconsistent("schedule"))?;
        validate_task_reference(inner, &schedule_id, "schedule")?;
    }
    if task.attr("import_task") == Some("1") {
        return Ok(());
    }

    let specialized: Vec<_> = [
        ("agent_group_id", "agent_group"),
        ("oci_image_target_id", "oci_image_target"),
        ("web_application_target_id", "web_application_target"),
    ]
    .into_iter()
    .filter(|(key, _)| task.attr(key).is_some())
    .collect();
    if specialized.len() > 1 {
        return Err(StoreError::Inconsistent("task target"));
    }
    let mut required = if let Some(reference) = specialized.first() {
        vec![*reference, ("scanner_id", "scanner")]
    } else {
        vec![
            ("target_id", "target"),
            ("config_id", "config"),
            ("scanner_id", "scanner"),
        ]
    };
    if !specialized.is_empty() && task.attr("config_id").is_some() {
        required.push(("config_id", "config"));
    }
    for (key, resource_type) in required {
        let id = stored_task_reference(task, key, resource_type)?;
        validate_task_reference(inner, &id, resource_type)?;
    }
    Ok(())
}

fn task_is_active(task: &Resource) -> bool {
    matches!(
        task.attr("status"),
        Some(
            "Requested"
                | "Queued"
                | "Running"
                | "Stop Requested"
                | "Delete Requested"
                | "Ultimate Delete Requested"
                | "Processing"
        )
    )
}

fn task_has_current_report(task: &Resource) -> bool {
    matches!(
        task.attr("status"),
        Some(
            "Requested"
                | "Queued"
                | "Running"
                | "Stop Requested"
                | "Delete Requested"
                | "Ultimate Delete Requested"
                | "Stopped"
                | "Interrupted"
                | "Processing"
        )
    )
}

fn report_is_current(report: &Resource) -> bool {
    matches!(
        report.attr("status"),
        Some(
            "Requested"
                | "Queued"
                | "Running"
                | "Stop Requested"
                | "Delete Requested"
                | "Ultimate Delete Requested"
                | "Stopped"
                | "Interrupted"
                | "Processing"
        )
    )
}

fn insert_resource(inner: &mut StoreInner, resource: Resource) -> Uuid {
    let id = resource.id;
    inner.next_insertion_order = inner.next_insertion_order.saturating_add(1);
    inner.insertion_order.insert(id, inner.next_insertion_order);
    inner.resources.insert(id, resource);
    id
}

fn remove_resource(inner: &mut StoreInner, id: &Uuid) -> Option<Resource> {
    inner.insertion_order.remove(id);
    inner.resources.remove(id)
}

fn insertion_order(inner: &StoreInner, report: &Resource) -> u64 {
    inner.insertion_order.get(&report.id).copied().unwrap_or(0)
}

fn report_creation_instant(report: &Resource) -> i64 {
    DateTime::parse_from_rfc3339(&report.creation_time)
        .map(|timestamp| timestamp.timestamp())
        .unwrap_or(i64::MIN)
}

fn latest_current_report<'a>(
    inner: &StoreInner,
    reports: impl Iterator<Item = &'a Resource>,
) -> Option<&'a Resource> {
    reports.max_by_key(|report| insertion_order(inner, report))
}

fn latest_completed_report<'a>(
    inner: &StoreInner,
    reports: impl Iterator<Item = &'a Resource>,
) -> Option<&'a Resource> {
    reports.max_by_key(|report| {
        (
            report_creation_instant(report),
            insertion_order(inner, report),
        )
    })
}

fn resolve_task_reports(inner: &StoreInner, task: &Resource) -> (Option<Uuid>, Option<Uuid>) {
    let task_id = task.id.to_string();
    let linked = || {
        inner.resources.values().filter(|report| {
            report.trashed == task.trashed
                && report.resource_type == "report"
                && report.attr("task_id") == Some(task_id.as_str())
        })
    };

    let current = if task_has_current_report(task) {
        task.attr("report_id")
            .and_then(|id| Uuid::parse_str(id).ok())
            .and_then(|id| inner.resources.get(&id))
            .filter(|report| {
                report.trashed == task.trashed
                    && report.resource_type == "report"
                    && report.attr("task_id") == Some(task_id.as_str())
                    && report_is_current(report)
            })
            .or_else(|| {
                latest_current_report(inner, linked().filter(|report| report_is_current(report)))
            })
            .map(|report| report.id)
    } else {
        None
    };
    let last = latest_completed_report(
        inner,
        linked().filter(|report| report.attr("status") == Some("Done")),
    )
    .map(|report| report.id);
    (current, last)
}

fn resolve_current_report_id(inner: &StoreInner, task: &Resource) -> Result<Uuid, StoreError> {
    resolve_task_reports(inner, task)
        .0
        .ok_or(StoreError::Inconsistent("task report"))
}

impl ResourceStore {
    /// Create a new empty store with default credentials.
    pub fn new() -> Self {
        Self::with_credentials("admin", "admin")
    }

    /// Create a store with specific credentials.
    pub fn with_credentials(username: &str, password: &str) -> Self {
        let resources = default_resources();
        let insertion_order = resources
            .keys()
            .copied()
            .enumerate()
            .map(|(index, id)| (id, index as u64 + 1))
            .collect();
        let next_insertion_order = resources.len() as u64;
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                resources,
                insertion_order,
                next_insertion_order,
                asset_input_profile: AssetInputProfile::GvmdStrict,
                authenticated_sessions: std::collections::HashSet::new(),
                username: username.to_string(),
                password: password.to_string(),
            })),
        }
    }

    /// Authenticate a session. Returns true if credentials are valid.
    pub fn authenticate(&self, session_id: u64, username: &str, password: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if inner.username == username && inner.password == password {
            inner.authenticated_sessions.insert(session_id);
            true
        } else {
            false
        }
    }

    /// Check if a session is authenticated.
    pub fn is_authenticated(&self, session_id: u64) -> bool {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.authenticated_sessions.contains(&session_id)
    }

    /// Set the asset request parsing profile before the server starts.
    pub(crate) fn set_asset_input_profile(&self, profile: AssetInputProfile) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.asset_input_profile = profile;
    }

    /// Return the configured asset request parsing profile.
    pub(crate) fn asset_input_profile(&self) -> AssetInputProfile {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.asset_input_profile
    }

    /// Check whether the provided credentials match the configured SSH credentials.
    #[cfg(feature = "ssh")]
    pub(crate) fn credentials_match(&self, username: &str, password: &str) -> bool {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.username == username && inner.password == password
    }

    /// Create a resource. Returns the generated UUID.
    pub fn create(&self, mut resource: Resource) -> Uuid {
        resource.modification_time = now_iso();
        let mut inner = self.inner.write().expect("store lock poisoned");
        insert_resource(&mut inner, resource)
    }

    pub(crate) fn create_task(
        &self,
        mut task: Resource,
        references: TaskReferences,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(target) = references.target {
            validate_task_reference(&inner, &target, "target")?;
            task.set_attr("target_id", &target.to_string());
        }
        if let Some(target) = references.specialized_target {
            validate_task_reference(&inner, &target.id(), target.resource_type())?;
            task.set_attr(target.attr_name(), &target.id().to_string());
        }
        if let Some(config) = references.config {
            validate_task_reference(&inner, &config, "config")?;
            task.set_attr("config_id", &config.to_string());
        }
        if let Some(scanner) = references.scanner {
            validate_task_reference(&inner, &scanner, "scanner")?;
            task.set_attr("scanner_id", &scanner.to_string());
        }
        if let Some(schedule) = references.schedule {
            validate_task_reference(&inner, &schedule, "schedule")?;
            task.set_attr("schedule_id", &schedule.to_string());
        }
        task.set_attr(
            "schedule_periods",
            &references.schedule_periods.unwrap_or(0).to_string(),
        );
        if references.target.is_none() && references.specialized_target.is_none() {
            task.attrs.remove("target_id");
            task.set_attr("import_task", "1");
            task.set_attr("status", TaskStatus::Done.as_str());
        } else {
            task.set_attr("status", TaskStatus::New.as_str());
        }
        task.modification_time = now_iso();
        Ok(insert_resource(&mut inner, task))
    }

    pub(crate) fn create_linked_report(
        &self,
        mut report: Resource,
        task_id: Option<Uuid>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(task_id) = task_id {
            active_typed_resource(&inner, &task_id, "task")?;
            report.set_attr("task_id", &task_id.to_string());
        }
        report.modification_time = now_iso();
        Ok(insert_resource(&mut inner, report))
    }

    /// Get a resource by UUID.
    pub fn get(&self, id: &Uuid) -> Option<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.resources.get(id).filter(|r| !r.trashed).cloned()
    }

    pub(crate) fn get_typed(&self, id: &Uuid, resource_type: &str) -> Option<Resource> {
        self.get(id)
            .filter(|resource| resource.resource_type == resource_type)
    }

    pub(crate) fn render_resource_xml(&self, resource: &Resource) -> String {
        if resource.resource_type != "task" {
            return resource.to_xml();
        }
        let inner = self.inner.read().expect("store lock poisoned");
        let (current_report, last_report) = resolve_task_reports(&inner, resource);
        let current_report = current_report.and_then(|id| inner.resources.get(&id));
        let last_report = last_report.and_then(|id| inner.resources.get(&id));
        let last_report_results = last_report.map_or_else(Vec::new, |report| {
            let report_id = report.id.to_string();
            inner
                .resources
                .values()
                .filter(|result| {
                    result.resource_type == "result"
                        && result.trashed == report.trashed
                        && result.attr("report_id") == Some(report_id.as_str())
                })
                .collect()
        });
        resource.to_xml_with_task_reports(current_report, last_report, &last_report_results, false)
    }

    /// Return the configured user timezone, falling back as gvmd does.
    pub(crate) fn user_timezone(&self) -> String {
        self.list("setting")
            .into_iter()
            .find(|resource| resource.name == "timezone")
            .and_then(|resource| resource.attr("value").map(str::to_string))
            .filter(|timezone| !timezone.trim().is_empty())
            .unwrap_or_else(|| "UTC".to_string())
    }

    /// Get all resources of a given type (non-trashed).
    pub fn list(&self, resource_type: &str) -> Vec<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .cloned()
            .collect()
    }

    /// Get all trashed resources of a given type.
    pub fn list_trashed(&self, resource_type: &str) -> Vec<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && r.trashed)
            .cloned()
            .collect()
    }

    /// Modify a resource. Returns true if found and updated.
    pub fn modify<F>(&self, id: &Uuid, f: F) -> bool
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(resource) = inner.resources.get_mut(id) {
            if resource.trashed {
                return false;
            }
            f(resource);
            resource.modification_time = now_iso();
            true
        } else {
            false
        }
    }

    /// Modify the comment of a non-trashed host asset.
    pub(crate) fn modify_host_asset_comment(&self, id: &Uuid, comment: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let Some(resource) = inner.resources.get_mut(id) else {
            return false;
        };
        if resource.trashed
            || resource.resource_type != "asset"
            || resource.asset_type() != Some("host")
        {
            return false;
        }
        comment.clone_into(&mut resource.comment);
        resource.modification_time = now_iso();
        true
    }

    pub(crate) fn modify_typed<F>(&self, id: &Uuid, resource_type: &str, f: F) -> bool
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let Some(resource) = inner
            .resources
            .get_mut(id)
            .filter(|resource| !resource.trashed && resource.resource_type == resource_type)
        else {
            return false;
        };
        f(resource);
        resource.modification_time = now_iso();
        true
    }

    pub(crate) fn modify_target<F>(
        &self,
        id: &Uuid,
        changes_scan_settings: bool,
        f: F,
    ) -> Result<(), StoreError>
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        active_typed_resource(&inner, id, "target")?;

        if changes_scan_settings {
            let id_text = id.to_string();
            let referenced = inner.resources.values().any(|candidate| {
                candidate.resource_type == "task"
                    && !candidate.trashed
                    && candidate.attr("target_id") == Some(id_text.as_str())
            });
            if referenced {
                return Err(StoreError::InUse("target"));
            }
        }

        let target = inner
            .resources
            .get_mut(id)
            .expect("validated target should remain present while locked");
        f(target);
        target.modification_time = now_iso();
        Ok(())
    }

    pub(crate) fn modify_task<F>(
        &self,
        id: &Uuid,
        references: TaskReferenceUpdates,
        f: F,
    ) -> Result<(), StoreError>
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?;
        let status = task
            .attr("status")
            .ok_or(StoreError::Inconsistent("task status"))?
            .to_string();
        let import_task = task.attr("import_task") == Some("1");

        if import_task && references.schedule != TaskScheduleUpdate::Omitted {
            return Err(StoreError::InvalidArgument(
                "Import tasks cannot have a schedule",
            ));
        }

        if references.changes_scan_definition() && status != TaskStatus::New.as_str() {
            return Err(StoreError::InvalidState(
                "Task references can only be changed while the task is New",
            ));
        }
        if let Some(target) = references.target {
            validate_task_reference(&inner, &target, "target")?;
        }
        if let Some(target) = references.specialized_target {
            validate_task_reference(&inner, &target.id(), target.resource_type())?;
        }
        if let Some(config) = references.config {
            validate_task_reference(&inner, &config, "config")?;
        }
        if let Some(scanner) = references.scanner {
            validate_task_reference(&inner, &scanner, "scanner")?;
        }
        if let TaskScheduleUpdate::Set(schedule) = references.schedule {
            validate_task_reference(&inner, &schedule, "schedule")?;
        }

        let task = inner
            .resources
            .get_mut(id)
            .expect("validated task should remain present while locked");
        if let Some(target) = references.target {
            task.set_attr("target_id", &target.to_string());
            for key in [
                "agent_group_id",
                "oci_image_target_id",
                "web_application_target_id",
            ] {
                task.attrs.remove(key);
            }
        }
        if let Some(target) = references.specialized_target {
            task.attrs.remove("target_id");
            for key in [
                "agent_group_id",
                "oci_image_target_id",
                "web_application_target_id",
            ] {
                task.attrs.remove(key);
            }
            task.set_attr(target.attr_name(), &target.id().to_string());
        }
        if let Some(config) = references.config {
            task.set_attr("config_id", &config.to_string());
        }
        if let Some(scanner) = references.scanner {
            task.set_attr("scanner_id", &scanner.to_string());
        }
        match references.schedule {
            TaskScheduleUpdate::Omitted => {
                if let Some(schedule_periods) = references.schedule_periods {
                    task.set_attr("schedule_periods", &schedule_periods.to_string());
                }
            }
            TaskScheduleUpdate::Set(schedule) => {
                task.set_attr("schedule_id", &schedule.to_string());
                task.set_attr(
                    "schedule_periods",
                    &references.schedule_periods.unwrap_or(0).to_string(),
                );
            }
            TaskScheduleUpdate::Clear => {
                task.attrs.remove("schedule_id");
                task.set_attr(
                    "schedule_periods",
                    &references.schedule_periods.unwrap_or(0).to_string(),
                );
            }
        }
        f(task);
        task.modification_time = now_iso();
        Ok(())
    }

    /// Delete a resource (move to trash or permanently).
    pub fn delete(&self, id: &Uuid, ultimate: bool) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if ultimate {
            remove_resource(&mut inner, id).is_some()
        } else if let Some(resource) = inner.resources.get_mut(id) {
            resource.trashed = true;
            true
        } else {
            false
        }
    }

    /// Permanently delete an asset while checking its lifecycle atomically.
    pub(crate) fn delete_asset_permanently(&self, id: &Uuid) -> DeleteAssetResult {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let Some(resource) = inner.resources.get(id) else {
            return DeleteAssetResult::NotFound;
        };
        if resource.resource_type != "asset" || resource.trashed {
            return DeleteAssetResult::NotFound;
        }
        if resource.asset_type() == Some("os")
            && resource
                .attr("installs")
                .and_then(|value| value.parse::<u32>().ok())
                .is_some_and(|count| count > 0)
        {
            return DeleteAssetResult::InUse;
        }
        remove_resource(&mut inner, id);
        DeleteAssetResult::Deleted
    }

    pub(crate) fn delete_typed(
        &self,
        id: &Uuid,
        resource_type: &str,
        ultimate: bool,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let resource = inner
            .resources
            .get(id)
            .filter(|resource| resource.resource_type == resource_type)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(resource_type.to_string()))?;

        if resource.trashed && !ultimate {
            return Ok(());
        }

        let task_reference = match resource_type {
            "target" => Some(("target_id", "target")),
            "agent_group" => Some(("agent_group_id", "agent_group")),
            "oci_image_target" => Some(("oci_image_target_id", "oci_image_target")),
            "web_application_target" => {
                Some(("web_application_target_id", "web_application_target"))
            }
            "config" => Some(("config_id", "config")),
            "scanner" => Some(("scanner_id", "scanner")),
            "schedule" => Some(("schedule_id", "schedule")),
            _ => None,
        };
        if let Some((reference_key, referenced_type)) = task_reference {
            let id = id.to_string();
            let referenced = inner.resources.values().any(|candidate| {
                candidate.resource_type == "task"
                    && candidate.attr(reference_key) == Some(id.as_str())
                    && (!candidate.trashed || (resource_type == "schedule" && ultimate))
            });
            if referenced {
                return Err(StoreError::InUse(referenced_type));
            }
        }

        if resource_type == "task" && !resource.trashed && task_is_active(&resource) {
            if let Ok(report_id) = resolve_current_report_id(&inner, &resource) {
                if let Some(report) = inner.resources.get_mut(&report_id) {
                    report.set_attr("status", TaskStatus::Stopped.as_str());
                    report.modification_time = now_iso();
                }
            }
            if let Some(task) = inner.resources.get_mut(id) {
                task.set_attr("status", TaskStatus::Stopped.as_str());
                task.modification_time = now_iso();
            }
        }

        if resource_type == "report" {
            let report_id = id.to_string();
            let task_links: Vec<(Uuid, bool, Option<Uuid>)> = inner
                .resources
                .values()
                .filter(|candidate| candidate.resource_type == "task")
                .map(|task| {
                    let stored_reference = task.attr("report_id") == Some(report_id.as_str());
                    let resolved_current = (!task.trashed && task_is_active(task))
                        .then(|| resolve_task_reports(&inner, task).0)
                        .flatten();
                    (task.id, stored_reference, resolved_current)
                })
                .collect();
            if task_links
                .iter()
                .any(|(_, _, resolved_current)| *resolved_current == Some(*id))
            {
                return Err(StoreError::InUse("report"));
            }
            for (task_id, stored_reference, resolved_current) in task_links {
                if !stored_reference {
                    continue;
                }
                if let Some(task) = inner.resources.get_mut(&task_id) {
                    if let Some(current_id) = resolved_current {
                        task.set_attr("report_id", &current_id.to_string());
                    } else {
                        task.attrs.remove("report_id");
                        task.set_attr("status", TaskStatus::New.as_str());
                    }
                    task.modification_time = now_iso();
                }
            }
        }

        if resource_type == "task" {
            let task_id = id.to_string();
            let report_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "report"
                        && candidate.attr("task_id") == Some(task_id.as_str())
                })
                .map(|candidate| candidate.id)
                .collect();
            let report_id_strings: Vec<String> = report_ids.iter().map(Uuid::to_string).collect();
            let result_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "result"
                        && candidate.attr("report_id").is_some_and(|candidate_id| {
                            report_id_strings
                                .iter()
                                .any(|report_id| report_id == candidate_id)
                        })
                })
                .map(|candidate| candidate.id)
                .collect();

            if ultimate {
                for dependent_id in report_ids.into_iter().chain(result_ids) {
                    remove_resource(&mut inner, &dependent_id);
                }
            } else {
                for dependent_id in report_ids.into_iter().chain(result_ids) {
                    if let Some(dependent) = inner.resources.get_mut(&dependent_id) {
                        dependent.trashed = true;
                        dependent.modification_time = now_iso();
                    }
                }
            }
        }

        if ultimate {
            remove_resource(&mut inner, id);
        } else if let Some(resource) = inner.resources.get_mut(id) {
            resource.trashed = true;
            resource.modification_time = now_iso();
        }
        Ok(())
    }

    /// Restore a trashed resource.
    pub fn restore(&self, id: &Uuid) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(resource) = inner.resources.get_mut(id) {
            if resource.trashed {
                resource.trashed = false;
                return true;
            }
        }
        false
    }

    pub(crate) fn restore_checked(&self, id: &Uuid) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let resource = inner
            .resources
            .get(id)
            .filter(|resource| resource.trashed)
            .cloned()
            .ok_or_else(|| StoreError::NotFound("resource".to_string()))?;

        if resource.resource_type == "task" {
            validate_stored_task_references(&inner, &resource)?;
            let task_id = id.to_string();
            let report_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "report"
                        && candidate.attr("task_id") == Some(task_id.as_str())
                })
                .map(|candidate| candidate.id)
                .collect();
            let report_id_strings: Vec<String> = report_ids.iter().map(Uuid::to_string).collect();
            let result_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "result"
                        && candidate.attr("report_id").is_some_and(|report_id| {
                            report_id_strings
                                .iter()
                                .any(|candidate_id| candidate_id == report_id)
                        })
                })
                .map(|candidate| candidate.id)
                .collect();
            for dependent_id in report_ids.into_iter().chain(result_ids) {
                if let Some(dependent) = inner.resources.get_mut(&dependent_id) {
                    dependent.trashed = false;
                    dependent.modification_time = now_iso();
                }
            }
        }

        let resource = inner
            .resources
            .get_mut(id)
            .expect("validated resource should remain present while locked");
        resource.trashed = false;
        resource.modification_time = now_iso();
        Ok(())
    }

    /// Empty the trashcan (permanently remove all trashed resources).
    pub fn empty_trashcan(&self) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let trashed: Vec<Uuid> = inner
            .resources
            .values()
            .filter(|resource| resource.trashed)
            .map(|resource| resource.id)
            .collect();
        for id in trashed {
            remove_resource(&mut inner, &id);
        }
    }

    /// Clone a resource (create a copy with a new UUID).
    pub fn clone_resource(&self, id: &Uuid) -> Option<Uuid> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = inner.resources.get(id)?.clone();
        if original.trashed {
            return None;
        }

        let mut copy = original;
        copy.id = Uuid::new_v4();
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        let new_id = copy.id;
        insert_resource(&mut inner, copy);
        Some(new_id)
    }

    pub(crate) fn clone_typed(&self, id: &Uuid, resource_type: &str) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = inner
            .resources
            .get(id)
            .filter(|resource| !resource.trashed && resource.resource_type == resource_type)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(resource_type.to_string()))?;
        if resource_type == "task" {
            validate_stored_task_references(&inner, &original)?;
        }
        if let Some(task_id) = original
            .attr("task_id")
            .filter(|_| resource_type == "report")
        {
            let task_id =
                Uuid::parse_str(task_id).map_err(|_| StoreError::Inconsistent("report task"))?;
            active_typed_resource(&inner, &task_id, "task")?;
        }

        let mut copy = original;
        copy.id = Uuid::new_v4();
        if resource_type == "task" {
            let status = if copy.attr("import_task") == Some("1") {
                TaskStatus::Done
            } else {
                TaskStatus::New
            };
            copy.set_attr("status", status.as_str());
            copy.attrs.remove("report_id");
        }
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        let new_id = copy.id;
        insert_resource(&mut inner, copy);
        Ok(new_id)
    }

    pub(crate) fn start_task(&self, id: &Uuid) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?.clone();
        if task.attr("import_task") == Some("1") {
            return Err(StoreError::InvalidState("Import tasks cannot be started"));
        }
        validate_stored_task_references(&inner, &task)?;

        match task.attr("status") {
            Some("New" | "Stopped" | "Done" | "Interrupted") => {}
            Some("Running" | "Requested") => {
                return Err(StoreError::InvalidState("Task is already running"));
            }
            Some(_) => {
                return Err(StoreError::InvalidState(
                    "Task cannot be started in current state",
                ));
            }
            None => return Err(StoreError::Inconsistent("task status")),
        }

        let report_id = Uuid::new_v4();
        let mut report =
            Resource::with_id("report", &format!("Report for {}", task.name), report_id);
        report.set_attr("task_id", &id.to_string());
        report.set_attr("status", TaskStatus::Running.as_str());
        if let Some(usage_type) = task.attr("usage_type") {
            report.set_attr("usage_type", usage_type);
        }
        insert_resource(&mut inner, report);

        let task = inner
            .resources
            .get_mut(id)
            .expect("validated task should remain present while locked");
        task.set_attr("status", TaskStatus::Running.as_str());
        task.set_attr("report_id", &report_id.to_string());
        task.modification_time = now_iso();
        Ok(report_id)
    }

    pub(crate) fn stop_task(&self, id: &Uuid) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?.clone();
        match task.attr("status") {
            Some("Running" | "Requested") => {}
            Some("Stopped") => return Err(StoreError::InvalidState("Task is already stopped")),
            Some(_) => {
                return Err(StoreError::InvalidState(
                    "Task cannot be stopped in current state",
                ));
            }
            None => return Err(StoreError::Inconsistent("task status")),
        }

        let report_id = resolve_current_report_id(&inner, &task)?;

        let report = inner
            .resources
            .get_mut(&report_id)
            .expect("validated report should remain present while locked");
        report.set_attr("status", TaskStatus::Stopped.as_str());
        report.modification_time = now_iso();
        let task = inner
            .resources
            .get_mut(id)
            .expect("validated task should remain present while locked");
        task.set_attr("status", TaskStatus::Stopped.as_str());
        task.set_attr("report_id", &report_id.to_string());
        task.modification_time = now_iso();
        Ok(())
    }

    pub(crate) fn resume_task(&self, id: &Uuid) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?.clone();
        validate_stored_task_references(&inner, &task)?;
        match task.attr("status") {
            Some("Stopped" | "Interrupted") => {}
            Some("Running" | "Requested") => {
                return Err(StoreError::InvalidState("Task is already running"));
            }
            Some(_) => {
                return Err(StoreError::InvalidState(
                    "Task can only be resumed from Stopped or Interrupted state",
                ));
            }
            None => return Err(StoreError::Inconsistent("task status")),
        }

        let report_id = resolve_current_report_id(&inner, &task)?;

        let report = inner
            .resources
            .get_mut(&report_id)
            .expect("validated report should remain present while locked");
        report.set_attr("status", TaskStatus::Running.as_str());
        report.modification_time = now_iso();
        let task = inner
            .resources
            .get_mut(id)
            .expect("validated task should remain present while locked");
        task.set_attr("status", TaskStatus::Running.as_str());
        task.set_attr("report_id", &report_id.to_string());
        task.modification_time = now_iso();
        Ok(report_id)
    }

    /// List resources of a type, filtered by a simple `name=value` filter string.
    pub fn list_filtered(&self, resource_type: &str, filter: &str) -> Vec<Resource> {
        // Parse simple "name=value" filters (GMP filter syntax subset)
        let inner = self.inner.read().expect("store lock poisoned");
        let mut results: Vec<Resource> = inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .cloned()
            .collect();

        // Apply filter predicates
        for part in filter.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "name" => {
                        results.retain(|r| r.name == value);
                    }
                    "type" => {
                        results.retain(|r| r.resource_type == value);
                    }
                    _ => {
                        // Check attrs
                        let key = key.to_string();
                        let value = value.to_string();
                        results.retain(|r| r.attr(&key) == Some(value.as_str()));
                    }
                }
            }
        }

        results
    }

    /// Count resources of a type (non-trashed).
    pub fn count(&self, resource_type: &str) -> usize {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .count()
    }

    /// Seed a resource for testing.
    pub fn seed(&self, resource: Resource) {
        let mut resource = resource;
        resource.modification_time = now_iso();
        let mut inner = self.inner.write().expect("store lock poisoned");
        insert_resource(&mut inner, resource);
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn create_valid_task(store: &ResourceStore, name: &str) -> Uuid {
        let target_id = store.create(Resource::new("target", &format!("{name} Target")));
        store
            .create_task(
                Resource::new("task", name),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(DEFAULT_CONFIG_ID),
                    scanner: Some(DEFAULT_SCANNER_ID),
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("valid task graph")
    }

    #[test]
    fn test_create_and_get() {
        let store = ResourceStore::new();
        let resource = Resource::new("task", "My Task");
        let id = store.create(resource);
        let fetched = store.get(&id).expect("should exist");
        assert_eq!(fetched.name, "My Task");
        assert_eq!(fetched.resource_type, "task");
    }

    #[test]
    fn test_list() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Task 1"));
        store.create(Resource::new("task", "Task 2"));
        store.create(Resource::new("target", "Target 1"));

        assert_eq!(store.list("task").len(), 2);
        assert_eq!(store.list("target").len(), 1);
        assert_eq!(store.list("config").len(), 1);
    }

    #[test]
    fn test_modify() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Old Name"));
        let modified = store.modify(&id, |r| {
            r.name = "New Name".to_string();
        });
        assert!(modified);
        assert_eq!(store.get(&id).unwrap().name, "New Name");
    }

    #[test]
    fn asset_helpers_cover_unknown_rendering_and_missing_modification() {
        let store = ResourceStore::new();
        let missing = Uuid::new_v4();
        assert!(!store.modify_host_asset_comment(&missing, "unused"));
        assert!(matches!(
            store.delete_asset_permanently(&missing),
            DeleteAssetResult::NotFound
        ));

        let mut unknown = Resource::new("asset", "mystery");
        unknown.set_attr("type", "firmware");
        assert!(unknown
            .to_asset_xml()
            .contains("<type>firmware</type></asset>"));
    }

    #[test]
    fn atomic_asset_delete_has_exactly_one_winner() {
        let store = ResourceStore::new();
        let mut host = Resource::new("asset", "192.0.2.10");
        host.set_attr("type", "host");
        let id = store.create(host);
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.delete_asset_permanently(&id)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("delete thread panicked"))
            .collect();

        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, DeleteAssetResult::Deleted))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, DeleteAssetResult::NotFound))
                .count(),
            1
        );
    }

    #[test]
    fn test_delete_to_trash() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Doomed"));
        assert!(store.delete(&id, false));
        assert!(store.get(&id).is_none()); // hidden from normal get
        assert_eq!(store.list_trashed("task").len(), 1);
    }

    #[test]
    fn test_delete_ultimate() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Gone"));
        assert!(store.delete(&id, true));
        assert!(store.get(&id).is_none());
        assert_eq!(store.list_trashed("task").len(), 0);
        let inner = store.inner.read().expect("store lock");
        assert!(!inner.insertion_order.contains_key(&id));
    }

    #[test]
    fn test_restore() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Restored"));
        store.delete(&id, false);
        assert!(store.get(&id).is_none());
        assert!(store.restore(&id));
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn test_empty_trashcan() {
        let store = ResourceStore::new();
        let id1 = store.create(Resource::new("task", "T1"));
        let id2 = store.create(Resource::new("task", "T2"));
        store.delete(&id1, false);
        store.delete(&id2, false);
        store.empty_trashcan();
        assert_eq!(store.list_trashed("task").len(), 0);
        let inner = store.inner.read().expect("store lock");
        assert!(!inner.insertion_order.contains_key(&id1));
        assert!(!inner.insertion_order.contains_key(&id2));
    }

    #[test]
    fn test_clone_resource() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Original"));
        let cloned_id = store.clone_resource(&id).expect("clone should work");
        assert_ne!(id, cloned_id);
        let original = store.get(&id).unwrap();
        let clone = store.get(&cloned_id).unwrap();
        assert_eq!(original.name, clone.name);
    }

    #[test]
    fn test_auth() {
        let store = ResourceStore::with_credentials("user", "pass");
        assert!(!store.is_authenticated(1));
        assert!(store.authenticate(1, "user", "pass"));
        assert!(store.is_authenticated(1));
        assert!(!store.authenticate(2, "user", "wrong"));
        assert!(!store.is_authenticated(2));
    }

    #[test]
    fn test_get_nonexistent() {
        let store = ResourceStore::new();
        assert!(store.get(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_delete_nonexistent() {
        let store = ResourceStore::new();
        assert!(!store.delete(&Uuid::new_v4(), false));
    }

    #[test]
    fn test_list_filtered_by_name() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Alpha"));
        store.create(Resource::new("task", "Beta"));
        store.create(Resource::new("task", "Alpha"));

        let filtered = store.list_filtered("task", "name=Alpha");
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.name == "Alpha"));
    }

    #[test]
    fn test_list_filtered_no_match() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Alpha"));
        let filtered = store.list_filtered("task", "name=Nonexistent");
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_list_filtered_by_attr() {
        let store = ResourceStore::new();
        let mut r = Resource::new("task", "T1");
        r.set_attr("status", "Running");
        store.create(r);
        let mut r2 = Resource::new("task", "T2");
        r2.set_attr("status", "New");
        store.create(r2);

        let filtered = store.list_filtered("task", "status=Running");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "T1");
    }

    #[test]
    fn test_count() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "T1"));
        store.create(Resource::new("task", "T2"));
        assert_eq!(store.count("task"), 2);
        assert_eq!(store.count("target"), 0);
    }

    #[test]
    fn test_modify_trashed_returns_false() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Trashed"));
        store.delete(&id, false);
        assert!(!store.modify(&id, |r| r.name = "New".to_string()));
    }

    #[test]
    fn test_clone_nonexistent() {
        let store = ResourceStore::new();
        assert!(store.clone_resource(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_count_excludes_trashed() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "T1"));
        let id2 = store.create(Resource::new("task", "T2"));
        store.delete(&id2, false);
        assert_eq!(store.count("task"), 1);
    }

    #[test]
    fn test_list_filtered_multi_term() {
        let store = ResourceStore::new();
        let mut r = Resource::new("task", "Alpha");
        r.set_attr("status", "Running");
        store.create(r);
        let mut r2 = Resource::new("task", "Alpha");
        r2.set_attr("status", "New");
        store.create(r2);
        let filtered = store.list_filtered("task", "name=Alpha status=Running");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_to_xml_sorts_attributes_deterministically() {
        let mut resource = Resource::new("task", "Ordered");
        resource.set_attr("zeta", "last");
        resource.set_attr("alpha", "first");

        let xml = resource.to_xml();

        assert!(xml.find("<alpha>").unwrap() < xml.find("<zeta>").unwrap());
    }

    #[test]
    fn task_report_references_are_selected_independently_from_linked_history() {
        let store = ResourceStore::new();
        let mut task = Resource::new("task", "Lifecycle task");
        let task_id = task.id;
        let target_id = store.create(Resource::new("target", "Lifecycle target"));
        task.set_attr("target_id", &target_id.to_string());
        task.set_attr("config_id", &DEFAULT_CONFIG_ID.to_string());
        task.set_attr("scanner_id", &DEFAULT_SCANNER_ID.to_string());
        task.set_attr("status", TaskStatus::Running.as_str());
        let active_id = Uuid::new_v4();
        task.set_attr("report_id", &active_id.to_string());
        store.seed(task);

        let mut older_done = Resource::new("report", "Older completed report");
        older_done.creation_time = "2026-01-01T00:00:00Z".to_string();
        older_done.set_attr("task_id", &task_id.to_string());
        older_done.set_attr("status", TaskStatus::Done.as_str());
        let older_done_id = older_done.id;
        store.seed(older_done);

        let mut last_done = Resource::new("report", "Latest completed report");
        last_done.creation_time = "2026-02-01T00:00:00Z".to_string();
        last_done.set_attr("task_id", &task_id.to_string());
        last_done.set_attr("status", TaskStatus::Done.as_str());
        let last_done_id = last_done.id;
        store.seed(last_done);

        let mut active = Resource::with_id("report", "Active report", active_id);
        active.creation_time = "2026-03-01T00:00:00Z".to_string();
        active.set_attr("task_id", &task_id.to_string());
        active.set_attr("status", TaskStatus::Running.as_str());
        store.seed(active);

        let mut mismatched = Resource::new("report", "Another task's report");
        let mismatched_id = mismatched.id;
        mismatched.set_attr("task_id", &Uuid::new_v4().to_string());
        mismatched.set_attr("status", TaskStatus::Running.as_str());
        store.seed(mismatched);

        let task = store.get(&task_id).expect("seeded task");
        let running = store.render_resource_xml(&task);
        assert!(running.contains(&format!("<current_report><report id=\"{active_id}\">")));
        assert!(running.contains(&format!("<last_report><report id=\"{last_done_id}\">")));
        assert!(running.contains("<timestamp>2026-03-01T00:00:00Z</timestamp>"));
        assert!(running.contains("<result_count><critical>0</critical>"));
        assert!(!running.contains(&older_done_id.to_string()));
        assert!(!running.contains("<report_id>"));

        assert!(store.modify(&task_id, |task| task
            .set_attr("report_id", &mismatched_id.to_string())));
        store
            .stop_task(&task_id)
            .expect("recover linked current report");
        let task = store.get(&task_id).expect("seeded task");
        assert_eq!(task.attr("report_id"), Some(active_id.to_string().as_str()));
        let stopped = store.render_resource_xml(&task);
        assert!(stopped.contains(&format!("<current_report><report id=\"{active_id}\">")));
        assert!(stopped.contains(&format!("<last_report><report id=\"{last_done_id}\">")));
        assert!(!stopped.contains(&mismatched_id.to_string()));

        assert_eq!(store.resume_task(&task_id), Ok(active_id));

        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Interrupted.as_str());
            task.set_attr("report_id", &active_id.to_string());
        }));
        assert!(store.modify(&active_id, |report| {
            report.set_attr("status", TaskStatus::Interrupted.as_str());
        }));
        let task = store.get(&task_id).expect("seeded task");
        let interrupted = store.render_resource_xml(&task);
        assert!(interrupted.contains(&format!("<current_report><report id=\"{active_id}\">")));
        assert!(interrupted.contains(&format!("<last_report><report id=\"{last_done_id}\">")));

        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Done.as_str());
        }));
        let task = store.get(&task_id).expect("seeded task");
        let done = store.render_resource_xml(&task);
        assert!(!done.contains("<current_report>"));
        assert!(done.contains(&format!("<last_report><report id=\"{last_done_id}\">")));
    }

    #[test]
    fn task_last_report_summaries_use_linked_scan_and_audit_results() {
        let scan_store = ResourceStore::new();
        let mut scan_task = Resource::new("task", "Scan summary");
        let scan_task_id = scan_task.id;
        scan_task.set_attr("status", TaskStatus::Done.as_str());
        scan_store.seed(scan_task);
        let mut scan_report = Resource::new("report", "Completed scan");
        let scan_report_id = scan_report.id;
        scan_report.set_attr("task_id", &scan_task_id.to_string());
        scan_report.set_attr("status", TaskStatus::Done.as_str());
        scan_report.set_attr("usage_type", "scan");
        scan_store.seed(scan_report);
        for severity in ["9.8", "7.5", "5.0", "2.0", "0.0"] {
            let mut result = Resource::new("result", "Scan result");
            result.set_attr("report_id", &scan_report_id.to_string());
            result.set_attr("severity", severity);
            scan_store.seed(result);
        }
        let mut false_positive = Resource::new("result", "False positive");
        false_positive.set_attr("report_id", &scan_report_id.to_string());
        false_positive.set_attr("severity", "10.0");
        false_positive.set_attr("false_positive", "1");
        scan_store.seed(false_positive);
        let mut trashed_result = Resource::new("result", "Trashed critical result");
        trashed_result.set_attr("report_id", &scan_report_id.to_string());
        trashed_result.set_attr("severity", "9.9");
        trashed_result.trashed = true;
        scan_store.seed(trashed_result);

        let scan_xml = scan_store
            .render_resource_xml(&scan_store.get(&scan_task_id).expect("seeded scan task"));
        for expected in [
            "<critical>1</critical>",
            "<high>1</high>",
            "<medium>1</medium>",
            "<low>1</low>",
            "<log>1</log>",
            "<false_positive>1</false_positive>",
            "<severity>10.0</severity>",
        ] {
            assert!(
                scan_xml.contains(expected),
                "missing {expected}: {scan_xml}"
            );
        }

        let audit_store = ResourceStore::new();
        let mut audit_task = Resource::new("task", "Audit summary");
        let audit_task_id = audit_task.id;
        audit_task.set_attr("status", TaskStatus::Done.as_str());
        audit_store.seed(audit_task);
        let mut audit_report = Resource::new("report", "Completed audit");
        let audit_report_id = audit_report.id;
        audit_report.set_attr("task_id", &audit_task_id.to_string());
        audit_report.set_attr("status", TaskStatus::Done.as_str());
        audit_report.set_attr("usage_type", "audit");
        audit_store.seed(audit_report);
        for compliance in ["yes", "yes", "no", "incomplete", "undefined"] {
            let mut result = Resource::new("result", "Audit result");
            result.set_attr("report_id", &audit_report_id.to_string());
            result.set_attr("compliance", compliance);
            audit_store.seed(result);
        }

        let audit_xml = audit_store
            .render_resource_xml(&audit_store.get(&audit_task_id).expect("seeded audit task"));
        assert!(audit_xml
            .contains("<compliance_count><yes>2</yes><no>1</no><incomplete>1</incomplete>"));
    }

    #[test]
    fn permanent_task_deletion_prunes_dependent_insertion_order() {
        let store = ResourceStore::new();
        let mut task = Resource::new("task", "Disposable history");
        let task_id = task.id;
        task.set_attr("status", TaskStatus::Done.as_str());
        store.seed(task);
        let mut report = Resource::new("report", "Disposable report");
        let report_id = report.id;
        report.set_attr("task_id", &task_id.to_string());
        report.set_attr("status", TaskStatus::Done.as_str());
        store.seed(report);
        let mut result = Resource::new("result", "Disposable result");
        let result_id = result.id;
        result.set_attr("report_id", &report_id.to_string());
        store.seed(result);

        store
            .delete_typed(&task_id, "task", true)
            .expect("delete task graph");

        let inner = store.inner.read().expect("store lock");
        for id in [task_id, report_id, result_id] {
            assert!(!inner.resources.contains_key(&id));
            assert!(!inner.insertion_order.contains_key(&id));
        }
    }

    #[test]
    fn task_report_ordering_uses_instants_and_insertion_order() {
        let store = ResourceStore::new();
        let mut task = Resource::new("task", "Ordered reports");
        let task_id = task.id;
        task.set_attr("status", TaskStatus::Running.as_str());
        store.seed(task);

        let mut later_text_earlier_instant = Resource::new("report", "Earlier instant");
        later_text_earlier_instant.creation_time = "2026-03-01T01:30:00+02:00".to_string();
        later_text_earlier_instant.set_attr("task_id", &task_id.to_string());
        later_text_earlier_instant.set_attr("status", TaskStatus::Done.as_str());
        store.seed(later_text_earlier_instant);

        let mut earlier_text_later_instant = Resource::new("report", "Later instant");
        earlier_text_later_instant.creation_time = "2026-03-01T00:00:00Z".to_string();
        earlier_text_later_instant.set_attr("task_id", &task_id.to_string());
        earlier_text_later_instant.set_attr("status", TaskStatus::Done.as_str());
        let expected_last = earlier_text_later_instant.id;
        store.seed(earlier_text_later_instant);

        let mut first_current = Resource::new("report", "First current");
        first_current.creation_time = "2026-03-01T01:00:00Z".to_string();
        first_current.set_attr("task_id", &task_id.to_string());
        first_current.set_attr("status", TaskStatus::Running.as_str());
        store.seed(first_current);

        let mut second_current = Resource::new("report", "Second current");
        second_current.creation_time = "2026-03-01T01:00:00Z".to_string();
        second_current.set_attr("task_id", &task_id.to_string());
        second_current.set_attr("status", TaskStatus::Processing.as_str());
        let expected_current = second_current.id;
        store.seed(second_current);

        let task = store.get(&task_id).expect("seeded task");
        let (current, last) = {
            let inner = store.inner.read().expect("store lock");
            resolve_task_reports(&inner, &task)
        };
        assert_eq!(current, Some(expected_current));
        assert_eq!(last, Some(expected_last));
    }

    #[test]
    fn every_gvmd_current_report_task_state_is_rendered() {
        for status in [
            TaskStatus::Requested,
            TaskStatus::Queued,
            TaskStatus::Running,
            TaskStatus::StopRequested,
            TaskStatus::DeleteRequested,
            TaskStatus::UltimateDeleteRequested,
            TaskStatus::Stopped,
            TaskStatus::Interrupted,
            TaskStatus::Processing,
        ] {
            let store = ResourceStore::new();
            let mut task = Resource::new("task", "State coverage");
            let task_id = task.id;
            task.set_attr("status", status.as_str());
            store.seed(task);
            let mut report = Resource::new("report", "Current report");
            let report_id = report.id;
            report.set_attr("task_id", &task_id.to_string());
            report.set_attr("status", status.as_str());
            store.seed(report);

            let task = store.get(&task_id).expect("seeded task");
            assert!(store
                .render_resource_xml(&task)
                .contains(&format!("<current_report><report id=\"{report_id}\">")));
        }
    }

    #[test]
    fn target_xml_always_observes_an_alive_test() {
        let default_target = Resource::new("target", "Default");
        assert!(default_target
            .to_xml()
            .contains("<alive_tests>Scan Config Default</alive_tests>"));

        let mut explicit_target = Resource::new("target", "Explicit");
        explicit_target.set_attr("alive_test", AliveTest::IcmpPing.as_target_name());
        assert!(explicit_target
            .to_xml()
            .contains("<alive_tests>ICMP Ping</alive_tests>"));

        assert!(!Resource::new("task", "Task")
            .to_xml()
            .contains("<alive_tests>"));
    }

    #[test]
    fn task_xml_uses_typed_report_reference_vocabulary() {
        let store = ResourceStore::new();
        let mut running = Resource::new("task", "Running Task");
        let task_id = running.id;
        running.set_attr("status", TaskStatus::Running.as_str());
        let mut report = Resource::new("report", "Running Report");
        let report_id = report.id;
        running.set_attr("report_id", &report_id.to_string());
        report.set_attr("task_id", &task_id.to_string());
        report.set_attr("status", TaskStatus::Running.as_str());
        store.seed(running);
        store.seed(report);

        let running_xml = store.render_resource_xml(&store.get(&task_id).expect("running task"));
        assert!(running_xml.contains(&format!("<current_report><report id=\"{report_id}\">")));
        assert!(!running_xml.contains("<report_id>"));

        assert!(store.modify(&task_id, |task| task.set_attr("status", "Done")));
        assert!(store.modify(&report_id, |report| report.set_attr("status", "Done")));
        let done_xml = store.render_resource_xml(&store.get(&task_id).expect("done task"));
        assert!(done_xml.contains(&format!("<last_report><report id=\"{report_id}\">")));
        assert!(!done_xml.contains("<report_id>"));
    }

    #[test]
    fn test_clone_resource_stress_with_concurrent_deletes() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Original"));
        let barrier = Arc::new(Barrier::new(3));

        let clone_store = store.clone();
        let clone_barrier = Arc::clone(&barrier);
        let clone_thread = thread::spawn(move || {
            clone_barrier.wait();
            for _ in 0..250 {
                let _ = clone_store.clone_resource(&id);
                thread::yield_now();
            }
        });

        let delete_store = store.clone();
        let delete_barrier = Arc::clone(&barrier);
        let delete_thread = thread::spawn(move || {
            delete_barrier.wait();
            for _ in 0..250 {
                let _ = delete_store.delete(&id, false);
                let _ = delete_store.restore(&id);
                thread::yield_now();
            }
        });

        barrier.wait();
        clone_thread.join().expect("clone thread");
        delete_thread.join().expect("delete thread");

        let tasks = store.list("task");
        assert!(tasks
            .iter()
            .all(|resource| resource.resource_type == "task"));
        assert!(tasks.iter().any(|resource| resource.id == id));
    }

    #[test]
    fn typed_task_modification_updates_and_validates_every_reference() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Mutable");
        let target_id = store.create(Resource::new("target", "Replacement Target"));
        let config_id = store.create(Resource::new("config", "Replacement Config"));
        let scanner_id = store.create(Resource::new("scanner", "Replacement Scanner"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(config_id),
                    scanner: Some(scanner_id),
                    schedule: TaskScheduleUpdate::Omitted,
                    schedule_periods: None,
                },
                |_| {},
            )
            .expect("New task references should be replaceable");

        let task = store.get(&task_id).expect("task");
        assert_eq!(task.attr("target_id"), Some(target_id.to_string().as_str()));
        assert_eq!(task.attr("config_id"), Some(config_id.to_string().as_str()));
        assert_eq!(
            task.attr("scanner_id"),
            Some(scanner_id.to_string().as_str())
        );
        assert!(!store.modify_typed(&target_id, "task", |_| {}));
    }

    #[test]
    fn task_schedule_periods_follow_gvmd_update_semantics_in_any_task_state() {
        let store = ResourceStore::new();
        let target_id = store.create(Resource::new("target", "Scheduled Target"));
        let first_schedule = store.create(Resource::new("schedule", "First Schedule"));
        let second_schedule = store.create(Resource::new("schedule", "Second Schedule"));
        let task_id = store
            .create_task(
                Resource::new("task", "Scheduled Task"),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(DEFAULT_CONFIG_ID),
                    scanner: Some(DEFAULT_SCANNER_ID),
                    schedule: Some(first_schedule),
                    schedule_periods: Some(5),
                },
            )
            .expect("create scheduled task");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Running.as_str());
        }));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule_periods: Some(4),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("period-only update should preserve the schedule");
        let task = store.get(&task_id).expect("task");
        assert_eq!(
            task.attr("schedule_id"),
            Some(first_schedule.to_string().as_str())
        );
        assert_eq!(task.attr("schedule_periods"), Some("4"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Set(second_schedule),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("schedule replacement should reset omitted periods");
        let task = store.get(&task_id).expect("task");
        assert_eq!(
            task.attr("schedule_id"),
            Some(second_schedule.to_string().as_str())
        );
        assert_eq!(task.attr("schedule_periods"), Some("0"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Clear,
                    schedule_periods: Some(2),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("schedule clearing should apply supplied periods");
        let task = store.get(&task_id).expect("task");
        assert_eq!(task.attr("schedule_id"), None);
        assert_eq!(task.attr("schedule_periods"), Some("2"));
    }

    #[test]
    fn import_task_schedule_updates_are_rejected_atomically() {
        let store = ResourceStore::new();
        let schedule_id = store.create(Resource::new("schedule", "Ignored Schedule"));
        let task_id = store
            .create_task(
                Resource::new("task", "Imported"),
                TaskReferences {
                    target: None,
                    specialized_target: None,
                    config: None,
                    scanner: None,
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("create import task");

        assert_eq!(
            store.modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Set(schedule_id),
                    schedule_periods: Some(4),
                    ..Default::default()
                },
                |_| {},
            ),
            Err(StoreError::InvalidArgument(
                "Import tasks cannot have a schedule"
            ))
        );
        let task = store.get(&task_id).expect("import task");
        assert_eq!(task.attr("schedule_id"), None);
        assert_eq!(task.attr("schedule_periods"), Some("0"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule_periods: Some(7),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("period-only import task update");

        assert_eq!(
            store.modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Clear,
                    schedule_periods: Some(3),
                    ..Default::default()
                },
                |_| {},
            ),
            Err(StoreError::InvalidArgument(
                "Import tasks cannot have a schedule"
            ))
        );
        let task = store.get(&task_id).expect("import task");
        assert_eq!(task.attr("schedule_id"), None);
        assert_eq!(task.attr("schedule_periods"), Some("7"));
    }

    #[test]
    fn task_delete_and_restore_cascade_to_reports_and_results() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Cascading");
        let report_id = store.start_task(&task_id).expect("start task");
        let mut result = Resource::new("result", "Linked Result");
        result.set_attr("report_id", &report_id.to_string());
        let result_id = store.create(result);
        store.stop_task(&task_id).expect("stop task");

        store
            .delete_typed(&task_id, "task", false)
            .expect("trash task");
        store
            .delete_typed(&task_id, "task", false)
            .expect("trashing an already trashed task is idempotent");
        assert!(store
            .list_trashed("report")
            .iter()
            .any(|r| r.id == report_id));
        assert!(store
            .list_trashed("result")
            .iter()
            .any(|r| r.id == result_id));

        store.restore_checked(&task_id).expect("restore task graph");
        assert!(store.get(&report_id).is_some());
        assert!(store.get(&result_id).is_some());

        store
            .delete_typed(&task_id, "task", true)
            .expect("delete task graph");
        assert!(store.get(&report_id).is_none());
        assert!(store.get(&result_id).is_none());
    }

    #[test]
    fn trashed_tasks_do_not_block_permanent_reference_deletion() {
        let store = ResourceStore::new();
        let target_id = store.create(Resource::new("target", "Disposable Target"));
        let config_id = store.create(Resource::new("config", "Disposable Config"));
        let scanner_id = store.create(Resource::new("scanner", "Disposable Scanner"));
        let task_id = store
            .create_task(
                Resource::new("task", "Trashed Task"),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(config_id),
                    scanner: Some(scanner_id),
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("create task");

        store
            .delete_typed(&task_id, "task", false)
            .expect("trash task");

        for (id, resource_type) in [
            (target_id, "target"),
            (config_id, "config"),
            (scanner_id, "scanner"),
        ] {
            store
                .delete_typed(&id, resource_type, true)
                .expect("trashed task must not block permanent deletion");
            assert!(store.get(&id).is_none());
        }
    }

    #[test]
    fn trashed_tasks_block_permanent_schedule_deletion() {
        let store = ResourceStore::new();
        let target_id = store.create(Resource::new("target", "Scheduled Target"));
        let schedule_id = store.create(Resource::new("schedule", "Retained Schedule"));
        let task_id = store
            .create_task(
                Resource::new("task", "Trashed Scheduled Task"),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(DEFAULT_CONFIG_ID),
                    scanner: Some(DEFAULT_SCANNER_ID),
                    schedule: Some(schedule_id),
                    schedule_periods: Some(2),
                },
            )
            .expect("create scheduled task");

        store
            .delete_typed(&task_id, "task", false)
            .expect("trash task");
        assert_eq!(
            store.delete_typed(&schedule_id, "schedule", true),
            Err(StoreError::InUse("schedule"))
        );

        store
            .delete_typed(&schedule_id, "schedule", false)
            .expect("trash schedule referenced only by a trashed task");
        assert_eq!(
            store.delete_typed(&schedule_id, "schedule", true),
            Err(StoreError::InUse("schedule"))
        );

        store
            .delete_typed(&task_id, "task", true)
            .expect("permanently delete dependent task");
        store
            .delete_typed(&schedule_id, "schedule", true)
            .expect("permanently delete unreferenced schedule");
    }

    #[test]
    fn deleting_an_active_task_tolerates_a_missing_report_reference() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Active Without Report");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Running.as_str());
            task.attrs.remove("report_id");
        }));

        store
            .delete_typed(&task_id, "task", true)
            .expect("synchronous mock deletion should still remove the task");
        assert!(store.get(&task_id).is_none());
    }

    #[test]
    fn deleting_an_active_task_does_not_mutate_an_unrelated_report_reference() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Corrupt Report Link");
        let other_task_id = create_valid_task(&store, "Report Owner");
        let other_report_id = store.start_task(&other_task_id).expect("start other task");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Running.as_str());
            task.set_attr("report_id", &other_report_id.to_string());
        }));

        store
            .delete_typed(&task_id, "task", true)
            .expect("delete corrupt task");

        let other_report = store
            .get(&other_report_id)
            .expect("unrelated report remains");
        assert_eq!(
            other_report.attr("task_id"),
            Some(other_task_id.to_string().as_str())
        );
        assert_eq!(
            other_report.attr("status"),
            Some(TaskStatus::Running.as_str())
        );
    }

    #[test]
    fn fallback_selected_active_report_is_protected_from_deletion() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Missing Current Pointer");
        let current_report_id = store.start_task(&task_id).expect("start task");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("report_id", &Uuid::new_v4().to_string());
        }));

        let task = store.get(&task_id).expect("active task");
        let resolved = {
            let inner = store.inner.read().expect("store lock");
            resolve_task_reports(&inner, &task).0
        };
        assert_eq!(resolved, Some(current_report_id));
        assert_eq!(
            store.delete_typed(&current_report_id, "report", true),
            Err(StoreError::InUse("report"))
        );
        assert!(store.get(&current_report_id).is_some());
    }

    #[test]
    fn deleting_stale_report_pointer_repairs_active_task_to_resolved_report() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Stale Current Pointer");
        let current_report_id = store.start_task(&task_id).expect("start task");
        let mut stale_report = Resource::new("report", "Stale completed report");
        stale_report.set_attr("status", TaskStatus::Done.as_str());
        let stale_report_id = store
            .create_linked_report(stale_report, Some(task_id))
            .expect("create stale report");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("report_id", &stale_report_id.to_string());
        }));

        store
            .delete_typed(&stale_report_id, "report", true)
            .expect("delete non-current stale report");

        let task = store.get(&task_id).expect("active task remains");
        assert_eq!(task.attr("status"), Some(TaskStatus::Running.as_str()));
        assert_eq!(
            task.attr("report_id"),
            Some(current_report_id.to_string().as_str())
        );
        assert!(store.get(&stale_report_id).is_none());
        assert!(store.get(&current_report_id).is_some());
    }

    #[test]
    fn cloning_validates_linked_reports_and_preserves_import_task_state() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Report Owner");
        let report_id = store
            .create_linked_report(Resource::new("report", "Linked"), Some(task_id))
            .expect("linked report");
        let report_copy = store
            .clone_typed(&report_id, "report")
            .expect("clone linked report");
        assert_eq!(
            store
                .get(&report_copy)
                .expect("report copy")
                .attr("task_id"),
            Some(task_id.to_string().as_str())
        );

        let mut malformed_report = Resource::new("report", "Malformed Link");
        malformed_report.set_attr("task_id", "not-a-uuid");
        let malformed_report_id = store.create(malformed_report);
        assert_eq!(
            store.clone_typed(&malformed_report_id, "report"),
            Err(StoreError::Inconsistent("report task"))
        );

        let mut missing_task_report = Resource::new("report", "Missing Task");
        missing_task_report.set_attr("task_id", &Uuid::new_v4().to_string());
        let missing_task_report_id = store.create(missing_task_report);
        assert_eq!(
            store.clone_typed(&missing_task_report_id, "report"),
            Err(StoreError::NotFound("task".to_string()))
        );

        let import_task_id = store
            .create_task(
                Resource::new("task", "Imported"),
                TaskReferences {
                    target: None,
                    specialized_target: None,
                    config: None,
                    scanner: None,
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("import task");
        let import_copy = store
            .clone_typed(&import_task_id, "task")
            .expect("clone import task");
        assert_eq!(
            store.get(&import_copy).expect("import copy").attr("status"),
            Some(TaskStatus::Done.as_str())
        );
        assert_eq!(
            store.start_task(&import_task_id),
            Err(StoreError::InvalidState("Import tasks cannot be started"))
        );
    }

    #[test]
    fn cloning_rejects_corrupt_specialized_task_graphs() {
        let store = ResourceStore::new();
        let agent_group_id = store.create(Resource::new("agent_group", "Agents"));
        let oci_target_id = store.create(Resource::new("oci_image_target", "OCI"));

        let mut multiple_targets = Resource::new("task", "Multiple specialized targets");
        multiple_targets.set_attr("agent_group_id", &agent_group_id.to_string());
        multiple_targets.set_attr("oci_image_target_id", &oci_target_id.to_string());
        multiple_targets.set_attr("scanner_id", &DEFAULT_SCANNER_ID.to_string());
        multiple_targets.set_attr("status", TaskStatus::New.as_str());
        let multiple_targets_id = store.create(multiple_targets);
        assert_eq!(
            store.clone_typed(&multiple_targets_id, "task"),
            Err(StoreError::Inconsistent("task target"))
        );

        let mut missing_config = Resource::new("task", "Missing optional config");
        missing_config.set_attr("agent_group_id", &agent_group_id.to_string());
        missing_config.set_attr("scanner_id", &DEFAULT_SCANNER_ID.to_string());
        missing_config.set_attr("config_id", &Uuid::new_v4().to_string());
        missing_config.set_attr("status", TaskStatus::New.as_str());
        let missing_config_id = store.create(missing_config);
        assert_eq!(
            store.clone_typed(&missing_config_id, "task"),
            Err(StoreError::NotFound("config".to_string()))
        );
    }

    #[test]
    fn lifecycle_rejects_corrupt_or_inapplicable_states_atomically() {
        let store = ResourceStore::new();

        let invalid_state_id = create_valid_task(&store, "Invalid State");
        assert!(store.modify(&invalid_state_id, |task| {
            task.set_attr("status", "Paused");
        }));
        assert_eq!(
            store.start_task(&invalid_state_id),
            Err(StoreError::InvalidState(
                "Task cannot be started in current state"
            ))
        );
        assert_eq!(
            store.stop_task(&invalid_state_id),
            Err(StoreError::InvalidState(
                "Task cannot be stopped in current state"
            ))
        );
        assert_eq!(
            store.resume_task(&invalid_state_id),
            Err(StoreError::InvalidState(
                "Task can only be resumed from Stopped or Interrupted state"
            ))
        );

        let missing_status_id = create_valid_task(&store, "Missing Status");
        assert!(store.modify(&missing_status_id, |task| {
            task.attrs.remove("status");
        }));
        for result in [
            store.start_task(&missing_status_id).map(|_| ()),
            store.stop_task(&missing_status_id),
            store.resume_task(&missing_status_id).map(|_| ()),
        ] {
            assert_eq!(result, Err(StoreError::Inconsistent("task status")));
        }

        let mismatched_report_id = create_valid_task(&store, "Mismatched Report");
        let report_id = store.start_task(&mismatched_report_id).expect("start task");
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &Uuid::new_v4().to_string());
        }));
        assert_eq!(
            store.stop_task(&mismatched_report_id),
            Err(StoreError::Inconsistent("task report"))
        );
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &mismatched_report_id.to_string());
        }));
        store.stop_task(&mismatched_report_id).expect("stop task");
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &Uuid::new_v4().to_string());
        }));
        assert_eq!(
            store.resume_task(&mismatched_report_id),
            Err(StoreError::Inconsistent("task report"))
        );
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &mismatched_report_id.to_string());
        }));
        assert!(store.modify(&mismatched_report_id, |task| {
            task.set_attr("status", TaskStatus::Interrupted.as_str());
        }));
        assert_eq!(
            store
                .resume_task(&mismatched_report_id)
                .expect("resume interrupted task"),
            report_id
        );
    }
}
