// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Authoritative command capabilities shared across the rust-gvm workspace.

use crate::GmpVersion;

/// Declared mock-server behavior for a known GMP command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockSupport {
    /// Command has meaningful stateful behavior, either custom or generic CRUD.
    Stateful,
    /// Command returns deterministic built-in fixture-style data.
    Fixture,
    /// Command intentionally returns the generic echo success response.
    EchoOnly,
}

/// Public gvmd evidence supporting a command in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GvmdEvidence {
    /// Command is documented in the repository's pinned public GMP.xml.in snapshot.
    PinnedSchema,
    /// Command is implemented in pinned public gvmd source but omitted from that schema.
    PublicSourceOnly,
    /// Command is retained for public legacy-client compatibility but absent from the
    /// pinned current gvmd schema and implementation.
    LegacyCompatibility,
}

/// Capability metadata for one known GMP wire command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandCapability {
    /// GMP wire command name.
    pub name: &'static str,
    /// Mock-server behavior level.
    pub support: MockSupport,
    /// Minimum negotiated GMP version, or the baseline 22.4 when omitted.
    pub min_version: Option<GmpVersion>,
    /// Public evidence qualification for current gvmd support.
    pub gvmd_evidence: GvmdEvidence,
    /// Whether callers must confirm availability from the server's `help`
    /// command listing instead of inferring it from the negotiated GMP version.
    pub requires_help_discovery: bool,
}

impl CommandCapability {
    /// Return whether this command is available in the negotiated GMP version.
    #[must_use]
    pub fn available_in(self, version: GmpVersion) -> bool {
        !self.requires_help_discovery && self.min_version.is_none_or(|minimum| version >= minimum)
    }

    /// Return whether the negotiated version permits attempting this command.
    ///
    /// A `true` result is not proof of availability when
    /// [`Self::requires_help_discovery`] is set.
    #[must_use]
    pub fn permitted_in(self, version: GmpVersion) -> bool {
        self.min_version.is_none_or(|minimum| version >= minimum)
    }
}

macro_rules! requires_help_discovery {
    () => {
        false
    };
    (Help) => {
        true
    };
}

macro_rules! command_capabilities {
    ($(($name:literal, $support:ident, $min_version:expr, $evidence:ident $(, $discovery:ident)?),)+) => {
        /// Authoritative, name-sorted command capability registry.
        pub static COMMAND_CAPABILITIES: &[CommandCapability] = &[
            $(CommandCapability {
                name: $name,
                support: MockSupport::$support,
                min_version: $min_version,
                gvmd_evidence: GvmdEvidence::$evidence,
                requires_help_discovery: requires_help_discovery!($($discovery)?),
            },)+
        ];

        /// Name-only projection of `COMMAND_CAPABILITIES`.
        pub static COMMAND_NAMES: &[&str] = &[$($name,)+];
    };
}

command_capabilities! {
    ("authenticate", Stateful, None, PinnedSchema),
    ("create_agent_group", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("create_alert", Stateful, None, PinnedSchema),
    ("create_asset", Stateful, None, PinnedSchema),
    ("create_config", Stateful, None, PinnedSchema),
    ("create_credential", Stateful, None, PinnedSchema),
    ("create_filter", Stateful, None, PinnedSchema),
    ("create_group", Stateful, None, PinnedSchema),
    ("create_note", Stateful, None, PinnedSchema),
    ("create_oci_image_target", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("create_override", Stateful, None, PinnedSchema),
    ("create_permission", Stateful, None, PinnedSchema),
    ("create_port_list", Stateful, None, PinnedSchema),
    ("create_port_range", Stateful, None, PinnedSchema),
    ("create_report", Stateful, None, PinnedSchema),
    ("create_report_config", Stateful, Some(GmpVersion(22, 6)), PinnedSchema),
    ("create_report_format", Stateful, None, PinnedSchema),
    ("create_role", Stateful, None, PinnedSchema),
    ("create_scanner", Stateful, None, PinnedSchema),
    ("create_schedule", Stateful, None, PinnedSchema),
    ("create_tag", Stateful, None, PinnedSchema),
    ("create_target", Stateful, None, PinnedSchema),
    ("create_task", Stateful, None, PinnedSchema),
    ("create_ticket", Stateful, None, PinnedSchema),
    ("create_tls_certificate", Stateful, None, PinnedSchema),
    ("create_user", Stateful, None, PinnedSchema),
    ("create_web_application_target", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("delete_agent", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("delete_agent_group", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("delete_alert", Stateful, None, PinnedSchema),
    ("delete_asset", Stateful, None, PinnedSchema),
    ("delete_config", Stateful, None, PinnedSchema),
    ("delete_credential", Stateful, None, PinnedSchema),
    ("delete_filter", Stateful, None, PinnedSchema),
    ("delete_group", Stateful, None, PinnedSchema),
    ("delete_note", Stateful, None, PinnedSchema),
    ("delete_oci_image_target", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("delete_override", Stateful, None, PinnedSchema),
    ("delete_permission", Stateful, None, PinnedSchema),
    ("delete_port_list", Stateful, None, PinnedSchema),
    ("delete_port_range", Stateful, None, PinnedSchema),
    ("delete_report", Stateful, None, PinnedSchema),
    ("delete_report_config", Stateful, Some(GmpVersion(22, 6)), PinnedSchema),
    ("delete_report_format", Stateful, None, PinnedSchema),
    ("delete_role", Stateful, None, PinnedSchema),
    ("delete_scanner", Stateful, None, PinnedSchema),
    ("delete_schedule", Stateful, None, PinnedSchema),
    ("delete_tag", Stateful, None, PinnedSchema),
    ("delete_target", Stateful, None, PinnedSchema),
    ("delete_task", Stateful, None, PinnedSchema),
    ("delete_ticket", Stateful, None, PinnedSchema),
    ("delete_tls_certificate", Stateful, None, LegacyCompatibility),
    ("delete_user", Stateful, None, PinnedSchema),
    ("delete_web_application_target", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("describe_auth", EchoOnly, None, PinnedSchema),
    ("empty_trashcan", Stateful, None, PinnedSchema),
    ("export_scan_report", Stateful, Some(GmpVersion(22, 7)), PinnedSchema, Help),
    ("get_agent_groups", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_agent_installer_instruction", Fixture, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_agent_support_bundle", Fixture, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_agents", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_aggregates", Fixture, None, PinnedSchema),
    ("get_alerts", Stateful, None, PinnedSchema),
    ("get_assets", Stateful, None, PinnedSchema),
    ("get_audit_report", Stateful, Some(GmpVersion(22, 7)), PinnedSchema),
    ("get_audit_report_hosts", Stateful, Some(GmpVersion(22, 7)), PinnedSchema),
    ("get_configs", Stateful, None, PinnedSchema),
    ("get_credential_stores", Fixture, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_credentials", Stateful, None, PinnedSchema),
    ("get_features", Stateful, Some(GmpVersion(22, 6)), PinnedSchema),
    ("get_feeds", Fixture, None, PinnedSchema),
    ("get_filters", Stateful, None, PinnedSchema),
    ("get_groups", Stateful, None, PinnedSchema),
    ("get_info", Fixture, None, PinnedSchema),
    ("get_integration_configs", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_license", Stateful, None, PinnedSchema),
    ("get_notes", Stateful, None, PinnedSchema),
    ("get_nvt_families", Stateful, None, PinnedSchema),
    ("get_nvts", Stateful, None, PinnedSchema),
    ("get_oci_image_targets", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_overrides", Stateful, None, PinnedSchema),
    ("get_permissions", Stateful, None, PinnedSchema),
    ("get_port_lists", Stateful, None, PinnedSchema),
    ("get_preferences", Stateful, None, PinnedSchema),
    ("get_report_applications", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_closed_cves", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_configs", Stateful, Some(GmpVersion(22, 6)), PinnedSchema),
    ("get_report_cves", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_errors", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_formats", Stateful, None, PinnedSchema),
    ("get_report_hosts", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_operating_systems", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_ports", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_tls_certificates", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_report_vulns", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_reports", Stateful, None, PinnedSchema),
    ("get_resource_names", Stateful, None, PinnedSchema),
    ("get_results", Stateful, None, PinnedSchema),
    ("get_roles", Stateful, None, PinnedSchema),
    ("get_scan_report", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_scanners", Stateful, None, PinnedSchema),
    ("get_schedules", Stateful, None, PinnedSchema),
    ("get_settings", Stateful, None, PinnedSchema),
    ("get_system_reports", Fixture, None, PinnedSchema),
    ("get_tags", Stateful, None, PinnedSchema),
    ("get_targets", Stateful, None, PinnedSchema),
    ("get_tasks", Stateful, None, PinnedSchema),
    ("get_tickets", Stateful, None, PinnedSchema),
    ("get_timezones", Fixture, Some(GmpVersion(22, 8)), PinnedSchema),
    ("get_tls_certificates", Stateful, None, PinnedSchema),
    ("get_users", Stateful, None, PinnedSchema),
    ("get_version", Stateful, None, PinnedSchema),
    ("get_vulns", Fixture, None, PinnedSchema),
    ("get_web_application_targets", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("help", Fixture, None, PinnedSchema),
    ("modify_agent", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("modify_agent_control_scan_config", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("modify_agent_group", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("modify_alert", Stateful, None, PinnedSchema),
    ("modify_asset", Stateful, None, PinnedSchema),
    ("modify_auth", Stateful, None, PinnedSchema),
    ("modify_config", Stateful, None, PinnedSchema),
    ("modify_credential", Stateful, None, PinnedSchema),
    ("modify_credential_store", Stateful, Some(GmpVersion(22, 8)), PublicSourceOnly),
    ("modify_filter", Stateful, None, PinnedSchema),
    ("modify_group", Stateful, None, PinnedSchema),
    ("modify_integration_config", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("modify_license", Stateful, None, PinnedSchema),
    ("modify_note", Stateful, None, PinnedSchema),
    ("modify_oci_image_target", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("modify_override", Stateful, None, PinnedSchema),
    ("modify_permission", Stateful, None, PinnedSchema),
    ("modify_port_list", Stateful, None, PinnedSchema),
    ("modify_report_config", Stateful, Some(GmpVersion(22, 6)), PinnedSchema),
    ("modify_report_format", Stateful, None, PinnedSchema),
    ("modify_role", Stateful, None, PinnedSchema),
    ("modify_scanner", Stateful, None, PinnedSchema),
    ("modify_schedule", Stateful, None, PinnedSchema),
    ("modify_setting", Stateful, None, PinnedSchema),
    ("modify_tag", Stateful, None, PinnedSchema),
    ("modify_target", Stateful, None, PinnedSchema),
    ("modify_task", Stateful, None, PinnedSchema),
    ("modify_ticket", Stateful, None, PinnedSchema),
    ("modify_tls_certificate", Stateful, None, PinnedSchema),
    ("modify_user", Stateful, None, PinnedSchema),
    ("modify_web_application_target", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("move_task", EchoOnly, None, PinnedSchema),
    ("restore", Stateful, None, PinnedSchema),
    ("resume_task", Stateful, None, PinnedSchema),
    ("run_wizard", Stateful, None, PinnedSchema),
    ("start_task", Stateful, None, PinnedSchema),
    ("stop_task", Stateful, None, PinnedSchema),
    ("sync_agents", Stateful, Some(GmpVersion(22, 8)), PinnedSchema),
    ("sync_config", EchoOnly, None, PinnedSchema),
    ("test_alert", EchoOnly, None, PinnedSchema),
    ("verify_credential_store", Stateful, Some(GmpVersion(22, 8)), PublicSourceOnly),
    ("verify_report_format", EchoOnly, None, PinnedSchema),
    ("verify_scanner", EchoOnly, None, PinnedSchema),
}

/// Look up a known command by its wire name.
#[must_use]
pub fn command_capability(name: &str) -> Option<&'static CommandCapability> {
    COMMAND_CAPABILITIES
        .binary_search_by_key(&name, |capability| capability.name)
        .ok()
        .map(|index| &COMMAND_CAPABILITIES[index])
}

/// Return whether a command name is present in the authoritative registry.
#[must_use]
pub fn is_known_command(name: &str) -> bool {
    command_capability(name).is_some()
}

/// Return the command's minimum GMP version when it is newer than the 22.4 baseline.
#[must_use]
pub fn minimum_version_for_command(name: &str) -> Option<GmpVersion> {
    match name {
        // Semantic aliases distinguish newer helper shapes that reuse baseline
        // wire command names.
        "create_credential_store_credential"
        | "get_report_export"
        | "modify_credential_store_credential" => Some(GmpVersion(22, 8)),
        _ => command_capability(name).and_then(|capability| capability.min_version),
    }
}

/// Return whether a command needs positive availability confirmation from a
/// parsed XML `help` command listing.
#[must_use]
pub fn command_requires_help_discovery(name: &str) -> bool {
    command_capability(name).is_some_and(|capability| capability.requires_help_discovery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_and_unique() {
        assert!(COMMAND_CAPABILITIES
            .windows(2)
            .all(|window| window[0].name < window[1].name));
        assert_eq!(COMMAND_CAPABILITIES.len(), COMMAND_NAMES.len());
    }

    #[test]
    fn version_gates_are_registry_driven() {
        let features = command_capability("get_features").expect("known command");
        assert!(!features.available_in(GmpVersion(22, 5)));
        assert!(features.available_in(GmpVersion(22, 6)));

        let reports = command_capability("get_reports").expect("known command");
        assert!(reports.available_in(GmpVersion(22, 4)));
        let export = command_capability("export_scan_report").expect("known discoverable command");
        assert!(!export.permitted_in(GmpVersion(22, 6)));
        assert!(export.permitted_in(GmpVersion(22, 7)));
        assert!(!export.available_in(GmpVersion(22, 7)));
        assert!(!export.available_in(GmpVersion(22, 8)));
        assert!(export.requires_help_discovery);
        let audit_report =
            command_capability("get_audit_report").expect("known structured audit command");
        assert!(!audit_report.available_in(GmpVersion(22, 6)));
        assert!(audit_report.available_in(GmpVersion(22, 7)));
        let audit_hosts =
            command_capability("get_audit_report_hosts").expect("known audit host command");
        assert!(!audit_hosts.available_in(GmpVersion(22, 6)));
        assert!(audit_hosts.available_in(GmpVersion(22, 7)));
        assert_eq!(
            minimum_version_for_command("get_report_export"),
            Some(GmpVersion(22, 8))
        );
        assert!(command_capability("unknown_prefixed_command").is_none());
    }

    #[test]
    fn non_schema_commands_are_explicitly_qualified() {
        let exceptions: Vec<_> = COMMAND_CAPABILITIES
            .iter()
            .filter(|capability| capability.gvmd_evidence != GvmdEvidence::PinnedSchema)
            .map(|capability| (capability.name, capability.gvmd_evidence))
            .collect();

        assert_eq!(
            exceptions,
            [
                ("delete_tls_certificate", GvmdEvidence::LegacyCompatibility),
                ("modify_credential_store", GvmdEvidence::PublicSourceOnly),
                ("verify_credential_store", GvmdEvidence::PublicSourceOnly),
            ]
        );
    }
}
