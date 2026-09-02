// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::collections::BTreeSet;

const INTEGRATION_COVERED: &[&str] = &[
    "get_version",
    "authenticate",
    "get_targets",
    "get_target",
    "create_target",
    "modify_target",
    "delete_target",
    "create_oci_image_target_parsed",
    "clone_oci_image_target_parsed",
    "get_oci_image_target_parsed",
    "get_oci_image_targets_parsed",
    "modify_oci_image_target_parsed",
    "delete_oci_image_target_parsed",
    "create_web_application_target_parsed",
    "clone_web_application_target_parsed",
    "get_web_application_target_parsed",
    "get_web_application_targets_parsed",
    "modify_web_application_target_parsed",
    "delete_web_application_target_parsed",
    "get_scan_configs",
    "create_scan_config",
    "import_scan_config",
    "get_scan_config",
    "get_policies",
    "get_policy",
    "import_policy",
    "modify_scan_config",
    "modify_scan_config_set_name",
    "modify_scan_config_set_comment",
    "modify_policy_set_name",
    "modify_policy_set_comment",
    "delete_scan_config",
    "clone_scan_config",
    "sync_scan_config",
    "sync_config",
    "get_scanners",
    "create_scanner",
    "get_scanner",
    "modify_scanner",
    "delete_scanner",
    "verify_scanner",
    "clone_scanner",
    "get_port_lists",
    "create_port_list",
    "modify_port_list",
    "get_tasks",
    "get_task",
    "create_task",
    "clone_task",
    "create_import_task",
    "create_container_task",
    "create_agent_group_task",
    "create_oci_image_target_task",
    "create_container_image_task",
    "create_web_application_task",
    "move_task",
    "get_audits",
    "get_audit",
    "create_audit",
    "clone_audit",
    "modify_audit",
    "delete_audit",
    "start_audit",
    "stop_audit",
    "resume_audit",
    "start_task",
    "resume_task",
    "modify_task",
    "stop_task",
    "delete_task",
    "empty_trashcan",
    "restore",
    "restore_from_trashcan",
    "get_reports",
    "get_audit_report",
    "get_audit_report_hosts",
    "get_report_vulns",
    "get_report_vulnerabilities",
    "get_report_tls_certificates",
    "get_report_hosts_parsed",
    "get_report_ports_parsed",
    "get_report_applications_parsed",
    "get_report_operating_systems_parsed",
    "get_report_cves_parsed",
    "get_report_errors",
    "get_report_closed_cves",
    "get_report_export",
    "get_report_export_with_opts",
    "export_scan_report",
    "get_results",
    "get_feeds",
    "get_feed",
    "get_timezones",
    "get_credential_stores",
    "verify_credential_store",
    "get_credential_stores_with_opts",
    "get_credential_store",
    "get_nvts",
    "get_scan_config_nvts",
    "get_scan_config_nvt",
    "get_nvt_families",
    "get_cves",
    "get_cve",
    "get_cpes",
    "get_cpe",
    "get_cert_bund_advisories",
    "get_cert_bund_advisory",
    "get_dfn_cert_advisories",
    "get_dfn_cert_advisory",
    "get_vulnerabilities",
    "get_vulnerability",
    "get_alerts",
    "get_alert",
    "create_alert",
    "clone_alert",
    "modify_alert",
    "delete_alert",
    "test_alert",
    "trigger_alert",
    "get_credentials",
    "create_credential",
    "modify_credential",
    "delete_credential",
    "create_credential_store_credential",
    "modify_credential_store_credential",
    "get_filters",
    "get_filter",
    "create_filter",
    "clone_filter",
    "modify_filter",
    "delete_filter",
    "get_notes",
    "create_note",
    "get_overrides",
    "create_override",
    "get_schedules",
    "get_schedule",
    "create_schedule",
    "create_typed_schedule",
    "clone_schedule",
    "modify_schedule",
    "modify_typed_schedule",
    "delete_schedule",
    "get_tags",
    "get_tag",
    "create_tag",
    "clone_tag",
    "modify_tag",
    "delete_tag",
    "get_tickets",
    "create_ticket",
    "modify_ticket",
    "get_users",
    "create_user",
    "modify_user",
    "get_groups",
    "create_group",
    "get_roles",
    "create_role",
    "get_permissions",
    "create_permission",
    "get_hosts",
    "create_host",
    "get_integration_config_parsed",
    "get_integration_configs_parsed",
    "modify_integration_config_parsed",
    "get_assets",
    "get_asset",
    "create_asset",
    "modify_asset",
    "delete_asset",
    "get_operating_system_assets",
    "get_operating_system_asset",
    "get_configs",
    "get_config",
    "create_config",
    "clone_config",
    "modify_config",
    "delete_config",
    "get_tls_certificates",
    "create_tls_certificate",
    "get_report_formats",
    "create_report_format",
    "clone_report_format",
    "import_report_format",
    "import_report",
    "get_report_configs_parsed",
    "clone_report_config",
    "get_aggregates",
    "get_features_parsed",
    "get_settings",
    "get_system_reports",
    "get_help",
    "get_help_with_mode",
    "describe_auth",
    "modify_auth",
    "modify_license",
    "run_wizard",
];

// Kept explicit so each public helper has exactly one of the three issue #398
// classifications. There are no signature-only exceptions in the current
// parser-returning facade and no known integration gaps.
const COMPILE_ONLY: &[&str] = &[];
const REQUIRES_INTEGRATION: &[&str] = &[];

fn public_typed_methods() -> BTreeSet<&'static str> {
    include_str!("../src/typed.rs")
        .lines()
        .filter_map(|line| {
            line.trim_start()
                .strip_prefix("pub async fn ")
                .and_then(|rest| rest.split('(').next())
        })
        .collect()
}

fn normalized_integration_sources() -> String {
    [
        include_str!("audit_integration.rs"),
        include_str!("client_integration.rs"),
        include_str!("report_config_integration.rs"),
        include_str!("structured_audit_report_integration.rs"),
        include_str!("tls_certificate_integration.rs"),
        include_str!("typed_facade_coverage.rs"),
        include_str!("versioned_client.rs"),
    ]
    .concat()
    .chars()
    .filter(|ch| !ch.is_whitespace())
    .collect()
}

#[test]
fn every_public_typed_helper_has_exactly_one_enforced_classification() {
    let public = public_typed_methods();
    let mut classified = BTreeSet::new();

    for (class, methods) in [
        ("integration covered", INTEGRATION_COVERED),
        ("compile only", COMPILE_ONLY),
        ("requires integration", REQUIRES_INTEGRATION),
    ] {
        for method in methods {
            assert!(
                classified.insert(*method),
                "{method} appears in more than one typed-facade classification ({class})"
            );
        }
    }

    assert_eq!(
        classified, public,
        "update the typed-facade coverage inventory for every added or removed public helper"
    );
    assert!(
        REQUIRES_INTEGRATION.is_empty(),
        "typed facade still has helpers requiring integration coverage: {REQUIRES_INTEGRATION:?}"
    );
}

#[test]
fn integration_classification_requires_a_direct_client_test_call() {
    let integration_sources = normalized_integration_sources();

    for method in INTEGRATION_COVERED {
        let call = format!(".{method}(");
        assert!(
            integration_sources.contains(&call),
            "{method} is classified as integration covered but has no direct client test call"
        );
    }
}
