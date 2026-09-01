// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{
    ExportScanReportOpts, GetOciImageTargetsOpts, GetReportExportOpts, GetWebApplicationTargetsOpts,
};
use gvm_client::{GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::alerts::{AlertOpts, GetAlertsOpts};
use gvm_gmp::commands::credentials::GetCredentialsOpts;
use gvm_gmp::commands::filters::{FilterOpts, GetFiltersOpts};
use gvm_gmp::commands::groups::{GetGroupsOpts, GroupOpts};
use gvm_gmp::commands::hosts::{GetHostsOpts, HostOpts};
use gvm_gmp::commands::notes::{GetNotesOpts, NoteOpts};
use gvm_gmp::commands::nvts::GetNvtsOpts;
use gvm_gmp::commands::overrides::{GetOverridesOpts, OverrideOpts};
use gvm_gmp::commands::permissions::{GetPermissionsOpts, PermissionOpts};
use gvm_gmp::commands::port_lists::{GetPortListsOpts, PortListOpts};
use gvm_gmp::commands::report_configs::GetReportConfigsOpts;
use gvm_gmp::commands::report_formats::{GetReportFormatsOpts, ReportFormatOpts};
use gvm_gmp::commands::reports::GetReportsOpts;
use gvm_gmp::commands::results::GetResultsOpts;
use gvm_gmp::commands::roles::{GetRolesOpts, RoleOpts};
use gvm_gmp::commands::scan_configs::GetScanConfigsOpts;
use gvm_gmp::commands::scanners::GetScannersOpts;
use gvm_gmp::commands::schedules::{GetSchedulesOpts, ScheduleOpts};
use gvm_gmp::commands::secinfo::GetSecInfoOpts;
use gvm_gmp::commands::tags::{GetTagsOpts, TagOpts};
use gvm_gmp::commands::targets::{GetTargetsOpts, GetTargetsRequest, ModifyTargetOpts};
use gvm_gmp::commands::tasks::{GetTasksOpts, ModifyTaskOpts};
use gvm_gmp::commands::tickets::{CreateTicketOpts, GetTicketsOpts, TicketOpenNote};
use gvm_gmp::commands::tls_certificates::{GetTlsCertificatesOpts, TlsCertificateOpts};
use gvm_gmp::commands::users::{GetUsersOpts, UserOpts};
use gvm_gmp::responses::{ActionResponse, ParseError};
use gvm_gmp::types::{EntityId, GmpVersion, ScalarUpdate};
use gvm_gmp::GmpRequest;
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};
use gvm_protocol::Request;

const CREATED_ID: &str = "11111111-1111-1111-1111-111111111111";

struct SemanticAliasRequest;

impl Request for SemanticAliasRequest {
    fn to_bytes(&self) -> Vec<u8> {
        b"<get_reports/>".to_vec()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("get_report_export")
    }
}

impl GmpRequest for SemanticAliasRequest {
    type Response = ActionResponse;
}

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("test entity id")
}

async fn fixture_server(version: MockVersion, overrides: &[(&str, &str)]) -> Option<MockGmpServer> {
    let mut builder = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto();
    for (command, response) in overrides {
        builder = builder.override_response(command, response);
    }

    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn client(server: &MockGmpServer) -> GmpClient<UnixSocketConnection> {
    GmpClient::connect(UnixSocketConnection::with_path(
        server.socket_path().expect("unix socket path"),
    ))
    .await
    .expect("client should connect")
}

macro_rules! assert_typed_success {
    ($future:expr) => {{
        let response = $future.await.expect("typed helper should parse");
        assert_eq!(response.status, 200);
        response
    }};
}

macro_rules! assert_create_success {
    ($future:expr) => {{
        let response = $future.await.expect("typed create helper should parse");
        assert_eq!(response.status, 201);
        assert_eq!(response.id.as_str(), CREATED_ID);
        response
    }};
}

macro_rules! assert_server_error {
    ($future:expr, $status:literal, $message:literal) => {{
        let error = $future.await.expect_err("typed helper should reject server error");
        assert!(matches!(
            error,
            GvmError::Parse(ParseError::ServerError { status: $status, message })
                if message == $message
        ));
    }};
}

macro_rules! create_response {
    ($root:literal) => {
        concat!(
            "<",
            $root,
            r#" status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#
        )
    };
}

#[tokio::test]
async fn generic_execute_decodes_the_requests_associated_response() {
    let Some(server) = fixture_server(
        MockVersion::V22_7,
        &[(
            "get_targets",
            r#"<get_targets_response status="200" status_text="OK"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let response = client
        .execute(GetTargetsRequest::new(GetTargetsOpts::default()))
        .await
        .expect("associated response should decode");

    assert_eq!(response.status, 200);
    assert!(response.items.is_empty());
}

#[tokio::test]
async fn generic_execute_preserves_semantic_alias_version_checks() {
    let Some(server) = fixture_server(MockVersion::V22_7, &[]).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let error = client
        .execute(SemanticAliasRequest)
        .await
        .expect_err("semantic alias should be checked before sending the wire command");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_report_export"
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

const MUTATION_SUCCESS_OVERRIDES: &[(&str, &str)] = &[
    (
        "delete_credential",
        r#"<delete_credential_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_schedule",
        r#"<modify_schedule_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_schedule",
        r#"<delete_schedule_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_target",
        r#"<delete_target_response status="200" status_text="OK"/>"#,
    ),
    (
        "modify_task",
        r#"<modify_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_task",
        r#"<delete_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="200" status_text="OK"/>"#,
    ),
];

const MUTATION_ERROR_OVERRIDES: &[(&str, &str)] = &[
    (
        "delete_credential",
        r#"<delete_credential_response status="409" status_text="conflict"/>"#,
    ),
    (
        "modify_schedule",
        r#"<modify_schedule_response status="409" status_text="conflict"/>"#,
    ),
    (
        "delete_schedule",
        r#"<delete_schedule_response status="409" status_text="conflict"/>"#,
    ),
    (
        "delete_target",
        r#"<delete_target_response status="409" status_text="conflict"/>"#,
    ),
    (
        "modify_task",
        r#"<modify_task_response status="409" status_text="conflict"/>"#,
    ),
    (
        "delete_task",
        r#"<delete_task_response status="409" status_text="conflict"/>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="409" status_text="conflict"/>"#,
    ),
];

const DISCOVERY_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_targets",
        r#"<get_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_oci_image_targets",
        r#"<get_oci_image_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_web_application_targets",
        r#"<get_web_application_targets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_configs",
        r#"<get_configs_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_scanners",
        r#"<get_scanners_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_port_lists",
        r#"<get_port_lists_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tasks",
        r#"<get_tasks_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_reports",
        r#"<get_reports_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_results",
        r#"<get_results_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_nvts",
        r#"<get_nvts_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_nvt_families",
        r#"<get_nvt_families_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_info",
        r#"<get_info_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_alerts",
        r#"<get_alerts_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_credentials",
        r#"<get_credentials_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_filters",
        r#"<get_filters_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_notes",
        r#"<get_notes_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_overrides",
        r#"<get_overrides_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_schedules",
        r#"<get_schedules_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tags",
        r#"<get_tags_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tickets",
        r#"<get_tickets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_users",
        r#"<get_users_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_groups",
        r#"<get_groups_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_roles",
        r#"<get_roles_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_permissions",
        r#"<get_permissions_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_assets",
        r#"<get_assets_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_tls_certificates",
        r#"<get_tls_certificates_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_report_formats",
        r#"<get_report_formats_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_report_configs",
        r#"<get_report_configs_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_settings",
        r#"<get_settings_response status="200" status_text="OK"/>"#,
    ),
    ("help", r#"<help_response status="200" status_text="OK"/>"#),
    (
        "describe_auth",
        r#"<describe_auth_response status="200" status_text="OK"/>"#,
    ),
];

#[tokio::test]
async fn discovery_and_administration_families_parse_through_real_client() {
    let Some(server) = fixture_server(MockVersion::V22_8, DISCOVERY_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;

    let version = assert_typed_success!(client.get_version());
    assert_eq!(version.version, "22.8");

    assert_typed_success!(client.get_targets(GetTargetsOpts::default()));
    assert_typed_success!(client.get_target(&id("11111111-1111-1111-1111-111111111111")));
    assert_typed_success!(client.get_oci_image_targets_parsed(GetOciImageTargetsOpts::default()));
    assert_typed_success!(
        client.get_web_application_targets_parsed(GetWebApplicationTargetsOpts::default())
    );
    assert_typed_success!(client.get_scan_configs(GetScanConfigsOpts::default()));
    assert_typed_success!(client.get_scanners(GetScannersOpts::default()));
    assert_typed_success!(client.get_port_lists(GetPortListsOpts::default()));
    assert_typed_success!(client.get_tasks(GetTasksOpts::default()));
    assert_typed_success!(client.get_reports(GetReportsOpts::default()));
    assert_typed_success!(client.get_results(GetResultsOpts::default()));
    assert_typed_success!(client.get_nvts(GetNvtsOpts::default()));
    assert_typed_success!(client.get_nvt_families());
    assert_typed_success!(client.get_cves(GetSecInfoOpts::default()));
    assert_typed_success!(client.get_cpes(GetSecInfoOpts::default()));
    assert_typed_success!(client.get_cert_bund_advisories(GetSecInfoOpts::default()));
    assert_typed_success!(client.get_dfn_cert_advisories(GetSecInfoOpts::default()));
    assert_typed_success!(client.get_alerts(GetAlertsOpts::default()));
    assert_typed_success!(client.get_credentials(GetCredentialsOpts::default()));
    assert_typed_success!(client.get_filters(GetFiltersOpts::default()));
    assert_typed_success!(client.get_notes(GetNotesOpts::default()));
    assert_typed_success!(client.get_overrides(GetOverridesOpts::default()));
    assert_typed_success!(client.get_schedules(GetSchedulesOpts::default()));
    assert_typed_success!(client.get_tags(GetTagsOpts::default()));
    assert_typed_success!(client.get_tickets(GetTicketsOpts::default()));
    assert_typed_success!(client.get_users(GetUsersOpts::default()));
    assert_typed_success!(client.get_groups(GetGroupsOpts::default()));
    assert_typed_success!(client.get_roles(GetRolesOpts::default()));
    assert_typed_success!(client.get_permissions(GetPermissionsOpts::default()));
    assert_typed_success!(client.get_hosts(GetHostsOpts::default()));
    assert_typed_success!(client.get_tls_certificates(GetTlsCertificatesOpts::default()));
    assert_typed_success!(client.get_report_formats(GetReportFormatsOpts::default()));
    assert_typed_success!(client.get_report_configs_parsed(GetReportConfigsOpts::default()));
    assert_typed_success!(client.get_settings());
    assert_typed_success!(client.get_help());
    assert_typed_success!(client.describe_auth());

    let history = server.command_history();
    for expected in [
        "get_targets",
        "get_oci_image_targets",
        "get_web_application_targets",
        "get_configs",
        "get_scanners",
        "get_reports",
        "get_info",
        "get_report_configs",
        "describe_auth",
    ] {
        assert!(
            history
                .iter()
                .any(|record| record.command_name() == expected),
            "missing command history entry for {expected}"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn create_families_parse_typed_ids_from_table_driven_fixture_responses() {
    let overrides = [
        (
            "create_port_list",
            create_response!("create_port_list_response"),
        ),
        ("create_alert", create_response!("create_alert_response")),
        ("create_filter", create_response!("create_filter_response")),
        ("create_note", create_response!("create_note_response")),
        (
            "create_override",
            create_response!("create_override_response"),
        ),
        (
            "create_schedule",
            create_response!("create_schedule_response"),
        ),
        ("create_tag", create_response!("create_tag_response")),
        ("create_ticket", create_response!("create_ticket_response")),
        ("create_user", create_response!("create_user_response")),
        ("create_group", create_response!("create_group_response")),
        ("create_role", create_response!("create_role_response")),
        (
            "create_permission",
            create_response!("create_permission_response"),
        ),
        ("create_asset", create_response!("create_asset_response")),
        (
            "create_tls_certificate",
            create_response!("create_tls_certificate_response"),
        ),
        (
            "create_report_format",
            create_response!("create_report_format_response"),
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_8, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    let related_id = id("22222222-2222-2222-2222-222222222222");

    assert_create_success!(client.create_port_list("ports", PortListOpts::default()));
    assert_create_success!(client.create_alert("alert", AlertOpts::default()));
    assert_create_success!(client.create_filter("filter", FilterOpts::default()));
    assert_create_success!(client.create_note("1.3.6.1.4.1.25623.1.0.1", NoteOpts::default()));
    assert_create_success!(
        client.create_override("1.3.6.1.4.1.25623.1.0.1", OverrideOpts::default())
    );
    assert_create_success!(client.create_schedule(
        "schedule",
        ScheduleOpts {
            icalendar: Some("BEGIN:VCALENDAR\nEND:VCALENDAR".into()),
            timezone: Some("UTC".into()),
            ..Default::default()
        }
    ));
    assert_create_success!(client.create_tag("tag", TagOpts::default()));
    assert_create_success!(client.create_ticket(
        &related_id,
        CreateTicketOpts {
            assigned_to: related_id.clone(),
            open_note: TicketOpenNote::new("Please investigate").expect("non-empty note"),
            comment: None,
        }
    ));
    assert_create_success!(client.create_user("user", UserOpts::default()));
    assert_create_success!(client.create_group("group", GroupOpts::default()));
    assert_create_success!(client.create_role("role", RoleOpts::default()));
    assert_create_success!(client.create_permission(PermissionOpts::default()));
    assert_create_success!(client.create_host(HostOpts::named("192.0.2.10")));
    assert_create_success!(
        client.create_tls_certificate("certificate", TlsCertificateOpts::default())
    );
    assert_create_success!(client.create_report_format("format", ReportFormatOpts::default()));

    let history = server.command_history();
    for (command, child) in [
        ("create_port_list", "<name>ports</name>"),
        ("create_note", r#"<nvt oid="1.3.6.1.4.1.25623.1.0.1"/>"#),
        ("create_schedule", "<timezone>UTC</timezone>"),
        ("create_asset", "<name>192.0.2.10</name>"),
        ("create_report_format", "<name>format</name>"),
    ] {
        let record = history
            .iter()
            .find(|record| record.command_name() == command)
            .unwrap_or_else(|| panic!("missing command history entry for {command}"));
        let xml = std::str::from_utf8(record.raw_xml()).expect("request XML");
        assert!(xml.contains(child), "{command} XML missing {child}: {xml}");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn remaining_mutation_families_use_typed_facade_and_scalar_relationship_updates() {
    let Some(server) = fixture_server(MockVersion::V22_8, MUTATION_SUCCESS_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let resource_id = id("resource-1");
    assert_typed_success!(client.delete_credential(&resource_id, false));
    assert_typed_success!(client.modify_schedule(
        &resource_id,
        ScheduleOpts {
            comment: Some("updated".into()),
            ..Default::default()
        }
    ));
    assert_typed_success!(client.delete_schedule(&resource_id, true));

    assert_typed_success!(client.modify_target(&resource_id, ModifyTargetOpts::default()));
    assert_typed_success!(client.modify_target(
        &resource_id,
        ModifyTargetOpts {
            ssh_credential_id: ScalarUpdate::set(id("credential-1")),
            ..Default::default()
        }
    ));
    assert_typed_success!(client.modify_target(
        &resource_id,
        ModifyTargetOpts {
            ssh_credential_id: ScalarUpdate::Clear,
            ..Default::default()
        }
    ));
    assert_typed_success!(client.delete_target(&resource_id, false));

    assert_typed_success!(client.modify_task(&resource_id, ModifyTaskOpts::default()));
    assert_typed_success!(client.modify_task(
        &resource_id,
        ModifyTaskOpts {
            schedule_id: ScalarUpdate::set(id("schedule-1")),
            ..Default::default()
        }
    ));
    assert_typed_success!(client.modify_task(
        &resource_id,
        ModifyTaskOpts {
            schedule_id: ScalarUpdate::Clear,
            ..Default::default()
        }
    ));
    assert_typed_success!(client.stop_task(&resource_id));
    assert_typed_success!(client.delete_task(&resource_id, true));

    let history = server.command_history();
    let xml_for = |command: &str| {
        history
            .iter()
            .filter(|record| record.command_name() == command)
            .map(|record| {
                std::str::from_utf8(record.raw_xml())
                    .expect("request XML")
                    .to_string()
            })
            .collect::<Vec<_>>()
    };

    let target_updates = xml_for("modify_target");
    assert_eq!(target_updates.len(), 3);
    assert_eq!(
        target_updates[0],
        r#"<modify_target target_id="resource-1"/>"#
    );
    assert!(target_updates[1].contains(r#"<ssh_credential id="credential-1"/>"#));
    assert!(target_updates[2].contains(r#"<ssh_credential id="0"/>"#));

    let task_updates = xml_for("modify_task");
    assert_eq!(task_updates.len(), 3);
    assert_eq!(task_updates[0], r#"<modify_task task_id="resource-1"/>"#);
    assert!(task_updates[1].contains(r#"<schedule id="schedule-1"/>"#));
    assert!(task_updates[2].contains(r#"<schedule id="0"/>"#));

    server.shutdown().await;
}

#[tokio::test]
async fn remaining_mutation_families_surface_non_success_responses() {
    let Some(server) = fixture_server(MockVersion::V22_8, MUTATION_ERROR_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    let resource_id = id("resource-1");

    assert_server_error!(
        client.delete_credential(&resource_id, false),
        409,
        "conflict"
    );
    assert_server_error!(
        client.modify_schedule(&resource_id, ScheduleOpts::default()),
        409,
        "conflict"
    );
    assert_server_error!(client.delete_schedule(&resource_id, false), 409, "conflict");
    assert_server_error!(client.delete_target(&resource_id, false), 409, "conflict");
    assert_server_error!(
        client.modify_task(&resource_id, ModifyTaskOpts::default()),
        409,
        "conflict"
    );
    assert_server_error!(client.stop_task(&resource_id), 409, "conflict");
    assert_server_error!(client.delete_task(&resource_id, false), 409, "conflict");

    server.shutdown().await;
}

#[tokio::test]
async fn report_export_simple_and_options_paths_preserve_distinct_xml() {
    let response = r#"<get_reports_response status="200" status_text="OK"><report id="11111111-1111-1111-1111-111111111111" format_id="33333333-3333-3333-3333-333333333333" extension="txt" content_type="text/plain">aGVsbG8=</report></get_reports_response>"#;
    let Some(server) = fixture_server(MockVersion::V22_8, &[("get_reports", response)]).await
    else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    let report_id = id(CREATED_ID);
    let format_id = id("33333333-3333-3333-3333-333333333333");
    let simple = client
        .get_report_export(&report_id, &format_id)
        .await
        .expect("simple report export should parse");
    assert_eq!(simple.bytes, b"hello");

    let mut options = GetReportExportOpts::new(format_id);
    options.report_config_id = Some(id("44444444-4444-4444-4444-444444444444"));
    options.filter_string = Some("severity>5".into());
    options.ignore_pagination = Some(false);
    let configured = client
        .get_report_export_with_opts(&report_id, options)
        .await
        .expect("options report export should parse");
    assert_eq!(configured.content_type.as_deref(), Some("text/plain"));

    let requests: Vec<_> = server
        .command_history()
        .into_iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("request XML"))
        .collect();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains(r#"report_id="11111111-1111-1111-1111-111111111111""#));
    assert!(requests[0].contains(r#"format_id="33333333-3333-3333-3333-333333333333""#));
    assert!(!requests[0].contains("config_id"));
    assert!(requests[1].contains(r#"config_id="44444444-4444-4444-4444-444444444444""#));
    assert!(requests[1].contains(r#"filter="severity&gt;5""#));
    assert!(requests[1].contains(r#"ignore_pagination="0""#));

    server.shutdown().await;
}

#[tokio::test]
async fn asynchronous_scan_report_export_uses_positive_help_discovery() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "help",
                r#"<help_response status="200" status_text="OK"><schema format="XML"><command><name>export_scan_report</name></command></schema></help_response>"#,
            ),
            (
                "export_scan_report",
                r#"<export_scan_report_response status="201" status_text="OK, resource created" id="11111111-1111-1111-1111-111111111111"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;
    assert_eq!(client.supports_command("export_scan_report"), None);
    client
        .discover_commands()
        .await
        .expect("help discovery should parse");

    let response = client
        .export_scan_report(
            &id("22222222-2222-2222-2222-222222222222"),
            ExportScanReportOpts::default(),
        )
        .await
        .expect("asynchronous export should parse");

    assert_eq!(response.status, 201);
    assert_eq!(response.export_status, None);
    server.shutdown().await;
}

#[tokio::test]
async fn asynchronous_scan_report_export_rejects_negative_help_discovery_on_22_8() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "help",
            r#"<help_response status="200" status_text="OK"><schema format="XML"><command><name>get_tasks</name></command></schema></help_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;
    client
        .discover_commands()
        .await
        .expect("negative help discovery should still parse");
    assert_eq!(client.supports_command("export_scan_report"), Some(false));
    server.clear_history();

    let error = client
        .export_scan_report(
            &id("22222222-2222-2222-2222-222222222222"),
            ExportScanReportOpts::default(),
        )
        .await
        .expect_err("22.8 alone must not unlock the command");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 8),
            required: "positive XML help discovery",
        } if command == "export_scan_report"
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn generic_execute_preserves_server_status_and_parse_error_context() {
    let Some(status_server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_targets",
            r#"<get_targets_response status="503" status_text="backend unavailable"/>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut status_client = client(&status_server).await;
    let status_error = status_client
        .execute(GetTargetsRequest::new(GetTargetsOpts::default()))
        .await
        .expect_err("server status should fail");
    assert!(matches!(
        status_error,
        GvmError::Parse(ParseError::ServerError {
            status: 503,
            message
        }) if message == "backend unavailable"
    ));
    status_server.shutdown().await;

    let Some(malformed_server) = fixture_server(
        MockVersion::V22_8,
        &[(
            "get_targets",
            r#"<get_targets_response status="200" status_text="OK"><target><name>missing id</name></target></get_targets_response>"#,
        )],
    )
    .await
    else {
        return;
    };
    let mut malformed_client = client(&malformed_server).await;
    let malformed_error = malformed_client
        .execute(GetTargetsRequest::new(GetTargetsOpts::default()))
        .await
        .expect_err("malformed typed payload should fail");
    assert!(matches!(
        malformed_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "target.id"
    ));
    malformed_server.shutdown().await;
}

#[tokio::test]
async fn distinct_registry_and_semantic_version_gates_fail_before_transport_send() {
    let Some(v225_server) = fixture_server(MockVersion::V22_5, &[]).await else {
        return;
    };
    let mut v225_client = client(&v225_server).await;
    v225_server.clear_history();

    let features_error = v225_client
        .get_features_parsed()
        .await
        .expect_err("22.6 registry gate should reject 22.5");
    assert!(matches!(
        features_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 5),
            required: "22.6",
        } if command == "get_features"
    ));
    let report_configs_error = v225_client
        .get_report_configs_parsed(GetReportConfigsOpts::default())
        .await
        .expect_err("22.6 report-config gate should reject 22.5");
    assert!(matches!(
        report_configs_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 5),
            required: "22.6",
        } if command == "get_report_configs"
    ));
    assert!(v225_server.command_history().is_empty());
    v225_server.shutdown().await;

    let Some(v227_server) = fixture_server(MockVersion::V22_7, &[]).await else {
        return;
    };
    let mut v227_client = client(&v227_server).await;
    v227_server.clear_history();
    let report_id = id(CREATED_ID);
    let format_id = id("33333333-3333-3333-3333-333333333333");

    let export_error = v227_client
        .get_report_export(&report_id, &format_id)
        .await
        .expect_err("22.8 semantic export gate should reject 22.7");
    assert!(matches!(
        export_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_report_export"
    ));
    let oci_error = v227_client
        .get_oci_image_targets_parsed(GetOciImageTargetsOpts::default())
        .await
        .expect_err("22.8 registry gate should reject 22.7");
    assert!(matches!(
        oci_error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_oci_image_targets"
    ));
    assert!(v227_server.command_history().is_empty());
    v227_server.shutdown().await;
}
