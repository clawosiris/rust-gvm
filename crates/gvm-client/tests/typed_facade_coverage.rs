// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{
    ExportScanReportOpts, GetOciImageTargetsOpts, GetReportExportOpts, GetWebApplicationTargetsOpts,
};
use gvm_client::{GmpClient, GvmError};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::alerts::{AlertOpts, GetAlertsOpts, TriggerAlertOpts};
use gvm_gmp::commands::credentials::{
    CloneCredentialRequest, CreateCredentialRequest, CredentialOpts, DeleteCredentialRequest,
    GetCredentialRequest, GetCredentialsOpts, GetCredentialsRequest, ModifyCredentialOpts,
    ModifyCredentialRequest,
};
use gvm_gmp::commands::filters::{FilterOpts, GetFiltersOpts};
use gvm_gmp::commands::groups::{GetGroupsOpts, GroupOpts};
use gvm_gmp::commands::hosts::{GetHostsOpts, HostOpts};
use gvm_gmp::commands::notes::{GetNotesOpts, ModifyNoteOpts, NoteOpts};
use gvm_gmp::commands::nvts::GetNvtsOpts;
use gvm_gmp::commands::overrides::{GetOverridesOpts, ModifyOverrideOpts, OverrideOpts};
use gvm_gmp::commands::permissions::{GetPermissionsOpts, PermissionOpts};
use gvm_gmp::commands::port_lists::{GetPortListsOpts, PortListOpts};
use gvm_gmp::commands::report_configs::GetReportConfigsOpts;
use gvm_gmp::commands::report_formats::{GetReportFormatsOpts, ReportFormatOpts};
use gvm_gmp::commands::reports::{
    GetReportDetailsOpts, GetReportExportRequest, GetReportVulnsRequest, GetReportsOpts,
    GetReportsRequest,
};
use gvm_gmp::commands::results::GetResultsOpts;
use gvm_gmp::commands::roles::{GetRolesOpts, RoleOpts};
use gvm_gmp::commands::scan_configs::GetScanConfigsOpts;
use gvm_gmp::commands::scanners::{
    CloneScannerRequest, CreateScannerRequest, DeleteScannerRequest, GetScannerRequest,
    GetScannersOpts, GetScannersRequest, ModifyScannerRequest, ScannerOpts, VerifyScannerRequest,
};
use gvm_gmp::commands::schedules::{GetSchedulesOpts, ScheduleOpts};
use gvm_gmp::commands::secinfo::GetSecInfoOpts;
use gvm_gmp::commands::tags::{GetTagsOpts, TagOpts};
use gvm_gmp::commands::targets::{GetTargetsOpts, GetTargetsRequest, ModifyTargetOpts};
use gvm_gmp::commands::tasks::{
    create_agent_group_task, create_container_image_task, create_oci_image_target_task,
    create_web_application_task, CloneTaskRequest, CreateAgentGroupTaskOpts,
    CreateOciImageTargetTaskOpts, CreateTaskOpts, CreateTaskRequest, CreateWebApplicationTaskOpts,
    DeleteTaskRequest, GetTaskRequest, GetTasksOpts, GetTasksRequest, ModifyTaskError,
    ModifyTaskOpts, ModifyTaskRequest, ResumeTaskRequest, StartTaskRequest, StopTaskRequest,
};
use gvm_gmp::commands::tickets::{CreateTicketOpts, GetTicketsOpts, TicketOpenNote};
use gvm_gmp::commands::tls_certificates::{GetTlsCertificatesOpts, TlsCertificateOpts};
use gvm_gmp::commands::users::{GetUsersOpts, ModifyUserOpts, UserOpts};
use gvm_gmp::responses::{ActionResponse, ParseError};
use gvm_gmp::types::{CollectionUpdate, EntityId, GmpVersion, ScalarUpdate};
use gvm_gmp::{
    GmpRequest, ScheduleDefinition, ScheduleInput, ScheduleRecurrence, ScheduleTimestamp,
    ScheduleTimezone,
};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};
use gvm_protocol::Request;

const CREATED_ID: &str = "11111111-1111-1111-1111-111111111111";
const TASK_LIFECYCLE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_tasks",
        r#"<get_tasks_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_task",
        r#"<create_task_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
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
        "start_task",
        r#"<start_task_response status="202" status_text="OK"><report_id>22222222-2222-2222-2222-222222222222</report_id></start_task_response>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "resume_task",
        r#"<resume_task_response status="202" status_text="OK"><report_id>33333333-3333-3333-3333-333333333333</report_id></resume_task_response>"#,
    ),
];

const DEFERRED_TASK_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_tasks",
        r#"<get_tasks_response status="200" status_text="OK"/>"#,
    ),
    (
        "create_task",
        r#"<create_task_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
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
        "move_task",
        r#"<move_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "start_task",
        r#"<start_task_response status="202" status_text="OK"><report_id>22222222-2222-2222-2222-222222222222</report_id></start_task_response>"#,
    ),
    (
        "stop_task",
        r#"<stop_task_response status="200" status_text="OK"/>"#,
    ),
    (
        "resume_task",
        r#"<resume_task_response status="202" status_text="OK"><report_id>33333333-3333-3333-3333-333333333333</report_id></resume_task_response>"#,
    ),
];

const CREDENTIAL_LIFECYCLE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_credentials",
        r#"<get_credentials_response status="200" status_text="OK"><credential_count>0<filtered>0</filtered></credential_count></get_credentials_response>"#,
    ),
    (
        "create_credential",
        r#"<create_credential_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_credential",
        r#"<modify_credential_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_credential",
        r#"<delete_credential_response status="200" status_text="OK"/>"#,
    ),
];

const SCANNER_LIFECYCLE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_scanners",
        r#"<get_scanners_response status="200" status_text="OK"><scanner_count>0<filtered>0</filtered></scanner_count></get_scanners_response>"#,
    ),
    (
        "create_scanner",
        r#"<create_scanner_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_scanner",
        r#"<modify_scanner_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_scanner",
        r#"<delete_scanner_response status="200" status_text="OK"/>"#,
    ),
    (
        "verify_scanner",
        r#"<verify_scanner_response status="200" status_text="OK"/>"#,
    ),
];

const ALERT_SCHEDULE_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_alerts",
        r#"<get_alerts_response status="200" status_text="OK"><alert_count>0<filtered>0</filtered></alert_count></get_alerts_response>"#,
    ),
    (
        "create_alert",
        r#"<create_alert_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_alert",
        r#"<modify_alert_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_alert",
        r#"<delete_alert_response status="200" status_text="OK"/>"#,
    ),
    (
        "test_alert",
        r#"<test_alert_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_reports",
        r#"<get_reports_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_schedules",
        r#"<get_schedules_response status="200" status_text="OK"><schedule_count>0<filtered>0</filtered></schedule_count></get_schedules_response>"#,
    ),
    (
        "create_schedule",
        r#"<create_schedule_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_schedule",
        r#"<modify_schedule_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_schedule",
        r#"<delete_schedule_response status="200" status_text="OK"/>"#,
    ),
];

const IDENTITY_PERMISSION_OVERRIDES: &[(&str, &str)] = &[
    (
        "get_users",
        r#"<get_users_response status="200" status_text="OK"><user_count>0<filtered>0</filtered></user_count></get_users_response>"#,
    ),
    (
        "create_user",
        r#"<create_user_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_user",
        r#"<modify_user_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_user",
        r#"<delete_user_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_groups",
        r#"<get_groups_response status="200" status_text="OK"><group_count>0<filtered>0</filtered></group_count></get_groups_response>"#,
    ),
    (
        "create_group",
        r#"<create_group_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_group",
        r#"<modify_group_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_group",
        r#"<delete_group_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_roles",
        r#"<get_roles_response status="200" status_text="OK"><role_count>0<filtered>0</filtered></role_count></get_roles_response>"#,
    ),
    (
        "create_role",
        r#"<create_role_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_role",
        r#"<modify_role_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_role",
        r#"<delete_role_response status="200" status_text="OK"/>"#,
    ),
    (
        "get_permissions",
        r#"<get_permissions_response status="200" status_text="OK"><permission_count>0<filtered>0</filtered></permission_count></get_permissions_response>"#,
    ),
    (
        "create_permission",
        r#"<create_permission_response status="201" status_text="OK" id="11111111-1111-1111-1111-111111111111"/>"#,
    ),
    (
        "modify_permission",
        r#"<modify_permission_response status="200" status_text="OK"/>"#,
    ),
    (
        "delete_permission",
        r#"<delete_permission_response status="200" status_text="OK"/>"#,
    ),
];

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

macro_rules! assert_unsupported_command {
    ($future:expr, $command:literal, $version:expr, $required:literal) => {{
        let error = $future
            .await
            .expect_err("typed helper should reject unsupported command before sending");
        assert!(matches!(
            error,
            GvmError::UnsupportedCommand {
                command,
                version,
                required: $required,
            } if command == $command && version == $version
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
async fn user_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_users(GetUsersOpts::default()));
    assert_typed_success!(client.get_user(&entity_id));
    assert_create_success!(client.create_user("user", UserOpts::default()));
    assert_create_success!(client.clone_user(&entity_id));
    assert_typed_success!(client.modify_user(&entity_id, ModifyUserOpts::default()));
    assert_typed_success!(client.delete_user(&entity_id, false));

    server.shutdown().await;
}

#[tokio::test]
async fn group_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_groups(GetGroupsOpts::default()));
    assert_typed_success!(client.get_group(&entity_id));
    assert_create_success!(client.create_group("group", GroupOpts::default()));
    assert_create_success!(client.clone_group(&entity_id));
    assert_typed_success!(client.modify_group(&entity_id, GroupOpts::default()));
    assert_typed_success!(client.delete_group(&entity_id, false));

    server.shutdown().await;
}

#[tokio::test]
async fn role_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_roles(GetRolesOpts::default()));
    assert_typed_success!(client.get_role(&entity_id));
    assert_create_success!(client.create_role("role", RoleOpts::default()));
    assert_create_success!(client.clone_role(&entity_id));
    assert_typed_success!(client.modify_role(&entity_id, RoleOpts::default()));
    assert_typed_success!(client.delete_role(&entity_id, false));

    server.shutdown().await;
}

#[tokio::test]
async fn permission_lifecycle_executes_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_8, IDENTITY_PERMISSION_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    let entity_id = id(CREATED_ID);

    assert_typed_success!(client.get_permissions(GetPermissionsOpts::default()));
    assert_typed_success!(client.get_permission(&entity_id));
    assert_create_success!(client.create_permission(PermissionOpts::default()));
    assert_create_success!(client.clone_permission(&entity_id));
    assert_typed_success!(client.modify_permission(&entity_id, PermissionOpts::default()));
    assert_typed_success!(client.delete_permission(&entity_id, false));

    server.shutdown().await;
}

#[tokio::test]
async fn identity_and_permission_facades_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_8,
        &[
            (
                "get_users",
                r#"<get_users_response status="409" status_text="identity conflict"/>"#,
            ),
            (
                "create_permission",
                r#"<create_permission_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    assert_server_error!(client.get_user(&id("user-1")), 409, "identity conflict");
    let parse_error = client
        .clone_permission(&id("permission-1"))
        .await
        .expect_err("missing cloned permission id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    server.shutdown().await;
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
async fn semantic_report_export_executes_binary_and_nested_xml_codecs() {
    let cases = [
        (
            r#"<get_reports_response status="200" status_text="OK"><report extension="bin" content_type="application/octet-stream">AP8B/g==</report></get_reports_response>"#,
            vec![0, 255, 1, 254],
        ),
        (
            r#"<get_reports_response status="200" status_text="OK"><report extension="xml" content_type="text/xml"><report id="report-1"><results><result id="one"/><result id="two"/></results></report></report></get_reports_response>"#,
            br#"<report id="report-1"><results><result id="one"/><result id="two"/></results></report>"#.to_vec(),
        ),
    ];

    for (fixture, expected) in cases {
        let Some(server) = fixture_server(MockVersion::V22_8, &[("get_reports", fixture)]).await
        else {
            return;
        };
        let mut client = client(&server).await;
        server.clear_history();

        let export = client
            .execute(GetReportExportRequest::new(
                id("report-1"),
                GetReportExportOpts::new(id("format-1")),
            ))
            .await
            .expect("associated irregular export response decodes");

        assert_eq!(export.bytes, expected);
        assert_eq!(server.command_history().len(), 1);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn semantic_report_requests_execute_large_and_mixed_repeated_responses() {
    const REPORTS: usize = 2_000;
    let mut large_fixture = String::from(r#"<get_reports_response status="200" status_text="OK">"#);
    for index in 0..REPORTS {
        large_fixture.push_str(&format!(
            r#"<report id="report-{index}"><name>Report {index}</name></report>"#
        ));
    }
    large_fixture.push_str(&format!(
        "<report_count>{REPORTS}<filtered>{REPORTS}</filtered></report_count></get_reports_response>"
    ));
    let overrides = [("get_reports", large_fixture.as_str())];
    let Some(server) = fixture_server(MockVersion::V22_8, &overrides).await else {
        return;
    };
    let mut large_client = client(&server).await;

    let reports = large_client
        .execute(GetReportsRequest::default())
        .await
        .expect("large associated report response decodes");
    assert_eq!(reports.items.len(), REPORTS);
    server.shutdown().await;

    let mixed_fixture = r#"<get_report_vulns_response status="200" status_text="OK"><vulns><vuln id="one"><name>First</name></vuln><vulnerability id="two"><name>Second</name></vulnerability><vuln id="three"><name>Third</name></vuln></vulns><report_vuln_count>3<filtered>3</filtered></report_vuln_count></get_report_vulns_response>"#;
    let Some(server) =
        fixture_server(MockVersion::V22_8, &[("get_report_vulns", mixed_fixture)]).await
    else {
        return;
    };
    let mut mixed_client = client(&server).await;

    let vulnerabilities = mixed_client
        .execute(GetReportVulnsRequest::new(
            id("report-1"),
            GetReportDetailsOpts::default(),
        ))
        .await
        .expect("mixed repeated response decodes");
    assert_eq!(vulnerabilities.items.len(), 3);
    assert_eq!(vulnerabilities.items[1].id.as_deref(), Some("three"));
    assert_eq!(vulnerabilities.items[2].id.as_deref(), Some("two"));
    server.shutdown().await;
}

#[tokio::test]
async fn standard_task_requests_execute_on_the_oldest_supported_version() {
    let Some(server) = fixture_server(MockVersion::V22_4, TASK_LIFECYCLE_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let task_id = id("task-1");

    let listed = client
        .execute(GetTasksRequest::default())
        .await
        .expect("task listing should be supported");
    assert_eq!(listed.status, 200);
    let detailed = client
        .execute(GetTaskRequest::new(task_id.clone()))
        .await
        .expect("detailed task get should be supported");
    assert_eq!(detailed.status, 200);

    let created = client
        .execute(CreateTaskRequest::new(
            "scan",
            id("config-1"),
            id("target-1"),
            id("scanner-1"),
            CreateTaskOpts::default(),
        ))
        .await
        .expect("standard task creation should be supported");
    assert_eq!(created.status, 201);
    let cloned = client
        .execute(CloneTaskRequest::new(task_id.clone()))
        .await
        .expect("task cloning should be supported");
    assert_eq!(cloned.status, 201);

    let modified = client
        .execute(
            ModifyTaskRequest::new(task_id.clone(), ModifyTaskOpts::default())
                .expect("valid task modification"),
        )
        .await
        .expect("task modification should be supported");
    assert_eq!(modified.status, 200);
    let deleted = client
        .execute(DeleteTaskRequest::new(task_id.clone(), false))
        .await
        .expect("task deletion should be supported");
    assert_eq!(deleted.status, 200);

    let started = client
        .execute(StartTaskRequest::new(task_id.clone()))
        .await
        .expect("task start should be supported");
    assert_eq!(started.status, 202);
    assert_eq!(
        started.report_id.as_ref().map(EntityId::as_str),
        Some("22222222-2222-2222-2222-222222222222")
    );
    let stopped = client
        .execute(StopTaskRequest::new(task_id.clone()))
        .await
        .expect("task stop should be supported");
    assert_eq!(stopped.status, 200);
    let resumed = client
        .execute(ResumeTaskRequest::new(task_id))
        .await
        .expect("task resume should be supported");
    assert_eq!(resumed.status, 202);

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_tasks",
            "get_tasks",
            "create_task",
            "create_task",
            "modify_task",
            "delete_task",
            "start_task",
            "stop_task",
            "resume_task",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn standard_task_execute_preserves_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_tasks",
                r#"<get_tasks_response status="409" status_text="task conflict"/>"#,
            ),
            (
                "create_task",
                r#"<create_task_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .execute(GetTaskRequest::new(id("task-1")))
        .await
        .expect_err("non-success task response should fail");
    assert!(matches!(
        status_error,
        GvmError::Parse(ParseError::ServerError { status: 409, message })
            if message == "task conflict"
    ));

    let parse_error = client
        .execute(CloneTaskRequest::new(id("task-1")))
        .await
        .expect_err("missing clone id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn specialized_task_create_and_move_helpers_use_typed_execution() {
    let Some(server) = fixture_server(MockVersion::V22_8, DEFERRED_TASK_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_create_success!(client.create_import_task("import", Some("comment")));
    assert_create_success!(client.create_container_task("container", None));
    assert_create_success!(client.create_agent_group_task(
        "agents",
        &id("agent-group-1"),
        &id("scanner-1"),
        CreateAgentGroupTaskOpts::default(),
    ));
    assert_create_success!(client.create_oci_image_target_task(
        "oci",
        &id("oci-target-1"),
        &id("scanner-1"),
        CreateOciImageTargetTaskOpts::default(),
    ));
    assert_create_success!(client.create_container_image_task(
        "container image",
        &id("oci-target-1"),
        &id("scanner-1"),
        CreateOciImageTargetTaskOpts::default(),
    ));
    assert_create_success!(client.create_web_application_task(
        "web",
        &id("web-target-1"),
        &id("scanner-1"),
        CreateWebApplicationTaskOpts::default(),
    ));
    assert_typed_success!(client.move_task(&id("task-1"), Some(&id("slave-1"))));

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "create_task",
            "create_task",
            "create_task",
            "create_task",
            "create_task",
            "create_task",
            "move_task",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn next_only_specialized_task_helpers_reject_before_send() {
    let Some(server) = fixture_server(MockVersion::V22_7, DEFERRED_TASK_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_unsupported_command!(
        client.send(create_agent_group_task(
            "raw agents",
            &id("agent-group-1"),
            &id("scanner-1"),
            CreateAgentGroupTaskOpts::default(),
        )),
        "create_agent_group_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.send(create_oci_image_target_task(
            "raw oci",
            &id("oci-target-1"),
            &id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        )),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.send(create_container_image_task(
            "raw container image",
            &id("oci-target-1"),
            &id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        )),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.send(create_web_application_task(
            "raw web",
            &id("web-target-1"),
            &id("scanner-1"),
            CreateWebApplicationTaskOpts::default(),
        )),
        "create_web_application_task",
        GmpVersion(22, 7),
        "22.8"
    );

    assert_unsupported_command!(
        client.create_agent_group_task(
            "agents",
            &id("agent-group-1"),
            &id("scanner-1"),
            CreateAgentGroupTaskOpts::default(),
        ),
        "create_agent_group_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.create_oci_image_target_task(
            "oci",
            &id("oci-target-1"),
            &id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        ),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.create_container_image_task(
            "container image",
            &id("oci-target-1"),
            &id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        ),
        "create_oci_image_target_task",
        GmpVersion(22, 7),
        "22.8"
    );
    assert_unsupported_command!(
        client.create_web_application_task(
            "web",
            &id("web-target-1"),
            &id("scanner-1"),
            CreateWebApplicationTaskOpts::default(),
        ),
        "create_web_application_task",
        GmpVersion(22, 7),
        "22.8"
    );

    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn audit_variant_helpers_use_typed_execution_and_presend_validation() {
    let Some(server) = fixture_server(MockVersion::V22_4, DEFERRED_TASK_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();

    assert_typed_success!(client.get_audits(GetTasksOpts::default()));
    assert_typed_success!(client.get_audit(&id("audit-1")));
    assert_create_success!(client.create_audit(
        "audit",
        &id("config-1"),
        &id("target-1"),
        &id("scanner-1"),
        CreateTaskOpts::default(),
    ));
    assert_create_success!(client.clone_audit(&id("audit-1")));
    assert_typed_success!(client.modify_audit(&id("audit-1"), ModifyTaskOpts::default()));
    assert_typed_success!(client.delete_audit(&id("audit-1")));
    assert_eq!(
        client
            .start_audit(&id("audit-1"))
            .await
            .expect("audit start should parse")
            .status,
        202
    );
    assert_typed_success!(client.stop_audit(&id("audit-1")));
    assert_eq!(
        client
            .resume_audit(&id("audit-1"))
            .await
            .expect("audit resume should parse")
            .status,
        202
    );

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_tasks",
            "get_tasks",
            "create_task",
            "create_task",
            "modify_task",
            "delete_task",
            "start_task",
            "stop_task",
            "resume_task",
        ]
    );

    server.clear_history();
    let error = client
        .modify_audit(
            &id("audit-1"),
            ModifyTaskOpts {
                observer_group_ids: gvm_gmp::types::CollectionUpdate::replace([id("group-1")]),
                ..Default::default()
            },
        )
        .await
        .expect_err("invalid audit observer update should fail before sending");
    assert!(matches!(
        error,
        GvmError::ModifyTask(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn standard_credential_requests_execute_on_the_oldest_supported_version() {
    let Some(server) = fixture_server(MockVersion::V22_4, CREDENTIAL_LIFECYCLE_OVERRIDES).await
    else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let credential_id = id("credential-1");

    let listed = client
        .execute(GetCredentialsRequest::new(GetCredentialsOpts::default()))
        .await
        .expect("credential listing should be supported");
    assert_eq!(listed.status, 200);
    let detailed = client
        .execute(GetCredentialRequest::new(credential_id.clone()))
        .await
        .expect("detailed credential get should be supported");
    assert_eq!(detailed.status, 200);

    let created = client
        .execute(CreateCredentialRequest::new(
            "credential",
            CredentialOpts::default(),
        ))
        .await
        .expect("credential creation should be supported");
    assert_eq!(created.status, 201);
    let cloned = client
        .execute(CloneCredentialRequest::new(credential_id.clone()))
        .await
        .expect("credential cloning should be supported");
    assert_eq!(cloned.status, 201);

    let modified = client
        .execute(ModifyCredentialRequest::new(
            credential_id.clone(),
            ModifyCredentialOpts::default(),
        ))
        .await
        .expect("credential modification should be supported");
    assert_eq!(modified.status, 200);
    let deleted = client
        .execute(DeleteCredentialRequest::new(credential_id, false))
        .await
        .expect("credential deletion should be supported");
    assert_eq!(deleted.status, 200);

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_credentials",
            "get_credentials",
            "create_credential",
            "create_credential",
            "modify_credential",
            "delete_credential",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn standard_credential_execute_preserves_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_credentials",
                r#"<get_credentials_response status="409" status_text="credential conflict"/>"#,
            ),
            (
                "create_credential",
                r#"<create_credential_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .execute(GetCredentialRequest::new(id("credential-1")))
        .await
        .expect_err("non-success credential response should fail");
    assert!(matches!(
        status_error,
        GvmError::Parse(ParseError::ServerError { status: 409, message })
            if message == "credential conflict"
    ));

    let parse_error = client
        .execute(CloneCredentialRequest::new(id("credential-1")))
        .await
        .expect_err("missing clone id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn scanner_requests_execute_on_the_oldest_supported_version() {
    let Some(server) = fixture_server(MockVersion::V22_4, SCANNER_LIFECYCLE_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let scanner_id = id("scanner-1");

    let listed = client
        .execute(GetScannersRequest::default())
        .await
        .expect("scanner listing should be supported");
    assert_eq!(listed.status, 200);
    let detailed = client
        .execute(GetScannerRequest::new(scanner_id.clone()))
        .await
        .expect("detailed scanner get should be supported");
    assert_eq!(detailed.status, 200);

    let created = client
        .execute(CreateScannerRequest::new("scanner", ScannerOpts::default()))
        .await
        .expect("scanner creation should be supported");
    assert_eq!(created.status, 201);
    let cloned = client
        .execute(CloneScannerRequest::new(scanner_id.clone()))
        .await
        .expect("scanner cloning should be supported");
    assert_eq!(cloned.status, 201);

    let modified = client
        .execute(ModifyScannerRequest::new(
            scanner_id.clone(),
            ScannerOpts::default(),
        ))
        .await
        .expect("scanner modification should be supported");
    assert_eq!(modified.status, 200);
    let deleted = client
        .execute(DeleteScannerRequest::new(scanner_id.clone(), false))
        .await
        .expect("scanner deletion should be supported");
    assert_eq!(deleted.status, 200);
    let verified = client
        .execute(VerifyScannerRequest::new(scanner_id))
        .await
        .expect("scanner verification should be supported");
    assert_eq!(verified.status, 200);

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_scanners",
            "get_scanners",
            "create_scanner",
            "create_scanner",
            "modify_scanner",
            "delete_scanner",
            "verify_scanner",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn scanner_execute_preserves_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_scanners",
                r#"<get_scanners_response status="409" status_text="scanner conflict"/>"#,
            ),
            (
                "create_scanner",
                r#"<create_scanner_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .execute(GetScannerRequest::new(id("scanner-1")))
        .await
        .expect_err("non-success scanner response should fail");
    assert!(matches!(
        status_error,
        GvmError::Parse(ParseError::ServerError { status: 409, message })
            if message == "scanner conflict"
    ));

    let parse_error = client
        .execute(CloneScannerRequest::new(id("scanner-1")))
        .await
        .expect_err("missing clone id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
}

fn typed_schedule_input() -> ScheduleInput {
    ScheduleInput::new(
        ScheduleDefinition {
            first_run: ScheduleTimestamp::parse("2030-01-01T00:00:00Z").expect("valid first run"),
            recurrence: ScheduleRecurrence::Daily,
        },
        ScheduleTimezone::new("UTC").expect("valid timezone"),
    )
}

#[tokio::test]
async fn alert_and_schedule_families_execute_through_typed_facade() {
    let Some(server) = fixture_server(MockVersion::V22_4, ALERT_SCHEDULE_OVERRIDES).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let alert_id = id("alert-1");
    let report_id = id("report-1");
    let schedule_id = id("schedule-1");

    assert_typed_success!(client.get_alerts(GetAlertsOpts::default()));
    assert_typed_success!(client.get_alert(&alert_id));
    assert_create_success!(client.create_alert("alert", AlertOpts::default()));
    assert_create_success!(client.clone_alert(&alert_id));
    assert_typed_success!(client.modify_alert(&alert_id, AlertOpts::default()));
    assert_typed_success!(client.delete_alert(&alert_id, false));
    assert_typed_success!(client.test_alert(&alert_id));
    assert_typed_success!(client.trigger_alert(&alert_id, &report_id, TriggerAlertOpts::default()));

    assert_typed_success!(client.get_schedules(GetSchedulesOpts::default()));
    assert_typed_success!(client.get_schedule(&schedule_id));
    assert_create_success!(client.create_schedule(
        "raw",
        ScheduleOpts {
            icalendar: Some("BEGIN:VCALENDAR\r\nEND:VCALENDAR".into()),
            timezone: Some("UTC".into()),
            ..Default::default()
        }
    ));
    assert_create_success!(client.create_typed_schedule("typed", typed_schedule_input()));
    assert_create_success!(client.clone_schedule(&schedule_id));
    assert_typed_success!(client.modify_schedule(&schedule_id, ScheduleOpts::default()));
    assert_typed_success!(client.modify_typed_schedule(&schedule_id, typed_schedule_input()));
    assert_typed_success!(client.delete_schedule(&schedule_id, true));

    let history = server.command_history();
    let commands = history
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_alerts",
            "get_alerts",
            "create_alert",
            "create_alert",
            "modify_alert",
            "delete_alert",
            "test_alert",
            "get_reports",
            "get_schedules",
            "get_schedules",
            "create_schedule",
            "create_schedule",
            "create_schedule",
            "modify_schedule",
            "modify_schedule",
            "delete_schedule",
        ]
    );

    let trigger_xml = history
        .iter()
        .find(|record| record.command_name() == "get_reports")
        .and_then(|record| std::str::from_utf8(record.raw_xml()).ok())
        .expect("trigger request XML");
    assert!(trigger_xml.contains("alert_id=\"alert-1\""));
    assert!(trigger_xml.contains("report_id=\"report-1\""));
    assert!(history.iter().any(|record| {
        record.command_name() == "create_schedule"
            && std::str::from_utf8(record.raw_xml())
                .is_ok_and(|xml| xml.contains("BEGIN:VCALENDAR"))
    }));
    server.shutdown().await;
}

#[tokio::test]
async fn alert_and_schedule_execute_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_alerts",
                r#"<get_alerts_response status="409" status_text="alert conflict"/>"#,
            ),
            (
                "create_schedule",
                r#"<create_schedule_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let status_error = client
        .get_alert(&id("alert-1"))
        .await
        .expect_err("non-success alert response should fail");
    assert!(matches!(
        status_error,
        GvmError::Parse(ParseError::ServerError { status: 409, message })
            if message == "alert conflict"
    ));

    let parse_error = client
        .clone_schedule(&id("schedule-1"))
        .await
        .expect_err("missing cloned schedule id should fail");
    assert!(matches!(
        parse_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));
    server.shutdown().await;
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
    assert_typed_success!(client.get_task(&id("11111111-1111-1111-1111-111111111111")));
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
        ("create_task", create_response!("create_task_response")),
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
    assert_create_success!(client.create_task(
        "scan",
        &related_id,
        &related_id,
        &related_id,
        CreateTaskOpts::default()
    ));
    assert_create_success!(client.clone_task(&related_id));

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
async fn filters_tags_and_trashcan_execute_through_typed_facade() {
    let overrides = [
        (
            "get_filters",
            r#"<get_filters_response status="200" status_text="OK"><filter_count>0<filtered>0</filtered></filter_count></get_filters_response>"#,
        ),
        ("create_filter", create_response!("create_filter_response")),
        (
            "modify_filter",
            r#"<modify_filter_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_filter",
            r#"<delete_filter_response status="200" status_text="OK"/>"#,
        ),
        (
            "get_tags",
            r#"<get_tags_response status="200" status_text="OK"><tag_count>0<filtered>0</filtered></tag_count></get_tags_response>"#,
        ),
        ("create_tag", create_response!("create_tag_response")),
        (
            "modify_tag",
            r#"<modify_tag_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_tag",
            r#"<delete_tag_response status="200" status_text="OK"/>"#,
        ),
        (
            "empty_trashcan",
            r#"<empty_trashcan_response status="200" status_text="OK"/>"#,
        ),
        (
            "restore",
            r#"<restore_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_4, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let resource_id = id("resource-1");

    assert_typed_success!(client.get_filters(GetFiltersOpts::default()));
    assert_typed_success!(client.get_filter(&resource_id));
    assert_create_success!(client.create_filter("filter", FilterOpts::default()));
    assert_create_success!(client.clone_filter(&resource_id));
    assert_typed_success!(client.modify_filter(&resource_id, FilterOpts::default()));
    assert_typed_success!(client.delete_filter(&resource_id, false));

    assert_typed_success!(client.get_tags(GetTagsOpts::default()));
    assert_typed_success!(client.get_tag(&resource_id));
    assert_create_success!(client.create_tag("tag", TagOpts::default()));
    assert_create_success!(client.clone_tag(&resource_id));
    assert_typed_success!(client.modify_tag(&resource_id, TagOpts::default()));
    assert_typed_success!(client.delete_tag(&resource_id, true));

    assert_typed_success!(client.empty_trashcan());
    assert_typed_success!(client.restore(&resource_id));
    assert_typed_success!(client.restore_from_trashcan(&resource_id));

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_filters",
            "get_filters",
            "create_filter",
            "create_filter",
            "modify_filter",
            "delete_filter",
            "get_tags",
            "get_tags",
            "create_tag",
            "create_tag",
            "modify_tag",
            "delete_tag",
            "empty_trashcan",
            "restore",
            "restore",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn filters_tags_and_trashcan_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_filters",
                r#"<get_filters_response status="409" status_text="filter conflict"/>"#,
            ),
            (
                "create_tag",
                r#"<create_tag_response status="201" status_text="OK"/>"#,
            ),
            (
                "empty_trashcan",
                r#"<empty_trashcan_response status="409" status_text="trashcan conflict"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let filter_error = client
        .get_filter(&id("filter-1"))
        .await
        .expect_err("non-success filter response should fail");
    assert!(matches!(
        filter_error,
        GvmError::Parse(ParseError::ServerError { status: 409, message })
            if message == "filter conflict"
    ));

    let tag_error = client
        .clone_tag(&id("tag-1"))
        .await
        .expect_err("missing cloned tag id should fail");
    assert!(matches!(
        tag_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

    let trashcan_error = client
        .empty_trashcan()
        .await
        .expect_err("non-success empty-trashcan response should fail");
    assert!(matches!(
        trashcan_error,
        GvmError::Parse(ParseError::ServerError { status: 409, message })
            if message == "trashcan conflict"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn notes_execute_through_typed_facade() {
    let overrides = [
        (
            "get_notes",
            r#"<get_notes_response status="200" status_text="OK"><note_count>0<filtered>0</filtered></note_count></get_notes_response>"#,
        ),
        ("create_note", create_response!("create_note_response")),
        (
            "modify_note",
            r#"<modify_note_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_note",
            r#"<delete_note_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_4, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let resource_id = id("resource-1");

    assert_typed_success!(client.get_notes(GetNotesOpts::default()));
    assert_typed_success!(client.get_note(&resource_id));
    assert_create_success!(client.create_note(
        "1.3.6.1.4.1.25623.1.0.1",
        NoteOpts {
            hosts: vec!["192.0.2.1".into()],
            ..Default::default()
        }
    ));
    assert_create_success!(client.clone_note(&resource_id));
    assert_typed_success!(client.modify_note(
        &resource_id,
        ModifyNoteOpts {
            hosts: CollectionUpdate::Clear,
            ..Default::default()
        }
    ));
    assert_typed_success!(client.delete_note(&resource_id, true));

    let history = server.command_history();
    let commands = history
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_notes",
            "get_notes",
            "create_note",
            "create_note",
            "modify_note",
            "delete_note",
        ]
    );
    let modify_note = history
        .iter()
        .find(|record| record.command_name() == "modify_note")
        .expect("modify_note history");
    assert!(std::str::from_utf8(modify_note.raw_xml())
        .expect("request XML")
        .contains("<hosts></hosts>"));
    let delete_note = history
        .iter()
        .find(|record| record.command_name() == "delete_note")
        .expect("delete_note history");
    assert!(std::str::from_utf8(delete_note.raw_xml())
        .expect("request XML")
        .contains(r#"ultimate="1""#));
    server.shutdown().await;
}

#[tokio::test]
async fn overrides_execute_through_typed_facade() {
    let overrides = [
        (
            "get_overrides",
            r#"<get_overrides_response status="200" status_text="OK"><override_count>0<filtered>0</filtered></override_count></get_overrides_response>"#,
        ),
        (
            "create_override",
            create_response!("create_override_response"),
        ),
        (
            "modify_override",
            r#"<modify_override_response status="200" status_text="OK"/>"#,
        ),
        (
            "delete_override",
            r#"<delete_override_response status="200" status_text="OK"/>"#,
        ),
    ];
    let Some(server) = fixture_server(MockVersion::V22_4, &overrides).await else {
        return;
    };
    let mut client = client(&server).await;
    server.clear_history();
    let resource_id = id("resource-1");

    assert_typed_success!(client.get_overrides(GetOverridesOpts::default()));
    assert_typed_success!(client.get_override(&resource_id));
    assert_create_success!(client.create_override(
        "1.3.6.1.4.1.25623.1.0.1",
        OverrideOpts {
            new_severity: Some("3.0".into()),
            ..Default::default()
        }
    ));
    assert_create_success!(client.clone_override(&resource_id));
    assert_typed_success!(client.modify_override(
        &resource_id,
        ModifyOverrideOpts {
            hosts: CollectionUpdate::replace(["192.0.2.2".into()]),
            ..Default::default()
        }
    ));
    assert_typed_success!(client.delete_override(&resource_id, false));

    let commands = server
        .command_history()
        .iter()
        .map(|record| record.command_name().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "get_overrides",
            "get_overrides",
            "create_override",
            "create_override",
            "modify_override",
            "delete_override",
        ]
    );
    server.shutdown().await;
}

#[tokio::test]
async fn notes_and_overrides_preserve_status_and_parse_context() {
    let Some(server) = fixture_server(
        MockVersion::V22_4,
        &[
            (
                "get_notes",
                r#"<get_notes_response status="409" status_text="note conflict"/>"#,
            ),
            (
                "create_override",
                r#"<create_override_response status="201" status_text="OK"/>"#,
            ),
        ],
    )
    .await
    else {
        return;
    };
    let mut client = client(&server).await;

    let note_error = client
        .get_note(&id("note-1"))
        .await
        .expect_err("non-success note response should fail");
    assert!(matches!(
        note_error,
        GvmError::Parse(ParseError::ServerError { status: 409, message })
            if message == "note conflict"
    ));

    let override_error = client
        .clone_override(&id("override-1"))
        .await
        .expect_err("missing cloned override id should fail");
    assert!(matches!(
        override_error,
        GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
    ));

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
