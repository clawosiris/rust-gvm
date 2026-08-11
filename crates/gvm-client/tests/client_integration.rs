// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{
    AggregateMode, AggregateSort, AggregateSortStatistic, CreateOciImageTargetOpts,
    CreateWebApplicationTargetOpts, CredentialStoreCredentialOpts, CredentialStoreCredentialType,
    GetAggregatesRequestOpts, GetCredentialStoresOpts, GetScanReportOpts, GetSystemReportsOpts,
    GmpClient, GmpNextCommands, GmpVersioned, GvmError, ImportReportOpts,
    ModifyCredentialStoreCredentialOpts, ModifyOciImageTargetOpts, ModifyWebApplicationTargetOpts,
    UsageType, WireTraceDirection, WireTraceEvent,
};
use gvm_connection::{ConnectionError, GvmConnection, UnixSocketConnection};
use gvm_gmp::commands::aggregates::{get_aggregates as get_aggregates_legacy, GetAggregatesOpts};
use gvm_gmp::commands::alerts::{
    trigger_alert, AlertData, AlertOpts, GetAlertsOpts, TriggerAlertOpts,
};
use gvm_gmp::commands::assets::{
    AssetType, CreateAssetOpts, DeleteAssetOpts, GetAssetsOpts, ModifyAssetOpts,
};
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::configs::{
    CloneConfigOpts, ConfigUsageType, CreateConfigOpts, DeleteConfigOpts, GetConfigOpts,
    GetConfigsOpts, ModifyConfigOpts,
};
use gvm_gmp::commands::credentials::{
    create_credential_store_credential, get_credential, modify_credential_store,
    modify_credential_store_credential, CredentialOpts, CredentialStorePreference,
    ModifyCredentialOpts,
    ModifyCredentialStoreCredentialOpts as GmpModifyCredentialStoreCredentialOpts,
    ModifyCredentialStoreOpts,
};
use gvm_gmp::commands::help::HelpMode;
use gvm_gmp::commands::nvts::{
    get_nvt_preference, get_nvt_preferences, GetNvtPreferencesOpts, GetNvtsOpts,
};
use gvm_gmp::commands::operating_systems::{get_operating_systems, GetOperatingSystemsOpts};
use gvm_gmp::commands::permissions::{modify_permission, GetPermissionsOpts, PermissionOpts};
use gvm_gmp::commands::port_lists::{GetPortListsOpts, ModifyPortListOpts, PortListOpts};
use gvm_gmp::commands::reports::{
    get_report_export, get_report_hosts, get_report_vulnerabilities, get_reports, GetReportsOpts,
};
use gvm_gmp::commands::roles::RoleOpts;
use gvm_gmp::commands::scan_configs::{
    create_policy, get_policies, get_scan_config_preference, get_scan_config_preferences,
    ConfigOpts, GetPolicyOpts, GetScanConfigPreferencesOpts, GetScanConfigsOpts,
};
use gvm_gmp::commands::scanners::ScannerOpts;
use gvm_gmp::commands::schedules::{GetSchedulesOpts, ScheduleOpts};
use gvm_gmp::commands::secinfo::{get_info, get_info_list, GenericInfoType, GetInfoListOpts};
use gvm_gmp::commands::system::get_timezones;
use gvm_gmp::commands::system::ModifyLicenseOpts;
use gvm_gmp::commands::system::RunWizardOpts;
use gvm_gmp::commands::targets::{
    create_target, delete_target, get_targets, CreateTargetError, CreateTargetOpts, GetTargetsOpts,
    InvalidTargetHost, ModifyTargetError, ModifyTargetOpts, TargetHostField,
};
use gvm_gmp::commands::tasks::{
    create_task, delete_task, get_task, start_task, stop_task, CreateTaskOpts, GetTasksOpts,
    ModifyTaskOpts,
};
use gvm_gmp::commands::tickets::{
    CreateTicketOpts, GetTicketsOpts, ModifyTicketOpts, TicketOpenNote,
};
use gvm_gmp::commands::users::{GetUsersOpts, ModifyUserOpts, UserOpts};
use gvm_gmp::responses::{
    Asset, ConfigUsageKind, CreateScanConfigResponse, CredentialKind, GetConfigsResponse,
    GetPermissionsResponse, GetScanConfigsResponse, GetScanReportResponse, ParseError, Permission,
    Target,
};
use gvm_gmp::types::EntityId;
use gvm_gmp::types::GmpVersion;
use gvm_gmp::{
    AlertCondition, AlertEvent, AlertMethod, AliveTest, CollectionUpdate, CredentialType, FeedType,
    PermissionSubjectType, ScalarUpdate, ScheduleDefinition, ScheduleInput, ScheduleRecurrence,
    ScheduleRecurrenceObservation, ScheduleTimestamp, ScheduleTimezone, ServicePort,
    SnmpAuthAlgorithm, SnmpPrivacyAlgorithm, SortOrder, TicketStatus,
};
use gvm_mock_server::{
    GmpVersion as MockVersion, MockGmpServer, Resource, ResourceStore, ServerMode,
};
use std::sync::{Arc, Mutex};

async fn stateful_server() -> Option<MockGmpServer> {
    stateful_server_with_version(MockVersion::V22_5).await
}

async fn stateful_server_with_version(version: MockVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn fixture_server_with_version_response(version_xml: &str) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .unix_socket_auto()
        .override_response(
            "get_version",
            &format!(
                "<get_version_response status=\"200\" status_text=\"OK\"><version>{version_xml}</version></get_version_response>"
            ),
        )
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn fixture_server(version: MockVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn echo_server(version: MockVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(version)
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

fn unix_connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("unix socket path"))
}

async fn authenticated_client(server: &MockGmpServer) -> GmpClient<UnixSocketConnection> {
    let mut client = GmpClient::connect(unix_connection(server))
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    client
}

async fn target_by_id(
    client: &mut GmpClient<UnixSocketConnection>,
    target_id: &EntityId,
) -> Target {
    client
        .get_target(target_id)
        .await
        .expect("target should be retrieved")
        .items
        .into_iter()
        .next()
        .expect("target should be present")
}

async fn create_test_credential(
    client: &mut GmpClient<UnixSocketConnection>,
    name: &str,
) -> EntityId {
    client
        .create_credential(name, CredentialOpts::default())
        .await
        .expect("credential should be created")
        .id
}

async fn create_test_smb_credential(
    client: &mut GmpClient<UnixSocketConnection>,
    name: &str,
) -> EntityId {
    client
        .create_credential(
            name,
            CredentialOpts {
                credential_type: Some(CredentialType::UsernamePassword),
                login: Some("scanner".into()),
                password: Some("secret".into()),
                ..Default::default()
            },
        )
        .await
        .expect("SMB credential should be created")
        .id
}

async fn assert_raw_server_error(
    client: &mut GmpClient<UnixSocketConnection>,
    xml: Vec<u8>,
    expected_status: u16,
) {
    let error = client
        .call(xml)
        .await
        .expect_err("raw request should be rejected");
    assert!(matches!(
        error,
        GvmError::Server { status, .. } if status == expected_status
    ));
}

fn assert_target_credentials(
    target: &Target,
    ssh_credential_id: &EntityId,
    ssh_port: u16,
    smb_credential_id: &EntityId,
) {
    assert_eq!(
        target
            .ssh_credential
            .as_ref()
            .map(|credential| &credential.id),
        Some(ssh_credential_id)
    );
    assert_eq!(
        target.ssh_credential_port.map(ServicePort::get),
        Some(ssh_port)
    );
    assert_eq!(
        target
            .smb_credential
            .as_ref()
            .map(|credential| &credential.id),
        Some(smb_credential_id)
    );
}

fn event_text(event: &WireTraceEvent) -> String {
    String::from_utf8(event.bytes.clone()).expect("trace event should be UTF-8")
}

fn permission_by_id<'a>(
    permissions: &'a GetPermissionsResponse,
    permission_id: &EntityId,
) -> &'a Permission {
    permissions
        .items
        .iter()
        .find(|item| item.meta.id == *permission_id)
        .expect("permission should be listed")
}

#[tokio::test]
async fn connect_negotiates_version_22_5() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);

    let client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    assert_eq!(client.version(), GmpVersion(22, 5));
    assert!(client.connection().is_connected());

    server.shutdown().await;
}

#[tokio::test]
async fn connect_negotiates_supported_versions() {
    for (mock_version, expected, matcher) in [
        (MockVersion::V22_4, GmpVersion(22, 4), 224_u16),
        (MockVersion::V22_5, GmpVersion(22, 5), 225_u16),
        (MockVersion::V22_6, GmpVersion(22, 6), 226_u16),
        (MockVersion::V22_7, GmpVersion(22, 7), 227_u16),
        (MockVersion::V22_8, GmpVersion(22, 8), 228_u16),
    ] {
        let Some(server) = stateful_server_with_version(mock_version).await else {
            return;
        };
        let connection = unix_connection(&server);
        let client = GmpVersioned::connect(connection)
            .await
            .expect("client should connect");

        assert_eq!(client.version(), expected);
        match (matcher, client) {
            (224, GmpVersioned::V224(_))
            | (225, GmpVersioned::V225(_))
            | (226, GmpVersioned::V226(_))
            | (227, GmpVersioned::V227(_))
            | (228, GmpVersioned::Next(_)) => {}
            (_, other) => panic!("unexpected versioned client: {other:?}"),
        }

        server.shutdown().await;
    }
}

#[tokio::test]
async fn typed_feature_discovery_parses_current_gvmd_shape_over_unix_transport() {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .override_response(
            "get_features",
            "<get_features_response status=\"200\" status_text=\"OK\">\
             <feature compiled_in=\"1\" enabled=\"1\"><name>ENABLE_AGENTS</name></feature>\
             <feature compiled_in=\"1\" enabled=\"0\"><name>ENABLE_JWT_AUTH</name></feature>\
             </get_features_response>",
        )
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("server should start: {error}"),
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let response = client
        .get_features_parsed()
        .await
        .expect("typed feature discovery should parse");

    assert_eq!(response.features.len(), 2);
    assert_eq!(response.features[0].name, "ENABLE_AGENTS");
    assert!(response.features[0].compiled_in);
    assert!(response.features[0].enabled);
    assert_eq!(response.features[1].name, "ENABLE_JWT_AUTH");
    assert!(response.features[1].compiled_in);
    assert!(!response.features[1].enabled);

    server.shutdown().await;
}

#[tokio::test]
async fn typed_aggregates_round_trip_current_shape_over_stateful_unix_transport() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate");
    server.clear_history();

    let response = client
        .get_aggregates(
            "task&<",
            GetAggregatesRequestOpts {
                filter_string: Some("owner=me & rows=-1".into()),
                data_columns: vec!["qod&<".into()],
                group_column: Some("status&<".into()),
                sorts: vec![AggregateSort {
                    field: "qod&<".into(),
                    statistic: Some(AggregateSortStatistic::Maximum),
                    order: Some(SortOrder::Descending),
                }],
                text_columns: vec!["name&<".into()],
                first_group: Some(1),
                max_groups: Some(-1),
                usage_type: Some(UsageType::Audit),
                ..Default::default()
            },
        )
        .await
        .expect("typed aggregate response should parse");

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let request = String::from_utf8(history[0].raw_xml().to_vec()).expect("request is UTF-8");
    assert_eq!(response.aggregates.len(), 1);
    let aggregate = &response.aggregates[0];
    assert_eq!(
        aggregate.data_type, "task&<",
        "unexpected response for request {request}"
    );
    assert_eq!(aggregate.data_columns, vec!["qod&<".to_string()]);
    assert_eq!(aggregate.group_column.as_deref(), Some("status&<"));
    assert_eq!(aggregate.groups.len(), 2);
    assert_eq!(aggregate.groups[0].count, 3);
    assert_eq!(aggregate.groups[1].c_count, Some(8));
    assert_eq!(aggregate.groups[0].statistics[0].column, "qod&<");
    assert_eq!(aggregate.groups[0].texts[0].column, "name&<");
    assert_eq!(
        response.filter.as_ref().expect("filter metadata").term,
        "owner=me & rows=-1"
    );

    assert_eq!(
        request,
        "<get_aggregates filter=\"owner=me &amp; rows=-1\" first_group=\"1\" \
         group_column=\"status&amp;&lt;\" max_groups=\"-1\" type=\"task&amp;&lt;\" \
         usage_type=\"audit\"><sort field=\"qod&amp;&lt;\" \
         order=\"descending\" stat=\"max\"/><data_column>qod&amp;&lt;</data_column>\
         <text_column>name&amp;&lt;</text_column></get_aggregates>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn legacy_aggregates_round_trip_comma_separated_columns_over_stateful_unix_transport() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate");
    server.clear_history();

    let response = client
        .call(get_aggregates_legacy(
            "task",
            GetAggregatesOpts {
                data_columns: Some("qod, severity".into()),
                text_columns: Some("name, comment".into()),
                ..Default::default()
            },
        ))
        .await
        .expect("legacy aggregate request should succeed");

    let xml = response.as_str().expect("response should be UTF-8");
    for column in ["qod", "severity"] {
        assert!(xml.contains(&format!("<data_column>{column}</data_column>")));
        assert!(xml.contains(&format!("<stats column=\"{column}\">")));
    }
    for column in ["name", "comment"] {
        assert!(xml.contains(&format!("<text_column>{column}</text_column>")));
        assert!(xml.contains(&format!("<text column=\"{column}\">All</text>")));
    }
    assert_eq!(
        server.command_history()[0].raw_xml(),
        br#"<get_aggregates data_columns="qod, severity" text_columns="name, comment" type="task"/>"#
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_word_count_aggregates_parse_current_gvmd_shape_over_unix_transport() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate");
    server.clear_history();

    let response = client
        .get_aggregates(
            "task",
            GetAggregatesRequestOpts {
                group_column: Some("comment".into()),
                mode: Some(AggregateMode::WordCounts),
                ..Default::default()
            },
        )
        .await
        .expect("current gvmd word-count response should parse");

    let aggregate = &response.aggregates[0];
    assert_eq!(aggregate.data_type, "task");
    assert_eq!(aggregate.group_column.as_deref(), Some("comment"));
    assert_eq!(aggregate.groups.len(), 2);
    assert_eq!(aggregate.groups[0].value, "security");
    assert_eq!(aggregate.groups[0].c_count, None);
    assert!(aggregate.groups[0].statistics.is_empty());
    assert!(aggregate.groups[0].texts.is_empty());
    assert_eq!(
        aggregate
            .column_info
            .iter()
            .map(|column| column.name.as_str())
            .collect::<Vec<_>>(),
        vec!["value", "count"]
    );

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].raw_xml(),
        br#"<get_aggregates group_column="comment" mode="word_counts" type="task"/>"#
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_modify_auth_uses_current_gvmd_shape_over_unix_transport() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate");
    server.clear_history();

    let response = client
        .modify_auth(
            "method:ldap_connect",
            &[
                ("enable".into(), "true".into()),
                ("ldaphost".into(), "ldap.example".into()),
            ],
        )
        .await
        .expect("current gvmd modify_auth response should parse");

    assert_eq!(response.status, 200);
    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].raw_xml(),
        br#"<modify_auth><group name="method:ldap_connect"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting><auth_conf_setting><key>ldaphost</key><value>ldap.example</value></auth_conf_setting></group></modify_auth>"#
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_modify_license_uses_current_gvmd_shape_over_unix_transport() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate");
    server.clear_history();

    let response = client
        .modify_license(
            "YWJj",
            ModifyLicenseOpts {
                allow_empty: Some(false),
            },
        )
        .await
        .expect("current gvmd modify_license response should parse");

    assert_eq!(response.status, 200);
    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].raw_xml(),
        br#"<modify_license allow_empty="0"><file>YWJj</file></modify_license>"#
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_run_wizard_uses_current_gvmd_shape_over_unix_transport() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate");
    server.clear_history();

    let response = client
        .run_wizard(
            "quick_first_scan",
            &[("hosts".into(), "localhost".into())],
            RunWizardOpts {
                mode: Some("step".into()),
                read_only: Some(false),
            },
        )
        .await
        .expect("current gvmd run_wizard response should parse");

    assert_eq!(response.status, 202);
    assert_eq!(
        response.response_xml.as_deref(),
        Some(br#"<start_task_response status="202" status_text="OK, request submitted"><report_id>00000000-0000-0000-0000-000000000001</report_id></start_task_response>"#.as_slice())
    );
    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].raw_xml(),
        br#"<run_wizard read_only="0"><mode>step</mode><name>quick_first_scan</name><params><param><name>hosts</name><value>localhost</value></param></params></run_wizard>"#
    );

    server.shutdown().await;
}

#[tokio::test]
async fn unsupported_version_returns_error() {
    let Some(server) = fixture_server_with_version_response("21.4").await else {
        return;
    };
    let connection = unix_connection(&server);

    let error = GmpClient::connect(connection)
        .await
        .expect_err("unsupported version should fail");
    assert!(matches!(error, GvmError::UnsupportedVersion(21, 4)));

    server.shutdown().await;
}

#[tokio::test]
async fn live_wire_trace_observes_typed_helper_with_redaction() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let events = Arc::new(Mutex::new(Vec::new()));
    let trace_events = Arc::clone(&events);

    let mut client = GmpClient::connect_with_wire_trace(connection, move |event| {
        trace_events.lock().expect("trace lock").push(event);
    })
    .await
    .expect("client should connect");

    let response = client
        .authenticate("admin", "admin")
        .await
        .expect("typed authenticate should succeed");
    assert_eq!(response.status, 200);

    assert_eq!(server.command_count(), 2);
    let history = server.command_history();
    assert_eq!(history[0].command_name(), "get_version");
    assert_eq!(history[1].command_name(), "authenticate");
    let raw_auth_request =
        String::from_utf8(history[1].raw_xml().to_vec()).expect("history should be UTF-8");
    assert!(raw_auth_request.contains("<password>admin</password>"));

    {
        let events = events.lock().expect("trace lock");
        assert!(events
            .iter()
            .any(|event| event.direction == WireTraceDirection::Request
                && event_text(event) == "<get_version/>"));
        assert!(events.iter().any(|event| {
            event.direction == WireTraceDirection::Response
                && event_text(event).contains("<get_version_response")
        }));

        let auth_request = events
            .iter()
            .find(|event| {
                event.direction == WireTraceDirection::Request
                    && event_text(event).contains("<authenticate>")
            })
            .map(event_text)
            .expect("authenticate request trace event");
        assert!(auth_request.contains("<password><redacted/></password>"));
        assert!(!auth_request.contains("<password>admin</password>"));

        assert!(events.iter().any(|event| {
            event.direction == WireTraceDirection::Response
                && event_text(event).contains("<authenticate_response")
        }));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn live_wire_trace_redacts_credential_store_preference_values() {
    const CREDENTIAL_STORE_ID: &str = "40000000-0000-4000-8000-000000000001";
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .seed(|store| {
            store.seed(Resource::with_id(
                "credential_store",
                "Trace Store",
                CREDENTIAL_STORE_ID.parse().expect("valid UUID"),
            ));
        })
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("server should start: {error}"),
    };
    let events = Arc::new(Mutex::new(Vec::new()));
    let trace_events = Arc::clone(&events);
    let mut client = GmpClient::connect_with_wire_trace(unix_connection(&server), move |event| {
        trace_events.lock().expect("trace lock").push(event);
    })
    .await
    .expect("client should connect");
    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authentication should succeed");
    server.clear_history();
    events.lock().expect("trace lock").clear();

    client
        .call(modify_credential_store(
            &EntityId::new(CREDENTIAL_STORE_ID).expect("valid ID"),
            ModifyCredentialStoreOpts {
                host: Some("store.example".into()),
                preferences: vec![CredentialStorePreference {
                    name: "token".into(),
                    value: "transport-preference-sentinel".into(),
                }],
                ..Default::default()
            },
        ))
        .await
        .expect("credential store modification should succeed");

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let raw = std::str::from_utf8(history[0].raw_xml()).expect("UTF-8 request");
    assert!(raw.contains("<value>transport-preference-sentinel</value>"));

    let request = {
        let events = events.lock().expect("trace lock");
        events
            .iter()
            .find(|event| {
                event.direction == WireTraceDirection::Request
                    && event_text(event).contains("<modify_credential_store")
            })
            .map(event_text)
            .expect("credential-store request trace")
    };
    assert!(request.contains("<host>store.example</host>"));
    assert!(request.contains("<name>token</name>"));
    assert!(request.contains("<value><redacted/></value>"));
    assert!(!request.contains("transport-preference-sentinel"));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_help_preserves_brief_xml_over_unix_transport() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authentication should succeed");

    let response = client
        .get_help_with_mode(HelpMode::BriefXml)
        .await
        .expect("brief XML help should parse");
    let schema = response.schema.expect("brief help schema");

    assert!(response.help_text.is_empty());
    assert_eq!(schema.format.as_deref(), Some("XML"));
    assert_eq!(schema.commands.len(), 6);
    assert!(schema
        .commands
        .iter()
        .any(|command| command.name == "get_tasks"));

    server.shutdown().await;
}

#[tokio::test]
async fn authenticate_succeeds() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let response = client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    assert_eq!(response.status_code(), Some(200));
    assert_eq!(
        response.root_element_name().as_deref(),
        Some("authenticate_response")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn create_target_and_get_targets_succeed() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let create_response = client
        .call(
            create_target(
                "Integration Target",
                CreateTargetOpts {
                    hosts: vec!["127.0.0.1".to_string()],
                    ..CreateTargetOpts::default()
                },
            )
            .expect("valid target"),
        )
        .await
        .expect("create_target should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    let list_response = client
        .call(get_targets(GetTargetsOpts {
            details: Some(true),
            ..GetTargetsOpts::default()
        }))
        .await
        .expect("get_targets should succeed");
    assert_eq!(list_response.status_code(), Some(200));
    assert!(list_response
        .as_str()
        .expect("valid UTF-8 XML")
        .contains("Integration Target"));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_fixture_targets_use_stateful_observation_vocabulary() {
    let Some(server) = fixture_server(MockVersion::V22_5).await else {
        return;
    };
    let mut client = GmpClient::connect(unix_connection(&server))
        .await
        .expect("client should connect");

    let targets = client
        .get_targets(GetTargetsOpts::default())
        .await
        .expect("fixture targets should parse");
    let target = targets.items.first().expect("fixture target should exist");
    assert_eq!(
        target.alive_tests.as_deref(),
        Some(AliveTest::ScanConfigDefault.as_target_name())
    );
    assert_eq!(target.ssh_credential_port.map(ServicePort::get), Some(22));
    assert_eq!(
        target
            .ssh_credential
            .as_ref()
            .map(|credential| credential.id.as_str()),
        Some("11111111-1111-4111-8111-111111111111")
    );
    assert_eq!(
        target
            .smb_credential
            .as_ref()
            .map(|credential| credential.id.as_str()),
        Some("22222222-2222-4222-8222-222222222222")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn trigger_alert_sends_get_reports_command() {
    let Some(server) = echo_server(MockVersion::V22_4).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let response = client
        .call(trigger_alert(
            &EntityId::new("alert-1").expect("valid id"),
            &EntityId::new("report-1").expect("valid id"),
            TriggerAlertOpts {
                filter_string: Some("severity>5".into()),
                filter_id: Some(EntityId::new("filter-1").expect("valid id")),
                report_format_id: Some(EntityId::new("format-1").expect("valid id")),
                delta_report_id: Some(EntityId::new("delta-1").expect("valid id")),
            },
        ))
        .await
        .expect("trigger_alert should send get_reports command");

    assert_eq!(response.status_code(), Some(200));
    assert_eq!(
        response.root_element_name().as_deref(),
        Some("get_reports_response")
    );

    let history = server.command_history();
    let command = history.last().expect("trigger command recorded");
    assert_eq!(command.command_name(), "get_reports");
    assert_eq!(
        std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command"),
        "<get_reports alert_id=\"alert-1\" delta_report_id=\"delta-1\" filt_id=\"filter-1\" filter=\"severity&gt;5\" format_id=\"format-1\" report_id=\"report-1\"/>"
    );

    server.shutdown().await;
}

fn only_alert(response: &gvm_gmp::responses::GetAlertsResponse) -> &gvm_gmp::responses::Alert {
    assert_eq!(response.items.len(), 1);
    &response.items[0]
}

fn assert_alert_data(
    alert: &gvm_gmp::responses::Alert,
    name: &str,
    event_status: Option<&str>,
    severity: &str,
    to_address: &str,
) {
    assert_eq!(alert.meta.name, name);
    assert_eq!(
        alert.event_data.get("status").map(String::as_str),
        event_status
    );
    assert_eq!(
        alert.condition_data.get("severity").map(String::as_str),
        Some(severity)
    );
    assert_eq!(
        alert.method_data.get("to_address").map(String::as_str),
        Some(to_address)
    );
}

#[tokio::test]
async fn typed_alert_data_maps_and_rename_round_trip() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let created = client
        .create_alert(
            "Typed Alert",
            AlertOpts {
                event: Some(AlertEvent::TaskRunStatusChanged),
                event_data: vec![AlertData::new("status", "Done")],
                condition: Some(AlertCondition::SeverityAtLeast),
                condition_data: vec![AlertData::new("severity", "5.5")],
                method: Some(AlertMethod::Email),
                method_data: vec![AlertData::new("to_address", "ops@example.com")],
                ..Default::default()
            },
        )
        .await
        .expect("create_alert should succeed");

    let fetched = client
        .get_alerts(GetAlertsOpts::default())
        .await
        .expect("get_alerts should succeed");
    let alert = only_alert(&fetched);
    assert_eq!(alert.meta.id, created.id);
    assert_alert_data(alert, "Typed Alert", Some("Done"), "5.5", "ops@example.com");

    client
        .modify_alert(
            &created.id,
            AlertOpts {
                name: Some("Renamed Alert".into()),
                event: Some(AlertEvent::TaskRunStatusChanged),
                event_data: vec![],
                condition: Some(AlertCondition::SeverityAtLeast),
                condition_data: vec![AlertData::new("severity", "7.0")],
                method: Some(AlertMethod::Email),
                method_data: vec![AlertData::new("to_address", "soc@example.com")],
                ..Default::default()
            },
        )
        .await
        .expect("modify_alert should succeed");

    let modified = client
        .get_alerts(GetAlertsOpts::default())
        .await
        .expect("get_alerts after modify should succeed");
    let alert = only_alert(&modified);
    assert_alert_data(alert, "Renamed Alert", None, "7.0", "soc@example.com");

    client
        .modify_alert(
            &created.id,
            AlertOpts {
                comment: Some("data omitted".into()),
                ..Default::default()
            },
        )
        .await
        .expect("partial modify_alert should succeed");
    let partially_modified = client
        .get_alerts(GetAlertsOpts::default())
        .await
        .expect("get_alerts after partial modify should succeed");
    let alert = only_alert(&partially_modified);
    assert_alert_data(alert, "Renamed Alert", None, "7.0", "soc@example.com");

    client
        .modify_alert(
            &created.id,
            AlertOpts {
                method: Some(AlertMethod::Email),
                method_data: vec![AlertData::new("to_address", "nested-name@example.com")],
                ..Default::default()
            },
        )
        .await
        .expect("data-only modify_alert should succeed");
    let data_only_modified = client
        .get_alerts(GetAlertsOpts::default())
        .await
        .expect("get_alerts after data-only modify should succeed");
    let alert = only_alert(&data_only_modified);
    assert_alert_data(
        alert,
        "Renamed Alert",
        None,
        "7.0",
        "nested-name@example.com",
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_ticket_create_read_and_reassign_round_trip() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let result_id = EntityId::new("result-1").expect("valid id");
    let first_assignee = EntityId::new("user-1").expect("valid id");
    let created = client
        .create_ticket(
            &result_id,
            CreateTicketOpts {
                assigned_to: first_assignee.clone(),
                open_note: TicketOpenNote::new("Please investigate").expect("non-empty note"),
                comment: Some("Typed ticket".into()),
            },
        )
        .await
        .expect("create_ticket should succeed");

    let fetched = client
        .get_tickets(GetTicketsOpts::default())
        .await
        .expect("get_tickets should succeed");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(
        fetched.items[0].assigned_to.as_ref().map(|user| &user.id),
        Some(&first_assignee)
    );
    assert_eq!(
        fetched.items[0].result.as_ref().map(|result| &result.id),
        Some(&result_id)
    );
    assert_eq!(
        fetched.items[0].open_note.as_deref(),
        Some("Please investigate")
    );

    let second_assignee = EntityId::new("user-2").expect("valid id");
    client
        .modify_ticket(
            &created.id,
            ModifyTicketOpts {
                assigned_to: Some(second_assignee.clone()),
                status: Some(TicketStatus::Fixed),
                fixed_note: Some("Fixed in update".into()),
                ..Default::default()
            },
        )
        .await
        .expect("modify_ticket should succeed");

    let reassigned = client
        .get_tickets(GetTicketsOpts::default())
        .await
        .expect("get_tickets after reassign should succeed");
    assert_eq!(
        reassigned.items[0]
            .assigned_to
            .as_ref()
            .map(|user| &user.id),
        Some(&second_assignee)
    );
    assert_eq!(reassigned.items[0].status.as_deref(), Some("Fixed"));
    assert_eq!(
        reassigned.items[0].fixed_note.as_deref(),
        Some("Fixed in update")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn operating_system_helpers_send_asset_commands() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let response = client
        .call(get_operating_systems(GetOperatingSystemsOpts {
            filter_string: Some("name=Debian".into()),
            filter_id: Some(EntityId::new("0").expect("valid id")),
            details: Some(true),
        }))
        .await
        .expect("get_operating_systems should send get_assets command");

    assert_eq!(response.status_code(), Some(200));

    let history = server.command_history();
    let command = history.last().expect("operating system command recorded");
    assert_eq!(command.command_name(), "get_assets");
    assert_eq!(
        std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command"),
        "<get_assets details=\"1\" filt_id=\"0\" filter=\"name=Debian\" type=\"os\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_generic_configs_round_trip_through_mock_server() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let config = client
        .create_config(CreateConfigOpts {
            name: "Generic policy".into(),
            base_id: None,
            comment: Some("generic config".into()),
            usage_type: Some(ConfigUsageType::Policy),
        })
        .await
        .expect("generic config create should parse");
    let custom_config = client
        .create_config(CreateConfigOpts {
            name: "Future config".into(),
            base_id: None,
            comment: None,
            usage_type: Some(ConfigUsageType::custom("future")),
        })
        .await
        .expect("custom config create should parse");

    let configs = client
        .get_configs(GetConfigsOpts::default())
        .await
        .expect("generic configs should parse");
    assert!(configs
        .items
        .iter()
        .any(|item| item.meta.id == config.id && item.usage_type == Some(ConfigUsageKind::Policy)));
    assert!(configs.items.iter().any(|item| {
        item.meta.id == custom_config.id
            && item.usage_type == Some(ConfigUsageKind::Custom("future".into()))
    }));

    let cloned = client
        .clone_config(
            &config.id,
            CloneConfigOpts {
                name: Some("Generic policy copy".into()),
            },
        )
        .await
        .expect("generic config clone should parse");
    assert_ne!(cloned.id, config.id);

    server.shutdown().await;
}

fn assert_single_generic_config(
    response: &GetConfigsResponse,
    id: &EntityId,
    name: &str,
    comment: &str,
    usage_type: ConfigUsageKind,
) {
    assert_eq!(response.items.len(), 1);
    assert_eq!(&response.items[0].meta.id, id);
    assert_eq!(response.items[0].meta.name, name);
    assert_eq!(response.items[0].meta.comment.as_deref(), Some(comment));
    assert_eq!(response.items[0].usage_type, Some(usage_type));
}

#[tokio::test]
async fn typed_generic_config_get_modify_and_delete_round_trip() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let config = client
        .create_config(CreateConfigOpts {
            name: "Mutable policy".into(),
            base_id: None,
            comment: Some("before modification".into()),
            usage_type: Some(ConfigUsageType::Policy),
        })
        .await
        .expect("generic config create should parse");

    let fetched = client
        .get_config(&config.id, GetConfigOpts::default())
        .await
        .expect("single generic config should parse");
    assert_single_generic_config(
        &fetched,
        &config.id,
        "Mutable policy",
        "before modification",
        ConfigUsageKind::Policy,
    );

    client
        .modify_config(
            &config.id,
            ModifyConfigOpts {
                name: Some("Updated policy".into()),
                comment: Some("after modification".into()),
                usage_type: Some(ConfigUsageType::Audit),
            },
        )
        .await
        .expect("generic config modify should parse");

    let updated = client
        .get_config(
            &config.id,
            GetConfigOpts {
                usage_type: Some(ConfigUsageType::Audit),
                ..Default::default()
            },
        )
        .await
        .expect("modified generic config should parse");
    assert_single_generic_config(
        &updated,
        &config.id,
        "Updated policy",
        "after modification",
        ConfigUsageKind::Audit,
    );

    client
        .delete_config(&config.id, DeleteConfigOpts::default())
        .await
        .expect("generic config trash should parse");
    let trashed = client
        .get_configs(GetConfigsOpts {
            trash: Some(true),
            ..Default::default()
        })
        .await
        .expect("trashed generic configs should parse");
    assert!(trashed.items.iter().any(|item| item.meta.id == config.id));

    client
        .delete_config(
            &config.id,
            DeleteConfigOpts {
                ultimate: Some(true),
            },
        )
        .await
        .expect("ultimate generic config deletion should parse");
    let remaining = client
        .get_configs(GetConfigsOpts {
            trash: Some(true),
            ..Default::default()
        })
        .await
        .expect("trash listing after ultimate deletion should parse");
    assert!(remaining.items.iter().all(|item| item.meta.id != config.id));

    server.shutdown().await;
}

async fn typed_host_asset_lifecycle(client: &mut GmpClient<UnixSocketConnection>) {
    let mut create_opts = CreateAssetOpts::host("192.0.2.10");
    create_opts.comment = Some("created through typed client".into());
    let created = client
        .create_asset(create_opts)
        .await
        .expect("create_asset should succeed");
    let asset_id = created
        .id
        .expect("direct host creation should return an id");

    let fetched = client
        .get_asset(&asset_id, AssetType::Host)
        .await
        .expect("get_asset should return the created host");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.counts.total, Some(1));
    assert_eq!(fetched.counts.filtered, Some(1));
    assert_eq!(fetched.counts.page, Some(1));
    let Asset::Host(host) = &fetched.items[0] else {
        panic!("created asset should be a host");
    };
    assert_eq!(host.meta.id, asset_id);
    assert_eq!(host.meta.name, "192.0.2.10");
    assert_eq!(
        host.meta.comment.as_deref(),
        Some("created through typed client")
    );

    client
        .modify_asset(
            &asset_id,
            ModifyAssetOpts {
                comment: Some("updated through typed client".into()),
                ..Default::default()
            },
        )
        .await
        .expect("modify_asset should succeed");

    let updated = client
        .get_assets(GetAssetsOpts {
            asset_id: Some(asset_id.clone()),
            type_: Some(AssetType::Host),
            ..Default::default()
        })
        .await
        .expect("get_assets should return the updated host");
    let Asset::Host(host) = &updated.items[0] else {
        panic!("updated asset should be a host");
    };
    assert_eq!(
        host.meta.comment.as_deref(),
        Some("updated through typed client")
    );

    client
        .modify_asset(&asset_id, ModifyAssetOpts::default())
        .await
        .expect("modify_asset without a comment should clear it");
    let cleared = client
        .get_assets(GetAssetsOpts {
            asset_id: Some(asset_id.clone()),
            type_: Some(AssetType::Host),
            ..Default::default()
        })
        .await
        .expect("get_assets should return the host with a cleared comment");
    let Asset::Host(host) = &cleared.items[0] else {
        panic!("cleared asset should be a host");
    };
    assert_eq!(host.meta.comment, None);

    client
        .delete_asset(&asset_id, DeleteAssetOpts::default())
        .await
        .expect("delete_asset should succeed");
    let remaining = client
        .get_assets(GetAssetsOpts {
            type_: Some(AssetType::Host),
            ..Default::default()
        })
        .await
        .expect("get_assets should succeed after deletion");
    assert!(remaining.items.is_empty());
    assert_eq!(remaining.counts.total, Some(0));
    assert_eq!(remaining.counts.filtered, Some(0));
    assert_eq!(remaining.counts.page, Some(0));
}

async fn typed_operating_system_get(client: &mut GmpClient<UnixSocketConnection>) {
    let operating_systems = client
        .get_operating_system_assets(GetOperatingSystemsOpts::default())
        .await
        .expect("typed operating-system assets should parse");
    assert_eq!(operating_systems.items.len(), 1);
    let operating_system = &operating_systems.items[0];
    assert_eq!(operating_system.title, "Example Linux");
    assert_eq!(operating_system.installs, 0);
    assert_eq!(operating_system.all_installs, 0);
    assert_eq!(operating_system.host_count, 0);
    assert!(operating_system.hosts.is_empty());
    assert_eq!(operating_system.latest_severity.as_deref(), Some("6.1"));

    let single = client
        .get_operating_system_asset(&operating_system.meta.id, Some(true))
        .await
        .expect("single operating-system asset should parse");
    assert_eq!(single.items.len(), 1);
    assert_eq!(single.items[0].meta.id, operating_system.meta.id);
}

#[tokio::test]
async fn typed_asset_helpers_cover_host_lifecycle_over_unix_transport() {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_5)
        .unix_socket_auto()
        .seed(|store| {
            let mut operating_system = Resource::new("asset", "cpe:/o:example:linux");
            operating_system.set_attr("type", "os");
            operating_system.set_attr("title", "Example Linux");
            operating_system.set_attr("installs", "0");
            operating_system.set_attr("all_installs", "0");
            operating_system.set_attr("latest_severity", "6.1");
            operating_system.set_attr("highest_severity", "9.8");
            operating_system.set_attr("average_severity", "7.95");
            store.seed(operating_system);
        })
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("server should start: {error}"),
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    typed_host_asset_lifecycle(&mut client).await;
    typed_operating_system_get(&mut client).await;

    server.shutdown().await;
}

#[tokio::test]
async fn get_feed_sends_typed_get_feeds_command() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let response = client
        .get_feed(FeedType::Nvt)
        .await
        .expect("get_feed should return typed feed data");

    assert_eq!(response.status, 200);
    assert!(response.feed_owner_set);
    assert!(response.feed_roles_set);
    assert!(response.feed_resources_access);
    assert_eq!(response.items.len(), 1);
    assert_eq!(response.items[0].type_, "NVT");
    assert_eq!(response.items[0].status, None);
    assert_eq!(response.counts, Default::default());

    let history = server.command_history();
    let command = history.last().expect("feed command recorded");
    assert_eq!(command.command_name(), "get_feeds");
    assert_eq!(
        std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command"),
        "<get_feeds type=\"NVT\"/>"
    );

    let all = client
        .get_feeds()
        .await
        .expect("all feeds should return typed data");
    assert_eq!(all.items.len(), 4);
    let scap = all
        .items
        .iter()
        .find(|feed| feed.type_ == "SCAP")
        .expect("SCAP feed");
    assert_eq!(
        scap.currently_syncing.as_deref(),
        Some("2026-03-18T00:00:00Z")
    );
    let cert = all
        .items
        .iter()
        .find(|feed| feed.type_ == "CERT")
        .expect("CERT feed");
    assert_eq!(
        cert.sync_not_available.as_deref(),
        Some("Feed synchronization is unavailable")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_system_reports_preserve_wire_options_and_payload_metadata() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let response = client
        .get_system_reports(GetSystemReportsOpts {
            name: Some("load".into()),
            duration: Some(3600),
            ..Default::default()
        })
        .await
        .expect("system report should parse");

    assert_eq!(response.reports.len(), 1);
    let report = &response.reports[0];
    assert_eq!(report.name, "load");
    assert_eq!(report.title.as_deref(), Some("System Load"));
    assert_eq!(report.report_format.as_deref(), Some("png"));
    assert_eq!(report.report_duration, Some(3600));
    assert!(report.report.is_some());

    let history = server.command_history();
    let command = history.last().expect("system-report command recorded");
    assert_eq!(command.command_name(), "get_system_reports");
    assert_eq!(
        std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command"),
        "<get_system_reports duration=\"3600\" name=\"load\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn server_error_maps_to_gvm_error() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let error = client
        .call(b"<get_targets/>".as_slice())
        .await
        .expect_err("unauthenticated request should fail");

    match error {
        GvmError::Server { status, message } => {
            assert_eq!(status, 401);
            assert_eq!(message, "Not authenticated");
        }
        other => panic!("expected server error, got {other:?}"),
    }

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_enum_returns_v225_for_default_mock_server() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);

    let client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    assert!(matches!(client, GmpVersioned::V225(_)));
    assert_eq!(client.version(), GmpVersion(22, 5));

    server.shutdown().await;
}

#[tokio::test]
async fn unsupported_next_command_rejected_before_send() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_7).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let error = client
        .call(get_report_hosts(
            &EntityId::new("report-1").expect("valid id"),
            Default::default(),
        ))
        .await
        .expect_err("22.7 should reject next-only command");

    match error {
        GvmError::UnsupportedCommand {
            command,
            version,
            required,
        } => {
            assert_eq!(command, "get_report_hosts");
            assert_eq!(version, GmpVersion(22, 7));
            assert_eq!(required, "22.8");
        }
        other => panic!("expected unsupported command error, got {other:?}"),
    }

    let error = client
        .call(get_report_vulnerabilities(
            &EntityId::new("report-1").expect("valid id"),
            Default::default(),
        ))
        .await
        .expect_err("22.7 should reject report vulnerabilities alias");
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8"
        } if command == "get_report_vulns"
    ));

    let error = client
        .call(get_timezones())
        .await
        .expect_err("22.7 should reject get_timezones");
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8"
        } if command == "get_timezones"
    ));

    let error = client
        .call(get_report_export(
            &EntityId::new("report-1").expect("valid id"),
            &EntityId::new("format-1").expect("valid id"),
        ))
        .await
        .expect_err("22.7 should reject the report export semantic operation");
    assert_unsupported_next_command(error, "get_report_export");

    server.shutdown().await;
}

#[tokio::test]
async fn credential_store_commands_are_rejected_before_v22_8() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_7).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let credential_store_id = EntityId::new("credential-store-1").expect("valid id");
    let error = client
        .verify_credential_store(&credential_store_id)
        .await
        .expect_err("22.7 should reject typed credential store verification");
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8"
        } if command == "verify_credential_store"
    ));

    let error = client
        .call(create_credential_store_credential(
            "Rejected Store Credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts::default(),
        ))
        .await
        .expect_err("22.7 should reject raw credential store credential create");
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8"
        } if command == "create_credential_store_credential"
    ));

    let error = client
        .create_credential_store_credential(
            "Rejected Typed Store Credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts::default(),
        )
        .await
        .expect_err("22.7 should reject typed credential store credential create");
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8"
        } if command == "create_credential_store_credential"
    ));

    assert_credential_store_credential_modify_rejected_before_next(&mut client).await;

    server.shutdown().await;
}

async fn assert_credential_store_credential_modify_rejected_before_next(
    client: &mut GmpClient<UnixSocketConnection>,
) {
    let credential_id = EntityId::new("credential-1").expect("valid id");
    for opts in [
        GmpModifyCredentialStoreCredentialOpts::default(),
        GmpModifyCredentialStoreCredentialOpts {
            vault_id: Some("vault-1".into()),
            ..Default::default()
        },
    ] {
        let error = client
            .call(modify_credential_store_credential(&credential_id, opts))
            .await
            .expect_err("22.7 should reject raw credential store credential modify");
        assert_unsupported_next_command(error, "modify_credential_store_credential");
    }

    let error = client
        .modify_credential_store_credential(
            &credential_id,
            ModifyCredentialStoreCredentialOpts::default(),
        )
        .await
        .expect_err("22.7 should reject typed credential store credential modify");
    assert_unsupported_next_command(error, "modify_credential_store_credential");
}

fn assert_unsupported_next_command(error: GvmError, expected_command: &str) {
    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8"
        } if command == expected_command
    ));
}

#[tokio::test]
async fn next_commands_work_on_v22_8() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let integration_config_id =
        EntityId::new("00000000-0000-0000-0000-000000000100").expect("valid id");
    let get_response = client
        .get_integration_config(&integration_config_id, Some(true))
        .await
        .expect("get_integration_config should succeed");
    assert_eq!(get_response.status_code(), Some(200));

    let list_response = client
        .get_integration_configs(Default::default())
        .await
        .expect("get_integration_configs should succeed");
    assert_eq!(list_response.status_code(), Some(200));

    let modify_response = client
        .modify_integration_config(
            &integration_config_id,
            gvm_client::ModifyIntegrationConfigOpts {
                service_url: Some("https://updated.example".into()),
                service_cacert: Some("UPDATED-CA".into()),
                oidc_provider_url: Some("https://updated-oidc.example".into()),
                oidc_provider_client_id: Some("updated-client".into()),
                oidc_provider_client_secret: Some("updated-secret".into()),
            },
        )
        .await
        .expect("modify_integration_config should succeed");
    assert_eq!(modify_response.status_code(), Some(200));

    let report_id = EntityId::new("00000000-0000-0000-0000-000000000200").expect("valid id");
    let helper_error = client
        .get_report_hosts(&report_id, Default::default())
        .await
        .expect_err("missing report should return server error");
    assert!(matches!(helper_error, GvmError::Server { status: 404, .. }));

    let alias_error = client
        .get_report_vulnerabilities(&report_id, Default::default())
        .await
        .expect_err("missing report should return server error through alias");
    assert!(matches!(alias_error, GvmError::Server { status: 404, .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_integration_configs_round_trip_over_unix_transport() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let integration_config_id =
        EntityId::new("00000000-0000-0000-0000-000000000100").expect("valid id");
    let get_response = client
        .get_integration_config_parsed(&integration_config_id, Some(true))
        .await
        .expect("detailed integration config should parse");
    assert_eq!(get_response.items.len(), 1);
    assert_eq!(
        get_response.items[0]
            .service
            .as_ref()
            .map(|service| service.url.as_str()),
        Some("https://service.example.invalid")
    );
    assert_eq!(
        get_response.items[0]
            .oidc
            .as_ref()
            .map(|oidc| oidc.client_id.as_str()),
        Some("mock-client-id")
    );

    let list_response = client
        .get_integration_configs_parsed(Default::default())
        .await
        .expect("integration config list should parse");
    assert_eq!(list_response.counts.total, Some(1));
    assert!(list_response.items[0].service.is_none());
    assert!(list_response.items[0].oidc.is_none());

    let modify_response = client
        .modify_integration_config_parsed(
            &integration_config_id,
            gvm_client::ModifyIntegrationConfigOpts {
                service_url: Some("https://typed.example".into()),
                service_cacert: Some("TYPED-CA".into()),
                oidc_provider_url: Some("https://typed-oidc.example".into()),
                oidc_provider_client_id: Some("typed-client".into()),
                oidc_provider_client_secret: Some("typed-secret".into()),
            },
        )
        .await
        .expect("typed modify response should parse");
    assert_eq!(modify_response.status, 200);

    server.shutdown().await;
}

#[tokio::test]
async fn typed_rest_support_gap_helpers_parse_fixture_responses() {
    let Some(server) = fixture_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let report_id = EntityId::new("report-1").expect("valid id");

    let vulns = client
        .get_report_vulns(&report_id, Default::default())
        .await
        .expect("report vulns should parse");
    assert_eq!(vulns.items.len(), 1);
    assert_eq!(vulns.items[0].severity.as_deref(), Some("5.0"));
    assert_eq!(
        vulns.items[0].nvt_oid.as_deref(),
        Some("1.3.6.1.4.1.25623.1.0.117761")
    );
    assert_eq!(vulns.items[0].cves, vec!["CVE-2011-1473", "CVE-2011-5094"]);
    assert_eq!(vulns.items[0].hosts_count, Some(2));
    assert_eq!(vulns.items[0].occurrences, Some(3));

    let vulnerabilities = client
        .get_report_vulnerabilities(&report_id, Default::default())
        .await
        .expect("report vulnerabilities alias should parse");
    assert_eq!(vulnerabilities.items.len(), 1);
    assert_eq!(vulnerabilities.items[0].threat.as_deref(), Some("Medium"));

    let tls = client
        .get_report_tls_certificates(&report_id, Default::default())
        .await
        .expect("report tls certs should parse");
    assert_eq!(tls.items[0].issuer.as_deref(), Some("CN=Example CA"));

    let errors = client
        .get_report_errors(&report_id, Default::default())
        .await
        .expect("report errors should parse");
    assert_eq!(errors.items[0].nvt_name.as_deref(), Some("Ping Host"));

    let closed_cves = client
        .get_report_closed_cves(&report_id, Default::default())
        .await
        .expect("closed cves should parse");
    assert_eq!(closed_cves.items[0].cve.as_deref(), Some("CVE-2025-9999"));
    assert_eq!(
        closed_cves.items[0].nvt_oid.as_deref(),
        Some("1.3.6.1.4.1.25623.1.0.100000")
    );
    assert_eq!(
        closed_cves.items[0].name.as_deref(),
        Some("Closed vulnerability check")
    );
    assert_eq!(closed_cves.items[0].threat.as_deref(), Some("Medium"));

    let timezones = client
        .get_timezones()
        .await
        .expect("timezones should parse");
    assert!(timezones
        .items
        .iter()
        .any(|timezone| timezone.name == "UTC"));

    server.clear_history();

    let stores = client
        .get_credential_stores()
        .await
        .expect("credential stores should parse");
    assert_eq!(stores.items[0].name, "Local credential store");

    let store_id = EntityId::new("local").expect("valid id");
    let store = client
        .get_credential_store(&store_id, Some(true))
        .await
        .expect("credential store should parse");
    assert_eq!(store.items[0].name, "Local credential store");

    let filtered_stores = client
        .get_credential_stores_with_opts(GetCredentialStoresOpts {
            filter_string: Some("name=Local".into()),
            filter_id: Some(EntityId::new("filter-1").expect("valid id")),
            details: Some(false),
        })
        .await
        .expect("filtered credential stores should parse");
    assert_eq!(filtered_stores.items[0].name, "Local credential store");

    let history = server.command_history();
    assert_eq!(history.len(), 3);
    assert!(history
        .iter()
        .all(|record| record.command_name() == "get_credential_stores"));
    let commands = history
        .iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("xml is utf-8"))
        .collect::<Vec<_>>();
    assert_eq!(commands[0], "<get_credential_stores/>");
    assert_eq!(
        commands[1],
        "<get_credential_stores details=\"1\"><credential_store_id>local</credential_store_id></get_credential_stores>"
    );
    assert_eq!(
        commands[2],
        "<get_credential_stores details=\"0\" filt_id=\"filter-1\" filter=\"name=Local\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_port_list_and_user_renames_round_trip() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authentication should succeed");

    let port_list = client
        .create_port_list("Old Port List", PortListOpts::default())
        .await
        .expect("port list creation should succeed");
    client
        .modify_port_list(
            &port_list.id,
            ModifyPortListOpts {
                name: Some("Renamed Port List".into()),
                comment: Some("renamed through typed client".into()),
                ..Default::default()
            },
        )
        .await
        .expect("port list rename should succeed");
    let port_lists = client
        .get_port_lists(GetPortListsOpts::default())
        .await
        .expect("port list read-back should succeed");
    let renamed_port_list = port_lists
        .items
        .iter()
        .find(|item| item.meta.id == port_list.id)
        .expect("renamed port list should be present");
    assert_eq!(renamed_port_list.meta.name, "Renamed Port List");
    assert_eq!(
        renamed_port_list.meta.comment.as_deref(),
        Some("renamed through typed client")
    );

    let user = client
        .create_user("old-user", UserOpts::default())
        .await
        .expect("user creation should succeed");
    client
        .modify_user(
            &user.id,
            ModifyUserOpts {
                new_name: Some("renamed-user".into()),
                comment: Some("renamed through typed client".into()),
                ..Default::default()
            },
        )
        .await
        .expect("user rename should succeed");
    let users = client
        .get_users(GetUsersOpts::default())
        .await
        .expect("user read-back should succeed");
    let renamed_user = users
        .items
        .iter()
        .find(|item| item.meta.id == user.id)
        .expect("renamed user should be present");
    assert_eq!(renamed_user.meta.name, "renamed-user");
    assert_eq!(
        renamed_user.meta.comment.as_deref(),
        Some("renamed through typed client")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_ssh_credential_lifecycle_uses_nested_key_shape() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let credential = client
        .create_credential(
            "SSH Credential",
            CredentialOpts {
                credential_type: Some(CredentialType::UsernameSshKey),
                login: Some("root".into()),
                private_key: Some("PRIVATE KEY".into()),
                key_phrase: Some("key phrase".into()),
                ..Default::default()
            },
        )
        .await
        .expect("SSH credential should be created");
    client
        .modify_credential(
            &credential.id,
            ModifyCredentialOpts {
                name: Some("Renamed SSH Credential".into()),
                login: Some("scanner".into()),
                private_key: Some("UPDATED PRIVATE KEY".into()),
                key_phrase: Some("updated phrase".into()),
                allow_insecure: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("SSH credential should be modified");
    let username_password = client
        .create_credential(
            "Username Password Credential",
            CredentialOpts {
                credential_type: Some(CredentialType::UsernamePassword),
                login: Some("operator".into()),
                password: Some("secret".into()),
                ..Default::default()
            },
        )
        .await
        .expect("username/password credential should be created");

    let credentials = client
        .get_credentials(Default::default())
        .await
        .expect("credentials should be retrieved");
    let fetched = credentials
        .items
        .iter()
        .find(|item| item.meta.id == credential.id)
        .expect("SSH credential should be listed");
    assert_eq!(fetched.meta.name, "Renamed SSH Credential");
    assert_eq!(fetched.type_.as_deref(), Some("usk"));
    assert_eq!(fetched.kind, CredentialKind::UsernameSshKey);
    assert_eq!(fetched.login.as_deref(), Some("scanner"));
    assert!(fetched.allow_insecure);
    let username_password = credentials
        .items
        .iter()
        .find(|item| item.meta.id == username_password.id)
        .expect("username/password credential should be listed");
    assert_eq!(username_password.kind, CredentialKind::UsernamePassword);

    let history = server.command_history();
    let create_xml = std::str::from_utf8(history[0].raw_xml()).expect("create XML");
    assert!(
        create_xml.contains("<key><phrase>key phrase</phrase><private>PRIVATE KEY</private></key>")
    );
    assert!(!create_xml.contains("<private_key>"));
    let modify_xml = std::str::from_utf8(history[1].raw_xml()).expect("modify XML");
    assert!(modify_xml.contains("<name>Renamed SSH Credential</name>"));
    assert!(modify_xml.contains(
        "<key><phrase>updated phrase</phrase><private>UPDATED PRIVATE KEY</private></key>"
    ));
    assert!(modify_xml.contains("<allow_insecure>1</allow_insecure>"));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_snmpv3_and_kerberos_credentials_use_current_wire_shapes() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let snmp = client
        .create_credential(
            "SNMPv3 Credential",
            CredentialOpts {
                credential_type: Some(CredentialType::SnmpV3),
                login: Some("snmp-user".into()),
                password: Some("auth secret".into()),
                auth_algorithm: Some(SnmpAuthAlgorithm::Sha1),
                privacy_password: Some("privacy secret".into()),
                privacy_algorithm: Some(SnmpPrivacyAlgorithm::Aes),
                ..Default::default()
            },
        )
        .await
        .expect("SNMPv3 credential should be created");
    let kerberos = client
        .create_credential(
            "Kerberos Credential",
            CredentialOpts {
                credential_type: Some(CredentialType::Kerberos5),
                login: Some("principal".into()),
                password: Some("kerberos secret".into()),
                kdcs: vec!["kdc1.example".into(), "kdc2.example".into()],
                realm: Some("EXAMPLE.COM".into()),
                ..Default::default()
            },
        )
        .await
        .expect("Kerberos credential should be created");

    let credentials = client
        .get_credentials(Default::default())
        .await
        .expect("credentials should be retrieved");
    let snmp = credentials
        .items
        .iter()
        .find(|item| item.meta.id == snmp.id)
        .expect("SNMPv3 credential should be listed");
    let kerberos = credentials
        .items
        .iter()
        .find(|item| item.meta.id == kerberos.id)
        .expect("Kerberos credential should be listed");
    assert_eq!(snmp.type_.as_deref(), Some("snmp"));
    assert_eq!(kerberos.type_.as_deref(), Some("krb5"));
    assert_eq!(snmp.kind, CredentialKind::Snmp);
    assert_eq!(kerberos.kind, CredentialKind::Kerberos5);

    let history = server.command_history();
    let snmp_xml = std::str::from_utf8(history[0].raw_xml()).expect("SNMP XML");
    assert!(snmp_xml.contains("<type>snmp</type>"));
    assert!(snmp_xml.contains(
        "<privacy><algorithm>aes</algorithm><password>privacy secret</password></privacy>"
    ));
    assert!(!snmp_xml.contains("<privacy_algorithm>"));
    let kerberos_xml = std::str::from_utf8(history[1].raw_xml()).expect("Kerberos XML");
    assert!(kerberos_xml.contains("<kdcs><kdc>kdc1.example</kdc><kdc>kdc2.example</kdc></kdcs>"));
    assert!(kerberos_xml.contains("<realm>EXAMPLE.COM</realm>"));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_verify_credential_store_uses_next_command_shape() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let credential_store_id = EntityId::new("credential-store-1").expect("valid id");
    let response = client
        .verify_credential_store(&credential_store_id)
        .await
        .expect("verify_credential_store should parse");
    assert_eq!(response.status, 200);

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "verify_credential_store");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("valid UTF-8 command"),
        "<verify_credential_store credential_store_id=\"credential-store-1\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_create_credential_store_credential_uses_next_shape() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    server.clear_history();

    let response = client
        .create_credential_store_credential(
            "Typed Store Credential",
            CredentialStoreCredentialType::PasswordOnly,
            "vault-typed",
            "host-typed",
            CredentialStoreCredentialOpts {
                comment: Some("typed store credential".into()),
                credential_store_id: Some(
                    EntityId::new("credential-store-typed").expect("valid id"),
                ),
            },
        )
        .await
        .expect("typed create should succeed");
    assert_eq!(response.status, 201);

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create command recorded");
    assert_eq!(command.command_name(), "create_credential");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("valid utf8");
    assert_eq!(
        raw_xml,
        "<create_credential><name>Typed Store Credential</name><type>cs_pw</type><comment>typed store credential</comment><credential_store_id>credential-store-typed</credential_store_id><vault_id>vault-typed</vault_id><host_identifier>host-typed</host_identifier></create_credential>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_modify_credential_store_credential_uses_next_shape() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let credential = client
        .create_credential("Stored Credential", Default::default())
        .await
        .expect("create credential should succeed");

    server.clear_history();

    let response = client
        .modify_credential_store_credential(
            &credential.id,
            ModifyCredentialStoreCredentialOpts {
                name: Some("Updated Store Credential".into()),
                comment: Some("from credential store".into()),
                credential_store_id: Some(EntityId::new("credential-store-1").expect("valid id")),
                vault_id: Some("vault-1".into()),
                host_identifier: Some("host-1".into()),
            },
        )
        .await
        .expect("typed modify should succeed");
    assert_eq!(response.status, 200);

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("modify command recorded");
    assert_eq!(command.command_name(), "modify_credential");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("valid utf8");
    assert_eq!(
        raw_xml,
        format!(
            "<modify_credential credential_id=\"{}\"><name>Updated Store Credential</name><comment>from credential store</comment><credential_store_id>credential-store-1</credential_store_id><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></modify_credential>",
            credential.id.as_str()
        )
    );

    let get = client
        .call(get_credential(&credential.id))
        .await
        .expect("get modified credential should succeed");
    let xml = get.as_str().expect("utf8 response");
    assert!(xml.contains("Updated Store Credential"));
    assert!(xml.contains("<comment>from credential store</comment>"));
    assert!(xml.contains("<credential_store_id>credential-store-1</credential_store_id>"));
    assert!(xml.contains("<vault_id>vault-1</vault_id>"));
    assert!(xml.contains("<host_identifier>host-1</host_identifier>"));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_secinfo_singular_helpers_fetch_one_entry() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let cve = client
        .get_cve("CVE-2026-1000")
        .await
        .expect("single CVE should parse");
    assert_eq!(cve.items.len(), 1);
    assert_eq!(cve.items[0].id, "CVE-2026-1000");
    assert_eq!(cve.items[0].name, "Mock CVE one");
    assert_eq!(cve.counts.total, Some(1));

    let cpe = client
        .get_cpe("cpe:/a:greenbone:gvm")
        .await
        .expect("single CPE should parse");
    assert_eq!(cpe.items.len(), 1);
    assert_eq!(cpe.items[0].id, "cpe:/a:greenbone:gvm");
    assert_eq!(cpe.items[0].name, "Greenbone GVM");

    let cert = client
        .get_cert_bund_advisory("CB-K26/001")
        .await
        .expect("single CERT-Bund advisory should parse");
    assert_eq!(cert.items.len(), 1);
    assert_eq!(cert.items[0].id, "CB-K26/001");

    let dfn = client
        .get_dfn_cert_advisory("DFN-2026-001")
        .await
        .expect("single DFN-CERT advisory should parse");
    assert_eq!(dfn.items.len(), 1);
    assert_eq!(dfn.items[0].id, "DFN-2026-001");

    server.shutdown().await;
}

#[tokio::test]
async fn typed_vulnerability_helpers_parse_stateful_mock_response() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    server.clear_history();

    let vulnerabilities = client
        .get_vulnerabilities(Default::default())
        .await
        .expect("vulnerabilities should parse");
    assert_eq!(vulnerabilities.items.len(), 2);
    assert_eq!(vulnerabilities.items[0].id, "vuln-1");

    let vulnerability = client
        .get_vulnerability("vuln-1")
        .await
        .expect("single vulnerability should parse");
    assert_eq!(vulnerability.items.len(), 1);
    assert_eq!(vulnerability.items[0].id, "vuln-1");
    assert_eq!(vulnerability.items[0].name, "Outdated package");
    assert_eq!(vulnerability.counts.total, Some(1));

    let history = server.command_history();
    assert_eq!(history.len(), 2);
    let commands = history
        .iter()
        .map(|command| {
            String::from_utf8(command.raw_xml().to_vec()).expect("history should be UTF-8")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        ["<get_vulns/>", "<get_vulns vuln_id=\"vuln-1\"/>",]
    );

    server.shutdown().await;
}

#[tokio::test]
async fn generic_secinfo_helpers_use_stateful_mock_server_path() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    server.clear_history();

    let nvt = client
        .call(get_info_list(
            GenericInfoType::Nvt,
            GetInfoListOpts {
                filter: Some("family=General".into()),
                filter_id: Some("filter-1".into()),
                name: Some("Mock NVT one".into()),
                details: Some(false),
            },
        ))
        .await
        .expect("NVT secinfo list should succeed");
    let text = nvt.as_str().expect("response should be UTF-8");
    assert!(text.contains("<nvt id=\"1.3.6.1.4.1.25623.1\">"));
    assert!(text.contains("Mock NVT one"));
    assert!(text.contains("<nvt_count>1<filtered>1</filtered></nvt_count>"));
    assert!(!text.contains("Mock NVT two"));

    let oval = client
        .call(get_info("oval:org.example:def:1", GenericInfoType::Ovaldef))
        .await
        .expect("OVALDEF secinfo lookup should succeed");
    let text = oval.as_str().expect("response should be UTF-8");
    assert!(text.contains("<ovaldef id=\"oval:org.example:def:1\">"));
    assert!(text.contains("Mock OVAL definition one"));
    assert!(text.contains("<ovaldef_count>1<filtered>1</filtered></ovaldef_count>"));

    let history = server.command_history();
    assert_eq!(history.len(), 2);
    let commands = history
        .iter()
        .map(|command| {
            String::from_utf8(command.raw_xml().to_vec()).expect("history should be UTF-8")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        commands,
        [
            "<get_info details=\"0\" filt_id=\"filter-1\" filter=\"family=General\" name=\"Mock NVT one\" type=\"NVT\"/>",
            "<get_info details=\"1\" info_id=\"oval:org.example:def:1\" type=\"OVALDEF\"/>",
        ]
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_scan_config_field_helpers_modify_stateful_mock_resource() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let created = client
        .create_scan_config(
            "Original config",
            None,
            ConfigOpts {
                comment: Some("initial comment".into()),
                usage_type: Some("scan".into()),
            },
        )
        .await
        .expect("scan config should be created");

    let fetched = client
        .get_scan_config(&created.id)
        .await
        .expect("created scan config should be fetched");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.items[0].meta.name, "Original config");
    assert_eq!(
        fetched.items[0].meta.comment.as_deref(),
        Some("initial comment")
    );

    client
        .modify_scan_config_set_name(&created.id, "Renamed config")
        .await
        .expect("scan config name should be modified");
    client
        .modify_scan_config_set_comment(&created.id, None)
        .await
        .expect("scan config comment should be cleared");

    let fetched = client
        .get_scan_config(&created.id)
        .await
        .expect("scan config should be fetched");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.items[0].meta.name, "Renamed config");
    assert_eq!(fetched.items[0].meta.comment, None);

    let response = client
        .send(create_policy(
            "Original policy",
            ConfigOpts {
                comment: Some("initial policy comment".into()),
                ..Default::default()
            },
        ))
        .await
        .expect("policy create request should succeed");
    let policy = CreateScanConfigResponse::from_response(&response).expect("policy create parses");

    client
        .modify_policy_set_name(&policy.id, "Renamed policy")
        .await
        .expect("policy name should be modified");
    client
        .modify_policy_set_comment(&policy.id, None)
        .await
        .expect("policy comment should be cleared");

    let response = client
        .send(get_policies(GetScanConfigsOpts::default()))
        .await
        .expect("policies should be fetched");
    let policies = GetScanConfigsResponse::from_response(&response).expect("policies parse");
    let policy = policies
        .items
        .iter()
        .find(|item| item.meta.id == policy.id)
        .expect("modified policy should be returned");
    assert_eq!(policy.meta.name, "Renamed policy");
    assert_eq!(policy.meta.comment, None);

    server.shutdown().await;
}

#[tokio::test]
async fn preference_getters_send_expected_mock_server_commands() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let responses = [
        client
            .call(get_scan_config_preferences(GetScanConfigPreferencesOpts {
                nvt_oid: Some("1.3.6.1".into()),
                config_id: Some(EntityId::new("config-1").expect("valid id")),
            }))
            .await
            .expect("scan-config preferences request should succeed"),
        client
            .call(get_scan_config_preference(
                "timeout",
                GetScanConfigPreferencesOpts {
                    nvt_oid: Some("1.3.6.1".into()),
                    config_id: Some(EntityId::new("config-1").expect("valid id")),
                },
            ))
            .await
            .expect("scan-config preference request should succeed"),
        client
            .call(get_nvt_preferences(GetNvtPreferencesOpts {
                nvt_oid: Some("1.3.6.1".into()),
            }))
            .await
            .expect("nvt preferences request should succeed"),
        client
            .call(get_nvt_preference(
                "timeout",
                GetNvtPreferencesOpts {
                    nvt_oid: Some("1.3.6.1".into()),
                },
            ))
            .await
            .expect("nvt preference request should succeed"),
    ];
    assert!(responses
        .iter()
        .all(|response| response.status_code() == Some(200)));

    let history = server.command_history();
    assert_eq!(history.len(), 4);
    assert!(history
        .iter()
        .all(|record| record.command_name() == "get_preferences"));
    let commands = history
        .iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("xml is utf-8"))
        .collect::<Vec<_>>();
    assert_eq!(
        commands[0],
        "<get_preferences config_id=\"config-1\" nvt_oid=\"1.3.6.1\"/>"
    );
    assert_eq!(
        commands[1],
        "<get_preferences config_id=\"config-1\" nvt_oid=\"1.3.6.1\" preference=\"timeout\"/>"
    );
    assert_eq!(commands[2], "<get_preferences nvt_oid=\"1.3.6.1\"/>");
    assert_eq!(
        commands[3],
        "<get_preferences nvt_oid=\"1.3.6.1\" preference=\"timeout\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_scan_config_nvt_helpers_use_stateful_mock_server_filters() {
    let wanted_oid = "1.3.6.1.4.1.25623.1.0.90001";
    let other_oid = "1.3.6.1.4.1.25623.1.0.90002";
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_5)
        .unix_socket_auto()
        .seed(move |store| {
            let mut wanted = Resource::new("nvt", "Config-scoped NVT");
            wanted.set_attr("oid", wanted_oid);
            wanted.set_attr("config_id", "config-1");
            wanted.set_attr("preferences_config_id", "prefs-1");
            wanted.set_attr("family", "General");
            store.seed(wanted);

            let mut other = Resource::new("nvt", "Other NVT");
            other.set_attr("oid", other_oid);
            other.set_attr("config_id", "config-2");
            other.set_attr("preferences_config_id", "prefs-2");
            other.set_attr("family", "Other");
            store.seed(other);
        })
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("server should start: {error}"),
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let listed = client
        .get_scan_config_nvts(GetNvtsOpts {
            details: Some(true),
            preferences: Some(true),
            preference_count: Some(true),
            timeout: Some(false),
            config_id: Some(EntityId::new("config-1").expect("valid id")),
            preferences_config_id: Some(EntityId::new("prefs-1").expect("valid id")),
            family: Some("General".into()),
            sort_order: Some("ascending".into()),
            sort_field: Some("name".into()),
            ..Default::default()
        })
        .await
        .expect("scan-config NVT list request should succeed");
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].oid, wanted_oid);
    assert_eq!(listed.items[0].name, "Config-scoped NVT");
    assert_eq!(listed.items[0].family.as_deref(), Some("General"));

    let single = client
        .get_scan_config_nvt(wanted_oid)
        .await
        .expect("scan-config NVT request should succeed");
    assert_eq!(single.items.len(), 1);
    assert_eq!(single.items[0].oid, wanted_oid);

    let history = server.command_history();
    assert_eq!(history.len(), 2);
    assert!(history
        .iter()
        .all(|record| record.command_name() == "get_nvts"));
    let commands = history
        .iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("xml is utf-8"))
        .collect::<Vec<_>>();
    assert_eq!(
        commands[0],
        "<get_nvts config_id=\"config-1\" details=\"1\" family=\"General\" preference_count=\"1\" preferences=\"1\" preferences_config_id=\"prefs-1\" sort_field=\"name\" sort_order=\"ascending\" timeout=\"0\"/>"
    );
    assert_eq!(
        commands[1],
        "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1.4.1.25623.1.0.90001\" preference_count=\"1\" preferences=\"1\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_config_getters_filter_stateful_mock_resources() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let scan_config = client
        .create_scan_config(
            "Scan Config One",
            None,
            ConfigOpts {
                usage_type: Some("scan".into()),
                ..Default::default()
            },
        )
        .await
        .expect("scan config should be created");

    let response = client
        .send(create_policy(
            "Policy One",
            ConfigOpts {
                comment: Some("policy comment".into()),
                ..Default::default()
            },
        ))
        .await
        .expect("policy create request should succeed");
    let policy = CreateScanConfigResponse::from_response(&response).expect("policy create parses");

    server.clear_history();

    let scan_configs = client
        .get_scan_configs(GetScanConfigsOpts::default())
        .await
        .expect("scan configs should be fetched");
    assert!(scan_configs
        .items
        .iter()
        .all(|item| item.usage_type.as_deref() == Some("scan")));
    assert!(scan_configs
        .items
        .iter()
        .any(|item| item.meta.id == scan_config.id));
    assert!(!scan_configs
        .items
        .iter()
        .any(|item| item.meta.id == policy.id));

    let policies = client
        .get_policies(GetScanConfigsOpts::default())
        .await
        .expect("policies should be fetched");
    assert_eq!(policies.items.len(), 1);
    assert_eq!(policies.items[0].meta.id, policy.id);
    assert_eq!(policies.items[0].meta.name, "Policy One");
    assert_eq!(policies.items[0].usage_type.as_deref(), Some("policy"));

    let fetched = client
        .get_policy(&policy.id, GetPolicyOpts { audits: Some(true) })
        .await
        .expect("policy should be fetched");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.items[0].meta.id, policy.id);
    assert_eq!(
        fetched.items[0].meta.comment.as_deref(),
        Some("policy comment")
    );
    assert_eq!(fetched.items[0].usage_type.as_deref(), Some("policy"));

    let history = server.command_history();
    assert_eq!(history.len(), 3);
    assert!(history
        .iter()
        .all(|record| record.command_name() == "get_configs"));
    let commands = history
        .iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("xml is utf-8"))
        .collect::<Vec<_>>();
    assert_eq!(commands[0], "<get_configs usage_type=\"scan\"/>");
    assert_eq!(commands[1], "<get_configs usage_type=\"policy\"/>");
    assert_eq!(
        commands[2],
        format!(
            "<get_configs config_id=\"{}\" details=\"1\" tasks=\"1\" usage_type=\"policy\"/>",
            policy.id.as_str()
        )
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_permission_lifecycle_uses_nested_references() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let role = client
        .create_role("Permission Role", RoleOpts::default())
        .await
        .expect("role should be created");
    let target = client
        .create_target(
            "Permission Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.1".into()],
                ..Default::default()
            },
        )
        .await
        .expect("target should be created");
    server.clear_history();
    let permission = client
        .create_permission(PermissionOpts {
            comment: Some("permission comment".into()),
            name: Some("get_targets".into()),
            resource_id: Some(target.id.clone()),
            resource_type: Some("target".into()),
            subject_type: Some(PermissionSubjectType::Role),
            subject_id: Some(role.id.clone()),
        })
        .await
        .expect("permission should be created");

    let permissions = client
        .get_permissions(GetPermissionsOpts::default())
        .await
        .expect("permission should be retrieved");
    let fetched = permission_by_id(&permissions, &permission.id);
    assert_eq!(fetched.meta.name, "get_targets");
    assert_eq!(fetched.subject_type.as_deref(), Some("role"));
    assert_eq!(fetched.subject.as_ref().expect("subject").id, role.id);
    assert_eq!(fetched.resource_type.as_deref(), Some("target"));
    assert_eq!(fetched.resource.as_ref().expect("resource").id, target.id);

    client
        .call(modify_permission(
            &permission.id,
            PermissionOpts {
                comment: Some("updated".into()),
                resource_id: Some(target.id.clone()),
                resource_type: Some("target".into()),
                subject_type: Some(PermissionSubjectType::Role),
                subject_id: Some(role.id.clone()),
                ..Default::default()
            },
        ))
        .await
        .expect("permission should be modified");

    let permissions = client
        .get_permissions(GetPermissionsOpts::default())
        .await
        .expect("modified permission should be retrieved");
    let fetched = permission_by_id(&permissions, &permission.id);
    assert_eq!(fetched.meta.comment.as_deref(), Some("updated"));
    assert_eq!(fetched.subject_type.as_deref(), Some("role"));
    assert_eq!(fetched.resource_type.as_deref(), Some("target"));

    let history = server.command_history();
    assert_eq!(history.len(), 4);
    let commands = history
        .iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("xml is utf-8"))
        .collect::<Vec<_>>();
    assert_eq!(
        commands[0],
        format!(
            "<create_permission><comment>permission comment</comment><name>get_targets</name><resource id=\"{}\"><type>target</type></resource><subject id=\"{}\"><type>role</type></subject></create_permission>",
            target.id.as_str(),
            role.id.as_str(),
        )
    );
    assert_eq!(commands[1], "<get_permissions/>");
    assert_eq!(
        commands[2],
        format!(
            "<modify_permission permission_id=\"{}\"><comment>updated</comment><resource id=\"{}\"><type>target</type></resource><subject id=\"{}\"><type>role</type></subject></modify_permission>",
            permission.id.as_str(),
            target.id.as_str(),
            role.id.as_str(),
        )
    );
    assert_eq!(commands[3], "<get_permissions/>");

    server.shutdown().await;
}

#[tokio::test]
async fn typed_target_host_updates_preserve_replace_and_clear_state() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let target = client
        .create_target(
            "Collection Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.1".into(), "192.0.2.2".into()],
                exclude_hosts: vec!["192.0.2.3".into()],
                ..Default::default()
            },
        )
        .await
        .expect("target should be created");
    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                comment: Some("hosts omitted".into()),
                ..Default::default()
            },
        )
        .await
        .expect("target should be modified without changing hosts");
    let targets = client
        .get_targets(GetTargetsOpts::default())
        .await
        .expect("targets should be retrieved");
    let fetched_target = targets
        .items
        .iter()
        .find(|item| item.meta.id == target.id)
        .expect("target should be listed");
    assert_eq!(
        fetched_target.hosts,
        vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()]
    );
    assert_eq!(fetched_target.exclude_hosts, vec!["192.0.2.3".to_string()]);

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                hosts: CollectionUpdate::Clear,
                exclude_hosts: CollectionUpdate::replace(["192.0.2.4".into()]),
                ..Default::default()
            },
        )
        .await
        .expect("target hosts should be cleared and exclusions replaced");
    let targets = client
        .get_targets(GetTargetsOpts::default())
        .await
        .expect("modified targets should be retrieved");
    let fetched_target = targets
        .items
        .iter()
        .find(|item| item.meta.id == target.id)
        .expect("target should be listed");
    assert!(fetched_target.hosts.is_empty());
    assert_eq!(fetched_target.exclude_hosts, vec!["192.0.2.4".to_string()]);

    let history = server.command_history();
    assert!(history.iter().any(|record| {
        record.command_name() == "modify_target"
            && std::str::from_utf8(record.raw_xml())
                .is_ok_and(|xml| xml.contains("<hosts></hosts>"))
    }));

    server.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn typed_target_credentials_round_trip_in_stateful_mode() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = authenticated_client(&server).await;
    let first_ssh = create_test_credential(&mut client, "First SSH").await;
    let first_smb = create_test_smb_credential(&mut client, "First SMB").await;
    let second_ssh = create_test_credential(&mut client, "Second SSH").await;
    let second_smb = create_test_smb_credential(&mut client, "Second SMB").await;

    let default_target = client
        .create_target(
            "Default Credential Port Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.9".into()],
                ssh_credential_id: Some(first_ssh.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("target with default SSH port should be created");
    assert_eq!(
        target_by_id(&mut client, &default_target.id)
            .await
            .ssh_credential_port
            .map(ServicePort::get),
        Some(22)
    );

    let target = client
        .create_target(
            "Credential Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.1".into()],
                ssh_credential_id: Some(first_ssh.clone()),
                ssh_credential_port: Some(ServicePort::new(2222).expect("valid port")),
                smb_credential_id: Some(first_smb.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("target should be created");
    let created = target_by_id(&mut client, &target.id).await;
    assert_eq!(
        created.alive_tests.as_deref(),
        Some(AliveTest::ScanConfigDefault.as_target_name())
    );
    assert_target_credentials(&created, &first_ssh, 2222, &first_smb);

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                comment: Some("relationships omitted".into()),
                ..Default::default()
            },
        )
        .await
        .expect("omitted target fields should be preserved");
    let preserved = target_by_id(&mut client, &target.id).await;
    assert_eq!(
        preserved.alive_tests.as_deref(),
        Some(AliveTest::ScanConfigDefault.as_target_name())
    );
    assert_target_credentials(&preserved, &first_ssh, 2222, &first_smb);

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                ssh_credential_id: ScalarUpdate::set(second_ssh.clone()),
                ssh_credential_port: ScalarUpdate::set(ServicePort::new(2200).expect("valid port")),
                smb_credential_id: ScalarUpdate::set(second_smb.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("target relationships should be replaced");
    assert_target_credentials(
        &target_by_id(&mut client, &target.id).await,
        &second_ssh,
        2200,
        &second_smb,
    );

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                ssh_credential_id: ScalarUpdate::set(second_ssh.clone()),
                ssh_credential_port: ScalarUpdate::Clear,
                ..Default::default()
            },
        )
        .await
        .expect("target SSH port should reset to gvmd's default");
    assert_target_credentials(
        &target_by_id(&mut client, &target.id).await,
        &second_ssh,
        22,
        &second_smb,
    );

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                ssh_credential_id: ScalarUpdate::Clear,
                smb_credential_id: ScalarUpdate::Clear,
                ..Default::default()
            },
        )
        .await
        .expect("target credentials should be cleared");
    let cleared = target_by_id(&mut client, &target.id).await;
    assert_eq!(cleared.ssh_credential, None);
    assert_eq!(cleared.ssh_credential_port, None);
    assert_eq!(cleared.smb_credential, None);

    let missing_credential =
        EntityId::new("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("valid missing credential ID");
    let error = client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                ssh_credential_id: ScalarUpdate::set(missing_credential),
                ..Default::default()
            },
        )
        .await
        .expect_err("missing credential reference should be rejected");
    assert!(matches!(
        error,
        GvmError::Parse(ParseError::ServerError { status: 404, .. })
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_target_create_rejects_an_orphaned_ssh_port_before_send() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = authenticated_client(&server).await;
    let create_count_before = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "create_target")
        .count();

    let error = client
        .create_target(
            "Invalid Credential Port Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.11".into()],
                ssh_credential_port: Some(ServicePort::new(2222).expect("valid port")),
                ..Default::default()
            },
        )
        .await
        .expect_err("orphaned SSH port should fail locally");
    assert!(matches!(
        error,
        GvmError::CreateTarget(CreateTargetError::SshPortWithoutCredential)
    ));
    let create_count_after = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "create_target")
        .count();
    assert_eq!(create_count_after, create_count_before);

    server.shutdown().await;
}

#[tokio::test]
async fn typed_target_host_validation_rejects_before_send() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = authenticated_client(&server).await;
    let create_count_before = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "create_target")
        .count();

    let create_error = client
        .create_target(
            "Invalid CIDR Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.1".into(), "198.51.100.1/31".into()],
                ..Default::default()
            },
        )
        .await
        .expect_err("invalid IPv4 CIDR should fail locally");
    assert!(matches!(
        create_error,
        GvmError::CreateTarget(CreateTargetError::InvalidHostSpecification(
            InvalidTargetHost {
                field: TargetHostField::Hosts,
                index: 1,
                specification,
            }
        )) if specification == "198.51.100.1/31"
    ));
    let create_count_after = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "create_target")
        .count();
    assert_eq!(create_count_after, create_count_before);

    let target = client
        .create_target(
            "Valid CIDR Target",
            CreateTargetOpts {
                hosts: vec!["198.51.100.1/30".into()],
                ..Default::default()
            },
        )
        .await
        .expect("supported IPv4 CIDR should be sent");
    let modify_count_before = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "modify_target")
        .count();

    let modify_error = client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                exclude_hosts: CollectionUpdate::replace(["2001:db8::1/0".into()]),
                ..Default::default()
            },
        )
        .await
        .expect_err("invalid IPv6 CIDR should fail locally");
    assert!(matches!(
        modify_error,
        GvmError::ModifyTarget(ModifyTargetError::InvalidHostSpecification(
            InvalidTargetHost {
                field: TargetHostField::ExcludeHosts,
                index: 0,
                specification,
            }
        )) if specification == "2001:db8::1/0"
    ));
    let modify_count_after = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "modify_target")
        .count();
    assert_eq!(modify_count_after, modify_count_before);

    client
        .delete_target(&target.id, true)
        .await
        .expect("target cleanup should succeed");
    server.shutdown().await;
}

#[tokio::test]
async fn typed_target_alive_tests_preserve_replace_and_validate_state() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = authenticated_client(&server).await;
    for alive_test in ["<alive_tests/>", "<alive_tests>   </alive_tests>"] {
        assert_raw_server_error(
            &mut client,
            format!(
                "<create_target><name>Invalid Alive Test</name><hosts>192.0.2.2</hosts>{alive_test}</create_target>"
            )
            .into_bytes(),
            400,
        )
        .await;
    }

    let target = client
        .create_target(
            "Alive Test Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.1".into()],
                alive_test: Some(AliveTest::ScanConfigDefault),
                ..Default::default()
            },
        )
        .await
        .expect("target should be created");

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                comment: Some("alive test omitted".into()),
                ..Default::default()
            },
        )
        .await
        .expect("omitted alive test should be preserved");
    let preserved = target_by_id(&mut client, &target.id).await;
    assert_eq!(
        preserved.alive_tests.as_deref(),
        Some(AliveTest::ScanConfigDefault.as_target_name())
    );

    for alive_test in [
        AliveTest::ScanConfigDefault,
        AliveTest::IcmpPing,
        AliveTest::TcpAckServicePing,
        AliveTest::TcpSynServicePing,
        AliveTest::ArpPing,
        AliveTest::IcmpAndTcpAckServicePing,
        AliveTest::IcmpAndArpPing,
        AliveTest::TcpAckServiceAndArpPing,
        AliveTest::IcmpTcpAckServiceAndArpPing,
        AliveTest::ConsiderAlive,
    ] {
        client
            .modify_target(
                &target.id,
                ModifyTargetOpts {
                    alive_test: Some(alive_test),
                    ..Default::default()
                },
            )
            .await
            .expect("supported alive test should be accepted");
        assert_eq!(
            target_by_id(&mut client, &target.id)
                .await
                .alive_tests
                .as_deref(),
            Some(alive_test.as_target_name())
        );
    }

    for alive_test in [
        "<alive_tests/>",
        "<alive_tests>   </alive_tests>",
        "<alive_tests>Not An Alive Test</alive_tests>",
    ] {
        assert_raw_server_error(
            &mut client,
            format!(
                "<modify_target target_id=\"{}\">{alive_test}</modify_target>",
                target.id,
            )
            .into_bytes(),
            400,
        )
        .await;
    }
    assert_eq!(
        target_by_id(&mut client, &target.id)
            .await
            .alive_tests
            .as_deref(),
        Some(AliveTest::ConsiderAlive.as_target_name())
    );

    server.shutdown().await;
}

#[tokio::test]
async fn raw_singular_target_alive_test_matches_gvmd_behavior() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = authenticated_client(&server).await;
    let singular_create = client
        .call(
            b"<create_target><name>Singular Alive Test</name><hosts>192.0.2.3</hosts><alive_test>ICMP Ping</alive_test></create_target>"
                .to_vec(),
        )
        .await
        .expect("singular alive test should be ignored on create");
    let singular_target_id = singular_create
        .id()
        .expect("created target ID")
        .parse()
        .expect("valid target ID");
    assert_eq!(
        target_by_id(&mut client, &singular_target_id)
            .await
            .alive_tests
            .as_deref(),
        Some(AliveTest::ScanConfigDefault.as_target_name())
    );

    let target = client
        .create_target(
            "Plural Alive Test",
            CreateTargetOpts {
                hosts: vec!["192.0.2.4".into()],
                alive_test: Some(AliveTest::ConsiderAlive),
                ..Default::default()
            },
        )
        .await
        .expect("plural alive test should be applied on create");
    assert_raw_server_error(
        &mut client,
        format!(
            "<modify_target target_id=\"{}\"><alive_test>ICMP Ping</alive_test></modify_target>",
            target.id,
        )
        .into_bytes(),
        400,
    )
    .await;
    assert_eq!(
        target_by_id(&mut client, &target.id)
            .await
            .alive_tests
            .as_deref(),
        Some(AliveTest::ConsiderAlive.as_target_name())
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_target_port_list_updates_preserve_omit_and_set_semantics() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let first_port_list = client
        .create_port_list("First Port List", PortListOpts::default())
        .await
        .expect("first port list should be created");
    let second_port_list = client
        .create_port_list("Second Port List", PortListOpts::default())
        .await
        .expect("second port list should be created");
    let target = client
        .create_target(
            "Port List Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.1".into()],
                port_list_id: Some(first_port_list.id.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("target should be created with a port list");

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                comment: Some("port list omitted".into()),
                ..Default::default()
            },
        )
        .await
        .expect("omitting the port list should preserve it");
    let targets = client
        .get_targets(GetTargetsOpts::default())
        .await
        .expect("targets should be retrieved");
    let fetched_target = targets
        .items
        .iter()
        .find(|item| item.meta.id == target.id)
        .expect("target should be listed");
    assert_eq!(
        fetched_target
            .port_list
            .as_ref()
            .map(|port_list| &port_list.id),
        Some(&first_port_list.id)
    );

    client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                port_list_id: ScalarUpdate::set(second_port_list.id.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("replacing the port list should succeed");
    let targets = client
        .get_targets(GetTargetsOpts::default())
        .await
        .expect("modified targets should be retrieved");
    let fetched_target = targets
        .items
        .iter()
        .find(|item| item.meta.id == target.id)
        .expect("target should be listed");
    assert_eq!(
        fetched_target
            .port_list
            .as_ref()
            .map(|port_list| &port_list.id),
        Some(&second_port_list.id)
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_target_port_list_clear_is_rejected_before_send() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    let target = client
        .create_target(
            "Port List Clear Target",
            CreateTargetOpts {
                hosts: vec!["192.0.2.1".into()],
                ..Default::default()
            },
        )
        .await
        .expect("target should be created");

    let modify_count_before_clear = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "modify_target")
        .count();
    let error = client
        .modify_target(
            &target.id,
            ModifyTargetOpts {
                port_list_id: ScalarUpdate::Clear,
                ..Default::default()
            },
        )
        .await
        .expect_err("clearing a target port list should be rejected locally");
    assert!(matches!(
        error,
        GvmError::ModifyTarget(ModifyTargetError::UnsupportedPortListClear)
    ));
    let modify_count_after_clear = server
        .command_history()
        .iter()
        .filter(|record| record.command_name() == "modify_target")
        .count();
    assert_eq!(modify_count_after_clear, modify_count_before_clear);

    let error = client
        .call(
            format!(
                "<modify_target target_id=\"{}\"><port_list id=\"0\"/></modify_target>",
                target.id
            )
            .into_bytes(),
        )
        .await
        .expect_err("the stateful mock should reject a manufactured clear sentinel");
    assert!(matches!(error, GvmError::Server { status: 400, .. }));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_user_role_updates_preserve_replace_and_clear_state() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let role_one = client
        .create_role("Collection Role One", RoleOpts::default())
        .await
        .expect("first role should be created");
    let role_two = client
        .create_role("Collection Role Two", RoleOpts::default())
        .await
        .expect("second role should be created");
    let user = client
        .create_user(
            "Collection User",
            UserOpts {
                role_ids: vec![role_one.id.clone()],
                ..Default::default()
            },
        )
        .await
        .expect("user should be created");
    client
        .modify_user(
            &user.id,
            ModifyUserOpts {
                comment: Some("roles omitted".into()),
                ..Default::default()
            },
        )
        .await
        .expect("user should be modified without changing roles");
    let users = client
        .get_users(GetUsersOpts::default())
        .await
        .expect("users should be retrieved");
    let fetched_user = users
        .items
        .iter()
        .find(|item| item.meta.id == user.id)
        .expect("user should be listed");
    assert_eq!(
        fetched_user
            .roles
            .iter()
            .map(|role| role.id.clone())
            .collect::<Vec<_>>(),
        vec![role_one.id.clone()]
    );

    client
        .modify_user(
            &user.id,
            ModifyUserOpts {
                role_ids: CollectionUpdate::replace([role_two.id.clone()]),
                ..Default::default()
            },
        )
        .await
        .expect("user roles should be replaced");
    client
        .modify_user(
            &user.id,
            ModifyUserOpts {
                role_ids: CollectionUpdate::Clear,
                ..Default::default()
            },
        )
        .await
        .expect("user roles should be cleared");
    let users = client
        .get_users(GetUsersOpts::default())
        .await
        .expect("modified users should be retrieved");
    let fetched_user = users
        .items
        .iter()
        .find(|item| item.meta.id == user.id)
        .expect("user should be listed");
    assert!(fetched_user.roles.is_empty());

    let history = server.command_history();
    assert!(history.iter().any(|record| {
        record.command_name() == "modify_user"
            && std::str::from_utf8(record.raw_xml())
                .is_ok_and(|xml| xml.contains("<role id=\"0\"/>"))
    }));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_policy_import_uses_stateful_mock_server_create_command() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    server.clear_history();

    let policy_xml = concat!(
        r#"<get_configs_response status="200" status_text="OK">"#,
        r#"<config id="c4aa21e4-23e6-4064-ae49-c0d425738a98">"#,
        "<owner><name>admin</name></owner>",
        "<name>Imported policy</name>",
        "<comment>Imported policy comment</comment>",
        "<usage_type>policy</usage_type>",
        "</config>",
        "</get_configs_response>"
    );
    let policy = client
        .import_policy(policy_xml)
        .await
        .expect("policy import should succeed");

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "create_config");
    assert_eq!(
        String::from_utf8(history[0].raw_xml().to_vec()).expect("xml is utf-8"),
        format!("<create_config>{policy_xml}</create_config>")
    );

    let fetched = client
        .get_policy(&policy.id, GetPolicyOpts { audits: Some(true) })
        .await
        .expect("imported policy should be fetched");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.items[0].meta.id, policy.id);
    assert_eq!(fetched.items[0].meta.name, "Imported policy");
    assert_eq!(
        fetched.items[0].meta.comment.as_deref(),
        Some("Imported policy comment")
    );
    assert_eq!(fetched.items[0].usage_type.as_deref(), Some("policy"));

    let multi_policy_xml = concat!(
        r#"<get_configs_response status="200" status_text="OK">"#,
        r#"<config id="c4aa21e4-23e6-4064-ae49-c0d425738a98">"#,
        "<name>First policy</name>",
        "<usage_type>policy</usage_type>",
        "</config>",
        r#"<config id="d5aa21e4-23e6-4064-ae49-c0d425738a99">"#,
        "<name>Second policy</name>",
        "<usage_type>policy</usage_type>",
        "</config>",
        "</get_configs_response>"
    );
    assert!(
        client.import_policy(multi_policy_xml).await.is_err(),
        "stateful mock should reject multi-config policy imports instead of truncating"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_scan_config_import_uses_stateful_mock_server_create_command() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let scan_config_xml = concat!(
        r#"<get_configs_response status="200" status_text="OK">"#,
        r#"<config id="c4aa21e4-23e6-4064-ae49-c0d425738a98">"#,
        "<owner><name>admin</name></owner>",
        "<name>Imported scan config</name>",
        "<comment>Imported comment</comment>",
        "<usage_type>scan</usage_type>",
        "</config>",
        "</get_configs_response>"
    );
    let imported = client
        .import_scan_config(scan_config_xml)
        .await
        .expect("scan config import should succeed");
    assert_eq!(imported.status, 201);

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "create_config");
    assert_eq!(
        String::from_utf8(history[0].raw_xml().to_vec()).expect("xml is utf-8"),
        format!("<create_config>{scan_config_xml}</create_config>")
    );

    let fetched = client
        .get_scan_config(&imported.id)
        .await
        .expect("imported scan config should be fetchable");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.items[0].meta.id, imported.id);
    assert_eq!(fetched.items[0].meta.name, "Imported scan config");
    assert_eq!(
        fetched.items[0].meta.comment.as_deref(),
        Some("Imported comment")
    );
    assert_eq!(fetched.items[0].usage_type.as_deref(), Some("scan"));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_report_format_import_and_clone_use_mock_server_create_command() {
    let Some(server) = echo_server(MockVersion::V22_5).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let report_format_id = EntityId::new("rf1").expect("valid id");
    let cloned = client
        .clone_report_format(&report_format_id)
        .await
        .expect("report format clone should succeed");
    assert_eq!(cloned.status, 201);

    let report_format_xml = r#"<get_report_formats_response status="200" status_text="OK"><report_format id="rf1"><name>Imported</name></report_format></get_report_formats_response>"#;
    let imported = client
        .import_report_format(report_format_xml)
        .await
        .expect("report format import should succeed");
    assert_eq!(imported.status, 201);

    let history = server.command_history();
    assert_eq!(history.len(), 2);
    assert!(history
        .iter()
        .all(|record| record.command_name() == "create_report_format"));
    let commands = history
        .iter()
        .map(|record| String::from_utf8(record.raw_xml().to_vec()).expect("xml is utf-8"))
        .collect::<Vec<_>>();
    assert_eq!(
        commands[0],
        "<create_report_format><copy>rf1</copy></create_report_format>"
    );
    assert_eq!(
        commands[1],
        format!("<create_report_format>{report_format_xml}</create_report_format>")
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_report_import_uses_mock_server_stateful_create_command() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");
    server.clear_history();

    let import_task = client
        .create_import_task("Report Import Task", None)
        .await
        .expect("import task should succeed");
    let task_id = import_task.id;
    server.clear_history();
    let report_xml = r#"<report id="imported-report"><name>Imported</name></report>"#;
    let created = client
        .import_report(
            report_xml,
            &task_id,
            ImportReportOpts {
                in_assets: Some(true),
            },
        )
        .await
        .expect("report import should succeed");
    assert_eq!(created.status, 201);

    let readback = client
        .send(get_reports(GetReportsOpts {
            details: Some(true),
            ..Default::default()
        }))
        .await
        .expect("get_reports should succeed");
    let readback_xml = readback.as_str().expect("response XML should be UTF-8");
    assert!(readback_xml.contains(&format!("id=\"{}\"", created.id)));
    assert!(readback_xml.contains(&format!("<task_id>{task_id}</task_id>")));
    assert!(readback_xml.contains("<in_assets>1</in_assets>"));

    let history = server.command_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].command_name(), "create_report");
    assert_eq!(history[1].command_name(), "get_reports");
    let import_command =
        String::from_utf8(history[0].raw_xml().to_vec()).expect("history should be UTF-8");
    assert_eq!(
        import_command,
        format!(
            r#"<create_report><task id="{task_id}"/><in_assets>1</in_assets>{report_xml}</create_report>"#
        )
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_report_drilldowns_parse_stateful_mock_responses() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let task_id = client
        .create_import_task("Report Drilldown Task", None)
        .await
        .expect("import task should succeed")
        .id;
    let created = client
        .import_report(
            r#"<report id="drilldown-report"><name>Drilldown</name></report>"#,
            &task_id,
            ImportReportOpts::default(),
        )
        .await
        .expect("report import should succeed");

    let hosts = client
        .get_report_hosts_parsed(&created.id, Default::default())
        .await
        .expect("report hosts should parse");
    assert_eq!(hosts.items.len(), 2);
    assert_eq!(hosts.items[0].name.as_deref(), Some("192.0.2.10"));

    let ports = client
        .get_report_ports_parsed(&created.id, Default::default())
        .await
        .expect("report ports should parse");
    assert_eq!(ports.items[0].name.as_deref(), Some("22/tcp"));

    let applications = client
        .get_report_applications_parsed(&created.id, Default::default())
        .await
        .expect("report applications should parse");
    assert_eq!(applications.items[0].name.as_deref(), Some("OpenSSH"));

    let operating_systems = client
        .get_report_operating_systems_parsed(&created.id, Default::default())
        .await
        .expect("report operating systems should parse");
    assert_eq!(operating_systems.items[0].name.as_deref(), Some("Debian"));

    let cves = client
        .get_report_cves_parsed(&created.id, Default::default())
        .await
        .expect("report cves should parse");
    assert_eq!(cves.items[0].name.as_deref(), Some("CVE-2026-0001"));

    server.shutdown().await;
}

const SCAN_REPORT_ID: &str = "10000000-0000-4000-8000-000000000001";
const SCAN_REPORT_TASK_ID: &str = "20000000-0000-4000-8000-000000000001";
const SCAN_REPORT_TARGET_ID: &str = "30000000-0000-4000-8000-000000000001";
const SCAN_REPORT_FILTER_ID: &str = "40000000-0000-4000-8000-000000000001";

fn seed_scan_report_fixture(store: &ResourceStore) {
    let mut target = Resource::with_id(
        "target",
        "Scan Report Target",
        SCAN_REPORT_TARGET_ID.parse().expect("valid target UUID"),
    );
    target.comment = "Target comment".into();
    store.seed(target);

    let mut task = Resource::with_id(
        "task",
        "Scan Report Task",
        SCAN_REPORT_TASK_ID.parse().expect("valid task UUID"),
    );
    task.comment = "Task comment".into();
    task.set_attr("target_id", SCAN_REPORT_TARGET_ID);
    task.set_attr("status", "Done");
    store.seed(task);

    let mut report = Resource::with_id(
        "report",
        "Structured Scan Report",
        SCAN_REPORT_ID.parse().expect("valid report UUID"),
    );
    report.comment = "Report comment".into();
    report.set_attr("task_id", SCAN_REPORT_TASK_ID);
    report.set_attr("status", "Done");
    report.set_attr("usage_type", "scan");
    store.seed(report);

    let mut saved_filter = Resource::with_id(
        "filter",
        "Saved Result Filter",
        SCAN_REPORT_FILTER_ID.parse().expect("valid filter UUID"),
    );
    saved_filter.set_attr(
        "term",
        "bare levels=chm min_qod=70 apply_overrides=0 first=1 rows=10 \
         sort-reverse=severity result_hosts_only=1 unknown=ignored",
    );
    store.seed(saved_filter);

    for (name, severity, qod, host, port, false_positive, threat) in [
        ("Critical", "9.5", "90", "192.0.2.1", "443/tcp", false, ""),
        ("High", "8.0", "80", "192.0.2.2", "22/tcp", false, ""),
        ("Medium", "5.0", "60", "192.0.2.1", "80/tcp", false, ""),
        ("Low", "2.0", "100", "192.0.2.3", "80/tcp", false, ""),
        ("Log", "0.0", "100", "192.0.2.4", "0/tcp", false, ""),
        (
            "False positive",
            "9.0",
            "100",
            "192.0.2.5",
            "25/tcp",
            true,
            "",
        ),
        (
            "Scanner error",
            "0.0",
            "100",
            "192.0.2.6",
            "0/tcp",
            false,
            "Error",
        ),
    ] {
        let mut result = Resource::new("result", name);
        result.set_attr("report_id", SCAN_REPORT_ID);
        result.set_attr("severity", severity);
        result.set_attr("qod", qod);
        result.set_attr("host", host);
        result.set_attr("port", port);
        if false_positive {
            result.set_attr("false_positive", "1");
        }
        if !threat.is_empty() {
            result.set_attr("threat", threat);
        }
        store.seed(result);
    }
}

fn assert_typed_scan_report(response: &GetScanReportResponse) {
    assert_eq!(response.report.meta.id.as_str(), SCAN_REPORT_ID);
    assert_eq!(response.report.scan_run_status.as_deref(), Some("Done"));
    assert_eq!(response.report.resources.hosts, Some(6));
    assert_eq!(response.report.resources.vulnerabilities, Some(7));
    assert_eq!(response.report.resources.errors, Some(1));
    let task = response.report.task.as_ref().expect("task should parse");
    assert_eq!(
        task.id.as_ref().map(EntityId::as_str),
        Some(SCAN_REPORT_TASK_ID)
    );
    assert_eq!(
        task.target
            .as_ref()
            .and_then(|target| target.id.as_ref())
            .map(EntityId::as_str),
        Some(SCAN_REPORT_TARGET_ID)
    );
    assert_eq!(
        task.target
            .as_ref()
            .and_then(|target| target.target_type.as_deref()),
        Some("target")
    );
    let result_count = response
        .report
        .result_count
        .as_ref()
        .expect("result counts should parse");
    assert_eq!(result_count.full, Some(7));
    assert_eq!(result_count.filtered, Some(2));
    assert_eq!(
        response
            .report
            .severity
            .as_ref()
            .and_then(|severity| severity.filtered.as_deref()),
        Some("9.5")
    );
    assert_eq!(
        response
            .filter
            .as_ref()
            .and_then(|filter| filter.id.as_ref())
            .map(EntityId::as_str),
        Some(SCAN_REPORT_FILTER_ID)
    );
    assert!(response.filter.as_ref().is_some_and(|filter| filter
        .keywords
        .iter()
        .any(|keyword| keyword.column == "levels")));
    assert_eq!(
        response.sort.as_ref().map(|sort| sort.field.as_str()),
        Some("severity")
    );
    assert_eq!(response.page.start, Some(1));
    assert_eq!(response.page.max, Some(1));
}

#[tokio::test]
async fn next_client_get_scan_report_uses_stateful_mock_transport() {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_8)
        .unix_socket_auto()
        .seed(seed_scan_report_fixture)
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("server should start: {error}"),
    };

    let mut client = GmpVersioned::connect(unix_connection(&server))
        .await
        .expect("client should connect");
    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authentication should succeed");
    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };
    server.clear_history();

    let response = client
        .get_scan_report(
            &EntityId::new(SCAN_REPORT_ID).expect("valid report ID"),
            GetScanReportOpts {
                filter_string: Some("levels=l".into()),
                filter_id: Some(EntityId::new(SCAN_REPORT_FILTER_ID).expect("valid filter ID")),
            },
        )
        .await
        .expect("get_scan_report should succeed");
    assert_typed_scan_report(&response);

    let raw_response = client
        .get_scan_report_raw(
            &EntityId::new(SCAN_REPORT_ID).expect("valid report ID"),
            GetScanReportOpts::default(),
        )
        .await
        .expect("raw compatibility path should succeed");
    assert!(raw_response
        .as_str()
        .expect("raw response should be UTF-8")
        .starts_with("<get_scan_report_response status=\"200\""));

    let history = server.command_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].command_name(), "get_scan_report");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("request should be UTF-8"),
        format!(
            "<get_scan_report filt_id=\"{SCAN_REPORT_FILTER_ID}\" filter=\"levels=l\" \
             scan_report_id=\"{SCAN_REPORT_ID}\"/>"
        )
    );
    assert_eq!(history[1].command_name(), "get_scan_report");

    server.shutdown().await;
}

#[tokio::test]
async fn full_crud_lifecycle_succeeds() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(authenticate("admin", "admin"))
        .await
        .expect("authenticate should succeed");

    let target_response = client
        .call(
            create_target(
                "Lifecycle Target",
                CreateTargetOpts {
                    hosts: vec!["127.0.0.1".to_string()],
                    ..CreateTargetOpts::default()
                },
            )
            .expect("valid target"),
        )
        .await
        .expect("create_target should succeed");
    let target_id = target_response.id().expect("target id");

    let config_id = "daba56c8-73ec-11df-a475-002264764cea"
        .parse()
        .expect("entity id");
    let scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
        .parse()
        .expect("entity id");
    let target_entity_id = target_id.parse().expect("entity id");

    let task_response = client
        .call(create_task(
            "Lifecycle Task",
            &config_id,
            &target_entity_id,
            &scanner_id,
            Default::default(),
        ))
        .await
        .expect("create_task should succeed");
    let task_id = task_response.id().expect("task id");
    let task_entity_id = task_id.parse().expect("entity id");

    let typed_tasks = client
        .get_tasks(Default::default())
        .await
        .expect("typed get_tasks should succeed");
    let typed_task = typed_tasks
        .items
        .iter()
        .find(|task| task.meta.id == task_entity_id)
        .expect("created classic task should be returned");
    assert_eq!(
        typed_task.target.as_ref().map(|target| &target.id),
        Some(&target_entity_id)
    );
    assert_eq!(typed_task.agent_group, None);
    assert_eq!(typed_task.oci_image_target, None);
    assert_eq!(typed_task.web_application_target, None);

    let start_response = client
        .call(start_task(&task_entity_id))
        .await
        .expect("start_task should succeed");
    assert_eq!(start_response.status_code(), Some(202));
    assert!(start_response.child_text("report_id").is_some());

    let get_response = client
        .call(get_task(&task_entity_id))
        .await
        .expect("get_task should succeed");
    let body = get_response.as_str().expect("utf8");
    assert!(body.contains(&task_id));
    assert!(body.contains("Running"));

    let stop_response = client
        .call(stop_task(&task_entity_id))
        .await
        .expect("stop_task should succeed");
    assert_eq!(stop_response.status_code(), Some(200));

    let delete_task_response = client
        .call(delete_task(&task_entity_id, true))
        .await
        .expect("delete_task should succeed");
    assert_eq!(delete_task_response.status_code(), Some(200));

    let delete_target_response = client
        .call(delete_target(&target_entity_id, true))
        .await
        .expect("delete_target should succeed");
    assert_eq!(delete_target_response.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn typed_create_import_task_uses_import_task_shape() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    server.clear_history();

    let response = client
        .create_import_task("Import Task", Some("Imported reports"))
        .await
        .expect("create_import_task should succeed");

    assert_eq!(response.status, 201);

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create_task command recorded");
    assert_eq!(command.command_name(), "create_task");
    assert_eq!(
        String::from_utf8(command.raw_xml().to_vec()).expect("history should be UTF-8"),
        "<create_task><name>Import Task</name><target id=\"0\"/><comment>Imported reports</comment></create_task>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn typed_trashcan_helpers_restore_deleted_task() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let empty_response = client
        .empty_trashcan()
        .await
        .expect("empty_trashcan should succeed");
    assert_eq!(empty_response.status, 200);

    let target_response = client
        .create_target(
            "Trashcan Target",
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        )
        .await
        .expect("create_target should succeed");
    let target_id = target_response.id;
    let config_id = "daba56c8-73ec-11df-a475-002264764cea"
        .parse()
        .expect("entity id");
    let scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
        .parse()
        .expect("entity id");

    let task_response = client
        .create_task(
            "Trashcan Task",
            &config_id,
            &target_id,
            &scanner_id,
            Default::default(),
        )
        .await
        .expect("create_task should succeed");
    let task_id = task_response.id;

    let delete_response = client
        .call(delete_task(&task_id, false))
        .await
        .expect("delete_task should succeed");
    assert_eq!(delete_response.status_code(), Some(200));

    let restore_response = client
        .restore_from_trashcan(&task_id)
        .await
        .expect("restore_from_trashcan should succeed");
    assert_eq!(restore_response.status, 200);

    let get_response = client
        .call(get_task(&task_id))
        .await
        .expect("get_task should succeed");
    let body = get_response.as_str().expect("utf8");
    assert!(body.contains("Trashcan Task"));

    server.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn typed_resume_task_returns_report_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let target_response = client
        .create_target(
            "Typed Resume Target",
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        )
        .await
        .expect("create_target should succeed");
    let target_id = target_response.id;

    let config_id = "daba56c8-73ec-11df-a475-002264764cea"
        .parse()
        .expect("entity id");
    let scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
        .parse()
        .expect("entity id");

    let task_response = client
        .create_task(
            "Typed Resume Task",
            &config_id,
            &target_id,
            &scanner_id,
            Default::default(),
        )
        .await
        .expect("create_task should succeed");
    let task_id = task_response.id;

    let start_response = client
        .start_task(&task_id)
        .await
        .expect("start_task should succeed");
    assert_eq!(start_response.status, 202);
    let report_id = start_response
        .report_id
        .expect("start should return report id");
    let running = client
        .get_tasks(Default::default())
        .await
        .expect("running task should be observable")
        .items
        .into_iter()
        .find(|task| task.meta.id == task_id)
        .expect("started task should be returned");
    assert_eq!(
        running.current_report.as_ref().map(|report| &report.id),
        Some(&report_id)
    );
    assert_eq!(running.last_report, None);

    client
        .call(stop_task(&task_id))
        .await
        .expect("stop_task should succeed");
    let stopped = client
        .get_tasks(Default::default())
        .await
        .expect("stopped task should be observable")
        .items
        .into_iter()
        .find(|task| task.meta.id == task_id)
        .expect("stopped task should be returned");
    assert_eq!(stopped.status.as_deref(), Some("Stopped"));
    assert_eq!(
        stopped.current_report.as_ref().map(|report| &report.id),
        Some(&report_id)
    );
    assert_eq!(stopped.last_report, None);

    let resume_response = client
        .resume_task(&task_id)
        .await
        .expect("resume_task should succeed");
    assert_eq!(resume_response.status, 202);
    assert_eq!(resume_response.report_id.as_ref(), Some(&report_id));
    let resumed = client
        .get_tasks(Default::default())
        .await
        .expect("resumed task should be observable")
        .items
        .into_iter()
        .find(|task| task.meta.id == task_id)
        .expect("resumed task should be returned");
    assert_eq!(resumed.status.as_deref(), Some("Running"));
    assert_eq!(
        resumed.current_report.as_ref().map(|report| &report.id),
        Some(&report_id)
    );
    assert_eq!(resumed.last_report, None);

    client
        .call(delete_task(&task_id, true))
        .await
        .expect("delete_task should succeed");
    client
        .call(delete_target(&target_id, true))
        .await
        .expect("delete_target should succeed");

    server.shutdown().await;
}

#[tokio::test]
async fn typed_oci_image_target_lifecycle_succeeds() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let created = client
        .create_oci_image_target_parsed(
            "OCI Target",
            &["registry.example/app:1".to_string()],
            CreateOciImageTargetOpts {
                comment: Some("created".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("create_oci_image_target should succeed");

    let fetched = client
        .get_oci_image_target_parsed(&created.id, Some(true))
        .await
        .expect("get_oci_image_target should succeed");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.items[0].meta.id, created.id);
    assert_eq!(
        fetched.items[0].image_references,
        vec!["registry.example/app:1".to_string()]
    );

    let modified = client
        .modify_oci_image_target_parsed(
            &created.id,
            ModifyOciImageTargetOpts {
                name: Some("OCI Target Updated".to_string()),
                image_references: vec!["registry.example/app:2".to_string()],
                ..Default::default()
            },
        )
        .await
        .expect("modify_oci_image_target should succeed");
    assert_eq!(modified.status, 200);

    let cloned = client
        .clone_oci_image_target_parsed(&created.id)
        .await
        .expect("clone_oci_image_target should succeed");
    assert_eq!(cloned.status, 201);

    let deleted = client
        .delete_oci_image_target_parsed(&created.id, true)
        .await
        .expect("delete_oci_image_target should succeed");
    assert_eq!(deleted.status, 200);

    server.shutdown().await;
}

#[tokio::test]
async fn typed_web_application_target_lifecycle_succeeds() {
    let Some(server) = stateful_server_with_version(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let created = client
        .create_web_application_target_parsed(
            "Web Target",
            &["https://example.com".to_string()],
            CreateWebApplicationTargetOpts {
                comment: Some("created".to_string()),
                exclude_urls: vec!["https://example.com/logout".to_string()],
                ..Default::default()
            },
        )
        .await
        .expect("create_web_application_target should succeed");

    let fetched = client
        .get_web_application_target_parsed(&created.id, Some(true))
        .await
        .expect("get_web_application_target should succeed");
    assert_eq!(fetched.items.len(), 1);
    assert_eq!(fetched.items[0].meta.id, created.id);
    assert_eq!(
        fetched.items[0].urls,
        vec!["https://example.com".to_string()]
    );
    assert_eq!(
        fetched.items[0].exclude_urls,
        vec!["https://example.com/logout".to_string()]
    );

    let modified = client
        .modify_web_application_target_parsed(
            &created.id,
            ModifyWebApplicationTargetOpts {
                name: Some("Web Target Updated".to_string()),
                urls: vec!["https://example.com/app".to_string()],
                exclude_urls: vec!["https://example.com/logout".to_string()],
                ..Default::default()
            },
        )
        .await
        .expect("modify_web_application_target should succeed");
    assert_eq!(modified.status, 200);

    let cloned = client
        .clone_web_application_target_parsed(&created.id)
        .await
        .expect("clone_web_application_target should succeed");
    assert_eq!(cloned.status, 201);

    let deleted = client
        .delete_web_application_target_parsed(&created.id, true)
        .await
        .expect("delete_web_application_target should succeed");
    assert_eq!(deleted.status, 200);

    server.shutdown().await;
}

async fn typed_scan_config_lifecycle(client: &mut GmpClient<UnixSocketConnection>) {
    let created_config = client
        .create_scan_config(
            "Typed Config",
            None,
            ConfigOpts {
                comment: Some("created".into()),
                usage_type: Some("scan".into()),
            },
        )
        .await
        .expect("create_scan_config should succeed");
    let config_id = created_config.id;

    let fetched_config = client
        .get_scan_config(&config_id)
        .await
        .expect("get_scan_config should succeed");
    assert_eq!(fetched_config.items.len(), 1);
    assert_eq!(fetched_config.items[0].meta.id, config_id);
    assert_eq!(fetched_config.items[0].meta.name, "Typed Config");

    client
        .modify_scan_config(
            &config_id,
            ConfigOpts {
                comment: Some("updated".into()),
                usage_type: Some("scan".into()),
            },
        )
        .await
        .expect("modify_scan_config should succeed");

    let updated_config = client
        .get_scan_config(&config_id)
        .await
        .expect("get_scan_config after modify should succeed");
    assert_eq!(
        updated_config.items[0].meta.comment.as_deref(),
        Some("updated")
    );

    client
        .sync_config()
        .await
        .expect("sync_config should succeed");
    #[allow(deprecated)]
    client
        .sync_scan_config(&config_id)
        .await
        .expect("deprecated sync_scan_config compatibility shim should succeed");

    let cloned_config = client
        .clone_scan_config(&config_id)
        .await
        .expect("clone_scan_config should succeed");
    let cloned_config_id = cloned_config.id;
    let cloned_config_response = client
        .get_scan_config(&cloned_config_id)
        .await
        .expect("get cloned config should succeed");
    assert_eq!(cloned_config_response.items[0].meta.name, "Typed Config");

    client
        .delete_scan_config(&cloned_config_id, true)
        .await
        .expect("delete cloned config should succeed");
    client
        .delete_scan_config(&config_id, true)
        .await
        .expect("delete original config should succeed");
}

fn assert_scanner_connection_fields(
    scanner: &gvm_gmp::responses::Scanner,
    name: &str,
    host: &str,
    port: u16,
    scanner_type: &str,
    ca_pub: &str,
    credential_id: &str,
) {
    assert_eq!(scanner.meta.name, name);
    assert_eq!(scanner.host.as_deref(), Some(host));
    assert_eq!(scanner.port, Some(port));
    assert_eq!(scanner.scanner_type.as_deref(), Some(scanner_type));
    assert_eq!(scanner.ca_pub.as_deref(), Some(ca_pub));
    assert_eq!(
        scanner
            .credential
            .as_ref()
            .map(|credential| credential.id.as_str()),
        Some(credential_id)
    );
}

async fn assert_partial_scanner_modify_preserves_fields(
    client: &mut GmpClient<UnixSocketConnection>,
    scanner_id: &EntityId,
) {
    client
        .modify_scanner(
            scanner_id,
            ScannerOpts {
                comment: Some("omitted fields stay unchanged".into()),
                ..Default::default()
            },
        )
        .await
        .expect("partial modify_scanner should succeed");
    let scanner = client
        .get_scanner(scanner_id)
        .await
        .expect("get_scanner after partial modify should succeed");
    assert_eq!(scanner.items[0].port, Some(9391));
    assert_eq!(scanner.items[0].ca_pub.as_deref(), Some("Replacement CA"));
    assert_eq!(
        scanner.items[0]
            .credential
            .as_ref()
            .map(|credential| credential.id.as_str()),
        Some("credential-2")
    );
}

async fn typed_scanner_lifecycle(client: &mut GmpClient<UnixSocketConnection>) {
    let created_scanner = client
        .create_scanner(
            "Typed Scanner",
            ScannerOpts {
                host: Some("scanner.example".into()),
                port: Some(9390),
                scanner_type: Some(gvm_gmp::ScannerType::OpenVasScanner),
                ca_pub: Some("Initial CA".into()),
                credential_id: Some(EntityId::new("credential-1").expect("valid id")),
                ..Default::default()
            },
        )
        .await
        .expect("create_scanner should succeed");
    let scanner_id = created_scanner.id;

    let fetched_scanner = client
        .get_scanner(&scanner_id)
        .await
        .expect("get_scanner should succeed");
    assert_eq!(fetched_scanner.items.len(), 1);
    assert_eq!(fetched_scanner.items[0].meta.id, scanner_id);
    assert_scanner_connection_fields(
        &fetched_scanner.items[0],
        "Typed Scanner",
        "scanner.example",
        9390,
        "2",
        "Initial CA",
        "credential-1",
    );

    client
        .modify_scanner(
            &scanner_id,
            ScannerOpts {
                name: Some("Renamed Scanner".into()),
                comment: Some("updated".into()),
                host: Some("127.0.0.1".into()),
                port: Some(9391),
                scanner_type: Some(gvm_gmp::ScannerType::GreenBoneSensorType),
                ca_pub: Some("Replacement CA".into()),
                credential_id: Some(EntityId::new("credential-2").expect("valid id")),
            },
        )
        .await
        .expect("modify_scanner should succeed");

    let updated_scanner = client
        .get_scanner(&scanner_id)
        .await
        .expect("get_scanner after modify should succeed");
    assert_eq!(
        updated_scanner.items[0].meta.comment.as_deref(),
        Some("updated")
    );
    assert_scanner_connection_fields(
        &updated_scanner.items[0],
        "Renamed Scanner",
        "127.0.0.1",
        9391,
        "5",
        "Replacement CA",
        "credential-2",
    );

    assert_partial_scanner_modify_preserves_fields(client, &scanner_id).await;

    client
        .verify_scanner(&scanner_id)
        .await
        .expect("verify_scanner should succeed");

    let cloned_scanner = client
        .clone_scanner(&scanner_id)
        .await
        .expect("clone_scanner should succeed");
    let cloned_scanner_id = cloned_scanner.id;
    let cloned_scanner_response = client
        .get_scanner(&cloned_scanner_id)
        .await
        .expect("get cloned scanner should succeed");
    assert_eq!(
        cloned_scanner_response.items[0].meta.name,
        "Renamed Scanner"
    );

    client
        .delete_scanner(&cloned_scanner_id, true)
        .await
        .expect("delete cloned scanner should succeed");
    client
        .delete_scanner(&scanner_id, true)
        .await
        .expect("delete original scanner should succeed");
}

#[tokio::test]
async fn typed_scan_config_and_scanner_helpers_cover_full_lifecycle() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    typed_scan_config_lifecycle(&mut client).await;
    typed_scanner_lifecycle(&mut client).await;

    server.shutdown().await;
}

#[tokio::test]
async fn typed_schedule_create_observe_modify_and_reobserve() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = GmpClient::connect(unix_connection(&server))
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let first_run =
        ScheduleTimestamp::parse("2030-01-01T00:00:00Z").expect("valid first run timestamp");
    let created = client
        .create_typed_schedule(
            "Typed Schedule",
            ScheduleInput::new(
                ScheduleDefinition {
                    first_run: first_run.clone(),
                    recurrence: ScheduleRecurrence::Daily,
                },
                ScheduleTimezone::new("UTC").expect("valid timezone"),
            ),
        )
        .await
        .expect("typed schedule create should succeed");

    let schedules = client
        .get_schedules(GetSchedulesOpts::default())
        .await
        .expect("schedule observation should succeed");
    let schedule = schedules
        .items
        .iter()
        .find(|schedule| schedule.meta.id == created.id)
        .expect("created schedule should be listed");
    assert_eq!(schedule.first_run_at.as_ref(), Some(&first_run));
    assert_eq!(schedule.next_run_at.as_ref(), Some(&first_run));
    assert_eq!(
        schedule.observation.as_ref().map(|value| &value.recurrence),
        Some(&ScheduleRecurrenceObservation::Supported(
            ScheduleRecurrence::Daily
        ))
    );
    let raw_icalendar = schedule
        .icalendar
        .clone()
        .expect("created schedule has iCalendar");

    client
        .modify_schedule(
            &created.id,
            ScheduleOpts {
                comment: Some("raw compatibility update".to_string()),
                icalendar: Some(raw_icalendar),
                ..Default::default()
            },
        )
        .await
        .expect("raw schedule modify should remain available");

    let modified_first_run =
        ScheduleTimestamp::parse("2031-02-03T04:05:06Z").expect("valid modified timestamp");
    let mut input = ScheduleInput::new(
        ScheduleDefinition {
            first_run: modified_first_run.clone(),
            recurrence: ScheduleRecurrence::Weekly,
        },
        ScheduleTimezone::new("Europe/Berlin").expect("valid timezone"),
    );
    input.name = Some("Modified Typed Schedule".to_string());
    client
        .modify_typed_schedule(&created.id, input)
        .await
        .expect("typed schedule modify should succeed");

    let schedules = client
        .get_schedules(GetSchedulesOpts::default())
        .await
        .expect("modified schedule observation should succeed");
    let schedule = schedules
        .items
        .iter()
        .find(|schedule| schedule.meta.id == created.id)
        .expect("modified schedule should be listed");
    assert_eq!(schedule.meta.name, "Modified Typed Schedule");
    assert_eq!(schedule.timezone.as_deref(), Some("Europe/Berlin"));
    assert_eq!(schedule.first_run_at.as_ref(), Some(&modified_first_run));
    assert_eq!(schedule.next_run_at.as_ref(), Some(&modified_first_run));
    assert_eq!(
        schedule.observation.as_ref().map(|value| &value.recurrence),
        Some(&ScheduleRecurrenceObservation::Supported(
            ScheduleRecurrence::Weekly
        ))
    );

    server.shutdown().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn typed_task_schedule_relationship_round_trip_and_dependency_ordering() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = GmpClient::connect(unix_connection(&server))
        .await
        .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authenticate should succeed");

    let target = client
        .create_target(
            "Scheduled Task Target",
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..Default::default()
            },
        )
        .await
        .expect("target create should succeed");
    let config_id = "daba56c8-73ec-11df-a475-002264764cea"
        .parse()
        .expect("config id");
    let scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
        .parse()
        .expect("scanner id");
    let schedule_input = |timestamp: &str| {
        ScheduleInput::new(
            ScheduleDefinition {
                first_run: ScheduleTimestamp::parse(timestamp).expect("valid timestamp"),
                recurrence: ScheduleRecurrence::Daily,
            },
            ScheduleTimezone::new("UTC").expect("valid timezone"),
        )
    };
    let first_schedule = client
        .create_typed_schedule(
            "First Task Schedule",
            schedule_input("2030-01-01T00:00:00Z"),
        )
        .await
        .expect("first schedule create should succeed");
    let second_schedule = client
        .create_typed_schedule(
            "Second Task Schedule",
            schedule_input("2031-01-01T00:00:00Z"),
        )
        .await
        .expect("second schedule create should succeed");

    let unscheduled = client
        .create_task(
            "Unscheduled Task",
            &config_id,
            &target.id,
            &scanner_id,
            CreateTaskOpts::default(),
        )
        .await
        .expect("unscheduled task create should succeed");
    let tasks = client
        .get_tasks(GetTasksOpts::default())
        .await
        .expect("task observation should succeed");
    let unscheduled_task = tasks
        .items
        .iter()
        .find(|task| task.meta.id == unscheduled.id)
        .expect("unscheduled task should be listed");
    assert!(unscheduled_task.schedule.is_none());
    assert_eq!(unscheduled_task.schedule_periods, Some(0));
    client
        .delete_task(&unscheduled.id, true)
        .await
        .expect("unscheduled task delete should succeed");

    let scheduled = client
        .create_task(
            "Scheduled Task",
            &config_id,
            &target.id,
            &scanner_id,
            CreateTaskOpts {
                schedule_id: Some(first_schedule.id.clone()),
                schedule_periods: Some(3),
                ..Default::default()
            },
        )
        .await
        .expect("scheduled task create should succeed");
    let observed = client
        .get_tasks(GetTasksOpts::default())
        .await
        .expect("task observation should succeed")
        .items
        .into_iter()
        .find(|task| task.meta.id == scheduled.id)
        .expect("created task should be listed");
    assert_eq!(
        observed
            .schedule
            .as_ref()
            .expect("created task should expose its schedule")
            .id,
        first_schedule.id
    );
    assert_eq!(observed.schedule_periods, Some(3));

    client
        .modify_task(
            &scheduled.id,
            ModifyTaskOpts {
                comment: Some("schedule omitted".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("omitting schedule should preserve it");
    let preserved = client
        .get_tasks(GetTasksOpts::default())
        .await
        .expect("task observation should succeed")
        .items
        .into_iter()
        .find(|task| task.meta.id == scheduled.id)
        .expect("scheduled task should be listed");
    assert_eq!(
        preserved
            .schedule
            .as_ref()
            .expect("omitted schedule should remain attached")
            .id,
        first_schedule.id
    );
    assert_eq!(preserved.schedule_periods, Some(3));

    client
        .modify_task(
            &scheduled.id,
            ModifyTaskOpts {
                schedule_id: ScalarUpdate::set(second_schedule.id.clone()),
                ..Default::default()
            },
        )
        .await
        .expect("schedule replacement should succeed");
    let replaced = client
        .get_tasks(GetTasksOpts::default())
        .await
        .expect("task observation should succeed")
        .items
        .into_iter()
        .find(|task| task.meta.id == scheduled.id)
        .expect("scheduled task should be listed");
    assert_eq!(
        replaced
            .schedule
            .as_ref()
            .expect("replaced schedule should be exposed")
            .id,
        second_schedule.id
    );
    assert_eq!(replaced.schedule_periods, Some(0));

    client
        .modify_task(
            &scheduled.id,
            ModifyTaskOpts {
                schedule_periods: Some(7),
                ..Default::default()
            },
        )
        .await
        .expect("period-only update should succeed");
    let period_updated = client
        .get_tasks(GetTasksOpts::default())
        .await
        .expect("task observation should succeed")
        .items
        .into_iter()
        .find(|task| task.meta.id == scheduled.id)
        .expect("scheduled task should be listed");
    assert_eq!(
        period_updated
            .schedule
            .as_ref()
            .expect("period-only update should preserve the schedule")
            .id,
        second_schedule.id
    );
    assert_eq!(period_updated.schedule_periods, Some(7));

    let missing_schedule: EntityId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        .parse()
        .expect("missing schedule id");
    let create_error = client
        .create_task(
            "Missing Schedule Task",
            &config_id,
            &target.id,
            &scanner_id,
            CreateTaskOpts {
                schedule_id: Some(missing_schedule.clone()),
                ..Default::default()
            },
        )
        .await
        .expect_err("missing schedule create should fail");
    assert!(
        matches!(
            &create_error,
            GvmError::Parse(ParseError::ServerError { status: 404, .. })
        ),
        "unexpected create error: {create_error:?}"
    );
    let modify_error = client
        .modify_task(
            &scheduled.id,
            ModifyTaskOpts {
                schedule_id: ScalarUpdate::set(missing_schedule),
                ..Default::default()
            },
        )
        .await
        .expect_err("missing schedule replacement should fail");
    assert!(
        matches!(
            &modify_error,
            GvmError::Parse(ParseError::ServerError { status: 404, .. })
        ),
        "unexpected modify error: {modify_error:?}"
    );
    let after_failed_update = client
        .get_tasks(GetTasksOpts::default())
        .await
        .expect("task observation should succeed")
        .items
        .into_iter()
        .find(|task| task.meta.id == scheduled.id)
        .expect("scheduled task should be listed");
    assert_eq!(
        after_failed_update
            .schedule
            .as_ref()
            .expect("failed update must preserve the schedule")
            .id,
        second_schedule.id
    );
    assert_eq!(after_failed_update.schedule_periods, Some(7));

    let dependency_error = client
        .delete_schedule(&second_schedule.id, true)
        .await
        .expect_err("attached schedule deletion should fail");
    assert!(matches!(
        dependency_error,
        GvmError::Parse(ParseError::ServerError { status: 409, .. })
    ));
    client
        .modify_task(
            &scheduled.id,
            ModifyTaskOpts {
                schedule_id: ScalarUpdate::Clear,
                ..Default::default()
            },
        )
        .await
        .expect("schedule clearing should succeed");
    let cleared = client
        .get_tasks(GetTasksOpts::default())
        .await
        .expect("task observation should succeed")
        .items
        .into_iter()
        .find(|task| task.meta.id == scheduled.id)
        .expect("scheduled task should be listed");
    assert!(cleared.schedule.is_none());
    assert_eq!(cleared.schedule_periods, Some(0));

    client
        .delete_schedule(&second_schedule.id, true)
        .await
        .expect("detached schedule delete should succeed");
    client
        .modify_task(
            &scheduled.id,
            ModifyTaskOpts {
                schedule_id: ScalarUpdate::set(first_schedule.id.clone()),
                schedule_periods: Some(4),
                ..Default::default()
            },
        )
        .await
        .expect("schedule reattachment should succeed");
    client
        .delete_task(&scheduled.id, false)
        .await
        .expect("task trash should succeed");
    let trashed_dependency_error = client
        .delete_schedule(&first_schedule.id, true)
        .await
        .expect_err("trashed dependent task should block permanent schedule deletion");
    assert!(matches!(
        trashed_dependency_error,
        GvmError::Parse(ParseError::ServerError { status: 409, .. })
    ));
    client
        .delete_task(&scheduled.id, true)
        .await
        .expect("permanent task delete should succeed");
    client
        .delete_schedule(&first_schedule.id, true)
        .await
        .expect("schedule delete after dependent task should succeed");
    client
        .delete_target(&target.id, true)
        .await
        .expect("target delete should succeed");

    server.shutdown().await;
}

#[tokio::test]
async fn disconnect_leaves_transport_disconnected() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .disconnect()
        .await
        .expect("disconnect should succeed");

    assert!(!client.connection().is_connected());

    server.shutdown().await;
}

#[tokio::test]
async fn send_after_disconnect_returns_connection_error() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    client
        .disconnect()
        .await
        .expect("disconnect should succeed");

    let error = client
        .send(get_targets(Default::default()))
        .await
        .expect_err("sending after disconnect should fail");
    match error {
        GvmError::Connection(ConnectionError::NotConnected) => {}
        other => panic!("expected connection error, got {other:?}"),
    }

    server.shutdown().await;
}
