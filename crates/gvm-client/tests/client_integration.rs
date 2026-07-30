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
use gvm_gmp::commands::alerts::{trigger_alert, TriggerAlertOpts};
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
    modify_credential_store_credential, CredentialStorePreference,
    ModifyCredentialStoreCredentialOpts as GmpModifyCredentialStoreCredentialOpts,
    ModifyCredentialStoreOpts,
};
use gvm_gmp::commands::help::HelpMode;
use gvm_gmp::commands::nvts::{
    get_nvt_preference, get_nvt_preferences, GetNvtPreferencesOpts, GetNvtsOpts,
};
use gvm_gmp::commands::operating_systems::{get_operating_systems, GetOperatingSystemsOpts};
use gvm_gmp::commands::permissions::{modify_permission, GetPermissionsOpts, PermissionOpts};
use gvm_gmp::commands::reports::{
    get_report_export, get_report_hosts, get_report_vulnerabilities, get_reports, GetReportsOpts,
};
use gvm_gmp::commands::roles::RoleOpts;
use gvm_gmp::commands::scan_configs::{
    create_policy, get_policies, get_scan_config_preference, get_scan_config_preferences,
    ConfigOpts, GetPolicyOpts, GetScanConfigPreferencesOpts, GetScanConfigsOpts,
};
use gvm_gmp::commands::scanners::ScannerOpts;
use gvm_gmp::commands::secinfo::{get_info, get_info_list, GenericInfoType, GetInfoListOpts};
use gvm_gmp::commands::system::get_timezones;
use gvm_gmp::commands::targets::{
    create_target, delete_target, get_targets, CreateTargetOpts, GetTargetsOpts,
};
use gvm_gmp::commands::tasks::{create_task, delete_task, get_task, start_task, stop_task};
use gvm_gmp::responses::{
    Asset, ConfigUsageKind, CreateScanConfigResponse, GetConfigsResponse, GetPermissionsResponse,
    GetScanConfigsResponse, Permission,
};
use gvm_gmp::types::EntityId;
use gvm_gmp::types::GmpVersion;
use gvm_gmp::{FeedType, PermissionSubjectType, SortOrder};
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
        .call(create_target(
            "Integration Target",
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        ))
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
    let xml = response.as_str().expect("response should be UTF-8");

    assert!(xml.starts_with("<get_scan_report_response status=\"200\""));
    assert!(xml.contains(&format!("<report id=\"{SCAN_REPORT_ID}\">")));
    assert!(xml.contains("<scan_run_status>Done</scan_run_status>"));
    assert!(xml.contains("<hosts><count>6</count></hosts>"));
    assert!(xml.contains("<vulns><count>7</count></vulns>"));
    assert!(xml.contains("<errors><count>1</count></errors>"));
    assert!(xml.contains(&format!("<task id=\"{SCAN_REPORT_TASK_ID}\">")));
    assert!(xml.contains(&format!("<target id=\"{SCAN_REPORT_TARGET_ID}\">")));
    assert!(xml.contains("<target_type>target</target_type>"));
    assert!(xml.contains("<full>7</full><filtered>2</filtered>"));
    assert!(xml.contains("<severity><full>9.5</full><filtered>9.5</filtered></severity>"));
    assert!(xml.contains(&format!("<filters id=\"{SCAN_REPORT_FILTER_ID}\">")));
    assert!(xml.contains("<column>levels</column>"));
    assert!(xml.contains("<sort><field>severity<order>descending</order></field></sort>"));
    assert!(xml.contains("<scan_report start=\"1\" max=\"1\"/>"));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "get_scan_report");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("request should be UTF-8"),
        format!(
            "<get_scan_report filt_id=\"{SCAN_REPORT_FILTER_ID}\" filter=\"levels=l\" \
             scan_report_id=\"{SCAN_REPORT_ID}\"/>"
        )
    );

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
        .call(create_target(
            "Lifecycle Target",
            CreateTargetOpts {
                hosts: vec!["127.0.0.1".to_string()],
                ..CreateTargetOpts::default()
            },
        ))
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
    assert!(start_response.report_id.is_some());

    client
        .call(stop_task(&task_id))
        .await
        .expect("stop_task should succeed");

    let resume_response = client
        .resume_task(&task_id)
        .await
        .expect("resume_task should succeed");
    assert_eq!(resume_response.status, 202);
    assert!(resume_response.report_id.is_some());

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
        .sync_scan_config(&config_id)
        .await
        .expect("sync_scan_config should succeed");

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

async fn typed_scanner_lifecycle(client: &mut GmpClient<UnixSocketConnection>) {
    let created_scanner = client
        .create_scanner("Typed Scanner", ScannerOpts::default())
        .await
        .expect("create_scanner should succeed");
    let scanner_id = created_scanner.id;

    let fetched_scanner = client
        .get_scanner(&scanner_id)
        .await
        .expect("get_scanner should succeed");
    assert_eq!(fetched_scanner.items.len(), 1);
    assert_eq!(fetched_scanner.items[0].meta.id, scanner_id);
    assert_eq!(fetched_scanner.items[0].meta.name, "Typed Scanner");

    client
        .modify_scanner(
            &scanner_id,
            ScannerOpts {
                comment: Some("updated".into()),
                host: Some("127.0.0.1".into()),
                port: Some(9390),
                ..Default::default()
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
    assert_eq!(updated_scanner.items[0].host.as_deref(), Some("127.0.0.1"));
    assert_eq!(updated_scanner.items[0].port, Some(9390));

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
    assert_eq!(cloned_scanner_response.items[0].meta.name, "Typed Scanner");

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
