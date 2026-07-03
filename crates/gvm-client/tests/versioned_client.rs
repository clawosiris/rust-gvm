// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stderr, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{
    CreateAgentGroupOpts, Gmp226Commands, GmpNextCommands, GmpVersioned, ModifyAgentGroupOpts,
};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::types::EntityId;
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

async fn stateful_server(version: MockVersion) -> Option<MockGmpServer> {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => server,
        Err(error)
            if error.to_string().contains("Permission denied")
                || error.to_string().contains("Operation not permitted") =>
        {
            eprintln!("Skipping: sandbox restriction");
            return None;
        }
        Err(error) => panic!("Failed to start server: {error}"),
    };

    Some(server)
}

fn unix_connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("unix socket path"))
}

#[tokio::test]
async fn versioned_client_resolves_correct_variant() {
    for (version, expected) in [
        (MockVersion::V22_4, 224_u16),
        (MockVersion::V22_5, 225_u16),
        (MockVersion::V22_6, 226_u16),
        (MockVersion::V22_7, 227_u16),
        (MockVersion::V22_8, 228_u16),
    ] {
        let Some(server) = stateful_server(version).await else {
            return;
        };
        let connection = unix_connection(&server);
        let client = GmpVersioned::connect(connection)
            .await
            .expect("client should connect");

        match (expected, client) {
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
async fn next_client_exposes_next_trait_methods() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let response = client
        .get_integration_configs(Default::default())
        .await
        .expect("next-only command should succeed");
    assert_eq!(response.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_agent_groups_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let agent_ids = [
        EntityId::new("agent-1").expect("valid id"),
        EntityId::new("agent-2").expect("valid id"),
    ];
    let create_response = client
        .create_agent_group(
            "Client Agent Group",
            &agent_ids,
            "0 */5 * * *",
            CreateAgentGroupOpts {
                comment: Some("created through client".into()),
            },
        )
        .await
        .expect("create_agent_group should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    let agent_group_id = EntityId::new(create_response.id().expect("created id"))
        .expect("server id should be valid");

    let clone_response = client
        .clone_agent_group(&agent_group_id)
        .await
        .expect("clone_agent_group should succeed");
    assert_eq!(clone_response.status_code(), Some(201));

    let get_response = client
        .get_agent_group(&agent_group_id)
        .await
        .expect("get_agent_group should succeed");
    let get_text = get_response.as_str().expect("valid UTF-8 XML");
    assert!(get_text.contains("Client Agent Group"));
    assert!(get_text.contains("<scheduler_cron_time>0 */5 * * *</scheduler_cron_time>"));

    let list_response = client
        .get_agent_groups(Default::default())
        .await
        .expect("get_agent_groups should succeed");
    assert_eq!(list_response.status_code(), Some(200));
    assert!(list_response
        .as_str()
        .expect("valid UTF-8 XML")
        .contains("<agent_group_count>2"));

    let modify_response = client
        .modify_agent_group(
            &agent_group_id,
            "0 */10 * * *",
            ModifyAgentGroupOpts {
                name: Some("Updated Agent Group".into()),
                comment: Some("modified through client".into()),
                agent_ids: vec![EntityId::new("agent-3").expect("valid id")],
            },
        )
        .await
        .expect("modify_agent_group should succeed");
    assert_eq!(modify_response.status_code(), Some(200));

    let updated_response = client
        .get_agent_group(&agent_group_id)
        .await
        .expect("updated get_agent_group should succeed");
    let updated_text = updated_response.as_str().expect("valid UTF-8 XML");
    assert!(updated_text.contains("Updated Agent Group"));
    assert!(updated_text.contains("<comment>modified through client</comment>"));
    assert!(updated_text.contains("<scheduler_cron_time>0 */10 * * *</scheduler_cron_time>"));

    let delete_response = client
        .delete_agent_group(&agent_group_id, true)
        .await
        .expect("delete_agent_group should succeed");
    assert_eq!(delete_response.status_code(), Some(200));

    let error = client
        .get_agent_group(&agent_group_id)
        .await
        .expect_err("deleted agent group should not be found");
    assert!(matches!(
        error,
        gvm_client::GvmError::Server { status: 404, .. }
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn gmp226_commands_work_on_v226() {
    let Some(server) = stateful_server(MockVersion::V22_6).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    let auth_response = client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");
    assert_eq!(auth_response.status_code(), Some(200));

    let mut client = match client {
        GmpVersioned::V226(client) => client,
        other => panic!("expected V226 client, got {other:?}"),
    };

    let features_response = client
        .get_features()
        .await
        .expect("get_features should succeed");
    assert_eq!(features_response.status_code(), Some(200));

    let create_response = client
        .create_report_config("Client Report Config", "report-format-1")
        .await
        .expect("create_report_config should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    server.shutdown().await;
}
