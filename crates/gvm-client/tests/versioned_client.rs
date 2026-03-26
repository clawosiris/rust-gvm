// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::print_stderr, missing_docs)]

use gvm_client::{Gmp226Commands, GmpVersioned};
use gvm_connection::UnixSocketConnection;
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
            | (227, GmpVersioned::V227(_)) => {}
            (_, other) => panic!("unexpected versioned client: {other:?}"),
        }

        server.shutdown().await;
    }
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
