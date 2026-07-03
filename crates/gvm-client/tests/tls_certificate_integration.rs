// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![cfg(feature = "unix-socket-tests")]
#![allow(missing_docs)]

use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::tls_certificates::clone_tls_certificate;
use gvm_gmp::types::EntityId;
use gvm_mock_server::{MockGmpServer, ServerMode};

async fn echo_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Echo)
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

#[tokio::test]
async fn clone_tls_certificate_sends_create_copy_command() {
    let Some(server) = echo_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let response = client
        .call(clone_tls_certificate(
            &EntityId::new("tls1").expect("valid id"),
        ))
        .await
        .expect("clone_tls_certificate should send create command");

    assert_eq!(response.status_code(), Some(201));

    let history = server.command_history();
    let command = history.last().expect("TLS clone command recorded");
    assert_eq!(command.command_name(), "create_tls_certificate");
    assert_eq!(
        std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command"),
        "<create_tls_certificate><copy>tls1</copy></create_tls_certificate>"
    );

    server.shutdown().await;
}
