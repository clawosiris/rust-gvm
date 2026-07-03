// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};

async fn build_server(builder: gvm_mock_server::MockGmpServerBuilder) -> Option<MockGmpServer> {
    match builder.build().await {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("should start: {error}"),
    }
}

#[tokio::test]
async fn builder_tcp_mode() {
    let server = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Echo)
            .version(GmpVersion::V22_5)
            .tcp("127.0.0.1:0"),
    )
    .await;
    let Some(server) = server else {
        return;
    };
    assert!(server.tcp_addr().is_some());
    server.shutdown().await;
}

#[tokio::test]
async fn builder_fixture_mode_with_override() {
    let server = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Fixture)
            .version(GmpVersion::V22_4)
            .override_response(
                "get_tasks",
                "<get_tasks_response status=\"200\" status_text=\"OK\"/>",
            )
            .unix_socket_auto(),
    )
    .await;
    let Some(server) = server else {
        return;
    };
    server.shutdown().await;
}

#[tokio::test]
#[should_panic(expected = "seed() is only supported in Stateful mode")]
async fn builder_seed_non_stateful_panics() {
    let _ = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .seed(|_store| {})
        .unix_socket_auto()
        .build()
        .await;
}

#[tokio::test]
async fn builder_with_credentials() {
    let server = build_server(
        MockGmpServer::builder()
            .mode(ServerMode::Stateful)
            .credentials("user", "pass")
            .unix_socket_auto(),
    )
    .await;
    let Some(server) = server else {
        return;
    };
    server.shutdown().await;
}
