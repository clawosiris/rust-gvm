#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};

#[tokio::test]
async fn builder_tcp_mode() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .tcp("127.0.0.1:0")
        .build()
        .await
        .expect("should start");
    assert!(server.tcp_addr().is_some());
    server.shutdown().await;
}

#[tokio::test]
async fn builder_fixture_mode_with_override() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_4)
        .override_response(
            "get_tasks",
            "<get_tasks_response status=\"200\" status_text=\"OK\"/>",
        )
        .unix_socket_auto()
        .build()
        .await
        .expect("should start");
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
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .credentials("user", "pass")
        .unix_socket_auto()
        .build()
        .await
        .expect("should start");
    server.shutdown().await;
}
