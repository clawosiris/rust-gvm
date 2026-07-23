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
#[cfg(feature = "tls")]
use tempfile::TempDir;

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

#[tokio::test]
async fn builder_rejects_zero_request_limit() {
    let result = MockGmpServer::builder()
        .with_max_request_bytes(Some(0))
        .unix_socket_auto()
        .build()
        .await;
    let error = match result {
        Ok(server) => {
            server.shutdown().await;
            panic!("zero request limit must be rejected");
        }
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn builder_requires_a_transport() {
    let result = MockGmpServer::builder().build().await;
    let error = match result {
        Ok(server) => {
            server.shutdown().await;
            panic!("builder without a transport must fail");
        }
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("No transport configured"));
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn builder_tls_mode_exposes_address_and_certificate() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .tls("127.0.0.1:0")
        .build()
        .await
        .expect("TLS server should start");

    assert!(server.tls_addr().is_some());
    assert!(server.tls_port().is_some());
    assert!(server
        .tls_certificate_pem()
        .expect("generated certificate")
        .contains("BEGIN CERTIFICATE"));
    server.shutdown().await;
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn client_certificate_requirement_needs_tls_transport() {
    let result = MockGmpServer::builder()
        .tcp("127.0.0.1:0")
        .require_client_cert("unused.pem")
        .build()
        .await;
    let error = match result {
        Ok(server) => {
            server.shutdown().await;
            panic!("client certificates without TLS must be rejected");
        }
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("can only be used with tls"));
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn empty_client_ca_is_rejected() {
    let directory = TempDir::new().expect("temporary directory");
    let ca_path = directory.path().join("empty-ca.pem");
    std::fs::write(&ca_path, "").expect("write empty CA");

    let result = MockGmpServer::builder()
        .tls("127.0.0.1:0")
        .require_client_cert(ca_path)
        .build()
        .await;
    let error = match result {
        Ok(server) => {
            server.shutdown().await;
            panic!("empty client CA must be rejected");
        }
        Err(error) => error,
    };

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("contains no certificates"));
}
