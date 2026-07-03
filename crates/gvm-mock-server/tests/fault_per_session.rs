// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_mock_server::{Fault, FaultKind, GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

#[tokio::test]
async fn once_fault_is_scoped_per_session() {
    let Some(server) = (match MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .inject_fault(Fault::once(FaultKind::ServerError500))
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }) else {
        return;
    };

    let path = server.socket_path().expect("should have socket path");

    let mut stream_a = UnixStream::connect(path)
        .await
        .expect("client A connect failed");
    let resp_a = send_recv(&mut stream_a, b"<get_version/>").await;
    assert_eq!(resp_a.status_code(), Some(500));
    drop(stream_a);

    let mut stream_b = UnixStream::connect(path)
        .await
        .expect("client B connect failed");
    let resp_b = send_recv(&mut stream_b, b"<get_version/>").await;
    assert_eq!(resp_b.status_code(), Some(500));

    server.shutdown().await;
}
