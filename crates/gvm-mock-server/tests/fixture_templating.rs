// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration tests for template variable substitution in Fixture mode.

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

/// Helper: send XML and read response via Unix socket.
async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

/// Helper: start a fixture server for the given version and connect a stream.
async fn fixture_server(version: GmpVersion) -> Option<(MockGmpServer, UnixStream)> {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(version)
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("server start failed: {error}"),
    };

    let path = server.socket_path().expect("should have socket path");
    let stream = UnixStream::connect(path).await.expect("connect failed");
    Some((server, stream))
}

fn extract_first_attr(text: &str, attr: &str) -> String {
    let needle = format!(r#"{attr}=""#);
    let start = text.find(&needle).expect("attribute should exist") + needle.len();
    let rest = &text[start..];
    let end = rest.find('"').expect("attribute should terminate");
    rest[..end].to_string()
}

fn extract_tag_value(text: &str, tag: &str) -> String {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let start = text.find(&start_tag).expect("tag should exist") + start_tag.len();
    let rest = &text[start..];
    let end = rest.find(&end_tag).expect("tag should terminate");
    rest[..end].to_string()
}

#[tokio::test]
async fn template_uuid_substitution() {
    let Some((server, mut stream)) = fixture_server(GmpVersion::V22_5).await else {
        return;
    };

    let resp = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    let text = resp.as_str().expect("response should be valid utf8");
    let id = extract_first_attr(text, "id");
    let uuid = Uuid::parse_str(&id).expect("id should be a valid UUID");

    assert_eq!(id.len(), 36, "uuid should be 36 characters");
    assert!(id.contains('-'), "uuid should contain hyphens");
    assert_eq!(uuid.get_version_num(), 4, "uuid should be v4");

    server.shutdown().await;
}

#[tokio::test]
async fn template_uuid_unique_per_call() {
    let Some((server, mut stream)) = fixture_server(GmpVersion::V22_5).await else { return; };

    let resp1 = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;
    let resp2 = send_recv(&mut stream, br#"<get_tasks usage_type="scan"/>"#).await;

    let text1 = resp1.as_str().expect("first response should be valid utf8");
    let text2 = resp2
        .as_str()
        .expect("second response should be valid utf8");
    let id1 = extract_first_attr(text1, "id");
    let id2 = extract_first_attr(text2, "id");

    assert_ne!(id1, id2, "fixture uuid should be regenerated per call");

    server.shutdown().await;
}

#[tokio::test]
async fn template_version_substitution() {
    let Some((server, mut stream)) = fixture_server(GmpVersion::V22_6).await else { return; };

    let resp = send_recv(&mut stream, b"<get_version/>").await;
    let text = resp.as_str().expect("response should be valid utf8");

    assert!(
        text.contains("<version>22.6</version>"),
        "response should contain substituted version, got: {text}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn template_version_v22_4() {
    let Some((server, mut stream)) = fixture_server(GmpVersion::V22_4).await else { return; };

    let resp = send_recv(&mut stream, b"<get_version/>").await;
    let text = resp.as_str().expect("response should be valid utf8");

    assert!(
        text.contains("<version>22.4</version>"),
        "response should contain substituted version, got: {text}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn template_now_substitution() {
    let Some((server, mut stream)) = fixture_server(GmpVersion::V22_5).await else { return; };

    let resp = send_recv(&mut stream, b"<get_tasks/>").await;
    let text = resp.as_str().expect("response should be valid utf8");
    let timestamp = if text.contains("<creation_time>") {
        extract_tag_value(text, "creation_time")
    } else {
        extract_tag_value(text, "modification_time")
    };

    assert!(
        timestamp.contains("202"),
        "timestamp should contain a current year prefix, got: {timestamp}"
    );
    assert!(
        timestamp.contains('T'),
        "timestamp should look like ISO 8601, got: {timestamp}"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn template_no_raw_placeholders() {
    let Some((server, mut stream)) = fixture_server(GmpVersion::V22_5).await else { return; };

    let resp = send_recv(&mut stream, b"<get_tasks/>").await;
    let text = resp.as_str().expect("response should be valid utf8");

    assert!(
        !text.contains("{{uuid}}"),
        "response should not contain raw uuid placeholder"
    );
    assert!(
        !text.contains("{{now}}"),
        "response should not contain raw now placeholder"
    );
    assert!(
        !text.contains("{{version}}"),
        "response should not contain raw version placeholder"
    );

    server.shutdown().await;
}
