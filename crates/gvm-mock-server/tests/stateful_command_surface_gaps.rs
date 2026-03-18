// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Integration coverage for the newly added command-surface gaps.

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

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn stateful_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_6)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server start failed: {error}"),
    }
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

async fn auth_admin(stream: &mut UnixStream) {
    let resp = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
}

fn extract_id(resp: &Response) -> String {
    resp.id().expect("response should contain id")
}

#[tokio::test]
async fn stateful_get_feeds_returns_static_entries() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, b"<get_feeds/>").await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("Network Vulnerability Tests"));
    assert!(text.contains("<type>SCAP</type>"));
    assert!(text.contains("<feed_count>3"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_policies_round_trip_with_usage_type_filtering() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let policy_resp = send_recv(
        &mut stream,
        b"<create_config><name>Policy One</name><usage_type>policy</usage_type></create_config>",
    )
    .await;
    let policy_id = extract_id(&policy_resp);
    send_recv(
        &mut stream,
        b"<create_config><name>Scan Config One</name><usage_type>scan</usage_type></create_config>",
    )
    .await;

    let policies = send_recv(&mut stream, br#"<get_configs usage_type="policy"/>"#).await;
    let policies_text = policies.as_str().expect("utf8");
    assert!(policies_text.contains("Policy One"));
    assert!(!policies_text.contains("Scan Config One"));

    let modify = send_recv(
        &mut stream,
        format!(
            "<modify_config config_id=\"{policy_id}\"><comment>updated</comment><usage_type>policy</usage_type></modify_config>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let get_one = send_recv(
        &mut stream,
        format!("<get_configs config_id=\"{policy_id}\" usage_type=\"policy\"/>").as_bytes(),
    )
    .await;
    let get_one_text = get_one.as_str().expect("utf8");
    assert!(get_one_text.contains("<usage_type>policy</usage_type>"));
    assert!(get_one_text.contains("<comment>updated</comment>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_audits_round_trip_with_usage_type_filtering() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let audit_resp = send_recv(
        &mut stream,
        b"<create_task><name>Audit One</name><usage_type>audit</usage_type><target id=\"t1\"/><config id=\"c1\"/><scanner id=\"s1\"/></create_task>",
    )
    .await;
    let audit_id = extract_id(&audit_resp);
    send_recv(
        &mut stream,
        b"<create_task><name>Scan One</name><usage_type>scan</usage_type><target id=\"t2\"/><config id=\"c2\"/><scanner id=\"s2\"/></create_task>",
    )
    .await;

    let audits = send_recv(&mut stream, br#"<get_tasks usage_type="audit"/>"#).await;
    let audits_text = audits.as_str().expect("utf8");
    assert!(audits_text.contains("Audit One"));
    assert!(!audits_text.contains("Scan One"));

    let modify = send_recv(
        &mut stream,
        format!(
            "<modify_task task_id=\"{audit_id}\"><comment>updated</comment><usage_type>audit</usage_type></modify_task>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let start = send_recv(
        &mut stream,
        format!("<start_task task_id=\"{audit_id}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(start.status_code(), Some(202));

    let get_one = send_recv(
        &mut stream,
        format!("<get_tasks task_id=\"{audit_id}\" usage_type=\"audit\"/>").as_bytes(),
    )
    .await;
    let get_one_text = get_one.as_str().expect("utf8");
    assert!(get_one_text.contains("<usage_type>audit</usage_type>"));
    assert!(get_one_text.contains("<comment>updated</comment>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_help_returns_command_listing() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, br#"<help format="brief"/>"#).await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<command>get_feeds</command>"));
    assert!(text.contains("<command>get_tasks</command>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_aggregates_returns_fixture_response() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(
        &mut stream,
        br#"<get_aggregates type="task" group_column="severity"/>"#,
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<type>task</type>"));
    assert!(text.contains("<group_column>severity</group_column>"));
    assert!(text.contains("<aggregate><text>High</text><value>3</value></aggregate>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_user_settings_get_and_modify() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let list = send_recv(&mut stream, b"<get_settings/>").await;
    assert_eq!(list.status_code(), Some(200));
    let list_text = list.as_str().expect("utf8");
    assert!(list_text.contains("timezone"));
    assert!(list_text.contains("<value>UTC</value>"));

    let setting_id = "00000000-0000-0000-0000-000000000001";
    let modify = send_recv(
        &mut stream,
        format!(
            "<modify_setting setting_id=\"{setting_id}\"><value>Europe/Berlin</value></modify_setting>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let get_one = send_recv(
        &mut stream,
        format!("<get_settings setting_id=\"{setting_id}\"/>").as_bytes(),
    )
    .await;
    let get_one_text = get_one.as_str().expect("utf8");
    assert!(get_one_text.contains("<value>Europe/Berlin</value>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_system_reports_return_fixture_response() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, b"<get_system_reports/>").await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("GVMD Performance Snapshot"));
    assert!(text.contains("<system_report_count>1"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_secinfo_returns_typed_entries() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(&mut stream, br#"<get_info type="vuln"/>"#).await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<vuln id=\"vuln-1\">"));
    assert!(text.contains("Outdated package"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_audit_reports_filter_by_usage_type() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let audit_task = send_recv(
        &mut stream,
        b"<create_task><name>Audit Task</name><usage_type>audit</usage_type><target id=\"t1\"/><config id=\"c1\"/><scanner id=\"s1\"/></create_task>",
    )
    .await;
    let scan_task = send_recv(
        &mut stream,
        b"<create_task><name>Scan Task</name><usage_type>scan</usage_type><target id=\"t2\"/><config id=\"c2\"/><scanner id=\"s2\"/></create_task>",
    )
    .await;
    let audit_task_id = extract_id(&audit_task);
    let scan_task_id = extract_id(&scan_task);

    let audit_report = send_recv(
        &mut stream,
        format!("<create_report><task id=\"{audit_task_id}\"/></create_report>").as_bytes(),
    )
    .await;
    let _scan_report = send_recv(
        &mut stream,
        format!("<create_report><task id=\"{scan_task_id}\"/></create_report>").as_bytes(),
    )
    .await;
    let audit_report_id = extract_id(&audit_report);

    let reports = send_recv(&mut stream, br#"<get_reports usage_type="audit"/>"#).await;
    let reports_text = reports.as_str().expect("utf8");
    assert!(reports_text.contains(&audit_report_id));
    assert!(reports_text.contains("<usage_type>audit</usage_type>"));
    assert!(!reports_text.contains("Scan Task"));

    let delete = send_recv(
        &mut stream,
        format!("<delete_report report_id=\"{audit_report_id}\" ultimate=\"0\"/>").as_bytes(),
    )
    .await;
    assert_eq!(delete.status_code(), Some(200));

    server.shutdown().await;
}
