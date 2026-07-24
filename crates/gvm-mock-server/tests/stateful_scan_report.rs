// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Stateful `get_scan_report` behavior from the current public gvmd contract.

#![cfg(feature = "unix-socket-tests")]
#![allow(clippy::unwrap_used, missing_docs)]

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const SCAN_REPORT_ID: &str = "10000000-0000-4000-8000-000000000001";
const AUDIT_REPORT_ID: &str = "10000000-0000-4000-8000-000000000002";
const ABSENT_REPORT_ID: &str = "10000000-0000-4000-8000-000000000003";
const ABSENT_FILTER_ID: &str = "40000000-0000-4000-8000-000000000001";

async fn send_recv(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn connect_and_auth(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().expect("Unix socket path"))
        .await
        .expect("connect failed");
    let response = send_recv(
        &mut stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    stream
}

async fn scan_report_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(|store| {
            let mut scan_report = Resource::with_id(
                "report",
                "Running Scan",
                SCAN_REPORT_ID.parse().expect("valid scan report UUID"),
            );
            scan_report.set_attr("status", "Running");
            scan_report.set_attr("usage_type", "scan");
            store.seed(scan_report);

            let mut audit_report = Resource::with_id(
                "report",
                "Audit Report",
                AUDIT_REPORT_ID.parse().expect("valid audit report UUID"),
            );
            audit_report.set_attr("status", "Done");
            audit_report.set_attr("usage_type", "audit");
            store.seed(audit_report);
        })
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn assert_scan_report_errors(stream: &mut UnixStream) {
    for (request, status) in [
        ("<get_scan_report/>".to_string(), 400),
        (
            "<get_scan_report scan_report_id=\"not-a-uuid\"/>".to_string(),
            400,
        ),
        (
            format!("<get_scan_report scan_report_id=\"{ABSENT_REPORT_ID}\"/>"),
            404,
        ),
        (
            format!(
                "<get_scan_report scan_report_id=\"{SCAN_REPORT_ID}\" filt_id=\"not-a-uuid\"/>"
            ),
            400,
        ),
        (
            format!(
                "<get_scan_report scan_report_id=\"{SCAN_REPORT_ID}\" filt_id=\"{ABSENT_FILTER_ID}\"/>"
            ),
            400,
        ),
        (
            format!("<get_scan_report scan_report_id=\"{AUDIT_REPORT_ID}\"/>"),
            400,
        ),
    ] {
        assert_eq!(
            send_recv(stream, request.as_bytes())
                .await
                .status_code(),
            Some(status),
            "unexpected status for {request}"
        );
    }
}

async fn assert_scan_report_filter_resolution(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        format!("<get_scan_report scan_report_id=\"{SCAN_REPORT_ID}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    let xml = response.as_str().expect("valid UTF-8 response");
    assert!(xml.contains("<writable>0</writable><in_use>0</in_use>"));
    assert!(xml.contains("<scan_run_status>Running</scan_run_status>"));
    assert!(xml.contains("<task><name></name><comment></comment><progress>0</progress></task>"));
    assert!(xml.contains("<result_count>0<full>0</full><filtered>0</filtered>"));
    assert!(xml.contains("<scan_end></scan_end>"));
    assert!(xml.contains("<filters id=\"\"><term>apply_overrides=0 min_qod=70</term><keywords>"));
    assert!(xml.contains("<sort><field>name<order>ascending</order></field></sort>"));

    let response = send_recv(
        stream,
        format!(
            "<get_scan_report scan_report_id=\"{SCAN_REPORT_ID}\" \
             filter=\"sort=host min_qod=0 apply_overrides=1\"/>"
        )
        .as_bytes(),
    )
    .await;
    let xml = response.as_str().expect("valid UTF-8 response");
    assert!(xml.contains("<term>sort=host min_qod=0 apply_overrides=1</term>"));
    assert!(xml.contains("<sort><field>host<order>ascending</order></field></sort>"));

    let created_filter = send_recv(
        stream,
        b"<create_filter><name>Scan Results</name><term>levels=l</term></create_filter>",
    )
    .await;
    assert_eq!(created_filter.status_code(), Some(201));
    let filter_id = created_filter.id().expect("created filter ID");
    let response = send_recv(
        stream,
        format!(
            "<get_scan_report scan_report_id=\"{SCAN_REPORT_ID}\" \
             filt_id=\"{filter_id}\" filter=\"levels=c\"/>"
        )
        .as_bytes(),
    )
    .await;
    let xml = response.as_str().expect("valid UTF-8 response");
    assert!(xml.contains(&format!(
        "<filters id=\"{filter_id}\"><term>apply_overrides=0 min_qod=70 levels=l</term>"
    )));
    assert!(xml.contains("<sort><field>name<order>ascending</order></field></sort>"));

    let modified_filter = send_recv(
        stream,
        format!("<modify_filter filter_id=\"{filter_id}\"><term>levels=hm</term></modify_filter>")
            .as_bytes(),
    )
    .await;
    assert_eq!(modified_filter.status_code(), Some(200));
    let response = send_recv(
        stream,
        format!("<get_scan_report scan_report_id=\"{SCAN_REPORT_ID}\" filt_id=\"{filter_id}\"/>")
            .as_bytes(),
    )
    .await;
    assert!(response
        .as_str()
        .expect("valid UTF-8 response")
        .contains("<term>apply_overrides=0 min_qod=70 levels=hm</term>"));
}

#[tokio::test]
async fn stateful_get_scan_report_validates_ids_type_and_singular_response() {
    let Some(server) = scan_report_server().await else {
        return;
    };
    let mut stream = connect_and_auth(&server).await;
    assert_scan_report_errors(&mut stream).await;
    assert_scan_report_filter_resolution(&mut stream).await;
    server.shutdown().await;
}
