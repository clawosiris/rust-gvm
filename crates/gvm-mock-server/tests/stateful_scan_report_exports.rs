// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stderr, clippy::unwrap_used, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::help::{help_with_mode, HelpMode};
use gvm_gmp::commands::reports::{export_scan_report, ExportScanReportOpts};
use gvm_gmp::EntityId;
use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const REPORT_ID: &str = "11111111-1111-1111-1111-111111111111";
const AUDIT_REPORT_ID: &str = "22222222-2222-2222-2222-222222222222";
const DELTA_REPORT_ID: &str = "33333333-3333-3333-3333-333333333333";

async fn stateful_server(version: GmpVersion) -> Option<MockGmpServer> {
    let report_id = Uuid::parse_str(REPORT_ID).expect("valid UUID");
    let audit_report_id = Uuid::parse_str(AUDIT_REPORT_ID).expect("valid UUID");
    let delta_report_id = Uuid::parse_str(DELTA_REPORT_ID).expect("valid UUID");
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .seed(move |store| {
            store.create(Resource::with_id("report", "Scan report", report_id));
            let mut audit_report = Resource::with_id("report", "Audit report", audit_report_id);
            audit_report.set_attr("usage_type", "audit");
            store.create(audit_report);
            let mut delta_report = Resource::with_id("report", "Delta report", delta_report_id);
            delta_report.set_attr("delta", "1");
            store.create(delta_report);
        })
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error)
            if error.to_string().contains("Permission denied")
                || error.to_string().contains("Operation not permitted") =>
        {
            eprintln!("Skipping: sandbox restriction");
            None
        }
        Err(error) => panic!("server should start: {error}"),
    }
}

async fn send_recv(stream: &mut UnixStream, request: impl Request) -> Response {
    stream
        .write_all(&request.to_bytes())
        .await
        .expect("request write");
    let mut bytes = vec![0; 16 * 1024];
    let size = stream.read(&mut bytes).await.expect("response read");
    bytes.truncate(size);
    Response::new(bytes)
}

async fn assert_created_and_reused(server: &MockGmpServer, stream: &mut UnixStream) {
    let help = send_recv(stream, help_with_mode(HelpMode::BriefXml)).await;
    assert_eq!(help.status_code(), Some(200));
    assert!(help
        .as_str()
        .expect("help UTF-8")
        .contains("<name>export_scan_report</name>"));

    let report_id = EntityId::new(REPORT_ID).expect("valid entity id");
    let export_options = || ExportScanReportOpts {
        filter_string: Some("severity>5 & rows=10".into()),
        notes_details: Some(true),
        ..Default::default()
    };
    let created = send_recv(stream, export_scan_report(&report_id, export_options())).await;
    assert_eq!(created.status_code(), Some(201));
    assert!(created
        .as_str()
        .expect("created UTF-8")
        .contains("OK, resource created"));
    let created_id = created.id().expect("created export id");

    let reused = send_recv(stream, export_scan_report(&report_id, export_options())).await;
    assert_eq!(reused.status_code(), Some(200));
    assert_eq!(reused.id().as_deref(), Some(created_id.as_str()));
    assert!(reused
        .as_str()
        .expect("reused UTF-8")
        .contains("export_status=\"pending\""));

    let request = server
        .command_history()
        .into_iter()
        .rev()
        .find(|record| record.command_name() == "export_scan_report")
        .expect("export request");
    let xml = std::str::from_utf8(request.raw_xml()).expect("request UTF-8");
    assert!(xml.contains(r#"filter="severity&gt;5 &amp; rows=10""#));
    assert!(xml.contains(r#"notes_details="1""#));
}

async fn assert_validation_errors(stream: &mut UnixStream) {
    let invalid = send_recv(
        stream,
        export_scan_report(
            &EntityId::new("not-a-uuid").expect("valid protocol entity id"),
            ExportScanReportOpts::default(),
        ),
    )
    .await;
    assert_eq!(invalid.status_code(), Some(400));
    assert_eq!(
        invalid.status_text().as_deref(),
        Some("Missing or invalid report_id")
    );

    let missing = send_recv(
        stream,
        export_scan_report(
            &EntityId::new("44444444-4444-4444-4444-444444444444").expect("valid entity id"),
            ExportScanReportOpts::default(),
        ),
    )
    .await;
    assert_eq!(missing.status_code(), Some(404));
    assert_eq!(
        missing.status_text().as_deref(),
        Some("Failed to find report")
    );

    for report_id in [AUDIT_REPORT_ID, DELTA_REPORT_ID] {
        let response = send_recv(
            stream,
            export_scan_report(
                &EntityId::new(report_id).expect("valid entity id"),
                ExportScanReportOpts::default(),
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(400));
        assert_eq!(
            response.status_text().as_deref(),
            Some("Report is not a scan report")
        );
    }
}

async fn assert_pre_22_7_unsupported() {
    let Some(server) = stateful_server(GmpVersion::V22_6).await else {
        return;
    };
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect");
    let _ = send_recv(&mut stream, authenticate("admin", "admin")).await;
    let unsupported = send_recv(
        &mut stream,
        export_scan_report(
            &EntityId::new(REPORT_ID).expect("valid entity id"),
            ExportScanReportOpts::default(),
        ),
    )
    .await;
    assert_eq!(unsupported.status_code(), Some(400));
    assert!(unsupported
        .status_text()
        .expect("status text")
        .contains("not available in GMP 22.6"));
    server.shutdown().await;
}

#[tokio::test]
async fn stateful_mock_rejects_invalid_inputs_and_pre_22_7_command_use() {
    let Some(server) = stateful_server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = UnixStream::connect(server.socket_path().expect("socket path"))
        .await
        .expect("connect");
    assert_eq!(
        send_recv(&mut stream, authenticate("admin", "admin"))
            .await
            .status_code(),
        Some(200)
    );

    assert_created_and_reused(&server, &mut stream).await;
    assert_validation_errors(&mut stream).await;
    server.shutdown().await;
    assert_pre_22_7_unsupported().await;
}
