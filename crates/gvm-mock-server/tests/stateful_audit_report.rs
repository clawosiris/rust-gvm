// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Stateful structured audit-report behavior derived from current gvmd.

#![cfg(feature = "unix-socket-tests")]
#![allow(
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]

use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const AUDIT_REPORT_ID: &str = "10000000-0000-0000-0000-000000000001";
const SCAN_REPORT_ID: &str = "10000000-0000-0000-0000-000000000002";
const TASK_ID: &str = "20000000-0000-0000-0000-000000000001";
const TARGET_ID: &str = "30000000-0000-0000-0000-000000000001";
const ASSET_ID: &str = "40000000-0000-0000-0000-000000000001";
const SNAPSHOT_ID: &str = "50000000-0000-0000-0000-000000000001";
const ROWS_PER_PAGE_SETTING_ID: &str = "00000000-0000-0000-0000-000000000002";

async fn server(version: GmpVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .seed(|store| {
            let mut target = Resource::with_id(
                "target",
                "Audit target",
                TARGET_ID.parse().expect("target UUID"),
            );
            target.comment = "deterministic target".into();
            store.seed(target);

            let mut task =
                Resource::with_id("task", "Audit task", TASK_ID.parse().expect("task UUID"));
            task.set_attr("usage_type", "audit");
            task.set_attr("status", "Done");
            task.set_attr("target_id", TARGET_ID);
            store.seed(task);

            let mut audit_report = Resource::with_id(
                "report",
                "Audit report",
                AUDIT_REPORT_ID.parse().expect("audit report UUID"),
            );
            audit_report.set_attr("usage_type", "audit");
            audit_report.set_attr("status", "Done");
            audit_report.set_attr("task_id", TASK_ID);
            store.seed(audit_report);

            let mut scan_report = Resource::with_id(
                "report",
                "Scan report",
                SCAN_REPORT_ID.parse().expect("scan report UUID"),
            );
            scan_report.set_attr("usage_type", "scan");
            scan_report.set_attr("status", "Done");
            store.seed(scan_report);

            seed_result(
                store,
                1,
                "Control compliant",
                "yes",
                95,
                "192.0.2.10",
                "2.0",
                "22/tcp",
            );
            seed_result(
                store,
                2,
                "Control non-compliant",
                "no",
                80,
                "192.0.2.10",
                "8.0",
                "443/tcp",
            );
            seed_result(
                store,
                3,
                "Control incomplete",
                "incomplete",
                60,
                "192.0.2.20",
                "4.0",
                "80/tcp",
            );
            seed_result(
                store,
                4,
                "Control undefined",
                "undefined",
                90,
                "192.0.2.30",
                "5.0",
                "general/tcp",
            );
        })
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("Skipping: sandbox restriction");
            None
        }
        Err(error) => panic!("server start failed: {error}"),
    }
}

fn seed_result(
    store: &gvm_mock_server::ResourceStore,
    suffix: u128,
    name: &str,
    compliance: &str,
    qod: u32,
    host: &str,
    severity: &str,
    port: &str,
) {
    let mut result = Resource::with_id(
        "result",
        name,
        Uuid::from_u128(0x60000000_0000_0000_0000_000000000000 + suffix),
    );
    result.set_attr("report_id", AUDIT_REPORT_ID);
    result.set_attr("compliance", compliance);
    result.set_attr("qod", &qod.to_string());
    result.set_attr("host", host);
    result.set_attr("severity", severity);
    result.set_attr("port", port);
    result.set_attr("host_start", "2026-07-29T10:00:00Z");
    result.set_attr("host_end", "2026-07-29T10:05:00Z");
    result.set_attr("hostname", &format!("host-{}", host.replace('.', "-")));
    result.set_attr("application", "cpe:/a:example:service");
    if host == "192.0.2.10" {
        result.set_attr("asset_id", ASSET_ID);
        result.set_attr("asset_snapshot_key", SNAPSHOT_ID);
    }
    if compliance == "yes" {
        result.set_attr("detail_name", "App");
        result.set_attr("detail_value", "cpe:/a:example:service");
        result.set_attr("detail_source_type", "NVT");
        result.set_attr("detail_source_name", "audit-control");
    } else if compliance == "no" {
        result.set_attr("detail_name", "scanned_with_scanner");
        result.set_attr("detail_value", "OpenVAS");
        result.set_attr("detail_source_type", "NVT");
        result.set_attr("detail_source_name", "audit-control");
    }
    store.seed(result);
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    UnixStream::connect(server.socket_path().expect("Unix socket"))
        .await
        .expect("connect")
}

async fn send_recv(stream: &mut UnixStream, request: &[u8]) -> Response {
    stream.write_all(request).await.expect("write");
    let mut buffer = vec![0_u8; 64 * 1024];
    let read = stream.read(&mut buffer).await.expect("read");
    buffer.truncate(read);
    Response::new(buffer)
}

async fn authenticate(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

#[tokio::test]
async fn structured_audit_commands_require_authentication() {
    let Some(server) = server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    for request in [
        format!("<get_audit_report audit_report_id=\"{AUDIT_REPORT_ID}\"/>"),
        format!("<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\"/>"),
    ] {
        let response = send_recv(&mut stream, request.as_bytes()).await;
        assert_eq!(response.status_code(), Some(401));
        assert_eq!(response.status_text().as_deref(), Some("Not authenticated"));
    }
    server.shutdown().await;
}

#[tokio::test]
async fn audit_summary_keeps_full_and_filtered_compliance_independent() {
    let Some(server) = server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let response = send_recv(
        &mut stream,
        format!("<get_audit_report audit_report_id=\"{AUDIT_REPORT_ID}\"/>").as_bytes(),
    )
    .await;
    let xml = response.as_str().expect("UTF-8");
    assert!(xml.contains("<compliance_count>4<full>4</full><filtered>3</filtered>"));
    assert!(xml.contains("<incomplete><full>1</full><filtered>0</filtered></incomplete>"));
    assert!(xml.contains("<compliance><full>no</full><filtered>no</filtered></compliance>"));

    let filtered = send_recv(
        &mut stream,
        format!(
            "<get_audit_report audit_report_id=\"{AUDIT_REPORT_ID}\" \
             filter=\"compliance_levels=y min_qod=70\"/>"
        )
        .as_bytes(),
    )
    .await;
    let xml = filtered.as_str().expect("UTF-8");
    assert!(xml.contains("<full>4</full><filtered>1</filtered>"));
    assert!(xml.contains("<compliance><full>no</full><filtered>yes</filtered></compliance>"));
    assert!(xml.contains("<column>compliance_levels</column>"));
    server.shutdown().await;
}

#[tokio::test]
async fn audit_hosts_filter_paginate_and_toggle_details_and_lean_output() {
    let Some(server) = server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let metadata_only = send_recv(
        &mut stream,
        format!(
            "<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\" details=\"0\" \
             filter=\"rows=1 first=2 sort=ip\"/>"
        )
        .as_bytes(),
    )
    .await;
    let xml = metadata_only.as_str().expect("UTF-8");
    assert!(!xml.contains("<host>"));
    assert!(xml.contains("<audit_report_hosts start=\"2\" max=\"1\"/>"));
    assert!(xml.contains("<audit_report_host_count>3<filtered>3</filtered><page>1</page>"));

    let full = send_recv(
        &mut stream,
        format!(
            "<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\" details=\"1\" \
             filter=\"ip=192.0.2.10 result_hosts_only=1 min_qod=70\"/>"
        )
        .as_bytes(),
    )
    .await;
    let xml = full.as_str().expect("UTF-8");
    assert!(xml.contains("<host><ip>192.0.2.10</ip>"));
    assert!(xml.contains(&format!("<asset asset_id=\"{ASSET_ID}\"/>")));
    assert!(xml.contains("<compliance_count><page>2</page>"));
    assert!(xml.contains("<host_compliance>no</host_compliance>"));
    assert!(xml.contains("<type>NVT</type>"));
    assert!(xml.contains("<name>scanned_with_scanner</name>"));

    let lean = send_recv(
        &mut stream,
        format!(
            "<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\" details=\"1\" lean=\"1\" \
             filter=\"ip=192.0.2.10 result_hosts_only=1 min_qod=70\"/>"
        )
        .as_bytes(),
    )
    .await;
    let xml = lean.as_str().expect("UTF-8");
    assert!(xml.contains("<name>App</name>"));
    assert!(!xml.contains("<type>NVT</type>"));
    assert!(!xml.contains("<name>scanned_with_scanner</name>"));
    server.shutdown().await;
}

#[tokio::test]
async fn audit_host_rows_follow_gvmd_sentinel_and_setting_semantics() {
    let Some(server) = server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    let default = send_recv(
        &mut stream,
        format!("<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\"/>").as_bytes(),
    )
    .await;
    assert_audit_host_page(&default, 100, 3);

    let setting = send_recv(
        &mut stream,
        format!(
            "<modify_setting setting_id=\"{ROWS_PER_PAGE_SETTING_ID}\">\
             <value>Mg==</value></modify_setting>"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(setting.status_code(), Some(200));

    for (filter, max, page) in [
        (None, 2, 2),
        (Some("rows=-2"), 2, 2),
        (Some("rows=-1"), -1, 3),
        (Some("rows=0"), 1, 1),
        (Some("rows=-9"), -1, 3),
        (Some("first=0 rows=1"), 1, 1),
        (Some("first=-4 rows=1"), 1, 1),
    ] {
        let filter = filter.map_or_else(String::new, |filter| format!(" filter=\"{filter}\""));
        let response = send_recv(
            &mut stream,
            format!("<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\"{filter}/>").as_bytes(),
        )
        .await;
        assert_audit_host_page(&response, max, page);
    }

    server.shutdown().await;
}

fn assert_audit_host_page(response: &Response, max: i32, page: usize) {
    assert_eq!(response.status_code(), Some(200));
    assert_eq!(response.status_text().as_deref(), Some("OK"));
    let xml = response.as_str().expect("UTF-8");
    assert!(
        xml.contains(&format!("<audit_report_hosts start=\"1\" max=\"{max}\"/>")),
        "{xml}"
    );
    assert!(
        xml.contains(&format!(
            "<audit_report_host_count>3<filtered>3</filtered><page>{page}</page>"
        )),
        "{xml}"
    );
}

#[tokio::test]
async fn audit_commands_return_gvmd_like_id_type_and_filter_errors() {
    let Some(server) = server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate(&mut stream).await;

    for (request, status, text) in [
        (
            "<get_audit_report/>".to_string(),
            400,
            "Missing audit_report_id attribute",
        ),
        (
            "<get_audit_report_hosts/>".to_string(),
            400,
            "Missing report_id attribute",
        ),
        (
            "<get_audit_report audit_report_id=\"not-a-uuid\"/>".to_string(),
            400,
            "Invalid UUID",
        ),
        (
            "<get_audit_report_hosts report_id=\"90000000-0000-0000-0000-000000000002\"/>"
                .to_string(),
            404,
            "Resource not found",
        ),
        (
            format!("<get_audit_report audit_report_id=\"{SCAN_REPORT_ID}\"/>"),
            400,
            "Report type is not supported",
        ),
        (
            format!("<get_audit_report_hosts report_id=\"{SCAN_REPORT_ID}\"/>"),
            400,
            "Report is not an audit report",
        ),
        (
            format!("<get_audit_report audit_report_id=\"{AUDIT_REPORT_ID}\" filter=\"broken\"/>"),
            400,
            "Malformed filter",
        ),
        (
            format!(
                "<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\" \
                 filt_id=\"90000000-0000-0000-0000-000000000001\"/>"
            ),
            400,
            "Failed to find filter",
        ),
    ] {
        let response = send_recv(&mut stream, request.as_bytes()).await;
        assert_eq!(response.status_code(), Some(status), "{request}");
        assert_eq!(response.status_text().as_deref(), Some(text), "{request}");
    }
    server.shutdown().await;
}

#[tokio::test]
async fn structured_audit_commands_are_gated_at_22_7() {
    let Some(old_server) = server(GmpVersion::V22_6).await else {
        return;
    };
    let mut old_stream = connect(&old_server).await;
    authenticate(&mut old_stream).await;
    for request in [
        format!("<get_audit_report audit_report_id=\"{AUDIT_REPORT_ID}\"/>"),
        format!("<get_audit_report_hosts report_id=\"{AUDIT_REPORT_ID}\"/>"),
    ] {
        let response = send_recv(&mut old_stream, request.as_bytes()).await;
        assert_eq!(response.status_code(), Some(400));
        assert!(response
            .status_text()
            .expect("status text")
            .contains("not available in GMP 22.6"));
    }
    old_server.shutdown().await;

    let Some(current_server) = server(GmpVersion::V22_7).await else {
        return;
    };
    let mut current_stream = connect(&current_server).await;
    authenticate(&mut current_stream).await;
    let response = send_recv(
        &mut current_stream,
        format!("<get_audit_report audit_report_id=\"{AUDIT_REPORT_ID}\"/>").as_bytes(),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
    current_server.shutdown().await;
}
