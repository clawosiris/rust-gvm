// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stderr, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::{
    GetAuditReportHostsOpts, GetAuditReportOpts, Gmp227Commands, GmpClient, GmpVersioned,
};
use gvm_connection::UnixSocketConnection;
use gvm_gmp::responses::{ComplianceValue, GetAuditReportHostsResponse, GetAuditReportResponse};
use gvm_gmp::EntityId;
use gvm_mock_server::{
    GmpVersion as MockVersion, MockGmpServer, Resource, ResourceStore, ServerMode,
};

const REPORT_ID: &str = "10000000-0000-0000-0000-000000000001";

async fn server(version: MockVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .seed(|store| {
            let mut report = Resource::with_id(
                "report",
                "Client audit report",
                REPORT_ID.parse().expect("report UUID"),
            );
            report.set_attr("usage_type", "audit");
            report.set_attr("status", "Done");
            store.seed(report);
            seed_result(store, 1, "yes", "192.0.2.10");
            seed_result(store, 2, "no", "192.0.2.20");
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
        Err(error) => panic!("server should start: {error}"),
    }
}

fn seed_result(store: &ResourceStore, suffix: u128, compliance: &str, host: &str) {
    let mut result = Resource::new("result", &format!("{compliance} control {suffix}"));
    result.set_attr("report_id", REPORT_ID);
    result.set_attr("compliance", compliance);
    result.set_attr("qod", "90");
    result.set_attr("host", host);
    result.set_attr("severity", if compliance == "no" { "8.0" } else { "2.0" });
    store.seed(result);
}

fn connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("Unix socket"))
}

async fn exercise_structured_audit_facade(
    client: &mut (impl Gmp227Commands + Send),
    report_id: &EntityId,
) -> (GetAuditReportResponse, GetAuditReportHostsResponse) {
    let report = client
        .get_audit_report(
            report_id,
            GetAuditReportOpts {
                filter_string: Some("compliance_levels=y min_qod=70".into()),
                filter_id: None,
            },
        )
        .await
        .expect("typed audit report should parse");
    let hosts = client
        .get_audit_report_hosts(
            report_id,
            GetAuditReportHostsOpts {
                filter_string: Some("result_hosts_only=1 levels=y rows=-1".into()),
                filter_id: None,
                lean: Some(true),
                details: Some(true),
            },
        )
        .await
        .expect("typed audit hosts should parse");
    (report, hosts)
}

#[tokio::test]
async fn structured_audit_facade_is_exposed_on_gmp227_and_gmpnext() {
    for version in [MockVersion::V22_7, MockVersion::V22_8] {
        let Some(server) = server(version).await else {
            return;
        };
        let mut client = GmpVersioned::connect(connection(&server))
            .await
            .expect("versioned client connects");
        client
            .call(gvm_gmp::commands::authentication::authenticate(
                "admin", "admin",
            ))
            .await
            .expect("authentication succeeds");

        let report_id = EntityId::new(REPORT_ID).expect("report ID");
        let (report, hosts) = match &mut client {
            GmpVersioned::V227(client) => {
                exercise_structured_audit_facade(client, &report_id).await
            }
            GmpVersioned::Next(client) => {
                exercise_structured_audit_facade(client, &report_id).await
            }
            other => panic!("unexpected client family: {other:?}"),
        };
        assert_eq!(report.report.compliance_counts.full, Some(2));
        assert_eq!(report.report.compliance_counts.filtered, Some(1));
        assert_eq!(
            report.report.compliance.filtered,
            Some(ComplianceValue::Yes)
        );
        assert_eq!(hosts.items.len(), 1);
        assert_eq!(hosts.items[0].ip, "192.0.2.10");
        assert_eq!(hosts.page.max, Some(-1));

        let history = server.command_history();
        let report_request = history
            .iter()
            .find(|record| record.command_name() == "get_audit_report")
            .expect("audit report request recorded");
        assert_eq!(
            std::str::from_utf8(report_request.raw_xml()).expect("request UTF-8"),
            format!(
                "<get_audit_report audit_report_id=\"{REPORT_ID}\" filter=\"compliance_levels=y min_qod=70\"/>"
            )
        );
        let hosts_request = history
            .iter()
            .find(|record| record.command_name() == "get_audit_report_hosts")
            .expect("audit hosts request recorded");
        assert_eq!(
            std::str::from_utf8(hosts_request.raw_xml()).expect("request UTF-8"),
            format!(
                "<get_audit_report_hosts details=\"1\" filter=\"result_hosts_only=1 levels=y rows=-1\" lean=\"1\" report_id=\"{REPORT_ID}\"/>"
            )
        );
        server.shutdown().await;
    }
}

#[tokio::test]
async fn generic_client_rejects_structured_audit_commands_before_22_7() {
    let Some(server) = server(MockVersion::V22_6).await else {
        return;
    };
    let mut client = GmpClient::connect(connection(&server))
        .await
        .expect("client connects");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authentication succeeds");
    server.clear_history();

    let error = client
        .get_audit_report(
            &EntityId::new(REPORT_ID).expect("report ID"),
            GetAuditReportOpts::default(),
        )
        .await
        .expect_err("22.6 should reject the 22.7 command before send");
    assert!(matches!(
        error,
        gvm_client::GvmError::UnsupportedCommand {
            command,
            required: "22.7",
            ..
        } if command == "get_audit_report"
    ));
    assert!(server.command_history().is_empty());
    server.shutdown().await;
}
