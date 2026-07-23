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

use base64::Engine;
use gvm_gmp::commands::agents::{
    delete_agent, get_agent_installer_instruction, get_agent_support_bundle, get_agents,
    modify_agent, modify_agent_control_scan_config, sync_agents, AgentInstallerLanguage,
    GetAgentsOpts, ModifyAgentControlScanConfigOpts, ModifyAgentOpts,
};
use gvm_gmp::commands::credentials::{
    create_credential_store_credential, modify_credential_store, verify_credential_store,
    CredentialStoreCredentialOpts, ModifyCredentialStoreOpts,
};
use gvm_gmp::commands::hosts::{create_host, get_host, get_hosts, HostOpts};
use gvm_gmp::commands::system::{modify_auth, modify_license};
use gvm_gmp::types::EntityId;
use gvm_gmp::CredentialStoreCredentialType;
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response};
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

async fn send_request(stream: &mut UnixStream, request: impl Request) -> Response {
    send_recv(stream, &request.to_bytes()).await
}

async fn stateful_server() -> Option<MockGmpServer> {
    stateful_server_with_version(GmpVersion::V22_6).await
}

async fn stateful_server_with_version(version: GmpVersion) -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
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

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid id")
}

fn text_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = text.find(start).expect("start marker") + start.len();
    let end_index = text[start_index..].find(end).expect("end marker") + start_index;
    &text[start_index..end_index]
}

#[tokio::test]
async fn stateful_agent_commands_use_gvmd_builder_shapes() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let agents = send_request(
        &mut stream,
        get_agents(GetAgentsOpts {
            filter_string: Some("scanner=agent-controller".into()),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(agents.status_code(), Some(200));

    let modify = send_request(
        &mut stream,
        modify_agent(
            &[id("agent-1")],
            ModifyAgentOpts {
                authorized: Some(true),
                update_to_latest: Some(true),
                comment: Some("managed".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    let delete = send_request(&mut stream, delete_agent(&[id("agent-1")])).await;
    assert_eq!(delete.status_code(), Some(200));

    let sync = send_request(&mut stream, sync_agents()).await;
    assert_eq!(sync.status_code(), Some(200));

    let control_config = send_request(
        &mut stream,
        modify_agent_control_scan_config(
            &id("scanner-1"),
            ModifyAgentControlScanConfigOpts {
                update_to_latest: Some(true),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(control_config.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_agent_download_helpers_return_fixture_shapes() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let instruction = send_request(
        &mut stream,
        get_agent_installer_instruction(
            &id("scanner-1"),
            AgentInstallerLanguage::En,
            "https://gvmd.example",
        ),
    )
    .await;
    assert_eq!(instruction.status_code(), Some(200));
    let instruction_text = instruction.as_str().expect("utf8");
    assert!(instruction_text.contains("<language>en</language>"));
    assert!(instruction_text.contains("<instruction>"));

    let bundle = send_request(
        &mut stream,
        get_agent_support_bundle(&id("agent-1"), Some(7)),
    )
    .await;
    assert_eq!(bundle.status_code(), Some(200));
    let bundle_text = bundle.as_str().expect("utf8");
    assert!(bundle_text.contains("<content_type>application/octet-stream</content_type>"));
    assert!(bundle_text.contains("<content encoding=\"base64\">"));
    let declared_size: usize = text_between(bundle_text, "<size>", "</size>")
        .parse()
        .expect("size");
    let encoded_content = text_between(bundle_text, "<content encoding=\"base64\">", "</content>");
    let decoded_content = base64::engine::general_purpose::STANDARD
        .decode(encoded_content)
        .expect("base64 content");
    assert_eq!(decoded_content.len(), declared_size);

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_modify_uses_gvmd_builder_shape() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let modify = send_request(
        &mut stream,
        modify_credential_store(
            &id("credential-store-1"),
            ModifyCredentialStoreOpts {
                active: Some(true),
                host: Some("store.example".into()),
                path: Some("/vault".into()),
                port: Some(8200),
                comment: Some("primary".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(modify.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_verify_uses_gvmd_builder_shape() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let verify = send_request(
        &mut stream,
        verify_credential_store(&id("credential-store-1")),
    )
    .await;
    assert_eq!(verify.status_code(), Some(200));

    let missing_id = send_recv(&mut stream, b"<verify_credential_store/>").await;
    assert_eq!(missing_id.status_code(), Some(400));
    assert!(missing_id
        .status_text()
        .expect("status text")
        .contains("credential_store_id"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_credential_store_create_credential_uses_gvmd_builder_shape() {
    let Some(server) = stateful_server_with_version(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create = send_request(
        &mut stream,
        create_credential_store_credential(
            "Store Credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts {
                comment: Some("from credential store".into()),
                credential_store_id: Some(id("credential-store-1")),
            },
        ),
    )
    .await;
    assert_eq!(create.status_code(), Some(201));

    let missing_vault = send_recv(
        &mut stream,
        b"<create_credential><name>Missing Vault</name><type>cs_up</type><host_identifier>host-1</host_identifier></create_credential>",
    )
    .await;
    assert_eq!(missing_vault.status_code(), Some(400));
    assert!(missing_vault.status_text().unwrap().contains("vault_id"));

    let empty_vault = send_recv(
        &mut stream,
        b"<create_credential><name>Empty Vault</name><type>cs_up</type><vault_id/><host_identifier>host-1</host_identifier></create_credential>",
    )
    .await;
    assert_eq!(empty_vault.status_code(), Some(400));
    assert!(empty_vault.status_text().unwrap().contains("vault_id"));

    let missing_host = send_recv(
        &mut stream,
        b"<create_credential><name>Missing Host</name><type>cs_up</type><vault_id>vault-1</vault_id></create_credential>",
    )
    .await;
    assert_eq!(missing_host.status_code(), Some(400));
    assert!(missing_host
        .status_text()
        .unwrap()
        .contains("host_identifier"));

    let empty_host = send_recv(
        &mut stream,
        b"<create_credential><name>Empty Host</name><type>cs_up</type><vault_id>vault-1</vault_id><host_identifier>  </host_identifier></create_credential>",
    )
    .await;
    assert_eq!(empty_host.status_code(), Some(400));
    assert!(empty_host
        .status_text()
        .unwrap()
        .contains("host_identifier"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_host_asset_uses_gmp_builder_shape() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create = send_request(
        &mut stream,
        create_host(HostOpts {
            value: Some("1.1.1.1".into()),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(create.status_code(), Some(201));
    let host_id = extract_id(&create);
    let host_entity_id = EntityId::new(host_id.clone()).expect("valid host id");

    let hosts = send_request(&mut stream, get_hosts(Default::default())).await;
    let hosts_text = hosts.as_str().expect("utf8");
    assert!(hosts_text.contains(&host_id));
    assert!(hosts_text.contains("<type>host</type>"));
    assert!(hosts_text.contains("<name>ip</name><value>1.1.1.1</value>"));
    assert!(hosts_text.contains("<host><severity>"));

    let host = send_request(&mut stream, get_host(&host_entity_id)).await;
    let host_text = host.as_str().expect("utf8");
    assert!(host_text.contains(&host_id));
    assert!(host_text.contains("<type>host</type>"));
    assert!(host_text.contains("<name>ip</name><value>1.1.1.1</value>"));
    assert!(host_text.contains("<host><severity>"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_auth_and_license_modifiers_use_gmp_builder_shape() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let auth = send_request(&mut stream, modify_auth(true)).await;
    assert_eq!(auth.status_code(), Some(200));

    let license = send_request(&mut stream, modify_license("abc")).await;
    assert_eq!(license.status_code(), Some(200));

    server.shutdown().await;
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
async fn stateful_secinfo_accepts_uppercase_type_and_info_id() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let resp = send_recv(
        &mut stream,
        br#"<get_info details="1" info_id="CVE-2026-1000" type="CVE"/>"#,
    )
    .await;
    assert_eq!(resp.status_code(), Some(200));
    let text = resp.as_str().expect("utf8");
    assert!(text.contains("<cve id=\"CVE-2026-1000\">"));
    assert!(text.contains("Mock CVE one"));
    assert!(text.contains("<cve_count>1<filtered>1</filtered></cve_count>"));
    assert!(!text.contains("CVE-2026-1001"));

    server.shutdown().await;
}

#[tokio::test]
async fn stateful_secinfo_renders_nvt_and_ovaldef_entries() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let nvt = send_recv(
        &mut stream,
        br#"<get_info details="0" name="Mock NVT one" type="NVT"/>"#,
    )
    .await;
    assert_eq!(nvt.status_code(), Some(200));
    let text = nvt.as_str().expect("utf8");
    assert!(text.contains("<nvt id=\"1.3.6.1.4.1.25623.1\">"));
    assert!(text.contains("Mock NVT one"));
    assert!(text.contains("<nvt_count>1<filtered>1</filtered></nvt_count>"));
    assert!(!text.contains("Mock NVT two"));

    let oval = send_recv(
        &mut stream,
        br#"<get_info details="1" info_id="oval:org.example:def:1" type="OVALDEF"/>"#,
    )
    .await;
    assert_eq!(oval.status_code(), Some(200));
    let text = oval.as_str().expect("utf8");
    assert!(text.contains("<ovaldef id=\"oval:org.example:def:1\">"));
    assert!(text.contains("Mock OVAL definition one"));
    assert!(text.contains("<ovaldef_count>1<filtered>1</filtered></ovaldef_count>"));
    assert!(!text.contains("Mock OVAL definition two"));

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

#[tokio::test]
async fn stateful_import_report_persists_task_and_in_assets() {
    let Some(server) = stateful_server().await else {
        return;
    };

    let mut stream = connect(&server).await;
    auth_admin(&mut stream).await;

    let create = send_recv(
        &mut stream,
        br#"<create_report><task id="task-import"/><report id="imported-report"><name>Imported</name><in_assets>0</in_assets></report><in_assets>1</in_assets></create_report>"#,
    )
    .await;
    let create_text = create.as_str().expect("response XML should be UTF-8");
    assert!(create_text.contains(r#"status="201""#), "{create_text}");

    let report_id = extract_id(&create);
    let listed = send_recv(&mut stream, br#"<get_reports details="1"/>"#).await;
    let listed_text = listed.as_str().expect("response XML should be UTF-8");

    assert!(
        listed_text.contains("<task_id>task-import</task_id>"),
        "{listed_text}"
    );
    assert!(
        listed_text.contains(&format!(r#"id="{report_id}""#)),
        "{listed_text}"
    );
    assert!(
        listed_text.contains("<in_assets>1</in_assets>"),
        "{listed_text}"
    );

    server.shutdown().await;
}
