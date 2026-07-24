// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::redundant_closure_for_method_calls,
    clippy::unwrap_used,
    missing_docs
)]
#![cfg(feature = "unix-socket-tests")]

use gvm_gmp::commands::agent_groups::{create_agent_group, get_agent_groups, CreateAgentGroupOpts};
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::credentials::{
    create_credential_store_credential, modify_credential_store_credential,
    verify_credential_store, CredentialStoreCredentialOpts, ModifyCredentialStoreCredentialOpts,
};
use gvm_gmp::commands::features::get_features;
use gvm_gmp::commands::integration_configs::{
    get_integration_config, get_integration_configs, modify_integration_config,
};
use gvm_gmp::commands::oci_image_targets::{
    create_oci_image_target, delete_oci_image_target, get_oci_image_targets,
    modify_oci_image_target, CreateOciImageTargetOpts, ModifyOciImageTargetOpts,
};
use gvm_gmp::commands::report_configs::{create_report_config, get_report_configs};
use gvm_gmp::commands::reports::{get_report_cves, get_report_hosts};
use gvm_gmp::commands::targets::{create_target, CreateTargetOpts};
use gvm_gmp::commands::tasks::{create_web_application_task, CreateWebApplicationTaskOpts};
use gvm_gmp::commands::web_application_targets::{
    create_web_application_target, get_web_application_targets, CreateWebApplicationTargetOpts,
};
use gvm_gmp::CredentialStoreCredentialType;
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::{Request, Response, XmlCommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn stateful_server(version: GmpVersion) -> Option<MockGmpServer> {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(version)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => server,
        Err(error)
            if error.to_string().contains("Permission denied")
                || error.to_string().contains("Operation not permitted") =>
        {
            eprintln!("Skipping: sandbox restriction");
            return None;
        }
        Err(error) => panic!("Failed to start server: {error}"),
    };

    Some(server)
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let path = server.socket_path().expect("should have socket path");
    UnixStream::connect(path).await.expect("connect failed")
}

async fn send_recv(stream: &mut UnixStream, request: impl Request) -> Response {
    stream
        .write_all(&request.to_bytes())
        .await
        .expect("write failed");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0_u8; 64 * 1024];
    let n = stream.read(&mut buf).await.expect("read failed");
    buf.truncate(n);
    Response::new(buf)
}

async fn authenticate_admin(stream: &mut UnixStream) {
    let response = send_recv(stream, authenticate("admin", "admin")).await;
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_version_gated_rejected(version: GmpVersion) {
    let Some(server) = stateful_server(version).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let create_response = send_recv(
        &mut stream,
        create_report_config("Version Gated Config", "report-format-1"),
    )
    .await;
    assert_eq!(create_response.status_code(), Some(400));
    let create_text = create_response.status_text().unwrap();
    assert!(
        create_text.contains("create_report_config"),
        "expected create_report_config in status_text, got: {create_text}"
    );

    let list_response = send_recv(&mut stream, get_report_configs()).await;
    assert_eq!(list_response.status_code(), Some(400));
    let list_text = list_response.status_text().unwrap();
    assert!(
        list_text.contains("get_report_configs"),
        "expected get_report_configs in status_text, got: {list_text}"
    );

    let features_response = send_recv(&mut stream, get_features()).await;
    assert_eq!(features_response.status_code(), Some(400));
    let features_text = features_response.status_text().unwrap();
    assert!(
        features_text.contains("get_features"),
        "expected get_features in status_text, got: {features_text}"
    );

    server.shutdown().await;
}

async fn assert_version_gated_accepted(version: GmpVersion) {
    let Some(server) = stateful_server(version).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let create_response = send_recv(
        &mut stream,
        create_report_config("Version Gated Config", "report-format-1"),
    )
    .await;
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    let list_response = send_recv(&mut stream, get_report_configs()).await;
    assert_eq!(list_response.status_code(), Some(200));
    let list_text = list_response.as_str().expect("valid utf8");
    assert!(list_text.contains("Version Gated Config"));

    let features_response = send_recv(&mut stream, get_features()).await;
    assert_eq!(features_response.status_code(), Some(200));
    let features_text = features_response.as_str().expect("valid UTF-8");
    assert!(features_text.contains(
        "<feature compiled_in=\"0\" enabled=\"0\"><name>ENABLE_OPENVASD</name></feature>"
    ));
    assert!(features_text.contains("<name>ENABLE_WEB_APPLICATION_SCANNING</name>"));

    server.shutdown().await;
}

#[tokio::test]
async fn version_22_4_rejects_report_config() {
    assert_version_gated_rejected(GmpVersion::V22_4).await;
}

#[tokio::test]
async fn version_22_5_rejects_report_config() {
    assert_version_gated_rejected(GmpVersion::V22_5).await;
}

#[tokio::test]
async fn version_22_6_accepts_report_config() {
    assert_version_gated_accepted(GmpVersion::V22_6).await;
}

#[tokio::test]
async fn version_22_7_accepts_report_config() {
    assert_version_gated_accepted(GmpVersion::V22_7).await;
}

#[tokio::test]
async fn base_commands_work_on_all_versions() {
    for version in [
        GmpVersion::V22_4,
        GmpVersion::V22_5,
        GmpVersion::V22_6,
        GmpVersion::V22_7,
        GmpVersion::V22_8,
    ] {
        let Some(server) = stateful_server(version).await else {
            return;
        };
        let mut stream = connect(&server).await;
        authenticate_admin(&mut stream).await;

        let response = send_recv(
            &mut stream,
            create_target(
                &format!("Base Target {}", version.as_str()),
                CreateTargetOpts {
                    hosts: vec!["127.0.0.1".to_string()],
                    ..CreateTargetOpts::default()
                },
            ),
        )
        .await;
        assert_eq!(response.status_code(), Some(201));

        server.shutdown().await;
    }
}

#[tokio::test]
async fn version_22_7_rejects_next_commands() {
    let Some(server) = stateful_server(GmpVersion::V22_7).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    let response = send_recv(&mut stream, get_integration_configs(Default::default())).await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("get_integration_configs"));

    let response = send_recv(&mut stream, get_agent_groups(Default::default())).await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("get_agent_groups"));

    let response = send_recv(
        &mut stream,
        get_report_hosts(
            &id("00000000-0000-0000-0000-000000000200"),
            Default::default(),
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("get_report_hosts"));

    let response = send_recv(&mut stream, get_web_application_targets(Default::default())).await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("get_web_application_targets"));

    let response = send_recv(&mut stream, get_oci_image_targets(Default::default())).await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("get_oci_image_targets"));

    let response = send_recv(
        &mut stream,
        verify_credential_store(&id("credential-store-1")),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("verify_credential_store"));

    let response = send_recv(
        &mut stream,
        create_oci_image_target(
            "Rejected OCI Target",
            &["registry.example/app:1".to_string()],
            CreateOciImageTargetOpts::default(),
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("create_oci_image_target"));

    let response = send_recv(
        &mut stream,
        create_web_application_task(
            "Rejected Web Application Task",
            &id("web-target-1"),
            &id("scanner-1"),
            CreateWebApplicationTaskOpts::default(),
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response
        .status_text()
        .unwrap()
        .contains("Web application target tasks"));

    assert_credential_store_credentials_rejected_before_next(&mut stream).await;

    server.shutdown().await;
}

async fn assert_credential_store_credentials_rejected_before_next(stream: &mut UnixStream) {
    let response = send_recv(
        stream,
        create_credential_store_credential(
            "Rejected Store Credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts::default(),
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));

    let response = send_recv(
        stream,
        modify_credential_store_credential(
            &id("credential-1"),
            ModifyCredentialStoreCredentialOpts {
                vault_id: Some("vault-1".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));

    let response = send_recv(
        stream,
        modify_credential_store_credential(
            &id("credential-1"),
            ModifyCredentialStoreCredentialOpts {
                host_identifier: Some("host-1".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));

    let response = send_recv(
        stream,
        &b"<modify_credential credential_id=\"credential-1\"><vault_id/></modify_credential>"[..],
    )
    .await;
    assert_eq!(response.status_code(), Some(400));
    assert!(response.status_text().unwrap().contains("GMP 22.8"));
}

#[tokio::test]
async fn version_22_8_accepts_next_commands() {
    let Some(server) = stateful_server(GmpVersion::V22_8).await else {
        return;
    };
    let mut stream = connect(&server).await;
    authenticate_admin(&mut stream).await;

    assert_integration_configs_work_on_next(&mut stream).await;

    let agent_group_response = send_recv(
        &mut stream,
        create_agent_group(
            "Version Gated Agent Group",
            &[id("agent-1")],
            "0 */5 * * *",
            CreateAgentGroupOpts::default(),
        ),
    )
    .await;
    assert_eq!(agent_group_response.status_code(), Some(201));

    let agent_groups_response = send_recv(&mut stream, get_agent_groups(Default::default())).await;
    assert_eq!(agent_groups_response.status_code(), Some(200));
    assert!(agent_groups_response
        .as_str()
        .expect("utf8")
        .contains("Version Gated Agent Group"));

    let report_response = send_recv(
        &mut stream,
        get_report_cves(
            &id("00000000-0000-0000-0000-000000000200"),
            Default::default(),
        ),
    )
    .await;
    assert_eq!(report_response.status_code(), Some(404));

    assert_credential_store_verify_works_on_next(&mut stream).await;
    assert_credential_store_credentials_work_on_next(&mut stream).await;
    assert_web_application_targets_and_tasks_work_on_next(&mut stream).await;
    assert_oci_image_targets_work_on_next(&mut stream).await;

    server.shutdown().await;
}

async fn assert_integration_configs_work_on_next(stream: &mut UnixStream) {
    let integration_config_id = id("00000000-0000-0000-0000-000000000100");
    let get_response = send_recv(
        stream,
        get_integration_config(&integration_config_id, Some(true)),
    )
    .await;
    assert_eq!(get_response.status_code(), Some(200));

    let list_response = send_recv(stream, get_integration_configs(Default::default())).await;
    assert_eq!(list_response.status_code(), Some(200));
    assert!(list_response
        .as_str()
        .expect("utf8")
        .contains("Default Integration Config"));

    let modify_response = send_recv(
        stream,
        modify_integration_config(
            &integration_config_id,
            gvm_gmp::commands::integration_configs::ModifyIntegrationConfigOpts {
                service_url: Some("https://updated.example".into()),
                service_cacert: Some("UPDATED-CA".into()),
                oidc_provider_url: Some("https://updated-oidc.example".into()),
                oidc_provider_client_id: Some("updated-client".into()),
                oidc_provider_client_secret: Some("updated-secret".into()),
            },
        ),
    )
    .await;
    assert_eq!(modify_response.status_code(), Some(200));

    let modified_get_response = send_recv(
        stream,
        get_integration_config(&integration_config_id, Some(true)),
    )
    .await;
    let modified_xml = modified_get_response.as_str().expect("utf8");
    assert!(modified_xml.contains("<service><url>https://updated.example</url></service>"));
    assert!(modified_xml.contains(
        "<oidc><url>https://updated-oidc.example</url><client><id>updated-client</id></client></oidc>"
    ));
    assert!(!modified_xml.contains("MOCK-CA-CERT"));
    assert!(!modified_xml.contains("mock-client-secret"));

    let missing_uuid_response =
        send_recv(stream, XmlCommand::new("modify_integration_config")).await;
    assert_eq!(missing_uuid_response.status_code(), Some(400));
    assert!(missing_uuid_response
        .status_text()
        .expect("status text")
        .contains("uuid"));

    let malformed_modify = send_recv(
        stream,
        XmlCommand::new("modify_integration_config")
            .attribute("uuid", "00000000-0000-0000-0000-000000000100"),
    )
    .await;
    assert_eq!(malformed_modify.status_code(), Some(400));
    assert!(malformed_modify
        .status_text()
        .expect("status text")
        .contains("service"));

    let partial_modify = send_recv(
        stream,
        modify_integration_config(
            &integration_config_id,
            gvm_gmp::commands::integration_configs::ModifyIntegrationConfigOpts {
                service_url: Some("https://partial.example".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(partial_modify.status_code(), Some(400));
    assert!(partial_modify
        .status_text()
        .expect("status text")
        .contains("oidc"));

    let clear_response = send_recv(
        stream,
        modify_integration_config(&integration_config_id, Default::default()),
    )
    .await;
    assert_eq!(clear_response.status_code(), Some(200));
}

async fn assert_web_application_targets_and_tasks_work_on_next(stream: &mut UnixStream) {
    let web_target_response = send_recv(
        stream,
        create_web_application_target(
            "Version Gated Web Target",
            &["https://example.com".to_string()],
            CreateWebApplicationTargetOpts {
                comment: Some("accepted on 22.8".into()),
                exclude_urls: vec!["https://example.com/logout".into()],
                credential_id: Some(id("credential-web-gate")),
            },
        ),
    )
    .await;
    assert_eq!(web_target_response.status_code(), Some(201));

    let web_target_list = send_recv(stream, get_web_application_targets(Default::default())).await;
    assert_eq!(web_target_list.status_code(), Some(200));
    let web_target_xml = web_target_list.as_str().expect("utf8");
    assert!(web_target_xml.contains("Version Gated Web Target"));
    assert!(web_target_xml.contains("<urls>https://example.com</urls>"));
    assert!(web_target_xml.contains("<credential_id>credential-web-gate</credential_id>"));

    let web_target_id = id(&web_target_response.id().expect("created web target id"));
    let web_task_response = send_recv(
        stream,
        create_web_application_task(
            "Version Gated Web Task",
            &web_target_id,
            &id("08b69003-5fc2-4037-a479-93b440211c73"),
            CreateWebApplicationTaskOpts::default(),
        ),
    )
    .await;
    assert_eq!(web_task_response.status_code(), Some(201));
}

async fn assert_credential_store_verify_works_on_next(stream: &mut UnixStream) {
    let response = send_recv(stream, verify_credential_store(&id("credential-store-1"))).await;
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_credential_store_credentials_work_on_next(stream: &mut UnixStream) {
    let create = send_recv(
        stream,
        create_credential_store_credential(
            "Version Gated Store Credential",
            CredentialStoreCredentialType::PasswordOnly,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts::default(),
        ),
    )
    .await;
    assert_eq!(create.status_code(), Some(201));
    let credential_id = id(&create.id().expect("created id"));

    let response = send_recv(
        stream,
        modify_credential_store_credential(
            &credential_id,
            ModifyCredentialStoreCredentialOpts {
                credential_store_id: Some(id("credential-store-gate")),
                vault_id: Some("vault-gate".into()),
                host_identifier: Some("host-gate".into()),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_oci_image_targets_work_on_next(stream: &mut UnixStream) {
    let oci_target_response = send_recv(
        stream,
        create_oci_image_target(
            "Version Gated OCI Target",
            &["registry.example/app:1".to_string()],
            CreateOciImageTargetOpts {
                comment: Some("accepted on 22.8".into()),
                credential_id: Some(id("credential-oci-gate")),
            },
        ),
    )
    .await;
    assert_eq!(oci_target_response.status_code(), Some(201));
    let oci_target_id = id(&oci_target_response.id().expect("created OCI target id"));

    let oci_target_list = send_recv(stream, get_oci_image_targets(Default::default())).await;
    assert_eq!(oci_target_list.status_code(), Some(200));
    let oci_target_xml = oci_target_list.as_str().expect("utf8");
    assert!(oci_target_xml.contains("Version Gated OCI Target"));
    assert!(oci_target_xml.contains("<image_references>registry.example/app:1</image_references>"));
    assert!(oci_target_xml.contains("<credential_id>credential-oci-gate</credential_id>"));

    let modify_response = send_recv(
        stream,
        modify_oci_image_target(
            &oci_target_id,
            ModifyOciImageTargetOpts {
                name: Some("Updated Version Gated OCI Target".into()),
                image_references: vec!["registry.example/app:latest".into()],
                credential_id: Some(id("credential-oci-updated")),
                ..Default::default()
            },
        ),
    )
    .await;
    assert_eq!(modify_response.status_code(), Some(200));

    let modified_list = send_recv(stream, get_oci_image_targets(Default::default())).await;
    let modified_xml = modified_list.as_str().expect("utf8");
    assert!(modified_xml.contains("Updated Version Gated OCI Target"));
    assert!(
        modified_xml.contains("<image_references>registry.example/app:latest</image_references>")
    );
    assert!(modified_xml.contains("<credential_id>credential-oci-updated</credential_id>"));

    let delete_response = send_recv(stream, delete_oci_image_target(&oci_target_id, true)).await;
    assert_eq!(delete_response.status_code(), Some(200));
}

fn id(value: &str) -> gvm_gmp::EntityId {
    gvm_gmp::EntityId::new(value).expect("valid id")
}
