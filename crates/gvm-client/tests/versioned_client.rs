// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stderr, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::GmpNext;
use gvm_client::{
    AgentInstallerLanguage, CreateAgentGroupOpts, CreateAgentGroupTaskOpts,
    CreateOciImageTargetOpts, CreateWebApplicationTargetOpts, GetAgentsOpts, Gmp226Commands,
    GmpNextCommands, GmpVersioned, GvmError, ModifyAgentControlScanConfigOpts,
    ModifyAgentGroupOpts, ModifyAgentOpts, ModifyOciImageTargetOpts,
    ModifyWebApplicationTargetOpts,
};
use gvm_connection::{GvmConnection, UnixSocketConnection};
use gvm_gmp::commands::agents::get_agents;
use gvm_gmp::commands::oci_image_targets::get_oci_image_targets;
use gvm_gmp::{EntityId, GmpVersion};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

async fn stateful_server(version: MockVersion) -> Option<MockGmpServer> {
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

fn unix_connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("unix socket path"))
}

async fn assert_create_agent_group_task_round_trip<C>(
    client: &mut GmpNext<C>,
    server: &MockGmpServer,
    agent_group_id: &EntityId,
) where
    C: GvmConnection + Send,
{
    server.clear_history();

    let scanner_id = EntityId::new("scanner-1").expect("valid id");
    let task_response = client
        .create_agent_group_task(
            "Client Agent Group Task",
            agent_group_id,
            &scanner_id,
            CreateAgentGroupTaskOpts {
                comment: Some("task through client".into()),
                alterable: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("create_agent_group_task should succeed");
    assert_eq!(task_response.status_code(), Some(201));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create_task command recorded");
    assert_eq!(command.command_name(), "create_task");
    assert_eq!(
        String::from_utf8(command.raw_xml().to_vec()).expect("history should be UTF-8"),
        format!(
            "<create_task><name>Client Agent Group Task</name><usage_type>scan</usage_type><agent_group id=\"{}\"/><scanner id=\"scanner-1\"/><comment>task through client</comment><alterable>1</alterable></create_task>",
            agent_group_id.as_str()
        )
    );
}

#[tokio::test]
async fn versioned_client_resolves_correct_variant() {
    for (version, expected) in [
        (MockVersion::V22_4, 224_u16),
        (MockVersion::V22_5, 225_u16),
        (MockVersion::V22_6, 226_u16),
        (MockVersion::V22_7, 227_u16),
        (MockVersion::V22_8, 228_u16),
    ] {
        let Some(server) = stateful_server(version).await else {
            return;
        };
        let connection = unix_connection(&server);
        let client = GmpVersioned::connect(connection)
            .await
            .expect("client should connect");

        match (expected, client) {
            (224, GmpVersioned::V224(_))
            | (225, GmpVersioned::V225(_))
            | (226, GmpVersioned::V226(_))
            | (227, GmpVersioned::V227(_))
            | (228, GmpVersioned::Next(_)) => {}
            (_, other) => panic!("unexpected versioned client: {other:?}"),
        }

        server.shutdown().await;
    }
}

#[tokio::test]
async fn next_client_exposes_next_trait_methods() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let response = client
        .get_integration_configs(Default::default())
        .await
        .expect("next-only command should succeed");
    assert_eq!(response.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_agent_groups_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let agent_ids = [
        EntityId::new("agent-1").expect("valid id"),
        EntityId::new("agent-2").expect("valid id"),
    ];
    let create_response = client
        .create_agent_group(
            "Client Agent Group",
            &agent_ids,
            "0 */5 * * *",
            CreateAgentGroupOpts {
                comment: Some("created through client".into()),
            },
        )
        .await
        .expect("create_agent_group should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    let agent_group_id = EntityId::new(create_response.id().expect("created id"))
        .expect("server id should be valid");

    assert_create_agent_group_task_round_trip(&mut client, &server, &agent_group_id).await;

    let clone_response = client
        .clone_agent_group(&agent_group_id)
        .await
        .expect("clone_agent_group should succeed");
    assert_eq!(clone_response.status_code(), Some(201));

    let get_response = client
        .get_agent_group(&agent_group_id)
        .await
        .expect("get_agent_group should succeed");
    let get_text = get_response.as_str().expect("valid UTF-8 XML");
    assert!(get_text.contains("Client Agent Group"));
    assert!(get_text.contains("<scheduler_cron_time>0 */5 * * *</scheduler_cron_time>"));

    let list_response = client
        .get_agent_groups(Default::default())
        .await
        .expect("get_agent_groups should succeed");
    assert_eq!(list_response.status_code(), Some(200));
    assert!(list_response
        .as_str()
        .expect("valid UTF-8 XML")
        .contains("<agent_group_count>2"));

    let modify_response = client
        .modify_agent_group(
            &agent_group_id,
            "0 */10 * * *",
            ModifyAgentGroupOpts {
                name: Some("Updated Agent Group".into()),
                comment: Some("modified through client".into()),
                agent_ids: vec![EntityId::new("agent-3").expect("valid id")],
            },
        )
        .await
        .expect("modify_agent_group should succeed");
    assert_eq!(modify_response.status_code(), Some(200));

    let updated_response = client
        .get_agent_group(&agent_group_id)
        .await
        .expect("updated get_agent_group should succeed");
    let updated_text = updated_response.as_str().expect("valid UTF-8 XML");
    assert!(updated_text.contains("Updated Agent Group"));
    assert!(updated_text.contains("<comment>modified through client</comment>"));
    assert!(updated_text.contains("<scheduler_cron_time>0 */10 * * *</scheduler_cron_time>"));

    let delete_response = client
        .delete_agent_group(&agent_group_id, true)
        .await
        .expect("delete_agent_group should succeed");
    assert_eq!(delete_response.status_code(), Some(200));

    let error = client
        .get_agent_group(&agent_group_id)
        .await
        .expect_err("deleted agent group should not be found");
    assert!(matches!(
        error,
        gvm_client::GvmError::Server { status: 404, .. }
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_client_rejects_oci_image_targets_before_next() {
    let Some(server) = stateful_server(MockVersion::V22_7).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let error = client
        .call(get_oci_image_targets(Default::default()))
        .await
        .expect_err("22.7 should reject next-only OCI image target command");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_oci_image_targets"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn versioned_client_rejects_agent_commands_before_next() {
    let Some(server) = stateful_server(MockVersion::V22_7).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let error = client
        .call(get_agents(Default::default()))
        .await
        .expect_err("22.7 should reject next-only agent commands");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "get_agents"
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_agent_commands_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let agents = client
        .get_agents(GetAgentsOpts {
            filter_string: Some("scanner=agent-controller".into()),
            ..Default::default()
        })
        .await
        .expect("get_agents should succeed");
    assert_eq!(agents.status_code(), Some(200));

    let missing_agent = client
        .get_agent(&id("ffffffff-ffff-ffff-ffff-ffffffffffff"))
        .await
        .expect_err("unseeded agent should not be found");
    assert!(matches!(
        missing_agent,
        GvmError::Server { status: 404, .. }
    ));

    let agent_ids = [id("00000000-0000-0000-0000-000000000002")];
    let modify = client
        .modify_agent(
            &agent_ids,
            ModifyAgentOpts {
                authorized: Some(true),
                update_to_latest: Some(true),
                comment: Some("managed from versioned client".into()),
                ..Default::default()
            },
        )
        .await
        .expect("modify_agent should succeed");
    assert_eq!(modify.status_code(), Some(200));

    let sync = client
        .sync_agents()
        .await
        .expect("sync_agents should succeed");
    assert_eq!(sync.status_code(), Some(200));

    let control_config = client
        .modify_agent_control_scan_config(
            &id("00000000-0000-0000-0000-000000000003"),
            ModifyAgentControlScanConfigOpts {
                update_to_latest: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("modify_agent_control_scan_config should succeed");
    assert_eq!(control_config.status_code(), Some(200));

    let instruction = client
        .get_agent_installer_instruction(
            &id("00000000-0000-0000-0000-000000000004"),
            AgentInstallerLanguage::En,
            "https://gvmd.example",
        )
        .await
        .expect("get_agent_installer_instruction should succeed");
    let instruction_xml = instruction.as_str().expect("valid UTF-8 XML");
    assert!(instruction_xml.contains("<language>en</language>"));
    assert!(instruction_xml.contains("<instruction>"));

    let bundle = client
        .get_agent_support_bundle(&agent_ids[0], Some(7))
        .await
        .expect("get_agent_support_bundle should succeed");
    let bundle_xml = bundle.as_str().expect("valid UTF-8 XML");
    assert!(bundle_xml.contains("<content_type>application/octet-stream</content_type>"));
    assert!(bundle_xml.contains("<content encoding=\"base64\">"));

    let delete = client
        .delete_agent(&agent_ids)
        .await
        .expect("delete_agent should succeed");
    assert_eq!(delete.status_code(), Some(200));

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_oci_image_targets_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let image_references = vec![
        "registry.example/app:1".to_string(),
        "registry.example/app:2".to_string(),
    ];
    let create_response = client
        .create_oci_image_target(
            "Client OCI Target",
            &image_references,
            CreateOciImageTargetOpts {
                comment: Some("created from versioned client".into()),
                credential_id: Some(id("credential-oci-1")),
            },
        )
        .await
        .expect("create_oci_image_target should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    let target_id = EntityId::new(create_response.id().expect("created id")).expect("valid id");

    let get_response = client
        .get_oci_image_target(&target_id, Some(true))
        .await
        .expect("get_oci_image_target should succeed");
    let get_xml = get_response.as_str().expect("valid utf8");
    assert!(get_xml.contains("<name>Client OCI Target</name>"));
    assert!(get_xml.contains(
        "<image_references>registry.example/app:1,registry.example/app:2</image_references>"
    ));
    assert!(get_xml.contains("<credential_id>credential-oci-1</credential_id>"));

    let clone_response = client
        .clone_oci_image_target(&target_id)
        .await
        .expect("clone_oci_image_target should succeed");
    assert_eq!(clone_response.status_code(), Some(201));

    let list_response = client
        .get_oci_image_targets(Default::default())
        .await
        .expect("get_oci_image_targets should succeed");
    let list_xml = list_response.as_str().expect("valid utf8");
    assert!(list_xml.contains("<oci_image_target_count>2<filtered>2</filtered>"));

    let modify_response = client
        .modify_oci_image_target(
            &target_id,
            ModifyOciImageTargetOpts {
                name: Some("Updated OCI Target".into()),
                comment: Some("updated from versioned client".into()),
                image_references: vec!["registry.example/app:latest".into()],
                credential_id: Some(id("credential-oci-2")),
            },
        )
        .await
        .expect("modify_oci_image_target should succeed");
    assert_eq!(modify_response.status_code(), Some(200));

    let modified_response = client
        .get_oci_image_target(&target_id, None)
        .await
        .expect("modified OCI image target should be readable");
    let modified_xml = modified_response.as_str().expect("valid utf8");
    assert!(modified_xml.contains("<name>Updated OCI Target</name>"));
    assert!(modified_xml.contains("<comment>updated from versioned client</comment>"));
    assert!(
        modified_xml.contains("<image_references>registry.example/app:latest</image_references>")
    );
    assert!(modified_xml.contains("<credential_id>credential-oci-2</credential_id>"));

    let delete_response = client
        .delete_oci_image_target(&target_id, true)
        .await
        .expect("delete_oci_image_target should succeed");
    assert_eq!(delete_response.status_code(), Some(200));

    let deleted_error = client
        .get_oci_image_target(&target_id, None)
        .await
        .expect_err("deleted OCI image target should be gone");
    assert!(matches!(
        deleted_error,
        GvmError::Server { status: 404, .. }
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_web_application_targets_round_trip() {
    let Some(server) = stateful_server(MockVersion::V22_8).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    let urls = vec![
        "https://example.com".to_string(),
        "https://example.com/app".to_string(),
    ];
    let create_response = client
        .create_web_application_target(
            "Client Web Target",
            &urls,
            CreateWebApplicationTargetOpts {
                comment: Some("created from versioned client".into()),
                exclude_urls: vec!["https://example.com/logout".into()],
                credential_id: Some(id("credential-web-1")),
            },
        )
        .await
        .expect("create_web_application_target should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    let target_id = EntityId::new(create_response.id().expect("created id")).expect("valid id");

    let get_response = client
        .get_web_application_target(&target_id, Some(true))
        .await
        .expect("get_web_application_target should succeed");
    let get_xml = get_response.as_str().expect("valid utf8");
    assert!(get_xml.contains("<name>Client Web Target</name>"));
    assert!(get_xml.contains("<urls>https://example.com,https://example.com/app</urls>"));
    assert!(get_xml.contains("<exclude_urls>https://example.com/logout</exclude_urls>"));
    assert!(get_xml.contains("<credential_id>credential-web-1</credential_id>"));

    let clone_response = client
        .clone_web_application_target(&target_id)
        .await
        .expect("clone_web_application_target should succeed");
    assert_eq!(clone_response.status_code(), Some(201));

    let list_response = client
        .get_web_application_targets(Default::default())
        .await
        .expect("get_web_application_targets should succeed");
    let list_xml = list_response.as_str().expect("valid utf8");
    assert!(list_xml.contains("<web_application_target_count>2<filtered>2</filtered>"));

    let modify_response = client
        .modify_web_application_target(
            &target_id,
            ModifyWebApplicationTargetOpts {
                name: Some("Updated Web Target".into()),
                comment: Some("updated from versioned client".into()),
                urls: vec!["https://updated.example".into()],
                exclude_urls: vec!["https://updated.example/logout".into()],
                credential_id: Some(id("credential-web-2")),
            },
        )
        .await
        .expect("modify_web_application_target should succeed");
    assert_eq!(modify_response.status_code(), Some(200));

    let modified_response = client
        .get_web_application_target(&target_id, None)
        .await
        .expect("modified web application target should be readable");
    let modified_xml = modified_response.as_str().expect("valid utf8");
    assert!(modified_xml.contains("<name>Updated Web Target</name>"));
    assert!(modified_xml.contains("<comment>updated from versioned client</comment>"));
    assert!(modified_xml.contains("<urls>https://updated.example</urls>"));
    assert!(modified_xml.contains("<exclude_urls>https://updated.example/logout</exclude_urls>"));
    assert!(modified_xml.contains("<credential_id>credential-web-2</credential_id>"));

    let delete_response = client
        .delete_web_application_target(&target_id, true)
        .await
        .expect("delete_web_application_target should succeed");
    assert_eq!(delete_response.status_code(), Some(200));

    let deleted_error = client
        .get_web_application_target(&target_id, None)
        .await
        .expect_err("deleted web application target should be gone");
    assert!(matches!(
        deleted_error,
        GvmError::Server { status: 404, .. }
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn gmp226_commands_work_on_v226() {
    let Some(server) = stateful_server(MockVersion::V22_6).await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpVersioned::connect(connection)
        .await
        .expect("client should connect");

    let auth_response = client
        .call(gvm_gmp::commands::authentication::authenticate(
            "admin", "admin",
        ))
        .await
        .expect("authenticate should succeed");
    assert_eq!(auth_response.status_code(), Some(200));

    let mut client = match client {
        GmpVersioned::V226(client) => client,
        other => panic!("expected V226 client, got {other:?}"),
    };

    let features_response = client
        .get_features()
        .await
        .expect("get_features should succeed");
    assert_eq!(features_response.status_code(), Some(200));

    let create_response = client
        .create_report_config("Client Report Config", "report-format-1")
        .await
        .expect("create_report_config should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    server.shutdown().await;
}

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid id")
}
