// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stderr, missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::GmpNext;
use gvm_client::{
    AgentInstallerLanguage, CreateAgentGroupOpts, CreateAgentGroupTaskOpts,
    CreateOciImageTargetOpts, CreateOciImageTargetTaskOpts, CreateWebApplicationTargetOpts,
    CreateWebApplicationTaskOpts, CredentialStoreCredentialOpts, CredentialStoreCredentialType,
    GetAgentsOpts, GetCredentialStoresOpts, Gmp226Commands, GmpNextCommands, GmpVersioned,
    GvmError, ModifyAgentControlScanConfigOpts, ModifyAgentGroupOpts, ModifyAgentOpts,
    ModifyCredentialStoreCredentialOpts, ModifyOciImageTargetOpts, ModifyWebApplicationTargetOpts,
};
use gvm_connection::{GvmConnection, UnixSocketConnection};
use gvm_gmp::commands::agents::get_agents;
use gvm_gmp::commands::credentials::{create_credential, verify_credential_store, CredentialOpts};
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

async fn assert_create_oci_image_target_task_round_trip<C>(
    client: &mut GmpNext<C>,
    server: &MockGmpServer,
    oci_image_target_id: &EntityId,
) where
    C: GvmConnection + Send,
{
    server.clear_history();

    let scanner_id = id("scanner-1");
    let task_response = client
        .create_container_image_task(
            "Client OCI Target Task",
            oci_image_target_id,
            &scanner_id,
            CreateOciImageTargetTaskOpts {
                comment: Some("task through client".into()),
                alterable: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("create_container_image_task should succeed");
    assert_eq!(task_response.status_code(), Some(201));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create_task command recorded");
    assert_eq!(command.command_name(), "create_task");
    assert_eq!(
        String::from_utf8(command.raw_xml().to_vec()).expect("history should be UTF-8"),
        format!(
            "<create_task><name>Client OCI Target Task</name><usage_type>scan</usage_type><oci_image_target id=\"{}\"/><scanner id=\"scanner-1\"/><comment>task through client</comment><alterable>1</alterable></create_task>",
            oci_image_target_id.as_str()
        )
    );
}

async fn assert_create_web_application_task_round_trip(
    client: &mut GmpNext<UnixSocketConnection>,
    server: &MockGmpServer,
    target_id: &EntityId,
) {
    server.clear_history();
    let scanner_id = EntityId::new("scanner-web-1").expect("valid id");
    let task_response = client
        .create_web_application_task(
            "Client Web Task",
            target_id,
            &scanner_id,
            CreateWebApplicationTaskOpts {
                comment: Some("created from versioned client".into()),
                ..Default::default()
            },
        )
        .await
        .expect("create_web_application_task should succeed");
    assert_eq!(task_response.status_code(), Some(201));
    let history = server.command_history();
    let command = history.last().expect("create task command recorded");
    assert_eq!(command.command_name(), "create_task");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("history should be utf8");
    assert_eq!(
        raw_xml,
        format!(
            "<create_task><name>Client Web Task</name><usage_type>scan</usage_type><web_application_target id=\"{target_id}\"/><scanner id=\"scanner-web-1\"/><comment>created from versioned client</comment></create_task>"
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
async fn next_client_verify_credential_store_round_trip() {
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

    server.clear_history();
    let credential_store_id = EntityId::new("credential-store-1").expect("valid id");
    let response = client
        .verify_credential_store(&credential_store_id)
        .await
        .expect("verify_credential_store should succeed");
    assert_eq!(response.status_code(), Some(200));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "verify_credential_store");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("valid UTF-8 request"),
        "<verify_credential_store credential_store_id=\"credential-store-1\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_credential_store_helpers_send_expected_commands() {
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

    server.clear_history();
    let credential_store_id = EntityId::new("local").expect("valid id");
    let response = client
        .get_credential_store(&credential_store_id, Some(true))
        .await
        .expect("get_credential_store should succeed");
    assert_eq!(response.status_code(), Some(200));
    assert!(response
        .as_str()
        .expect("valid UTF-8 XML")
        .contains("Local credential store"));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "get_credential_stores");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("valid UTF-8 request"),
        "<get_credential_stores details=\"1\"><credential_store_id>local</credential_store_id></get_credential_stores>"
    );

    server.clear_history();
    let response = client
        .get_credential_stores_with_opts(GetCredentialStoresOpts {
            filter_string: Some("name=Local".into()),
            filter_id: Some(EntityId::new("filter-1").expect("valid id")),
            details: Some(false),
        })
        .await
        .expect("get_credential_stores_with_opts should succeed");
    assert_eq!(response.status_code(), Some(200));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].command_name(), "get_credential_stores");
    assert_eq!(
        std::str::from_utf8(history[0].raw_xml()).expect("valid UTF-8 request"),
        "<get_credential_stores details=\"0\" filt_id=\"filter-1\" filter=\"name=Local\"/>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_create_credential_store_credential_round_trip() {
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

    server.clear_history();
    let create_response = client
        .create_credential_store_credential(
            "Client Store Credential",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts {
                comment: Some("stored credential".into()),
                credential_store_id: Some(id("credential-store-1")),
            },
        )
        .await
        .expect("create_credential_store_credential should succeed");
    assert_eq!(create_response.status_code(), Some(201));
    assert!(create_response.id().is_some());

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("create command recorded");
    assert_eq!(command.command_name(), "create_credential");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("valid utf8");
    assert_eq!(
        raw_xml,
        "<create_credential><name>Client Store Credential</name><type>cs_up</type><comment>stored credential</comment><credential_store_id>credential-store-1</credential_store_id><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn next_client_modify_credential_store_credential_round_trip() {
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

    let create_response = client
        .call(create_credential(
            "Next Store Credential",
            CredentialOpts::default(),
        ))
        .await
        .expect("create credential should succeed");
    let credential_id = id(&create_response.id().expect("created id"));

    let mut client = match client {
        GmpVersioned::Next(client) => client,
        other => panic!("expected Next client, got {other:?}"),
    };

    server.clear_history();

    let response = client
        .modify_credential_store_credential(
            &credential_id,
            ModifyCredentialStoreCredentialOpts {
                name: Some("Next Updated Store Credential".into()),
                credential_store_id: Some(id("credential-store-next")),
                vault_id: Some("vault-next".into()),
                host_identifier: Some("host-next".into()),
                ..Default::default()
            },
        )
        .await
        .expect("modify_credential_store_credential should succeed");
    assert_eq!(response.status_code(), Some(200));

    let history = server.command_history();
    assert_eq!(history.len(), 1);
    let command = history.last().expect("modify command recorded");
    assert_eq!(command.command_name(), "modify_credential");
    let raw_xml = String::from_utf8(command.raw_xml().to_vec()).expect("valid utf8");
    assert_eq!(
        raw_xml,
        format!(
            "<modify_credential credential_id=\"{}\"><name>Next Updated Store Credential</name><credential_store_id>credential-store-next</credential_store_id><vault_id>vault-next</vault_id><host_identifier>host-next</host_identifier></modify_credential>",
            credential_id.as_str()
        )
    );

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
    assert_eq!(create_response.status, 201);
    let agent_group_id = create_response.id;

    assert_create_agent_group_task_round_trip(&mut client, &server, &agent_group_id).await;

    let clone_response = client
        .clone_agent_group(&agent_group_id)
        .await
        .expect("clone_agent_group should succeed");
    assert_eq!(clone_response.status, 201);

    let get_response = client
        .get_agent_group(&agent_group_id)
        .await
        .expect("get_agent_group should succeed");
    assert_eq!(get_response.items.len(), 1);
    assert_eq!(get_response.items[0].meta.name, "Client Agent Group");
    assert_eq!(
        get_response.items[0].scheduler_cron_time.as_deref(),
        Some("0 */5 * * *")
    );

    let list_response = client
        .get_agent_groups(Default::default())
        .await
        .expect("get_agent_groups should succeed");
    assert_eq!(list_response.status, 200);
    assert_eq!(list_response.counts.total, Some(2));

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
    assert_eq!(modify_response.status, 200);

    let updated_response = client
        .get_agent_group(&agent_group_id)
        .await
        .expect("updated get_agent_group should succeed");
    assert_eq!(updated_response.items[0].meta.name, "Updated Agent Group");
    assert_eq!(
        updated_response.items[0].meta.comment.as_deref(),
        Some("modified through client")
    );
    assert_eq!(
        updated_response.items[0].scheduler_cron_time.as_deref(),
        Some("0 */10 * * *")
    );

    let delete_response = client
        .delete_agent_group(&agent_group_id, true)
        .await
        .expect("delete_agent_group should succeed");
    assert_eq!(delete_response.status, 200);

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

    let credential_store_id = EntityId::new("credential-store-1").expect("valid id");
    let error = client
        .call(verify_credential_store(&credential_store_id))
        .await
        .expect_err("22.7 should reject next-only credential store verify command");

    assert!(matches!(
        error,
        GvmError::UnsupportedCommand {
            command,
            version: GmpVersion(22, 7),
            required: "22.8",
        } if command == "verify_credential_store"
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
    assert_eq!(agents.status, 200);

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
    assert_eq!(modify.status, 200);

    let sync = client
        .sync_agents()
        .await
        .expect("sync_agents should succeed");
    assert_eq!(sync.status, 200);

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
    assert_eq!(control_config.status, 200);

    let instruction = client
        .get_agent_installer_instruction(
            &id("00000000-0000-0000-0000-000000000004"),
            AgentInstallerLanguage::En,
            "https://gvmd.example",
        )
        .await
        .expect("get_agent_installer_instruction should succeed");
    assert_eq!(instruction.language, "en");
    assert!(instruction.instruction.contains("mock agent"));

    let bundle = client
        .get_agent_support_bundle(&agent_ids[0], Some(7))
        .await
        .expect("get_agent_support_bundle should succeed");
    assert_eq!(
        bundle.file.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(bundle.file.content, b"hello-mock");

    let delete = client
        .delete_agent(&agent_ids)
        .await
        .expect("delete_agent should succeed");
    assert_eq!(delete.status, 200);

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

    assert_create_oci_image_target_task_round_trip(&mut client, &server, &target_id).await;

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

    assert_create_web_application_task_round_trip(&mut client, &server, &target_id).await;

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
