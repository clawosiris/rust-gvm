// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stdout, clippy::unwrap_used, missing_docs)]
#![cfg(all(feature = "ssh", feature = "unix-socket-tests"))]

use std::io::ErrorKind;

use gvm_connection::{
    ConnectionError, GvmConnection, SshAuth, SshConfig, SshConnection, SshHostKeyPolicy,
};
use gvm_mock_server::{GmpVersion, MockGmpServer, ScenarioMode, ScenarioStep, ServerMode};
use gvm_protocol::{Request, Response, XmlCommand};

async fn start_mock() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .ssh("127.0.0.1:0")
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => None,
        Err(error) => panic!("mock server start failed: {error}"),
    }
}

fn config_for(server: &MockGmpServer) -> SshConfig {
    SshConfig::new("127.0.0.1", "admin", SshAuth::Password("admin".to_string()))
        .with_port(server.ssh_port().expect("ssh port"))
        .with_remote_socket("/run/gvmd/gvmd.sock")
}

#[tokio::test]
async fn ssh_connect_and_get_version() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };

    let mut conn = SshConnection::new(config_for(&server));
    conn.connect().await.expect("connect failed");
    assert!(conn.is_connected());

    let cmd = XmlCommand::new("get_version");
    conn.send(&cmd.to_bytes()).await.expect("send failed");

    let response = Response::new(conn.read().await.expect("read failed"));
    assert_eq!(response.status_code(), Some(200));
    assert_eq!(response.child_text("version").as_deref(), Some("22.5"));

    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_authenticate_and_crud() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };

    let mut conn = SshConnection::new(config_for(&server));
    conn.connect().await.expect("connect failed");

    conn.send(b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>")
        .await
        .expect("send auth failed");
    assert_eq!(
        Response::new(conn.read().await.expect("read auth failed")).status_code(),
        Some(200)
    );

    conn.send(
        b"<create_target><name>SSH Target</name><hosts>192.168.1.0/24</hosts></create_target>",
    )
    .await
    .expect("send create failed");
    let create_response = Response::new(conn.read().await.expect("read create failed"));
    assert_eq!(create_response.status_code(), Some(201));
    let target_id = create_response.id().expect("target id");

    conn.send(b"<get_targets/>").await.expect("send get failed");
    let targets_response = Response::new(conn.read().await.expect("read get failed"));
    assert_eq!(targets_response.status_code(), Some(200));
    assert!(String::from_utf8_lossy(targets_response.as_ref()).contains(&target_id.to_string()));

    let delete_xml = format!("<delete_target target_id=\"{target_id}\"/>");
    conn.send(delete_xml.as_bytes())
        .await
        .expect("send delete failed");
    assert_eq!(
        Response::new(conn.read().await.expect("read delete failed")).status_code(),
        Some(200)
    );

    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_reconnect_flow() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };

    let mut conn = SshConnection::new(config_for(&server));
    conn.connect().await.expect("connect 1 failed");
    conn.send(b"<get_version/>").await.expect("send 1 failed");
    let version = Response::new(conn.read().await.expect("read 1 failed"));
    assert_eq!(version.child_text("version").as_deref(), Some("22.5"));
    conn.disconnect().await.expect("disconnect 1 failed");

    let mut conn2 = SshConnection::new(config_for(&server));
    conn2.connect().await.expect("connect 2 failed");
    conn2
        .send(
            b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>",
        )
        .await
        .expect("send auth failed");
    assert_eq!(
        Response::new(conn2.read().await.expect("read auth failed")).status_code(),
        Some(200)
    );

    conn2.send(b"<get_targets/>").await.expect("send 2 failed");
    assert_eq!(
        Response::new(conn2.read().await.expect("read 2 failed")).status_code(),
        Some(200)
    );

    conn2.disconnect().await.expect("disconnect 2 failed");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_not_connected_errors() {
    let mut conn = SshConnection::new(SshConfig::default());
    assert!(!conn.is_connected());

    let send = conn.send(b"<get_version/>").await;
    assert!(matches!(send, Err(ConnectionError::NotConnected)));

    let read = conn.read().await;
    assert!(matches!(read, Err(ConnectionError::NotConnected)));
}

#[tokio::test]
async fn ssh_connect_with_pinned_fingerprint() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };

    let config = config_for(&server).with_host_key_policy(SshHostKeyPolicy::Fingerprint(
        server
            .ssh_host_key_fingerprint()
            .expect("ssh host key fingerprint")
            .to_string(),
    ));
    let mut conn = SshConnection::new(config);

    conn.connect().await.expect("connect failed");
    conn.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_rejects_wrong_fingerprint() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };

    let config =
        config_for(&server).with_host_key_policy(SshHostKeyPolicy::Fingerprint("wrong".into()));
    let mut conn = SshConnection::new(config);

    let error = conn.connect().await.expect_err("connect should fail");
    assert!(matches!(error, ConnectionError::ConnectFailed(_)));

    server.shutdown().await;
}

#[tokio::test]
async fn ssh_coalesced_commands_are_processed_in_order() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let mut connection = SshConnection::new(config_for(&server));
    connection.connect().await.expect("connect");

    connection
        .send(b"<get_version/><get_tasks/>")
        .await
        .expect("coalesced send");
    let version = Response::new(connection.read().await.expect("version response"));
    let tasks = Response::new(connection.read().await.expect("tasks response"));

    assert_eq!(
        version.root_element_name().as_deref(),
        Some("get_version_response")
    );
    assert_eq!(
        tasks.root_element_name().as_deref(),
        Some("get_tasks_response")
    );
    let history = server.command_history();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].raw_xml(), b"<get_version/>");
    assert_eq!(history[1].raw_xml(), b"<get_tasks/>");

    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_coalesced_responses_are_returned_one_frame_at_a_time() {
    let server = match MockGmpServer::builder()
        .scenario(
            ScenarioMode::Strict,
            vec![ScenarioStep {
                expect_command: "get_version".to_string(),
                respond_xml: Some("<first_response/><second_response/>".to_string()),
            }],
        )
        .ssh("127.0.0.1:0")
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("mock server start failed: {error}"),
    };
    let mut connection = SshConnection::new(config_for(&server));
    connection.connect().await.expect("connect");
    connection.send(b"<get_version/>").await.expect("send");

    assert_eq!(
        connection.read().await.expect("first response"),
        b"<first_response/>"
    );
    assert_eq!(
        connection.read().await.expect("second response"),
        b"<second_response/>"
    );

    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_reconnect_on_same_connection_discards_pending_response_tail() {
    let server = match MockGmpServer::builder()
        .scenario(
            ScenarioMode::Strict,
            vec![ScenarioStep {
                expect_command: "get_version".to_string(),
                respond_xml: Some("<current_response/><stale_response/>".to_string()),
            }],
        )
        .ssh("127.0.0.1:0")
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("mock server start failed: {error}"),
    };
    let mut connection = SshConnection::new(config_for(&server));

    connection.connect().await.expect("first connect");
    connection
        .send(b"<get_version/>")
        .await
        .expect("first send");
    assert_eq!(
        connection.read().await.expect("current response"),
        b"<current_response/>"
    );
    connection.disconnect().await.expect("disconnect");

    connection.connect().await.expect("second connect");
    connection
        .send(b"<get_version/>")
        .await
        .expect("second send");
    assert_eq!(
        connection.read().await.expect("fresh current response"),
        b"<current_response/>"
    );

    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_malformed_response_invalidates_connection() {
    let server = match MockGmpServer::builder()
        .scenario(
            ScenarioMode::Strict,
            vec![ScenarioStep {
                expect_command: "get_version".to_string(),
                respond_xml: Some("<response></wrong>".to_string()),
            }],
        )
        .ssh("127.0.0.1:0")
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("mock server start failed: {error}"),
    };
    let mut connection = SshConnection::new(config_for(&server));
    connection.connect().await.expect("connect");
    connection.send(b"<get_version/>").await.expect("send");

    let error = connection.read().await.expect_err("malformed response");
    assert!(matches!(
        error,
        ConnectionError::ReadFailed(ref source)
            if source.kind() == ErrorKind::InvalidData
    ));
    assert!(!connection.is_connected());
    assert!(matches!(
        connection.send(b"<get_version/>").await,
        Err(ConnectionError::NotConnected)
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn ssh_response_limit_is_applied_independently_to_coalesced_frames() {
    let first = b"<first_response/>";
    let server = match MockGmpServer::builder()
        .scenario(
            ScenarioMode::Strict,
            vec![ScenarioStep {
                expect_command: "get_version".to_string(),
                respond_xml: Some("<first_response/><oversized-response-without-close".to_string()),
            }],
        )
        .ssh("127.0.0.1:0")
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("mock server start failed: {error}"),
    };
    let config = config_for(&server).with_max_response_bytes(Some(first.len()));
    let mut connection = SshConnection::new(config);
    connection.connect().await.expect("connect");
    connection.send(b"<get_version/>").await.expect("send");

    assert_eq!(connection.read().await.expect("first response"), first);
    let error = connection
        .read()
        .await
        .expect_err("oversized second response");
    assert!(matches!(
        error,
        ConnectionError::ReadFailed(ref source)
            if source.kind() == ErrorKind::InvalidData
    ));
    assert!(!connection.is_connected());

    server.shutdown().await;
}

#[tokio::test]
async fn ssh_mock_rejects_malformed_request_then_closes_channel() {
    let server = match MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .version(GmpVersion::V22_5)
        .ssh("127.0.0.1:0")
        .build()
        .await
    {
        Ok(server) => server,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
        Err(error) => panic!("mock server start failed: {error}"),
    };
    let mut connection = SshConnection::new(config_for(&server));
    connection.connect().await.expect("connect");
    connection
        .send(b"<get_version></wrong>")
        .await
        .expect("send malformed command");

    let response = Response::new(connection.read().await.expect("rejection response"));
    assert_eq!(response.status_code(), Some(400));
    let error = connection.read().await.expect_err("closed SSH channel");
    assert!(matches!(
        error,
        ConnectionError::ReadFailed(ref source)
            if source.kind() == ErrorKind::UnexpectedEof
    ));
    assert!(!connection.is_connected());
    assert_eq!(server.command_count(), 0);

    server.shutdown().await;
}
