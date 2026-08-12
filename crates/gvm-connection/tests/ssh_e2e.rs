// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(clippy::print_stdout, clippy::unwrap_used, missing_docs)]
#![cfg(all(unix, feature = "ssh", feature = "unix-socket-tests"))]

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use gvm_connection::{
    ConnectionError, GvmConnection, SshAuth, SshConfig, SshConnection, SshHostKeyPolicy,
};
use gvm_mock_server::{GmpVersion, MockGmpServer, ScenarioMode, ScenarioStep, ServerMode};
use gvm_protocol::{Request, Response, XmlCommand};
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::rand_core::{TryCryptoRng, TryRng, UnwrapErr};
use russh::keys::{Algorithm, PrivateKey};
use tokio_stream::wrappers::UnixListenerStream;

static SSH_AGENT_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct SystemRng;

impl TryRng for SystemRng {
    type Error = std::io::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(std::io::Error::other)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).map_err(std::io::Error::other)
    }
}

impl TryCryptoRng for SystemRng {}

struct AgentSocketEnv {
    previous: Option<std::ffi::OsString>,
}

impl AgentSocketEnv {
    fn set(path: &Path) -> Self {
        let previous = std::env::var_os("SSH_AUTH_SOCK");
        std::env::set_var("SSH_AUTH_SOCK", path);
        Self { previous }
    }
}

impl Drop for AgentSocketEnv {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var("SSH_AUTH_SOCK", previous);
        } else {
            std::env::remove_var("SSH_AUTH_SOCK");
        }
    }
}

struct TestAgent {
    socket_path: PathBuf,
    _directory: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl TestAgent {
    async fn start() -> Self {
        let directory = tempfile::tempdir().expect("agent temporary directory");
        let socket_path = directory.path().join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind test agent");
        let task = tokio::spawn(async move {
            russh::keys::agent::server::serve(UnixListenerStream::new(listener), ())
                .await
                .expect("serve test agent");
        });
        Self {
            socket_path,
            _directory: directory,
            task,
        }
    }

    async fn add_identity(&self, key: &PrivateKey) {
        let stream = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .expect("connect test agent");
        AgentClient::connect(stream)
            .add_identity(key, &[])
            .await
            .expect("add test identity");
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn generate_user_key() -> PrivateKey {
    PrivateKey::random(&mut UnwrapErr(SystemRng), Algorithm::Ed25519)
        .expect("generate SSH user key")
}

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
    config_with_auth(server, "admin", SshAuth::Password("admin".to_string()))
}

fn config_with_auth(server: &MockGmpServer, username: &str, auth: SshAuth) -> SshConfig {
    SshConfig::new("127.0.0.1", username, auth)
        .with_port(server.ssh_port().expect("ssh port"))
        .with_remote_socket("/run/gvmd/gvmd.sock")
        .with_host_key_policy(SshHostKeyPolicy::Fingerprint(
            server
                .ssh_host_key_fingerprint()
                .expect("SSH host key fingerprint")
                .to_string(),
        ))
}

async fn start_key_mock(username: &str, key: &PrivateKey) -> MockGmpServer {
    MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .ssh_authorized_key(
            username,
            key.public_key()
                .to_openssh()
                .expect("encode SSH public key"),
        )
        .ssh("127.0.0.1:0")
        .build()
        .await
        .expect("start public-key SSH mock")
}

async fn assert_connected_round_trip(connection: &mut SshConnection) {
    connection.connect().await.expect("connect");
    assert!(connection.is_connected());
    connection
        .send(b"<get_version/>")
        .await
        .expect("send get_version");
    let response = Response::new(connection.read().await.expect("read get_version"));
    assert_eq!(response.status_code(), Some(200));
}

async fn assert_clean_failed_connection(connection: &mut SshConnection) {
    assert!(!connection.is_connected());
    assert!(matches!(
        connection.send(b"<get_version/>").await,
        Err(ConnectionError::NotConnected)
    ));
    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::NotConnected)
    ));
}

fn assert_permission_denied(error: ConnectionError, secrets: &[&str]) {
    let diagnostic = error.to_string();
    match error {
        ConnectionError::ConnectFailed(source) => {
            assert_eq!(source.kind(), ErrorKind::PermissionDenied);
        }
        other => panic!("expected ConnectFailed(PermissionDenied), got {other:?}"),
    }
    assert!(diagnostic.contains("ssh authentication failed"));
    assert!(diagnostic.contains("partial_success"));
    assert!(diagnostic.contains("remaining_methods"));
    for secret in secrets {
        assert!(!diagnostic.contains(secret));
    }
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
async fn ssh_authenticates_with_unencrypted_private_key() {
    let key = generate_user_key();
    let server = start_key_mock("key-user", &key).await;
    let directory = tempfile::tempdir().expect("private key directory");
    let key_path = directory.path().join("id_ed25519");
    std::fs::write(
        &key_path,
        key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encode private key")
            .as_bytes(),
    )
    .expect("write private key");
    let mut connection = SshConnection::new(config_with_auth(
        &server,
        "key-user",
        SshAuth::PrivateKey {
            key_path,
            passphrase: None,
        },
    ));

    assert_connected_round_trip(&mut connection).await;
    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_authenticates_with_encrypted_private_key() {
    let key = generate_user_key();
    let server = start_key_mock("encrypted-key-user", &key).await;
    let encrypted = key
        .encrypt(&mut UnwrapErr(SystemRng), "correct key passphrase")
        .expect("encrypt private key");
    let directory = tempfile::tempdir().expect("private key directory");
    let key_path = directory.path().join("id_ed25519_encrypted");
    std::fs::write(
        &key_path,
        encrypted
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encode encrypted private key")
            .as_bytes(),
    )
    .expect("write encrypted private key");
    let mut connection = SshConnection::new(config_with_auth(
        &server,
        "encrypted-key-user",
        SshAuth::PrivateKey {
            key_path,
            passphrase: Some("correct key passphrase".to_string()),
        },
    ));

    assert_connected_round_trip(&mut connection).await;
    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_authenticates_with_agent_identity() {
    let _environment_lock = SSH_AGENT_ENV_LOCK.lock().await;
    let key = generate_user_key();
    let server = start_key_mock("agent-user", &key).await;
    let agent = TestAgent::start().await;
    agent.add_identity(&key).await;
    let _agent_environment = AgentSocketEnv::set(&agent.socket_path);
    let mut connection =
        SshConnection::new(config_with_auth(&server, "agent-user", SshAuth::Agent));

    assert_connected_round_trip(&mut connection).await;
    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_wrong_password_and_unknown_user_are_permission_denied_without_secrets() {
    let server = start_mock().await.expect("start password SSH mock");
    let attempts = [
        ("admin", "not-the-password"),
        ("unknown-user", "unknown-user-password"),
    ];

    for (username, password) in attempts {
        let mut connection = SshConnection::new(config_with_auth(
            &server,
            username,
            SshAuth::Password(password.to_string()),
        ));
        let error = connection
            .connect()
            .await
            .expect_err("authentication should fail");

        assert_permission_denied(error, &[password]);
        assert_clean_failed_connection(&mut connection).await;
    }

    server.shutdown().await;
}

#[tokio::test]
async fn ssh_invalid_key_path_and_wrong_passphrase_fail_cleanly() {
    let key = generate_user_key();
    let server = start_key_mock("key-user", &key).await;
    let directory = tempfile::tempdir().expect("private key directory");
    let missing_path = directory.path().join("missing-key");
    let mut missing_key_connection = SshConnection::new(config_with_auth(
        &server,
        "key-user",
        SshAuth::PrivateKey {
            key_path: missing_path,
            passphrase: None,
        },
    ));
    let missing_key_error = missing_key_connection
        .connect()
        .await
        .expect_err("missing key should fail");
    assert!(matches!(
        missing_key_error,
        ConnectionError::ConnectFailed(_)
    ));
    assert!(missing_key_error.to_string().contains("missing-key"));
    assert_clean_failed_connection(&mut missing_key_connection).await;

    let encrypted = key
        .encrypt(&mut UnwrapErr(SystemRng), "correct passphrase")
        .expect("encrypt private key");
    let key_path = directory.path().join("encrypted-key");
    std::fs::write(
        &key_path,
        encrypted
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .expect("encode encrypted private key")
            .as_bytes(),
    )
    .expect("write encrypted private key");
    let wrong_passphrase = "definitely wrong passphrase";
    let mut wrong_passphrase_connection = SshConnection::new(config_with_auth(
        &server,
        "key-user",
        SshAuth::PrivateKey {
            key_path,
            passphrase: Some(wrong_passphrase.to_string()),
        },
    ));
    let wrong_passphrase_error = wrong_passphrase_connection
        .connect()
        .await
        .expect_err("wrong passphrase should fail");
    assert!(matches!(
        wrong_passphrase_error,
        ConnectionError::ConnectFailed(_)
    ));
    assert!(!wrong_passphrase_error
        .to_string()
        .contains(wrong_passphrase));
    assert_clean_failed_connection(&mut wrong_passphrase_connection).await;

    server.shutdown().await;
}

#[tokio::test]
async fn ssh_agent_missing_socket_fails_cleanly() {
    let _environment_lock = SSH_AGENT_ENV_LOCK.lock().await;
    let directory = tempfile::tempdir().expect("agent temporary directory");
    let missing_socket = directory.path().join("missing-agent.sock");
    let _agent_environment = AgentSocketEnv::set(&missing_socket);
    let server = start_mock().await.expect("start SSH mock");
    let mut connection = SshConnection::new(config_with_auth(&server, "admin", SshAuth::Agent));

    let error = connection
        .connect()
        .await
        .expect_err("missing agent socket should fail");
    assert!(matches!(error, ConnectionError::ConnectFailed(_)));
    assert!(error.to_string().contains("missing-agent.sock"));
    assert_clean_failed_connection(&mut connection).await;

    server.shutdown().await;
}

#[tokio::test]
async fn ssh_agent_empty_then_added_identity_retries_cleanly() {
    let _environment_lock = SSH_AGENT_ENV_LOCK.lock().await;
    let key = generate_user_key();
    let server = start_key_mock("agent-user", &key).await;
    let agent = TestAgent::start().await;
    let _agent_environment = AgentSocketEnv::set(&agent.socket_path);
    let mut connection =
        SshConnection::new(config_with_auth(&server, "agent-user", SshAuth::Agent));

    let error = connection
        .connect()
        .await
        .expect_err("empty agent should fail");
    assert!(matches!(error, ConnectionError::ConnectFailed(_)));
    assert!(error
        .to_string()
        .contains("ssh-agent did not return any identities"));
    assert_clean_failed_connection(&mut connection).await;

    agent.add_identity(&key).await;
    assert_connected_round_trip(&mut connection).await;
    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_agent_rejected_identity_is_permission_denied() {
    let _environment_lock = SSH_AGENT_ENV_LOCK.lock().await;
    let authorized_key = generate_user_key();
    let rejected_key = generate_user_key();
    let server = start_key_mock("agent-user", &authorized_key).await;
    let agent = TestAgent::start().await;
    agent.add_identity(&rejected_key).await;
    let _agent_environment = AgentSocketEnv::set(&agent.socket_path);
    let mut connection =
        SshConnection::new(config_with_auth(&server, "agent-user", SshAuth::Agent));

    let error = connection
        .connect()
        .await
        .expect_err("rejected agent identity should fail");
    assert_permission_denied(error, &[]);
    assert_clean_failed_connection(&mut connection).await;

    server.shutdown().await;
}

#[tokio::test]
async fn ssh_auth_timeout_leaves_clean_state_and_retry_succeeds() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .credentials("admin", "admin")
        .ssh_auth_delay_once(Duration::from_millis(1_500))
        .ssh("127.0.0.1:0")
        .build()
        .await
        .expect("start delayed-auth SSH mock");
    let timeout = Duration::from_millis(500);
    let mut connection = SshConnection::new(config_for(&server).with_timeout(timeout));

    assert!(matches!(
        connection.connect().await,
        Err(ConnectionError::Timeout(duration)) if duration == timeout
    ));
    assert_clean_failed_connection(&mut connection).await;

    assert_connected_round_trip(&mut connection).await;
    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_channel_open_timeout_leaves_clean_state_and_retry_succeeds() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .credentials("admin", "admin")
        .ssh_channel_open_delay_once(Duration::from_millis(1_500))
        .ssh("127.0.0.1:0")
        .build()
        .await
        .expect("start delayed-channel SSH mock");
    let timeout = Duration::from_millis(500);
    let mut connection = SshConnection::new(config_for(&server).with_timeout(timeout));

    assert!(matches!(
        connection.connect().await,
        Err(ConnectionError::Timeout(duration)) if duration == timeout
    ));
    assert_clean_failed_connection(&mut connection).await;

    assert_connected_round_trip(&mut connection).await;
    connection.disconnect().await.expect("disconnect");
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
        b"<create_target><name>SSH Target</name><hosts>192.168.1.0/24</hosts><port_range>T:1-65535</port_range></create_target>",
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
async fn ssh_response_timeout_invalidates_connection() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let mut connection =
        SshConnection::new(config_for(&server).with_timeout(Duration::from_millis(500)));
    connection.connect().await.expect("connect");
    connection.send(b"<incomplete").await.expect("send request");

    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::Timeout(_))
    ));
    assert!(!connection.is_connected());
    assert!(matches!(
        connection.send(b"<get_version/>").await,
        Err(ConnectionError::NotConnected)
    ));
    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::NotConnected)
    ));

    connection.connect().await.expect("reconnect");
    connection
        .send(b"<get_version/>")
        .await
        .expect("send fresh request");
    assert_eq!(
        Response::new(connection.read().await.expect("fresh response")).status_code(),
        Some(200)
    );
    connection.disconnect().await.expect("disconnect");

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
async fn ssh_connect_with_known_hosts_file() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("known_hosts");
    std::fs::write(
        &path,
        format!(
            "[127.0.0.1]:{} {}\n",
            server.ssh_port().expect("ssh port"),
            server.ssh_host_public_key().expect("SSH host public key")
        ),
    )
    .expect("write known_hosts");
    let config = config_for(&server).with_host_key_policy(SshHostKeyPolicy::KnownHostsFile(path));
    let mut connection = SshConnection::new(config);

    connection.connect().await.expect("connect failed");
    connection
        .send(b"<get_version/>")
        .await
        .expect("send failed");
    let response = Response::new(connection.read().await.expect("read failed"));
    assert_eq!(response.status_code(), Some(200));
    connection.disconnect().await.expect("disconnect failed");
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_rejects_unknown_host_in_known_hosts_file() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("known_hosts");
    std::fs::write(&path, "").expect("write known_hosts");
    let config = config_for(&server).with_host_key_policy(SshHostKeyPolicy::KnownHostsFile(path));
    let mut connection = SshConnection::new(config);

    let error = connection.connect().await.expect_err("connect should fail");
    assert!(matches!(error, ConnectionError::ConnectFailed(_)));
    server.shutdown().await;
}

#[tokio::test]
async fn ssh_rejects_changed_key_in_known_hosts_file() {
    let trusted_server = start_mock().await;
    let Some(trusted_server) = trusted_server else {
        return;
    };
    let server = start_mock().await;
    let Some(server) = server else {
        trusted_server.shutdown().await;
        return;
    };
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("known_hosts");
    std::fs::write(
        &path,
        format!(
            "[127.0.0.1]:{} {}\n",
            server.ssh_port().expect("ssh port"),
            trusted_server
                .ssh_host_public_key()
                .expect("trusted SSH host public key")
        ),
    )
    .expect("write known_hosts");
    let config = config_for(&server).with_host_key_policy(SshHostKeyPolicy::KnownHostsFile(path));
    let mut connection = SshConnection::new(config);

    let error = connection.connect().await.expect_err("connect should fail");
    assert!(matches!(error, ConnectionError::ConnectFailed(_)));
    assert!(error.to_string().to_ascii_lowercase().contains("changed"));
    server.shutdown().await;
    trusted_server.shutdown().await;
}

#[tokio::test]
async fn ssh_connect_with_explicit_accept_all() {
    let server = start_mock().await;
    let Some(server) = server else {
        return;
    };
    let config = config_for(&server).with_host_key_policy(SshHostKeyPolicy::AcceptAll);
    let mut connection = SshConnection::new(config);

    connection.connect().await.expect("connect failed");
    connection.disconnect().await.expect("disconnect failed");
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
