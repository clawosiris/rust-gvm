// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! End-to-end verified TLS and mutual-TLS transport tests.

#![cfg(feature = "tls")]
#![allow(clippy::unwrap_used, missing_docs)]

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use gvm_connection::{ConnectionError, GvmConnection, TlsClientIdentity, TlsConfig, TlsConnection};
use gvm_mock_server::{GmpVersion, MockGmpServer, ServerMode};
use gvm_protocol::Response;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use tempfile::TempDir;
use tokio::net::TcpListener;
use x509_cert::builder::profile::cabf::tls::{CertificateType, Subscriber};
use x509_cert::builder::profile::cabf::Root;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::EncodePem;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::SubjectPublicKeyInfo;

struct ClientMaterial {
    ca_pem: String,
    certificate_pem: String,
    private_key_pem: String,
}

fn client_material() -> ClientMaterial {
    let validity =
        Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60)).expect("certificate validity");
    let ca_key = SigningKey::generate();
    let ca_subject = Name::from_str("CN=rust-gvm test CA,O=rust-gvm,C=US").expect("CA subject");
    let ca_profile = Root::new(false, ca_subject.clone()).expect("CA profile");
    let ca_public_key_der = ca_key
        .verifying_key()
        .to_public_key_der()
        .expect("CA public key DER");
    let ca_public_key = SubjectPublicKeyInfo::try_from(ca_public_key_der.as_bytes())
        .expect("CA subject public key");
    let ca_certificate = CertificateBuilder::new(
        ca_profile,
        SerialNumber::from(1u32),
        validity,
        ca_public_key,
    )
    .expect("CA certificate builder")
    .build::<_, DerSignature>(&ca_key)
    .expect("CA certificate");

    let client_key = SigningKey::generate();
    let client_subject = Name::from_str("CN=rust-gvm.test").expect("client subject");
    let client_names = vec![GeneralName::DnsName(
        Ia5String::new(b"rust-gvm.test").expect("client DNS name"),
    )];
    let client_profile = Subscriber {
        certificate_type: CertificateType::domain_validated(client_subject, client_names.clone())
            .expect("client certificate profile"),
        issuer: ca_subject,
        client_auth: true,
    };
    let client_public_key_der = client_key
        .verifying_key()
        .to_public_key_der()
        .expect("client public key DER");
    let client_public_key = SubjectPublicKeyInfo::try_from(client_public_key_der.as_bytes())
        .expect("client subject public key");
    let mut client_builder = CertificateBuilder::new(
        client_profile,
        SerialNumber::from(2u32),
        validity,
        client_public_key,
    )
    .expect("client certificate builder");
    client_builder
        .add_extension(&SubjectAltName(client_names))
        .expect("client subject alternative name");
    let client_certificate = client_builder
        .build::<_, DerSignature>(&ca_key)
        .expect("client certificate");

    ClientMaterial {
        ca_pem: ca_certificate
            .to_pem(LineEnding::LF)
            .expect("CA certificate PEM"),
        certificate_pem: client_certificate
            .to_pem(LineEnding::LF)
            .expect("client certificate PEM"),
        private_key_pem: client_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("client private key PEM")
            .to_string(),
    }
}

async fn start_tls(client_ca: Option<&Path>) -> MockGmpServer {
    let builder = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_5)
        .credentials("admin", "admin")
        .tls("127.0.0.1:0");
    let builder = match client_ca {
        Some(client_ca) => builder.require_client_cert(client_ca),
        None => builder,
    };
    builder.build().await.expect("TLS mock server")
}

fn config_for(server: &MockGmpServer) -> TlsConfig {
    TlsConfig::new("127.0.0.1")
        .with_port(server.tls_port().expect("TLS port"))
        .with_native_roots(false)
        .with_root_certificate_pem(
            server
                .tls_certificate_pem()
                .expect("TLS server certificate")
                .as_bytes()
                .to_vec(),
        )
}

async fn get_version(connection: &mut TlsConnection) -> Response {
    connection
        .send(b"<get_version/>")
        .await
        .expect("send get_version");
    Response::new(connection.read().await.expect("read get_version"))
}

#[tokio::test]
async fn verified_tls_round_trip_and_reconnect() {
    let server = start_tls(None).await;
    let config = config_for(&server);
    let mut connection = TlsConnection::new(config.clone());

    connection.connect().await.expect("verified TLS connect");
    assert!(connection.is_connected());
    let response = get_version(&mut connection).await;
    assert_eq!(response.status_code(), Some(200));
    assert_eq!(response.child_text("version").as_deref(), Some("22.5"));
    connection.disconnect().await.expect("disconnect");
    assert!(!connection.is_connected());

    connection.connect().await.expect("verified TLS reconnect");
    assert_eq!(get_version(&mut connection).await.status_code(), Some(200));
    assert!(matches!(
        connection.connect().await,
        Err(ConnectionError::AlreadyConnected)
    ));
    connection.disconnect().await.expect("second disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn verified_tls_supports_authentication_and_commands() {
    let server = start_tls(None).await;
    let mut connection = TlsConnection::new(config_for(&server));
    connection.connect().await.expect("connect");

    connection
        .send(b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>")
        .await
        .expect("send authenticate");
    assert_eq!(
        Response::new(connection.read().await.expect("read authenticate")).status_code(),
        Some(200)
    );

    connection
        .send(b"<get_targets/>")
        .await
        .expect("send get_targets");
    assert_eq!(
        Response::new(connection.read().await.expect("read get_targets")).status_code(),
        Some(200)
    );

    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn wrong_server_name_is_rejected() {
    let server = start_tls(None).await;
    let config = config_for(&server).with_server_name("not-localhost.invalid");
    let mut connection = TlsConnection::new(config);

    let error = connection
        .connect()
        .await
        .expect_err("SAN mismatch must fail");
    assert!(matches!(error, ConnectionError::ConnectFailed(_)));
    assert!(!connection.is_connected());
    server.shutdown().await;
}

#[tokio::test]
async fn untrusted_server_certificate_is_rejected() {
    let trusted_server = start_tls(None).await;
    let untrusted_server = start_tls(None).await;
    let config = TlsConfig::new("127.0.0.1")
        .with_port(untrusted_server.tls_port().expect("TLS port"))
        .with_native_roots(false)
        .with_root_certificate_pem(
            trusted_server
                .tls_certificate_pem()
                .expect("trusted certificate")
                .as_bytes()
                .to_vec(),
        );
    let mut connection = TlsConnection::new(config);

    let error = connection
        .connect()
        .await
        .expect_err("untrusted certificate must fail");
    assert!(matches!(error, ConnectionError::ConnectFailed(_)));
    trusted_server.shutdown().await;
    untrusted_server.shutdown().await;
}

#[tokio::test]
async fn mutual_tls_requires_and_accepts_trusted_client_identity() {
    let material = client_material();
    let directory = TempDir::new().expect("temporary directory");
    let ca_path = directory.path().join("client-ca.pem");
    std::fs::write(&ca_path, &material.ca_pem).expect("write client CA");
    let server = start_tls(Some(&ca_path)).await;

    let mut anonymous = TlsConnection::new(config_for(&server));
    anonymous
        .connect()
        .await
        .expect("client-side TLS handshake");
    let rejection = async {
        anonymous.send(b"<get_version/>").await?;
        anonymous.read().await.map(|_| ())
    }
    .await
    .expect_err("anonymous TLS client must be rejected before a GMP response");
    assert!(matches!(
        rejection,
        ConnectionError::SendFailed(_) | ConnectionError::ReadFailed(_)
    ));
    assert!(matches!(
        anonymous.disconnect().await,
        Err(ConnectionError::DisconnectFailed(_))
    ));

    let identity = TlsClientIdentity::from_pem(
        material.certificate_pem.into_bytes(),
        material.private_key_pem.into_bytes(),
    );
    let mut authenticated = TlsConnection::new(config_for(&server).with_client_identity(identity));
    authenticated.connect().await.expect("mutual TLS connect");
    assert_eq!(
        get_version(&mut authenticated).await.status_code(),
        Some(200)
    );
    authenticated.disconnect().await.expect("disconnect");
    server.shutdown().await;
}

#[tokio::test]
async fn missing_trust_roots_are_a_configuration_error() {
    let mut connection = TlsConnection::new(TlsConfig::new("127.0.0.1").with_native_roots(false));
    let error = connection
        .connect()
        .await
        .expect_err("empty roots must fail before connecting");
    assert!(matches!(error, ConnectionError::InvalidConfiguration(_)));
}

#[tokio::test]
async fn tls_handshake_timeout_is_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let port = listener.local_addr().expect("address").port();
    let server_task = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept");
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let material = client_material();
    let config = TlsConfig::new("127.0.0.1")
        .with_port(port)
        .with_native_roots(false)
        .with_root_certificate_pem(material.ca_pem.into_bytes())
        .with_timeout(Duration::from_millis(50));
    let mut connection = TlsConnection::new(config);
    let error = connection
        .connect()
        .await
        .expect_err("handshake should time out");
    assert!(matches!(error, ConnectionError::Timeout(_)));

    server_task.abort();
}

#[tokio::test]
async fn disconnected_tls_operations_fail() {
    let mut connection = TlsConnection::new(TlsConfig::default());
    assert!(matches!(
        connection.send(b"<get_version/>").await,
        Err(ConnectionError::NotConnected)
    ));
    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::NotConnected)
    ));
}

#[tokio::test]
async fn certificate_file_builders_and_debug_are_usable() {
    let server = start_tls(None).await;
    let material = client_material();
    let directory = TempDir::new().expect("temporary directory");
    let root_path = directory.path().join("server.pem");
    let certificate_path = directory.path().join("client.pem");
    let key_path = directory.path().join("client-key.pem");
    std::fs::write(
        &root_path,
        server.tls_certificate_pem().expect("server certificate"),
    )
    .expect("write server certificate");
    std::fs::write(&certificate_path, &material.certificate_pem).expect("write client certificate");
    std::fs::write(&key_path, &material.private_key_pem).expect("write client key");

    let identity =
        TlsClientIdentity::from_files(&certificate_path, &key_path).expect("load client identity");
    let config = TlsConfig::new("127.0.0.1")
        .with_port(server.tls_port().expect("TLS port"))
        .with_native_roots(false)
        .with_root_certificate_file(root_path)
        .expect("load root certificate")
        .with_client_identity(identity)
        .with_max_response_bytes(None);
    assert_eq!(config.max_response_bytes, None);

    let mut connection = TlsConnection::new(config);
    assert!(format!("{connection:?}").contains("connected: false"));
    connection.connect().await.expect("TLS connect");
    assert_eq!(get_version(&mut connection).await.status_code(), Some(200));
    connection.disconnect().await.expect("disconnect");

    assert!(TlsClientIdentity::from_files(directory.path().join("missing"), &key_path).is_err());
    server.shutdown().await;
}

#[tokio::test]
async fn invalid_certificate_and_key_material_are_rejected() {
    let server = start_tls(None).await;
    let server_root = server
        .tls_certificate_pem()
        .expect("server certificate")
        .as_bytes()
        .to_vec();

    let mut empty_root = TlsConnection::new(
        TlsConfig::new("127.0.0.1")
            .with_native_roots(false)
            .with_root_certificate_pem(b"not a certificate".to_vec()),
    );
    assert!(matches!(
        empty_root.connect().await,
        Err(ConnectionError::InvalidConfiguration(_))
    ));

    let invalid_der = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let mut invalid_root = TlsConnection::new(
        TlsConfig::new("127.0.0.1")
            .with_native_roots(false)
            .with_root_certificate_pem(invalid_der.to_vec()),
    );
    assert!(matches!(
        invalid_root.connect().await,
        Err(ConnectionError::InvalidConfiguration(_))
    ));

    let material = client_material();
    let mut missing_certificate = TlsConnection::new(config_for(&server).with_client_identity(
        TlsClientIdentity::from_pem(Vec::new(), material.private_key_pem.clone().into_bytes()),
    ));
    assert!(matches!(
        missing_certificate.connect().await,
        Err(ConnectionError::InvalidConfiguration(_))
    ));

    let mut missing_key = TlsConnection::new(config_for(&server).with_client_identity(
        TlsClientIdentity::from_pem(material.certificate_pem.clone().into_bytes(), Vec::new()),
    ));
    assert!(matches!(
        missing_key.connect().await,
        Err(ConnectionError::InvalidConfiguration(_))
    ));

    let other_material = client_material();
    let mut mismatched_identity = TlsConnection::new(
        TlsConfig::new("127.0.0.1")
            .with_port(server.tls_port().expect("TLS port"))
            .with_native_roots(false)
            .with_root_certificate_pem(server_root)
            .with_client_identity(TlsClientIdentity::from_pem(
                material.certificate_pem.into_bytes(),
                other_material.private_key_pem.into_bytes(),
            )),
    );
    assert!(matches!(
        mismatched_identity.connect().await,
        Err(ConnectionError::InvalidConfiguration(_))
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn invalid_server_name_and_tcp_timeout_are_reported() {
    let server = start_tls(None).await;

    let mut invalid_name = TlsConnection::new(config_for(&server).with_server_name(String::new()));
    assert!(matches!(
        invalid_name.connect().await,
        Err(ConnectionError::InvalidConfiguration(_))
    ));

    let mut timed_out = TlsConnection::new(
        TlsConfig::new("192.0.2.1")
            .with_port(9)
            .with_native_roots(false)
            .with_root_certificate_pem(
                server
                    .tls_certificate_pem()
                    .expect("server certificate")
                    .as_bytes()
                    .to_vec(),
            )
            .with_timeout(Duration::ZERO),
    );
    assert!(matches!(
        timed_out.connect().await,
        Err(ConnectionError::Timeout(_))
    ));

    server.shutdown().await;
}

#[tokio::test]
async fn response_timeout_and_size_limit_are_reported() {
    let server = start_tls(None).await;
    let mut timed_out =
        TlsConnection::new(config_for(&server).with_timeout(Duration::from_millis(100)));
    timed_out.connect().await.expect("connect");
    timed_out
        .send(b"<incomplete")
        .await
        .expect("send incomplete command");
    assert!(matches!(
        timed_out.read().await,
        Err(ConnectionError::Timeout(_))
    ));
    timed_out.disconnect().await.expect("disconnect");

    let mut size_limited = TlsConnection::new(config_for(&server).with_max_response_bytes(Some(8)));
    size_limited.connect().await.expect("connect");
    size_limited
        .send(b"<get_version/>")
        .await
        .expect("send get_version");
    assert!(matches!(
        size_limited.read().await,
        Err(ConnectionError::ReadFailed(_))
    ));
    size_limited.disconnect().await.expect("disconnect");

    server.shutdown().await;
}

#[tokio::test]
async fn malformed_tls_response_is_a_read_error() {
    let server = MockGmpServer::builder()
        .mode(ServerMode::Fixture)
        .version(GmpVersion::V22_5)
        .override_response("get_version", "<root><!x></root>")
        .tls("127.0.0.1:0")
        .build()
        .await
        .expect("TLS mock server");
    let mut connection =
        TlsConnection::new(config_for(&server).with_timeout(Duration::from_secs(1)));
    connection.connect().await.expect("connect");
    connection
        .send(b"<get_version/>")
        .await
        .expect("send get_version");
    assert!(matches!(
        connection.read().await,
        Err(ConnectionError::ReadFailed(_))
    ));
    connection.disconnect().await.expect("disconnect");
    server.shutdown().await;
}
