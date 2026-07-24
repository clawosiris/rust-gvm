// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! TLS listener support for the mock GMP server.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use x509_cert::builder::profile::cabf::tls::{CertificateType, Subscriber};
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::pem::LineEnding;
use x509_cert::der::{Encode, EncodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::SubjectPublicKeyInfo;

use crate::listener::{handle_stream, ListenerState};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn generate_tls_acceptor(
    client_ca_certificate: Option<&Path>,
) -> std::io::Result<(TlsAcceptor, String)> {
    let signing_key = SigningKey::generate();
    let public_key_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .map_err(invalid_input)?;
    let public_key =
        SubjectPublicKeyInfo::try_from(public_key_der.as_bytes()).map_err(invalid_input)?;
    let subject = Name::from_str("CN=localhost").map_err(invalid_input)?;
    let names = vec![
        GeneralName::DnsName(Ia5String::new(b"localhost").map_err(invalid_input)?),
        GeneralName::from(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        GeneralName::from(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];
    let profile = Subscriber {
        certificate_type: CertificateType::domain_validated(subject.clone(), names.clone())
            .map_err(invalid_input)?,
        issuer: subject,
        client_auth: false,
    };
    let validity =
        Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60)).map_err(invalid_input)?;
    let mut certificate_builder =
        CertificateBuilder::new(profile, SerialNumber::from(1u32), validity, public_key)
            .map_err(invalid_input)?;
    certificate_builder
        .add_extension(&SubjectAltName(names))
        .map_err(invalid_input)?;
    let certificate = certificate_builder
        .build::<_, DerSignature>(&signing_key)
        .map_err(invalid_input)?;

    let builder = ServerConfig::builder();
    let builder = match client_ca_certificate {
        Some(path) => {
            let certificates = parse_certificates(&std::fs::read(path)?)?;
            let mut roots = RootCertStore::empty();
            for certificate in certificates {
                roots.add(certificate).map_err(invalid_input)?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(invalid_input)?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let certificate_pem = certificate.to_pem(LineEnding::LF).map_err(invalid_input)?;
    let certificate_der = certificate.to_der().map_err(invalid_input)?;
    let private_key_der = signing_key.to_pkcs8_der().map_err(invalid_input)?;
    let private_key = PrivatePkcs8KeyDer::from(private_key_der.as_bytes().to_vec()).into();
    let config = builder
        .with_single_cert(vec![CertificateDer::from(certificate_der)], private_key)
        .map_err(invalid_input)?;

    Ok((TlsAcceptor::from(Arc::new(config)), certificate_pem))
}

/// Run a TLS listener with optional strict client-certificate authentication.
pub async fn run_tls_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<ListenerState>,
) {
    loop {
        tokio::select! {
            (stream, address) = accept_tls_socket(|| listener.accept()) => {
                let acceptor = acceptor.clone();
                let state = Arc::clone(&state);
                tokio::spawn(handle_tls_stream(
                    stream,
                    address,
                    acceptor,
                    state,
                    HANDSHAKE_TIMEOUT,
                ));
            }
            () = state.shutdown.notified() => {
                tracing::debug!("TLS listener shutting down");
                break;
            }
        }
    }
}

async fn accept_tls_socket<F, Fut>(mut accept: F) -> (TcpStream, std::net::SocketAddr)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::io::Result<(TcpStream, std::net::SocketAddr)>>,
{
    loop {
        let accepted = accept().await.inspect_err(log_accept_error);
        if let Ok(connection) = accepted {
            return connection;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn handle_tls_stream(
    stream: TcpStream,
    address: std::net::SocketAddr,
    acceptor: TlsAcceptor,
    state: Arc<ListenerState>,
    handshake_timeout: Duration,
) {
    match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
        Ok(Ok(stream)) => {
            tracing::debug!(%address, "TLS connection established");
            handle_stream(stream, &state).await;
        }
        Ok(Err(error)) => {
            tracing::debug!(%address, %error, "TLS handshake rejected");
        }
        Err(_) => {
            tracing::debug!(%address, "TLS handshake timed out");
        }
    }
}

fn parse_certificates(pem: &[u8]) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid_data(legacy_pem_error_message(error)))?;
    if certificates.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "client CA PEM contains no certificates",
        ));
    }
    Ok(certificates)
}

fn invalid_input(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
}

fn invalid_data(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

fn legacy_pem_error_message(error: PemError) -> String {
    match error {
        PemError::MissingSectionEnd { end_marker } => format!(
            "section end {:?} missing",
            String::from_utf8_lossy(&end_marker)
        ),
        PemError::IllegalSectionStart { line } => {
            format!(
                "illegal section start: {:?}",
                String::from_utf8_lossy(&line)
            )
        }
        PemError::Base64Decode(error) => error,
        error => format!("{error:?}"),
    }
}

fn log_accept_error(error: &std::io::Error) {
    tracing::warn!(%error, "TLS accept error");
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;
    use crate::fault::FaultEngine;
    use crate::history::CommandHistory;
    use crate::version::GmpVersion;
    use crate::ServerMode;
    use tokio::sync::Notify;

    fn listener_state() -> Arc<ListenerState> {
        Arc::new(ListenerState {
            mode: ServerMode::Echo,
            version: GmpVersion::V22_5,
            history: CommandHistory::new(),
            session_counter: AtomicU64::new(0),
            fixtures: None,
            store: None,
            scenario_config: None,
            large_report: None,
            max_request_bytes: Some(64 * 1024 * 1024),
            fault_engine: FaultEngine::none(),
            shutdown: Arc::new(Notify::new()),
        })
    }

    #[tokio::test]
    async fn stalled_handshake_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address)
            .await
            .expect("client connection");
        let (server_stream, peer_address) = listener.accept().await.expect("accepted connection");
        let (acceptor, _) = generate_tls_acceptor(None).expect("TLS acceptor");

        handle_tls_stream(
            server_stream,
            peer_address,
            acceptor,
            listener_state(),
            Duration::from_millis(1),
        )
        .await;

        drop(client);
    }

    #[test]
    fn client_ca_parser_preserves_empty_and_malformed_error_kinds() {
        let empty = parse_certificates(b"").expect_err("empty client CA");
        let malformed =
            parse_certificates(b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n")
                .expect_err("malformed client CA");

        assert_eq!(empty.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(malformed.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(malformed.to_string(), "InvalidCharacter(37)");
    }

    #[test]
    fn legacy_pem_error_mapping_covers_all_native_error_classes() {
        assert_eq!(
            legacy_pem_error_message(PemError::MissingSectionEnd {
                end_marker: b"CERTIFICATE".to_vec(),
            }),
            "section end \"CERTIFICATE\" missing"
        );
        assert_eq!(
            legacy_pem_error_message(PemError::IllegalSectionStart {
                line: b"-----BEGIN".to_vec(),
            }),
            "illegal section start: \"-----BEGIN\""
        );
        assert_eq!(
            legacy_pem_error_message(PemError::Base64Decode("bad data".to_owned())),
            "bad data"
        );
        assert_eq!(
            legacy_pem_error_message(PemError::SectionTooLarge),
            "SectionTooLarge"
        );
    }

    #[tokio::test]
    async fn accept_retries_after_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(address)
            .await
            .expect("client connection");
        let connection = listener.accept().await.expect("accepted connection");
        let mut outcomes = std::collections::VecDeque::from([
            Err(std::io::Error::other("temporary accept failure")),
            Ok(connection),
        ]);

        let (_, accepted_address) =
            accept_tls_socket(|| std::future::ready(outcomes.pop_front().expect("outcome"))).await;
        assert_eq!(
            accepted_address,
            client.local_addr().expect("client address")
        );
    }

    #[test]
    fn io_error_helpers_preserve_context() {
        let invalid = invalid_input("bad certificate");
        assert_eq!(invalid.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(invalid.to_string(), "bad certificate");

        log_accept_error(&std::io::Error::other("accept failed"));
    }
}
