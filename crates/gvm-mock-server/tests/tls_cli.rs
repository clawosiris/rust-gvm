// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Standalone TLS and mutual-TLS CLI tests.

#![cfg(all(feature = "tls", unix))]
#![allow(clippy::unwrap_used, missing_docs)]

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::pkcs8::EncodePublicKey;
use tempfile::TempDir;
use x509_cert::builder::profile::cabf::Root;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::pem::LineEnding;
use x509_cert::der::EncodePem;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::SubjectPublicKeyInfo;

const BINARY: &str = env!("CARGO_BIN_EXE_gvm-mock-server");

fn client_ca_pem() -> String {
    let key = SigningKey::generate();
    let subject = Name::from_str("CN=rust-gvm test CA,O=rust-gvm,C=US").expect("CA subject");
    let profile = Root::new(false, subject).expect("CA profile");
    let public_key_der = key
        .verifying_key()
        .to_public_key_der()
        .expect("CA public key DER");
    let public_key =
        SubjectPublicKeyInfo::try_from(public_key_der.as_bytes()).expect("CA subject public key");
    let validity =
        Validity::from_now(Duration::from_secs(365 * 24 * 60 * 60)).expect("certificate validity");
    CertificateBuilder::new(profile, SerialNumber::from(1u32), validity, public_key)
        .expect("CA certificate builder")
        .build::<_, DerSignature>(&key)
        .expect("CA certificate")
        .to_pem(LineEnding::LF)
        .expect("CA certificate PEM")
}

#[test]
fn cli_rejects_multiple_transports() {
    let output = Command::new(BINARY)
        .args(["--tcp", "127.0.0.1:0", "--tls", "127.0.0.1:0"])
        .output()
        .expect("run mock server CLI");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("Specify exactly one of --socket, --tcp, or --tls"));
}

#[test]
fn cli_starts_mtls_listener_and_exports_server_certificate() {
    let directory = TempDir::new().expect("temporary directory");
    let client_ca_path = directory.path().join("client-ca.pem");
    let server_certificate_path = directory.path().join("server.pem");
    std::fs::write(&client_ca_path, client_ca_pem()).expect("write client CA");

    let mut child = Command::new(BINARY)
        .args([
            "--mode",
            "stateful",
            "--version",
            "22.5",
            "--tls",
            "127.0.0.1:0",
            "--tls-client-ca",
        ])
        .arg(&client_ca_path)
        .arg("--tls-cert-out")
        .arg(&server_certificate_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start mock server CLI");

    let stdout = child.stdout.take().expect("child stdout");
    let mut stdout = BufReader::new(stdout);
    let mut readiness = String::new();
    stdout
        .read_line(&mut readiness)
        .expect("read readiness line");
    assert!(readiness.starts_with("Listening on TLS: 127.0.0.1:"));
    assert!(std::fs::read_to_string(&server_certificate_path)
        .expect("read exported server certificate")
        .contains("BEGIN CERTIFICATE"));

    let signal_status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(signal_status.success());
    let mut remaining_stdout = String::new();
    stdout
        .read_to_string(&mut remaining_stdout)
        .expect("read remaining output");
    assert!(child.wait().expect("wait for mock server").success());
}
