// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "ssh")]

use std::path::PathBuf;
use std::time::Duration;

use gvm_connection::{GvmConnection, SshAuth, SshConfig, SshConnection, SshHostKeyPolicy};

#[test]
fn test_default_config() {
    let config = SshConfig::default();
    assert_eq!(config.port, 22);
    assert_eq!(config.remote_socket, "/run/gvmd/gvmd.sock");
    assert_eq!(config.timeout, Duration::from_secs(60));
    assert_eq!(config.host_key_policy, SshHostKeyPolicy::KnownHosts);
}

#[test]
fn test_custom_config() {
    let config = SshConfig::new("gvmd.example", "scanner", SshAuth::Agent)
        .with_port(2200)
        .with_remote_socket("/srv/gvmd.sock")
        .with_timeout(Duration::from_secs(5));

    assert_eq!(config.hostname, "gvmd.example");
    assert_eq!(config.username, "scanner");
    assert_eq!(config.port, 2200);
    assert_eq!(config.remote_socket, "/srv/gvmd.sock");
    assert_eq!(config.timeout, Duration::from_secs(5));
    assert_eq!(config.host_key_policy, SshHostKeyPolicy::KnownHosts);
}

#[test]
fn test_custom_host_key_policies() {
    let known_hosts = SshConfig::default().with_host_key_policy(SshHostKeyPolicy::KnownHostsFile(
        PathBuf::from("/etc/gvm/known_hosts"),
    ));
    assert_eq!(
        known_hosts.host_key_policy,
        SshHostKeyPolicy::KnownHostsFile(PathBuf::from("/etc/gvm/known_hosts"))
    );

    let fingerprint = SshConfig::default()
        .with_host_key_policy(SshHostKeyPolicy::Fingerprint("sha256".to_string()));
    assert_eq!(
        fingerprint.host_key_policy,
        SshHostKeyPolicy::Fingerprint("sha256".to_string())
    );

    let insecure = SshConfig::default().with_host_key_policy(SshHostKeyPolicy::AcceptAll);
    assert_eq!(insecure.host_key_policy, SshHostKeyPolicy::AcceptAll);
}

#[test]
fn test_not_connected_initially() {
    let conn = SshConnection::new(SshConfig::default());
    assert!(!conn.is_connected());
}

#[test]
fn test_password_auth_construction() {
    let auth = SshAuth::Password("secret".to_string());
    match auth {
        SshAuth::Password(password) => assert_eq!(password, "secret"),
        _ => panic!("expected password auth"),
    }
}

#[test]
fn test_key_auth_construction() {
    let auth = SshAuth::PrivateKey {
        key_path: PathBuf::from("/tmp/id_ed25519"),
        passphrase: Some("hunter2".to_string()),
    };

    match auth {
        SshAuth::PrivateKey {
            key_path,
            passphrase,
        } => {
            assert_eq!(key_path, PathBuf::from("/tmp/id_ed25519"));
            assert_eq!(passphrase.as_deref(), Some("hunter2"));
        }
        _ => panic!("expected private key auth"),
    }
}
