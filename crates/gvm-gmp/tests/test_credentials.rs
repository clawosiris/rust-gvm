// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::credentials::*;
use gvm_gmp::{
    CredentialFormat, CredentialStoreCredentialType, CredentialType, SnmpAuthAlgorithm,
    SnmpPrivacyAlgorithm,
};

#[test]
fn test_create_credential_basic() {
    assert_eq!(
        xml(create_credential("cred", Default::default())),
        "<create_credential><name>cred</name></create_credential>"
    );
}

#[test]
fn test_create_credential_with_all_optionals() {
    assert_eq!(
        xml(create_credential(
            "cred",
            CredentialOpts {
                comment: Some("c".into()),
                credential_type: Some(CredentialType::UsernamePassword),
                login: Some("u".into()),
                password: Some("p".into()),
                private_key: Some("k".into()),
                certificate: Some("cert".into()),
                auth_algorithm: Some(SnmpAuthAlgorithm::Sha1),
                privacy_algorithm: Some(SnmpPrivacyAlgorithm::Aes),
                format: Some(CredentialFormat::Pem),
            }
        )),
        "<create_credential><name>cred</name><comment>c</comment><type>up</type><login>u</login><password>p</password><private>k</private><certificate>cert</certificate><auth_algorithm>sha1</auth_algorithm><privacy_algorithm>aes</privacy_algorithm><format>pem</format></create_credential>"
    );
}

#[test]
fn test_create_credential_store_credential() {
    assert_eq!(
        xml(create_credential_store_credential(
            "stored",
            CredentialStoreCredentialType::UsernamePassword,
            "vault-1",
            "host-1",
            CredentialStoreCredentialOpts {
                comment: Some("from store".into()),
                credential_store_id: Some(id("cs1")),
            },
        )),
        "<create_credential><name>stored</name><type>cs_up</type><comment>from store</comment><credential_store_id>cs1</credential_store_id><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>"
    );
}

#[test]
fn test_create_credential_store_credential_types() {
    for (credential_type, wire_type) in [
        (CredentialStoreCredentialType::ClientCertificate, "cs_cc"),
        (CredentialStoreCredentialType::Snmp, "cs_snmp"),
        (CredentialStoreCredentialType::UsernamePassword, "cs_up"),
        (CredentialStoreCredentialType::UsernameSshKey, "cs_usk"),
        (CredentialStoreCredentialType::SmimeCertificate, "cs_smime"),
        (CredentialStoreCredentialType::PgpEncryptionKey, "cs_pgp"),
        (CredentialStoreCredentialType::PasswordOnly, "cs_pw"),
    ] {
        let rendered = xml(create_credential_store_credential(
            "stored",
            credential_type,
            "vault-1",
            "host-1",
            Default::default(),
        ));
        assert!(rendered.contains(&format!("<type>{wire_type}</type>")));
        assert!(rendered.contains("<vault_id>vault-1</vault_id>"));
        assert!(rendered.contains("<host_identifier>host-1</host_identifier>"));
    }
}

#[test]
fn test_credential_get_modify_delete() {
    assert_eq!(
        xml(clone_credential(&id("c1"))),
        "<create_credential><copy>c1</copy></create_credential>"
    );
    assert_eq!(
        xml(get_credential(&id("c1"))),
        "<get_credentials credential_id=\"c1\" details=\"1\"/>"
    );
    assert_eq!(
        xml(delete_credential(&id("c1"), true)),
        "<delete_credential credential_id=\"c1\" ultimate=\"1\"/>"
    );
}
