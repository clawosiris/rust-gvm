// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::credentials::*;
use gvm_gmp::{
    CredentialStoreCredentialType, CredentialType, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm,
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
                key_phrase: Some("phrase".into()),
                public_key: None,
                certificate: Some("cert".into()),
                community: Some("community".into()),
                auth_algorithm: Some(SnmpAuthAlgorithm::Sha1),
                privacy_password: Some("privacy".into()),
                privacy_algorithm: Some(SnmpPrivacyAlgorithm::Aes),
                allow_insecure: Some(true),
                kdc: Some("legacy-kdc".into()),
                kdcs: vec!["kdc-1".into(), "kdc-2".into()],
                realm: Some("EXAMPLE.COM".into()),
                ..Default::default()
            }
        )),
        "<create_credential><name>cred</name><comment>c</comment><type>up</type><allow_insecure>1</allow_insecure><certificate>cert</certificate><kdc>legacy-kdc</kdc><kdcs><kdc>kdc-1</kdc><kdc>kdc-2</kdc></kdcs><key><phrase>phrase</phrase><private>k</private></key><login>u</login><password>p</password><auth_algorithm>sha1</auth_algorithm><community>community</community><privacy><algorithm>aes</algorithm><password>privacy</password></privacy><realm>EXAMPLE.COM</realm></create_credential>"
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

#[test]
fn test_modify_credential_store_credential() {
    assert_eq!(
        xml(modify_credential_store_credential(
            &id("c1"),
            ModifyCredentialStoreCredentialOpts::default(),
        )),
        "<modify_credential credential_id=\"c1\"/>"
    );
    assert_eq!(
        xml(modify_credential_store_credential(
            &id("c1"),
            ModifyCredentialStoreCredentialOpts {
                name: Some("foo_name".into()),
                comment: Some("foo_comment".into()),
                credential_store_id: Some(id("foo_csid")),
                vault_id: Some("foo_vid".into()),
                host_identifier: Some("foo_hid".into()),
            },
        )),
        "<modify_credential credential_id=\"c1\"><name>foo_name</name><comment>foo_comment</comment><credential_store_id>foo_csid</credential_store_id><vault_id>foo_vid</vault_id><host_identifier>foo_hid</host_identifier></modify_credential>"
    );
}
