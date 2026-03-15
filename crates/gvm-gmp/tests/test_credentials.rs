#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::credentials::*;
use gvm_gmp::{CredentialFormat, CredentialType, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm};

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
