mod common;

use common::{id, xml};
use gvm_gmp::commands::tls_certificates::*;

#[test]
fn test_create_tls_certificate_basic() {
    assert_eq!(xml(create_tls_certificate("tls", Default::default())), "<create_tls_certificate><name>tls</name></create_tls_certificate>");
}

#[test]
fn test_create_tls_certificate_with_optionals() {
    assert_eq!(
        xml(create_tls_certificate(
            "tls",
            TlsCertificateOpts {
                comment: Some("c".into()),
                certificate: Some("cert".into()),
                private_key: Some("key".into()),
            }
        )),
        "<create_tls_certificate><name>tls</name><comment>c</comment><certificate>cert</certificate><private>key</private></create_tls_certificate>"
    );
}

#[test]
fn test_tls_certificate_get_modify_delete() {
    assert_eq!(xml(get_tls_certificate(&id("tls1"))), "<get_tls_certificates details=\"1\" tls_certificate_id=\"tls1\"/>");
    assert_eq!(xml(delete_tls_certificate(&id("tls1"), true)), "<delete_tls_certificate tls_certificate_id=\"tls1\" ultimate=\"1\"/>");
}

