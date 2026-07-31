// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::scanners::*;
use gvm_gmp::ScannerType;

#[test]
fn test_create_scanner_basic() {
    assert_eq!(
        xml(create_scanner("scanner", Default::default())),
        "<create_scanner><name>scanner</name></create_scanner>"
    );
}

#[test]
fn test_create_scanner_with_optionals() {
    assert_eq!(
        xml(create_scanner(
            "scanner",
            ScannerOpts {
                comment: Some("c".into()),
                host: Some("127.0.0.1".into()),
                port: Some(9390),
                scanner_type: Some(ScannerType::OpenVasScanner),
                ca_pub: Some("CA certificate".into()),
                credential_id: Some(id("cred1")),
                ..Default::default()
            }
        )),
        "<create_scanner><name>scanner</name><comment>c</comment><host>127.0.0.1</host><port>9390</port><type>2</type><ca_pub>CA certificate</ca_pub><credential id=\"cred1\"/></create_scanner>"
    );
}

#[test]
fn test_modify_scanner_with_optionals() {
    assert_eq!(
        xml(modify_scanner(
            &id("s1"),
            ScannerOpts {
                name: Some("renamed".into()),
                comment: Some("updated".into()),
                host: Some("scanner.example".into()),
                port: Some(9390),
                scanner_type: Some(ScannerType::OpenVasScanner),
                ca_pub: Some("Replacement CA".into()),
                credential_id: Some(id("cred2")),
            }
        )),
        "<modify_scanner scanner_id=\"s1\"><name>renamed</name><comment>updated</comment><host>scanner.example</host><port>9390</port><type>2</type><ca_pub>Replacement CA</ca_pub><credential id=\"cred2\"/></modify_scanner>"
    );
}

#[test]
fn test_scanner_get_delete_verify() {
    assert_eq!(
        xml(clone_scanner(&id("s1"))),
        "<create_scanner><copy>s1</copy></create_scanner>"
    );
    assert_eq!(
        xml(get_scanner(&id("s1"))),
        "<get_scanners details=\"1\" scanner_id=\"s1\"/>"
    );
    assert_eq!(
        xml(verify_scanner(&id("s1"))),
        "<verify_scanner scanner_id=\"s1\"/>"
    );
}
