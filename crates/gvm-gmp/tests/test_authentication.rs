// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::xml;
use gvm_gmp::commands::authentication::authenticate;

#[test]
fn test_authenticate_basic() {
    assert_eq!(
        xml(authenticate("foo", "bar")),
        "<authenticate><credentials><username>foo</username><password>bar</password></credentials></authenticate>"
    );
}

#[test]
fn test_authenticate_preserves_empty_values() {
    assert_eq!(
        xml(authenticate("", "")),
        "<authenticate><credentials><username></username><password></password></credentials></authenticate>"
    );
}

#[test]
fn test_authenticate_escapes_xml_special_chars() {
    assert_eq!(
        xml(authenticate(r#"<>&"'"#, r#""'&<>"#)),
        "<authenticate><credentials><username>&lt;&gt;&amp;&quot;&apos;</username><password>&quot;&apos;&amp;&lt;&gt;</password></credentials></authenticate>"
    );
}
