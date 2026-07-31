// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Scanner command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::ScannerType;
use crate::types::EntityId;

/// Optional fields shared by scanner create and modify requests.
///
/// [`create_scanner`] takes its name as a separate required argument and does
/// not read [`Self::name`]. All other fields apply to both request types.
#[derive(Debug, Clone, Default)]
pub struct ScannerOpts {
    /// Optional replacement name emitted only by [`modify_scanner`].
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional host name or address.
    pub host: Option<String>,
    /// Optional port selector.
    pub port: Option<u16>,
    /// Optional scanner type.
    pub scanner_type: Option<ScannerType>,
    /// Optional CA certificate in PEM format.
    pub ca_pub: Option<String>,
    /// Optional credential identifier.
    pub credential_id: Option<EntityId>,
}

/// Options for `get_scanners` requests.
#[derive(Debug, Clone, Default)]
pub struct GetScannersOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a clone request for an existing scanner.
#[must_use]
pub fn clone_scanner(scanner_id: &EntityId) -> impl Request {
    XmlCommand::new("create_scanner").child_with_text("copy", scanner_id.as_str())
}

/// Build a `create_scanner` request.
#[must_use]
pub fn create_scanner(name: &str, opts: ScannerOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_scanner");
    cmd.add_element_with_text("name", name);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "host", opts.host.as_deref());
    if let Some(port) = opts.port {
        cmd.add_element_with_text("port", &port.to_string());
    }
    if let Some(scanner_type) = opts.scanner_type {
        cmd.add_element_with_text("type", scanner_type.as_scanner_type());
    }
    add_text_element(&mut cmd, "ca_pub", opts.ca_pub.as_deref());
    if let Some(credential_id) = opts.credential_id.as_ref() {
        cmd.add_element("credential")
            .set_attribute("id", credential_id.as_str());
    }
    cmd
}

/// Build a `get_scanners` request.
#[must_use]
pub fn get_scanners(opts: GetScannersOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_scanners");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_scanner` request.
#[must_use]
pub fn get_scanner(scanner_id: &EntityId) -> impl Request {
    XmlCommand::new("get_scanners")
        .attribute("scanner_id", scanner_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_scanner` request.
#[must_use]
pub fn modify_scanner(scanner_id: &EntityId, opts: ScannerOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_scanner").attribute("scanner_id", scanner_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "host", opts.host.as_deref());
    if let Some(port) = opts.port {
        cmd.add_element_with_text("port", &port.to_string());
    }
    if let Some(scanner_type) = opts.scanner_type {
        cmd.add_element_with_text("type", scanner_type.as_scanner_type());
    }
    add_text_element(&mut cmd, "ca_pub", opts.ca_pub.as_deref());
    if let Some(credential_id) = opts.credential_id.as_ref() {
        cmd.add_element("credential")
            .set_attribute("id", credential_id.as_str());
    }
    cmd
}

/// Build a `delete_scanner` request.
#[must_use]
pub fn delete_scanner(scanner_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_scanner")
        .attribute("scanner_id", scanner_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `verify_scanner` request.
#[must_use]
pub fn verify_scanner(scanner_id: &EntityId) -> impl Request {
    XmlCommand::new("verify_scanner").attribute("scanner_id", scanner_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn scanner_commands_build_xml() {
        let rendered = xml(create_scanner(
            "scanner",
            ScannerOpts {
                host: Some("127.0.0.1".into()),
                port: Some(9390),
                scanner_type: Some(ScannerType::OpenVasScanner),
                ca_pub: Some("CA certificate".into()),
                credential_id: Some(id("cred1")),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<create_scanner><name>scanner</name><host>127.0.0.1</host><port>9390</port><type>2</type><ca_pub>CA certificate</ca_pub><credential id=\"cred1\"/></create_scanner>"
        );
        assert_eq!(
            xml(clone_scanner(&id("s1"))),
            "<create_scanner><copy>s1</copy></create_scanner>"
        );
        assert_eq!(
            xml(get_scanner(&id("s1"))),
            "<get_scanners details=\"1\" scanner_id=\"s1\"/>"
        );
    }

    #[test]
    fn scanner_get_modify_delete_verify_build_xml() {
        let rendered = xml(get_scanners(GetScannersOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_scanner(
            &id("s1"),
            ScannerOpts {
                name: Some("Renamed scanner".into()),
                comment: Some("updated".into()),
                host: Some("localhost".into()),
                port: Some(9390),
                scanner_type: Some(ScannerType::OpenVasScanner),
                ca_pub: Some("Replacement CA".into()),
                credential_id: Some(id("cred2")),
            },
        ));
        assert_eq!(
            rendered,
            "<modify_scanner scanner_id=\"s1\"><name>Renamed scanner</name><comment>updated</comment><host>localhost</host><port>9390</port><type>2</type><ca_pub>Replacement CA</ca_pub><credential id=\"cred2\"/></modify_scanner>"
        );
        assert_eq!(
            xml(modify_scanner(&id("s1"), ScannerOpts::default())),
            "<modify_scanner scanner_id=\"s1\"/>"
        );
        assert_eq!(
            xml(delete_scanner(&id("s1"), true)),
            "<delete_scanner scanner_id=\"s1\" ultimate=\"1\"/>"
        );
        assert_eq!(
            xml(verify_scanner(&id("s1"))),
            "<verify_scanner scanner_id=\"s1\"/>"
        );
    }
}
