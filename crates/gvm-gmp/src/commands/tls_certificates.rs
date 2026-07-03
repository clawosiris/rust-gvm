// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! TLS certificate command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

/// Optional fields for TLS-certificate create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct TlsCertificateOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional private key material.
    pub private_key: Option<String>,
}

/// Options for `get_tls_certificates` requests.
#[derive(Debug, Clone, Default)]
pub struct GetTlsCertificatesOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a `create_tls_certificate` request.
#[must_use]
pub fn create_tls_certificate(name: &str, opts: TlsCertificateOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_tls_certificate");
    cmd.add_element_with_text("name", name);
    add_tls_body(&mut cmd, &opts);
    cmd
}

/// Build a `clone_tls_certificate` request.
#[must_use]
pub fn clone_tls_certificate(tls_certificate_id: &EntityId) -> impl Request {
    let mut cmd = XmlCommand::new("create_tls_certificate");
    cmd.add_element_with_text("copy", tls_certificate_id.as_str());
    cmd
}

/// Build a `get_tls_certificates` request.
#[must_use]
pub fn get_tls_certificates(opts: GetTlsCertificatesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_tls_certificates");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_tls_certificate` request.
#[must_use]
pub fn get_tls_certificate(tls_certificate_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tls_certificates")
        .attribute("tls_certificate_id", tls_certificate_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_tls_certificate` request.
#[must_use]
pub fn modify_tls_certificate(
    tls_certificate_id: &EntityId,
    opts: TlsCertificateOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("modify_tls_certificate")
        .attribute("tls_certificate_id", tls_certificate_id.as_str());
    add_tls_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_tls_certificate` request.
#[must_use]
pub fn delete_tls_certificate(tls_certificate_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_tls_certificate")
        .attribute("tls_certificate_id", tls_certificate_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_tls_body(cmd: &mut XmlCommand, opts: &TlsCertificateOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "certificate", opts.certificate.as_deref());
    add_text_element(cmd, "private", opts.private_key.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn tls_commands_build_xml() {
        let rendered = xml(create_tls_certificate(
            "tls",
            TlsCertificateOpts {
                certificate: Some("cert".into()),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<certificate>cert</certificate>"));
        assert_eq!(
            xml(clone_tls_certificate(&id("tls1"))),
            "<create_tls_certificate><copy>tls1</copy></create_tls_certificate>"
        );
        assert_eq!(
            xml(get_tls_certificate(&id("tls1"))),
            "<get_tls_certificates details=\"1\" tls_certificate_id=\"tls1\"/>"
        );
    }

    #[test]
    fn tls_get_modify_delete_build_xml() {
        let rendered = xml(get_tls_certificates(GetTlsCertificatesOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_tls_certificate(
            &id("tls1"),
            TlsCertificateOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(rendered, "<modify_tls_certificate tls_certificate_id=\"tls1\"><comment>updated</comment></modify_tls_certificate>");
        assert_eq!(
            xml(delete_tls_certificate(&id("tls1"), true)),
            "<delete_tls_certificate tls_certificate_id=\"tls1\" ultimate=\"1\"/>"
        );
    }
}
