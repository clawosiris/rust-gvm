// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! TLS certificate command builders.

use std::fmt;

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateTlsCertificateResponse, DeleteTlsCertificateResponse, GetTlsCertificatesResponse,
    ModifyTlsCertificateResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for TLS-certificate create and modify requests.
#[derive(Clone, Default)]
pub struct TlsCertificateOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional private key material.
    pub private_key: Option<String>,
}

impl fmt::Debug for TlsCertificateOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsCertificateOpts")
            .field("comment", &self.comment)
            .field(
                "certificate",
                &self.certificate.as_ref().map(|_| "<present>"),
            )
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
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

/// Semantic request for creating a TLS certificate.
#[derive(Debug, Clone)]
pub struct CreateTlsCertificateRequest {
    name: String,
    opts: TlsCertificateOpts,
}

impl CreateTlsCertificateRequest {
    /// Create a TLS-certificate creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: TlsCertificateOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreateTlsCertificateRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_tls_certificate(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateTlsCertificateRequest {
    type Response = CreateTlsCertificateResponse;
}

macro_rules! tls_certificate_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(tls_certificate_id: EntityId) -> Self {
                Self(tls_certificate_id)
            }
        }

        impl Request for $name {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.0).to_bytes()
            }
        }

        impl GmpRequest for $name {
            type Response = $response;
        }
    };
}

tls_certificate_id_request!(
    CloneTlsCertificateRequest,
    CreateTlsCertificateResponse,
    clone_tls_certificate
);
tls_certificate_id_request!(
    GetTlsCertificateRequest,
    GetTlsCertificatesResponse,
    get_tls_certificate
);

/// Semantic request for listing TLS certificates.
#[derive(Debug, Clone, Default)]
pub struct GetTlsCertificatesRequest(GetTlsCertificatesOpts);

impl GetTlsCertificatesRequest {
    /// Create a TLS-certificate list request.
    #[must_use]
    pub fn new(opts: GetTlsCertificatesOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetTlsCertificatesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_tls_certificates(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetTlsCertificatesRequest {
    type Response = GetTlsCertificatesResponse;
}

/// Semantic request for modifying a TLS certificate.
#[derive(Debug, Clone)]
pub struct ModifyTlsCertificateRequest {
    tls_certificate_id: EntityId,
    opts: TlsCertificateOpts,
}

impl ModifyTlsCertificateRequest {
    /// Create a TLS-certificate modification request.
    #[must_use]
    pub fn new(tls_certificate_id: EntityId, opts: TlsCertificateOpts) -> Self {
        Self {
            tls_certificate_id,
            opts,
        }
    }
}

impl Request for ModifyTlsCertificateRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_tls_certificate(&self.tls_certificate_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyTlsCertificateRequest {
    type Response = ModifyTlsCertificateResponse;
}

/// Semantic request for deleting a TLS certificate.
#[derive(Debug, Clone)]
pub struct DeleteTlsCertificateRequest {
    tls_certificate_id: EntityId,
    ultimate: bool,
}

impl DeleteTlsCertificateRequest {
    /// Create a TLS-certificate deletion request.
    #[must_use]
    pub fn new(tls_certificate_id: EntityId, ultimate: bool) -> Self {
        Self {
            tls_certificate_id,
            ultimate,
        }
    }
}

impl Request for DeleteTlsCertificateRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_tls_certificate(&self.tls_certificate_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteTlsCertificateRequest {
    type Response = DeleteTlsCertificateResponse;
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

    #[test]
    fn semantic_requests_match_all_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let tls_certificate_id = id("tls-1");
        let opts = TlsCertificateOpts {
            comment: Some("comment".into()),
            certificate: Some("certificate".into()),
            private_key: Some("private".into()),
        };
        let get_opts = GetTlsCertificatesOpts {
            details: Some(true),
            ..Default::default()
        };

        let create = CreateTlsCertificateRequest::new("certificate", opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_tls_certificate("certificate", opts.clone()).to_bytes()
        );
        associated::<_, CreateTlsCertificateResponse>(&create);

        let clone = CloneTlsCertificateRequest::new(tls_certificate_id.clone());
        assert_eq!(
            clone.to_bytes(),
            clone_tls_certificate(&tls_certificate_id).to_bytes()
        );
        associated::<_, CreateTlsCertificateResponse>(&clone);

        let list = GetTlsCertificatesRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_tls_certificates(get_opts).to_bytes());
        associated::<_, GetTlsCertificatesResponse>(&list);

        let get = GetTlsCertificateRequest::new(tls_certificate_id.clone());
        assert_eq!(
            get.to_bytes(),
            get_tls_certificate(&tls_certificate_id).to_bytes()
        );
        associated::<_, GetTlsCertificatesResponse>(&get);

        let modify = ModifyTlsCertificateRequest::new(tls_certificate_id.clone(), opts.clone());
        assert_eq!(
            modify.to_bytes(),
            modify_tls_certificate(&tls_certificate_id, opts).to_bytes()
        );
        associated::<_, ModifyTlsCertificateResponse>(&modify);

        let delete = DeleteTlsCertificateRequest::new(tls_certificate_id.clone(), true);
        assert_eq!(
            delete.to_bytes(),
            delete_tls_certificate(&tls_certificate_id, true).to_bytes()
        );
        associated::<_, DeleteTlsCertificateResponse>(&delete);
    }

    #[test]
    fn tls_certificate_option_debug_output_redacts_key_material() {
        let opts = TlsCertificateOpts {
            comment: Some("comment".into()),
            certificate: Some("certificate-material".into()),
            private_key: Some("private-key-material".into()),
        };

        let rendered = format!("{opts:?}");
        assert!(rendered.contains("comment"));
        assert!(rendered.contains("<present>"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("certificate-material"));
        assert!(!rendered.contains("private-key-material"));
    }
}
