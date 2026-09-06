// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! TLS certificate response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta,
    status_from_response, ActionResponse, CountInfo, EntityMeta, ParseError,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsCertificate {
    pub meta: EntityMeta,
    pub certificate: Option<String>,
    pub issuer_dn: Option<String>,
    pub activation_time: Option<String>,
    pub expiration_time: Option<String>,
    pub md5_fingerprint: Option<String>,
    pub sha256_fingerprint: Option<String>,
    pub subject_dn: Option<String>,
    pub valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTlsCertificatesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<TlsCertificate>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateTlsCertificateResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl TlsCertificate {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            certificate: node.optional_child_text("certificate"),
            issuer_dn: node.optional_child_text("issuer_dn"),
            activation_time: node.optional_child_text("activation_time"),
            expiration_time: node.optional_child_text("expiration_time"),
            md5_fingerprint: node.optional_child_text("md5_fingerprint"),
            sha256_fingerprint: node.optional_child_text("sha256_fingerprint"),
            subject_dn: node.optional_child_text("subject_dn"),
            valid: node
                .optional_child_text("valid")
                .map(|value| parse_bool(&value, "valid"))
                .transpose()?
                .unwrap_or(false),
        })
    }
}

impl GetTlsCertificatesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("tls_certificate")
            .map(TlsCertificate::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "tls_certificate_count")?,
        })
    }
}

impl CreateTlsCertificateResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let id = parse_entity_id(
            root.attr("id")
                .ok_or_else(|| ParseError::MissingElement("id".to_string()))?,
            "id",
        )?;
        Ok(Self {
            status,
            status_text,
            id,
        })
    }
}

impl GmpResponse for GetTlsCertificatesResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl GmpResponse for CreateTlsCertificateResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

pub type ModifyTlsCertificateResponse = ActionResponse;
pub type DeleteTlsCertificateResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_tls_certificates() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK">
                <tls_certificate id="tc-1">
                    <owner><name>admin</name></owner>
                    <name>Cert One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <certificate>MIIB...</certificate>
                    <issuer_dn>CN=Example CA</issuer_dn>
                    <activation_time>2026-01-01T00:00:00Z</activation_time>
                    <expiration_time>2027-01-01T00:00:00Z</expiration_time>
                    <md5_fingerprint>aa:bb:cc:dd</md5_fingerprint>
                    <sha256_fingerprint>ee:ff:00:11</sha256_fingerprint>
                    <subject_dn>CN=example.com</subject_dn>
                    <valid>1</valid>
                </tls_certificate>
                <tls_certificate id="tc-2">
                    <name>Cert Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <valid>0</valid>
                </tls_certificate>
                <tls_certificate_count>2<filtered>2</filtered><page>1</page></tls_certificate_count>
            </get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("tls_certs parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].issuer_dn.as_deref(), Some("CN=Example CA"));
        assert_eq!(
            parsed.items[0].subject_dn.as_deref(),
            Some("CN=example.com")
        );
        assert_eq!(
            parsed.items[0].md5_fingerprint.as_deref(),
            Some("aa:bb:cc:dd")
        );
        assert!(parsed.items[0].valid);
        assert!(!parsed.items[1].valid);
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_tls_certificates() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK"><tls_certificate_count>0<filtered>0</filtered></tls_certificate_count></get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("tls_certs parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_tls_certificate_response() {
        let response = Response::from(
            r#"<create_tls_certificate_response status="201" status_text="OK, resource created" id="tc-1"/>"#,
        );

        let parsed = CreateTlsCertificateResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "tc-1");
    }

    #[test]
    fn rejects_server_error() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="400" status_text="Bad request"/>"#,
        );

        let error =
            GetTlsCertificatesResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_tls_certificate_fields() {
        let response = Response::from(
            r#"<get_tls_certificates_response status="200" status_text="OK">
                <tls_certificate id="tc-1">
                    <name>Only Required</name>
                </tls_certificate>
            </get_tls_certificates_response>"#,
        );

        let parsed = GetTlsCertificatesResponse::from_response(&response).expect("tls_certs parse");
        let cert = &parsed.items[0];

        assert_eq!(cert.meta.comment, None);
        assert_eq!(cert.certificate, None);
        assert_eq!(cert.issuer_dn, None);
        assert_eq!(cert.subject_dn, None);
        assert!(!cert.valid);
    }
}
