// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Scanner response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u16, parse_document, parse_entity_id, parse_entity_meta,
    parse_named_entity, status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity,
    ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Scanner {
    pub meta: EntityMeta,
    pub scanner_type: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub credential: Option<NamedEntity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetScannersResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Scanner>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateScannerResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Scanner {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            scanner_type: node.optional_child_text("type"),
            host: node.optional_child_text("host"),
            port: optional_u16(node, "port", "port")?,
            credential: parse_named_entity(node, "credential")?,
        })
    }
}

impl GetScannersResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("scanner")
            .map(Scanner::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "scanner_count")?,
        })
    }
}

impl CreateScannerResponse {
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

pub type ModifyScannerResponse = ActionResponse;
pub type DeleteScannerResponse = ActionResponse;
pub type VerifyScannerResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_scanners() {
        let response = Response::from(
            r#"<get_scanners_response status="200" status_text="OK">
                <scanner id="scanner-1">
                    <owner><name>admin</name></owner>
                    <name>Default Scanner</name>
                    <comment>primary</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <type>OpenVAS</type>
                    <host>127.0.0.1</host>
                    <port>9390</port>
                    <credential id="cred-1"><name>OSP Credential</name></credential>
                </scanner>
                <scanner id="scanner-2">
                    <name>Secondary Scanner</name>
                </scanner>
                <scanner_count>2<filtered>2</filtered></scanner_count>
            </get_scanners_response>"#,
        );

        let parsed = GetScannersResponse::from_response(&response).expect("scanners parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].scanner_type.as_deref(), Some("OpenVAS"));
        assert_eq!(parsed.items[0].port, Some(9390));
        assert_eq!(
            parsed.items[0]
                .credential
                .as_ref()
                .map(|credential| credential.name.as_str()),
            Some("OSP Credential")
        );
    }

    #[test]
    fn parses_empty_scanners() {
        let response = Response::from(
            r#"<get_scanners_response status="200" status_text="OK"><scanner_count>0<filtered>0</filtered></scanner_count></get_scanners_response>"#,
        );

        let parsed = GetScannersResponse::from_response(&response).expect("scanners parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_scanner_response() {
        let response = Response::from(
            r#"<create_scanner_response status="201" status_text="OK, resource created" id="scanner-1"/>"#,
        );

        let parsed = CreateScannerResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "scanner-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_scanners_response status="503" status_text="Unavailable"/>"#);

        let error = GetScannersResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 503,
                message
            } if message == "Unavailable"
        ));
    }

    #[test]
    fn parses_missing_optional_scanner_fields() {
        let response = Response::from(
            r#"<get_scanners_response status="200" status_text="OK">
                <scanner id="scanner-1">
                    <name>Only Required</name>
                </scanner>
            </get_scanners_response>"#,
        );

        let parsed = GetScannersResponse::from_response(&response).expect("scanners parse");
        let scanner = &parsed.items[0];

        assert_eq!(scanner.host, None);
        assert_eq!(scanner.port, None);
        assert_eq!(scanner.credential, None);
    }
}
