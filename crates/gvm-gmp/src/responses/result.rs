// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Result response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, parse_entity_meta, status_from_response, CountInfo,
    EntityMeta, ParseError,
};

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScanResult {
    pub meta: EntityMeta,
    pub host: Option<String>,
    pub port: Option<String>,
    pub nvt: Option<NvtRef>,
    pub threat: Option<String>,
    pub severity: Option<String>,
    pub qod: Option<QodInfo>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NvtRef {
    pub oid: String,
    pub name: Option<String>,
    pub family: Option<String>,
    pub cvss_base: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QodInfo {
    pub value: Option<u32>,
    pub type_: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetResultsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<ScanResult>,
    pub counts: CountInfo,
}

impl ScanResult {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            host: node.optional_child_text("host"),
            port: node.optional_child_text("port"),
            nvt: node
                .child("nvt")
                .map(|nvt| -> Result<NvtRef, ParseError> {
                    Ok(NvtRef {
                        oid: nvt
                            .attr("oid")
                            .ok_or_else(|| ParseError::MissingElement("nvt.oid".to_string()))?
                            .to_string(),
                        name: nvt.optional_child_text("name"),
                        family: nvt.optional_child_text("family"),
                        cvss_base: nvt.optional_child_text("cvss_base"),
                    })
                })
                .transpose()?,
            threat: node.optional_child_text("threat"),
            severity: node.optional_child_text("severity"),
            qod: node
                .child("qod")
                .map(|qod| -> Result<QodInfo, ParseError> {
                    Ok(QodInfo {
                        value: optional_u32(qod, "value", "qod.value")?,
                        type_: qod.optional_child_text("type"),
                    })
                })
                .transpose()?,
            description: node.optional_child_text("description"),
        })
    }
}

impl GetResultsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("result")
            .map(ScanResult::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "result_count")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_results() {
        let response = Response::from(
            r#"<get_results_response status="200" status_text="OK">
                <result id="res-1">
                    <name>HTTP Server Detection</name>
                    <owner><name>admin</name></owner>
                    <creation_time>2026-01-15T10:35:00Z</creation_time>
                    <modification_time>2026-01-15T10:35:00Z</modification_time>
                    <writable>0</writable>
                    <in_use>0</in_use>
                    <host>192.168.1.1</host>
                    <port>80/tcp</port>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.100315">
                        <name>HTTP Server Detection</name>
                        <family>Service detection</family>
                        <cvss_base>0.0</cvss_base>
                    </nvt>
                    <threat>Log</threat>
                    <severity>0.0</severity>
                    <qod><value>80</value><type>remote_banner</type></qod>
                    <description>An HTTP server was detected on the target.</description>
                </result>
                <result id="res-2">
                    <name>SSH Detection</name>
                    <host>192.168.1.2</host>
                </result>
                <result_count>2<filtered>2</filtered><page>1</page></result_count>
            </get_results_response>"#,
        );

        let parsed = GetResultsResponse::from_response(&response).expect("results parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].host.as_deref(), Some("192.168.1.1"));
        assert_eq!(
            parsed.items[0].nvt.as_ref().map(|nvt| nvt.oid.as_str()),
            Some("1.3.6.1.4.1.25623.1.0.100315")
        );
        assert_eq!(
            parsed.items[0].qod.as_ref().and_then(|qod| qod.value),
            Some(80)
        );
        assert_eq!(parsed.items[1].port, None);
    }

    #[test]
    fn parses_empty_results() {
        let response = Response::from(
            r#"<get_results_response status="200" status_text="OK"><result_count>0<filtered>0</filtered></result_count></get_results_response>"#,
        );

        let parsed = GetResultsResponse::from_response(&response).expect("results parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.filtered, Some(0));
    }

    #[test]
    fn parses_nvt_with_oid_attribute() {
        let response = Response::from(
            r#"<get_results_response status="200" status_text="OK">
                <result id="res-1">
                    <name>HTTP Server Detection</name>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.100315">
                        <name>HTTP Server Detection</name>
                    </nvt>
                </result>
            </get_results_response>"#,
        );

        let parsed = GetResultsResponse::from_response(&response).expect("results parse");
        let result = &parsed.items[0];

        assert_eq!(
            result.nvt.as_ref().map(|nvt| nvt.oid.as_str()),
            Some("1.3.6.1.4.1.25623.1.0.100315")
        );
        assert_eq!(
            result.nvt.as_ref().and_then(|nvt| nvt.name.as_deref()),
            Some("HTTP Server Detection")
        );
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_results_response status="503" status_text="Unavailable"/>"#);

        let error = GetResultsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 503,
                message
            } if message == "Unavailable"
        ));
    }

    #[test]
    fn parses_missing_optional_result_fields() {
        let response = Response::from(
            r#"<get_results_response status="200" status_text="OK">
                <result id="res-1">
                    <name>Only Required</name>
                </result>
            </get_results_response>"#,
        );

        let parsed = GetResultsResponse::from_response(&response).expect("results parse");
        let result = &parsed.items[0];

        assert_eq!(result.meta.comment, None);
        assert_eq!(result.host, None);
        assert_eq!(result.nvt, None);
        assert_eq!(result.qod, None);
        assert_eq!(result.description, None);
    }
}
