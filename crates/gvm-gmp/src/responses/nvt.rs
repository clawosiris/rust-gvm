// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! NVT response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_document, status_from_response, CountInfo, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Nvt {
    pub oid: String,
    pub name: String,
    pub family: Option<String>,
    pub cvss_base: Option<String>,
    pub severity: Option<String>,
    pub tags: Option<String>,
    pub solution_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NvtFamily {
    pub name: String,
    pub max_nvt_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetNvtsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Nvt>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetNvtFamiliesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<NvtFamily>,
    pub counts: CountInfo,
}

impl Nvt {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            oid: node
                .attr("oid")
                .or_else(|| node.attr("id"))
                .ok_or_else(|| ParseError::MissingElement("nvt.oid".to_string()))?
                .to_string(),
            name: node.required_child_text("name")?,
            family: node.optional_child_text("family"),
            cvss_base: node.optional_child_text("cvss_base"),
            severity: node.optional_child_text("severity"),
            tags: node.optional_child_text("tags"),
            solution_type: node.optional_child_text("solution_type"),
        })
    }
}

impl NvtFamily {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            name: node.required_child_text("name")?,
            max_nvt_count: optional_u32(node, "count", "nvt_family.count")?,
        })
    }
}

impl GetNvtsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("nvt")
            .map(Nvt::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "nvt_count")?,
        })
    }
}

impl GetNvtFamiliesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("nvt_family")
            .map(NvtFamily::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        let counts = {
            let counts = count_info(&root, "nvt_family_count")?;
            if counts.total.is_none() && counts.filtered.is_none() && counts.page.is_none() {
                count_info(&root, "family_count")?
            } else {
                counts
            }
        };
        Ok(Self {
            status,
            status_text,
            items,
            counts,
        })
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_nvts() {
        let response = Response::from(
            r#"<get_nvts_response status="200" status_text="OK">
                <nvt oid="1.3.6.1.4.1.25623.1.0.100001">
                    <name>HTTP Detection</name>
                    <family>Service detection</family>
                    <cvss_base>0.0</cvss_base>
                    <severity>0.0</severity>
                    <tags>summary=Detects HTTP server</tags>
                    <solution_type>NoneAvailable</solution_type>
                </nvt>
                <nvt oid="1.3.6.1.4.1.25623.1.0.100002">
                    <name>SSH Detection</name>
                    <family>Service detection</family>
                    <cvss_base>0.0</cvss_base>
                    <severity>0.0</severity>
                    <tags>summary=Detects SSH server</tags>
                    <solution_type>Workaround</solution_type>
                </nvt>
                <nvt_count>2<filtered>2</filtered><page>1</page></nvt_count>
            </get_nvts_response>"#,
        );

        let parsed = GetNvtsResponse::from_response(&response).expect("nvts parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].oid, "1.3.6.1.4.1.25623.1.0.100001");
        assert_eq!(parsed.items[1].solution_type.as_deref(), Some("Workaround"));
    }

    #[test]
    fn parses_empty_nvts() {
        let response = Response::from(
            r#"<get_nvts_response status="200" status_text="OK"><nvt_count>0<filtered>0</filtered></nvt_count></get_nvts_response>"#,
        );

        let parsed = GetNvtsResponse::from_response(&response).expect("nvts parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_nvt_oid_from_id_fallback() {
        let response = Response::from(
            r#"<get_nvts_response status="200" status_text="OK">
                <nvt id="1.3.6.1.4.1.25623.1.0.100315">
                    <name>Fallback OID</name>
                </nvt>
            </get_nvts_response>"#,
        );

        let parsed = GetNvtsResponse::from_response(&response).expect("nvts parse");

        assert_eq!(parsed.items[0].oid, "1.3.6.1.4.1.25623.1.0.100315");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_nvts_response status="503" status_text="Unavailable"/>"#);

        let error = GetNvtsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 503,
                message
            } if message == "Unavailable"
        ));
    }

    #[test]
    fn parses_missing_optional_nvt_fields() {
        let response = Response::from(
            r#"<get_nvts_response status="200" status_text="OK">
                <nvt oid="1.3.6.1.4.1.25623.1.0.123456">
                    <name>Only Required</name>
                </nvt>
            </get_nvts_response>"#,
        );

        let parsed = GetNvtsResponse::from_response(&response).expect("nvts parse");
        let nvt = &parsed.items[0];

        assert_eq!(nvt.family, None);
        assert_eq!(nvt.cvss_base, None);
        assert_eq!(nvt.severity, None);
        assert_eq!(nvt.tags, None);
        assert_eq!(nvt.solution_type, None);
    }

    #[test]
    fn parses_nvt_families() {
        let response = Response::from(
            r#"<get_nvt_families_response status="200" status_text="OK">
                <nvt_family>
                    <name>Service detection</name>
                    <count>10</count>
                </nvt_family>
                <nvt_family>
                    <name>General</name>
                    <count>4</count>
                </nvt_family>
                <family_count>2<filtered>2</filtered><page>1</page></family_count>
            </get_nvt_families_response>"#,
        );

        let parsed = GetNvtFamiliesResponse::from_response(&response).expect("nvt families parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].name, "Service detection");
        assert_eq!(parsed.items[0].max_nvt_count, Some(10));
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
    }
}
