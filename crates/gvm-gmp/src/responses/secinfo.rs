// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Security-info response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_document, status_from_response, CountInfo, ParseError,
};
use crate::{GmpResponse, GmpVersion};

const GENERIC_INFO_ELEMENTS: &[(&str, &str)] = &[
    ("cert_bund_adv", "CERT_BUND_ADV"),
    ("cpe", "CPE"),
    ("cve", "CVE"),
    ("dfn_cert_adv", "DFN_CERT_ADV"),
    ("nvt", "NVT"),
    ("ovaldef", "OVALDEF"),
    ("os", "os"),
    ("vuln", "vuln"),
];

/// A resource returned by the generic `get_info` compatibility command.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GenericInfo {
    /// GMP `type` value corresponding to the resource element.
    pub info_type: String,
    /// Resource identifier. NVT `oid` attributes are normalized into this field.
    pub id: String,
    /// Resource name.
    pub name: String,
}

/// Typed response for generic `get_info` list and detail requests.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetInfoResponse {
    /// GMP response status.
    pub status: u16,
    /// GMP response status text.
    pub status_text: String,
    /// Returned resources in wire order.
    pub items: Vec<GenericInfo>,
    /// Generic resource counts when supplied by gvmd.
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Cve {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Cpe {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CertBundAdvisory {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DfnCertAdvisory {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetCvesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Cve>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetCpesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Cpe>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetCertBundAdvisoriesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<CertBundAdvisory>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetDfnCertAdvisoriesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<DfnCertAdvisory>,
    pub counts: CountInfo,
}

fn parse_secinfo_item(
    node: &crate::responses::common::XmlNode,
    element_name: &str,
) -> Result<(String, String), ParseError> {
    let id = node
        .attr("id")
        .ok_or_else(|| ParseError::MissingElement(format!("{element_name}.id")))?
        .to_string();
    let name = node.required_child_text("name")?;
    Ok((id, name))
}

impl GenericInfo {
    fn from_node(
        node: &crate::responses::common::XmlNode,
        info_type: &str,
    ) -> Result<Self, ParseError> {
        let id = node
            .attr("id")
            .or_else(|| node.attr("oid"))
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ParseError::MissingElement(format!("{}.id", node.name)))?;
        Ok(Self {
            info_type: info_type.to_string(),
            id: id.to_string(),
            name: node.required_child_text("name")?,
        })
    }
}

impl GetInfoResponse {
    /// Parse any public generic `get_info` resource shape.
    ///
    /// # Errors
    /// Returns an error for a non-success status or malformed known resource.
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children
            .iter()
            .filter_map(|node| {
                GENERIC_INFO_ELEMENTS
                    .iter()
                    .find(|(element, _)| *element == node.name)
                    .map(|(_, info_type)| GenericInfo::from_node(node, info_type))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut counts = CountInfo::default();
        for (element, _) in GENERIC_INFO_ELEMENTS {
            let candidate = count_info(&root, &format!("{element}_count"))?;
            if candidate != CountInfo::default() {
                counts = candidate;
                break;
            }
        }
        Ok(Self {
            status,
            status_text,
            items,
            counts,
        })
    }
}

impl GmpResponse for GetInfoResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl Cve {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let (id, name) = parse_secinfo_item(node, "cve")?;
        Ok(Self { id, name })
    }
}

impl Cpe {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let (id, name) = parse_secinfo_item(node, "cpe")?;
        Ok(Self { id, name })
    }
}

impl CertBundAdvisory {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let (id, name) = parse_secinfo_item(node, "cert_bund_adv")?;
        Ok(Self { id, name })
    }
}

impl DfnCertAdvisory {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let (id, name) = parse_secinfo_item(node, "dfn_cert_adv")?;
        Ok(Self { id, name })
    }
}

impl GetCvesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("cve")
            .map(Cve::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "cve_count")?,
        })
    }
}

impl GetCpesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("cpe")
            .map(Cpe::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "cpe_count")?,
        })
    }
}

impl GetCertBundAdvisoriesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("cert_bund_adv")
            .map(CertBundAdvisory::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "cert_bund_adv_count")?,
        })
    }
}

impl GetDfnCertAdvisoriesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("dfn_cert_adv")
            .map(DfnCertAdvisory::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "dfn_cert_adv_count")?,
        })
    }
}

macro_rules! impl_gmp_response {
    ($($response:ty),+ $(,)?) => {
        $(
            impl GmpResponse for $response {
                fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
                    Self::from_response(response)
                }
            }
        )+
    };
}

impl_gmp_response!(
    GetCvesResponse,
    GetCpesResponse,
    GetCertBundAdvisoriesResponse,
    GetDfnCertAdvisoriesResponse,
);

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_cves() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <cve id="CVE-2026-0001"><name>Buffer Overflow in Demo Service</name></cve>
                <cve id="CVE-2026-0002"><name>Authentication Bypass in Demo Service</name></cve>
                <cve_count>2<filtered>2</filtered><page>1</page></cve_count>
            </get_info_response>"#,
        );

        let parsed = GetCvesResponse::from_response(&response).expect("cves parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].id, "CVE-2026-0001");
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
    }

    #[test]
    fn parses_empty_cves() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK"><cve_count>0<filtered>0</filtered></cve_count></get_info_response>"#,
        );

        let parsed = GetCvesResponse::from_response(&response).expect("cves parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn rejects_server_error_for_cves() {
        let response =
            Response::from(r#"<get_info_response status="404" status_text="Not Found"/>"#);

        let error = GetCvesResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 404,
                message
            } if message == "Not Found"
        ));
    }

    #[test]
    fn rejects_missing_required_cve_fields() {
        let missing_id = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <cve><name>Missing Id</name></cve>
            </get_info_response>"#,
        );
        let missing_name = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <cve id="CVE-2026-9999"></cve>
            </get_info_response>"#,
        );

        assert!(matches!(
            GetCvesResponse::from_response(&missing_id),
            Err(ParseError::MissingElement(field)) if field == "cve.id"
        ));
        assert!(matches!(
            GetCvesResponse::from_response(&missing_name),
            Err(ParseError::MissingElement(field)) if field == "name"
        ));
    }

    #[test]
    fn parses_multiple_cpes() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <cpe id="cpe:/a:vendor:product:1"><name>Vendor Product 1</name></cpe>
                <cpe id="cpe:/a:vendor:product:2"><name>Vendor Product 2</name></cpe>
                <cpe_count>2<filtered>2</filtered></cpe_count>
            </get_info_response>"#,
        );

        let parsed = GetCpesResponse::from_response(&response).expect("cpes parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[1].name, "Vendor Product 2");
        assert_eq!(parsed.counts.filtered, Some(2));
    }

    #[test]
    fn parses_multiple_cert_bund_advisories() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <cert_bund_adv id="CB-K26-001"><name>CERT-Bund Advisory 1</name></cert_bund_adv>
                <cert_bund_adv id="CB-K26-002"><name>CERT-Bund Advisory 2</name></cert_bund_adv>
                <cert_bund_adv_count>2</cert_bund_adv_count>
            </get_info_response>"#,
        );

        let parsed = GetCertBundAdvisoriesResponse::from_response(&response)
            .expect("cert bund advisories parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].id, "CB-K26-001");
        assert_eq!(parsed.counts.total, Some(2));
    }

    #[test]
    fn parses_multiple_dfn_cert_advisories() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <dfn_cert_adv id="DFN-2026-001"><name>DFN-CERT Advisory 1</name></dfn_cert_adv>
                <dfn_cert_adv id="DFN-2026-002"><name>DFN-CERT Advisory 2</name></dfn_cert_adv>
                <dfn_cert_adv_count>2</dfn_cert_adv_count>
            </get_info_response>"#,
        );

        let parsed =
            GetDfnCertAdvisoriesResponse::from_response(&response).expect("dfn advisories parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[1].name, "DFN-CERT Advisory 2");
        assert_eq!(parsed.counts.total, Some(2));
    }

    #[test]
    fn counts_default_when_missing_count_element() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <cpe id="cpe:/a:vendor:product:1"><name>Vendor Product 1</name></cpe>
            </get_info_response>"#,
        );

        let parsed = GetCpesResponse::from_response(&response).expect("cpes parse");

        assert_eq!(parsed.counts, CountInfo::default());
    }

    #[test]
    fn parses_generic_info_resources_and_counts() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK">
                <nvt oid="1.3.6.1"><name>Example NVT</name></nvt>
                <nvt_count>1<filtered>1</filtered></nvt_count>
            </get_info_response>"#,
        );

        let parsed = GetInfoResponse::from_response(&response).expect("generic info parses");

        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].info_type, "NVT");
        assert_eq!(parsed.items[0].id, "1.3.6.1");
        assert_eq!(parsed.items[0].name, "Example NVT");
        assert_eq!(parsed.counts.total, Some(1));
        assert_eq!(parsed.counts.filtered, Some(1));
    }

    #[test]
    fn generic_info_preserves_parse_context() {
        let response = Response::from(
            r#"<get_info_response status="200" status_text="OK"><ovaldef><name>Missing id</name></ovaldef></get_info_response>"#,
        );

        assert!(matches!(
            GetInfoResponse::from_response(&response),
            Err(ParseError::MissingElement(field)) if field == "ovaldef.id"
        ));
    }
}

// === Additional SecInfo Response Types ===

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatingSystem {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Vulnerability {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetOperatingSystemsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<OperatingSystem>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetVulnerabilitiesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Vulnerability>,
    pub counts: CountInfo,
}

impl OperatingSystem {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let (id, name) = parse_secinfo_item(node, "os")?;
        Ok(Self { id, name })
    }
}

impl Vulnerability {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let (id, name) = parse_secinfo_item(node, "vuln")?;
        Ok(Self { id, name })
    }
}

impl GetOperatingSystemsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("os")
            .map(OperatingSystem::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "os_count")?,
        })
    }
}

impl GetVulnerabilitiesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("vuln")
            .map(Vulnerability::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "vuln_count")?,
        })
    }
}

impl_gmp_response!(GetOperatingSystemsResponse, GetVulnerabilitiesResponse);

#[cfg(test)]
mod additional_tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_get_vulns_response() {
        let response = Response::from(
            r#"<get_vulns_response status="200" status_text="OK">
                <vuln id="vuln-1"><name>Outdated package</name></vuln>
                <vuln_count>1<filtered>1</filtered></vuln_count>
            </get_vulns_response>"#,
        );

        let parsed = GetVulnerabilitiesResponse::from_response(&response).expect("vulns parse");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.items.len(), 1);
        assert_eq!(parsed.items[0].id, "vuln-1");
        assert_eq!(parsed.items[0].name, "Outdated package");
        assert_eq!(parsed.counts.total, Some(1));
    }
}
