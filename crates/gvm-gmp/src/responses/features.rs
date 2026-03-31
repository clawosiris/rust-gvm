// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feature response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError, XmlNode};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Feature {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetFeaturesResponse {
    pub status: u16,
    pub status_text: String,
    pub features: Vec<Feature>,
}

impl Feature {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let name = node.required_child_text("name")?;
        let enabled = node
            .child_text("_enabled")
            .map(|text| text == "1" || text.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(Self { name, enabled })
    }
}

impl GetFeaturesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let features = root
            .children_named("feature")
            .map(Feature::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            features,
        })
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_features_response() {
        let response = Response::from(
            r#"<get_features_response status="200" status_text="OK">
                <feature><name>SCAP</name><_enabled>1</_enabled></feature>
                <feature><name>CERT_BUND</name><_enabled>1</_enabled></feature>
                <feature><name>ENTERPRISE</name><_enabled>0</_enabled></feature>
            </get_features_response>"#,
        );

        let parsed = GetFeaturesResponse::from_response(&response).expect("parse features");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.features.len(), 3);
        assert_eq!(parsed.features[0].name, "SCAP");
        assert!(parsed.features[0].enabled);
        assert!(!parsed.features[2].enabled);
    }

    #[test]
    fn parses_empty_features() {
        let response =
            Response::from(r#"<get_features_response status="200" status_text="OK"/>"#);

        let parsed = GetFeaturesResponse::from_response(&response).expect("parse");

        assert!(parsed.features.is_empty());
    }
}
