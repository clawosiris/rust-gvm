// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feature response models.

use gvm_protocol::Response;

use crate::responses::common::{
    parse_bool, parse_document, status_from_response, ParseError, XmlNode,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Feature {
    pub name: String,
    pub compiled_in: bool,
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
        let compiled_in = node
            .attr("compiled_in")
            .ok_or_else(|| ParseError::MissingElement("feature.compiled_in".to_string()))
            .and_then(|value| parse_bool(value, "feature.compiled_in"))?;
        let enabled = node
            .attr("enabled")
            .ok_or_else(|| ParseError::MissingElement("feature.enabled".to_string()))
            .and_then(|value| parse_bool(value, "feature.enabled"))?;
        Ok(Self {
            name,
            compiled_in,
            enabled,
        })
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

impl GmpResponse for GetFeaturesResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
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
                <feature compiled_in="1" enabled="1"><name>ENABLE_OPENVASD</name></feature>
                <feature compiled_in="true" enabled="1"><name>ENABLE_AGENTS</name></feature>
                <feature compiled_in="0" enabled="false"><name>ENABLE_JWT_AUTH</name></feature>
            </get_features_response>"#,
        );

        let parsed = GetFeaturesResponse::from_response(&response).expect("parse features");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.features.len(), 3);
        assert_eq!(parsed.features[0].name, "ENABLE_OPENVASD");
        assert!(parsed.features[0].compiled_in);
        assert!(parsed.features[0].enabled);
        assert!(parsed.features[1].compiled_in);
        assert!(!parsed.features[2].compiled_in);
        assert!(!parsed.features[2].enabled);
    }

    #[test]
    fn parses_empty_features() {
        let response = Response::from(r#"<get_features_response status="200" status_text="OK"/>"#);

        let parsed = GetFeaturesResponse::from_response(&response).expect("parse");

        assert!(parsed.features.is_empty());
    }

    #[test]
    fn rejects_missing_feature_attributes() {
        let response = Response::from(
            r#"<get_features_response status="200" status_text="OK">
                <feature enabled="1"><name>ENABLE_AGENTS</name></feature>
            </get_features_response>"#,
        );

        let error = GetFeaturesResponse::from_response(&response).expect_err("missing compiled_in");

        assert!(matches!(
            error,
            ParseError::MissingElement(field) if field == "feature.compiled_in"
        ));
    }

    #[test]
    fn rejects_invalid_feature_attributes() {
        let response = Response::from(
            r#"<get_features_response status="200" status_text="OK">
                <feature compiled_in="1" enabled="sometimes"><name>ENABLE_AGENTS</name></feature>
            </get_features_response>"#,
        );

        let error = GetFeaturesResponse::from_response(&response).expect_err("invalid enabled");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, value }
                if field == "feature.enabled" && value == "sometimes"
        ));
    }
}
