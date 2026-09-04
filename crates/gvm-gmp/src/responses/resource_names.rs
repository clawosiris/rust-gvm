// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Resource-names response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError, XmlNode};
use crate::types::EntityId;
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ResourceName {
    pub id: EntityId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetResourceNamesResponse {
    pub status: u16,
    pub status_text: String,
    pub resource_type: Option<String>,
    pub items: Vec<ResourceName>,
}

impl ResourceName {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let id = node
            .attr("id")
            .ok_or_else(|| ParseError::MissingElement("resource.id".to_string()))?;
        let id = EntityId::new(id).map_err(|_| ParseError::InvalidValue {
            field: "resource.id".to_string(),
            value: id.to_string(),
        })?;
        let name = node.required_child_text("name")?;
        Ok(Self { id, name })
    }
}

impl GetResourceNamesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let resource_type = root.attr("type").map(String::from);
        let items = root
            .children_named("resource")
            .map(ResourceName::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            resource_type,
            items,
        })
    }
}

impl GmpResponse for GetResourceNamesResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_resource_names_response() {
        let response = Response::from(
            r#"<get_resource_names_response status="200" status_text="OK" type="target">
                <resource id="t1"><name>Target One</name></resource>
                <resource id="t2"><name>Target Two</name></resource>
            </get_resource_names_response>"#,
        );

        let parsed =
            GetResourceNamesResponse::from_response(&response).expect("parse resource names");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.resource_type.as_deref(), Some("target"));
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].name, "Target One");
    }

    #[test]
    fn parses_empty_resource_names() {
        let response = Response::from(
            r#"<get_resource_names_response status="200" status_text="OK" type="filter"/>"#,
        );

        let parsed = GetResourceNamesResponse::from_response(&response).expect("parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.resource_type.as_deref(), Some("filter"));
    }
}
