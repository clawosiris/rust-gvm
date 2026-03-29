// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Alert response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta, parse_named_entity,
    status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Alert {
    pub meta: EntityMeta,
    pub event: Option<String>,
    pub condition: Option<String>,
    pub method: Option<String>,
    pub filter: Option<NamedEntity>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAlertsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Alert>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateAlertResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Alert {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            event: node.optional_child_text("event"),
            condition: node.optional_child_text("condition"),
            method: node.optional_child_text("method"),
            filter: parse_named_entity(node, "filter")?,
            active: node
                .optional_child_text("active")
                .map(|value| parse_bool(&value, "active"))
                .transpose()?
                .unwrap_or(false),
        })
    }
}

impl GetAlertsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("alert")
            .map(Alert::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "alert_count")?,
        })
    }
}

impl CreateAlertResponse {
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

pub type ModifyAlertResponse = ActionResponse;
pub type DeleteAlertResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_alerts() {
        let response = Response::from(
            r#"<get_alerts_response status="200" status_text="OK">
                <alert id="a-1">
                    <owner><name>admin</name></owner>
                    <name>Alert One</name>
                    <comment>first alert</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <event>task_run_status_changed</event>
                    <condition>always</condition>
                    <method>email</method>
                    <filter id="f-1"><name>My Filter</name></filter>
                    <active>1</active>
                </alert>
                <alert id="a-2">
                    <name>Alert Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <active>0</active>
                </alert>
                <alert_count>2<filtered>2</filtered><page>1</page></alert_count>
            </get_alerts_response>"#,
        );

        let parsed = GetAlertsResponse::from_response(&response).expect("alerts parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(
            parsed.items[0].event.as_deref(),
            Some("task_run_status_changed")
        );
        assert_eq!(parsed.items[0].condition.as_deref(), Some("always"));
        assert_eq!(parsed.items[0].method.as_deref(), Some("email"));
        assert_eq!(
            parsed.items[0].filter.as_ref().map(|f| f.name.as_str()),
            Some("My Filter")
        );
        assert!(parsed.items[0].active);
        assert!(!parsed.items[1].active);
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_alerts() {
        let response = Response::from(
            r#"<get_alerts_response status="200" status_text="OK"><alert_count>0<filtered>0</filtered></alert_count></get_alerts_response>"#,
        );

        let parsed = GetAlertsResponse::from_response(&response).expect("alerts parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_alert_response() {
        let response = Response::from(
            r#"<create_alert_response status="201" status_text="OK, resource created" id="a-1"/>"#,
        );

        let parsed = CreateAlertResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "a-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_alerts_response status="400" status_text="Bad request"/>"#);

        let error = GetAlertsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_alert_fields() {
        let response = Response::from(
            r#"<get_alerts_response status="200" status_text="OK">
                <alert id="a-1">
                    <name>Only Required</name>
                </alert>
            </get_alerts_response>"#,
        );

        let parsed = GetAlertsResponse::from_response(&response).expect("alerts parse");
        let alert = &parsed.items[0];

        assert_eq!(alert.meta.comment, None);
        assert_eq!(alert.event, None);
        assert_eq!(alert.condition, None);
        assert_eq!(alert.method, None);
        assert_eq!(alert.filter, None);
        assert!(!alert.active);
    }
}
