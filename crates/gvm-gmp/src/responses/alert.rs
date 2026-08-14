// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Alert response models.

use std::collections::HashMap;
use std::str::FromStr;

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_document, parse_entity_id, parse_entity_meta, parse_named_entity,
    status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity, ParseError,
};
use crate::{AlertCondition, AlertEvent, AlertMethod};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Alert {
    pub meta: EntityMeta,
    pub event: Option<String>,
    pub event_data: HashMap<String, String>,
    pub condition: Option<String>,
    pub condition_data: HashMap<String, String>,
    pub method: Option<String>,
    pub method_data: HashMap<String, String>,
    pub filter: Option<NamedEntity>,
    /// Whether the alert is enabled.
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
            event: alert_field_text(node, "event").map(normalize_alert_event),
            event_data: alert_data(node, "event"),
            condition: node
                .child("condition")
                .and_then(alert_field_value)
                .map(normalize_alert_condition),
            condition_data: alert_data(node, "condition"),
            method: node
                .child("method")
                .and_then(alert_field_value)
                .map(normalize_alert_method),
            method_data: alert_data(node, "method"),
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

fn alert_field_text(node: &crate::responses::common::XmlNode, field: &str) -> Option<String> {
    node.child(field).and_then(alert_field_value)
}

fn alert_field_value(node: &crate::responses::common::XmlNode) -> Option<String> {
    node.optional_child_text("name")
        .or_else(|| (!node.text.is_empty()).then(|| node.text.clone()))
}

fn alert_data(node: &crate::responses::common::XmlNode, field: &str) -> HashMap<String, String> {
    node.child(field).map(parse_alert_data).unwrap_or_default()
}

fn parse_alert_data(node: &crate::responses::common::XmlNode) -> HashMap<String, String> {
    let mut data = HashMap::new();
    for item in node.children_named("data") {
        let Some(name) = item
            .attr("name")
            .map(ToString::to_string)
            .or_else(|| item.child_text("name"))
        else {
            continue;
        };
        let value = item
            .attr("value")
            .map(ToString::to_string)
            .or_else(|| item.child_text("value"))
            .or_else(|| item.child_text("data"))
            .unwrap_or_else(|| item.text.clone());
        data.insert(name, value);
    }
    data
}

fn normalize_alert_event(value: String) -> String {
    AlertEvent::from_str(&value)
        .map(AlertEvent::as_gmp_str)
        .unwrap_or(value.as_str())
        .to_string()
}

fn normalize_alert_condition(value: String) -> String {
    AlertCondition::from_str(&value)
        .map(AlertCondition::as_gmp_str)
        .unwrap_or(value.as_str())
        .to_string()
}

fn normalize_alert_method(value: String) -> String {
    AlertMethod::from_str(&value)
        .map(AlertMethod::as_gmp_str)
        .unwrap_or(value.as_str())
        .to_string()
}

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
    fn normalizes_gvmd_alert_display_names_to_stable_values() {
        let response = Response::from(
            r#"<get_alerts_response status="200" status_text="OK">
                <alert id="a-1">
                    <name>Display Name Alert</name>
                    <event>Task run status changed</event>
                    <condition>Always</condition>
                    <method>SysLog</method>
                </alert>
                <alert id="a-2">
                    <name>Alternate Method Casing</name>
                    <method>Syslog</method>
                </alert>
            </get_alerts_response>"#,
        );

        let parsed = GetAlertsResponse::from_response(&response).expect("alerts parse");

        assert_eq!(
            parsed.items[0].event.as_deref(),
            Some("task_run_status_changed")
        );
        assert_eq!(parsed.items[0].condition.as_deref(), Some("always"));
        assert_eq!(parsed.items[0].method.as_deref(), Some("syslog"));
        assert_eq!(parsed.items[1].method.as_deref(), Some("syslog"));
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
        assert!(alert.event_data.is_empty());
        assert_eq!(alert.condition, None);
        assert!(alert.condition_data.is_empty());
        assert_eq!(alert.method, None);
        assert!(alert.method_data.is_empty());
        assert_eq!(alert.filter, None);
        assert!(!alert.active);
    }

    #[test]
    fn parses_alert_data_maps() {
        let response = Response::from(
            r#"<get_alerts_response status="200" status_text="OK">
                <alert id="a-1">
                    <name>Data Alert</name>
                    <event>
                        <name>Task run status changed</name>
                        <data><name>status</name>Done</data>
                    </event>
                    <condition>
                        Severity at least
                        <data><name>severity</name>5.0</data>
                    </condition>
                    <method>
                        Email
                        <data><name>to_address</name>ops@example.com</data>
                    </method>
                </alert>
            </get_alerts_response>"#,
        );

        let parsed = GetAlertsResponse::from_response(&response).expect("alerts parse");
        let alert = &parsed.items[0];

        assert_eq!(alert.event.as_deref(), Some("task_run_status_changed"));
        assert_eq!(
            alert.event_data.get("status").map(String::as_str),
            Some("Done")
        );
        assert_eq!(alert.condition.as_deref(), Some("severity_at_least"));
        assert_eq!(
            alert.condition_data.get("severity").map(String::as_str),
            Some("5.0")
        );
        assert_eq!(alert.method.as_deref(), Some("email"));
        assert_eq!(
            alert.method_data.get("to_address").map(String::as_str),
            Some("ops@example.com")
        );
    }
}
