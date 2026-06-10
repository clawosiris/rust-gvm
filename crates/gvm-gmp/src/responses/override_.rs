// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Override response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, parse_bool, parse_csv_list, parse_document, parse_entity_id,
    parse_entity_meta_optional_name, parse_named_entity, status_from_response, ActionResponse,
    CountInfo, EntityMeta, NamedEntity, ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Override {
    pub meta: EntityMeta,
    pub text: Option<String>,
    pub nvt_oid: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    pub new_severity: Option<String>,
    pub task: Option<NamedEntity>,
    pub result: Option<NamedEntity>,
    pub active: bool,
    pub end_time: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetOverridesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Override>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateOverrideResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Override {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta_optional_name(node)?,
            text: node.optional_child_text("text"),
            nvt_oid: node
                .child("nvt")
                .and_then(|n| n.attr("oid"))
                .map(String::from),
            hosts: node
                .optional_child_text("hosts")
                .map(|value| parse_csv_list(&value))
                .unwrap_or_default(),
            port: node.optional_child_text("port"),
            severity: node.optional_child_text("severity"),
            new_severity: node.optional_child_text("new_severity"),
            task: parse_named_entity(node, "task")?,
            result: parse_named_entity(node, "result")?,
            active: node
                .optional_child_text("active")
                .map(|value| parse_bool(&value, "active"))
                .transpose()?
                .unwrap_or(false),
            end_time: node.optional_child_text("end_time"),
        })
    }
}

impl GetOverridesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("override")
            .map(Override::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "override_count")?,
        })
    }
}

impl CreateOverrideResponse {
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

pub type ModifyOverrideResponse = ActionResponse;
pub type DeleteOverrideResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_overrides() {
        let response = Response::from(
            r#"<get_overrides_response status="200" status_text="OK">
                <override id="o-1">
                    <owner><name>admin</name></owner>
                    <name>Override One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <text>Override text</text>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.12345"><name>Some NVT</name></nvt>
                    <hosts>192.168.1.1,192.168.1.2, </hosts>
                    <port>80/tcp</port>
                    <severity>5.0</severity>
                    <new_severity>2.0</new_severity>
                    <task id="t-1"><name>Task One</name></task>
                    <result id="r-1"><name>Result One</name></result>
                    <active>1</active>
                    <end_time>2027-01-01T00:00:00Z</end_time>
                </override>
                <override id="o-2">
                    <name>Override Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                    <active>0</active>
                </override>
                <override_count>2<filtered>2</filtered><page>1</page></override_count>
            </get_overrides_response>"#,
        );

        let parsed = GetOverridesResponse::from_response(&response).expect("overrides parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(parsed.items[0].text.as_deref(), Some("Override text"));
        assert_eq!(
            parsed.items[0].nvt_oid.as_deref(),
            Some("1.3.6.1.4.1.25623.1.0.12345")
        );
        assert_eq!(parsed.items[0].new_severity.as_deref(), Some("2.0"));
        assert_eq!(
            parsed.items[0].hosts,
            vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()]
        );
        assert_eq!(
            parsed.items[0].task.as_ref().map(|t| t.name.as_str()),
            Some("Task One")
        );
        assert!(parsed.items[0].active);
        assert!(!parsed.items[1].active);
    }

    #[test]
    fn parses_empty_overrides() {
        let response = Response::from(
            r#"<get_overrides_response status="200" status_text="OK"><override_count>0<filtered>0</filtered></override_count></get_overrides_response>"#,
        );

        let parsed = GetOverridesResponse::from_response(&response).expect("overrides parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_override_response() {
        let response = Response::from(
            r#"<create_override_response status="201" status_text="OK, resource created" id="o-1"/>"#,
        );

        let parsed = CreateOverrideResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "o-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_overrides_response status="400" status_text="Bad request"/>"#);

        let error = GetOverridesResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_override_fields() {
        let response = Response::from(
            r#"<get_overrides_response status="200" status_text="OK">
                <override id="o-1">
                    <name>Only Required</name>
                </override>
            </get_overrides_response>"#,
        );

        let parsed = GetOverridesResponse::from_response(&response).expect("overrides parse");
        let ov = &parsed.items[0];

        assert_eq!(ov.meta.comment, None);
        assert_eq!(ov.text, None);
        assert_eq!(ov.nvt_oid, None);
        assert!(ov.hosts.is_empty());
        assert_eq!(ov.new_severity, None);
        assert_eq!(ov.task, None);
        assert!(!ov.active);
    }

    #[test]
    fn parses_gvmd_override_without_top_level_name() {
        let response = Response::from(
            r#"<get_overrides_response status="200" status_text="OK">
                <override id="6a9710b1-7ac3-4140-a212-25a0aa504979">
                    <permissions><permission><name>Everything</name></permission></permissions>
                    <owner><name>admin</name></owner>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.12288"><name>Global variable settings</name><type>nvt</type></nvt>
                    <creation_time>2026-06-10T12:42:24Z</creation_time>
                    <modification_time>2026-06-10T12:42:24Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <active>1</active>
                    <end_time>2026-06-11T12:42:24Z</end_time>
                    <text>raw gmp override parser repro</text>
                    <hosts></hosts>
                    <port></port>
                    <threat></threat>
                    <severity></severity>
                    <new_threat>Log</new_threat>
                    <new_severity>0</new_severity>
                    <task id=""><name></name><trash>0</trash></task>
                    <orphan>0</orphan>
                    <result id=""/>
                </override>
            </get_overrides_response>"#,
        );

        let parsed = GetOverridesResponse::from_response(&response).expect("override parses");
        let ov = &parsed.items[0];

        assert_eq!(ov.meta.id.as_str(), "6a9710b1-7ac3-4140-a212-25a0aa504979");
        assert_eq!(ov.meta.name, "");
        assert_eq!(
            ov.meta.owner.as_ref().map(|owner| owner.name.as_str()),
            Some("admin")
        );
        assert_eq!(
            ov.meta.creation_time.as_deref(),
            Some("2026-06-10T12:42:24Z")
        );
        assert_eq!(
            ov.meta.modification_time.as_deref(),
            Some("2026-06-10T12:42:24Z")
        );
        assert!(ov.meta.writable);
        assert!(!ov.meta.in_use);
        assert!(ov.active);
        assert_eq!(ov.end_time.as_deref(), Some("2026-06-11T12:42:24Z"));
        assert_eq!(ov.text.as_deref(), Some("raw gmp override parser repro"));
        assert_eq!(ov.nvt_oid.as_deref(), Some("1.3.6.1.4.1.25623.1.0.12288"));
        assert!(ov.hosts.is_empty());
        assert_eq!(ov.port, None);
        assert_eq!(ov.severity, None);
        assert_eq!(ov.new_severity.as_deref(), Some("0"));
        assert_eq!(ov.task, None);
        assert_eq!(ov.result, None);
    }
}
