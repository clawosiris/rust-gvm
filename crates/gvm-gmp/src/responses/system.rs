// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System (settings, help, auth) response models.

use gvm_protocol::Response;

use crate::responses::common::{
    parse_document, parse_entity_id, status_from_response, ActionResponse, ParseError,
};
use crate::EntityId;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Setting {
    pub id: EntityId,
    pub name: String,
    pub comment: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetSettingsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Setting>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Timezone {
    pub name: String,
    pub offset: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTimezonesResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Timezone>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HelpResponse {
    pub status: u16,
    pub status_text: String,
    pub help_text: String,
    pub schema: Option<HelpSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HelpSchema {
    pub format: Option<String>,
    pub extension: Option<String>,
    pub content_type: Option<String>,
    pub content: Option<String>,
    pub commands: Vec<HelpCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HelpCommand {
    pub name: String,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DescribeAuthResponse {
    pub status: u16,
    pub status_text: String,
    pub groups: Vec<AuthGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthGroup {
    pub name: String,
    pub settings: Vec<AuthConfSetting>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthConfSetting {
    pub key: Option<String>,
    pub value: Option<String>,
}

/// Response returned after modifying authentication configuration.
pub type ModifyAuthResponse = ActionResponse;

/// Response returned after modifying the gvmd license.
pub type ModifyLicenseResponse = ActionResponse;

impl Setting {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            id: parse_entity_id(
                node.attr("id")
                    .ok_or_else(|| ParseError::MissingElement("setting.id".to_string()))?,
                "setting.id",
            )?,
            name: node.required_child_text("name")?,
            comment: node.optional_child_text("comment"),
            value: node.optional_child_text("value"),
        })
    }
}

impl GetSettingsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("setting")
            .map(Setting::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
        })
    }
}

impl Timezone {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        let name = node
            .optional_child_text("name")
            .or_else(|| node.attr("name").map(ToString::to_string))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| node.text.clone());
        if name.is_empty() {
            return Err(ParseError::MissingElement("timezone.name".to_string()));
        }
        Ok(Self {
            name,
            offset: node.optional_child_text("offset"),
        })
    }
}

impl GetTimezonesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("timezone")
            .map(Timezone::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
        })
    }
}

impl HelpResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let schema = root.child("schema").map(|schema| {
            let mut commands = Vec::new();
            collect_help_commands(schema, &mut commands);
            HelpSchema {
                format: schema.attr("format").map(ToString::to_string),
                extension: schema.attr("extension").map(ToString::to_string),
                content_type: schema.attr("content_type").map(ToString::to_string),
                content: (!schema.text.is_empty()).then(|| schema.text.clone()),
                commands,
            }
        });
        Ok(Self {
            status,
            status_text,
            help_text: root.text.clone(),
            schema,
        })
    }
}

fn collect_help_commands(
    node: &crate::responses::common::XmlNode,
    commands: &mut Vec<HelpCommand>,
) {
    for child in &node.children {
        if child.name == "command" {
            if let Some(name) = child
                .optional_child_text("name")
                .or_else(|| (!child.text.is_empty()).then(|| child.text.clone()))
            {
                commands.push(HelpCommand {
                    name,
                    summary: child.optional_child_text("summary"),
                });
            }
        } else {
            collect_help_commands(child, commands);
        }
    }
}

impl DescribeAuthResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let groups = root
            .children_named("group")
            .map(|g| {
                let name = g.attr("name").unwrap_or("").to_string();
                let settings = g
                    .children_named("auth_conf_setting")
                    .map(|s| AuthConfSetting {
                        key: s.optional_child_text("key"),
                        value: s.optional_child_text("value"),
                    })
                    .collect();
                Ok(AuthGroup { name, settings })
            })
            .collect::<Result<Vec<_>, ParseError>>()?;
        Ok(Self {
            status,
            status_text,
            groups,
        })
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_settings() {
        let response = Response::from(
            r#"<get_settings_response status="200" status_text="OK">
                <setting id="s-1">
                    <name>Setting One</name>
                    <comment>first setting</comment>
                    <value>value1</value>
                </setting>
                <setting id="s-2">
                    <name>Setting Two</name>
                    <value>value2</value>
                </setting>
            </get_settings_response>"#,
        );

        let parsed = GetSettingsResponse::from_response(&response).expect("settings parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].id.as_str(), "s-1");
        assert_eq!(parsed.items[0].name, "Setting One");
        assert_eq!(parsed.items[0].comment.as_deref(), Some("first setting"));
        assert_eq!(parsed.items[0].value.as_deref(), Some("value1"));
        assert_eq!(parsed.items[1].name, "Setting Two");
        assert_eq!(parsed.items[1].comment, None);
    }

    #[test]
    fn parses_empty_settings() {
        let response = Response::from(
            r#"<get_settings_response status="200" status_text="OK"></get_settings_response>"#,
        );

        let parsed = GetSettingsResponse::from_response(&response).expect("settings parse");

        assert!(parsed.items.is_empty());
    }

    #[test]
    fn parses_timezones() {
        let response = Response::from(
            r#"<get_timezones_response status="200" status_text="OK">
                <timezone>UTC</timezone>
                <timezone><name>Europe/Berlin</name><offset>+01:00</offset></timezone>
            </get_timezones_response>"#,
        );

        let parsed = GetTimezonesResponse::from_response(&response).expect("timezones parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[0].name, "UTC");
        assert_eq!(parsed.items[1].offset.as_deref(), Some("+01:00"));
    }

    #[test]
    fn parses_help_response() {
        let response = Response::from(
            r#"<help_response status="200" status_text="OK">Available commands: get_tasks, get_alerts</help_response>"#,
        );

        let parsed = HelpResponse::from_response(&response).expect("help parse");

        assert_eq!(parsed.status, 200);
        assert_eq!(
            parsed.help_text,
            "Available commands: get_tasks, get_alerts"
        );
        assert!(parsed.schema.is_none());
    }

    #[test]
    fn parses_brief_xml_help_response() {
        let response = Response::from(
            r#"<help_response status="200" status_text="OK">
                <schema format="XML" extension="xml" content_type="text/xml">
                    <command><name>get_tasks</name><summary>Get tasks</summary></command>
                    <command><name>get_alerts</name><summary>Get alerts</summary></command>
                </schema>
            </help_response>"#,
        );

        let parsed = HelpResponse::from_response(&response).expect("brief XML help parse");
        let schema = parsed.schema.expect("schema");

        assert!(parsed.help_text.is_empty());
        assert_eq!(schema.format.as_deref(), Some("XML"));
        assert_eq!(schema.extension.as_deref(), Some("xml"));
        assert_eq!(schema.content_type.as_deref(), Some("text/xml"));
        assert_eq!(schema.commands.len(), 2);
        assert_eq!(schema.commands[0].name, "get_tasks");
        assert_eq!(schema.commands[0].summary.as_deref(), Some("Get tasks"));
    }

    #[test]
    fn parses_encoded_schema_content_and_nested_commands() {
        let encoded = Response::from(
            r#"<help_response status="200" status_text="OK">
                <schema format="html" extension="html" content_type="text/html">PGh0bWw+PC9odG1sPg==</schema>
            </help_response>"#,
        );
        let parsed = HelpResponse::from_response(&encoded).expect("encoded help parse");
        assert_eq!(
            parsed.schema.expect("schema").content.as_deref(),
            Some("PGh0bWw+PC9odG1sPg==")
        );

        let xml = Response::from(
            r#"<help_response status="200" status_text="OK">
                <schema format="XML" extension="xml" content_type="text/xml">
                    <protocol><command><name>get_tasks</name></command></protocol>
                </schema>
            </help_response>"#,
        );
        let parsed = HelpResponse::from_response(&xml).expect("nested XML help parse");
        assert_eq!(parsed.schema.expect("schema").commands[0].name, "get_tasks");
    }

    #[test]
    fn parses_describe_auth_response() {
        let response = Response::from(
            r#"<describe_auth_response status="200" status_text="OK">
                <group name="method:ldap_connect">
                    <auth_conf_setting>
                        <key>ldaphost</key>
                        <value>ldap.example.com</value>
                    </auth_conf_setting>
                    <auth_conf_setting>
                        <key>enable</key>
                        <value>true</value>
                    </auth_conf_setting>
                </group>
                <group name="method:radius_connect">
                    <auth_conf_setting>
                        <key>radiushost</key>
                        <value>radius.example.com</value>
                    </auth_conf_setting>
                </group>
            </describe_auth_response>"#,
        );

        let parsed = DescribeAuthResponse::from_response(&response).expect("describe_auth parse");

        assert_eq!(parsed.groups.len(), 2);
        assert_eq!(parsed.groups[0].name, "method:ldap_connect");
        assert_eq!(parsed.groups[0].settings.len(), 2);
        assert_eq!(
            parsed.groups[0].settings[0].key.as_deref(),
            Some("ldaphost")
        );
        assert_eq!(
            parsed.groups[0].settings[0].value.as_deref(),
            Some("ldap.example.com")
        );
        assert_eq!(parsed.groups[1].name, "method:radius_connect");
        assert_eq!(parsed.groups[1].settings.len(), 1);
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_settings_response status="400" status_text="Bad request"/>"#);

        let error = GetSettingsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }
}
