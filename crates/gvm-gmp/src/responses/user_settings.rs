// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! User-setting response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError, XmlNode};
use crate::types::EntityId;
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UserSetting {
    pub id: EntityId,
    pub name: String,
    pub value: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetUserSettingsResponse {
    pub status: u16,
    pub status_text: String,
    pub settings: Vec<UserSetting>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ModifyUserSettingResponse {
    pub status: u16,
    pub status_text: String,
}

impl UserSetting {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let id = node
            .attr("id")
            .ok_or_else(|| ParseError::MissingElement("setting.id".to_string()))?;
        let id = EntityId::new(id).map_err(|_| ParseError::InvalidValue {
            field: "setting.id".to_string(),
            value: id.to_string(),
        })?;
        let name = node.required_child_text("name")?;
        let value = node.optional_child_text("value");
        let comment = node.optional_child_text("comment");
        Ok(Self {
            id,
            name,
            value,
            comment,
        })
    }
}

impl GetUserSettingsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let settings = root
            .children_named("setting")
            .map(UserSetting::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            settings,
        })
    }
}

impl GmpResponse for GetUserSettingsResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

impl ModifyUserSettingResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let _ = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
        })
    }
}

impl GmpResponse for ModifyUserSettingResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_user_settings_response() {
        let response = Response::from(
            r#"<get_settings_response status="200" status_text="OK">
                <setting id="s1">
                    <name>timezone</name>
                    <value>UTC</value>
                    <comment>User timezone</comment>
                </setting>
                <setting id="s2">
                    <name>rows_per_page</name>
                    <value>25</value>
                </setting>
            </get_settings_response>"#,
        );

        let parsed =
            GetUserSettingsResponse::from_response(&response).expect("parse user settings");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.settings.len(), 2);
        assert_eq!(parsed.settings[0].name, "timezone");
        assert_eq!(parsed.settings[0].value.as_deref(), Some("UTC"));
        assert_eq!(parsed.settings[0].comment.as_deref(), Some("User timezone"));
        assert!(parsed.settings[1].comment.is_none());
    }

    #[test]
    fn parses_modify_setting_response() {
        let response =
            Response::from(r#"<modify_setting_response status="200" status_text="OK"/>"#);

        let parsed = ModifyUserSettingResponse::from_response(&response).expect("parse");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
    }

    #[test]
    fn parses_empty_settings() {
        let response = Response::from(r#"<get_settings_response status="200" status_text="OK"/>"#);

        let parsed = GetUserSettingsResponse::from_response(&response).expect("parse");

        assert!(parsed.settings.is_empty());
    }
}
