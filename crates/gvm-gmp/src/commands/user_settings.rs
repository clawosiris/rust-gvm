// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! User-setting command builders.

use base64::Engine as _;
use gvm_protocol::{Request, XmlCommand};

use crate::common::add_filter_attrs;
use crate::responses::{GetUserSettingsResponse, ModifyUserSettingResponse};
use crate::types::EntityId;
use crate::GmpRequest;

/// Options for `get_settings` requests.
#[derive(Debug, Clone, Default)]
pub struct GetUserSettingsOpts {
    /// Optional inline filter expression.
    pub filter: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `modify_setting` requests.
#[derive(Debug, Clone)]
pub struct ModifyUserSettingOpts {
    /// UTF-8 setting value to apply; the builder Base64-encodes it for GMP.
    pub value: String,
}

/// Semantic request for listing user settings.
#[derive(Debug, Clone, Default)]
pub struct GetUserSettingsRequest {
    opts: GetUserSettingsOpts,
}

impl GetUserSettingsRequest {
    /// Create a user-setting list request.
    #[must_use]
    pub fn new(opts: GetUserSettingsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetUserSettingsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_user_settings(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetUserSettingsRequest {
    type Response = GetUserSettingsResponse;
}

/// Semantic request for one user setting.
#[derive(Debug, Clone)]
pub struct GetUserSettingRequest {
    setting_id: EntityId,
}

impl GetUserSettingRequest {
    /// Create a detailed single-setting request.
    #[must_use]
    pub fn new(setting_id: EntityId) -> Self {
        Self { setting_id }
    }
}

impl Request for GetUserSettingRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_user_setting(&self.setting_id).to_bytes()
    }
}

impl GmpRequest for GetUserSettingRequest {
    type Response = GetUserSettingsResponse;
}

/// Semantic request for modifying a user setting.
#[derive(Clone)]
pub struct ModifyUserSettingRequest {
    setting_id: EntityId,
    opts: ModifyUserSettingOpts,
}

impl std::fmt::Debug for ModifyUserSettingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyUserSettingRequest")
            .field("setting_id", &self.setting_id)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ModifyUserSettingRequest {
    /// Create a user-setting modification request.
    #[must_use]
    pub fn new(setting_id: EntityId, opts: ModifyUserSettingOpts) -> Self {
        Self { setting_id, opts }
    }
}

impl Request for ModifyUserSettingRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_user_setting(&self.setting_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyUserSettingRequest {
    type Response = ModifyUserSettingResponse;
}

/// Build a `get_settings` request.
#[must_use]
pub fn get_user_settings(opts: GetUserSettingsOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_settings");
    add_filter_attrs(&mut cmd, opts.filter.as_deref(), opts.filter_id.as_ref());
    cmd
}

/// Build a `get_settings` request for a single setting.
#[must_use]
pub fn get_user_setting(id: &EntityId) -> XmlCommand {
    XmlCommand::new("get_settings").attribute("setting_id", id.as_str())
}

/// Build a `modify_setting` request, Base64-encoding the UTF-8 value for GMP.
#[must_use]
pub fn modify_user_setting(id: &EntityId, opts: ModifyUserSettingOpts) -> XmlCommand {
    let encoded = base64::engine::general_purpose::STANDARD.encode(opts.value.as_bytes());
    XmlCommand::new("modify_setting")
        .attribute("setting_id", id.as_str())
        .child_with_text("value", &encoded)
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Request;

    use crate::commands::user_settings::{
        get_user_setting, get_user_settings, modify_user_setting, GetUserSettingRequest,
        GetUserSettingsOpts, GetUserSettingsRequest, ModifyUserSettingOpts,
        ModifyUserSettingRequest,
    };
    use crate::common::xml;
    use crate::responses::{GetUserSettingsResponse, ModifyUserSettingResponse};
    use crate::types::EntityId;
    use crate::GmpRequest;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn user_setting_commands_build_xml() {
        assert_eq!(
            xml(get_user_settings(GetUserSettingsOpts {
                filter: Some("name=timezone".into()),
                filter_id: Some(id("f1")),
            })),
            "<get_settings filt_id=\"f1\" filter=\"name=timezone\"/>"
        );
        assert_eq!(
            xml(get_user_setting(&id("s1"))),
            "<get_settings setting_id=\"s1\"/>"
        );
        assert_eq!(
            xml(modify_user_setting(
                &id("s1"),
                ModifyUserSettingOpts {
                    value: "UTC".into(),
                }
            )),
            "<modify_setting setting_id=\"s1\"><value>VVRD</value></modify_setting>"
        );
    }

    #[test]
    fn semantic_user_setting_requests_preserve_builder_bytes_and_associations() {
        fn get<R: GmpRequest<Response = GetUserSettingsResponse>>(_: &R) {}
        fn modify<R: GmpRequest<Response = ModifyUserSettingResponse>>(_: &R) {}

        let get_opts = GetUserSettingsOpts {
            filter: Some("name=timezone".into()),
            filter_id: Some(id("filter-1")),
        };
        let list = GetUserSettingsRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_user_settings(get_opts).to_bytes());
        get(&list);

        let setting_id = id("setting-1");
        let detail = GetUserSettingRequest::new(setting_id.clone());
        assert_eq!(detail.to_bytes(), get_user_setting(&setting_id).to_bytes());
        get(&detail);

        let modify_opts = ModifyUserSettingOpts {
            value: "setting-secret".into(),
        };
        let modification = ModifyUserSettingRequest::new(setting_id.clone(), modify_opts.clone());
        assert_eq!(
            modification.to_bytes(),
            modify_user_setting(&setting_id, modify_opts).to_bytes()
        );
        modify(&modification);
    }

    #[test]
    fn semantic_user_setting_debug_redacts_value() {
        let debug = format!(
            "{:?}",
            ModifyUserSettingRequest::new(
                id("setting-1"),
                ModifyUserSettingOpts {
                    value: "setting-secret".into(),
                }
            )
        );
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("setting-secret"));
    }
}
