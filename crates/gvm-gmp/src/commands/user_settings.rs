// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! User-setting command builders.

use base64::Engine as _;
use gvm_protocol::XmlCommand;

use crate::common::add_filter_attrs;
use crate::types::EntityId;

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
    use crate::commands::user_settings::{
        get_user_setting, get_user_settings, modify_user_setting, GetUserSettingsOpts,
        ModifyUserSettingOpts,
    };
    use crate::common::xml;
    use crate::types::EntityId;

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
}
