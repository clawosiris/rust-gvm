// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Operating-system asset command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::types::EntityId;

/// Options for `get_operating_systems` requests.
#[derive(Debug, Clone, Default)]
pub struct GetOperatingSystemsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a `get_operating_systems` request.
#[must_use]
pub fn get_operating_systems(opts: GetOperatingSystemsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_assets").attribute("type", "os");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_operating_system` request.
#[must_use]
pub fn get_operating_system(operating_system_id: &EntityId, details: Option<bool>) -> impl Request {
    let mut cmd = XmlCommand::new("get_assets")
        .attribute("asset_id", operating_system_id.as_str())
        .attribute("type", "os");
    set_optional_bool_attr(&mut cmd, "details", details);
    cmd
}

/// Build a `modify_operating_system` request.
#[must_use]
pub fn modify_operating_system(
    operating_system_id: &EntityId,
    comment: Option<&str>,
) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_asset").attribute("asset_id", operating_system_id.as_str());
    cmd.add_element_with_text("comment", comment.unwrap_or_default());
    cmd
}

/// Build a `delete_operating_system` request.
#[must_use]
pub fn delete_operating_system(operating_system_id: &EntityId) -> impl Request {
    XmlCommand::new("delete_asset").attribute("asset_id", operating_system_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn operating_system_gets_build_xml() {
        assert_eq!(
            xml(get_operating_systems(GetOperatingSystemsOpts {
                filter_string: Some("name=Debian".into()),
                filter_id: Some(id("f1")),
                details: Some(true),
            })),
            "<get_assets details=\"1\" filt_id=\"f1\" filter=\"name=Debian\" type=\"os\"/>"
        );
        assert_eq!(
            xml(get_operating_system(&id("os1"), Some(false))),
            "<get_assets asset_id=\"os1\" details=\"0\" type=\"os\"/>"
        );
    }

    #[test]
    fn operating_system_modify_delete_build_xml() {
        assert_eq!(
            xml(modify_operating_system(&id("os1"), Some("updated"))),
            "<modify_asset asset_id=\"os1\"><comment>updated</comment></modify_asset>"
        );
        assert_eq!(
            xml(modify_operating_system(&id("os1"), None)),
            "<modify_asset asset_id=\"os1\"><comment></comment></modify_asset>"
        );
        assert_eq!(
            xml(delete_operating_system(&id("os1"))),
            "<delete_asset asset_id=\"os1\"/>"
        );
    }
}
