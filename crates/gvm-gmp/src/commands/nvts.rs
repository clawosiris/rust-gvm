// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! NVT command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::types::EntityId;

/// Options for `get_nvts` requests.
#[derive(Debug, Clone, Default)]
pub struct GetNvtsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Options for NVT `get_preferences` requests.
#[derive(Debug, Clone, Default)]
pub struct GetNvtPreferencesOpts {
    /// Optional NVT OID to restrict preference lookup.
    pub nvt_oid: Option<String>,
}

/// Build a `get_nvts` request.
#[must_use]
pub fn get_nvts(opts: GetNvtsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_nvts");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_nvts` request for a single NVT.
#[must_use]
pub fn get_nvt(nvt_oid: &str) -> impl Request {
    XmlCommand::new("get_nvts")
        .attribute("nvt_oid", nvt_oid)
        .attribute("details", "1")
}

/// Build a `get_preferences` request for NVT preferences.
#[must_use]
pub fn get_nvt_preferences(opts: GetNvtPreferencesOpts) -> impl Request {
    get_preferences_with(None, opts.nvt_oid.as_deref())
}

/// Build a `get_preferences` request for a single NVT preference.
#[must_use]
pub fn get_nvt_preference(name: &str, opts: GetNvtPreferencesOpts) -> impl Request {
    get_preferences_with(Some(name), opts.nvt_oid.as_deref())
}

fn get_preferences_with(preference: Option<&str>, nvt_oid: Option<&str>) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_preferences");
    if let Some(preference) = preference {
        cmd.set_attribute("preference", preference);
    }
    if let Some(nvt_oid) = nvt_oid {
        cmd.set_attribute("nvt_oid", nvt_oid);
    }
    cmd
}

/// Build a `get_nvt_families` request.
#[must_use]
pub fn get_nvt_families() -> impl Request {
    XmlCommand::new("get_nvt_families")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn nvt_commands_build_xml() {
        let rendered = xml(get_nvts(GetNvtsOpts {
            filter_id: Some(id("f1")),
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("filt_id=\"f1\""));
        assert!(rendered.contains("details=\"1\""));
        assert_eq!(
            xml(get_nvt("1.3.6.1")),
            "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\"/>"
        );
        assert_eq!(
            xml(get_nvt_preferences(GetNvtPreferencesOpts::default())),
            "<get_preferences/>"
        );
        assert_eq!(
            xml(get_nvt_preferences(GetNvtPreferencesOpts {
                nvt_oid: Some("1.3.6.1".into())
            })),
            "<get_preferences nvt_oid=\"1.3.6.1\"/>"
        );
        assert_eq!(
            xml(get_nvt_preference(
                "timeout",
                GetNvtPreferencesOpts {
                    nvt_oid: Some("1.3.6.1".into())
                }
            )),
            "<get_preferences nvt_oid=\"1.3.6.1\" preference=\"timeout\"/>"
        );
        assert_eq!(xml(get_nvt_families()), "<get_nvt_families/>");
    }
}
