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
    /// Whether to include NVT preferences.
    pub preferences: Option<bool>,
    /// Whether to include the preference count.
    pub preference_count: Option<bool>,
    /// Whether to include the special timeout preference.
    pub timeout: Option<bool>,
    /// Optional scan config identifier to restrict NVT listing.
    pub config_id: Option<EntityId>,
    /// Optional scan config identifier to use for preference values.
    pub preferences_config_id: Option<EntityId>,
    /// Optional NVT family to restrict listing.
    pub family: Option<String>,
    /// Optional sort order.
    pub sort_order: Option<String>,
    /// Optional sort field.
    pub sort_field: Option<String>,
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
    set_optional_bool_attr(&mut cmd, "preferences", opts.preferences);
    set_optional_bool_attr(&mut cmd, "preference_count", opts.preference_count);
    set_optional_bool_attr(&mut cmd, "timeout", opts.timeout);
    if let Some(config_id) = opts.config_id.as_ref() {
        cmd.set_attribute("config_id", config_id.as_str());
    }
    if let Some(preferences_config_id) = opts.preferences_config_id.as_ref() {
        cmd.set_attribute("preferences_config_id", preferences_config_id.as_str());
    }
    if let Some(family) = opts.family.as_deref() {
        cmd.set_attribute("family", family);
    }
    if let Some(sort_order) = opts.sort_order.as_deref() {
        cmd.set_attribute("sort_order", sort_order);
    }
    if let Some(sort_field) = opts.sort_field.as_deref() {
        cmd.set_attribute("sort_field", sort_field);
    }
    cmd
}

/// Build a `get_nvts` request for scan-config scoped NVT listing.
#[must_use]
pub fn get_scan_config_nvts(opts: GetNvtsOpts) -> impl Request {
    get_nvts(opts)
}

/// Build a `get_nvts` request for a single NVT.
#[must_use]
pub fn get_nvt(nvt_oid: &str) -> impl Request {
    XmlCommand::new("get_nvts")
        .attribute("nvt_oid", nvt_oid)
        .attribute("details", "1")
}

/// Build a scan-config compatibility `get_nvts` request for a single NVT.
#[must_use]
pub fn get_scan_config_nvt(nvt_oid: &str) -> impl Request {
    XmlCommand::new("get_nvts")
        .attribute("nvt_oid", nvt_oid)
        .attribute("details", "1")
        .attribute("preferences", "1")
        .attribute("preference_count", "1")
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
            xml(get_scan_config_nvts(GetNvtsOpts {
                filter_string: Some("family=General".into()),
                filter_id: Some(id("f1")),
                details: Some(true),
                preferences: Some(true),
                preference_count: Some(false),
                timeout: Some(true),
                config_id: Some(id("c1")),
                preferences_config_id: Some(id("pc1")),
                family: Some("General".into()),
                sort_order: Some("ascending".into()),
                sort_field: Some("name".into()),
            })),
            "<get_nvts config_id=\"c1\" details=\"1\" family=\"General\" filt_id=\"f1\" filter=\"family=General\" preference_count=\"0\" preferences=\"1\" preferences_config_id=\"pc1\" sort_field=\"name\" sort_order=\"ascending\" timeout=\"1\"/>"
        );
        assert_eq!(
            xml(get_scan_config_nvt("1.3.6.1")),
            "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\" preference_count=\"1\" preferences=\"1\"/>"
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
