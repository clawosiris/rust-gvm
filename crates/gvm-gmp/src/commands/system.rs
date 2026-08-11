// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-level command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::user_settings::{modify_user_setting, ModifyUserSettingOpts};
use crate::common::add_filter_attrs;
use crate::enums::{AggregateStatistic, FeedType, HelpFormat, InfoType, ResourceType, SortOrder};
use crate::types::EntityId;

pub use super::system_reports::{get_system_reports, GetSystemReportsOpts};

/// Legacy system-module options for `get_aggregates` requests.
///
/// This type and [`get_aggregates`] are retained for source compatibility.
/// They predate current gvmd's required aggregate resource type. New code
/// should use [`crate::commands::aggregates::get_aggregates_request`].
#[derive(Debug, Clone, Default)]
pub struct GetAggregatesOpts {
    /// Optional aggregate data column.
    pub data_column: Option<String>,
    /// Optional aggregate group-by column.
    pub group_column: Option<String>,
    /// Optional aggregate statistic.
    pub statistic: Option<AggregateStatistic>,
    /// Optional aggregate sort field.
    pub sort_field: Option<String>,
    /// Optional sort order.
    pub sort_order: Option<SortOrder>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `get_feeds` requests.
#[derive(Debug, Clone, Default)]
pub struct GetFeedsOpts {
    /// Optional feed type.
    pub feed_type: Option<FeedType>,
}

/// Options for `get_info` requests.
#[derive(Debug, Clone, Default)]
pub struct GetInfoOpts {
    /// Optional info type.
    pub info_type: Option<InfoType>,
    /// Optional info object identifier.
    pub info_id: Option<EntityId>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `get_resource_names` requests.
#[derive(Debug, Clone, Default)]
pub struct GetResourceNamesOpts {
    /// Optional related resource type.
    pub resource_type: Option<ResourceType>,
    /// Optional related resource identifier.
    pub resource_id: Option<EntityId>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Shared filter options for simple getter requests.
#[derive(Debug, Clone, Default)]
pub struct FilteredGetOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

/// Options for `modify_license` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyLicenseOpts {
    /// Whether gvmd may accept an empty license file.
    pub allow_empty: Option<bool>,
}

/// Build a `help` request.
#[must_use]
pub fn help(format: Option<HelpFormat>) -> impl Request {
    match format {
        Some(format) => {
            crate::commands::help::help_with_mode(crate::commands::help::HelpMode::Schema(format))
        }
        None => crate::commands::help::help_with_mode(crate::commands::help::HelpMode::Text),
    }
}

/// Build a `get_feeds` request.
#[must_use]
pub fn get_feeds(opts: GetFeedsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_feeds");
    if let Some(feed_type) = opts.feed_type {
        cmd.set_attribute("type", feed_type.as_gmp_str());
    }
    cmd
}

/// Build a `get_settings` request.
#[must_use]
pub fn get_settings(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_settings");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_timezones` request.
#[must_use]
pub fn get_timezones() -> impl Request {
    XmlCommand::new("get_timezones")
}

/// Build a legacy system-module `get_aggregates` request.
///
/// New code should use
/// [`crate::commands::aggregates::get_aggregates_request`], which includes the
/// required resource type and models repeated sort and column elements.
#[must_use]
pub fn get_aggregates(opts: GetAggregatesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_aggregates");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(data_column) = opts.data_column.as_deref() {
        cmd.set_attribute("data_column", data_column);
    }
    if let Some(group_column) = opts.group_column.as_deref() {
        cmd.set_attribute("group_column", group_column);
    }
    if let Some(statistic) = opts.statistic {
        cmd.set_attribute("statistic", statistic.as_gmp_str());
    }
    if let Some(sort_field) = opts.sort_field.as_deref() {
        cmd.set_attribute("sort_field", sort_field);
    }
    if let Some(sort_order) = opts.sort_order {
        cmd.set_attribute("sort_order", sort_order.as_gmp_str());
    }
    cmd
}

/// Build a `get_info` request.
#[must_use]
pub fn get_info(opts: GetInfoOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_info");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(info_type) = opts.info_type {
        cmd.set_attribute("type", info_type.as_gmp_str());
    }
    if let Some(info_id) = opts.info_id.as_ref() {
        cmd.set_attribute("info_id", info_id.as_str());
    }
    cmd
}

/// Build a `get_preferences` request.
#[must_use]
pub fn get_preferences(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_preferences");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_resource_names` request.
#[must_use]
pub fn get_resource_names(opts: GetResourceNamesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_resource_names");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    if let Some(resource_type) = opts.resource_type {
        cmd.set_attribute("type", resource_type.as_gmp_str());
    }
    if let Some(resource_id) = opts.resource_id.as_ref() {
        cmd.set_attribute("resource_id", resource_id.as_str());
    }
    cmd
}

/// Build a `get_resource_names` request for a single resource.
#[must_use]
pub fn get_resource_name(resource_id: &EntityId, resource_type: ResourceType) -> impl Request {
    let mut cmd = XmlCommand::new("get_resource_names");
    cmd.set_attribute("resource_id", resource_id.as_str());
    cmd.set_attribute("type", resource_type.as_gmp_str());
    cmd
}

/// Build a `get_vulns` request.
#[must_use]
pub fn get_vulns(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_vulns");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_vulns` request for a single vulnerability entry.
#[must_use]
pub fn get_vuln(vuln_id: &str) -> impl Request {
    XmlCommand::new("get_vulns").attribute("vuln_id", vuln_id)
}

/// Build a `get_vulns` request using python-gvm's descriptive helper name.
#[must_use]
pub fn get_vulnerability(vulnerability_id: &str) -> impl Request {
    get_vuln(vulnerability_id)
}

/// Build a `get_license` request.
#[must_use]
pub fn get_license() -> impl Request {
    XmlCommand::new("get_license")
}

/// Build a `describe_auth` request.
#[must_use]
pub fn describe_auth() -> impl Request {
    XmlCommand::new("describe_auth")
}

/// Build a `modify_auth` request for a named authentication group.
///
/// `auth_conf_settings` must contain at least one key/value pair. Current gvmd
/// accepts a group containing authentication configuration settings; the old
/// `enabled` root attribute is not part of the command contract.
#[must_use]
pub fn modify_auth(group_name: &str, auth_conf_settings: &[(String, String)]) -> impl Request {
    let mut cmd = XmlCommand::new("modify_auth");
    let group = cmd.add_element("group");
    group.set_attribute("name", group_name);
    for (key, value) in auth_conf_settings {
        let setting = group.add_child("auth_conf_setting");
        setting.add_child_with_text("key", key);
        setting.add_child_with_text("value", value);
    }
    cmd
}

/// Build a `modify_license` request with a base64-encoded license file.
#[must_use]
pub fn modify_license(file: &str) -> impl Request {
    modify_license_with_opts(file, ModifyLicenseOpts::default())
}

/// Build a `modify_license` request with explicit options.
#[must_use]
pub fn modify_license_with_opts(file: &str, opts: ModifyLicenseOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_license");
    if let Some(allow_empty) = opts.allow_empty {
        cmd.set_attribute("allow_empty", if allow_empty { "1" } else { "0" });
    }
    cmd.add_element_with_text("file", file);
    cmd
}

/// Build a `modify_setting` request, Base64-encoding the UTF-8 value for GMP.
#[must_use]
pub fn modify_setting(setting_id: &EntityId, value: &str) -> impl Request {
    modify_user_setting(
        setting_id,
        ModifyUserSettingOpts {
            value: value.to_string(),
        },
    )
}

/// Build a `run_wizard` request.
#[must_use]
pub fn run_wizard(name: &str, params: &[(String, String)]) -> impl Request {
    let mut cmd = XmlCommand::new("run_wizard").attribute("name", name);
    for (key, value) in params {
        let param = cmd.add_element("param");
        param.set_attribute("name", key);
        param.set_text(value);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn system_commands_build_xml() {
        assert_eq!(xml(help(Some(HelpFormat::Xml))), "<help format=\"xml\"/>");
        assert_eq!(
            xml(get_feeds(GetFeedsOpts {
                feed_type: Some(FeedType::Nvt)
            })),
            "<get_feeds type=\"NVT\"/>"
        );
        let rendered = xml(get_aggregates(GetAggregatesOpts {
            data_column: Some("severity".into()),
            statistic: Some(AggregateStatistic::Count),
            sort_order: Some(SortOrder::Descending),
            ..Default::default()
        }));
        assert!(rendered.contains("data_column=\"severity\""));
        assert!(rendered.contains("statistic=\"count\""));
        assert_eq!(xml(get_license()), "<get_license/>");
        assert_eq!(xml(describe_auth()), "<describe_auth/>");
        assert_eq!(xml(get_timezones()), "<get_timezones/>");
    }

    #[test]
    fn system_filtered_mutation_commands_build_xml() {
        assert!(xml(get_settings(FilteredGetOpts {
            filter_id: Some(id("f1")),
            ..Default::default()
        }))
        .contains("filt_id=\"f1\""));
        assert!(xml(get_system_reports(GetSystemReportsOpts {
            name: Some("load".into()),
            ..Default::default()
        }))
        .contains("name=\"load\""));
        assert!(xml(get_info(GetInfoOpts {
            info_type: Some(InfoType::Nvt),
            info_id: Some(id("i1")),
            ..Default::default()
        }))
        .contains("type=\"NVT\""));
        assert!(xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(ResourceType::Task),
            resource_id: Some(id("t1")),
            ..Default::default()
        }))
        .contains("resource_id=\"t1\""));
        assert_eq!(
            xml(get_vulns(FilteredGetOpts {
                filter_string: Some("severity>5".into()),
                filter_id: Some(id("filter-1")),
            })),
            "<get_vulns filt_id=\"filter-1\" filter=\"severity&gt;5\"/>"
        );
        assert_eq!(xml(get_vuln("vuln-1")), "<get_vulns vuln_id=\"vuln-1\"/>");
        assert_eq!(
            xml(get_vulnerability("vuln-1")),
            "<get_vulns vuln_id=\"vuln-1\"/>"
        );
        assert_eq!(
            xml(modify_auth(
                "method:ldap_connect",
                &[("enable".into(), "true".into())]
            )),
            "<modify_auth><group name=\"method:ldap_connect\"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting></group></modify_auth>"
        );
        assert_eq!(
            xml(modify_license("abc")),
            "<modify_license><file>abc</file></modify_license>"
        );
        assert_eq!(
            xml(modify_license_with_opts(
                "",
                ModifyLicenseOpts {
                    allow_empty: Some(true)
                }
            )),
            "<modify_license allow_empty=\"1\"><file></file></modify_license>"
        );
        assert_eq!(
            xml(modify_setting(&id("s1"), "Europe/Berlin")),
            "<modify_setting setting_id=\"s1\"><value>RXVyb3BlL0Jlcmxpbg==</value></modify_setting>"
        );
        let rendered = xml(run_wizard("quick", &[("target".into(), "10.0.0.1".into())]));
        assert!(rendered.contains("<param name=\"target\">10.0.0.1</param>"));
    }
}
