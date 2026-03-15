// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! System-level command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::add_filter_attrs;
use crate::enums::{AggregateStatistic, EntityType, FeedType, HelpFormat, InfoType, SortOrder};
use crate::types::EntityId;

/// Options for `get_aggregates` requests.
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
    pub resource_type: Option<EntityType>,
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

/// Build a `help` request.
pub fn help(format: Option<HelpFormat>) -> impl Request {
    let mut cmd = XmlCommand::new("help");
    if let Some(format) = format {
        cmd.set_attribute("format", format.as_gmp_str());
    }
    cmd
}

/// Build a `get_feeds` request.
pub fn get_feeds(opts: GetFeedsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_feeds");
    if let Some(feed_type) = opts.feed_type {
        cmd.set_attribute("type", feed_type.as_gmp_str());
    }
    cmd
}

/// Build a `get_settings` request.
pub fn get_settings(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_settings");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_aggregates` request.
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

/// Build a `get_system_reports` request.
pub fn get_system_reports(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_system_reports");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_info` request.
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

/// Build a `get_vulns` request.
pub fn get_vulns(opts: FilteredGetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_vulns");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    cmd
}

/// Build a `get_license` request.
pub fn get_license() -> impl Request {
    XmlCommand::new("get_license")
}

/// Build a `describe_auth` request.
pub fn describe_auth() -> impl Request {
    XmlCommand::new("describe_auth")
}

/// Build a `modify_auth` request.
pub fn modify_auth(enabled: bool) -> impl Request {
    XmlCommand::new("modify_auth").attribute("enabled", if enabled { "1" } else { "0" })
}

/// Build a `modify_license` request.
pub fn modify_license(key: &str) -> impl Request {
    XmlCommand::new("modify_license").child_with_text("key", key)
}

/// Build a `modify_setting` request.
pub fn modify_setting(setting_id: &EntityId, value: &str) -> impl Request {
    XmlCommand::new("modify_setting")
        .attribute("setting_id", setting_id.as_str())
        .child_with_text("value", value)
}

/// Build a `run_wizard` request.
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
    }

    #[test]
    fn system_filtered_mutation_commands_build_xml() {
        assert!(xml(get_settings(FilteredGetOpts {
            filter_id: Some(id("f1")),
            ..Default::default()
        }))
        .contains("filt_id=\"f1\""));
        assert!(xml(get_system_reports(FilteredGetOpts {
            filter_string: Some("name=foo".into()),
            ..Default::default()
        }))
        .contains("filter=\"name=foo\""));
        assert!(xml(get_info(GetInfoOpts {
            info_type: Some(InfoType::Nvt),
            info_id: Some(id("i1")),
            ..Default::default()
        }))
        .contains("type=\"NVT\""));
        assert!(xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(EntityType::Task),
            resource_id: Some(id("t1")),
            ..Default::default()
        }))
        .contains("resource_id=\"t1\""));
        assert_eq!(xml(modify_auth(true)), "<modify_auth enabled=\"1\"/>");
        assert_eq!(
            xml(modify_license("abc")),
            "<modify_license><key>abc</key></modify_license>"
        );
        assert_eq!(
            xml(modify_setting(&id("s1"), "v")),
            "<modify_setting setting_id=\"s1\"><value>v</value></modify_setting>"
        );
        let rendered = xml(run_wizard("quick", &[("target".into(), "10.0.0.1".into())]));
        assert!(rendered.contains("<param name=\"target\">10.0.0.1</param>"));
    }
}
