// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Aggregate command builders.

use gvm_protocol::XmlCommand;

use crate::types::EntityId;

/// Options for `get_aggregates` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAggregatesOpts {
    /// Optional group-by column.
    pub group_column: Option<String>,
    /// Optional sort criteria expression.
    pub sort_criteria: Option<String>,
    /// Optional comma-separated data columns.
    pub data_columns: Option<String>,
    /// Optional inline filter expression.
    pub filter: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Optional comma-separated text columns.
    pub text_columns: Option<String>,
    /// Optional first group offset.
    pub first_group: Option<u32>,
    /// Optional maximum number of groups.
    pub max_groups: Option<u32>,
    /// Optional aggregate mode.
    pub mode: Option<String>,
}

/// Build a `get_aggregates` request.
#[must_use]
pub fn get_aggregates(resource_type: &str, opts: GetAggregatesOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_aggregates");
    cmd.set_attribute("type", resource_type);
    if let Some(group_column) = opts.group_column.as_deref() {
        cmd.set_attribute("group_column", group_column);
    }
    if let Some(sort_criteria) = opts.sort_criteria.as_deref() {
        cmd.set_attribute("sort_criteria", sort_criteria);
    }
    if let Some(data_columns) = opts.data_columns.as_deref() {
        cmd.set_attribute("data_columns", data_columns);
    }
    if let Some(filter) = opts.filter.as_deref() {
        cmd.set_attribute("filter", filter);
    }
    if let Some(filter_id) = opts.filter_id.as_ref() {
        cmd.set_attribute("filt_id", filter_id.as_str());
    }
    if let Some(text_columns) = opts.text_columns.as_deref() {
        cmd.set_attribute("text_columns", text_columns);
    }
    if let Some(first_group) = opts.first_group {
        cmd.set_attribute("first_group", &first_group.to_string());
    }
    if let Some(max_groups) = opts.max_groups {
        cmd.set_attribute("max_groups", &max_groups.to_string());
    }
    if let Some(mode) = opts.mode.as_deref() {
        cmd.set_attribute("mode", mode);
    }
    cmd
}

#[cfg(test)]
mod tests {
    use crate::commands::aggregates::{get_aggregates, GetAggregatesOpts};
    use crate::common::xml;
    use crate::types::EntityId;

    #[test]
    fn get_aggregates_builds_xml() {
        assert_eq!(
            xml(get_aggregates(
                "task",
                GetAggregatesOpts {
                    group_column: Some("severity".into()),
                    sort_criteria: Some("value desc".into()),
                    data_columns: Some("value,count".into()),
                    filter: Some("rows=10".into()),
                    filter_id: Some(EntityId::new("f1").expect("valid id")),
                    text_columns: Some("name".into()),
                    first_group: Some(2),
                    max_groups: Some(5),
                    mode: Some("dynamic".into()),
                }
            )),
            "<get_aggregates data_columns=\"value,count\" filt_id=\"f1\" filter=\"rows=10\" first_group=\"2\" group_column=\"severity\" max_groups=\"5\" mode=\"dynamic\" sort_criteria=\"value desc\" text_columns=\"name\" type=\"task\"/>"
        );
    }
}
