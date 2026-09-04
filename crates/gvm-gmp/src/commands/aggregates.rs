// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Aggregate command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::enums::SortOrder;
use crate::responses::GetAggregatesResponse;
use crate::types::EntityId;
use crate::GmpRequest;

/// Legacy options for `get_aggregates` requests.
///
/// This type preserves the original rust-gvm wire shape. New code should use
/// [`GetAggregatesRequestOpts`] with [`get_aggregates_request`] so repeated
/// columns and sort criteria use the current gvmd child-element form.
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

/// A statistic accepted by current gvmd aggregate sort criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AggregateSortStatistic {
    /// Sort by the minimum value.
    Minimum,
    /// Sort by the maximum value.
    Maximum,
    /// Sort by the arithmetic mean.
    Mean,
    /// Sort by the sum.
    Sum,
    /// Sort by the resource count.
    Count,
    /// Sort by the group value.
    Value,
}

impl AggregateSortStatistic {
    /// Return the current gvmd wire value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Minimum => "min",
            Self::Maximum => "max",
            Self::Mean => "mean",
            Self::Sum => "sum",
            Self::Count => "count",
            Self::Value => "value",
        }
    }
}

/// One current gvmd aggregate sort criterion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateSort {
    /// Aggregate field to sort by.
    pub field: String,
    /// Optional statistic for the selected field.
    pub statistic: Option<AggregateSortStatistic>,
    /// Optional sort direction.
    pub order: Option<SortOrder>,
}

/// Special aggregate processing modes supported by current gvmd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AggregateMode {
    /// Count words in the selected group column.
    WordCounts,
}

impl AggregateMode {
    /// Return the current gvmd wire value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::WordCounts => "word_counts",
        }
    }
}

/// Current gvmd options for [`get_aggregates_request`].
#[derive(Debug, Clone, Default)]
pub struct GetAggregatesRequestOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Columns whose numeric statistics should be returned.
    pub data_columns: Vec<String>,
    /// Optional group-by column.
    pub group_column: Option<String>,
    /// Optional subgroup column. Current gvmd requires `group_column` with it.
    pub subgroup_column: Option<String>,
    /// Ordered sort criteria.
    pub sorts: Vec<AggregateSort>,
    /// Columns returned as text without calculated statistics.
    pub text_columns: Vec<String>,
    /// One-based index of the first aggregate group to return.
    pub first_group: Option<u32>,
    /// Maximum groups to return. Use `-1` for all groups.
    pub max_groups: Option<i32>,
    /// Optional special processing mode.
    pub mode: Option<AggregateMode>,
    /// Optional task or config usage type.
    pub usage_type: Option<UsageType>,
}

/// Semantic request for current gvmd aggregate discovery.
#[derive(Debug, Clone)]
pub struct GetAggregatesRequest {
    resource_type: String,
    opts: GetAggregatesRequestOpts,
}

impl GetAggregatesRequest {
    /// Create a current aggregate-discovery request.
    #[must_use]
    pub fn new(resource_type: impl Into<String>, opts: GetAggregatesRequestOpts) -> Self {
        Self {
            resource_type: resource_type.into(),
            opts,
        }
    }
}

impl Request for GetAggregatesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_aggregates_request(&self.resource_type, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetAggregatesRequest {
    type Response = GetAggregatesResponse;
}

/// Semantic compatibility request for the legacy aggregate wire shape.
#[derive(Debug, Clone)]
pub struct GetLegacyAggregatesRequest {
    resource_type: String,
    opts: GetAggregatesOpts,
}

impl GetLegacyAggregatesRequest {
    /// Create a legacy aggregate-discovery request.
    #[must_use]
    pub fn new(resource_type: impl Into<String>, opts: GetAggregatesOpts) -> Self {
        Self {
            resource_type: resource_type.into(),
            opts,
        }
    }
}

impl Request for GetLegacyAggregatesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_aggregates(&self.resource_type, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetLegacyAggregatesRequest {
    type Response = GetAggregatesResponse;
}

/// Build a current gvmd `get_aggregates` request.
#[must_use]
pub fn get_aggregates_request(resource_type: &str, opts: GetAggregatesRequestOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_aggregates");
    cmd.set_attribute("type", resource_type);
    if let Some(filter) = opts.filter_string.as_deref() {
        cmd.set_attribute("filter", filter);
    }
    if let Some(filter_id) = opts.filter_id.as_ref() {
        cmd.set_attribute("filt_id", filter_id.as_str());
    }
    if let Some(group_column) = opts.group_column.as_deref() {
        cmd.set_attribute("group_column", group_column);
    }
    if let Some(subgroup_column) = opts.subgroup_column.as_deref() {
        cmd.set_attribute("subgroup_column", subgroup_column);
    }
    if let Some(first_group) = opts.first_group {
        cmd.set_attribute("first_group", &first_group.to_string());
    }
    if let Some(max_groups) = opts.max_groups {
        cmd.set_attribute("max_groups", &max_groups.to_string());
    }
    if let Some(mode) = opts.mode {
        cmd.set_attribute("mode", mode.as_gmp_str());
    }
    if let Some(usage_type) = opts.usage_type {
        cmd.set_attribute("usage_type", usage_type.as_gmp_str());
    }
    for sort in opts.sorts {
        let sort_element = cmd.add_element("sort");
        sort_element.set_attribute("field", &sort.field);
        if let Some(statistic) = sort.statistic {
            sort_element.set_attribute("stat", statistic.as_gmp_str());
        }
        if let Some(order) = sort.order {
            sort_element.set_attribute("order", order.as_gmp_str());
        }
    }
    for data_column in opts.data_columns {
        cmd.add_element("data_column").set_text(&data_column);
    }
    for text_column in opts.text_columns {
        cmd.add_element("text_column").set_text(&text_column);
    }
    cmd
}

/// Build a legacy rust-gvm `get_aggregates` request.
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
    use crate::commands::aggregates::{
        get_aggregates, get_aggregates_request, AggregateMode, AggregateSort,
        AggregateSortStatistic, GetAggregatesOpts, GetAggregatesRequestOpts,
    };
    use crate::commands::usage_type::UsageType;
    use crate::common::xml;
    use crate::enums::SortOrder;
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

    #[test]
    fn current_get_aggregates_builds_schema_faithful_xml() {
        assert_eq!(
            xml(get_aggregates_request(
                "task",
                GetAggregatesRequestOpts {
                    filter_string: Some("rows=10 & owner=me".into()),
                    filter_id: Some(EntityId::new("f1").expect("valid id")),
                    data_columns: vec!["severity".into(), "qod".into()],
                    group_column: Some("name".into()),
                    subgroup_column: Some("status".into()),
                    sorts: vec![
                        AggregateSort {
                            field: "severity".into(),
                            statistic: Some(AggregateSortStatistic::Maximum),
                            order: Some(SortOrder::Descending),
                        },
                        AggregateSort {
                            field: "name".into(),
                            statistic: Some(AggregateSortStatistic::Value),
                            order: Some(SortOrder::Ascending),
                        },
                    ],
                    text_columns: vec!["comment".into()],
                    first_group: Some(2),
                    max_groups: Some(-1),
                    mode: Some(AggregateMode::WordCounts),
                    usage_type: Some(UsageType::Audit),
                }
            )),
            "<get_aggregates filt_id=\"f1\" filter=\"rows=10 &amp; owner=me\" first_group=\"2\" group_column=\"name\" max_groups=\"-1\" mode=\"word_counts\" subgroup_column=\"status\" type=\"task\" usage_type=\"audit\"><sort field=\"severity\" order=\"descending\" stat=\"max\"/><sort field=\"name\" order=\"ascending\" stat=\"value\"/><data_column>severity</data_column><data_column>qod</data_column><text_column>comment</text_column></get_aggregates>"
        );
    }

    #[test]
    fn aggregate_sort_statistics_use_current_gvmd_wire_values() {
        assert_eq!(AggregateSortStatistic::Minimum.as_gmp_str(), "min");
        assert_eq!(AggregateSortStatistic::Maximum.as_gmp_str(), "max");
        assert_eq!(AggregateSortStatistic::Mean.as_gmp_str(), "mean");
        assert_eq!(AggregateSortStatistic::Sum.as_gmp_str(), "sum");
        assert_eq!(AggregateSortStatistic::Count.as_gmp_str(), "count");
        assert_eq!(AggregateSortStatistic::Value.as_gmp_str(), "value");
    }
}
