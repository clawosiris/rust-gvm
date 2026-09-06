// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Aggregate response models.

use gvm_protocol::Response;

use crate::responses::common::{
    parse_document, parse_u32, status_from_response, ParseError, XmlNode,
};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateText {
    pub column: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateStatisticValues {
    pub column: String,
    pub min: String,
    pub max: String,
    pub mean: String,
    pub sum: String,
    pub c_sum: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateColumnInfo {
    pub name: String,
    pub statistic: String,
    pub resource_type: String,
    pub column: String,
    pub data_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateFilterKeyword {
    pub column: String,
    pub relation: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateFilter {
    pub id: String,
    pub term: String,
    pub name: Option<String>,
    pub keywords: Vec<AggregateFilterKeyword>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateGroup {
    pub value: String,
    pub count: u32,
    pub c_count: Option<u32>,
    pub text: Option<String>,
    pub subgroups: Vec<AggregateSubgroup>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub statistics: Vec<AggregateStatisticValues>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub texts: Vec<AggregateText>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateSubgroup {
    pub value: String,
    pub count: u32,
    pub c_count: Option<u32>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub statistics: Vec<AggregateStatisticValues>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateStats {
    pub column: String,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub mean: Option<f64>,
    pub sum: Option<f64>,
    pub c_sum: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateOverall {
    pub count: u32,
    pub c_count: u32,
    pub statistics: Vec<AggregateStatisticValues>,
    pub texts: Vec<AggregateText>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateResult {
    pub data_type: String,
    pub data_columns: Vec<String>,
    pub group_column: Option<String>,
    pub subgroup_column: Option<String>,
    pub text_columns: Vec<String>,
    pub groups: Vec<AggregateGroup>,
    pub overall: Option<AggregateOverall>,
    pub subgroup_values: Vec<String>,
    pub column_info: Vec<AggregateColumnInfo>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAggregatesResponse {
    pub status: u16,
    pub status_text: String,
    #[cfg_attr(feature = "serde", serde(default))]
    pub aggregates: Vec<AggregateResult>,
    pub filter: Option<AggregateFilter>,
    /// Groups from the first aggregate, retained for API compatibility.
    pub groups: Vec<AggregateGroup>,
    /// Column names from the first aggregate, retained for API compatibility.
    pub column_info: Vec<String>,
    /// First numeric overall statistic, retained for API compatibility.
    pub overall: Option<AggregateStats>,
}

fn required_u32(node: &XmlNode, element: &str, field: &str) -> Result<u32, ParseError> {
    let value = node.required_child_text(element)?;
    parse_u32(&value, field)
}

fn statistic_values_from_node(node: &XmlNode) -> Result<AggregateStatisticValues, ParseError> {
    Ok(AggregateStatisticValues {
        column: node.attr("column").unwrap_or_default().to_string(),
        min: node.required_child_text("min")?,
        max: node.required_child_text("max")?,
        mean: node.required_child_text("mean")?,
        sum: node.required_child_text("sum")?,
        c_sum: node.required_child_text("c_sum")?,
    })
}

fn statistics_from_node(node: &XmlNode) -> Result<Vec<AggregateStatisticValues>, ParseError> {
    node.children_named("stats")
        .map(statistic_values_from_node)
        .collect()
}

fn texts_from_node(node: &XmlNode) -> Vec<AggregateText> {
    node.children_named("text")
        .map(|text| AggregateText {
            // Current gvmd emits `column`; the GMP schema historically named
            // this attribute `name`, so accept either spelling.
            column: text
                .attr("column")
                .or_else(|| text.attr("name"))
                .unwrap_or_default()
                .to_string(),
            value: text.text.clone(),
        })
        .collect()
}

impl AggregateGroup {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let value = node.required_child_text("value")?;
        let count = required_u32(node, "count", "aggregate.group.count")?;
        // Standard aggregates include c_count. gvmd's word_counts mode omits
        // it, despite the general response schema marking it as required.
        let c_count = node
            .optional_child_text("c_count")
            .map(|value| parse_u32(&value, "aggregate.group.c_count"))
            .transpose()?;
        let texts = texts_from_node(node);
        let text = texts.first().map(|text| text.value.clone());

        let subgroups = node
            .children_named("subgroup")
            .map(|subgroup| {
                Ok(AggregateSubgroup {
                    value: subgroup.required_child_text("value")?,
                    count: required_u32(subgroup, "count", "aggregate.group.subgroup.count")?,
                    c_count: Some(required_u32(
                        subgroup,
                        "c_count",
                        "aggregate.group.subgroup.c_count",
                    )?),
                    statistics: statistics_from_node(subgroup)?,
                })
            })
            .collect::<Result<Vec<_>, ParseError>>()?;

        Ok(Self {
            value,
            count,
            c_count,
            text,
            subgroups,
            statistics: statistics_from_node(node)?,
            texts,
        })
    }
}

impl AggregateResult {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let groups = node
            .children_named("group")
            .map(AggregateGroup::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        let overall = node
            .child("overall")
            .map(|overall| {
                Ok::<AggregateOverall, ParseError>(AggregateOverall {
                    count: required_u32(overall, "count", "aggregate.overall.count")?,
                    c_count: required_u32(overall, "c_count", "aggregate.overall.c_count")?,
                    statistics: statistics_from_node(overall)?,
                    texts: texts_from_node(overall),
                })
            })
            .transpose()?;
        let column_info_node = node
            .child("column_info")
            .ok_or_else(|| ParseError::MissingElement("column_info".to_string()))?;
        let column_info = column_info_node
            .children_named("aggregate_column")
            .map(|column| {
                Ok(AggregateColumnInfo {
                    name: column.required_child_text("name")?,
                    statistic: column.required_child_text("stat")?,
                    resource_type: column.required_child_text("type")?,
                    column: column.required_child_text("column")?,
                    data_type: column.required_child_text("data_type")?,
                })
            })
            .collect::<Result<Vec<_>, ParseError>>()?;

        Ok(Self {
            data_type: node.required_child_text("data_type")?,
            data_columns: node
                .children_named("data_column")
                .map(|column| column.text.clone())
                .collect(),
            group_column: node.optional_child_text("group_column"),
            subgroup_column: node.optional_child_text("subgroup_column"),
            text_columns: node
                .children_named("text_column")
                .map(|column| column.text.clone())
                .collect(),
            groups,
            overall,
            subgroup_values: node
                .child("subgroups")
                .map(|subgroups| {
                    subgroups
                        .children_named("value")
                        .map(|value| value.text.clone())
                        .collect()
                })
                .unwrap_or_default(),
            column_info,
        })
    }
}

fn filter_from_node(node: &XmlNode) -> Result<AggregateFilter, ParseError> {
    let keywords = node
        .child("keywords")
        .map(|keywords| {
            keywords
                .children_named("keyword")
                .map(|keyword| {
                    Ok(AggregateFilterKeyword {
                        column: keyword.required_child_text("column")?,
                        relation: keyword.required_child_text("relation")?,
                        value: keyword.required_child_text("value")?,
                    })
                })
                .collect::<Result<Vec<_>, ParseError>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(AggregateFilter {
        id: node.attr("id").unwrap_or_default().to_string(),
        term: node.required_child_text("term")?,
        name: node.optional_child_text("name"),
        keywords,
    })
}

fn legacy_stats(statistic: &AggregateStatisticValues) -> AggregateStats {
    AggregateStats {
        column: statistic.column.clone(),
        min: statistic.min.parse().ok(),
        max: statistic.max.parse().ok(),
        mean: statistic.mean.parse().ok(),
        sum: statistic.sum.parse().ok(),
        c_sum: statistic.c_sum.parse().ok(),
    }
}

impl GetAggregatesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let aggregates = root
            .children_named("aggregate")
            .map(AggregateResult::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        let groups = aggregates
            .first()
            .map(|aggregate| aggregate.groups.clone())
            .unwrap_or_default();
        let column_info = aggregates
            .first()
            .map(|aggregate| {
                aggregate
                    .column_info
                    .iter()
                    .map(|column| column.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let overall = aggregates
            .first()
            .and_then(|aggregate| aggregate.overall.as_ref())
            .and_then(|overall| overall.statistics.first())
            .map(legacy_stats);
        let filter = root.child("filters").map(filter_from_node).transpose()?;

        Ok(Self {
            status,
            status_text,
            aggregates,
            filter,
            groups,
            column_info,
            overall,
        })
    }
}

impl GmpResponse for GetAggregatesResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_aggregates_response() {
        let response = Response::from(
            r#"<get_aggregates_response status="200" status_text="OK">
                <aggregate>
                    <data_type>task</data_type>
                    <data_column>severity</data_column>
                    <group_column>status</group_column>
                    <column_info>
                        <aggregate_column>
                            <name>value</name><stat>value</stat><type>task</type>
                            <column>status</column><data_type>text</data_type>
                        </aggregate_column>
                    </column_info>
                    <group>
                        <value>High</value>
                        <count>5</count>
                        <c_count>5</c_count>
                        <stats column="severity">
                            <min>7.0</min><max>10.0</max><mean>8.5</mean>
                            <sum>42.5</sum><c_sum>42.5</c_sum>
                        </stats>
                        <text column="comment">urgent</text>
                    </group>
                    <group>
                        <value>Medium</value>
                        <count>10</count>
                        <c_count>15</c_count>
                    </group>
                </aggregate>
                <filters id="">
                    <term>rows=-1</term>
                    <keywords>
                        <keyword>
                            <column>rows</column><relation>=</relation><value>-1</value>
                        </keyword>
                    </keywords>
                </filters>
            </get_aggregates_response>"#,
        );

        let parsed = GetAggregatesResponse::from_response(&response).expect("parse aggregates");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.groups.len(), 2);
        assert_eq!(parsed.groups[0].value, "High");
        assert_eq!(parsed.groups[0].count, 5);
        assert_eq!(parsed.groups[1].c_count, Some(15));
        assert_eq!(parsed.groups[0].statistics[0].sum, "42.5");
        assert_eq!(parsed.groups[0].texts[0].column, "comment");
        assert_eq!(parsed.column_info, vec!["value".to_string()]);
        assert_eq!(parsed.aggregates[0].data_type, "task");
        assert_eq!(
            parsed.filter.as_ref().expect("filter metadata").keywords[0].value,
            "-1"
        );
    }

    #[test]
    fn parses_overall_and_multiple_aggregates() {
        let response = Response::from(
            r#"<get_aggregates_response status="200" status_text="OK">
                <aggregate>
                    <data_type>task</data_type>
                    <overall>
                        <count>3</count><c_count>3</c_count>
                        <stats column="severity">
                            <min>4</min><max>9</max><mean>6.5</mean>
                            <sum>19.5</sum><c_sum>19.5</c_sum>
                        </stats>
                    </overall>
                    <column_info/>
                </aggregate>
                <aggregate>
                    <data_type>result</data_type>
                    <column_info/>
                </aggregate>
            </get_aggregates_response>"#,
        );

        let parsed = GetAggregatesResponse::from_response(&response).expect("parse");

        assert!(parsed.groups.is_empty());
        assert_eq!(parsed.aggregates.len(), 2);
        assert_eq!(
            parsed.aggregates[0]
                .overall
                .as_ref()
                .expect("overall")
                .count,
            3
        );
        assert_eq!(
            parsed.overall.as_ref().expect("legacy overall").mean,
            Some(6.5)
        );
    }

    #[test]
    fn parses_subgroups_and_timestamp_statistics_without_numeric_loss() {
        let response = Response::from(
            r#"<get_aggregates_response status="200" status_text="OK">
                <aggregate>
                    <data_type>task</data_type>
                    <group_column>status</group_column>
                    <subgroup_column>creation_time</subgroup_column>
                    <group>
                        <value>Running</value>
                        <subgroup>
                            <value>2026-07-24T10:00:00Z</value>
                            <count>2</count><c_count>2</c_count>
                            <stats column="creation_time">
                                <min>2026-07-24T10:00:00Z</min>
                                <max>2026-07-24T11:00:00Z</max>
                                <mean>2026-07-24T10:30:00Z</mean>
                                <sum></sum><c_sum></c_sum>
                            </stats>
                        </subgroup>
                        <count>2</count><c_count>2</c_count>
                    </group>
                    <subgroups><value>2026-07-24T10:00:00Z</value></subgroups>
                    <column_info/>
                </aggregate>
            </get_aggregates_response>"#,
        );

        let parsed = GetAggregatesResponse::from_response(&response).expect("parse");
        let subgroup = &parsed.groups[0].subgroups[0];
        assert_eq!(subgroup.c_count, Some(2));
        assert_eq!(subgroup.statistics[0].min, "2026-07-24T10:00:00Z");
        assert_eq!(
            parsed.aggregates[0].subgroup_values,
            vec!["2026-07-24T10:00:00Z".to_string()]
        );
    }

    #[test]
    fn rejects_invalid_required_counts() {
        let response = Response::from(
            r#"<get_aggregates_response status="200" status_text="OK">
                <aggregate>
                    <data_type>task</data_type>
                    <group><value>Running</value><count>three</count><c_count>3</c_count></group>
                    <column_info/>
                </aggregate>
            </get_aggregates_response>"#,
        );

        let error = GetAggregatesResponse::from_response(&response).expect_err("invalid count");
        assert!(matches!(
            error,
            ParseError::InvalidValue { ref field, ref value }
                if field == "aggregate.group.count" && value == "three"
        ));

        let invalid_subgroup = Response::from(
            r#"<get_aggregates_response status="200" status_text="OK">
                <aggregate>
                    <data_type>task</data_type>
                    <group>
                        <value>Running</value>
                        <subgroup>
                            <value>Primary</value><count>3</count><c_count>three</c_count>
                        </subgroup>
                        <count>3</count><c_count>3</c_count>
                    </group>
                    <column_info/>
                </aggregate>
            </get_aggregates_response>"#,
        );

        let error = GetAggregatesResponse::from_response(&invalid_subgroup)
            .expect_err("invalid subgroup count");
        assert!(matches!(
            error,
            ParseError::InvalidValue { ref field, ref value }
                if field == "aggregate.group.subgroup.c_count" && value == "three"
        ));
    }

    #[test]
    fn parses_word_counts_without_cumulative_counts() {
        let response = Response::from(
            r#"<get_aggregates_response status="200" status_text="OK">
                <aggregate>
                    <data_type>task</data_type>
                    <group_column>comment</group_column>
                    <group><value>security</value><count>4</count></group>
                    <column_info>
                        <aggregate_column>
                            <name>value</name><stat>value</stat><type>task</type>
                            <column>comment</column><data_type>text</data_type>
                        </aggregate_column>
                    </column_info>
                </aggregate>
            </get_aggregates_response>"#,
        );

        let parsed = GetAggregatesResponse::from_response(&response).expect("word counts parse");
        assert_eq!(parsed.groups[0].value, "security");
        assert_eq!(parsed.groups[0].count, 4);
        assert_eq!(parsed.groups[0].c_count, None);
    }
}
