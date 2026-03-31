// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Aggregate response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError, XmlNode};

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateGroup {
    pub value: String,
    pub count: u32,
    pub c_count: Option<u32>,
    pub text: Option<String>,
    pub subgroups: Vec<AggregateSubgroup>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AggregateSubgroup {
    pub value: String,
    pub count: u32,
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
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetAggregatesResponse {
    pub status: u16,
    pub status_text: String,
    pub groups: Vec<AggregateGroup>,
    pub column_info: Vec<String>,
    pub overall: Option<AggregateStats>,
}

impl AggregateGroup {
    fn from_node(node: &XmlNode) -> Result<Self, ParseError> {
        let value = node.child_text("value").unwrap_or_default();
        let count = node
            .child_text("count")
            .and_then(|text| text.parse().ok())
            .unwrap_or(0);
        let c_count = node
            .child_text("c_count")
            .and_then(|text| text.parse().ok());
        let text = node.optional_child_text("text");

        let subgroups = node
            .children_named("subgroup")
            .filter_map(|subgroup| {
                let sub_value = subgroup.child_text("value")?;
                let sub_count = subgroup
                    .child_text("count")
                    .and_then(|text| text.parse().ok())
                    .unwrap_or(0);
                Some(AggregateSubgroup {
                    value: sub_value,
                    count: sub_count,
                })
            })
            .collect();

        Ok(Self {
            value,
            count,
            c_count,
            text,
            subgroups,
        })
    }
}

impl GetAggregatesResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;

        let aggregate = root.child("aggregate");
        let groups = aggregate
            .map(|agg| {
                agg.children_named("group")
                    .map(AggregateGroup::from_node)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();

        let column_info = aggregate
            .and_then(|agg| agg.child("column_info"))
            .map(|col_info| {
                col_info
                    .children_named("aggregate_column")
                    .filter_map(|col| col.child_text("name"))
                    .collect()
            })
            .unwrap_or_default();

        let overall = aggregate
            .and_then(|agg| agg.child("overall"))
            .map(|o| AggregateStats {
                column: o.child_text("column").unwrap_or_default(),
                min: o.child_text("min").and_then(|t| t.parse().ok()),
                max: o.child_text("max").and_then(|t| t.parse().ok()),
                mean: o.child_text("mean").and_then(|t| t.parse().ok()),
                sum: o.child_text("sum").and_then(|t| t.parse().ok()),
            });

        Ok(Self {
            status,
            status_text,
            groups,
            column_info,
            overall,
        })
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
                    <column_info>
                        <aggregate_column><name>severity</name></aggregate_column>
                    </column_info>
                    <group>
                        <value>High</value>
                        <count>5</count>
                        <c_count>5</c_count>
                    </group>
                    <group>
                        <value>Medium</value>
                        <count>10</count>
                        <c_count>15</c_count>
                    </group>
                </aggregate>
            </get_aggregates_response>"#,
        );

        let parsed = GetAggregatesResponse::from_response(&response).expect("parse aggregates");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.groups.len(), 2);
        assert_eq!(parsed.groups[0].value, "High");
        assert_eq!(parsed.groups[0].count, 5);
        assert_eq!(parsed.groups[1].c_count, Some(15));
        assert_eq!(parsed.column_info, vec!["severity".to_string()]);
    }

    #[test]
    fn parses_empty_aggregates() {
        let response = Response::from(
            r#"<get_aggregates_response status="200" status_text="OK">
                <aggregate/>
            </get_aggregates_response>"#,
        );

        let parsed = GetAggregatesResponse::from_response(&response).expect("parse");

        assert!(parsed.groups.is_empty());
    }
}
