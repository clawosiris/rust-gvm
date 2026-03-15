// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::filters::*;
use gvm_gmp::{FilterType, SortOrder};

#[test]
fn test_create_filter_basic() {
    assert_eq!(
        xml(create_filter("f", Default::default())),
        "<create_filter><name>f</name></create_filter>"
    );
}

#[test]
fn test_create_filter_with_optionals() {
    assert_eq!(
        xml(create_filter(
            "f",
            FilterOpts {
                comment: Some("c".into()),
                term: Some("rows=10".into()),
                filter_type: Some(FilterType::Task),
                sort_order: Some(SortOrder::Ascending),
            }
        )),
        "<create_filter><name>f</name><comment>c</comment><term>rows=10</term><type>task</type><sort_order>ascending</sort_order></create_filter>"
    );
}

#[test]
fn test_filter_get_modify_delete() {
    assert_eq!(
        xml(clone_filter(&id("f1"))),
        "<create_filter><copy>f1</copy></create_filter>"
    );
    assert_eq!(
        xml(get_filter(&id("f1"))),
        "<get_filters details=\"1\" filter_id=\"f1\"/>"
    );
    assert_eq!(
        xml(delete_filter(&id("f1"), false)),
        "<delete_filter filter_id=\"f1\" ultimate=\"0\"/>"
    );
}
