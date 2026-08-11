// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::system::*;
use gvm_gmp::{AggregateStatistic, FeedType, HelpFormat, InfoType, ResourceType, SortOrder};

#[test]
fn test_system_help_and_feeds() {
    assert_eq!(xml(help(None)), "<help/>");
    assert_eq!(xml(help(Some(HelpFormat::Xml))), "<help format=\"xml\"/>");
    assert_eq!(
        xml(get_feeds(GetFeedsOpts {
            feed_type: Some(FeedType::Nvt)
        })),
        "<get_feeds type=\"NVT\"/>"
    );
}

#[test]
fn test_system_filtered_getters() {
    assert_eq!(xml(get_settings(Default::default())), "<get_settings/>");
    assert_eq!(
        xml(get_system_reports(GetSystemReportsOpts {
            name: Some("load".into()),
            brief: Some(true),
            ..Default::default()
        })),
        "<get_system_reports brief=\"1\" name=\"load\"/>"
    );
    assert_eq!(
        xml(get_preferences(FilteredGetOpts {
            filter_string: Some("foo=bar".into()),
            filter_id: None
        })),
        "<get_preferences filter=\"foo=bar\"/>"
    );
    assert_eq!(
        xml(get_vulns(FilteredGetOpts {
            filter_string: Some("qod>0".into()),
            filter_id: Some(id("f2"))
        })),
        "<get_vulns filt_id=\"f2\" filter=\"qod&gt;0\"/>"
    );
}

#[test]
fn test_system_aggregates_info_resource_names_and_mutations() {
    assert_eq!(
        xml(get_aggregates(GetAggregatesOpts {
            data_column: Some("severity".into()),
            group_column: Some("task_id".into()),
            statistic: Some(AggregateStatistic::Count),
            sort_field: Some("severity".into()),
            sort_order: Some(SortOrder::Descending),
            filter_string: Some("rows=10".into()),
            filter_id: Some(id("f1")),
        })),
        "<get_aggregates data_column=\"severity\" filt_id=\"f1\" filter=\"rows=10\" group_column=\"task_id\" sort_field=\"severity\" sort_order=\"descending\" statistic=\"count\"/>"
    );
    assert_eq!(
        xml(get_info(GetInfoOpts {
            info_type: Some(InfoType::Nvt),
            info_id: Some(id("i1")),
            filter_string: Some("family=foo".into()),
            filter_id: Some(id("f1"))
        })),
        "<get_info filt_id=\"f1\" filter=\"family=foo\" info_id=\"i1\" type=\"NVT\"/>"
    );
    assert_eq!(
        xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(ResourceType::Task),
            resource_id: Some(id("t1")),
            filter_string: None,
            filter_id: None
        })),
        "<get_resource_names resource_id=\"t1\" type=\"TASK\"/>"
    );
    assert_eq!(xml(get_license()), "<get_license/>");
    assert_eq!(xml(describe_auth()), "<describe_auth/>");
    assert_eq!(
        xml(modify_auth(
            "method:ldap_connect",
            &[
                ("enable".into(), "true".into()),
                ("ldaphost".into(), "ldap.example".into()),
            ]
        )),
        "<modify_auth><group name=\"method:ldap_connect\"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting><auth_conf_setting><key>ldaphost</key><value>ldap.example</value></auth_conf_setting></group></modify_auth>"
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
    assert_eq!(xml(run_wizard("quick", &[("target".into(), "10.0.0.1".into()), ("ports".into(), "T:1-5".into())])), "<run_wizard name=\"quick\"><param name=\"target\">10.0.0.1</param><param name=\"ports\">T:1-5</param></run_wizard>");
}
