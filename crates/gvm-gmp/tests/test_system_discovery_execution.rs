// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::aggregates::{
    get_aggregates as get_legacy_aggregates, get_aggregates_request, GetAggregatesOpts,
    GetAggregatesRequest, GetAggregatesRequestOpts, GetLegacyAggregatesRequest,
};
use gvm_gmp::commands::features::{get_features, GetFeaturesRequest};
use gvm_gmp::commands::feed::{get_feed, get_feeds, GetFeedRequest, GetFeedsRequest};
use gvm_gmp::commands::help::{
    help as help_command, help_with_mode, HelpFormat as CommandHelpFormat, HelpMode, HelpRequest,
    HelpWithModeRequest,
};
use gvm_gmp::commands::system::{
    describe_auth, get_aggregates, get_feeds as get_system_feeds, get_info, get_license,
    get_preferences, get_resource_name, get_resource_names, get_settings, get_timezones, get_vuln,
    get_vulnerability, get_vulns, DescribeAuthRequest, FilteredGetOpts,
    GetAggregatesOpts as SystemAggregatesOpts, GetInfoOpts, GetLicenseRequest,
    GetResourceNameRequest, GetResourceNamesOpts, GetResourceNamesRequest, GetSettingsRequest,
    GetSystemAggregatesRequest, GetSystemFeedsRequest, GetSystemInfoRequest,
    GetSystemPreferencesRequest, GetTimezonesRequest, GetVulnRequest, GetVulnerabilityRequest,
    GetVulnsRequest, SystemHelpRequest,
};
use gvm_gmp::commands::system_reports::{
    get_system_reports, GetSystemReportsOpts, GetSystemReportsRequest,
};
use gvm_gmp::responses::{
    ActionResponse, DescribeAuthResponse, GetAggregatesResponse, GetFeaturesResponse,
    GetFeedsResponse, GetInfoResponse, GetResourceNamesResponse, GetScanConfigPreferencesResponse,
    GetSettingsResponse, GetSystemReportsResponse, GetTimezonesResponse,
    GetVulnerabilitiesResponse, HelpResponse,
};
use gvm_gmp::{FeedType, GmpRequest, GmpResponse, HelpFormat, InfoType, ResourceType};
use gvm_protocol::Request;

fn assert_associated<R, T>(_: &R)
where
    R: GmpRequest<Response = T>,
    T: GmpResponse,
{
}

macro_rules! assert_request {
    ($request:expr, $builder:expr, $response:ty) => {{
        let request = $request;
        assert_eq!(request.to_bytes(), $builder.to_bytes());
        assert_associated::<_, $response>(&request);
    }};
}

fn id(value: &str) -> gvm_gmp::EntityId {
    gvm_gmp::EntityId::new(value).expect("valid test id")
}

fn assert_discovery_requests() {
    let aggregate_opts = GetAggregatesRequestOpts {
        filter_string: Some("rows=5".into()),
        data_columns: vec!["severity".into()],
        group_column: Some("status".into()),
        ..Default::default()
    };
    assert_request!(
        GetAggregatesRequest::new("task", aggregate_opts.clone()),
        get_aggregates_request("task", aggregate_opts),
        GetAggregatesResponse
    );

    let legacy_aggregate_opts = GetAggregatesOpts {
        group_column: Some("status".into()),
        filter: Some("rows=5".into()),
        ..Default::default()
    };
    assert_request!(
        GetLegacyAggregatesRequest::new("task", legacy_aggregate_opts.clone()),
        get_legacy_aggregates("task", legacy_aggregate_opts),
        GetAggregatesResponse
    );

    assert_request!(
        GetFeaturesRequest::new(),
        get_features(),
        GetFeaturesResponse
    );
    assert_request!(GetFeedsRequest::new(), get_feeds(), GetFeedsResponse);
    assert_request!(
        GetFeedRequest::new(FeedType::Nvt),
        get_feed(FeedType::Nvt),
        GetFeedsResponse
    );
    assert_request!(
        HelpRequest::new(Some(CommandHelpFormat::Brief)),
        help_command(Some(CommandHelpFormat::Brief)),
        HelpResponse
    );
    assert_request!(
        HelpWithModeRequest::new(HelpMode::Schema(HelpFormat::Rnc)),
        help_with_mode(HelpMode::Schema(HelpFormat::Rnc)),
        HelpResponse
    );

    let report_opts = GetSystemReportsOpts {
        name: Some("load".into()),
        brief: Some(true),
        ..Default::default()
    };
    assert_request!(
        GetSystemReportsRequest::new(report_opts.clone()),
        get_system_reports(report_opts),
        GetSystemReportsResponse
    );
}

fn assert_system_inventory_requests() {
    assert_request!(
        SystemHelpRequest::new(Some(HelpFormat::Xml)),
        gvm_gmp::commands::system::help(Some(HelpFormat::Xml)),
        HelpResponse
    );

    let system_feed_opts = gvm_gmp::commands::system::GetFeedsOpts {
        feed_type: Some(FeedType::Scap),
    };
    assert_request!(
        GetSystemFeedsRequest::new(system_feed_opts.clone()),
        get_system_feeds(system_feed_opts),
        GetFeedsResponse
    );

    let filtered = FilteredGetOpts {
        filter_string: Some("name=example".into()),
        filter_id: Some(id("filter-1")),
    };
    assert_request!(
        GetSettingsRequest::new(filtered.clone()),
        get_settings(filtered.clone()),
        GetSettingsResponse
    );
    assert_request!(
        GetTimezonesRequest::new(),
        get_timezones(),
        GetTimezonesResponse
    );

    let system_aggregate_opts = SystemAggregatesOpts {
        data_column: Some("severity".into()),
        group_column: Some("task_id".into()),
        filter_string: Some("rows=5".into()),
        ..Default::default()
    };
    assert_request!(
        GetSystemAggregatesRequest::new(system_aggregate_opts.clone()),
        get_aggregates(system_aggregate_opts),
        GetAggregatesResponse
    );

    let info_opts = GetInfoOpts {
        info_type: Some(InfoType::Cve),
        info_id: Some(id("CVE-2026-0001")),
        filter_string: Some("rows=1".into()),
        ..Default::default()
    };
    assert_request!(
        GetSystemInfoRequest::new(info_opts.clone()),
        get_info(info_opts),
        GetInfoResponse
    );
    assert_request!(
        GetSystemPreferencesRequest::new(filtered.clone()),
        get_preferences(filtered.clone()),
        GetScanConfigPreferencesResponse
    );
}

fn assert_system_resource_requests() {
    let filtered = FilteredGetOpts {
        filter_string: Some("name=example".into()),
        filter_id: Some(id("filter-1")),
    };
    let resource_opts = GetResourceNamesOpts {
        resource_type: Some(ResourceType::Task),
        resource_id: Some(id("task-1")),
        filter_string: Some("name=example".into()),
        ..Default::default()
    };
    assert_request!(
        GetResourceNamesRequest::new(resource_opts.clone()),
        get_resource_names(resource_opts),
        GetResourceNamesResponse
    );
    assert_request!(
        GetResourceNameRequest::new(id("task-1"), ResourceType::Task),
        get_resource_name(&id("task-1"), ResourceType::Task),
        GetResourceNamesResponse
    );

    assert_request!(
        GetVulnsRequest::new(filtered.clone()),
        get_vulns(filtered),
        GetVulnerabilitiesResponse
    );
    assert_request!(
        GetVulnRequest::new("vuln-1"),
        get_vuln("vuln-1"),
        GetVulnerabilitiesResponse
    );
    assert_request!(
        GetVulnerabilityRequest::new("vuln-1"),
        get_vulnerability("vuln-1"),
        GetVulnerabilitiesResponse
    );
    assert_eq!(
        GetVulnRequest::new("vuln-1").to_bytes(),
        GetVulnerabilityRequest::new("vuln-1").to_bytes()
    );

    assert_request!(GetLicenseRequest::new(), get_license(), ActionResponse);
    assert_request!(
        DescribeAuthRequest::new(),
        describe_auth(),
        DescribeAuthResponse
    );
}

#[test]
fn all_twenty_two_semantic_requests_preserve_builder_bytes_and_responses() {
    assert_discovery_requests();
    assert_system_inventory_requests();
    assert_system_resource_requests();
}
