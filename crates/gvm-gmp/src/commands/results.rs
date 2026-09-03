// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Result command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::GetResultsResponse;
use crate::types::EntityId;
use crate::GmpRequest;

/// Options for `get_results` requests.
#[derive(Debug, Clone, Default)]
pub struct GetResultsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing scan results.
#[derive(Debug, Clone)]
pub struct GetResultsRequest {
    opts: GetResultsOpts,
}

impl GetResultsRequest {
    /// Create a result-list request.
    #[must_use]
    pub fn new(opts: GetResultsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetResultsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_results(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetResultsRequest {
    type Response = GetResultsResponse;
}

/// Semantic request for retrieving one scan result.
#[derive(Debug, Clone)]
pub struct GetResultRequest {
    result_id: EntityId,
}

impl GetResultRequest {
    /// Create a single-result request.
    #[must_use]
    pub fn new(result_id: EntityId) -> Self {
        Self { result_id }
    }
}

impl Request for GetResultRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_result(&self.result_id).to_bytes()
    }
}

impl GmpRequest for GetResultRequest {
    type Response = GetResultsResponse;
}

/// Build a `get_results` request.
#[must_use]
pub fn get_results(opts: GetResultsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_results");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_result` request.
#[must_use]
pub fn get_result(result_id: &EntityId) -> impl Request {
    XmlCommand::new("get_results")
        .attribute("result_id", result_id.as_str())
        .attribute("details", "1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn result_commands_build_xml() {
        let rendered = xml(get_results(GetResultsOpts {
            filter_string: Some("severity>5".into()),
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("filter=\"severity&gt;5\""));
        assert_eq!(
            xml(get_result(&id("res1"))),
            "<get_results details=\"1\" result_id=\"res1\"/>"
        );
    }

    #[test]
    fn semantic_result_requests_match_builder_bytes_and_responses() {
        fn assert_response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let opts = GetResultsOpts {
            filter_string: Some("severity>5".into()),
            filter_id: Some(id("filter-1")),
            details: Some(true),
        };
        let request = GetResultsRequest::new(opts.clone());
        assert_eq!(request.to_bytes(), get_results(opts).to_bytes());
        assert_response::<_, GetResultsResponse>(&request);

        let request = GetResultRequest::new(id("result-1"));
        assert_eq!(request.to_bytes(), get_result(&id("result-1")).to_bytes());
        assert_response::<_, GetResultsResponse>(&request);
    }
}
