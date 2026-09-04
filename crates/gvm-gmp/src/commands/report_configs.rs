// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report configuration command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_text_element, bool_str};
use crate::responses::{
    CreateReportConfigResponse, DeleteReportConfigResponse, GetReportConfigsResponse,
    ModifyReportConfigResponse,
};
use crate::GmpRequest;

/// Optional fields for `create_report_config` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateReportConfigOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
}

/// Optional fields for `delete_report_config` requests.
#[derive(Debug, Clone, Default)]
pub struct DeleteReportConfigOpts {
    /// Whether to permanently delete the report configuration.
    pub ultimate: Option<bool>,
}

/// Options for `get_report_configs` requests.
#[derive(Debug, Clone, Default)]
pub struct GetReportConfigsOpts {
    /// Optional inline filter expression.
    pub filter: Option<String>,
    /// Optional offset for the first row.
    pub first: Option<u32>,
    /// Optional row count limit.
    pub rows: Option<u32>,
}

/// Optional fields for `modify_report_config` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyReportConfigOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
}

/// Semantic request for creating a report configuration with default options.
#[derive(Debug, Clone)]
pub struct CreateReportConfigRequest {
    name: String,
    report_format_id: String,
}

impl CreateReportConfigRequest {
    /// Create a report-configuration request with default options.
    #[must_use]
    pub fn new(name: impl Into<String>, report_format_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            report_format_id: report_format_id.into(),
        }
    }
}

impl Request for CreateReportConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_report_config(&self.name, &self.report_format_id).to_bytes()
    }
}

impl GmpRequest for CreateReportConfigRequest {
    type Response = CreateReportConfigResponse;
}

/// Semantic request for creating a report configuration with optional fields.
#[derive(Debug, Clone)]
pub struct CreateReportConfigWithOptsRequest {
    name: String,
    report_format_id: String,
    opts: CreateReportConfigOpts,
}

impl CreateReportConfigWithOptsRequest {
    /// Create a report-configuration request with optional fields.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        report_format_id: impl Into<String>,
        opts: CreateReportConfigOpts,
    ) -> Self {
        Self {
            name: name.into(),
            report_format_id: report_format_id.into(),
            opts,
        }
    }
}

impl Request for CreateReportConfigWithOptsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_report_config_opts(&self.name, &self.report_format_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateReportConfigWithOptsRequest {
    type Response = CreateReportConfigResponse;
}

macro_rules! report_config_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(String);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(id: impl Into<String>) -> Self {
                Self(id.into())
            }
        }

        impl Request for $name {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.0).to_bytes()
            }
        }

        impl GmpRequest for $name {
            type Response = $response;
        }
    };
}

report_config_id_request!(
    CloneReportConfigRequest,
    CreateReportConfigResponse,
    clone_report_config
);
report_config_id_request!(
    DeleteReportConfigRequest,
    DeleteReportConfigResponse,
    delete_report_config
);
report_config_id_request!(
    GetReportConfigRequest,
    GetReportConfigsResponse,
    get_report_config
);

/// Semantic request for deleting a report configuration with optional fields.
#[derive(Debug, Clone)]
pub struct DeleteReportConfigWithOptsRequest {
    id: String,
    opts: DeleteReportConfigOpts,
}

impl DeleteReportConfigWithOptsRequest {
    /// Create a report-configuration deletion request with optional fields.
    #[must_use]
    pub fn new(id: impl Into<String>, opts: DeleteReportConfigOpts) -> Self {
        Self {
            id: id.into(),
            opts,
        }
    }
}

impl Request for DeleteReportConfigWithOptsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_report_config_opts(&self.id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for DeleteReportConfigWithOptsRequest {
    type Response = DeleteReportConfigResponse;
}

/// Semantic request for listing report configurations with default options.
#[derive(Debug, Clone, Default)]
pub struct GetReportConfigsRequest;

impl GetReportConfigsRequest {
    /// Create a report-configuration list request with default options.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for GetReportConfigsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_report_configs().to_bytes()
    }
}

impl GmpRequest for GetReportConfigsRequest {
    type Response = GetReportConfigsResponse;
}

/// Semantic request for listing report configurations with optional attributes.
#[derive(Debug, Clone, Default)]
pub struct GetReportConfigsWithOptsRequest(GetReportConfigsOpts);

impl GetReportConfigsWithOptsRequest {
    /// Create a report-configuration list request with optional attributes.
    #[must_use]
    pub fn new(opts: GetReportConfigsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetReportConfigsWithOptsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_report_configs_opts(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetReportConfigsWithOptsRequest {
    type Response = GetReportConfigsResponse;
}

/// Semantic request for modifying a report configuration.
#[derive(Debug, Clone)]
pub struct ModifyReportConfigRequest {
    id: String,
    opts: ModifyReportConfigOpts,
}

impl ModifyReportConfigRequest {
    /// Create a report-configuration modification request.
    #[must_use]
    pub fn new(id: impl Into<String>, opts: ModifyReportConfigOpts) -> Self {
        Self {
            id: id.into(),
            opts,
        }
    }
}

impl Request for ModifyReportConfigRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_report_config(&self.id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyReportConfigRequest {
    type Response = ModifyReportConfigResponse;
}

/// Build a `create_report_config` request.
#[must_use]
pub fn create_report_config(name: &str, report_format_id: &str) -> XmlCommand {
    create_report_config_opts(name, report_format_id, CreateReportConfigOpts::default())
}

/// Build a `create_report_config` request with optional fields.
#[must_use]
pub fn create_report_config_opts(
    name: &str,
    report_format_id: &str,
    opts: CreateReportConfigOpts,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_report_config");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("report_format_id", report_format_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    cmd
}

/// Build a clone request for an existing report configuration.
#[must_use]
pub fn clone_report_config(id: &str) -> XmlCommand {
    XmlCommand::new("create_report_config").child_with_text("copy", id)
}

/// Build a `delete_report_config` request.
#[must_use]
pub fn delete_report_config(id: &str) -> XmlCommand {
    delete_report_config_opts(id, DeleteReportConfigOpts::default())
}

/// Build a `delete_report_config` request with optional fields.
#[must_use]
pub fn delete_report_config_opts(id: &str, opts: DeleteReportConfigOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("delete_report_config").attribute("report_config_id", id);
    if let Some(ultimate) = opts.ultimate {
        cmd = cmd.attribute("ultimate", bool_str(ultimate));
    }
    cmd
}

/// Build a `get_report_configs` request.
#[must_use]
pub fn get_report_configs() -> XmlCommand {
    get_report_configs_opts(GetReportConfigsOpts::default())
}

/// Build a `get_report_configs` request with optional attributes.
#[must_use]
pub fn get_report_configs_opts(opts: GetReportConfigsOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_report_configs");
    if let Some(filter) = opts.filter.filter(|filter| !filter.is_empty()) {
        cmd = cmd.attribute("filter", &filter);
    }
    if let Some(first) = opts.first {
        cmd = cmd.attribute("first", &first.to_string());
    }
    if let Some(rows) = opts.rows {
        cmd = cmd.attribute("rows", &rows.to_string());
    }
    cmd
}

/// Build a `get_report_config` request.
#[must_use]
pub fn get_report_config(id: &str) -> XmlCommand {
    XmlCommand::new("get_report_configs").attribute("report_config_id", id)
}

/// Build a `modify_report_config` request.
#[must_use]
pub fn modify_report_config(id: &str, opts: ModifyReportConfigOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_report_config").attribute("report_config_id", id);
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    #[test]
    fn report_config_commands_build_xml() {
        assert_eq!(
            xml(create_report_config("cfg", "rf1")),
            "<create_report_config><name>cfg</name><report_format_id>rf1</report_format_id></create_report_config>"
        );
        assert_eq!(
            xml(get_report_config("cfg1")),
            "<get_report_configs report_config_id=\"cfg1\"/>"
        );
        assert_eq!(
            xml(clone_report_config("cfg1")),
            "<create_report_config><copy>cfg1</copy></create_report_config>"
        );
    }

    #[test]
    fn report_config_options_build_xml() {
        assert_eq!(
            xml(create_report_config_opts(
                "cfg",
                "rf1",
                CreateReportConfigOpts {
                    comment: Some("note".into())
                }
            )),
            "<create_report_config><name>cfg</name><report_format_id>rf1</report_format_id><comment>note</comment></create_report_config>"
        );
        assert_eq!(
            xml(modify_report_config(
                "cfg1",
                ModifyReportConfigOpts {
                    name: Some("updated".into()),
                    comment: Some("comment".into())
                }
            )),
            "<modify_report_config report_config_id=\"cfg1\"><name>updated</name><comment>comment</comment></modify_report_config>"
        );
    }

    #[test]
    fn report_config_get_and_delete_build_xml() {
        assert_eq!(xml(get_report_configs()), "<get_report_configs/>");
        assert_eq!(
            xml(get_report_configs_opts(GetReportConfigsOpts {
                filter: Some("name=cfg".into()),
                first: Some(10),
                rows: Some(25)
            })),
            "<get_report_configs filter=\"name=cfg\" first=\"10\" rows=\"25\"/>"
        );
        assert_eq!(
            xml(delete_report_config("cfg1")),
            "<delete_report_config report_config_id=\"cfg1\"/>"
        );
        assert_eq!(
            xml(delete_report_config_opts(
                "cfg1",
                DeleteReportConfigOpts {
                    ultimate: Some(true)
                }
            )),
            "<delete_report_config report_config_id=\"cfg1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn semantic_requests_match_all_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let create_opts = CreateReportConfigOpts {
            comment: Some("comment".into()),
        };
        let delete_opts = DeleteReportConfigOpts {
            ultimate: Some(true),
        };
        let get_opts = GetReportConfigsOpts {
            filter: Some("name=cfg".into()),
            first: Some(2),
            rows: Some(4),
        };
        let modify_opts = ModifyReportConfigOpts {
            name: Some("renamed".into()),
            comment: Some("changed".into()),
        };

        let create = CreateReportConfigRequest::new("cfg", "rf-1");
        assert_eq!(
            create.to_bytes(),
            create_report_config("cfg", "rf-1").to_bytes()
        );
        associated::<_, CreateReportConfigResponse>(&create);

        let create_with_opts =
            CreateReportConfigWithOptsRequest::new("cfg", "rf-1", create_opts.clone());
        assert_eq!(
            create_with_opts.to_bytes(),
            create_report_config_opts("cfg", "rf-1", create_opts).to_bytes()
        );
        associated::<_, CreateReportConfigResponse>(&create_with_opts);

        let clone = CloneReportConfigRequest::new("cfg-1");
        assert_eq!(clone.to_bytes(), clone_report_config("cfg-1").to_bytes());
        associated::<_, CreateReportConfigResponse>(&clone);

        let delete = DeleteReportConfigRequest::new("cfg-1");
        assert_eq!(delete.to_bytes(), delete_report_config("cfg-1").to_bytes());
        associated::<_, DeleteReportConfigResponse>(&delete);

        let delete_with_opts = DeleteReportConfigWithOptsRequest::new("cfg-1", delete_opts.clone());
        assert_eq!(
            delete_with_opts.to_bytes(),
            delete_report_config_opts("cfg-1", delete_opts).to_bytes()
        );
        associated::<_, DeleteReportConfigResponse>(&delete_with_opts);

        let list = GetReportConfigsRequest::new();
        assert_eq!(list.to_bytes(), get_report_configs().to_bytes());
        associated::<_, GetReportConfigsResponse>(&list);

        let list_with_opts = GetReportConfigsWithOptsRequest::new(get_opts.clone());
        assert_eq!(
            list_with_opts.to_bytes(),
            get_report_configs_opts(get_opts).to_bytes()
        );
        associated::<_, GetReportConfigsResponse>(&list_with_opts);

        let get = GetReportConfigRequest::new("cfg-1");
        assert_eq!(get.to_bytes(), get_report_config("cfg-1").to_bytes());
        associated::<_, GetReportConfigsResponse>(&get);

        let modify = ModifyReportConfigRequest::new("cfg-1", modify_opts.clone());
        assert_eq!(
            modify.to_bytes(),
            modify_report_config("cfg-1", modify_opts).to_bytes()
        );
        associated::<_, ModifyReportConfigResponse>(&modify);
    }
}
