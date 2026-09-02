// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Filter command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{FilterType, SortOrder};
use crate::responses::{
    CreateFilterResponse, DeleteFilterResponse, GetFiltersResponse, ModifyFilterResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for filter create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct FilterOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional filter term expression.
    pub term: Option<String>,
    /// Optional resource type the filter applies to.
    pub filter_type: Option<FilterType>,
    /// Optional sort order.
    pub sort_order: Option<SortOrder>,
}

/// Options for `get_filters` requests.
#[derive(Debug, Clone, Default)]
pub struct GetFiltersOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing filters.
#[derive(Debug, Clone, Default)]
pub struct GetFiltersRequest(GetFiltersOpts);

impl GetFiltersRequest {
    /// Create a filter-list request.
    #[must_use]
    pub fn new(opts: GetFiltersOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetFiltersRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_filters(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetFiltersRequest {
    type Response = GetFiltersResponse;
}

macro_rules! filter_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(filter_id: EntityId) -> Self {
                Self(filter_id)
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

filter_id_request!(GetFilterRequest, GetFiltersResponse, get_filter);
filter_id_request!(CloneFilterRequest, CreateFilterResponse, clone_filter);

/// Semantic request for creating a filter.
#[derive(Debug, Clone)]
pub struct CreateFilterRequest {
    name: String,
    opts: FilterOpts,
}

impl CreateFilterRequest {
    /// Create a filter-creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: FilterOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreateFilterRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_filter(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateFilterRequest {
    type Response = CreateFilterResponse;
}

/// Semantic request for modifying a filter.
#[derive(Debug, Clone)]
pub struct ModifyFilterRequest {
    filter_id: EntityId,
    opts: FilterOpts,
}

impl ModifyFilterRequest {
    /// Create a filter-modification request.
    #[must_use]
    pub fn new(filter_id: EntityId, opts: FilterOpts) -> Self {
        Self { filter_id, opts }
    }
}

impl Request for ModifyFilterRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_filter(&self.filter_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyFilterRequest {
    type Response = ModifyFilterResponse;
}

/// Semantic request for deleting a filter.
#[derive(Debug, Clone)]
pub struct DeleteFilterRequest {
    filter_id: EntityId,
    ultimate: bool,
}

impl DeleteFilterRequest {
    /// Create a filter-deletion request.
    #[must_use]
    pub fn new(filter_id: EntityId, ultimate: bool) -> Self {
        Self {
            filter_id,
            ultimate,
        }
    }
}

impl Request for DeleteFilterRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_filter(&self.filter_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteFilterRequest {
    type Response = DeleteFilterResponse;
}

/// Build a clone request for an existing filter.
#[must_use]
pub fn clone_filter(filter_id: &EntityId) -> impl Request {
    XmlCommand::new("create_filter").child_with_text("copy", filter_id.as_str())
}

/// Build a `create_filter` request.
#[must_use]
pub fn create_filter(name: &str, opts: FilterOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_filter");
    cmd.add_element_with_text("name", name);
    add_filter_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_filters` request.
#[must_use]
pub fn get_filters(opts: GetFiltersOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_filters");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_filter` request.
#[must_use]
pub fn get_filter(filter_id: &EntityId) -> impl Request {
    XmlCommand::new("get_filters")
        .attribute("filter_id", filter_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_filter` request.
#[must_use]
pub fn modify_filter(filter_id: &EntityId, opts: FilterOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_filter").attribute("filter_id", filter_id.as_str());
    add_filter_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_filter` request.
#[must_use]
pub fn delete_filter(filter_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_filter")
        .attribute("filter_id", filter_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_filter_body(cmd: &mut XmlCommand, opts: &FilterOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "term", opts.term.as_deref());
    if let Some(filter_type) = opts.filter_type {
        cmd.add_element_with_text("type", filter_type.as_gmp_str());
    }
    if let Some(sort_order) = opts.sort_order {
        cmd.add_element_with_text("sort_order", sort_order.as_gmp_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn semantic_filter_requests_match_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }
        let filter_id = id("filter-1");
        let get_opts = GetFiltersOpts {
            details: Some(true),
            ..Default::default()
        };
        let opts = FilterOpts {
            term: Some("rows=10".into()),
            ..Default::default()
        };
        let list = GetFiltersRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_filters(get_opts).to_bytes());
        associated::<_, GetFiltersResponse>(&list);
        let get = GetFilterRequest::new(filter_id.clone());
        assert_eq!(get.to_bytes(), get_filter(&filter_id).to_bytes());
        associated::<_, GetFiltersResponse>(&get);
        let create = CreateFilterRequest::new("filter", opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_filter("filter", opts.clone()).to_bytes()
        );
        associated::<_, CreateFilterResponse>(&create);
        let clone = CloneFilterRequest::new(filter_id.clone());
        assert_eq!(clone.to_bytes(), clone_filter(&filter_id).to_bytes());
        associated::<_, CreateFilterResponse>(&clone);
        let modify = ModifyFilterRequest::new(filter_id.clone(), opts.clone());
        assert_eq!(
            modify.to_bytes(),
            modify_filter(&filter_id, opts).to_bytes()
        );
        associated::<_, ModifyFilterResponse>(&modify);
        let delete = DeleteFilterRequest::new(filter_id.clone(), true);
        assert_eq!(
            delete.to_bytes(),
            delete_filter(&filter_id, true).to_bytes()
        );
        associated::<_, DeleteFilterResponse>(&delete);
    }

    #[test]
    fn filter_commands_build_xml() {
        let rendered = xml(create_filter(
            "f",
            FilterOpts {
                term: Some("rows=10".into()),
                filter_type: Some(FilterType::Task),
                sort_order: Some(SortOrder::Ascending),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<term>rows=10</term>"));
        assert_eq!(
            xml(clone_filter(&id("f1"))),
            "<create_filter><copy>f1</copy></create_filter>"
        );
        assert_eq!(
            xml(get_filter(&id("f1"))),
            "<get_filters details=\"1\" filter_id=\"f1\"/>"
        );
    }

    #[test]
    fn filter_get_modify_delete_build_xml() {
        let rendered = xml(get_filters(GetFiltersOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_filter(
            &id("f1"),
            FilterOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_filter filter_id=\"f1\"><comment>updated</comment></modify_filter>"
        );
        assert_eq!(
            xml(delete_filter(&id("f1"), false)),
            "<delete_filter filter_id=\"f1\" ultimate=\"0\"/>"
        );
    }
}
