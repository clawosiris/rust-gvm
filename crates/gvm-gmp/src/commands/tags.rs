// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Tag command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{EntityType, SeverityLevel};
use crate::responses::{CreateTagResponse, DeleteTagResponse, GetTagsResponse, ModifyTagResponse};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for tag create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct TagOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional free-form value payload.
    pub value: Option<String>,
    /// Optional related resource type.
    pub resource_type: Option<EntityType>,
    /// Optional related resource identifier.
    pub resource_id: Option<EntityId>,
    /// Optional severity value.
    pub severity: Option<SeverityLevel>,
    /// Whether the resource should be active.
    pub active: Option<bool>,
}

/// Options for `get_tags` requests.
#[derive(Debug, Clone, Default)]
pub struct GetTagsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing tags.
#[derive(Debug, Clone, Default)]
pub struct GetTagsRequest(GetTagsOpts);

impl GetTagsRequest {
    /// Create a tag-list request.
    #[must_use]
    pub fn new(opts: GetTagsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetTagsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_tags(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetTagsRequest {
    type Response = GetTagsResponse;
}

macro_rules! tag_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(tag_id: EntityId) -> Self {
                Self(tag_id)
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

tag_id_request!(GetTagRequest, GetTagsResponse, get_tag);
tag_id_request!(CloneTagRequest, CreateTagResponse, clone_tag);

/// Semantic request for creating a tag.
#[derive(Debug, Clone)]
pub struct CreateTagRequest {
    name: String,
    opts: TagOpts,
}

impl CreateTagRequest {
    /// Create a tag-creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: TagOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreateTagRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_tag(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateTagRequest {
    type Response = CreateTagResponse;
}

/// Semantic request for modifying a tag.
#[derive(Debug, Clone)]
pub struct ModifyTagRequest {
    tag_id: EntityId,
    opts: TagOpts,
}

impl ModifyTagRequest {
    /// Create a tag-modification request.
    #[must_use]
    pub fn new(tag_id: EntityId, opts: TagOpts) -> Self {
        Self { tag_id, opts }
    }
}

impl Request for ModifyTagRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_tag(&self.tag_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyTagRequest {
    type Response = ModifyTagResponse;
}

/// Semantic request for deleting a tag.
#[derive(Debug, Clone)]
pub struct DeleteTagRequest {
    tag_id: EntityId,
    ultimate: bool,
}

impl DeleteTagRequest {
    /// Create a tag-deletion request.
    #[must_use]
    pub fn new(tag_id: EntityId, ultimate: bool) -> Self {
        Self { tag_id, ultimate }
    }
}

impl Request for DeleteTagRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_tag(&self.tag_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteTagRequest {
    type Response = DeleteTagResponse;
}

/// Build a clone request for an existing tag.
#[must_use]
pub fn clone_tag(tag_id: &EntityId) -> impl Request {
    XmlCommand::new("create_tag").child_with_text("copy", tag_id.as_str())
}

/// Build a `create_tag` request.
#[must_use]
pub fn create_tag(name: &str, opts: TagOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_tag");
    cmd.add_element_with_text("name", name);
    add_tag_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_tags` request.
#[must_use]
pub fn get_tags(opts: GetTagsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_tags");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_tag` request.
#[must_use]
pub fn get_tag(tag_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tags")
        .attribute("tag_id", tag_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_tag` request.
#[must_use]
pub fn modify_tag(tag_id: &EntityId, opts: TagOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_tag").attribute("tag_id", tag_id.as_str());
    add_tag_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_tag` request.
#[must_use]
pub fn delete_tag(tag_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_tag")
        .attribute("tag_id", tag_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_tag_body(cmd: &mut XmlCommand, opts: &TagOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "value", opts.value.as_deref());

    // GMP expects a <resources> block with a <type> child.
    if let Some(resource_type) = opts.resource_type {
        let resources = cmd.add_element("resources");

        // Align with python-gvm behavior: audit -> task, policy -> scan_config
        let actual_type = match resource_type {
            EntityType::Policy => EntityType::Config,
            other => other,
        };

        if let Some(resource_id) = opts.resource_id.as_ref() {
            resources
                .add_child("resource")
                .set_attribute("id", resource_id.as_str());
        }

        resources
            .add_child("type")
            .set_text(actual_type.as_gmp_str());
    }

    if let Some(severity) = opts.severity {
        cmd.add_element_with_text("severity", severity.as_gmp_str());
    }
    if let Some(active) = opts.active {
        cmd.add_element_with_text("active", bool_str(active));
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
    fn semantic_tag_requests_match_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }
        let tag_id = id("tag-1");
        let get_opts = GetTagsOpts {
            details: Some(true),
            ..Default::default()
        };
        let opts = TagOpts {
            value: Some("value".into()),
            ..Default::default()
        };
        let list = GetTagsRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_tags(get_opts).to_bytes());
        associated::<_, GetTagsResponse>(&list);
        let get = GetTagRequest::new(tag_id.clone());
        assert_eq!(get.to_bytes(), get_tag(&tag_id).to_bytes());
        associated::<_, GetTagsResponse>(&get);
        let create = CreateTagRequest::new("tag", opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_tag("tag", opts.clone()).to_bytes()
        );
        associated::<_, CreateTagResponse>(&create);
        let clone = CloneTagRequest::new(tag_id.clone());
        assert_eq!(clone.to_bytes(), clone_tag(&tag_id).to_bytes());
        associated::<_, CreateTagResponse>(&clone);
        let modify = ModifyTagRequest::new(tag_id.clone(), opts.clone());
        assert_eq!(modify.to_bytes(), modify_tag(&tag_id, opts).to_bytes());
        associated::<_, ModifyTagResponse>(&modify);
        let delete = DeleteTagRequest::new(tag_id.clone(), true);
        assert_eq!(delete.to_bytes(), delete_tag(&tag_id, true).to_bytes());
        associated::<_, DeleteTagResponse>(&delete);
    }

    #[test]
    fn tag_commands_build_xml() {
        let rendered = xml(create_tag(
            "tag",
            TagOpts {
                value: Some("blue".into()),
                resource_type: Some(EntityType::Task),
                resource_id: Some(id("t1")),
                severity: Some(SeverityLevel::High),
                active: Some(true),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<resources>"));
        assert!(rendered.contains("<resource id=\"t1\"/>"));
        assert!(rendered.contains("<type>task</type>"));
        assert!(rendered.contains("<severity>high</severity>"));
        assert_eq!(
            xml(clone_tag(&id("tg1"))),
            "<create_tag><copy>tg1</copy></create_tag>"
        );
        assert_eq!(
            xml(get_tag(&id("tg1"))),
            "<get_tags details=\"1\" tag_id=\"tg1\"/>"
        );
    }

    #[test]
    fn tag_get_modify_delete_build_xml() {
        let rendered = xml(get_tags(GetTagsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_tag(
            &id("tg1"),
            TagOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_tag tag_id=\"tg1\"><comment>updated</comment></modify_tag>"
        );
        assert_eq!(
            xml(delete_tag(&id("tg1"), false)),
            "<delete_tag tag_id=\"tg1\" ultimate=\"0\"/>"
        );
    }
}
