// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Group command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateGroupResponse, DeleteGroupResponse, GetGroupsResponse, ModifyGroupResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for group create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct GroupOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// User names associated with the request.
    pub users: Vec<String>,
}

/// Options for `get_groups` requests.
#[derive(Debug, Clone, Default)]
pub struct GetGroupsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing groups.
#[derive(Debug, Clone, Default)]
pub struct GetGroupsRequest(GetGroupsOpts);

impl GetGroupsRequest {
    /// Create a group-list request.
    #[must_use]
    pub fn new(opts: GetGroupsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetGroupsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_groups(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetGroupsRequest {
    type Response = GetGroupsResponse;
}

macro_rules! group_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(group_id: EntityId) -> Self {
                Self(group_id)
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

group_id_request!(GetGroupRequest, GetGroupsResponse, get_group);
group_id_request!(CloneGroupRequest, CreateGroupResponse, clone_group);

/// Semantic request for creating a group.
#[derive(Debug, Clone)]
pub struct CreateGroupRequest {
    name: String,
    opts: GroupOpts,
}

impl CreateGroupRequest {
    /// Create a group-creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: GroupOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreateGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_group(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateGroupRequest {
    type Response = CreateGroupResponse;
}

/// Semantic request for modifying a group.
#[derive(Debug, Clone)]
pub struct ModifyGroupRequest {
    group_id: EntityId,
    opts: GroupOpts,
}

impl ModifyGroupRequest {
    /// Create a group-modification request.
    #[must_use]
    pub fn new(group_id: EntityId, opts: GroupOpts) -> Self {
        Self { group_id, opts }
    }
}

impl Request for ModifyGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_group(&self.group_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyGroupRequest {
    type Response = ModifyGroupResponse;
}

/// Semantic request for deleting a group.
#[derive(Debug, Clone)]
pub struct DeleteGroupRequest {
    group_id: EntityId,
    ultimate: bool,
}

impl DeleteGroupRequest {
    /// Create a group-deletion request.
    #[must_use]
    pub fn new(group_id: EntityId, ultimate: bool) -> Self {
        Self { group_id, ultimate }
    }
}

impl Request for DeleteGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_group(&self.group_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteGroupRequest {
    type Response = DeleteGroupResponse;
}

/// Build a clone request for an existing group.
#[must_use]
pub fn clone_group(group_id: &EntityId) -> impl Request {
    XmlCommand::new("create_group").child_with_text("copy", group_id.as_str())
}

/// Build a `create_group` request.
#[must_use]
pub fn create_group(name: &str, opts: GroupOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_group");
    cmd.add_element_with_text("name", name);
    add_group_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_groups` request.
#[must_use]
pub fn get_groups(opts: GetGroupsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_groups");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_group` request.
#[must_use]
pub fn get_group(group_id: &EntityId) -> impl Request {
    XmlCommand::new("get_groups")
        .attribute("group_id", group_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_group` request.
#[must_use]
pub fn modify_group(group_id: &EntityId, opts: GroupOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_group").attribute("group_id", group_id.as_str());
    add_group_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_group` request.
#[must_use]
pub fn delete_group(group_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_group")
        .attribute("group_id", group_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_group_body(cmd: &mut XmlCommand, opts: &GroupOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    if !opts.users.is_empty() {
        cmd.add_element_with_text("users", &opts.users.join(","));
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
    fn semantic_group_requests_match_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }
        let group_id = id("group-1");
        let get_opts = GetGroupsOpts {
            details: Some(true),
            ..Default::default()
        };
        let opts = GroupOpts {
            users: vec!["alice".into()],
            ..Default::default()
        };

        let list = GetGroupsRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_groups(get_opts).to_bytes());
        associated::<_, GetGroupsResponse>(&list);
        let get = GetGroupRequest::new(group_id.clone());
        assert_eq!(get.to_bytes(), get_group(&group_id).to_bytes());
        associated::<_, GetGroupsResponse>(&get);
        let create = CreateGroupRequest::new("group", opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_group("group", opts.clone()).to_bytes()
        );
        associated::<_, CreateGroupResponse>(&create);
        let clone = CloneGroupRequest::new(group_id.clone());
        assert_eq!(clone.to_bytes(), clone_group(&group_id).to_bytes());
        associated::<_, CreateGroupResponse>(&clone);
        let modify = ModifyGroupRequest::new(group_id.clone(), opts.clone());
        assert_eq!(modify.to_bytes(), modify_group(&group_id, opts).to_bytes());
        associated::<_, ModifyGroupResponse>(&modify);
        let delete = DeleteGroupRequest::new(group_id.clone(), true);
        assert_eq!(delete.to_bytes(), delete_group(&group_id, true).to_bytes());
        associated::<_, DeleteGroupResponse>(&delete);
    }

    #[test]
    fn group_commands_build_xml() {
        let rendered = xml(create_group(
            "group",
            GroupOpts {
                users: vec!["alice".into()],
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<users>alice</users>"));
        assert_eq!(
            xml(clone_group(&id("g1"))),
            "<create_group><copy>g1</copy></create_group>"
        );
        assert_eq!(
            xml(get_group(&id("g1"))),
            "<get_groups details=\"1\" group_id=\"g1\"/>"
        );
    }

    #[test]
    fn group_get_modify_delete_build_xml() {
        let rendered = xml(get_groups(GetGroupsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_group(
            &id("g1"),
            GroupOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_group group_id=\"g1\"><comment>updated</comment></modify_group>"
        );
        assert_eq!(
            xml(delete_group(&id("g1"), false)),
            "<delete_group group_id=\"g1\" ultimate=\"0\"/>"
        );
    }
}
