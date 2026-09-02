// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Permission command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::PermissionSubjectType;
use crate::responses::{
    CreatePermissionResponse, DeletePermissionResponse, GetPermissionsResponse,
    ModifyPermissionResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for permission create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct PermissionOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional permission name.
    pub name: Option<String>,
    /// Optional resource identifier; pair with `resource_type` for a valid request.
    pub resource_id: Option<EntityId>,
    /// Optional resource type; pair with `resource_id` for a valid request.
    pub resource_type: Option<String>,
    /// Optional permission subject type; pair with `subject_id` for a valid request.
    pub subject_type: Option<PermissionSubjectType>,
    /// Optional permission subject identifier; pair with `subject_type` for a valid request.
    pub subject_id: Option<EntityId>,
}

/// Options for `get_permissions` requests.
#[derive(Debug, Clone, Default)]
pub struct GetPermissionsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing permissions.
#[derive(Debug, Clone, Default)]
pub struct GetPermissionsRequest(GetPermissionsOpts);

impl GetPermissionsRequest {
    /// Create a permission-list request.
    #[must_use]
    pub fn new(opts: GetPermissionsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetPermissionsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_permissions(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetPermissionsRequest {
    type Response = GetPermissionsResponse;
}

macro_rules! permission_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(permission_id: EntityId) -> Self {
                Self(permission_id)
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

permission_id_request!(GetPermissionRequest, GetPermissionsResponse, get_permission);
permission_id_request!(
    ClonePermissionRequest,
    CreatePermissionResponse,
    clone_permission
);

/// Semantic request for creating a permission.
#[derive(Debug, Clone)]
pub struct CreatePermissionRequest(PermissionOpts);

impl CreatePermissionRequest {
    /// Create a permission-creation request.
    #[must_use]
    pub fn new(opts: PermissionOpts) -> Self {
        Self(opts)
    }
}

impl Request for CreatePermissionRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_permission(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for CreatePermissionRequest {
    type Response = CreatePermissionResponse;
}

/// Semantic request for modifying a permission.
#[derive(Debug, Clone)]
pub struct ModifyPermissionRequest {
    permission_id: EntityId,
    opts: PermissionOpts,
}

impl ModifyPermissionRequest {
    /// Create a permission-modification request.
    #[must_use]
    pub fn new(permission_id: EntityId, opts: PermissionOpts) -> Self {
        Self {
            permission_id,
            opts,
        }
    }
}

impl Request for ModifyPermissionRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_permission(&self.permission_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyPermissionRequest {
    type Response = ModifyPermissionResponse;
}

/// Semantic request for deleting a permission.
#[derive(Debug, Clone)]
pub struct DeletePermissionRequest {
    permission_id: EntityId,
    ultimate: bool,
}

impl DeletePermissionRequest {
    /// Create a permission-deletion request.
    #[must_use]
    pub fn new(permission_id: EntityId, ultimate: bool) -> Self {
        Self {
            permission_id,
            ultimate,
        }
    }
}

impl Request for DeletePermissionRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_permission(&self.permission_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeletePermissionRequest {
    type Response = DeletePermissionResponse;
}

/// Build a clone request for an existing permission.
#[must_use]
pub fn clone_permission(permission_id: &EntityId) -> impl Request {
    XmlCommand::new("create_permission").child_with_text("copy", permission_id.as_str())
}

/// Build a `create_permission` request.
#[must_use]
pub fn create_permission(opts: PermissionOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_permission");
    add_permission_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_permissions` request.
#[must_use]
pub fn get_permissions(opts: GetPermissionsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_permissions");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_permission` request.
#[must_use]
pub fn get_permission(permission_id: &EntityId) -> impl Request {
    XmlCommand::new("get_permissions")
        .attribute("permission_id", permission_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_permission` request.
#[must_use]
pub fn modify_permission(permission_id: &EntityId, opts: PermissionOpts) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_permission").attribute("permission_id", permission_id.as_str());
    add_permission_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_permission` request.
#[must_use]
pub fn delete_permission(permission_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_permission")
        .attribute("permission_id", permission_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_permission_body(cmd: &mut XmlCommand, opts: &PermissionOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "name", opts.name.as_deref());
    add_permission_reference(
        cmd,
        "resource",
        opts.resource_id.as_ref(),
        opts.resource_type.as_deref(),
    );
    add_permission_reference(
        cmd,
        "subject",
        opts.subject_id.as_ref(),
        opts.subject_type.map(PermissionSubjectType::as_gmp_str),
    );
}

fn add_permission_reference(
    cmd: &mut XmlCommand,
    element_name: &str,
    id: Option<&EntityId>,
    reference_type: Option<&str>,
) {
    if id.is_none() && reference_type.is_none() {
        return;
    }

    let reference = cmd.add_element(element_name);
    if let Some(id) = id {
        reference.set_attribute("id", id.as_str());
    }
    if let Some(reference_type) = reference_type {
        reference.add_child_with_text("type", reference_type);
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
    fn semantic_permission_requests_match_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }
        let permission_id = id("permission-1");
        let get_opts = GetPermissionsOpts {
            details: Some(true),
            ..Default::default()
        };
        let opts = PermissionOpts {
            name: Some("get_tasks".into()),
            subject_type: Some(PermissionSubjectType::Role),
            subject_id: Some(id("role-1")),
            ..Default::default()
        };

        let list = GetPermissionsRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_permissions(get_opts).to_bytes());
        associated::<_, GetPermissionsResponse>(&list);
        let get = GetPermissionRequest::new(permission_id.clone());
        assert_eq!(get.to_bytes(), get_permission(&permission_id).to_bytes());
        associated::<_, GetPermissionsResponse>(&get);
        let create = CreatePermissionRequest::new(opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_permission(opts.clone()).to_bytes()
        );
        associated::<_, CreatePermissionResponse>(&create);
        let clone = ClonePermissionRequest::new(permission_id.clone());
        assert_eq!(
            clone.to_bytes(),
            clone_permission(&permission_id).to_bytes()
        );
        associated::<_, CreatePermissionResponse>(&clone);
        let modify = ModifyPermissionRequest::new(permission_id.clone(), opts.clone());
        assert_eq!(
            modify.to_bytes(),
            modify_permission(&permission_id, opts).to_bytes()
        );
        associated::<_, ModifyPermissionResponse>(&modify);
        let delete = DeletePermissionRequest::new(permission_id.clone(), true);
        assert_eq!(
            delete.to_bytes(),
            delete_permission(&permission_id, true).to_bytes()
        );
        associated::<_, DeletePermissionResponse>(&delete);
    }

    #[test]
    fn permission_commands_build_xml() {
        let rendered = xml(create_permission(PermissionOpts {
            name: Some("get_tasks".into()),
            subject_type: Some(PermissionSubjectType::Role),
            subject_id: Some(id("r1")),
            ..Default::default()
        }));
        assert_eq!(
            rendered,
            "<create_permission><name>get_tasks</name><subject id=\"r1\"><type>role</type></subject></create_permission>"
        );
        assert_eq!(
            xml(clone_permission(&id("p1"))),
            "<create_permission><copy>p1</copy></create_permission>"
        );
        assert_eq!(
            xml(get_permission(&id("p1"))),
            "<get_permissions details=\"1\" permission_id=\"p1\"/>"
        );
    }

    #[test]
    fn permission_get_modify_delete_build_xml() {
        let rendered = xml(get_permissions(GetPermissionsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_permission(
            &id("p1"),
            PermissionOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(rendered, "<modify_permission permission_id=\"p1\"><comment>updated</comment></modify_permission>");
        assert_eq!(
            xml(delete_permission(&id("p1"), false)),
            "<delete_permission permission_id=\"p1\" ultimate=\"0\"/>"
        );
    }
}
