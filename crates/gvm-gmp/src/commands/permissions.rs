//! Permission command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::PermissionSubjectType;
use crate::types::EntityId;

/// Optional fields for permission create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct PermissionOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional related resource identifier.
    pub resource_id: Option<EntityId>,
    /// Optional related resource type.
    pub resource_type: Option<String>,
    /// Optional permission subject type.
    pub subject_type: Option<PermissionSubjectType>,
    /// Optional permission subject identifier.
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

/// Build a clone request for an existing permission.
pub fn clone_permission(permission_id: &EntityId) -> impl Request {
    XmlCommand::new("create_permission").child_with_text("copy", permission_id.as_str())
}

/// Build a `create_permission` request.
pub fn create_permission(opts: PermissionOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_permission");
    add_permission_body(&mut cmd, &opts);
    cmd
}

/// Build a `get_permissions` request.
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
pub fn get_permission(permission_id: &EntityId) -> impl Request {
    XmlCommand::new("get_permissions")
        .attribute("permission_id", permission_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_permission` request.
pub fn modify_permission(permission_id: &EntityId, opts: PermissionOpts) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_permission").attribute("permission_id", permission_id.as_str());
    add_permission_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_permission` request.
pub fn delete_permission(permission_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_permission")
        .attribute("permission_id", permission_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_permission_body(cmd: &mut XmlCommand, opts: &PermissionOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "name", opts.name.as_deref());
    add_text_element(cmd, "resource_type", opts.resource_type.as_deref());
    if let Some(resource_id) = opts.resource_id.as_ref() {
        cmd.add_element_with_text("resource_id", resource_id.as_str());
    }
    if let Some(subject_type) = opts.subject_type {
        cmd.add_element_with_text("subject_type", subject_type.as_gmp_str());
    }
    if let Some(subject_id) = opts.subject_id.as_ref() {
        cmd.add_element_with_text("subject_id", subject_id.as_str());
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
    fn permission_commands_build_xml() {
        let rendered = xml(create_permission(PermissionOpts {
            name: Some("get_tasks".into()),
            subject_type: Some(PermissionSubjectType::Role),
            subject_id: Some(id("r1")),
            ..Default::default()
        }));
        assert!(rendered.contains("<subject_type>role</subject_type>"));
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
