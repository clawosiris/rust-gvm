// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! OCI image target command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::types::EntityId;

/// Optional fields for `create_oci_image_target` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateOciImageTargetOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

/// Options for `get_oci_image_targets` requests.
#[derive(Debug, Clone, Default)]
pub struct GetOciImageTargetsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to include tasks that use the target.
    pub tasks: Option<bool>,
}

/// Optional fields for `modify_oci_image_target` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyOciImageTargetOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// OCI image references to scan.
    pub image_references: Vec<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

/// Build a clone request for an existing OCI image target.
#[must_use]
pub fn clone_oci_image_target(oci_image_target_id: &EntityId) -> impl Request {
    XmlCommand::new("create_oci_image_target").child_with_text("copy", oci_image_target_id.as_str())
}

/// Build a `create_oci_image_target` request.
#[must_use]
pub fn create_oci_image_target(
    name: &str,
    image_references: &[String],
    opts: CreateOciImageTargetOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_oci_image_target");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("image_references", &image_references.join(","));
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_optional_id_element(&mut cmd, "credential", opts.credential_id.as_ref());
    cmd
}

/// Build a `get_oci_image_targets` request.
#[must_use]
pub fn get_oci_image_targets(opts: GetOciImageTargetsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_oci_image_targets");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "tasks", opts.tasks);
    cmd
}

/// Build a `get_oci_image_target` request.
#[must_use]
pub fn get_oci_image_target(oci_image_target_id: &EntityId, tasks: Option<bool>) -> impl Request {
    let mut cmd = XmlCommand::new("get_oci_image_targets")
        .attribute("oci_image_target_id", oci_image_target_id.as_str());
    set_optional_bool_attr(&mut cmd, "tasks", tasks);
    cmd
}

/// Build a `modify_oci_image_target` request.
#[must_use]
pub fn modify_oci_image_target(
    oci_image_target_id: &EntityId,
    opts: ModifyOciImageTargetOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("modify_oci_image_target")
        .attribute("oci_image_target_id", oci_image_target_id.as_str());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_string_list_text(&mut cmd, "image_references", &opts.image_references);
    add_optional_id_element(&mut cmd, "credential", opts.credential_id.as_ref());
    cmd
}

/// Build a `delete_oci_image_target` request.
#[must_use]
pub fn delete_oci_image_target(oci_image_target_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_oci_image_target")
        .attribute("oci_image_target_id", oci_image_target_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_string_list_text(cmd: &mut XmlCommand, name: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    cmd.add_element_with_text(name, &values.join(","));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn oci_image_target_create_and_clone_build_xml() {
        assert_eq!(
            xml(create_oci_image_target(
                "oci",
                &["registry.example/image:1".into(), "registry.example/image:2".into()],
                CreateOciImageTargetOpts {
                    comment: Some("note".into()),
                    credential_id: Some(id("cred-1")),
                },
            )),
            "<create_oci_image_target><name>oci</name><image_references>registry.example/image:1,registry.example/image:2</image_references><comment>note</comment><credential id=\"cred-1\"/></create_oci_image_target>"
        );
        assert_eq!(
            xml(clone_oci_image_target(&id("target-1"))),
            "<create_oci_image_target><copy>target-1</copy></create_oci_image_target>"
        );
    }

    #[test]
    fn oci_image_target_get_builds_xml() {
        assert_eq!(
            xml(get_oci_image_targets(GetOciImageTargetsOpts {
                filter_string: Some("name=oci".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(false),
                tasks: Some(true),
            })),
            "<get_oci_image_targets filt_id=\"filter-1\" filter=\"name=oci\" tasks=\"1\" trash=\"0\"/>"
        );
        assert_eq!(
            xml(get_oci_image_target(&id("target-1"), Some(false))),
            "<get_oci_image_targets oci_image_target_id=\"target-1\" tasks=\"0\"/>"
        );
    }

    #[test]
    fn oci_image_target_modify_and_delete_build_xml() {
        assert_eq!(
            xml(modify_oci_image_target(
                &id("target-1"),
                ModifyOciImageTargetOpts {
                    name: Some("updated".into()),
                    comment: Some("changed".into()),
                    image_references: vec!["registry.example/image:latest".into()],
                    credential_id: Some(id("cred-1")),
                },
            )),
            "<modify_oci_image_target oci_image_target_id=\"target-1\"><comment>changed</comment><name>updated</name><image_references>registry.example/image:latest</image_references><credential id=\"cred-1\"/></modify_oci_image_target>"
        );
        assert_eq!(
            xml(delete_oci_image_target(&id("target-1"), true)),
            "<delete_oci_image_target oci_image_target_id=\"target-1\" ultimate=\"1\"/>"
        );
    }
}
