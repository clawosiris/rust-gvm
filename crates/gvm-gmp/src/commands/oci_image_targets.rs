// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! OCI image target command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::responses::{
    CreateOciImageTargetResponse, DeleteOciImageTargetResponse, GetOciImageTargetsResponse,
    ModifyOciImageTargetResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

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

/// Semantic request for cloning an OCI image target.
#[derive(Debug, Clone)]
pub struct CloneOciImageTargetRequest {
    oci_image_target_id: EntityId,
}

impl CloneOciImageTargetRequest {
    /// Create an OCI-image-target clone request.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId) -> Self {
        Self {
            oci_image_target_id,
        }
    }
}

impl Request for CloneOciImageTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_oci_image_target(&self.oci_image_target_id).to_bytes()
    }
}

impl GmpRequest for CloneOciImageTargetRequest {
    type Response = CreateOciImageTargetResponse;
}

/// Semantic request for creating an OCI image target.
#[derive(Debug, Clone)]
pub struct CreateOciImageTargetRequest {
    name: String,
    image_references: Vec<String>,
    opts: CreateOciImageTargetOpts,
}

impl CreateOciImageTargetRequest {
    /// Create an OCI-image-target creation request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        image_references: Vec<String>,
        opts: CreateOciImageTargetOpts,
    ) -> Self {
        Self {
            name: name.into(),
            image_references,
            opts,
        }
    }
}

impl Request for CreateOciImageTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_oci_image_target(&self.name, &self.image_references, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateOciImageTargetRequest {
    type Response = CreateOciImageTargetResponse;
}

/// Semantic request for listing OCI image targets.
#[derive(Debug, Clone, Default)]
pub struct GetOciImageTargetsRequest {
    opts: GetOciImageTargetsOpts,
}

impl GetOciImageTargetsRequest {
    /// Create an OCI-image-target list request.
    #[must_use]
    pub fn new(opts: GetOciImageTargetsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetOciImageTargetsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_oci_image_targets(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetOciImageTargetsRequest {
    type Response = GetOciImageTargetsResponse;
}

/// Semantic request for one detailed OCI image target.
#[derive(Debug, Clone)]
pub struct GetOciImageTargetRequest {
    oci_image_target_id: EntityId,
    tasks: Option<bool>,
}

impl GetOciImageTargetRequest {
    /// Create a detailed OCI-image-target request.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId, tasks: Option<bool>) -> Self {
        Self {
            oci_image_target_id,
            tasks,
        }
    }
}

impl Request for GetOciImageTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_oci_image_target(&self.oci_image_target_id, self.tasks).to_bytes()
    }
}

impl GmpRequest for GetOciImageTargetRequest {
    type Response = GetOciImageTargetsResponse;
}

/// Semantic request for modifying an OCI image target.
#[derive(Debug, Clone)]
pub struct ModifyOciImageTargetRequest {
    oci_image_target_id: EntityId,
    opts: ModifyOciImageTargetOpts,
}

impl ModifyOciImageTargetRequest {
    /// Create an OCI-image-target modification request.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId, opts: ModifyOciImageTargetOpts) -> Self {
        Self {
            oci_image_target_id,
            opts,
        }
    }
}

impl Request for ModifyOciImageTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_oci_image_target(&self.oci_image_target_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyOciImageTargetRequest {
    type Response = ModifyOciImageTargetResponse;
}

/// Semantic request for deleting an OCI image target.
#[derive(Debug, Clone)]
pub struct DeleteOciImageTargetRequest {
    oci_image_target_id: EntityId,
    ultimate: bool,
}

impl DeleteOciImageTargetRequest {
    /// Create an OCI-image-target deletion request.
    #[must_use]
    pub fn new(oci_image_target_id: EntityId, ultimate: bool) -> Self {
        Self {
            oci_image_target_id,
            ultimate,
        }
    }
}

impl Request for DeleteOciImageTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_oci_image_target(&self.oci_image_target_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteOciImageTargetRequest {
    type Response = DeleteOciImageTargetResponse;
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

    #[test]
    fn semantic_requests_preserve_builder_bytes_and_response_associations() {
        fn assert_response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let target_id = id("target-1");
        let request = CloneOciImageTargetRequest::new(target_id.clone());
        assert_eq!(
            request.to_bytes(),
            clone_oci_image_target(&target_id).to_bytes()
        );
        assert_response::<_, CreateOciImageTargetResponse>(&request);

        let create_opts = CreateOciImageTargetOpts {
            comment: Some("note".into()),
            credential_id: Some(id("cred-1")),
        };
        let image_references = vec!["registry.example/image:1".into()];
        let request =
            CreateOciImageTargetRequest::new("oci", image_references.clone(), create_opts.clone());
        assert_eq!(
            request.to_bytes(),
            create_oci_image_target("oci", &image_references, create_opts).to_bytes()
        );
        assert_response::<_, CreateOciImageTargetResponse>(&request);

        let get_opts = GetOciImageTargetsOpts {
            filter_string: Some("name=oci".into()),
            tasks: Some(true),
            ..Default::default()
        };
        let request = GetOciImageTargetsRequest::new(get_opts.clone());
        assert_eq!(
            request.to_bytes(),
            get_oci_image_targets(get_opts).to_bytes()
        );
        assert_response::<_, GetOciImageTargetsResponse>(&request);

        let request = GetOciImageTargetRequest::new(target_id.clone(), Some(false));
        assert_eq!(
            request.to_bytes(),
            get_oci_image_target(&target_id, Some(false)).to_bytes()
        );
        assert_response::<_, GetOciImageTargetsResponse>(&request);

        let modify_opts = ModifyOciImageTargetOpts {
            name: Some("updated".into()),
            image_references: vec!["registry.example/image:latest".into()],
            ..Default::default()
        };
        let request = ModifyOciImageTargetRequest::new(target_id.clone(), modify_opts.clone());
        assert_eq!(
            request.to_bytes(),
            modify_oci_image_target(&target_id, modify_opts).to_bytes()
        );
        assert_response::<_, ModifyOciImageTargetResponse>(&request);

        let request = DeleteOciImageTargetRequest::new(target_id.clone(), true);
        assert_eq!(
            request.to_bytes(),
            delete_oci_image_target(&target_id, true).to_bytes()
        );
        assert_response::<_, DeleteOciImageTargetResponse>(&request);
    }
}
