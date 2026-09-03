// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Web application target command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::responses::{
    CreateWebApplicationTargetResponse, DeleteWebApplicationTargetResponse,
    GetWebApplicationTargetsResponse, ModifyWebApplicationTargetResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for `create_web_application_target` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateWebApplicationTargetOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// URLs to exclude from the scan.
    pub exclude_urls: Vec<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

/// Options for `get_web_application_targets` requests.
#[derive(Debug, Clone, Default)]
pub struct GetWebApplicationTargetsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to include tasks that use the target.
    pub tasks: Option<bool>,
}

/// Optional fields for `modify_web_application_target` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyWebApplicationTargetOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// URLs to scan.
    pub urls: Vec<String>,
    /// URLs to exclude from the scan.
    pub exclude_urls: Vec<String>,
    /// Optional credential used for the target.
    pub credential_id: Option<EntityId>,
}

/// Semantic request for cloning a web application target.
#[derive(Debug, Clone)]
pub struct CloneWebApplicationTargetRequest {
    web_application_target_id: EntityId,
}

impl CloneWebApplicationTargetRequest {
    /// Create a web-application-target clone request.
    #[must_use]
    pub fn new(web_application_target_id: EntityId) -> Self {
        Self {
            web_application_target_id,
        }
    }
}

impl Request for CloneWebApplicationTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_web_application_target(&self.web_application_target_id).to_bytes()
    }
}

impl GmpRequest for CloneWebApplicationTargetRequest {
    type Response = CreateWebApplicationTargetResponse;
}

/// Semantic request for creating a web application target.
#[derive(Debug, Clone)]
pub struct CreateWebApplicationTargetRequest {
    name: String,
    urls: Vec<String>,
    opts: CreateWebApplicationTargetOpts,
}

impl CreateWebApplicationTargetRequest {
    /// Create a web-application-target creation request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        urls: Vec<String>,
        opts: CreateWebApplicationTargetOpts,
    ) -> Self {
        Self {
            name: name.into(),
            urls,
            opts,
        }
    }
}

impl Request for CreateWebApplicationTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_web_application_target(&self.name, &self.urls, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateWebApplicationTargetRequest {
    type Response = CreateWebApplicationTargetResponse;
}

/// Semantic request for listing web application targets.
#[derive(Debug, Clone, Default)]
pub struct GetWebApplicationTargetsRequest {
    opts: GetWebApplicationTargetsOpts,
}

impl GetWebApplicationTargetsRequest {
    /// Create a web-application-target list request.
    #[must_use]
    pub fn new(opts: GetWebApplicationTargetsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetWebApplicationTargetsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_web_application_targets(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetWebApplicationTargetsRequest {
    type Response = GetWebApplicationTargetsResponse;
}

/// Semantic request for one detailed web application target.
#[derive(Debug, Clone)]
pub struct GetWebApplicationTargetRequest {
    web_application_target_id: EntityId,
    tasks: Option<bool>,
}

impl GetWebApplicationTargetRequest {
    /// Create a detailed web-application-target request.
    #[must_use]
    pub fn new(web_application_target_id: EntityId, tasks: Option<bool>) -> Self {
        Self {
            web_application_target_id,
            tasks,
        }
    }
}

impl Request for GetWebApplicationTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_web_application_target(&self.web_application_target_id, self.tasks).to_bytes()
    }
}

impl GmpRequest for GetWebApplicationTargetRequest {
    type Response = GetWebApplicationTargetsResponse;
}

/// Semantic request for modifying a web application target.
#[derive(Debug, Clone)]
pub struct ModifyWebApplicationTargetRequest {
    web_application_target_id: EntityId,
    opts: ModifyWebApplicationTargetOpts,
}

impl ModifyWebApplicationTargetRequest {
    /// Create a web-application-target modification request.
    #[must_use]
    pub fn new(web_application_target_id: EntityId, opts: ModifyWebApplicationTargetOpts) -> Self {
        Self {
            web_application_target_id,
            opts,
        }
    }
}

impl Request for ModifyWebApplicationTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_web_application_target(&self.web_application_target_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyWebApplicationTargetRequest {
    type Response = ModifyWebApplicationTargetResponse;
}

/// Semantic request for deleting a web application target.
#[derive(Debug, Clone)]
pub struct DeleteWebApplicationTargetRequest {
    web_application_target_id: EntityId,
    ultimate: bool,
}

impl DeleteWebApplicationTargetRequest {
    /// Create a web-application-target deletion request.
    #[must_use]
    pub fn new(web_application_target_id: EntityId, ultimate: bool) -> Self {
        Self {
            web_application_target_id,
            ultimate,
        }
    }
}

impl Request for DeleteWebApplicationTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_web_application_target(&self.web_application_target_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteWebApplicationTargetRequest {
    type Response = DeleteWebApplicationTargetResponse;
}

/// Build a clone request for an existing web application target.
#[must_use]
pub fn clone_web_application_target(web_application_target_id: &EntityId) -> impl Request {
    XmlCommand::new("create_web_application_target")
        .child_with_text("copy", web_application_target_id.as_str())
}

/// Build a `create_web_application_target` request.
#[must_use]
pub fn create_web_application_target(
    name: &str,
    urls: &[String],
    opts: CreateWebApplicationTargetOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_web_application_target");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("urls", &urls.join(","));
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_string_list_text(&mut cmd, "exclude_urls", &opts.exclude_urls);
    add_optional_id_element(&mut cmd, "credential", opts.credential_id.as_ref());
    cmd
}

/// Build a `get_web_application_targets` request.
#[must_use]
pub fn get_web_application_targets(opts: GetWebApplicationTargetsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_web_application_targets");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "tasks", opts.tasks);
    cmd
}

/// Build a `get_web_application_target` request.
#[must_use]
pub fn get_web_application_target(
    web_application_target_id: &EntityId,
    tasks: Option<bool>,
) -> impl Request {
    let mut cmd = XmlCommand::new("get_web_application_targets").attribute(
        "web_application_target_id",
        web_application_target_id.as_str(),
    );
    set_optional_bool_attr(&mut cmd, "tasks", tasks);
    cmd
}

/// Build a `modify_web_application_target` request.
#[must_use]
pub fn modify_web_application_target(
    web_application_target_id: &EntityId,
    opts: ModifyWebApplicationTargetOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("modify_web_application_target").attribute(
        "web_application_target_id",
        web_application_target_id.as_str(),
    );
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_string_list_text(&mut cmd, "urls", &opts.urls);
    add_string_list_text(&mut cmd, "exclude_urls", &opts.exclude_urls);
    add_optional_id_element(&mut cmd, "credential", opts.credential_id.as_ref());
    cmd
}

/// Build a `delete_web_application_target` request.
#[must_use]
pub fn delete_web_application_target(
    web_application_target_id: &EntityId,
    ultimate: bool,
) -> impl Request {
    XmlCommand::new("delete_web_application_target")
        .attribute(
            "web_application_target_id",
            web_application_target_id.as_str(),
        )
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
    fn web_application_target_create_and_clone_build_xml() {
        assert_eq!(
            xml(create_web_application_target(
                "web",
                &["https://example.com".into(), "https://example.com/app".into()],
                CreateWebApplicationTargetOpts {
                    comment: Some("note".into()),
                    exclude_urls: vec!["https://example.com/logout".into()],
                    credential_id: Some(id("cred-1")),
                },
            )),
            "<create_web_application_target><name>web</name><urls>https://example.com,https://example.com/app</urls><comment>note</comment><exclude_urls>https://example.com/logout</exclude_urls><credential id=\"cred-1\"/></create_web_application_target>"
        );
        assert_eq!(
            xml(clone_web_application_target(&id("target-1"))),
            "<create_web_application_target><copy>target-1</copy></create_web_application_target>"
        );
    }

    #[test]
    fn web_application_target_get_builds_xml() {
        assert_eq!(
            xml(get_web_application_targets(GetWebApplicationTargetsOpts {
                filter_string: Some("name=web".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(false),
                tasks: Some(true),
            })),
            "<get_web_application_targets filt_id=\"filter-1\" filter=\"name=web\" tasks=\"1\" trash=\"0\"/>"
        );
        assert_eq!(
            xml(get_web_application_target(&id("target-1"), Some(false))),
            "<get_web_application_targets tasks=\"0\" web_application_target_id=\"target-1\"/>"
        );
    }

    #[test]
    fn web_application_target_modify_and_delete_build_xml() {
        assert_eq!(
            xml(modify_web_application_target(
                &id("target-1"),
                ModifyWebApplicationTargetOpts {
                    name: Some("updated".into()),
                    comment: Some("changed".into()),
                    urls: vec!["https://example.com".into()],
                    exclude_urls: vec!["https://example.com/logout".into()],
                    credential_id: Some(id("cred-1")),
                },
            )),
            "<modify_web_application_target web_application_target_id=\"target-1\"><comment>changed</comment><name>updated</name><urls>https://example.com</urls><exclude_urls>https://example.com/logout</exclude_urls><credential id=\"cred-1\"/></modify_web_application_target>"
        );
        assert_eq!(
            xml(delete_web_application_target(&id("target-1"), true)),
            "<delete_web_application_target ultimate=\"1\" web_application_target_id=\"target-1\"/>"
        );
    }

    #[test]
    fn semantic_requests_preserve_builder_bytes_and_response_associations() {
        fn assert_response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let target_id = id("target-1");
        let request = CloneWebApplicationTargetRequest::new(target_id.clone());
        assert_eq!(
            request.to_bytes(),
            clone_web_application_target(&target_id).to_bytes()
        );
        assert_response::<_, CreateWebApplicationTargetResponse>(&request);

        let create_opts = CreateWebApplicationTargetOpts {
            comment: Some("note".into()),
            exclude_urls: vec!["https://example.com/logout".into()],
            credential_id: Some(id("cred-1")),
        };
        let urls = vec!["https://example.com".into()];
        let request =
            CreateWebApplicationTargetRequest::new("web", urls.clone(), create_opts.clone());
        assert_eq!(
            request.to_bytes(),
            create_web_application_target("web", &urls, create_opts).to_bytes()
        );
        assert_response::<_, CreateWebApplicationTargetResponse>(&request);

        let get_opts = GetWebApplicationTargetsOpts {
            filter_string: Some("name=web".into()),
            tasks: Some(true),
            ..Default::default()
        };
        let request = GetWebApplicationTargetsRequest::new(get_opts.clone());
        assert_eq!(
            request.to_bytes(),
            get_web_application_targets(get_opts).to_bytes()
        );
        assert_response::<_, GetWebApplicationTargetsResponse>(&request);

        let request = GetWebApplicationTargetRequest::new(target_id.clone(), Some(false));
        assert_eq!(
            request.to_bytes(),
            get_web_application_target(&target_id, Some(false)).to_bytes()
        );
        assert_response::<_, GetWebApplicationTargetsResponse>(&request);

        let modify_opts = ModifyWebApplicationTargetOpts {
            name: Some("updated".into()),
            urls: vec!["https://example.com/app".into()],
            exclude_urls: vec!["https://example.com/logout".into()],
            ..Default::default()
        };
        let request =
            ModifyWebApplicationTargetRequest::new(target_id.clone(), modify_opts.clone());
        assert_eq!(
            request.to_bytes(),
            modify_web_application_target(&target_id, modify_opts).to_bytes()
        );
        assert_response::<_, ModifyWebApplicationTargetResponse>(&request);

        let request = DeleteWebApplicationTargetRequest::new(target_id.clone(), true);
        assert_eq!(
            request.to_bytes(),
            delete_web_application_target(&target_id, true).to_bytes()
        );
        assert_response::<_, DeleteWebApplicationTargetResponse>(&request);
    }
}
