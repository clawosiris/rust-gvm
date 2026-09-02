// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Override command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CreateOverrideResponse, DeleteOverrideResponse, GetOverridesResponse, ModifyOverrideResponse,
};
use crate::types::{CollectionUpdate, EntityId};
use crate::GmpRequest;

/// Optional fields for override create requests.
#[derive(Debug, Clone, Default)]
pub struct OverrideOpts {
    /// Optional text body.
    pub text: Option<String>,
    /// Host entries associated with the request.
    pub hosts: Vec<String>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional severity value.
    pub severity: Option<String>,
    /// Optional replacement severity value.
    pub new_severity: Option<String>,
    /// Optional task identifier.
    pub task_id: Option<EntityId>,
    /// Optional result identifier.
    pub result_id: Option<EntityId>,
    /// Whether the resource should be active.
    pub active: Option<bool>,
}

/// Optional fields for `modify_override` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyOverrideOpts {
    /// Optional text body.
    pub text: Option<String>,
    /// Host update: omit, replace, or explicitly clear.
    pub hosts: CollectionUpdate<String>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional severity value.
    pub severity: Option<String>,
    /// Optional replacement severity value.
    pub new_severity: Option<String>,
    /// Optional task identifier.
    pub task_id: Option<EntityId>,
    /// Optional result identifier.
    pub result_id: Option<EntityId>,
    /// Whether the resource should be active.
    pub active: Option<bool>,
}

/// Options for `get_overrides` requests.
#[derive(Debug, Clone, Default)]
pub struct GetOverridesOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to include associated result references in the response.
    pub result: Option<bool>,
}

/// Semantic request for listing overrides.
#[derive(Debug, Clone, Default)]
pub struct GetOverridesRequest(GetOverridesOpts);

impl GetOverridesRequest {
    /// Create an override-list request.
    #[must_use]
    pub fn new(opts: GetOverridesOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetOverridesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_overrides(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetOverridesRequest {
    type Response = GetOverridesResponse;
}

macro_rules! override_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(override_id: EntityId) -> Self {
                Self(override_id)
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

override_id_request!(GetOverrideRequest, GetOverridesResponse, get_override);
override_id_request!(CloneOverrideRequest, CreateOverrideResponse, clone_override);

/// Semantic request for creating an override.
#[derive(Debug, Clone)]
pub struct CreateOverrideRequest {
    nvt_oid: String,
    opts: OverrideOpts,
}

impl CreateOverrideRequest {
    /// Create an override-creation request.
    #[must_use]
    pub fn new(nvt_oid: impl Into<String>, opts: OverrideOpts) -> Self {
        Self {
            nvt_oid: nvt_oid.into(),
            opts,
        }
    }
}

impl Request for CreateOverrideRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_override(&self.nvt_oid, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateOverrideRequest {
    type Response = CreateOverrideResponse;
}

/// Semantic request for modifying an override.
#[derive(Debug, Clone)]
pub struct ModifyOverrideRequest {
    override_id: EntityId,
    opts: ModifyOverrideOpts,
}

impl ModifyOverrideRequest {
    /// Create an override-modification request.
    #[must_use]
    pub fn new(override_id: EntityId, opts: ModifyOverrideOpts) -> Self {
        Self { override_id, opts }
    }
}

impl Request for ModifyOverrideRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_override(&self.override_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyOverrideRequest {
    type Response = ModifyOverrideResponse;
}

/// Semantic request for deleting an override.
#[derive(Debug, Clone)]
pub struct DeleteOverrideRequest {
    override_id: EntityId,
    ultimate: bool,
}

impl DeleteOverrideRequest {
    /// Create an override-deletion request.
    #[must_use]
    pub fn new(override_id: EntityId, ultimate: bool) -> Self {
        Self {
            override_id,
            ultimate,
        }
    }
}

impl Request for DeleteOverrideRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_override(&self.override_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteOverrideRequest {
    type Response = DeleteOverrideResponse;
}

/// Build a clone request for an existing override.
#[must_use]
pub fn clone_override(override_id: &EntityId) -> impl Request {
    XmlCommand::new("create_override").child_with_text("copy", override_id.as_str())
}

/// Build a `create_override` request.
#[must_use]
pub fn create_override(nvt_oid: &str, opts: OverrideOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_override");
    cmd.add_element("nvt").set_attribute("oid", nvt_oid);
    add_text_element(&mut cmd, "text", opts.text.as_deref());
    if !opts.hosts.is_empty() {
        cmd.add_element_with_text("hosts", &opts.hosts.join(","));
    }
    add_override_tail(
        &mut cmd,
        opts.port.as_deref(),
        opts.severity.as_deref(),
        opts.new_severity.as_deref(),
        opts.task_id.as_ref(),
        opts.result_id.as_ref(),
        opts.active,
    );
    cmd
}

/// Build a `get_overrides` request.
#[must_use]
pub fn get_overrides(opts: GetOverridesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_overrides");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "result", opts.result);
    cmd
}

/// Build a `get_override` request.
#[must_use]
pub fn get_override(override_id: &EntityId) -> impl Request {
    XmlCommand::new("get_overrides")
        .attribute("override_id", override_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_override` request.
#[must_use]
pub fn modify_override(override_id: &EntityId, opts: ModifyOverrideOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_override").attribute("override_id", override_id.as_str());
    add_text_element(&mut cmd, "text", opts.text.as_deref());
    add_hosts_update(&mut cmd, &opts.hosts);
    add_override_tail(
        &mut cmd,
        opts.port.as_deref(),
        opts.severity.as_deref(),
        opts.new_severity.as_deref(),
        opts.task_id.as_ref(),
        opts.result_id.as_ref(),
        opts.active,
    );
    cmd
}

/// Build a `delete_override` request.
#[must_use]
pub fn delete_override(override_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_override")
        .attribute("override_id", override_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_override_tail(
    cmd: &mut XmlCommand,
    port: Option<&str>,
    severity: Option<&str>,
    new_severity: Option<&str>,
    task_id: Option<&EntityId>,
    result_id: Option<&EntityId>,
    active: Option<bool>,
) {
    add_text_element(cmd, "port", port);
    add_text_element(cmd, "severity", severity);
    add_text_element(cmd, "new_severity", new_severity);
    if let Some(task_id) = task_id {
        cmd.add_element("task")
            .set_attribute("id", task_id.as_str());
    }
    if let Some(result_id) = result_id {
        cmd.add_element("result")
            .set_attribute("id", result_id.as_str());
    }
    if let Some(active) = active {
        cmd.add_element_with_text("active", bool_str(active));
    }
}

fn add_hosts_update(cmd: &mut XmlCommand, update: &CollectionUpdate<String>) {
    match update {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(hosts) => {
            cmd.add_element_with_text("hosts", &hosts.join(","));
        }
        CollectionUpdate::Clear => {
            cmd.add_element_with_text("hosts", "");
        }
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
    fn semantic_override_requests_match_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }
        let override_id = id("override-1");
        let get_opts = GetOverridesOpts {
            details: Some(true),
            result: Some(true),
            ..Default::default()
        };
        let opts = OverrideOpts {
            text: Some("body".into()),
            hosts: vec!["192.0.2.1".into()],
            new_severity: Some("3.0".into()),
            ..Default::default()
        };
        let modify_opts = ModifyOverrideOpts {
            hosts: CollectionUpdate::Clear,
            ..Default::default()
        };

        let list = GetOverridesRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_overrides(get_opts).to_bytes());
        associated::<_, GetOverridesResponse>(&list);
        let get = GetOverrideRequest::new(override_id.clone());
        assert_eq!(get.to_bytes(), get_override(&override_id).to_bytes());
        associated::<_, GetOverridesResponse>(&get);
        let create = CreateOverrideRequest::new("1.3.6.1", opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_override("1.3.6.1", opts).to_bytes()
        );
        associated::<_, CreateOverrideResponse>(&create);
        let clone = CloneOverrideRequest::new(override_id.clone());
        assert_eq!(clone.to_bytes(), clone_override(&override_id).to_bytes());
        associated::<_, CreateOverrideResponse>(&clone);
        let modify = ModifyOverrideRequest::new(override_id.clone(), modify_opts.clone());
        assert_eq!(
            modify.to_bytes(),
            modify_override(&override_id, modify_opts).to_bytes()
        );
        associated::<_, ModifyOverrideResponse>(&modify);
        let delete = DeleteOverrideRequest::new(override_id.clone(), true);
        assert_eq!(
            delete.to_bytes(),
            delete_override(&override_id, true).to_bytes()
        );
        associated::<_, DeleteOverrideResponse>(&delete);
    }

    #[test]
    fn override_commands_build_xml() {
        let rendered = xml(create_override(
            "oid",
            OverrideOpts {
                text: Some("body".into()),
                new_severity: Some("7.5".into()),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<nvt oid=\"oid\"/>"));
        assert!(rendered.contains("<new_severity>7.5</new_severity>"));
        assert_eq!(
            xml(clone_override(&id("o1"))),
            "<create_override><copy>o1</copy></create_override>"
        );
        assert_eq!(
            xml(get_override(&id("o1"))),
            "<get_overrides details=\"1\" override_id=\"o1\"/>"
        );
    }

    #[test]
    fn override_modify_get_delete_build_xml() {
        let rendered = xml(get_overrides(GetOverridesOpts {
            filter_string: Some("name=foo".into()),
            details: Some(true),
            result: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        assert!(rendered.contains("result=\"1\""));
        let rendered = xml(modify_override(
            &id("o1"),
            ModifyOverrideOpts {
                text: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_override override_id=\"o1\"><text>updated</text></modify_override>"
        );
        assert_eq!(
            xml(delete_override(&id("o1"), false)),
            "<delete_override override_id=\"o1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn modify_override_distinguishes_omitted_replaced_and_cleared_hosts() {
        assert_eq!(
            xml(modify_override(&id("o1"), ModifyOverrideOpts::default())),
            "<modify_override override_id=\"o1\"/>"
        );
        assert_eq!(
            xml(modify_override(
                &id("o1"),
                ModifyOverrideOpts {
                    hosts: CollectionUpdate::replace(["192.0.2.1".into(), "192.0.2.2".into()]),
                    ..Default::default()
                }
            )),
            "<modify_override override_id=\"o1\"><hosts>192.0.2.1,192.0.2.2</hosts></modify_override>"
        );
        assert_eq!(
            xml(modify_override(
                &id("o1"),
                ModifyOverrideOpts {
                    hosts: CollectionUpdate::Clear,
                    ..Default::default()
                }
            )),
            "<modify_override override_id=\"o1\"><hosts></hosts></modify_override>"
        );
    }
}
