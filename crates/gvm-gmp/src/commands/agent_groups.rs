// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Agent group command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::responses::{
    CloneAgentGroupResponse, CreateAgentGroupResponse, DeleteAgentGroupResponse,
    GetAgentGroupsResponse, ModifyAgentGroupResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for `create_agent_group` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateAgentGroupOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
}

/// Options for `get_agent_groups` requests.
#[derive(Debug, Clone, Default)]
pub struct GetAgentGroupsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
}

/// Optional fields for `modify_agent_group` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyAgentGroupOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional agent ids to set for the group.
    pub agent_ids: Vec<EntityId>,
}

/// Semantic request for cloning an agent group.
#[derive(Debug, Clone)]
pub struct CloneAgentGroupRequest(EntityId);

impl CloneAgentGroupRequest {
    /// Create an agent-group clone request.
    #[must_use]
    pub fn new(agent_group_id: EntityId) -> Self {
        Self(agent_group_id)
    }
}

impl Request for CloneAgentGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_agent_group(&self.0).to_bytes()
    }
}

impl GmpRequest for CloneAgentGroupRequest {
    type Response = CloneAgentGroupResponse;
}

/// Semantic request for creating an agent group.
#[derive(Debug, Clone)]
pub struct CreateAgentGroupRequest {
    name: String,
    agent_ids: Vec<EntityId>,
    scheduler_cron_time: String,
    opts: CreateAgentGroupOpts,
}

impl CreateAgentGroupRequest {
    /// Create an agent-group creation request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        agent_ids: Vec<EntityId>,
        scheduler_cron_time: impl Into<String>,
        opts: CreateAgentGroupOpts,
    ) -> Self {
        Self {
            name: name.into(),
            agent_ids,
            scheduler_cron_time: scheduler_cron_time.into(),
            opts,
        }
    }
}

impl Request for CreateAgentGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_agent_group(
            &self.name,
            &self.agent_ids,
            &self.scheduler_cron_time,
            self.opts.clone(),
        )
        .to_bytes()
    }
}

impl GmpRequest for CreateAgentGroupRequest {
    type Response = CreateAgentGroupResponse;
}

/// Semantic request for listing agent groups.
#[derive(Debug, Clone, Default)]
pub struct GetAgentGroupsRequest(GetAgentGroupsOpts);

impl GetAgentGroupsRequest {
    /// Create an agent-group list request.
    #[must_use]
    pub fn new(opts: GetAgentGroupsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetAgentGroupsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_agent_groups(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetAgentGroupsRequest {
    type Response = GetAgentGroupsResponse;
}

/// Semantic request for one agent group.
#[derive(Debug, Clone)]
pub struct GetAgentGroupRequest(EntityId);

impl GetAgentGroupRequest {
    /// Create a single agent-group request.
    #[must_use]
    pub fn new(agent_group_id: EntityId) -> Self {
        Self(agent_group_id)
    }
}

impl Request for GetAgentGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_agent_group(&self.0).to_bytes()
    }
}

impl GmpRequest for GetAgentGroupRequest {
    type Response = GetAgentGroupsResponse;
}

/// Semantic request for modifying an agent group.
#[derive(Debug, Clone)]
pub struct ModifyAgentGroupRequest {
    agent_group_id: EntityId,
    scheduler_cron_time: String,
    opts: ModifyAgentGroupOpts,
}

impl ModifyAgentGroupRequest {
    /// Create an agent-group modification request.
    #[must_use]
    pub fn new(
        agent_group_id: EntityId,
        scheduler_cron_time: impl Into<String>,
        opts: ModifyAgentGroupOpts,
    ) -> Self {
        Self {
            agent_group_id,
            scheduler_cron_time: scheduler_cron_time.into(),
            opts,
        }
    }
}

impl Request for ModifyAgentGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_agent_group(
            &self.agent_group_id,
            &self.scheduler_cron_time,
            self.opts.clone(),
        )
        .to_bytes()
    }
}

impl GmpRequest for ModifyAgentGroupRequest {
    type Response = ModifyAgentGroupResponse;
}

/// Semantic request for deleting an agent group.
#[derive(Debug, Clone)]
pub struct DeleteAgentGroupRequest {
    agent_group_id: EntityId,
    ultimate: bool,
}

impl DeleteAgentGroupRequest {
    /// Create an agent-group deletion request.
    #[must_use]
    pub fn new(agent_group_id: EntityId, ultimate: bool) -> Self {
        Self {
            agent_group_id,
            ultimate,
        }
    }
}

impl Request for DeleteAgentGroupRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_agent_group(&self.agent_group_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteAgentGroupRequest {
    type Response = DeleteAgentGroupResponse;
}

/// Build a clone request for an existing agent group.
#[must_use]
pub fn clone_agent_group(agent_group_id: &EntityId) -> impl Request {
    XmlCommand::new("create_agent_group").child_with_text("copy", agent_group_id.as_str())
}

/// Build a `create_agent_group` request.
#[must_use]
pub fn create_agent_group(
    name: &str,
    agent_ids: &[EntityId],
    scheduler_cron_time: &str,
    opts: CreateAgentGroupOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_agent_group");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("scheduler_cron_time", scheduler_cron_time);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_agent_elements(&mut cmd, agent_ids);
    cmd
}

/// Build a `get_agent_groups` request.
#[must_use]
pub fn get_agent_groups(opts: GetAgentGroupsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_agent_groups");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    cmd
}

/// Build a `get_agent_group` request.
#[must_use]
pub fn get_agent_group(agent_group_id: &EntityId) -> impl Request {
    XmlCommand::new("get_agent_groups").attribute("agent_group_id", agent_group_id.as_str())
}

/// Build a `modify_agent_group` request.
#[must_use]
pub fn modify_agent_group(
    agent_group_id: &EntityId,
    scheduler_cron_time: &str,
    opts: ModifyAgentGroupOpts,
) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_agent_group").attribute("agent_group_id", agent_group_id.as_str());
    cmd.add_element_with_text("scheduler_cron_time", scheduler_cron_time);
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_agent_elements(&mut cmd, &opts.agent_ids);
    cmd
}

/// Build a `delete_agent_group` request.
#[must_use]
pub fn delete_agent_group(agent_group_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_agent_group")
        .attribute("agent_group_id", agent_group_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_agent_elements(cmd: &mut XmlCommand, agent_ids: &[EntityId]) {
    if agent_ids.is_empty() {
        return;
    }

    let agents = cmd.add_element("agents");
    for agent_id in agent_ids {
        agents
            .add_child("agent")
            .set_attribute("id", agent_id.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;
    use crate::responses::{
        CreateAgentGroupResponse, DeleteAgentGroupResponse, GetAgentGroupsResponse,
        ModifyAgentGroupResponse,
    };

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn agent_group_create_and_clone_build_xml() {
        assert_eq!(
            xml(create_agent_group(
                "agents",
                &[id("agent-1"), id("agent-2")],
                "0 */5 * * *",
                CreateAgentGroupOpts {
                    comment: Some("scheduled".into()),
                },
            )),
            "<create_agent_group><name>agents</name><scheduler_cron_time>0 */5 * * *</scheduler_cron_time><comment>scheduled</comment><agents><agent id=\"agent-1\"/><agent id=\"agent-2\"/></agents></create_agent_group>"
        );
        assert_eq!(
            xml(clone_agent_group(&id("group-1"))),
            "<create_agent_group><copy>group-1</copy></create_agent_group>"
        );
    }

    #[test]
    fn agent_group_get_builds_xml() {
        assert_eq!(
            xml(get_agent_groups(GetAgentGroupsOpts {
                filter_string: Some("name=agents".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(true),
            })),
            "<get_agent_groups filt_id=\"filter-1\" filter=\"name=agents\" trash=\"1\"/>"
        );
        assert_eq!(
            xml(get_agent_group(&id("group-1"))),
            "<get_agent_groups agent_group_id=\"group-1\"/>"
        );
    }

    #[test]
    fn agent_group_modify_and_delete_build_xml() {
        assert_eq!(
            xml(modify_agent_group(
                &id("group-1"),
                "0 */10 * * *",
                ModifyAgentGroupOpts {
                    name: Some("updated".into()),
                    comment: Some("changed".into()),
                    agent_ids: vec![id("agent-3")],
                },
            )),
            "<modify_agent_group agent_group_id=\"group-1\"><scheduler_cron_time>0 */10 * * *</scheduler_cron_time><name>updated</name><comment>changed</comment><agents><agent id=\"agent-3\"/></agents></modify_agent_group>"
        );
        assert_eq!(
            xml(delete_agent_group(&id("group-1"), false)),
            "<delete_agent_group agent_group_id=\"group-1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn semantic_requests_preserve_builder_bytes_and_response_associations() {
        fn groups<R: GmpRequest<Response = GetAgentGroupsResponse>>(_: &R) {}
        fn create<R: GmpRequest<Response = CreateAgentGroupResponse>>(_: &R) {}
        fn modify<R: GmpRequest<Response = ModifyAgentGroupResponse>>(_: &R) {}
        fn delete<R: GmpRequest<Response = DeleteAgentGroupResponse>>(_: &R) {}

        let group_id = id("group-1");
        let agent_ids = vec![id("agent-1"), id("agent-2")];
        let create_opts = CreateAgentGroupOpts {
            comment: Some("scheduled".into()),
        };
        let list_opts = GetAgentGroupsOpts {
            filter_string: Some("name=agents".into()),
            filter_id: Some(id("filter-1")),
            trash: Some(true),
        };
        let modify_opts = ModifyAgentGroupOpts {
            name: Some("updated".into()),
            comment: Some("changed".into()),
            agent_ids: vec![id("agent-3")],
        };

        let clone = CloneAgentGroupRequest::new(group_id.clone());
        create(&clone);
        assert_eq!(clone.to_bytes(), clone_agent_group(&group_id).to_bytes());
        let create_request = CreateAgentGroupRequest::new(
            "agents",
            agent_ids.clone(),
            "0 */5 * * *",
            create_opts.clone(),
        );
        create(&create_request);
        assert_eq!(
            create_request.to_bytes(),
            create_agent_group("agents", &agent_ids, "0 */5 * * *", create_opts).to_bytes()
        );
        let list = GetAgentGroupsRequest::new(list_opts.clone());
        groups(&list);
        assert_eq!(list.to_bytes(), get_agent_groups(list_opts).to_bytes());
        let get = GetAgentGroupRequest::new(group_id.clone());
        groups(&get);
        assert_eq!(get.to_bytes(), get_agent_group(&group_id).to_bytes());
        let modify_request =
            ModifyAgentGroupRequest::new(group_id.clone(), "0 */10 * * *", modify_opts.clone());
        modify(&modify_request);
        assert_eq!(
            modify_request.to_bytes(),
            modify_agent_group(&group_id, "0 */10 * * *", modify_opts).to_bytes()
        );
        let delete_request = DeleteAgentGroupRequest::new(group_id.clone(), true);
        delete(&delete_request);
        assert_eq!(
            delete_request.to_bytes(),
            delete_agent_group(&group_id, true).to_bytes()
        );
    }
}
