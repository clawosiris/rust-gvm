// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Task command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{
    add_filter_attrs, add_id_element, add_optional_id_element, add_preferences,
    add_scalar_id_update, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::enums::HostsOrdering;
use crate::responses::{
    CreateTaskResponse, DeleteTaskResponse, GetTasksResponse, ModifyTaskResponse, MoveTaskResponse,
    ResumeTaskResponse, StartTaskResponse, StopTaskResponse,
};
use crate::types::{CollectionUpdate, EntityId, ScalarUpdate};
use crate::GmpRequest;

/// Optional fields for `create_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateTaskOpts {
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional task host ordering.
    pub hosts_ordering: Option<HostsOrdering>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Optional fields for `create_agent_group_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateAgentGroupTaskOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Optional fields for `create_oci_image_target_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateOciImageTargetTaskOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Optional fields for web application target `create_task` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateWebApplicationTaskOpts {
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional schedule identifier.
    pub schedule_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Vec<EntityId>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional schedule period count, serialized only when [`Self::schedule_id`] is set.
    pub schedule_periods: Option<u32>,
    /// Observer names associated with the task.
    pub observers: Vec<String>,
    /// Observer group identifiers associated with the task.
    pub observer_group_ids: Vec<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Options for `get_tasks` requests.
#[derive(Debug, Clone, Default)]
pub struct GetTasksOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to limit results to scheduled tasks.
    pub schedules_only: Option<bool>,
    /// Whether pagination should be ignored.
    pub ignore_pagination: Option<bool>,
}

/// Optional fields for `modify_task` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyTaskOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Whether the task should be alterable.
    pub alterable: Option<bool>,
    /// Optional task host ordering.
    pub hosts_ordering: Option<HostsOrdering>,
    /// Schedule relationship update: omit, set, or detach.
    pub schedule_id: ScalarUpdate<EntityId>,
    /// Optional schedule period count.
    pub schedule_periods: Option<u32>,
    /// Optional target identifier.
    pub target_id: Option<EntityId>,
    /// Optional scan configuration identifier.
    pub config_id: Option<EntityId>,
    /// Optional scanner identifier.
    pub scanner_id: Option<EntityId>,
    /// Alert identifiers associated with the request.
    pub alert_ids: Option<Vec<EntityId>>,
    /// Observer-user update: omit, replace, or clear.
    ///
    /// An explicit clear emits an empty `<observers>` element, which gvmd
    /// interprets as removing every user observer.
    pub observers: CollectionUpdate<String>,
    /// Observer-group update: omit, replace, or clear.
    ///
    /// gvmd accepts group children on `modify_task` even though the published
    /// GMP grammar documents only observer-user text. Because opening the
    /// shared `<observers>` container also updates the user list, a group
    /// update requires [`Self::observers`] to explicitly replace or clear the
    /// users. Clearing groups is encoded with gvmd's `group id="0"` sentinel.
    pub observer_group_ids: CollectionUpdate<EntityId>,
    /// Preference key/value pairs to include.
    pub preferences: Vec<(String, String)>,
}

/// Errors raised while building a `modify_task` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModifyTaskError {
    /// A group update would otherwise clear users implicitly on gvmd.
    #[error(
        "updating task observer groups requires explicitly replacing or clearing observer users"
    )]
    ObserverGroupsWithoutUserUpdate,
}

/// Semantic request for listing standard scan tasks.
///
/// The associated response is fixed at compile time:
///
/// ```compile_fail
/// use gvm_gmp::commands::tasks::{GetTasksOpts, GetTasksRequest};
/// use gvm_gmp::responses::CreateTaskResponse;
/// use gvm_gmp::GmpRequest;
///
/// fn require_create<R: GmpRequest<Response = CreateTaskResponse>>(_: R) {}
/// require_create(GetTasksRequest::new(GetTasksOpts::default()));
/// ```
#[derive(Debug, Clone, Default)]
pub struct GetTasksRequest {
    opts: GetTasksOpts,
}

impl GetTasksRequest {
    /// Create a standard scan-task list request.
    #[must_use]
    pub fn new(opts: GetTasksOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetTasksRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_tasks(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetTasksRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for one detailed standard scan task.
#[derive(Debug, Clone)]
pub struct GetTaskRequest {
    task_id: EntityId,
}

impl GetTaskRequest {
    /// Create a detailed single-task request.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self { task_id }
    }
}

impl Request for GetTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_task(&self.task_id).to_bytes()
    }
}

impl GmpRequest for GetTaskRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for creating a standard scan task.
#[derive(Debug, Clone)]
pub struct CreateTaskRequest {
    name: String,
    config_id: EntityId,
    target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateTaskOpts,
}

impl CreateTaskRequest {
    /// Create a standard scan-task creation request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        config_id: EntityId,
        target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            config_id,
            target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_task(
            &self.name,
            &self.config_id,
            &self.target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }
}

impl GmpRequest for CreateTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for cloning a standard scan task.
#[derive(Debug, Clone)]
pub struct CloneTaskRequest {
    task_id: EntityId,
}

impl CloneTaskRequest {
    /// Create a task-clone request.
    #[must_use]
    pub fn new(task_id: EntityId) -> Self {
        Self { task_id }
    }
}

impl Request for CloneTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        clone_task(&self.task_id).to_bytes()
    }
}

impl GmpRequest for CloneTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for modifying a standard scan task.
#[derive(Debug, Clone)]
pub struct ModifyTaskRequest {
    task_id: EntityId,
    opts: ModifyTaskOpts,
}

impl ModifyTaskRequest {
    /// Validate and create a task-modification request.
    ///
    /// # Errors
    /// Returns the same construction errors as [`modify_task`].
    pub fn new(task_id: EntityId, opts: ModifyTaskOpts) -> Result<Self, ModifyTaskError> {
        validate_modify_task_opts(&opts)?;
        Ok(Self { task_id, opts })
    }
}

impl Request for ModifyTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_task_with_usage(&self.task_id, self.opts.clone(), None).to_bytes()
    }
}

impl GmpRequest for ModifyTaskRequest {
    type Response = ModifyTaskResponse;
}

/// Semantic request for deleting a standard scan task.
#[derive(Debug, Clone)]
pub struct DeleteTaskRequest {
    task_id: EntityId,
    ultimate: bool,
}

impl DeleteTaskRequest {
    /// Create a task-deletion request.
    #[must_use]
    pub fn new(task_id: EntityId, ultimate: bool) -> Self {
        Self { task_id, ultimate }
    }
}

impl Request for DeleteTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_task(&self.task_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteTaskRequest {
    type Response = DeleteTaskResponse;
}

macro_rules! task_action_request {
    ($request:ident, $response:ty, $builder:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            task_id: EntityId,
        }

        impl $request {
            /// Create the task-action request.
            #[must_use]
            pub fn new(task_id: EntityId) -> Self {
                Self { task_id }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.task_id).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = $response;
        }
    };
}

task_action_request!(
    StartTaskRequest,
    StartTaskResponse,
    start_task,
    "Semantic request for starting a standard scan task."
);
task_action_request!(
    StopTaskRequest,
    StopTaskResponse,
    stop_task,
    "Semantic request for stopping a standard scan task."
);
task_action_request!(
    ResumeTaskRequest,
    ResumeTaskResponse,
    resume_task,
    "Semantic request for resuming a standard scan task."
);

/// Semantic request for creating an import task.
#[derive(Debug, Clone)]
pub struct CreateImportTaskRequest {
    name: String,
    comment: Option<String>,
}

impl CreateImportTaskRequest {
    /// Create an import-task request.
    #[must_use]
    pub fn new(name: impl Into<String>, comment: Option<String>) -> Self {
        Self {
            name: name.into(),
            comment,
        }
    }
}

impl Request for CreateImportTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_import_task(&self.name, self.comment.as_deref()).to_bytes()
    }
}

impl GmpRequest for CreateImportTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic compatibility-alias request for creating a container/import task.
#[derive(Debug, Clone)]
pub struct CreateContainerTaskRequest {
    name: String,
    comment: Option<String>,
}

impl CreateContainerTaskRequest {
    /// Create a container/import-task request.
    #[must_use]
    pub fn new(name: impl Into<String>, comment: Option<String>) -> Self {
        Self {
            name: name.into(),
            comment,
        }
    }
}

impl Request for CreateContainerTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_container_task(&self.name, self.comment.as_deref()).to_bytes()
    }
}

impl GmpRequest for CreateContainerTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating an agent-group scan task.
#[derive(Debug, Clone)]
pub struct CreateAgentGroupTaskRequest {
    name: String,
    agent_group_id: EntityId,
    scanner_id: EntityId,
    opts: CreateAgentGroupTaskOpts,
}

impl CreateAgentGroupTaskRequest {
    /// Create an agent-group task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        agent_group_id: EntityId,
        scanner_id: EntityId,
        opts: CreateAgentGroupTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            agent_group_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateAgentGroupTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_agent_group_task(
            &self.name,
            &self.agent_group_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_agent_group_task")
    }
}

impl GmpRequest for CreateAgentGroupTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating an OCI image-target scan task.
#[derive(Debug, Clone)]
pub struct CreateOciImageTargetTaskRequest {
    name: String,
    oci_image_target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateOciImageTargetTaskOpts,
}

impl CreateOciImageTargetTaskRequest {
    /// Create an OCI image-target task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        oci_image_target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            oci_image_target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateOciImageTargetTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_oci_image_target_task(
            &self.name,
            &self.oci_image_target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_oci_image_target_task")
    }
}

impl GmpRequest for CreateOciImageTargetTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic compatibility-alias request for creating a container-image task.
#[derive(Debug, Clone)]
pub struct CreateContainerImageTaskRequest {
    name: String,
    oci_image_target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateOciImageTargetTaskOpts,
}

impl CreateContainerImageTaskRequest {
    /// Create a container-image task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        oci_image_target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            oci_image_target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateContainerImageTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_container_image_task(
            &self.name,
            &self.oci_image_target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_oci_image_target_task")
    }
}

impl GmpRequest for CreateContainerImageTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for creating a web-application-target scan task.
#[derive(Debug, Clone)]
pub struct CreateWebApplicationTaskRequest {
    name: String,
    web_application_target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateWebApplicationTaskOpts,
}

impl CreateWebApplicationTaskRequest {
    /// Create a web-application task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        web_application_target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateWebApplicationTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            web_application_target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateWebApplicationTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_web_application_task(
            &self.name,
            &self.web_application_target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }

    fn semantic_command_name(&self) -> Option<&'static str> {
        Some("create_web_application_task")
    }
}

impl GmpRequest for CreateWebApplicationTaskRequest {
    type Response = CreateTaskResponse;
}

/// Semantic request for moving a task to or from a remote slave.
#[derive(Debug, Clone)]
pub struct MoveTaskRequest {
    task_id: EntityId,
    slave_id: Option<EntityId>,
}

impl MoveTaskRequest {
    /// Create a task-move request.
    #[must_use]
    pub fn new(task_id: EntityId, slave_id: Option<EntityId>) -> Self {
        Self { task_id, slave_id }
    }
}

impl Request for MoveTaskRequest {
    fn to_bytes(&self) -> Vec<u8> {
        move_task(&self.task_id, self.slave_id.as_ref()).to_bytes()
    }
}

impl GmpRequest for MoveTaskRequest {
    type Response = MoveTaskResponse;
}

/// Semantic request for listing audit tasks.
#[derive(Debug, Clone, Default)]
pub struct GetAuditsRequest {
    opts: GetTasksOpts,
}

impl GetAuditsRequest {
    /// Create an audit-list request.
    #[must_use]
    pub fn new(opts: GetTasksOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetAuditsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_audits(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetAuditsRequest {
    type Response = GetTasksResponse;
}

/// Semantic request for creating an audit task.
#[derive(Debug, Clone)]
pub struct CreateAuditRequest {
    name: String,
    config_id: EntityId,
    target_id: EntityId,
    scanner_id: EntityId,
    opts: CreateTaskOpts,
}

impl CreateAuditRequest {
    /// Create an audit-task request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        config_id: EntityId,
        target_id: EntityId,
        scanner_id: EntityId,
        opts: CreateTaskOpts,
    ) -> Self {
        Self {
            name: name.into(),
            config_id,
            target_id,
            scanner_id,
            opts,
        }
    }
}

impl Request for CreateAuditRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_audit(
            &self.name,
            &self.config_id,
            &self.target_id,
            &self.scanner_id,
            self.opts.clone(),
        )
        .to_bytes()
    }
}

impl GmpRequest for CreateAuditRequest {
    type Response = CreateTaskResponse;
}

task_action_request!(
    GetAuditRequest,
    GetTasksResponse,
    get_audit,
    "Semantic request for one detailed audit task."
);
task_action_request!(
    CloneAuditRequest,
    CreateTaskResponse,
    clone_audit,
    "Semantic request for cloning an audit task."
);

/// Semantic request for modifying an audit task.
#[derive(Debug, Clone)]
pub struct ModifyAuditRequest {
    task_id: EntityId,
    opts: ModifyTaskOpts,
}

impl ModifyAuditRequest {
    /// Validate and create an audit-modification request.
    ///
    /// # Errors
    /// Returns the same construction errors as [`modify_audit`].
    pub fn new(task_id: EntityId, opts: ModifyTaskOpts) -> Result<Self, ModifyTaskError> {
        validate_modify_task_opts(&opts)?;
        Ok(Self { task_id, opts })
    }
}

impl Request for ModifyAuditRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_task_with_usage(&self.task_id, self.opts.clone(), Some(UsageType::Audit)).to_bytes()
    }
}

impl GmpRequest for ModifyAuditRequest {
    type Response = ModifyTaskResponse;
}

task_action_request!(
    DeleteAuditRequest,
    DeleteTaskResponse,
    delete_audit,
    "Semantic request for deleting an audit task."
);
task_action_request!(
    StartAuditRequest,
    StartTaskResponse,
    start_audit,
    "Semantic request for starting an audit task."
);
task_action_request!(
    StopAuditRequest,
    StopTaskResponse,
    stop_audit,
    "Semantic request for stopping an audit task."
);
task_action_request!(
    ResumeAuditRequest,
    ResumeTaskResponse,
    resume_audit,
    "Semantic request for resuming an audit task."
);

/// Build a clone request for an existing task.
#[must_use]
pub fn clone_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("create_task").child_with_text("copy", task_id.as_str())
}

/// Build a `create_task` request for an import task.
#[must_use]
pub fn create_import_task(name: &str, comment: Option<&str>) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element("target").set_attribute("id", "0");
    add_text_element(&mut cmd, "comment", comment);
    cmd
}

/// Build a `create_task` request for an import task.
///
/// This is a compatibility alias for [`create_import_task`].
#[must_use]
pub fn create_container_task(name: &str, comment: Option<&str>) -> impl Request {
    create_import_task(name, comment)
}

/// Build a `create_task` request for an agent-group scan task.
#[must_use]
pub fn create_agent_group_task(
    name: &str,
    agent_group_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateAgentGroupTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(&mut cmd, "agent_group", agent_group_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    if let Some(schedule_id) = opts.schedule_id.as_ref() {
        add_id_element(&mut cmd, "schedule", schedule_id);
        if let Some(schedule_periods) = opts.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `create_task` request for an OCI image target scan task.
#[must_use]
pub fn create_oci_image_target_task(
    name: &str,
    oci_image_target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateOciImageTargetTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(&mut cmd, "oci_image_target", oci_image_target_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    if let Some(schedule_id) = opts.schedule_id.as_ref() {
        add_id_element(&mut cmd, "schedule", schedule_id);
        if let Some(schedule_periods) = opts.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `create_task` request for an OCI image target scan task.
///
/// This compatibility alias uses python-gvm's historic "container image"
/// helper name for the same GMP Next OCI image target task shape.
#[must_use]
pub fn create_container_image_task(
    name: &str,
    oci_image_target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateOciImageTargetTaskOpts,
) -> impl Request {
    create_oci_image_target_task(name, oci_image_target_id, scanner_id, opts)
}

/// Build a `create_task` request.
#[must_use]
pub fn create_task(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
) -> impl Request {
    create_task_with_usage(
        name,
        config_id,
        target_id,
        scanner_id,
        opts,
        UsageType::Scan,
    )
}

fn create_task_with_usage(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
    usage_type: UsageType,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
    add_id_element(&mut cmd, "config", config_id);
    add_id_element(&mut cmd, "target", target_id);
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    if let Some(hosts_ordering) = opts.hosts_ordering {
        cmd.add_element_with_text("hosts_ordering", hosts_ordering.as_gmp_str());
    }
    add_optional_id_element(&mut cmd, "schedule", opts.schedule_id.as_ref());
    if let Some(schedule_periods) = opts.schedule_periods {
        cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `create_task` request for a web application target.
#[must_use]
pub fn create_web_application_task(
    name: &str,
    web_application_target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateWebApplicationTaskOpts,
) -> impl Request {
    let mut cmd = XmlCommand::new("create_task");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("usage_type", UsageType::Scan.as_gmp_str());
    add_id_element(
        &mut cmd,
        "web_application_target",
        web_application_target_id,
    );
    add_id_element(&mut cmd, "scanner", scanner_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    for alert_id in &opts.alert_ids {
        add_id_element(&mut cmd, "alert", alert_id);
    }
    if let Some(schedule_id) = opts.schedule_id.as_ref() {
        add_id_element(&mut cmd, "schedule", schedule_id);
        if let Some(schedule_periods) = opts.schedule_periods {
            cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
        }
    }
    add_task_observers(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

/// Build a `delete_task` request.
#[must_use]
pub fn delete_task(task_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_task")
        .attribute("task_id", task_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `get_tasks` request.
#[must_use]
pub fn get_tasks(opts: GetTasksOpts) -> impl Request {
    get_tasks_with_usage(opts, UsageType::Scan)
}

fn get_tasks_with_usage(opts: GetTasksOpts, usage_type: UsageType) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_tasks").attribute("usage_type", usage_type.as_gmp_str());
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "schedules_only", opts.schedules_only);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", opts.ignore_pagination);
    cmd
}

/// Build a `get_task` request.
#[must_use]
pub fn get_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tasks")
        .attribute("task_id", task_id.as_str())
        .attribute("usage_type", UsageType::Scan.as_gmp_str())
        .attribute("details", "1")
}

/// Build a `modify_task` request.
///
/// # Errors
/// Returns [`ModifyTaskError::ObserverGroupsWithoutUserUpdate`] when observer
/// groups are updated without an explicit observer-user replacement or clear.
pub fn modify_task(
    task_id: &EntityId,
    opts: ModifyTaskOpts,
) -> Result<impl Request, ModifyTaskError> {
    validate_modify_task_opts(&opts)?;
    Ok(modify_task_with_usage(task_id, opts, None))
}

fn validate_modify_task_opts(opts: &ModifyTaskOpts) -> Result<(), ModifyTaskError> {
    if !matches!(opts.observer_group_ids, CollectionUpdate::Omitted)
        && matches!(opts.observers, CollectionUpdate::Omitted)
    {
        return Err(ModifyTaskError::ObserverGroupsWithoutUserUpdate);
    }
    Ok(())
}

fn modify_task_with_usage(
    task_id: &EntityId,
    opts: ModifyTaskOpts,
    usage_type: Option<UsageType>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_task").attribute("task_id", task_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(usage_type) = usage_type {
        cmd.add_element_with_text("usage_type", usage_type.as_gmp_str());
    }
    if let Some(alterable) = opts.alterable {
        cmd.add_element_with_text("alterable", bool_str(alterable));
    }
    if let Some(hosts_ordering) = opts.hosts_ordering {
        cmd.add_element_with_text("hosts_ordering", hosts_ordering.as_gmp_str());
    }
    add_scalar_id_update(&mut cmd, "schedule", &opts.schedule_id);
    if let Some(schedule_periods) = opts.schedule_periods {
        cmd.add_element_with_text("schedule_periods", &schedule_periods.to_string());
    }
    add_optional_id_element(&mut cmd, "target", opts.target_id.as_ref());
    add_optional_id_element(&mut cmd, "config", opts.config_id.as_ref());
    add_optional_id_element(&mut cmd, "scanner", opts.scanner_id.as_ref());
    if let Some(alert_ids) = opts.alert_ids.as_ref() {
        if alert_ids.is_empty() {
            cmd.add_element("alert").set_attribute("id", "0");
        } else {
            for alert_id in alert_ids {
                add_id_element(&mut cmd, "alert", alert_id);
            }
        }
    }
    add_task_observer_update(&mut cmd, &opts.observers, &opts.observer_group_ids);
    add_preferences(&mut cmd, &opts.preferences);
    cmd
}

fn add_task_observers(cmd: &mut XmlCommand, observers: &[String], observer_group_ids: &[EntityId]) {
    if observers.is_empty() && observer_group_ids.is_empty() {
        return;
    }
    let element = cmd.add_element("observers");
    if !observers.is_empty() {
        element.set_text(&observers.join(" "));
    }
    for group_id in observer_group_ids {
        element
            .add_child("group")
            .set_attribute("id", group_id.as_str());
    }
}

fn add_task_observer_update(
    cmd: &mut XmlCommand,
    observers: &CollectionUpdate<String>,
    observer_group_ids: &CollectionUpdate<EntityId>,
) {
    debug_assert!(
        matches!(observer_group_ids, CollectionUpdate::Omitted)
            || !matches!(observers, CollectionUpdate::Omitted),
        "task observer-group updates must be validated before encoding"
    );
    if matches!(observers, CollectionUpdate::Omitted)
        && matches!(observer_group_ids, CollectionUpdate::Omitted)
    {
        return;
    }

    let element = cmd.add_element("observers");
    if let CollectionUpdate::Replace(observers) = observers {
        if !observers.is_empty() {
            element.set_text(&observers.join(" "));
        }
    }
    match observer_group_ids {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(group_ids) if !group_ids.is_empty() => {
            for group_id in group_ids {
                element
                    .add_child("group")
                    .set_attribute("id", group_id.as_str());
            }
        }
        CollectionUpdate::Replace(_) | CollectionUpdate::Clear => {
            element.add_child("group").set_attribute("id", "0");
        }
    }
}

/// Build a `move_task` request.
#[must_use]
pub fn move_task(task_id: &EntityId, slave_id: Option<&EntityId>) -> impl Request {
    let mut cmd = XmlCommand::new("move_task").attribute("task_id", task_id.as_str());
    if let Some(slave_id) = slave_id {
        cmd.set_attribute("slave_id", slave_id.as_str());
    }
    cmd
}

/// Build a `start_task` request.
#[must_use]
pub fn start_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("start_task").attribute("task_id", task_id.as_str())
}

/// Build a `resume_task` request.
#[must_use]
pub fn resume_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("resume_task").attribute("task_id", task_id.as_str())
}

/// Build a `stop_task` request.
#[must_use]
pub fn stop_task(task_id: &EntityId) -> impl Request {
    XmlCommand::new("stop_task").attribute("task_id", task_id.as_str())
}

/// Build a `create_task` request for an audit.
#[must_use]
pub fn create_audit(
    name: &str,
    config_id: &EntityId,
    target_id: &EntityId,
    scanner_id: &EntityId,
    opts: CreateTaskOpts,
) -> impl Request {
    create_task_with_usage(
        name,
        config_id,
        target_id,
        scanner_id,
        opts,
        UsageType::Audit,
    )
}

/// Build a `get_tasks` request scoped to audits.
#[must_use]
pub fn get_audits(opts: GetTasksOpts) -> impl Request {
    get_tasks_with_usage(opts, UsageType::Audit)
}

/// Build a clone request for an existing audit.
#[must_use]
pub fn clone_audit(task_id: &EntityId) -> impl Request {
    clone_task(task_id)
}

/// Build a `get_tasks` request for a single audit.
#[must_use]
pub fn get_audit(task_id: &EntityId) -> impl Request {
    XmlCommand::new("get_tasks")
        .attribute("task_id", task_id.as_str())
        .attribute("usage_type", UsageType::Audit.as_gmp_str())
        .attribute("details", "1")
}

/// Build a `start_task` request for an audit.
#[must_use]
pub fn start_audit(task_id: &EntityId) -> impl Request {
    start_task(task_id)
}

/// Build a `stop_task` request for an audit.
#[must_use]
pub fn stop_audit(task_id: &EntityId) -> impl Request {
    stop_task(task_id)
}

/// Build a `resume_task` request for an audit.
#[must_use]
pub fn resume_audit(task_id: &EntityId) -> impl Request {
    resume_task(task_id)
}

/// Build a `modify_task` request scoped to audits.
///
/// # Errors
/// Returns [`ModifyTaskError::ObserverGroupsWithoutUserUpdate`] when observer
/// groups are updated without an explicit observer-user replacement or clear.
pub fn modify_audit(
    task_id: &EntityId,
    opts: ModifyTaskOpts,
) -> Result<impl Request, ModifyTaskError> {
    validate_modify_task_opts(&opts)?;
    Ok(modify_task_with_usage(
        task_id,
        opts,
        Some(UsageType::Audit),
    ))
}

/// Build a `delete_task` request for an audit.
#[must_use]
pub fn delete_audit(task_id: &EntityId) -> impl Request {
    delete_task(task_id, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;
    use crate::enums::HostsOrdering;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn clone_task_builds_copy_xml() {
        assert_eq!(
            xml(clone_task(&id("a1"))),
            "<create_task><copy>a1</copy></create_task>"
        );
    }

    #[test]
    fn semantic_task_requests_match_legacy_builder_bytes() {
        let list_opts = GetTasksOpts {
            filter_string: Some("name=production".into()),
            details: Some(true),
            schedules_only: Some(false),
            ..Default::default()
        };
        assert_eq!(
            GetTasksRequest::new(list_opts.clone()).to_bytes(),
            get_tasks(list_opts).to_bytes()
        );

        let task_id = id("task-1");
        assert_eq!(
            GetTaskRequest::new(task_id.clone()).to_bytes(),
            get_task(&task_id).to_bytes()
        );

        let create_opts = CreateTaskOpts {
            alterable: Some(true),
            hosts_ordering: Some(HostsOrdering::Random),
            schedule_id: Some(id("schedule-1")),
            alert_ids: vec![id("alert-1")],
            comment: Some("production scan".into()),
            schedule_periods: Some(3),
            observers: vec!["alice".into()],
            observer_group_ids: vec![id("group-1")],
            preferences: vec![("max_hosts".into(), "10".into())],
        };
        assert_eq!(
            CreateTaskRequest::new(
                "production",
                id("config-1"),
                id("target-1"),
                id("scanner-1"),
                create_opts.clone(),
            )
            .to_bytes(),
            create_task(
                "production",
                &id("config-1"),
                &id("target-1"),
                &id("scanner-1"),
                create_opts,
            )
            .to_bytes()
        );

        assert_eq!(
            CloneTaskRequest::new(task_id.clone()).to_bytes(),
            clone_task(&task_id).to_bytes()
        );

        let modify_opts = ModifyTaskOpts {
            name: Some("renamed".into()),
            schedule_id: ScalarUpdate::set(id("schedule-2")),
            observers: CollectionUpdate::replace(["bob".into()]),
            observer_group_ids: CollectionUpdate::replace([id("group-2")]),
            ..Default::default()
        };
        assert_eq!(
            ModifyTaskRequest::new(task_id.clone(), modify_opts.clone())
                .expect("valid semantic modify request")
                .to_bytes(),
            modify_task(&task_id, modify_opts)
                .expect("valid legacy modify request")
                .to_bytes()
        );

        assert_eq!(
            DeleteTaskRequest::new(task_id.clone(), true).to_bytes(),
            delete_task(&task_id, true).to_bytes()
        );
        assert_eq!(
            StartTaskRequest::new(task_id.clone()).to_bytes(),
            start_task(&task_id).to_bytes()
        );
        assert_eq!(
            StopTaskRequest::new(task_id.clone()).to_bytes(),
            stop_task(&task_id).to_bytes()
        );
        assert_eq!(
            ResumeTaskRequest::new(task_id.clone()).to_bytes(),
            resume_task(&task_id).to_bytes()
        );
    }

    #[test]
    fn semantic_specialized_task_requests_match_legacy_builder_bytes() {
        let task_id = id("task-1");
        let scanner_id = id("scanner-1");
        assert_eq!(
            CreateImportTaskRequest::new("import", Some("comment".into())).to_bytes(),
            create_import_task("import", Some("comment")).to_bytes()
        );
        assert_eq!(
            CreateContainerTaskRequest::new("container", Some("comment".into())).to_bytes(),
            create_container_task("container", Some("comment")).to_bytes()
        );

        let agent_opts = CreateAgentGroupTaskOpts {
            comment: Some("agents".into()),
            alterable: Some(true),
            schedule_id: Some(id("schedule-1")),
            alert_ids: vec![id("alert-1")],
            schedule_periods: Some(2),
            observers: vec!["alice".into()],
            observer_group_ids: vec![id("group-1")],
            preferences: vec![("key".into(), "value".into())],
        };
        assert_eq!(
            CreateAgentGroupTaskRequest::new(
                "agent task",
                id("agent-group-1"),
                scanner_id.clone(),
                agent_opts.clone(),
            )
            .to_bytes(),
            create_agent_group_task("agent task", &id("agent-group-1"), &scanner_id, agent_opts,)
                .to_bytes()
        );

        let oci_opts = CreateOciImageTargetTaskOpts {
            comment: Some("images".into()),
            alterable: Some(true),
            schedule_id: Some(id("schedule-1")),
            alert_ids: vec![id("alert-1")],
            schedule_periods: Some(2),
            observers: vec!["alice".into()],
            observer_group_ids: vec![id("group-1")],
            preferences: vec![("key".into(), "value".into())],
        };
        assert_eq!(
            CreateOciImageTargetTaskRequest::new(
                "oci task",
                id("oci-target-1"),
                scanner_id.clone(),
                oci_opts.clone(),
            )
            .to_bytes(),
            create_oci_image_target_task(
                "oci task",
                &id("oci-target-1"),
                &scanner_id,
                oci_opts.clone(),
            )
            .to_bytes()
        );
        assert_eq!(
            CreateContainerImageTaskRequest::new(
                "container image task",
                id("oci-target-1"),
                scanner_id.clone(),
                oci_opts.clone(),
            )
            .to_bytes(),
            create_container_image_task(
                "container image task",
                &id("oci-target-1"),
                &scanner_id,
                oci_opts,
            )
            .to_bytes()
        );

        let web_opts = CreateWebApplicationTaskOpts {
            alterable: Some(true),
            schedule_id: Some(id("schedule-1")),
            alert_ids: vec![id("alert-1")],
            comment: Some("web".into()),
            schedule_periods: Some(2),
            observers: vec!["alice".into()],
            observer_group_ids: vec![id("group-1")],
            preferences: vec![("key".into(), "value".into())],
        };
        assert_eq!(
            CreateWebApplicationTaskRequest::new(
                "web task",
                id("web-target-1"),
                scanner_id.clone(),
                web_opts.clone(),
            )
            .to_bytes(),
            create_web_application_task("web task", &id("web-target-1"), &scanner_id, web_opts,)
                .to_bytes()
        );
        assert_eq!(
            MoveTaskRequest::new(task_id.clone(), Some(id("slave-1"))).to_bytes(),
            move_task(&task_id, Some(&id("slave-1"))).to_bytes()
        );
    }

    #[test]
    fn semantic_audit_requests_match_legacy_builder_bytes() {
        let task_id = id("task-1");
        let scanner_id = id("scanner-1");
        let list_opts = GetTasksOpts {
            details: Some(true),
            ..Default::default()
        };
        assert_eq!(
            GetAuditsRequest::new(list_opts.clone()).to_bytes(),
            get_audits(list_opts).to_bytes()
        );
        assert_eq!(
            GetAuditRequest::new(task_id.clone()).to_bytes(),
            get_audit(&task_id).to_bytes()
        );
        let audit_create_opts = CreateTaskOpts::default();
        assert_eq!(
            CreateAuditRequest::new(
                "audit",
                id("config-1"),
                id("target-1"),
                scanner_id.clone(),
                audit_create_opts.clone(),
            )
            .to_bytes(),
            create_audit(
                "audit",
                &id("config-1"),
                &id("target-1"),
                &scanner_id,
                audit_create_opts,
            )
            .to_bytes()
        );
        assert_eq!(
            CloneAuditRequest::new(task_id.clone()).to_bytes(),
            clone_audit(&task_id).to_bytes()
        );
        let audit_modify_opts = ModifyTaskOpts {
            comment: Some("updated".into()),
            ..Default::default()
        };
        assert_eq!(
            ModifyAuditRequest::new(task_id.clone(), audit_modify_opts.clone())
                .expect("valid semantic audit modification")
                .to_bytes(),
            modify_audit(&task_id, audit_modify_opts)
                .expect("valid builder audit modification")
                .to_bytes()
        );
        assert_eq!(
            DeleteAuditRequest::new(task_id.clone()).to_bytes(),
            delete_audit(&task_id).to_bytes()
        );
        assert_eq!(
            StartAuditRequest::new(task_id.clone()).to_bytes(),
            start_audit(&task_id).to_bytes()
        );
        assert_eq!(
            StopAuditRequest::new(task_id.clone()).to_bytes(),
            stop_audit(&task_id).to_bytes()
        );
        assert_eq!(
            ResumeAuditRequest::new(task_id.clone()).to_bytes(),
            resume_audit(&task_id).to_bytes()
        );
    }

    #[test]
    fn semantic_modify_task_preserves_builder_validation() {
        let opts = ModifyTaskOpts {
            observer_group_ids: CollectionUpdate::replace([id("group-1")]),
            ..Default::default()
        };
        assert_eq!(
            ModifyTaskRequest::new(id("task-1"), opts.clone()).err(),
            Some(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
        );
        assert_eq!(
            modify_task(&id("task-1"), opts).err(),
            Some(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
        );
        let audit_opts = ModifyTaskOpts {
            observer_group_ids: CollectionUpdate::replace([id("group-1")]),
            ..Default::default()
        };
        assert_eq!(
            ModifyAuditRequest::new(id("audit-1"), audit_opts.clone()).err(),
            Some(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
        );
        assert_eq!(
            modify_audit(&id("audit-1"), audit_opts).err(),
            Some(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
        );
    }

    #[test]
    fn semantic_task_requests_have_the_expected_response_associations() {
        fn assert_response<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let task_id = id("task-1");
        assert_response::<_, GetTasksResponse>(&GetTasksRequest::default());
        assert_response::<_, GetTasksResponse>(&GetTaskRequest::new(task_id.clone()));
        assert_response::<_, CreateTaskResponse>(&CreateTaskRequest::new(
            "scan",
            id("config-1"),
            id("target-1"),
            id("scanner-1"),
            CreateTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CloneTaskRequest::new(task_id.clone()));
        assert_response::<_, ModifyTaskResponse>(
            &ModifyTaskRequest::new(task_id.clone(), ModifyTaskOpts::default())
                .expect("valid modify request"),
        );
        assert_response::<_, DeleteTaskResponse>(&DeleteTaskRequest::new(task_id.clone(), false));
        assert_response::<_, StartTaskResponse>(&StartTaskRequest::new(task_id.clone()));
        assert_response::<_, StopTaskResponse>(&StopTaskRequest::new(task_id.clone()));
        assert_response::<_, ResumeTaskResponse>(&ResumeTaskRequest::new(task_id.clone()));
        assert_response::<_, CreateTaskResponse>(&CreateImportTaskRequest::new("import", None));
        assert_response::<_, CreateTaskResponse>(&CreateContainerTaskRequest::new(
            "container",
            None,
        ));
        assert_response::<_, CreateTaskResponse>(&CreateAgentGroupTaskRequest::new(
            "agents",
            id("agent-group-1"),
            id("scanner-1"),
            CreateAgentGroupTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CreateOciImageTargetTaskRequest::new(
            "oci",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CreateContainerImageTaskRequest::new(
            "container image",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CreateWebApplicationTaskRequest::new(
            "web",
            id("web-target-1"),
            id("scanner-1"),
            CreateWebApplicationTaskOpts::default(),
        ));
        assert_response::<_, MoveTaskResponse>(&MoveTaskRequest::new(task_id.clone(), None));
        assert_response::<_, GetTasksResponse>(&GetAuditsRequest::default());
        assert_response::<_, GetTasksResponse>(&GetAuditRequest::new(task_id.clone()));
        assert_response::<_, CreateTaskResponse>(&CreateAuditRequest::new(
            "audit",
            id("config-1"),
            id("target-1"),
            id("scanner-1"),
            CreateTaskOpts::default(),
        ));
        assert_response::<_, CreateTaskResponse>(&CloneAuditRequest::new(task_id.clone()));
        assert_response::<_, ModifyTaskResponse>(
            &ModifyAuditRequest::new(task_id.clone(), ModifyTaskOpts::default())
                .expect("valid audit modification"),
        );
        assert_response::<_, DeleteTaskResponse>(&DeleteAuditRequest::new(task_id.clone()));
        assert_response::<_, StartTaskResponse>(&StartAuditRequest::new(task_id.clone()));
        assert_response::<_, StopTaskResponse>(&StopAuditRequest::new(task_id.clone()));
        assert_response::<_, ResumeTaskResponse>(&ResumeAuditRequest::new(task_id));
    }

    #[test]
    fn specialized_task_requests_preserve_next_only_semantic_names() {
        let agent = CreateAgentGroupTaskRequest::new(
            "agents",
            id("agent-group-1"),
            id("scanner-1"),
            CreateAgentGroupTaskOpts::default(),
        );
        assert_eq!(
            agent.semantic_command_name(),
            Some("create_agent_group_task")
        );

        let oci = CreateOciImageTargetTaskRequest::new(
            "oci",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        );
        assert_eq!(
            oci.semantic_command_name(),
            Some("create_oci_image_target_task")
        );
        let alias = CreateContainerImageTaskRequest::new(
            "container image",
            id("oci-target-1"),
            id("scanner-1"),
            CreateOciImageTargetTaskOpts::default(),
        );
        assert_eq!(
            alias.semantic_command_name(),
            Some("create_oci_image_target_task")
        );

        let web = CreateWebApplicationTaskRequest::new(
            "web",
            id("web-target-1"),
            id("scanner-1"),
            CreateWebApplicationTaskOpts::default(),
        );
        assert_eq!(
            web.semantic_command_name(),
            Some("create_web_application_task")
        );
    }

    #[test]
    fn create_task_builds_full_xml() {
        let rendered = xml(create_task(
            "foo",
            &id("c1"),
            &id("t1"),
            &id("s1"),
            CreateTaskOpts {
                alterable: Some(true),
                hosts_ordering: Some(HostsOrdering::Random),
                schedule_id: Some(id("sched1")),
                alert_ids: vec![id("a1"), id("a2")],
                comment: Some("bar".into()),
                schedule_periods: Some(5),
                observers: vec!["alice".into(), "bob".into()],
                observer_group_ids: vec![id("group-1")],
                preferences: vec![("k".into(), "v".into())],
            },
        ));
        assert!(rendered.contains("<usage_type>scan</usage_type>"));
        assert!(rendered.contains("<config id=\"c1\"/>"));
        assert!(rendered.contains("<hosts_ordering>random</hosts_ordering>"));
        assert!(rendered.contains("<schedule id=\"sched1\"/>"));
        assert!(rendered.contains("<alert id=\"a1\"/>"));
        assert!(rendered.contains("<observers>alice bob<group id=\"group-1\"/></observers>"));
        assert!(rendered.contains("<scanner_name>k</scanner_name><value>v</value>"));
    }

    #[test]
    fn create_web_application_task_builds_full_xml() {
        let rendered = xml(create_web_application_task(
            "web task",
            &id("wt1"),
            &id("s1"),
            CreateWebApplicationTaskOpts {
                alterable: Some(true),
                schedule_id: Some(id("sched1")),
                alert_ids: vec![id("a1"), id("a2")],
                comment: Some("scan web app".into()),
                schedule_periods: Some(5),
                observers: vec!["alice".into(), "bob".into()],
                observer_group_ids: vec![id("group-1")],
                preferences: vec![("k".into(), "v".into())],
            },
        ));
        assert_eq!(
            rendered,
            "<create_task><name>web task</name><usage_type>scan</usage_type><web_application_target id=\"wt1\"/><scanner id=\"s1\"/><comment>scan web app</comment><alterable>1</alterable><alert id=\"a1\"/><alert id=\"a2\"/><schedule id=\"sched1\"/><schedule_periods>5</schedule_periods><observers>alice bob<group id=\"group-1\"/></observers><preferences><preference><scanner_name>k</scanner_name><value>v</value></preference></preferences></create_task>"
        );
    }

    #[test]
    fn create_web_application_task_omits_schedule_periods_without_schedule() {
        assert_eq!(
            xml(create_web_application_task(
                "web task",
                &id("wt1"),
                &id("s1"),
                CreateWebApplicationTaskOpts {
                    schedule_periods: Some(5),
                    ..Default::default()
                },
            )),
            "<create_task><name>web task</name><usage_type>scan</usage_type><web_application_target id=\"wt1\"/><scanner id=\"s1\"/></create_task>"
        );
    }

    #[test]
    fn get_and_delete_task_commands_build_attributes() {
        assert_eq!(
            xml(get_task(&id("a1"))),
            "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"scan\"/>"
        );
        assert_eq!(
            xml(delete_task(&id("a1"), true)),
            "<delete_task task_id=\"a1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn modify_and_action_commands_build_xml() {
        let rendered = xml(modify_task(
            &id("t1"),
            ModifyTaskOpts {
                name: Some("foo".into()),
                alert_ids: Some(Vec::new()),
                ..Default::default()
            },
        )
        .expect("valid task update"));
        assert_eq!(
            rendered,
            "<modify_task task_id=\"t1\"><name>foo</name><alert id=\"0\"/></modify_task>"
        );
        assert_eq!(
            xml(move_task(&id("a1"), Some(&id("s1")))),
            "<move_task slave_id=\"s1\" task_id=\"a1\"/>"
        );
        assert_eq!(xml(start_task(&id("a1"))), "<start_task task_id=\"a1\"/>");
        assert_eq!(xml(resume_task(&id("a1"))), "<resume_task task_id=\"a1\"/>");
        assert_eq!(xml(stop_task(&id("a1"))), "<stop_task task_id=\"a1\"/>");
    }

    #[test]
    fn modify_task_builds_observer_user_list_text() {
        assert_eq!(
            xml(modify_task(
                &id("t1"),
                ModifyTaskOpts {
                    observers: CollectionUpdate::replace(["alice".into(), "bob".into(),]),
                    ..Default::default()
                },
            )
            .expect("valid observer update"),),
            "<modify_task task_id=\"t1\"><observers>alice bob</observers></modify_task>"
        );
    }

    #[test]
    fn modify_task_distinguishes_omitted_replaced_and_cleared_observers() {
        assert_eq!(
            xml(modify_task(&id("t1"), ModifyTaskOpts::default()).expect("valid omission")),
            "<modify_task task_id=\"t1\"/>"
        );
        assert_eq!(
            xml(
                modify_task(
                    &id("t1"),
                    ModifyTaskOpts {
                        observers: CollectionUpdate::replace(["alice".into()]),
                        observer_group_ids: CollectionUpdate::replace([id("group-1")]),
                        ..Default::default()
                    },
                )
                .expect("valid observer replacement"),
            ),
            "<modify_task task_id=\"t1\"><observers>alice<group id=\"group-1\"/></observers></modify_task>"
        );
        assert_eq!(
            xml(modify_task(
                &id("t1"),
                ModifyTaskOpts {
                    observers: CollectionUpdate::Clear,
                    ..Default::default()
                },
            )
            .expect("valid observer clear"),),
            "<modify_task task_id=\"t1\"><observers/></modify_task>"
        );
        assert_eq!(
            xml(
                modify_task(
                    &id("t1"),
                    ModifyTaskOpts {
                        observers: CollectionUpdate::replace(["alice".into()]),
                        observer_group_ids: CollectionUpdate::Clear,
                        ..Default::default()
                    },
                )
                .expect("valid observer-group clear"),
            ),
            "<modify_task task_id=\"t1\"><observers>alice<group id=\"0\"/></observers></modify_task>"
        );
    }

    #[test]
    fn modify_task_rejects_group_update_without_explicit_users() {
        assert_eq!(
            modify_task(
                &id("t1"),
                ModifyTaskOpts {
                    observer_group_ids: CollectionUpdate::replace([id("group-1")]),
                    ..Default::default()
                },
            )
            .err(),
            Some(ModifyTaskError::ObserverGroupsWithoutUserUpdate)
        );
    }

    #[test]
    fn modify_task_distinguishes_omitted_set_and_cleared_schedule() {
        assert_eq!(
            xml(modify_task(&id("t1"), ModifyTaskOpts::default()).expect("valid omission")),
            "<modify_task task_id=\"t1\"/>"
        );
        assert_eq!(
            xml(modify_task(
                &id("t1"),
                ModifyTaskOpts {
                    schedule_id: ScalarUpdate::set(id("schedule-1")),
                    ..Default::default()
                },
            )
            .expect("valid schedule update"),),
            "<modify_task task_id=\"t1\"><schedule id=\"schedule-1\"/></modify_task>"
        );
        assert_eq!(
            xml(modify_task(
                &id("t1"),
                ModifyTaskOpts {
                    schedule_id: ScalarUpdate::Clear,
                    ..Default::default()
                },
            )
            .expect("valid schedule clear"),),
            "<modify_task task_id=\"t1\"><schedule id=\"0\"/></modify_task>"
        );
    }

    #[test]
    fn get_tasks_builds_optional_attributes() {
        let rendered = xml(get_tasks(GetTasksOpts {
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
            trash: Some(true),
            details: Some(true),
            schedules_only: Some(true),
            ignore_pagination: Some(true),
        }));
        assert!(rendered.contains("usage_type=\"scan\""));
        assert!(rendered.contains("filter=\"name=foo\""));
        assert!(rendered.contains("filt_id=\"f1\""));
        assert!(rendered.contains("trash=\"1\""));
        assert!(rendered.contains("details=\"1\""));
        assert!(rendered.contains("schedules_only=\"1\""));
        assert!(rendered.contains("ignore_pagination=\"1\""));
    }

    #[test]
    fn audit_commands_build_xml() {
        assert!(xml(create_audit(
            "audit",
            &id("c1"),
            &id("t1"),
            &id("s1"),
            CreateTaskOpts::default(),
        ))
        .contains("<usage_type>audit</usage_type>"));
        assert_eq!(
            xml(get_audits(GetTasksOpts::default())),
            "<get_tasks usage_type=\"audit\"/>"
        );
        assert_eq!(
            xml(clone_audit(&id("a1"))),
            "<create_task><copy>a1</copy></create_task>"
        );
        assert_eq!(
            xml(get_audit(&id("a1"))),
            "<get_tasks details=\"1\" task_id=\"a1\" usage_type=\"audit\"/>"
        );
        assert_eq!(
            xml(
                modify_audit(
                    &id("a1"),
                    ModifyTaskOpts {
                        comment: Some("updated".into()),
                        ..Default::default()
                    },
                )
                .expect("valid audit update"),
            ),
            "<modify_task task_id=\"a1\"><comment>updated</comment><usage_type>audit</usage_type></modify_task>"
        );
        assert_eq!(xml(start_audit(&id("a1"))), "<start_task task_id=\"a1\"/>");
        assert_eq!(xml(stop_audit(&id("a1"))), "<stop_task task_id=\"a1\"/>");
        assert_eq!(
            xml(resume_audit(&id("a1"))),
            "<resume_task task_id=\"a1\"/>"
        );
        assert_eq!(
            xml(delete_audit(&id("a1"))),
            "<delete_task task_id=\"a1\" ultimate=\"0\"/>"
        );
    }
}
