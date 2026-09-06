// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed convenience methods for [`GmpClient`].
//!
//! Each method combines a GMP command builder with the corresponding typed
//! response parser, eliminating the need for callers to import response types
//! and call `from_response()` manually.
//!
//! Migrated command families delegate to [`GmpClient::execute`], while
//! not-yet-migrated helpers continue to use [`GmpClient::send`] directly. Both
//! paths preserve [`gvm_gmp::responses::ParseError`] ownership of response
//! validation, including non-2xx status detection.

use gvm_connection::GvmConnection;
use gvm_gmp::commands::aggregates::{get_aggregates_request, GetAggregatesRequestOpts};
use gvm_gmp::commands::alerts::{
    AlertOpts, CloneAlertRequest, CreateAlertRequest, DeleteAlertRequest, GetAlertRequest,
    GetAlertsOpts, GetAlertsRequest, ModifyAlertRequest, TestAlertRequest, TriggerAlertOpts,
    TriggerAlertRequest,
};
use gvm_gmp::commands::assets::{
    AssetType, CreateAssetOpts, CreateAssetRequest, DeleteAssetOpts, DeleteAssetRequest,
    GetAssetRequest, GetAssetsOpts, GetAssetsRequest, ModifyAssetOpts, ModifyAssetRequest,
};
use gvm_gmp::commands::authentication::AuthenticateRequest;
use gvm_gmp::commands::configs::{
    CloneConfigOpts, CloneConfigRequest, CreateConfigOpts, CreateConfigRequest, DeleteConfigOpts,
    DeleteConfigRequest, GetConfigOpts, GetConfigRequest, GetConfigsOpts, GetConfigsRequest,
    ModifyConfigOpts, ModifyConfigRequest,
};
use gvm_gmp::commands::credentials::{
    CreateCredentialRequest, CreateCredentialStoreCredentialRequest, CredentialOpts,
    CredentialStoreCredentialOpts, DeleteCredentialRequest, GetCredentialStoreRequest,
    GetCredentialStoresOpts, GetCredentialStoresRequest, GetCredentialsOpts, GetCredentialsRequest,
    ModifyCredentialOpts, ModifyCredentialRequest, ModifyCredentialStoreCredentialOpts,
    ModifyCredentialStoreCredentialRequest, VerifyCredentialStoreRequest,
};
use gvm_gmp::commands::features::get_features;
use gvm_gmp::commands::feed::{get_feed, get_feeds};
use gvm_gmp::commands::filters::{
    CloneFilterRequest, CreateFilterRequest, DeleteFilterRequest, FilterOpts, GetFilterRequest,
    GetFiltersOpts, GetFiltersRequest, ModifyFilterRequest,
};
use gvm_gmp::commands::groups::{
    CloneGroupRequest, CreateGroupRequest, DeleteGroupRequest, GetGroupRequest, GetGroupsOpts,
    GetGroupsRequest, GroupOpts, ModifyGroupRequest,
};
use gvm_gmp::commands::help::{help, help_with_mode, HelpMode};
use gvm_gmp::commands::hosts::{
    CreateHostRequest, DeleteHostRequest, GetHostRequest, GetHostsOpts, GetHostsRequest, HostOpts,
    ModifyHostRequest,
};
use gvm_gmp::commands::integration_configs::{
    GetIntegrationConfigRequest, GetIntegrationConfigsOpts, GetIntegrationConfigsRequest,
    ModifyIntegrationConfigOpts, ModifyIntegrationConfigRequest,
};
use gvm_gmp::commands::notes::{
    CloneNoteRequest, CreateNoteRequest, DeleteNoteRequest, GetNoteRequest, GetNotesOpts,
    GetNotesRequest, ModifyNoteOpts, ModifyNoteRequest, NoteOpts,
};
use gvm_gmp::commands::nvts::{
    GetNvtFamiliesRequest, GetNvtPreferenceRequest, GetNvtPreferencesOpts,
    GetNvtPreferencesRequest, GetNvtRequest, GetNvtsOpts, GetNvtsRequest, GetScanConfigNvtRequest,
    GetScanConfigNvtsRequest,
};
use gvm_gmp::commands::oci_image_targets::{
    CloneOciImageTargetRequest, CreateOciImageTargetOpts, CreateOciImageTargetRequest,
    DeleteOciImageTargetRequest, GetOciImageTargetRequest, GetOciImageTargetsOpts,
    GetOciImageTargetsRequest, ModifyOciImageTargetOpts, ModifyOciImageTargetRequest,
};
use gvm_gmp::commands::operating_systems::{
    DeleteOperatingSystemAssetRequest, GetOperatingSystemAssetRequest,
    GetOperatingSystemAssetsRequest, GetOperatingSystemsOpts, ModifyOperatingSystemAssetRequest,
};
use gvm_gmp::commands::overrides::{
    CloneOverrideRequest, CreateOverrideRequest, DeleteOverrideRequest, GetOverrideRequest,
    GetOverridesOpts, GetOverridesRequest, ModifyOverrideOpts, ModifyOverrideRequest, OverrideOpts,
};
use gvm_gmp::commands::permissions::{
    ClonePermissionRequest, CreatePermissionRequest, DeletePermissionRequest, GetPermissionRequest,
    GetPermissionsOpts, GetPermissionsRequest, ModifyPermissionRequest, PermissionOpts,
};
use gvm_gmp::commands::port_lists::{
    ClonePortListRequest, CreatePortListRequest, CreatePortRangeRequest, DeletePortListRequest,
    DeletePortRangeRequest, GetPortListRequest, GetPortListsOpts, GetPortListsRequest,
    ModifyPortListOpts, ModifyPortListRequest, PortListOpts,
};
use gvm_gmp::commands::report_configs::{
    CloneReportConfigRequest, CreateReportConfigOpts, CreateReportConfigRequest,
    CreateReportConfigWithOptsRequest, DeleteReportConfigOpts, DeleteReportConfigRequest,
    DeleteReportConfigWithOptsRequest, GetReportConfigRequest, GetReportConfigsOpts,
    GetReportConfigsWithOptsRequest, ModifyReportConfigOpts, ModifyReportConfigRequest,
};
use gvm_gmp::commands::report_formats::{
    CloneReportFormatRequest, CreateReportFormatRequest, DeleteReportFormatRequest,
    GetReportFormatRequest, GetReportFormatsOpts, GetReportFormatsRequest,
    ImportReportFormatRequest, ModifyReportFormatRequest, ReportFormatOpts,
    VerifyReportFormatRequest,
};
use gvm_gmp::commands::reports::{
    ExportScanReportOpts, ExportScanReportRequest, GetAuditReportHostsOpts,
    GetAuditReportHostsRequest, GetAuditReportOpts, GetAuditReportRequest,
    GetReportApplicationsRequest, GetReportClosedCvesRequest, GetReportCvesRequest,
    GetReportDetailsOpts, GetReportErrorsRequest, GetReportExportOpts, GetReportExportRequest,
    GetReportHostsRequest, GetReportOperatingSystemsRequest, GetReportPortsRequest,
    GetReportTlsCertificatesRequest, GetReportVulnsRequest, GetReportsOpts, GetReportsRequest,
    ImportReportOpts, ImportReportRequest,
};
use gvm_gmp::commands::results::{GetResultRequest, GetResultsOpts, GetResultsRequest};
use gvm_gmp::commands::roles::{
    CloneRoleRequest, CreateRoleRequest, DeleteRoleRequest, GetRoleRequest, GetRolesOpts,
    GetRolesRequest, ModifyRoleRequest, RoleOpts,
};
use gvm_gmp::commands::scan_configs::{
    CloneScanConfigRequest, ConfigOpts, CreateScanConfigRequest, DeleteScanConfigRequest,
    GetPoliciesRequest, GetPolicyOpts, GetPolicyRequest, GetScanConfigRequest, GetScanConfigsOpts,
    GetScanConfigsRequest, ImportPolicyRequest, ImportScanConfigRequest,
    ModifyPolicySetCommentRequest, ModifyPolicySetNameRequest, ModifyScanConfigRequest,
    ModifyScanConfigSetCommentRequest, ModifyScanConfigSetNameRequest, SyncConfigRequest,
};
use gvm_gmp::commands::scanners::{
    CloneScannerRequest, CreateScannerRequest, DeleteScannerRequest, GetScannerRequest,
    GetScannersOpts, GetScannersRequest, ModifyScannerRequest, ScannerOpts, VerifyScannerRequest,
};
use gvm_gmp::commands::schedules::{
    CloneScheduleRequest, CreateScheduleRequest, CreateTypedScheduleRequest, DeleteScheduleRequest,
    GetScheduleRequest, GetSchedulesOpts, GetSchedulesRequest, ModifyScheduleRequest,
    ModifyTypedScheduleRequest, ScheduleOpts,
};
use gvm_gmp::commands::secinfo::{
    GenericInfoType, GetCertBundAdvisoriesRequest, GetCertBundAdvisoryRequest, GetCpeRequest,
    GetCpesRequest, GetCveRequest, GetCvesRequest, GetDfnCertAdvisoriesRequest,
    GetDfnCertAdvisoryRequest, GetInfoListOpts, GetInfoListRequest, GetInfoRequest,
    GetOperatingSystemsRequest, GetSecInfoOpts, GetVulnerabilitiesRequest,
};
use gvm_gmp::commands::system::{
    describe_auth, get_settings, get_timezones, get_vulnerability as get_vulnerability_cmd,
    get_vulns, modify_auth, modify_license_with_opts, run_wizard_with_opts, FilteredGetOpts,
    ModifyLicenseOpts, RunWizardOpts,
};
use gvm_gmp::commands::system_reports::{get_system_reports, GetSystemReportsOpts};
use gvm_gmp::commands::tags::{
    CloneTagRequest, CreateTagRequest, DeleteTagRequest, GetTagRequest, GetTagsOpts,
    GetTagsRequest, ModifyTagRequest, TagOpts,
};
use gvm_gmp::commands::targets::{
    CreateTargetOpts, CreateTargetRequest, DeleteTargetRequest, GetTargetRequest, GetTargetsOpts,
    GetTargetsRequest, ModifyTargetOpts, ModifyTargetRequest,
};
use gvm_gmp::commands::tasks::{
    CloneAuditRequest, CloneTaskRequest, CreateAgentGroupTaskOpts, CreateAgentGroupTaskRequest,
    CreateAuditRequest, CreateContainerImageTaskRequest, CreateContainerTaskRequest,
    CreateImportTaskRequest, CreateOciImageTargetTaskOpts, CreateOciImageTargetTaskRequest,
    CreateTaskOpts, CreateTaskRequest, CreateWebApplicationTaskOpts,
    CreateWebApplicationTaskRequest, DeleteAuditRequest, DeleteTaskRequest, GetAuditRequest,
    GetAuditsRequest, GetTaskRequest, GetTasksOpts, GetTasksRequest, ModifyAuditRequest,
    ModifyTaskOpts, ModifyTaskRequest, MoveTaskRequest, ResumeAuditRequest, ResumeTaskRequest,
    StartAuditRequest, StartTaskRequest, StopAuditRequest, StopTaskRequest,
};
use gvm_gmp::commands::tickets::{
    create_ticket, get_tickets, modify_ticket, CreateTicketOpts, GetTicketsOpts, ModifyTicketOpts,
};
use gvm_gmp::commands::tls_certificates::{
    CloneTlsCertificateRequest, CreateTlsCertificateRequest, DeleteTlsCertificateRequest,
    GetTlsCertificateRequest, GetTlsCertificatesOpts, GetTlsCertificatesRequest,
    ModifyTlsCertificateRequest, TlsCertificateOpts,
};
use gvm_gmp::commands::trashcan::{
    EmptyTrashcanRequest, RestoreFromTrashcanRequest, RestoreRequest,
};
use gvm_gmp::commands::users::{
    CloneUserRequest, CreateUserRequest, DeleteUserRequest, GetUserRequest, GetUsersOpts,
    GetUsersRequest, ModifyUserOpts, ModifyUserRequest, UserOpts,
};
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::commands::web_application_targets::{
    CloneWebApplicationTargetRequest, CreateWebApplicationTargetOpts,
    CreateWebApplicationTargetRequest, DeleteWebApplicationTargetRequest,
    GetWebApplicationTargetRequest, GetWebApplicationTargetsOpts, GetWebApplicationTargetsRequest,
    ModifyWebApplicationTargetOpts, ModifyWebApplicationTargetRequest,
};
use gvm_gmp::responses::{
    ActionResponse, AuthenticateResponse, CreateAlertResponse, CreateAssetResponse,
    CreateConfigResponse, CreateCredentialResponse, CreateFilterResponse, CreateGroupResponse,
    CreateHostResponse, CreateNoteResponse, CreateOciImageTargetResponse, CreateOverrideResponse,
    CreatePermissionResponse, CreatePortListResponse, CreatePortRangeResponse,
    CreateReportConfigResponse, CreateReportFormatResponse, CreateReportResponse,
    CreateRoleResponse, CreateScanConfigResponse, CreateScannerResponse, CreateScheduleResponse,
    CreateTagResponse, CreateTargetResponse, CreateTaskResponse, CreateTicketResponse,
    CreateTlsCertificateResponse, CreateUserResponse, CreateWebApplicationTargetResponse,
    DeleteAlertResponse, DeleteAssetResponse, DeleteConfigResponse, DeleteCredentialResponse,
    DeleteFilterResponse, DeleteGroupResponse, DeleteHostResponse, DeleteNoteResponse,
    DeleteOciImageTargetResponse, DeleteOverrideResponse, DeletePermissionResponse,
    DeletePortListResponse, DeletePortRangeResponse, DeleteReportConfigResponse,
    DeleteReportFormatResponse, DeleteRoleResponse, DeleteScanConfigResponse,
    DeleteScannerResponse, DeleteScheduleResponse, DeleteTagResponse, DeleteTargetResponse,
    DeleteTaskResponse, DeleteTlsCertificateResponse, DeleteUserResponse,
    DeleteWebApplicationTargetResponse, DescribeAuthResponse, EmptyTrashcanResponse,
    ExportScanReportResponse, GetAggregatesResponse, GetAlertsResponse, GetAssetsResponse,
    GetAuditReportHostsResponse, GetAuditReportResponse, GetCertBundAdvisoriesResponse,
    GetConfigsResponse, GetCpesResponse, GetCredentialStoresResponse, GetCredentialsResponse,
    GetCvesResponse, GetDfnCertAdvisoriesResponse, GetFeaturesResponse, GetFeedsResponse,
    GetFiltersResponse, GetGroupsResponse, GetHostsResponse, GetInfoResponse,
    GetIntegrationConfigsResponse, GetNotesResponse, GetNvtFamiliesResponse, GetNvtsResponse,
    GetOciImageTargetsResponse, GetOperatingSystemAssetsResponse, GetOperatingSystemsResponse,
    GetOverridesResponse, GetPermissionsResponse, GetPortListsResponse,
    GetReportApplicationsResponse, GetReportClosedCvesResponse, GetReportConfigsResponse,
    GetReportCvesResponse, GetReportErrorsResponse, GetReportFormatsResponse,
    GetReportHostsResponse, GetReportOperatingSystemsResponse, GetReportPortsResponse,
    GetReportTlsCertificatesResponse, GetReportVulnsResponse, GetReportsResponse,
    GetResultsResponse, GetRolesResponse, GetScanConfigPreferencesResponse, GetScanConfigsResponse,
    GetScannersResponse, GetSchedulesResponse, GetSettingsResponse, GetSystemReportsResponse,
    GetTagsResponse, GetTargetsResponse, GetTasksResponse, GetTicketsResponse,
    GetTimezonesResponse, GetTlsCertificatesResponse, GetUsersResponse, GetVersionResponse,
    GetVulnerabilitiesResponse, GetWebApplicationTargetsResponse, HelpResponse,
    ModifyAlertResponse, ModifyAssetResponse, ModifyAuthResponse, ModifyConfigResponse,
    ModifyCredentialResponse, ModifyFilterResponse, ModifyGroupResponse, ModifyHostResponse,
    ModifyIntegrationConfigResponse, ModifyLicenseResponse, ModifyNoteResponse,
    ModifyOciImageTargetResponse, ModifyOverrideResponse, ModifyPermissionResponse,
    ModifyPortListResponse, ModifyReportConfigResponse, ModifyReportFormatResponse,
    ModifyRoleResponse, ModifyScanConfigResponse, ModifyScannerResponse, ModifyScheduleResponse,
    ModifyTagResponse, ModifyTargetResponse, ModifyTaskResponse, ModifyTicketResponse,
    ModifyTlsCertificateResponse, ModifyUserResponse, ModifyWebApplicationTargetResponse,
    MoveTaskResponse, ReportExport, RestoreResponse, ResumeTaskResponse, RunWizardResponse,
    StartTaskResponse, StopTaskResponse, SyncConfigResponse, VerifyCredentialStoreResponse,
    VerifyReportFormatResponse, VerifyScannerResponse,
};
use gvm_gmp::types::EntityId;
use gvm_gmp::{CredentialStoreCredentialType, FeedType, PortRangeType, ScheduleInput};

use crate::{GmpClient, GvmError};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Version & Auth ────────────────────────────────────────────────────────

    /// Send a `get_version` request and return a typed [`GetVersionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_version(&mut self) -> Result<GetVersionResponse, GvmError> {
        self.execute(GetVersionRequest::new()).await
    }

    /// Send an `authenticate` request and return a typed [`AuthenticateResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn authenticate(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticateResponse, GvmError> {
        self.execute(AuthenticateRequest::new(username, password))
            .await
    }

    // ── Targets ───────────────────────────────────────────────────────────────

    /// Send a `get_targets` request and return a typed [`GetTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_targets(
        &mut self,
        opts: GetTargetsOpts,
    ) -> Result<GetTargetsResponse, GvmError> {
        self.execute(GetTargetsRequest::new(opts)).await
    }

    /// Send a detailed `get_targets` request for one target and return a typed
    /// [`GetTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_target(
        &mut self,
        target_id: &EntityId,
    ) -> Result<GetTargetsResponse, GvmError> {
        self.execute(GetTargetRequest::new(target_id.clone())).await
    }

    /// Send a `create_target` request and return a typed [`CreateTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_target(
        &mut self,
        name: &str,
        opts: CreateTargetOpts,
    ) -> Result<CreateTargetResponse, GvmError> {
        let request = CreateTargetRequest::new(name, opts)?;
        self.execute(request).await
    }

    /// Send a `modify_target` request and return a typed [`ModifyTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_target(
        &mut self,
        target_id: &EntityId,
        opts: ModifyTargetOpts,
    ) -> Result<ModifyTargetResponse, GvmError> {
        let request = ModifyTargetRequest::new(target_id.clone(), opts)?;
        self.execute(request).await
    }

    /// Send a `delete_target` request and return a typed [`DeleteTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_target(
        &mut self,
        target_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteTargetResponse, GvmError> {
        self.execute(DeleteTargetRequest::new(target_id.clone(), ultimate))
            .await
    }

    /// Send a `create_oci_image_target` request and return a typed
    /// [`CreateOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_oci_image_target_parsed(
        &mut self,
        name: &str,
        image_references: &[String],
        opts: CreateOciImageTargetOpts,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.execute(CreateOciImageTargetRequest::new(
            name,
            image_references.to_vec(),
            opts,
        ))
        .await
    }

    /// Send a `clone_oci_image_target` request and return a typed
    /// [`CreateOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
    ) -> Result<CreateOciImageTargetResponse, GvmError> {
        self.execute(CloneOciImageTargetRequest::new(oci_image_target_id.clone()))
            .await
    }

    /// Send a `get_oci_image_targets` request for one target and return a typed
    /// [`GetOciImageTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.execute(GetOciImageTargetRequest::new(
            oci_image_target_id.clone(),
            tasks,
        ))
        .await
    }

    /// Send a `get_oci_image_targets` request and return a typed
    /// [`GetOciImageTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_oci_image_targets_parsed(
        &mut self,
        opts: GetOciImageTargetsOpts,
    ) -> Result<GetOciImageTargetsResponse, GvmError> {
        self.execute(GetOciImageTargetsRequest::new(opts)).await
    }

    /// Send a `modify_oci_image_target` request and return a typed
    /// [`ModifyOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
        opts: ModifyOciImageTargetOpts,
    ) -> Result<ModifyOciImageTargetResponse, GvmError> {
        self.execute(ModifyOciImageTargetRequest::new(
            oci_image_target_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `delete_oci_image_target` request and return a typed
    /// [`DeleteOciImageTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_oci_image_target_parsed(
        &mut self,
        oci_image_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteOciImageTargetResponse, GvmError> {
        self.execute(DeleteOciImageTargetRequest::new(
            oci_image_target_id.clone(),
            ultimate,
        ))
        .await
    }

    /// Send a `create_web_application_target` request and return a typed
    /// [`CreateWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_web_application_target_parsed(
        &mut self,
        name: &str,
        urls: &[String],
        opts: CreateWebApplicationTargetOpts,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.execute(CreateWebApplicationTargetRequest::new(
            name,
            urls.to_vec(),
            opts,
        ))
        .await
    }

    /// Send a `clone_web_application_target` request and return a typed
    /// [`CreateWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
    ) -> Result<CreateWebApplicationTargetResponse, GvmError> {
        self.execute(CloneWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
        ))
        .await
    }

    /// Send a `get_web_application_targets` request for one target and return a
    /// typed [`GetWebApplicationTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
        tasks: Option<bool>,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.execute(GetWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
            tasks,
        ))
        .await
    }

    /// Send a `get_web_application_targets` request and return a typed
    /// [`GetWebApplicationTargetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_web_application_targets_parsed(
        &mut self,
        opts: GetWebApplicationTargetsOpts,
    ) -> Result<GetWebApplicationTargetsResponse, GvmError> {
        self.execute(GetWebApplicationTargetsRequest::new(opts))
            .await
    }

    /// Send a `modify_web_application_target` request and return a typed
    /// [`ModifyWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
        opts: ModifyWebApplicationTargetOpts,
    ) -> Result<ModifyWebApplicationTargetResponse, GvmError> {
        self.execute(ModifyWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `delete_web_application_target` request and return a typed
    /// [`DeleteWebApplicationTargetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_web_application_target_parsed(
        &mut self,
        web_application_target_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteWebApplicationTargetResponse, GvmError> {
        self.execute(DeleteWebApplicationTargetRequest::new(
            web_application_target_id.clone(),
            ultimate,
        ))
        .await
    }

    // ── Scan Configs ──────────────────────────────────────────────────────────

    /// Send a `get_scan_configs` request and return a typed [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_configs(
        &mut self,
        opts: GetScanConfigsOpts,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetScanConfigsRequest::new(opts)).await
    }

    /// Send a `create_scan_config` request and return a typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_scan_config(
        &mut self,
        name: &str,
        base_id: Option<&EntityId>,
        opts: ConfigOpts,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(CreateScanConfigRequest::new(name, base_id.cloned(), opts))
            .await
    }

    /// Send a `create_config` request that imports scan-config XML and return a
    /// typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the import XML is invalid, the request fails, or
    /// response parsing fails.
    pub async fn import_scan_config(
        &mut self,
        scan_config_xml: &str,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(ImportScanConfigRequest::new(scan_config_xml)?)
            .await
    }

    /// Send a `get_scan_config` request and return a typed [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config(
        &mut self,
        config_id: &EntityId,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetScanConfigRequest::new(config_id.clone()))
            .await
    }

    /// Send a policy-scoped `get_configs` request and return a typed
    /// [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_policies(
        &mut self,
        opts: GetScanConfigsOpts,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetPoliciesRequest::new(opts)).await
    }

    /// Send a `get_configs` request for a single policy and return a typed
    /// [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_policy(
        &mut self,
        policy_id: &EntityId,
        opts: GetPolicyOpts,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        self.execute(GetPolicyRequest::new(policy_id.clone(), opts))
            .await
    }

    /// Send a `create_config` request that imports policy XML and return a
    /// typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the import XML is invalid, request sending fails, or
    /// response parsing fails.
    pub async fn import_policy(
        &mut self,
        policy_xml: &str,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(ImportPolicyRequest::new(policy_xml)?).await
    }

    /// Send a `modify_scan_config` request and return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config(
        &mut self,
        config_id: &EntityId,
        opts: ConfigOpts,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyScanConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a `modify_config` request to set a scan-config name and return a
    /// typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config_set_name(
        &mut self,
        config_id: &EntityId,
        name: &str,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyScanConfigSetNameRequest::new(config_id.clone(), name))
            .await
    }

    /// Send a `modify_config` request to set or clear a scan-config comment and
    /// return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scan_config_set_comment(
        &mut self,
        config_id: &EntityId,
        comment: Option<&str>,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyScanConfigSetCommentRequest::new(
            config_id.clone(),
            comment.map(str::to_string),
        ))
        .await
    }

    /// Send a `modify_config` request to set a policy name and return a typed
    /// [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_policy_set_name(
        &mut self,
        policy_id: &EntityId,
        name: &str,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyPolicySetNameRequest::new(policy_id.clone(), name))
            .await
    }

    /// Send a `modify_config` request to set or clear a policy comment and
    /// return a typed [`ModifyScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_policy_set_comment(
        &mut self,
        policy_id: &EntityId,
        comment: Option<&str>,
    ) -> Result<ModifyScanConfigResponse, GvmError> {
        self.execute(ModifyPolicySetCommentRequest::new(
            policy_id.clone(),
            comment.map(str::to_string),
        ))
        .await
    }

    /// Send a `delete_scan_config` request and return a typed [`DeleteScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_scan_config(
        &mut self,
        config_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteScanConfigResponse, GvmError> {
        self.execute(DeleteScanConfigRequest::new(config_id.clone(), ultimate))
            .await
    }

    /// Send a `clone_scan_config` request and return a typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scan_config(
        &mut self,
        config_id: &EntityId,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        self.execute(CloneScanConfigRequest::new(config_id.clone()))
            .await
    }

    /// Send the global `sync_config` request and return a typed
    /// [`SyncConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn sync_config(&mut self) -> Result<SyncConfigResponse, GvmError> {
        self.execute(SyncConfigRequest::new()).await
    }

    /// Send the global `sync_config` request and return a typed
    /// [`SyncConfigResponse`].
    ///
    /// The GMP command synchronizes all configs and does not accept a config
    /// identifier. The argument is retained temporarily for source
    /// compatibility and is ignored.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    #[deprecated(note = "use sync_config(), which has global semantics")]
    pub async fn sync_scan_config(
        &mut self,
        _config_id: &EntityId,
    ) -> Result<SyncConfigResponse, GvmError> {
        self.sync_config().await
    }

    // ── Scanners ──────────────────────────────────────────────────────────────

    /// Send a `get_scanners` request and return a typed [`GetScannersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scanners(
        &mut self,
        opts: GetScannersOpts,
    ) -> Result<GetScannersResponse, GvmError> {
        self.execute(GetScannersRequest::new(opts)).await
    }

    /// Send a `create_scanner` request and return a typed [`CreateScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_scanner(
        &mut self,
        name: &str,
        opts: ScannerOpts,
    ) -> Result<CreateScannerResponse, GvmError> {
        self.execute(CreateScannerRequest::new(name, opts)).await
    }

    /// Send a `get_scanner` request and return a typed [`GetScannersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<GetScannersResponse, GvmError> {
        self.execute(GetScannerRequest::new(scanner_id.clone()))
            .await
    }

    /// Send a `modify_scanner` request and return a typed [`ModifyScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_scanner(
        &mut self,
        scanner_id: &EntityId,
        opts: ScannerOpts,
    ) -> Result<ModifyScannerResponse, GvmError> {
        self.execute(ModifyScannerRequest::new(scanner_id.clone(), opts))
            .await
    }

    /// Send a `delete_scanner` request and return a typed [`DeleteScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_scanner(
        &mut self,
        scanner_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteScannerResponse, GvmError> {
        self.execute(DeleteScannerRequest::new(scanner_id.clone(), ultimate))
            .await
    }

    /// Send a `verify_scanner` request and return a typed [`VerifyScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<VerifyScannerResponse, GvmError> {
        self.execute(VerifyScannerRequest::new(scanner_id.clone()))
            .await
    }

    /// Send a `clone_scanner` request and return a typed [`CreateScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<CreateScannerResponse, GvmError> {
        self.execute(CloneScannerRequest::new(scanner_id.clone()))
            .await
    }

    // ── Port Lists ────────────────────────────────────────────────────────────

    /// Send a `get_port_lists` request and return a typed [`GetPortListsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_port_lists(
        &mut self,
        opts: GetPortListsOpts,
    ) -> Result<GetPortListsResponse, GvmError> {
        self.execute(GetPortListsRequest::new(opts)).await
    }

    /// Send a detailed `get_port_lists` request for one port list.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_port_list(
        &mut self,
        port_list_id: &EntityId,
    ) -> Result<GetPortListsResponse, GvmError> {
        self.execute(GetPortListRequest::new(port_list_id.clone()))
            .await
    }

    /// Send a `create_port_list` request and return a typed [`CreatePortListResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_port_list(
        &mut self,
        name: &str,
        opts: PortListOpts,
    ) -> Result<CreatePortListResponse, GvmError> {
        self.execute(CreatePortListRequest::new(name, opts)).await
    }

    /// Clone a port list through `create_port_list`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_port_list(
        &mut self,
        port_list_id: &EntityId,
    ) -> Result<CreatePortListResponse, GvmError> {
        self.execute(ClonePortListRequest::new(port_list_id.clone()))
            .await
    }

    /// Send a `modify_port_list` request and return a typed
    /// [`ModifyPortListResponse`].
    ///
    /// gvmd replaces both the name and comment, clearing either field when its
    /// option is omitted. Use the port-range commands to change ranges.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_port_list(
        &mut self,
        port_list_id: &EntityId,
        opts: ModifyPortListOpts,
    ) -> Result<ModifyPortListResponse, GvmError> {
        self.execute(ModifyPortListRequest::new(port_list_id.clone(), opts))
            .await
    }

    /// Send a `delete_port_list` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_port_list(
        &mut self,
        port_list_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeletePortListResponse, GvmError> {
        self.execute(DeletePortListRequest::new(port_list_id.clone(), ultimate))
            .await
    }

    /// Send a `create_port_range` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_port_range(
        &mut self,
        port_list_id: &EntityId,
        range_type: PortRangeType,
        start: u16,
        end: u16,
    ) -> Result<CreatePortRangeResponse, GvmError> {
        self.execute(CreatePortRangeRequest::new(
            port_list_id.clone(),
            range_type,
            start,
            end,
        ))
        .await
    }

    /// Send a `delete_port_range` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_port_range(
        &mut self,
        port_range_id: &EntityId,
    ) -> Result<DeletePortRangeResponse, GvmError> {
        self.execute(DeletePortRangeRequest::new(port_range_id.clone()))
            .await
    }

    // ── Tasks ─────────────────────────────────────────────────────────────────

    /// Send a `get_tasks` request and return a typed [`GetTasksResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tasks(&mut self, opts: GetTasksOpts) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetTasksRequest::new(opts)).await
    }

    /// Send a detailed single-task `get_tasks` request and return a typed
    /// [`GetTasksResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_task(&mut self, task_id: &EntityId) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetTaskRequest::new(task_id.clone())).await
    }

    /// Send a `create_task` request and return a typed [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_task(
        &mut self,
        name: &str,
        config_id: &EntityId,
        target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateTaskRequest::new(
            name,
            config_id.clone(),
            target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a task-copy `create_task` request and return a typed
    /// [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_task(&mut self, task_id: &EntityId) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CloneTaskRequest::new(task_id.clone())).await
    }

    /// Send a `create_task` import-task request and return a typed [`CreateTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_import_task(
        &mut self,
        name: &str,
        comment: Option<&str>,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateImportTaskRequest::new(
            name,
            comment.map(str::to_owned),
        ))
        .await
    }

    /// Send the compatibility-alias container/import `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_container_task(
        &mut self,
        name: &str,
        comment: Option<&str>,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateContainerTaskRequest::new(
            name,
            comment.map(str::to_owned),
        ))
        .await
    }

    /// Send an agent-group `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_agent_group_task(
        &mut self,
        name: &str,
        agent_group_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateAgentGroupTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateAgentGroupTaskRequest::new(
            name,
            agent_group_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send an OCI image-target `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_oci_image_target_task(
        &mut self,
        name: &str,
        oci_image_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateOciImageTargetTaskRequest::new(
            name,
            oci_image_target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send the compatibility-alias container-image `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_container_image_task(
        &mut self,
        name: &str,
        oci_image_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateOciImageTargetTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateContainerImageTaskRequest::new(
            name,
            oci_image_target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a web-application-target `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_web_application_task(
        &mut self,
        name: &str,
        web_application_target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateWebApplicationTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateWebApplicationTaskRequest::new(
            name,
            web_application_target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `move_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn move_task(
        &mut self,
        task_id: &EntityId,
        slave_id: Option<&EntityId>,
    ) -> Result<MoveTaskResponse, GvmError> {
        self.execute(MoveTaskRequest::new(task_id.clone(), slave_id.cloned()))
            .await
    }

    /// Send an audit-scoped `get_tasks` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audits(&mut self, opts: GetTasksOpts) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetAuditsRequest::new(opts)).await
    }

    /// Send a detailed single-audit `get_tasks` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit(&mut self, audit_id: &EntityId) -> Result<GetTasksResponse, GvmError> {
        self.execute(GetAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_audit(
        &mut self,
        name: &str,
        config_id: &EntityId,
        target_id: &EntityId,
        scanner_id: &EntityId,
        opts: CreateTaskOpts,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CreateAuditRequest::new(
            name,
            config_id.clone(),
            target_id.clone(),
            scanner_id.clone(),
            opts,
        ))
        .await
    }

    /// Send an audit-copy `create_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<CreateTaskResponse, GvmError> {
        self.execute(CloneAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit-scoped `modify_task` request.
    ///
    /// # Errors
    /// Returns an error if request construction, transmission, or response parsing fails.
    pub async fn modify_audit(
        &mut self,
        audit_id: &EntityId,
        opts: ModifyTaskOpts,
    ) -> Result<ModifyTaskResponse, GvmError> {
        self.execute(ModifyAuditRequest::new(audit_id.clone(), opts)?)
            .await
    }

    /// Send an audit `delete_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<DeleteTaskResponse, GvmError> {
        self.execute(DeleteAuditRequest::new(audit_id.clone()))
            .await
    }

    /// Send an audit `start_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn start_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<StartTaskResponse, GvmError> {
        self.execute(StartAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit `stop_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn stop_audit(&mut self, audit_id: &EntityId) -> Result<StopTaskResponse, GvmError> {
        self.execute(StopAuditRequest::new(audit_id.clone())).await
    }

    /// Send an audit `resume_task` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn resume_audit(
        &mut self,
        audit_id: &EntityId,
    ) -> Result<ResumeTaskResponse, GvmError> {
        self.execute(ResumeAuditRequest::new(audit_id.clone()))
            .await
    }

    /// Send a `start_task` request and return a typed [`StartTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn start_task(&mut self, task_id: &EntityId) -> Result<StartTaskResponse, GvmError> {
        self.execute(StartTaskRequest::new(task_id.clone())).await
    }

    /// Send a `resume_task` request and return a typed [`ResumeTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn resume_task(
        &mut self,
        task_id: &EntityId,
    ) -> Result<ResumeTaskResponse, GvmError> {
        self.execute(ResumeTaskRequest::new(task_id.clone())).await
    }

    /// Send a `modify_task` request and return a typed [`ModifyTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_task(
        &mut self,
        task_id: &EntityId,
        opts: ModifyTaskOpts,
    ) -> Result<ModifyTaskResponse, GvmError> {
        self.execute(ModifyTaskRequest::new(task_id.clone(), opts)?)
            .await
    }

    /// Send a `stop_task` request and return a typed [`StopTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn stop_task(&mut self, task_id: &EntityId) -> Result<StopTaskResponse, GvmError> {
        self.execute(StopTaskRequest::new(task_id.clone())).await
    }

    /// Send a `delete_task` request and return a typed [`DeleteTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_task(
        &mut self,
        task_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteTaskResponse, GvmError> {
        self.execute(DeleteTaskRequest::new(task_id.clone(), ultimate))
            .await
    }

    /// Send an `empty_trashcan` request and return a typed [`EmptyTrashcanResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn empty_trashcan(&mut self) -> Result<EmptyTrashcanResponse, GvmError> {
        self.execute(EmptyTrashcanRequest::new()).await
    }

    /// Send a `restore` request through its baseline helper name.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn restore(&mut self, resource_id: &EntityId) -> Result<RestoreResponse, GvmError> {
        self.execute(RestoreRequest::new(resource_id.clone())).await
    }

    /// Send a `restore` request and return a typed [`RestoreResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn restore_from_trashcan(
        &mut self,
        resource_id: &EntityId,
    ) -> Result<RestoreResponse, GvmError> {
        self.execute(RestoreFromTrashcanRequest::new(resource_id.clone()))
            .await
    }

    // ── Reports ───────────────────────────────────────────────────────────────

    /// Send a `get_audit_report` request and return a typed structured report.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit_report(
        &mut self,
        audit_report_id: &EntityId,
        opts: GetAuditReportOpts,
    ) -> Result<GetAuditReportResponse, GvmError> {
        self.execute(GetAuditReportRequest::new(audit_report_id.clone(), opts))
            .await
    }

    /// Send a `get_audit_report_hosts` request and return typed host summaries.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_audit_report_hosts(
        &mut self,
        report_id: &EntityId,
        opts: GetAuditReportHostsOpts,
    ) -> Result<GetAuditReportHostsResponse, GvmError> {
        self.execute(GetAuditReportHostsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_reports` request and return a typed [`GetReportsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_reports(
        &mut self,
        opts: GetReportsOpts,
    ) -> Result<GetReportsResponse, GvmError> {
        self.execute(GetReportsRequest::new(opts)).await
    }

    /// Queue or reuse an asynchronous scan-report export and return its typed
    /// identifier and optional processing status.
    ///
    /// Call [`GmpClient::discover_commands`] first. The negotiated GMP version
    /// does not prove that the server implements this command.
    ///
    /// # Errors
    /// Returns an error if positive help discovery is missing, the command is
    /// unavailable, the request fails, or response parsing fails.
    pub async fn export_scan_report(
        &mut self,
        report_id: &EntityId,
        opts: ExportScanReportOpts,
    ) -> Result<ExportScanReportResponse, GvmError> {
        self.execute(ExportScanReportRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_vulns` request and return a typed [`GetReportVulnsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_vulns(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportVulnsResponse, GvmError> {
        self.execute(GetReportVulnsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_vulns` request using python-gvm's descriptive helper
    /// name and return a typed [`GetReportVulnsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_vulnerabilities(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportVulnsResponse, GvmError> {
        self.execute(GetReportVulnsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_tls_certificates` request and return a typed [`GetReportTlsCertificatesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_tls_certificates(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportTlsCertificatesResponse, GvmError> {
        self.execute(GetReportTlsCertificatesRequest::new(
            report_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `get_report_hosts` request and return a typed
    /// [`GetReportHostsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_hosts`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_hosts_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportHostsResponse, GvmError> {
        self.execute(GetReportHostsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_ports` request and return a typed
    /// [`GetReportPortsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_ports`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_ports_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportPortsResponse, GvmError> {
        self.execute(GetReportPortsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_applications` request and return a typed
    /// [`GetReportApplicationsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_applications`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_applications_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportApplicationsResponse, GvmError> {
        self.execute(GetReportApplicationsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_operating_systems` request and return a typed
    /// [`GetReportOperatingSystemsResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_operating_systems`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_operating_systems_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportOperatingSystemsResponse, GvmError> {
        self.execute(GetReportOperatingSystemsRequest::new(
            report_id.clone(),
            opts,
        ))
        .await
    }

    /// Send a `get_report_cves` request and return a typed
    /// [`GetReportCvesResponse`].
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_report_cves`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_cves_parsed(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportCvesResponse, GvmError> {
        self.execute(GetReportCvesRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_errors` request and return a typed [`GetReportErrorsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_errors(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportErrorsResponse, GvmError> {
        self.execute(GetReportErrorsRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_report_closed_cves` request and return a typed [`GetReportClosedCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_closed_cves(
        &mut self,
        report_id: &EntityId,
        opts: GetReportDetailsOpts,
    ) -> Result<GetReportClosedCvesResponse, GvmError> {
        self.execute(GetReportClosedCvesRequest::new(report_id.clone(), opts))
            .await
    }

    /// Send a `get_reports` export request and return a typed [`ReportExport`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_export(
        &mut self,
        report_id: &EntityId,
        report_format_id: &EntityId,
    ) -> Result<ReportExport, GvmError> {
        self.execute(GetReportExportRequest::new(
            report_id.clone(),
            GetReportExportOpts::new(report_format_id.clone()),
        ))
        .await
    }

    /// Send a `get_reports` export request with export options and return a typed [`ReportExport`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_export_with_opts(
        &mut self,
        report_id: &EntityId,
        opts: GetReportExportOpts,
    ) -> Result<ReportExport, GvmError> {
        self.execute(GetReportExportRequest::new(report_id.clone(), opts))
            .await
    }

    // ── Results ───────────────────────────────────────────────────────────────

    /// Send a `get_results` request and return a typed [`GetResultsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_results(
        &mut self,
        opts: GetResultsOpts,
    ) -> Result<GetResultsResponse, GvmError> {
        self.execute(GetResultsRequest::new(opts)).await
    }

    /// Send a single-result `get_results` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_result(
        &mut self,
        result_id: &EntityId,
    ) -> Result<GetResultsResponse, GvmError> {
        self.execute(GetResultRequest::new(result_id.clone())).await
    }

    // ── Feeds ─────────────────────────────────────────────────────────────────

    /// Send a `get_feeds` request and return a typed [`GetFeedsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_feeds(&mut self) -> Result<GetFeedsResponse, GvmError> {
        let response = self.send(get_feeds()).await?;
        GetFeedsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a type-filtered `get_feeds` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_feed(&mut self, feed_type: FeedType) -> Result<GetFeedsResponse, GvmError> {
        let response = self.send(get_feed(feed_type)).await?;
        GetFeedsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_timezones` request and return a typed [`GetTimezonesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_timezones(&mut self) -> Result<GetTimezonesResponse, GvmError> {
        let response = self.send(get_timezones()).await?;
        GetTimezonesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_credential_stores` request and return a typed [`GetCredentialStoresResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credential_stores(&mut self) -> Result<GetCredentialStoresResponse, GvmError> {
        self.execute(GetCredentialStoresRequest::default()).await
    }

    /// Send a `verify_credential_store` request and return a typed
    /// [`VerifyCredentialStoreResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_credential_store(
        &mut self,
        credential_store_id: &EntityId,
    ) -> Result<VerifyCredentialStoreResponse, GvmError> {
        self.execute(VerifyCredentialStoreRequest::new(
            credential_store_id.clone(),
        ))
        .await
    }

    /// Send a filtered `get_credential_stores` request and return a typed
    /// [`GetCredentialStoresResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credential_stores_with_opts(
        &mut self,
        opts: GetCredentialStoresOpts,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.execute(GetCredentialStoresRequest::new(opts)).await
    }

    /// Send a single-store `get_credential_stores` request and return a typed
    /// [`GetCredentialStoresResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credential_store(
        &mut self,
        credential_store_id: &EntityId,
        details: Option<bool>,
    ) -> Result<GetCredentialStoresResponse, GvmError> {
        self.execute(GetCredentialStoreRequest::new(
            credential_store_id.clone(),
            details,
        ))
        .await
    }

    // ── NVTs ──────────────────────────────────────────────────────────────────

    /// Send a `get_nvts` request and return a typed [`GetNvtsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvts(&mut self, opts: GetNvtsOpts) -> Result<GetNvtsResponse, GvmError> {
        self.execute(GetNvtsRequest::new(opts)).await
    }

    /// Send a detailed `get_nvts` request for one NVT.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt(&mut self, nvt_oid: &str) -> Result<GetNvtsResponse, GvmError> {
        self.execute(GetNvtRequest::new(nvt_oid)).await
    }

    /// Send a scan-config scoped `get_nvts` request and return a typed [`GetNvtsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config_nvts(
        &mut self,
        opts: GetNvtsOpts,
    ) -> Result<GetNvtsResponse, GvmError> {
        self.execute(GetScanConfigNvtsRequest::new(opts)).await
    }

    /// Send a scan-config compatibility `get_nvts` request for a single NVT.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config_nvt(
        &mut self,
        nvt_oid: &str,
    ) -> Result<GetNvtsResponse, GvmError> {
        self.execute(GetScanConfigNvtRequest::new(nvt_oid)).await
    }

    /// Send a `get_preferences` request for NVT preferences.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt_preferences(
        &mut self,
        opts: GetNvtPreferencesOpts,
    ) -> Result<GetScanConfigPreferencesResponse, GvmError> {
        self.execute(GetNvtPreferencesRequest::new(opts)).await
    }

    /// Send a `get_preferences` request for one NVT preference.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt_preference(
        &mut self,
        name: &str,
        opts: GetNvtPreferencesOpts,
    ) -> Result<GetScanConfigPreferencesResponse, GvmError> {
        self.execute(GetNvtPreferenceRequest::new(name, opts)).await
    }

    /// Send a `get_nvt_families` request and return a typed [`GetNvtFamiliesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt_families(&mut self) -> Result<GetNvtFamiliesResponse, GvmError> {
        self.execute(GetNvtFamiliesRequest::new()).await
    }

    // ── SecInfo ───────────────────────────────────────────────────────────────

    /// Send a `get_info` request for CVE entries and return a typed [`GetCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cves(&mut self, opts: GetSecInfoOpts) -> Result<GetCvesResponse, GvmError> {
        self.execute(GetCvesRequest::new(opts)).await
    }

    /// Send a `get_info` request for a single CVE entry and return a typed
    /// [`GetCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cve(&mut self, cve_id: &str) -> Result<GetCvesResponse, GvmError> {
        self.execute(GetCveRequest::new(cve_id)).await
    }

    /// Send a `get_info` request for CPE entries and return a typed [`GetCpesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cpes(&mut self, opts: GetSecInfoOpts) -> Result<GetCpesResponse, GvmError> {
        self.execute(GetCpesRequest::new(opts)).await
    }

    /// Send a `get_info` request for a single CPE entry and return a typed
    /// [`GetCpesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cpe(&mut self, cpe_id: &str) -> Result<GetCpesResponse, GvmError> {
        self.execute(GetCpeRequest::new(cpe_id)).await
    }

    /// Send a `get_info` request for CERT-Bund advisories and return a typed
    /// [`GetCertBundAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cert_bund_advisories(
        &mut self,
        opts: GetSecInfoOpts,
    ) -> Result<GetCertBundAdvisoriesResponse, GvmError> {
        self.execute(GetCertBundAdvisoriesRequest::new(opts)).await
    }

    /// Send a `get_info` request for a single CERT-Bund advisory and return a
    /// typed [`GetCertBundAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cert_bund_advisory(
        &mut self,
        cert_id: &str,
    ) -> Result<GetCertBundAdvisoriesResponse, GvmError> {
        self.execute(GetCertBundAdvisoryRequest::new(cert_id)).await
    }

    /// Send a `get_info` request for DFN-CERT advisories and return a typed
    /// [`GetDfnCertAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_dfn_cert_advisories(
        &mut self,
        opts: GetSecInfoOpts,
    ) -> Result<GetDfnCertAdvisoriesResponse, GvmError> {
        self.execute(GetDfnCertAdvisoriesRequest::new(opts)).await
    }

    /// Send a `get_info` request for a single DFN-CERT advisory and return a
    /// typed [`GetDfnCertAdvisoriesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_dfn_cert_advisory(
        &mut self,
        cert_id: &str,
    ) -> Result<GetDfnCertAdvisoriesResponse, GvmError> {
        self.execute(GetDfnCertAdvisoryRequest::new(cert_id)).await
    }

    /// Send a generic single-entry `get_info` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_info(
        &mut self,
        info_id: &str,
        info_type: GenericInfoType,
    ) -> Result<GetInfoResponse, GvmError> {
        self.execute(GetInfoRequest::new(info_id, info_type)).await
    }

    /// Send a generic `get_info` list request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_info_list(
        &mut self,
        info_type: GenericInfoType,
        opts: GetInfoListOpts,
    ) -> Result<GetInfoResponse, GvmError> {
        self.execute(GetInfoListRequest::new(info_type, opts)).await
    }

    /// Send a `SecInfo` `get_info type="os"` list request.
    ///
    /// This is distinct from [`Self::get_operating_system_assets`], which
    /// executes the `get_assets` command family.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_secinfo_operating_systems(
        &mut self,
        opts: GetSecInfoOpts,
    ) -> Result<GetOperatingSystemsResponse, GvmError> {
        self.execute(GetOperatingSystemsRequest::new(opts)).await
    }

    /// Send a `SecInfo` `get_info type="vuln"` list request.
    ///
    /// This is distinct from [`Self::get_vulnerabilities`], which executes the
    /// legacy `get_vulns` command family.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_secinfo_vulnerabilities(
        &mut self,
        opts: GetSecInfoOpts,
    ) -> Result<GetVulnerabilitiesResponse, GvmError> {
        self.execute(GetVulnerabilitiesRequest::new(opts)).await
    }

    /// Send a `get_vulns` request for vulnerabilities and return a typed
    /// [`GetVulnerabilitiesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_vulnerabilities(
        &mut self,
        opts: FilteredGetOpts,
    ) -> Result<GetVulnerabilitiesResponse, GvmError> {
        let response = self.send(get_vulns(opts)).await?;
        GetVulnerabilitiesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_vulns` request for a single vulnerability and return a typed
    /// [`GetVulnerabilitiesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_vulnerability(
        &mut self,
        vulnerability_id: &str,
    ) -> Result<GetVulnerabilitiesResponse, GvmError> {
        let response = self.send(get_vulnerability_cmd(vulnerability_id)).await?;
        GetVulnerabilitiesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Alerts ────────────────────────────────────────────────────────────────

    /// Send a `get_alerts` request and return a typed [`GetAlertsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_alerts(&mut self, opts: GetAlertsOpts) -> Result<GetAlertsResponse, GvmError> {
        self.execute(GetAlertsRequest::new(opts)).await
    }

    /// Send a detailed single-alert `get_alerts` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_alert(&mut self, alert_id: &EntityId) -> Result<GetAlertsResponse, GvmError> {
        self.execute(GetAlertRequest::new(alert_id.clone())).await
    }

    /// Send a `create_alert` request and return a typed [`CreateAlertResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_alert(
        &mut self,
        name: &str,
        opts: AlertOpts,
    ) -> Result<CreateAlertResponse, GvmError> {
        self.execute(CreateAlertRequest::new(name, opts)).await
    }

    /// Send an alert-copy `create_alert` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_alert(
        &mut self,
        alert_id: &EntityId,
    ) -> Result<CreateAlertResponse, GvmError> {
        self.execute(CloneAlertRequest::new(alert_id.clone())).await
    }

    /// Send a `modify_alert` request and return a typed [`ModifyAlertResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_alert(
        &mut self,
        alert_id: &EntityId,
        opts: AlertOpts,
    ) -> Result<ModifyAlertResponse, GvmError> {
        self.execute(ModifyAlertRequest::new(alert_id.clone(), opts))
            .await
    }

    /// Send a `delete_alert` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_alert(
        &mut self,
        alert_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteAlertResponse, GvmError> {
        self.execute(DeleteAlertRequest::new(alert_id.clone(), ultimate))
            .await
    }

    /// Send a `test_alert` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn test_alert(&mut self, alert_id: &EntityId) -> Result<ActionResponse, GvmError> {
        self.execute(TestAlertRequest::new(alert_id.clone())).await
    }

    /// Trigger an alert for a report through the report query command.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn trigger_alert(
        &mut self,
        alert_id: &EntityId,
        report_id: &EntityId,
        opts: TriggerAlertOpts,
    ) -> Result<GetReportsResponse, GvmError> {
        self.execute(TriggerAlertRequest::new(
            alert_id.clone(),
            report_id.clone(),
            opts,
        ))
        .await
    }

    // ── Credentials ───────────────────────────────────────────────────────────

    /// Send a `get_credentials` request and return a typed [`GetCredentialsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_credentials(
        &mut self,
        opts: GetCredentialsOpts,
    ) -> Result<GetCredentialsResponse, GvmError> {
        self.execute(GetCredentialsRequest::new(opts)).await
    }

    /// Send a `create_credential` request and return a typed [`CreateCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_credential(
        &mut self,
        name: &str,
        opts: CredentialOpts,
    ) -> Result<CreateCredentialResponse, GvmError> {
        self.execute(CreateCredentialRequest::new(name, opts)).await
    }

    /// Send a `modify_credential` request and return a typed
    /// [`ModifyCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_credential(
        &mut self,
        credential_id: &EntityId,
        opts: ModifyCredentialOpts,
    ) -> Result<ModifyCredentialResponse, GvmError> {
        self.execute(ModifyCredentialRequest::new(credential_id.clone(), opts))
            .await
    }

    /// Send a `delete_credential` request and return a typed
    /// [`DeleteCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_credential(
        &mut self,
        credential_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteCredentialResponse, GvmError> {
        self.execute(DeleteCredentialRequest::new(
            credential_id.clone(),
            ultimate,
        ))
        .await
    }

    /// Send a credential-store-backed `create_credential` request and return a
    /// typed [`CreateCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_credential_store_credential(
        &mut self,
        name: &str,
        credential_type: CredentialStoreCredentialType,
        vault_id: &str,
        host_identifier: &str,
        opts: CredentialStoreCredentialOpts,
    ) -> Result<CreateCredentialResponse, GvmError> {
        self.execute(CreateCredentialStoreCredentialRequest::new(
            name,
            credential_type,
            vault_id,
            host_identifier,
            opts,
        ))
        .await
    }

    /// Send a credential-store-backed `modify_credential` request and return a
    /// typed [`ModifyCredentialResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_credential_store_credential(
        &mut self,
        credential_id: &EntityId,
        opts: ModifyCredentialStoreCredentialOpts,
    ) -> Result<ModifyCredentialResponse, GvmError> {
        self.execute(ModifyCredentialStoreCredentialRequest::new(
            credential_id.clone(),
            opts,
        ))
        .await
    }

    // ── Filters ───────────────────────────────────────────────────────────────

    /// Send a `get_filters` request and return a typed [`GetFiltersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_filters(
        &mut self,
        opts: GetFiltersOpts,
    ) -> Result<GetFiltersResponse, GvmError> {
        self.execute(GetFiltersRequest::new(opts)).await
    }

    /// Send a detailed single-filter request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_filter(
        &mut self,
        filter_id: &EntityId,
    ) -> Result<GetFiltersResponse, GvmError> {
        self.execute(GetFilterRequest::new(filter_id.clone())).await
    }

    /// Send a `create_filter` request and return a typed [`CreateFilterResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_filter(
        &mut self,
        name: &str,
        opts: FilterOpts,
    ) -> Result<CreateFilterResponse, GvmError> {
        self.execute(CreateFilterRequest::new(name, opts)).await
    }

    /// Clone a filter through `create_filter`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_filter(
        &mut self,
        filter_id: &EntityId,
    ) -> Result<CreateFilterResponse, GvmError> {
        self.execute(CloneFilterRequest::new(filter_id.clone()))
            .await
    }

    /// Send a `modify_filter` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_filter(
        &mut self,
        filter_id: &EntityId,
        opts: FilterOpts,
    ) -> Result<ModifyFilterResponse, GvmError> {
        self.execute(ModifyFilterRequest::new(filter_id.clone(), opts))
            .await
    }

    /// Send a `delete_filter` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_filter(
        &mut self,
        filter_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteFilterResponse, GvmError> {
        self.execute(DeleteFilterRequest::new(filter_id.clone(), ultimate))
            .await
    }

    // ── Notes ─────────────────────────────────────────────────────────────────

    /// Send a `get_notes` request and return a typed [`GetNotesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_notes(&mut self, opts: GetNotesOpts) -> Result<GetNotesResponse, GvmError> {
        self.execute(GetNotesRequest::new(opts)).await
    }

    /// Send a detailed single-note request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_note(&mut self, note_id: &EntityId) -> Result<GetNotesResponse, GvmError> {
        self.execute(GetNoteRequest::new(note_id.clone())).await
    }

    /// Send a `create_note` request and return a typed [`CreateNoteResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_note(
        &mut self,
        nvt_oid: &str,
        opts: NoteOpts,
    ) -> Result<CreateNoteResponse, GvmError> {
        self.execute(CreateNoteRequest::new(nvt_oid, opts)).await
    }

    /// Clone a note through `create_note`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_note(&mut self, note_id: &EntityId) -> Result<CreateNoteResponse, GvmError> {
        self.execute(CloneNoteRequest::new(note_id.clone())).await
    }

    /// Send a `modify_note` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_note(
        &mut self,
        note_id: &EntityId,
        opts: ModifyNoteOpts,
    ) -> Result<ModifyNoteResponse, GvmError> {
        self.execute(ModifyNoteRequest::new(note_id.clone(), opts))
            .await
    }

    /// Send a `delete_note` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_note(
        &mut self,
        note_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteNoteResponse, GvmError> {
        self.execute(DeleteNoteRequest::new(note_id.clone(), ultimate))
            .await
    }

    // ── Overrides ─────────────────────────────────────────────────────────────

    /// Send a `get_overrides` request and return a typed [`GetOverridesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_overrides(
        &mut self,
        opts: GetOverridesOpts,
    ) -> Result<GetOverridesResponse, GvmError> {
        self.execute(GetOverridesRequest::new(opts)).await
    }

    /// Send a detailed single-override request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_override(
        &mut self,
        override_id: &EntityId,
    ) -> Result<GetOverridesResponse, GvmError> {
        self.execute(GetOverrideRequest::new(override_id.clone()))
            .await
    }

    /// Send a `create_override` request and return a typed [`CreateOverrideResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_override(
        &mut self,
        nvt_oid: &str,
        opts: OverrideOpts,
    ) -> Result<CreateOverrideResponse, GvmError> {
        self.execute(CreateOverrideRequest::new(nvt_oid, opts))
            .await
    }

    /// Clone an override through `create_override`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_override(
        &mut self,
        override_id: &EntityId,
    ) -> Result<CreateOverrideResponse, GvmError> {
        self.execute(CloneOverrideRequest::new(override_id.clone()))
            .await
    }

    /// Send a `modify_override` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_override(
        &mut self,
        override_id: &EntityId,
        opts: ModifyOverrideOpts,
    ) -> Result<ModifyOverrideResponse, GvmError> {
        self.execute(ModifyOverrideRequest::new(override_id.clone(), opts))
            .await
    }

    /// Send a `delete_override` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_override(
        &mut self,
        override_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteOverrideResponse, GvmError> {
        self.execute(DeleteOverrideRequest::new(override_id.clone(), ultimate))
            .await
    }

    // ── Schedules ─────────────────────────────────────────────────────────────

    /// Send a `get_schedules` request and return a typed [`GetSchedulesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_schedules(
        &mut self,
        opts: GetSchedulesOpts,
    ) -> Result<GetSchedulesResponse, GvmError> {
        self.execute(GetSchedulesRequest::new(opts)).await
    }

    /// Send a detailed single-schedule `get_schedules` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_schedule(
        &mut self,
        schedule_id: &EntityId,
    ) -> Result<GetSchedulesResponse, GvmError> {
        self.execute(GetScheduleRequest::new(schedule_id.clone()))
            .await
    }

    /// Send a `create_schedule` request and return a typed [`CreateScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_schedule(
        &mut self,
        name: &str,
        opts: ScheduleOpts,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(CreateScheduleRequest::new(name, opts)).await
    }

    /// Send a `create_schedule` request from typed recurrence input.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_typed_schedule(
        &mut self,
        name: &str,
        input: ScheduleInput,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(CreateTypedScheduleRequest::new(name, input))
            .await
    }

    /// Send a schedule-copy `create_schedule` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_schedule(
        &mut self,
        schedule_id: &EntityId,
    ) -> Result<CreateScheduleResponse, GvmError> {
        self.execute(CloneScheduleRequest::new(schedule_id.clone()))
            .await
    }

    /// Send a `modify_schedule` request using raw compatibility options and
    /// return a typed [`ModifyScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_schedule(
        &mut self,
        schedule_id: &EntityId,
        opts: ScheduleOpts,
    ) -> Result<ModifyScheduleResponse, GvmError> {
        self.execute(ModifyScheduleRequest::new(schedule_id.clone(), opts))
            .await
    }

    /// Send a `modify_schedule` request from typed recurrence input.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_typed_schedule(
        &mut self,
        schedule_id: &EntityId,
        input: ScheduleInput,
    ) -> Result<ModifyScheduleResponse, GvmError> {
        self.execute(ModifyTypedScheduleRequest::new(schedule_id.clone(), input))
            .await
    }

    /// Send a `delete_schedule` request and return a typed
    /// [`DeleteScheduleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_schedule(
        &mut self,
        schedule_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteScheduleResponse, GvmError> {
        self.execute(DeleteScheduleRequest::new(schedule_id.clone(), ultimate))
            .await
    }

    // ── Tags ──────────────────────────────────────────────────────────────────

    /// Send a `get_tags` request and return a typed [`GetTagsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tags(&mut self, opts: GetTagsOpts) -> Result<GetTagsResponse, GvmError> {
        self.execute(GetTagsRequest::new(opts)).await
    }

    /// Send a detailed single-tag request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tag(&mut self, tag_id: &EntityId) -> Result<GetTagsResponse, GvmError> {
        self.execute(GetTagRequest::new(tag_id.clone())).await
    }

    /// Send a `create_tag` request and return a typed [`CreateTagResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_tag(
        &mut self,
        name: &str,
        opts: TagOpts,
    ) -> Result<CreateTagResponse, GvmError> {
        self.execute(CreateTagRequest::new(name, opts)).await
    }

    /// Clone a tag through `create_tag`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_tag(&mut self, tag_id: &EntityId) -> Result<CreateTagResponse, GvmError> {
        self.execute(CloneTagRequest::new(tag_id.clone())).await
    }

    /// Send a `modify_tag` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_tag(
        &mut self,
        tag_id: &EntityId,
        opts: TagOpts,
    ) -> Result<ModifyTagResponse, GvmError> {
        self.execute(ModifyTagRequest::new(tag_id.clone(), opts))
            .await
    }

    /// Send a `delete_tag` request.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_tag(
        &mut self,
        tag_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteTagResponse, GvmError> {
        self.execute(DeleteTagRequest::new(tag_id.clone(), ultimate))
            .await
    }

    // ── Tickets ───────────────────────────────────────────────────────────────

    /// Send a `get_tickets` request and return a typed [`GetTicketsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tickets(
        &mut self,
        opts: GetTicketsOpts,
    ) -> Result<GetTicketsResponse, GvmError> {
        let response = self.send(get_tickets(opts)).await?;
        GetTicketsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `create_ticket` request and return a typed [`CreateTicketResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_ticket(
        &mut self,
        result_id: &EntityId,
        opts: CreateTicketOpts,
    ) -> Result<CreateTicketResponse, GvmError> {
        let response = self.send(create_ticket(result_id, opts)).await?;
        CreateTicketResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `modify_ticket` request and return a typed [`ModifyTicketResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_ticket(
        &mut self,
        ticket_id: &EntityId,
        opts: ModifyTicketOpts,
    ) -> Result<ModifyTicketResponse, GvmError> {
        let response = self.send(modify_ticket(ticket_id, opts)).await?;
        ModifyTicketResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    /// Send a `get_users` request and return a typed [`GetUsersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_users(&mut self, opts: GetUsersOpts) -> Result<GetUsersResponse, GvmError> {
        self.execute(GetUsersRequest::new(opts)).await
    }

    /// Send a single-user `get_users` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_user(&mut self, user_id: &EntityId) -> Result<GetUsersResponse, GvmError> {
        self.execute(GetUserRequest::new(user_id.clone())).await
    }

    /// Send a `create_user` request and return a typed [`CreateUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_user(
        &mut self,
        name: &str,
        opts: UserOpts,
    ) -> Result<CreateUserResponse, GvmError> {
        self.execute(CreateUserRequest::new(name, opts)).await
    }

    /// Send a `clone_user` request and return a typed [`CreateUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_user(&mut self, user_id: &EntityId) -> Result<CreateUserResponse, GvmError> {
        self.execute(CloneUserRequest::new(user_id.clone())).await
    }

    /// Send a `modify_user` request and return a typed [`ModifyUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_user(
        &mut self,
        user_id: &EntityId,
        opts: ModifyUserOpts,
    ) -> Result<ModifyUserResponse, GvmError> {
        self.execute(ModifyUserRequest::new(user_id.clone(), opts))
            .await
    }

    /// Send a `delete_user` request and return a typed [`DeleteUserResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_user(
        &mut self,
        user_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteUserResponse, GvmError> {
        self.execute(DeleteUserRequest::new(user_id.clone(), ultimate))
            .await
    }

    // ── Groups ────────────────────────────────────────────────────────────────

    /// Send a `get_groups` request and return a typed [`GetGroupsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_groups(&mut self, opts: GetGroupsOpts) -> Result<GetGroupsResponse, GvmError> {
        self.execute(GetGroupsRequest::new(opts)).await
    }

    /// Send a single-group `get_groups` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_group(&mut self, group_id: &EntityId) -> Result<GetGroupsResponse, GvmError> {
        self.execute(GetGroupRequest::new(group_id.clone())).await
    }

    /// Send a `create_group` request and return a typed [`CreateGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_group(
        &mut self,
        name: &str,
        opts: GroupOpts,
    ) -> Result<CreateGroupResponse, GvmError> {
        self.execute(CreateGroupRequest::new(name, opts)).await
    }

    /// Send a `clone_group` request and return a typed [`CreateGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_group(
        &mut self,
        group_id: &EntityId,
    ) -> Result<CreateGroupResponse, GvmError> {
        self.execute(CloneGroupRequest::new(group_id.clone())).await
    }

    /// Send a `modify_group` request and return a typed [`ModifyGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_group(
        &mut self,
        group_id: &EntityId,
        opts: GroupOpts,
    ) -> Result<ModifyGroupResponse, GvmError> {
        self.execute(ModifyGroupRequest::new(group_id.clone(), opts))
            .await
    }

    /// Send a `delete_group` request and return a typed [`DeleteGroupResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_group(
        &mut self,
        group_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteGroupResponse, GvmError> {
        self.execute(DeleteGroupRequest::new(group_id.clone(), ultimate))
            .await
    }

    // ── Roles ─────────────────────────────────────────────────────────────────

    /// Send a `get_roles` request and return a typed [`GetRolesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_roles(&mut self, opts: GetRolesOpts) -> Result<GetRolesResponse, GvmError> {
        self.execute(GetRolesRequest::new(opts)).await
    }

    /// Send a single-role `get_roles` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_role(&mut self, role_id: &EntityId) -> Result<GetRolesResponse, GvmError> {
        self.execute(GetRoleRequest::new(role_id.clone())).await
    }

    /// Send a `create_role` request and return a typed [`CreateRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_role(
        &mut self,
        name: &str,
        opts: RoleOpts,
    ) -> Result<CreateRoleResponse, GvmError> {
        self.execute(CreateRoleRequest::new(name, opts)).await
    }

    /// Send a `clone_role` request and return a typed [`CreateRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_role(&mut self, role_id: &EntityId) -> Result<CreateRoleResponse, GvmError> {
        self.execute(CloneRoleRequest::new(role_id.clone())).await
    }

    /// Send a `modify_role` request and return a typed [`ModifyRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_role(
        &mut self,
        role_id: &EntityId,
        opts: RoleOpts,
    ) -> Result<ModifyRoleResponse, GvmError> {
        self.execute(ModifyRoleRequest::new(role_id.clone(), opts))
            .await
    }

    /// Send a `delete_role` request and return a typed [`DeleteRoleResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_role(
        &mut self,
        role_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteRoleResponse, GvmError> {
        self.execute(DeleteRoleRequest::new(role_id.clone(), ultimate))
            .await
    }

    // ── Permissions ───────────────────────────────────────────────────────────

    /// Send a `get_permissions` request and return a typed [`GetPermissionsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_permissions(
        &mut self,
        opts: GetPermissionsOpts,
    ) -> Result<GetPermissionsResponse, GvmError> {
        self.execute(GetPermissionsRequest::new(opts)).await
    }

    /// Send a single-permission `get_permissions` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_permission(
        &mut self,
        permission_id: &EntityId,
    ) -> Result<GetPermissionsResponse, GvmError> {
        self.execute(GetPermissionRequest::new(permission_id.clone()))
            .await
    }

    /// Send a `create_permission` request and return a typed [`CreatePermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_permission(
        &mut self,
        opts: PermissionOpts,
    ) -> Result<CreatePermissionResponse, GvmError> {
        self.execute(CreatePermissionRequest::new(opts)).await
    }

    /// Send a `clone_permission` request and return a typed [`CreatePermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_permission(
        &mut self,
        permission_id: &EntityId,
    ) -> Result<CreatePermissionResponse, GvmError> {
        self.execute(ClonePermissionRequest::new(permission_id.clone()))
            .await
    }

    /// Send a `modify_permission` request and return a typed [`ModifyPermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_permission(
        &mut self,
        permission_id: &EntityId,
        opts: PermissionOpts,
    ) -> Result<ModifyPermissionResponse, GvmError> {
        self.execute(ModifyPermissionRequest::new(permission_id.clone(), opts))
            .await
    }

    /// Send a `delete_permission` request and return a typed [`DeletePermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_permission(
        &mut self,
        permission_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeletePermissionResponse, GvmError> {
        self.execute(DeletePermissionRequest::new(
            permission_id.clone(),
            ultimate,
        ))
        .await
    }

    // ── Hosts ─────────────────────────────────────────────────────────────────

    /// Send a `get_hosts` request and return a typed [`GetHostsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_hosts(&mut self, opts: GetHostsOpts) -> Result<GetHostsResponse, GvmError> {
        self.execute(GetHostsRequest::new(opts)).await
    }

    /// Send a single-host `get_assets` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_host(&mut self, host_id: &EntityId) -> Result<GetHostsResponse, GvmError> {
        self.execute(GetHostRequest::new(host_id.clone())).await
    }

    /// Send a `create_host` request and return a typed [`CreateHostResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_host(&mut self, opts: HostOpts) -> Result<CreateHostResponse, GvmError> {
        self.execute(CreateHostRequest::new(opts)).await
    }

    /// Send a `modify_asset` request for a host and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_host(
        &mut self,
        host_id: &EntityId,
        opts: HostOpts,
    ) -> Result<ModifyHostResponse, GvmError> {
        self.execute(ModifyHostRequest::new(host_id.clone(), opts))
            .await
    }

    /// Send a `delete_asset` request for a host and return a typed response.
    ///
    /// The `ultimate` value is retained for compatibility and remains ignored
    /// by the host builder because gvmd applies asset-specific deletion.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_host(
        &mut self,
        host_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteHostResponse, GvmError> {
        self.execute(DeleteHostRequest::new(host_id.clone(), ultimate))
            .await
    }

    // ── Integration Configurations ────────────────────────────────────────────

    /// Send a single `get_integration_config` request and return a typed response.
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_integration_config`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_integration_config_parsed(
        &mut self,
        integration_config_id: &EntityId,
        details: Option<bool>,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.execute(GetIntegrationConfigRequest::new(
            integration_config_id.clone(),
            details,
        ))
        .await
    }

    /// Send a `get_integration_configs` request and return a typed response.
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::get_integration_configs`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_integration_configs_parsed(
        &mut self,
        opts: GetIntegrationConfigsOpts,
    ) -> Result<GetIntegrationConfigsResponse, GvmError> {
        self.execute(GetIntegrationConfigsRequest::new(opts)).await
    }

    /// Send a `modify_integration_config` request and return a typed response.
    ///
    /// The `_parsed` suffix distinguishes this helper from the raw
    /// [`GmpClient::modify_integration_config`] method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_integration_config_parsed(
        &mut self,
        integration_config_id: &EntityId,
        opts: ModifyIntegrationConfigOpts,
    ) -> Result<ModifyIntegrationConfigResponse, GvmError> {
        self.execute(ModifyIntegrationConfigRequest::new(
            integration_config_id.clone(),
            opts,
        ))
        .await
    }

    // ── Assets ──────────────────────────────────────────────────────────────────

    /// Send a `get_assets` request and return a typed [`GetAssetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_assets(&mut self, opts: GetAssetsOpts) -> Result<GetAssetsResponse, GvmError> {
        self.execute(GetAssetsRequest::new(opts)).await
    }

    /// Send a single-asset `get_assets` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_asset(
        &mut self,
        asset_id: &EntityId,
        asset_type: AssetType,
    ) -> Result<GetAssetsResponse, GvmError> {
        self.execute(GetAssetRequest::new(asset_id.clone(), asset_type))
            .await
    }

    /// Send a `create_asset` request and return a typed [`CreateAssetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_asset(
        &mut self,
        opts: CreateAssetOpts,
    ) -> Result<CreateAssetResponse, GvmError> {
        self.execute(CreateAssetRequest::new(opts)).await
    }

    /// Send a `modify_asset` request and return a typed [`ModifyAssetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_asset(
        &mut self,
        asset_id: &EntityId,
        opts: ModifyAssetOpts,
    ) -> Result<ModifyAssetResponse, GvmError> {
        self.execute(ModifyAssetRequest::new(asset_id.clone(), opts))
            .await
    }

    /// Send a `delete_asset` request and return a typed [`DeleteAssetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_asset(
        &mut self,
        asset_id: &EntityId,
        opts: DeleteAssetOpts,
    ) -> Result<DeleteAssetResponse, GvmError> {
        self.execute(DeleteAssetRequest::new(asset_id.clone(), opts))
            .await
    }

    /// Send a `get_assets type="os"` request and return typed operating-system assets.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_operating_system_assets(
        &mut self,
        opts: GetOperatingSystemsOpts,
    ) -> Result<GetOperatingSystemAssetsResponse, GvmError> {
        self.execute(GetOperatingSystemAssetsRequest::new(opts))
            .await
    }

    /// Send a single operating-system asset request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_operating_system_asset(
        &mut self,
        operating_system_id: &EntityId,
        details: Option<bool>,
    ) -> Result<GetOperatingSystemAssetsResponse, GvmError> {
        self.execute(GetOperatingSystemAssetRequest::new(
            operating_system_id.clone(),
            details,
        ))
        .await
    }

    /// Send a `modify_asset` request for an operating-system asset.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_operating_system_asset(
        &mut self,
        operating_system_id: &EntityId,
        comment: Option<String>,
    ) -> Result<ModifyAssetResponse, GvmError> {
        self.execute(ModifyOperatingSystemAssetRequest::new(
            operating_system_id.clone(),
            comment,
        ))
        .await
    }

    /// Send a `delete_asset` request for an operating-system asset.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_operating_system_asset(
        &mut self,
        operating_system_id: &EntityId,
    ) -> Result<DeleteAssetResponse, GvmError> {
        self.execute(DeleteOperatingSystemAssetRequest::new(
            operating_system_id.clone(),
        ))
        .await
    }

    // ── Generic Configs ──────────────────────────────────────────────────────

    /// Send a generic `get_configs` request and return typed generic configs.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_configs(
        &mut self,
        opts: GetConfigsOpts,
    ) -> Result<GetConfigsResponse, GvmError> {
        self.execute(GetConfigsRequest::new(opts)).await
    }

    /// Send a generic single-config `get_configs` request and return typed generic configs.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_config(
        &mut self,
        config_id: &EntityId,
        opts: GetConfigOpts,
    ) -> Result<GetConfigsResponse, GvmError> {
        self.execute(GetConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a generic `create_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_config(
        &mut self,
        opts: CreateConfigOpts,
    ) -> Result<CreateConfigResponse, GvmError> {
        self.execute(CreateConfigRequest::new(opts)).await
    }

    /// Send a generic config clone request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_config(
        &mut self,
        config_id: &EntityId,
        opts: CloneConfigOpts,
    ) -> Result<CreateConfigResponse, GvmError> {
        self.execute(CloneConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a generic `modify_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_config(
        &mut self,
        config_id: &EntityId,
        opts: ModifyConfigOpts,
    ) -> Result<ModifyConfigResponse, GvmError> {
        self.execute(ModifyConfigRequest::new(config_id.clone(), opts))
            .await
    }

    /// Send a generic `delete_config` request and return a typed response.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_config(
        &mut self,
        config_id: &EntityId,
        opts: DeleteConfigOpts,
    ) -> Result<DeleteConfigResponse, GvmError> {
        self.execute(DeleteConfigRequest::new(config_id.clone(), opts))
            .await
    }

    // ── TLS Certificates ──────────────────────────────────────────────────────

    /// Send a `get_tls_certificates` request and return a typed
    /// [`GetTlsCertificatesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tls_certificates(
        &mut self,
        opts: GetTlsCertificatesOpts,
    ) -> Result<GetTlsCertificatesResponse, GvmError> {
        self.execute(GetTlsCertificatesRequest::new(opts)).await
    }

    /// Send a detailed `get_tls_certificates` request for one certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
    ) -> Result<GetTlsCertificatesResponse, GvmError> {
        self.execute(GetTlsCertificateRequest::new(tls_certificate_id.clone()))
            .await
    }

    /// Send a `create_tls_certificate` request and return a typed
    /// [`CreateTlsCertificateResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_tls_certificate(
        &mut self,
        name: &str,
        opts: TlsCertificateOpts,
    ) -> Result<CreateTlsCertificateResponse, GvmError> {
        self.execute(CreateTlsCertificateRequest::new(name, opts))
            .await
    }

    /// Clone a TLS certificate through `create_tls_certificate`.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
    ) -> Result<CreateTlsCertificateResponse, GvmError> {
        self.execute(CloneTlsCertificateRequest::new(tls_certificate_id.clone()))
            .await
    }

    /// Modify a TLS certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
        opts: TlsCertificateOpts,
    ) -> Result<ModifyTlsCertificateResponse, GvmError> {
        self.execute(ModifyTlsCertificateRequest::new(
            tls_certificate_id.clone(),
            opts,
        ))
        .await
    }

    /// Delete a TLS certificate.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_tls_certificate(
        &mut self,
        tls_certificate_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteTlsCertificateResponse, GvmError> {
        self.execute(DeleteTlsCertificateRequest::new(
            tls_certificate_id.clone(),
            ultimate,
        ))
        .await
    }

    // ── Report Formats ────────────────────────────────────────────────────────

    /// Send a `get_report_formats` request and return a typed [`GetReportFormatsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_formats(
        &mut self,
        opts: GetReportFormatsOpts,
    ) -> Result<GetReportFormatsResponse, GvmError> {
        self.execute(GetReportFormatsRequest::new(opts)).await
    }

    /// Send a detailed `get_report_formats` request for one report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_format(
        &mut self,
        report_format_id: &EntityId,
    ) -> Result<GetReportFormatsResponse, GvmError> {
        self.execute(GetReportFormatRequest::new(report_format_id.clone()))
            .await
    }

    /// Send a `create_report_format` request and return a typed
    /// [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_report_format(
        &mut self,
        name: &str,
        opts: ReportFormatOpts,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(CreateReportFormatRequest::new(name, opts))
            .await
    }

    /// Send a `create_report_format` request that clones an existing report
    /// format and return a typed [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_report_format(
        &mut self,
        report_format_id: &EntityId,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(CloneReportFormatRequest::new(report_format_id.clone()))
            .await
    }

    /// Send a `create_report_format` request that imports report-format XML and
    /// return a typed [`CreateReportFormatResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn import_report_format(
        &mut self,
        report_format_xml: &str,
    ) -> Result<CreateReportFormatResponse, GvmError> {
        self.execute(ImportReportFormatRequest::new(report_format_xml)?)
            .await
    }

    /// Modify a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_report_format(
        &mut self,
        report_format_id: &EntityId,
        opts: ReportFormatOpts,
    ) -> Result<ModifyReportFormatResponse, GvmError> {
        self.execute(ModifyReportFormatRequest::new(
            report_format_id.clone(),
            opts,
        ))
        .await
    }

    /// Delete a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_format(
        &mut self,
        report_format_id: &EntityId,
        ultimate: bool,
    ) -> Result<DeleteReportFormatResponse, GvmError> {
        self.execute(DeleteReportFormatRequest::new(
            report_format_id.clone(),
            ultimate,
        ))
        .await
    }

    /// Verify a report format.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_report_format(
        &mut self,
        report_format_id: &EntityId,
    ) -> Result<VerifyReportFormatResponse, GvmError> {
        self.execute(VerifyReportFormatRequest::new(report_format_id.clone()))
            .await
    }

    // ── Reports ───────────────────────────────────────────────────────────────

    /// Send a `create_report` request that imports report XML and return a typed
    /// [`CreateReportResponse`].
    ///
    /// # Errors
    /// Returns an error if request construction fails, the request fails, or
    /// response parsing fails.
    pub async fn import_report(
        &mut self,
        report_xml: &str,
        task_id: &EntityId,
        opts: ImportReportOpts,
    ) -> Result<CreateReportResponse, GvmError> {
        self.execute(ImportReportRequest::new(report_xml, task_id, opts)?)
            .await
    }

    // ── Report Configs ────────────────────────────────────────────────────────

    /// Send a `get_report_configs` request with filter options and return a typed
    /// [`GetReportConfigsResponse`].
    ///
    /// Note: This method uses the `_parsed` suffix to avoid conflicting with the
    /// [`crate::Gmp226Commands::get_report_configs`] trait method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_configs_parsed(
        &mut self,
        opts: GetReportConfigsOpts,
    ) -> Result<GetReportConfigsResponse, GvmError> {
        self.execute(GetReportConfigsWithOptsRequest::new(opts))
            .await
    }

    /// Send a detailed `get_report_configs` request for one report configuration.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_report_config(
        &mut self,
        id: &str,
    ) -> Result<GetReportConfigsResponse, GvmError> {
        self.execute(GetReportConfigRequest::new(id)).await
    }

    /// Create a report configuration with default options.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_report_config(
        &mut self,
        name: &str,
        report_format_id: &str,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(CreateReportConfigRequest::new(name, report_format_id))
            .await
    }

    /// Create a report configuration with optional fields.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_report_config_with_opts(
        &mut self,
        name: &str,
        report_format_id: &str,
        opts: CreateReportConfigOpts,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(CreateReportConfigWithOptsRequest::new(
            name,
            report_format_id,
            opts,
        ))
        .await
    }

    /// Send a `clone_report_config` request and return a typed
    /// [`CreateReportConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_report_config(
        &mut self,
        id: &str,
    ) -> Result<CreateReportConfigResponse, GvmError> {
        self.execute(CloneReportConfigRequest::new(id)).await
    }

    /// Modify a report configuration.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_report_config(
        &mut self,
        id: &str,
        opts: ModifyReportConfigOpts,
    ) -> Result<ModifyReportConfigResponse, GvmError> {
        self.execute(ModifyReportConfigRequest::new(id, opts)).await
    }

    /// Delete a report configuration with default options.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_config(
        &mut self,
        id: &str,
    ) -> Result<DeleteReportConfigResponse, GvmError> {
        self.execute(DeleteReportConfigRequest::new(id)).await
    }

    /// Delete a report configuration with optional fields.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn delete_report_config_with_opts(
        &mut self,
        id: &str,
        opts: DeleteReportConfigOpts,
    ) -> Result<DeleteReportConfigResponse, GvmError> {
        self.execute(DeleteReportConfigWithOptsRequest::new(id, opts))
            .await
    }

    // ── System ────────────────────────────────────────────────────────────────

    /// Send a current gvmd `get_aggregates` request and return its typed result.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_aggregates(
        &mut self,
        resource_type: &str,
        opts: GetAggregatesRequestOpts,
    ) -> Result<GetAggregatesResponse, GvmError> {
        let response = self
            .send(get_aggregates_request(resource_type, opts))
            .await?;
        GetAggregatesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_features` request and return a typed
    /// [`GetFeaturesResponse`].
    ///
    /// The `_parsed` suffix avoids conflicting with the raw
    /// [`crate::Gmp226Commands::get_features`] versioned-client method.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_features_parsed(&mut self) -> Result<GetFeaturesResponse, GvmError> {
        let response = self.send(get_features()).await?;
        GetFeaturesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_settings` request and return a typed [`GetSettingsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_settings(&mut self) -> Result<GetSettingsResponse, GvmError> {
        let response = self.send(get_settings(FilteredGetOpts::default())).await?;
        GetSettingsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_system_reports` request and return typed report metadata and payloads.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_system_reports(
        &mut self,
        opts: GetSystemReportsOpts,
    ) -> Result<GetSystemReportsResponse, GvmError> {
        let response = self.send(get_system_reports(opts)).await?;
        GetSystemReportsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `help` request and return a typed [`HelpResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_help(&mut self) -> Result<HelpResponse, GvmError> {
        let response = self.send(help(None)).await?;
        HelpResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `help` request for an explicit response mode.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_help_with_mode(&mut self, mode: HelpMode) -> Result<HelpResponse, GvmError> {
        let response = self.send(help_with_mode(mode)).await?;
        HelpResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `describe_auth` request and return a typed [`DescribeAuthResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn describe_auth(&mut self) -> Result<DescribeAuthResponse, GvmError> {
        let response = self.send(describe_auth()).await?;
        DescribeAuthResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Modify a named authentication group and return a typed
    /// [`ModifyAuthResponse`].
    ///
    /// `auth_conf_settings` must contain at least one key/value pair.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_auth(
        &mut self,
        group_name: &str,
        auth_conf_settings: &[(String, String)],
    ) -> Result<ModifyAuthResponse, GvmError> {
        let response = self
            .send(modify_auth(group_name, auth_conf_settings))
            .await?;
        ModifyAuthResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Upload a base64-encoded license file and return a typed
    /// [`ModifyLicenseResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn modify_license(
        &mut self,
        file: &str,
        opts: ModifyLicenseOpts,
    ) -> Result<ModifyLicenseResponse, GvmError> {
        let response = self.send(modify_license_with_opts(file, opts)).await?;
        ModifyLicenseResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Run a gvmd wizard and return its typed response envelope.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn run_wizard(
        &mut self,
        name: &str,
        params: &[(String, String)],
        opts: RunWizardOpts,
    ) -> Result<RunWizardResponse, GvmError> {
        let response = self.send(run_wizard_with_opts(name, params, opts)).await?;
        RunWizardResponse::from_response(&response).map_err(GvmError::Parse)
    }
}

#[cfg(test)]
mod tests {
    use gvm_gmp::responses::{common::ParseError, GetVersionResponse};

    use crate::GvmError;

    #[test]
    fn parse_error_converts_to_gvm_error() {
        let parse_err = ParseError::MissingElement("test".to_string());
        let gvm_err: GvmError = parse_err.into();
        assert!(matches!(gvm_err, GvmError::Parse(_)));
    }

    #[test]
    fn parse_error_display_forwarded() {
        let gvm_err = GvmError::Parse(ParseError::MissingElement("version".to_string()));
        assert!(gvm_err.to_string().contains("version"));
    }

    #[test]
    fn get_version_response_from_response_compiles() {
        use gvm_protocol::Response;
        let response = Response::from(
            r#"<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>"#,
        );
        let result = GetVersionResponse::from_response(&response);
        assert!(result.is_ok());
    }
}
