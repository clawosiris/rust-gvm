// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed convenience methods for [`GmpClient`].
//!
//! Each method combines a GMP command builder with the corresponding typed
//! response parser, eliminating the need for callers to import response types
//! and call `from_response()` manually.
//!
//! All methods use [`GmpClient::send`] internally so that
//! [`gvm_gmp::responses::ParseError`] owns all response validation (including
//! non-2xx status detection), which is then converted to [`GvmError::Parse`].

use gvm_connection::GvmConnection;
use gvm_gmp::commands::alerts::{create_alert, get_alerts, AlertOpts, GetAlertsOpts};
use gvm_gmp::commands::assets::{
    create_asset, delete_asset, get_assets, modify_asset, CreateAssetOpts, DeleteAssetOpts,
    GetAssetsOpts, ModifyAssetOpts,
};
use gvm_gmp::commands::authentication::authenticate;
use gvm_gmp::commands::credentials::{
    create_credential, create_credential_store_credential, get_credential_store,
    get_credential_stores, get_credential_stores_with_opts, get_credentials,
    modify_credential_store_credential, verify_credential_store, CredentialOpts,
    CredentialStoreCredentialOpts, GetCredentialStoresOpts, GetCredentialsOpts,
    ModifyCredentialStoreCredentialOpts,
};
use gvm_gmp::commands::feed::get_feeds;
use gvm_gmp::commands::filters::{create_filter, get_filters, FilterOpts, GetFiltersOpts};
use gvm_gmp::commands::groups::{create_group, get_groups, GetGroupsOpts, GroupOpts};
use gvm_gmp::commands::help::{help, help_with_mode, HelpMode};
use gvm_gmp::commands::hosts::{create_host, get_hosts, GetHostsOpts, HostOpts};
use gvm_gmp::commands::notes::{create_note, get_notes, GetNotesOpts, NoteOpts};
use gvm_gmp::commands::nvts::{
    get_nvt_families, get_nvts, get_scan_config_nvt, get_scan_config_nvts, GetNvtsOpts,
};
use gvm_gmp::commands::oci_image_targets::{
    clone_oci_image_target, create_oci_image_target, delete_oci_image_target, get_oci_image_target,
    get_oci_image_targets, modify_oci_image_target, CreateOciImageTargetOpts,
    GetOciImageTargetsOpts, ModifyOciImageTargetOpts,
};
use gvm_gmp::commands::overrides::{
    create_override, get_overrides, GetOverridesOpts, OverrideOpts,
};
use gvm_gmp::commands::permissions::{
    create_permission, get_permissions, GetPermissionsOpts, PermissionOpts,
};
use gvm_gmp::commands::port_lists::{
    create_port_list, get_port_lists, GetPortListsOpts, PortListOpts,
};
use gvm_gmp::commands::report_configs::{
    clone_report_config, get_report_configs_opts, GetReportConfigsOpts,
};
use gvm_gmp::commands::report_formats::{
    clone_report_format, create_report_format, get_report_formats, import_report_format,
    GetReportFormatsOpts, ReportFormatOpts,
};
use gvm_gmp::commands::reports::{
    get_report_applications, get_report_closed_cves, get_report_cves, get_report_errors,
    get_report_export, get_report_export_with_opts, get_report_hosts, get_report_operating_systems,
    get_report_ports, get_report_tls_certificates, get_report_vulnerabilities, get_report_vulns,
    get_reports, import_report, GetReportDetailsOpts, GetReportExportOpts, GetReportsOpts,
    ImportReportOpts,
};
use gvm_gmp::commands::results::{get_results, GetResultsOpts};
use gvm_gmp::commands::roles::{create_role, get_roles, GetRolesOpts, RoleOpts};
use gvm_gmp::commands::scan_configs::{
    clone_scan_config, create_scan_config, delete_scan_config, get_policies, get_policy,
    get_scan_config, get_scan_configs, import_policy, modify_policy_set_comment,
    modify_policy_set_name, modify_scan_config, modify_scan_config_set_comment,
    modify_scan_config_set_name, sync_config, ConfigOpts, GetPolicyOpts, GetScanConfigsOpts,
};
use gvm_gmp::commands::scanners::{
    clone_scanner, create_scanner, delete_scanner, get_scanner, get_scanners, modify_scanner,
    verify_scanner, GetScannersOpts, ScannerOpts,
};
use gvm_gmp::commands::schedules::{
    create_schedule, get_schedules, GetSchedulesOpts, ScheduleOpts,
};
use gvm_gmp::commands::secinfo::{
    get_cert_bund_advisories, get_cert_bund_advisory, get_cpe, get_cpes, get_cve, get_cves,
    get_dfn_cert_advisories, get_dfn_cert_advisory, GetSecInfoOpts,
};
use gvm_gmp::commands::system::{
    describe_auth, get_settings, get_timezones, get_vulnerability as get_vulnerability_cmd,
    get_vulns, FilteredGetOpts,
};
use gvm_gmp::commands::tags::{create_tag, get_tags, GetTagsOpts, TagOpts};
use gvm_gmp::commands::targets::{create_target, get_targets, CreateTargetOpts, GetTargetsOpts};
use gvm_gmp::commands::tasks::{
    create_import_task, create_task, get_tasks, resume_task, start_task, CreateTaskOpts,
    GetTasksOpts,
};
use gvm_gmp::commands::tickets::{create_ticket, get_tickets, GetTicketsOpts, TicketOpts};
use gvm_gmp::commands::tls_certificates::{
    create_tls_certificate, get_tls_certificates, GetTlsCertificatesOpts, TlsCertificateOpts,
};
use gvm_gmp::commands::trashcan::{empty_trashcan, restore_from_trashcan};
use gvm_gmp::commands::users::{create_user, get_users, GetUsersOpts, UserOpts};
use gvm_gmp::commands::version::get_version;
use gvm_gmp::commands::web_application_targets::{
    clone_web_application_target, create_web_application_target, delete_web_application_target,
    get_web_application_target, get_web_application_targets, modify_web_application_target,
    CreateWebApplicationTargetOpts, GetWebApplicationTargetsOpts, ModifyWebApplicationTargetOpts,
};
use gvm_gmp::responses::{
    AuthenticateResponse, CreateAlertResponse, CreateAssetResponse, CreateCredentialResponse,
    CreateFilterResponse, CreateGroupResponse, CreateHostResponse, CreateNoteResponse,
    CreateOciImageTargetResponse, CreateOverrideResponse, CreatePermissionResponse,
    CreatePortListResponse, CreateReportConfigResponse, CreateReportFormatResponse,
    CreateReportResponse, CreateRoleResponse, CreateScanConfigResponse, CreateScannerResponse,
    CreateScheduleResponse, CreateTagResponse, CreateTargetResponse, CreateTaskResponse,
    CreateTicketResponse, CreateTlsCertificateResponse, CreateUserResponse,
    CreateWebApplicationTargetResponse, DeleteAssetResponse, DeleteOciImageTargetResponse,
    DeleteScanConfigResponse, DeleteScannerResponse, DeleteWebApplicationTargetResponse,
    DescribeAuthResponse, EmptyTrashcanResponse, GetAlertsResponse, GetAssetsResponse,
    GetCertBundAdvisoriesResponse, GetCpesResponse, GetCredentialStoresResponse,
    GetCredentialsResponse, GetCvesResponse, GetDfnCertAdvisoriesResponse, GetFeedsResponse,
    GetFiltersResponse, GetGroupsResponse, GetHostsResponse, GetNotesResponse,
    GetNvtFamiliesResponse, GetNvtsResponse, GetOciImageTargetsResponse, GetOverridesResponse,
    GetPermissionsResponse, GetPortListsResponse, GetReportApplicationsResponse,
    GetReportClosedCvesResponse, GetReportConfigsResponse, GetReportCvesResponse,
    GetReportErrorsResponse, GetReportFormatsResponse, GetReportHostsResponse,
    GetReportOperatingSystemsResponse, GetReportPortsResponse, GetReportTlsCertificatesResponse,
    GetReportVulnsResponse, GetReportsResponse, GetResultsResponse, GetRolesResponse,
    GetScanConfigsResponse, GetScannersResponse, GetSchedulesResponse, GetSettingsResponse,
    GetTagsResponse, GetTargetsResponse, GetTasksResponse, GetTicketsResponse,
    GetTimezonesResponse, GetTlsCertificatesResponse, GetUsersResponse, GetVersionResponse,
    GetVulnerabilitiesResponse, GetWebApplicationTargetsResponse, HelpResponse,
    ModifyAssetResponse, ModifyCredentialResponse, ModifyOciImageTargetResponse,
    ModifyScanConfigResponse, ModifyScannerResponse, ModifyWebApplicationTargetResponse,
    ReportExport, RestoreResponse, ResumeTaskResponse, StartTaskResponse, SyncConfigResponse,
    VerifyCredentialStoreResponse, VerifyScannerResponse,
};
use gvm_gmp::types::EntityId;
use gvm_gmp::CredentialStoreCredentialType;

use crate::{GmpClient, GvmError};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Version & Auth ────────────────────────────────────────────────────────

    /// Send a `get_version` request and return a typed [`GetVersionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_version(&mut self) -> Result<GetVersionResponse, GvmError> {
        let response = self.send(get_version()).await?;
        GetVersionResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(authenticate(username, password)).await?;
        AuthenticateResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_targets(opts)).await?;
        GetTargetsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_target(name, opts)).await?;
        CreateTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(create_oci_image_target(name, image_references, opts))
            .await?;
        CreateOciImageTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(clone_oci_image_target(oci_image_target_id))
            .await?;
        CreateOciImageTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_oci_image_target(oci_image_target_id, tasks))
            .await?;
        GetOciImageTargetsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_oci_image_targets(opts)).await?;
        GetOciImageTargetsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(modify_oci_image_target(oci_image_target_id, opts))
            .await?;
        ModifyOciImageTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(delete_oci_image_target(oci_image_target_id, ultimate))
            .await?;
        DeleteOciImageTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(create_web_application_target(name, urls, opts))
            .await?;
        CreateWebApplicationTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(clone_web_application_target(web_application_target_id))
            .await?;
        CreateWebApplicationTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_web_application_target(web_application_target_id, tasks))
            .await?;
        GetWebApplicationTargetsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_web_application_targets(opts)).await?;
        GetWebApplicationTargetsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(modify_web_application_target(
                web_application_target_id,
                opts,
            ))
            .await?;
        ModifyWebApplicationTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(delete_web_application_target(
                web_application_target_id,
                ultimate,
            ))
            .await?;
        DeleteWebApplicationTargetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_scan_configs(opts)).await?;
        GetScanConfigsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_scan_config(name, base_id, opts)).await?;
        CreateScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let request = gvm_gmp::commands::scan_configs::import_scan_config(scan_config_xml)?;
        let response = self.send(request).await?;
        CreateScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_scan_config` request and return a typed [`GetScanConfigsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config(
        &mut self,
        config_id: &EntityId,
    ) -> Result<GetScanConfigsResponse, GvmError> {
        let response = self.send(get_scan_config(config_id)).await?;
        GetScanConfigsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_policies(opts)).await?;
        GetScanConfigsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_policy(policy_id, opts)).await?;
        GetScanConfigsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let request = import_policy(policy_xml)?;
        let response = self.send(request).await?;
        CreateScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(modify_scan_config(config_id, opts)).await?;
        ModifyScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(modify_scan_config_set_name(config_id, name))
            .await?;
        ModifyScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(modify_scan_config_set_comment(config_id, comment))
            .await?;
        ModifyScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(modify_policy_set_name(policy_id, name)).await?;
        ModifyScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(modify_policy_set_comment(policy_id, comment))
            .await?;
        ModifyScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(delete_scan_config(config_id, ultimate)).await?;
        DeleteScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `clone_scan_config` request and return a typed [`CreateScanConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scan_config(
        &mut self,
        config_id: &EntityId,
    ) -> Result<CreateScanConfigResponse, GvmError> {
        let response = self.send(clone_scan_config(config_id)).await?;
        CreateScanConfigResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `sync_config` request and return a typed [`SyncConfigResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn sync_scan_config(
        &mut self,
        config_id: &EntityId,
    ) -> Result<SyncConfigResponse, GvmError> {
        let response = self.send(sync_config(config_id)).await?;
        SyncConfigResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_scanners(opts)).await?;
        GetScannersResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_scanner(name, opts)).await?;
        CreateScannerResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_scanner` request and return a typed [`GetScannersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<GetScannersResponse, GvmError> {
        let response = self.send(get_scanner(scanner_id)).await?;
        GetScannersResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(modify_scanner(scanner_id, opts)).await?;
        ModifyScannerResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(delete_scanner(scanner_id, ultimate)).await?;
        DeleteScannerResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `verify_scanner` request and return a typed [`VerifyScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn verify_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<VerifyScannerResponse, GvmError> {
        let response = self.send(verify_scanner(scanner_id)).await?;
        VerifyScannerResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `clone_scanner` request and return a typed [`CreateScannerResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn clone_scanner(
        &mut self,
        scanner_id: &EntityId,
    ) -> Result<CreateScannerResponse, GvmError> {
        let response = self.send(clone_scanner(scanner_id)).await?;
        CreateScannerResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_port_lists(opts)).await?;
        GetPortListsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_port_list(name, opts)).await?;
        CreatePortListResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Tasks ─────────────────────────────────────────────────────────────────

    /// Send a `get_tasks` request and return a typed [`GetTasksResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tasks(&mut self, opts: GetTasksOpts) -> Result<GetTasksResponse, GvmError> {
        let response = self.send(get_tasks(opts)).await?;
        GetTasksResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(create_task(name, config_id, target_id, scanner_id, opts))
            .await?;
        CreateTaskResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_import_task(name, comment)).await?;
        CreateTaskResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `start_task` request and return a typed [`StartTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn start_task(&mut self, task_id: &EntityId) -> Result<StartTaskResponse, GvmError> {
        let response = self.send(start_task(task_id)).await?;
        StartTaskResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `resume_task` request and return a typed [`ResumeTaskResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn resume_task(
        &mut self,
        task_id: &EntityId,
    ) -> Result<ResumeTaskResponse, GvmError> {
        let response = self.send(resume_task(task_id)).await?;
        ResumeTaskResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send an `empty_trashcan` request and return a typed [`EmptyTrashcanResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn empty_trashcan(&mut self) -> Result<EmptyTrashcanResponse, GvmError> {
        let response = self.send(empty_trashcan()).await?;
        EmptyTrashcanResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `restore` request and return a typed [`RestoreResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn restore_from_trashcan(
        &mut self,
        resource_id: &EntityId,
    ) -> Result<RestoreResponse, GvmError> {
        let response = self.send(restore_from_trashcan(resource_id)).await?;
        RestoreResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Reports ───────────────────────────────────────────────────────────────

    /// Send a `get_reports` request and return a typed [`GetReportsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_reports(
        &mut self,
        opts: GetReportsOpts,
    ) -> Result<GetReportsResponse, GvmError> {
        let response = self.send(get_reports(opts)).await?;
        GetReportsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_vulns(report_id, opts)).await?;
        GetReportVulnsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_report_vulnerabilities(report_id, opts))
            .await?;
        GetReportVulnsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_report_tls_certificates(report_id, opts))
            .await?;
        GetReportTlsCertificatesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_hosts(report_id, opts)).await?;
        GetReportHostsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_ports(report_id, opts)).await?;
        GetReportPortsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_applications(report_id, opts)).await?;
        GetReportApplicationsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_report_operating_systems(report_id, opts))
            .await?;
        GetReportOperatingSystemsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_cves(report_id, opts)).await?;
        GetReportCvesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_errors(report_id, opts)).await?;
        GetReportErrorsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_closed_cves(report_id, opts)).await?;
        GetReportClosedCvesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_report_export(report_id, report_format_id))
            .await?;
        ReportExport::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_report_export_with_opts(report_id, opts))
            .await?;
        ReportExport::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_results(opts)).await?;
        GetResultsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_credential_stores()).await?;
        GetCredentialStoresResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(verify_credential_store(credential_store_id))
            .await?;
        VerifyCredentialStoreResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_credential_stores_with_opts(opts)).await?;
        GetCredentialStoresResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(get_credential_store(credential_store_id, details))
            .await?;
        GetCredentialStoresResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── NVTs ──────────────────────────────────────────────────────────────────

    /// Send a `get_nvts` request and return a typed [`GetNvtsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvts(&mut self, opts: GetNvtsOpts) -> Result<GetNvtsResponse, GvmError> {
        let response = self.send(get_nvts(opts)).await?;
        GetNvtsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a scan-config scoped `get_nvts` request and return a typed [`GetNvtsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config_nvts(
        &mut self,
        opts: GetNvtsOpts,
    ) -> Result<GetNvtsResponse, GvmError> {
        let response = self.send(get_scan_config_nvts(opts)).await?;
        GetNvtsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a scan-config compatibility `get_nvts` request for a single NVT.
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_scan_config_nvt(
        &mut self,
        nvt_oid: &str,
    ) -> Result<GetNvtsResponse, GvmError> {
        let response = self.send(get_scan_config_nvt(nvt_oid)).await?;
        GetNvtsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_nvt_families` request and return a typed [`GetNvtFamiliesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_nvt_families(&mut self) -> Result<GetNvtFamiliesResponse, GvmError> {
        let response = self.send(get_nvt_families()).await?;
        GetNvtFamiliesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── SecInfo ───────────────────────────────────────────────────────────────

    /// Send a `get_info` request for CVE entries and return a typed [`GetCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cves(&mut self, opts: GetSecInfoOpts) -> Result<GetCvesResponse, GvmError> {
        let response = self.send(get_cves(opts)).await?;
        GetCvesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_info` request for a single CVE entry and return a typed
    /// [`GetCvesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cve(&mut self, cve_id: &str) -> Result<GetCvesResponse, GvmError> {
        let response = self.send(get_cve(cve_id)).await?;
        GetCvesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_info` request for CPE entries and return a typed [`GetCpesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cpes(&mut self, opts: GetSecInfoOpts) -> Result<GetCpesResponse, GvmError> {
        let response = self.send(get_cpes(opts)).await?;
        GetCpesResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `get_info` request for a single CPE entry and return a typed
    /// [`GetCpesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_cpe(&mut self, cpe_id: &str) -> Result<GetCpesResponse, GvmError> {
        let response = self.send(get_cpe(cpe_id)).await?;
        GetCpesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_cert_bund_advisories(opts)).await?;
        GetCertBundAdvisoriesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_cert_bund_advisory(cert_id)).await?;
        GetCertBundAdvisoriesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_dfn_cert_advisories(opts)).await?;
        GetDfnCertAdvisoriesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_dfn_cert_advisory(cert_id)).await?;
        GetDfnCertAdvisoriesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_alerts(opts)).await?;
        GetAlertsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_alert(name, opts)).await?;
        CreateAlertResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_credentials(opts)).await?;
        GetCredentialsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_credential(name, opts)).await?;
        CreateCredentialResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self
            .send(create_credential_store_credential(
                name,
                credential_type,
                vault_id,
                host_identifier,
                opts,
            ))
            .await?;
        CreateCredentialResponse::from_response(&response).map_err(GvmError::Parse)
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
        self.ensure_semantic_command_supported("modify_credential_store_credential")?;
        let response = self
            .send(modify_credential_store_credential(credential_id, opts))
            .await?;
        ModifyCredentialResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_filters(opts)).await?;
        GetFiltersResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_filter(name, opts)).await?;
        CreateFilterResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Notes ─────────────────────────────────────────────────────────────────

    /// Send a `get_notes` request and return a typed [`GetNotesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_notes(&mut self, opts: GetNotesOpts) -> Result<GetNotesResponse, GvmError> {
        let response = self.send(get_notes(opts)).await?;
        GetNotesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_note(nvt_oid, opts)).await?;
        CreateNoteResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_overrides(opts)).await?;
        GetOverridesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_override(nvt_oid, opts)).await?;
        CreateOverrideResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_schedules(opts)).await?;
        GetSchedulesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_schedule(name, opts)).await?;
        CreateScheduleResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Tags ──────────────────────────────────────────────────────────────────

    /// Send a `get_tags` request and return a typed [`GetTagsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_tags(&mut self, opts: GetTagsOpts) -> Result<GetTagsResponse, GvmError> {
        let response = self.send(get_tags(opts)).await?;
        GetTagsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_tag(name, opts)).await?;
        CreateTagResponse::from_response(&response).map_err(GvmError::Parse)
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
        opts: TicketOpts,
    ) -> Result<CreateTicketResponse, GvmError> {
        let response = self.send(create_ticket(result_id, opts)).await?;
        CreateTicketResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    /// Send a `get_users` request and return a typed [`GetUsersResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_users(&mut self, opts: GetUsersOpts) -> Result<GetUsersResponse, GvmError> {
        let response = self.send(get_users(opts)).await?;
        GetUsersResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_user(name, opts)).await?;
        CreateUserResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Groups ────────────────────────────────────────────────────────────────

    /// Send a `get_groups` request and return a typed [`GetGroupsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_groups(&mut self, opts: GetGroupsOpts) -> Result<GetGroupsResponse, GvmError> {
        let response = self.send(get_groups(opts)).await?;
        GetGroupsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_group(name, opts)).await?;
        CreateGroupResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Roles ─────────────────────────────────────────────────────────────────

    /// Send a `get_roles` request and return a typed [`GetRolesResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_roles(&mut self, opts: GetRolesOpts) -> Result<GetRolesResponse, GvmError> {
        let response = self.send(get_roles(opts)).await?;
        GetRolesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_role(name, opts)).await?;
        CreateRoleResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_permissions(opts)).await?;
        GetPermissionsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `create_permission` request and return a typed [`CreatePermissionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_permission(
        &mut self,
        opts: PermissionOpts,
    ) -> Result<CreatePermissionResponse, GvmError> {
        let response = self.send(create_permission(opts)).await?;
        CreatePermissionResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Hosts ─────────────────────────────────────────────────────────────────

    /// Send a `get_hosts` request and return a typed [`GetHostsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_hosts(&mut self, opts: GetHostsOpts) -> Result<GetHostsResponse, GvmError> {
        let response = self.send(get_hosts(opts)).await?;
        GetHostsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `create_host` request and return a typed [`CreateHostResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_host(&mut self, opts: HostOpts) -> Result<CreateHostResponse, GvmError> {
        let response = self.send(create_host(opts)).await?;
        CreateHostResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── Assets ──────────────────────────────────────────────────────────────────

    /// Send a `get_assets` request and return a typed [`GetAssetsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_assets(&mut self, opts: GetAssetsOpts) -> Result<GetAssetsResponse, GvmError> {
        let response = self.send(get_assets(opts)).await?;
        GetAssetsResponse::from_response(&response).map_err(GvmError::Parse)
    }

    /// Send a `create_asset` request and return a typed [`CreateAssetResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn create_asset(
        &mut self,
        opts: CreateAssetOpts,
    ) -> Result<CreateAssetResponse, GvmError> {
        let response = self.send(create_asset(opts)).await?;
        CreateAssetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(modify_asset(asset_id, opts)).await?;
        ModifyAssetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(delete_asset(asset_id, opts)).await?;
        DeleteAssetResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_tls_certificates(opts)).await?;
        GetTlsCertificatesResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_tls_certificate(name, opts)).await?;
        CreateTlsCertificateResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_formats(opts)).await?;
        GetReportFormatsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(create_report_format(name, opts)).await?;
        CreateReportFormatResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(clone_report_format(report_format_id)).await?;
        CreateReportFormatResponse::from_response(&response).map_err(GvmError::Parse)
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
        let request = import_report_format(report_format_xml)?;
        let response = self.send(request).await?;
        CreateReportFormatResponse::from_response(&response).map_err(GvmError::Parse)
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
        let request = import_report(report_xml, task_id, opts)?;
        let response = self.send(request).await?;
        CreateReportResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(get_report_configs_opts(opts)).await?;
        GetReportConfigsResponse::from_response(&response).map_err(GvmError::Parse)
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
        let response = self.send(clone_report_config(id)).await?;
        CreateReportConfigResponse::from_response(&response).map_err(GvmError::Parse)
    }

    // ── System ────────────────────────────────────────────────────────────────

    /// Send a `get_settings` request and return a typed [`GetSettingsResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_settings(&mut self) -> Result<GetSettingsResponse, GvmError> {
        let response = self.send(get_settings(FilteredGetOpts::default())).await?;
        GetSettingsResponse::from_response(&response).map_err(GvmError::Parse)
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
