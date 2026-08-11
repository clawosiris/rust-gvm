// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed GMP response models.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

pub mod agent;
pub mod agent_group;
pub mod aggregates;
pub mod alert;
pub mod asset;
pub mod audit_report;
pub mod auth;
pub mod common;
pub mod config;
pub mod credential;
pub mod features;
pub mod feed;
pub mod filter;
pub mod group;
pub mod host;
pub mod integration_config;
pub mod note;
pub mod nvt;
pub mod oci_image_target;
pub mod override_;
pub mod permission;
pub mod port_list;
pub mod report;
pub mod report_config;
pub mod report_format;
pub mod resource_names;
pub mod result;
pub mod role;
pub mod scan_config;
pub mod scan_report;
pub mod scanner;
pub mod schedule;
pub mod secinfo;
pub mod system;
pub mod system_reports;
pub mod tag;
pub mod target;
pub mod task;
pub mod ticket;
pub mod tls_certificate;
pub mod trashcan;
pub mod user;
pub mod user_settings;
pub mod version;
pub mod web_application_target;

pub use agent::{
    Agent, AgentConfig, AgentControlConfig, AgentHeartbeatConfig, AgentRetryConfig,
    AgentScriptExecutorConfig, AgentSupportBundle, DeleteAgentResponse,
    GetAgentInstallerInstructionResponse, GetAgentSupportBundleResponse, GetAgentsResponse,
    ModifyAgentControlScanConfigResponse, ModifyAgentResponse, SyncAgentsResponse,
};
pub use agent_group::{
    AgentGroup, CloneAgentGroupResponse, CreateAgentGroupResponse, DeleteAgentGroupResponse,
    GetAgentGroupsResponse, ModifyAgentGroupResponse,
};
pub use aggregates::{
    AggregateColumnInfo, AggregateFilter, AggregateFilterKeyword, AggregateGroup, AggregateOverall,
    AggregateResult, AggregateStatisticValues, AggregateStats, AggregateSubgroup, AggregateText,
    GetAggregatesResponse,
};
pub use alert::{
    Alert, CreateAlertResponse, DeleteAlertResponse, GetAlertsResponse, ModifyAlertResponse,
};
pub use asset::{
    Asset, AssetIdentifier, AssetKind, CreateAssetResponse, DeleteAssetResponse, GenericAsset,
    GetAssetsResponse, GetOperatingSystemAssetsResponse, ModifyAssetResponse, OperatingSystemAsset,
    OperatingSystemHost,
};
pub use audit_report::{
    AuditComplianceClassCount, AuditReport, AuditReportCompliance, AuditReportComplianceCounts,
    AuditReportHost, AuditReportHostComplianceCounts, AuditReportHostDetail,
    AuditReportHostDetailSource, ComplianceValue, GetAuditReportHostsResponse,
    GetAuditReportResponse, ReportFilter, ReportFilterKeyword, ReportPage, ReportSort,
    StructuredReportResourceCounts, StructuredReportTarget, StructuredReportTask,
};
pub use auth::AuthenticateResponse;
pub use common::{
    ActionResponse, CountInfo, EntityMeta, NamedEntity, NvtReference, Owner, ParseError,
};
pub use config::{
    ConfigUsageKind, CreateConfigResponse, DeleteConfigResponse, GenericConfig, GetConfigsResponse,
    ModifyConfigResponse,
};
pub use credential::{
    CreateCredentialResponse, Credential, CredentialKind, CredentialStore,
    DeleteCredentialResponse, GetCredentialStoresResponse, GetCredentialsResponse,
    ModifyCredentialResponse, VerifyCredentialStoreResponse,
};
pub use features::{Feature, GetFeaturesResponse};
pub use feed::{Feed, GetFeedsResponse};
pub use filter::{
    CreateFilterResponse, DeleteFilterResponse, Filter, GetFiltersResponse, ModifyFilterResponse,
};
pub use group::{
    CreateGroupResponse, DeleteGroupResponse, GetGroupsResponse, Group, ModifyGroupResponse,
};
pub use host::{
    AssetSource, CreateHostResponse, DeleteHostResponse, GetHostsResponse, Host, HostDetail,
    HostIdentifier, HostOperatingSystem, ModifyHostResponse,
};
pub use integration_config::{
    GetIntegrationConfigsResponse, IntegrationConfig, IntegrationConfigOidc,
    IntegrationConfigService, ModifyIntegrationConfigResponse,
};
pub use note::{
    CreateNoteResponse, DeleteNoteResponse, GetNotesResponse, ModifyNoteResponse, Note,
};
pub use nvt::{GetNvtFamiliesResponse, GetNvtsResponse, Nvt, NvtFamily};
pub use oci_image_target::{
    CreateOciImageTargetResponse, DeleteOciImageTargetResponse, GetOciImageTargetsResponse,
    ModifyOciImageTargetResponse, OciImageTarget,
};
pub use override_::{
    CreateOverrideResponse, DeleteOverrideResponse, GetOverridesResponse, ModifyOverrideResponse,
    Override,
};
pub use permission::{
    CreatePermissionResponse, DeletePermissionResponse, GetPermissionsResponse,
    ModifyPermissionResponse, Permission,
};
pub use port_list::{
    CreatePortListResponse, GetPortListsResponse, ModifyPortListResponse, PortList,
};
pub use report::{
    CreateReportResponse, DeleteReportResponse, GetReportApplicationsResponse,
    GetReportClosedCvesResponse, GetReportCvesResponse, GetReportErrorsResponse,
    GetReportHostsResponse, GetReportOperatingSystemsResponse, GetReportPortsResponse,
    GetReportTlsCertificatesResponse, GetReportVulnsResponse, GetReportsResponse, Report,
    ReportApplicationSummary, ReportClosedCve, ReportCveSummary, ReportError, ReportExport,
    ReportHostSummary, ReportOperatingSystemSummary, ReportPortSummary, ReportTlsCertificate,
    ReportVulnerability, ResultCount, Severity,
};
pub use report_config::{
    CreateReportConfigResponse, DeleteReportConfigResponse, GetReportConfigsResponse,
    ModifyReportConfigResponse, ReportConfig,
};
pub use report_format::{
    CreateReportFormatResponse, DeleteReportFormatResponse, GetReportFormatsResponse,
    ModifyReportFormatResponse, ReportFormat,
};
pub use resource_names::{GetResourceNamesResponse, ResourceName};
pub use result::{GetResultsResponse, NvtRef, QodInfo, ScanResult};
pub use role::{
    CreateRoleResponse, DeleteRoleResponse, GetRolesResponse, ModifyRoleResponse, Role,
};
pub use scan_config::{
    CreateScanConfigResponse, DeleteScanConfigResponse, GetScanConfigsResponse,
    ModifyScanConfigResponse, ScanConfig, SyncConfigResponse,
};
pub use scan_report::{GetScanReportResponse, ScanReport, ScanReportResultCount};
pub use scanner::{
    CreateScannerResponse, DeleteScannerResponse, GetScannersResponse, ModifyScannerResponse,
    Scanner, VerifyScannerResponse,
};
pub use schedule::{
    CreateScheduleResponse, DeleteScheduleResponse, GetSchedulesResponse, ModifyScheduleResponse,
    Schedule,
};
pub use secinfo::{
    CertBundAdvisory, Cpe, Cve, DfnCertAdvisory, GetCertBundAdvisoriesResponse, GetCpesResponse,
    GetCvesResponse, GetDfnCertAdvisoriesResponse, GetOperatingSystemsResponse,
    GetVulnerabilitiesResponse, OperatingSystem, Vulnerability,
};
pub use system::{
    AuthConfSetting, AuthGroup, DescribeAuthResponse, GetSettingsResponse, GetTimezonesResponse,
    HelpCommand, HelpResponse, HelpSchema, ModifyAuthResponse, Setting, Timezone,
};
pub use system_reports::{GetSystemReportsResponse, SystemReport};
pub use tag::{CreateTagResponse, DeleteTagResponse, GetTagsResponse, ModifyTagResponse, Tag};
pub use target::{
    CreateTargetResponse, DeleteTargetResponse, GetTargetsResponse, ModifyTargetResponse, Target,
};
pub use task::{
    CreateTaskResponse, CurrentReport, DeleteTaskResponse, GetTasksResponse, LastReport,
    ModifyTaskResponse, MoveTaskResponse, ResumeTaskResponse, StartTaskResponse, StopTaskResponse,
    Task, TaskReportComplianceCount, TaskReportResultCount, TaskTargetReference,
};
pub use ticket::{
    CreateTicketResponse, DeleteTicketResponse, GetTicketsResponse, ModifyTicketResponse, Ticket,
};
pub use tls_certificate::{
    CreateTlsCertificateResponse, DeleteTlsCertificateResponse, GetTlsCertificatesResponse,
    ModifyTlsCertificateResponse, TlsCertificate,
};
pub use trashcan::{EmptyTrashcanResponse, RestoreResponse};
pub use user::{
    CreateUserResponse, DeleteUserResponse, GetUsersResponse, ModifyUserResponse, User,
};
pub use user_settings::{GetUserSettingsResponse, ModifyUserSettingResponse, UserSetting};
pub use version::GetVersionResponse;
pub use web_application_target::{
    CreateWebApplicationTargetResponse, DeleteWebApplicationTargetResponse,
    GetWebApplicationTargetsResponse, ModifyWebApplicationTargetResponse, WebApplicationTarget,
};
