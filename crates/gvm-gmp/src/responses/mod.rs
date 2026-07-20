// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed GMP response models.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

pub mod aggregates;
pub mod alert;
pub mod auth;
pub mod common;
pub mod credential;
pub mod features;
pub mod feed;
pub mod filter;
pub mod group;
pub mod host;
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

pub use aggregates::{AggregateGroup, AggregateStats, AggregateSubgroup, GetAggregatesResponse};
pub use alert::{
    Alert, CreateAlertResponse, DeleteAlertResponse, GetAlertsResponse, ModifyAlertResponse,
};
pub use auth::AuthenticateResponse;
pub use common::{ActionResponse, CountInfo, EntityMeta, NamedEntity, Owner, ParseError};
pub use credential::{
    CreateCredentialResponse, Credential, CredentialStore, DeleteCredentialResponse,
    GetCredentialStoresResponse, GetCredentialsResponse, ModifyCredentialResponse,
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
    CreateHostResponse, DeleteHostResponse, GetHostsResponse, Host, ModifyHostResponse,
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
pub use port_list::{CreatePortListResponse, GetPortListsResponse, PortList};
pub use report::{
    CreateReportResponse, DeleteReportResponse, GetReportClosedCvesResponse,
    GetReportErrorsResponse, GetReportTlsCertificatesResponse, GetReportVulnsResponse,
    GetReportsResponse, Report, ReportClosedCve, ReportError, ReportExport, ReportTlsCertificate,
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
    HelpResponse, Setting, Timezone,
};
pub use system_reports::{GetSystemReportsResponse, SystemReport};
pub use tag::{CreateTagResponse, DeleteTagResponse, GetTagsResponse, ModifyTagResponse, Tag};
pub use target::{CreateTargetResponse, GetTargetsResponse, Target};
pub use task::{
    CreateTaskResponse, DeleteTaskResponse, GetTasksResponse, LastReport, ModifyTaskResponse,
    MoveTaskResponse, ResumeTaskResponse, StartTaskResponse, StopTaskResponse, Task,
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
