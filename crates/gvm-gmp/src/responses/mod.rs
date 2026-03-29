// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed GMP response models.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

pub mod alert;
pub mod auth;
pub mod common;
pub mod credential;
pub mod feed;
pub mod filter;
pub mod group;
pub mod host;
pub mod note;
pub mod nvt;
pub mod override_;
pub mod permission;
pub mod port_list;
pub mod report;
pub mod report_config;
pub mod report_format;
pub mod result;
pub mod role;
pub mod scan_config;
pub mod scanner;
pub mod schedule;
pub mod secinfo;
pub mod system;
pub mod tag;
pub mod target;
pub mod task;
pub mod ticket;
pub mod tls_certificate;
pub mod user;
pub mod version;

pub use alert::{
    Alert, CreateAlertResponse, DeleteAlertResponse, GetAlertsResponse, ModifyAlertResponse,
};
pub use auth::AuthenticateResponse;
pub use common::{ActionResponse, CountInfo, EntityMeta, NamedEntity, Owner, ParseError};
pub use credential::{
    CreateCredentialResponse, Credential, DeleteCredentialResponse, GetCredentialsResponse,
    ModifyCredentialResponse,
};
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
pub use override_::{
    CreateOverrideResponse, DeleteOverrideResponse, GetOverridesResponse, ModifyOverrideResponse,
    Override,
};
pub use permission::{
    CreatePermissionResponse, DeletePermissionResponse, GetPermissionsResponse,
    ModifyPermissionResponse, Permission,
};
pub use port_list::{CreatePortListResponse, GetPortListsResponse, PortList};
pub use report::{DeleteReportResponse, GetReportsResponse, Report, ResultCount, Severity};
pub use report_config::{
    CreateReportConfigResponse, DeleteReportConfigResponse, GetReportConfigsResponse,
    ModifyReportConfigResponse, ReportConfig,
};
pub use report_format::{
    CreateReportFormatResponse, DeleteReportFormatResponse, GetReportFormatsResponse,
    ModifyReportFormatResponse, ReportFormat,
};
pub use result::{GetResultsResponse, NvtRef, QodInfo, ScanResult};
pub use role::{
    CreateRoleResponse, DeleteRoleResponse, GetRolesResponse, ModifyRoleResponse, Role,
};
pub use scan_config::{CreateScanConfigResponse, GetScanConfigsResponse, ScanConfig};
pub use scanner::{CreateScannerResponse, GetScannersResponse, Scanner};
pub use schedule::{
    CreateScheduleResponse, DeleteScheduleResponse, GetSchedulesResponse, ModifyScheduleResponse,
    Schedule,
};
pub use secinfo::{
    CertBundAdvisory, Cpe, Cve, DfnCertAdvisory, GetCertBundAdvisoriesResponse, GetCpesResponse,
    GetCvesResponse, GetDfnCertAdvisoriesResponse,
};
pub use system::{
    AuthConfSetting, AuthGroup, DescribeAuthResponse, GetSettingsResponse, HelpResponse, Setting,
};
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
pub use user::{
    CreateUserResponse, DeleteUserResponse, GetUsersResponse, ModifyUserResponse, User,
};
pub use version::GetVersionResponse;
