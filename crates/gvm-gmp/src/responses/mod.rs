// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed GMP response models.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

pub mod auth;
pub mod common;
pub mod port_list;
pub mod report;
pub mod result;
pub mod scan_config;
pub mod scanner;
pub mod target;
pub mod task;
pub mod version;

pub use auth::AuthenticateResponse;
pub use common::{ActionResponse, CountInfo, EntityMeta, NamedEntity, Owner, ParseError};
pub use port_list::{CreatePortListResponse, GetPortListsResponse, PortList};
pub use report::{DeleteReportResponse, GetReportsResponse, Report, ResultCount, Severity};
pub use result::{GetResultsResponse, NvtRef, QodInfo, ScanResult};
pub use scan_config::{CreateScanConfigResponse, GetScanConfigsResponse, ScanConfig};
pub use scanner::{CreateScannerResponse, GetScannersResponse, Scanner};
pub use target::{CreateTargetResponse, GetTargetsResponse, Target};
pub use task::{
    CreateTaskResponse, DeleteTaskResponse, GetTasksResponse, LastReport, ModifyTaskResponse,
    MoveTaskResponse, ResumeTaskResponse, StartTaskResponse, StopTaskResponse, Task,
};
pub use version::GetVersionResponse;
