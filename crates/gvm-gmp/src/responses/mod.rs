// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed GMP response models.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]

pub mod auth;
pub mod common;
pub mod port_list;
pub mod scan_config;
pub mod scanner;
pub mod target;
pub mod version;

pub use auth::AuthenticateResponse;
pub use common::{ActionResponse, CountInfo, EntityMeta, NamedEntity, Owner, ParseError};
pub use port_list::{CreatePortListResponse, GetPortListsResponse, PortList};
pub use scan_config::{CreateScanConfigResponse, GetScanConfigsResponse, ScanConfig};
pub use scanner::{CreateScannerResponse, GetScannersResponse, Scanner};
pub use target::{CreateTargetResponse, GetTargetsResponse, Target};
pub use version::GetVersionResponse;
