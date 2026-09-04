// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feature command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::responses::GetFeaturesResponse;
use crate::GmpRequest;

/// Semantic request for discovering compiled and enabled gvmd features.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetFeaturesRequest;

impl GetFeaturesRequest {
    /// Create a feature-discovery request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for GetFeaturesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_features().to_bytes()
    }
}

impl GmpRequest for GetFeaturesRequest {
    type Response = GetFeaturesResponse;
}

/// Build a `get_features` request.
#[must_use]
pub fn get_features() -> XmlCommand {
    XmlCommand::new("get_features")
}
