// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Version command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::responses::GetVersionResponse;
use crate::GmpRequest;

/// Semantic `get_version` request.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetVersionRequest;

impl GetVersionRequest {
    /// Create a version request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for GetVersionRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_version().to_bytes()
    }
}

impl GmpRequest for GetVersionRequest {
    type Response = GetVersionResponse;
}

/// Build a `get_version` command.
#[must_use]
pub fn get_version() -> impl Request {
    XmlCommand::new("get_version")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    #[test]
    fn get_version_builds_xml() {
        assert_eq!(xml(get_version()), "<get_version/>");
    }

    #[test]
    fn semantic_request_matches_builder_bytes() {
        assert_eq!(
            GetVersionRequest::new().to_bytes(),
            get_version().to_bytes()
        );
    }
}
