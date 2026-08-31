// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Authentication command builders.

use std::fmt;

use gvm_protocol::{Request, XmlCommand};

use crate::responses::AuthenticateResponse;
use crate::GmpRequest;

/// Semantic `authenticate` request.
#[derive(Clone)]
pub struct AuthenticateRequest {
    username: String,
    password: String,
}

impl AuthenticateRequest {
    /// Create an authentication request.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl fmt::Debug for AuthenticateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticateRequest")
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

impl Request for AuthenticateRequest {
    fn to_bytes(&self) -> Vec<u8> {
        authenticate(&self.username, &self.password).to_bytes()
    }
}

impl GmpRequest for AuthenticateRequest {
    type Response = AuthenticateResponse;
}

/// Build an `authenticate` request.
#[must_use]
pub fn authenticate(username: &str, password: &str) -> impl Request {
    let mut cmd = XmlCommand::new("authenticate");
    let credentials = cmd.add_element("credentials");
    credentials.add_child_with_text("username", username);
    credentials.add_child_with_text("password", password);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    #[test]
    fn authenticate_builds_credentials_xml() {
        assert_eq!(
            xml(authenticate("admin", "pass")),
            "<authenticate><credentials><username>admin</username><password>pass</password></credentials></authenticate>"
        );
    }

    #[test]
    fn semantic_request_matches_builder_bytes_and_redacts_debug() {
        let request = AuthenticateRequest::new("admin", "pass");
        assert_eq!(request.to_bytes(), authenticate("admin", "pass").to_bytes());
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("admin"));
        assert!(!debug.contains("pass"));
    }
}
