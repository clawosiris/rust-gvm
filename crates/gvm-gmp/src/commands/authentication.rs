// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Authentication command builders.

use gvm_protocol::{Request, XmlCommand};

/// Build an `authenticate` request.
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
}
