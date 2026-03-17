// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Feature command builders.

use gvm_protocol::XmlCommand;

/// Build a `get_features` request.
#[must_use]
pub fn get_features() -> XmlCommand {
    XmlCommand::new("get_features")
}
