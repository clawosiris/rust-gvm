// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Trashcan command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::types::EntityId;

/// Build an `empty_trashcan` request.
#[must_use]
pub fn empty_trashcan() -> impl Request {
    XmlCommand::new("empty_trashcan")
}

/// Build a `restore` request.
#[must_use]
pub fn restore(resource_id: &EntityId) -> impl Request {
    XmlCommand::new("restore").attribute("id", resource_id.as_str())
}

/// Build a `restore` request for a resource in the trashcan.
///
/// This is a python-gvm-compatible name for [`restore`].
#[must_use]
pub fn restore_from_trashcan(resource_id: &EntityId) -> impl Request {
    restore(resource_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;
    use crate::types::EntityId;

    #[test]
    fn trashcan_commands_build_xml() {
        assert_eq!(xml(empty_trashcan()), "<empty_trashcan/>");
        assert_eq!(
            xml(restore(&EntityId::new("a1").expect("valid id"))),
            "<restore id=\"a1\"/>"
        );
        assert_eq!(
            xml(restore_from_trashcan(
                &EntityId::new("a1").expect("valid id")
            )),
            "<restore id=\"a1\"/>"
        );
    }
}
