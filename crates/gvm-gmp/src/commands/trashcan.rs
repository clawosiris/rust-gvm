// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Trashcan command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::types::EntityId;

/// Build an `empty_trashcan` request.
pub fn empty_trashcan() -> impl Request {
    XmlCommand::new("empty_trashcan")
}

/// Build a `restore` request.
pub fn restore(resource_id: &EntityId) -> impl Request {
    XmlCommand::new("restore").attribute("id", resource_id.as_str())
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
    }
}
