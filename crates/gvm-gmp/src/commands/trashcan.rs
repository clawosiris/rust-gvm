// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Trashcan command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::responses::{EmptyTrashcanResponse, RestoreResponse};
use crate::types::EntityId;
use crate::GmpRequest;

/// Semantic request for emptying the trashcan.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyTrashcanRequest;

impl EmptyTrashcanRequest {
    /// Create an empty-trashcan request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Request for EmptyTrashcanRequest {
    fn to_bytes(&self) -> Vec<u8> {
        empty_trashcan().to_bytes()
    }
}

impl GmpRequest for EmptyTrashcanRequest {
    type Response = EmptyTrashcanResponse;
}

macro_rules! restore_request {
    ($name:ident, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic restore request.
            #[must_use]
            pub fn new(resource_id: EntityId) -> Self {
                Self(resource_id)
            }
        }

        impl Request for $name {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.0).to_bytes()
            }
        }

        impl GmpRequest for $name {
            type Response = RestoreResponse;
        }
    };
}

restore_request!(RestoreRequest, restore);
restore_request!(RestoreFromTrashcanRequest, restore_from_trashcan);

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
    fn semantic_trashcan_requests_match_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }
        let resource_id = EntityId::new("resource-1").expect("valid id");
        let empty = EmptyTrashcanRequest::new();
        assert_eq!(empty.to_bytes(), empty_trashcan().to_bytes());
        associated::<_, EmptyTrashcanResponse>(&empty);
        let restore = RestoreRequest::new(resource_id.clone());
        assert_eq!(restore.to_bytes(), super::restore(&resource_id).to_bytes());
        associated::<_, RestoreResponse>(&restore);
        let alias = RestoreFromTrashcanRequest::new(resource_id.clone());
        assert_eq!(
            alias.to_bytes(),
            restore_from_trashcan(&resource_id).to_bytes()
        );
        associated::<_, RestoreResponse>(&alias);
    }

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
