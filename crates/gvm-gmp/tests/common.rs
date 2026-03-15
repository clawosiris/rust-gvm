// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(dead_code, missing_docs)]

use gvm_gmp::EntityId;
use gvm_protocol::Request;

pub fn xml(request: impl Request) -> String {
    String::from_utf8(request.to_bytes()).expect("valid utf8")
}

pub fn id(s: &str) -> EntityId {
    EntityId::new(s).expect("valid id")
}
