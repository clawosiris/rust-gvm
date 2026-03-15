// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::xml;
use gvm_gmp::commands::version::get_version;

#[test]
fn test_get_version_basic() {
    assert_eq!(xml(get_version()), "<get_version/>");
}
