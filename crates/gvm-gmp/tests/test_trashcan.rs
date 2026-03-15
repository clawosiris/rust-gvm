#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::trashcan::{empty_trashcan, restore};

#[test]
fn test_empty_trashcan_basic() {
    assert_eq!(xml(empty_trashcan()), "<empty_trashcan/>");
}

#[test]
fn test_restore_basic() {
    assert_eq!(xml(restore(&id("r1"))), "<restore id=\"r1\"/>");
}
