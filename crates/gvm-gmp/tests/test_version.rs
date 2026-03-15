mod common;

use common::xml;
use gvm_gmp::commands::version::get_version;

#[test]
fn test_get_version_basic() {
    assert_eq!(xml(get_version()), "<get_version/>");
}

