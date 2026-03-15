mod common;

use common::xml;
use gvm_gmp::commands::authentication::authenticate;

#[test]
fn test_authenticate_basic() {
    assert_eq!(
        xml(authenticate("foo", "bar")),
        "<authenticate><credentials><username>foo</username><password>bar</password></credentials></authenticate>"
    );
}

#[test]
fn test_authenticate_preserves_empty_values() {
    assert_eq!(
        xml(authenticate("", "")),
        "<authenticate><credentials><username></username><password></password></credentials></authenticate>"
    );
}

