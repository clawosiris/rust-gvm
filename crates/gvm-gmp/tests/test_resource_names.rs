#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::resource_names::{get_resource_names, GetResourceNamesOpts};
use gvm_gmp::EntityType;

#[test]
fn test_get_resource_names_basic() {
    assert_eq!(
        xml(get_resource_names(Default::default())),
        "<get_resource_names/>"
    );
}

#[test]
fn test_get_resource_names_with_options() {
    assert_eq!(
        xml(get_resource_names(GetResourceNamesOpts {
            resource_type: Some(EntityType::Task),
            resource_id: Some(id("t1")),
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
        })),
        "<get_resource_names filt_id=\"f1\" filter=\"name=foo\" resource_id=\"t1\" type=\"task\"/>"
    );
}
