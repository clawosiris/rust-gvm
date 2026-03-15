mod common;

use common::{id, xml};
use gvm_gmp::commands::nvts::{get_nvt, get_nvt_families, get_nvts, GetNvtsOpts};

#[test]
fn test_get_nvts_basic() {
    assert_eq!(xml(get_nvts(Default::default())), "<get_nvts/>");
}

#[test]
fn test_get_nvts_with_options() {
    assert_eq!(
        xml(get_nvts(GetNvtsOpts {
            filter_string: Some("family=foo".into()),
            filter_id: Some(id("f1")),
            details: Some(true),
        })),
        "<get_nvts details=\"1\" filt_id=\"f1\" filter=\"family=foo\"/>"
    );
}

#[test]
fn test_get_nvt_and_families() {
    assert_eq!(xml(get_nvt("1.3.6.1")), "<get_nvts details=\"1\" nvt_oid=\"1.3.6.1\"/>");
    assert_eq!(xml(get_nvt_families()), "<get_nvt_families/>");
}

