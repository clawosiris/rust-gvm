mod common;

use common::{id, xml};
use gvm_gmp::commands::scan_configs::*;

#[test]
fn test_create_scan_config_basic() {
    assert_eq!(xml(create_scan_config("cfg", None, Default::default())), "<create_config><name>cfg</name></create_config>");
}

#[test]
fn test_create_scan_config_with_copy_and_options() {
    assert_eq!(
        xml(create_scan_config(
            "cfg",
            Some(&id("base1")),
            ConfigOpts {
                comment: Some("c".into()),
                usage_type: Some("scan".into()),
            }
        )),
        "<create_config><name>cfg</name><copy>base1</copy><comment>c</comment><usage_type>scan</usage_type></create_config>"
    );
}

#[test]
fn test_scan_config_get_delete_sync() {
    assert_eq!(xml(clone_scan_config(&id("c1"))), "<create_config><copy>c1</copy></create_config>");
    assert_eq!(xml(get_scan_config(&id("c1"))), "<get_configs config_id=\"c1\" details=\"1\"/>");
    assert_eq!(xml(sync_config(&id("c1"))), "<sync_config config_id=\"c1\"/>");
}

