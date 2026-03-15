mod common;

use common::{id, xml};
use gvm_gmp::commands::targets::*;
use gvm_gmp::AliveTest;

#[test]
fn test_create_target_basic() {
    assert_eq!(xml(create_target("target", Default::default())), "<create_target><name>target</name></create_target>");
}

#[test]
fn test_create_target_with_optionals() {
    assert_eq!(
        xml(create_target(
            "target",
            CreateTargetOpts {
                comment: Some("c".into()),
                hosts: vec!["1.1.1.1".into(), "2.2.2.2".into()],
                exclude_hosts: vec!["3.3.3.3".into()],
                alive_test: Some(AliveTest::IcmpPing),
                port_list_id: Some(id("pl1")),
                reverse_lookup_only: Some(true),
                reverse_lookup_unify: Some(false),
            }
        )),
        "<create_target><name>target</name><comment>c</comment><hosts>1.1.1.1,2.2.2.2</hosts><exclude_hosts>3.3.3.3</exclude_hosts><alive_test>ICMP Ping</alive_test><port_list id=\"pl1\"/><reverse_lookup_only>1</reverse_lookup_only><reverse_lookup_unify>0</reverse_lookup_unify></create_target>"
    );
}

#[test]
fn test_target_get_modify_delete() {
    assert_eq!(xml(clone_target(&id("t1"))), "<create_target><copy>t1</copy></create_target>");
    assert_eq!(xml(get_target(&id("t1"))), "<get_targets details=\"1\" target_id=\"t1\"/>");
    assert_eq!(xml(delete_target(&id("t1"), false)), "<delete_target target_id=\"t1\" ultimate=\"0\"/>");
}

