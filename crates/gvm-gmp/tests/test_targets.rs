// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::targets::*;
use gvm_gmp::{AliveTest, ScalarUpdate, ServicePort, TargetHost, TargetHosts, TargetPortSelection};

fn host(value: &str) -> TargetHost {
    value.parse().expect("valid target host")
}

fn hosts(included: &[&str], excluded: &[&str]) -> TargetHosts {
    TargetHosts::new(
        included.iter().map(|value| host(value)),
        excluded.iter().map(|value| host(value)),
    )
    .expect("valid target hosts")
}

fn direct_ports() -> TargetPortSelection {
    TargetPortSelection::PortRange("T:1-65535".parse().expect("valid port range"))
}

#[test]
fn test_create_target_basic() {
    assert_eq!(
        xml(create_target(
            "target",
            CreateTargetOpts::new(hosts(&["192.0.2.1"], &[]), direct_ports()),
        )
        .expect("valid target")),
        "<create_target><name>target</name><hosts>192.0.2.1</hosts><exclude_hosts></exclude_hosts><port_range>T:1-65535</port_range></create_target>"
    );
}

#[test]
fn test_create_target_with_optionals() {
    assert_eq!(
        xml(
            create_target(
                "target",
                CreateTargetOpts {
                comment: Some("c".into()),
                hosts: hosts(&["1.1.1.1", "2.2.2.2"], &["3.3.3.3"]),
                alive_test: Some(AliveTest::IcmpAndArpPing),
                ports: TargetPortSelection::PortList(id("pl1")),
                reverse_lookup_only: Some(true),
                reverse_lookup_unify: Some(false),
                ..CreateTargetOpts::new(hosts(&["192.0.2.1"], &[]), direct_ports())
                },
            )
            .expect("valid target"),
        ),
        "<create_target><name>target</name><comment>c</comment><hosts>1.1.1.1,2.2.2.2</hosts><exclude_hosts>3.3.3.3</exclude_hosts><alive_tests>ICMP &amp; ARP Ping</alive_tests><port_list id=\"pl1\"/><reverse_lookup_only>1</reverse_lookup_only><reverse_lookup_unify>0</reverse_lookup_unify></create_target>"
    );
}

#[test]
fn test_modify_target_uses_plural_alive_tests_element() {
    let request = modify_target(
        &id("target1"),
        ModifyTargetOpts {
            alive_test: Some(AliveTest::IcmpPing),
            ..Default::default()
        },
    )
    .expect("valid target update");

    assert_eq!(
        xml(request),
        "<modify_target target_id=\"target1\"><alive_tests>ICMP Ping</alive_tests></modify_target>"
    );
}

#[test]
fn test_target_ssh_credential_port_is_nested_in_credential() {
    assert_eq!(
        xml(
            create_target(
                "target",
                CreateTargetOpts {
                    ssh_credential_id: Some(id("ssh1")),
                    ssh_credential_port: Some(ServicePort::new(2222).expect("valid port")),
                    ..CreateTargetOpts::new(hosts(&["192.0.2.1"], &[]), direct_ports())
                },
            )
            .expect("valid target"),
        ),
        "<create_target><name>target</name><hosts>192.0.2.1</hosts><exclude_hosts></exclude_hosts><port_range>T:1-65535</port_range><ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential></create_target>"
    );

    assert_eq!(
        xml(modify_target(
            &id("target1"),
            ModifyTargetOpts {
                ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                ssh_credential_port: ScalarUpdate::set(
                    ServicePort::new(2222).expect("valid port"),
                ),
                ..Default::default()
            }
        )
        .expect("valid target update")),
        "<modify_target target_id=\"target1\"><ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential></modify_target>"
    );

    assert_eq!(
        xml(modify_target(
            &id("target1"),
            ModifyTargetOpts {
                ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                ssh_credential_port: ScalarUpdate::Clear,
                ..Default::default()
            }
        )
        .expect("valid target update")),
        "<modify_target target_id=\"target1\"><ssh_credential id=\"ssh1\"><port>0</port></ssh_credential></modify_target>"
    );
}

#[test]
fn test_target_get_modify_delete() {
    assert_eq!(
        xml(clone_target(&id("t1"))),
        "<create_target><copy>t1</copy></create_target>"
    );
    assert_eq!(
        xml(get_target(&id("t1"))),
        "<get_targets details=\"1\" target_id=\"t1\"/>"
    );
    assert_eq!(
        xml(delete_target(&id("t1"), false)),
        "<delete_target target_id=\"t1\" ultimate=\"0\"/>"
    );
}
