// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Target command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_scalar_id_update, add_text_element, bool_str,
    set_optional_bool_attr,
};
use crate::enums::AliveTest;
use crate::types::{CollectionUpdate, EntityId, ScalarUpdate};

/// Optional fields for `create_target` requests.
#[derive(Debug, Clone, Default)]
pub struct CreateTargetOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Host entries associated with the request.
    pub hosts: Vec<String>,
    /// Hosts to exclude from the request.
    pub exclude_hosts: Vec<String>,
    /// Optional alive-test strategy.
    pub alive_test: Option<AliveTest>,
    /// Optional port-list identifier.
    pub port_list_id: Option<EntityId>,
    /// Optional SSH credential identifier.
    pub ssh_credential_id: Option<EntityId>,
    /// Optional SSH service port nested below the SSH credential.
    pub ssh_credential_port: Option<u16>,
    /// Optional SMB credential identifier.
    pub smb_credential_id: Option<EntityId>,
    /// Optional `ESXi` credential identifier.
    pub esxi_credential_id: Option<EntityId>,
    /// Optional SNMP credential identifier.
    pub snmp_credential_id: Option<EntityId>,
    /// Whether reverse lookup only should be enabled.
    pub reverse_lookup_only: Option<bool>,
    /// Whether reverse-lookup unification should be enabled.
    pub reverse_lookup_unify: Option<bool>,
}

/// Options for `get_targets` requests.
#[derive(Debug, Clone, Default)]
pub struct GetTargetsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Optional fields for `modify_target` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyTargetOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Host update: omit, replace, or explicitly clear.
    pub hosts: CollectionUpdate<String>,
    /// Excluded-host update: omit, replace, or explicitly clear.
    pub exclude_hosts: CollectionUpdate<String>,
    /// Optional alive-test strategy.
    pub alive_test: Option<AliveTest>,
    /// Port-list relationship update: omit or set/replace.
    ///
    /// Current gvmd versions do not support detaching an existing port list.
    /// Passing [`ScalarUpdate::Clear`] is therefore rejected by
    /// [`modify_target`] instead of being translated to a protocol sentinel.
    pub port_list_id: ScalarUpdate<EntityId>,
    /// SSH credential relationship update: omit, set, or detach.
    pub ssh_credential_id: ScalarUpdate<EntityId>,
    /// Optional SSH service port nested below a set SSH credential.
    pub ssh_credential_port: Option<u16>,
    /// SMB credential relationship update: omit, set, or detach.
    pub smb_credential_id: ScalarUpdate<EntityId>,
    /// `ESXi` credential relationship update: omit, set, or detach.
    pub esxi_credential_id: ScalarUpdate<EntityId>,
    /// SNMP credential relationship update: omit, set, or detach.
    pub snmp_credential_id: ScalarUpdate<EntityId>,
    /// Whether reverse lookup only should be enabled.
    pub reverse_lookup_only: Option<bool>,
    /// Whether reverse-lookup unification should be enabled.
    pub reverse_lookup_unify: Option<bool>,
}

/// Errors raised while building a `modify_target` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModifyTargetError {
    /// gvmd has no wire representation for detaching a target port list.
    #[error("gvmd does not support clearing a target port-list relationship")]
    UnsupportedPortListClear,
}

/// Build a clone request for an existing target.
#[must_use]
pub fn clone_target(target_id: &EntityId) -> impl Request {
    XmlCommand::new("create_target").child_with_text("copy", target_id.as_str())
}

/// Build a `create_target` request.
#[must_use]
pub fn create_target(name: &str, opts: CreateTargetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_target");
    cmd.add_element_with_text("name", name);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if !opts.hosts.is_empty() {
        cmd.add_element_with_text("hosts", &opts.hosts.join(","));
    }
    if !opts.exclude_hosts.is_empty() {
        cmd.add_element_with_text("exclude_hosts", &opts.exclude_hosts.join(","));
    }
    if let Some(alive_test) = opts.alive_test {
        cmd.add_element_with_text("alive_test", alive_test.as_target_name());
    }
    add_optional_id_element(&mut cmd, "port_list", opts.port_list_id.as_ref());
    add_create_target_credentials(&mut cmd, &opts);
    if let Some(value) = opts.reverse_lookup_only {
        cmd.add_element_with_text("reverse_lookup_only", bool_str(value));
    }
    if let Some(value) = opts.reverse_lookup_unify {
        cmd.add_element_with_text("reverse_lookup_unify", bool_str(value));
    }
    cmd
}

/// Build a `get_targets` request.
#[must_use]
pub fn get_targets(opts: GetTargetsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_targets");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_target` request.
#[must_use]
pub fn get_target(target_id: &EntityId) -> impl Request {
    XmlCommand::new("get_targets")
        .attribute("target_id", target_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_target` request.
///
/// # Errors
/// Returns [`ModifyTargetError::UnsupportedPortListClear`] when the port-list
/// update requests clearing. gvmd accepts omission and replacement, but does
/// not define a sentinel for detaching an existing port list.
pub fn modify_target(
    target_id: &EntityId,
    opts: ModifyTargetOpts,
) -> Result<impl Request, ModifyTargetError> {
    if matches!(opts.port_list_id, ScalarUpdate::Clear) {
        return Err(ModifyTargetError::UnsupportedPortListClear);
    }

    let mut cmd = XmlCommand::new("modify_target").attribute("target_id", target_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_collection_update(&mut cmd, "hosts", &opts.hosts);
    add_collection_update(&mut cmd, "exclude_hosts", &opts.exclude_hosts);
    if let Some(alive_test) = opts.alive_test {
        cmd.add_element_with_text("alive_test", alive_test.as_target_name());
    }
    if let ScalarUpdate::Set(port_list_id) = &opts.port_list_id {
        add_optional_id_element(&mut cmd, "port_list", Some(port_list_id));
    }
    add_modify_target_credentials(&mut cmd, &opts);
    if let Some(value) = opts.reverse_lookup_only {
        cmd.add_element_with_text("reverse_lookup_only", bool_str(value));
    }
    if let Some(value) = opts.reverse_lookup_unify {
        cmd.add_element_with_text("reverse_lookup_unify", bool_str(value));
    }
    Ok(cmd)
}

/// Build a `delete_target` request.
#[must_use]
pub fn delete_target(target_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_target")
        .attribute("target_id", target_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_create_target_credentials(cmd: &mut XmlCommand, opts: &CreateTargetOpts) {
    add_ssh_credential(
        cmd,
        opts.ssh_credential_id.as_ref(),
        opts.ssh_credential_port,
    );
    add_optional_id_element(cmd, "smb_credential", opts.smb_credential_id.as_ref());
    add_optional_id_element(cmd, "esxi_credential", opts.esxi_credential_id.as_ref());
    add_optional_id_element(cmd, "snmp_credential", opts.snmp_credential_id.as_ref());
}

fn add_modify_target_credentials(cmd: &mut XmlCommand, opts: &ModifyTargetOpts) {
    match &opts.ssh_credential_id {
        ScalarUpdate::Omitted => {}
        ScalarUpdate::Set(id) => add_ssh_credential(cmd, Some(id), opts.ssh_credential_port),
        ScalarUpdate::Clear => {
            add_scalar_id_update(cmd, "ssh_credential", &ScalarUpdate::<EntityId>::Clear);
        }
    }
    add_scalar_id_update(cmd, "smb_credential", &opts.smb_credential_id);
    add_scalar_id_update(cmd, "esxi_credential", &opts.esxi_credential_id);
    add_scalar_id_update(cmd, "snmp_credential", &opts.snmp_credential_id);
}

fn add_ssh_credential(cmd: &mut XmlCommand, id: Option<&EntityId>, port: Option<u16>) {
    let Some(id) = id else {
        return;
    };
    let credential = cmd.add_element("ssh_credential");
    credential.set_attribute("id", id.as_str());
    if let Some(port) = port {
        credential.add_child_with_text("port", &port.to_string());
    }
}

fn add_collection_update(cmd: &mut XmlCommand, element: &str, update: &CollectionUpdate<String>) {
    match update {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(values) => {
            cmd.add_element_with_text(element, &values.join(","));
        }
        CollectionUpdate::Clear => {
            cmd.add_element_with_text(element, "");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn target_commands_build_xml() {
        let rendered = xml(create_target(
            "target",
            CreateTargetOpts {
                comment: Some("c".into()),
                hosts: vec!["1.1.1.1".into()],
                exclude_hosts: vec!["2.2.2.2".into()],
                alive_test: Some(AliveTest::IcmpPing),
                port_list_id: Some(id("pl1")),
                ssh_credential_id: Some(id("ssh1")),
                ssh_credential_port: Some(2222),
                smb_credential_id: Some(id("smb1")),
                esxi_credential_id: Some(id("esxi1")),
                snmp_credential_id: Some(id("snmp1")),
                reverse_lookup_only: Some(true),
                reverse_lookup_unify: Some(false),
            },
        ));
        assert!(rendered.contains("<name>target</name>"));
        assert!(rendered.contains("<hosts>1.1.1.1</hosts>"));
        assert!(rendered.contains("<alive_test>ICMP Ping</alive_test>"));
        assert!(rendered.contains("<port_list id=\"pl1\"/>"));
        assert!(rendered.contains("<ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential>"));
        assert!(rendered.contains("<smb_credential id=\"smb1\"/>"));
        assert!(rendered.contains("<esxi_credential id=\"esxi1\"/>"));
        assert!(rendered.contains("<snmp_credential id=\"snmp1\"/>"));
        assert_eq!(
            xml(clone_target(&id("t1"))),
            "<create_target><copy>t1</copy></create_target>"
        );
    }

    #[test]
    fn target_get_modify_delete_build_xml() {
        assert_eq!(
            xml(get_target(&id("t1"))),
            "<get_targets details=\"1\" target_id=\"t1\"/>"
        );
        let rendered = xml(get_targets(GetTargetsOpts {
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
            trash: Some(true),
            details: Some(true),
        }));
        assert!(rendered.contains("filter=\"name=foo\""));
        assert!(rendered.contains("trash=\"1\""));
        let rendered = xml(modify_target(
            &id("t1"),
            ModifyTargetOpts {
                name: Some("n".into()),
                alive_test: Some(AliveTest::IcmpAndArpPing),
                ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                ssh_credential_port: Some(2222),
                smb_credential_id: ScalarUpdate::set(id("smb1")),
                esxi_credential_id: ScalarUpdate::set(id("esxi1")),
                snmp_credential_id: ScalarUpdate::set(id("snmp1")),
                reverse_lookup_only: Some(true),
                reverse_lookup_unify: Some(false),
                ..Default::default()
            },
        )
        .expect("valid target update"));
        assert!(rendered.contains("<name>n</name>"));
        assert!(rendered.contains("<alive_test>ICMP &amp; ARP Ping</alive_test>"));
        assert!(rendered.contains("<ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential>"));
        assert!(rendered.contains("<smb_credential id=\"smb1\"/>"));
        assert!(rendered.contains("<esxi_credential id=\"esxi1\"/>"));
        assert!(rendered.contains("<snmp_credential id=\"snmp1\"/>"));
        assert!(rendered.contains("<reverse_lookup_only>1</reverse_lookup_only>"));
        assert!(rendered.contains("<reverse_lookup_unify>0</reverse_lookup_unify>"));
        assert_eq!(
            xml(delete_target(&id("t1"), false)),
            "<delete_target target_id=\"t1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn modify_target_distinguishes_omitted_replaced_and_cleared_hosts() {
        assert_eq!(
            xml(modify_target(&id("t1"), ModifyTargetOpts::default()).expect("valid update")),
            "<modify_target target_id=\"t1\"/>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    hosts: CollectionUpdate::replace(["192.0.2.1".into(), "192.0.2.2".into()]),
                    exclude_hosts: CollectionUpdate::replace(["192.0.2.3".into()]),
                    ..Default::default()
                }
            ).expect("valid update")),
            "<modify_target target_id=\"t1\"><hosts>192.0.2.1,192.0.2.2</hosts><exclude_hosts>192.0.2.3</exclude_hosts></modify_target>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    hosts: CollectionUpdate::Clear,
                    exclude_hosts: CollectionUpdate::Clear,
                    ..Default::default()
                }
            ).expect("valid update")),
            "<modify_target target_id=\"t1\"><hosts></hosts><exclude_hosts></exclude_hosts></modify_target>"
        );
    }

    #[test]
    fn modify_target_distinguishes_omitted_set_and_cleared_credentials() {
        assert_eq!(
            xml(modify_target(&id("t1"), ModifyTargetOpts::default()).expect("valid update")),
            "<modify_target target_id=\"t1\"/>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                    ssh_credential_port: Some(2222),
                    smb_credential_id: ScalarUpdate::set(id("smb1")),
                    ..Default::default()
                }
            ).expect("valid update")),
            "<modify_target target_id=\"t1\"><ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential><smb_credential id=\"smb1\"/></modify_target>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::Clear,
                    smb_credential_id: ScalarUpdate::Clear,
                    esxi_credential_id: ScalarUpdate::Clear,
                    snmp_credential_id: ScalarUpdate::Clear,
                    ..Default::default()
                }
            ).expect("valid update")),
            "<modify_target target_id=\"t1\"><ssh_credential id=\"0\"/><smb_credential id=\"0\"/><esxi_credential id=\"0\"/><snmp_credential id=\"0\"/></modify_target>"
        );
    }

    #[test]
    fn modify_target_distinguishes_omitted_set_and_unsupported_port_list_clear() {
        assert_eq!(
            xml(modify_target(&id("t1"), ModifyTargetOpts::default()).expect("valid update")),
            "<modify_target target_id=\"t1\"/>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    port_list_id: ScalarUpdate::set(id("pl1")),
                    ..Default::default()
                }
            )
            .expect("setting a port list is supported")),
            "<modify_target target_id=\"t1\"><port_list id=\"pl1\"/></modify_target>"
        );
        assert_eq!(
            modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    port_list_id: ScalarUpdate::Clear,
                    ..Default::default()
                }
            )
            .err(),
            Some(ModifyTargetError::UnsupportedPortListClear)
        );
    }
}
