// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Target command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_text_element, bool_str, set_optional_bool_attr,
};
use crate::enums::AliveTest;
use crate::types::EntityId;

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
    /// Host entries associated with the request.
    pub hosts: Vec<String>,
    /// Hosts to exclude from the request.
    pub exclude_hosts: Vec<String>,
    /// Optional alive-test strategy.
    pub alive_test: Option<AliveTest>,
    /// Optional port-list identifier.
    pub port_list_id: Option<EntityId>,
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
        cmd.add_element_with_text("alive_test", alive_test.as_gmp_str());
    }
    add_optional_id_element(&mut cmd, "port_list", opts.port_list_id.as_ref());
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
#[must_use]
pub fn modify_target(target_id: &EntityId, opts: ModifyTargetOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_target").attribute("target_id", target_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if !opts.hosts.is_empty() {
        cmd.add_element_with_text("hosts", &opts.hosts.join(","));
    }
    if !opts.exclude_hosts.is_empty() {
        cmd.add_element_with_text("exclude_hosts", &opts.exclude_hosts.join(","));
    }
    if let Some(alive_test) = opts.alive_test {
        cmd.add_element_with_text("alive_test", alive_test.as_gmp_str());
    }
    add_optional_id_element(&mut cmd, "port_list", opts.port_list_id.as_ref());
    cmd
}

/// Build a `delete_target` request.
#[must_use]
pub fn delete_target(target_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_target")
        .attribute("target_id", target_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
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
                reverse_lookup_only: Some(true),
                reverse_lookup_unify: Some(false),
            },
        ));
        assert!(rendered.contains("<name>target</name>"));
        assert!(rendered.contains("<hosts>1.1.1.1</hosts>"));
        assert!(rendered.contains("<alive_test>ICMP Ping</alive_test>"));
        assert!(rendered.contains("<port_list id=\"pl1\"/>"));
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
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_target target_id=\"t1\"><name>n</name></modify_target>"
        );
        assert_eq!(
            xml(delete_target(&id("t1"), false)),
            "<delete_target target_id=\"t1\" ultimate=\"0\"/>"
        );
    }
}
