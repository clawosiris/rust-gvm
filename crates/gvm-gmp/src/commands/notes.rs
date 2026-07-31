// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Note command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::{CollectionUpdate, EntityId};

/// Optional fields for note create requests.
#[derive(Debug, Clone, Default)]
pub struct NoteOpts {
    /// Optional text body.
    pub text: Option<String>,
    /// Host entries associated with the request.
    pub hosts: Vec<String>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional severity value.
    pub severity: Option<String>,
    /// Optional task identifier.
    pub task_id: Option<EntityId>,
    /// Optional result identifier.
    pub result_id: Option<EntityId>,
    /// Whether the resource should be active.
    pub active: Option<bool>,
    /// Whether the note should be marked as orphaned.
    pub orphan: Option<bool>,
}

/// Optional fields for `modify_note` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyNoteOpts {
    /// Optional text body.
    pub text: Option<String>,
    /// Host update: omit, replace, or explicitly clear.
    pub hosts: CollectionUpdate<String>,
    /// Optional port selector.
    pub port: Option<String>,
    /// Optional severity value.
    pub severity: Option<String>,
    /// Optional task identifier.
    pub task_id: Option<EntityId>,
    /// Optional result identifier.
    pub result_id: Option<EntityId>,
    /// Whether the resource should be active.
    pub active: Option<bool>,
    /// Whether the note should be marked as orphaned.
    pub orphan: Option<bool>,
}

/// Options for `get_notes` requests.
#[derive(Debug, Clone, Default)]
pub struct GetNotesOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
    /// Whether to include associated result references in the response.
    pub result: Option<bool>,
}

/// Build a clone request for an existing note.
#[must_use]
pub fn clone_note(note_id: &EntityId) -> impl Request {
    XmlCommand::new("create_note").child_with_text("copy", note_id.as_str())
}

/// Build a `create_note` request.
#[must_use]
pub fn create_note(nvt_oid: &str, opts: NoteOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_note");
    cmd.add_element("nvt").set_attribute("oid", nvt_oid);
    add_text_element(&mut cmd, "text", opts.text.as_deref());
    if !opts.hosts.is_empty() {
        cmd.add_element_with_text("hosts", &opts.hosts.join(","));
    }
    add_note_tail(
        &mut cmd,
        opts.port.as_deref(),
        opts.severity.as_deref(),
        opts.task_id.as_ref(),
        opts.result_id.as_ref(),
        opts.active,
        opts.orphan,
    );
    cmd
}

/// Build a `get_notes` request.
#[must_use]
pub fn get_notes(opts: GetNotesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_notes");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    set_optional_bool_attr(&mut cmd, "result", opts.result);
    cmd
}

/// Build a `get_note` request.
#[must_use]
pub fn get_note(note_id: &EntityId) -> impl Request {
    XmlCommand::new("get_notes")
        .attribute("note_id", note_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_note` request.
#[must_use]
pub fn modify_note(note_id: &EntityId, opts: ModifyNoteOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_note").attribute("note_id", note_id.as_str());
    add_text_element(&mut cmd, "text", opts.text.as_deref());
    add_hosts_update(&mut cmd, &opts.hosts);
    add_note_tail(
        &mut cmd,
        opts.port.as_deref(),
        opts.severity.as_deref(),
        opts.task_id.as_ref(),
        opts.result_id.as_ref(),
        opts.active,
        opts.orphan,
    );
    cmd
}

/// Build a `delete_note` request.
#[must_use]
pub fn delete_note(note_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_note")
        .attribute("note_id", note_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_note_tail(
    cmd: &mut XmlCommand,
    port: Option<&str>,
    severity: Option<&str>,
    task_id: Option<&EntityId>,
    result_id: Option<&EntityId>,
    active: Option<bool>,
    orphan: Option<bool>,
) {
    add_text_element(cmd, "port", port);
    add_text_element(cmd, "severity", severity);
    if let Some(task_id) = task_id {
        cmd.add_element("task")
            .set_attribute("id", task_id.as_str());
    }
    if let Some(result_id) = result_id {
        cmd.add_element("result")
            .set_attribute("id", result_id.as_str());
    }
    if let Some(active) = active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    if let Some(orphan) = orphan {
        cmd.add_element_with_text("orphan", bool_str(orphan));
    }
}

fn add_hosts_update(cmd: &mut XmlCommand, update: &CollectionUpdate<String>) {
    match update {
        CollectionUpdate::Omitted => {}
        CollectionUpdate::Replace(hosts) => {
            cmd.add_element_with_text("hosts", &hosts.join(","));
        }
        CollectionUpdate::Clear => {
            cmd.add_element_with_text("hosts", "");
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
    fn note_commands_build_xml() {
        let rendered = xml(create_note(
            "1.3.6.1",
            NoteOpts {
                text: Some("body".into()),
                hosts: vec!["1.1.1.1".into()],
                task_id: Some(id("t1")),
                active: Some(true),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<nvt oid=\"1.3.6.1\""));
        assert!(rendered.contains("<text>body</text>"));
        assert_eq!(
            xml(clone_note(&id("n1"))),
            "<create_note><copy>n1</copy></create_note>"
        );
        let rendered = xml(get_note(&id("n1")));
        assert!(rendered.contains("<get_notes "));
        assert!(rendered.contains("note_id=\"n1\""));
        assert!(rendered.contains("details=\"1\""));
    }

    #[test]
    fn note_modify_get_delete_build_xml() {
        let rendered = xml(get_notes(GetNotesOpts {
            filter_string: Some("name=foo".into()),
            details: Some(true),
            result: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("filter=\"name=foo\""));
        assert!(rendered.contains("details=\"1\""));
        assert!(rendered.contains("result=\"1\""));
        let rendered = xml(modify_note(
            &id("n1"),
            ModifyNoteOpts {
                text: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(
            rendered,
            "<modify_note note_id=\"n1\"><text>updated</text></modify_note>"
        );
        assert_eq!(
            xml(delete_note(&id("n1"), true)),
            "<delete_note note_id=\"n1\" ultimate=\"1\"/>"
        );
    }

    #[test]
    fn modify_note_distinguishes_omitted_replaced_and_cleared_hosts() {
        assert_eq!(
            xml(modify_note(&id("n1"), ModifyNoteOpts::default())),
            "<modify_note note_id=\"n1\"/>"
        );
        assert_eq!(
            xml(modify_note(
                &id("n1"),
                ModifyNoteOpts {
                    hosts: CollectionUpdate::replace(["192.0.2.1".into(), "192.0.2.2".into()]),
                    ..Default::default()
                }
            )),
            "<modify_note note_id=\"n1\"><hosts>192.0.2.1,192.0.2.2</hosts></modify_note>"
        );
        assert_eq!(
            xml(modify_note(
                &id("n1"),
                ModifyNoteOpts {
                    hosts: CollectionUpdate::Clear,
                    ..Default::default()
                }
            )),
            "<modify_note note_id=\"n1\"><hosts></hosts></modify_note>"
        );
    }
}
