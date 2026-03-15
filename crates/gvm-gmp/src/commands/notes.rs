use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct NoteOpts {
    pub text: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<String>,
    pub severity: Option<String>,
    pub task_id: Option<EntityId>,
    pub result_id: Option<EntityId>,
    pub active: Option<bool>,
    pub orphan: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct GetNotesOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_note(note_id: &EntityId) -> impl Request {
    XmlCommand::new("create_note").child_with_text("copy", note_id.as_str())
}

pub fn create_note(nvt_oid: &str, opts: NoteOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_note");
    cmd.add_element("nvt").set_attribute("oid", nvt_oid);
    add_note_body(&mut cmd, &opts);
    cmd
}

pub fn get_notes(opts: GetNotesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_notes");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_note(note_id: &EntityId) -> impl Request {
    XmlCommand::new("get_notes").attribute("note_id", note_id.as_str()).attribute("details", "1")
}

pub fn modify_note(note_id: &EntityId, opts: NoteOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_note").attribute("note_id", note_id.as_str());
    add_note_body(&mut cmd, &opts);
    cmd
}

pub fn delete_note(note_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_note").attribute("note_id", note_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

fn add_note_body(cmd: &mut XmlCommand, opts: &NoteOpts) {
    add_text_element(cmd, "text", opts.text.as_deref());
    if !opts.hosts.is_empty() {
        cmd.add_element_with_text("hosts", &opts.hosts.join(","));
    }
    add_text_element(cmd, "port", opts.port.as_deref());
    add_text_element(cmd, "severity", opts.severity.as_deref());
    if let Some(task_id) = opts.task_id.as_ref() {
        cmd.add_element("task").set_attribute("id", task_id.as_str());
    }
    if let Some(result_id) = opts.result_id.as_ref() {
        cmd.add_element("result").set_attribute("id", result_id.as_str());
    }
    if let Some(active) = opts.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    if let Some(orphan) = opts.orphan {
        cmd.add_element_with_text("orphan", bool_str(orphan));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn note_commands_build_xml() {
        let rendered = xml(create_note("1.3.6.1", NoteOpts { text: Some("body".into()), hosts: vec!["1.1.1.1".into()], task_id: Some(id("t1")), active: Some(true), ..Default::default() }));
        assert!(rendered.contains("<nvt oid=\"1.3.6.1\""));
        assert!(rendered.contains("<text>body</text>"));
        assert_eq!(xml(clone_note(&id("n1"))), "<create_note><copy>n1</copy></create_note>");
        let rendered = xml(get_note(&id("n1")));
        assert!(rendered.contains("<get_notes "));
        assert!(rendered.contains("note_id=\"n1\""));
        assert!(rendered.contains("details=\"1\""));
    }

    #[test]
    fn note_modify_get_delete_build_xml() {
        let rendered = xml(get_notes(GetNotesOpts { filter_string: Some("name=foo".into()), details: Some(true), ..Default::default() }));
        assert!(rendered.contains("filter=\"name=foo\""));
        let rendered = xml(modify_note(&id("n1"), NoteOpts { text: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_note note_id=\"n1\"><text>updated</text></modify_note>");
        assert_eq!(xml(delete_note(&id("n1"), true)), "<delete_note note_id=\"n1\" ultimate=\"1\"/>");
    }
}
