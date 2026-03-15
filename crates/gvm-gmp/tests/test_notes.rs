#![allow(missing_docs)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::notes::*;

#[test]
fn test_create_note_basic() {
    assert_eq!(
        xml(create_note("1.3.6.1", Default::default())),
        "<create_note><nvt oid=\"1.3.6.1\"/></create_note>"
    );
}

#[test]
fn test_create_note_with_optionals() {
    assert_eq!(
        xml(create_note(
            "1.3.6.1",
            NoteOpts {
                text: Some("body".into()),
                hosts: vec!["1.1.1.1".into()],
                port: Some("22".into()),
                severity: Some("7.5".into()),
                task_id: Some(id("t1")),
                result_id: Some(id("r1")),
                active: Some(true),
                orphan: Some(false),
            }
        )),
        "<create_note><nvt oid=\"1.3.6.1\"/><text>body</text><hosts>1.1.1.1</hosts><port>22</port><severity>7.5</severity><task id=\"t1\"/><result id=\"r1\"/><active>1</active><orphan>0</orphan></create_note>"
    );
}

#[test]
fn test_note_get_modify_delete() {
    assert_eq!(
        xml(clone_note(&id("n1"))),
        "<create_note><copy>n1</copy></create_note>"
    );
    assert_eq!(
        xml(get_note(&id("n1"))),
        "<get_notes details=\"1\" note_id=\"n1\"/>"
    );
    assert_eq!(
        xml(delete_note(&id("n1"), true)),
        "<delete_note note_id=\"n1\" ultimate=\"1\"/>"
    );
}
