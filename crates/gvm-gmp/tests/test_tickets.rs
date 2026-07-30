// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::{id, xml};
use gvm_gmp::commands::tickets::*;
use gvm_gmp::TicketStatus;

#[test]
fn test_create_ticket_basic() {
    assert_eq!(
        xml(create_ticket(
            &id("r1"),
            CreateTicketOpts {
                assigned_to: id("u1"),
                open_note: "Investigate".into(),
                comment: None,
            }
        )),
        "<create_ticket><result id=\"r1\"/><assigned_to><user id=\"u1\"/></assigned_to><open_note>Investigate</open_note></create_ticket>"
    );
}

#[test]
fn test_create_ticket_with_optionals() {
    assert_eq!(
        xml(create_ticket(
            &id("r1"),
            CreateTicketOpts {
                assigned_to: id("u1"),
                open_note: "o".into(),
                comment: Some("c".into()),
            }
        )),
        "<create_ticket><result id=\"r1\"/><assigned_to><user id=\"u1\"/></assigned_to><open_note>o</open_note><comment>c</comment></create_ticket>"
    );
}

#[test]
fn test_ticket_get_modify_delete() {
    assert_eq!(
        xml(clone_ticket(&id("tick1"))),
        "<create_ticket><copy>tick1</copy></create_ticket>"
    );
    assert_eq!(
        xml(get_ticket(&id("tick1"))),
        "<get_tickets details=\"1\" ticket_id=\"tick1\"/>"
    );
    assert_eq!(
        xml(modify_ticket(
            &id("tick1"),
            ModifyTicketOpts {
                assigned_to: Some(id("u2")),
                status: Some(TicketStatus::Closed),
                closed_note: Some("done".into()),
                ..Default::default()
            }
        )),
        "<modify_ticket ticket_id=\"tick1\"><status>Closed</status><closed_note>done</closed_note><assigned_to><user id=\"u2\"/></assigned_to></modify_ticket>"
    );
    assert_eq!(
        xml(delete_ticket(&id("tick1"), true)),
        "<delete_ticket ticket_id=\"tick1\" ultimate=\"1\"/>"
    );
}
