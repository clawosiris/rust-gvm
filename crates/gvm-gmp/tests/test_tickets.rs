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
        xml(create_ticket(&id("r1"), Default::default())),
        "<create_ticket><result id=\"r1\"/></create_ticket>"
    );
}

#[test]
fn test_create_ticket_with_optionals() {
    assert_eq!(
        xml(create_ticket(
            &id("r1"),
            TicketOpts {
                assigned_to: Some("alice".into()),
                comment: Some("c".into()),
                status: Some(TicketStatus::Open),
                open_note: Some("o".into()),
                fixed_note: Some("f".into()),
                closed_note: Some("cl".into()),
            }
        )),
        "<create_ticket><result id=\"r1\"/><assigned_to>alice</assigned_to><comment>c</comment><status>open</status><open_note>o</open_note><fixed_note>f</fixed_note><closed_note>cl</closed_note></create_ticket>"
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
        xml(delete_ticket(&id("tick1"), true)),
        "<delete_ticket ticket_id=\"tick1\" ultimate=\"1\"/>"
    );
}
