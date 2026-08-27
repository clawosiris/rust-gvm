// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use gvm_protocol::XmlCommand;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::responses::ParseError;
use crate::types::{EntityId, ScalarUpdate};

pub(crate) fn bool_str(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

pub(crate) fn add_text_element(cmd: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        cmd.add_element_with_text(name, value);
    }
}

pub(crate) fn add_id_element(cmd: &mut XmlCommand, name: &str, id: &EntityId) {
    cmd.add_element(name).set_attribute("id", id.as_str());
}

pub(crate) fn add_optional_id_element(cmd: &mut XmlCommand, name: &str, id: Option<&EntityId>) {
    if let Some(id) = id {
        add_id_element(cmd, name, id);
    }
}

pub(crate) fn add_scalar_id_update(
    cmd: &mut XmlCommand,
    name: &str,
    update: &ScalarUpdate<EntityId>,
) {
    match update {
        ScalarUpdate::Omitted => {}
        ScalarUpdate::Set(id) => add_id_element(cmd, name, id),
        ScalarUpdate::Clear => {
            cmd.add_element(name).set_attribute("id", "0");
        }
    }
}

pub(crate) fn add_filter_attrs(
    cmd: &mut XmlCommand,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) {
    cmd.add_filter(filter_string, filter_id.map(EntityId::as_str));
}

pub(crate) fn set_optional_bool_attr(cmd: &mut XmlCommand, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        cmd.set_attribute(name, bool_str(value));
    }
}

pub(crate) fn add_preferences(cmd: &mut XmlCommand, preferences: &[(String, String)]) {
    if preferences.is_empty() {
        return;
    }
    let prefs = cmd.add_element("preferences");
    for (key, value) in preferences {
        let pref = prefs.add_child("preference");
        pref.add_child_with_text("scanner_name", key);
        pref.add_child_with_text("value", value);
    }
}

pub(crate) fn validate_single_xml_document(
    xml: &str,
    field: &str,
    expected_root: Option<&str>,
) -> Result<(), ParseError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut completed_root = false;

    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                if completed_root {
                    return Err(ParseError::InvalidValue {
                        field: field.to_string(),
                        value: "multiple root elements".to_string(),
                    });
                }
                if depth == 0 {
                    validate_root_name(event.name().as_ref(), field, expected_root)?;
                }
                saw_root = true;
                depth += 1;
            }
            Event::Empty(event) => {
                if completed_root {
                    return Err(ParseError::InvalidValue {
                        field: field.to_string(),
                        value: "multiple root elements".to_string(),
                    });
                }
                if depth == 0 {
                    validate_root_name(event.name().as_ref(), field, expected_root)?;
                }
                saw_root = true;
                completed_root = depth == 0;
            }
            Event::End(_) => {
                if depth == 0 {
                    return Err(ParseError::InvalidValue {
                        field: field.to_string(),
                        value: "unmatched end tag".to_string(),
                    });
                }
                depth -= 1;
                if depth == 0 {
                    completed_root = true;
                }
            }
            Event::Text(event) => {
                if depth == 0 && !event.as_ref().trim().is_empty() {
                    return Err(ParseError::InvalidValue {
                        field: field.to_string(),
                        value: if completed_root {
                            "text after root element"
                        } else {
                            "text before root element"
                        }
                        .to_string(),
                    });
                }
            }
            Event::CData(_) | Event::GeneralRef(_) if depth == 0 => {
                return Err(ParseError::InvalidValue {
                    field: field.to_string(),
                    value: "content outside root element".to_string(),
                });
            }
            Event::Eof => {
                if saw_root && depth == 0 {
                    return Ok(());
                }
                return Err(ParseError::MissingElement("root".to_string()));
            }
            Event::Decl(_) | Event::DocType(_) => {
                return Err(ParseError::InvalidValue {
                    field: field.to_string(),
                    value: "XML declarations and doctypes are not valid embedded command XML"
                        .to_string(),
                });
            }
            Event::PI(_) | Event::Comment(_) | Event::CData(_) | Event::GeneralRef(_) => {}
        }
    }
}

fn validate_root_name(
    actual: &str,
    field: &str,
    expected_root: Option<&str>,
) -> Result<(), ParseError> {
    let Some(expected_root) = expected_root else {
        return Ok(());
    };
    if actual == expected_root {
        return Ok(());
    }
    Err(ParseError::InvalidValue {
        field: field.to_string(),
        value: format!("expected <{expected_root}> root element, got <{actual}>"),
    })
}

#[cfg(test)]
pub(crate) fn xml(request: impl gvm_protocol::Request) -> String {
    String::from_utf8(request.to_bytes()).expect("request XML should be valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_xml_document_allows_nested_empty_element_before_sibling() {
        validate_single_xml_document(
            "<report><summary/><results/></report>",
            "report_xml",
            Some("report"),
        )
        .expect("nested empty elements must not complete the root document");
    }

    #[test]
    fn single_xml_document_allows_self_closing_root() {
        validate_single_xml_document("<report/>", "report_xml", Some("report"))
            .expect("a self-closing root is a complete document");
    }

    #[test]
    fn single_xml_document_rejects_second_root_after_self_closing_root() {
        let error =
            validate_single_xml_document("<report/><report/>", "report_xml", Some("report"))
                .expect_err("a second top-level root must be rejected");

        match error {
            ParseError::InvalidValue { field, value } => {
                assert_eq!(field, "report_xml");
                assert_eq!(value, "multiple root elements");
            }
            error => panic!("expected invalid-value error, got {error:?}"),
        }
    }
}
