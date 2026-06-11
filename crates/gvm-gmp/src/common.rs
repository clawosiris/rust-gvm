// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use gvm_protocol::xml_command::XmlElement;
use gvm_protocol::XmlCommand;

use crate::types::EntityId;
use std::collections::HashMap;

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

pub(crate) fn add_string_list(cmd: &mut XmlCommand, parent: &str, child: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let root = cmd.add_element(parent);
    for value in values {
        root.add_child_with_text(child, value);
    }
}

pub(crate) fn add_named_data_map(parent: &mut XmlElement, values: &HashMap<String, String>) {
    for (key, value) in values {
        let data = parent.add_child("data");
        data.set_text(value);
        data.add_child_with_text("name", key);
    }
}

#[cfg(test)]
pub(crate) fn xml(request: impl gvm_protocol::Request) -> String {
    String::from_utf8(request.to_bytes()).expect("request XML should be valid UTF-8")
}
