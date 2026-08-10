// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Shared response-model types and XML helpers.

use std::collections::HashMap;
use std::str;

use gvm_protocol::Response;
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use crate::EntityId;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid XML: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("missing required element: {0}")]
    MissingElement(String),
    #[error("invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },
    #[error("server error {status}: {message}")]
    ServerError { status: u16, message: String },
    #[error("invalid UTF-8: {0}")]
    Utf8(#[from] str::Utf8Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Owner {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NamedEntity {
    pub id: EntityId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NvtReference {
    pub oid: String,
    pub name: Option<String>,
    pub type_: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CountInfo {
    pub total: Option<u32>,
    pub filtered: Option<u32>,
    pub page: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ActionResponse {
    pub status: u16,
    pub status_text: String,
}

impl ActionResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let _ = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EntityMeta {
    pub id: EntityId,
    pub name: String,
    pub comment: Option<String>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
    pub owner: Option<Owner>,
    pub in_use: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XmlNode {
    pub(crate) name: String,
    pub(crate) attributes: HashMap<String, String>,
    pub(crate) text: String,
    raw_text: Option<Box<str>>,
    pub(crate) children: Vec<XmlNode>,
}

impl XmlNode {
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    pub(crate) fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|child| child.name == name)
    }

    pub(crate) fn children_named<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a XmlNode> + 'a {
        self.children.iter().filter(move |child| child.name == name)
    }

    pub(crate) fn child_text(&self, name: &str) -> Option<String> {
        self.child(name).map(|child| child.text.clone())
    }

    pub(crate) fn child_raw_text(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|child| child.raw_text.as_deref().unwrap_or(&child.text))
    }

    pub(crate) fn required_child_text(&self, name: &str) -> Result<String, ParseError> {
        self.child_text(name)
            .ok_or_else(|| ParseError::MissingElement(name.to_string()))
    }

    pub(crate) fn optional_child_text(&self, name: &str) -> Option<String> {
        self.child_text(name)
            .and_then(|text| (!text.is_empty()).then_some(text))
    }
}

pub(crate) fn status_from_response(response: &Response) -> Result<(u16, String), ParseError> {
    let status = response
        .status_code()
        .ok_or_else(|| ParseError::MissingElement("status".to_string()))?;
    let status_text = response
        .status_text()
        .ok_or_else(|| ParseError::MissingElement("status_text".to_string()))?;
    if !(200..300).contains(&status) {
        return Err(ParseError::ServerError {
            status,
            message: status_text,
        });
    }
    Ok((status, status_text))
}

pub(crate) fn parse_document(data: &[u8]) -> Result<XmlNode, ParseError> {
    let text = str::from_utf8(data)?;
    let mut reader = Reader::from_str(text);
    // Trimming each event loses significant whitespace when quick-xml splits
    // text around a character reference (for example `left &amp; right`).
    reader.config_mut().trim_text(false);
    let mut stack: Vec<XmlNode> = Vec::new();

    loop {
        match reader.read_event()? {
            Event::Start(event) => {
                stack.push(XmlNode {
                    name: str::from_utf8(event.name().as_ref())?.to_string(),
                    attributes: collect_attributes(&event)?,
                    text: String::new(),
                    raw_text: None,
                    children: Vec::new(),
                });
            }
            Event::Empty(event) => {
                let node = XmlNode {
                    name: str::from_utf8(event.name().as_ref())?.to_string(),
                    attributes: collect_attributes(&event)?,
                    text: String::new(),
                    raw_text: None,
                    children: Vec::new(),
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    return Ok(node);
                }
            }
            Event::Text(event) => {
                if let Some(node) = stack.last_mut() {
                    let text = str::from_utf8(event.as_ref())?;
                    let text = quick_xml::escape::unescape(text)
                        .map_err(quick_xml::Error::from)?
                        .into_owned();
                    node.text.push_str(&text);
                }
            }
            Event::CData(event) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(str::from_utf8(event.as_ref())?);
                }
            }
            Event::GeneralRef(event) => {
                let node = stack.last_mut().ok_or_else(|| {
                    ParseError::MissingElement("root for entity reference".to_string())
                })?;
                if let Some(character) = event.resolve_char_ref()? {
                    node.text.push(character);
                } else {
                    let entity = event.decode().map_err(quick_xml::Error::from)?;
                    let Some(value) = quick_xml::escape::resolve_xml_entity(&entity) else {
                        return Err(ParseError::InvalidValue {
                            field: "entity reference".to_string(),
                            value: entity.into_owned(),
                        });
                    };
                    node.text.push_str(value);
                }
            }
            Event::End(_) => {
                let Some(mut node) = stack.pop() else {
                    return Err(ParseError::MissingElement("root".to_string()));
                };
                let raw_text = std::mem::take(&mut node.text);
                let trimmed_text = raw_text.trim();
                if node.children.is_empty() && trimmed_text.len() != raw_text.len() {
                    node.text = trimmed_text.to_string();
                    node.raw_text = Some(raw_text.into_boxed_str());
                } else {
                    node.text = trimmed_text.to_string();
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    return Ok(node);
                }
            }
            Event::Eof => return Err(ParseError::MissingElement("root".to_string())),
            Event::Decl(_) | Event::PI(_) | Event::DocType(_) | Event::Comment(_) => {}
        }
    }
}

fn collect_attributes(
    event: &quick_xml::events::BytesStart<'_>,
) -> Result<HashMap<String, String>, ParseError> {
    let mut attributes = HashMap::new();
    for attribute in event.attributes() {
        let attribute = attribute.map_err(quick_xml::Error::from)?;
        attributes.insert(
            str::from_utf8(attribute.key.as_ref())?.to_string(),
            attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, event.decoder())?
                .into_owned(),
        );
    }
    Ok(attributes)
}

pub(crate) fn parse_entity_id(value: &str, field: &str) -> Result<EntityId, ParseError> {
    EntityId::new(value).map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_nvt_reference(
    node: &XmlNode,
    field_prefix: &str,
) -> Result<Option<NvtReference>, ParseError> {
    node.child("nvt")
        .map(|nvt| {
            Ok(NvtReference {
                oid: nvt
                    .attr("oid")
                    .ok_or_else(|| ParseError::MissingElement(format!("{field_prefix}.oid")))?
                    .to_string(),
                name: nvt.optional_child_text("name"),
                type_: nvt.optional_child_text("type"),
            })
        })
        .transpose()
}

pub(crate) fn parse_bool(value: &str, field: &str) -> Result<bool, ParseError> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(ParseError::InvalidValue {
            field: field.to_string(),
            value: value.to_string(),
        }),
    }
}

pub(crate) fn parse_csv_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn parse_u16(value: &str, field: &str) -> Result<u16, ParseError> {
    value.parse::<u16>().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_u32(value: &str, field: &str) -> Result<u32, ParseError> {
    value.parse::<u32>().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_i32(value: &str, field: &str) -> Result<i32, ParseError> {
    value.parse::<i32>().map_err(|_| ParseError::InvalidValue {
        field: field.to_string(),
        value: value.to_string(),
    })
}

pub(crate) fn parse_score(value: &str) -> Option<f64> {
    value.parse::<f64>().ok().filter(|score| score.is_finite())
}

pub(crate) fn optional_u16(
    node: &XmlNode,
    name: &str,
    field: &str,
) -> Result<Option<u16>, ParseError> {
    node.optional_child_text(name)
        .map(|value| parse_u16(&value, field))
        .transpose()
}

pub(crate) fn optional_u32(
    node: &XmlNode,
    name: &str,
    field: &str,
) -> Result<Option<u32>, ParseError> {
    node.optional_child_text(name)
        .map(|value| parse_u32(&value, field))
        .transpose()
}

pub(crate) fn count_info(node: &XmlNode, count_name: &str) -> Result<CountInfo, ParseError> {
    let Some(count_node) = node.child(count_name) else {
        return Ok(CountInfo::default());
    };
    Ok(CountInfo {
        total: (!count_node.text.is_empty())
            .then(|| parse_u32(&count_node.text, count_name))
            .transpose()?,
        filtered: count_node
            .optional_child_text("filtered")
            .map(|value| parse_u32(&value, &format!("{count_name}.filtered")))
            .transpose()?,
        page: count_node
            .optional_child_text("page")
            .map(|value| parse_u32(&value, &format!("{count_name}.page")))
            .transpose()?,
    })
}

pub(crate) fn parse_owner(node: &XmlNode) -> Result<Option<Owner>, ParseError> {
    node.child("owner")
        .map(|owner| {
            Ok(Owner {
                name: owner.required_child_text("name")?,
            })
        })
        .transpose()
}

pub(crate) fn parse_named_entity(
    node: &XmlNode,
    field: &str,
) -> Result<Option<NamedEntity>, ParseError> {
    node.child(field)
        .map(|child| {
            let Some(raw_id) = child.attr("id") else {
                return Err(ParseError::MissingElement(format!("{field}.id")));
            };
            if raw_id.is_empty() {
                return Ok(None);
            }
            let id = parse_entity_id(raw_id, &format!("{field}.id"))?;
            let name = child.required_child_text("name")?;
            Ok(Some(NamedEntity { id, name }))
        })
        .transpose()
        .map(Option::flatten)
}

pub(crate) fn parse_entity_ref(
    node: &XmlNode,
    field: &str,
) -> Result<Option<NamedEntity>, ParseError> {
    node.child(field)
        .map(|child| {
            let Some(raw_id) = child.attr("id") else {
                return Err(ParseError::MissingElement(format!("{field}.id")));
            };
            if raw_id.is_empty() {
                return Ok(None);
            }
            let id = parse_entity_id(raw_id, &format!("{field}.id"))?;
            let name = child.optional_child_text("name").unwrap_or_default();
            Ok(Some(NamedEntity { id, name }))
        })
        .transpose()
        .map(Option::flatten)
}

fn parse_entity_meta_with_name(
    node: &XmlNode,
    name_required: bool,
) -> Result<EntityMeta, ParseError> {
    let id = parse_entity_id(
        node.attr("id")
            .ok_or_else(|| ParseError::MissingElement(format!("{}.id", node.name)))?,
        &format!("{}.id", node.name),
    )?;
    let name = if name_required {
        node.required_child_text("name")?
    } else {
        node.optional_child_text("name").unwrap_or_default()
    };

    Ok(EntityMeta {
        id,
        name,
        comment: node.optional_child_text("comment"),
        creation_time: node.optional_child_text("creation_time"),
        modification_time: node.optional_child_text("modification_time"),
        owner: parse_owner(node)?,
        in_use: node
            .optional_child_text("in_use")
            .map(|value| parse_bool(&value, "in_use"))
            .transpose()?
            .unwrap_or(false),
        writable: node
            .optional_child_text("writable")
            .map(|value| parse_bool(&value, "writable"))
            .transpose()?
            .unwrap_or(false),
    })
}

pub(crate) fn parse_entity_meta(node: &XmlNode) -> Result<EntityMeta, ParseError> {
    parse_entity_meta_with_name(node, true)
}

pub(crate) fn parse_entity_meta_optional_name(node: &XmlNode) -> Result<EntityMeta, ParseError> {
    parse_entity_meta_with_name(node, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity_node(id: Option<&str>, name: &str) -> XmlNode {
        let mut attributes = HashMap::new();
        if let Some(id) = id {
            attributes.insert("id".to_string(), id.to_string());
        }
        XmlNode {
            name: "schedule".to_string(),
            attributes,
            text: String::new(),
            raw_text: None,
            children: vec![XmlNode {
                name: "name".to_string(),
                attributes: HashMap::new(),
                text: name.to_string(),
                raw_text: None,
                children: Vec::new(),
            }],
        }
    }

    #[test]
    fn parse_named_entity_treats_empty_id_as_absent() {
        let root = XmlNode {
            name: "task".to_string(),
            attributes: HashMap::new(),
            text: String::new(),
            raw_text: None,
            children: vec![entity_node(Some(""), "")],
        };

        let parsed = parse_named_entity(&root, "schedule").expect("empty id parses");

        assert_eq!(parsed, None);
    }

    #[test]
    fn parse_named_entity_rejects_invalid_non_empty_id() {
        let root = XmlNode {
            name: "task".to_string(),
            attributes: HashMap::new(),
            text: String::new(),
            raw_text: None,
            children: vec![entity_node(Some("not valid"), "Weekly")],
        };

        let error = parse_named_entity(&root, "schedule").expect_err("invalid id should fail");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, value }
                if field == "schedule.id" && value == "not valid"
        ));
    }

    #[test]
    fn parse_score_rejects_non_finite_values() {
        assert_eq!(parse_score("7.5"), Some(7.5));
        assert_eq!(parse_score("NaN"), None);
        assert_eq!(parse_score("inf"), None);
        assert_eq!(parse_score("-inf"), None);
    }

    #[test]
    fn parse_document_preserves_predefined_and_character_references() {
        let root = parse_document(
            br#"<?xml version="1.0"?><!-- metadata --><?test instruction?><!DOCTYPE root><root attr="A &amp; B"><value>A &amp; B &lt; &#x21;&#33;</value></root>"#,
        )
        .expect("valid references should parse");

        assert_eq!(root.attr("attr"), Some("A & B"));
        assert_eq!(root.child_text("value").as_deref(), Some("A & B < !!"));
    }

    #[test]
    fn parse_document_retains_original_padded_leaf_text() {
        let root = parse_document(
            br#"<root><plain> up </plain><reference>&#x20;up&#x20;</reference><cdata><![CDATA[ up ]]></cdata><clean>up</clean><empty/></root>"#,
        )
        .expect("padded leaf text should parse");

        assert_eq!(root.child_text("plain").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("plain"), Some(" up "));
        assert_eq!(root.child_text("reference").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("reference"), Some(" up "));
        assert_eq!(root.child_text("cdata").as_deref(), Some("up"));
        assert_eq!(root.child_raw_text("cdata"), Some(" up "));
        assert_eq!(root.child_raw_text("clean"), Some("up"));
        assert_eq!(root.child_raw_text("empty"), Some(""));
    }

    #[test]
    fn parse_document_rejects_unknown_entity_references() {
        let error =
            parse_document(b"<root>&unknown;</root>").expect_err("unknown entity should fail");

        assert!(matches!(
            error,
            ParseError::InvalidValue { field, value }
                if field == "entity reference" && value == "unknown"
        ));

        assert!(matches!(
            parse_document(b"&amp;<root/>"),
            Err(ParseError::MissingElement(element))
                if element == "root for entity reference"
        ));
    }
}
