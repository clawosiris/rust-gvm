// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report format command builders.

use gvm_protocol::{Request, XmlCommand};
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::ReportFormatType;
use crate::responses::ParseError;
use crate::types::EntityId;

/// Optional fields for report-format create and modify requests.
#[derive(Debug, Clone, Default)]
pub struct ReportFormatOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional content type string.
    pub content_type: Option<String>,
    /// Optional report format type.
    pub format_type: Option<ReportFormatType>,
}

/// Options for `get_report_formats` requests.
#[derive(Debug, Clone, Default)]
pub struct GetReportFormatsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Build a `create_report_format` request.
#[must_use]
pub fn create_report_format(name: &str, opts: ReportFormatOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_report_format");
    cmd.add_element_with_text("name", name);
    add_report_format_body(&mut cmd, &opts);
    cmd
}

/// Build a `create_report_format` request that clones an existing report format.
#[must_use]
pub fn clone_report_format(report_format_id: &EntityId) -> impl Request {
    XmlCommand::new("create_report_format").child_with_text("copy", report_format_id.as_str())
}

/// Build a `create_report_format` request that imports report-format XML.
///
/// # Errors
/// Returns an error if `report_format_xml` is not a single well-formed XML
/// document.
pub fn import_report_format(report_format_xml: &str) -> Result<impl Request, ParseError> {
    validate_single_xml_document(report_format_xml)?;
    let mut request = Vec::with_capacity(
        "<create_report_format></create_report_format>".len() + report_format_xml.len(),
    );
    request.extend_from_slice(b"<create_report_format>");
    request.extend_from_slice(report_format_xml.as_bytes());
    request.extend_from_slice(b"</create_report_format>");
    Ok(request)
}

/// Build a `get_report_formats` request.
#[must_use]
pub fn get_report_formats(opts: GetReportFormatsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_report_formats");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_report_format` request.
#[must_use]
pub fn get_report_format(report_format_id: &EntityId) -> impl Request {
    XmlCommand::new("get_report_formats")
        .attribute("report_format_id", report_format_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_report_format` request.
#[must_use]
pub fn modify_report_format(report_format_id: &EntityId, opts: ReportFormatOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_report_format")
        .attribute("report_format_id", report_format_id.as_str());
    add_report_format_body(&mut cmd, &opts);
    cmd
}

/// Build a `delete_report_format` request.
#[must_use]
pub fn delete_report_format(report_format_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_report_format")
        .attribute("report_format_id", report_format_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `verify_report_format` request.
#[must_use]
pub fn verify_report_format(report_format_id: &EntityId) -> impl Request {
    XmlCommand::new("verify_report_format").attribute("report_format_id", report_format_id.as_str())
}

fn add_report_format_body(cmd: &mut XmlCommand, opts: &ReportFormatOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    add_text_element(cmd, "content_type", opts.content_type.as_deref());
    if let Some(format_type) = opts.format_type {
        cmd.add_element_with_text("type", format_type.as_gmp_str());
    }
}

fn validate_single_xml_document(xml: &str) -> Result<(), ParseError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut completed_root = false;

    loop {
        match reader.read_event()? {
            Event::Start(_) => {
                if completed_root {
                    return Err(ParseError::InvalidValue {
                        field: "report_format_xml".to_string(),
                        value: "multiple root elements".to_string(),
                    });
                }
                saw_root = true;
                depth += 1;
            }
            Event::Empty(_) => {
                if completed_root {
                    return Err(ParseError::InvalidValue {
                        field: "report_format_xml".to_string(),
                        value: "multiple root elements".to_string(),
                    });
                }
                saw_root = true;
                completed_root = true;
            }
            Event::End(_) => {
                if depth == 0 {
                    return Err(ParseError::InvalidValue {
                        field: "report_format_xml".to_string(),
                        value: "unmatched end tag".to_string(),
                    });
                }
                depth -= 1;
                if depth == 0 {
                    completed_root = true;
                }
            }
            Event::Text(event) => {
                if depth == 0 && !std::str::from_utf8(event.as_ref())?.trim().is_empty() {
                    return Err(ParseError::InvalidValue {
                        field: "report_format_xml".to_string(),
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
                    field: "report_format_xml".to_string(),
                    value: "content outside root element".to_string(),
                });
            }
            Event::Eof => {
                if saw_root && depth == 0 {
                    return Ok(());
                }
                return Err(ParseError::MissingElement("root".to_string()));
            }
            Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::Comment(_)
            | Event::CData(_)
            | Event::GeneralRef(_) => {}
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
    fn report_format_commands_build_xml() {
        let rendered = xml(create_report_format(
            "rf",
            ReportFormatOpts {
                format_type: Some(ReportFormatType::Pdf),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<type>pdf</type>"));
        assert_eq!(
            xml(clone_report_format(&id("rf1"))),
            "<create_report_format><copy>rf1</copy></create_report_format>"
        );
        assert_eq!(
            xml(import_report_format(
                r#"<get_report_formats_response status="200" status_text="OK"><report_format id="rf1"><name>Imported</name></report_format></get_report_formats_response>"#
            )
            .expect("valid report format XML")),
            r#"<create_report_format><get_report_formats_response status="200" status_text="OK"><report_format id="rf1"><name>Imported</name></report_format></get_report_formats_response></create_report_format>"#
        );
        assert!(import_report_format(
            r#"<get_report_formats_response status="200" status_text="OK"/></create_report_format><delete_task/>"#
        )
        .is_err());
        assert!(import_report_format(
            r#"prefix<get_report_formats_response status="200" status_text="OK"/>"#
        )
        .is_err());
        assert!(import_report_format(
            r#"<get_report_formats_response status="200" status_text="OK"/>suffix"#
        )
        .is_err());
        assert!(import_report_format("").is_err());
        assert_eq!(
            xml(get_report_format(&id("rf1"))),
            "<get_report_formats details=\"1\" report_format_id=\"rf1\"/>"
        );
    }

    #[test]
    fn report_format_get_modify_delete_verify_build_xml() {
        let rendered = xml(get_report_formats(GetReportFormatsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_report_format(
            &id("rf1"),
            ReportFormatOpts {
                comment: Some("updated".into()),
                ..Default::default()
            },
        ));
        assert_eq!(rendered, "<modify_report_format report_format_id=\"rf1\"><comment>updated</comment></modify_report_format>");
        assert_eq!(
            xml(delete_report_format(&id("rf1"), false)),
            "<delete_report_format report_format_id=\"rf1\" ultimate=\"0\"/>"
        );
        assert_eq!(
            xml(verify_report_format(&id("rf1"))),
            "<verify_report_format report_format_id=\"rf1\"/>"
        );
    }
}
