// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report format command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr,
    validate_single_xml_document,
};
use crate::enums::ReportFormatType;
use crate::responses::{
    CreateReportFormatResponse, DeleteReportFormatResponse, GetReportFormatsResponse,
    ModifyReportFormatResponse, ParseError, VerifyReportFormatResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

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

/// Semantic request for creating a report format.
#[derive(Debug, Clone)]
pub struct CreateReportFormatRequest {
    name: String,
    opts: ReportFormatOpts,
}

impl CreateReportFormatRequest {
    /// Create a report-format creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: ReportFormatOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreateReportFormatRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_report_format(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreateReportFormatRequest {
    type Response = CreateReportFormatResponse;
}

macro_rules! report_format_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(report_format_id: EntityId) -> Self {
                Self(report_format_id)
            }
        }

        impl Request for $name {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.0).to_bytes()
            }
        }

        impl GmpRequest for $name {
            type Response = $response;
        }
    };
}

report_format_id_request!(
    CloneReportFormatRequest,
    CreateReportFormatResponse,
    clone_report_format
);
report_format_id_request!(
    GetReportFormatRequest,
    GetReportFormatsResponse,
    get_report_format
);
report_format_id_request!(
    VerifyReportFormatRequest,
    VerifyReportFormatResponse,
    verify_report_format
);

/// Semantic request for importing report-format XML.
#[derive(Debug, Clone)]
pub struct ImportReportFormatRequest {
    bytes: Vec<u8>,
}

impl ImportReportFormatRequest {
    /// Validate import XML and create a report-format import request.
    ///
    /// # Errors
    /// Returns an error under the same conditions as [`import_report_format`].
    pub fn new(report_format_xml: &str) -> Result<Self, ParseError> {
        Ok(Self {
            bytes: import_report_format(report_format_xml)?.to_bytes(),
        })
    }
}

impl Request for ImportReportFormatRequest {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl GmpRequest for ImportReportFormatRequest {
    type Response = CreateReportFormatResponse;
}

/// Semantic request for listing report formats.
#[derive(Debug, Clone, Default)]
pub struct GetReportFormatsRequest(GetReportFormatsOpts);

impl GetReportFormatsRequest {
    /// Create a report-format list request.
    #[must_use]
    pub fn new(opts: GetReportFormatsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetReportFormatsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_report_formats(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetReportFormatsRequest {
    type Response = GetReportFormatsResponse;
}

/// Semantic request for modifying a report format.
#[derive(Debug, Clone)]
pub struct ModifyReportFormatRequest {
    report_format_id: EntityId,
    opts: ReportFormatOpts,
}

impl ModifyReportFormatRequest {
    /// Create a report-format modification request.
    #[must_use]
    pub fn new(report_format_id: EntityId, opts: ReportFormatOpts) -> Self {
        Self {
            report_format_id,
            opts,
        }
    }
}

impl Request for ModifyReportFormatRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_report_format(&self.report_format_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyReportFormatRequest {
    type Response = ModifyReportFormatResponse;
}

/// Semantic request for deleting a report format.
#[derive(Debug, Clone)]
pub struct DeleteReportFormatRequest {
    report_format_id: EntityId,
    ultimate: bool,
}

impl DeleteReportFormatRequest {
    /// Create a report-format deletion request.
    #[must_use]
    pub fn new(report_format_id: EntityId, ultimate: bool) -> Self {
        Self {
            report_format_id,
            ultimate,
        }
    }
}

impl Request for DeleteReportFormatRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_report_format(&self.report_format_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteReportFormatRequest {
    type Response = DeleteReportFormatResponse;
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
    validate_single_xml_document(report_format_xml, "report_format_xml", None)?;
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
        assert!(import_report_format(
            r#"<?xml version="1.0"?><get_report_formats_response status="200" status_text="OK"/>"#
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

    #[test]
    fn semantic_requests_match_all_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let report_format_id = id("rf-1");
        let opts = ReportFormatOpts {
            comment: Some("comment".into()),
            content_type: Some("application/example".into()),
            format_type: Some(ReportFormatType::Pdf),
        };
        let get_opts = GetReportFormatsOpts {
            details: Some(true),
            ..Default::default()
        };
        let import_xml = r#"<get_report_formats_response status="200" status_text="OK"/>"#;

        let create = CreateReportFormatRequest::new("format", opts.clone());
        assert_eq!(
            create.to_bytes(),
            create_report_format("format", opts.clone()).to_bytes()
        );
        associated::<_, CreateReportFormatResponse>(&create);

        let clone = CloneReportFormatRequest::new(report_format_id.clone());
        assert_eq!(
            clone.to_bytes(),
            clone_report_format(&report_format_id).to_bytes()
        );
        associated::<_, CreateReportFormatResponse>(&clone);

        let import = ImportReportFormatRequest::new(import_xml).expect("valid import XML");
        assert_eq!(
            import.to_bytes(),
            import_report_format(import_xml)
                .expect("valid import XML")
                .to_bytes()
        );
        associated::<_, CreateReportFormatResponse>(&import);

        let invalid_import = "<one/><two/>";
        assert!(matches!(
            import_report_format(invalid_import),
            Err(ParseError::InvalidValue { field, value })
                if field == "report_format_xml" && value == "multiple root elements"
        ));
        assert!(matches!(
            ImportReportFormatRequest::new(invalid_import),
            Err(ParseError::InvalidValue { field, value })
                if field == "report_format_xml" && value == "multiple root elements"
        ));

        let list = GetReportFormatsRequest::new(get_opts.clone());
        assert_eq!(list.to_bytes(), get_report_formats(get_opts).to_bytes());
        associated::<_, GetReportFormatsResponse>(&list);

        let get = GetReportFormatRequest::new(report_format_id.clone());
        assert_eq!(
            get.to_bytes(),
            get_report_format(&report_format_id).to_bytes()
        );
        associated::<_, GetReportFormatsResponse>(&get);

        let modify = ModifyReportFormatRequest::new(report_format_id.clone(), opts.clone());
        assert_eq!(
            modify.to_bytes(),
            modify_report_format(&report_format_id, opts).to_bytes()
        );
        associated::<_, ModifyReportFormatResponse>(&modify);

        let delete = DeleteReportFormatRequest::new(report_format_id.clone(), true);
        assert_eq!(
            delete.to_bytes(),
            delete_report_format(&report_format_id, true).to_bytes()
        );
        associated::<_, DeleteReportFormatResponse>(&delete);

        let verify = VerifyReportFormatRequest::new(report_format_id.clone());
        assert_eq!(
            verify.to_bytes(),
            verify_report_format(&report_format_id).to_bytes()
        );
        associated::<_, VerifyReportFormatResponse>(&verify);
    }
}
