// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Report configuration command builders.

use gvm_protocol::XmlCommand;

use crate::common::{add_text_element, bool_str};

/// Optional fields for `create_report_config` requests.
#[derive(Debug, Default)]
pub struct CreateReportConfigOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
}

/// Optional fields for `delete_report_config` requests.
#[derive(Debug, Default)]
pub struct DeleteReportConfigOpts {
    /// Whether to permanently delete the report configuration.
    pub ultimate: Option<bool>,
}

/// Options for `get_report_configs` requests.
#[derive(Debug, Default)]
pub struct GetReportConfigsOpts {
    /// Optional inline filter expression.
    pub filter: Option<String>,
    /// Optional offset for the first row.
    pub first: Option<u32>,
    /// Optional row count limit.
    pub rows: Option<u32>,
}

/// Optional fields for `modify_report_config` requests.
#[derive(Debug, Default)]
pub struct ModifyReportConfigOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
}

/// Build a `create_report_config` request.
#[must_use]
pub fn create_report_config(name: &str, report_format_id: &str) -> XmlCommand {
    create_report_config_opts(name, report_format_id, CreateReportConfigOpts::default())
}

/// Build a `create_report_config` request with optional fields.
#[must_use]
pub fn create_report_config_opts(
    name: &str,
    report_format_id: &str,
    opts: CreateReportConfigOpts,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_report_config");
    cmd.add_element_with_text("name", name);
    cmd.add_element_with_text("report_format_id", report_format_id);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    cmd
}

/// Build a clone request for an existing report configuration.
#[must_use]
pub fn clone_report_config(id: &str) -> XmlCommand {
    XmlCommand::new("create_report_config").child_with_text("copy", id)
}

/// Build a `delete_report_config` request.
#[must_use]
pub fn delete_report_config(id: &str) -> XmlCommand {
    delete_report_config_opts(id, DeleteReportConfigOpts::default())
}

/// Build a `delete_report_config` request with optional fields.
#[must_use]
pub fn delete_report_config_opts(id: &str, opts: DeleteReportConfigOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("delete_report_config").attribute("report_config_id", id);
    if let Some(ultimate) = opts.ultimate {
        cmd = cmd.attribute("ultimate", bool_str(ultimate));
    }
    cmd
}

/// Build a `get_report_configs` request.
#[must_use]
pub fn get_report_configs() -> XmlCommand {
    get_report_configs_opts(GetReportConfigsOpts::default())
}

/// Build a `get_report_configs` request with optional attributes.
#[must_use]
pub fn get_report_configs_opts(opts: GetReportConfigsOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_report_configs");
    if let Some(filter) = opts.filter.filter(|filter| !filter.is_empty()) {
        cmd = cmd.attribute("filter", &filter);
    }
    if let Some(first) = opts.first {
        cmd = cmd.attribute("first", &first.to_string());
    }
    if let Some(rows) = opts.rows {
        cmd = cmd.attribute("rows", &rows.to_string());
    }
    cmd
}

/// Build a `get_report_config` request.
#[must_use]
pub fn get_report_config(id: &str) -> XmlCommand {
    XmlCommand::new("get_report_configs").attribute("report_config_id", id)
}

/// Build a `modify_report_config` request.
#[must_use]
pub fn modify_report_config(id: &str, opts: ModifyReportConfigOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_report_config").attribute("report_config_id", id);
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    #[test]
    fn report_config_commands_build_xml() {
        assert_eq!(
            xml(create_report_config("cfg", "rf1")),
            "<create_report_config><name>cfg</name><report_format_id>rf1</report_format_id></create_report_config>"
        );
        assert_eq!(
            xml(get_report_config("cfg1")),
            "<get_report_configs report_config_id=\"cfg1\"/>"
        );
        assert_eq!(
            xml(clone_report_config("cfg1")),
            "<create_report_config><copy>cfg1</copy></create_report_config>"
        );
    }

    #[test]
    fn report_config_options_build_xml() {
        assert_eq!(
            xml(create_report_config_opts(
                "cfg",
                "rf1",
                CreateReportConfigOpts {
                    comment: Some("note".into())
                }
            )),
            "<create_report_config><name>cfg</name><report_format_id>rf1</report_format_id><comment>note</comment></create_report_config>"
        );
        assert_eq!(
            xml(modify_report_config(
                "cfg1",
                ModifyReportConfigOpts {
                    name: Some("updated".into()),
                    comment: Some("comment".into())
                }
            )),
            "<modify_report_config report_config_id=\"cfg1\"><name>updated</name><comment>comment</comment></modify_report_config>"
        );
    }

    #[test]
    fn report_config_get_and_delete_build_xml() {
        assert_eq!(xml(get_report_configs()), "<get_report_configs/>");
        assert_eq!(
            xml(get_report_configs_opts(GetReportConfigsOpts {
                filter: Some("name=cfg".into()),
                first: Some(10),
                rows: Some(25)
            })),
            "<get_report_configs filter=\"name=cfg\" first=\"10\" rows=\"25\"/>"
        );
        assert_eq!(
            xml(delete_report_config("cfg1")),
            "<delete_report_config report_config_id=\"cfg1\"/>"
        );
        assert_eq!(
            xml(delete_report_config_opts(
                "cfg1",
                DeleteReportConfigOpts {
                    ultimate: Some(true)
                }
            )),
            "<delete_report_config report_config_id=\"cfg1\" ultimate=\"1\"/>"
        );
    }
}
