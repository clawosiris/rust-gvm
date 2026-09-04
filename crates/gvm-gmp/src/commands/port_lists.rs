// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Port list command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::PortRangeType;
use crate::responses::{
    CreatePortListResponse, CreatePortRangeResponse, DeletePortListResponse,
    DeletePortRangeResponse, GetPortListsResponse, ModifyPortListResponse,
};
use crate::types::EntityId;
use crate::GmpRequest;

/// Optional fields for port-list create requests.
#[derive(Debug, Clone, Default)]
pub struct PortListOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Optional port range expression.
    pub port_range: Option<String>,
}

/// Replacement fields for port-list modify requests.
///
/// `modify_port_list` uses replacement semantics: gvmd stores an empty string
/// for each omitted field. Port ranges are changed separately with
/// [`create_port_range`] and [`delete_port_range`].
#[derive(Debug, Clone, Default)]
pub struct ModifyPortListOpts {
    /// Replacement name. Omission clears the current name.
    pub name: Option<String>,
    /// Replacement comment. Omission clears the current comment.
    pub comment: Option<String>,
}

/// Options for `get_port_lists` requests.
#[derive(Debug, Clone, Default)]
pub struct GetPortListsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Semantic request for listing port lists.
#[derive(Debug, Clone, Default)]
pub struct GetPortListsRequest(GetPortListsOpts);

impl GetPortListsRequest {
    /// Create a port-list list request.
    #[must_use]
    pub fn new(opts: GetPortListsOpts) -> Self {
        Self(opts)
    }
}

impl Request for GetPortListsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_port_lists(self.0.clone()).to_bytes()
    }
}

impl GmpRequest for GetPortListsRequest {
    type Response = GetPortListsResponse;
}

macro_rules! port_list_id_request {
    ($name:ident, $response:ty, $builder:ident) => {
        #[doc = concat!("Semantic request backed by [`", stringify!($builder), "`].")]
        #[derive(Debug, Clone)]
        pub struct $name(EntityId);

        impl $name {
            /// Create the semantic request.
            #[must_use]
            pub fn new(port_list_id: EntityId) -> Self {
                Self(port_list_id)
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

port_list_id_request!(GetPortListRequest, GetPortListsResponse, get_port_list);
port_list_id_request!(
    ClonePortListRequest,
    CreatePortListResponse,
    clone_port_list
);

/// Semantic request for creating a port list.
#[derive(Debug, Clone)]
pub struct CreatePortListRequest {
    name: String,
    opts: PortListOpts,
}

impl CreatePortListRequest {
    /// Create a port-list creation request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: PortListOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for CreatePortListRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_port_list(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for CreatePortListRequest {
    type Response = CreatePortListResponse;
}

/// Semantic request for modifying a port list.
#[derive(Debug, Clone)]
pub struct ModifyPortListRequest {
    port_list_id: EntityId,
    opts: ModifyPortListOpts,
}

impl ModifyPortListRequest {
    /// Create a port-list modification request.
    #[must_use]
    pub fn new(port_list_id: EntityId, opts: ModifyPortListOpts) -> Self {
        Self { port_list_id, opts }
    }
}

impl Request for ModifyPortListRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_port_list(&self.port_list_id, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for ModifyPortListRequest {
    type Response = ModifyPortListResponse;
}

/// Semantic request for deleting a port list.
#[derive(Debug, Clone)]
pub struct DeletePortListRequest {
    port_list_id: EntityId,
    ultimate: bool,
}

impl DeletePortListRequest {
    /// Create a port-list deletion request.
    #[must_use]
    pub fn new(port_list_id: EntityId, ultimate: bool) -> Self {
        Self {
            port_list_id,
            ultimate,
        }
    }
}

impl Request for DeletePortListRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_port_list(&self.port_list_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeletePortListRequest {
    type Response = DeletePortListResponse;
}

/// Semantic request for adding a range to a port list.
#[derive(Debug, Clone)]
pub struct CreatePortRangeRequest {
    port_list_id: EntityId,
    range_type: PortRangeType,
    start: u16,
    end: u16,
}

impl CreatePortRangeRequest {
    /// Create a port-range creation request.
    #[must_use]
    pub fn new(port_list_id: EntityId, range_type: PortRangeType, start: u16, end: u16) -> Self {
        Self {
            port_list_id,
            range_type,
            start,
            end,
        }
    }
}

impl Request for CreatePortRangeRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_port_range(&self.port_list_id, self.range_type, self.start, self.end).to_bytes()
    }
}

impl GmpRequest for CreatePortRangeRequest {
    type Response = CreatePortRangeResponse;
}

/// Semantic request for deleting a port range.
#[derive(Debug, Clone)]
pub struct DeletePortRangeRequest(EntityId);

impl DeletePortRangeRequest {
    /// Create a port-range deletion request.
    #[must_use]
    pub fn new(port_range_id: EntityId) -> Self {
        Self(port_range_id)
    }
}

impl Request for DeletePortRangeRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_port_range(&self.0).to_bytes()
    }
}

impl GmpRequest for DeletePortRangeRequest {
    type Response = DeletePortRangeResponse;
}

/// Build a clone request for an existing port list.
#[must_use]
pub fn clone_port_list(port_list_id: &EntityId) -> impl Request {
    XmlCommand::new("create_port_list").child_with_text("copy", port_list_id.as_str())
}

/// Build a `create_port_list` request.
#[must_use]
pub fn create_port_list(name: &str, opts: PortListOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_port_list");
    cmd.add_element_with_text("name", name);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    add_text_element(&mut cmd, "port_range", opts.port_range.as_deref());
    cmd
}

/// Build a `create_port_range` request.
#[must_use]
pub fn create_port_range(
    port_list_id: &EntityId,
    range_type: PortRangeType,
    start: u16,
    end: u16,
) -> impl Request {
    XmlCommand::new("create_port_range")
        .attribute("port_list_id", port_list_id.as_str())
        .attribute("type", range_type.as_port_range_type())
        .attribute("start", &start.to_string())
        .attribute("end", &end.to_string())
}

/// Build a `get_port_lists` request.
#[must_use]
pub fn get_port_lists(opts: GetPortListsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_port_lists");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_port_list` request.
#[must_use]
pub fn get_port_list(port_list_id: &EntityId) -> impl Request {
    XmlCommand::new("get_port_lists")
        .attribute("port_list_id", port_list_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_port_list` request.
///
/// This is a full replacement of the port list's name and comment: gvmd
/// clears either field when its element is omitted. Port ranges must instead
/// be changed with [`create_port_range`] or [`delete_port_range`].
#[must_use]
pub fn modify_port_list(port_list_id: &EntityId, opts: ModifyPortListOpts) -> impl Request {
    let mut cmd =
        XmlCommand::new("modify_port_list").attribute("port_list_id", port_list_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    cmd
}

/// Build a `delete_port_list` request.
#[must_use]
pub fn delete_port_list(port_list_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_port_list")
        .attribute("port_list_id", port_list_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

/// Build a `delete_port_range` request.
#[must_use]
pub fn delete_port_range(port_range_id: &EntityId) -> impl Request {
    XmlCommand::new("delete_port_range").attribute("port_range_id", port_range_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    #[test]
    fn semantic_port_list_requests_match_builder_bytes_and_responses() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let port_list_id = id("port-list-1");
        let port_range_id = id("port-range-1");
        let list_opts = GetPortListsOpts {
            filter_string: Some("name=web".into()),
            details: Some(true),
            ..Default::default()
        };
        let request = GetPortListsRequest::new(list_opts.clone());
        assert_eq!(request.to_bytes(), get_port_lists(list_opts).to_bytes());
        associated::<_, GetPortListsResponse>(&request);

        let request = GetPortListRequest::new(port_list_id.clone());
        assert_eq!(request.to_bytes(), get_port_list(&port_list_id).to_bytes());
        associated::<_, GetPortListsResponse>(&request);

        let create_opts = PortListOpts {
            comment: Some("web services".into()),
            port_range: Some("T:80,443".into()),
        };
        let request = CreatePortListRequest::new("web", create_opts.clone());
        assert_eq!(
            request.to_bytes(),
            create_port_list("web", create_opts).to_bytes()
        );
        associated::<_, CreatePortListResponse>(&request);

        let request = ClonePortListRequest::new(port_list_id.clone());
        assert_eq!(
            request.to_bytes(),
            clone_port_list(&port_list_id).to_bytes()
        );
        associated::<_, CreatePortListResponse>(&request);

        let modify_opts = ModifyPortListOpts {
            name: Some("renamed".into()),
            comment: Some(String::new()),
        };
        let request = ModifyPortListRequest::new(port_list_id.clone(), modify_opts.clone());
        assert_eq!(
            request.to_bytes(),
            modify_port_list(&port_list_id, modify_opts).to_bytes()
        );
        associated::<_, ModifyPortListResponse>(&request);

        let request = DeletePortListRequest::new(port_list_id.clone(), true);
        assert_eq!(
            request.to_bytes(),
            delete_port_list(&port_list_id, true).to_bytes()
        );
        associated::<_, DeletePortListResponse>(&request);

        let request =
            CreatePortRangeRequest::new(port_list_id.clone(), PortRangeType::Tcp, 80, 443);
        assert_eq!(
            request.to_bytes(),
            create_port_range(&port_list_id, PortRangeType::Tcp, 80, 443).to_bytes()
        );
        associated::<_, CreatePortRangeResponse>(&request);

        let request = DeletePortRangeRequest::new(port_range_id.clone());
        assert_eq!(
            request.to_bytes(),
            delete_port_range(&port_range_id).to_bytes()
        );
        associated::<_, DeletePortRangeResponse>(&request);
    }

    #[test]
    fn port_list_commands_build_xml() {
        let rendered = xml(create_port_list(
            "ports",
            PortListOpts {
                port_range: Some("T:1-5".into()),
                ..Default::default()
            },
        ));
        assert!(rendered.contains("<port_range>T:1-5</port_range>"));
        assert_eq!(
            xml(clone_port_list(&id("pl1"))),
            "<create_port_list><copy>pl1</copy></create_port_list>"
        );
        assert_eq!(
            xml(get_port_list(&id("pl1"))),
            "<get_port_lists details=\"1\" port_list_id=\"pl1\"/>"
        );
        assert_eq!(
            xml(create_port_range(&id("pl1"), PortRangeType::Tcp, 1, 5)),
            "<create_port_range end=\"5\" port_list_id=\"pl1\" start=\"1\" type=\"TCP\"/>"
        );
    }

    #[test]
    fn port_list_get_modify_delete_build_xml() {
        let rendered = xml(get_port_lists(GetPortListsOpts {
            details: Some(true),
            ..Default::default()
        }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_port_list(
            &id("pl1"),
            ModifyPortListOpts {
                name: Some("Renamed ports".into()),
                comment: Some("updated".into()),
            },
        ));
        assert_eq!(
            rendered,
            "<modify_port_list port_list_id=\"pl1\"><name>Renamed ports</name><comment>updated</comment></modify_port_list>"
        );
        assert_eq!(
            xml(modify_port_list(&id("pl1"), ModifyPortListOpts::default())),
            "<modify_port_list port_list_id=\"pl1\"/>"
        );
        assert_eq!(
            xml(delete_port_list(&id("pl1"), false)),
            "<delete_port_list port_list_id=\"pl1\" ultimate=\"0\"/>"
        );
        assert_eq!(
            xml(delete_port_range(&id("pr1"))),
            "<delete_port_range port_range_id=\"pr1\"/>"
        );
    }
}
