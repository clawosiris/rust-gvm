// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Target response models.

use gvm_protocol::Response;

use crate::responses::common::{
    count_info, optional_u32, parse_csv_list, parse_document, parse_entity_id, parse_entity_meta,
    parse_named_entity, status_from_response, ActionResponse, CountInfo, EntityMeta, NamedEntity,
    ParseError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Target {
    pub meta: EntityMeta,
    pub hosts: Vec<String>,
    pub exclude_hosts: Vec<String>,
    pub alive_tests: Option<String>,
    pub reverse_lookup_only: bool,
    pub reverse_lookup_unify: bool,
    pub port_list: Option<NamedEntity>,
    pub ssh_credential: Option<NamedEntity>,
    pub smb_credential: Option<NamedEntity>,
    pub esxi_credential: Option<NamedEntity>,
    pub snmp_credential: Option<NamedEntity>,
    pub max_hosts: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetTargetsResponse {
    pub status: u16,
    pub status_text: String,
    pub items: Vec<Target>,
    pub counts: CountInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateTargetResponse {
    pub status: u16,
    pub status_text: String,
    pub id: crate::EntityId,
}

impl Target {
    fn from_node(node: &crate::responses::common::XmlNode) -> Result<Self, ParseError> {
        Ok(Self {
            meta: parse_entity_meta(node)?,
            hosts: node
                .optional_child_text("hosts")
                .map(|value| parse_csv_list(&value))
                .unwrap_or_default(),
            exclude_hosts: node
                .optional_child_text("exclude_hosts")
                .map(|value| parse_csv_list(&value))
                .unwrap_or_default(),
            alive_tests: node.optional_child_text("alive_tests"),
            reverse_lookup_only: node
                .optional_child_text("reverse_lookup_only")
                .map(|value| crate::responses::common::parse_bool(&value, "reverse_lookup_only"))
                .transpose()?
                .unwrap_or(false),
            reverse_lookup_unify: node
                .optional_child_text("reverse_lookup_unify")
                .map(|value| crate::responses::common::parse_bool(&value, "reverse_lookup_unify"))
                .transpose()?
                .unwrap_or(false),
            port_list: parse_named_entity(node, "port_list")?,
            ssh_credential: parse_named_entity(node, "ssh_credential")?,
            smb_credential: parse_named_entity(node, "smb_credential")?,
            esxi_credential: parse_named_entity(node, "esxi_credential")?,
            snmp_credential: parse_named_entity(node, "snmp_credential")?,
            max_hosts: optional_u32(node, "max_hosts", "max_hosts")?,
        })
    }
}

impl GetTargetsResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let items = root
            .children_named("target")
            .map(Target::from_node)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            status,
            status_text,
            items,
            counts: count_info(&root, "target_count")?,
        })
    }
}

impl CreateTargetResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        let id = parse_entity_id(
            root.attr("id")
                .ok_or_else(|| ParseError::MissingElement("id".to_string()))?,
            "id",
        )?;
        Ok(Self {
            status,
            status_text,
            id,
        })
    }
}

pub type ModifyTargetResponse = ActionResponse;
pub type DeleteTargetResponse = ActionResponse;

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_multiple_targets() {
        let response = Response::from(
            r#"<get_targets_response status="200" status_text="OK">
                <target id="t-1">
                    <owner><name>admin</name></owner>
                    <name>Target One</name>
                    <comment>first</comment>
                    <creation_time>2026-01-01T00:00:00Z</creation_time>
                    <modification_time>2026-01-02T00:00:00Z</modification_time>
                    <writable>1</writable>
                    <in_use>0</in_use>
                    <hosts>192.168.1.0/24, 192.168.2.0/24, </hosts>
                    <exclude_hosts>192.168.1.5, ,192.168.1.6</exclude_hosts>
                    <alive_tests>Scan Config Default</alive_tests>
                    <reverse_lookup_only>0</reverse_lookup_only>
                    <reverse_lookup_unify>1</reverse_lookup_unify>
                    <port_list id="pl-1"><name>All TCP</name></port_list>
                    <ssh_credential id="cred-ssh"><name>SSH Cred</name></ssh_credential>
                    <smb_credential id="cred-smb"><name>SMB Cred</name></smb_credential>
                    <esxi_credential id="cred-esxi"><name>ESXi Cred</name></esxi_credential>
                    <snmp_credential id="cred-snmp"><name>SNMP Cred</name></snmp_credential>
                    <max_hosts>4096</max_hosts>
                </target>
                <target id="t-2">
                    <name>Target Two</name>
                    <writable>0</writable>
                    <in_use>1</in_use>
                </target>
                <target_count>2<filtered>2</filtered><page>1</page></target_count>
            </get_targets_response>"#,
        );

        let parsed = GetTargetsResponse::from_response(&response).expect("targets parse");

        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.counts.total, Some(2));
        assert_eq!(parsed.counts.filtered, Some(2));
        assert_eq!(parsed.counts.page, Some(1));
        assert_eq!(
            parsed.items[0]
                .meta
                .owner
                .as_ref()
                .map(|owner| owner.name.as_str()),
            Some("admin")
        );
        assert_eq!(
            parsed.items[0]
                .port_list
                .as_ref()
                .map(|port_list| port_list.name.as_str()),
            Some("All TCP")
        );
        assert_eq!(
            parsed.items[0]
                .ssh_credential
                .as_ref()
                .map(|credential| credential.name.as_str()),
            Some("SSH Cred")
        );
        assert_eq!(
            parsed.items[0]
                .smb_credential
                .as_ref()
                .map(|credential| credential.name.as_str()),
            Some("SMB Cred")
        );
        assert_eq!(
            parsed.items[0]
                .esxi_credential
                .as_ref()
                .map(|credential| credential.name.as_str()),
            Some("ESXi Cred")
        );
        assert_eq!(
            parsed.items[0]
                .snmp_credential
                .as_ref()
                .map(|credential| credential.name.as_str()),
            Some("SNMP Cred")
        );
        assert_eq!(
            parsed.items[0].hosts,
            vec!["192.168.1.0/24".to_string(), "192.168.2.0/24".to_string()]
        );
        assert_eq!(
            parsed.items[0].exclude_hosts,
            vec!["192.168.1.5".to_string(), "192.168.1.6".to_string()]
        );
        assert!(parsed.items[0].reverse_lookup_unify);
        assert!(parsed.items[1].meta.in_use);
    }

    #[test]
    fn parses_empty_targets() {
        let response = Response::from(
            r#"<get_targets_response status="200" status_text="OK"><target_count>0<filtered>0</filtered></target_count></get_targets_response>"#,
        );

        let parsed = GetTargetsResponse::from_response(&response).expect("targets parse");

        assert!(parsed.items.is_empty());
        assert_eq!(parsed.counts.total, Some(0));
    }

    #[test]
    fn parses_create_target_response() {
        let response = Response::from(
            r#"<create_target_response status="201" status_text="OK, resource created" id="t-1"/>"#,
        );

        let parsed = CreateTargetResponse::from_response(&response).expect("create parses");

        assert_eq!(parsed.id.as_str(), "t-1");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_targets_response status="400" status_text="Bad request"/>"#);

        let error = GetTargetsResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 400,
                message
            } if message == "Bad request"
        ));
    }

    #[test]
    fn parses_missing_optional_target_fields() {
        let response = Response::from(
            r#"<get_targets_response status="200" status_text="OK">
                <target id="t-1">
                    <name>Only Required</name>
                </target>
            </get_targets_response>"#,
        );

        let parsed = GetTargetsResponse::from_response(&response).expect("targets parse");
        let target = &parsed.items[0];

        assert_eq!(target.meta.comment, None);
        assert!(target.hosts.is_empty());
        assert!(target.exclude_hosts.is_empty());
        assert_eq!(target.port_list, None);
        assert_eq!(target.ssh_credential, None);
        assert_eq!(target.smb_credential, None);
        assert_eq!(target.esxi_credential, None);
        assert_eq!(target.snmp_credential, None);
        assert!(!target.meta.in_use);
        assert!(!target.meta.writable);
    }
}
