// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Target command builders.

use gvm_protocol::{Request, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_scalar_id_update, add_text_element, bool_str,
    set_optional_bool_attr,
};
use crate::enums::AliveTest;
use crate::responses::{
    CreateTargetResponse, DeleteTargetResponse, GetTargetsResponse, ModifyTargetResponse,
};
use crate::target::{TargetHost, TargetHosts, TargetPortSelection};
use crate::types::{EntityId, ScalarUpdate, ServicePort};
use crate::GmpRequest;

/// Required and optional fields for `create_target` requests.
#[derive(Debug, Clone)]
pub struct CreateTargetOpts {
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Validated included and excluded target hosts.
    pub hosts: TargetHosts,
    /// Optional alive-test strategy.
    pub alive_test: Option<AliveTest>,
    /// Required port list or direct port range.
    pub ports: TargetPortSelection,
    /// Optional SSH credential identifier.
    pub ssh_credential_id: Option<EntityId>,
    /// Optional SSH service port nested below the SSH credential.
    pub ssh_credential_port: Option<ServicePort>,
    /// Optional SSH privilege-escalation credential identifier.
    pub ssh_elevate_credential_id: Option<EntityId>,
    /// Optional SMB credential identifier.
    pub smb_credential_id: Option<EntityId>,
    /// Optional Kerberos 5 credential identifier.
    pub krb5_credential_id: Option<EntityId>,
    /// Optional `ESXi` credential identifier.
    pub esxi_credential_id: Option<EntityId>,
    /// Optional SNMP credential identifier.
    pub snmp_credential_id: Option<EntityId>,
    /// Whether reverse lookup only should be enabled.
    pub reverse_lookup_only: Option<bool>,
    /// Whether reverse-lookup unification should be enabled.
    pub reverse_lookup_unify: Option<bool>,
    /// Whether multiple IP addresses of one host may be scanned simultaneously.
    pub allow_simultaneous_ips: Option<bool>,
}

impl CreateTargetOpts {
    /// Create options for the required manual target host selection.
    #[must_use]
    pub fn new(hosts: TargetHosts, ports: TargetPortSelection) -> Self {
        Self {
            comment: None,
            hosts,
            alive_test: None,
            ports,
            ssh_credential_id: None,
            ssh_credential_port: None,
            ssh_elevate_credential_id: None,
            smb_credential_id: None,
            krb5_credential_id: None,
            esxi_credential_id: None,
            snmp_credential_id: None,
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            allow_simultaneous_ips: None,
        }
    }
}

/// Options for `get_targets` requests.
#[derive(Debug, Clone, Default)]
pub struct GetTargetsOpts {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

/// Optional fields for `modify_target` requests.
#[derive(Debug, Clone, Default)]
pub struct ModifyTargetOpts {
    /// Optional resource name.
    pub name: Option<String>,
    /// Optional comment text included in the request.
    pub comment: Option<String>,
    /// Atomic replacement of included and excluded hosts, or `None` to omit.
    pub hosts: Option<TargetHosts>,
    /// Optional alive-test strategy.
    pub alive_test: Option<AliveTest>,
    /// Port-list relationship update: omit or set/replace.
    ///
    /// Current gvmd versions do not support detaching an existing port list.
    /// Passing [`ScalarUpdate::Clear`] is therefore rejected by
    /// [`modify_target`] instead of being translated to a protocol sentinel.
    pub port_list_id: ScalarUpdate<EntityId>,
    /// SSH credential relationship update: omit, set, or detach.
    pub ssh_credential_id: ScalarUpdate<EntityId>,
    /// SSH service-port update: omit, set/replace, or reset to gvmd's default.
    ///
    /// Setting or clearing the port requires [`Self::ssh_credential_id`] to
    /// contain [`ScalarUpdate::Set`] because GMP nests the port below a
    /// credential element carrying the credential identifier. When the
    /// credential is set and this update is omitted, gvmd selects its default
    /// SSH port (22); omitting both updates preserves the existing binding.
    pub ssh_credential_port: ScalarUpdate<ServicePort>,
    /// SSH privilege-escalation credential relationship update: omit, set, or detach.
    pub ssh_elevate_credential_id: ScalarUpdate<EntityId>,
    /// SMB credential relationship update: omit, set, or detach.
    pub smb_credential_id: ScalarUpdate<EntityId>,
    /// Kerberos 5 credential relationship update: omit, set, or detach.
    pub krb5_credential_id: ScalarUpdate<EntityId>,
    /// `ESXi` credential relationship update: omit, set, or detach.
    pub esxi_credential_id: ScalarUpdate<EntityId>,
    /// SNMP credential relationship update: omit, set, or detach.
    pub snmp_credential_id: ScalarUpdate<EntityId>,
    /// Whether reverse lookup only should be enabled.
    pub reverse_lookup_only: Option<bool>,
    /// Whether reverse-lookup unification should be enabled.
    pub reverse_lookup_unify: Option<bool>,
    /// Whether multiple IP addresses of one host may be scanned simultaneously.
    pub allow_simultaneous_ips: Option<bool>,
}

/// Errors raised while building a `create_target` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CreateTargetError {
    /// A service port cannot be encoded without an SSH credential identifier.
    #[error("setting an SSH credential port requires an SSH credential identifier")]
    SshPortWithoutCredential,
    /// An SSH elevation credential requires a separate SSH login credential.
    #[error("setting an SSH elevation credential requires an SSH credential")]
    SshElevateWithoutSshCredential,
    /// The SSH login and elevation credentials must be different.
    #[error("the SSH elevation credential must differ from the SSH credential")]
    SshElevateMatchesSshCredential,
    /// gvmd does not allow SMB and Kerberos credentials on the same target.
    #[error("SMB and Kerberos credentials are mutually exclusive")]
    SmbAndKrb5Credentials,
}

/// Errors raised while building a `modify_target` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModifyTargetError {
    /// gvmd has no wire representation for detaching a target port list.
    #[error("gvmd does not support clearing a target port-list relationship")]
    UnsupportedPortListClear,
    /// A service-port update cannot be encoded without a credential identifier.
    #[error("updating an SSH credential port requires setting the SSH credential identifier")]
    SshPortWithoutCredential,
    /// A service-port update is incompatible with detaching the credential.
    #[error("an SSH credential port cannot be updated while detaching the SSH credential")]
    SshPortWithCredentialClear,
    /// A newly bound elevation credential cannot accompany SSH credential detachment.
    #[error("setting an SSH elevation credential requires an SSH credential")]
    SshElevateWithoutSshCredential,
    /// The SSH login and elevation credentials must be different.
    #[error("the SSH elevation credential must differ from the SSH credential")]
    SshElevateMatchesSshCredential,
    /// gvmd does not allow SMB and Kerberos credentials to be set together.
    #[error("SMB and Kerberos credentials are mutually exclusive")]
    SmbAndKrb5Credentials,
}

/// Semantic request for listing targets.
#[derive(Debug, Clone, Default)]
pub struct GetTargetsRequest {
    opts: GetTargetsOpts,
}

impl GetTargetsRequest {
    /// Create a target-list request.
    #[must_use]
    pub fn new(opts: GetTargetsOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetTargetsRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_targets(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetTargetsRequest {
    type Response = GetTargetsResponse;
}

/// Semantic request for one detailed target.
#[derive(Debug, Clone)]
pub struct GetTargetRequest {
    target_id: EntityId,
}

impl GetTargetRequest {
    /// Create a detailed single-target request.
    #[must_use]
    pub fn new(target_id: EntityId) -> Self {
        Self { target_id }
    }
}

impl Request for GetTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_target(&self.target_id).to_bytes()
    }
}

impl GmpRequest for GetTargetRequest {
    type Response = GetTargetsResponse;
}

/// Semantic request for creating a target.
#[derive(Debug, Clone)]
pub struct CreateTargetRequest {
    name: String,
    opts: CreateTargetOpts,
}

impl CreateTargetRequest {
    /// Validate and create a target-creation request.
    ///
    /// # Errors
    /// Returns the same construction errors as [`create_target`].
    pub fn new(name: impl Into<String>, opts: CreateTargetOpts) -> Result<Self, CreateTargetError> {
        validate_create_target_opts(&opts)?;
        Ok(Self {
            name: name.into(),
            opts,
        })
    }
}

impl Request for CreateTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        create_target_command(&self.name, &self.opts).to_bytes()
    }
}

impl GmpRequest for CreateTargetRequest {
    type Response = CreateTargetResponse;
}

/// Semantic request for modifying a target.
#[derive(Debug, Clone)]
pub struct ModifyTargetRequest {
    target_id: EntityId,
    opts: ModifyTargetOpts,
}

impl ModifyTargetRequest {
    /// Validate and create a target-modification request.
    ///
    /// # Errors
    /// Returns the same construction errors as [`modify_target`].
    pub fn new(target_id: EntityId, opts: ModifyTargetOpts) -> Result<Self, ModifyTargetError> {
        validate_modify_target_opts(&opts)?;
        Ok(Self { target_id, opts })
    }
}

impl Request for ModifyTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        modify_target_command(&self.target_id, &self.opts).to_bytes()
    }
}

impl GmpRequest for ModifyTargetRequest {
    type Response = ModifyTargetResponse;
}

/// Semantic request for deleting a target.
#[derive(Debug, Clone)]
pub struct DeleteTargetRequest {
    target_id: EntityId,
    ultimate: bool,
}

impl DeleteTargetRequest {
    /// Create a target-deletion request.
    #[must_use]
    pub fn new(target_id: EntityId, ultimate: bool) -> Self {
        Self {
            target_id,
            ultimate,
        }
    }
}

impl Request for DeleteTargetRequest {
    fn to_bytes(&self) -> Vec<u8> {
        delete_target(&self.target_id, self.ultimate).to_bytes()
    }
}

impl GmpRequest for DeleteTargetRequest {
    type Response = DeleteTargetResponse;
}

/// Build a clone request for an existing target.
#[must_use]
pub fn clone_target(target_id: &EntityId) -> impl Request {
    XmlCommand::new("create_target").child_with_text("copy", target_id.as_str())
}

/// Build a `create_target` request.
///
/// # Errors
/// Returns [`CreateTargetError::SshPortWithoutCredential`] when a service port
/// is supplied without the SSH credential identifier required by GMP.
pub fn create_target(
    name: &str,
    opts: CreateTargetOpts,
) -> Result<impl Request, CreateTargetError> {
    validate_create_target_opts(&opts)?;
    Ok(create_target_command(name, &opts))
}

fn validate_create_target_opts(opts: &CreateTargetOpts) -> Result<(), CreateTargetError> {
    if opts.ssh_credential_port.is_some() && opts.ssh_credential_id.is_none() {
        return Err(CreateTargetError::SshPortWithoutCredential);
    }
    if opts.ssh_elevate_credential_id.is_some() && opts.ssh_credential_id.is_none() {
        return Err(CreateTargetError::SshElevateWithoutSshCredential);
    }
    if opts.ssh_elevate_credential_id == opts.ssh_credential_id
        && opts.ssh_elevate_credential_id.is_some()
    {
        return Err(CreateTargetError::SshElevateMatchesSshCredential);
    }
    // gvmd enforces this in the GMP create-target handler in gmp.c, before
    // dispatching to the SQL-layer create_target implementation.
    if opts.smb_credential_id.is_some() && opts.krb5_credential_id.is_some() {
        return Err(CreateTargetError::SmbAndKrb5Credentials);
    }
    Ok(())
}

fn create_target_command(name: &str, opts: &CreateTargetOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_target");
    cmd.add_element_with_text("name", name);
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    cmd.add_element_with_text("hosts", &join_hosts(opts.hosts.included()));
    cmd.add_element_with_text("exclude_hosts", &join_hosts(opts.hosts.excluded()));
    if let Some(alive_test) = opts.alive_test {
        cmd.add_element_with_text("alive_tests", alive_test.as_target_name());
    }
    match &opts.ports {
        TargetPortSelection::PortList(port_list_id) => {
            add_optional_id_element(&mut cmd, "port_list", Some(port_list_id));
        }
        TargetPortSelection::PortRange(port_range) => {
            cmd.add_element_with_text("port_range", port_range.as_str());
        }
    }
    add_create_target_credentials(&mut cmd, opts);
    if let Some(value) = opts.reverse_lookup_only {
        cmd.add_element_with_text("reverse_lookup_only", bool_str(value));
    }
    if let Some(value) = opts.reverse_lookup_unify {
        cmd.add_element_with_text("reverse_lookup_unify", bool_str(value));
    }
    if let Some(value) = opts.allow_simultaneous_ips {
        cmd.add_element_with_text("allow_simultaneous_ips", bool_str(value));
    }
    cmd
}

/// Build a `get_targets` request.
#[must_use]
pub fn get_targets(opts: GetTargetsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_targets");
    add_filter_attrs(
        &mut cmd,
        opts.filter_string.as_deref(),
        opts.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

/// Build a `get_target` request.
#[must_use]
pub fn get_target(target_id: &EntityId) -> impl Request {
    XmlCommand::new("get_targets")
        .attribute("target_id", target_id.as_str())
        .attribute("details", "1")
}

/// Build a `modify_target` request.
///
/// # Errors
/// Returns [`ModifyTargetError::UnsupportedPortListClear`] when the port-list
/// update requests clearing. gvmd accepts omission and replacement, but does
/// not define a sentinel for detaching an existing port list.
pub fn modify_target(
    target_id: &EntityId,
    opts: ModifyTargetOpts,
) -> Result<impl Request, ModifyTargetError> {
    validate_modify_target_opts(&opts)?;
    Ok(modify_target_command(target_id, &opts))
}

fn validate_modify_target_opts(opts: &ModifyTargetOpts) -> Result<(), ModifyTargetError> {
    if matches!(opts.port_list_id, ScalarUpdate::Clear) {
        return Err(ModifyTargetError::UnsupportedPortListClear);
    }
    match (&opts.ssh_credential_id, &opts.ssh_credential_port) {
        (ScalarUpdate::Omitted, ScalarUpdate::Set(_) | ScalarUpdate::Clear) => {
            return Err(ModifyTargetError::SshPortWithoutCredential);
        }
        (ScalarUpdate::Clear, ScalarUpdate::Set(_) | ScalarUpdate::Clear) => {
            return Err(ModifyTargetError::SshPortWithCredentialClear);
        }
        _ => {}
    }
    if matches!(opts.ssh_elevate_credential_id, ScalarUpdate::Set(_))
        && matches!(opts.ssh_credential_id, ScalarUpdate::Clear)
    {
        return Err(ModifyTargetError::SshElevateWithoutSshCredential);
    }
    if let (ScalarUpdate::Set(ssh), ScalarUpdate::Set(elevate)) =
        (&opts.ssh_credential_id, &opts.ssh_elevate_credential_id)
    {
        if ssh == elevate {
            return Err(ModifyTargetError::SshElevateMatchesSshCredential);
        }
    }
    if matches!(opts.smb_credential_id, ScalarUpdate::Set(_))
        && matches!(opts.krb5_credential_id, ScalarUpdate::Set(_))
    {
        return Err(ModifyTargetError::SmbAndKrb5Credentials);
    }
    Ok(())
}

fn modify_target_command(target_id: &EntityId, opts: &ModifyTargetOpts) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_target").attribute("target_id", target_id.as_str());
    add_text_element(&mut cmd, "name", opts.name.as_deref());
    add_text_element(&mut cmd, "comment", opts.comment.as_deref());
    if let Some(hosts) = &opts.hosts {
        cmd.add_element_with_text("hosts", &join_hosts(hosts.included()));
        cmd.add_element_with_text("exclude_hosts", &join_hosts(hosts.excluded()));
    }
    if let Some(alive_test) = opts.alive_test {
        cmd.add_element_with_text("alive_tests", alive_test.as_target_name());
    }
    if let ScalarUpdate::Set(port_list_id) = &opts.port_list_id {
        add_optional_id_element(&mut cmd, "port_list", Some(port_list_id));
    }
    add_modify_target_credentials(&mut cmd, opts);
    if let Some(value) = opts.reverse_lookup_only {
        cmd.add_element_with_text("reverse_lookup_only", bool_str(value));
    }
    if let Some(value) = opts.reverse_lookup_unify {
        cmd.add_element_with_text("reverse_lookup_unify", bool_str(value));
    }
    if let Some(value) = opts.allow_simultaneous_ips {
        cmd.add_element_with_text("allow_simultaneous_ips", bool_str(value));
    }
    cmd
}

/// Build a `delete_target` request.
#[must_use]
pub fn delete_target(target_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_target")
        .attribute("target_id", target_id.as_str())
        .attribute("ultimate", bool_str(ultimate))
}

fn add_create_target_credentials(cmd: &mut XmlCommand, opts: &CreateTargetOpts) {
    add_ssh_credential(
        cmd,
        opts.ssh_credential_id.as_ref(),
        opts.ssh_credential_port,
    );
    add_optional_id_element(
        cmd,
        "ssh_elevate_credential",
        opts.ssh_elevate_credential_id.as_ref(),
    );
    add_optional_id_element(cmd, "smb_credential", opts.smb_credential_id.as_ref());
    add_optional_id_element(cmd, "krb5_credential", opts.krb5_credential_id.as_ref());
    add_optional_id_element(cmd, "esxi_credential", opts.esxi_credential_id.as_ref());
    add_optional_id_element(cmd, "snmp_credential", opts.snmp_credential_id.as_ref());
}

fn add_modify_target_credentials(cmd: &mut XmlCommand, opts: &ModifyTargetOpts) {
    match &opts.ssh_credential_id {
        ScalarUpdate::Omitted => {}
        ScalarUpdate::Set(id) => {
            let credential = add_credential(cmd, "ssh_credential", id);
            match opts.ssh_credential_port {
                ScalarUpdate::Omitted => {}
                ScalarUpdate::Set(port) => {
                    credential.add_child_with_text("port", &port.to_string());
                }
                ScalarUpdate::Clear => {
                    // gvmd treats zero on modify as a request to restore port 22.
                    credential.add_child_with_text("port", "0");
                }
            }
        }
        ScalarUpdate::Clear => {
            add_scalar_id_update(cmd, "ssh_credential", &ScalarUpdate::<EntityId>::Clear);
        }
    }
    add_scalar_id_update(
        cmd,
        "ssh_elevate_credential",
        &opts.ssh_elevate_credential_id,
    );
    add_scalar_id_update(cmd, "smb_credential", &opts.smb_credential_id);
    add_scalar_id_update(cmd, "krb5_credential", &opts.krb5_credential_id);
    add_scalar_id_update(cmd, "esxi_credential", &opts.esxi_credential_id);
    add_scalar_id_update(cmd, "snmp_credential", &opts.snmp_credential_id);
}

fn add_ssh_credential(cmd: &mut XmlCommand, id: Option<&EntityId>, port: Option<ServicePort>) {
    let Some(id) = id else {
        return;
    };
    let credential = add_credential(cmd, "ssh_credential", id);
    if let Some(port) = port {
        credential.add_child_with_text("port", &port.to_string());
    }
}

fn add_credential<'a>(
    cmd: &'a mut XmlCommand,
    element: &str,
    id: &EntityId,
) -> &'a mut gvm_protocol::xml_command::XmlElement {
    let credential = cmd.add_element(element);
    credential.set_attribute("id", id.as_str());
    credential
}

fn join_hosts(hosts: &[TargetHost]) -> String {
    hosts
        .iter()
        .map(TargetHost::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn host(value: &str) -> TargetHost {
        value.parse().expect("valid target host")
    }

    fn hosts(included: &[&str], excluded: &[&str]) -> TargetHosts {
        TargetHosts::new(
            included.iter().map(|value| host(value)),
            excluded.iter().map(|value| host(value)),
        )
        .expect("valid target hosts")
    }

    fn direct_ports() -> TargetPortSelection {
        TargetPortSelection::PortRange("T:1-65535".parse().expect("valid port range"))
    }

    #[test]
    fn target_commands_build_xml() {
        let rendered = xml(create_target(
            "target",
            CreateTargetOpts {
                comment: Some("c".into()),
                hosts: hosts(&["1.1.1.1"], &["2.2.2.2"]),
                alive_test: Some(AliveTest::IcmpPing),
                ports: TargetPortSelection::PortList(id("pl1")),
                ssh_credential_id: Some(id("ssh1")),
                ssh_credential_port: Some(ServicePort::new(2222).expect("valid port")),
                ssh_elevate_credential_id: Some(id("elevate1")),
                smb_credential_id: Some(id("smb1")),
                krb5_credential_id: None,
                esxi_credential_id: Some(id("esxi1")),
                snmp_credential_id: Some(id("snmp1")),
                reverse_lookup_only: Some(true),
                reverse_lookup_unify: Some(false),
                allow_simultaneous_ips: Some(true),
            },
        )
        .expect("valid target"));
        assert!(rendered.contains("<name>target</name>"));
        assert!(rendered.contains("<hosts>1.1.1.1</hosts>"));
        assert!(rendered.contains("<alive_tests>ICMP Ping</alive_tests>"));
        assert!(rendered.contains("<port_list id=\"pl1\"/>"));
        assert!(rendered.contains("<ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential>"));
        assert!(rendered.contains("<ssh_elevate_credential id=\"elevate1\"/>"));
        assert!(rendered.contains("<smb_credential id=\"smb1\"/>"));
        assert!(rendered.contains("<esxi_credential id=\"esxi1\"/>"));
        assert!(rendered.contains("<snmp_credential id=\"snmp1\"/>"));
        assert!(rendered.contains("<allow_simultaneous_ips>1</allow_simultaneous_ips>"));
        assert_eq!(
            xml(clone_target(&id("t1"))),
            "<create_target><copy>t1</copy></create_target>"
        );
    }

    #[test]
    fn target_get_modify_delete_build_xml() {
        assert_eq!(
            xml(get_target(&id("t1"))),
            "<get_targets details=\"1\" target_id=\"t1\"/>"
        );
        let rendered = xml(get_targets(GetTargetsOpts {
            filter_string: Some("name=foo".into()),
            filter_id: Some(id("f1")),
            trash: Some(true),
            details: Some(true),
        }));
        assert!(rendered.contains("filter=\"name=foo\""));
        assert!(rendered.contains("trash=\"1\""));
        let rendered = xml(modify_target(
            &id("t1"),
            ModifyTargetOpts {
                name: Some("n".into()),
                alive_test: Some(AliveTest::IcmpAndArpPing),
                ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                ssh_credential_port: ScalarUpdate::set(ServicePort::new(2222).expect("valid port")),
                ssh_elevate_credential_id: ScalarUpdate::set(id("elevate1")),
                smb_credential_id: ScalarUpdate::set(id("smb1")),
                esxi_credential_id: ScalarUpdate::set(id("esxi1")),
                snmp_credential_id: ScalarUpdate::set(id("snmp1")),
                reverse_lookup_only: Some(true),
                reverse_lookup_unify: Some(false),
                allow_simultaneous_ips: Some(false),
                ..Default::default()
            },
        )
        .expect("valid target update"));
        assert!(rendered.contains("<name>n</name>"));
        assert!(rendered.contains("<alive_tests>ICMP &amp; ARP Ping</alive_tests>"));
        assert!(rendered.contains("<ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential>"));
        assert!(rendered.contains("<ssh_elevate_credential id=\"elevate1\"/>"));
        assert!(rendered.contains("<smb_credential id=\"smb1\"/>"));
        assert!(rendered.contains("<esxi_credential id=\"esxi1\"/>"));
        assert!(rendered.contains("<snmp_credential id=\"snmp1\"/>"));
        assert!(rendered.contains("<reverse_lookup_only>1</reverse_lookup_only>"));
        assert!(rendered.contains("<reverse_lookup_unify>0</reverse_lookup_unify>"));
        assert!(rendered.contains("<allow_simultaneous_ips>0</allow_simultaneous_ips>"));
        assert_eq!(
            xml(delete_target(&id("t1"), false)),
            "<delete_target target_id=\"t1\" ultimate=\"0\"/>"
        );
    }

    #[test]
    fn semantic_target_requests_match_legacy_builder_bytes() {
        let list_opts = GetTargetsOpts {
            filter_string: Some("name=production".into()),
            details: Some(true),
            ..Default::default()
        };
        assert_eq!(
            GetTargetsRequest::new(list_opts.clone()).to_bytes(),
            get_targets(list_opts).to_bytes()
        );

        let target_id = id("target-1");
        assert_eq!(
            GetTargetRequest::new(target_id.clone()).to_bytes(),
            get_target(&target_id).to_bytes()
        );

        let create_opts =
            CreateTargetOpts::new(hosts(&["192.0.2.1"], &["192.0.2.2"]), direct_ports());
        assert_eq!(
            CreateTargetRequest::new("production", create_opts.clone())
                .expect("valid semantic create request")
                .to_bytes(),
            create_target("production", create_opts)
                .expect("valid legacy create request")
                .to_bytes()
        );

        let modify_opts = ModifyTargetOpts {
            name: Some("renamed".into()),
            allow_simultaneous_ips: Some(false),
            ..Default::default()
        };
        assert_eq!(
            ModifyTargetRequest::new(target_id.clone(), modify_opts.clone())
                .expect("valid semantic modify request")
                .to_bytes(),
            modify_target(&target_id, modify_opts)
                .expect("valid legacy modify request")
                .to_bytes()
        );

        assert_eq!(
            DeleteTargetRequest::new(target_id.clone(), true).to_bytes(),
            delete_target(&target_id, true).to_bytes()
        );
    }

    #[test]
    fn modify_target_omits_or_atomically_replaces_hosts() {
        assert_eq!(
            xml(modify_target(&id("t1"), ModifyTargetOpts::default()).expect("valid update")),
            "<modify_target target_id=\"t1\"/>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    hosts: Some(hosts(
                        &["192.0.2.1", "192.0.2.2"],
                        &["192.0.2.3"],
                    )),
                    ..Default::default()
                }
            ).expect("valid update")),
            "<modify_target target_id=\"t1\"><hosts>192.0.2.1,192.0.2.2</hosts><exclude_hosts>192.0.2.3</exclude_hosts></modify_target>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    hosts: Some(hosts(&["192.0.2.1"], &[])),
                    ..Default::default()
                }
            )
            .expect("valid update")),
            "<modify_target target_id=\"t1\"><hosts>192.0.2.1</hosts><exclude_hosts></exclude_hosts></modify_target>"
        );
    }

    #[test]
    fn modify_target_distinguishes_omitted_set_and_cleared_credentials() {
        assert_eq!(
            xml(modify_target(&id("t1"), ModifyTargetOpts::default()).expect("valid update")),
            "<modify_target target_id=\"t1\"/>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                    ssh_credential_port: ScalarUpdate::set(
                        ServicePort::new(2222).expect("valid port"),
                    ),
                    smb_credential_id: ScalarUpdate::set(id("smb1")),
                    ..Default::default()
                }
            ).expect("valid update")),
            "<modify_target target_id=\"t1\"><ssh_credential id=\"ssh1\"><port>2222</port></ssh_credential><smb_credential id=\"smb1\"/></modify_target>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::Clear,
                    ssh_elevate_credential_id: ScalarUpdate::Clear,
                    smb_credential_id: ScalarUpdate::Clear,
                    krb5_credential_id: ScalarUpdate::Clear,
                    esxi_credential_id: ScalarUpdate::Clear,
                    snmp_credential_id: ScalarUpdate::Clear,
                    ..Default::default()
                }
            ).expect("valid update")),
            "<modify_target target_id=\"t1\"><ssh_credential id=\"0\"/><ssh_elevate_credential id=\"0\"/><smb_credential id=\"0\"/><krb5_credential id=\"0\"/><esxi_credential id=\"0\"/><snmp_credential id=\"0\"/></modify_target>"
        );
    }

    #[test]
    fn modify_target_distinguishes_omitted_set_and_unsupported_port_list_clear() {
        assert_eq!(
            xml(modify_target(&id("t1"), ModifyTargetOpts::default()).expect("valid update")),
            "<modify_target target_id=\"t1\"/>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    port_list_id: ScalarUpdate::set(id("pl1")),
                    ..Default::default()
                }
            )
            .expect("setting a port list is supported")),
            "<modify_target target_id=\"t1\"><port_list id=\"pl1\"/></modify_target>"
        );
        assert_eq!(
            modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    port_list_id: ScalarUpdate::Clear,
                    ..Default::default()
                }
            )
            .err(),
            Some(ModifyTargetError::UnsupportedPortListClear)
        );
    }

    #[test]
    fn modify_target_resets_ssh_port_without_exposing_the_wire_sentinel() {
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                    ssh_credential_port: ScalarUpdate::Clear,
                    ..Default::default()
                }
            )
            .expect("valid reset")),
            "<modify_target target_id=\"t1\"><ssh_credential id=\"ssh1\"><port>0</port></ssh_credential></modify_target>"
        );
    }

    #[test]
    fn modify_target_rejects_orphaned_ssh_port_updates() {
        let port = ServicePort::new(2222).expect("valid port");
        assert_eq!(
            modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_port: ScalarUpdate::set(port),
                    ..Default::default()
                }
            )
            .err(),
            Some(ModifyTargetError::SshPortWithoutCredential)
        );
        assert_eq!(
            modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::Clear,
                    ssh_credential_port: ScalarUpdate::Clear,
                    ..Default::default()
                }
            )
            .err(),
            Some(ModifyTargetError::SshPortWithCredentialClear)
        );
    }

    #[test]
    fn create_target_rejects_an_ssh_port_without_a_credential() {
        assert_eq!(
            create_target(
                "target",
                CreateTargetOpts {
                    ssh_credential_port: Some(ServicePort::new(2222).expect("valid port")),
                    ..CreateTargetOpts::new(hosts(&["192.0.2.1"], &[]), direct_ports())
                }
            )
            .err(),
            Some(CreateTargetError::SshPortWithoutCredential)
        );
    }

    #[test]
    fn target_new_fields_have_exact_wire_shapes() {
        assert_eq!(
            xml(create_target(
                "target",
                CreateTargetOpts {
                    ssh_credential_id: Some(id("ssh1")),
                    ssh_elevate_credential_id: Some(id("elevate1")),
                    allow_simultaneous_ips: Some(true),
                    ..CreateTargetOpts::new(hosts(&["192.0.2.1"], &[]), direct_ports())
                }
            )
            .expect("valid elevation target")),
            "<create_target><name>target</name><hosts>192.0.2.1</hosts><exclude_hosts></exclude_hosts><port_range>T:1-65535</port_range><ssh_credential id=\"ssh1\"/><ssh_elevate_credential id=\"elevate1\"/><allow_simultaneous_ips>1</allow_simultaneous_ips></create_target>"
        );
        assert_eq!(
            xml(create_target(
                "target",
                CreateTargetOpts {
                    krb5_credential_id: Some(id("krb1")),
                    allow_simultaneous_ips: Some(false),
                    ..CreateTargetOpts::new(hosts(&["192.0.2.1"], &[]), direct_ports())
                }
            )
            .expect("valid Kerberos target")),
            "<create_target><name>target</name><hosts>192.0.2.1</hosts><exclude_hosts></exclude_hosts><port_range>T:1-65535</port_range><krb5_credential id=\"krb1\"/><allow_simultaneous_ips>0</allow_simultaneous_ips></create_target>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::set(id("ssh1")),
                    ssh_elevate_credential_id: ScalarUpdate::set(id("elevate1")),
                    krb5_credential_id: ScalarUpdate::set(id("krb1")),
                    allow_simultaneous_ips: Some(true),
                    ..Default::default()
                }
            )
            .expect("valid target update")),
            "<modify_target target_id=\"t1\"><ssh_credential id=\"ssh1\"/><ssh_elevate_credential id=\"elevate1\"/><krb5_credential id=\"krb1\"/><allow_simultaneous_ips>1</allow_simultaneous_ips></modify_target>"
        );
        assert_eq!(
            xml(modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_elevate_credential_id: ScalarUpdate::set(id("elevate1")),
                    ..Default::default()
                }
            )
            .expect("existing SSH credential may be preserved")),
            "<modify_target target_id=\"t1\"><ssh_elevate_credential id=\"elevate1\"/></modify_target>"
        );
    }

    #[test]
    fn target_new_credential_invariants_are_typed_errors() {
        let base = || CreateTargetOpts::new(hosts(&["192.0.2.1"], &[]), direct_ports());
        assert_eq!(
            create_target(
                "target",
                CreateTargetOpts {
                    ssh_elevate_credential_id: Some(id("elevate1")),
                    ..base()
                }
            )
            .err(),
            Some(CreateTargetError::SshElevateWithoutSshCredential)
        );
        assert_eq!(
            create_target(
                "target",
                CreateTargetOpts {
                    ssh_credential_id: Some(id("same")),
                    ssh_elevate_credential_id: Some(id("same")),
                    ..base()
                }
            )
            .err(),
            Some(CreateTargetError::SshElevateMatchesSshCredential)
        );
        assert_eq!(
            create_target(
                "target",
                CreateTargetOpts {
                    smb_credential_id: Some(id("smb1")),
                    krb5_credential_id: Some(id("krb1")),
                    ..base()
                }
            )
            .err(),
            Some(CreateTargetError::SmbAndKrb5Credentials)
        );
        assert_eq!(
            modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::Clear,
                    ssh_elevate_credential_id: ScalarUpdate::set(id("elevate1")),
                    ..Default::default()
                }
            )
            .err(),
            Some(ModifyTargetError::SshElevateWithoutSshCredential)
        );
        assert_eq!(
            modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    ssh_credential_id: ScalarUpdate::set(id("same")),
                    ssh_elevate_credential_id: ScalarUpdate::set(id("same")),
                    ..Default::default()
                }
            )
            .err(),
            Some(ModifyTargetError::SshElevateMatchesSshCredential)
        );
        assert_eq!(
            modify_target(
                &id("t1"),
                ModifyTargetOpts {
                    smb_credential_id: ScalarUpdate::set(id("smb1")),
                    krb5_credential_id: ScalarUpdate::set(id("krb1")),
                    ..Default::default()
                }
            )
            .err(),
            Some(ModifyTargetError::SmbAndKrb5Credentials)
        );
    }
}
