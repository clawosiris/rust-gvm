use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct RoleOpts {
    pub comment: Option<String>,
    pub users: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GetRolesOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_role(role_id: &EntityId) -> impl Request {
    XmlCommand::new("create_role").child_with_text("copy", role_id.as_str())
}

pub fn create_role(name: &str, opts: RoleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_role");
    cmd.add_element_with_text("name", name);
    add_role_body(&mut cmd, &opts);
    cmd
}

pub fn get_roles(opts: GetRolesOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_roles");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_role(role_id: &EntityId) -> impl Request {
    XmlCommand::new("get_roles").attribute("role_id", role_id.as_str()).attribute("details", "1")
}

pub fn modify_role(role_id: &EntityId, opts: RoleOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_role").attribute("role_id", role_id.as_str());
    add_role_body(&mut cmd, &opts);
    cmd
}

pub fn delete_role(role_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_role").attribute("role_id", role_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

fn add_role_body(cmd: &mut XmlCommand, opts: &RoleOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    if !opts.users.is_empty() {
        cmd.add_element_with_text("users", &opts.users.join(","));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn role_commands_build_xml() {
        let rendered = xml(create_role("role", RoleOpts { users: vec!["alice".into()], ..Default::default() }));
        assert!(rendered.contains("<users>alice</users>"));
        assert_eq!(xml(clone_role(&id("r1"))), "<create_role><copy>r1</copy></create_role>");
        assert_eq!(xml(get_role(&id("r1"))), "<get_roles details=\"1\" role_id=\"r1\"/>");
    }

    #[test]
    fn role_get_modify_delete_build_xml() {
        let rendered = xml(get_roles(GetRolesOpts { details: Some(true), ..Default::default() }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_role(&id("r1"), RoleOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_role role_id=\"r1\"><comment>updated</comment></modify_role>");
        assert_eq!(xml(delete_role(&id("r1"), false)), "<delete_role role_id=\"r1\" ultimate=\"0\"/>");
    }
}
