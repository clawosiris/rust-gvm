use gvm_protocol::{Request, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{AlertCondition, AlertEvent, AlertMethod};
use crate::types::EntityId;

#[derive(Debug, Clone, Default)]
pub struct AlertOpts {
    pub comment: Option<String>,
    pub event: Option<AlertEvent>,
    pub condition: Option<AlertCondition>,
    pub method: Option<AlertMethod>,
    pub filter_id: Option<EntityId>,
}

#[derive(Debug, Clone, Default)]
pub struct GetAlertsOpts {
    pub filter_string: Option<String>,
    pub filter_id: Option<EntityId>,
    pub trash: Option<bool>,
    pub details: Option<bool>,
}

pub fn clone_alert(alert_id: &EntityId) -> impl Request {
    XmlCommand::new("create_alert").child_with_text("copy", alert_id.as_str())
}

pub fn create_alert(name: &str, opts: AlertOpts) -> impl Request {
    let mut cmd = XmlCommand::new("create_alert");
    cmd.add_element_with_text("name", name);
    add_alert_body(&mut cmd, &opts);
    cmd
}

pub fn get_alerts(opts: GetAlertsOpts) -> impl Request {
    let mut cmd = XmlCommand::new("get_alerts");
    add_filter_attrs(&mut cmd, opts.filter_string.as_deref(), opts.filter_id.as_ref());
    set_optional_bool_attr(&mut cmd, "trash", opts.trash);
    set_optional_bool_attr(&mut cmd, "details", opts.details);
    cmd
}

pub fn get_alert(alert_id: &EntityId) -> impl Request {
    XmlCommand::new("get_alerts").attribute("alert_id", alert_id.as_str()).attribute("details", "1")
}

pub fn modify_alert(alert_id: &EntityId, opts: AlertOpts) -> impl Request {
    let mut cmd = XmlCommand::new("modify_alert").attribute("alert_id", alert_id.as_str());
    add_alert_body(&mut cmd, &opts);
    cmd
}

pub fn delete_alert(alert_id: &EntityId, ultimate: bool) -> impl Request {
    XmlCommand::new("delete_alert").attribute("alert_id", alert_id.as_str()).attribute("ultimate", bool_str(ultimate))
}

pub fn test_alert(alert_id: &EntityId) -> impl Request {
    XmlCommand::new("test_alert").attribute("alert_id", alert_id.as_str())
}

fn add_alert_body(cmd: &mut XmlCommand, opts: &AlertOpts) {
    add_text_element(cmd, "comment", opts.comment.as_deref());
    if let Some(event) = opts.event {
        cmd.add_element_with_text("event", event.as_gmp_str());
    }
    if let Some(condition) = opts.condition {
        cmd.add_element_with_text("condition", condition.as_gmp_str());
    }
    if let Some(method) = opts.method {
        cmd.add_element_with_text("method", method.as_gmp_str());
    }
    if let Some(filter_id) = opts.filter_id.as_ref() {
        cmd.add_element("filter").set_attribute("id", filter_id.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::xml;

    fn id(value: &str) -> EntityId { EntityId::new(value).expect("valid id") }

    #[test]
    fn alert_commands_build_xml() {
        let rendered = xml(create_alert("alert", AlertOpts { event: Some(AlertEvent::TaskRunStatusChanged), condition: Some(AlertCondition::Always), method: Some(AlertMethod::Email), filter_id: Some(id("f1")), ..Default::default() }));
        assert!(rendered.contains("<event>task_run_status_changed</event>"));
        assert!(rendered.contains("<filter id=\"f1\"/>"));
        assert_eq!(xml(clone_alert(&id("a1"))), "<create_alert><copy>a1</copy></create_alert>");
        let rendered = xml(get_alert(&id("a1")));
        assert!(rendered.contains("<get_alerts "));
        assert!(rendered.contains("alert_id=\"a1\""));
        assert!(rendered.contains("details=\"1\""));
    }

    #[test]
    fn alert_get_modify_delete_test_build_xml() {
        let rendered = xml(get_alerts(GetAlertsOpts { details: Some(true), ..Default::default() }));
        assert!(rendered.contains("details=\"1\""));
        let rendered = xml(modify_alert(&id("a1"), AlertOpts { comment: Some("updated".into()), ..Default::default() }));
        assert_eq!(rendered, "<modify_alert alert_id=\"a1\"><comment>updated</comment></modify_alert>");
        assert_eq!(xml(delete_alert(&id("a1"), false)), "<delete_alert alert_id=\"a1\" ultimate=\"0\"/>");
        assert_eq!(xml(test_alert(&id("a1"))), "<test_alert alert_id=\"a1\"/>");
    }
}
