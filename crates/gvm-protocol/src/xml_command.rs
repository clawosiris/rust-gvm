//! GMP XML command builder.
//!
//! Mirrors python-gvm's `XmlCommand` class for constructing GMP XML requests.

use std::collections::BTreeMap;

use crate::request::Request;

/// A builder for GMP XML commands.
///
/// # Example
/// ```
/// use gvm_protocol::{XmlCommand, Request};
///
/// let cmd = XmlCommand::new("get_tasks")
///     .attribute("usage_type", "scan")
///     .attribute("details", "1");
/// assert_eq!(
///     String::from_utf8(cmd.to_bytes()).unwrap(),
///     r#"<get_tasks details="1" usage_type="scan"/>"#
/// );
/// ```
#[derive(Debug, Clone)]
pub struct XmlCommand {
    name: String,
    attributes: BTreeMap<String, String>,
    children: Vec<XmlElement>,
}

/// A child element within an XML command.
#[derive(Debug, Clone)]
pub struct XmlElement {
    name: String,
    attributes: BTreeMap<String, String>,
    text: Option<String>,
    children: Vec<XmlElement>,
}

impl XmlCommand {
    /// Create a new XML command with the given element name.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            attributes: BTreeMap::new(),
            children: Vec::new(),
        }
    }

    /// Set an attribute on the command element.
    #[must_use]
    pub fn attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Set an attribute on the command element (mutable reference version).
    pub fn set_attribute(&mut self, key: &str, value: &str) -> &mut Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Add a child element with text content.
    #[must_use]
    pub fn child_with_text(mut self, name: &str, text: &str) -> Self {
        self.children.push(XmlElement {
            name: name.to_string(),
            attributes: BTreeMap::new(),
            text: Some(text.to_string()),
            children: Vec::new(),
        });
        self
    }

    /// Add a child element with text content (mutable reference version).
    pub fn add_element_with_text(&mut self, name: &str, text: &str) -> &mut Self {
        self.children.push(XmlElement {
            name: name.to_string(),
            attributes: BTreeMap::new(),
            text: Some(text.to_string()),
            children: Vec::new(),
        });
        self
    }

    /// Add a child element with an attribute (e.g., `<target id="123"/>`).
    #[must_use]
    pub fn child_with_attr(mut self, name: &str, attr_key: &str, attr_val: &str) -> Self {
        let mut attrs = BTreeMap::new();
        attrs.insert(attr_key.to_string(), attr_val.to_string());
        self.children.push(XmlElement {
            name: name.to_string(),
            attributes: attrs,
            text: None,
            children: Vec::new(),
        });
        self
    }

    /// Add a child element and return a mutable reference to it for further building.
    ///
    /// # Panics
    /// Panics if the just-pushed child cannot be retrieved, which would indicate
    /// internal vector corruption.
    pub fn add_element(&mut self, name: &str) -> &mut XmlElement {
        self.children.push(XmlElement {
            name: name.to_string(),
            attributes: BTreeMap::new(),
            text: None,
            children: Vec::new(),
        });
        self.children.last_mut().expect("just pushed")
    }

    /// Add GMP filter attributes.
    pub fn add_filter(
        &mut self,
        filter_string: Option<&str>,
        filter_id: Option<&str>,
    ) -> &mut Self {
        if let Some(f) = filter_string {
            self.attributes.insert("filter".to_string(), f.to_string());
        }
        if let Some(id) = filter_id {
            self.attributes
                .insert("filt_id".to_string(), id.to_string());
        }
        self
    }

    /// Get the command name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if the command has any children.
    #[must_use]
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

impl XmlElement {
    /// Set an attribute on this element.
    pub fn set_attribute(&mut self, key: &str, value: &str) -> &mut Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the text content of this element.
    pub fn set_text(&mut self, text: &str) -> &mut Self {
        self.text = Some(text.to_string());
        self
    }

    /// Add a child element and return a mutable reference to it.
    ///
    /// # Panics
    /// Panics if the just-pushed child cannot be retrieved, which would indicate
    /// internal vector corruption.
    pub fn add_child(&mut self, name: &str) -> &mut XmlElement {
        self.children.push(XmlElement {
            name: name.to_string(),
            attributes: BTreeMap::new(),
            text: None,
            children: Vec::new(),
        });
        self.children.last_mut().expect("just pushed")
    }

    /// Add a child element with text content.
    pub fn add_child_with_text(&mut self, name: &str, text: &str) -> &mut Self {
        self.children.push(XmlElement {
            name: name.to_string(),
            attributes: BTreeMap::new(),
            text: Some(text.to_string()),
            children: Vec::new(),
        });
        self
    }

    fn write_to(&self, buf: &mut String) {
        buf.push('<');
        buf.push_str(&self.name);
        for (k, v) in &self.attributes {
            buf.push(' ');
            buf.push_str(k);
            buf.push_str("=\"");
            xml_escape_into(buf, v);
            buf.push('"');
        }
        if self.text.is_none() && self.children.is_empty() {
            buf.push_str("/>");
        } else {
            buf.push('>');
            if let Some(ref t) = self.text {
                xml_escape_into(buf, t);
            }
            for child in &self.children {
                child.write_to(buf);
            }
            buf.push_str("</");
            buf.push_str(&self.name);
            buf.push('>');
        }
    }
}

impl Request for XmlCommand {
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = String::with_capacity(256);
        buf.push('<');
        buf.push_str(&self.name);
        for (k, v) in &self.attributes {
            buf.push(' ');
            buf.push_str(k);
            buf.push_str("=\"");
            xml_escape_into(&mut buf, v);
            buf.push('"');
        }
        if self.children.is_empty() {
            buf.push_str("/>");
        } else {
            buf.push('>');
            for child in &self.children {
                child.write_to(&mut buf);
            }
            buf.push_str("</");
            buf.push_str(&self.name);
            buf.push('>');
        }
        buf.into_bytes()
    }
}

/// XML-escape a string into the buffer.
fn xml_escape_into(buf: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            '\'' => buf.push_str("&apos;"),
            _ => buf.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CMD-001
    #[test]
    fn test_simple_command() {
        let cmd = XmlCommand::new("get_version");
        assert_eq!(
            String::from_utf8(cmd.to_bytes()).expect("valid utf8"),
            "<get_version/>"
        );
    }

    // CMD-002
    #[test]
    fn test_command_with_attribute() {
        let cmd = XmlCommand::new("get_tasks").attribute("task_id", "a1");
        assert_eq!(
            String::from_utf8(cmd.to_bytes()).expect("valid utf8"),
            r#"<get_tasks task_id="a1"/>"#
        );
    }

    // CMD-003
    #[test]
    fn test_command_with_child_text() {
        let cmd = XmlCommand::new("create_task").child_with_text("name", "foo");
        assert_eq!(
            String::from_utf8(cmd.to_bytes()).expect("valid utf8"),
            "<create_task><name>foo</name></create_task>"
        );
    }

    // CMD-004
    #[test]
    fn test_command_with_attr_child() {
        let cmd = XmlCommand::new("create_task").child_with_attr("target", "id", "0");
        assert_eq!(
            String::from_utf8(cmd.to_bytes()).expect("valid utf8"),
            r#"<create_task><target id="0"/></create_task>"#
        );
    }

    // CMD-010
    #[test]
    fn test_special_chars_escaped() {
        let cmd = XmlCommand::new("create_task").child_with_text("name", "a<b>&c\"d");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("a&lt;b&gt;&amp;c&quot;d"));
    }

    // CMD-011
    #[test]
    fn test_utf8_preserved() {
        let cmd = XmlCommand::new("create_task").child_with_text("name", "Tëst Tàsk");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("Tëst Tàsk"));
    }

    // CMD-007
    #[test]
    fn test_filter_string() {
        let mut cmd = XmlCommand::new("get_tasks");
        cmd.add_filter(Some("name=foo"), None);
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains(r#"filter="name=foo""#));
    }

    // CMD-008
    #[test]
    fn test_filter_id() {
        let mut cmd = XmlCommand::new("get_tasks");
        cmd.add_filter(None, Some("f1"));
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains(r#"filt_id="f1""#));
    }

    #[test]
    fn test_set_attribute_mutable() {
        let mut cmd = XmlCommand::new("get_tasks");
        cmd.set_attribute("details", "1");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("details=\"1\""));
    }

    #[test]
    fn test_child_with_attr() {
        let cmd = XmlCommand::new("create_task").child_with_attr("target", "id", "abc-123");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("<target id=\"abc-123\"/>"));
    }

    #[test]
    fn test_add_element_with_text() {
        let mut cmd = XmlCommand::new("create_task");
        cmd.add_element_with_text("name", "My Task");
        cmd.add_element_with_text("comment", "A comment");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("<name>My Task</name>"));
        assert!(xml.contains("<comment>A comment</comment>"));
    }

    #[test]
    fn test_add_filter_with_filter_id() {
        let mut cmd = XmlCommand::new("get_tasks");
        cmd.add_filter(None, Some("filter-uuid-123"));
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("filt_id=\"filter-uuid-123\""));
    }

    #[test]
    fn test_add_filter_with_both() {
        let mut cmd = XmlCommand::new("get_tasks");
        cmd.add_filter(Some("name=foo"), Some("filter-uuid"));
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("filter=\"name=foo\""));
        assert!(xml.contains("filt_id=\"filter-uuid\""));
    }

    #[test]
    fn test_add_filter_with_neither() {
        let mut cmd = XmlCommand::new("get_tasks");
        cmd.add_filter(None, None);
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(!xml.contains("filter="));
        assert!(!xml.contains("filt_id="));
    }

    #[test]
    fn test_name() {
        let cmd = XmlCommand::new("get_version");
        assert_eq!(cmd.name(), "get_version");
    }

    #[test]
    fn test_has_children() {
        let cmd = XmlCommand::new("get_version");
        assert!(!cmd.has_children());

        let cmd_with = XmlCommand::new("create_task").child_with_text("name", "T");
        assert!(cmd_with.has_children());
    }

    #[test]
    fn test_element_set_attribute() {
        let mut cmd = XmlCommand::new("create_task");
        let elem = cmd.add_element("target");
        elem.set_attribute("id", "target-123");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("<target id=\"target-123\""));
    }

    #[test]
    fn test_element_set_text() {
        let mut cmd = XmlCommand::new("create_task");
        let elem = cmd.add_element("name");
        elem.set_text("Dynamic Name");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("<name>Dynamic Name</name>"));
    }

    #[test]
    fn test_element_add_child() {
        let mut cmd = XmlCommand::new("create_task");
        let elem = cmd.add_element("preferences");
        let child = elem.add_child("preference");
        child.set_text("value1");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("<preferences><preference>value1</preference></preferences>"));
    }

    #[test]
    fn test_element_add_child_with_text() {
        let mut cmd = XmlCommand::new("create_task");
        let elem = cmd.add_element("preferences");
        elem.add_child_with_text("pref1", "val1");
        elem.add_child_with_text("pref2", "val2");
        let xml = String::from_utf8(cmd.to_bytes()).expect("valid utf8");
        assert!(xml.contains("<pref1>val1</pref1>"));
        assert!(xml.contains("<pref2>val2</pref2>"));
    }
}
