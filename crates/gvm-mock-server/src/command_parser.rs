//! GMP XML command parser.
//!
//! Parses incoming GMP XML to extract the command name, attributes, and child elements.

use std::collections::HashMap;

use quick_xml::events::Event;
use quick_xml::Reader;

/// A parsed GMP command extracted from incoming XML.
#[derive(Debug, Clone)]
pub struct ParsedCommand {
    /// The command name (e.g., "get_tasks", "create_task", "authenticate").
    pub name: String,
    /// Attributes on the root command element.
    pub attributes: HashMap<String, String>,
    /// Child elements with their text content and attributes.
    pub children: Vec<ParsedElement>,
    /// The raw XML bytes.
    pub raw_xml: Vec<u8>,
}

/// A parsed child element.
#[derive(Debug, Clone)]
pub struct ParsedElement {
    /// Element name.
    pub name: String,
    /// Attributes on this element.
    pub attributes: HashMap<String, String>,
    /// Text content (if any).
    pub text: Option<String>,
    /// Nested children.
    pub children: Vec<ParsedElement>,
}

impl ParsedCommand {
    /// Get an attribute value by key.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(String::as_str)
    }

    /// Get the text of a direct child element by name.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.children
            .iter()
            .find(|c| c.name == name)
            .and_then(|c| c.text.as_deref())
    }

    /// Get a child element's attribute.
    pub fn child_attr(&self, child_name: &str, attr_key: &str) -> Option<&str> {
        self.children
            .iter()
            .find(|c| c.name == child_name)
            .and_then(|c| c.attributes.get(attr_key).map(String::as_str))
    }
}

/// Parse a GMP XML command from bytes.
///
/// # Errors
/// Returns `None` if the XML cannot be parsed or is empty.
pub fn parse_command(xml: &[u8]) -> Option<ParsedCommand> {
    let text = std::str::from_utf8(xml).ok()?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    // Find the root element
    let (name, attributes) = loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).ok()?.to_string();
                let attributes = extract_attributes(e);
                break (name, attributes);
            }
            Ok(Event::Empty(ref e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).ok()?.to_string();
                let attributes = extract_attributes(e);
                return Some(ParsedCommand {
                    name,
                    attributes,
                    children: Vec::new(),
                    raw_xml: xml.to_vec(),
                });
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            _ => continue,
        }
    };

    // Parse children
    let children = parse_children(&mut reader, &name);

    Some(ParsedCommand {
        name,
        attributes,
        children,
        raw_xml: xml.to_vec(),
    })
}

fn parse_children(reader: &mut Reader<&[u8]>, parent_name: &str) -> Vec<ParsedElement> {
    let mut children = Vec::new();
    let mut current_text = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let child_name = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_string();
                let attrs = extract_attributes(e);
                let grandchildren = parse_children(reader, &child_name);

                // Collect text that was accumulated
                let text = if current_text.is_empty() {
                    None
                } else {
                    let t = current_text.clone();
                    current_text.clear();
                    Some(t)
                };

                // If we had grandchildren that collected text, use that
                // otherwise check if we have a direct text child
                children.push(ParsedElement {
                    name: child_name,
                    attributes: attrs,
                    text,
                    children: grandchildren,
                });
            }
            Ok(Event::Empty(ref e)) => {
                let child_name = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_string();
                let attrs = extract_attributes(e);
                children.push(ParsedElement {
                    name: child_name,
                    attributes: attrs,
                    text: None,
                    children: Vec::new(),
                });
            }
            Ok(Event::Text(ref t)) => {
                if let Ok(unescaped) = t.unescape() {
                    current_text.push_str(&unescaped);
                }
            }
            Ok(Event::End(ref e)) => {
                let end_name = std::str::from_utf8(e.name().as_ref()).unwrap_or("");
                if end_name == parent_name {
                    // If there's accumulated text and no children were added,
                    // this is a text-only element — but that's handled by the caller.
                    // The text for a child element gets associated via the Start handler.
                    break;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => continue,
        }
    }

    // If we have accumulated text but it belongs to this element (not a child),
    // we need to handle it. But for children parsing, text between child elements
    // is generally whitespace and can be ignored.

    children
}

/// Helper: re-parse children to associate text with the correct element.
/// This is a simplified parser that handles the common GMP pattern where
/// child elements contain text: `<name>text</name>`.
pub fn parse_element_text(xml: &[u8], element_name: &str) -> Option<String> {
    let text = std::str::from_utf8(xml).ok()?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut inside = false;
    let mut result = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).ok()?;
                if name == element_name {
                    inside = true;
                    result.clear();
                }
            }
            Ok(Event::Text(ref t)) if inside => {
                if let Ok(unescaped) = t.unescape() {
                    result.push_str(&unescaped);
                }
            }
            Ok(Event::End(ref e)) if inside => {
                let name = std::str::from_utf8(e.name().as_ref()).ok()?;
                if name == element_name {
                    return Some(result);
                }
            }
            Ok(Event::Eof) => return None,
            Err(_) => return None,
            _ => continue,
        }
    }
}

fn extract_attributes(e: &quick_xml::events::BytesStart<'_>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for attr in e.attributes().flatten() {
        if let (Ok(key), Ok(val)) = (
            std::str::from_utf8(attr.key.as_ref()),
            std::str::from_utf8(&attr.value),
        ) {
            map.insert(key.to_string(), val.to_string());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    // XML-001
    #[test]
    fn test_parse_simple_command() {
        let cmd = parse_command(b"<get_version/>").expect("should parse");
        assert_eq!(cmd.name, "get_version");
        assert!(cmd.attributes.is_empty());
        assert!(cmd.children.is_empty());
    }

    // XML-002
    #[test]
    fn test_parse_command_with_attributes() {
        let cmd =
            parse_command(br#"<get_tasks usage_type="scan" details="1"/>"#).expect("should parse");
        assert_eq!(cmd.name, "get_tasks");
        assert_eq!(cmd.attr("usage_type"), Some("scan"));
        assert_eq!(cmd.attr("details"), Some("1"));
    }

    // XML-003
    #[test]
    fn test_parse_command_with_id() {
        let cmd = parse_command(br#"<get_tasks task_id="abc-123"/>"#).expect("should parse");
        assert_eq!(cmd.attr("task_id"), Some("abc-123"));
    }

    // XML-004
    #[test]
    fn test_parse_command_with_children() {
        let xml = br#"<create_task><name>foo</name><target id="t1"/></create_task>"#;
        let cmd = parse_command(xml).expect("should parse");
        assert_eq!(cmd.name, "create_task");
        assert_eq!(cmd.child_attr("target", "id"), Some("t1"));
    }

    // XML-006
    #[test]
    fn test_parse_authenticate() {
        let xml = b"<authenticate><credentials><username>admin</username><password>pass</password></credentials></authenticate>";
        let cmd = parse_command(xml).expect("should parse");
        assert_eq!(cmd.name, "authenticate");
        assert!(!cmd.children.is_empty());
    }

    // XML-008
    #[test]
    fn test_empty_input() {
        assert!(parse_command(b"").is_none());
    }

    // XML-011
    #[test]
    fn test_unknown_command() {
        let cmd = parse_command(b"<do_something_weird/>").expect("should parse");
        assert_eq!(cmd.name, "do_something_weird");
    }

    // XML-010
    #[test]
    fn test_unicode_content() {
        let xml = "<create_task><name>Tëst Tàsk</name></create_task>".as_bytes();
        let cmd = parse_command(xml).expect("should parse");
        assert_eq!(cmd.name, "create_task");
    }
}
