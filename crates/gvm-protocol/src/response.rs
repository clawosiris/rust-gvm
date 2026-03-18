// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! GMP response parsing.

use std::collections::HashMap;
use std::sync::OnceLock;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::ProtocolError;

#[derive(Debug, Clone, Default)]
struct ParsedHeader {
    status_code: Option<u16>,
    status_text: Option<String>,
    root_element: Option<String>,
    id: Option<String>,
}

/// A GMP response received from the server.
#[derive(Debug)]
pub struct Response {
    data: Vec<u8>,
    header: OnceLock<ParsedHeader>,
    child_texts: OnceLock<HashMap<String, String>>,
}

impl Clone for Response {
    fn clone(&self) -> Self {
        let cloned = Self::new(self.data.clone());
        if let Some(header) = self.header.get() {
            let _ = cloned.header.set(header.clone());
        }
        if let Some(child_texts) = self.child_texts.get() {
            let _ = cloned.child_texts.set(child_texts.clone());
        }
        cloned
    }
}

impl Response {
    /// Create a new Response from raw bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            header: OnceLock::new(),
            child_texts: OnceLock::new(),
        }
    }

    /// Return the raw response data as bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Return the response data as a UTF-8 string.
    ///
    /// # Errors
    /// Returns an error if the data is not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, ProtocolError> {
        std::str::from_utf8(&self.data)
            .map_err(|e| ProtocolError::XmlParse(format!("Invalid UTF-8: {e}")))
    }

    /// Extract the status code from the response root element.
    ///
    /// Returns `None` if the response doesn't contain a valid status code.
    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        self.header().status_code
    }

    /// Extract the `status_text` from the response root element.
    #[must_use]
    pub fn status_text(&self) -> Option<String> {
        self.header().status_text.clone()
    }

    /// Returns `true` if the response has a success status code (2xx).
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status_code()
            .map(|s| (200..300).contains(&s))
            .unwrap_or(false)
    }

    /// Check the status and return an error if it's not a success.
    ///
    /// # Errors
    /// Returns `ProtocolError::ServerError` if the status code is not 2xx.
    pub fn raise_for_status(&self) -> Result<&Self, ProtocolError> {
        if self.is_success() {
            return Ok(self);
        }
        let status = self.status_code().unwrap_or(0);
        let message = self
            .status_text()
            .unwrap_or_else(|| "Unknown error".to_string());
        Err(ProtocolError::ServerError { status, message })
    }

    /// Extract the root element name from the response.
    #[must_use]
    pub fn root_element_name(&self) -> Option<String> {
        self.header().root_element.clone()
    }

    /// Extract the `id` attribute from the response root element (used for create responses).
    #[must_use]
    pub fn id(&self) -> Option<String> {
        self.header().id.clone()
    }

    /// Extract the text content of a named direct child element of the response root.
    ///
    /// Returns `None` when the child is absent or the response body is not valid UTF-8 or
    /// well-formed XML.
    #[must_use]
    pub fn child_text(&self, element_name: &str) -> Option<String> {
        self.child_texts().get(element_name).cloned()
    }

    fn header(&self) -> &ParsedHeader {
        self.header.get_or_init(|| self.parse_header())
    }

    fn child_texts(&self) -> &HashMap<String, String> {
        self.child_texts.get_or_init(|| self.parse_child_texts())
    }

    fn parse_header(&self) -> ParsedHeader {
        let Ok(text) = std::str::from_utf8(&self.data) else {
            return ParsedHeader::default();
        };

        let mut reader = Reader::from_str(text);
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                    let mut header = ParsedHeader {
                        root_element: std::str::from_utf8(e.name().as_ref())
                            .ok()
                            .map(String::from),
                        ..ParsedHeader::default()
                    };

                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"status" => {
                                header.status_code = std::str::from_utf8(&attr.value)
                                    .ok()
                                    .and_then(|value| value.parse::<u16>().ok());
                            }
                            b"status_text" => {
                                header.status_text =
                                    std::str::from_utf8(&attr.value).ok().map(String::from);
                            }
                            b"id" => {
                                header.id = std::str::from_utf8(&attr.value).ok().map(String::from);
                            }
                            _ => {}
                        }
                    }

                    return header;
                }
                Ok(Event::Eof) | Err(_) => return ParsedHeader::default(),
                _ => continue,
            }
        }
    }

    fn parse_child_texts(&self) -> HashMap<String, String> {
        let Ok(text) = std::str::from_utf8(&self.data) else {
            return HashMap::new();
        };

        let mut child_texts = HashMap::new();
        let mut reader = Reader::from_str(text);
        let mut root_depth = 0_usize;
        let mut current_child_name: Option<String> = None;
        let mut current_child_depth = 0_usize;
        let mut current_text = String::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    root_depth += 1;

                    if current_child_name.is_some() {
                        current_child_depth += 1;
                        continue;
                    }

                    if root_depth == 2 {
                        let qname = e.name();
                        let Ok(name) = std::str::from_utf8(qname.as_ref()) else {
                            return HashMap::new();
                        };
                        current_child_name = Some(name.to_string());
                        current_child_depth = 1;
                        current_text.clear();
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    if root_depth == 1 {
                        let qname = e.name();
                        let Ok(name) = std::str::from_utf8(qname.as_ref()) else {
                            return HashMap::new();
                        };
                        child_texts.entry(name.to_string()).or_default();
                    }
                }
                Ok(Event::Text(ref text)) => {
                    if current_child_name.is_some() {
                        let Ok(unescaped) = text.xml_content() else {
                            return HashMap::new();
                        };
                        current_text.push_str(&unescaped);
                    }
                }
                Ok(Event::CData(ref text)) => {
                    if current_child_name.is_some() {
                        let Ok(unescaped) = text.xml_content() else {
                            return HashMap::new();
                        };
                        current_text.push_str(&unescaped);
                    }
                }
                Ok(Event::End(_)) => {
                    if let Some(name) = current_child_name.as_ref() {
                        current_child_depth = current_child_depth.saturating_sub(1);
                        if current_child_depth == 0 {
                            child_texts
                                .entry(name.clone())
                                .or_insert_with(|| std::mem::take(&mut current_text));
                            current_child_name = None;
                        }
                    }

                    root_depth = root_depth.saturating_sub(1);
                }
                Ok(Event::Eof) => return child_texts,
                Err(_) => return HashMap::new(),
                _ => {}
            }
        }
    }
}

impl From<Vec<u8>> for Response {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&str> for Response {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
}

impl AsRef<[u8]> for Response {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_code_200() {
        let resp = Response::from(r#"<get_tasks_response status="200" status_text="OK"/>"#);
        assert_eq!(resp.status_code(), Some(200));
        assert!(resp.is_success());
    }

    #[test]
    fn test_status_code_201() {
        let resp = Response::from(
            r#"<create_task_response status="201" status_text="OK, resource created" id="abc-123"/>"#,
        );
        assert_eq!(resp.status_code(), Some(201));
        assert!(resp.is_success());
        assert_eq!(resp.id(), Some("abc-123".to_string()));
    }

    #[test]
    fn test_status_code_400() {
        let resp =
            Response::from(r#"<authenticate_response status="400" status_text="Auth failed"/>"#);
        assert_eq!(resp.status_code(), Some(400));
        assert!(!resp.is_success());
    }

    #[test]
    fn test_raise_for_status_success() {
        let resp = Response::from(r#"<get_version_response status="200" status_text="OK"/>"#);
        assert!(resp.raise_for_status().is_ok());
    }

    #[test]
    fn test_raise_for_status_error() {
        let resp = Response::from(r#"<get_tasks_response status="404" status_text="Not Found"/>"#);
        let err = resp.raise_for_status().unwrap_err();
        match err {
            ProtocolError::ServerError { status, message } => {
                assert_eq!(status, 404);
                assert_eq!(message, "Not Found");
            }
            other => panic!("Expected ServerError, got: {other:?}"),
        }
    }

    #[test]
    fn test_root_element_name() {
        let resp = Response::from(r#"<get_tasks_response status="200" status_text="OK"/>"#);
        assert_eq!(
            resp.root_element_name(),
            Some("get_tasks_response".to_string())
        );
    }

    #[test]
    fn test_child_text() {
        let resp = Response::from(
            r#"<get_version_response status="200" status_text="OK"><version>22.5</version></get_version_response>"#,
        );
        assert_eq!(resp.child_text("version"), Some("22.5".to_string()));
    }

    #[test]
    fn test_child_text_with_nested_same_name_element() {
        let resp = Response::from(
            r#"<response><item><item>inner</item><name>outer</name></item></response>"#,
        );
        assert_eq!(resp.child_text("item"), Some("innerouter".to_string()));
    }

    #[test]
    fn test_status_text() {
        let resp = Response::from(r#"<get_tasks_response status="200" status_text="OK"/>"#);
        assert_eq!(resp.status_text(), Some("OK".to_string()));
    }

    #[test]
    fn test_missing_status() {
        let resp = Response::from(r#"<something/>"#);
        assert_eq!(resp.status_code(), None);
    }
}
