//! GMP response parsing.

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::ProtocolError;

/// A GMP response received from the server.
#[derive(Debug, Clone)]
pub struct Response {
    data: Vec<u8>,
}

impl Response {
    /// Create a new Response from raw bytes.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
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
        let text = std::str::from_utf8(&self.data).ok()?;
        let mut reader = Reader::from_str(text);
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"status" {
                            let val = std::str::from_utf8(&attr.value).ok()?;
                            return val.parse::<u16>().ok();
                        }
                    }
                    return None;
                }
                Ok(Event::Eof) => return None,
                Err(_) => return None,
                _ => continue,
            }
        }
    }

    /// Extract the `status_text` from the response root element.
    #[must_use]
    pub fn status_text(&self) -> Option<String> {
        let text = std::str::from_utf8(&self.data).ok()?;
        let mut reader = Reader::from_str(text);
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"status_text" {
                            return std::str::from_utf8(&attr.value).ok().map(String::from);
                        }
                    }
                    return None;
                }
                Ok(Event::Eof) => return None,
                Err(_) => return None,
                _ => continue,
            }
        }
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
    pub fn root_element_name(&self) -> Option<String> {
        let text = std::str::from_utf8(&self.data).ok()?;
        let mut reader = Reader::from_str(text);
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                    return std::str::from_utf8(e.name().as_ref())
                        .ok()
                        .map(String::from);
                }
                Ok(Event::Eof) => return None,
                Err(_) => return None,
                _ => continue,
            }
        }
    }

    /// Extract the `id` attribute from the response root element (used for create responses).
    pub fn id(&self) -> Option<String> {
        let text = std::str::from_utf8(&self.data).ok()?;
        let mut reader = Reader::from_str(text);
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"id" {
                            return std::str::from_utf8(&attr.value).ok().map(String::from);
                        }
                    }
                    return None;
                }
                Ok(Event::Eof) => return None,
                Err(_) => return None,
                _ => continue,
            }
        }
    }

    /// Extract the text content of a named child element.
    #[must_use]
    pub fn child_text(&self, element_name: &str) -> Option<String> {
        let text = std::str::from_utf8(&self.data).ok()?;
        let mut reader = Reader::from_str(text);
        let mut inside_target = false;
        let mut buf = String::new();
        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    let qname = e.name();
                    let name = std::str::from_utf8(qname.as_ref()).ok()?;
                    if name == element_name {
                        inside_target = true;
                        buf.clear();
                    }
                }
                Ok(Event::Text(ref t)) if inside_target => {
                    let unescaped = t.unescape().ok()?;
                    buf.push_str(&unescaped);
                }
                Ok(Event::End(ref e)) if inside_target => {
                    let qname = e.name();
                    let name = std::str::from_utf8(qname.as_ref()).ok()?;
                    if name == element_name {
                        return Some(buf);
                    }
                }
                Ok(Event::Eof) => return None,
                Err(_) => return None,
                _ => continue,
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
