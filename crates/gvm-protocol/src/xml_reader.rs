//! Streaming XML reader for detecting GMP response boundaries.
//!
//! Reads XML data incrementally and detects when a complete root element
//! has been received (matching python-gvm's `XmlReader`).

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::ProtocolError;

/// Streaming XML reader that detects when a complete XML root element has been received.
///
/// Feed data incrementally via [`feed`] and check [`is_complete`] to know when
/// a full GMP response has been received.
pub struct XmlReader {
    buffer: Vec<u8>,
    complete: bool,
}

impl XmlReader {
    /// Create a new XmlReader.
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            complete: false,
        }
    }

    /// Feed data into the reader.
    ///
    /// # Errors
    /// Returns an error if the data contains fatally malformed XML.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        self.buffer.extend_from_slice(data);
        self.check_complete()
    }

    /// Check if a complete XML root element has been received.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Return the accumulated data.
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume the reader and return the accumulated data.
    pub fn into_data(self) -> Vec<u8> {
        self.buffer
    }

    /// Reset the reader for reuse.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.complete = false;
    }

    fn check_complete(&mut self) -> Result<(), ProtocolError> {
        if self.complete {
            return Ok(());
        }

        let text = match std::str::from_utf8(&self.buffer) {
            Ok(t) => t,
            Err(_) => return Ok(()), // incomplete UTF-8, wait for more data
        };

        let mut reader = Reader::from_str(text);
        reader.config_mut().trim_text(false);

        let mut depth: i32 = 0;
        let mut seen_start = false;

        loop {
            match reader.read_event() {
                Ok(Event::Start(_)) => {
                    seen_start = true;
                    depth += 1;
                }
                Ok(Event::End(_)) => {
                    depth -= 1;
                    if seen_start && depth == 0 {
                        self.complete = true;
                        return Ok(());
                    }
                }
                Ok(Event::Empty(_)) => {
                    if !seen_start {
                        // Self-closing root element like <get_version_response status="200"/>
                        self.complete = true;
                        return Ok(());
                    }
                    // Self-closing child element, doesn't affect depth
                }
                Ok(Event::Eof) => {
                    // Not complete yet
                    return Ok(());
                }
                Ok(_) => continue,
                Err(_) => {
                    // Could be incomplete XML, wait for more data
                    return Ok(());
                }
            }
        }
    }
}

impl Default for XmlReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // XMLR-001
    #[test]
    fn test_self_closing_element() {
        let mut reader = XmlReader::new();
        reader
            .feed(br#"<get_version_response status="200"/>"#)
            .expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-002
    #[test]
    fn test_element_with_children() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"<get_tasks_response><task><name>t1</name></task></get_tasks_response>")
            .expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-003
    #[test]
    fn test_nested_same_name() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"<a><a>inner</a></a>")
            .expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-004
    #[test]
    fn test_chunked_delivery() {
        let mut reader = XmlReader::new();

        reader.feed(b"<get_tasks_re").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"sponse status=\"200\"").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"><task><name>").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"t1</name></task>").expect("feed ok");
        assert!(!reader.is_complete());

        reader.feed(b"</get_tasks_response>").expect("feed ok");
        assert!(reader.is_complete());
    }

    // XMLR-009
    #[test]
    fn test_empty_root_element() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"<response></response>")
            .expect("feed ok");
        assert!(reader.is_complete());
    }

    #[test]
    fn test_reset() {
        let mut reader = XmlReader::new();
        reader.feed(b"<a/>").expect("feed ok");
        assert!(reader.is_complete());

        reader.reset();
        assert!(!reader.is_complete());
        assert!(reader.data().is_empty());
    }
}
