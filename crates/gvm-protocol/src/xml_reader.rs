// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Streaming XML reader for detecting GMP response boundaries.
//!
//! Reads XML data incrementally and detects when a complete root element
//! has been received (matching python-gvm's `XmlReader`).

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::ProtocolError;

/// Streaming XML reader that detects when a complete XML root element has been received.
///
/// Feed data incrementally via [`XmlReader::feed`] and check [`XmlReader::is_complete`] to know when
/// a full GMP response has been received.
pub struct XmlReader {
    buffer: Vec<u8>,
    complete: bool,
    depth: i32,
    seen_start: bool,
    resume_offset: usize,
}

impl XmlReader {
    /// Create a new `XmlReader`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            complete: false,
            depth: 0,
            seen_start: false,
            resume_offset: 0,
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
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Return the accumulated data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume the reader and return the accumulated data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.buffer
    }

    /// Reset the reader for reuse.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.complete = false;
        self.depth = 0;
        self.seen_start = false;
        self.resume_offset = 0;
    }

    fn check_complete(&mut self) -> Result<(), ProtocolError> {
        if self.complete {
            return Ok(());
        }

        let mut reader = Reader::from_reader(&self.buffer[self.resume_offset..]);
        reader.config_mut().trim_text(false);
        reader.config_mut().check_end_names = false;
        reader.config_mut().allow_unmatched_ends = true;
        let mut event_buf = Vec::new();
        let mut parsed_len = 0_usize;

        loop {
            match reader.read_event_into(&mut event_buf) {
                Ok(Event::Start(_)) => {
                    self.seen_start = true;
                    self.depth += 1;
                    parsed_len = reader.buffer_position() as usize;
                }
                Ok(Event::End(_)) => {
                    self.depth -= 1;
                    parsed_len = reader.buffer_position() as usize;
                    if self.seen_start && self.depth == 0 {
                        self.complete = true;
                        return Ok(());
                    }
                }
                Ok(Event::Empty(_)) => {
                    parsed_len = reader.buffer_position() as usize;
                    if !self.seen_start {
                        // Self-closing root element like <get_version_response status="200"/>
                        self.complete = true;
                        return Ok(());
                    }
                    // Self-closing child element, doesn't affect depth
                }
                Ok(Event::Eof) => {
                    // Not complete yet
                    self.resume_offset += parsed_len;
                    return Ok(());
                }
                Ok(_) => {
                    parsed_len = reader.buffer_position() as usize;
                }
                Err(_) => {
                    // Could be incomplete XML, wait for more data
                    self.resume_offset += parsed_len;
                    return Ok(());
                }
            }

            event_buf.clear();
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
        reader.feed(b"<a><a>inner</a></a>").expect("feed ok");
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
        reader.feed(b"<response></response>").expect("feed ok");
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

    #[test]
    fn test_resume_offset_tracks_completed_events() {
        let mut reader = XmlReader::new();

        reader.feed(b"<root><child>").expect("feed ok");

        assert_eq!(reader.resume_offset, b"<root><child>".len());
        assert_eq!(reader.depth, 2);
        assert!(reader.seen_start);
        assert!(!reader.is_complete());

        reader.feed(b"value</child></root>").expect("feed ok");
        assert!(reader.is_complete());
    }
}
