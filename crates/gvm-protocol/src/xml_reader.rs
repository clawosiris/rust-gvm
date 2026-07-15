// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Streaming XML reader for detecting GMP response boundaries.
//!
//! Reads XML data incrementally, validates document structure, and preserves
//! exact root-element boundaries across transport chunks.

use quick_xml::errors::{Error as XmlError, IllFormedError, SyntaxError};
use quick_xml::escape::resolve_xml_entity;
use quick_xml::events::{BytesDecl, BytesEnd, BytesRef, BytesStart, BytesText, Event};
use quick_xml::{Reader, XmlVersion};

use crate::error::ProtocolError;

const DEFAULT_MAX_BUFFER_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_DEPTH: usize = 256;
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Streaming XML reader that detects when a complete XML root element has been received.
///
/// Feed data incrementally via [`XmlReader::feed`] and check [`XmlReader::is_complete`] to know when
/// a full GMP response has been received.
pub struct XmlReader {
    buffer: Vec<u8>,
    max_buffer_bytes: Option<usize>,
    max_depth: usize,
    complete: bool,
    seen_start: bool,
    declaration_allowed: bool,
    resume_offset: usize,
    frame_end: Option<usize>,
    element_names: Vec<Vec<u8>>,
}

impl std::fmt::Debug for XmlReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XmlReader")
            .field("buffer_len", &self.buffer.len())
            .field("max_buffer_bytes", &self.max_buffer_bytes)
            .field("max_depth", &self.max_depth)
            .field("complete", &self.complete)
            .field("frame_end", &self.frame_end)
            .field("depth", &self.element_names.len())
            .finish()
    }
}

impl XmlReader {
    /// Create a new `XmlReader`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_buffer_limit(Some(DEFAULT_MAX_BUFFER_BYTES))
    }

    /// Create a new `XmlReader` with a custom maximum buffer size.
    #[must_use]
    pub fn with_max_buffer(max: usize) -> Self {
        Self::with_buffer_limit(Some(max))
    }

    /// Create a new `XmlReader` with an optional maximum buffer size.
    #[must_use]
    pub fn with_buffer_limit(max_buffer_bytes: Option<usize>) -> Self {
        Self::with_limits(max_buffer_bytes, DEFAULT_MAX_DEPTH)
    }

    /// Create a new `XmlReader` with custom buffer and nesting limits.
    #[must_use]
    pub fn with_limits(max_buffer_bytes: Option<usize>, max_depth: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_buffer_bytes,
            max_depth,
            complete: false,
            seen_start: false,
            declaration_allowed: true,
            resume_offset: 0,
            frame_end: None,
            element_names: Vec::new(),
        }
    }

    /// Feed data into the reader.
    ///
    /// # Errors
    /// Returns an error if the data contains fatally malformed XML.
    pub fn feed(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        if let Some(max) = self.max_buffer_bytes {
            if self.buffer.len().saturating_add(data.len()) > max {
                return Err(ProtocolError::BufferOverflow { max });
            }
        }

        self.buffer.extend_from_slice(data);
        self.check_complete()
    }

    /// Feed only the bytes belonging to the current XML frame.
    ///
    /// The returned count is the number of bytes consumed from `data`. Once
    /// [`XmlReader::is_complete`] is true, any unconsumed suffix belongs to the
    /// next frame. This method applies the configured size limit to each frame
    /// independently and never copies an unbounded trailing frame into the
    /// current reader.
    ///
    /// # Errors
    /// Returns an error if the current frame is malformed, too deeply nested,
    /// or exceeds the configured buffer limit. Reset the reader before reuse
    /// after an error.
    pub fn feed_frame(&mut self, data: &[u8]) -> Result<usize, ProtocolError> {
        if self.complete {
            return Ok(0);
        }

        // `take_frame` can leave an already-buffered tail from `feed`. Parse
        // that tail before consuming any new bytes so mixed API use cannot
        // discard a complete buffered frame.
        self.check_complete()?;
        if self.complete {
            return Ok(0);
        }

        let previous_len = self.buffer.len();
        let accepted = match self.max_buffer_bytes {
            Some(max) => data.len().min(max.saturating_sub(previous_len)),
            None => data.len(),
        };

        self.buffer.extend_from_slice(&data[..accepted]);
        self.check_complete()?;

        if let Some(frame_end) = self.frame_end {
            let consumed = frame_end.saturating_sub(previous_len);
            self.buffer.truncate(frame_end);
            return Ok(consumed);
        }

        if accepted < data.len()
            || self
                .max_buffer_bytes
                .is_some_and(|max| self.buffer.len() >= max)
        {
            return Err(ProtocolError::BufferOverflow {
                max: self.max_buffer_bytes.unwrap_or_default(),
            });
        }

        Ok(accepted)
    }

    /// Check if a complete XML root element has been received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Return the length of the first complete XML frame.
    #[must_use]
    pub fn frame_len(&self) -> Option<usize> {
        self.frame_end
    }

    /// Return the first complete XML frame, if available.
    #[must_use]
    pub fn frame(&self) -> Option<&[u8]> {
        self.frame_end.map(|end| &self.buffer[..end])
    }

    /// Return bytes accumulated after the first complete XML frame.
    #[must_use]
    pub fn tail(&self) -> Option<&[u8]> {
        self.frame_end.map(|end| &self.buffer[end..])
    }

    /// Remove and return the first complete XML frame.
    ///
    /// Any trailing bytes remain buffered and are parsed on the next call.
    ///
    /// # Errors
    /// Returns an error if buffered trailing data is malformed when this method
    /// is called again to extract the next frame.
    pub fn take_frame(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        self.check_complete()?;
        let Some(frame_end) = self.frame_end else {
            return Ok(None);
        };

        let tail = self.buffer.split_off(frame_end);
        let frame = std::mem::replace(&mut self.buffer, tail);
        self.reset_state();
        Ok(Some(frame))
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
        self.reset_state();
    }

    fn reset_state(&mut self) {
        self.complete = false;
        self.seen_start = false;
        self.declaration_allowed = true;
        self.resume_offset = 0;
        self.frame_end = None;
        self.element_names.clear();
    }

    fn check_complete(&mut self) -> Result<(), ProtocolError> {
        if self.complete {
            return Ok(());
        }

        let unparsed = &self.buffer[self.resume_offset..];
        let bom_len =
            usize::from(self.resume_offset == 0 && unparsed.starts_with(UTF8_BOM)) * UTF8_BOM.len();
        let mut reader = configured_reader(unparsed);
        let (mut event_buf, mut parsed_len) = (Vec::new(), 0_usize);

        loop {
            match reader.read_event_into(&mut event_buf) {
                Ok(Event::Start(element)) => {
                    open_element(
                        &element,
                        &mut self.seen_start,
                        &mut self.element_names,
                        self.max_depth,
                    )?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::End(element)) => {
                    parsed_len = bom_len + reader.buffer_position() as usize;
                    if close_element(&element, &mut self.element_names)? {
                        let frame_end =
                            validated_frame_end(&self.buffer, self.resume_offset, parsed_len)?;
                        self.complete = true;
                        self.frame_end = Some(frame_end);
                        return Ok(());
                    }
                }
                Ok(Event::Empty(element)) => {
                    parsed_len = bom_len + reader.buffer_position() as usize;
                    validate_empty_element(&element, self.element_names.len(), self.max_depth)?;
                    if !self.seen_start {
                        let frame_end =
                            validated_frame_end(&self.buffer, self.resume_offset, parsed_len)?;
                        self.seen_start = true;
                        self.complete = true;
                        self.frame_end = Some(frame_end);
                        return Ok(());
                    }
                }
                Ok(Event::Text(text)) => {
                    if validate_text(&text, self.seen_start, &mut self.declaration_allowed)? {
                        self.resume_offset += parsed_len;
                        return Ok(());
                    }
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::CData(data)) => {
                    validate_cdata(data.as_ref(), self.seen_start)?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::DocType(_)) => {
                    return Err(xml_parse_error("DOCTYPE declarations are not supported"));
                }
                Ok(Event::Decl(declaration)) => {
                    accept_declaration(
                        &declaration,
                        self.seen_start,
                        &mut self.declaration_allowed,
                    )?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::Comment(comment)) => {
                    validate_misc(
                        comment.as_ref(),
                        self.seen_start,
                        &mut self.declaration_allowed,
                    )?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::PI(instruction)) => {
                    validate_processing_instruction(
                        instruction.as_ref(),
                        self.seen_start,
                        &mut self.declaration_allowed,
                    )?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::GeneralRef(reference)) => {
                    if !self.seen_start {
                        return Err(xml_parse_error("entity reference before root element"));
                    }
                    validate_reference(&reference)?;
                    parsed_len = bom_len + reader.buffer_position() as usize;
                }
                Ok(Event::Eof) => {
                    self.resume_offset += parsed_len;
                    return Ok(());
                }
                Err(error) => {
                    if !is_incomplete_xml_error(&error) {
                        return Err(xml_parse_error(error));
                    }

                    self.resume_offset += parsed_len;
                    return Ok(());
                }
            }

            event_buf.clear();
        }
    }
}

fn configured_reader(input: &[u8]) -> Reader<&[u8]> {
    let mut reader = Reader::from_reader(input);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = false;
    reader.config_mut().allow_unmatched_ends = true;
    reader.config_mut().check_comments = true;
    reader
}

fn validate_misc(
    data: &[u8],
    seen_start: bool,
    declaration_allowed: &mut bool,
) -> Result<(), ProtocolError> {
    validate_xml_bytes(data)?;
    if !seen_start {
        *declaration_allowed = false;
    }
    Ok(())
}

fn validate_processing_instruction(
    data: &[u8],
    seen_start: bool,
    declaration_allowed: &mut bool,
) -> Result<(), ProtocolError> {
    validate_misc(data, seen_start, declaration_allowed)?;
    let target_end = data
        .iter()
        .position(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(data.len());
    let target = &data[..target_end];
    validate_name(target)?;
    if target.eq_ignore_ascii_case(b"xml") {
        return Err(xml_parse_error(
            "processing instruction target 'xml' is reserved",
        ));
    }
    Ok(())
}

fn accept_declaration(
    declaration: &BytesDecl<'_>,
    seen_start: bool,
    declaration_allowed: &mut bool,
) -> Result<(), ProtocolError> {
    if seen_start || !*declaration_allowed {
        return Err(xml_parse_error(
            "XML declaration must be the first document event",
        ));
    }
    validate_declaration(declaration)?;
    *declaration_allowed = false;
    Ok(())
}

fn validate_cdata(data: &[u8], seen_start: bool) -> Result<(), ProtocolError> {
    if !seen_start {
        return Err(xml_parse_error("CDATA before root element"));
    }
    validate_xml_bytes(data)
}

fn open_element(
    element: &BytesStart<'_>,
    seen_start: &mut bool,
    element_names: &mut Vec<Vec<u8>>,
    max_depth: usize,
) -> Result<(), ProtocolError> {
    validate_start(element)?;
    *seen_start = true;
    element_names.push(element.name().as_ref().to_vec());
    if element_names.len() > max_depth {
        return Err(xml_parse_error(format!(
            "XML nesting exceeds configured limit of {max_depth}"
        )));
    }
    Ok(())
}

fn close_element(
    element: &BytesEnd<'_>,
    element_names: &mut Vec<Vec<u8>>,
) -> Result<bool, ProtocolError> {
    let Some(expected) = element_names.pop() else {
        return Err(xml_parse_error("unmatched closing tag"));
    };
    if expected.as_slice() != element.name().as_ref() {
        return Err(xml_parse_error("mismatched closing tag"));
    }
    Ok(element_names.is_empty())
}

fn validate_empty_element(
    element: &BytesStart<'_>,
    current_depth: usize,
    max_depth: usize,
) -> Result<(), ProtocolError> {
    validate_start(element)?;
    if current_depth.saturating_add(1) > max_depth {
        return Err(xml_parse_error(format!(
            "XML nesting exceeds configured limit of {max_depth}"
        )));
    }
    Ok(())
}

fn validate_text(
    text: &BytesText<'_>,
    seen_start: bool,
    declaration_allowed: &mut bool,
) -> Result<bool, ProtocolError> {
    let decoded = match std::str::from_utf8(text.as_ref()) {
        Ok(text) => text,
        Err(error) if error.error_len().is_none() => {
            let prefix = std::str::from_utf8(&text.as_ref()[..error.valid_up_to()])
                .map_err(xml_parse_error)?;
            validate_xml_chars(prefix)?;
            if !seen_start && !prefix.chars().all(is_xml_whitespace) {
                return Err(xml_parse_error("non-whitespace text before root element"));
            }
            if !seen_start && !prefix.is_empty() {
                *declaration_allowed = false;
            }
            return Ok(true);
        }
        Err(error) => return Err(xml_parse_error(error)),
    };

    validate_xml_chars(decoded)?;
    if !seen_start {
        if !decoded.chars().all(is_xml_whitespace) {
            return Err(xml_parse_error("non-whitespace text before root element"));
        }
        *declaration_allowed = false;
    }
    Ok(false)
}

fn validate_start(element: &BytesStart<'_>) -> Result<(), ProtocolError> {
    validate_name(element.name().as_ref())?;
    validate_xml_bytes(element.as_ref())?;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(xml_parse_error)?;
        validate_name(attribute.key.as_ref())?;
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(xml_parse_error)?;
        validate_xml_chars(&value)?;
    }
    Ok(())
}

fn validate_declaration(declaration: &BytesDecl<'_>) -> Result<(), ProtocolError> {
    validate_xml_bytes(declaration.as_ref())?;
    declaration.xml_version().map_err(xml_parse_error)?;
    if let Some(encoding) = declaration.encoding() {
        let encoding = encoding.map_err(xml_parse_error)?;
        if !encoding.eq_ignore_ascii_case(b"utf-8") {
            return Err(xml_parse_error("only UTF-8 XML declarations are supported"));
        }
    }
    if let Some(standalone) = declaration.standalone() {
        let standalone = standalone.map_err(xml_parse_error)?;
        if standalone.as_ref() != b"yes" && standalone.as_ref() != b"no" {
            return Err(xml_parse_error("standalone must be 'yes' or 'no'"));
        }
    }
    Ok(())
}

fn validate_reference(reference: &BytesRef<'_>) -> Result<(), ProtocolError> {
    if let Some(character) = reference.resolve_char_ref().map_err(xml_parse_error)? {
        return validate_xml_chars(&character.to_string());
    }
    let reference = reference.decode().map_err(xml_parse_error)?;
    if resolve_xml_entity(&reference).is_none() {
        return Err(xml_parse_error("unknown entity reference"));
    }
    Ok(())
}

fn validate_frame(frame: &[u8]) -> Result<(), ProtocolError> {
    validate_xml_bytes(frame)
}

fn validated_frame_end(
    buffer: &[u8],
    resume_offset: usize,
    parsed_len: usize,
) -> Result<usize, ProtocolError> {
    let frame_end = resume_offset + parsed_len;
    validate_frame(&buffer[..frame_end])?;
    Ok(frame_end)
}

fn validate_xml_bytes(data: &[u8]) -> Result<(), ProtocolError> {
    let decoded = std::str::from_utf8(data).map_err(xml_parse_error)?;
    validate_xml_chars(decoded)
}

fn validate_xml_chars(data: &str) -> Result<(), ProtocolError> {
    if data.chars().all(is_xml_char) {
        Ok(())
    } else {
        Err(xml_parse_error("character is not legal in XML 1.0"))
    }
}

fn validate_name(name: &[u8]) -> Result<(), ProtocolError> {
    let name = std::str::from_utf8(name).map_err(xml_parse_error)?;
    let mut characters = name.chars();
    if !characters.next().is_some_and(is_xml_name_start) || !characters.all(is_xml_name_character) {
        return Err(xml_parse_error("invalid XML name"));
    }
    Ok(())
}

fn is_xml_whitespace(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn is_xml_char(character: char) -> bool {
    matches!(
        character,
        '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

fn is_xml_name_start(character: char) -> bool {
    matches!(
        character,
        ':' | 'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}'
    )
}

fn is_xml_name_character(character: char) -> bool {
    is_xml_name_start(character)
        || matches!(
            character,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}'
        )
}

fn xml_parse_error(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::XmlParse(format!("Malformed XML: {error}"))
}

impl Default for XmlReader {
    fn default() -> Self {
        Self::new()
    }
}

fn is_incomplete_xml_error(error: &XmlError) -> bool {
    matches!(
        error,
        XmlError::Syntax(
            SyntaxError::UnclosedPI
                | SyntaxError::UnclosedXmlDecl
                | SyntaxError::UnclosedComment
                | SyntaxError::UnclosedDoctype
                | SyntaxError::UnclosedCData
                | SyntaxError::UnclosedTag
                | SyntaxError::UnclosedSingleQuotedAttributeValue
                | SyntaxError::UnclosedDoubleQuotedAttributeValue
        ) | XmlError::IllFormed(
            IllFormedError::MissingEndTag(_) | IllFormedError::UnclosedReference
        )
    )
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
        assert_eq!(reader.element_names.len(), 2);
        assert!(reader.seen_start);
        assert!(!reader.is_complete());

        reader.feed(b"value</child></root>").expect("feed ok");
        assert!(reader.is_complete());
    }

    #[test]
    fn test_buffer_overflow() {
        let mut reader = XmlReader::with_max_buffer(8);
        let error = reader.feed(b"<response/>").expect_err("buffer overflow");

        assert!(matches!(error, ProtocolError::BufferOverflow { max: 8 }));
    }

    #[test]
    fn test_malformed_xml_returns_parse_error_after_start() {
        let mut reader = XmlReader::new();
        let error = reader.feed(b"<root><!x></root>").expect_err("parse error");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_unmatched_end_tag_before_start_is_rejected() {
        let mut reader = XmlReader::new();

        let error = reader.feed(b"</garbage>").expect_err("parse error");
        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_non_whitespace_text_before_root_is_rejected() {
        let mut reader = XmlReader::new();

        let error = reader
            .feed(b"garbage<real_response/>")
            .expect_err("parse error");
        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_mismatched_closing_tag_is_rejected_across_chunks() {
        let mut reader = XmlReader::new();

        reader.feed(b"<root><child>").expect("incomplete XML");
        let error = reader.feed(b"</root></child>").expect_err("parse error");
        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_exact_frame_and_tail_are_preserved() {
        let mut reader = XmlReader::new();

        reader.feed(b"<one/><two/>").expect("feed ok");

        assert_eq!(reader.frame_len(), Some(b"<one/>".len()));
        assert_eq!(reader.frame(), Some(b"<one/>".as_slice()));
        assert_eq!(reader.tail(), Some(b"<two/>".as_slice()));
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<one/>".to_vec())
        );
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<two/>".to_vec())
        );
        assert_eq!(reader.take_frame().expect("valid XML"), None);
    }

    #[test]
    fn test_exact_boundary_after_resumed_parse() {
        let mut reader = XmlReader::new();

        reader.feed(b"<root><child>").expect("incomplete XML");
        reader
            .feed(b"value</child></root><next/>")
            .expect("feed ok");

        assert_eq!(
            reader.frame(),
            Some(b"<root><child>value</child></root>".as_slice())
        );
        assert_eq!(reader.tail(), Some(b"<next/>".as_slice()));
    }

    #[test]
    fn test_valid_prefix_is_part_of_frame() {
        let mut reader = XmlReader::new();
        let xml = b"<?xml version=\"1.0\"?> \n<!-- comment --><root/>";

        reader.feed(xml).expect("feed ok");

        assert_eq!(reader.frame(), Some(xml.as_slice()));
        assert_eq!(reader.tail(), Some(b"".as_slice()));
    }

    #[test]
    fn test_declaration_after_whitespace_is_rejected() {
        let mut reader = XmlReader::new();
        let error = reader
            .feed(b" \n<?xml version=\"1.0\"?><root/>")
            .expect_err("misplaced declaration");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_utf8_bom_is_preserved_in_exact_frame() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"\xEF\xBB\xBF<one/><two/>")
            .expect("BOM-prefixed XML");

        assert_eq!(reader.frame(), Some(b"\xEF\xBB\xBF<one/>".as_slice()));
        assert_eq!(reader.tail(), Some(b"<two/>".as_slice()));
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"\xEF\xBB\xBF<one/>".to_vec())
        );
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<two/>".to_vec())
        );
    }

    #[test]
    fn test_split_utf8_bom_is_chunk_safe() {
        let mut reader = XmlReader::new();
        for byte in b"\xEF\xBB\xBF<root/>" {
            reader.feed(&[*byte]).expect("BOM fragment");
        }

        assert_eq!(reader.frame(), Some(b"\xEF\xBB\xBF<root/>".as_slice()));
    }

    #[test]
    fn test_doctype_is_rejected() {
        let mut reader = XmlReader::new();
        let error = reader
            .feed(b"<!DOCTYPE root><root/>")
            .expect_err("doctype must be rejected");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_invalid_declaration_is_rejected() {
        let mut reader = XmlReader::new();
        let error = reader
            .feed(b"<?xml?><root/>")
            .expect_err("declaration version is required");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_invalid_processing_instruction_targets_are_rejected() {
        for xml in [
            b"<?XML data?><root/>".as_slice(),
            b"<?1bad?><root/>".as_slice(),
            b"<?bad!name?><root/>".as_slice(),
        ] {
            let mut reader = XmlReader::new();
            let error = reader.feed(xml).expect_err("invalid PI target");
            assert!(matches!(error, ProtocolError::XmlParse(_)));
        }

        let mut valid = XmlReader::new();
        valid
            .feed(b"<?gmp instruction?><root/>")
            .expect("valid PI target");
        assert!(valid.is_complete());
    }

    #[test]
    fn test_invalid_names_and_references_are_rejected() {
        for xml in [
            b"<1bad/>".as_slice(),
            b"<bad!name/>".as_slice(),
            b"<root>&bogus;</root>".as_slice(),
            b"<root>&#0;</root>".as_slice(),
            b"<root value=\"&bogus;\"/>".as_slice(),
        ] {
            let mut reader = XmlReader::new();
            let error = reader.feed(xml).expect_err("malformed XML");
            assert!(matches!(error, ProtocolError::XmlParse(_)));
        }

        let mut valid = XmlReader::new();
        valid
            .feed(b"<root value=\"&amp;\">&lt;&#65;</root>")
            .expect("predefined and legal numeric references");
        assert!(valid.is_complete());
    }

    #[test]
    fn test_xml_illegal_characters_are_rejected() {
        for xml in [
            b"\x0B<root/>".as_slice(),
            "\u{A0}<root/>".as_bytes(),
            b"<root>\x0B</root>".as_slice(),
            b"<root><![CDATA[\x0B]]></root>".as_slice(),
        ] {
            let mut reader = XmlReader::new();
            let error = reader.feed(xml).expect_err("illegal XML character");
            assert!(matches!(error, ProtocolError::XmlParse(_)));
        }
    }

    #[test]
    fn test_incomplete_utf8_cannot_mask_invalid_prefix() {
        let data = [0, 0, 2, 2, 0, 0, 52, 0, 127, 223];
        let mut single = XmlReader::new();
        assert!(matches!(
            single.feed(&data),
            Err(ProtocolError::XmlParse(_))
        ));

        let mut chunked = XmlReader::new();
        let mut error = None;
        for byte in data {
            if let Err(found) = chunked.feed(&[byte]) {
                error = Some(found);
                break;
            }
        }
        assert!(matches!(error, Some(ProtocolError::XmlParse(_))));
    }

    #[test]
    fn test_debug_output_redacts_buffer_contents() {
        let mut reader = XmlReader::new();
        reader
            .feed(b"<secret>do-not-log</secret>")
            .expect("valid XML");

        let debug = format!("{reader:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("do-not-log"));
        assert!(debug.contains("buffer_len"));
    }

    #[test]
    fn test_depth_limit_is_enforced() {
        let mut reader = XmlReader::with_limits(None, 2);
        let error = reader
            .feed(b"<one><two><three/></two></one>")
            .expect_err("depth must be bounded");

        assert!(matches!(error, ProtocolError::XmlParse(_)));
    }

    #[test]
    fn test_feed_frame_consumes_only_first_frame() {
        let mut reader = XmlReader::with_max_buffer(6);
        let input = b"<one/><second-response/>";

        let consumed = reader.feed_frame(input).expect("first frame within limit");

        assert_eq!(consumed, b"<one/>".len());
        assert_eq!(reader.data(), b"<one/>");
        assert_eq!(&input[consumed..], b"<second-response/>");
    }

    #[test]
    fn test_feed_frame_does_not_discard_a_buffered_tail() {
        let mut reader = XmlReader::new();
        reader.feed(b"<one/><two/><three/>").expect("feed ok");
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<one/>".to_vec())
        );

        assert_eq!(reader.feed_frame(b"<four/>").expect("buffered frame"), 0);
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<two/>".to_vec())
        );
        assert_eq!(reader.feed_frame(b"<four/>").expect("buffered frame"), 0);
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<three/>".to_vec())
        );

        assert_eq!(reader.feed_frame(b"<four/>").expect("new frame"), 7);
        assert_eq!(
            reader.take_frame().expect("valid XML"),
            Some(b"<four/>".to_vec())
        );
    }

    #[test]
    fn test_feed_frame_accepts_exact_limit_and_rejects_incomplete_limit() {
        let mut exact = XmlReader::with_max_buffer(6);
        assert_eq!(exact.feed_frame(b"<one/>").expect("exact limit"), 6);
        assert!(exact.is_complete());

        let mut incomplete = XmlReader::with_max_buffer(6);
        let error = incomplete
            .feed_frame(b"<root>")
            .expect_err("incomplete frame at limit");
        assert!(matches!(error, ProtocolError::BufferOverflow { max: 6 }));
    }

    #[test]
    fn test_incomplete_multibyte_text_across_chunks() {
        let mut reader = XmlReader::new();
        let xml = "<root>Grüße</root>".as_bytes();
        let split = xml.iter().position(|byte| *byte == 0xC3).expect("umlaut") + 1;

        reader.feed(&xml[..split]).expect("incomplete UTF-8");
        assert!(!reader.is_complete());
        reader.feed(&xml[split..]).expect("complete UTF-8");

        assert!(reader.is_complete());
    }
}
