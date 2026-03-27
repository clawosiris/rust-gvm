// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! P1 fuzz target for grammar-based XML node builder fuzzing.
//!
//! Tests `parse_document()` with structured arbitrary input to exercise
//! attribute parsing, child ordering, mixed content, CDATA, and edge cases.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// ASCII-safe string for element/attribute names (avoids invalid XML names).
#[derive(Debug, Clone, Arbitrary)]
struct XmlName(#[arbitrary(with = |u: &mut arbitrary::Unstructured| -> arbitrary::Result<String> {
    // XML names must start with letter or underscore, contain letters/digits/hyphens/underscores
    let len = u.int_in_range(1..=16)?;
    let mut name = String::with_capacity(len);
    
    // First char: letter or underscore
    let first_chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    let idx = u.int_in_range(0..=first_chars.len() - 1)?;
    name.push(first_chars[idx] as char);
    
    // Remaining chars
    let rest_chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    for _ in 1..len {
        let idx = u.int_in_range(0..=rest_chars.len() - 1)?;
        name.push(rest_chars[idx] as char);
    }
    
    Ok(name)
})] String);

/// Text content that's safe for XML (escaped).
#[derive(Debug, Clone, Arbitrary)]
struct XmlText(#[arbitrary(with = |u: &mut arbitrary::Unstructured| -> arbitrary::Result<String> {
    let len = u.int_in_range(0..=64)?;
    let mut text = String::with_capacity(len);
    
    for _ in 0..len {
        // Include some characters that need escaping
        let chars = b"abcdefghijklmnopqrstuvwxyz 0123456789!@#$%^*()[]{}|;:',./?\n\t";
        let idx = u.int_in_range(0..=chars.len() - 1)?;
        text.push(chars[idx] as char);
    }
    
    Ok(text)
})] String);

#[derive(Debug, Clone, Arbitrary)]
struct XmlAttribute {
    name: XmlName,
    value: XmlText,
}

#[derive(Debug, Clone, Arbitrary)]
enum XmlContent {
    Text(XmlText),
    CData(XmlText),
    Comment(XmlText),
    Child(Box<XmlElement>),
}

#[derive(Debug, Clone, Arbitrary)]
struct XmlElement {
    name: XmlName,
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| -> arbitrary::Result<Vec<XmlAttribute>> {
        let len = u.int_in_range(0..=8)?;
        (0..len).map(|_| XmlAttribute::arbitrary(u)).collect()
    })]
    attributes: Vec<XmlAttribute>,
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| -> arbitrary::Result<Vec<XmlContent>> {
        let len = u.int_in_range(0..=8)?;
        (0..len).map(|_| XmlContent::arbitrary(u)).collect()
    })]
    contents: Vec<XmlContent>,
    self_closing: bool,
}

fn escape_xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_cdata(s: &str) -> String {
    // CDATA cannot contain "]]>" — replace with escaped version
    s.replace("]]>", "]]&gt;")
}

fn escape_comment(s: &str) -> String {
    // Comments cannot contain "--"
    s.replace("--", "- -")
}

impl XmlElement {
    fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push('<');
        xml.push_str(&self.name.0);

        for attr in &self.attributes {
            xml.push(' ');
            xml.push_str(&attr.name.0);
            xml.push_str("=\"");
            xml.push_str(&escape_xml_text(&attr.value.0));
            xml.push('"');
        }

        if self.self_closing && self.contents.is_empty() {
            xml.push_str("/>");
            return xml;
        }

        xml.push('>');

        for content in &self.contents {
            match content {
                XmlContent::Text(text) => {
                    xml.push_str(&escape_xml_text(&text.0));
                }
                XmlContent::CData(text) => {
                    xml.push_str("<![CDATA[");
                    xml.push_str(&escape_cdata(&text.0));
                    xml.push_str("]]>");
                }
                XmlContent::Comment(text) => {
                    xml.push_str("<!--");
                    xml.push_str(&escape_comment(&text.0));
                    xml.push_str("-->");
                }
                XmlContent::Child(child) => {
                    xml.push_str(&child.to_xml());
                }
            }
        }

        xml.push_str("</");
        xml.push_str(&self.name.0);
        xml.push('>');
        xml
    }
}

fuzz_target!(|input: XmlElement| {
    let xml = input.to_xml();

    // Test parse_document via gvm_gmp Response parsing
    // We construct a valid-ish response wrapper and parse
    let response = gvm_protocol::Response::from(xml.as_str());

    // Access all fields to ensure no panics during traversal
    let _ = response.data();
    let _ = response.status_code();
    let _ = response.status_text();

    // Also try the typed parsers which call parse_document internally
    let _ = gvm_gmp::responses::version::GetVersionResponse::from_response(&response);
    let _ = gvm_gmp::responses::auth::AuthenticateResponse::from_response(&response);
});
