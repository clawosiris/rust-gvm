// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Structure-aware redaction for opt-in GMP wire traces.

use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, Writer};

const NON_UTF8_REDACTED: &[u8] = b"<non-utf8-redacted/>";
const MALFORMED_XML_REDACTED: &[u8] = b"<malformed-xml-redacted/>";
const REDACTED: &[u8] = b"redacted";

pub(super) fn redact_wire_bytes(bytes: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return NON_UTF8_REDACTED.to_vec();
    };
    redact_xml(text).unwrap_or_else(|| MALFORMED_XML_REDACTED.to_vec())
}

fn redact_xml(xml: &str) -> Option<Vec<u8>> {
    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::with_capacity(xml.len()));
    let mut stack = Vec::new();
    let mut sensitive_depth = 0_usize;
    let mut saw_root = false;
    let mut completed_root = false;
    let mut saw_declaration = false;

    loop {
        let event = reader.read_event().ok()?;
        match event {
            Event::Start(start) => {
                if stack.is_empty() {
                    if saw_root || completed_root {
                        return None;
                    }
                    saw_root = true;
                }
                let local_name = local_name(start.name().local_name().as_ref())?;
                let redacted_start = redact_attributes(&start, &stack, &local_name)?;
                let redact_contents =
                    sensitive_depth == 0 && is_sensitive_element(&stack, &local_name);
                stack.push(local_name);

                if sensitive_depth > 0 {
                    sensitive_depth += 1;
                } else {
                    writer.write_event(Event::Start(redacted_start)).ok()?;
                    if redact_contents {
                        writer
                            .write_event(Event::Empty(BytesStart::new("redacted")))
                            .ok()?;
                        sensitive_depth = 1;
                    }
                }
            }
            Event::Empty(start) => {
                if stack.is_empty() {
                    if saw_root || completed_root {
                        return None;
                    }
                    saw_root = true;
                    completed_root = true;
                }
                let local_name = local_name(start.name().local_name().as_ref())?;
                let redacted_start = redact_attributes(&start, &stack, &local_name)?;
                if sensitive_depth == 0 {
                    writer.write_event(Event::Empty(redacted_start)).ok()?;
                }
            }
            Event::End(end) => {
                stack.pop()?;
                if sensitive_depth > 0 {
                    sensitive_depth -= 1;
                    if sensitive_depth == 0 {
                        writer.write_event(Event::End(end)).ok()?;
                    }
                } else {
                    writer.write_event(Event::End(end)).ok()?;
                }
                if stack.is_empty() {
                    completed_root = true;
                }
            }
            Event::Text(text) => {
                if stack.is_empty() && !text.as_ref().iter().all(u8::is_ascii_whitespace) {
                    return None;
                }
                if sensitive_depth == 0 {
                    writer.write_event(Event::Text(text)).ok()?;
                }
            }
            Event::CData(data) => {
                if stack.is_empty() {
                    return None;
                }
                if sensitive_depth == 0 {
                    writer.write_event(Event::CData(data)).ok()?;
                }
            }
            Event::GeneralRef(reference) => write_general_reference(
                &mut writer,
                reference,
                !stack.is_empty(),
                sensitive_depth == 0,
            )?,
            Event::Decl(declaration) => {
                if saw_declaration || saw_root {
                    return None;
                }
                saw_declaration = true;
                writer.write_event(Event::Decl(declaration)).ok()?;
            }
            Event::DocType(_) => return None,
            Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => {
                return (saw_root && completed_root && stack.is_empty())
                    .then(|| writer.into_inner());
            }
        }
    }
}

fn write_general_reference(
    writer: &mut Writer<Vec<u8>>,
    reference: BytesRef<'_>,
    in_element: bool,
    visible: bool,
) -> Option<()> {
    if !in_element || !valid_general_reference(&reference) {
        return None;
    }
    if visible {
        writer.write_event(Event::GeneralRef(reference)).ok()?;
    }
    Some(())
}

fn valid_general_reference(reference: &BytesRef<'_>) -> bool {
    match reference.resolve_char_ref() {
        Ok(Some(character)) => matches!(
            character,
            '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
        ),
        Ok(None) => matches!(
            reference.as_ref(),
            b"lt" | b"gt" | b"amp" | b"apos" | b"quot"
        ),
        Err(_) => false,
    }
}

fn redact_attributes(
    start: &BytesStart<'_>,
    stack: &[String],
    element_name: &str,
) -> Option<BytesStart<'static>> {
    let mut redacted = start.clone().into_owned();
    redacted.clear_attributes();
    let credential_store_preference = is_credential_store_preference(stack, element_name);

    for attribute in start.attributes() {
        let attribute = attribute.ok()?;
        let key = attribute.key.as_ref();
        let key_name = local_name(attribute.key.local_name().as_ref())?;
        let sensitive = is_sensitive_name(&key_name)
            || (key_name == "value"
                && (credential_store_preference || is_sensitive_name(element_name)));
        redacted.push_attribute((
            key,
            if sensitive {
                REDACTED
            } else {
                attribute.value.as_ref()
            },
        ));
    }
    Some(redacted)
}

fn is_sensitive_element(stack: &[String], element_name: &str) -> bool {
    is_sensitive_name(element_name)
        || matches!(element_name, "value" | "param" | "default_value")
        || (element_name == "file" && stack.first().is_some_and(|root| root == "modify_license"))
}

fn is_credential_store_preference(stack: &[String], element_name: &str) -> bool {
    let in_credential_store = stack
        .first()
        .is_some_and(|root| root.contains("credential_store"));
    let in_preferences = stack.iter().any(|name| name == "preferences");
    let in_preference =
        element_name == "preference" || stack.iter().any(|name| name == "preference");
    in_credential_store && in_preferences && in_preference
}

fn is_sensitive_name(name: &str) -> bool {
    matches!(
        name,
        "password"
            | "community"
            | "private"
            | "private_key"
            | "private-key"
            | "passphrase"
            | "secret"
            | "client_secret"
            | "client-secret"
            | "auth_password"
            | "auth-password"
            | "privacy_password"
            | "privacy-password"
            | "key"
            | "token"
            | "api_key"
            | "api-key"
            | "access_token"
            | "access-token"
            | "refresh_token"
            | "refresh-token"
    )
}

fn local_name(name: &[u8]) -> Option<String> {
    std::str::from_utf8(name).ok().map(str::to_ascii_lowercase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_namespaced_case_insensitive_elements_and_sensitive_attributes() {
        let xml = br#"<g:modify_credential_store xmlns:g="urn:gmp" TOKEN="attribute-secret" visible="keep"><g:preferences><g:preference value="attribute-value"><g:name>token</g:name><g:value>preference-secret</g:value><g:default_value>server-default-secret</g:default_value></g:preference></g:preferences><g:Password algorithm="plain" value="password-attribute">nested<child>hidden</child></g:Password><Secret>&amp;<![CDATA[cdata-secret]]></Secret><COMMUNITY>snmp-secret</COMMUNITY><param name="timeout">generic-secret-capable</param><status>visible-value</status></g:modify_credential_store>"#;

        let redacted = String::from_utf8(redact_wire_bytes(xml)).expect("valid UTF-8");

        assert_eq!(
            redacted,
            r#"<g:modify_credential_store xmlns:g="urn:gmp" TOKEN="redacted" visible="keep"><g:preferences><g:preference value="redacted"><g:name>token</g:name><g:value><redacted/></g:value><g:default_value><redacted/></g:default_value></g:preference></g:preferences><g:Password algorithm="plain" value="redacted"><redacted/></g:Password><Secret><redacted/></Secret><COMMUNITY><redacted/></COMMUNITY><param name="timeout"><redacted/></param><status>visible-value</status></g:modify_credential_store>"#
        );
        for secret in [
            "attribute-secret",
            "attribute-value",
            "preference-secret",
            "server-default-secret",
            "password-attribute",
            "nested",
            "hidden",
            "cdata-secret",
            "snmp-secret",
            "generic-secret-capable",
        ] {
            assert!(!redacted.contains(secret));
        }
        assert!(redacted.contains("visible-value"));
        assert!(redacted.contains("algorithm=\"plain\""));
    }

    #[test]
    fn malformed_or_unsafe_xml_fails_closed() {
        for xml in [
            "<root><password>secret",
            "<root><password>secret</root>",
            "<root duplicate=\"1\" duplicate=\"2\"/>",
            "<!DOCTYPE root><root/>",
            "<root/><second/>",
            "<root/><second></second>",
            "<root/>not-whitespace",
            "<![CDATA[outside-root]]><root/>",
            "&amp;<root/>",
            "<root>&custom;</root>",
            "<root>&#0;</root>",
            "<root>&#1;</root>",
            "<?xml version=\"1.0\"?><?xml version=\"1.0\"?><root/>",
        ] {
            assert_eq!(
                redact_wire_bytes(xml.as_bytes()),
                MALFORMED_XML_REDACTED,
                "unexpected redaction for {xml}"
            );
        }
    }

    #[test]
    fn preserves_valid_declaration_and_non_secret_structure() {
        let xml = br#"<?xml version="1.0"?><root visible="a&amp;b"><status><![CDATA[keep<&>]]>&amp;&#65;</status><!--omitted--><?trace omitted?></root>"#;

        assert_eq!(
            redact_wire_bytes(xml),
            br#"<?xml version="1.0"?><root visible="a&amp;b"><status><![CDATA[keep<&>]]>&amp;&#65;</status></root>"#
        );
    }

    #[test]
    fn suppresses_empty_elements_nested_inside_sensitive_content() {
        assert_eq!(
            redact_wire_bytes(b"<root><password><empty/></password></root>"),
            b"<root><password><redacted/></password></root>"
        );
    }
}
