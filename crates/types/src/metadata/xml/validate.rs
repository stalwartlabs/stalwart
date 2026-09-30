/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{XML_PREFIX, XMLNS_PREFIX, XmlError};
use crate::metadata::registry::{XML_NAMESPACE, XMLNS_NAMESPACE};
use memchr::memchr;

const LINEAR_SCAN_MAX: usize = 8;
const LANG_ATTRIBUTE: &str = "lang";
const NONCHARACTER_LEAD_BYTE: u8 = 0xEF;

pub(crate) fn is_nc_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_name_start) && chars.all(is_name_char)
}

fn is_name_start(ch: char) -> bool {
    if ch.is_ascii() {
        ch.is_ascii_alphabetic() || ch == '_'
    } else {
        matches!(
            ch,
            '\u{C0}'..='\u{D6}'
                | '\u{D8}'..='\u{F6}'
                | '\u{F8}'..='\u{2FF}'
                | '\u{370}'..='\u{37D}'
                | '\u{37F}'..='\u{1FFF}'
                | '\u{200C}'..='\u{200D}'
                | '\u{2070}'..='\u{218F}'
                | '\u{2C00}'..='\u{2FEF}'
                | '\u{3001}'..='\u{D7FF}'
                | '\u{F900}'..='\u{FDCF}'
                | '\u{FDF0}'..='\u{FFFD}'
                | '\u{10000}'..='\u{EFFFF}'
        )
    }
}

fn is_name_char(ch: char) -> bool {
    is_name_start(ch)
        || ch.is_ascii_digit()
        || matches!(
            ch,
            '-' | '.' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}'
        )
}

pub(crate) fn is_xml_text(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes
        .iter()
        .all(|&byte| byte >= 0x20 || matches!(byte, b'\t' | b'\n' | b'\r'))
        && (memchr(NONCHARACTER_LEAD_BYTE, bytes).is_none()
            || !text.contains(['\u{FFFE}', '\u{FFFF}']))
}

pub(crate) fn check_text(text: &str) -> Result<(), XmlError> {
    if is_xml_text(text) {
        Ok(())
    } else {
        Err(XmlError::InvalidCharacter)
    }
}

fn check_local_name(name: &str) -> Result<(), XmlError> {
    if is_nc_name(name) {
        Ok(())
    } else {
        Err(XmlError::InvalidName)
    }
}

fn check_namespace(uri: &str) -> Result<(), XmlError> {
    if uri.is_empty() || uri == XMLNS_NAMESPACE {
        Err(XmlError::InvalidNamespace)
    } else {
        check_text(uri)
    }
}

pub(crate) fn check_property_name(namespace: Option<&str>, name: &str) -> Result<(), XmlError> {
    check_local_name(name)?;
    match namespace {
        Some(XML_NAMESPACE) => Err(XmlError::InvalidNamespace),
        Some(uri) => check_namespace(uri),
        None => Ok(()),
    }
}

pub(crate) fn check_element(
    namespace: Option<&str>,
    name: &str,
    prefix: Option<&str>,
) -> Result<(), XmlError> {
    check_local_name(name)?;
    let Some(uri) = namespace else {
        return Ok(());
    };
    check_namespace(uri)?;
    let is_xml_namespace = uri == XML_NAMESPACE;
    match prefix {
        Some(prefix)
            if !is_nc_name(prefix)
                || prefix == XMLNS_PREFIX
                || (prefix == XML_PREFIX) != is_xml_namespace =>
        {
            Err(XmlError::InvalidPrefix)
        }
        None if is_xml_namespace => Err(XmlError::InvalidPrefix),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributeScope {
    Property,
    Element,
}

pub(crate) fn check_attribute(
    namespace: Option<&str>,
    name: &str,
    value: &str,
    scope: AttributeScope,
) -> Result<(), XmlError> {
    check_local_name(name)?;
    match namespace {
        None if name == XMLNS_PREFIX => return Err(XmlError::ReservedAttribute),
        Some(XML_NAMESPACE) if scope == AttributeScope::Property && name == LANG_ATTRIBUTE => {
            return Err(XmlError::ReservedAttribute);
        }
        Some(XMLNS_NAMESPACE) => return Err(XmlError::ReservedAttribute),
        Some(uri) => check_namespace(uri)?,
        None => {}
    }
    check_text(value)
}

pub(crate) fn has_duplicates<'i, T, K: Ord>(items: &'i [T], key: impl Fn(&'i T) -> K) -> bool {
    if items.len() <= LINEAR_SCAN_MAX {
        let mut rest = items;
        while let [first, tail @ ..] = rest {
            let first = key(first);
            if tail.iter().any(|item| key(item) == first) {
                return true;
            }
            rest = tail;
        }
        false
    } else {
        let mut keys = items.iter().map(key).collect::<Vec<_>>();
        keys.sort_unstable();
        keys.windows(2).any(|pair| matches!(pair, [a, b] if a == b))
    }
}

#[cfg(test)]
mod tests {
    use super::{has_duplicates, is_nc_name, is_xml_text};

    #[test]
    fn nc_names() {
        for name in [
            "a",
            "_x",
            "calendar-color",
            "a.b-c_d9",
            "\u{e9}t\u{e9}",
            "\u{65e5}",
        ] {
            assert!(is_nc_name(name), "{name}");
        }
        for name in ["", "1a", "-a", ".a", "a:b", "a b", "a<", "a\"", "\u{B7}a"] {
            assert!(!is_nc_name(name), "{name}");
        }
    }

    #[test]
    fn xml_text() {
        assert!(is_xml_text("tab\tnew\nline\rreturn \u{e9}\u{FFFD}"));
        for text in ["\u{0}", "a\u{1}b", "\u{1F}", "\u{FFFE}", "x\u{FFFF}"] {
            assert!(!is_xml_text(text), "{text:?}");
        }
    }

    #[test]
    fn duplicates_linear_and_sorted() {
        for len in [0usize, 1, 2, 8, 9, 40] {
            let unique: Vec<usize> = (0..len).rev().collect();
            assert!(!has_duplicates(&unique, |item| *item), "{len}");
            if len > 1 {
                let mut repeated = unique.clone();
                repeated.push(len / 2);
                assert!(has_duplicates(&repeated, |item| *item), "{len}");
            }
        }
    }
}
