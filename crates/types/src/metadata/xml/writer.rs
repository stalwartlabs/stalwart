/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ELEMENT_HAS_PREFIX, GENERATED_PREFIX, MAX_XML_NESTING, NODE_ELEMENT, NODE_TEXT, XML_PREFIX,
    element_prefix, read_ns_ref,
};
use crate::metadata::{codec::TrustedReader, registry::XML_NAMESPACE};
use memchr::{memchr, memchr3};
use std::fmt;

pub(super) fn write_element<'a>(
    out: &mut dyn fmt::Write,
    namespace: Option<&'a str>,
    name: &'a str,
    bound_prefix: Option<&'a str>,
    lang: Option<&'a str>,
    reader: &mut TrustedReader<'a>,
) -> fmt::Result {
    let mut writer = XmlWriter {
        out,
        bindings: Vec::new(),
        next_generated: 0,
    };
    let prefix = match (bound_prefix, namespace) {
        (Some(prefix), Some(uri)) => {
            writer.bindings.push(Binding {
                prefix: Prefix::Stored(prefix),
                uri,
            });
            Some(prefix)
        }
        _ => None,
    };
    writer.element_at(
        ElementStart {
            namespace,
            name,
            prefix,
            lang,
        },
        reader,
        DefaultNamespace::Unknown,
        0,
    )
}

pub(super) fn write_empty_element(
    out: &mut dyn fmt::Write,
    namespace: Option<&str>,
    name: &str,
) -> fmt::Result {
    out.write_char('<')?;
    out.write_str(name)?;
    out.write_str(" xmlns=\"")?;
    escape(out, namespace.unwrap_or_default(), Escape::Attribute)?;
    out.write_str("\"/>")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultNamespace<'a> {
    Unknown,
    Namespace(Option<&'a str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prefix<'a> {
    Stored(&'a str),
    Generated(u32),
}

struct Binding<'a> {
    prefix: Prefix<'a>,
    uri: &'a str,
}

struct ElementStart<'a> {
    namespace: Option<&'a str>,
    name: &'a str,
    prefix: Option<&'a str>,
    lang: Option<&'a str>,
}

struct XmlWriter<'w, 'a> {
    out: &'w mut dyn fmt::Write,
    bindings: Vec<Binding<'a>>,
    next_generated: u32,
}

impl Prefix<'_> {
    fn write(self, out: &mut dyn fmt::Write) -> fmt::Result {
        match self {
            Prefix::Stored(prefix) => out.write_str(prefix),
            Prefix::Generated(number) => write!(out, "{GENERATED_PREFIX}{number}"),
        }
    }

    fn renders_as(self, other: Prefix<'_>) -> bool {
        match (self, other) {
            (Prefix::Stored(left), Prefix::Stored(right)) => left == right,
            (Prefix::Generated(left), Prefix::Generated(right)) => left == right,
            (Prefix::Stored(stored), Prefix::Generated(number))
            | (Prefix::Generated(number), Prefix::Stored(stored)) => {
                renders_generated(stored, number)
            }
        }
    }
}

fn renders_generated(stored: &str, number: u32) -> bool {
    stored.strip_prefix(GENERATED_PREFIX).is_some_and(|digits| {
        digits.bytes().all(|byte| byte.is_ascii_digit())
            && (digits.len() == 1 || !digits.starts_with('0'))
            && digits.parse::<u32>() == Ok(number)
    })
}

impl<'a> XmlWriter<'_, 'a> {
    fn resolve(&self, prefix: Prefix<'_>) -> Option<&'a str> {
        self.bindings
            .iter()
            .rev()
            .find(|binding| binding.prefix.renders_as(prefix))
            .map(|binding| binding.uri)
    }

    fn is_bound(&self, prefix: &str, uri: &str) -> bool {
        (prefix == XML_PREFIX && uri == XML_NAMESPACE)
            || self.resolve(Prefix::Stored(prefix)) == Some(uri)
    }

    fn prefix_for(&self, uri: &str) -> Option<Prefix<'a>> {
        self.bindings
            .iter()
            .rev()
            .filter(|binding| binding.uri == uri)
            .map(|binding| binding.prefix)
            .find(|prefix| self.resolve(*prefix) == Some(uri))
    }

    fn generate_prefix(&mut self) -> Result<Prefix<'a>, fmt::Error> {
        loop {
            let candidate = Prefix::Generated(self.next_generated);
            self.next_generated = self.next_generated.checked_add(1).ok_or(fmt::Error)?;
            if self.resolve(candidate).is_none() {
                return Ok(candidate);
            }
        }
    }

    fn element_at(
        &mut self,
        start: ElementStart<'a>,
        reader: &mut TrustedReader<'a>,
        parent_default: DefaultNamespace<'a>,
        nesting: u32,
    ) -> fmt::Result {
        if nesting > MAX_XML_NESTING {
            return Err(fmt::Error);
        }
        let mark = self.bindings.len();
        let prefix = element_prefix(start.namespace, start.prefix);
        let mut child_default = parent_default;

        self.out.write_char('<')?;
        match (prefix, start.namespace) {
            (Some(prefix), Some(uri)) => {
                self.out.write_str(prefix)?;
                self.out.write_char(':')?;
                self.out.write_str(start.name)?;
                if !self.is_bound(prefix, uri) {
                    self.out.write_str(" xmlns:")?;
                    self.out.write_str(prefix)?;
                    self.out.write_str("=\"")?;
                    escape(self.out, uri, Escape::Attribute)?;
                    self.out.write_char('"')?;
                    self.bindings.push(Binding {
                        prefix: Prefix::Stored(prefix),
                        uri,
                    });
                }
            }
            _ => {
                self.out.write_str(start.name)?;
                let own = DefaultNamespace::Namespace(start.namespace);
                if parent_default != own {
                    self.out.write_str(" xmlns=\"")?;
                    escape(
                        self.out,
                        start.namespace.unwrap_or_default(),
                        Escape::Attribute,
                    )?;
                    self.out.write_char('"')?;
                }
                child_default = own;
            }
        }

        if let Some(lang) = start.lang {
            self.out.write_str(" xml:lang=\"")?;
            escape(self.out, lang, Escape::Attribute)?;
            self.out.write_char('"')?;
        }

        let attributes = reader.len().ok_or(fmt::Error)?;
        for _ in 0..attributes {
            let namespace = read_ns_ref(reader).ok_or(fmt::Error)?;
            let name = reader.str().ok_or(fmt::Error)?;
            let value = reader.str().ok_or(fmt::Error)?;
            self.out.write_char(' ')?;
            match namespace {
                None => {}
                Some(XML_NAMESPACE) => self.out.write_str("xml:")?,
                Some(uri) => {
                    let prefix = match self.prefix_for(uri) {
                        Some(prefix) => prefix,
                        None => {
                            let prefix = self.generate_prefix()?;
                            self.out.write_str("xmlns:")?;
                            prefix.write(self.out)?;
                            self.out.write_str("=\"")?;
                            escape(self.out, uri, Escape::Attribute)?;
                            self.out.write_str("\" ")?;
                            self.bindings.push(Binding { prefix, uri });
                            prefix
                        }
                    };
                    prefix.write(self.out)?;
                    self.out.write_char(':')?;
                }
            }
            self.out.write_str(name)?;
            self.out.write_str("=\"")?;
            escape(self.out, value, Escape::Attribute)?;
            self.out.write_char('"')?;
        }

        let children = reader.len().ok_or(fmt::Error)?;
        if children == 0 {
            self.out.write_str("/>")?;
        } else {
            self.out.write_char('>')?;
            for _ in 0..children {
                match reader.u8().ok_or(fmt::Error)? {
                    NODE_TEXT => escape(self.out, reader.str().ok_or(fmt::Error)?, Escape::Text)?,
                    NODE_ELEMENT => {
                        let namespace = read_ns_ref(reader).ok_or(fmt::Error)?;
                        let name = reader.str().ok_or(fmt::Error)?;
                        let prefix = match reader.u8().ok_or(fmt::Error)? {
                            ELEMENT_HAS_PREFIX => Some(reader.str().ok_or(fmt::Error)?),
                            _ => None,
                        };
                        self.element_at(
                            ElementStart {
                                namespace,
                                name,
                                prefix,
                                lang: None,
                            },
                            reader,
                            child_default,
                            nesting + 1,
                        )?;
                    }
                    _ => return Err(fmt::Error),
                }
            }
            self.out.write_str("</")?;
            if let (Some(prefix), Some(_)) = (prefix, start.namespace) {
                self.out.write_str(prefix)?;
                self.out.write_char(':')?;
            }
            self.out.write_str(start.name)?;
            self.out.write_char('>')?;
        }

        self.bindings.truncate(mark);
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    Text,
    Attribute,
}

fn escape_for(byte: u8, context: Escape) -> Option<&'static str> {
    match (byte, context) {
        (b'<', _) => Some("&lt;"),
        (b'&', _) => Some("&amp;"),
        (b'\r', _) => Some("&#13;"),
        (b'>', Escape::Text) => Some("&gt;"),
        (b'"', Escape::Attribute) => Some("&quot;"),
        (b'\n', Escape::Attribute) => Some("&#10;"),
        (b'\t', Escape::Attribute) => Some("&#9;"),
        _ => None,
    }
}

fn find_markup(bytes: &[u8], from: usize, context: Escape) -> Option<usize> {
    let rest = bytes.get(from..)?;
    match context {
        Escape::Text => memchr3(b'<', b'&', b'>', rest),
        Escape::Attribute => memchr3(b'<', b'&', b'"', rest),
    }
    .map(|position| position + from)
}

fn find_whitespace(bytes: &[u8], from: usize, context: Escape) -> Option<usize> {
    let rest = bytes.get(from..)?;
    match context {
        Escape::Text => memchr(b'\r', rest),
        Escape::Attribute => memchr3(b'\t', b'\n', b'\r', rest),
    }
    .map(|position| position + from)
}

fn escape(out: &mut dyn fmt::Write, text: &str, context: Escape) -> fmt::Result {
    let bytes = text.as_bytes();
    let mut markup = find_markup(bytes, 0, context);
    let mut whitespace = find_whitespace(bytes, 0, context);
    let mut last = 0;

    loop {
        let index = match (markup, whitespace) {
            (Some(markup), Some(whitespace)) => markup.min(whitespace),
            (Some(index), None) | (None, Some(index)) => index,
            (None, None) => break,
        };
        if let Some(replacement) = bytes.get(index).and_then(|byte| escape_for(*byte, context)) {
            out.write_str(text.get(last..index).unwrap_or_default())?;
            out.write_str(replacement)?;
        }
        last = index + 1;
        if markup == Some(index) {
            markup = find_markup(bytes, last, context);
        }
        if whitespace == Some(index) {
            whitespace = find_whitespace(bytes, last, context);
        }
    }

    out.write_str(text.get(last..).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::{Escape, escape, escape_for};

    fn reference(text: &str, context: Escape) -> String {
        let mut out = String::new();
        for character in text.chars() {
            match u8::try_from(character)
                .ok()
                .and_then(|byte| escape_for(byte, context))
            {
                Some(replacement) => out.push_str(replacement),
                None => out.push(character),
            }
        }
        out
    }

    #[test]
    fn escape_matches_reference() {
        let alphabet = [
            "a", "<", ">", "&", "\"", "\t", "\n", "\r", "é", "日", "😀", " ", "'",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for len in 0..200 {
            let mut text = String::new();
            for _ in 0..len {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                text.push_str(alphabet[(state >> 33) as usize % alphabet.len()]);
            }
            for context in [Escape::Text, Escape::Attribute] {
                let mut out = String::new();
                escape(&mut out, &text, context).expect("infallible");
                assert_eq!(out, reference(&text, context), "{text:?}");
            }
        }
    }
}
