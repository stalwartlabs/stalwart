/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    document::Document,
    layout::{Layout, fingerprint},
    object::{Array, ArrayIter, Name, Object},
    pages::{Page, Visited},
    text_string::decode_text_string,
};
use crate::output::Output;
use std::collections::HashSet;

pub(crate) const MAX_FIELD_DEPTH: usize = 64;
pub(crate) const MAX_FIELDS: usize = 100_000;
const MAX_ANNOTATIONS: usize = 100_000;
const PASSWORD_FLAG: i64 = 1 << 13;
const SKIPPED_ANNOTATIONS: &[&[u8]] = &[b"Popup", b"Link", b"Widget"];
const MAX_RETAINED: usize = 1 << 16;

#[derive(Debug, Default)]
pub(crate) struct FormScratch {
    seen: HashSet<u64>,
    text: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldType {
    Text,
    Choice,
    Button,
    Signature,
}

#[derive(Clone, Copy)]
struct Inherited<'d> {
    kind: Option<FieldType>,
    flags: i64,
    options: Option<Array<'d>>,
}

impl FormScratch {
    pub(crate) fn shrink(&mut self) {
        self.seen = HashSet::new();
        self.text.clear();
        self.text.shrink_to(MAX_RETAINED);
        self.bytes.clear();
        self.bytes.shrink_to(MAX_RETAINED);
    }

    fn emit(&mut self, layout: &mut Layout, out: &mut Output<'_>) {
        let text = self.text.trim();
        if !text.is_empty() && self.seen.insert(fingerprint(text)) {
            layout.block(out, text);
        }
        self.text.clear();
    }
}

impl FieldType {
    fn from_name(name: Name<'_>) -> Option<Self> {
        hashify::map!(name.raw(), FieldType,
            b"Tx" => FieldType::Text,
            b"Ch" => FieldType::Choice,
            b"Btn" => FieldType::Button,
            b"Sig" => FieldType::Signature,
        )
        .copied()
    }
}

pub(crate) fn annotations(
    doc: &Document<'_>,
    page: &Page<'_>,
    layout: &mut Layout,
    out: &mut Output<'_>,
    scratch: &mut FormScratch,
) {
    let Some(annots) = page.annots(doc) else {
        return;
    };
    scratch.seen.clear();
    for annot in doc.array_iter(annots).take(MAX_ANNOTATIONS) {
        if out.is_full() || doc.exhausted() {
            return;
        }
        let Object::Dict(dict) = annot else {
            continue;
        };
        if doc.get_name(dict, b"Subtype").is_some_and(|subtype| {
            SKIPPED_ANNOTATIONS
                .iter()
                .any(|skipped| subtype.is(skipped))
        }) {
            continue;
        }
        text_value(doc, doc.dict_get(dict, b"Contents"), scratch);
        if scratch.text.trim().is_empty() {
            scratch.text.clear();
            text_value(doc, doc.dict_get(dict, b"RC"), scratch);
            strip_markup(&mut scratch.text);
        }
        scratch.emit(layout, out);
    }
}

pub(crate) fn acroform(
    doc: &Document<'_>,
    layout: &mut Layout,
    out: &mut Output<'_>,
    scratch: &mut FormScratch,
    visited: &mut Visited,
) {
    let Some(fields) = doc.acroform_fields() else {
        return;
    };
    scratch.seen.clear();
    visited.clear();
    let root = Inherited {
        kind: None,
        flags: 0,
        options: None,
    };
    let mut stack: Vec<(ArrayIter<'_>, Inherited<'_>)> = vec![(fields.iter(), root)];
    let mut count = 0usize;
    while let Some((kids, inherited)) = stack.last_mut() {
        if out.is_full() || doc.exhausted() || count >= MAX_FIELDS {
            return;
        }
        let inherited = *inherited;
        let Some(kid) = kids.next() else {
            stack.pop();
            continue;
        };
        count += 1;
        if let Some(id) = kid.as_ref()
            && !visited.insert(id.num)
        {
            continue;
        }
        let Object::Dict(node) = doc.resolve(kid) else {
            continue;
        };
        let current = Inherited {
            kind: doc
                .get_name(node, b"FT")
                .and_then(FieldType::from_name)
                .or(inherited.kind),
            flags: doc.get_int(node, b"Ff").unwrap_or(inherited.flags),
            options: doc.get_array(node, b"Opt").or(inherited.options),
        };
        if let Some(value) = node.get(b"V") {
            field_value(doc, &current, doc.resolve(value), scratch);
            scratch.emit(layout, out);
        }
        if let Some(children) = doc.get_array(node, b"Kids")
            && stack.len() < MAX_FIELD_DEPTH
        {
            stack.push((children.iter(), current));
        }
    }
}

fn field_value(
    doc: &Document<'_>,
    field: &Inherited<'_>,
    value: Object<'_>,
    scratch: &mut FormScratch,
) {
    match field.kind {
        Some(FieldType::Button | FieldType::Signature) => {}
        Some(FieldType::Text) if field.flags & PASSWORD_FLAG != 0 => {}
        Some(FieldType::Choice) => match value {
            Object::Array(values) => {
                for item in doc.array_iter(values) {
                    choice(doc, field.options, item, scratch);
                    scratch.text.push('\n');
                }
            }
            other => choice(doc, field.options, other, scratch),
        },
        _ => text_value(doc, value, scratch),
    }
}

fn choice(
    doc: &Document<'_>,
    options: Option<Array<'_>>,
    value: Object<'_>,
    scratch: &mut FormScratch,
) {
    let Object::Str(selected) = value else {
        return;
    };
    let selected = doc.string(selected);
    let display = options.and_then(|options| {
        doc.array_iter(options).find_map(|option| match option {
            Object::Array(pair) => {
                let mut items = doc.array_iter(pair);
                let export = items.next()?.as_str()?;
                let display = items.next()?.as_str()?;
                (*doc.string(export) == *selected).then_some(display)
            }
            _ => None,
        })
    });
    match display {
        Some(display) => decode_text_string(&doc.string(display), &mut scratch.text),
        None => decode_text_string(&selected, &mut scratch.text),
    }
}

fn text_value(doc: &Document<'_>, value: Object<'_>, scratch: &mut FormScratch) {
    match value {
        Object::Str(text) => decode_text_string(&doc.string(text), &mut scratch.text),
        Object::Stream(stream) => {
            scratch.bytes.clear();
            if !doc.decode_stream(stream, &mut scratch.bytes).is_failure() {
                decode_text_string(&scratch.bytes, &mut scratch.text);
            }
        }
        _ => {}
    }
}

fn strip_markup(text: &mut String) {
    if !text.contains('<') && !text.contains('&') {
        return;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(ch) = rest.chars().next() {
        match ch {
            '<' => {
                out.push(' ');
                rest = rest.split_once('>').map_or("", |(_, after)| after);
            }
            '&' => {
                let (entity, after) = rest
                    .get(1..)
                    .and_then(|body| body.split_once(';'))
                    .filter(|(entity, _)| entity.len() <= 8)
                    .unwrap_or(("", ""));
                match decode_entity(entity) {
                    Some(decoded) => {
                        out.push(decoded);
                        rest = after;
                    }
                    None => {
                        out.push('&');
                        rest = rest.get(1..).unwrap_or_default();
                    }
                }
            }
            other => {
                out.push(other);
                rest = rest.get(other.len_utf8()..).unwrap_or_default();
            }
        }
    }
    *text = out;
}

fn decode_entity(entity: &str) -> Option<char> {
    hashify::fnc_map!(entity.as_bytes(),
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => {
            let number = entity.strip_prefix('#')?;
            let value = match number.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => number.parse().ok()?,
            };
            char::from_u32(value)
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rich_text_is_stripped() {
        let mut text = String::from(
            "<?xml version=\"1.0\"?><body><p>Fish &amp; chips</p><p>caf&#233; &#x41;&bogus;</p></body>",
        );
        strip_markup(&mut text);
        assert_eq!(
            text.split_whitespace().collect::<Vec<_>>().join(" "),
            "Fish & chips caf\u{e9} A&bogus;"
        );
    }
}
