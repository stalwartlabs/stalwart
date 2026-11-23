/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::{memchr, memmem};

const REPLACEMENT: &[u8] = "\u{FFFD}".as_bytes();
const NONCHARACTER_LEAD: u8 = 0xEF;
const NONCHARACTER_PREFIX: &[u8] = b"\xEF\xBF";
const NONCHARACTERS: [char; 2] = ['\u{FFFE}', '\u{FFFF}'];

#[derive(Clone, Copy)]
enum Context {
    Text,
    Attr,
}

static TEXT_SPECIALS: [bool; 256] = specials(Context::Text);
static ATTR_SPECIALS: [bool; 256] = specials(Context::Attr);

pub fn escape_text(s: &str, out: &mut Vec<u8>) {
    escape(s, out, Context::Text);
}

pub fn escape_attr(s: &str, out: &mut Vec<u8>) {
    escape(s, out, Context::Attr);
}

const fn entity(b: u8, context: Context) -> Option<&'static [u8]> {
    match (b, context) {
        (b'"', Context::Attr) => Some(b"&quot;"),
        (b'\'', Context::Attr) => Some(b"&apos;"),
        (b'\t', Context::Attr) => Some(b"&#9;"),
        (b'\n', Context::Attr) => Some(b"&#10;"),
        (b'&', _) => Some(b"&amp;"),
        (b'<', _) => Some(b"&lt;"),
        (b'>', _) => Some(b"&gt;"),
        (b'\r', _) => Some(b"&#13;"),
        (b'\t' | b'\n', _) => None,
        (0x00..=0x1F, _) => Some(REPLACEMENT),
        _ => None,
    }
}

const fn specials(context: Context) -> [bool; 256] {
    let mut table = [false; 256];
    let mut rest: &mut [bool] = &mut table;
    let mut b = 0u8;
    while let [slot, tail @ ..] = rest {
        *slot = entity(b, context).is_some();
        rest = tail;
        b = b.wrapping_add(1);
    }
    table
}

fn escape(s: &str, out: &mut Vec<u8>, context: Context) {
    let bytes = s.as_bytes();
    if memchr(NONCHARACTER_LEAD, bytes).is_some()
        && memmem::find(bytes, NONCHARACTER_PREFIX).is_some()
    {
        escape_noncharacters(s, out, context);
    } else {
        escape_run(bytes, out, context);
    }
}

#[cold]
#[inline(never)]
fn escape_noncharacters(s: &str, out: &mut Vec<u8>, context: Context) {
    let mut parts = s.split(NONCHARACTERS);
    if let Some(first) = parts.next() {
        escape_run(first.as_bytes(), out, context);
    }
    for part in parts {
        out.extend_from_slice(REPLACEMENT);
        escape_run(part.as_bytes(), out, context);
    }
}

fn escape_run(s: &[u8], out: &mut Vec<u8>, context: Context) {
    let specials = match context {
        Context::Text => &TEXT_SPECIALS,
        Context::Attr => &ATTR_SPECIALS,
    };
    out.reserve(s.len());
    let mut start = 0usize;
    for (pos, b) in s.iter().enumerate() {
        if specials.get(usize::from(*b)).copied().unwrap_or(false) {
            out.extend_from_slice(s.get(start..pos).unwrap_or_default());
            out.extend_from_slice(entity(*b, context).unwrap_or_default());
            start = pos.saturating_add(1);
        }
    }
    out.extend_from_slice(s.get(start..).unwrap_or_default());
}
