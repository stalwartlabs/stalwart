/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EMAIL_ADDRESS, FULL_VERSION, HOME_MESSAGE_DATABASE, OAB_CONTAINER_GUID, OAB_DISTINGUISHED_NAME,
    OAB_NAME, OAB_SEQUENCE, OAB_TRUNCATED_PROPERTIES, OabError, OabProp, OabValue, crc,
};
use crate::mapi::prop::{PropTag, PropType};
use smallvec::SmallVec;

pub const STRING_LIMIT: usize = 3400;
pub const MV_STRING_LIMIT: usize = 65536;
pub const BINARY_LIMIT: usize = 32768;

const HDR_LEN: usize = 12;
const U32_LEN: usize = 4;
const PROP_REC_LEN: usize = 8;
const MAX_ONE_BYTE_INT: u32 = 0x7F;
const INT_COUNT_BASE: u8 = 0x80;

type Truncated = SmallVec<[u32; 4]>;

#[derive(Debug, Clone, Copy)]
pub struct OabHeader<'x> {
    pub name: &'x str,
    pub distinguished_name: &'x str,
    pub sequence: u32,
    pub container_guid: &'x str,
}

impl<'x> OabHeader<'x> {
    fn value(&self, tag: PropTag) -> Option<OabValue<'x>> {
        match tag {
            OAB_NAME => Some(OabValue::Text(self.name)),
            OAB_DISTINGUISHED_NAME => Some(OabValue::Text(self.distinguished_name)),
            OAB_SEQUENCE => Some(OabValue::Int(self.sequence)),
            OAB_CONTAINER_GUID => Some(OabValue::Text(self.container_guid)),
            _ => None,
        }
    }
}

pub fn full_head(
    header: &OabHeader<'_>,
    header_props: &[OabProp],
    object_props: &[OabProp],
    records: &[u8],
    record_count: u32,
) -> Result<Vec<u8>, OabError> {
    let meta_len = U32_LEN * 3 + PROP_REC_LEN * (header_props.len() + object_props.len());
    let meta_size = u32::try_from(meta_len).map_err(|_| OabError::TooLarge)?;
    let mut head = Vec::with_capacity(HDR_LEN + meta_len + 128);
    head.extend_from_slice(&FULL_VERSION.to_le_bytes());
    head.extend_from_slice(&[0; U32_LEN]);
    head.extend_from_slice(&record_count.to_le_bytes());
    head.extend_from_slice(&meta_size.to_le_bytes());
    for table in [header_props, object_props] {
        let count = u32::try_from(table.len()).map_err(|_| OabError::TooLarge)?;
        head.extend_from_slice(&count.to_le_bytes());
        for prop in table {
            head.extend_from_slice(&prop.tag.0.to_le_bytes());
            head.extend_from_slice(&prop.flags.to_le_bytes());
        }
    }
    write_record(&mut head, header_props, |tag| header.value(tag))?;
    let serial = crc(&[head.get(HDR_LEN..).unwrap_or_default(), records]);
    if let Some(slot) = head.get_mut(U32_LEN..U32_LEN * 2) {
        slot.copy_from_slice(&serial.to_le_bytes());
    }
    Ok(head)
}

pub fn write_record<'v>(
    out: &mut Vec<u8>,
    props: &[OabProp],
    mut value: impl FnMut(PropTag) -> Option<OabValue<'v>>,
) -> Result<(), OabError> {
    let start = out.len();
    out.extend_from_slice(&[0; U32_LEN]);
    let presence = out.len();
    out.resize(presence + props.len().div_ceil(8), 0);
    let mut truncated = Truncated::new();
    for (index, prop) in props.iter().enumerate() {
        let present = if prop.tag == OAB_TRUNCATED_PROPERTIES {
            write_ints(out, &truncated)
        } else {
            value(prop.tag).is_some_and(|value| write_value(out, prop.tag, value, &mut truncated))
        };
        if present && let Some(byte) = out.get_mut(presence + index / 8) {
            *byte |= 0x80 >> (index % 8);
        }
    }
    let size = u32::try_from(out.len() - start).map_err(|_| OabError::TooLarge)?;
    if let Some(slot) = out.get_mut(start..presence) {
        slot.copy_from_slice(&size.to_le_bytes());
    }
    Ok(())
}

fn write_value(
    out: &mut Vec<u8>,
    tag: PropTag,
    value: OabValue<'_>,
    truncated: &mut Truncated,
) -> bool {
    match (tag.ptype(), value) {
        (PropType::I32, OabValue::Int(value)) => {
            write_int(out, value);
            true
        }
        (PropType::Bool, OabValue::Bool(value)) => {
            out.push(u8::from(value));
            true
        }
        (PropType::Unicode, OabValue::Text(text)) => write_text(out, tag, text, truncated),
        (PropType::String8, OabValue::Text(text)) if text.is_ascii() => {
            write_text(out, tag, text, truncated)
        }
        (PropType::Binary, OabValue::Binary(bytes)) => match bytes.len() {
            0 => false,
            len if len > BINARY_LIMIT => {
                truncated.push(tag.0);
                false
            }
            len => {
                write_len(out, len);
                out.extend_from_slice(bytes);
                true
            }
        },
        (PropType::MvUnicode, OabValue::Texts(texts)) => write_texts(out, tag, texts, truncated),
        (PropType::MvString8, OabValue::Texts(texts)) => write_texts(out, tag, texts, truncated),
        (_, OabValue::Online) => {
            truncated.push(tag.0);
            false
        }
        _ => false,
    }
}

fn write_int(out: &mut Vec<u8>, value: u32) {
    if value <= MAX_ONE_BYTE_INT {
        out.push(value as u8);
    } else {
        let bytes = value.to_le_bytes();
        let len = U32_LEN - (value.leading_zeros() / 8) as usize;
        let significant = bytes.get(..len).unwrap_or(&bytes);
        out.push(INT_COUNT_BASE | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    write_int(out, u32::try_from(len).unwrap_or(u32::MAX));
}

fn write_ints(out: &mut Vec<u8>, values: &[u32]) -> bool {
    if values.is_empty() {
        return false;
    }
    write_len(out, values.len());
    for value in values {
        write_int(out, *value);
    }
    true
}

fn write_text(out: &mut Vec<u8>, tag: PropTag, text: &str, truncated: &mut Truncated) -> bool {
    let limit = if tag == EMAIL_ADDRESS || tag == HOME_MESSAGE_DATABASE {
        usize::MAX
    } else {
        STRING_LIMIT
    };
    let start = out.len();
    let mut room = limit;
    for piece in text.split('\0') {
        if piece.len() > room {
            out.extend_from_slice(utf8_prefix(piece, room).as_bytes());
            truncated.push(tag.0);
            break;
        }
        out.extend_from_slice(piece.as_bytes());
        room -= piece.len();
    }
    if out.len() == start {
        return false;
    }
    out.push(0);
    true
}

fn write_texts(
    out: &mut Vec<u8>,
    tag: PropTag,
    texts: &[Box<str>],
    truncated: &mut Truncated,
) -> bool {
    let ascii_only = tag.ptype() == PropType::MvString8;
    let repeated = repeated_texts(texts);
    let mut budget = MvBudget::new(ascii_only);
    let mut count = 0usize;
    let mut over = false;
    for (text, repeated) in texts.iter().zip(&repeated) {
        match budget.admit(text, *repeated) {
            Admission::Keep => count += 1,
            Admission::Over => over = true,
            Admission::Skip => {}
        }
    }
    if over {
        truncated.push(tag.0);
    }
    if count == 0 {
        return false;
    }
    write_len(out, count);
    let mut budget = MvBudget::new(ascii_only);
    for (text, repeated) in texts.iter().zip(&repeated) {
        if budget.admit(text, *repeated) == Admission::Keep {
            for piece in text.split('\0') {
                out.extend_from_slice(piece.as_bytes());
            }
            out.push(0);
        }
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Keep,
    Skip,
    Over,
}

struct MvBudget {
    used: usize,
    ascii_only: bool,
}

impl MvBudget {
    fn new(ascii_only: bool) -> Self {
        MvBudget {
            used: 0,
            ascii_only,
        }
    }

    fn admit(&mut self, text: &str, repeated: bool) -> Admission {
        if repeated || (self.ascii_only && !text.is_ascii()) || text.bytes().all(|b| b == 0) {
            return Admission::Skip;
        }
        let size = text.len() + 1 - memchr::memchr_iter(0, text.as_bytes()).count();
        if self.used + size > MV_STRING_LIMIT {
            return Admission::Over;
        }
        self.used += size;
        Admission::Keep
    }
}

fn repeated_texts(texts: &[Box<str>]) -> Vec<bool> {
    let mut repeated = vec![false; texts.len()];
    if texts.len() < 2 {
        return repeated;
    }
    let mut order: Vec<(&str, usize)> = texts.iter().map(|text| &**text).zip(0..).collect();
    order.sort_unstable_by(|(a, i), (b, j)| folded(a).cmp(folded(b)).then(i.cmp(j)));
    for pair in order.windows(2) {
        if let [(first, _), (second, index)] = pair
            && folded(first).eq(folded(second))
            && let Some(flag) = repeated.get_mut(*index)
        {
            *flag = true;
        }
    }
    repeated
}

fn folded(text: &str) -> impl Iterator<Item = u8> + '_ {
    text.bytes()
        .filter(|b| *b != 0)
        .map(|b| b.to_ascii_lowercase())
}

fn utf8_prefix(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}
