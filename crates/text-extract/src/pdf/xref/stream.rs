/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Builder, Entry, NO_SLOT};
use crate::pdf::{
    decode::Chain,
    object::{Array, Dict, Indirect},
    source::Source,
};

const FIELDS: usize = 3;
const MAX_FIELD_WIDTH: usize = 8;

pub(crate) fn read_stream_section<'a>(
    source: &Source<'a>,
    pos: usize,
    builder: &mut Builder<'_>,
    section: u16,
) -> Option<Dict<'a>> {
    let object = Indirect::parse(source.data, pos, true)?;
    let dict = object.value.as_dict()?;
    let start = object.stream_start?;
    if !dict.is_type(b"XRef") {
        return None;
    }
    let widths = widths(dict.get(b"W")?.as_array()?)?;
    let length = dict.get(b"Length").and_then(|length| length.as_int());
    let raw = source.stream_data(start, length);
    let chain = Chain::parse(dict, &|object| object);
    let mut decoded = Vec::new();
    source.decode(&chain, raw, None, &mut decoded);
    read_entries(&decoded, widths, dict, builder, section);
    Some(dict)
}

fn widths(array: Array<'_>) -> Option<[usize; FIELDS]> {
    let mut widths = [0usize; FIELDS];
    let mut values = array.iter();
    for width in &mut widths {
        *width = values
            .next()?
            .as_int()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|&value| value <= MAX_FIELD_WIDTH)?;
    }
    (widths.iter().sum::<usize>() > 0).then_some(widths)
}

pub(crate) fn read_entries(
    data: &[u8],
    widths: [usize; FIELDS],
    dict: Dict<'_>,
    builder: &mut Builder<'_>,
    section: u16,
) {
    let row = widths.iter().sum::<usize>();
    let mut rows = data.chunks_exact(row);
    let default_count = || {
        dict.get(b"Size")
            .and_then(|size| size.as_int())
            .and_then(|size| u64::try_from(size).ok())
            .unwrap_or((data.len() / row) as u64)
    };
    let pairs: Vec<(u64, u64)> = match dict.get(b"Index").and_then(|index| index.as_array()) {
        Some(index) => {
            let mut values = index.iter().map(|value| value.as_int());
            std::iter::from_fn(|| Some((values.next()?, values.next()?)))
                .filter_map(|(start, count)| {
                    Some((u64::try_from(start?).ok()?, u64::try_from(count?).ok()?))
                })
                .take(rows.len())
                .collect()
        }
        None => vec![(0, default_count())],
    };
    for (start, count) in pairs {
        for num in (0..count).map_while(|offset| start.checked_add(offset)) {
            let Some(bytes) = rows.next() else {
                return;
            };
            let [type_width, second_width, _] = widths;
            let (kind, rest) = bytes.split_at(type_width.min(bytes.len()));
            let (second, third) = rest.split_at(second_width.min(rest.len()));
            let kind = if type_width == 0 { 1 } else { big_endian(kind) };
            let (second, third) = (big_endian(second), big_endian(third));
            let entry = match kind {
                0 => Entry::Free { section },
                1 => match u32::try_from(second) {
                    Ok(offset) if offset > 0 => Entry::Offset {
                        offset,
                        generation: u16::try_from(third).unwrap_or(u16::MAX),
                        slot: NO_SLOT,
                    },
                    _ => Entry::Free { section },
                },
                2 => match (u32::try_from(second), u32::try_from(third)) {
                    (Ok(stream), Ok(index)) => Entry::Compressed { stream, index },
                    _ => continue,
                },
                _ => continue,
            };
            builder.merge(num, entry, section);
        }
    }
}

fn big_endian(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |value, &byte| value << 8 | u64::from(byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::{lexer::Lexer, object::Object, xref::Entries};

    fn dict(source: &[u8]) -> Dict<'_> {
        Object::read(&mut Lexer::new(source), None)
            .and_then(|object| object.as_dict())
            .unwrap_or_else(|| panic!("dict"))
    }

    #[test]
    fn stream_entries_are_bounded_by_data() {
        let mut entries = Entries::default();
        let mut builder = Builder::new(&mut entries, 1 << 20, 1 << 20);
        let data = [0u8, 0, 0, 1, 0, 10, 2, 0, 5];
        read_entries(
            &data,
            [1, 2, 0],
            dict(b"<< /Size 1000000 /Index [4 2 7 1000000 -1 3] >>"),
            &mut builder,
            0,
        );
        builder.finish();
        assert_eq!(entries.iter().count(), 8);
        assert_eq!(entries.get(4), Entry::Free { section: 0 });
        assert!(matches!(entries.get(5), Entry::Offset { offset: 10, .. }));
        assert_eq!(
            entries.get(7),
            Entry::Compressed {
                stream: 5,
                index: 0
            }
        );
        assert!(
            widths(
                dict(b"<< /W [0 0 0] >>")
                    .get(b"W")
                    .and_then(|w| w.as_array())
                    .unwrap_or_else(|| panic!("w"))
            )
            .is_none()
        );
        assert!(
            widths(
                dict(b"<< /W [1 9 0] >>")
                    .get(b"W")
                    .and_then(|w| w.as_array())
                    .unwrap_or_else(|| panic!("w"))
            )
            .is_none()
        );
        assert!(
            widths(
                dict(b"<< /W [1 2] >>")
                    .get(b"W")
                    .and_then(|w| w.as_array())
                    .unwrap_or_else(|| panic!("w"))
            )
            .is_none()
        );
    }
}
