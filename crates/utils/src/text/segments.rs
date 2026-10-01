/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) const CHUNK: usize = 192;
pub(crate) const SHORT_LEN: usize = 64;

pub(crate) enum Change {
    Ascii { position: usize, checked: usize },
    Unicode,
}

pub(crate) fn find_change(
    text: &str,
    ascii_changes: impl Fn(u8) -> bool,
    unicode_keeps: impl Fn(char) -> bool,
) -> Option<Change> {
    let mut rest = text;
    let mut offset = 0;
    loop {
        let bytes = rest.as_bytes();
        let head = bytes.get(..CHUNK).unwrap_or(bytes);
        if head.is_empty() {
            return None;
        }
        let (high, hit) = scan_chunk(head, &ascii_changes);
        let end = if high < 0x80 {
            if hit {
                return head
                    .iter()
                    .position(|&byte| ascii_changes(byte))
                    .map(|position| Change::Ascii {
                        position: offset + position,
                        checked: offset + head.len(),
                    });
            }
            head.len()
        } else {
            let end = rest.ceil_char_boundary(head.len());
            if hit
                || !rest
                    .get(..end)
                    .is_some_and(|segment| segment.chars().all(&unicode_keeps))
            {
                return Some(Change::Unicode);
            }
            end
        };
        let Some(tail) = rest.get(end..) else {
            return Some(Change::Unicode);
        };
        rest = tail;
        offset += end;
    }
}

pub(crate) fn is_ascii(bytes: &[u8]) -> bool {
    bytes.chunks(CHUNK).all(chunk_is_ascii)
}

fn chunk_is_ascii(chunk: &[u8]) -> bool {
    chunk.iter().fold(0u8, |acc, &byte| acc | byte) < 0x80
}

fn scan_chunk(chunk: &[u8], matches: impl Fn(u8) -> bool) -> (u8, bool) {
    let (high, hit) = chunk.iter().fold((0u8, 0u8), |(high, hit), &byte| {
        (high | byte, hit | u8::from(matches(byte)))
    });
    (high, hit != 0)
}

pub(crate) fn count_in_chunk(chunk: &[u8], matches: impl Fn(u8) -> bool) -> usize {
    usize::from(
        chunk
            .iter()
            .fold(0u8, |acc, &byte| acc.wrapping_add(u8::from(matches(byte)))),
    )
}

pub(crate) fn any_in_chunk(chunk: &[u8], matches: impl Fn(u8) -> bool) -> bool {
    chunk
        .iter()
        .fold(0u8, |acc, &byte| acc | u8::from(matches(byte)))
        != 0
}
