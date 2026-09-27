/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod stream;
mod table;

pub(crate) use stream::read_stream_section;

use super::{
    lexer::{Lexer, is_regular},
    object::{Dict, Indirect, MAX_OBJECT_NUMBER, keyword_at},
    source::Source,
};
use memchr::memmem;
use std::collections::VecDeque;

pub(crate) const MAX_SECTIONS: usize = 256;
pub(crate) const NO_SLOT: u32 = u32::MAX;
const MAX_STARTXREF_CANDIDATES: usize = 8;
const MAX_OFFSET_DIGITS: usize = 10;
const CORRECTION_WINDOW: usize = 64;
const DENSE_BASE: usize = 1 << 14;
const STARTXREF: &[u8] = b"startxref";
const XREF: &[u8] = b"xref";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Entry {
    #[default]
    Missing,
    Free {
        section: u16,
    },
    Offset {
        offset: u32,
        generation: u16,
        slot: u32,
    },
    Compressed {
        stream: u32,
        index: u32,
    },
}

#[derive(Debug, Clone, Copy)]
struct Sparse {
    num: u32,
    section: u16,
    entry: Entry,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Entries {
    dense: Vec<Entry>,
    sparse: Vec<Sparse>,
}

pub(crate) struct Builder<'e> {
    entries: &'e mut Entries,
    dense_cap: usize,
    sparse_cap: usize,
}

pub(crate) struct Sections<'a> {
    pub(crate) trailers: Vec<Dict<'a>>,
    pub(crate) bias: usize,
    pub(crate) complete: bool,
}

impl Entry {
    #[inline]
    pub(crate) fn is_used(&self) -> bool {
        matches!(self, Entry::Offset { .. } | Entry::Compressed { .. })
    }
}

impl Entries {
    pub(crate) fn clear(&mut self) {
        self.dense.clear();
        self.sparse.clear();
    }

    pub(crate) fn shrink(&mut self, max_bytes: usize) {
        self.clear();
        self.dense
            .shrink_to(max_bytes / std::mem::size_of::<Entry>());
        self.sparse
            .shrink_to(max_bytes / std::mem::size_of::<Sparse>());
    }

    #[inline]
    pub(crate) fn get(&self, num: u32) -> Entry {
        match self.dense.get(num as usize) {
            Some(entry) => *entry,
            None => self
                .sparse
                .binary_search_by_key(&num, |sparse| sparse.num)
                .ok()
                .and_then(|index| self.sparse.get(index))
                .map_or(Entry::Missing, |sparse| sparse.entry),
        }
    }

    pub(crate) fn get_mut(&mut self, num: u32) -> Option<&mut Entry> {
        if let Some(entry) = self.dense.get_mut(num as usize) {
            return Some(entry);
        }
        let index = self
            .sparse
            .binary_search_by_key(&num, |sparse| sparse.num)
            .ok()?;
        self.sparse.get_mut(index).map(|sparse| &mut sparse.entry)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (u32, Entry)> + '_ {
        self.dense
            .iter()
            .zip(0u32..)
            .map(|(entry, num)| (num, *entry))
            .chain(self.sparse.iter().map(|sparse| (sparse.num, sparse.entry)))
    }

    pub(crate) fn put_sorted(&mut self, num: u32, entry: Entry, dense_cap: usize) {
        let index = num as usize;
        if index < dense_cap {
            if index >= self.dense.len() {
                self.dense.resize(index + 1, Entry::Missing);
            }
            if let Some(slot) = self.dense.get_mut(index) {
                *slot = entry;
            }
        } else {
            self.sparse.push(Sparse {
                num,
                section: 0,
                entry,
            });
        }
    }
}

impl<'e> Builder<'e> {
    pub(crate) fn new(entries: &'e mut Entries, input_len: usize, max_objects: usize) -> Self {
        entries.clear();
        let dense_cap = Builder::dense_cap(input_len, max_objects);
        Builder {
            entries,
            dense_cap,
            sparse_cap: dense_cap,
        }
    }

    pub(crate) fn sparse(entries: &'e mut Entries, cap: usize) -> Self {
        entries.clear();
        Builder {
            entries,
            dense_cap: 0,
            sparse_cap: cap,
        }
    }

    pub(crate) fn dense_cap(input_len: usize, max_objects: usize) -> usize {
        max_objects
            .min(MAX_OBJECT_NUMBER as usize + 1)
            .min(input_len / 4 + DENSE_BASE)
    }

    pub(crate) fn merge(&mut self, num: u64, entry: Entry, section: u16) {
        let Some(num) = u32::try_from(num)
            .ok()
            .filter(|&num| num <= MAX_OBJECT_NUMBER)
        else {
            return;
        };
        let index = num as usize;
        if index >= self.dense_cap {
            if self.entries.sparse.len() < self.sparse_cap {
                self.entries.sparse.push(Sparse {
                    num,
                    section,
                    entry,
                });
            }
            return;
        }
        if index >= self.entries.dense.len() {
            self.entries.dense.resize(index + 1, Entry::Missing);
        }
        if let Some(slot) = self.entries.dense.get_mut(index) {
            slot.merge(entry, section);
        }
    }

    pub(crate) fn finish(self) {
        let sparse = &mut self.entries.sparse;
        sparse.sort_by_key(|sparse| sparse.num);
        sparse.dedup_by(|later, kept| {
            if later.num != kept.num {
                return false;
            }
            kept.entry.merge(later.entry, later.section);
            true
        });
    }
}

impl Entry {
    fn merge(&mut self, entry: Entry, section: u16) {
        match *self {
            Entry::Missing => *self = entry,
            Entry::Free { section: owner } if owner == section && entry.is_used() => *self = entry,
            _ => {}
        }
    }
}

pub(crate) fn looks_like_section(data: &[u8], pos: usize) -> bool {
    let mut lexer = Lexer::at(data, pos);
    lexer.skip_whitespace();
    keyword_at(data, lexer.pos(), XREF) || Indirect::header(data, lexer.pos()).is_some()
}

pub(crate) fn locate_section(data: &[u8], pos: usize) -> Option<usize> {
    if pos >= data.len() {
        return None;
    }
    if looks_like_section(data, pos) {
        return Some(pos);
    }
    let from = pos.saturating_sub(CORRECTION_WINDOW);
    let to = pos.saturating_add(CORRECTION_WINDOW).min(data.len());
    let window = data.get(from..to)?;
    let xref = memmem::find_iter(window, XREF)
        .map(|offset| from + offset)
        .filter(|&found| {
            found
                .checked_sub(1)
                .and_then(|before| data.get(before))
                .is_none_or(|&byte| !byte.is_ascii_alphanumeric())
                && keyword_at(data, found, XREF)
        });
    let headers = (from..to).filter(|&candidate| {
        data.get(candidate).is_some_and(u8::is_ascii_digit)
            && candidate
                .checked_sub(1)
                .and_then(|before| data.get(before))
                .is_none_or(|&byte| !is_regular(byte))
            && Indirect::header(data, candidate).is_some()
    });
    xref.chain(headers).min_by_key(|&found| found.abs_diff(pos))
}

pub(crate) fn startxref_candidates(data: &[u8]) -> impl Iterator<Item = usize> + '_ {
    let finder = memmem::FinderRev::new(STARTXREF);
    let mut end = data.len();
    std::iter::from_fn(move || {
        let found = finder.rfind(data.get(..end)?)?;
        end = found;
        Some(found)
    })
    .take(MAX_STARTXREF_CANDIDATES)
    .filter_map(|found| {
        let mut lexer = Lexer::at(data, found + STARTXREF.len());
        lexer.skip_whitespace();
        let digits = lexer
            .rest()
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .take(MAX_OFFSET_DIGITS + 1)
            .try_fold(0usize, |value, &digit| {
                value
                    .checked_mul(10)?
                    .checked_add(usize::from(digit - b'0'))
            })?;
        Some(digits).filter(|&offset| offset != 0 && offset < data.len())
    })
}

pub(crate) fn read_sections<'a>(
    source: &Source<'a>,
    builder: &mut Builder<'_>,
) -> Option<Sections<'a>> {
    let data = source.data;
    let header = source.header;
    let biases: &[usize] = if header > 0 { &[header, 0] } else { &[0] };
    let (start, bias) = startxref_candidates(data).find_map(|offset| {
        biases
            .iter()
            .find_map(|&bias| {
                let pos = bias.checked_add(offset)?;
                (pos < data.len() && looks_like_section(data, pos)).then_some((pos, bias))
            })
            .or_else(|| {
                biases.iter().find_map(|&bias| {
                    locate_section(data, bias.checked_add(offset)?).map(|pos| (pos, bias))
                })
            })
    })?;
    let mut sections = Sections {
        trailers: Vec::new(),
        bias,
        complete: true,
    };
    let mut queue = VecDeque::from([start]);
    let mut visited: Vec<usize> = Vec::new();
    let mut section = 0u16;
    while let Some(target) = queue.pop_front() {
        if usize::from(section) >= MAX_SECTIONS {
            sections.complete = false;
            break;
        }
        if visited.contains(&target) {
            continue;
        }
        visited.push(target);
        let Some(pos) = locate_section(data, target) else {
            sections.complete = false;
            continue;
        };
        if pos != target {
            if visited.contains(&pos) {
                continue;
            }
            visited.push(pos);
        }
        let trailer = read_section(source, pos, builder, section, &mut visited, bias);
        section = section.saturating_add(1);
        let Some(trailer) = trailer else {
            sections.complete = false;
            continue;
        };
        sections.trailers.push(trailer);
        if !source.charge_scan(trailer.body().len()) {
            sections.complete = false;
            break;
        }
        if let Some(previous) = trailer
            .get(b"Prev")
            .and_then(|prev| {
                prev.as_int()
                    .or_else(|| prev.as_ref().map(|id| i64::from(id.num)))
            })
            .and_then(|prev| usize::try_from(prev).ok())
            .filter(|&prev| prev > 0)
            .and_then(|prev| prev.checked_add(bias))
            .filter(|&prev| prev < data.len())
        {
            queue.push_back(previous);
        }
    }
    (!sections.trailers.is_empty()).then_some(sections)
}

fn read_section<'a>(
    source: &Source<'a>,
    pos: usize,
    builder: &mut Builder<'_>,
    section: u16,
    visited: &mut Vec<usize>,
    bias: usize,
) -> Option<Dict<'a>> {
    let data = source.data;
    let mut lexer = Lexer::at(data, pos);
    lexer.skip_whitespace();
    if !keyword_at(data, lexer.pos(), XREF) {
        return read_stream_section(source, lexer.pos(), builder, section);
    }
    let trailer = table::read_table(data, lexer.pos() + XREF.len(), builder, section)?;
    if let Some(stream) = trailer
        .get(b"XRefStm")
        .and_then(|value| value.as_int())
        .and_then(|value| usize::try_from(value).ok())
        .filter(|&value| value > 0)
        .and_then(|value| value.checked_add(bias))
        .and_then(|value| locate_section(data, value))
        .filter(|value| !visited.contains(value))
    {
        visited.push(stream);
        read_stream_section(source, stream, builder, section);
    }
    Some(trailer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_is_twelve_bytes() {
        assert_eq!(std::mem::size_of::<Entry>(), 12);
    }

    #[test]
    fn merge_prefers_newer_and_used_over_free() {
        let mut entries = Entries::default();
        let mut builder = Builder::new(&mut entries, 0, 1 << 20);
        let sparse = DENSE_BASE as u64 + 10;
        for num in [3, sparse] {
            builder.merge(num, Entry::Free { section: 0 }, 0);
            builder.merge(
                num,
                Entry::Compressed {
                    stream: 1,
                    index: 0,
                },
                0,
            );
            builder.merge(num + 1, Entry::Free { section: 0 }, 0);
            builder.merge(
                num + 1,
                Entry::Compressed {
                    stream: 1,
                    index: 1,
                },
                1,
            );
        }
        builder.merge(
            u64::from(MAX_OBJECT_NUMBER) + 1,
            Entry::Free { section: 0 },
            0,
        );
        builder.finish();
        for num in [3, sparse as u32] {
            assert_eq!(
                entries.get(num),
                Entry::Compressed {
                    stream: 1,
                    index: 0
                }
            );
            assert_eq!(entries.get(num + 1), Entry::Free { section: 0 });
            assert_eq!(entries.get(num + 2), Entry::Missing);
        }
        assert_eq!(entries.iter().count(), 5 + 2);
    }

    #[test]
    fn startxref_search_and_correction() {
        let data = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\nxref\n0 1\nstartxref\n0\n%%EOF\nstartxref\n30\n%%EOF\n\0\0";
        assert_eq!(startxref_candidates(data).collect::<Vec<_>>(), vec![30]);
        assert!(looks_like_section(data, 29));
        assert_eq!(locate_section(data, 33), Some(29));
        assert_eq!(locate_section(data, 12), Some(9));
    }
}
