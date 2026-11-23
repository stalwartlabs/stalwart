/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::DecodeError;
use bytes::Bytes;
use std::cmp::Ordering;
use std::fmt;
use std::iter::FusedIterator;

const LEN_PREFIX: usize = 4;

pub type Entry<'a> = (&'a [u8], &'a [u8]);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum RowOrder {
    #[default]
    Unchecked,
    Unordered,
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KeyValues<'a> {
    entries: &'a [u8],
    len: usize,
    last: usize,
    order: RowOrder,
}

#[derive(Clone, Default)]
pub struct KeyValuesBuf {
    data: Bytes,
    len: u32,
    last: u32,
    order: RowOrder,
}

const _: () = assert!(size_of::<KeyValues<'static>>() <= 40);
const _: () = assert!(size_of::<KeyValuesBuf>() <= 48);

#[derive(Debug, Clone)]
pub struct KeyValueIter<'a> {
    rest: &'a [u8],
    remaining: usize,
}

fn split_prefixed(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = data.split_first_chunk::<LEN_PREFIX>()?;
    let len = u32::from_le_bytes(*len) as usize;
    (len <= rest.len()).then(|| rest.split_at(len))
}

fn split_entry(data: &[u8]) -> Option<(Entry<'_>, &[u8])> {
    let (key, rest) = split_prefixed(data)?;
    let (value, rest) = split_prefixed(rest)?;
    Some(((key, value), rest))
}

impl<'a> KeyValues<'a> {
    pub fn parse(blob: &'a [u8]) -> Result<Self, DecodeError> {
        Self::walk::<false>(blob)
    }

    pub fn parse_with_order(blob: &'a [u8]) -> Result<Self, DecodeError> {
        Self::walk::<true>(blob)
    }

    fn walk<const ORDER: bool>(blob: &'a [u8]) -> Result<Self, DecodeError> {
        let (count, entries) = blob
            .split_first_chunk::<LEN_PREFIX>()
            .ok_or(DecodeError::Length)?;
        let len = u32::from_le_bytes(*count) as usize;
        let mut rest = entries;
        let mut last = 0;
        let mut ascending = ORDER;
        let mut descending = ORDER;
        let mut previous: &[u8] = &[];
        for index in 0..len {
            last = entries.len() - rest.len();
            let ((key, _), next) = split_entry(rest).ok_or(DecodeError::Length)?;
            if ORDER && index > 0 && (ascending || descending) {
                match previous.cmp(key) {
                    Ordering::Less => descending = false,
                    Ordering::Greater => ascending = false,
                    Ordering::Equal => {
                        ascending = false;
                        descending = false;
                    }
                }
            }
            previous = key;
            rest = next;
        }
        if !rest.is_empty() {
            return Err(DecodeError::Length);
        }
        let order = match (ORDER, ascending, descending) {
            (false, _, _) => RowOrder::Unchecked,
            (true, true, _) => RowOrder::Ascending,
            (true, false, true) => RowOrder::Descending,
            (true, false, false) => RowOrder::Unordered,
        };
        Ok(KeyValues {
            entries,
            len,
            last,
            order,
        })
    }

    pub fn is_strictly_ascending(&self) -> bool {
        self.len <= 1 || self.order == RowOrder::Ascending
    }

    pub fn is_strictly_descending(&self) -> bool {
        self.len <= 1 || self.order == RowOrder::Descending
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> KeyValueIter<'a> {
        KeyValueIter {
            rest: self.entries,
            remaining: self.len,
        }
    }

    pub fn last(&self) -> Option<Entry<'a>> {
        if self.len == 0 {
            return None;
        }
        self.entries
            .get(self.last..)
            .and_then(split_entry)
            .map(|(entry, _)| entry)
    }
}

impl KeyValuesBuf {
    pub fn new(reply: &Bytes, rows: KeyValues<'_>) -> Result<Self, DecodeError> {
        Ok(KeyValuesBuf {
            data: share(reply, rows.entries).ok_or(DecodeError::OutOfBounds)?,
            len: u32::try_from(rows.len).map_err(|_| DecodeError::Length)?,
            last: u32::try_from(rows.last).map_err(|_| DecodeError::Length)?,
            order: rows.order,
        })
    }

    pub fn view(&self) -> KeyValues<'_> {
        KeyValues {
            entries: &self.data,
            len: self.len as usize,
            last: self.last as usize,
            order: self.order,
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn share(&self, slice: &[u8]) -> Option<Bytes> {
        share(&self.data, slice)
    }
}

impl fmt::Debug for KeyValuesBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyValuesBuf")
            .field("len", &self.len)
            .field("bytes", &self.data.len())
            .field("order", &self.order)
            .finish()
    }
}

pub(crate) fn share(buffer: &Bytes, slice: &[u8]) -> Option<Bytes> {
    let buffer_range = buffer.as_ptr_range();
    let slice_range = slice.as_ptr_range();
    if slice.is_empty() {
        Some(Bytes::new())
    } else if buffer_range.start <= slice_range.start && slice_range.end <= buffer_range.end {
        Some(buffer.slice_ref(slice))
    } else {
        None
    }
}

impl<'a> IntoIterator for &KeyValues<'a> {
    type Item = Entry<'a>;
    type IntoIter = KeyValueIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> Iterator for KeyValueIter<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let Some((entry, rest)) = split_entry(self.rest) else {
            self.remaining = 0;
            return None;
        };
        self.rest = rest;
        self.remaining -= 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for KeyValueIter<'_> {}

impl FusedIterator for KeyValueIter<'_> {}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/codec/kv/tests.rs"]
mod tests;
