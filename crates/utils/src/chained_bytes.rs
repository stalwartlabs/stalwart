/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, ops::Range};

#[derive(Debug, Clone)]
pub struct ChainedBytes<'x> {
    first: &'x [u8],
    last: &'x [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceRange<'x> {
    Single(&'x [u8]),
    Split(&'x [u8], &'x [u8]),
    None,
}

impl<'x> ChainedBytes<'x> {
    pub fn new(first: &'x [u8]) -> Self {
        Self { first, last: &[] }
    }

    pub fn append(&mut self, bytes: &'x [u8]) {
        self.last = bytes;
    }

    pub fn with_last(mut self, bytes: &'x [u8]) -> Self {
        self.last = bytes;
        self
    }

    pub fn get(&self, index: Range<usize>) -> Option<Cow<'x, [u8]>> {
        let start = index.start;
        let end = index.end;

        if let Some(bytes) = self.first.get(start..end) {
            Some(Cow::Borrowed(bytes))
        } else if start >= self.first.len() {
            self.last
                .get(start - self.first.len()..end - self.first.len())
                .map(Cow::Borrowed)
        } else if let (Some(first), Some(last)) = (
            self.first.get(start..),
            self.last.get(..end - self.first.len()),
        ) {
            let mut vec = vec![0u8; first.len() + last.len()];
            vec[..first.len()].copy_from_slice(first);
            vec[first.len()..].copy_from_slice(last);
            Some(Cow::Owned(vec))
        } else {
            None
        }
    }

    pub fn get_slice_range(&self, index: Range<usize>) -> SliceRange<'x> {
        let start = index.start;
        let end = index.end;

        if let Some(bytes) = self.first.get(start..end) {
            SliceRange::Single(bytes)
        } else if start >= self.first.len() {
            self.last
                .get(start - self.first.len()..end - self.first.len())
                .map(SliceRange::Single)
                .unwrap_or(SliceRange::None)
        } else if let (Some(first), Some(last)) = (
            self.first.get(start..),
            self.last.get(..end - self.first.len()),
        ) {
            SliceRange::Split(first, last)
        } else {
            SliceRange::None
        }
    }

    pub fn get_full_range(&self) -> SliceRange<'x> {
        if self.last.is_empty() {
            SliceRange::Single(self.first)
        } else {
            SliceRange::Split(self.first, self.last)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; self.first.len() + self.last.len()];
        bytes[..self.first.len()].copy_from_slice(self.first);
        bytes[self.first.len()..].copy_from_slice(self.last);
        bytes
    }

    pub fn len(&self) -> usize {
        self.first.len() + self.last.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'x> SliceRange<'x> {
    pub fn len(&self) -> usize {
        match self {
            SliceRange::Single(bytes) => bytes.len(),
            SliceRange::Split(first, last) => first.len() + last.len(),
            SliceRange::None => 0,
        }
    }

    pub fn try_into_bytes(self) -> Option<Cow<'x, [u8]>> {
        match self {
            SliceRange::Single(bytes) => Some(Cow::Borrowed(bytes)),
            SliceRange::Split(first, last) => {
                let mut vec = vec![0u8; first.len() + last.len()];
                vec[..first.len()].copy_from_slice(first);
                vec[first.len()..].copy_from_slice(last);
                Some(Cow::Owned(vec))
            }
            SliceRange::None => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn into_pairs(self) -> (&'x [u8], &'x [u8]) {
        match self {
            SliceRange::Single(bytes) => (bytes, &[][..]),
            SliceRange::Split(first, last) => (first, last),
            SliceRange::None => (&[][..], &[][..]),
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, SliceRange::None)
    }

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }
}

impl<'x> IntoIterator for SliceRange<'x> {
    type Item = &'x u8;
    type IntoIter = std::iter::Chain<std::slice::Iter<'x, u8>, std::slice::Iter<'x, u8>>;

    fn into_iter(self) -> Self::IntoIter {
        let (first, last) = self.into_pairs();

        first.iter().chain(last.iter())
    }
}
