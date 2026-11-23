/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;
use smallvec::SmallVec;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    Inline(Range<usize>),
    Shared(Bytes),
}

#[derive(Debug, Clone, Default)]
pub struct Segments {
    inline: Vec<u8>,
    parts: SmallVec<[Part; 4]>,
}

impl Segments {
    pub(crate) fn new(inline: Vec<u8>, parts: SmallVec<[Part; 4]>) -> Self {
        Segments { inline, parts }
    }

    pub fn len(&self) -> usize {
        self.parts.iter().fold(0usize, |total, part| {
            total.saturating_add(match part {
                Part::Inline(range) => range.len(),
                Part::Shared(bytes) => bytes.len(),
            })
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.parts.iter().map(|part| match part {
            Part::Inline(range) => self.inline.get(range.clone()).unwrap_or_default(),
            Part::Shared(bytes) => bytes.as_ref(),
        })
    }

    pub fn into_parts(self) -> impl Iterator<Item = Bytes> {
        let inline = Bytes::from(self.inline);
        self.parts.into_iter().map(move |part| match part {
            Part::Inline(range) => {
                if range.end <= inline.len() && range.start <= range.end {
                    inline.slice(range)
                } else {
                    Bytes::new()
                }
            }
            Part::Shared(bytes) => bytes,
        })
    }

    pub fn into_vec(self) -> Vec<u8> {
        if let [Part::Inline(range)] = self.parts.as_slice()
            && range.start == 0
            && range.end == self.inline.len()
        {
            return self.inline;
        }
        let mut out = Vec::with_capacity(self.len());
        for slice in self.iter() {
            out.extend_from_slice(slice);
        }
        out
    }
}
