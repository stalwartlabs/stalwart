/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(super) trait ReadBytes {
    fn be_u8(&self, at: usize) -> Option<u8>;
    fn be_u16(&self, at: usize) -> Option<u16>;
    fn be_u32(&self, at: usize) -> Option<u32>;
    fn range(&self, at: usize, len: usize) -> Option<&[u8]>;
}

impl ReadBytes for [u8] {
    fn be_u8(&self, at: usize) -> Option<u8> {
        self.get(at).copied()
    }

    fn be_u16(&self, at: usize) -> Option<u16> {
        self.get(at..)?
            .first_chunk::<2>()
            .map(|bytes| u16::from_be_bytes(*bytes))
    }

    fn be_u32(&self, at: usize) -> Option<u32> {
        self.get(at..)?
            .first_chunk::<4>()
            .map(|bytes| u32::from_be_bytes(*bytes))
    }

    fn range(&self, at: usize, len: usize) -> Option<&[u8]> {
        self.get(at..at.checked_add(len)?)
    }
}

pub(super) struct Reader<'x> {
    data: &'x [u8],
}

impl<'x> Reader<'x> {
    pub(super) fn new(data: &'x [u8]) -> Self {
        Self { data }
    }

    pub(super) fn at(data: &'x [u8], offset: usize) -> Option<Self> {
        data.get(offset..).map(Self::new)
    }

    pub(super) fn u8(&mut self) -> Option<u8> {
        let (&byte, rest) = self.data.split_first()?;
        self.data = rest;
        Some(byte)
    }

    pub(super) fn u16(&mut self) -> Option<u16> {
        let (bytes, rest) = self.data.split_first_chunk::<2>()?;
        self.data = rest;
        Some(u16::from_be_bytes(*bytes))
    }

    pub(super) fn u32(&mut self) -> Option<u32> {
        let (bytes, rest) = self.data.split_first_chunk::<4>()?;
        self.data = rest;
        Some(u32::from_be_bytes(*bytes))
    }

    pub(super) fn remaining(&self) -> &'x [u8] {
        self.data
    }
}

pub(super) struct NameTable {
    pub(super) names: &'static [u8],
    pub(super) offsets: &'static [u16],
}

impl NameTable {
    pub(super) fn get(&self, index: usize) -> Option<&'static [u8]> {
        let &[start, end] = self.offsets.get(index..)?.first_chunk::<2>()?;
        self.names.get(usize::from(start)..usize::from(end))
    }
}
