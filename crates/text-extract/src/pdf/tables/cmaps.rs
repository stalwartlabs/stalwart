/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::cid::CidCollection;
use super::cmap_data::{
    CMAP_INFO, CMAP_NAMES, CMAP_OFFSETS, CODE_RANGES, PATCH_BYTES, PATCH_CHARS,
};
use super::names::NameTable;

static CMAPS: NameTable = NameTable::new(CMAP_NAMES, &CMAP_OFFSETS);

const MAX_CODE_LEN: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CmapDecoder {
    Identity,
    Utf16Be,
    Utf8,
    Utf32Be,
    Gbk,
    Gb18030,
    Big5,
    EucTw,
    ShiftJis,
    EucJp,
    JisRowCell,
    EucKr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CodeRange {
    len: u8,
    low: [u8; MAX_CODE_LEN],
    high: [u8; MAX_CODE_LEN],
}

impl CodeRange {
    pub(crate) const fn new(len: u8, low: [u8; MAX_CODE_LEN], high: [u8; MAX_CODE_LEN]) -> Self {
        Self { len, low, high }
    }

    pub(crate) fn len(self) -> usize {
        usize::from(self.len)
    }

    pub(crate) fn contains(self, code: &[u8]) -> bool {
        code.len() == self.len() && self.accepts_prefix(code)
    }

    pub(crate) fn accepts_prefix(self, prefix: &[u8]) -> bool {
        prefix.len() <= self.len()
            && prefix
                .iter()
                .zip(self.low.iter().zip(self.high.iter()))
                .all(|(byte, (low, high))| (low..=high).contains(&byte))
    }
}

pub(super) struct CmapInfo {
    pub(super) ranges: u8,
    pub(super) range_count: u8,
    pub(super) decoder: CmapDecoder,
    pub(super) collection: Option<CidCollection>,
    pub(super) vertical: bool,
    pub(super) patches: u8,
    pub(super) patch_count: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PredefinedCmap(usize);

impl PredefinedCmap {
    pub(crate) fn from_name(name: &[u8]) -> Option<Self> {
        CMAPS.find(name).map(Self)
    }

    #[cfg(test)]
    pub(crate) fn name(self) -> &'static str {
        CMAPS.get(self.0).unwrap_or_default()
    }

    pub(crate) fn codespace(self) -> &'static [CodeRange] {
        self.info()
            .and_then(|info| {
                let start = usize::from(info.ranges);
                CODE_RANGES.get(start..start + usize::from(info.range_count))
            })
            .unwrap_or_default()
    }

    pub(crate) fn decoder(self) -> CmapDecoder {
        self.info()
            .map_or(CmapDecoder::Identity, |info| info.decoder)
    }

    pub(crate) fn collection(self) -> Option<CidCollection> {
        self.info().and_then(|info| info.collection)
    }

    pub(crate) fn is_vertical(self) -> bool {
        self.info().is_some_and(|info| info.vertical)
    }

    pub(crate) fn single_byte(self, byte: u8) -> Option<char> {
        let info = self.info()?;
        let start = usize::from(info.patches);
        let end = start + usize::from(info.patch_count);
        let position = PATCH_BYTES.get(start..end)?.binary_search(&byte).ok()?;
        PATCH_CHARS.get(start + position).copied()
    }

    fn info(self) -> Option<&'static CmapInfo> {
        CMAP_INFO.get(self.0)
    }
}
