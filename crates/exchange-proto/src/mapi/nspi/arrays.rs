/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{error::NspiDecodeError, minid::MinimalId};
use crate::{
    common::{LeReader, Utf16Le},
    mapi::prop::PropTag,
};

const BINARY_MAX: u32 = 2_097_152;

fn read_capped(r: &mut LeReader<'_>, cap: u32, min_size: usize) -> Result<u32, NspiDecodeError> {
    let offset = r.offset();
    let count = r.u32()?;
    let fits = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(min_size))
        .is_some_and(|len| len <= r.remaining().len());
    if count > cap {
        return Err(NspiDecodeError::TooMany {
            offset: NspiDecodeError::at(offset),
        });
    }
    if !fits {
        return Err(NspiDecodeError::Truncated {
            offset: NspiDecodeError::at(offset),
        });
    }
    Ok(count)
}

fn read_words<'a>(r: &mut LeReader<'a>, cap: u32) -> Result<&'a [u8], NspiDecodeError> {
    let count = read_capped(r, cap, 4)?;
    let len = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .saturating_mul(4);
    Ok(r.bytes(len)?)
}

fn words(bytes: &[u8]) -> impl ExactSizeIterator<Item = u32> + '_ {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MidArray<'a>(&'a [u8]);

impl<'a> MidArray<'a> {
    pub(crate) fn decode(r: &mut LeReader<'a>, cap: u32) -> Result<Self, NspiDecodeError> {
        read_words(r, cap).map(MidArray)
    }

    pub fn len(&self) -> usize {
        self.0.len() / 4
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = MinimalId> + 'a {
        words(self.0).map(MinimalId)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PropTagList<'a>(&'a [u8]);

impl<'a> PropTagList<'a> {
    pub(crate) fn decode(r: &mut LeReader<'a>, cap: u32) -> Result<Self, NspiDecodeError> {
        read_words(r, cap).map(PropTagList)
    }

    pub fn len(&self) -> usize {
        self.0.len() / 4
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = PropTag> + 'a {
        words(self.0).map(PropTag)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsciiStrings<'a> {
    bytes: &'a [u8],
    count: u32,
}

impl<'a> AsciiStrings<'a> {
    pub(crate) fn decode(r: &mut LeReader<'a>, cap: u32) -> Result<Self, NspiDecodeError> {
        let count = read_capped(r, cap, 1)?;
        let start = r.remaining();
        let before = r.offset();
        for _ in 0..count {
            r.ascii_z()?;
        }
        let len = r.offset().saturating_sub(before);
        Ok(AsciiStrings {
            bytes: start.get(..len).unwrap_or_default(),
            count,
        })
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let count = usize::try_from(self.count).unwrap_or(0);
        self.bytes.split(|b| *b == 0).take(count)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WideStrings<'a> {
    bytes: &'a [u8],
    count: u32,
    terminator: WideTerminator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WideTerminator {
    Single,
    Double,
}

impl WideTerminator {
    pub(crate) fn read<'a>(self, r: &mut LeReader<'a>) -> Result<Utf16Le<'a>, NspiDecodeError> {
        let value = r.utf16_z()?;
        if self == WideTerminator::Double {
            let offset = r.offset();
            if r.u16()? != 0 {
                return Err(NspiDecodeError::BadString {
                    offset: NspiDecodeError::at(offset),
                });
            }
        }
        Ok(value)
    }
}

impl<'a> WideStrings<'a> {
    pub(crate) fn decode(
        r: &mut LeReader<'a>,
        cap: u32,
        terminator: WideTerminator,
    ) -> Result<Self, NspiDecodeError> {
        let count = read_capped(r, cap, 2)?;
        let start = r.remaining();
        let before = r.offset();
        for _ in 0..count {
            terminator.read(r)?;
        }
        let len = r.offset().saturating_sub(before);
        Ok(WideStrings {
            bytes: start.get(..len).unwrap_or_default(),
            count,
            terminator,
        })
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = Utf16Le<'a>> + 'a {
        let mut r = LeReader::new(self.bytes);
        let terminator = self.terminator;
        (0..self.count).map_while(move |_| terminator.read(&mut r).ok())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryArray<'a> {
    bytes: &'a [u8],
    count: u32,
}

impl<'a> BinaryArray<'a> {
    pub(crate) fn decode(r: &mut LeReader<'a>, cap: u32) -> Result<Self, NspiDecodeError> {
        let count = read_capped(r, cap, 4)?;
        let start = r.remaining();
        let before = r.offset();
        for _ in 0..count {
            let offset = r.offset();
            let len = r.u32()?;
            if len > BINARY_MAX {
                return Err(NspiDecodeError::TooMany {
                    offset: NspiDecodeError::at(offset),
                });
            }
            r.skip(usize::try_from(len).unwrap_or(usize::MAX))?;
        }
        let len = r.offset().saturating_sub(before);
        Ok(BinaryArray {
            bytes: start.get(..len).unwrap_or_default(),
            count,
        })
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a [u8]> + 'a {
        let mut r = LeReader::new(self.bytes);
        (0..self.count).map_while(move |_| {
            let len = usize::try_from(r.u32().ok()?).ok()?;
            r.bytes(len).ok()
        })
    }
}
