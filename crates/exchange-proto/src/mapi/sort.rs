/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{prop::PropTag, rop::RopDecodeError};
use crate::common::{LeReader, LeWriter};

const SORT_ORDER_LEN: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
    MaximumCategory,
}

impl SortDirection {
    pub const fn from_wire(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(SortDirection::Ascending),
            0x01 => Some(SortDirection::Descending),
            0x04 => Some(SortDirection::MaximumCategory),
            _ => None,
        }
    }

    pub const fn to_wire(self) -> u8 {
        match self {
            SortDirection::Ascending => 0x00,
            SortDirection::Descending => 0x01,
            SortDirection::MaximumCategory => 0x04,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortOrder {
    pub tag: PropTag,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortOrders<'a>(&'a [u8]);

impl<'a> SortOrders<'a> {
    pub fn len(&self) -> usize {
        self.0.len() / SORT_ORDER_LEN
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = SortOrder> + 'a {
        self.0
            .as_chunks::<SORT_ORDER_LEN>()
            .0
            .iter()
            .map(|[t0, t1, t2, t3, order]| SortOrder {
                tag: PropTag(u32::from_le_bytes([*t0, *t1, *t2, *t3])),
                direction: SortDirection::from_wire(*order).unwrap_or(SortDirection::Ascending),
            })
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SortOrderSet<'a> {
    pub categories: u16,
    pub expanded: u16,
    pub orders: SortOrders<'a>,
}

impl<'a> SortOrderSet<'a> {
    pub fn decode(r: &mut LeReader<'a>) -> Result<Self, RopDecodeError> {
        let offset = r.offset();
        let count = r.u16()?;
        let categories = r.u16()?;
        let expanded = r.u16()?;
        let bytes = r.bytes(usize::from(count).saturating_mul(SORT_ORDER_LEN))?;
        let bad = RopDecodeError::BadValue {
            offset: RopDecodeError::at(offset),
        };
        if categories > count || expanded > categories {
            return Err(bad);
        }
        if bytes
            .as_chunks::<SORT_ORDER_LEN>()
            .0
            .iter()
            .any(|[.., order]| SortDirection::from_wire(*order).is_none())
        {
            return Err(bad);
        }
        Ok(SortOrderSet {
            categories,
            expanded,
            orders: SortOrders(bytes),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.put_u16(u16::try_from(self.orders.len()).unwrap_or(0));
        out.put_u16(self.categories);
        out.put_u16(self.expanded);
        out.extend_from_slice(self.orders.as_bytes());
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/sort/tests.rs"]
mod tests;
