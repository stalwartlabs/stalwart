/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::codec::{
    DecodeError,
    kv::{KeyValueIter, KeyValues, KeyValuesBuf},
};
use bytes::Bytes;
use std::iter::FusedIterator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyValue<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct RangePage {
    rows: KeyValuesBuf,
}

#[derive(Debug, Clone)]
pub struct KeyPage {
    rows: KeyValuesBuf,
}

#[derive(Debug, Clone)]
pub struct RangeRows<'a> {
    rows: KeyValueIter<'a>,
}

#[derive(Debug, Clone)]
pub struct RangeKeys<'a> {
    rows: KeyValueIter<'a>,
}

impl<'a> From<(&'a [u8], &'a [u8])> for KeyValue<'a> {
    fn from((key, value): (&'a [u8], &'a [u8])) -> Self {
        KeyValue { key, value }
    }
}

impl RangePage {
    #[cfg_attr(not(all(test, stalwart_tests)), expect(dead_code))]
    pub(crate) fn new(reply: &Bytes, rows: KeyValues<'_>) -> Result<RangePage, DecodeError> {
        KeyValuesBuf::new(reply, rows).map(|rows| RangePage { rows })
    }

    pub(crate) fn from_rows(rows: KeyValuesBuf) -> Self {
        RangePage { rows }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn iter(&self) -> RangeRows<'_> {
        RangeRows {
            rows: self.rows.view().iter(),
        }
    }

    pub fn first(&self) -> Option<KeyValue<'_>> {
        self.rows.view().iter().next().map(KeyValue::from)
    }

    pub fn last(&self) -> Option<KeyValue<'_>> {
        self.rows.view().last().map(KeyValue::from)
    }

    pub fn share(&self, slice: &[u8]) -> Option<Bytes> {
        self.rows.share(slice)
    }
}

impl KeyPage {
    #[cfg_attr(not(all(test, stalwart_tests)), expect(dead_code))]
    pub(crate) fn new(reply: &Bytes, rows: KeyValues<'_>) -> Result<KeyPage, DecodeError> {
        KeyValuesBuf::new(reply, rows).map(|rows| KeyPage { rows })
    }

    pub(crate) fn from_rows(rows: KeyValuesBuf) -> Self {
        KeyPage { rows }
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn iter(&self) -> RangeKeys<'_> {
        RangeKeys {
            rows: self.rows.view().iter(),
        }
    }

    pub fn first(&self) -> Option<&[u8]> {
        self.rows.view().iter().next().map(|(key, _)| key)
    }

    pub fn last(&self) -> Option<&[u8]> {
        self.rows.view().last().map(|(key, _)| key)
    }

    pub fn share(&self, slice: &[u8]) -> Option<Bytes> {
        self.rows.share(slice)
    }

    pub fn value_lengths(
        &self,
    ) -> Option<impl ExactSizeIterator<Item = (&[u8], u32)> + FusedIterator> {
        Some(
            self.rows
                .view()
                .iter()
                .map(|(key, value)| (key, value.len() as u32)),
        )
    }
}

impl<'a> IntoIterator for &'a RangePage {
    type Item = KeyValue<'a>;
    type IntoIter = RangeRows<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a KeyPage {
    type Item = &'a [u8];
    type IntoIter = RangeKeys<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> Iterator for RangeRows<'a> {
    type Item = KeyValue<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.rows.next().map(KeyValue::from)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.rows.size_hint()
    }
}

impl ExactSizeIterator for RangeRows<'_> {}

impl FusedIterator for RangeRows<'_> {}

impl<'a> Iterator for RangeKeys<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.rows.next().map(|(key, _)| key)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.rows.size_hint()
    }
}

impl ExactSizeIterator for RangeKeys<'_> {}

impl FusedIterator for RangeKeys<'_> {}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/api/page/tests.rs"]
mod tests;
