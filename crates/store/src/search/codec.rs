/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SUBSPACE_SEARCH_INDEX, U16_LEN, U32_LEN,
    write::{AnyKey, SearchIndex, SearchIndexClass},
};
use std::slice::Iter;
use utils::{
    cheeky_hash::CheekyHash,
    codec::leb128::{Leb128_, Leb128Iterator, Leb128Vec},
};

const RANGE_PADDING: [u8; 22] = [u8::MAX; 22];

pub(crate) const ACCOUNT_TERM_BASE_LEN: usize = U32_LEN + 2;
pub(crate) const GLOBAL_TERM_BASE_LEN: usize = 2;

pub(crate) struct Writer {
    buf: Vec<u8>,
}

pub(crate) struct PrefixKey<'x> {
    pub term: &'x [u8],
    pub len: u8,
    pub block_id: u16,
}

pub(crate) struct Reader<'x> {
    iter: Iter<'x, u8>,
}

impl<'x> Reader<'x> {
    pub fn new(bytes: &'x [u8]) -> Self {
        Reader { iter: bytes.iter() }
    }

    pub fn leb128<T: Leb128_>(&mut self) -> Option<T> {
        self.iter.next_leb128()
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.iter.next().copied()
    }

    pub fn slice(&mut self, len: usize) -> Option<&'x [u8]> {
        let (slice, rest) = self.iter.as_slice().split_at_checked(len)?;
        self.iter = rest.iter();
        Some(slice)
    }

    pub fn term(&mut self) -> Option<CheekyHash> {
        let len = self.u8()?;
        let key = self.slice((len as usize).min(CheekyHash::HASH_SIZE))?;
        CheekyHash::from_key_bytes(key, len)
    }
}

impl Writer {
    pub fn with_capacity(capacity: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    pub fn push_leb128<T: Leb128_>(&mut self, value: T) {
        self.buf.push_leb128(value);
    }

    pub fn push_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn push_term(&mut self, term: &CheekyHash) {
        self.buf.push(term.len() as u8);
        self.buf.extend_from_slice(term.as_key());
    }
}

pub(crate) fn any_key(key: Vec<u8>) -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: SUBSPACE_SEARCH_INDEX,
        key,
    }
}

pub(crate) fn account_region_range(
    typ: u8,
    index: SearchIndex,
    account_id: u32,
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(1 + U32_LEN + RANGE_PADDING.len());
    begin.push(typ | index.to_u8());
    begin.extend_from_slice(&account_id.to_be_bytes());
    let mut end = begin.clone();
    end.extend_from_slice(&RANGE_PADDING);
    (begin, end)
}

pub(crate) fn account_term_prefix_range(
    index: SearchIndex,
    account_id: u32,
    field: u8,
    prefix: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(U32_LEN + prefix.len() + RANGE_PADDING.len() + 2);
    begin.push(SearchIndexClass::TYPE_TERM | index.to_u8());
    begin.extend_from_slice(&account_id.to_be_bytes());
    begin.push(field);
    begin.extend_from_slice(prefix);
    let mut end = begin.clone();
    end.extend_from_slice(&RANGE_PADDING);
    (begin, end)
}

pub(crate) fn global_term_prefix_range(
    index: SearchIndex,
    field: u8,
    prefix: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(prefix.len() + RANGE_PADDING.len() + 2);
    begin.push(SearchIndexClass::TYPE_TERM | index.to_u8());
    begin.push(field);
    begin.extend_from_slice(prefix);
    let mut end = begin.clone();
    end.extend_from_slice(&RANGE_PADDING);
    (begin, end)
}

pub(crate) fn account_term_range(
    index: SearchIndex,
    account_id: u32,
    field: u8,
    term: &CheekyHash,
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(ACCOUNT_TERM_BASE_LEN + term.key_len() + 3);
    begin.push(SearchIndexClass::TYPE_TERM | index.to_u8());
    begin.extend_from_slice(&account_id.to_be_bytes());
    begin.push(field);
    begin.extend_from_slice(term.as_key());
    begin.push(term.len() as u8);
    let mut end = begin.clone();
    end.extend_from_slice(&[u8::MAX; 2]);
    (begin, end)
}

pub(crate) fn account_document_key(
    index: SearchIndex,
    account_id: u32,
    document_id: u32,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + U32_LEN * 2);
    key.push(SearchIndexClass::TYPE_DOCUMENT | index.to_u8());
    key.extend_from_slice(&account_id.to_be_bytes());
    key.extend_from_slice(&document_id.to_be_bytes());
    key
}

pub(crate) fn global_term_block_range(
    index: SearchIndex,
    field: u8,
    term: &CheekyHash,
    from_block: u16,
    until_block: u16,
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = Vec::with_capacity(GLOBAL_TERM_BASE_LEN + term.key_len() + U16_LEN + 2);
    begin.push(SearchIndexClass::TYPE_TERM | index.to_u8());
    begin.push(field);
    begin.extend_from_slice(term.as_key());
    begin.push(term.len() as u8);
    let mut end = begin.clone();
    begin.extend_from_slice(&from_block.to_be_bytes());
    end.extend_from_slice(&until_block.to_be_bytes());
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn global_document_id_range(
    index: SearchIndex,
    from_block: u16,
    until_block: u16,
) -> (Vec<u8>, Vec<u8>) {
    let base = SearchIndexClass::TYPE_DOCUMENT_ID | index.to_u8();
    let mut begin = Vec::with_capacity(U16_LEN + 2);
    begin.push(base);
    begin.extend_from_slice(&from_block.to_be_bytes());
    let mut end = Vec::with_capacity(U16_LEN + 2);
    end.push(base);
    end.extend_from_slice(&until_block.to_be_bytes());
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn parse_prefix_key(
    key: &[u8],
    base_len: usize,
    block_len: usize,
) -> Option<PrefixKey<'_>> {
    let mut suffix = key.get(base_len..)?;
    let mut block_id = 0;
    if block_len > 0 {
        let (rest, block) = suffix.split_at_checked(suffix.len().checked_sub(block_len)?)?;
        block_id = match block {
            [block] => *block as u16,
            [hi, lo] => u16::from_be_bytes([*hi, *lo]),
            _ => return None,
        };
        suffix = rest;
    }
    let (len, term) = suffix.split_last()?;
    Some(PrefixKey {
        term,
        len: *len,
        block_id,
    })
}

pub(crate) fn parse_block_id(key: &[u8]) -> Option<u16> {
    key.get(key.len().checked_sub(U16_LEN)?..)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Key, ValueKey, write::ValueClass};

    #[test]
    fn test_account_term_keys() {
        let short_term = CheekyHash::new(b"hello");
        let hashed_term = CheekyHash::new(b"this term is longer than sixteen bytes");

        for (term, block_id) in [
            (short_term, 0u8),
            (short_term, 7),
            (short_term, u8::MAX),
            (hashed_term, 3),
        ] {
            let key = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Term {
                index: SearchIndex::Email,
                account_id: 42,
                field: 3,
                term,
                block_id,
            }))
            .serialize(0);
            let (begin, end) = account_term_range(SearchIndex::Email, 42, 3, &term);
            assert!(key >= begin && key < end, "block {block_id} outside range");
            let parsed = parse_prefix_key(&key, ACCOUNT_TERM_BASE_LEN, 1).unwrap();
            assert_eq!(parsed.term, term.as_key());
            assert_eq!(parsed.len as usize, term.len());
            assert_eq!(parsed.block_id, block_id as u16);
            assert_eq!(
                CheekyHash::from_key_bytes(parsed.term, parsed.len),
                Some(term)
            );
        }

        let (begin, end) = account_term_prefix_range(SearchIndex::Email, 42, 3, b"hel");
        for word in [&b"hello"[..], b"help", b"hel"] {
            let key = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Term {
                index: SearchIndex::Email,
                account_id: 42,
                field: 3,
                term: CheekyHash::new(word),
                block_id: 5,
            }))
            .serialize(0);
            assert!(key >= begin && key < end, "prefix range misses {word:?}");
        }
        let outside = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Term {
            index: SearchIndex::Email,
            account_id: 42,
            field: 3,
            term: CheekyHash::new(b"hex"),
            block_id: 5,
        }))
        .serialize(0);
        assert!(!(outside >= begin && outside < end));

        assert!(parse_prefix_key(&[1, 2], ACCOUNT_TERM_BASE_LEN, 1).is_none());
        assert!(parse_block_id(&[1]).is_none());
    }

    #[test]
    fn test_global_term_keys() {
        let term = CheekyHash::new(b"hello");
        let key = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
            index: SearchIndex::Tracing,
            field: 5,
            term,
            block_id: 0x1234,
        }))
        .serialize(0);

        let (begin, end) = global_term_block_range(SearchIndex::Tracing, 5, &term, 0, u16::MAX);
        assert!(key >= begin && key < end);
        let parsed = parse_prefix_key(&key, GLOBAL_TERM_BASE_LEN, U16_LEN).unwrap();
        assert_eq!(parsed.term, term.as_key());
        assert_eq!(parsed.block_id, 0x1234);

        let (begin, end) = global_term_block_range(SearchIndex::Tracing, 5, &term, 0x1000, 0x1234);
        assert!(key >= begin && key < end);
        let (begin, end) = global_term_block_range(SearchIndex::Tracing, 5, &term, 0x2000, 0x3000);
        assert!(!(key >= begin && key < end));

        let key = ValueKey::from(ValueClass::SearchIndex(
            SearchIndexClass::GlobalDocumentId {
                index: SearchIndex::Tracing,
                block_id: 9,
            },
        ))
        .serialize(0);
        let (begin, end) = global_document_id_range(SearchIndex::Tracing, 0, u16::MAX);
        assert!(key >= begin && key < end);
        assert_eq!(parse_block_id(&key), Some(9));
        let (begin, end) = global_document_id_range(SearchIndex::Tracing, 10, 20);
        assert!(!(key >= begin && key < end));
    }
}
