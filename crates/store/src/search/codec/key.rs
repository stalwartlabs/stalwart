/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SUBSPACE_SEARCH_INDEX, U32_LEN, U64_LEN,
    search::codec::SearchDocId,
    write::{AnyKey, SearchIndex, SearchIndexClass},
};
use utils::cheeky_hash::CheekyHash;

pub(crate) fn parse_term_key<Id: SearchDocId>(key: &[u8]) -> Option<(u8, CheekyHash, Id)> {
    let (head, suffix) = key.split_at_checked(key.len().checked_sub(Id::TERM_KEY_SUFFIX)?)?;
    let (base, image) = head.split_at_checked(Id::TERM_KEY_BASE)?;
    let (len, document_id) = suffix.split_first()?;
    let field = *base.last()?;
    let document_id = Id::from_be_slice(document_id)?;
    CheekyHash::from_key_bytes(image, *len).map(|term| (field, term, document_id))
}

pub(crate) fn parse_wal_key(key: &[u8]) -> Option<(u32, u64)> {
    let (account_id, id) = key.split_at_checked(5)?;
    Some((
        u32::from_be_bytes(account_id.get(1..)?.try_into().ok()?),
        u64::from_be_bytes(id.try_into().ok()?),
    ))
}

pub(crate) fn parse_document_key(key: &[u8]) -> Option<(u32, u32)> {
    let (account_id, document_id) = key.split_at_checked(5)?;
    Some((
        u32::from_be_bytes(account_id.get(1..)?.try_into().ok()?),
        u32::from_be_bytes(document_id.try_into().ok()?),
    ))
}

pub(crate) fn parse_global_id_key(key: &[u8]) -> Option<u64> {
    key.get(1..)
        .and_then(|id| id.try_into().ok())
        .map(u64::from_be_bytes)
}

fn region_key(typ: u8, index: SearchIndex, tail: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + tail.len());
    key.push(typ | index.to_u8());
    key.extend_from_slice(tail);
    key
}

pub(crate) fn any_key(key: Vec<u8>) -> AnyKey<Vec<u8>> {
    AnyKey {
        subspace: SUBSPACE_SEARCH_INDEX,
        key,
    }
}

pub(crate) fn any_key_ref(key: &[u8]) -> AnyKey<&[u8]> {
    AnyKey {
        subspace: SUBSPACE_SEARCH_INDEX,
        key,
    }
}

pub(crate) fn term_range(
    index: SearchIndex,
    account_id: u32,
    field: u8,
    term: &CheekyHash,
) -> (Vec<u8>, Vec<u8>) {
    let mut base = region_key(
        SearchIndexClass::TYPE_TERM,
        index,
        &account_id.to_be_bytes(),
    );
    base.push(field);
    base.extend_from_slice(term.as_key());
    base.push(term.len() as u8);
    let mut begin = base.clone();
    begin.extend_from_slice(&[0u8; U32_LEN]);
    let mut end = base;
    end.extend_from_slice(&[u8::MAX; U32_LEN]);
    (begin, end)
}

pub(crate) fn term_prefix_range(
    index: SearchIndex,
    account_id: u32,
    field: u8,
    prefix: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = region_key(
        SearchIndexClass::TYPE_TERM,
        index,
        &account_id.to_be_bytes(),
    );
    begin.push(field);
    begin.extend_from_slice(prefix);
    let mut end = begin.clone();
    end.extend_from_slice(&[u8::MAX; 22]);
    (begin, end)
}

pub(crate) fn account_type_range(
    typ: u8,
    index: SearchIndex,
    account_id: u32,
) -> (Vec<u8>, Vec<u8>) {
    let account = account_id.to_be_bytes();
    (region_key(typ, index, &account), {
        let mut end = region_key(typ, index, &account);
        end.extend_from_slice(&[u8::MAX; 22]);
        end
    })
}

pub(crate) fn document_record_key(
    index: SearchIndex,
    account_id: u32,
    document_id: u32,
) -> Vec<u8> {
    let mut key = region_key(
        SearchIndexClass::TYPE_DOCUMENT,
        index,
        &account_id.to_be_bytes(),
    );
    key.extend_from_slice(&document_id.to_be_bytes());
    key
}

pub(crate) fn document_record_range(
    index: SearchIndex,
    account_id: u32,
    document_id: u32,
) -> (Vec<u8>, Vec<u8>) {
    let begin = document_record_key(index, account_id, document_id);
    let mut end = begin.clone();
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn global_wal_range(index: SearchIndex) -> (Vec<u8>, Vec<u8>) {
    (
        region_key(SearchIndexClass::TYPE_GLOBAL_WAL, index, &[]),
        region_key(
            SearchIndexClass::TYPE_GLOBAL_WAL,
            index,
            &[u8::MAX; U64_LEN],
        ),
    )
}

pub(crate) fn global_term_range(
    index: SearchIndex,
    field: u8,
    term: &CheekyHash,
    until_document_id: u64,
) -> (Vec<u8>, Vec<u8>) {
    let mut base = region_key(SearchIndexClass::TYPE_GLOBAL_TERM, index, &[field]);
    base.extend_from_slice(term.as_key());
    base.push(term.len() as u8);
    let mut begin = base.clone();
    begin.extend_from_slice(&[0u8; U64_LEN]);
    let mut end = base;
    end.extend_from_slice(&until_document_id.to_be_bytes());
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn global_term_prefix_range(
    index: SearchIndex,
    field: u8,
    prefix: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut begin = region_key(SearchIndexClass::TYPE_GLOBAL_TERM, index, &[field]);
    begin.extend_from_slice(prefix);
    let mut end = begin.clone();
    end.extend_from_slice(&[u8::MAX; 26]);
    (begin, end)
}

pub(crate) fn global_document_key(index: SearchIndex, document_id: u64) -> Vec<u8> {
    region_key(
        SearchIndexClass::TYPE_GLOBAL_DOCUMENT,
        index,
        &document_id.to_be_bytes(),
    )
}

pub(crate) fn global_document_range(
    index: SearchIndex,
    from_document_id: u64,
    until_document_id: u64,
) -> (Vec<u8>, Vec<u8>) {
    let begin = global_document_key(index, from_document_id);
    let mut end = global_document_key(index, until_document_id);
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn global_meta_key(index: SearchIndex, kind: u8) -> Vec<u8> {
    region_key(SearchIndexClass::TYPE_GLOBAL_META, index, &[kind])
}

pub(crate) fn global_meta_range(index: SearchIndex, kind: u8) -> (Vec<u8>, Vec<u8>) {
    let begin = global_meta_key(index, kind);
    let mut end = begin.clone();
    end.push(u8::MAX);
    (begin, end)
}

pub(crate) fn global_type_range(typ: u8, index: SearchIndex) -> (Vec<u8>, Vec<u8>) {
    (
        region_key(typ, index, &[]),
        region_key(typ, index, &[u8::MAX; 26]),
    )
}
