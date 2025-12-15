/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, U32_LEN, ValueKey,
    search::*,
    write::{
        SEARCH_INDEX_MAX_FIELD_LEN, SearchIndex, SearchIndexClass, SearchIndexField, SearchIndexId,
        SearchIndexType, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
    },
};
use ahash::AHashMap;
use roaring::RoaringBitmap;
use std::{
    collections::hash_map::Entry,
    ops::{BitAndAssign, BitOrAssign},
};
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

#[derive(Default)]
pub(super) struct BitmapCache {
    cache: AHashMap<(CheekyHash, u8), Option<RoaringBitmap>>,
}

impl BitmapCache {
    pub async fn merge_bitmaps(
        &mut self,
        store: &Store,
        index: SearchIndex,
        account_id: u32,
        hashes: impl Iterator<Item = CheekyHash>,
        field: u8,
        is_union: bool,
    ) -> trc::Result<Option<RoaringBitmap>> {
        let mut result = RoaringBitmap::new();
        for (idx, hash) in hashes.enumerate() {
            match self.cache.entry((hash, field)) {
                Entry::Occupied(entry) => {
                    if let Some(bm) = entry.get() {
                        if is_union {
                            result.bitor_assign(bm);
                        } else if idx == 0 {
                            result = bm.clone();
                        } else {
                            result.bitand_assign(bm);
                            if result.is_empty() {
                                return Ok(None);
                            }
                        }
                    } else if !is_union {
                        return Ok(None);
                    }
                }
                Entry::Vacant(entry) => {
                    let from_key = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: 0,
                        },
                        typ: SearchIndexType::Term { hash, field },
                    }));
                    let to_key = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: u32::MAX,
                        },
                        typ: SearchIndexType::Term { hash, field },
                    }));
                    let key_len = (U32_LEN * 2) + hash.len() + 2;
                    let mut documents = RoaringBitmap::new();
                    store
                        .iterate(
                            IterateParams::new(from_key, to_key).no_values().ascending(),
                            |key, _| {
                                if key.len() == key_len {
                                    documents.insert(key.deserialize_be_u32(key.len() - U32_LEN)?);
                                }

                                Ok(true)
                            },
                        )
                        .await
                        .caused_by(trc::location!())?;

                    if !documents.is_empty() {
                        if is_union {
                            result.bitor_assign(&documents);
                        } else if idx == 0 {
                            result = documents.clone();
                        } else {
                            result.bitand_assign(&documents);
                            if result.is_empty() {
                                entry.insert(Some(documents));
                                return Ok(None);
                            }
                        }
                        entry.insert(Some(documents));
                    } else if !is_union {
                        entry.insert(None);
                        return Ok(None);
                    }
                }
            }
        }

        if !result.is_empty() {
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }
}

pub(crate) async fn range_to_bitmap(
    store: &Store,
    index: SearchIndex,
    account_id: u32,
    field_id: u8,
    match_value: &[u8],
    op: SearchOperator,
) -> trc::Result<Option<RoaringBitmap>> {
    let ((from_value, from_doc_id, from_field), (end_value, end_doc_id, end_field)) = match op {
        SearchOperator::LowerThan => ((&[][..], 0, field_id), (match_value, 0, field_id)),
        SearchOperator::LowerEqualThan => {
            ((&[][..], 0, field_id), (match_value, u32::MAX, field_id))
        }
        SearchOperator::GreaterThan => (
            (match_value, u32::MAX, field_id),
            (&[][..], u32::MAX, field_id + 1),
        ),
        SearchOperator::GreaterEqualThan => (
            (match_value, 0, field_id),
            (&[][..], u32::MAX, field_id + 1),
        ),
        SearchOperator::Equal | SearchOperator::Contains => (
            (match_value, 0, field_id),
            (match_value, u32::MAX, field_id),
        ),
    };

    let begin = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        id: SearchIndexId::Account {
            account_id,
            document_id: from_doc_id,
        },
        typ: SearchIndexType::Index {
            field: SearchIndexField {
                field_id: from_field,
                data: from_value.to_vec(),
            },
        },
    }));

    let end = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        id: SearchIndexId::Account {
            account_id,
            document_id: end_doc_id,
        },
        typ: SearchIndexType::Index {
            field: SearchIndexField {
                field_id: end_field,
                data: end_value.to_vec(),
            },
        },
    }));

    let mut bm = RoaringBitmap::new();
    let prefix = KeySerializer::new(U32_LEN + 2)
        .write(index.as_u8() | 1 << 6)
        .write(account_id)
        .write(field_id)
        .finalize();
    let prefix_len = prefix.len();

    store
        .iterate(
            IterateParams::new(begin, end).no_values().ascending(),
            |key, _| {
                if !key.starts_with(&prefix) {
                    return Ok(false);
                }

                let id_pos = key.len() - U32_LEN;
                let value = key
                    .get(prefix_len..id_pos)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;

                let matches = match op {
                    SearchOperator::LowerThan => value < match_value,
                    SearchOperator::LowerEqualThan => value <= match_value,
                    SearchOperator::GreaterThan => value > match_value,
                    SearchOperator::GreaterEqualThan => value >= match_value,
                    SearchOperator::Equal | SearchOperator::Contains => value == match_value,
                };

                if matches {
                    bm.insert(key.deserialize_be_u32(id_pos)?);
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    if !bm.is_empty() {
        Ok(Some(bm))
    } else {
        Ok(None)
    }
}

pub(crate) async fn sort_order(
    store: &Store,
    index: SearchIndex,
    account_id: u32,
    field_id: u8,
) -> trc::Result<AHashMap<u32, u32>> {
    let begin = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        id: SearchIndexId::Account {
            account_id,
            document_id: 0,
        },
        typ: SearchIndexType::Index {
            field: SearchIndexField {
                field_id,
                data: vec![0u8],
            },
        },
    }));
    let end = ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
        index,
        id: SearchIndexId::Account {
            account_id,
            document_id: u32::MAX,
        },
        typ: SearchIndexType::Index {
            field: SearchIndexField {
                field_id,
                data: vec![u8::MAX; SEARCH_INDEX_MAX_FIELD_LEN],
            },
        },
    }));

    let mut last_value = Vec::new();
    let mut results = AHashMap::new();
    let mut pos = 0;
    store
        .iterate(
            IterateParams::new(begin, end).no_values().ascending(),
            |key, _| {
                let value = key
                    .get(U32_LEN + 2..key.len() - U32_LEN)
                    .ok_or_else(|| trc::Error::corrupted_key(key, None, trc::location!()))?;
                if value != last_value {
                    pos += 1;
                    last_value = value.to_vec();
                }

                results.insert(key.deserialize_be_u32(key.len() - U32_LEN)?, pos);
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    Ok(results)
}
