/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, Store, ValueKey,
    search::codec::{self, SearchDocId},
    write::{BatchBuilder, SearchIndex, SearchIndexClass, ValueClass, assert::AssertValue},
};
use std::collections::BTreeMap;
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

use super::codec::GLOBAL_META_GENERATION;

pub(crate) struct MetaU64(pub u64);

impl Deserialize for MetaU64 {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        bytes
            .try_into()
            .map(|bytes| MetaU64(u64::from_be_bytes(bytes)))
            .map_err(|_| trc::Error::corrupted_key(bytes, None, trc::location!()))
    }
}

pub(crate) type TermDeltas<Id> = BTreeMap<Id, Option<Vec<u8>>>;

pub(crate) struct Slice<Id> {
    pub(crate) wal_keys: Vec<Vec<u8>>,
    pub(crate) groups: BTreeMap<(u8, CheekyHash), TermDeltas<Id>>,
    pub(crate) bytes: usize,
}

impl<Id> Slice<Id> {
    pub(crate) fn new() -> Self {
        Slice {
            wal_keys: Vec::new(),
            groups: BTreeMap::new(),
            bytes: 0,
        }
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn fold_term<Id: SearchDocId>(
    chunks: &[(Id, Vec<u8>)],
    deltas: TermDeltas<Id>,
    min_document_id: Id,
) -> Option<(Vec<Id>, Vec<(Id, Vec<u8>)>)> {
    let mut builder = codec::ChunkBuilder::new();
    let mut new_chunks: Vec<(Id, Vec<u8>)> = Vec::new();
    let mut deltas = deltas.into_iter().peekable();
    for (first_document_id, value) in chunks {
        codec::walk_chunk(*first_document_id, value, |document_id, payload| {
            while let Some((delta_id, op)) = deltas.next_if(|(id, _)| *id <= document_id) {
                if delta_id == document_id {
                    if let Some(payload) = op
                        && delta_id >= min_document_id
                        && let Some(chunk) = builder.push(delta_id, &payload)
                    {
                        new_chunks.push(chunk);
                    }
                    return true;
                } else if let Some(payload) = op
                    && delta_id >= min_document_id
                    && let Some(chunk) = builder.push(delta_id, &payload)
                {
                    new_chunks.push(chunk);
                }
            }
            if document_id >= min_document_id
                && let Some(chunk) = builder.push(document_id, payload)
            {
                new_chunks.push(chunk);
            }
            true
        })?;
    }
    for (document_id, op) in deltas {
        if let Some(payload) = op
            && document_id >= min_document_id
            && let Some(chunk) = builder.push(document_id, &payload)
        {
            new_chunks.push(chunk);
        }
    }
    if let Some(chunk) = builder.finish() {
        new_chunks.push(chunk);
    }

    let cleared = chunks
        .iter()
        .map(|(first_document_id, _)| *first_document_id)
        .filter(|boundary| {
            !new_chunks
                .iter()
                .any(|(first_document_id, _)| first_document_id == boundary)
        })
        .collect::<Vec<_>>();

    Some((cleared, new_chunks))
}

impl Store {
    pub(crate) async fn claim_generation(
        &self,
        index: SearchIndex,
        account_id: u32,
    ) -> trc::Result<u64> {
        self.claim_meta_generation(ValueClass::SearchIndex(SearchIndexClass::Meta {
            index,
            account_id,
        }))
        .await
    }

    pub(crate) async fn claim_global_generation(&self, index: SearchIndex) -> trc::Result<u64> {
        self.claim_meta_generation(ValueClass::SearchIndex(SearchIndexClass::GlobalMeta {
            index,
            kind: GLOBAL_META_GENERATION,
        }))
        .await
    }

    async fn claim_meta_generation(&self, class: ValueClass) -> trc::Result<u64> {
        let current = self
            .get_value::<MetaU64>(ValueKey::from(class.clone()))
            .await
            .caused_by(trc::location!())?;
        let next = current.as_ref().map_or(0, |generation| generation.0) + 1;
        let mut batch = BatchBuilder::new();
        batch.assert_value(
            class.clone(),
            current.map_or(AssertValue::None, |generation| {
                AssertValue::U64(generation.0)
            }),
        );
        batch.set(class, next.to_be_bytes().to_vec());
        self.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
        Ok(next)
    }

    pub(crate) async fn global_meta(&self, index: SearchIndex, kind: u8) -> trc::Result<u64> {
        self.get_value::<MetaU64>(ValueKey::from(ValueClass::SearchIndex(
            SearchIndexClass::GlobalMeta { index, kind },
        )))
        .await
        .map(|value| value.map_or(0, |value| value.0))
    }
}
