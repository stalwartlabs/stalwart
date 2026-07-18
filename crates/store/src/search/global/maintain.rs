/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, SUBSPACE_SEARCH_INDEX, Store,
    search::{
        codec::{
            self, FOLD_BATCH_BYTES, GLOBAL_META_GENERATION, GLOBAL_META_SWEPT,
            GLOBAL_META_WATERMARK, SLICE_BUDGET_BYTES, WalEvent,
        },
        maintain::{Slice, fold_term},
    },
    write::{
        AnyClass, BatchBuilder, Operation, SearchIndex, SearchIndexClass, ValueClass, ValueOp,
        assert::AssertValue,
    },
};
use std::collections::BTreeMap;
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

impl Store {
    pub async fn maintain_global_search_index(&self) -> trc::Result<()> {
        for index in [SearchIndex::Tracing] {
            self.maintain_global_index(index)
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }

    async fn maintain_global_index(&self, index: SearchIndex) -> trc::Result<()> {
        let watermark = self.global_meta(index, GLOBAL_META_WATERMARK).await?;
        let swept = self.global_meta(index, GLOBAL_META_SWEPT).await?;

        let (region_begin, region_end) = codec::global_wal_range(index);
        let mut cursor = region_begin;
        let mut claimed: Option<u64> = None;

        loop {
            let mut slice = Slice::new();
            let mut next_cursor: Option<Vec<u8>> = None;
            let mut corrupted = None;

            self.iterate(
                IterateParams::new(codec::any_key_ref(&cursor), codec::any_key_ref(&region_end)),
                |key, value| {
                    if codec::parse_global_id_key(key).is_none() {
                        corrupted = Some(trc::Error::corrupted_key(key, None, trc::location!()));
                        return Ok(false);
                    }
                    if slice.bytes > SLICE_BUDGET_BYTES {
                        next_cursor = Some(key.to_vec());
                        return Ok(false);
                    }
                    slice.bytes += value.len();
                    let valid = codec::walk_wal::<u64>(value, |event| {
                        if let WalEvent::Add {
                            document_id,
                            field,
                            term,
                            ..
                        } = event
                        {
                            slice
                                .groups
                                .entry((field, term))
                                .or_default()
                                .insert(document_id, Some(Vec::new()));
                        }
                        true
                    });
                    if valid.is_none() {
                        corrupted = Some(trc::Error::corrupted_key(
                            key,
                            Some(value),
                            trc::location!(),
                        ));
                        return Ok(false);
                    }
                    slice.wal_keys.push(key.to_vec());
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

            if let Some(err) = corrupted {
                return Err(err);
            }
            if slice.wal_keys.is_empty() {
                break;
            }

            let generation = match claimed {
                Some(generation) => generation,
                None => match self.claim_global_generation(index).await {
                    Ok(generation) => {
                        claimed = Some(generation);
                        generation
                    }
                    Err(err) if err.is_assertion_failure() => {
                        trc::event!(
                            Store(trc::StoreEvent::AssertValueFailed),
                            Details = "Global search index claimed by another compactor",
                        );
                        return Ok(());
                    }
                    Err(err) => {
                        return Err(err.caused_by(trc::location!()));
                    }
                },
            };

            match self
                .fold_global_slice(index, generation, watermark, slice)
                .await
            {
                Ok(()) => match next_cursor {
                    Some(next) => cursor = next,
                    None => break,
                },
                Err(err) if err.is_assertion_failure() => {
                    trc::event!(
                        Store(trc::StoreEvent::AssertValueFailed),
                        Details = "Global search index claimed by another compactor",
                    );
                    return Ok(());
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        if watermark > swept {
            match self.sweep_global_index(index, watermark, claimed).await {
                Ok(()) => {}
                Err(err) if err.is_assertion_failure() => {
                    trc::event!(
                        Store(trc::StoreEvent::AssertValueFailed),
                        Details = "Global search index claimed by another compactor",
                    );
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        Ok(())
    }

    async fn fold_global_slice(
        &self,
        index: SearchIndex,
        generation: u64,
        watermark: u64,
        slice: Slice<u64>,
    ) -> trc::Result<()> {
        let meta_class = ValueClass::SearchIndex(SearchIndexClass::GlobalMeta {
            index,
            kind: GLOBAL_META_GENERATION,
        });
        let mut batch = BatchBuilder::new();
        batch.assert_value(meta_class.clone(), AssertValue::U64(generation));

        for ((field, term), deltas) in slice.groups {
            let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
            let (begin, end) = codec::global_term_range(index, field, &term, u64::MAX);
            let mut corrupted = None;
            self.iterate(
                IterateParams::new(codec::any_key(begin), codec::any_key(end)),
                |key, value| {
                    if let Some((_, _, first_document_id)) = codec::parse_term_key::<u64>(key) {
                        chunks.push((first_document_id, value.to_vec()));
                        Ok(true)
                    } else {
                        corrupted = Some(trc::Error::corrupted_key(key, None, trc::location!()));
                        Ok(false)
                    }
                },
            )
            .await
            .caused_by(trc::location!())?;
            if let Some(err) = corrupted {
                return Err(err);
            }

            let (cleared, new_chunks) = fold_term(&chunks, deltas, watermark)
                .ok_or_else(|| trc::Error::corrupted_key(term.as_key(), None, trc::location!()))?;

            for boundary in cleared {
                batch.clear(ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
                    index,
                    field,
                    term,
                    first_document_id: boundary,
                }));
            }
            for (first_document_id, value) in new_chunks {
                batch.set(
                    ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
                        index,
                        field,
                        term,
                        first_document_id,
                    }),
                    value,
                );
            }

            if batch.len() > FOLD_BATCH_BYTES {
                self.write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
                batch.assert_value(meta_class.clone(), AssertValue::U64(generation));
            }
        }

        for key in slice.wal_keys {
            batch.any_op(Operation::Value {
                class: ValueClass::Any(AnyClass {
                    subspace: SUBSPACE_SEARCH_INDEX,
                    key,
                }),
                op: ValueOp::Clear,
            });
            if batch.is_large_batch() {
                self.write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                batch = BatchBuilder::new();
                batch.assert_value(meta_class.clone(), AssertValue::U64(generation));
            }
        }

        self.write(batch.build_all())
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    async fn sweep_global_index(
        &self,
        index: SearchIndex,
        watermark: u64,
        claimed: Option<u64>,
    ) -> trc::Result<()> {
        let generation = match claimed {
            Some(generation) => generation,
            None => self.claim_global_generation(index).await?,
        };
        let meta_class = ValueClass::SearchIndex(SearchIndexClass::GlobalMeta {
            index,
            kind: GLOBAL_META_GENERATION,
        });

        let (region_begin, region_end) =
            codec::global_type_range(SearchIndexClass::TYPE_GLOBAL_TERM, index);
        let mut cursor = region_begin;

        loop {
            let mut terms: Vec<((u8, CheekyHash), Vec<(u64, Vec<u8>)>)> = Vec::new();
            let mut skipping: Option<(u8, CheekyHash)> = None;
            let mut bytes = 0usize;
            let mut next_cursor: Option<Vec<u8>> = None;
            let mut corrupted = None;

            self.iterate(
                IterateParams::new(codec::any_key_ref(&cursor), codec::any_key_ref(&region_end)),
                |key, value| {
                    let Some((field, term, first_document_id)) = codec::parse_term_key::<u64>(key)
                    else {
                        corrupted = Some(trc::Error::corrupted_key(key, None, trc::location!()));
                        return Ok(false);
                    };
                    let probe = (field, term);
                    if terms.last().is_some_and(|(current, _)| *current == probe) {
                        bytes += value.len();
                        terms
                            .last_mut()
                            .unwrap()
                            .1
                            .push((first_document_id, value.to_vec()));
                        return Ok(true);
                    }
                    if skipping == Some(probe) {
                        return Ok(true);
                    }
                    if bytes > SLICE_BUDGET_BYTES {
                        next_cursor = Some(key.to_vec());
                        return Ok(false);
                    }
                    if first_document_id < watermark {
                        bytes += value.len();
                        terms.push((probe, vec![(first_document_id, value.to_vec())]));
                    } else {
                        skipping = Some(probe);
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

            if let Some(err) = corrupted {
                return Err(err);
            }

            let mut batch = BatchBuilder::new();
            batch.assert_value(meta_class.clone(), AssertValue::U64(generation));

            for ((field, term), chunks) in terms {
                let (cleared, new_chunks) = fold_term(&chunks, BTreeMap::new(), watermark)
                    .ok_or_else(|| {
                        trc::Error::corrupted_key(term.as_key(), None, trc::location!())
                    })?;

                for boundary in cleared {
                    batch.clear(ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
                        index,
                        field,
                        term,
                        first_document_id: boundary,
                    }));
                }
                for (first_document_id, value) in new_chunks {
                    batch.set(
                        ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
                            index,
                            field,
                            term,
                            first_document_id,
                        }),
                        value,
                    );
                }

                if batch.len() > FOLD_BATCH_BYTES {
                    self.write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                    batch = BatchBuilder::new();
                    batch.assert_value(meta_class.clone(), AssertValue::U64(generation));
                }
            }

            if next_cursor.is_none() {
                batch.set(
                    ValueClass::SearchIndex(SearchIndexClass::GlobalMeta {
                        index,
                        kind: GLOBAL_META_SWEPT,
                    }),
                    watermark.to_be_bytes().to_vec(),
                );
            }
            self.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;

            match next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }

        Ok(())
    }
}
