/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, SUBSPACE_SEARCH_INDEX, Store,
    search::{
        codec::{self, FOLD_BATCH_BYTES, SLICE_BUDGET_BYTES, WalEvent},
        maintain::{Slice, fold_term},
    },
    write::{
        AnyClass, BatchBuilder, Operation, SearchIndex, SearchIndexClass, ValueClass, ValueOp,
        assert::AssertValue,
    },
};
use trc::AddContext;

impl Store {
    pub async fn maintain_account_search_index(&self, account_id: u32) -> trc::Result<()> {
        for index in [
            SearchIndex::Email,
            SearchIndex::Calendar,
            SearchIndex::Contacts,
            SearchIndex::File,
        ] {
            self.maintain_account_index(index, account_id)
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }

    async fn maintain_account_index(&self, index: SearchIndex, account_id: u32) -> trc::Result<()> {
        let (region_begin, region_end) =
            codec::account_type_range(SearchIndexClass::TYPE_WAL, index, account_id);
        let mut cursor = region_begin;
        let mut claimed: Option<u64> = None;

        loop {
            let mut slice = Slice::new();
            let mut next_cursor: Option<Vec<u8>> = None;
            let mut corrupted = None;

            self.iterate(
                IterateParams::new(codec::any_key_ref(&cursor), codec::any_key_ref(&region_end)),
                |key, value| {
                    if codec::parse_wal_key(key).is_none() {
                        corrupted = Some(trc::Error::corrupted_key(key, None, trc::location!()));
                        return Ok(false);
                    }
                    if slice.bytes > SLICE_BUDGET_BYTES {
                        next_cursor = Some(key.to_vec());
                        return Ok(false);
                    }
                    slice.bytes += value.len();
                    let valid = codec::walk_wal::<u32>(value, |event| {
                        match event {
                            WalEvent::Add {
                                document_id,
                                field,
                                term,
                                payload,
                            } => {
                                slice
                                    .groups
                                    .entry((field, term))
                                    .or_default()
                                    .insert(document_id, Some(payload.to_vec()));
                            }
                            WalEvent::TombstoneDocument { .. } => {}
                            WalEvent::Tombstone {
                                document_id,
                                mut mask,
                                term,
                            } => {
                                while mask != 0 {
                                    let field = mask.trailing_zeros() as u8;
                                    mask &= mask - 1;
                                    slice
                                        .groups
                                        .entry((field, term))
                                        .or_default()
                                        .insert(document_id, None);
                                }
                            }
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
                None => match self.claim_generation(index, account_id).await {
                    Ok(generation) => {
                        claimed = Some(generation);
                        generation
                    }
                    Err(err) if err.is_assertion_failure() => {
                        trc::event!(
                            Store(trc::StoreEvent::AssertValueFailed),
                            Details = "Search index account claimed by another compactor",
                            AccountId = account_id,
                        );
                        return Ok(());
                    }
                    Err(err) => {
                        return Err(err.caused_by(trc::location!()));
                    }
                },
            };

            match self.fold_slice(index, account_id, generation, slice).await {
                Ok(()) => match next_cursor {
                    Some(next) => cursor = next,
                    None => break,
                },
                Err(err) if err.is_assertion_failure() => {
                    trc::event!(
                        Store(trc::StoreEvent::AssertValueFailed),
                        Details = "Search index account claimed by another compactor",
                        AccountId = account_id,
                    );
                    return Ok(());
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        Ok(())
    }

    async fn fold_slice(
        &self,
        index: SearchIndex,
        account_id: u32,
        generation: u64,
        slice: Slice<u32>,
    ) -> trc::Result<()> {
        let meta_class = ValueClass::SearchIndex(SearchIndexClass::Meta { index, account_id });
        let mut batch = BatchBuilder::new();
        batch.assert_value(meta_class.clone(), AssertValue::U64(generation));

        for ((field, term), deltas) in slice.groups {
            let mut chunks: Vec<(u32, Vec<u8>)> = Vec::new();
            let (begin, end) = codec::term_range(index, account_id, field, &term);
            let mut corrupted = None;
            self.iterate(
                IterateParams::new(codec::any_key(begin), codec::any_key(end)),
                |key, value| {
                    if let Some((_, _, first_document_id)) = codec::parse_term_key::<u32>(key) {
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

            let (cleared, new_chunks) = fold_term(&chunks, deltas, 0)
                .ok_or_else(|| trc::Error::corrupted_key(term.as_key(), None, trc::location!()))?;

            for boundary in cleared {
                batch.clear(ValueClass::SearchIndex(SearchIndexClass::Term {
                    index,
                    account_id,
                    field,
                    term,
                    first_document_id: boundary,
                }));
            }
            for (first_document_id, value) in new_chunks {
                batch.set(
                    ValueClass::SearchIndex(SearchIndexClass::Term {
                        index,
                        account_id,
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
}
