/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, ValueKey,
    search::{
        GLOBAL_BUCKET_SHIFT, IndexDocument, SearchField, SearchFilter, SearchQuery, SearchValue,
        codec,
        term::{AccountIndexer, GlobalIndexer, deserialize_term_fields},
    },
    write::{SearchIndex, SearchIndexClass, ValueClass, serialize::RawValue},
};
use ahash::{AHashMap, AHashSet};
use std::cmp::Ordering;
use trc::AddContext;

impl Store {
    pub(crate) async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let todo = "group index by account and index, then build batch for each group";

        let mut account_indexers: AHashMap<(u32, SearchIndex), AccountIndexer> = AHashMap::new();
        let mut global_indexer = GlobalIndexer::default();

        for document in documents.into_iter().rev() {
            let index = document.index;

            if !matches!(index, SearchIndex::Tracing) {
                let account_id = document
                    .fields
                    .get(&SearchField::AccountId)
                    .and_then(|v| match v {
                        SearchValue::Uint(v) => Some(*v as u32),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details("Missing accountId for document")
                    })?;
                let document_id = document
                    .fields
                    .get(&SearchField::DocumentId)
                    .and_then(|v| match v {
                        SearchValue::Uint(v) => Some(*v as u32),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details("Missing documentId for document")
                    })?;
                let account_indexer = account_indexers.entry((account_id, index)).or_default();

                if account_indexer.documents.contains_key(&document_id) {
                    continue;
                }

                account_indexer.insert(document, document_id);

                if matches!(index, SearchIndex::Calendar | SearchIndex::Contacts)
                    && let Some(current_document) = self
                        .get_value::<RawValue>(ValueKey::from(ValueClass::SearchIndex(
                            SearchIndexClass::Document {
                                index,
                                account_id,
                                document_id,
                            },
                        )))
                        .await
                        .caused_by(trc::location!())?
                {
                    account_indexer
                        .diff(&current_document.0, document_id)
                        .caused_by(trc::location!())?;
                }
            } else {
                let document_id = document
                    .fields
                    .get(&SearchField::Id)
                    .and_then(|v| match v {
                        SearchValue::Uint(v) => Some(*v),
                        _ => None,
                    })
                    .ok_or_else(|| {
                        trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details("Missing id for document")
                    })?;

                if global_indexer.documents.contains_key(&document_id) {
                    continue;
                }

                global_indexer.insert(document, document_id);
            }
        }

        for ((account_id, index), account_indexer) in account_indexers {
            let mut batch = account_indexer.build_batch(index, account_id);
            let mut commit_points = batch.commit_points();
            for commit_point in commit_points.iter() {
                let batch = batch.build_one(commit_point);
                self.write(batch).await.caused_by(trc::location!())?;
            }
        }

        if !global_indexer.is_empty() {
            let mut batch = global_indexer.build_batch(SearchIndex::Tracing);
            let mut commit_points = batch.commit_points();
            for commit_point in commit_points.iter() {
                let batch = batch.build_one(commit_point);
                self.write(batch).await.caused_by(trc::location!())?;
            }
        }

        Ok(())
    }

    pub(crate) async fn unindex(&self, query: SearchQuery) -> trc::Result<()> {
        let index = query.index;
        let mut account_documents: AHashMap<u32, Vec<u32>> = AHashMap::new();
        let mut before_id = None;
        let mut last_account_id = None;

        for filter in query.filters {
            match filter {
                SearchFilter::Integer {
                    field: SearchField::AccountId,
                    op: Ordering::Equal,
                    value,
                } => {
                    last_account_id = Some(value as u32);
                    account_documents.entry(value as u32).or_default();
                }
                SearchFilter::Integer {
                    field: SearchField::DocumentId,
                    op: Ordering::Equal,
                    value,
                } if last_account_id.is_some() => {
                    account_documents
                        .get_mut(&last_account_id.unwrap())
                        .unwrap()
                        .push(value as u32);
                }
                SearchFilter::Integer {
                    field: SearchField::Id,
                    op: Ordering::Less,
                    value,
                } => {
                    before_id = Some(value);
                }
                SearchFilter::And | SearchFilter::Or | SearchFilter::End => {}
                _ => {
                    return Err(trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details(format!("Unsupported unindex filter {filter:?}")));
                }
            }
        }

        // Delete by account and document ids
        for (account_id, document_ids) in account_documents {
            if !document_ids.is_empty() {
                let mut account_indexer = AccountIndexer::default();

                for document_id in document_ids {
                    let Some(document) = self
                        .get_value::<RawValue>(ValueKey::from(ValueClass::SearchIndex(
                            SearchIndexClass::Document {
                                index,
                                account_id,
                                document_id,
                            },
                        )))
                        .await
                        .caused_by(trc::location!())?
                    else {
                        continue;
                    };

                    account_indexer
                        .remove(&document.0, document_id)
                        .caused_by(trc::location!())?;
                }

                let mut batch = account_indexer.build_batch(index, account_id);
                let mut commit_points = batch.commit_points();
                for commit_point in commit_points.iter() {
                    let batch = batch.build_one(commit_point);
                    self.write(batch).await.caused_by(trc::location!())?;
                }
            } else {
                // Delete all documents for the account
                for typ in [SearchIndexClass::TYPE_DOCUMENT, SearchIndexClass::TYPE_TERM] {
                    let (begin, end) = codec::account_region_range(typ, index, account_id);
                    self.delete_range(codec::any_key(begin), codec::any_key(end))
                        .await
                        .caused_by(trc::location!())?;
                }
            }
        }

        // Delete ranges
        if let Some(before_id) = before_id {
            let last_bucket = (before_id >> GLOBAL_BUCKET_SHIFT)
                .checked_sub(1)
                .ok_or_else(|| {
                    trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details("Invalid id cutoff for global unindex")
                })? as u16;
            let last_id =
                ((last_bucket as u64) << GLOBAL_BUCKET_SHIFT) | ((1 << GLOBAL_BUCKET_SHIFT) - 1);
            let mut delete_terms = AHashSet::new();
            let mut has_documents = false;

            self.iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                        index,
                        document_id: 0,
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                        index,
                        document_id: last_id + 1,
                    })),
                ),
                |key, value| {
                    has_documents = true;
                    deserialize_term_fields(value, |term_hash, mut field_mask| {
                        while field_mask != 0 {
                            let item = 31 - field_mask.leading_zeros();
                            field_mask ^= 1 << item;
                            delete_terms.insert((term_hash, item as u8));
                        }
                    })
                    .ok_or_else(|| {
                        trc::Error::corrupted_key(key, value.into(), trc::location!())
                    })?;

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

            if has_documents {
                // Delete terms
                for (term_hash, field) in delete_terms {
                    self.delete_range(
                        ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
                            index,
                            field,
                            term: term_hash,
                            block_id: 0,
                        })),
                        ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
                            index,
                            field,
                            term: term_hash,
                            block_id: last_bucket + 1,
                        })),
                    )
                    .await
                    .caused_by(trc::location!())?;
                }

                // Delete global documents
                self.delete_range(
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                        index,
                        document_id: 0,
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                        index,
                        document_id: last_id + 1,
                    })),
                )
                .await
                .caused_by(trc::location!())?;

                // Delete global document ids
                self.delete_range(
                    ValueKey::from(ValueClass::SearchIndex(
                        SearchIndexClass::GlobalDocumentId { index, block_id: 0 },
                    )),
                    ValueKey::from(ValueClass::SearchIndex(
                        SearchIndexClass::GlobalDocumentId {
                            index,
                            block_id: last_bucket + 1,
                        },
                    )),
                )
                .await
                .caused_by(trc::location!())?;
            }
        }

        Ok(())
    }
}
