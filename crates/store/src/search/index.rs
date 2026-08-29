/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, ValueKey,
    search::{
        GLOBAL_BUCKET_SHIFT, IndexDocument, SearchField, SearchValue, codec,
        term::{AccountIndexer, GlobalIndexer, deserialize_term_fields},
    },
    write::{BatchBuilder, SearchIndex, SearchIndexClass, ValueClass, serialize::RawValue},
};
use ahash::AHashSet;
use trc::AddContext;

impl Store {
    pub async fn index_account_documents(
        &self,
        account_id: u32,
        index: SearchIndex,
        index_documents: Vec<IndexDocument>,
        unindex_document_ids: Vec<u32>,
    ) -> trc::Result<()> {
        let mut account_indexer = AccountIndexer::default();

        for document_id in unindex_document_ids {
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

        for document in index_documents.into_iter().rev() {
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
        }

        let mut batch = account_indexer.build_batch(index, account_id);
        self.write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    pub async fn index_trace(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut global_indexer = GlobalIndexer::default();

        for document in documents.into_iter().rev() {
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

        let mut batch = global_indexer.build_batch(SearchIndex::Tracing);
        self.write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    pub async fn unindex_account(&self, index: SearchIndex, account_id: u32) -> trc::Result<()> {
        let (begin, end) = codec::account_region_range(index, account_id);

        self.delete_range(codec::term_key(begin.clone()), codec::term_key(end.clone()))
            .await
            .caused_by(trc::location!())?;

        self.delete_range(codec::document_key(begin), codec::document_key(end))
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    pub async fn clear_search_index_queue(
        &self,
        index: SearchIndex,
        partition: u32,
    ) -> trc::Result<()> {
        let (from_class, to_class) = SearchIndexClass::queue_range(index, partition);
        self.delete_range(ValueKey::from(from_class), ValueKey::from(to_class))
            .await
            .caused_by(trc::location!())?;

        let mut batch = BatchBuilder::new();
        batch
            .clear(SearchIndexClass::QueueIndex { index, partition })
            .clear(SearchIndexClass::QueueStatus { index, partition });
        self.write_batch(&mut batch)
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    pub async fn unindex_traces(&self, before_id: u64) -> trc::Result<()> {
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
        let mut scratch = Vec::new();

        self.iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                    index: SearchIndex::Tracing,
                    document_id: 0,
                })),
                ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                    index: SearchIndex::Tracing,
                    document_id: last_id + 1,
                })),
            ),
            |key, value| {
                has_documents = true;
                deserialize_term_fields(value, &mut scratch, |term_hash, mut field_mask| {
                    while field_mask != 0 {
                        let item = 31 - field_mask.leading_zeros();
                        field_mask ^= 1 << item;
                        delete_terms.insert((term_hash, item as u8));
                    }
                })
                .ok_or_else(|| trc::Error::corrupted_key(key, value.into(), trc::location!()))?;

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
                        index: SearchIndex::Tracing,
                        field,
                        term: term_hash,
                        block_id: 0,
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
                        index: SearchIndex::Tracing,
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
                    index: SearchIndex::Tracing,
                    document_id: 0,
                })),
                ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                    index: SearchIndex::Tracing,
                    document_id: last_id + 1,
                })),
            )
            .await
            .caused_by(trc::location!())?;

            // Delete global document ids
            self.delete_range(
                ValueKey::from(ValueClass::SearchIndex(
                    SearchIndexClass::GlobalDocumentId {
                        index: SearchIndex::Tracing,
                        block_id: 0,
                    },
                )),
                ValueKey::from(ValueClass::SearchIndex(
                    SearchIndexClass::GlobalDocumentId {
                        index: SearchIndex::Tracing,
                        block_id: last_bucket + 1,
                    },
                )),
            )
            .await
            .caused_by(trc::location!())?;
        }

        Ok(())
    }
}

#[cfg(feature = "test_mode")]
impl IndexDocument {
    pub fn into_term_document(self, document_id: u32) -> Vec<u8> {
        let mut indexer = AccountIndexer::default();
        indexer.insert(self, document_id);
        indexer
            .documents
            .remove(&document_id)
            .flatten()
            .map(|document| document.encode().into_plain())
            .unwrap_or_default()
    }
}
