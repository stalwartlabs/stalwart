/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, U32_LEN, ValueKey,
    search::{
        GLOBAL_BUCKET_SHIFT, IndexDocument, MAX_DOCUMENT_SIZE, SearchField, SearchValue, codec,
        term::{AccountIndexer, GlobalIndexer, deserialize_term_fields},
    },
    write::{BatchBuilder, SearchIndex, SearchIndexClass, ValueClass},
};
use ahash::AHashSet;
use trc::AddContext;

const STORED_DOCUMENT_BATCH: usize = 1024;

impl Store {
    pub async fn index_account_documents(
        &self,
        account_id: u32,
        index: SearchIndex,
        index_documents: Vec<IndexDocument>,
        unindex_document_ids: Vec<u32>,
    ) -> trc::Result<()> {
        let diffs = matches!(
            index,
            SearchIndex::Email | SearchIndex::Calendar | SearchIndex::Contacts | SearchIndex::File
        );
        let documents = numbered_documents(index_documents)?;

        let mut read_ids = unindex_document_ids.clone();
        if diffs {
            read_ids.extend(documents.iter().map(|(document_id, _)| *document_id));
        }
        let stored = self
            .stored_documents(index, account_id, read_ids)
            .await
            .caused_by(trc::location!())?;

        let mut batch = account_batch(
            index,
            account_id,
            documents,
            &unindex_document_ids,
            &stored,
            diffs,
        )?;
        self.write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;

        Ok(())
    }

    async fn stored_documents(
        &self,
        index: SearchIndex,
        account_id: u32,
        mut document_ids: Vec<u32>,
    ) -> trc::Result<Vec<(u32, Vec<u8>)>> {
        document_ids.sort_unstable();
        document_ids.dedup();
        let mut stored = Vec::with_capacity(document_ids.len());
        for chunk in document_ids.chunks(STORED_DOCUMENT_BATCH) {
            let ranges = chunk
                .iter()
                .map(|document_id| {
                    let key = codec::account_document_key(index, account_id, *document_id);
                    IterateParams::new(codec::document_key(key.clone()), codec::document_key(key))
                })
                .collect::<Vec<_>>();
            let mut corrupted = None;
            self.iterate_many(ranges, |key, value| {
                match key
                    .get(key.len().wrapping_sub(U32_LEN)..)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u32::from_be_bytes)
                {
                    Some(document_id) => {
                        stored.push((document_id, value.to_vec()));
                        Ok(true)
                    }
                    None => {
                        corrupted = Some(trc::Error::corrupted_key(
                            key,
                            Some(value),
                            trc::location!(),
                        ));
                        Ok(false)
                    }
                }
            })
            .await?;
            if let Some(err) = corrupted {
                return Err(err);
            }
        }
        Ok(stored)
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

            if let Some(size) = global_indexer.insert(document, document_id) {
                trc::event!(
                    SearchIndex(trc::SearchIndexEvent::DocumentTruncated),
                    DocumentId = document_id,
                    Size = size,
                    Limit = MAX_DOCUMENT_SIZE,
                );
            }
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
        let Some(last_bucket) = (before_id >> GLOBAL_BUCKET_SHIFT).checked_sub(1) else {
            return Ok(());
        };
        let last_bucket = last_bucket as u16;
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

pub(crate) fn numbered_documents(
    index_documents: Vec<IndexDocument>,
) -> trc::Result<Vec<(u32, IndexDocument)>> {
    let mut documents = Vec::with_capacity(index_documents.len());
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
        documents.push((document_id, document));
    }
    Ok(documents)
}

pub(crate) fn account_batch(
    index: SearchIndex,
    account_id: u32,
    documents: Vec<(u32, IndexDocument)>,
    unindex_document_ids: &[u32],
    stored: &[(u32, Vec<u8>)],
    diffs: bool,
) -> trc::Result<BatchBuilder> {
    let mut account_indexer = AccountIndexer::default();
    for document_id in unindex_document_ids {
        if let Some(document) = stored_document(stored, *document_id) {
            account_indexer
                .remove(document, *document_id)
                .caused_by(trc::location!())?;
        }
    }

    for (document_id, document) in documents {
        if account_indexer.documents.contains_key(&document_id) {
            continue;
        }

        if let Some(size) = account_indexer.insert(document, document_id) {
            trc::event!(
                SearchIndex(trc::SearchIndexEvent::DocumentTruncated),
                AccountId = account_id,
                DocumentId = document_id,
                Size = size,
                Limit = MAX_DOCUMENT_SIZE,
            );
        }

        if diffs && let Some(current_document) = stored_document(stored, document_id) {
            account_indexer
                .diff(current_document, document_id)
                .caused_by(trc::location!())?;
        }
    }

    account_indexer.build_batch(index, account_id)
}

pub(crate) fn stored_document(stored: &[(u32, Vec<u8>)], document_id: u32) -> Option<&[u8]> {
    stored
        .binary_search_by_key(&document_id, |(id, _)| *id)
        .ok()
        .and_then(|position| stored.get(position))
        .map(|(_, document)| document.as_slice())
}

#[cfg(stalwart_tests)]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/search/index/test_support.rs"]
mod test_support;

#[cfg(all(test, stalwart_tests, feature = "rocks"))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/store/src/search/index/tests.rs"]
mod tests;
