/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Deserialize, IterateParams, Store, U64_LEN, ValueKey,
    search::{
        IndexDocument, SearchField, SearchFilter, SearchOperator, SearchQuery, SearchValue,
        term::{TermIndex, TermIndexBuilder},
    },
    write::{
        AlignedBytes, Archive, BatchBuilder, SEARCH_INDEX_MAX_FIELD_LEN, SearchIndex,
        SearchIndexClass, SearchIndexField, SearchIndexId, SearchIndexType, ValueClass,
        key::DeserializeBigEndian,
    },
};
use ahash::AHashMap;
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

impl Store {
    pub(crate) async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let truncate_at = if self.is_foundationdb() { 1_048_576 } else { 0 };

        for document in documents {
            let mut batch = BatchBuilder::new();
            let index = document.index;
            let mut old_term_index = None;

            if matches!(index, SearchIndex::Calendar | SearchIndex::Contacts) {
                let mut account_id = None;
                let mut document_id = None;
                for (field, value) in &document.fields {
                    if let SearchValue::Uint(id) = value {
                        match field {
                            SearchField::AccountId => {
                                account_id = Some(*id as u32);
                            }
                            SearchField::DocumentId => {
                                document_id = Some(*id as u32);
                            }
                            _ => {}
                        }
                    }
                }

                if let (Some(account_id), Some(document_id)) = (account_id, document_id)
                    && let Some(archive) = self
                        .get_value::<Archive<AlignedBytes>>(ValueKey::from(
                            ValueClass::SearchIndex(SearchIndexClass {
                                index,
                                id: SearchIndexId::Account {
                                    account_id,
                                    document_id,
                                },
                                typ: SearchIndexType::Document,
                            }),
                        ))
                        .await
                        .caused_by(trc::location!())?
                {
                    old_term_index = Some(archive);
                }
            }

            let term_index_builder = TermIndexBuilder::build(document, truncate_at);
            if let Some(old_term_index) = old_term_index {
                let old_term_index = old_term_index
                    .unarchive::<TermIndex>()
                    .caused_by(trc::location!())?;
                term_index_builder
                    .index
                    .merge_index(&mut batch, index, term_index_builder.id, old_term_index)
                    .caused_by(trc::location!())?;
            } else {
                term_index_builder
                    .index
                    .write_index(&mut batch, index, term_index_builder.id)
                    .caused_by(trc::location!())?;
            }

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
        let mut ids = vec![];
        let mut to_id = None;
        let mut last_account_id = None;

        for filter in query.filters {
            match filter {
                SearchFilter::Operator { field, op, value } => match (field, value) {
                    (SearchField::AccountId, SearchValue::Uint(id))
                        if op == SearchOperator::Equal =>
                    {
                        last_account_id = Some(id as u32);
                        account_documents.entry(id as u32).or_default();
                    }
                    (SearchField::DocumentId, SearchValue::Uint(id))
                        if op == SearchOperator::Equal && last_account_id.is_some() =>
                    {
                        account_documents
                            .get_mut(&last_account_id.unwrap())
                            .unwrap()
                            .push(id as u32);
                    }
                    (SearchField::Id, SearchValue::Uint(id)) => match op {
                        SearchOperator::LowerThan => {
                            to_id = Some(id.saturating_sub(1));
                        }
                        SearchOperator::LowerEqualThan => {
                            to_id = Some(id);
                        }
                        SearchOperator::Equal => {
                            ids.push(id);
                        }
                        _ => {
                            return Err(trc::StoreEvent::UnexpectedError
                                .into_err()
                                .reason("Unsupported operator for Id field"));
                        }
                    },
                    filter => {
                        return Err(trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details(format!("Unsupported unindex filter {filter:?}")));
                    }
                },
                SearchFilter::And | SearchFilter::Or | SearchFilter::End => {}
                SearchFilter::Not | SearchFilter::DocumentSet(_) => {
                    return Err(trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details(format!("Unsupported unindex filter {filter:?}")));
                }
            }
        }

        // Delete by account and document ids
        for (account_id, document_ids) in account_documents {
            if !document_ids.is_empty() {
                for document_id in document_ids {
                    let Some(archive) = self
                        .get_value::<Archive<AlignedBytes>>(ValueKey::from(
                            ValueClass::SearchIndex(SearchIndexClass {
                                index,
                                id: SearchIndexId::Account {
                                    account_id,
                                    document_id,
                                },
                                typ: SearchIndexType::Document,
                            }),
                        ))
                        .await
                        .caused_by(trc::location!())?
                    else {
                        continue;
                    };
                    let term_index = archive
                        .unarchive::<TermIndex>()
                        .caused_by(trc::location!())?;
                    let mut batch = BatchBuilder::new();
                    term_index.delete_index(
                        &mut batch,
                        index,
                        SearchIndexId::Account {
                            account_id,
                            document_id,
                        },
                    );
                    self.write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }
            } else {
                // Delete all documents for the account
                self.delete_range(
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: 0,
                        },
                        typ: SearchIndexType::Document,
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: u32::MAX,
                        },
                        typ: SearchIndexType::Document,
                    })),
                )
                .await
                .caused_by(trc::location!())?;

                self.delete_range(
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: 0,
                        },
                        typ: SearchIndexType::Index {
                            field: SearchIndexField {
                                field_id: 0,
                                data: vec![0u8],
                            },
                        },
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: u32::MAX,
                        },
                        typ: SearchIndexType::Index {
                            field: SearchIndexField {
                                field_id: u8::MAX,
                                data: vec![u8::MAX; SEARCH_INDEX_MAX_FIELD_LEN],
                            },
                        },
                    })),
                )
                .await
                .caused_by(trc::location!())?;

                self.delete_range(
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: 0,
                        },
                        typ: SearchIndexType::Term {
                            hash: CheekyHash::NULL,
                            field: 0,
                        },
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Account {
                            account_id,
                            document_id: u32::MAX,
                        },
                        typ: SearchIndexType::Term {
                            hash: CheekyHash::FULL,
                            field: u8::MAX,
                        },
                    })),
                )
                .await
                .caused_by(trc::location!())?;
            }
        }

        // Delete by global ids
        for id in ids {
            let Some(archive) = self
                .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::SearchIndex(
                    SearchIndexClass {
                        index,
                        id: SearchIndexId::Global { id },
                        typ: SearchIndexType::Document,
                    },
                )))
                .await
                .caused_by(trc::location!())?
            else {
                continue;
            };
            let term_index = archive
                .unarchive::<TermIndex>()
                .caused_by(trc::location!())?;
            let mut batch = BatchBuilder::new();
            term_index.delete_index(&mut batch, index, SearchIndexId::Global { id });
            self.write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }

        // Delete ranges
        if let Some(to_id) = to_id {
            let mut batches = Vec::new();
            self.iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Global { id: 0 },
                        typ: SearchIndexType::Document,
                    })),
                    ValueKey::from(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id: SearchIndexId::Global { id: to_id },
                        typ: SearchIndexType::Document,
                    })),
                ),
                |key, value| {
                    let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(value)?;
                    let term_index = archive.unarchive::<TermIndex>()?;
                    let mut batch = BatchBuilder::new();
                    term_index.delete_index(
                        &mut batch,
                        index,
                        SearchIndexId::Global {
                            id: key.deserialize_be_u64(key.len() - U64_LEN)?,
                        },
                    );
                    batches.push(batch);

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

            for mut batch in batches {
                self.write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        Ok(())
    }
}
