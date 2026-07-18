/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Store,
    search::{
        IndexDocument, SearchField, SearchFilter, SearchQuery, SearchValue,
        account::index::{AccountGroups, Analyzed, analyze_account},
        global::index::{GlobalGroups, analyze_global},
    },
    write::{BatchBuilder, SearchIndex},
};
use ahash::AHashMap;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

enum AnalyzedDocument {
    Account {
        index: SearchIndex,
        account_id: u32,
        analyzed: Analyzed,
    },
    Global {
        index: SearchIndex,
        document_id: u64,
        members: BTreeSet<(u8, CheekyHash)>,
    },
}

fn analyze(mut document: IndexDocument) -> trc::Result<AnalyzedDocument> {
    let index = document.index;
    let account_id = match document.fields.remove(&SearchField::AccountId) {
        Some(SearchValue::Uint(v)) => Some(v as u32),
        _ => None,
    };
    let document_id = match document.fields.remove(&SearchField::DocumentId) {
        Some(SearchValue::Uint(v)) => Some(v as u32),
        _ => None,
    };
    let global_id = match document.fields.remove(&SearchField::Id) {
        Some(SearchValue::Uint(v)) => Some(v),
        _ => None,
    };

    match (account_id, document_id, global_id) {
        (Some(account_id), Some(document_id), None) => Ok(AnalyzedDocument::Account {
            index,
            account_id,
            analyzed: analyze_account(document_id, document),
        }),
        (None, None, Some(document_id)) => Ok(AnalyzedDocument::Global {
            index,
            document_id,
            members: analyze_global(document),
        }),
        _ => Err(trc::StoreEvent::UnexpectedError
            .into_err()
            .details("Missing account or document id in indexed document")),
    }
}

impl Store {
    pub(crate) async fn index(&self, documents: Vec<IndexDocument>) -> trc::Result<()> {
        let mut groups = AccountGroups::new();
        let mut global_groups = GlobalGroups::new();
        for document in documents {
            if document.is_empty() {
                continue;
            }
            match analyze(document)? {
                AnalyzedDocument::Account {
                    index,
                    account_id,
                    analyzed,
                } => {
                    groups
                        .entry((index, account_id))
                        .or_default()
                        .insert(analyzed.document_id, analyzed);
                }
                AnalyzedDocument::Global {
                    index,
                    document_id,
                    members,
                } => {
                    global_groups
                        .entry(index)
                        .or_default()
                        .insert(document_id, members);
                }
            }
        }

        let mut batch = BatchBuilder::new();
        self.index_account_documents(&mut batch, groups).await?;
        self.index_global_documents(&mut batch, global_groups);

        let mut points = batch.commit_points();
        for point in points.iter() {
            self.write(batch.build_one(point))
                .await
                .caused_by(trc::location!())?;
        }
        Ok(())
    }

    pub(crate) async fn unindex(&self, query: SearchQuery) -> trc::Result<()> {
        let index = query.index;
        let mut account_documents: AHashMap<u32, Vec<u32>> = AHashMap::new();
        let mut last_account_id = None;
        let mut global_purge: Option<u64> = None;

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
                    global_purge = Some(global_purge.map_or(value, |current| current.max(value)));
                }
                SearchFilter::And | SearchFilter::Or | SearchFilter::End => {}
                filter => {
                    return Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details(format!("Unsupported unindex filter {filter:?}")));
                }
            }
        }

        if let Some(purge_id) = global_purge {
            self.unindex_global(index, purge_id)
                .await
                .caused_by(trc::location!())?;
        }

        self.unindex_accounts(index, account_documents)
            .await
            .caused_by(trc::location!())
    }
}
