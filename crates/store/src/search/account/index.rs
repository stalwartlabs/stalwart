/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store,
    search::{
        IndexDocument, SearchValue,
        codec::{
            self, MAX_FIELD_TOKENS, MAX_TERM_POSITIONS, WAL_ADDS, WAL_TOMBSTONES, WalWriter,
            tombstones_from_record,
        },
        tokenize,
    },
    write::{BatchBuilder, SearchIndex, SearchIndexClass, ValueClass},
};
use ahash::AHashMap;
use std::collections::{BTreeMap, BTreeSet};
use trc::AddContext;
use utils::{cheeky_hash::CheekyHash, codec::leb128::Leb128Vec};

pub(crate) type AccountGroups = AHashMap<(SearchIndex, u32), AHashMap<u32, Analyzed>>;

pub(crate) struct Analyzed {
    pub(crate) document_id: u32,
    pub(crate) exact: BTreeMap<(u8, CheekyHash), Vec<u32>>,
    pub(crate) members: BTreeSet<(u8, CheekyHash)>,
    pub(crate) record: BTreeMap<CheekyHash, u32>,
}

pub(crate) fn analyze_account(document_id: u32, document: IndexDocument) -> Analyzed {
    let mut analyzed = Analyzed {
        document_id,
        exact: BTreeMap::new(),
        members: BTreeSet::new(),
        record: BTreeMap::new(),
    };

    for (field, value) in document.fields {
        let field_id = field.u8_id();
        let field_mask = 1u32 << field_id;

        match value {
            SearchValue::Text { value, language } => {
                let mut position = 0u32;
                tokenize::tokenize(&value, language, |token| {
                    let term = CheekyHash::new(token.word.as_bytes());
                    let positions = analyzed.exact.entry((field_id, term)).or_default();
                    if positions.len() < MAX_TERM_POSITIONS {
                        positions.push(position);
                    }
                    *analyzed.record.entry(term).or_default() |= field_mask;
                    if let Some(stem) = token.stem {
                        let term = tokenize::stem_term(&stem);
                        analyzed.members.insert((field_id, term));
                        *analyzed.record.entry(term).or_default() |= field_mask;
                    }
                    position += 1;
                    position < MAX_FIELD_TOKENS as u32
                });
            }
            SearchValue::KeyValues(map) => {
                for (key, value) in map {
                    let term = CheekyHash::new(key.as_bytes());
                    analyzed.members.insert((field_id, term));
                    *analyzed.record.entry(term).or_default() |= field_mask;
                    tokenize::tokenize(&value, nlp::language::Language::None, |token| {
                        let term = tokenize::key_value_term(&key, &token.word);
                        analyzed.members.insert((field_id, term));
                        *analyzed.record.entry(term).or_default() |= field_mask;
                        true
                    });
                }
            }
            SearchValue::Int(v) => {
                let term = tokenize::integer_term(v as u64);
                analyzed.members.insert((field_id, term));
                *analyzed.record.entry(term).or_default() |= field_mask;
            }
            SearchValue::Uint(v) => {
                let term = tokenize::integer_term(v);
                analyzed.members.insert((field_id, term));
                *analyzed.record.entry(term).or_default() |= field_mask;
            }
            SearchValue::Boolean(v) => {
                let term = tokenize::integer_term(v as u64);
                analyzed.members.insert((field_id, term));
                *analyzed.record.entry(term).or_default() |= field_mask;
            }
        }
    }

    analyzed
}

impl Store {
    pub(crate) async fn index_account_documents(
        &self,
        batch: &mut BatchBuilder,
        groups: AccountGroups,
    ) -> trc::Result<()> {
        for ((index, account_id), documents) in groups {
            let mut old_records: AHashMap<u32, Vec<u8>> = AHashMap::new();
            if matches!(index, SearchIndex::Calendar | SearchIndex::Contacts) {
                let mut document_ids = documents.keys().copied().collect::<Vec<_>>();
                document_ids.sort_unstable();
                let ranges = document_ids
                    .into_iter()
                    .map(|document_id| {
                        let (begin, end) =
                            codec::document_record_range(index, account_id, document_id);
                        IterateParams::new(codec::any_key(begin), codec::any_key(end))
                    })
                    .collect::<Vec<_>>();
                self.iterate_many(ranges, |key, value| {
                    if let Some((_, document_id)) = codec::parse_document_key(key) {
                        old_records.insert(document_id, value.to_vec());
                    }
                    Ok(true)
                })
                .await
                .caused_by(trc::location!())?;
            }

            if !old_records.is_empty() {
                let mut tombstones = WalWriter::new(WAL_TOMBSTONES);
                for doc in documents.values() {
                    if let Some(record) = old_records.get(&doc.document_id) {
                        tombstones_from_record(&mut tombstones, doc.document_id, record)
                            .ok_or_else(|| {
                                trc::Error::corrupted_key(record, None, trc::location!())
                            })?;
                    }
                }
                for (id, value) in tombstones.finish() {
                    batch.set(
                        ValueClass::SearchIndex(SearchIndexClass::Wal {
                            index,
                            account_id,
                            id,
                        }),
                        value,
                    );
                }
            }

            let mut adds = WalWriter::new(WAL_ADDS);
            for doc in documents.values() {
                adds.begin_document(doc.document_id);
                for ((field, term), positions) in &doc.exact {
                    adds.push_entry(|buf| {
                        buf.push(*field);
                        codec::push_term(buf, term);
                        codec::encode_positions(positions, buf);
                    });
                }
                for (field, term) in &doc.members {
                    adds.push_entry(|buf| {
                        buf.push(*field);
                        codec::push_term(buf, term);
                        buf.push_leb128(0usize);
                    });
                }
                adds.end_document();

                let mut record = Vec::with_capacity(doc.record.len() * 22 + 5);
                record.push_leb128(doc.record.len() as u32);
                for (term, mask) in &doc.record {
                    codec::push_term(&mut record, term);
                    record.push_leb128(*mask);
                }
                batch.set(
                    ValueClass::SearchIndex(SearchIndexClass::Document {
                        index,
                        account_id,
                        document_id: doc.document_id,
                    }),
                    record,
                );
                batch.commit_point();
            }
            for (id, value) in adds.finish() {
                batch.set(
                    ValueClass::SearchIndex(SearchIndexClass::Wal {
                        index,
                        account_id,
                        id,
                    }),
                    value,
                );
            }
            batch.commit_point();
        }

        Ok(())
    }

    pub(crate) async fn unindex_accounts(
        &self,
        index: SearchIndex,
        account_documents: AHashMap<u32, Vec<u32>>,
    ) -> trc::Result<()> {
        for (account_id, mut document_ids) in account_documents {
            document_ids.sort_unstable();
            document_ids.dedup();
            if document_ids.is_empty() {
                let (begin, end) =
                    codec::account_type_range(SearchIndexClass::TYPE_WAL, index, account_id);
                self.delete_range(codec::any_key(begin), codec::any_key(end))
                    .await
                    .caused_by(trc::location!())?;

                let mut attempts = 0;
                loop {
                    match self.claim_generation(index, account_id).await {
                        Ok(_) => break,
                        Err(err) if err.is_assertion_failure() && attempts < 3 => {
                            attempts += 1;
                        }
                        Err(err) => {
                            return Err(err.caused_by(trc::location!()));
                        }
                    }
                }

                for typ in [
                    SearchIndexClass::TYPE_TERM,
                    SearchIndexClass::TYPE_DOCUMENT,
                    SearchIndexClass::TYPE_META,
                ] {
                    let (begin, end) = codec::account_type_range(typ, index, account_id);
                    self.delete_range(codec::any_key(begin), codec::any_key(end))
                        .await
                        .caused_by(trc::location!())?;
                }
                continue;
            }

            for chunk in document_ids.chunks(128) {
                let ranges = chunk
                    .iter()
                    .map(|document_id| {
                        let (begin, end) =
                            codec::document_record_range(index, account_id, *document_id);
                        IterateParams::new(codec::any_key(begin), codec::any_key(end))
                    })
                    .collect::<Vec<_>>();
                let mut records: AHashMap<u32, Vec<u8>> = AHashMap::new();
                self.iterate_many(ranges, |key, value| {
                    if let Some((_, document_id)) = codec::parse_document_key(key) {
                        records.insert(document_id, value.to_vec());
                    }
                    Ok(true)
                })
                .await
                .caused_by(trc::location!())?;
                if records.is_empty() {
                    continue;
                }

                let mut tombstones = WalWriter::new(WAL_TOMBSTONES);
                for (document_id, record) in &records {
                    tombstones_from_record(&mut tombstones, *document_id, record)
                        .ok_or_else(|| trc::Error::corrupted_key(record, None, trc::location!()))?;
                }

                let mut batch = BatchBuilder::new();
                for (id, value) in tombstones.finish() {
                    batch.set(
                        ValueClass::SearchIndex(SearchIndexClass::Wal {
                            index,
                            account_id,
                            id,
                        }),
                        value,
                    );
                }
                for document_id in records.keys() {
                    batch.clear(ValueClass::SearchIndex(SearchIndexClass::Document {
                        index,
                        account_id,
                        document_id: *document_id,
                    }));
                }
                self.write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
        }

        Ok(())
    }
}
