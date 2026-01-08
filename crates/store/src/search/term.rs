/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Serialize,
    backend::MAX_TOKEN_LENGTH,
    search::*,
    write::{
        Archiver, BatchBuilder, SEARCH_INDEX_MAX_FIELD_LEN, SearchIndexClass, SearchIndexField,
        SearchIndexId, SearchIndexType, ValueClass,
    },
};
use ahash::AHashSet;
use nlp::{
    language::stemmer::Stemmer,
    tokenizers::{space::SpaceTokenizer, word::WordTokenizer},
};
use utils::{
    cheeky_hash::{CheekyBTreeMap, CheekyHash},
    map::bitmap::BitPop,
};

#[derive(Debug, PartialEq, Eq, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub(crate) struct TermIndex {
    terms: Vec<Term>,
    fields: Vec<SearchIndexField>,
}

#[derive(Debug, PartialEq, Eq, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub(crate) struct Term {
    hash: CheekyHash,
    fields: u32,
}

pub(crate) struct TermIndexBuilder {
    pub(crate) index: TermIndex,
    pub(crate) id: SearchIndexId,
}

impl TermIndexBuilder {
    pub fn build(document: IndexDocument, truncate_at: usize) -> Self {
        let mut terms: CheekyBTreeMap<u32> = CheekyBTreeMap::new();
        let mut fields: Vec<SearchIndexField> = Vec::new();
        let mut account_id = None;
        let mut document_id = None;
        let mut id = None;

        for (field, value) in document.fields {
            match field {
                SearchField::Id => {
                    if let SearchValue::Uint(v) = value {
                        fields.push(SearchIndexField {
                            field_id: field.u8_id(),
                            data: v.to_be_bytes().to_vec(),
                        });
                        id = Some(v);
                    }

                    continue;
                }
                SearchField::AccountId => {
                    if let SearchValue::Uint(v) = value {
                        account_id = Some(v);
                    }
                    continue;
                }
                SearchField::DocumentId => {
                    if let SearchValue::Uint(v) = value {
                        document_id = Some(v);
                    }
                    continue;
                }
                _ => {}
            }

            let field = match value {
                SearchValue::Text { value, language } => {
                    if field.is_text() {
                        let value = if truncate_at > 0 && value.len() > truncate_at {
                            let pos = value.floor_char_boundary(truncate_at);
                            &value[..pos]
                        } else {
                            &value
                        };

                        match language {
                            Language::Unknown => {
                                for token in WordTokenizer::new(value, MAX_TOKEN_LENGTH) {
                                    terms
                                        .entry(CheekyHash::new(token.word.as_bytes()))
                                        .or_default()
                                        .bit_push(field.u8_id());
                                }
                            }
                            Language::None => {
                                for token in SpaceTokenizer::new(value, MAX_TOKEN_LENGTH) {
                                    terms
                                        .entry(CheekyHash::new(token.as_bytes()))
                                        .or_default()
                                        .bit_push(field.u8_id());
                                }
                            }
                            _ => {
                                for token in Stemmer::new(value, language, MAX_TOKEN_LENGTH) {
                                    terms
                                        .entry(CheekyHash::new(token.word.as_bytes()))
                                        .or_default()
                                        .bit_push(field.u8_id());

                                    if let Some(stemmed_word) = token.stemmed_word {
                                        terms
                                            .entry(CheekyHash::new(
                                                format!("{}*", stemmed_word).as_bytes(),
                                            ))
                                            .or_default()
                                            .bit_push(field.u8_id());
                                    }
                                }
                            }
                        }
                    }

                    if field.is_indexed() {
                        let mut data = value.into_bytes();
                        data.truncate(SEARCH_INDEX_MAX_FIELD_LEN);

                        SearchIndexField {
                            field_id: field.u8_id(),
                            data,
                        }
                    } else {
                        continue;
                    }
                }
                SearchValue::KeyValues(map) => {
                    for (key, value) in map {
                        terms
                            .entry(CheekyHash::new(key.as_bytes()))
                            .or_default()
                            .bit_push(field.u8_id());
                        for token in SpaceTokenizer::new(value.as_str(), MAX_TOKEN_LENGTH) {
                            terms
                                .entry(CheekyHash::new(format!("{key} {token}").as_bytes()))
                                .or_default()
                                .bit_push(field.u8_id());
                        }
                    }

                    continue;
                }
                SearchValue::Int(v) => SearchIndexField {
                    field_id: field.u8_id(),
                    data: (v as u64).to_be_bytes().to_vec(),
                },
                SearchValue::Uint(v) => SearchIndexField {
                    field_id: field.u8_id(),
                    data: v.to_be_bytes().to_vec(),
                },
                SearchValue::Boolean(v) => SearchIndexField {
                    field_id: field.u8_id(),
                    data: vec![v as u8],
                },
            };

            fields.push(field);
        }

        TermIndexBuilder {
            index: TermIndex {
                terms: terms
                    .into_iter()
                    .map(|(k, v)| Term { hash: k, fields: v })
                    .collect(),
                fields,
            },
            id: match (account_id, document_id, id) {
                (Some(account_id), Some(document_id), None) => SearchIndexId::Account {
                    account_id: account_id as u32,
                    document_id: document_id as u32,
                },
                (None, None, Some(id)) => SearchIndexId::Global { id },
                _ => {
                    debug_assert!(
                        false,
                        "Invalid combination of AccountId {account_id:?}, DocumentId {document_id:?} and Id {id:?} fields"
                    );
                    SearchIndexId::Global { id: 0 }
                }
            },
        }
    }
}

impl TermIndex {
    pub fn write_index(
        self,
        batch: &mut BatchBuilder,
        index: SearchIndex,
        id: SearchIndexId,
    ) -> trc::Result<()> {
        let archive = Archiver::new(self);
        batch
            .set(
                ValueClass::SearchIndex(SearchIndexClass {
                    index,
                    id,
                    typ: SearchIndexType::Document,
                }),
                archive.serialize()?,
            )
            .commit_point();

        for term in archive.inner.terms {
            let mut fields = term.fields;
            while let Some(field) = fields.bit_pop() {
                batch
                    .set(
                        ValueClass::SearchIndex(SearchIndexClass {
                            index,
                            id,
                            typ: SearchIndexType::Term {
                                hash: term.hash,
                                field,
                            },
                        }),
                        vec![],
                    )
                    .commit_point();
            }
        }

        for field in archive.inner.fields {
            batch
                .set(
                    ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id,
                        typ: SearchIndexType::Index { field },
                    }),
                    vec![],
                )
                .commit_point();
        }

        Ok(())
    }

    pub fn merge_index(
        self,
        batch: &mut BatchBuilder,
        index: SearchIndex,
        id: SearchIndexId,
        old_term: &ArchivedTermIndex,
    ) -> trc::Result<()> {
        let archive = Archiver::new(self);
        batch
            .set(
                ValueClass::SearchIndex(SearchIndexClass {
                    index,
                    id,
                    typ: SearchIndexType::Document,
                }),
                archive.serialize()?,
            )
            .commit_point();

        let mut old_terms = AHashSet::with_capacity(old_term.terms.len());
        let mut old_fields = AHashSet::with_capacity(old_term.fields.len());
        for term in old_term.terms.iter() {
            let mut fields = term.fields.to_native();
            while let Some(field) = fields.bit_pop() {
                old_terms.insert(SearchIndexType::Term {
                    hash: term.hash.to_native(),
                    field,
                });
            }
        }
        for field in old_term.fields.iter() {
            old_fields.insert(SearchIndexField {
                field_id: field.field_id,
                data: field.data.to_vec(),
            });
        }

        for term in archive.inner.terms {
            let mut fields = term.fields;
            while let Some(field) = fields.bit_pop() {
                let typ = SearchIndexType::Term {
                    hash: term.hash,
                    field,
                };

                if !old_terms.remove(&typ) {
                    batch
                        .set(
                            ValueClass::SearchIndex(SearchIndexClass { index, id, typ }),
                            vec![],
                        )
                        .commit_point();
                }
            }
        }

        for field in archive.inner.fields {
            if !old_fields.remove(&field) {
                batch
                    .set(
                        ValueClass::SearchIndex(SearchIndexClass {
                            index,
                            id,
                            typ: SearchIndexType::Index { field },
                        }),
                        vec![],
                    )
                    .commit_point();
            }
        }

        for typ in old_terms {
            batch
                .clear(ValueClass::SearchIndex(SearchIndexClass { index, id, typ }))
                .commit_point();
        }

        for field in old_fields {
            batch
                .clear(ValueClass::SearchIndex(SearchIndexClass {
                    index,
                    id,
                    typ: SearchIndexType::Index { field },
                }))
                .commit_point();
        }

        Ok(())
    }
}

impl ArchivedTermIndex {
    pub fn delete_index(&self, batch: &mut BatchBuilder, index: SearchIndex, id: SearchIndexId) {
        batch
            .clear(ValueClass::SearchIndex(SearchIndexClass {
                index,
                id,
                typ: SearchIndexType::Document,
            }))
            .commit_point();

        for term in self.terms.iter() {
            let mut fields = term.fields.to_native();
            while let Some(field) = fields.bit_pop() {
                batch
                    .clear(ValueClass::SearchIndex(SearchIndexClass {
                        index,
                        id,
                        typ: SearchIndexType::Term {
                            hash: term.hash.to_native(),
                            field,
                        },
                    }))
                    .commit_point();
            }
        }

        for field in self.fields.iter() {
            batch
                .clear(ValueClass::SearchIndex(SearchIndexClass {
                    index,
                    id,
                    typ: SearchIndexType::Index {
                        field: SearchIndexField {
                            field_id: field.field_id,
                            data: field.data.to_vec(),
                        },
                    },
                }))
                .commit_point();
        }
    }
}

impl SearchIndex {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            SearchIndex::Email => 0,
            SearchIndex::Calendar => 1,
            SearchIndex::Contacts => 2,
            SearchIndex::File => 3,
            SearchIndex::Tracing => 4,
            SearchIndex::InMemory => unreachable!(),
        }
    }
}

impl SearchField {
    pub(crate) fn u8_id(&self) -> u8 {
        match self {
            SearchField::AccountId => 0,
            SearchField::DocumentId => 1,
            SearchField::Id => 2,
            SearchField::Email(field) => match field {
                EmailSearchField::From => 3,
                EmailSearchField::To => 4,
                EmailSearchField::Cc => 5,
                EmailSearchField::Bcc => 6,
                EmailSearchField::Subject => 7,
                EmailSearchField::Body => 8,
                EmailSearchField::Attachment => 9,
                EmailSearchField::ReceivedAt => 10,
                EmailSearchField::SentAt => 11,
                EmailSearchField::Size => 12,
                EmailSearchField::HasAttachment => 13,
                EmailSearchField::Headers => 14,
            },
            SearchField::Calendar(field) => match field {
                CalendarSearchField::Title => 3,
                CalendarSearchField::Description => 4,
                CalendarSearchField::Location => 5,
                CalendarSearchField::Owner => 6,
                CalendarSearchField::Attendee => 7,
                CalendarSearchField::Start => 8,
                CalendarSearchField::Uid => 9,
            },
            SearchField::Contact(field) => match field {
                ContactSearchField::Member => 3,
                ContactSearchField::Kind => 4,
                ContactSearchField::Name => 5,
                ContactSearchField::Nickname => 6,
                ContactSearchField::Organization => 7,
                ContactSearchField::Email => 8,
                ContactSearchField::Phone => 9,
                ContactSearchField::OnlineService => 10,
                ContactSearchField::Address => 11,
                ContactSearchField::Note => 12,
                ContactSearchField::Uid => 13,
            },
            SearchField::File(field) => match field {
                FileSearchField::Name => 3,
                FileSearchField::Content => 4,
            },
            SearchField::Tracing(field) => match field {
                TracingSearchField::EventType => 3,
                TracingSearchField::QueueId => 4,
                TracingSearchField::Keywords => 5,
            },
        }
    }
}
