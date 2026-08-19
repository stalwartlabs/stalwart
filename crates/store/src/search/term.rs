/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Serialize, U32_LEN,
    search::{
        ACCOUNT_BLOCK_SHIFT, EmailSearchField, GLOBAL_BUCKET_SHIFT, IndexDocument,
        MAX_DOCUMENT_SIZE, SearchField, SearchValue,
        codec::{self},
        tokenize::{integer_term, key_value_term, stem_term, tokenize, zigzag},
    },
    write::{
        BatchBuilder, MergeResult, SearchIndex, SearchIndexClass,
        lazybitmap::{LazyBitmap, LazyTreemap},
    },
};
use ahash::{AHashMap, AHashSet};
use indexmap::{IndexMap, map::Entry};
use nlp::language::Language;
use roaring::{RoaringBitmap, RoaringTreemap};
use utils::cheeky_hash::{CheekyHash, CheekyHashMap};

#[derive(Default)]
pub(crate) struct AccountIndexer {
    #[allow(clippy::type_complexity)]
    pub terms: CheekyHashMap<AHashMap<u8, AHashMap<u16, AHashMap<u32, bool>>>>,
    pub documents: AHashMap<u32, Option<Document>>,
}

#[derive(Default)]
pub(crate) struct GlobalIndexer {
    pub terms: CheekyHashMap<AHashMap<u8, AHashMap<u16, AHashSet<u64>>>>,
    pub documents: AHashMap<u64, Document>,
}

#[derive(Default)]
pub(crate) struct Document {
    pub terms: IndexMap<CheekyHash, Term, nohash_hasher::BuildNoHashHasher<u64>>,
    pub fields: IndexMap<u8, Vec<u32>, ahash::RandomState>,
    size: usize,
}

const TERM_OVERHEAD: usize = 4;
const POSITION_SIZE: usize = 3;
const FIELD_OVERHEAD: usize = 5;

#[derive(Default)]
pub(crate) struct Term {
    id: u32,
    field_mask: u32,
}

impl AccountIndexer {
    pub fn insert(&mut self, index_document: IndexDocument, document_id: u32) {
        let mut document = Document::default();
        let mut buf = String::new();
        let mut body = None;
        let mut attach = None;

        for (field, value) in &index_document.fields {
            match field {
                SearchField::AccountId | SearchField::DocumentId => {}
                SearchField::Email(EmailSearchField::Body) => {
                    body = Some((field.u8_id(), value));
                }
                SearchField::Email(EmailSearchField::Attachment) => {
                    attach = Some((field.u8_id(), value));
                }
                _ => {
                    self.insert_value(&mut document, &mut buf, document_id, field.u8_id(), value);
                }
            }
        }

        if let Some((field_id, value)) = body {
            self.insert_value(&mut document, &mut buf, document_id, field_id, value);
        }

        if let Some((field_id, value)) = attach {
            self.insert_value(&mut document, &mut buf, document_id, field_id, value);
        }

        self.documents.insert(document_id, Some(document));
    }

    fn insert_value(
        &mut self,
        document: &mut Document,
        buf: &mut String,
        document_id: u32,
        field_id: u8,
        value: &SearchValue,
    ) {
        match value {
            SearchValue::Text { value, language } => {
                let language = *language;
                let add_position = language != Language::None;
                tokenize(value, language, |token| {
                    let term = CheekyHash::new(token.word.as_bytes());
                    if !document.add_term(term, field_id, add_position) {
                        return false;
                    }
                    self.add_term(document_id, term, field_id);
                    if let Some(stem) = token.stem {
                        let term = stem_term(&stem, buf);
                        if !document.add_term(term, field_id, false) {
                            return false;
                        }
                        self.add_term(document_id, term, field_id);
                    }
                    true
                });
            }
            SearchValue::KeyValues(map) => {
                for (key, value) in map {
                    let term = CheekyHash::new(key.as_bytes());
                    if !document.add_term(term, field_id, false) {
                        break;
                    }
                    self.add_term(document_id, term, field_id);
                    tokenize(value, Language::None, |token| {
                        let term = key_value_term(key, &token.word, buf);
                        if !document.add_term(term, field_id, false) {
                            return false;
                        }
                        self.add_term(document_id, term, field_id);
                        true
                    });
                }
            }
            SearchValue::Int(v) => {
                let term = integer_term(zigzag(*v));
                if document.add_term(term, field_id, false) {
                    self.add_term(document_id, term, field_id);
                }
            }
            SearchValue::Uint(v) => {
                let term = integer_term(*v);
                if document.add_term(term, field_id, false) {
                    self.add_term(document_id, term, field_id);
                }
            }
            SearchValue::Boolean(v) => {
                let term = CheekyHash::new([*v as u8]);
                if document.add_term(term, field_id, false) {
                    self.add_term(document_id, term, field_id);
                }
            }
        }
    }

    pub fn diff(&mut self, current_document: &[u8], document_id: u32) -> trc::Result<()> {
        let block_id = (document_id >> ACCOUNT_BLOCK_SHIFT) as u16;
        deserialize_term_fields(current_document, |term_hash, mut field_mask| {
            let fields = self.terms.entry(term_hash).or_default();
            while field_mask != 0 {
                let item = 31 - field_mask.leading_zeros();
                field_mask ^= 1 << item;
                let map = fields
                    .entry(item as u8)
                    .or_default()
                    .entry(block_id)
                    .or_default();
                if map.remove(&document_id).is_none() {
                    map.insert(document_id, false);
                }
            }
        })
        .ok_or_else(|| trc::Error::corrupted_key(current_document, None, trc::location!()))
    }

    pub fn remove(&mut self, current_document: &[u8], document_id: u32) -> trc::Result<()> {
        self.documents.insert(document_id, None);

        let block_id = (document_id >> ACCOUNT_BLOCK_SHIFT) as u16;
        deserialize_term_fields(current_document, |term_hash, mut field_mask| {
            while field_mask != 0 {
                let item = 31 - field_mask.leading_zeros();
                field_mask ^= 1 << item;
                self.terms
                    .entry(term_hash)
                    .or_default()
                    .entry(item as u8)
                    .or_default()
                    .entry(block_id)
                    .or_default()
                    .insert(document_id, false);
            }
        })
        .ok_or_else(|| trc::Error::corrupted_key(current_document, None, trc::location!()))
    }

    fn add_term(&mut self, document_id: u32, term: CheekyHash, field_id: u8) {
        self.terms
            .entry(term)
            .or_default()
            .entry(field_id)
            .or_default()
            .entry((document_id >> ACCOUNT_BLOCK_SHIFT) as u16)
            .or_default()
            .insert(document_id, true);
    }

    pub fn build_batch(self, index: SearchIndex, account_id: u32) -> BatchBuilder {
        let mut batch = BatchBuilder::new();

        // Build terms
        let mut num_merge_ops = 0;
        for (term, fields) in self.terms {
            for (field, blocks) in fields {
                for (block_id, documents) in blocks {
                    if documents.is_empty() {
                        continue;
                    }
                    let block_base = (block_id as u32) << ACCOUNT_BLOCK_SHIFT;

                    batch.merge_fnc(
                        SearchIndexClass::Term {
                            index,
                            account_id,
                            field,
                            term,
                            block_id,
                        },
                        move |_, bytes| {
                            if let Some(bytes) = bytes {
                                let mut map = LazyBitmap::deserialize_delta(bytes, block_base)?;
                                let mut has_changes = false;
                                for (document_id, do_insert) in &documents {
                                    if *do_insert {
                                        has_changes |= map.0.insert(*document_id);
                                    } else {
                                        has_changes |= map.0.remove(*document_id);
                                    }
                                }
                                if has_changes {
                                    if !map.0.is_empty() {
                                        Ok(MergeResult::Update(map.serialize_optimized(block_base)))
                                    } else {
                                        Ok(MergeResult::Delete)
                                    }
                                } else {
                                    Ok(MergeResult::Skip)
                                }
                            } else {
                                let mut map = RoaringBitmap::new();
                                for (document_id, do_insert) in &documents {
                                    if *do_insert {
                                        map.insert(*document_id);
                                    }
                                }
                                if !map.is_empty() {
                                    Ok(MergeResult::Update(
                                        LazyBitmap(map).serialize_optimized(block_base),
                                    ))
                                } else {
                                    Ok(MergeResult::Skip)
                                }
                            }
                        },
                    );
                    if num_merge_ops >= 1000 {
                        batch.add_commit_point();
                        num_merge_ops = 0;
                    } else {
                        num_merge_ops += 1;
                    }
                }
            }
        }

        // Add documents
        for (document_id, document) in self.documents {
            if let Some(document) = document {
                batch
                    .set(
                        SearchIndexClass::Document {
                            index,
                            account_id,
                            document_id,
                        },
                        document.serialize().unwrap_or_default(),
                    )
                    .commit_point();
            } else {
                batch
                    .clear(SearchIndexClass::Document {
                        index,
                        account_id,
                        document_id,
                    })
                    .commit_point();
            }
        }

        batch
    }
}

impl GlobalIndexer {
    pub fn insert(&mut self, index_document: IndexDocument, document_id: u64) {
        let mut document = Document::default();
        let mut buf = String::new();

        self.terms
            .entry(CheekyHash::new("_id"))
            .or_default()
            .entry(SearchField::Id.u8_id())
            .or_default()
            .entry((document_id >> GLOBAL_BUCKET_SHIFT) as u16)
            .or_default()
            .insert(document_id);

        for (field, value) in index_document.fields {
            if field == SearchField::Id {
                continue;
            }

            let field_id = field.u8_id();

            match value {
                SearchValue::Text { value, language } => {
                    tokenize(&value, language, |token| {
                        let term = CheekyHash::new(token.word.as_bytes());
                        if !document.add_term(term, field_id, false) {
                            return false;
                        }
                        self.add_term(document_id, term, field_id);
                        true
                    });
                }
                SearchValue::KeyValues(map) => {
                    for (key, value) in map {
                        let term = CheekyHash::new(key.as_bytes());
                        if !document.add_term(term, field_id, false) {
                            break;
                        }
                        self.add_term(document_id, term, field_id);
                        tokenize(&value, Language::None, |token| {
                            let term = key_value_term(&key, &token.word, &mut buf);
                            if !document.add_term(term, field_id, false) {
                                return false;
                            }
                            self.add_term(document_id, term, field_id);
                            true
                        });
                    }
                }
                SearchValue::Int(v) => {
                    let term = integer_term(zigzag(v));
                    if document.add_term(term, field_id, false) {
                        self.add_term(document_id, term, field_id);
                    }
                }
                SearchValue::Uint(v) => {
                    let term = integer_term(v);
                    if document.add_term(term, field_id, false) {
                        self.add_term(document_id, term, field_id);
                    }
                }
                SearchValue::Boolean(v) => {
                    let term = CheekyHash::new([v as u8]);
                    if document.add_term(term, field_id, false) {
                        self.add_term(document_id, term, field_id);
                    }
                }
            }
        }

        self.documents.insert(document_id, document);
    }

    fn add_term(&mut self, document_id: u64, term: CheekyHash, field_id: u8) {
        self.terms
            .entry(term)
            .or_default()
            .entry(field_id)
            .or_default()
            .entry((document_id >> GLOBAL_BUCKET_SHIFT) as u16)
            .or_default()
            .insert(document_id);
    }

    pub fn build_batch(self, index: SearchIndex) -> BatchBuilder {
        let mut batch = BatchBuilder::new();

        // Build terms
        let mut num_merge_ops = 0;
        for (term, fields) in self.terms {
            for (field, blocks) in fields {
                for (block_id, document_ids) in blocks {
                    let key = if field != SearchField::Id.u8_id() {
                        SearchIndexClass::GlobalTerm {
                            index,
                            field,
                            term,
                            block_id,
                        }
                    } else {
                        SearchIndexClass::GlobalDocumentId { index, block_id }
                    };

                    batch.merge_fnc(key, move |_, bytes| {
                        if let Some(bytes) = bytes {
                            let mut treemap = LazyTreemap::deserialize_delta(
                                bytes,
                                (block_id as u64) << GLOBAL_BUCKET_SHIFT,
                            )?;
                            let cur_len = treemap.0.len();
                            for document_id in &document_ids {
                                treemap.0.insert(*document_id);
                            }
                            if treemap.0.len() > cur_len {
                                Ok(MergeResult::Update(
                                    treemap
                                        .serialize_delta((block_id as u64) << GLOBAL_BUCKET_SHIFT),
                                ))
                            } else {
                                Ok(MergeResult::Skip)
                            }
                        } else {
                            let mut treemap = RoaringTreemap::new();

                            for document_id in &document_ids {
                                treemap.insert(*document_id);
                            }

                            Ok(MergeResult::Update(
                                LazyTreemap(treemap)
                                    .serialize_delta((block_id as u64) << GLOBAL_BUCKET_SHIFT),
                            ))
                        }
                    });

                    if num_merge_ops >= 1000 {
                        batch.add_commit_point();
                        num_merge_ops = 0;
                    } else {
                        num_merge_ops += 1;
                    }
                }
            }
        }

        // Add documents
        for (document_id, document) in self.documents {
            batch
                .set(
                    SearchIndexClass::GlobalDocument { index, document_id },
                    document.serialize().unwrap_or_default(),
                )
                .commit_point();
        }

        batch
    }
}

impl Document {
    fn add_term(&mut self, term: CheekyHash, field_id: u8, add_position: bool) -> bool {
        let mut cost = if add_position {
            POSITION_SIZE
                + if self.fields.contains_key(&field_id) {
                    0
                } else {
                    FIELD_OVERHEAD
                }
        } else {
            0
        };

        let field_mask = 1 << field_id;
        let term_id = self.terms.len() as u32;
        let term_id = match self.terms.entry(term) {
            Entry::Occupied(entry) => {
                if self.size + cost > MAX_DOCUMENT_SIZE {
                    return false;
                }
                let term = entry.into_mut();
                term.field_mask |= field_mask;
                term.id
            }
            Entry::Vacant(entry) => {
                cost += term.key_len() + TERM_OVERHEAD;
                if self.size + cost > MAX_DOCUMENT_SIZE {
                    return false;
                }

                entry.insert(Term {
                    id: term_id,
                    field_mask,
                });
                term_id
            }
        };

        self.size += cost;

        if add_position {
            self.fields.entry(field_id).or_default().push(term_id);
        }

        true
    }
}

impl Serialize for Document {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        let mut writer =
            codec::Writer::with_capacity(self.terms.len() * (CheekyHash::HASH_SIZE + U32_LEN));
        writer.push_leb128(self.terms.len());
        for (term_hash, term) in &self.terms {
            writer.push_term(term_hash);
            writer.push_leb128(term.field_mask);
        }
        writer.push_leb128(self.fields.len());
        for (field, positions) in &self.fields {
            writer.push_u8(*field);
            writer.push_leb128(positions.len());
            for position in positions {
                writer.push_leb128(*position);
            }
        }

        Ok(writer.into_inner())
    }
}

pub(crate) fn matches_phrase(
    bytes: &[u8],
    field: u8,
    words: &[CheekyHash],
    ordinals: &mut Vec<u32>,
    failure: &mut Vec<usize>,
) -> Option<bool> {
    let mut reader = codec::Reader::new(bytes);

    let items = reader.leb128::<usize>()?;
    ordinals.clear();
    ordinals.resize(words.len(), u32::MAX);
    let mut found_all = false;
    for ordinal in 0..items {
        let term_hash = reader.term()?;
        reader.leb128::<u32>()?;
        if !found_all {
            let mut num_found = 0;
            for (word, slot) in words.iter().zip(ordinals.iter_mut()) {
                if *slot == u32::MAX {
                    if *word == term_hash {
                        *slot = ordinal as u32;
                        num_found += 1;
                    }
                } else {
                    num_found += 1;
                }
            }
            found_all = num_found == words.len();
        }
    }
    if !found_all {
        return Some(false);
    }

    let num_fields = reader.leb128::<usize>()?;
    for _ in 0..num_fields {
        let field_id = reader.u8()?;
        let num_positions = reader.leb128::<usize>()?;
        if field_id == field {
            failure.clear();
            failure.resize(ordinals.len(), 0);
            let mut prefix_len = 0;
            for i in 1..ordinals.len() {
                while prefix_len > 0 && ordinals[i] != ordinals[prefix_len] {
                    prefix_len = failure[prefix_len - 1];
                }
                if ordinals[i] == ordinals[prefix_len] {
                    prefix_len += 1;
                }
                failure[i] = prefix_len;
            }

            let mut matched = 0;
            for _ in 0..num_positions {
                let position = reader.leb128::<u32>()?;
                while matched > 0 && position != ordinals[matched] {
                    matched = failure[matched - 1];
                }
                if position == ordinals[matched] {
                    matched += 1;
                    if matched == ordinals.len() {
                        return Some(true);
                    }
                }
            }
            return Some(false);
        } else {
            for _ in 0..num_positions {
                reader.leb128::<u32>()?;
            }
        }
    }

    Some(true)
}

pub(crate) fn deserialize_term_fields(
    bytes: &[u8],
    mut cb: impl FnMut(CheekyHash, u32),
) -> Option<()> {
    let mut reader = codec::Reader::new(bytes);

    let items = reader.leb128::<usize>()?;

    for _ in 0..items {
        let term_hash = reader.term()?;
        let field_mask = reader.leb128::<u32>()?;
        cb(term_hash, field_mask);
    }

    Some(())
}
