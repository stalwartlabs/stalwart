/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store,
    search::{
        KeyValueMatch, QueryResults, SearchField, SearchFilter, SearchQuery, TextMatch,
        codec::{self, Probe, TYPE_MASK, WalEvent},
        tokenize,
    },
    write::{SearchIndex, SearchIndexClass},
};
use ahash::{AHashMap, AHashSet};
use nlp::language::Language;
use roaring::RoaringBitmap;
use std::cmp::Ordering;
use std::ops::{BitAndAssign, BitOrAssign, BitXorAssign};
use utils::cheeky_hash::CheekyHash;

#[derive(Default)]
struct TermPostings {
    docs: RoaringBitmap,
    positions: AHashMap<u32, Vec<u8>>,
}

enum Node {
    Probes {
        groups: Vec<Vec<Probe>>,
    },
    Phrase {
        field: u8,
        words: Vec<CheekyHash>,
    },
    Prefix {
        field: u8,
        prefix: Box<[u8]>,
        last_use: bool,
    },
    DocumentSet(RoaringBitmap),
    Empty,
    And,
    Or,
    Not,
    End,
}

#[derive(Default)]
struct Plan {
    nodes: Vec<Node>,
    terms: AHashMap<Probe, TermPostings>,
    positions_needed: AHashSet<Probe>,
    prefixes: AHashMap<(u8, Box<[u8]>), RoaringBitmap>,
}

impl Plan {
    fn probe(&mut self, field: u8, term: CheekyHash) -> Probe {
        let probe = (field, term);
        self.terms.entry(probe).or_default();
        probe
    }

    fn phrase_word(&mut self, field: u8, term: CheekyHash) -> CheekyHash {
        let probe = self.probe(field, term);
        self.positions_needed.insert(probe);
        term
    }

    fn add_text(&mut self, field: u8, op: TextMatch, value: &str, language: Language) {
        match op {
            TextMatch::Exact => {
                let words = tokenize::tokenize_query(value, language)
                    .into_iter()
                    .map(|token| CheekyHash::new(token.word.as_bytes()))
                    .collect::<Vec<_>>();
                match words.len() {
                    0 => self.nodes.push(Node::Empty),
                    1 => {
                        let probe = self.probe(field, words[0]);
                        self.nodes.push(Node::Probes {
                            groups: vec![vec![probe]],
                        });
                    }
                    _ => {
                        let words = words
                            .into_iter()
                            .map(|word| self.phrase_word(field, word))
                            .collect();
                        self.nodes.push(Node::Phrase { field, words });
                    }
                }
            }
            TextMatch::Standard => {
                let mut groups = Vec::new();
                for token in tokenize::tokenize_query(value, language) {
                    let mut group = vec![self.probe(field, CheekyHash::new(token.word.as_bytes()))];
                    if !matches!(language, Language::None | Language::Unknown) {
                        group.push(self.probe(field, tokenize::stem_term(&token.word)));
                        if let Some(stem) = &token.stem {
                            group.push(self.probe(field, CheekyHash::new(stem.as_bytes())));
                            group.push(self.probe(field, tokenize::stem_term(stem)));
                        }
                    }
                    groups.push(group);
                }
                if groups.is_empty() {
                    self.nodes.push(Node::Empty);
                } else {
                    self.nodes.push(Node::Probes { groups });
                }
            }
            TextMatch::Prefix => {
                let mut tokens = tokenize::tokenize_query(value, language);
                let Some(last) = tokens.pop() else {
                    self.nodes.push(Node::Empty);
                    return;
                };
                let prefix = last.word.into_owned().into_bytes().into_boxed_slice();
                if prefix.len() > CheekyHash::HASH_SIZE {
                    self.nodes.push(Node::Empty);
                    return;
                }
                self.prefixes.entry((field, prefix.clone())).or_default();
                if tokens.is_empty() {
                    self.nodes.push(Node::Prefix {
                        field,
                        prefix,
                        last_use: false,
                    });
                } else {
                    let groups = tokens
                        .into_iter()
                        .map(|token| {
                            vec![self.probe(field, CheekyHash::new(token.word.as_bytes()))]
                        })
                        .collect();
                    self.nodes.push(Node::And);
                    self.nodes.push(Node::Probes { groups });
                    self.nodes.push(Node::Prefix {
                        field,
                        prefix,
                        last_use: false,
                    });
                    self.nodes.push(Node::End);
                }
            }
        }
    }
}

fn build_plan(filters: Vec<SearchFilter>) -> trc::Result<(u32, Plan)> {
    let mut account_id = None;
    let mut plan = Plan::default();

    for filter in filters {
        match filter {
            SearchFilter::Integer {
                field: SearchField::AccountId,
                op: Ordering::Equal,
                value,
            } => {
                account_id = Some(value as u32);
            }
            SearchFilter::Integer { field, op, value } => {
                if op != Ordering::Equal {
                    return Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details("Integer range filters are not supported"));
                }
                let probe = plan.probe(field.u8_id(), tokenize::integer_term(value));
                plan.nodes.push(Node::Probes {
                    groups: vec![vec![probe]],
                });
            }
            SearchFilter::Text {
                field,
                op,
                value,
                language,
            } => {
                plan.add_text(field.u8_id(), op, &value, language);
            }
            SearchFilter::KeyValue { field, key, op } => {
                let field = field.u8_id();
                let key = key
                    .chars()
                    .filter(|ch| !ch.is_control())
                    .map(|ch| ch.to_ascii_lowercase())
                    .collect::<String>();
                let value = match &op {
                    KeyValueMatch::Equals(value) | KeyValueMatch::Contains(value) => value.as_str(),
                    KeyValueMatch::Exists => "",
                };
                let mut groups = Vec::new();
                for token in tokenize::tokenize_query(value, Language::None) {
                    groups.push(vec![
                        plan.probe(field, tokenize::key_value_term(&key, &token.word)),
                    ]);
                }
                if groups.is_empty() {
                    groups.push(vec![plan.probe(field, CheekyHash::new(key.as_bytes()))]);
                }
                plan.nodes.push(Node::Probes { groups });
            }
            SearchFilter::DocumentSet(set) => {
                plan.nodes.push(Node::DocumentSet(set));
            }
            SearchFilter::And => plan.nodes.push(Node::And),
            SearchFilter::Or => plan.nodes.push(Node::Or),
            SearchFilter::Not => plan.nodes.push(Node::Not),
            SearchFilter::End => plan.nodes.push(Node::End),
        }
    }

    let mut seen = AHashSet::new();
    let mut last_uses = Vec::new();
    for (position, node) in plan.nodes.iter().enumerate().rev() {
        if let Node::Prefix { field, prefix, .. } = node
            && seen.insert((*field, prefix.as_ref()))
        {
            last_uses.push(position);
        }
    }
    for position in last_uses {
        if let Node::Prefix { last_use, .. } = &mut plan.nodes[position] {
            *last_use = true;
        }
    }

    account_id
        .map(|account_id| (account_id, plan))
        .ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Account ID filter is required for account queries")
        })
}

impl Plan {
    async fn fetch(
        &mut self,
        store: &Store,
        index: SearchIndex,
        account_id: u32,
    ) -> trc::Result<()> {
        if self.terms.is_empty() && self.prefixes.is_empty() {
            return Ok(());
        }

        let mut bounds = Vec::with_capacity(self.terms.len() + self.prefixes.len() + 1);
        bounds.push(codec::account_type_range(
            SearchIndexClass::TYPE_WAL,
            index,
            account_id,
        ));
        'prefix: for (field, prefix) in self.prefixes.keys() {
            for (other_field, other_prefix) in self.prefixes.keys() {
                if other_field == field
                    && other_prefix.len() < prefix.len()
                    && prefix.starts_with(other_prefix)
                {
                    continue 'prefix;
                }
            }
            bounds.push(codec::term_prefix_range(index, account_id, *field, prefix));
        }
        'probe: for (field, term) in self.terms.keys() {
            if term.len() <= CheekyHash::HASH_SIZE {
                for (prefix_field, prefix) in self.prefixes.keys() {
                    if prefix_field == field && term.as_key().starts_with(prefix) {
                        continue 'probe;
                    }
                }
            }
            bounds.push(codec::term_range(index, account_id, *field, term));
        }
        let ranges = bounds
            .into_iter()
            .map(|(begin, end)| IterateParams::new(codec::any_key(begin), codec::any_key(end)))
            .collect::<Vec<_>>();

        type TermOverlay = AHashMap<Probe, AHashMap<u32, Option<Vec<u8>>>>;
        let prefix_keys = self.prefixes.keys().cloned().collect::<Vec<_>>();
        let mut term_overlay = TermOverlay::new();
        let mut prefix_overlay: Vec<AHashMap<u32, bool>> = vec![AHashMap::new(); prefix_keys.len()];
        let mut corrupted = None;

        store
            .iterate_many(ranges, |key, value| {
                let mut valid = Some(());
                match key.first().copied().unwrap_or_default() & TYPE_MASK {
                    SearchIndexClass::TYPE_WAL => {
                        valid = codec::walk_wal::<u32>(value, |event| {
                            match event {
                                WalEvent::Add {
                                    document_id,
                                    field,
                                    term,
                                    payload,
                                } => {
                                    let probe = (field, term);
                                    if self.terms.contains_key(&probe) {
                                        let payload = if self.positions_needed.contains(&probe) {
                                            payload.to_vec()
                                        } else {
                                            Vec::new()
                                        };
                                        term_overlay
                                            .entry(probe)
                                            .or_default()
                                            .insert(document_id, Some(payload));
                                    }
                                    if term.len() <= CheekyHash::HASH_SIZE
                                        && term.as_key().last() != Some(&b'*')
                                    {
                                        for ((prefix_field, prefix), overlay) in
                                            prefix_keys.iter().zip(prefix_overlay.iter_mut())
                                        {
                                            if *prefix_field == field
                                                && term.as_key().starts_with(prefix)
                                            {
                                                overlay.insert(document_id, true);
                                            }
                                        }
                                    }
                                }
                                WalEvent::TombstoneDocument { document_id } => {
                                    for overlay in prefix_overlay.iter_mut() {
                                        overlay.insert(document_id, false);
                                    }
                                }
                                WalEvent::Tombstone {
                                    document_id,
                                    mut mask,
                                    term,
                                } => {
                                    while mask != 0 {
                                        let field = mask.trailing_zeros() as u8;
                                        mask &= mask - 1;
                                        if self.terms.contains_key(&(field, term)) {
                                            term_overlay
                                                .entry((field, term))
                                                .or_default()
                                                .insert(document_id, None);
                                        }
                                    }
                                }
                            }
                            true
                        });
                    }
                    SearchIndexClass::TYPE_TERM => {
                        if let Some((field, term, first_document_id)) =
                            codec::parse_term_key::<u32>(key)
                        {
                            let needs_positions = self.positions_needed.contains(&(field, term));
                            let mut postings = self.terms.get_mut(&(field, term));
                            let mut prefix_docs = if term.len() <= CheekyHash::HASH_SIZE
                                && term.as_key().last() != Some(&b'*')
                            {
                                self.prefixes
                                    .iter_mut()
                                    .filter(|((prefix_field, prefix), _)| {
                                        *prefix_field == field && term.as_key().starts_with(prefix)
                                    })
                                    .map(|(_, docs)| docs)
                                    .collect::<Vec<_>>()
                            } else {
                                Vec::new()
                            };
                            if (postings.is_some() || !prefix_docs.is_empty())
                                && codec::walk_chunk(first_document_id, value, |doc, payload| {
                                    if let Some(postings) = &mut postings {
                                        postings.docs.insert(doc);
                                        if needs_positions {
                                            postings.positions.insert(doc, payload.to_vec());
                                        }
                                    }
                                    for docs in prefix_docs.iter_mut() {
                                        docs.insert(doc);
                                    }
                                    true
                                })
                                .is_none()
                            {
                                valid = None;
                            }
                        }
                    }
                    _ => {}
                }
                if valid.is_none() {
                    corrupted = Some(trc::Error::corrupted_key(
                        key,
                        Some(value),
                        trc::location!(),
                    ));
                    Ok(false)
                } else {
                    Ok(true)
                }
            })
            .await?;

        if let Some(err) = corrupted {
            return Err(err);
        }

        for (probe, ops) in term_overlay {
            let needs_positions = self.positions_needed.contains(&probe);
            if let Some(postings) = self.terms.get_mut(&probe) {
                for (document_id, op) in ops {
                    match op {
                        Some(payload) => {
                            postings.docs.insert(document_id);
                            if needs_positions {
                                postings.positions.insert(document_id, payload);
                            }
                        }
                        None => {
                            postings.docs.remove(document_id);
                            postings.positions.remove(&document_id);
                        }
                    }
                }
            }
        }
        for (key, ops) in prefix_keys.into_iter().zip(prefix_overlay) {
            if let Some(docs) = self.prefixes.get_mut(&key) {
                for (document_id, add) in ops {
                    if add {
                        docs.insert(document_id);
                    } else {
                        docs.remove(document_id);
                    }
                }
            }
        }

        Ok(())
    }

    fn union(&self, probes: &[Probe]) -> RoaringBitmap {
        let mut result = RoaringBitmap::new();
        for probe in probes {
            if let Some(postings) = self.terms.get(probe) {
                result |= &postings.docs;
            }
        }
        result
    }

    fn phrase(&self, field: u8, words: &[CheekyHash]) -> trc::Result<RoaringBitmap> {
        let mut result = RoaringBitmap::new();
        let Some(first) = words.first() else {
            return Ok(result);
        };
        let mut candidates = self
            .terms
            .get(&(field, *first))
            .map(|postings| postings.docs.clone())
            .unwrap_or_default();
        for word in &words[1..] {
            if candidates.is_empty() {
                return Ok(result);
            }
            if let Some(postings) = self.terms.get(&(field, *word)) {
                candidates &= &postings.docs;
            } else {
                return Ok(result);
            }
        }

        let mut current = Vec::new();
        let mut next = Vec::new();
        'document: for document_id in candidates {
            let Some(payload) = self
                .terms
                .get(&(field, *first))
                .and_then(|postings| postings.positions.get(&document_id))
            else {
                continue;
            };
            codec::decode_positions(payload, &mut current)
                .ok_or_else(|| trc::Error::corrupted_key(payload, None, trc::location!()))?;
            if current.is_empty() {
                continue;
            }
            for word in &words[1..] {
                let Some(payload) = self
                    .terms
                    .get(&(field, *word))
                    .and_then(|postings| postings.positions.get(&document_id))
                else {
                    continue 'document;
                };
                codec::decode_positions(payload, &mut next)
                    .ok_or_else(|| trc::Error::corrupted_key(payload, None, trc::location!()))?;
                if next.is_empty() {
                    continue 'document;
                }
                current.retain(|position| next.binary_search(&(position + 1)).is_ok());
                if current.is_empty() {
                    continue 'document;
                }
                for position in current.iter_mut() {
                    *position += 1;
                }
            }
            result.insert(document_id);
        }
        Ok(result)
    }

    fn evaluate(mut self, mask: RoaringBitmap) -> trc::Result<RoaringBitmap> {
        struct State {
            op: u8,
            bm: Option<RoaringBitmap>,
        }
        const OP_AND: u8 = 0;
        const OP_OR: u8 = 1;
        const OP_NOT: u8 = 2;

        if !self
            .nodes
            .iter()
            .any(|node| !matches!(node, Node::And | Node::Or | Node::Not | Node::End))
        {
            return Ok(mask);
        }

        let mut state = State {
            op: OP_AND,
            bm: None,
        };
        let mut stack = Vec::new();
        let nodes = std::mem::take(&mut self.nodes);
        let mut nodes = nodes.into_iter().peekable();

        while let Some(node) = nodes.next() {
            let result = match node {
                Node::Probes { groups } => {
                    let mut merged: Option<RoaringBitmap> = None;
                    for group in &groups {
                        let bitmap = self.union(group);
                        if let Some(merged) = &mut merged {
                            merged.bitand_assign(bitmap);
                        } else {
                            merged = Some(bitmap);
                        }
                        if merged.as_ref().unwrap().is_empty() {
                            break;
                        }
                    }
                    Some(merged.unwrap_or_default())
                }
                Node::Phrase { field, words } => Some(self.phrase(field, &words)?),
                Node::Prefix {
                    field,
                    prefix,
                    last_use,
                } => Some(if last_use {
                    self.prefixes.remove(&(field, prefix)).unwrap_or_default()
                } else {
                    self.prefixes
                        .get(&(field, prefix))
                        .cloned()
                        .unwrap_or_default()
                }),
                Node::DocumentSet(set) => Some(set),
                Node::Empty => Some(RoaringBitmap::new()),
                Node::And => {
                    stack.push(state);
                    state = State {
                        op: OP_AND,
                        bm: None,
                    };
                    continue;
                }
                Node::Or => {
                    stack.push(state);
                    state = State {
                        op: OP_OR,
                        bm: None,
                    };
                    continue;
                }
                Node::Not => {
                    stack.push(state);
                    state = State {
                        op: OP_NOT,
                        bm: None,
                    };
                    continue;
                }
                Node::End => {
                    if let Some(prev_state) = stack.pop() {
                        let bm = state.bm;
                        state = prev_state;
                        bm
                    } else {
                        break;
                    }
                }
            };

            if let Some(dest) = &mut state.bm {
                match state.op {
                    OP_AND => {
                        if let Some(result) = result {
                            dest.bitand_assign(result);
                        } else {
                            dest.clear();
                        }
                    }
                    OP_OR => {
                        if let Some(result) = result {
                            dest.bitor_assign(result);
                        }
                    }
                    OP_NOT => {
                        if let Some(mut result) = result {
                            result.bitxor_assign(&mask);
                            dest.bitand_assign(result);
                        }
                    }
                    _ => unreachable!(),
                }
            } else if let Some(mut result) = result {
                if state.op == OP_NOT {
                    result.bitxor_assign(&mask);
                }
                state.bm = Some(result);
            } else if state.op == OP_NOT {
                state.bm = Some(mask.clone());
            } else {
                state.bm = Some(RoaringBitmap::new());
            }

            if state.op == OP_AND && state.bm.as_ref().unwrap().is_empty() {
                let mut depth = 0u32;
                while let Some(node) = nodes.peek() {
                    match node {
                        Node::And | Node::Or | Node::Not => depth += 1,
                        Node::End if depth == 0 => break,
                        Node::End => depth -= 1,
                        _ => {}
                    }
                    nodes.next();
                }
            }
        }

        let mut results = state.bm.unwrap_or_default();
        results.bitand_assign(&mask);
        Ok(results)
    }
}

impl Store {
    pub(crate) async fn query_account(&self, query: SearchQuery) -> trc::Result<Vec<u32>> {
        let (account_id, mut plan) = build_plan(query.filters)?;
        plan.fetch(self, query.index, account_id).await?;
        let results = plan.evaluate(query.mask)?;

        match results.len().cmp(&1) {
            Ordering::Equal => Ok(vec![results.min().unwrap()]),
            Ordering::Less => Ok(vec![]),
            Ordering::Greater => {
                if !query.comparators.is_empty() {
                    Ok(QueryResults::new(results, query.comparators).into_sorted())
                } else {
                    Ok(results.iter().collect())
                }
            }
        }
    }
}
