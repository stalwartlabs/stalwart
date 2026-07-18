/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, U64_LEN,
    search::{
        KeyValueMatch, SearchField, SearchFilter, SearchQuery, TextMatch,
        codec::{self, GLOBAL_META_WATERMARK, Probe, TYPE_MASK, WalEvent},
        tokenize,
    },
    write::{SearchIndex, SearchIndexClass},
};
use ahash::{AHashMap, AHashSet};
use nlp::language::Language;
use roaring::RoaringTreemap;
use std::cmp::Ordering;
use std::ops::{BitAndAssign, BitOrAssign};
use utils::cheeky_hash::CheekyHash;

enum GlobalNode {
    Probes {
        groups: Vec<Vec<Probe>>,
    },
    Prefix {
        field: u8,
        prefix: Box<[u8]>,
        last_use: bool,
    },
    Empty,
    And,
    Or,
    End,
}

struct GlobalPlan {
    nodes: Vec<GlobalNode>,
    terms: AHashMap<Probe, RoaringTreemap>,
    prefixes: AHashMap<(u8, Box<[u8]>), RoaringTreemap>,
    from_id: u64,
    until_id: u64,
}

impl GlobalPlan {
    fn probe(&mut self, field: u8, term: CheekyHash) -> Probe {
        let probe = (field, term);
        self.terms.entry(probe).or_default();
        probe
    }

    fn add_text(&mut self, field: u8, op: TextMatch, value: &str, language: Language) {
        match op {
            TextMatch::Exact | TextMatch::Standard => {
                let groups = tokenize::tokenize_query(value, language)
                    .into_iter()
                    .map(|token| vec![self.probe(field, CheekyHash::new(token.word.as_bytes()))])
                    .collect::<Vec<_>>();
                if groups.is_empty() {
                    self.nodes.push(GlobalNode::Empty);
                } else {
                    self.nodes.push(GlobalNode::Probes { groups });
                }
            }
            TextMatch::Prefix => {
                let mut tokens = tokenize::tokenize_query(value, language);
                let Some(last) = tokens.pop() else {
                    self.nodes.push(GlobalNode::Empty);
                    return;
                };
                let prefix = last.word.into_owned().into_bytes().into_boxed_slice();
                if prefix.len() > CheekyHash::HASH_SIZE {
                    self.nodes.push(GlobalNode::Empty);
                    return;
                }
                self.prefixes.entry((field, prefix.clone())).or_default();
                if tokens.is_empty() {
                    self.nodes.push(GlobalNode::Prefix {
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
                    self.nodes.push(GlobalNode::And);
                    self.nodes.push(GlobalNode::Probes { groups });
                    self.nodes.push(GlobalNode::Prefix {
                        field,
                        prefix,
                        last_use: false,
                    });
                    self.nodes.push(GlobalNode::End);
                }
            }
        }
    }

    fn set_empty_window(&mut self) {
        self.from_id = 1;
        self.until_id = 0;
    }
}

fn build_global_plan(filters: Vec<SearchFilter>) -> trc::Result<GlobalPlan> {
    let mut plan = GlobalPlan {
        nodes: Vec::new(),
        terms: AHashMap::new(),
        prefixes: AHashMap::new(),
        from_id: 0,
        until_id: u64::MAX,
    };
    let mut conjunctive = Vec::new();

    for filter in filters {
        match filter {
            SearchFilter::Integer {
                field: SearchField::Id,
                op,
                value,
            } => {
                if conjunctive.contains(&false) {
                    return Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details("Id filters are only supported as conjunctions"));
                }
                match op {
                    Ordering::Greater => match value.checked_add(1) {
                        Some(from_id) => plan.from_id = plan.from_id.max(from_id),
                        None => plan.set_empty_window(),
                    },
                    Ordering::Less => match value.checked_sub(1) {
                        Some(until_id) => plan.until_id = plan.until_id.min(until_id),
                        None => plan.set_empty_window(),
                    },
                    Ordering::Equal => {
                        plan.from_id = plan.from_id.max(value);
                        plan.until_id = plan.until_id.min(value);
                    }
                }
            }
            SearchFilter::Integer { field, op, value } => {
                if op != Ordering::Equal {
                    return Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details("Integer range filters are not supported"));
                }
                let probe = plan.probe(field.u8_id(), tokenize::integer_term(value));
                plan.nodes.push(GlobalNode::Probes {
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
                plan.nodes.push(GlobalNode::Probes { groups });
            }
            SearchFilter::And => {
                conjunctive.push(true);
                plan.nodes.push(GlobalNode::And);
            }
            SearchFilter::Or => {
                conjunctive.push(false);
                plan.nodes.push(GlobalNode::Or);
            }
            SearchFilter::End => {
                conjunctive.pop();
                plan.nodes.push(GlobalNode::End);
            }
            filter @ (SearchFilter::DocumentSet(_) | SearchFilter::Not) => {
                return Err(trc::StoreEvent::NotSupported
                    .into_err()
                    .details(format!("Unsupported global query filter {filter:?}")));
            }
        }
    }

    let mut seen = AHashSet::new();
    let mut last_uses = Vec::new();
    for (position, node) in plan.nodes.iter().enumerate().rev() {
        if let GlobalNode::Prefix { field, prefix, .. } = node
            && seen.insert((*field, prefix.as_ref()))
        {
            last_uses.push(position);
        }
    }
    for position in last_uses {
        if let GlobalNode::Prefix { last_use, .. } = &mut plan.nodes[position] {
            *last_use = true;
        }
    }

    Ok(plan)
}

impl GlobalPlan {
    async fn fetch(&mut self, store: &Store, index: SearchIndex) -> trc::Result<u64> {
        let mut bounds = Vec::with_capacity(self.terms.len() + self.prefixes.len() + 2);
        bounds.push(codec::global_wal_range(index));
        bounds.push(codec::global_meta_range(index, GLOBAL_META_WATERMARK));
        'prefix: for (field, prefix) in self.prefixes.keys() {
            for (other_field, other_prefix) in self.prefixes.keys() {
                if other_field == field
                    && other_prefix.len() < prefix.len()
                    && prefix.starts_with(other_prefix)
                {
                    continue 'prefix;
                }
            }
            bounds.push(codec::global_term_prefix_range(index, *field, prefix));
        }
        'probe: for (field, term) in self.terms.keys() {
            if term.len() <= CheekyHash::HASH_SIZE {
                for (prefix_field, prefix) in self.prefixes.keys() {
                    if prefix_field == field && term.as_key().starts_with(prefix) {
                        continue 'probe;
                    }
                }
            }
            bounds.push(codec::global_term_range(index, *field, term, self.until_id));
        }
        let ranges = bounds
            .into_iter()
            .map(|(begin, end)| IterateParams::new(codec::any_key(begin), codec::any_key(end)))
            .collect::<Vec<_>>();

        let mut watermark = 0u64;
        let mut corrupted = None;

        store
            .iterate_many(ranges, |key, value| {
                let mut valid = Some(());
                match key.first().copied().unwrap_or_default() & TYPE_MASK {
                    SearchIndexClass::TYPE_GLOBAL_WAL => {
                        valid = codec::walk_wal::<u64>(value, |event| {
                            if let WalEvent::Add {
                                document_id,
                                field,
                                term,
                                ..
                            } = event
                            {
                                if let Some(docs) = self.terms.get_mut(&(field, term)) {
                                    docs.insert(document_id);
                                }
                                if term.len() <= CheekyHash::HASH_SIZE {
                                    for ((prefix_field, prefix), docs) in self.prefixes.iter_mut() {
                                        if *prefix_field == field
                                            && term.as_key().starts_with(prefix.as_ref())
                                        {
                                            docs.insert(document_id);
                                        }
                                    }
                                }
                            }
                            true
                        });
                    }
                    SearchIndexClass::TYPE_GLOBAL_TERM => {
                        if let Some((field, term, first_document_id)) =
                            codec::parse_term_key::<u64>(key)
                        {
                            let mut postings = self.terms.get_mut(&(field, term));
                            let mut prefix_docs = if term.len() <= CheekyHash::HASH_SIZE {
                                self.prefixes
                                    .iter_mut()
                                    .filter(|((prefix_field, prefix), _)| {
                                        *prefix_field == field
                                            && term.as_key().starts_with(prefix.as_ref())
                                    })
                                    .map(|(_, docs)| docs)
                                    .collect::<Vec<_>>()
                            } else {
                                Vec::new()
                            };
                            if (postings.is_some() || !prefix_docs.is_empty())
                                && codec::walk_chunk::<u64>(
                                    first_document_id,
                                    value,
                                    |document_id, _| {
                                        if let Some(postings) = &mut postings {
                                            postings.insert(document_id);
                                        }
                                        for docs in prefix_docs.iter_mut() {
                                            docs.insert(document_id);
                                        }
                                        true
                                    },
                                )
                                .is_none()
                            {
                                valid = None;
                            }
                        }
                    }
                    SearchIndexClass::TYPE_GLOBAL_META => {
                        if let Some(value) =
                            value.get(..U64_LEN).and_then(|value| value.try_into().ok())
                        {
                            watermark = u64::from_be_bytes(value);
                        } else {
                            valid = None;
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

        Ok(watermark)
    }

    fn union(&self, probes: &[Probe]) -> RoaringTreemap {
        let mut result = RoaringTreemap::new();
        for probe in probes {
            if let Some(docs) = self.terms.get(probe) {
                result |= docs;
            }
        }
        result
    }

    fn evaluate(mut self) -> RoaringTreemap {
        struct State {
            op: u8,
            bm: Option<RoaringTreemap>,
        }
        const OP_AND: u8 = 0;
        const OP_OR: u8 = 1;

        let mut state = State {
            op: OP_AND,
            bm: None,
        };
        let mut stack = Vec::new();
        let nodes = std::mem::take(&mut self.nodes);
        let mut nodes = nodes.into_iter().peekable();

        while let Some(node) = nodes.next() {
            let result = match node {
                GlobalNode::Probes { groups } => {
                    let mut merged: Option<RoaringTreemap> = None;
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
                GlobalNode::Prefix {
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
                GlobalNode::Empty => Some(RoaringTreemap::new()),
                GlobalNode::And => {
                    stack.push(state);
                    state = State {
                        op: OP_AND,
                        bm: None,
                    };
                    continue;
                }
                GlobalNode::Or => {
                    stack.push(state);
                    state = State {
                        op: OP_OR,
                        bm: None,
                    };
                    continue;
                }
                GlobalNode::End => {
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
                    _ => unreachable!(),
                }
            } else if let Some(result) = result {
                state.bm = Some(result);
            } else {
                state.bm = Some(RoaringTreemap::new());
            }

            if state.op == OP_AND && state.bm.as_ref().unwrap().is_empty() {
                let mut depth = 0u32;
                while let Some(node) = nodes.peek() {
                    match node {
                        GlobalNode::And | GlobalNode::Or => depth += 1,
                        GlobalNode::End if depth == 0 => break,
                        GlobalNode::End => depth -= 1,
                        _ => {}
                    }
                    nodes.next();
                }
            }
        }

        state.bm.unwrap_or_default()
    }
}

impl Store {
    pub(crate) async fn query_global(&self, query: SearchQuery) -> trc::Result<RoaringTreemap> {
        let index = query.index;
        let mut plan = build_global_plan(query.filters)?;
        if plan.from_id > plan.until_id {
            return Ok(RoaringTreemap::new());
        }

        let mut results;
        let watermark;
        if plan
            .nodes
            .iter()
            .all(|node| matches!(node, GlobalNode::And | GlobalNode::Or | GlobalNode::End))
        {
            let mut ids = RoaringTreemap::new();
            let mut corrupted = None;
            let (begin, end) = codec::global_document_range(index, plan.from_id, plan.until_id);
            self.iterate(
                IterateParams::new(codec::any_key(begin), codec::any_key(end)).no_values(),
                |key, _| {
                    if let Some(document_id) = codec::parse_global_id_key(key) {
                        ids.insert(document_id);
                        Ok(true)
                    } else {
                        corrupted = Some(trc::Error::corrupted_key(key, None, trc::location!()));
                        Ok(false)
                    }
                },
            )
            .await?;
            if let Some(err) = corrupted {
                return Err(err);
            }
            watermark = self.global_meta(index, GLOBAL_META_WATERMARK).await?;
            results = ids;
        } else {
            watermark = plan.fetch(self, index).await?;
            let (from_id, until_id) = (plan.from_id, plan.until_id);
            results = plan.evaluate();
            if from_id > 0 {
                results.remove_range(..from_id);
            }
            if until_id < u64::MAX {
                results.remove_range(until_id + 1..);
            }
        }
        if watermark > 0 {
            results.remove_range(..watermark);
        }
        Ok(results)
    }
}
