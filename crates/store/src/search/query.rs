/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, Store, U16_LEN, U32_LEN,
    search::{
        ACCOUNT_BLOCK_SHIFT, GLOBAL_BUCKET_SHIFT, KeyValueMatch, SearchField, SearchFilter,
        SearchQuery, TextMatch, codec,
        term::matches_phrase,
        tokenize::{integer_term, key_value_term, stem_term, tokenize},
    },
    write::{
        SearchIndex,
        lazybitmap::{LazyBitmap, LazyTreemap},
    },
};
use ahash::{AHashMap, AHashSet};
use nlp::language::Language;
use roaring::{RoaringBitmap, RoaringTreemap};
use std::borrow::Cow;
use std::cmp::Ordering;
use utils::cheeky_hash::CheekyHash;

const DOCUMENT_FETCH_CHUNK: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    And,
    Or,
    Not,
}

impl Store {
    pub async fn query_account(&self, query: SearchQuery) -> trc::Result<RoaringBitmap> {
        let mut account_id = None;
        for filter in &query.filters {
            if let SearchFilter::Integer {
                field: SearchField::AccountId,
                op: Ordering::Equal,
                value,
            } = filter
            {
                account_id = Some(*value as u32);
            }
        }
        let Some(account_id) = account_id else {
            return Err(trc::StoreEvent::UnexpectedError
                .into_err()
                .details("Account ID filter is required for account queries"));
        };

        let mut ctx = AccountContext {
            store: self,
            index: query.index,
            account_id,
            terms: AHashMap::new(),
            prefixes: AHashMap::new(),
        };
        let mut filters = query.filters;
        let mut groups: Vec<Group> = Vec::new();
        let mut skip_depth: Option<usize> = None;
        let mut has_filters = false;

        for filter in filters.iter_mut() {
            match filter {
                SearchFilter::And => groups.push(Group::And),
                SearchFilter::Or => groups.push(Group::Or),
                SearchFilter::Not => groups.push(Group::Not),
                SearchFilter::End => {
                    groups.pop();
                    if skip_depth.is_some_and(|depth| groups.len() < depth) {
                        skip_depth = None;
                    }
                }
                SearchFilter::Integer {
                    field: SearchField::AccountId,
                    op: Ordering::Equal,
                    ..
                } => {}
                SearchFilter::DocumentSet(set) => {
                    has_filters = true;
                    if skip_depth.is_none()
                        && set.is_empty()
                        && !matches!(groups.last(), Some(Group::Or | Group::Not))
                    {
                        skip_depth = Some(groups.len());
                    }
                }
                filter @ (SearchFilter::Text { .. }
                | SearchFilter::Integer { .. }
                | SearchFilter::KeyValue { .. }) => {
                    has_filters = true;
                    let result = if skip_depth.is_none() {
                        ctx.resolve(std::mem::take(filter)).await?
                    } else {
                        RoaringBitmap::new()
                    };
                    if skip_depth.is_none()
                        && result.is_empty()
                        && !matches!(groups.last(), Some(Group::Or | Group::Not))
                    {
                        skip_depth = Some(groups.len());
                    }
                    *filter = SearchFilter::DocumentSet(result);
                }
            }
        }

        if has_filters {
            Ok(SearchQuery::new(query.index)
                .with_filters(filters)
                .with_mask(query.mask)
                .filter()
                .into_bitmap())
        } else {
            Ok(query.mask)
        }
    }

    pub async fn query_global(&self, query: SearchQuery) -> trc::Result<RoaringTreemap> {
        let mut from_id = 0u64;
        let mut until_id = u64::MAX;
        let mut has_filters = false;
        let mut groups: Vec<Group> = Vec::new();

        for filter in &query.filters {
            match filter {
                SearchFilter::And => groups.push(Group::And),
                SearchFilter::Or => groups.push(Group::Or),
                SearchFilter::End => {
                    groups.pop();
                }
                SearchFilter::Integer {
                    field: SearchField::Id,
                    op,
                    value,
                } => {
                    if groups.contains(&Group::Or) {
                        return Err(trc::StoreEvent::NotSupported
                            .into_err()
                            .details("Id filters are only supported as conjunctions"));
                    }
                    match op {
                        Ordering::Greater => match value.checked_add(1) {
                            Some(value) => from_id = from_id.max(value),
                            None => {
                                from_id = 1;
                                until_id = 0;
                            }
                        },
                        Ordering::Less => match value.checked_sub(1) {
                            Some(value) => until_id = until_id.min(value),
                            None => {
                                from_id = 1;
                                until_id = 0;
                            }
                        },
                        Ordering::Equal => {
                            from_id = from_id.max(*value);
                            until_id = until_id.min(*value);
                        }
                    }
                }
                SearchFilter::Text { .. }
                | SearchFilter::KeyValue { .. }
                | SearchFilter::Integer { .. } => {
                    has_filters = true;
                }
                filter @ (SearchFilter::Not | SearchFilter::DocumentSet(_)) => {
                    return Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details(format!("Unsupported global query filter {filter:?}")));
                }
            }
        }

        if from_id > until_id {
            return Ok(RoaringTreemap::new());
        }

        let mut ctx = GlobalContext {
            store: self,
            index: query.index,
            from_block: (from_id >> GLOBAL_BUCKET_SHIFT) as u16,
            until_block: (until_id >> GLOBAL_BUCKET_SHIFT) as u16,
            terms: AHashMap::new(),
            prefixes: AHashMap::new(),
        };

        let mut results = if has_filters {
            struct State {
                op: Group,
                acc: Option<RoaringTreemap>,
            }
            let mut state = State {
                op: Group::And,
                acc: None,
            };
            let mut stack = Vec::new();
            let mut skip_depth: Option<usize> = None;

            for filter in query.filters {
                let result = match filter {
                    SearchFilter::And => {
                        stack.push(state);
                        state = State {
                            op: Group::And,
                            acc: None,
                        };
                        continue;
                    }
                    SearchFilter::Or => {
                        stack.push(state);
                        state = State {
                            op: Group::Or,
                            acc: None,
                        };
                        continue;
                    }
                    SearchFilter::End => {
                        if let Some(prev_state) = stack.pop() {
                            let result = state.acc.unwrap_or_default();
                            state = prev_state;
                            if skip_depth.is_some_and(|depth| stack.len() < depth) {
                                skip_depth = None;
                            }
                            result
                        } else {
                            break;
                        }
                    }
                    SearchFilter::Integer {
                        field: SearchField::Id,
                        ..
                    } => continue,
                    filter @ (SearchFilter::Text { .. }
                    | SearchFilter::Integer { .. }
                    | SearchFilter::KeyValue { .. }) => {
                        if skip_depth.is_none() {
                            ctx.resolve(filter).await?
                        } else {
                            RoaringTreemap::new()
                        }
                    }
                    SearchFilter::Not | SearchFilter::DocumentSet(_) => unreachable!(),
                };

                match state.op {
                    Group::And => {
                        if let Some(acc) = &mut state.acc {
                            *acc &= result;
                        } else {
                            state.acc = Some(result);
                        }
                        if skip_depth.is_none() && state.acc.as_ref().unwrap().is_empty() {
                            skip_depth = Some(stack.len());
                        }
                    }
                    Group::Or => {
                        if let Some(acc) = &mut state.acc {
                            *acc |= result;
                        } else {
                            state.acc = Some(result);
                        }
                    }
                    Group::Not => unreachable!(),
                }
            }

            while let Some(mut prev_state) = stack.pop() {
                let result = state.acc.unwrap_or_default();
                match prev_state.op {
                    Group::And => {
                        if let Some(acc) = &mut prev_state.acc {
                            *acc &= result;
                        } else {
                            prev_state.acc = Some(result);
                        }
                    }
                    Group::Or => {
                        if let Some(acc) = &mut prev_state.acc {
                            *acc |= result;
                        } else {
                            prev_state.acc = Some(result);
                        }
                    }
                    Group::Not => unreachable!(),
                }
                state = prev_state;
            }

            state.acc.unwrap_or_default()
        } else {
            ctx.document_ids().await?
        };

        if from_id > 0 {
            results.remove_range(..from_id);
        }
        if until_id < u64::MAX {
            results.remove_range(until_id + 1..);
        }

        Ok(results)
    }
}

struct AccountContext<'x> {
    store: &'x Store,
    index: SearchIndex,
    account_id: u32,
    terms: AHashMap<(u8, CheekyHash), RoaringBitmap>,
    prefixes: AHashMap<(u8, CheekyHash), RoaringBitmap>,
}

fn single_term_prefix(value: &str) -> Cow<'_, str> {
    if value.chars().any(char::is_uppercase) {
        Cow::Owned(value.to_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

impl AccountContext<'_> {
    async fn resolve(&mut self, filter: SearchFilter) -> trc::Result<RoaringBitmap> {
        match filter {
            SearchFilter::Text {
                field,
                op,
                value,
                language,
            } => {
                let field = field.u8_id();
                match op {
                    TextMatch::Standard => {
                        let stemmed = !matches!(language, Language::None | Language::Unknown);
                        let mut groups: Vec<[Option<CheekyHash>; 4]> = Vec::new();
                        let mut buf = String::new();
                        tokenize(&value, language, |token| {
                            let mut group = [
                                Some(CheekyHash::new(token.word.as_bytes())),
                                None,
                                None,
                                None,
                            ];
                            if stemmed {
                                group[1] = Some(stem_term(&token.word, &mut buf));
                                if let Some(stem) = &token.stem {
                                    group[2] = Some(CheekyHash::new(stem.as_bytes()));
                                    group[3] = Some(stem_term(stem, &mut buf));
                                }
                            }
                            groups.push(group);
                            true
                        });
                        if groups.is_empty() {
                            return Ok(RoaringBitmap::new());
                        }
                        self.fetch(
                            groups.iter().flatten().flatten().map(|hash| (field, *hash)),
                            None,
                        )
                        .await?;

                        let mut result: Option<RoaringBitmap> = None;
                        for group in &groups {
                            let mut matches = RoaringBitmap::new();
                            for hash in group.iter().flatten() {
                                matches |= self.term(&(field, *hash));
                            }
                            if let Some(result) = &mut result {
                                *result &= matches;
                            } else {
                                result = Some(matches);
                            }
                            if result.as_ref().unwrap().is_empty() {
                                return Ok(RoaringBitmap::new());
                            }
                        }
                        Ok(result.unwrap_or_default())
                    }
                    TextMatch::Exact => {
                        let mut words = Vec::new();
                        tokenize(&value, language, |token| {
                            words.push(CheekyHash::new(token.word.as_bytes()));
                            true
                        });
                        match words.as_slice() {
                            [] => Ok(RoaringBitmap::new()),
                            [word] => {
                                let probe = (field, *word);
                                self.fetch(std::iter::once(probe), None).await?;
                                Ok(self.term(&probe).clone())
                            }
                            _ => self.phrase(field, words).await,
                        }
                    }
                    TextMatch::Prefix => {
                        let prefix = single_term_prefix(&value);
                        let prefix = prefix.as_bytes();
                        if prefix.is_empty() || prefix.len() > CheekyHash::HASH_SIZE {
                            return Ok(RoaringBitmap::new());
                        }
                        self.fetch(std::iter::empty(), Some((field, prefix)))
                            .await?;
                        Ok(self.prefix(field, prefix).clone())
                    }
                }
            }
            SearchFilter::Integer { field, op, value } => {
                if op == Ordering::Equal {
                    let probe = (field.u8_id(), integer_term(value));
                    self.fetch(std::iter::once(probe), None).await?;
                    Ok(self.term(&probe).clone())
                } else {
                    Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details("Integer range filters are not supported"))
                }
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
                let mut probes = Vec::new();
                let mut buf = String::new();
                tokenize(value, Language::None, |token| {
                    probes.push((field, key_value_term(&key, &token.word, &mut buf)));
                    true
                });
                if probes.is_empty() {
                    let probe = (field, CheekyHash::new(key.as_bytes()));
                    self.fetch(std::iter::once(probe), None).await?;
                    return Ok(self.term(&probe).clone());
                }
                self.fetch(probes.iter().copied(), None).await?;
                Ok(self.intersect(probes.iter().copied()))
            }
            _ => unreachable!(),
        }
    }

    fn intersect(&self, mut probes: impl Iterator<Item = (u8, CheekyHash)>) -> RoaringBitmap {
        let Some(first) = probes.next() else {
            return RoaringBitmap::new();
        };
        let first = self.term(&first);
        if first.is_empty() {
            return RoaringBitmap::new();
        }
        let mut result: Option<RoaringBitmap> = None;
        for probe in probes {
            let matches = self.term(&probe);
            if let Some(result) = &mut result {
                *result &= matches;
            } else {
                result = Some(first & matches);
            }
            if result.as_ref().unwrap().is_empty() {
                return RoaringBitmap::new();
            }
        }
        result.unwrap_or_else(|| first.clone())
    }

    async fn phrase(&mut self, field: u8, words: Vec<CheekyHash>) -> trc::Result<RoaringBitmap> {
        self.fetch(words.iter().map(|word| (field, *word)), None)
            .await?;

        let candidates = self.intersect(words.iter().map(|word| (field, *word)));
        if candidates.is_empty() {
            return Ok(RoaringBitmap::new());
        }

        let mut result = RoaringBitmap::new();
        let mut ordinals = Vec::new();
        let mut failure = Vec::new();
        let mut scratch = Vec::new();
        let store = self.store;
        let mut candidate_iter = candidates.iter().peekable();

        while candidate_iter.peek().is_some() {
            let ranges = candidate_iter
                .by_ref()
                .take(DOCUMENT_FETCH_CHUNK)
                .map(|document_id| {
                    let begin =
                        codec::account_document_key(self.index, self.account_id, document_id);
                    let mut end = begin.clone();
                    end.push(u8::MAX);
                    IterateParams::new(codec::document_key(begin), codec::document_key(end))
                })
                .collect::<Vec<_>>();
            let mut corrupted = None;

            store
                .iterate_many(ranges, |key, value| {
                    let matched = key
                        .get(key.len().wrapping_sub(U32_LEN)..)
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u32::from_be_bytes)
                        .zip(matches_phrase(
                            value,
                            &mut scratch,
                            field,
                            &words,
                            &mut ordinals,
                            &mut failure,
                        ));
                    if let Some((document_id, matched)) = matched {
                        if matched {
                            result.insert(document_id);
                        }
                        Ok(true)
                    } else {
                        corrupted = Some(trc::Error::corrupted_key(
                            key,
                            Some(value),
                            trc::location!(),
                        ));
                        Ok(false)
                    }
                })
                .await?;

            if let Some(err) = corrupted {
                return Err(err);
            }
        }

        Ok(result)
    }

    async fn fetch(
        &mut self,
        probes: impl Iterator<Item = (u8, CheekyHash)>,
        prefix: Option<(u8, &[u8])>,
    ) -> trc::Result<()> {
        let mut ranges = Vec::new();
        let mut fetch_probes: AHashSet<(u8, CheekyHash)> = AHashSet::new();
        for probe in probes {
            if !self.terms.contains_key(&probe) && fetch_probes.insert(probe) {
                let (begin, end) =
                    codec::account_term_range(self.index, self.account_id, probe.0, &probe.1);
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
                self.terms.insert(probe, RoaringBitmap::new());
            }
        }
        let mut fetch_prefix = None;
        if let Some((field, prefix)) = prefix {
            let cache_key = (field, CheekyHash::new(prefix));
            if !self.prefixes.contains_key(&cache_key) {
                let (begin, end) =
                    codec::account_term_prefix_range(self.index, self.account_id, field, prefix);
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
                fetch_prefix = Some((field, prefix, cache_key));
            }
        }
        if ranges.is_empty() {
            return Ok(());
        }

        let mut prefix_matches = RoaringBitmap::new();
        let terms = &mut self.terms;
        let mut corrupted = None;

        self.store
            .iterate_many(ranges, |key, value| {
                let Some((field, hash, parsed)) = key
                    .get(codec::ACCOUNT_TERM_BASE_LEN - 1)
                    .copied()
                    .zip(codec::parse_prefix_key(
                        key,
                        codec::ACCOUNT_TERM_BASE_LEN,
                        U16_LEN,
                    ))
                    .and_then(|(field, parsed)| {
                        CheekyHash::from_key_bytes(parsed.term, parsed.len)
                            .map(|hash| (field, hash, parsed))
                    })
                else {
                    corrupted = Some(trc::Error::corrupted_key(
                        key,
                        Some(value),
                        trc::location!(),
                    ));
                    return Ok(false);
                };

                let probe = (field, hash);
                let is_probe = fetch_probes.contains(&probe);
                let has_prefix = fetch_prefix.is_some_and(|(prefix_field, prefix, _)| {
                    prefix_field == field
                        && parsed.len as usize <= CheekyHash::HASH_SIZE
                        && parsed.term.last() != Some(&b'*')
                        && parsed.term.starts_with(prefix)
                });

                if is_probe || has_prefix {
                    match LazyBitmap::deserialize_delta(
                        value,
                        (parsed.block_id as u32) << ACCOUNT_BLOCK_SHIFT,
                    ) {
                        Ok(bitmap) => {
                            if has_prefix {
                                prefix_matches |= &bitmap.0;
                            }
                            if is_probe {
                                *terms.get_mut(&probe).unwrap() |= bitmap.0;
                            }
                        }
                        Err(err) => {
                            corrupted = Some(err);
                            return Ok(false);
                        }
                    }
                }

                Ok(true)
            })
            .await?;

        if let Some(err) = corrupted {
            return Err(err);
        }

        if let Some((_, _, cache_key)) = fetch_prefix {
            self.prefixes.insert(cache_key, prefix_matches);
        }

        Ok(())
    }

    fn term(&self, probe: &(u8, CheekyHash)) -> &RoaringBitmap {
        &self.terms[probe]
    }

    fn prefix(&self, field: u8, prefix: &[u8]) -> &RoaringBitmap {
        &self.prefixes[&(field, CheekyHash::new(prefix))]
    }
}

struct GlobalContext<'x> {
    store: &'x Store,
    index: SearchIndex,
    from_block: u16,
    until_block: u16,
    terms: AHashMap<(u8, CheekyHash), RoaringTreemap>,
    prefixes: AHashMap<(u8, CheekyHash), RoaringTreemap>,
}

impl GlobalContext<'_> {
    async fn resolve(&mut self, filter: SearchFilter) -> trc::Result<RoaringTreemap> {
        match filter {
            SearchFilter::Text {
                field,
                op,
                value,
                language,
            } => {
                let field = field.u8_id();
                match op {
                    TextMatch::Exact | TextMatch::Standard => {
                        let mut probes = Vec::new();
                        tokenize(&value, language, |token| {
                            probes.push((field, CheekyHash::new(token.word.as_bytes())));
                            true
                        });
                        if probes.is_empty() {
                            return Ok(RoaringTreemap::new());
                        }
                        self.fetch(probes.iter().copied(), None).await?;
                        Ok(self.intersect(probes.iter().copied()))
                    }
                    TextMatch::Prefix => {
                        let prefix = single_term_prefix(&value);
                        let prefix = prefix.as_bytes();
                        if prefix.is_empty() || prefix.len() > CheekyHash::HASH_SIZE {
                            return Ok(RoaringTreemap::new());
                        }
                        self.fetch(std::iter::empty(), Some((field, prefix)))
                            .await?;
                        Ok(self.prefix(field, prefix).clone())
                    }
                }
            }
            SearchFilter::Integer { field, op, value } => {
                if op == Ordering::Equal {
                    let probe = (field.u8_id(), integer_term(value));
                    self.fetch(std::iter::once(probe), None).await?;
                    Ok(self.term(&probe).clone())
                } else {
                    Err(trc::StoreEvent::NotSupported
                        .into_err()
                        .details("Integer range filters are not supported"))
                }
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
                let mut probes = Vec::new();
                let mut buf = String::new();
                tokenize(value, Language::None, |token| {
                    probes.push((field, key_value_term(&key, &token.word, &mut buf)));
                    true
                });
                if probes.is_empty() {
                    let probe = (field, CheekyHash::new(key.as_bytes()));
                    self.fetch(std::iter::once(probe), None).await?;
                    return Ok(self.term(&probe).clone());
                }
                self.fetch(probes.iter().copied(), None).await?;
                Ok(self.intersect(probes.iter().copied()))
            }
            _ => unreachable!(),
        }
    }

    fn intersect(&self, mut probes: impl Iterator<Item = (u8, CheekyHash)>) -> RoaringTreemap {
        let Some(first) = probes.next() else {
            return RoaringTreemap::new();
        };
        let first = self.term(&first);
        if first.is_empty() {
            return RoaringTreemap::new();
        }
        let mut result: Option<RoaringTreemap> = None;
        for probe in probes {
            let matches = self.term(&probe);
            if let Some(result) = &mut result {
                *result &= matches;
            } else {
                result = Some(first & matches);
            }
            if result.as_ref().unwrap().is_empty() {
                return RoaringTreemap::new();
            }
        }
        result.unwrap_or_else(|| first.clone())
    }

    async fn fetch(
        &mut self,
        probes: impl Iterator<Item = (u8, CheekyHash)>,
        prefix: Option<(u8, &[u8])>,
    ) -> trc::Result<()> {
        let mut ranges = Vec::new();
        let mut fetch_probes: AHashSet<(u8, CheekyHash)> = AHashSet::new();
        for probe in probes {
            if !self.terms.contains_key(&probe) && fetch_probes.insert(probe) {
                let (begin, end) = codec::global_term_block_range(
                    self.index,
                    probe.0,
                    &probe.1,
                    self.from_block,
                    self.until_block,
                );
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
                self.terms.insert(probe, RoaringTreemap::new());
            }
        }
        let mut fetch_prefix = None;
        if let Some((field, prefix)) = prefix {
            let cache_key = (field, CheekyHash::new(prefix));
            if !self.prefixes.contains_key(&cache_key) {
                let (begin, end) = codec::global_term_prefix_range(self.index, field, prefix);
                ranges.push(IterateParams::new(
                    codec::term_key(begin),
                    codec::term_key(end),
                ));
                fetch_prefix = Some((field, prefix, cache_key));
            }
        }
        if ranges.is_empty() {
            return Ok(());
        }

        let mut prefix_matches = RoaringTreemap::new();
        let terms = &mut self.terms;
        let mut corrupted = None;

        self.store
            .iterate_many(ranges, |key, value| {
                let Some((field, hash, parsed)) = key
                    .get(codec::GLOBAL_TERM_BASE_LEN - 1)
                    .copied()
                    .zip(codec::parse_prefix_key(
                        key,
                        codec::GLOBAL_TERM_BASE_LEN,
                        U16_LEN,
                    ))
                    .and_then(|(field, parsed)| {
                        CheekyHash::from_key_bytes(parsed.term, parsed.len)
                            .map(|hash| (field, hash, parsed))
                    })
                else {
                    corrupted = Some(trc::Error::corrupted_key(
                        key,
                        Some(value),
                        trc::location!(),
                    ));
                    return Ok(false);
                };

                let probe = (field, hash);
                let is_probe = fetch_probes.contains(&probe);
                let has_prefix = fetch_prefix.is_some_and(|(prefix_field, prefix, _)| {
                    prefix_field == field
                        && parsed.len as usize <= CheekyHash::HASH_SIZE
                        && parsed.term.last() != Some(&b'*')
                        && parsed.term.starts_with(prefix)
                });

                if is_probe || has_prefix {
                    match LazyTreemap::deserialize_delta(
                        value,
                        (parsed.block_id as u64) << GLOBAL_BUCKET_SHIFT,
                    ) {
                        Ok(treemap) => {
                            if has_prefix {
                                prefix_matches |= &treemap.0;
                            }
                            if is_probe {
                                *terms.get_mut(&probe).unwrap() |= treemap.0;
                            }
                        }
                        Err(err) => {
                            corrupted = Some(err);
                            return Ok(false);
                        }
                    }
                }

                Ok(true)
            })
            .await?;

        if let Some(err) = corrupted {
            return Err(err);
        }

        if let Some((_, _, cache_key)) = fetch_prefix {
            self.prefixes.insert(cache_key, prefix_matches);
        }

        Ok(())
    }

    async fn document_ids(&self) -> trc::Result<RoaringTreemap> {
        let (begin, end) =
            codec::global_document_id_range(self.index, self.from_block, self.until_block);
        let mut results = RoaringTreemap::new();
        let mut corrupted = None;

        self.store
            .iterate(
                IterateParams::new(codec::term_key(begin), codec::term_key(end)),
                |key, value| {
                    let decoded = codec::parse_block_id(key).and_then(|block_id| {
                        LazyTreemap::deserialize_delta(
                            value,
                            (block_id as u64) << GLOBAL_BUCKET_SHIFT,
                        )
                        .ok()
                    });
                    if let Some(treemap) = decoded {
                        results |= treemap.0;
                        Ok(true)
                    } else {
                        corrupted = Some(trc::Error::corrupted_key(
                            key,
                            Some(value),
                            trc::location!(),
                        ));
                        Ok(false)
                    }
                },
            )
            .await?;

        if let Some(err) = corrupted {
            return Err(err);
        }

        Ok(results)
    }

    fn term(&self, probe: &(u8, CheekyHash)) -> &RoaringTreemap {
        &self.terms[probe]
    }

    fn prefix(&self, field: u8, prefix: &[u8]) -> &RoaringTreemap {
        &self.prefixes[&(field, CheekyHash::new(prefix))]
    }
}
