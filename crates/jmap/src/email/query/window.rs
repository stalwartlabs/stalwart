/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Candidates, Page, SPARSE_RESIDUAL_RATIO, WalkOrder};
use common::{MessageStoreCache, MessagesCache, Server, cache::email::MessageRef};
use email::{cache::email::MessageCacheAccess, message::query::RowFilter};
use store::{dispatch::search::MAX_FILTER_CANDIDATES, roaring::RoaringBitmap, search::SearchQuery};
use trc::AddContext;

const MIN_FIRST_WINDOW: usize = 32;
const MAX_FIRST_WINDOW: usize = 128;
const WINDOW_GROWTH: usize = 4;
const MAX_WINDOWS: u32 = 6;
const MAX_MISSED_WINDOWS: u32 = 2;
const PRIOR_HITS: f64 = 0.5;
const RESOLVED_ROW_COST: f64 = 0.35;
const NEEDED_ROWS_MARGIN: f64 = 1.25;

const _: () =
    assert!(MAX_FIRST_WINDOW * WINDOW_GROWTH.pow(MAX_WINDOWS - 3) < MAX_FILTER_CANDIDATES);

pub(super) struct WindowedWalk {
    pub order: WalkOrder,
    pub query: SearchQuery,
    pub resolve_rows: Option<f64>,
}

pub(super) enum TextSource<'x> {
    Store(&'x Server),
    #[cfg(all(test, stalwart_tests))]
    Fake(&'x super::tests::FakeText),
}

pub(super) struct TextWindow {
    query: SearchQuery,
    ids: Vec<u32>,
    window: usize,
    growth: usize,
    wanted: u64,
    candidates: u64,
    resolve_rows: f64,
    examined: u64,
    matched: u64,
    last_examined: u64,
    last_matched: u64,
    windows: u32,
    missed: u32,
    #[cfg(all(test, stalwart_tests))]
    resolve_after: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowStep {
    Next,
    Done,
    Resolve,
}

impl TextSource<'_> {
    async fn filter_candidates(
        &self,
        query: &SearchQuery,
        candidates: &[u32],
    ) -> trc::Result<RoaringBitmap> {
        match self {
            TextSource::Store(server) => server
                .search_store()
                .filter_candidates(query, candidates)
                .await
                .caused_by(trc::location!()),
            #[cfg(all(test, stalwart_tests))]
            TextSource::Fake(text) => Ok(text.filter_candidates(query, candidates)),
        }
    }

    async fn filter_account(&self, query: SearchQuery) -> trc::Result<RoaringBitmap> {
        match self {
            TextSource::Store(server) => server
                .search_store()
                .filter_account(query)
                .await
                .caused_by(trc::location!()),
            #[cfg(all(test, stalwart_tests))]
            TextSource::Fake(text) => Ok(text.filter_account(&query)),
        }
    }
}

impl TextWindow {
    pub fn new(
        query: SearchQuery,
        wanted: usize,
        candidates: usize,
        resolve_rows: Option<f64>,
    ) -> Self {
        let wanted = wanted.max(1);
        TextWindow {
            query,
            ids: Vec::new(),
            window: wanted
                .saturating_mul(2)
                .clamp(MIN_FIRST_WINDOW, MAX_FIRST_WINDOW),
            growth: WINDOW_GROWTH,
            wanted: wanted as u64,
            candidates: candidates as u64,
            resolve_rows: resolve_rows.unwrap_or(f64::INFINITY),
            examined: 0,
            matched: 0,
            last_examined: 0,
            last_matched: 0,
            windows: 0,
            missed: 0,
            #[cfg(all(test, stalwart_tests))]
            resolve_after: None,
        }
    }

    #[cfg(all(test, stalwart_tests))]
    pub fn reschedule(&mut self, first_window: usize, growth: usize, resolve_after: u32) {
        self.window = first_window.max(1);
        self.growth = growth.max(1);
        self.resolve_after = Some(resolve_after);
    }

    pub fn next_window(&self) -> usize {
        self.window.min(MAX_FILTER_CANDIDATES)
    }

    pub fn record(&mut self, examined: usize, matched: u64) {
        self.last_examined = examined as u64;
        self.last_matched = matched;
        self.examined += self.last_examined;
        self.matched += matched;
        self.windows += 1;
        self.missed = if matched == 0 { self.missed + 1 } else { 0 };
    }

    pub fn plan(&mut self, emitted: usize) -> WindowStep {
        if emitted as u64 >= self.wanted {
            return WindowStep::Done;
        }
        #[cfg(all(test, stalwart_tests))]
        if let Some(windows) = self.resolve_after {
            self.window = self.window.saturating_mul(self.growth);
            return if self.windows >= windows {
                WindowStep::Resolve
            } else {
                WindowStep::Next
            };
        }
        if self.windows > MAX_WINDOWS || self.missed >= MAX_MISSED_WINDOWS {
            return WindowStep::Resolve;
        }
        let rate = (self.last_matched as f64 + PRIOR_HITS) / self.last_examined.max(1) as f64;
        let left = self.candidates.saturating_sub(self.examined) as f64;
        let remaining = self.wanted.saturating_sub(emitted as u64).max(1) as f64;
        let window_rows = (remaining / rate).min(left);
        let resolve_rows =
            (RESOLVED_ROW_COST * (self.matched as f64 + rate * left)).min(self.resolve_rows);
        if window_rows > resolve_rows || window_rows > self.window_capacity() {
            return WindowStep::Resolve;
        }
        let grown = self.window.saturating_mul(self.growth);
        self.window = if self.last_matched > 0 {
            let needed = (window_rows * NEEDED_ROWS_MARGIN).ceil() as usize;
            grown.min(needed.max(MIN_FIRST_WINDOW))
        } else {
            grown
        };
        WindowStep::Next
    }

    fn window_capacity(&self) -> f64 {
        let mut window = self.window;
        let mut rows = 0usize;
        for _ in self.windows..=MAX_WINDOWS {
            window = window
                .saturating_mul(self.growth)
                .min(MAX_FILTER_CANDIDATES);
            rows = rows.saturating_add(window);
        }
        rows as f64
    }

    fn into_resolved(self, mask: RoaringBitmap) -> SearchQuery {
        self.query.with_mask(mask)
    }
}

impl Page {
    fn fill_window<'x>(
        &self,
        filter: &RowFilter,
        messages: &mut impl Iterator<Item = MessageRef<'x>>,
        text: &mut TextWindow,
        window: &mut Vec<MessageRef<'x>>,
    ) -> bool {
        window.clear();
        window.extend(
            messages
                .by_ref()
                .filter(|message| {
                    filter.matches(*message)
                        && self
                            .threads
                            .as_ref()
                            .is_none_or(|threads| !threads.contains(message.thread_id()))
                })
                .take(text.next_window()),
        );
        text.ids.clear();
        text.ids
            .extend(window.iter().map(|message| message.document_id()));
        !window.is_empty()
    }

    fn emit_window(
        &mut self,
        window: &[MessageRef<'_>],
        hits: &RoaringBitmap,
        text: &mut TextWindow,
    ) -> WindowStep {
        let requested = text.next_window();
        text.record(window.len(), hits.len());

        for message in window {
            if hits.contains(message.document_id()) && !self.emit(*message) {
                return WindowStep::Done;
            }
        }

        if window.len() < requested {
            WindowStep::Done
        } else {
            text.plan(self.total)
        }
    }

    pub(super) async fn walk_windowed(
        &mut self,
        source: TextSource<'_>,
        cache: &MessageStoreCache,
        filter: &mut RowFilter,
        candidates: &Candidates,
        order: WalkOrder,
        text: TextWindow,
    ) -> trc::Result<()> {
        let messages = &cache.emails;
        match (candidates, order) {
            (Candidates::All, WalkOrder::Ascending) => {
                self.fill_windowed(
                    &source,
                    cache,
                    filter,
                    candidates,
                    &mut messages.iter(),
                    order,
                    text,
                )
                .await
            }
            (Candidates::All, WalkOrder::Descending) => {
                self.fill_windowed(
                    &source,
                    cache,
                    filter,
                    candidates,
                    &mut messages.iter().rev(),
                    order,
                    text,
                )
                .await
            }
            (Candidates::Positions(positions), WalkOrder::Ascending) => {
                self.fill_windowed(
                    &source,
                    cache,
                    filter,
                    candidates,
                    &mut positions
                        .iter()
                        .filter_map(|position| messages.at(*position)),
                    order,
                    text,
                )
                .await
            }
            (Candidates::Positions(positions), WalkOrder::Descending) => {
                self.fill_windowed(
                    &source,
                    cache,
                    filter,
                    candidates,
                    &mut positions
                        .iter()
                        .rev()
                        .filter_map(|position| messages.at(*position)),
                    order,
                    text,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn fill_windowed<'x>(
        &mut self,
        source: &TextSource<'_>,
        cache: &'x MessageStoreCache,
        filter: &mut RowFilter,
        candidates: &Candidates,
        messages: &mut (impl Iterator<Item = MessageRef<'x>> + Send),
        order: WalkOrder,
        mut text: TextWindow,
    ) -> trc::Result<()> {
        let mut window = Vec::with_capacity(text.next_window());
        while self.fill_window(filter, messages, &mut text, &mut window) {
            let hits = source.filter_candidates(&text.query, &text.ids).await?;
            match self.emit_window(&window, &hits, &mut text) {
                WindowStep::Next => (),
                WindowStep::Done => return Ok(()),
                WindowStep::Resolve => {
                    let last = window.last().map(|message| message.position());
                    let resolved = source
                        .filter_account(text.into_resolved(cache.email_document_ids()))
                        .await?;
                    let matches = match filter.residual.take() {
                        Some(residual) => residual & resolved,
                        None => resolved,
                    };
                    if let Some(last) = last.filter(|_| !matches.is_empty()) {
                        let cache = &cache.emails;
                        match remaining_positions(cache, candidates, &matches, order, last) {
                            Some(positions) => self.fill(
                                filter,
                                &mut positions.iter().filter_map(|position| cache.at(*position)),
                            ),
                            None => {
                                filter.residual = Some(matches);
                                self.fill(filter, messages)
                            }
                        };
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

fn remaining_positions(
    cache: &MessagesCache,
    candidates: &Candidates,
    matches: &RoaringBitmap,
    order: WalkOrder,
    last: u32,
) -> Option<Vec<u32>> {
    if matches.len().saturating_mul(SPARSE_RESIDUAL_RATIO) >= candidates.len(cache) as u64 {
        return None;
    }
    let mut positions = matches
        .iter()
        .filter_map(|document_id| cache.position(document_id))
        .filter(|position| {
            (match order {
                WalkOrder::Ascending => *position > last,
                WalkOrder::Descending => *position < last,
            }) && match candidates {
                Candidates::All => true,
                Candidates::Positions(positions) => positions.binary_search(position).is_ok(),
            }
        })
        .collect::<Vec<_>>();
    match order {
        WalkOrder::Ascending => positions.sort_unstable(),
        WalkOrder::Descending => positions.sort_unstable_by(|a, b| b.cmp(a)),
    }
    Some(positions)
}
