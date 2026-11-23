/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::identity::DirectoryRef;
use common::auth::{AccountCache, EmailAddress};
use exchange_proto::mapi::nspi::{
    MinimalId,
    tags::{DT_DISTLIST, DT_MAILUSER, MAPI_DISTLIST, MAPI_MAILUSER},
};
use std::{
    cmp::{Ordering, Reverse},
    collections::BinaryHeap,
    sync::Arc,
};
use utils::cache::CacheItemWeight;

pub const MAX_WINDOW: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbKind {
    User,
    List,
}

impl AbKind {
    pub fn display_type(self) -> u32 {
        match self {
            AbKind::User => DT_MAILUSER,
            AbKind::List => DT_DISTLIST,
        }
    }

    pub fn object_type(self) -> u32 {
        match self {
            AbKind::User => MAPI_MAILUSER,
            AbKind::List => MAPI_DISTLIST,
        }
    }
}

#[derive(Debug, Clone)]
enum RowSubject {
    Account(MinimalId, Arc<AccountCache>),
    List(MinimalId, Arc<DirectoryList>),
}

#[derive(Debug, Clone, Copy)]
pub enum RowRef<'a> {
    Account(&'a AccountCache),
    List(&'a DirectoryList),
}

#[derive(Debug, Clone)]
pub struct RowKey(RowSubject);

const _: () = assert!(size_of::<RowKey>() <= 16);

impl RowKey {
    pub fn new(account: Arc<AccountCache>) -> Option<Self> {
        MinimalId::from_principal(MinimalId::KIND_ADDRESS, account.account_id())
            .map(|mid| RowKey(RowSubject::Account(mid, account)))
    }

    pub fn list(list_id: u32, list: Arc<DirectoryList>) -> Option<Self> {
        MinimalId::from_principal(MinimalId::KIND_LIST, list_id)
            .map(|mid| RowKey(RowSubject::List(mid, list)))
    }

    pub fn subject(&self) -> RowRef<'_> {
        match &self.0 {
            RowSubject::Account(_, account) => RowRef::Account(account),
            RowSubject::List(_, list) => RowRef::List(list),
        }
    }

    pub fn principal(&self) -> DirectoryRef {
        match &self.0 {
            RowSubject::Account(_, account) => DirectoryRef::Account(account.account_id()),
            RowSubject::List(mid, _) => {
                DirectoryRef::List(mid.principal().map_or(u32::MAX, |(_, id)| id))
            }
        }
    }

    pub fn kind(&self) -> AbKind {
        self.subject().kind()
    }

    pub fn mid(&self) -> MinimalId {
        match &self.0 {
            RowSubject::Account(mid, _) | RowSubject::List(mid, _) => *mid,
        }
    }

    pub fn display_name(&self) -> &str {
        self.subject().display_name()
    }

    pub fn weight(&self) -> u64 {
        match &self.0 {
            RowSubject::Account(_, account) => account.weight(),
            RowSubject::List(_, list) => list.weight(),
        }
    }
}

impl<'a> RowRef<'a> {
    pub fn kind(self) -> AbKind {
        match self {
            RowRef::Account(_) => AbKind::User,
            RowRef::List(_) => AbKind::List,
        }
    }

    pub fn display_name(self) -> &'a str {
        match self {
            RowRef::Account(account) => display_name(account),
            RowRef::List(list) => list.display_name(),
        }
    }

    pub fn account_name(self) -> &'a str {
        match self {
            RowRef::Account(account) => account.name(),
            RowRef::List(list) => list.name(),
        }
    }
}

impl PartialEq for RowKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RowKey {}

impl PartialOrd for RowKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RowKey {
    fn cmp(&self, other: &Self) -> Ordering {
        fold_cmp(self.display_name(), other.display_name())
            .then_with(|| self.mid().cmp(&other.mid()))
    }
}

pub fn display_name(account: &AccountCache) -> &str {
    account.description().unwrap_or(account.name())
}

#[derive(Debug, Default)]
pub struct DirectoryList {
    pub addresses: Box<[EmailAddress]>,
    pub recipients: Arc<[Box<str>]>,
    pub description: Option<Box<str>>,
}

impl DirectoryList {
    pub fn display_name(&self) -> &str {
        self.description.as_deref().unwrap_or(self.name())
    }

    pub fn name(&self) -> &str {
        self.addresses
            .first()
            .map_or("", |address| address.local_part.as_str())
    }
}

impl CacheItemWeight for DirectoryList {
    fn weight(&self) -> u64 {
        size_of::<DirectoryList>() as u64
            + self.addresses.iter().map(|a| a.weight()).sum::<u64>()
            + self
                .recipients
                .iter()
                .map(|r| (r.len() + size_of::<Box<str>>()) as u64)
                .sum::<u64>()
            + self.description.as_ref().map_or(0, |d| d.len() as u64)
    }
}

pub fn fold(text: &str) -> String {
    let mut folded = String::with_capacity(text.len());
    folded.extend(text.chars().flat_map(char::to_lowercase));
    folded
}

pub fn fold_cmp(a: &str, b: &str) -> Ordering {
    if a.is_ascii() && b.is_ascii() {
        a.bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(b.bytes().map(|byte| byte.to_ascii_lowercase()))
    } else {
        a.chars()
            .flat_map(char::to_lowercase)
            .cmp(b.chars().flat_map(char::to_lowercase))
    }
}

pub fn fold_cmp_folded(text: &str, folded: &str) -> Ordering {
    if text.is_ascii() {
        text.bytes()
            .map(|byte| byte.to_ascii_lowercase())
            .cmp(folded.bytes())
    } else {
        text.chars()
            .flat_map(char::to_lowercase)
            .cmp(folded.chars())
    }
}

#[derive(Debug, Clone)]
pub enum Anchor {
    Start,
    End,
    Row(RowKey),
    Prefix(Box<str>),
}

impl Anchor {
    pub fn is_below(&self, key: &RowKey) -> bool {
        match self {
            Anchor::Start => false,
            Anchor::End => true,
            Anchor::Row(anchor) => key < anchor,
            Anchor::Prefix(folded) => fold_cmp_folded(key.display_name(), folded).is_lt(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Seek {
    At(Anchor),
    Fraction { num_pos: u32, total_recs: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    Window { back: usize, forward: usize },
    Positional,
}

impl Seek {
    pub fn strategy(&self, delta: i32, count: usize) -> Strategy {
        let Seek::At(_) = self else {
            return Strategy::Positional;
        };
        let back = usize::try_from(delta.min(0).unsigned_abs()).unwrap_or(usize::MAX);
        let forward = usize::try_from(delta.max(0))
            .unwrap_or(usize::MAX)
            .saturating_add(count);
        if back.saturating_add(forward) <= MAX_WINDOW {
            Strategy::Window { back, forward }
        } else {
            Strategy::Positional
        }
    }
}

#[derive(Debug, Default)]
pub struct Page {
    pub rows: Vec<RowKey>,
    pub start: usize,
    pub anchor: usize,
    pub total: usize,
}

impl Page {
    pub fn mid_at(&self, position: usize) -> MinimalId {
        position
            .checked_sub(self.start)
            .and_then(|offset| self.rows.get(offset))
            .map_or(MinimalId::END_OF_TABLE, RowKey::mid)
    }
}

pub fn target(anchor: usize, delta: i32, total: usize) -> usize {
    let target = i64::try_from(anchor)
        .unwrap_or(i64::MAX)
        .saturating_add(i64::from(delta))
        .max(0);
    usize::try_from(target).unwrap_or(total).min(total)
}

pub fn fraction(total: usize, num_pos: u32, total_recs: u32) -> usize {
    if total_recs == 0 {
        return 0;
    }
    let total64 = u64::try_from(total).unwrap_or(u64::MAX);
    let position = total64.saturating_mul(u64::from(num_pos)) / u64::from(total_recs);
    usize::try_from(position.min(total64)).unwrap_or(total)
}

pub struct Window<'a> {
    anchor: &'a Anchor,
    below: BinaryHeap<Reverse<RowKey>>,
    above: BinaryHeap<RowKey>,
    back: usize,
    forward: usize,
    below_count: usize,
    total: usize,
}

impl<'a> Window<'a> {
    pub fn new(anchor: &'a Anchor, back: usize, forward: usize) -> Self {
        Window {
            anchor,
            below: BinaryHeap::with_capacity(back.min(MAX_WINDOW)),
            above: BinaryHeap::with_capacity(forward.min(MAX_WINDOW)),
            back,
            forward,
            below_count: 0,
            total: 0,
        }
    }

    pub fn push(&mut self, key: RowKey) {
        self.total += 1;
        if self.anchor.is_below(&key) {
            self.below_count += 1;
            if self.below.len() < self.back {
                self.below.push(Reverse(key));
            } else if let Some(mut smallest) = self.below.peek_mut()
                && key > smallest.0
            {
                *smallest = Reverse(key);
            }
        } else if self.above.len() < self.forward {
            self.above.push(key);
        } else if let Some(mut largest) = self.above.peek_mut()
            && key < *largest
        {
            *largest = key;
        }
    }

    pub fn kept(&self) -> impl Iterator<Item = &RowKey> {
        self.below
            .iter()
            .map(|Reverse(key)| key)
            .chain(self.above.iter())
    }

    pub fn finish(self, delta: i32, count: usize) -> Page {
        let Window {
            below,
            above,
            below_count,
            total,
            ..
        } = self;
        let kept_below = below.len();
        let mut rows = Vec::with_capacity(kept_below + above.len());
        rows.extend(below.into_iter().map(|Reverse(key)| key));
        rows.extend(above);
        rows.sort_unstable();
        let first = below_count - kept_below;
        let start = target(below_count, delta, total).max(first);
        rows.drain(..(start - first).min(rows.len()));
        rows.truncate(count);
        Page {
            rows,
            start,
            anchor: below_count,
            total,
        }
    }
}

pub fn select(mut keys: Vec<RowKey>, start: usize, count: usize, anchor: usize) -> Page {
    let total = keys.len();
    let start = start.min(total);
    if start > 0 && start < total {
        keys.select_nth_unstable(start);
    }
    keys.drain(..start);
    if count > 0 && count < keys.len() {
        keys.select_nth_unstable(count - 1);
    }
    keys.truncate(count);
    keys.sort_unstable();
    Page {
        rows: keys,
        start,
        anchor,
        total,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/nspi/page/tests.rs"]
pub mod tests;
