/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FlagEdit, MailEdits, SEEN_BIT};
use crate::{cache::ExchangeCacheFetch, store::category::SpellingChanges};
use common::{
    Server,
    cache::exchange::{CategoryTable, ExchangeAccountCache},
    config::mailstore::limits::EmailLimits,
};
use compact_str::CompactString;
use email::message::messagedata::{KeywordDiff, MessageData, merge_keywords};
use exchange_proto::convert::category::{from_keyword, is_category_keyword, to_keyword};
use smallvec::SmallVec;
use std::borrow::Cow;
use store::write::BatchBuilder;
use trc::AddContext;
use types::keyword::Keyword;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CategoryOutcome {
    Changed,
    Renamed,
    Unchanged,
    KeywordLimit,
    InvalidName,
}

#[derive(Debug, Clone, Copy)]
pub struct AccountCategories<'x> {
    table: &'x CategoryTable,
}

impl<'x> AccountCategories<'x> {
    pub fn new(cache: &'x ExchangeAccountCache) -> Self {
        AccountCategories {
            table: &cache.categories,
        }
    }

    pub fn from_table(table: &'x CategoryTable) -> Self {
        AccountCategories { table }
    }

    pub fn name<'k>(&self, keyword: &'k str) -> Cow<'k, str>
    where
        'x: 'k,
    {
        let table: &'x CategoryTable = self.table;
        match table.spelling(keyword) {
            Some(name) => Cow::Borrowed(name),
            None => from_keyword(keyword),
        }
    }

    pub fn resolve<'k>(
        self,
        keywords: &'k [CompactString],
    ) -> impl Iterator<Item = Cow<'k, str>> + 'k
    where
        'x: 'k,
    {
        keywords
            .iter()
            .filter(|keyword| is_category_keyword(keyword))
            .map(move |keyword| self.name(keyword))
    }

    pub fn any(keywords: &[CompactString]) -> bool {
        keywords.iter().any(|keyword| is_category_keyword(keyword))
    }

    pub fn add_keywords(
        self,
        limits: &EmailLimits,
        names: &[&str],
        keywords: &mut Vec<Keyword>,
        spellings: &mut SpellingChanges,
    ) -> CategoryOutcome {
        let start = keywords.len();
        let mut pending = SmallVec::<[(CompactString, Option<Box<str>>); 8]>::new();
        for &name in names.iter().filter(|name| !name.is_empty()) {
            let existing = keywords
                .iter()
                .enumerate()
                .find_map(|(index, keyword)| match keyword {
                    Keyword::Other(keyword)
                        if is_category_keyword(keyword)
                            && from_keyword(keyword).eq_ignore_ascii_case(name) =>
                    {
                        Some((index, keyword))
                    }
                    _ => None,
                });
            let keyword = match existing {
                Some((index, _)) if index >= start => continue,
                Some((_, keyword)) => keyword.clone(),
                None => {
                    let Some(keyword) = to_keyword(name) else {
                        keywords.truncate(start);
                        return CategoryOutcome::InvalidName;
                    };
                    keywords.push(Keyword::Other(keyword.clone()));
                    keyword
                }
            };
            if let Some(spelling) = self.spelling_change(&keyword, name) {
                pending.push((keyword, spelling));
            }
        }
        let added = keywords.get(start..).unwrap_or_default();
        if limits.validate_keyword_count(keywords.len()).is_err() && !added.is_empty() {
            keywords.truncate(start);
            return CategoryOutcome::KeywordLimit;
        }
        if limits
            .validate_keyword_names(added.iter().filter_map(|keyword| keyword.id().err()))
            .is_err()
        {
            keywords.truncate(start);
            return CategoryOutcome::InvalidName;
        }
        let changed = !added.is_empty() || !pending.is_empty();
        for (keyword, spelling) in pending {
            spellings.push(keyword, spelling);
        }
        if changed {
            CategoryOutcome::Changed
        } else {
            CategoryOutcome::Unchanged
        }
    }

    pub fn respell(self, keyword: &str, name: &str, spellings: &mut SpellingChanges) {
        if let Some(spelling) = self.spelling_change(keyword, name) {
            spellings.push(keyword.into(), spelling);
        }
    }

    fn spelling_change(&self, keyword: &str, name: &str) -> Option<Option<Box<str>>> {
        let decoded = from_keyword(keyword);
        match self.table.spelling(keyword) {
            Some(current) if current == name => None,
            Some(_) if *decoded == *name => Some(None),
            None if *decoded == *name => None,
            _ => Some(Some(name.into())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CategoryUse {
    Assigned,
    Tested,
}

#[derive(Debug, Default)]
pub struct CategoryNames(Vec<(CompactString, Box<str>, CategoryUse)>);

impl CategoryNames {
    pub fn keyword(&mut self, name: &str, usage: CategoryUse) -> Option<String> {
        let keyword = to_keyword(name)?;
        let stored = keyword.as_str().to_owned();
        self.0.push((keyword, name.into(), usage));
        Some(stored)
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn recorded(&self) -> usize {
        self.0.len()
    }

    pub fn forget_since(&mut self, recorded: usize) {
        self.0.truncate(recorded);
    }

    pub async fn save(&mut self, server: &Server, account_id: u32) -> trc::Result<()> {
        if self.0.is_empty() {
            return Ok(());
        }
        let exchange = server.get_cached_exchange(account_id).await?;
        let categories = AccountCategories::new(&exchange);
        let mut spellings = SpellingChanges::default();
        self.0
            .sort_by(|(left, _, left_use), (right, _, right_use)| {
                left.cmp(right).then(left_use.cmp(right_use))
            });
        for uses in self.0.chunk_by(|(left, ..), (right, ..)| left == right) {
            let chosen = uses
                .iter()
                .rfind(|(_, _, usage)| *usage == CategoryUse::Assigned)
                .or_else(|| uses.last());
            if let Some((keyword, name, usage)) = chosen
                && (*usage == CategoryUse::Assigned || categories.table.spelling(keyword).is_none())
            {
                categories.respell(keyword, name, &mut spellings);
            }
        }
        self.0.clear();
        if spellings.is_empty() {
            return Ok(());
        }
        let mut batch = BatchBuilder::new();
        spellings.queue(&mut batch, account_id);
        server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
        server.mark_exchange_stale(account_id);
        Ok(())
    }
}

struct Category<'x> {
    keyword: CompactString,
    name: &'x str,
}

impl MailEdits {
    pub fn set_categories(
        &mut self,
        limits: &EmailLimits,
        document_id: u32,
        data: &MessageData,
        flags: FlagEdit,
        names: &[&str],
        categories: AccountCategories<'_>,
    ) -> trc::Result<CategoryOutcome> {
        let (added, removed) = flags.diff(data.keywords);
        let count = data.keyword_count();
        let max_categories = limits.keywords_per_email.max(count);
        let current = data
            .keywords_extra
            .iter()
            .filter(|keyword| is_category_keyword(keyword))
            .map(|keyword| (keyword, from_keyword(keyword)))
            .collect::<SmallVec<[_; 8]>>();
        let mut target = SmallVec::<[Category<'_>; 8]>::new();
        for &name in names.iter().filter(|name| !name.is_empty()) {
            let existing = current
                .iter()
                .find(|(_, display)| display.eq_ignore_ascii_case(name));
            let keyword = match existing {
                Some((keyword, _)) => (*keyword).clone(),
                None => match to_keyword(name) {
                    Some(keyword) => keyword,
                    None => return Ok(CategoryOutcome::InvalidName),
                },
            };
            if target.iter().any(|category| category.keyword == keyword) {
                continue;
            }
            if target.len() >= max_categories {
                return Ok(CategoryOutcome::KeywordLimit);
            }
            target.push(Category { keyword, name });
        }

        let removed_extra = current
            .iter()
            .filter(|(keyword, _)| !target.iter().any(|category| category.keyword == **keyword))
            .map(|(keyword, _)| (*keyword).clone())
            .collect::<Vec<_>>();
        let added_extra = target
            .iter()
            .filter(|category| !data.keywords_extra.contains(&category.keyword))
            .map(|category| category.keyword.clone())
            .collect::<Vec<_>>();
        let next_count = count
            .saturating_add(added.count_ones() as usize + added_extra.len())
            .saturating_sub(removed.count_ones() as usize + removed_extra.len());
        if limits.validate_keyword_change(count, next_count).is_err() {
            return Ok(CategoryOutcome::KeywordLimit);
        }
        if limits
            .validate_keyword_names(added_extra.iter().map(|keyword| keyword.as_str()))
            .is_err()
        {
            return Ok(CategoryOutcome::InvalidName);
        }

        let spellings = target
            .into_iter()
            .filter_map(|category| {
                categories
                    .spelling_change(&category.keyword, category.name)
                    .map(|spelling| (category.keyword, spelling))
            })
            .collect::<SmallVec<[_; 8]>>();
        let keywords_changed =
            added != 0 || removed != 0 || !added_extra.is_empty() || !removed_extra.is_empty();
        if !keywords_changed && spellings.is_empty() {
            return Ok(CategoryOutcome::Unchanged);
        }
        self.claim(document_id)?;
        if (added | removed) & SEEN_BIT != 0 {
            self.note_seen(data);
        }
        if keywords_changed {
            merge_keywords(
                &mut self.batch,
                data.thread_id,
                KeywordDiff::Patch {
                    added,
                    removed,
                    added_extra,
                    removed_extra,
                },
            );
        }
        for (keyword, spelling) in spellings {
            self.spellings.push(keyword, spelling);
        }
        self.commit_point();
        Ok(if keywords_changed {
            CategoryOutcome::Changed
        } else {
            CategoryOutcome::Renamed
        })
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/mail/category/tests.rs"]
mod tests;
