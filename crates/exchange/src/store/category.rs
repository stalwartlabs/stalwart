/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{account::merge_exchange_account, account_key};
use common::{Server, cache::exchange::CategoryTable};
use compact_str::CompactString;
use store::{
    Deserialize, Serialize,
    write::{
        Archive, ArchiveBytes, ArchiveCompression, Archiver, BatchBuilder, MergeResult,
        metadata::ExchangeClass,
    },
};
use trc::AddContext;
use types::collection::Collection;

pub const MAX_CATEGORY_SPELLINGS: usize = 256;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CategorySpellings {
    pub entries: Vec<CategorySpelling>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CategorySpelling {
    pub keyword: String,
    pub name: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpellingChanges(pub(crate) Vec<(CompactString, Option<Box<str>>)>);

impl ArchiveCompression for CategorySpellings {}

impl CategorySpellings {
    fn apply(&mut self, changes: &[(CompactString, Option<Box<str>>)]) -> bool {
        let mut changed = false;
        for (keyword, spelling) in changes {
            let current = self
                .entries
                .iter()
                .position(|entry| entry.keyword == keyword.as_str());
            match (current, spelling) {
                (Some(index), Some(name))
                    if self
                        .entries
                        .get(index)
                        .is_some_and(|entry| *entry.name == **name) => {}
                (current, Some(name)) => {
                    if let Some(index) = current {
                        self.entries.remove(index);
                    } else if self.entries.len() >= MAX_CATEGORY_SPELLINGS {
                        self.entries.remove(0);
                    }
                    self.entries.push(CategorySpelling {
                        keyword: String::from(keyword.as_str()),
                        name: String::from(&**name),
                    });
                    changed = true;
                }
                (Some(index), None) => {
                    self.entries.remove(index);
                    changed = true;
                }
                (None, None) => {}
            }
        }
        changed
    }

    fn into_table(self) -> CategoryTable {
        CategoryTable::new(
            self.entries
                .into_iter()
                .map(|entry| (entry.keyword.into(), entry.name.into())),
        )
    }
}

impl SpellingChanges {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn push(&mut self, keyword: CompactString, spelling: Option<Box<str>>) {
        match self.0.iter_mut().find(|(pending, _)| *pending == keyword) {
            Some((_, pending)) => *pending = spelling,
            None => self.0.push((keyword, spelling)),
        }
    }

    pub(crate) fn queue(self, batch: &mut BatchBuilder, account_id: u32) {
        if self.0.is_empty() {
            return;
        }
        let changes = self.0;
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Principal)
            .with_document(0)
            .merge_fnc(ExchangeClass::Categories, move |_, bytes| {
                let mut stored = match bytes {
                    Some(bytes) => <Archive<ArchiveBytes> as Deserialize>::deserialize(bytes)?
                        .deserialize::<CategorySpellings>()?,
                    None => CategorySpellings::default(),
                };
                if !stored.apply(&changes) {
                    Ok(MergeResult::Skip)
                } else if stored.entries.is_empty() {
                    Ok(MergeResult::Delete)
                } else {
                    Archiver::new(stored).serialize().map(MergeResult::Update)
                }
            });
        merge_exchange_account(batch, account_id, |account| {
            account.categories_version = account.categories_version.wrapping_add(1);
        });
    }
}

pub(crate) async fn read_category_table(
    server: &Server,
    account_id: u32,
) -> trc::Result<CategoryTable> {
    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(account_key(account_id, ExchangeClass::Categories))
        .await
        .caused_by(trc::location!())?
    {
        Some(stored) => Ok(stored.deserialize::<CategorySpellings>()?.into_table()),
        None => Ok(CategoryTable::default()),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/store/category/tests.rs"]
mod tests;
