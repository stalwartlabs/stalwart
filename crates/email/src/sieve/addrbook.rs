/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{GroupwareResources, Server};
use groupware::cache::GroupwareCache;
use percent_encoding::percent_decode_str;
use std::sync::Arc;
use store::{ahash::AHashMap, roaring::RoaringBitmap};
use trc::AddContext;
use types::{collection::Collection, collection::SyncCollection, field::ContactField};

const ADDRBOOK_PREFIXES: [&str; 2] = [":addrbook:", "urn:ietf:params:sieve:addrbook:"];
const DEFAULT_ADDRBOOK: &str = "default";
pub(super) const MAX_LIST_LOOKUPS: usize = 64;
const MAX_DELIVERY_LOOKUPS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AddressBookList {
    Default,
    Named(Box<str>),
}

impl AddressBookList {
    pub(super) fn parse(list: &str) -> Option<Self> {
        let name = ADDRBOOK_PREFIXES.iter().find_map(|prefix| {
            let (head, name) = list.split_at_checked(prefix.len())?;
            head.eq_ignore_ascii_case(prefix).then_some(name)
        })?;
        let name = percent_decode_str(name).decode_utf8().ok()?;
        match name.as_ref() {
            "" => None,
            name if name.eq_ignore_ascii_case(DEFAULT_ADDRBOOK) => Some(AddressBookList::Default),
            name => Some(AddressBookList::Named(name.into())),
        }
    }
}

pub(super) fn name_slug(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut separator = false;
    for ch in name.chars() {
        if ch.is_alphanumeric() {
            if separator && !slug.is_empty() {
                slug.push('-');
            }
            separator = false;
            slug.extend(ch.to_lowercase());
        } else if !matches!(ch, '\'' | '\u{2019}' | '`') {
            separator = true;
        }
    }
    slug
}

pub(super) struct AddressBooks {
    account_id: u32,
    resources: Option<Arc<GroupwareResources>>,
    card_ids: AHashMap<String, RoaringBitmap>,
    lookups_left: usize,
}

impl AddressBooks {
    pub(super) fn new(account_id: u32) -> Self {
        AddressBooks {
            account_id,
            resources: None,
            card_ids: AHashMap::new(),
            lookups_left: MAX_DELIVERY_LOOKUPS,
        }
    }

    async fn resources(&mut self, server: &Server) -> trc::Result<Arc<GroupwareResources>> {
        if let Some(resources) = &self.resources {
            return Ok(resources.clone());
        }
        let resources = server
            .fetch_groupware_resources(
                self.account_id,
                self.account_id,
                SyncCollection::AddressBook,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(self.resources.insert(resources).clone())
    }

    async fn any_card(
        &mut self,
        server: &Server,
        email: &str,
        matches: impl Fn(&RoaringBitmap) -> bool,
    ) -> trc::Result<bool> {
        if let Some(card_ids) = self.card_ids.get(email) {
            return Ok(matches(card_ids));
        }
        let Some(lookups_left) = self.lookups_left.checked_sub(1) else {
            return Ok(false);
        };
        self.lookups_left = lookups_left;
        let card_ids = server
            .document_ids_matching(
                self.account_id,
                Collection::ContactCard,
                ContactField::Email,
                email.as_bytes(),
            )
            .await
            .caused_by(trc::location!())?;
        let result = matches(&card_ids);
        self.card_ids.insert(email.into(), card_ids);
        Ok(result)
    }

    async fn book_id(&mut self, server: &Server, name: &str) -> trc::Result<Option<u32>> {
        let slug = name_slug(name);
        let resources = self.resources(server).await?;
        Ok(resources
            .containers()
            .find(|book| {
                book.container_name().is_some_and(|href| {
                    href.eq_ignore_ascii_case(name)
                        || (!slug.is_empty() && href.eq_ignore_ascii_case(&slug))
                })
            })
            .map(|book| book.document_id()))
    }

    pub(super) async fn exist(&mut self, server: &Server, names: &[Box<str>]) -> trc::Result<bool> {
        for name in names {
            if self.book_id(server, name).await?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(super) async fn contains(
        &mut self,
        server: &Server,
        lists: &[AddressBookList],
        emails: &[String],
    ) -> trc::Result<bool> {
        for list in lists {
            match list {
                AddressBookList::Default => {
                    for email in emails {
                        if self
                            .any_card(server, email, |card_ids| !card_ids.is_empty())
                            .await?
                        {
                            return Ok(true);
                        }
                    }
                }
                AddressBookList::Named(name) => {
                    let Some(book_id) = self.book_id(server, name).await? else {
                        continue;
                    };
                    let resources = self.resources(server).await?;
                    for email in emails {
                        if self
                            .any_card(server, email, |card_ids| {
                                card_ids.iter().any(|card_id| {
                                    resources.item_by_id(card_id).is_some_and(|card| {
                                        card.child_names()
                                            .iter()
                                            .any(|name| name.parent_id == book_id)
                                    })
                                })
                            })
                            .await?
                        {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/sieve/addrbook/tests.rs"]
mod tests;
