/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Contacts, address_book_of};
use crate::{
    contact_group::{archived_text, internet_emails, is_archived_group},
    ews::{
        context::EwsContext,
        folder::{FolderSelector, resolve_folder},
        groupware::items::GroupwareRef,
        item::ItemError,
    },
    mapi::nspi::{
        page::{fold_cmp, fold_cmp_folded},
        table::name_anr,
    },
};
use calcard::vcard::{ArchivedVCard, VCardProperty};
use common::Server;
use exchange_proto::ews::{
    Status,
    schema::{DistinguishedFolderName, ResponseCode},
    types::ids::{BaseFolderId, DistinguishedFolderId},
};
use groupware::contact::ContactCardContent;
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{collection::Collection, field::ContactField};

const NOT_CONTACTS: &str = "ResolveNames requires a contacts folder.";
const ONE_FOLDER: &str = "ResolveNames accepts a single contacts folder.";
const NAME_COMPONENTS: usize = 2;

#[derive(Clone, Copy)]
pub(crate) enum CardQuery<'q> {
    Name {
        query: &'q str,
        folded: &'q str,
        exact: bool,
    },
    Address {
        address: &'q str,
        exact: bool,
    },
}

pub(crate) struct CardMatch {
    pub item: GroupwareRef,
    pub name: String,
    pub email: Option<String>,
    pub group: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct CardHit<'c> {
    pub email: Option<&'c str>,
    pub group: bool,
}

pub(crate) struct CardMatches {
    pub cards: Vec<CardMatch>,
    pub complete: bool,
}

impl CardQuery<'_> {
    pub(crate) fn matches<'c>(&self, card: &'c ArchivedVCard) -> Option<CardHit<'c>> {
        let group = is_archived_group(card);
        let mut emails = internet_emails(card).filter(|_| !group);
        let email = match *self {
            CardQuery::Address { address, exact } => {
                Some(emails.find(|email| address_matches(email, address, exact))?)
            }
            CardQuery::Name {
                query,
                folded,
                exact,
            } => {
                let mut first = None;
                for email in emails.by_ref() {
                    let hit = if exact {
                        email.eq_ignore_ascii_case(query)
                    } else {
                        address_matches(email, folded, false)
                    };
                    if hit {
                        return Some(CardHit {
                            email: Some(email),
                            group,
                        });
                    }
                    first.get_or_insert(email);
                }
                if first.is_none() && !group {
                    return None;
                }
                let named = if exact {
                    card.property(&VCardProperty::Fn)
                        .and_then(archived_text)
                        .is_some_and(|text| fold_cmp_folded(text, folded).is_eq())
                } else {
                    name_texts(card).any(|text| name_anr(text, folded))
                };
                named.then_some(first)?
            }
        };
        Some(CardHit { email, group })
    }
}

impl Contacts {
    pub(crate) async fn match_cards(
        &self,
        server: &Server,
        address_book: u32,
        query: CardQuery<'_>,
        limit: usize,
    ) -> trc::Result<CardMatches> {
        let documents = self
            .members(address_book)
            .map(|item| item.document_id)
            .collect::<RoaringBitmap>();
        let mut cards = Vec::new();
        let mut complete = true;
        server
            .archives(
                self.account_id,
                Collection::ContactCard,
                ContactField::Content.into(),
                &documents,
                |document_id, archive| {
                    let content = match archive.unarchive::<ContactCardContent>() {
                        Ok(content) => content,
                        Err(err) => {
                            trc::error!(err.caused_by(trc::location!()));
                            return Ok(true);
                        }
                    };
                    let card = &content.card;
                    let Some(hit) = query.matches(card) else {
                        return Ok(true);
                    };
                    if cards.len() == limit {
                        complete = false;
                        return Ok(false);
                    }
                    cards.push(CardMatch {
                        item: GroupwareRef {
                            container: address_book,
                            document_id,
                        },
                        name: card
                            .property(&VCardProperty::Fn)
                            .and_then(archived_text)
                            .or(hit.email)
                            .unwrap_or_default()
                            .to_string(),
                        email: hit.email.map(str::to_string),
                        group: hit.group,
                    });
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        cards.sort_unstable_by(|a, b| fold_cmp(&a.name, &b.name));
        Ok(CardMatches { cards, complete })
    }
}

pub(crate) async fn resolve_address_book(
    server: &Server,
    ctx: &EwsContext,
    folders: &[BaseFolderId<'_>],
) -> trc::Result<Result<u32, Status<'static>>> {
    let contacts = BaseFolderId::Distinguished(DistinguishedFolderId {
        name: DistinguishedFolderName::Contacts,
        change_key: None,
        mailbox: None,
    });
    let folder = match folders {
        [] => &contacts,
        [folder] => folder,
        _ => {
            return Ok(Err(Status::error(
                ResponseCode::ErrorResolveNamesOnlyOneContactsFolderAllowed,
                ONE_FOLDER,
            )));
        }
    };
    let tree = ctx.folder_tree(server).await?;
    Ok(
        match resolve_folder(server, ctx, &tree, FolderSelector::from(folder)).await? {
            Ok(entry) if !ctx.access.of(entry.node).reads_items() => {
                Err(ItemError::Forbidden.status())
            }
            Ok(entry) => address_book_of(entry.node).ok_or_else(|| {
                Status::error(
                    ResponseCode::ErrorResolveNamesInvalidFolderType,
                    NOT_CONTACTS,
                )
            }),
            Err(status) => Err(status),
        },
    )
}

fn name_texts(card: &ArchivedVCard) -> impl Iterator<Item = &str> {
    let full = card.property(&VCardProperty::Fn).and_then(archived_text);
    let parts = card
        .property(&VCardProperty::N)
        .into_iter()
        .flat_map(|entry| entry.values.iter().take(NAME_COMPONENTS))
        .filter_map(|value| value.as_text())
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let company = card.property(&VCardProperty::Org).and_then(archived_text);
    full.into_iter().chain(parts).chain(company)
}

fn address_matches(email: &str, wanted: &str, exact: bool) -> bool {
    if exact {
        email.eq_ignore_ascii_case(wanted)
    } else {
        email
            .get(..wanted.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(wanted))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/ews/contact/resolve/tests.rs"]
mod tests;
