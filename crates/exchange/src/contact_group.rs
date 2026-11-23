/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    folders::{FolderNode, access::ViewRights},
    store::{FolderKind, FolderRef},
};
use ahash::AHashMap;
use calcard::vcard::{
    ArchivedVCard, ArchivedVCardEntry, ArchivedVCardKind, ArchivedVCardParameterName,
    ArchivedVCardParameterValue, ArchivedVCardValue, VCard, VCardProperty,
};
use common::{CachedName, GroupwareResources, Server, storage::dav::CachedUid};
use exchange_proto::convert::vcard::{contact_group_members, is_internet_email_type};
use groupware::contact::ContactCardContent;
use store::{dispatch::ReadShape, roaring::RoaringBitmap};
use trc::AddContext;
use types::{collection::Collection, field::ContactField};

const MAILTO: &str = "mailto:";
const URN_UUID: &str = "urn:uuid:";
const URI_SCHEME_SEPARATOR: char = ':';
const UID_INDEX_THRESHOLD: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupMember<'x> {
    OneOff {
        uri: &'x str,
        email: &'x str,
    },
    Card {
        uri: &'x str,
        document_id: u32,
        address_book: u32,
    },
}

pub(crate) struct MemberCard {
    pub document_id: u32,
    pub name: String,
    pub email: String,
    pub group: bool,
}

pub(crate) struct MemberCards(Vec<MemberCard>);

pub(crate) struct MemberResolver<'x> {
    resources: &'x GroupwareResources,
    view: &'x ViewRights,
    by_uid: Option<AHashMap<&'x str, (u32, Option<u32>)>>,
}

impl<'x> MemberResolver<'x> {
    pub fn new(resources: &'x GroupwareResources, view: &'x ViewRights, card: &VCard) -> Self {
        let indexed = contact_group_members(card)
            .filter(|uri| strip_prefix_ignore_case(uri, MAILTO).is_none())
            .nth(UID_INDEX_THRESHOLD - 1)
            .is_some();
        MemberResolver {
            resources,
            view,
            by_uid: indexed.then(|| uid_index(resources, view)),
        }
    }

    pub fn keeps_on_save(&self, uri: &str) -> bool {
        GroupMember::of(self, uri).is_none_or(|member| !member.is_readable(self.view))
    }

    fn card(&self, uri: &str) -> Option<(u32, u32)> {
        let (document_id, address_book) = match strip_prefix_ignore_case(uri, URN_UUID) {
            Some(uid) => self.lookup_either(uid, uri),
            None => self.lookup(uri),
        }?;
        Some((document_id, address_book?))
    }

    fn lookup_either(&self, uid: &str, uri: &str) -> Option<(u32, Option<u32>)> {
        let stripped = self.lookup(uid);
        if stripped.is_some_and(|(_, book)| readable_or_unfiled(self.view, book)) {
            return stripped;
        }
        let full = self.lookup(uri);
        full.filter(|(_, book)| readable_or_unfiled(self.view, *book))
            .or(stripped)
            .or(full)
    }

    fn lookup(&self, uid: &str) -> Option<(u32, Option<u32>)> {
        let cached_uid = uid.cached_uid();
        match &self.by_uid {
            Some(by_uid) => by_uid.get(cached_uid.as_ref()).copied(),
            None => self
                .resources
                .resources
                .find_by_uid(cached_uid)
                .map(|resource| {
                    (
                        resource.document_id(),
                        preferred_book(self.view, resource.child_names()),
                    )
                })
                .min_by_key(|card| rank(self.view, *card)),
        }
    }
}

pub(crate) fn book_readable(view: &ViewRights, id: u32) -> bool {
    view.of(FolderNode::Stored(FolderRef {
        kind: FolderKind::AddressBook,
        id,
    }))
    .reads_items()
}

fn readable_or_unfiled(view: &ViewRights, book: Option<u32>) -> bool {
    book.is_none_or(|book| book_readable(view, book))
}

fn preferred_book(view: &ViewRights, names: &[CachedName]) -> Option<u32> {
    names
        .iter()
        .map(|name| name.parent_id)
        .find(|book| book_readable(view, *book))
        .or_else(|| names.first().map(|name| name.parent_id))
}

fn rank(view: &ViewRights, (document_id, book): (u32, Option<u32>)) -> (bool, u32) {
    (!readable_or_unfiled(view, book), document_id)
}

fn uid_index<'x>(
    resources: &'x GroupwareResources,
    view: &ViewRights,
) -> AHashMap<&'x str, (u32, Option<u32>)> {
    let mut by_uid = AHashMap::with_capacity(resources.resources.len());
    for resource in resources.resources.iter_run(false) {
        let Some(uid) = resource.uid() else {
            continue;
        };
        let entry = (
            resource.document_id(),
            preferred_book(view, resource.child_names()),
        );
        let slot = by_uid.entry(uid).or_insert(entry);
        if entry != *slot && rank(view, entry) < rank(view, *slot) {
            *slot = entry;
        }
    }
    by_uid
}

impl<'x> GroupMember<'x> {
    pub fn of(resolver: &MemberResolver<'_>, uri: &'x str) -> Option<Self> {
        if let Some(email) = strip_prefix_ignore_case(uri, MAILTO) {
            return Some(GroupMember::OneOff { uri, email });
        }
        resolver
            .card(uri)
            .map(|(document_id, address_book)| GroupMember::Card {
                uri,
                document_id,
                address_book,
            })
    }

    pub fn document_id(&self) -> Option<u32> {
        match self {
            GroupMember::Card { document_id, .. } => Some(*document_id),
            GroupMember::OneOff { .. } => None,
        }
    }

    pub fn is_readable(&self, view: &ViewRights) -> bool {
        match self {
            GroupMember::OneOff { .. } => true,
            GroupMember::Card { address_book, .. } => book_readable(view, *address_book),
        }
    }
}

impl MemberCard {
    fn of(document_id: u32, card: &ArchivedVCard) -> Self {
        let email = internet_emails(card).next().unwrap_or_default();
        MemberCard {
            document_id,
            name: card
                .property(&VCardProperty::Fn)
                .and_then(archived_text)
                .unwrap_or(email)
                .to_string(),
            email: email.to_string(),
            group: is_archived_group(card),
        }
    }
}

impl MemberCards {
    pub async fn read(
        server: &Server,
        account_id: u32,
        documents: impl IntoIterator<Item = u32>,
    ) -> trc::Result<Self> {
        let documents = documents.into_iter().collect::<RoaringBitmap>();
        let mut cards = Vec::with_capacity(usize::try_from(documents.len()).unwrap_or_default());
        if !documents.is_empty() {
            server
                .archives_fields(
                    account_id,
                    Collection::ContactCard,
                    ReadShape::Keys,
                    &[(ContactField::Content.into(), &documents)],
                    |_, document_id, archive| {
                        match archive.unarchive::<ContactCardContent>() {
                            Ok(content) => cards.push(MemberCard::of(document_id, &content.card)),
                            Err(err) => {
                                trc::error!(err.caused_by(trc::location!()));
                            }
                        }
                        Ok(true)
                    },
                )
                .await
                .caused_by(trc::location!())?;
            cards.sort_unstable_by_key(|card| card.document_id);
        }
        Ok(MemberCards(cards))
    }

    pub fn get(&self, document_id: u32) -> Option<&MemberCard> {
        self.0
            .binary_search_by_key(&document_id, |card| card.document_id)
            .ok()
            .and_then(|position| self.0.get(position))
    }
}

pub(crate) fn is_archived_group(card: &ArchivedVCard) -> bool {
    card.property(&VCardProperty::Kind)
        .and_then(|entry| entry.values.first())
        .is_some_and(|value| matches!(value, ArchivedVCardValue::Kind(ArchivedVCardKind::Group)))
}

pub(crate) fn card_uri(uid: &str) -> String {
    if uid.contains(URI_SCHEME_SEPARATOR) {
        uid.to_string()
    } else {
        format!("{URN_UUID}{uid}")
    }
}

pub(crate) fn mailto_uri(email: &str) -> String {
    format!("{MAILTO}{email}")
}

pub(crate) fn mailto_address(uri: &str) -> Option<&str> {
    strip_prefix_ignore_case(uri, MAILTO)
}

fn strip_prefix_ignore_case<'x>(value: &'x str, prefix: &str) -> Option<&'x str> {
    value
        .split_at_checked(prefix.len())
        .filter(|(head, _)| head.eq_ignore_ascii_case(prefix))
        .map(|(_, rest)| rest)
}

fn type_params(entry: &ArchivedVCardEntry) -> impl Iterator<Item = &str> {
    entry
        .params
        .iter()
        .filter(|param| matches!(param.name, ArchivedVCardParameterName::Type))
        .filter_map(|param| match &param.value {
            ArchivedVCardParameterValue::Text(text) => Some(text.as_str()),
            _ => None,
        })
}

pub(crate) fn internet_emails(card: &ArchivedVCard) -> impl Iterator<Item = &str> {
    card.properties(&VCardProperty::Email)
        .filter(|entry| is_internet_email_type(type_params(entry)))
        .filter_map(archived_text)
}

pub(crate) fn archived_text(entry: &ArchivedVCardEntry) -> Option<&str> {
    entry
        .values
        .first()
        .and_then(ArchivedVCardValue::as_text)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/contact_group/tests.rs"]
mod tests;
