/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    identity::{DirectoryRef, directory_ref_from_dn},
    mapi::nspi::book::{AbEntry, directory_entry},
};
use common::{Server, auth::AccessToken};
use exchange_proto::{
    convert::{
        context::{AddressResolver, ResolvedAddress},
        model::{MessageContent, PropBag as ContentBag},
    },
    ids::entryid::EntryId,
    mapi::prop::{OwnedPropValue, PropKeyRef, PropTag, PropType, tags},
};
use smallvec::SmallVec;
use std::{borrow::Cow, iter::once};

pub const MAX_RESOLVED: usize = 256;
const ADDRESS_TYPE_EX: &str = "EX";

const ADDRESS_GROUPS: [(PropTag, PropTag, PropTag); 3] = [
    (tags::ADDRESS_TYPE, tags::EMAIL_ADDRESS, tags::ENTRY_ID),
    (
        tags::SENDER_ADDRESS_TYPE,
        tags::SENDER_EMAIL_ADDRESS,
        tags::SENDER_ENTRY_ID,
    ),
    (
        tags::SENT_REPRESENTING_ADDRESS_TYPE,
        tags::SENT_REPRESENTING_EMAIL_ADDRESS,
        tags::SENT_REPRESENTING_ENTRY_ID,
    ),
];

#[derive(Default)]
pub struct DirectoryResolver {
    entries: Vec<AbEntry>,
}

impl DirectoryResolver {
    pub async fn for_content(
        server: &Server,
        access_token: &AccessToken,
        content: &MessageContent,
    ) -> trc::Result<Self> {
        let mut principals = SmallVec::<[DirectoryRef; 8]>::new();
        directory_principals(content, &mut principals);
        let mut entries = Vec::with_capacity(principals.len());
        for principal in principals {
            if let Some(entry) = directory_entry(server, access_token, principal).await? {
                entries.push(entry);
            }
        }
        Ok(DirectoryResolver { entries })
    }
}

impl AddressResolver for DirectoryResolver {
    fn resolve(&self, smtp: &str) -> Option<ResolvedAddress<'_>> {
        self.entries
            .iter()
            .find(|entry| entry.smtp.eq_ignore_ascii_case(smtp))
            .map(resolved)
    }

    fn resolve_dn(&self, essdn: &str) -> Option<ResolvedAddress<'_>> {
        let principal = directory_ref_from_dn(essdn.as_bytes())?;
        self.entries
            .iter()
            .find(|entry| entry.principal == principal)
            .map(resolved)
    }
}

fn resolved(entry: &AbEntry) -> ResolvedAddress<'_> {
    ResolvedAddress {
        display_name: Cow::Borrowed(&entry.display_name),
        smtp: Cow::Borrowed(&entry.smtp),
        essdn: Cow::Borrowed(&entry.dn),
        object_type: entry.kind.object_type(),
        display_type: entry.kind.display_type(),
    }
}

pub fn directory_principals(content: &MessageContent, out: &mut SmallVec<[DirectoryRef; 8]>) {
    for bag in once(&content.props).chain(&content.recipients) {
        for (address_type, email, entry_id) in ADDRESS_GROUPS {
            if out.len() >= MAX_RESOLVED {
                return;
            }
            if let Some(principal) = bag_principal(bag, address_type, email, entry_id)
                && !out.contains(&principal)
            {
                out.push(principal);
            }
        }
    }
}

pub(in crate::mapi::emsmdb) fn bag_principal(
    bag: &ContentBag,
    address_type: PropTag,
    email: PropTag,
    entry_id: PropTag,
) -> Option<DirectoryRef> {
    let is_ex = matches!(
        bag.get(PropKeyRef::Tag(address_type.id()), PropType::Unicode),
        Some(OwnedPropValue::Unicode(kind)) if kind.eq_ignore_ascii_case(ADDRESS_TYPE_EX)
    );
    if is_ex
        && let Some(OwnedPropValue::Unicode(dn)) =
            bag.get(PropKeyRef::Tag(email.id()), PropType::Unicode)
        && let Some(principal) = directory_ref_from_dn(dn.as_bytes())
    {
        return Some(principal);
    }
    match bag.get(PropKeyRef::Tag(entry_id.id()), PropType::Binary) {
        Some(OwnedPropValue::Binary(bytes)) => match EntryId::decode(bytes).ok()? {
            EntryId::AddressBook(id) => directory_ref_from_dn(&id.dn),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/resolve/tests.rs"]
mod tests;
