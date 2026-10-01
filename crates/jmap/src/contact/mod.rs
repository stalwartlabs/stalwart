/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::jscontact::JSContactProperty;
use common::{DavName, GroupwareResources, NO_ID};
use jmap_proto::error::set::SetError;
use store::ahash::AHashMap;
use types::id::Id;

pub mod copy;
pub mod get;
pub mod parse;
pub mod query;
pub mod set;

#[derive(Default)]
pub struct CreatedUids(AHashMap<String, Vec<u32>>);

impl CreatedUids {
    pub fn record(&mut self, address_books: &[DavName], uid: Option<&str>) {
        let Some(uid) = uid else {
            return;
        };
        let address_book_ids = address_books.iter().map(|name| name.parent_id);
        match self.0.get_mut(uid) {
            Some(ids) => ids.extend(address_book_ids),
            None => {
                self.0.insert(uid.to_string(), address_book_ids.collect());
            }
        }
    }

    fn address_book_with(&self, addressbook_ids: &[DavName], uid: &str) -> Option<u32> {
        self.0.get(uid)?.iter().copied().find(|address_book_id| {
            addressbook_ids
                .iter()
                .any(|name| name.parent_id == *address_book_id)
        })
    }
}

pub(super) fn assert_is_unique_uid(
    resources: &GroupwareResources,
    created_uids: &CreatedUids,
    addressbook_ids: &[DavName],
    uid: Option<&str>,
) -> trc::Result<Result<(), SetError<JSContactProperty<Id>>>> {
    if let Some(uid) = uid {
        let hits = resources.uid_matches(uid);
        if !hits.is_empty() {
            for document_id in resources
                .paths
                .iter()
                .filter(move |(_, path)| {
                    path.parent_id != NO_ID
                        && addressbook_ids
                            .iter()
                            .any(|ab| ab.parent_id == path.parent_id)
                })
                .map(|(_, path)| path.document_id)
            {
                if hits.contains(document_id) {
                    return Ok(Err(SetError::invalid_properties()
                        .with_property(JSContactProperty::Uid)
                        .with_description(format!(
                            "Contact with UID {uid} already exists with id {}.",
                            Id::from(document_id)
                        ))));
                }
            }
        }

        if let Some(address_book_id) = created_uids.address_book_with(addressbook_ids, uid) {
            return Ok(Err(SetError::invalid_properties()
                .with_property(JSContactProperty::Uid)
                .with_description(format!(
                    "Contact with UID {uid} is already created in address book {}.",
                    Id::from(address_book_id)
                ))));
        }
    }

    Ok(Ok(()))
}
