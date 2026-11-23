/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod find;
pub mod group;
pub mod list;
pub mod resolve;
pub mod sync;
pub mod write;

use super::{
    filter::PropValue,
    groupware::{
        GroupwareFields, GroupwareKind,
        items::{GroupwareItems, LoadedItem},
    },
};
use crate::{
    folders::FolderNode,
    store::{FolderKind, FolderRef},
};
use exchange_proto::{
    common::UtcSeconds,
    convert::model::PropBag,
    ews::{
        contact::{ContactFieldSet, ContactProps},
        types::{item::Item, shape::ItemShape, value::DateTime},
    },
};
use find::ContactProp;

pub(crate) type Contacts = GroupwareItems<ContactFieldSet>;

impl GroupwareFields for ContactFieldSet {
    const KIND: GroupwareKind = GroupwareKind::Contact;
    type Prop = ContactProp;

    fn from_shape(shape: &ItemShape<'_>) -> Self {
        ContactFieldSet::from_shape(shape)
    }

    fn for_list(self) -> Self {
        ContactFieldSet::for_list(self)
    }

    fn needs_content(self) -> bool {
        ContactFieldSet::needs_content(self)
    }

    fn needs_kind(self) -> bool {
        self.has(ContactFieldSet::KIND)
    }

    fn value<'p>(
        contacts: &Contacts,
        document_id: u32,
        prop: ContactProp,
        props: &'p PropBag,
    ) -> Option<PropValue<'p>> {
        prop.value(ContactProps::new(props), || {
            contacts
                .resources
                .item_by_id(document_id)
                .and_then(|resource| resource.modified_at())
        })
    }

    fn render<'c>(self, contacts: &Contacts, loaded: &'c LoadedItem) -> Item<'c> {
        let mut item = match loaded
            .content
            .as_ref()
            .map(|content| ContactProps::new(&content.props))
        {
            Some(props) if props.is_distlist() => {
                Item::DistributionList(Box::new(props.render_distlist(self)))
            }
            Some(props) => Item::Contact(Box::new(props.render(self))),
            None => Item::Contact(Box::default()),
        };
        let fields = item.fields_mut();
        if self.has(ContactFieldSet::ID) {
            fields.item_id = Some(contacts.item_id(loaded.item, loaded.change_id));
        }
        if self.has(ContactFieldSet::PARENT) {
            fields.parent_folder_id = Some(contacts.parent_id(loaded));
        }
        if self.has(ContactFieldSet::LAST_MODIFIED) && fields.last_modified_time.is_none() {
            fields.last_modified_time = contacts
                .resources
                .item_by_id(loaded.item.document_id)
                .and_then(|resource| resource.modified_at())
                .map(|modified| DateTime::utc(UtcSeconds(modified)));
        }
        item
    }
}

pub(crate) fn address_book_of(node: FolderNode) -> Option<u32> {
    match node {
        FolderNode::Stored(FolderRef {
            kind: FolderKind::AddressBook,
            id,
        }) => Some(id),
        _ => None,
    }
}
