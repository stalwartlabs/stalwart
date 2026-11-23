/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Contacts, address_book_of,
    list::{ListEdit, contact_change},
};
use crate::{
    ews::{
        context::{EwsCaller, EwsContext},
        folder::{FolderSelector, folder_not_found, resolve_folder, saved_folder_status},
        groupware::{change_id_of, items::GroupwareRef, write::failure_error},
        item::ItemError,
    },
    folders::SpecialFolder,
    groupware_write::{
        WriteFailure, assert_card_room, card_failure, card_name, card_size, new_card, new_uid,
        store_failure,
    },
};
use calcard::vcard::VCard;
use common::Server;
use exchange_proto::{
    convert::vcard::is_contact_group,
    ews::{
        Status,
        contact::{ContactEdit, ContactEditError, ContactFieldSet},
        types::{
            change::ItemChange,
            ids::{ItemId, TargetFolderId},
            item::{ContactItem, DistributionListItem, Item, ItemFields},
        },
    },
};
use groupware::contact::{
    ContactCardContent,
    write::{CardCreate, CardWriter},
};
use std::slice;

const MAX_ATTEMPTS: usize = 2;

pub(crate) struct ContactWriter<'x> {
    server: &'x Server,
    caller: EwsCaller<'x>,
    contacts: &'x Contacts,
    created: usize,
}

impl<'x> ContactWriter<'x> {
    pub fn new(server: &'x Server, caller: EwsCaller<'x>, contacts: &'x Contacts) -> Self {
        ContactWriter {
            server,
            caller,
            contacts,
            created: 0,
        }
    }

    pub async fn create(
        &mut self,
        address_book: u32,
        item: &ContactItem<'_>,
    ) -> trc::Result<Result<ItemId<'static>, ItemError>> {
        let edit = match ContactEdit::from_item(item) {
            Ok(edit) => edit,
            Err(err) => return Ok(Err(edit_error(err))),
        };
        let uid = new_uid();
        let name = card_name(&uid);
        let mut card = new_card(uid);
        if let Err(err) = edit.apply(&mut card) {
            return Ok(Err(edit_error(err)));
        }
        self.insert(address_book, name, card).await
    }

    pub async fn create_list(
        &mut self,
        address_book: u32,
        list: &DistributionListItem<'_>,
    ) -> trc::Result<Result<ItemId<'static>, ItemError>> {
        let edit = match ListEdit::from_item(self.contacts, list) {
            Ok(edit) => edit,
            Err(err) => return Ok(Err(err)),
        };
        let uid = new_uid();
        let name = card_name(&uid);
        let mut card = new_card(uid);
        if let Err(err) = edit.apply(self.contacts, &mut card) {
            return Ok(Err(err));
        }
        self.insert(address_book, name, card).await
    }

    pub async fn insert(
        &mut self,
        address_book: u32,
        name: String,
        card: VCard,
    ) -> trc::Result<Result<ItemId<'static>, ItemError>> {
        let Some(size) = card_size(self.server, &card) else {
            return Ok(Err(ItemError::ItemSave));
        };
        if let Err(err) = assert_card_room(
            self.server,
            self.contacts.account_id,
            &self.contacts.resources,
            self.created,
        )
        .await
        {
            return store_failure(err).map(|failure| Err(failure_error(failure)));
        }
        let writer = self.card_writer();
        let written = match writer.prepare_create(address_book) {
            Ok(new) => {
                writer
                    .create(
                        new,
                        CardCreate {
                            name,
                            vcard: card,
                            size: Some(size),
                        },
                    )
                    .await
            }
            Err(err) => Err(err),
        };
        match written {
            Ok(written) => {
                self.created += 1;
                self.current_id(GroupwareRef {
                    container: address_book,
                    document_id: written.document_id,
                })
                .await
                .map(Ok)
            }
            Err(err) => card_failure(err).map(|failure| Err(failure_error(failure))),
        }
    }

    pub async fn update(
        &self,
        contact: GroupwareRef,
        expected_change: Option<u64>,
        changes: &[ItemChange<'_>],
    ) -> trc::Result<Result<Item<'static>, ItemError>> {
        let edit = match CardEdit::of(self.contacts, changes) {
            Ok(edit) => edit,
            Err(err) => return Ok(Err(err)),
        };
        self.commit(contact, expected_change, |card| {
            edit.apply(self.contacts, changes, card)
        })
        .await
    }

    pub async fn replace(
        &self,
        contact: GroupwareRef,
        mut next: impl FnMut() -> Result<VCard, ItemError>,
    ) -> trc::Result<Result<Item<'static>, ItemError>> {
        self.commit(contact, None, |stored| {
            *stored = next()?;
            Ok(())
        })
        .await
    }

    async fn commit(
        &self,
        contact: GroupwareRef,
        expected_change: Option<u64>,
        mut apply: impl FnMut(&mut VCard) -> Result<(), ItemError>,
    ) -> trc::Result<Result<Item<'static>, ItemError>> {
        let writer = self.card_writer();
        for _ in 0..MAX_ATTEMPTS {
            let stored = match writer
                .prepare_update(contact.container, contact.document_id)
                .await
            {
                Ok(stored) => stored,
                Err(err) => return card_failure(err).map(|failure| Err(failure_error(failure))),
            };
            let version = match stored.card() {
                Ok(card) => card.version,
                Err(err) => return Ok(Err(unreadable(err))),
            };
            if expected_change.is_some_and(|expected| expected != change_id_of(version)) {
                return Ok(Err(ItemError::Stale));
            }
            let mut card = match stored
                .content()
                .and_then(|content| content.deserialize::<ContactCardContent>())
            {
                Ok(content) => content.card,
                Err(err) => return Ok(Err(unreadable(err))),
            };
            if let Err(err) = apply(&mut card) {
                return Ok(Err(err));
            }
            if card_size(self.server, &card).is_none() {
                return Ok(Err(ItemError::ItemSave));
            }
            let id_only = if is_contact_group(&card) {
                list_id_only
            } else {
                contact_id_only
            };
            match writer.update(stored, card).await {
                Ok(_) => return self.current_id(contact).await.map(|id| Ok(id_only(id))),
                Err(err) => match card_failure(err)? {
                    WriteFailure::Conflict => continue,
                    failure => return Ok(Err(failure_error(failure))),
                },
            }
        }
        Ok(Err(ItemError::Stale))
    }

    pub async fn delete(&self, contact: GroupwareRef) -> trc::Result<Result<(), ItemError>> {
        let Some(path) = self
            .contacts
            .resources
            .format_resource_path_by_parent(contact.document_id, contact.container)
        else {
            return Ok(Err(ItemError::NotFound));
        };
        let writer = self.card_writer();
        for _ in 0..MAX_ATTEMPTS {
            let deleted = match writer
                .prepare_delete(contact.container, contact.document_id)
                .await
            {
                Ok(deletion) => writer.delete(deletion, Some(path.clone())).await,
                Err(err) => Err(err),
            };
            match deleted {
                Ok(()) => return Ok(Ok(())),
                Err(err) => match card_failure(err)? {
                    WriteFailure::Conflict => continue,
                    failure => return Ok(Err(failure_error(failure))),
                },
            }
        }
        Ok(Err(ItemError::Stale))
    }

    async fn current_id(&self, contact: GroupwareRef) -> trc::Result<ItemId<'static>> {
        let change_id = self
            .contacts
            .load_many(
                self.server,
                slice::from_ref(&contact),
                ContactFieldSet::id_only(),
            )
            .await?
            .first()
            .map_or(0, |loaded| loaded.change_id);
        Ok(self.contacts.item_id(contact, change_id))
    }

    fn card_writer(&self) -> CardWriter<'_> {
        CardWriter {
            server: self.server,
            access_token: self.caller.access_token,
            account_id: self.contacts.account_id,
            resources: &self.contacts.resources,
        }
    }
}

pub(crate) async fn contact_destination(
    server: &Server,
    ctx: &EwsContext,
    id: Option<&TargetFolderId<'_>>,
) -> trc::Result<Result<u32, Status<'static>>> {
    let tree = ctx.folder_tree(server).await?;
    let entry = match id {
        Some(id) => match resolve_folder(server, ctx, &tree, FolderSelector::from(id)).await? {
            Ok(entry) => entry,
            Err(status) => return Ok(Err(saved_folder_status(ctx, status))),
        },
        None => match tree.special(SpecialFolder::Contacts) {
            Some(entry) => entry,
            None => return Ok(Err(folder_not_found())),
        },
    };
    Ok(address_book_of(entry.node).ok_or_else(|| ItemError::ContactFolder.status()))
}

enum CardEdit {
    Contact(ContactEdit),
    List(ListEdit),
}

impl CardEdit {
    fn of(contacts: &Contacts, changes: &[ItemChange<'_>]) -> Result<Self, ItemError> {
        if changes.iter().any(ListEdit::is_list_change) {
            Self::list(contacts, changes).map(CardEdit::List)
        } else {
            let mut edit = ContactEdit::default();
            for change in changes {
                edit.change(&contact_change(change)).map_err(edit_error)?;
            }
            Ok(CardEdit::Contact(edit))
        }
    }

    fn list(contacts: &Contacts, changes: &[ItemChange<'_>]) -> Result<ListEdit, ItemError> {
        let mut edit = ListEdit::default();
        for change in changes {
            edit.change(contacts, change)?;
        }
        Ok(edit)
    }

    fn apply(
        &self,
        contacts: &Contacts,
        changes: &[ItemChange<'_>],
        card: &mut VCard,
    ) -> Result<(), ItemError> {
        match self {
            CardEdit::Contact(_) if is_contact_group(card) => {
                Self::list(contacts, changes)?.apply(contacts, card)
            }
            CardEdit::Contact(edit) => edit.apply(card).map_err(edit_error),
            CardEdit::List(edit) if is_contact_group(card) => edit.apply(contacts, card),
            CardEdit::List(_) => Err(ItemError::InvalidPropertySet),
        }
    }
}

pub(crate) fn contact_id_only(id: ItemId<'static>) -> Item<'static> {
    Item::Contact(Box::new(ContactItem {
        item: ItemFields {
            item_id: Some(id),
            ..Default::default()
        },
        ..Default::default()
    }))
}

pub(crate) fn list_id_only(id: ItemId<'static>) -> Item<'static> {
    Item::DistributionList(Box::new(DistributionListItem {
        item: ItemFields {
            item_id: Some(id),
            ..Default::default()
        },
        ..Default::default()
    }))
}

fn unreadable(err: trc::Error) -> ItemError {
    trc::error!(err.caused_by(trc::location!()));
    ItemError::Unparsable
}

pub(super) fn edit_error(err: ContactEditError) -> ItemError {
    match err {
        ContactEditError::NotAContact | ContactEditError::InvalidPropertySet => {
            ItemError::InvalidPropertySet
        }
        ContactEditError::InvalidPropertyAppend => ItemError::InvalidPropertyAppend,
        ContactEditError::Conversion => ItemError::ItemSave,
    }
}
