/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Contacts, write::edit_error};
use crate::{
    contact_group::{MemberResolver, card_uri, mailto_address, mailto_uri},
    ews::{
        groupware::{GroupwareKind, items::decode_item_id},
        item::ItemError,
    },
};
use calcard::vcard::VCard;
use exchange_proto::{
    convert::vcard::{contact_group_members, patch_distlist},
    ews::{
        contact::ContactEdit,
        schema::{DictionaryField, UnindexedField},
        types::{
            change::ItemChange,
            item::{ContactItem, DistributionListItem, Item, ItemFields, contact::Member},
            path::Path,
        },
    },
};
use std::{
    borrow::Cow,
    collections::HashSet,
    hash::{Hash, Hasher},
};

enum MemberOp {
    Clear,
    Append(Vec<String>),
    Remove(String),
}

#[derive(Default)]
pub(crate) struct ListEdit {
    display_name: Option<String>,
    subject: Option<String>,
    ops: Vec<MemberOp>,
    item: Option<ContactEdit>,
}

impl ListEdit {
    pub fn is_list_change(change: &ItemChange<'_>) -> bool {
        match change {
            ItemChange::Set { value, .. } | ItemChange::Append { value, .. } => {
                matches!(value, Item::DistributionList(_))
            }
            ItemChange::Delete(path) => matches!(
                path,
                Path::Field(UnindexedField::DistributionlistMembers)
                    | Path::Indexed {
                        field: DictionaryField::DistributionlistMembersMember,
                        ..
                    }
            ),
        }
    }

    pub fn from_item(
        contacts: &Contacts,
        list: &DistributionListItem<'_>,
    ) -> Result<Self, ItemError> {
        let mut ops = Vec::with_capacity(1);
        if let Some(members) = &list.list.members {
            ops.push(MemberOp::Append(member_uris(contacts, &members.0)?));
        }
        let item = ContactEdit::from_item(&ContactItem {
            item: list.item.clone(),
            ..Default::default()
        })
        .map_err(edit_error)?;
        Ok(ListEdit {
            display_name: Some(
                list.list
                    .display_name
                    .as_deref()
                    .or(list.item.subject.as_deref())
                    .unwrap_or_default()
                    .to_string(),
            ),
            subject: None,
            ops,
            item: Some(item),
        })
    }

    pub fn change(
        &mut self,
        contacts: &Contacts,
        change: &ItemChange<'_>,
    ) -> Result<(), ItemError> {
        match change {
            ItemChange::Set {
                path: Path::Field(UnindexedField::ContactsDisplayName),
                value,
            } => {
                self.display_name = Some(name(list_of(value)?.list.display_name.as_deref())?);
                Ok(())
            }
            ItemChange::Set {
                path: Path::Field(UnindexedField::ItemSubject),
                value,
            } => {
                self.subject = Some(name(item_fields_of(value)?.subject.as_deref())?);
                Ok(())
            }
            ItemChange::Set {
                path: Path::Field(UnindexedField::DistributionlistMembers),
                value,
            } => {
                let members = list_members(contacts, list_of(value)?)?;
                self.ops.push(MemberOp::Clear);
                self.ops.push(MemberOp::Append(members));
                Ok(())
            }
            ItemChange::Append {
                path: Path::Field(UnindexedField::DistributionlistMembers),
                value,
            } => {
                let members = list_members(contacts, list_of(value)?)?;
                self.ops.push(MemberOp::Append(members));
                Ok(())
            }
            ItemChange::Delete(Path::Field(UnindexedField::DistributionlistMembers)) => {
                self.ops.push(MemberOp::Clear);
                Ok(())
            }
            ItemChange::Delete(Path::Indexed {
                field: DictionaryField::DistributionlistMembersMember,
                index,
            }) => {
                self.ops.push(MemberOp::Remove(index.to_string()));
                Ok(())
            }
            ItemChange::Delete(Path::Field(UnindexedField::ContactsDisplayName)) => {
                Err(ItemError::InvalidPropertySet)
            }
            ItemChange::Set {
                path: Path::Field(UnindexedField::ItemImportance),
                ..
            }
            | ItemChange::Delete(Path::Field(UnindexedField::ItemImportance)) => Ok(()),
            ItemChange::Set { path, value } => self.item_change(ItemChange::Set {
                path: path.clone(),
                value: as_contact(value)?,
            }),
            ItemChange::Append { path, value } => self.item_change(ItemChange::Append {
                path: path.clone(),
                value: as_contact(value)?,
            }),
            ItemChange::Delete(path) => self.item_change(ItemChange::Delete(path.clone())),
        }
    }

    fn removes(&self, contacts: &Contacts, uri: &str) -> bool {
        !contacts.view().is_delegate()
            && self.ops.iter().any(
                |op| matches!(op, MemberOp::Remove(key) if MemberKey::new(key) == MemberKey::new(uri)),
            )
    }

    pub fn apply(&self, contacts: &Contacts, card: &mut VCard) -> Result<(), ItemError> {
        if let Some(edit) = &self.item {
            edit.apply(card).map_err(edit_error)?;
        }
        let resolver = (!self.ops.is_empty())
            .then(|| MemberResolver::new(&contacts.resources, contacts.view(), card));
        let keeps = |uri: &str| {
            resolver
                .as_ref()
                .is_some_and(|resolver| resolver.keeps_on_save(uri))
        };
        let members = resolver.is_some().then(|| {
            let mut uris = contact_group_members(card)
                .map(str::to_string)
                .collect::<Vec<_>>();
            let mut removed = HashSet::new();
            for op in &self.ops {
                match op {
                    MemberOp::Clear => {
                        removed.clear();
                        uris.clear();
                    }
                    MemberOp::Append(added) => {
                        remove_members(&mut uris, &mut removed);
                        uris.extend(added.iter().cloned());
                    }
                    MemberOp::Remove(key) => {
                        removed.insert(MemberKey::new(key));
                    }
                }
            }
            remove_members(&mut uris, &mut removed);
            uris.retain(|uri| !keeps(uri));
            let keep = {
                let mut seen = HashSet::with_capacity(uris.len());
                uris.iter()
                    .map(|uri| seen.insert(MemberKey::new(uri)))
                    .collect::<Vec<_>>()
            };
            let mut keep = keep.into_iter();
            uris.retain(|_| keep.next().unwrap_or_default());
            uris
        });
        patch_distlist(
            card,
            self.display_name.as_deref().or(self.subject.as_deref()),
            members.as_deref(),
            &|uri| keeps(uri) && !self.removes(contacts, uri),
        );
        Ok(())
    }

    fn item_change(&mut self, change: ItemChange<'_>) -> Result<(), ItemError> {
        self.item
            .get_or_insert_default()
            .change(&change)
            .map_err(edit_error)
    }
}

enum MemberKey<'x> {
    Mailto(&'x str),
    Other(&'x str),
}

impl<'x> MemberKey<'x> {
    fn new(uri: &'x str) -> Self {
        mailto_address(uri).map_or(MemberKey::Other(uri), MemberKey::Mailto)
    }
}

impl Hash for MemberKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            MemberKey::Mailto(address) => {
                state.write_u8(0);
                for byte in address.bytes() {
                    state.write_u8(byte.to_ascii_lowercase());
                }
                state.write_u8(0xff);
            }
            MemberKey::Other(uri) => {
                state.write_u8(1);
                uri.hash(state);
            }
        }
    }
}

impl PartialEq for MemberKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MemberKey::Mailto(left), MemberKey::Mailto(right)) => left.eq_ignore_ascii_case(right),
            (MemberKey::Other(left), MemberKey::Other(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for MemberKey<'_> {}

fn remove_members(uris: &mut Vec<String>, removed: &mut HashSet<MemberKey<'_>>) {
    if !removed.is_empty() {
        uris.retain(|uri| !removed.contains(&MemberKey::new(uri)));
        removed.clear();
    }
}

fn name(value: Option<&str>) -> Result<String, ItemError> {
    value
        .map(str::to_string)
        .ok_or(ItemError::InvalidPropertySet)
}

fn as_contact<'x>(value: &Item<'x>) -> Result<Item<'x>, ItemError> {
    item_fields_of(value).map(contact_with)
}

fn item_fields_of<'v, 'x>(value: &'v Item<'x>) -> Result<&'v ItemFields<'x>, ItemError> {
    match value {
        Item::DistributionList(list) => Ok(&list.item),
        Item::Contact(contact) => Ok(&contact.item),
        Item::Item(item) => Ok(item),
        _ => Err(ItemError::InvalidPropertySet),
    }
}

fn contact_with<'x>(item: &ItemFields<'x>) -> Item<'x> {
    Item::Contact(Box::new(ContactItem {
        item: item.clone(),
        ..Default::default()
    }))
}

pub(super) fn contact_change<'c, 'x>(change: &'c ItemChange<'x>) -> Cow<'c, ItemChange<'x>> {
    match change {
        ItemChange::Set {
            path,
            value: Item::Item(item),
        } => Cow::Owned(ItemChange::Set {
            path: path.clone(),
            value: contact_with(item),
        }),
        ItemChange::Append {
            path,
            value: Item::Item(item),
        } => Cow::Owned(ItemChange::Append {
            path: path.clone(),
            value: contact_with(item),
        }),
        change => Cow::Borrowed(change),
    }
}

fn list_of<'v, 'x>(value: &'v Item<'x>) -> Result<&'v DistributionListItem<'x>, ItemError> {
    match value {
        Item::DistributionList(list) => Ok(list),
        _ => Err(ItemError::InvalidPropertySet),
    }
}

fn list_members(
    contacts: &Contacts,
    list: &DistributionListItem<'_>,
) -> Result<Vec<String>, ItemError> {
    member_uris(
        contacts,
        list.list
            .members
            .as_ref()
            .map_or(&[][..], |members| members.0.as_slice()),
    )
}

fn member_uris(contacts: &Contacts, members: &[Member<'_>]) -> Result<Vec<String>, ItemError> {
    members
        .iter()
        .map(|member| member_uri(contacts, member))
        .collect()
}

fn member_uri(contacts: &Contacts, member: &Member<'_>) -> Result<String, ItemError> {
    let mailbox = member
        .fields
        .mailbox
        .as_ref()
        .ok_or(ItemError::InvalidMailbox)?;
    if let Some(id) = mailbox.item_id.as_deref() {
        return match decode_item_id(id) {
            Some((GroupwareKind::Contact, account, item)) if account == contacts.account_id => {
                if contacts.view().is_delegate() && contacts.check(account, item).is_err() {
                    return Err(ItemError::InvalidMailbox);
                }
                contacts
                    .resources
                    .item_by_id(item.document_id)
                    .and_then(|cached| cached.uid())
                    .map(card_uri)
                    .ok_or(ItemError::InvalidMailbox)
            }
            _ => Err(ItemError::InvalidMailbox),
        };
    }
    mailbox
        .email_address
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(mailto_uri)
        .ok_or(ItemError::InvalidMailbox)
}
