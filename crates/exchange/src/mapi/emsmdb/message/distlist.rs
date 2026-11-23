/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::load::{LoadDepth, convert_error};
use crate::{
    contact_group::{
        GroupMember, MemberCards, MemberResolver, book_readable, card_uri, mailto_uri,
    },
    folders::FolderNode,
    identity::directory_ref_from_dn,
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError},
            store::StoreGuids,
        },
        ids::{IdSpace, MapiId},
        nspi::book::directory_entry,
    },
    store::{FolderKind, FolderRef, alias::GroupwareKind},
};
use calcard::vcard::VCard;
use common::GroupwareResources;
use exchange_proto::{
    convert::{
        ConvertError,
        model::{MessageContent, PropBag as ContentBag},
        vcard::{
            AddressType, DistMember, DistTarget, MemberKind, contact_group_members,
            distlist_members, distlist_to_message,
        },
    },
    ids::{Eid, ReplId, entryid::EntryId},
};
use groupware::cache::GroupwareCache;
use std::borrow::Cow;
use trc::AddContext;
use types::collection::SyncCollection;

impl RopContext<'_, '_> {
    pub(super) async fn group_message(
        &mut self,
        account_id: u32,
        guids: StoreGuids,
        card: &VCard,
        depth: LoadDepth,
    ) -> Result<Result<MessageContent, ConvertError>, RopError> {
        if depth == LoadDepth::Envelope {
            return Ok(distlist_to_message(card, None));
        }
        let server = self.request.server;
        let resources = server
            .fetch_groupware_resources(account_id, account_id, SyncCollection::AddressBook)
            .await
            .caused_by(trc::location!())?;
        let rights = self.view_rights(account_id).await?;
        let resolver = MemberResolver::new(&resources, &rights, card);
        let slots = contact_group_members(card)
            .filter_map(|uri| GroupMember::of(&resolver, uri))
            .filter(|member| member.is_readable(&rights))
            .collect::<Vec<_>>();
        let cards = MemberCards::read(
            server,
            account_id,
            slots.iter().filter_map(GroupMember::document_id),
        )
        .await?;
        let view = self.mailbox(account_id).await?;
        let mut members = Vec::with_capacity(slots.len());
        for slot in slots {
            match slot {
                GroupMember::OneOff { email, .. } => members.push(DistMember {
                    target: DistTarget::OneOff,
                    name: Cow::Borrowed(email),
                    address_type: AddressType::Smtp,
                    email: Cow::Borrowed(email),
                }),
                GroupMember::Card {
                    document_id,
                    address_book,
                    ..
                } => {
                    let Some(member) = cards.get(document_id) else {
                        continue;
                    };
                    let EntryId::Message(entry) = guids.message_entry_id(
                        MapiId::new(IdSpace::AddressBook, address_book).to_client(&view.exchange),
                        view.client_item(
                            FolderRef {
                                kind: FolderKind::AddressBook,
                                id: address_book,
                            },
                            document_id,
                        ),
                    ) else {
                        continue;
                    };
                    members.push(DistMember {
                        target: DistTarget::Message {
                            kind: if member.group {
                                MemberKind::PersonalList
                            } else {
                                MemberKind::Contact
                            },
                            entry,
                        },
                        name: Cow::Borrowed(member.name.as_str()),
                        address_type: AddressType::Smtp,
                        email: Cow::Borrowed(member.email.as_str()),
                    });
                }
            }
        }
        Ok(distlist_to_message(card, Some(&members)))
    }

    pub(super) async fn group_uris(
        &mut self,
        account_id: u32,
        resources: &GroupwareResources,
        props: &ContentBag,
        changes: Option<&ContentBag>,
    ) -> Result<Vec<String>, RopError> {
        let members =
            distlist_members(props, changes).map_err(|err| RopError::Code(convert_error(err)))?;
        let guids = self.store_guids(account_id).await?;
        let view = self.mailbox(account_id).await?;
        let rights = self.view_rights(account_id).await?;
        let mut uris = Vec::with_capacity(members.len());
        for member in &members {
            let email = match &member.target {
                DistTarget::Message { entry, .. } => {
                    if let Some(uid) = (entry.provider == guids.mailbox
                        && entry.message.guid == guids.replica)
                        .then(|| {
                            MapiId::from_eid(Eid {
                                replid: ReplId::LOCAL,
                                counter: entry.message.counter,
                            })
                        })
                        .flatten()
                        .and_then(|id| match id.space {
                            IdSpace::Contact => Some(id.id),
                            IdSpace::Email => MapiId::from_eid(Eid {
                                replid: ReplId::LOCAL,
                                counter: entry.folder.counter,
                            })
                            .and_then(|folder| folder.to_folder(&view.exchange))
                            .and_then(|folder| match folder {
                                FolderNode::Stored(FolderRef {
                                    kind: FolderKind::AddressBook,
                                    id: address_book,
                                }) => view.exchange.groupware_document(
                                    GroupwareKind::Contact.folder(address_book),
                                    id.id,
                                ),
                                _ => None,
                            }),
                            _ => None,
                        })
                        .and_then(|document_id| resources.item_by_id(document_id))
                        .filter(|item| {
                            item.child_names()
                                .iter()
                                .any(|name| book_readable(&rights, name.parent_id))
                        })
                        .and_then(|item| item.uid())
                    {
                        uris.push(card_uri(uid));
                        continue;
                    }
                    None
                }
                DistTarget::Directory { dn, .. } => self.directory_email(dn).await?,
                DistTarget::OneOff => None,
            };
            let email = match (email, member.address_type) {
                (Some(email), _) => Some(email),
                (None, _) if member.email.is_empty() => None,
                (None, AddressType::Smtp) => Some(member.email.to_string()),
                (None, AddressType::LegacyDn) => {
                    self.directory_email(member.email.as_bytes()).await?
                }
                (None, AddressType::Other) => None,
            };
            if let Some(email) = email {
                uris.push(mailto_uri(&email));
            }
        }
        Ok(uris)
    }

    async fn directory_email(&mut self, dn: &[u8]) -> Result<Option<String>, RopError> {
        match directory_ref_from_dn(dn) {
            Some(principal) => {
                Ok(
                    directory_entry(self.request.server, self.request.access_token, principal)
                        .await?
                        .map(|entry| entry.smtp.into_string()),
                )
            }
            None => Ok(None),
        }
    }
}
