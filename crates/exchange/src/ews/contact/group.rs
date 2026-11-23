/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Contacts;
use crate::{
    contact_group::{GroupMember, MemberCards, MemberResolver},
    ews::{
        directory::ROUTING_SMTP,
        groupware::{
            change_id_of, contact_content,
            items::{GroupwareRef, LoadedItem},
        },
        item::ItemError,
    },
};
use calcard::vcard::VCard;
use common::Server;
use exchange_proto::{
    convert::vcard::contact_group_members,
    ews::{
        schema::{MailboxType, MemberStatus},
        types::{
            address::EmailAddress,
            item::contact::{Member, MemberFields},
        },
    },
};
use groupware::contact::ContactCardContent;
use std::borrow::Cow;
use trc::AddContext;
use types::{collection::Collection, field::ContactField};

pub(crate) struct OpenedCard {
    pub loaded: LoadedItem,
    pub card: VCard,
}

pub(crate) struct GroupMembers<'x> {
    members: Vec<GroupMember<'x>>,
    cards: MemberCards,
    pub complete: bool,
}

impl Contacts {
    pub async fn open_card(
        &self,
        server: &Server,
        item: GroupwareRef,
    ) -> trc::Result<Result<OpenedCard, ItemError>> {
        let (archive, content) = server
            .archive_and_field(
                self.account_id,
                Collection::ContactCard,
                item.document_id,
                ContactField::Content.into(),
            )
            .await
            .caused_by(trc::location!())?;
        let (Some(archive), Some(content)) = (archive, content) else {
            return Ok(Err(ItemError::NotFound));
        };
        let card = match content.deserialize::<ContactCardContent>() {
            Ok(content) => content.card,
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                return Ok(Err(ItemError::Unparsable));
            }
        };
        let Ok(content) = contact_content(&card, &self.options()) else {
            return Ok(Err(ItemError::Unparsable));
        };
        Ok(Ok(OpenedCard {
            loaded: LoadedItem {
                item,
                change_id: change_id_of(archive.version),
                content: Some(content),
                occurrences: None,
                mime: None,
            },
            card,
        }))
    }

    pub async fn group_members<'x>(
        &self,
        server: &Server,
        card: &'x VCard,
        limit: usize,
    ) -> trc::Result<GroupMembers<'x>> {
        let resolver = MemberResolver::new(&self.resources, self.view(), card);
        let mut uris = contact_group_members(card)
            .filter_map(|uri| GroupMember::of(&resolver, uri))
            .filter(|member| member.is_readable(self.view()));
        let members = uris.by_ref().take(limit).collect::<Vec<_>>();
        let complete = uris.next().is_none();
        let cards = MemberCards::read(
            server,
            self.account_id,
            members.iter().filter_map(GroupMember::document_id),
        )
        .await?;
        Ok(GroupMembers {
            members,
            cards,
            complete,
        })
    }
}

impl<'x> GroupMembers<'x> {
    pub fn mailboxes<'s>(
        &'s self,
        contacts: &'s Contacts,
    ) -> impl Iterator<Item = (&'x str, EmailAddress<'s>)> + 's {
        self.members.iter().filter_map(move |member| match *member {
            GroupMember::OneOff { uri, email } => Some((
                uri,
                EmailAddress {
                    name: Some(Cow::Borrowed(email)),
                    email_address: Some(Cow::Borrowed(email)),
                    routing_type: Some(Cow::Borrowed(ROUTING_SMTP)),
                    mailbox_type: Some(MailboxType::OneOff),
                    ..Default::default()
                },
            )),
            GroupMember::Card {
                uri,
                document_id,
                address_book,
            } => {
                let card = self.cards.get(document_id)?;
                let email = (!card.email.is_empty()).then_some(card.email.as_str());
                Some((
                    uri,
                    EmailAddress {
                        name: Some(Cow::Borrowed(card.name.as_str())),
                        email_address: email.map(Cow::Borrowed),
                        routing_type: email.map(|_| Cow::Borrowed(ROUTING_SMTP)),
                        mailbox_type: Some(if card.group {
                            MailboxType::PrivateDL
                        } else {
                            MailboxType::Contact
                        }),
                        item_id: Some(Box::new(contacts.unversioned_id(GroupwareRef {
                            container: address_book,
                            document_id,
                        }))),
                        ..Default::default()
                    },
                ))
            }
        })
    }

    pub fn members<'s>(&'s self, contacts: &'s Contacts) -> impl Iterator<Item = Member<'s>> + 's {
        self.mailboxes(contacts).map(|(uri, mailbox)| Member {
            key: Some(Cow::Borrowed(uri)),
            fields: MemberFields {
                mailbox: Some(mailbox),
                status: Some(MemberStatus::Normal),
            },
        })
    }
}
