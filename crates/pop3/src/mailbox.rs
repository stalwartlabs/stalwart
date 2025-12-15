/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Session;
use common::listener::SessionStream;
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::INBOX_ID,
};
use std::collections::BTreeMap;
use trc::AddContext;
use types::special_use::SpecialUse;

#[derive(Default)]
pub struct Mailbox {
    pub messages: Vec<Message>,
    pub account_id: u32,
    pub uid_validity: u32,
    pub total: u32,
    pub size: u32,
}

pub struct Message {
    pub id: u32,
    pub uid: u32,
    pub size: u32,
    pub deleted: bool,
}

impl<T: SessionStream> Session<T> {
    pub async fn fetch_mailbox(&self, account_id: u32) -> trc::Result<Mailbox> {
        // Obtain UID validity
        let cache = self
            .server
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;

        if cache.emails.items.is_empty() {
            return Ok(Mailbox::default());
        }

        let uid_validity = cache
            .mailbox_by_role(&SpecialUse::Inbox)
            .map(|x| x.uid_validity)
            .unwrap_or_default();

        // Sort by UID
        let message_map = cache
            .emails
            .items
            .iter()
            .filter_map(|message| {
                message
                    .mailboxes
                    .iter()
                    .find(|m| m.mailbox_id == INBOX_ID)
                    .map(|m| (m.uid, (message.document_id, message.size)))
            })
            .collect::<BTreeMap<u32, (u32, u32)>>();

        // Create mailbox
        let mut mailbox = Mailbox {
            messages: Vec::with_capacity(message_map.len()),
            uid_validity,
            account_id,
            ..Default::default()
        };
        for (uid, (id, size)) in message_map {
            mailbox.messages.push(Message {
                id,
                uid,
                size,
                deleted: false,
            });
            mailbox.total += 1;
            mailbox.size += size;
        }

        Ok(mailbox)
    }
}
