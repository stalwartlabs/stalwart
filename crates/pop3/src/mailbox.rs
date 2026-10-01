/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::Session;
use common::network::SessionStream;
use email::{
    cache::{MessageCacheFetch, mailbox::MailboxCacheAccess},
    mailbox::INBOX_ID,
};
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

        if cache.emails.is_empty() {
            return Ok(Mailbox::default());
        }

        let uid_validity = cache
            .mailbox_by_role(&SpecialUse::Inbox)
            .map(|x| x.uid_validity)
            .unwrap_or_default();

        // Sort by UID
        let mut messages = cache
            .emails
            .iter()
            .filter_map(|message| {
                message
                    .mailboxes()
                    .iter()
                    .find(|m| m.mailbox_id == INBOX_ID)
                    .map(|m| Message {
                        id: message.document_id(),
                        uid: m.uid,
                        size: message.size(),
                        deleted: false,
                    })
            })
            .collect::<Vec<_>>();
        messages.sort_unstable_by_key(|message| message.uid);
        messages.dedup_by_key(|message| message.uid);

        Ok(Mailbox {
            total: messages.len() as u32,
            size: messages
                .iter()
                .fold(0u32, |size, message| size.wrapping_add(message.size)),
            messages,
            uid_validity,
            account_id,
        })
    }
}
