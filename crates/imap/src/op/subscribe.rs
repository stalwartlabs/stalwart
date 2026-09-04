/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use compact_str::CompactString;

use super::ImapContext;
use crate::core::{Session, SessionData};
use common::network::SessionStream;
use email::mailbox::merge_subscription;
use imap_proto::{Command, ResponseCode, StatusResponse, receiver::Request};
use registry::schema::enums::Permission;
use std::time::Instant;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder},
};
use tokio::sync::OwnedSemaphorePermit;
use types::collection::Collection;

impl<T: SessionStream> Session<T> {
    pub async fn handle_subscribe(
        &mut self,
        request: Request<Command>,
        is_subscribe: bool,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapSubscribe)?;

        let op_start = Instant::now();
        let arguments = request.parse_subscribe(self.is_utf8)?;
        let data = self.state.session_data();

        let response = data
            .subscribe_folder(
                arguments.tag,
                arguments.mailbox_name,
                is_subscribe,
                op_start,
            )
            .await?;

        data.write_bytes(response.into_bytes()).await
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn subscribe_folder(
        &self,
        tag: CompactString,
        mailbox_name: CompactString,
        subscribe: bool,
        op_start: Instant,
    ) -> trc::Result<StatusResponse> {
        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&tag, trc::location!())?;

        // Validate mailbox
        let (account_id, mailbox_id) = match self.get_mailbox_by_name(&mailbox_name) {
            Some(mailbox) => (mailbox.account_id, mailbox.mailbox_id),
            None => {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent)
                    .id(tag)
                    .caused_by(trc::location!()));
            }
        };

        // Verify if mailbox is already subscribed/unsubscribed
        if self
            .mailboxes
            .lock()
            .iter()
            .find(|account| account.account_id == account_id)
            .is_some_and(|account| account.is_subscribed(mailbox_id, self.account_id) == subscribe)
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(if subscribe {
                    "Mailbox is already subscribed."
                } else {
                    "Mailbox is already unsubscribed."
                })
                .id(tag));
        }

        // Obtain mailbox
        let mailbox_ = self
            .server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                account_id,
                Collection::Mailbox,
                mailbox_id,
            ))
            .await
            .imap_ctx(&tag, trc::location!())?
            .ok_or_else(|| {
                trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent)
                    .id(tag.clone())
                    .caused_by(trc::location!())
            })?;
        let mailbox = mailbox_
            .to_unarchived::<email::mailbox::Mailbox>()
            .imap_ctx(&tag, trc::location!())?;

        if mailbox.inner.is_subscribed(self.account_id) != subscribe {
            // Build batch
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Mailbox)
                .with_document(mailbox_id);
            merge_subscription(&mut batch, self.account_id, subscribe);
            self.server
                .commit_batch(batch)
                .await
                .imap_ctx(&tag, trc::location!())?;
        }

        trc::event!(
            Imap(if subscribe {
                trc::ImapEvent::Subscribe
            } else {
                trc::ImapEvent::Unsubscribe
            }),
            SpanId = self.session_id,
            AccountId = account_id,
            MailboxId = mailbox_id,
            MailboxName = mailbox_name,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok(if subscribe {
            "Mailbox subscribed."
        } else {
            "Mailbox unsubscribed."
        })
        .with_tag(tag))
    }
}
