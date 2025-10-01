/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ImapContext;
use crate::{
    core::{Session, SessionData},
    spawn_op,
};
use common::listener::SessionStream;
use directory::Permission;
use email::mailbox::destroy::{MailboxDestroy, MailboxDestroyError};
use imap_proto::{
    Command, ResponseCode, StatusResponse, protocol::delete::Arguments, receiver::Request,
};
use std::time::Instant;

impl<T: SessionStream> Session<T> {
    pub async fn handle_delete(&mut self, requests: Vec<Request<Command>>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapDelete)?;

        let data = self.state.session_data();
        let is_utf8 = self.is_utf8;

        spawn_op!(data, {
            for request in requests {
                match request.parse_delete(is_utf8) {
                    Ok(argument) => match data.delete_folder(argument).await {
                        Ok(response) => {
                            data.write_bytes(response.into_bytes()).await?;
                        }
                        Err(error) => {
                            data.write_error(error).await?;
                        }
                    },
                    Err(response) => data.write_error(response).await?,
                }
            }

            Ok(())
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn delete_folder(&self, arguments: Arguments) -> trc::Result<StatusResponse> {
        let op_start = Instant::now();

        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate mailbox
        let (account_id, mailbox_id) =
            if let Some(mailbox) = self.get_mailbox_by_name(&arguments.mailbox_name) {
                (mailbox.account_id, mailbox.mailbox_id)
            } else {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::TryCreate)
                    .id(arguments.tag));
            };

        // Delete message
        let access_token = self
            .get_access_token()
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        if let Err(err) = self
            .server
            .mailbox_destroy(account_id, mailbox_id, &access_token, true)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
        {
            let (code, message) = match err {
                MailboxDestroyError::CannotDestroy => {
                    (ResponseCode::NoPerm, "You cannot delete system mailboxes")
                }
                MailboxDestroyError::Forbidden => (
                    ResponseCode::NoPerm,
                    "You do not have enough permissions to delete this mailbox",
                ),
                MailboxDestroyError::HasChildren => {
                    (ResponseCode::HasChildren, "Mailbox has children")
                }
                MailboxDestroyError::HasEmails => (ResponseCode::HasChildren, "Mailbox has emails"),
                MailboxDestroyError::NotFound => (ResponseCode::NonExistent, "Mailbox not found"),
                MailboxDestroyError::AssertionFailed => (
                    ResponseCode::Cannot,
                    "Another process is accessing this mailbox",
                ),
            };

            return Err(trc::ImapEvent::Error
                .into_err()
                .details(message)
                .code(code)
                .id(arguments.tag));
        }

        // Update mailbox cache
        for account in self.mailboxes.lock().iter_mut() {
            if account.account_id == account_id {
                account.mailbox_names.remove(&arguments.mailbox_name);
                account.mailbox_state.remove(&mailbox_id);
                break;
            }
        }

        trc::event!(
            Imap(trc::ImapEvent::DeleteMailbox),
            SpanId = self.session_id,
            MailboxName = arguments.mailbox_name,
            AccountId = account_id,
            MailboxId = mailbox_id,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("Mailbox deleted.").with_tag(arguments.tag))
    }
}
