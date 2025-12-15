/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ImapContext;
use crate::{
    core::{MailboxId, SelectedMailbox, Session, SessionData},
    spawn_op,
};
use common::{ipc::PushNotification, listener::SessionStream, storage::index::ObjectIndexBuilder};
use directory::Permission;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    mailbox::{JUNK_ID, TRASH_ID, UidMailbox},
    message::{
        copy::{CopyMessageError, EmailCopy},
        ingest::EmailIngest,
        metadata::MessageData,
    },
};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse, protocol::copy_move::Arguments,
    receiver::Request,
};
use std::{sync::Arc, time::Instant};
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, VanishedCollection},
    type_state::{DataType, StateChange},
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_copy_move(
        &mut self,
        request: Request<Command>,
        is_move: bool,
        is_uid: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(if is_move {
            Permission::ImapMove
        } else {
            Permission::ImapCopy
        })?;

        let op_start = Instant::now();
        let arguments = request.parse_copy_move(self.is_utf8)?;
        let (data, src_mailbox) = self.state.mailbox_state();
        let is_qresync = self.is_qresync;

        spawn_op!(data, {
            // Refresh mailboxes
            data.synchronize_mailboxes(false)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            // Make sure the mailbox exists.
            let dest_mailbox =
                if let Some(mailbox) = data.get_mailbox_by_name(&arguments.mailbox_name) {
                    mailbox
                } else {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Destination mailbox does not exist.")
                        .code(ResponseCode::TryCreate)
                        .id(arguments.tag));
                };

            // Check that the destination mailbox is not the same as the source mailbox.
            if src_mailbox.id.account_id == dest_mailbox.account_id
                && src_mailbox.id.mailbox_id == dest_mailbox.mailbox_id
            {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Source and destination mailboxes are the same.")
                    .code(ResponseCode::Cannot)
                    .id(arguments.tag));
            }

            data.copy_move(
                arguments,
                src_mailbox,
                dest_mailbox,
                is_move,
                is_uid,
                is_qresync,
                op_start,
            )
            .await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn copy_move(
        &self,
        arguments: Arguments,
        src_mailbox: Arc<SelectedMailbox>,
        dest_mailbox: MailboxId,
        is_move: bool,
        is_uid: bool,
        is_qresync: bool,
        op_start: Instant,
    ) -> trc::Result<()> {
        self.synchronize_messages(&src_mailbox)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert IMAP ids to JMAP ids.
        let ids = src_mailbox
            .sequence_to_ids(&arguments.sequence_set, is_uid)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        if ids.is_empty() {
            trc::event!(
                Imap(if is_move {
                    trc::ImapEvent::Move
                } else {
                    trc::ImapEvent::Copy
                }),
                SpanId = self.session_id,
                Source = src_mailbox.id.account_id,
                Details = trc::Value::None,
                Uid = trc::Value::None,
                AccountId = dest_mailbox.account_id,
                MailboxId = dest_mailbox.mailbox_id,
                Elapsed = op_start.elapsed()
            );

            return self
                .write_bytes(
                    StatusResponse::ok(if is_move {
                        "No messages were moved."
                    } else {
                        "No messages were copied."
                    })
                    .with_tag(arguments.tag)
                    .into_bytes(),
                )
                .await;
        }

        // Verify that the user can delete messages from the source mailbox.
        if is_move
            && !self
                .check_mailbox_acl(
                    src_mailbox.id.account_id,
                    src_mailbox.id.mailbox_id,
                    Acl::RemoveItems,
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(concat!(
                    "You do not have the required permissions to ",
                    "remove messages from the source mailbox."
                ))
                .code(ResponseCode::NoPerm)
                .id(arguments.tag));
        }

        // Verify that the user can append messages to the destination mailbox.
        let dest_mailbox_id = dest_mailbox.mailbox_id;
        if !self
            .check_mailbox_acl(dest_mailbox.account_id, dest_mailbox_id, Acl::AddItems)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(concat!(
                    "You do not have the required permissions to ",
                    "add messages to the destination mailbox."
                ))
                .code(ResponseCode::NoPerm)
                .id(arguments.tag));
        }

        let mut response = StatusResponse::completed(if is_move {
            Command::Move(is_uid)
        } else {
            Command::Copy(is_uid)
        });
        let mut did_move = false;
        let mut copied_ids = Vec::with_capacity(ids.len());
        let access_token = self
            .server
            .get_access_token(dest_mailbox.account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        if src_mailbox.id.account_id == dest_mailbox.account_id {
            // Mailboxes are in the same account
            let account_id = src_mailbox.id.account_id;
            let dest_mailbox_id = UidMailbox::new_unassigned(dest_mailbox_id);
            let mut batch = BatchBuilder::new();

            for (id, imap_id) in ids {
                // Obtain mailbox tags
                let data_ = if let Some(result) = self
                    .get_message_data(account_id, id)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
                {
                    result
                } else {
                    continue;
                };

                // Deserialize
                let data = data_
                    .to_unarchived::<MessageData>()
                    .imap_ctx(&arguments.tag, trc::location!())?;

                // Make sure the message still belongs to this mailbox
                if !data
                    .inner
                    .mailboxes
                    .iter()
                    .any(|mailbox| mailbox.mailbox_id == src_mailbox.id.mailbox_id)
                {
                    continue;
                }

                // If the message is already in the destination mailbox, skip it.
                if let Some(mailbox) = data
                    .inner
                    .mailboxes
                    .iter()
                    .find(|mailbox| mailbox.mailbox_id == dest_mailbox_id.mailbox_id)
                {
                    copied_ids.push((imap_id.uid, mailbox.uid.to_native()));

                    if is_move {
                        let mut new_data = data.inner.to_builder();
                        new_data.remove_mailbox(src_mailbox.id.mailbox_id);
                        batch
                            .with_account_id(account_id)
                            .with_collection(Collection::Email)
                            .with_document(id)
                            .custom(
                                ObjectIndexBuilder::new()
                                    .with_current(data)
                                    .with_changes(new_data.seal()),
                            )
                            .imap_ctx(&arguments.tag, trc::location!())?
                            .log_vanished_item(
                                VanishedCollection::Email,
                                (src_mailbox.id.mailbox_id, imap_id.uid),
                            )
                            .commit_point();
                        did_move = true;
                    }

                    continue;
                }

                // Prepare changes
                let mut new_data = data.inner.to_builder();

                // Add destination folder
                new_data.add_mailbox(dest_mailbox_id);
                if is_move {
                    new_data.remove_mailbox(src_mailbox.id.mailbox_id);
                }

                // Assign IMAP UIDs
                let ids = self
                    .server
                    .assign_email_ids(
                        account_id,
                        new_data
                            .mailboxes
                            .iter()
                            .filter(|m| m.uid == 0)
                            .map(|m| m.mailbox_id),
                        false,
                    )
                    .await
                    .caused_by(trc::location!())?;

                for (uid_mailbox, uid) in new_data
                    .mailboxes
                    .iter_mut()
                    .filter(|m| m.uid == 0)
                    .zip(ids)
                {
                    copied_ids.push((imap_id.uid, uid));
                    uid_mailbox.uid = uid;
                }

                // Prepare write batch
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email)
                    .with_document(id)
                    .custom(
                        ObjectIndexBuilder::new()
                            .with_current(data)
                            .with_changes(new_data.seal()),
                    )
                    .imap_ctx(&arguments.tag, trc::location!())?;
                if is_move {
                    batch.log_vanished_item(
                        VanishedCollection::Email,
                        (src_mailbox.id.mailbox_id, imap_id.uid),
                    );
                }

                // Add message to training queue
                if dest_mailbox_id.mailbox_id == JUNK_ID {
                    self.server
                        .add_account_spam_sample(&mut batch, account_id, id, true, self.session_id)
                        .await
                        .imap_ctx(&arguments.tag, trc::location!())?;
                } else if src_mailbox.id.mailbox_id == JUNK_ID
                    && dest_mailbox_id.mailbox_id != TRASH_ID
                {
                    self.server
                        .add_account_spam_sample(&mut batch, account_id, id, false, self.session_id)
                        .await
                        .imap_ctx(&arguments.tag, trc::location!())?;
                }

                batch.commit_point();

                // Update changelog
                if is_move {
                    did_move = true;
                }
            }

            // Write changes
            self.server
                .commit_batch(batch)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
        } else {
            // Obtain quota for target account
            let src_account_id = src_mailbox.id.account_id;
            let mut dest_change_id = None;
            let dest_account_id = dest_mailbox.account_id;
            let resource_token = access_token.as_resource_token();
            let mut destroy_ids = RoaringBitmap::new();
            let cache = self
                .server
                .get_cached_messages(src_account_id)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            for (id, imap_id) in ids {
                match self
                    .server
                    .copy_message(
                        src_account_id,
                        id,
                        &resource_token,
                        vec![dest_mailbox_id],
                        cache
                            .email_by_id(&id)
                            .map(|e| cache.expand_keywords(e).collect())
                            .unwrap_or_default(),
                        None,
                        self.session_id,
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
                {
                    Ok(email) => {
                        dest_change_id = email.change_id.into();
                        if let Some(assigned_uid) = email.imap_uids.first() {
                            debug_assert!(*assigned_uid > 0);
                            copied_ids.push((imap_id.uid, *assigned_uid));
                        }
                    }
                    Err(err) => {
                        match err {
                            CopyMessageError::OverQuota => {
                                response.rtype = ResponseType::No;
                                response.code = Some(ResponseCode::OverQuota);
                                response.message = "Mailbox quota exceeded".into();
                            }
                            CopyMessageError::NotFound => (),
                        }
                        continue;
                    }
                };

                if is_move {
                    destroy_ids.insert(id);
                }
            }

            // Untag or delete emails
            if !destroy_ids.is_empty() {
                let mut batch = BatchBuilder::new();
                self.email_untag_or_delete(
                    src_account_id,
                    src_mailbox.id.mailbox_id,
                    &destroy_ids,
                    &mut batch,
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

                self.server
                    .commit_batch(batch)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;

                did_move = true;
            }

            // Broadcast changes on destination account
            if let Some(change_id) = dest_change_id {
                self.server
                    .broadcast_push_notification(PushNotification::StateChange(
                        StateChange::new(dest_account_id)
                            .with_change_id(change_id)
                            .with_change(DataType::Email)
                            .with_change(DataType::Thread)
                            .with_change(DataType::Mailbox),
                    ))
                    .await;
            }
        }

        // Map copied JMAP Ids to IMAP UIDs in the destination folder.
        if copied_ids.is_empty() {
            return if response.rtype != ResponseType::Ok {
                Err(trc::ImapEvent::Error
                    .into_err()
                    .details(response.message)
                    .ctx_opt(trc::Key::Code, response.code)
                    .id(arguments.tag))
            } else {
                trc::event!(
                    Imap(if is_move {
                        trc::ImapEvent::Move
                    } else {
                        trc::ImapEvent::Copy
                    }),
                    SpanId = self.session_id,
                    Source = src_mailbox.id.account_id,
                    Details = trc::Value::None,
                    Uid = trc::Value::None,
                    AccountId = dest_mailbox.account_id,
                    MailboxId = dest_mailbox.mailbox_id,
                    Elapsed = op_start.elapsed()
                );

                self.write_bytes(
                    StatusResponse::ok(if is_move {
                        "No messages were moved."
                    } else {
                        "No messages were copied."
                    })
                    .with_tag(arguments.tag)
                    .into_bytes(),
                )
                .await
            };
        }

        // Prepare response
        let uid_validity = self
            .mailbox_state(&dest_mailbox)
            .map(|m| m.uid_validity as u32)
            .unwrap_or_default();

        let mut src_uids = Vec::with_capacity(copied_ids.len());
        let mut dest_uids = Vec::with_capacity(copied_ids.len());
        for (src_uid, dest_uid) in copied_ids {
            src_uids.push(src_uid);
            dest_uids.push(dest_uid);
        }
        src_uids.sort_unstable();
        dest_uids.sort_unstable();

        trc::event!(
            Imap(if is_move {
                trc::ImapEvent::Move
            } else {
                trc::ImapEvent::Copy
            }),
            SpanId = self.session_id,
            Source = src_mailbox.id.account_id,
            Details = src_uids
                .iter()
                .map(|r| trc::Value::from(*r))
                .collect::<Vec<_>>(),
            AccountId = dest_mailbox.account_id,
            MailboxId = dest_mailbox.mailbox_id,
            Uid = dest_uids
                .iter()
                .map(|r| trc::Value::from(*r))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        let response = if is_move {
            self.write_bytes(
                StatusResponse::ok("Copied UIDs")
                    .with_code(ResponseCode::CopyUid {
                        uid_validity,
                        src_uids,
                        dest_uids,
                    })
                    .into_bytes(),
            )
            .await?;

            if did_move {
                // Resynchronize source mailbox on a successful move
                self.write_mailbox_changes(&src_mailbox, is_qresync)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;
            }

            response.with_tag(arguments.tag).into_bytes()
        } else {
            response
                .with_tag(arguments.tag)
                .with_code(ResponseCode::CopyUid {
                    uid_validity,
                    src_uids,
                    dest_uids,
                })
                .into_bytes()
        };

        self.write_bytes(response).await
    }

    pub async fn get_message_data(
        &self,
        account_id: u32,
        id: u32,
    ) -> trc::Result<Option<Archive<AlignedBytes>>> {
        if let Some(data) = self
            .server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Email,
                id,
            ))
            .await?
        {
            Ok(Some(data))
        } else {
            trc::event!(
                Store(trc::StoreEvent::NotFound),
                AccountId = account_id,
                Collection = Collection::Email,
                MessageId = id,
                SpanId = self.session_id,
                Details = "Message not found"
            );

            Ok(None)
        }
    }
}
