/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ToModSeq;
use crate::{
    core::{AccountCaches, MailboxId, Session, SessionData},
    op::ImapContext,
    spawn_op,
};
use common::{MessageStoreCache, network::SessionStream};
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::{
        ObjectId,
        status::{Status, StatusItem, StatusItemType},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::time::Instant;
use tokio::sync::OwnedSemaphorePermit;
use types::id::Id;

impl<T: SessionStream> Session<T> {
    pub async fn handle_status(
        &mut self,
        requests: Vec<Request<Command>>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapStatus)?;

        let is_utf8 = self.is_utf8;

        // Parse requests and activate OBJECTID+ if the OBJECTID attribute is requested
        let mut parsed = Vec::with_capacity(requests.len());
        let mut activate = false;
        for request in requests {
            match request.parse_status(is_utf8) {
                Ok(arguments) => {
                    if arguments.items.contains(&Status::ObjectId) {
                        activate = true;
                    }
                    parsed.push(Ok(arguments));
                }
                Err(err) => parsed.push(Err(err)),
            }
        }
        if activate && let Some(enabled) = self.activate_objectid() {
            self.write_bytes(enabled).await?;
        }

        let data = self.state.session_data();

        spawn_op!(permit, data, {
            let mut caches = None;

            for request in parsed {
                match request {
                    Ok(arguments) => {
                        let op_start = Instant::now();
                        let caches = match &mut caches {
                            Some(caches) => caches,
                            None => caches.insert(
                                data.synchronize_mailboxes(false)
                                    .await
                                    .imap_ctx(&arguments.tag, trc::location!())?
                                    .caches,
                            ),
                        };

                        // Fetch status
                        let status = data
                            .status(caches, arguments.mailbox_name, &arguments.items)
                            .await
                            .imap_ctx(&arguments.tag, trc::location!())?;

                        trc::event!(
                            Imap(trc::ImapEvent::Status),
                            SpanId = data.session_id,
                            MailboxName = status.mailbox_name.clone(),
                            Details = arguments
                                .items
                                .iter()
                                .map(|c| trc::Value::from(format!("{c:?}")))
                                .collect::<Vec<_>>(),
                            Elapsed = op_start.elapsed()
                        );

                        let mut buf = Vec::with_capacity(32);
                        status.serialize(&mut buf, is_utf8);
                        data.write_bytes(
                            StatusResponse::completed(Command::Status)
                                .with_tag(arguments.tag)
                                .serialize(buf),
                        )
                        .await?;
                    }
                    Err(err) => data.write_error(err).await?,
                }
            }

            Ok(())
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn status(
        &self,
        caches: &mut AccountCaches,
        mailbox_name: String,
        items: &[Status],
    ) -> trc::Result<StatusItem> {
        // Get mailbox id
        let mailbox = if let Some(mailbox) = self.get_mailbox_by_name(&mailbox_name) {
            mailbox
        } else {
            // Some IMAP clients will try to get the status of a mailbox with the NoSelect flag
            return if mailbox_name == self.server.core.email.shared_folder
                || mailbox_name
                    .split_once('/')
                    .is_some_and(|(base_name, path)| {
                        base_name == self.server.core.email.shared_folder && !path.contains('/')
                    })
            {
                Ok(StatusItem {
                    mailbox_name,
                    items: items
                        .iter()
                        .map(|item| {
                            (
                                *item,
                                match item {
                                    Status::Messages
                                    | Status::Size
                                    | Status::Unseen
                                    | Status::Recent
                                    | Status::Deleted
                                    | Status::HighestModSeq
                                    | Status::DeletedStorage => StatusItemType::Number(0),
                                    Status::UidNext | Status::UidValidity => {
                                        StatusItemType::Number(1)
                                    }
                                    Status::ObjectId => {
                                        StatusItemType::ObjectId(ObjectId::default())
                                    }
                                },
                            )
                        })
                        .collect(),
                })
            } else {
                Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent))
            };
        };

        let cache = caches.fetch(&self.server, mailbox.account_id).await?;

        self.status_in(&cache, mailbox, mailbox_name, items).await
    }

    pub async fn status_in(
        &self,
        cache: &MessageStoreCache,
        mailbox: MailboxId,
        mailbox_name: String,
        items: &[Status],
    ) -> trc::Result<StatusItem> {
        let uid_next = if items.contains(&Status::UidNext) {
            Some(self.uid_next(cache, &mailbox).await?)
        } else {
            None
        };
        let needs_counters = items.iter().any(|item| {
            matches!(
                item,
                Status::Messages
                    | Status::Unseen
                    | Status::Deleted
                    | Status::DeletedStorage
                    | Status::Size
            )
        });

        if needs_counters {
            self.ensure_counters(mailbox.account_id, cache);
        }

        let accounts = self.mailboxes.lock();
        let account = accounts
            .iter()
            .find(|account| account.account_id == mailbox.account_id)
            .ok_or_else(|| {
                trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox does not exist.")
                    .code(ResponseCode::NonExistent)
            })?;
        let counters = if needs_counters {
            account.counters_of(mailbox.mailbox_id)
        } else {
            Default::default()
        };
        let uid_validity = account.uid_validity(mailbox.mailbox_id);

        let is_deferred = |item: &Status| matches!(item, Status::Size | Status::DeletedStorage);

        Ok(StatusItem {
            mailbox_name,
            items: items
                .iter()
                .filter(|item| !is_deferred(item))
                .chain(items.iter().filter(|item| is_deferred(item)))
                .map(|item| {
                    (
                        *item,
                        match item {
                            Status::Messages => StatusItemType::Number(counters.total as u64),
                            Status::UidNext => {
                                StatusItemType::Number(uid_next.unwrap_or_default() as u64)
                            }
                            Status::UidValidity => StatusItemType::Number(uid_validity as u64),
                            Status::Unseen => StatusItemType::Number(counters.unseen as u64),
                            Status::Deleted => StatusItemType::Number(counters.deleted as u64),
                            Status::DeletedStorage => StatusItemType::Number(counters.deleted_size),
                            Status::Size => StatusItemType::Number(counters.size),
                            Status::HighestModSeq => {
                                StatusItemType::Number(cache.emails.change_id.to_modseq())
                            }
                            Status::ObjectId => StatusItemType::ObjectId(ObjectId {
                                mailbox_id: Some(Id::from(mailbox.mailbox_id)),
                                account_id: Some(Id::from(mailbox.account_id)),
                                ..Default::default()
                            }),
                            Status::Recent => StatusItemType::Number(0),
                        },
                    )
                })
                .collect(),
        })
    }
}
