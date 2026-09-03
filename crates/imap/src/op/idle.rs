/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::{AccountCaches, SelectedMailbox, Session, SessionData, State},
    op::ImapContext,
};
use common::{ipc::PushNotification, network::SessionStream};
use email::cache::MessageCacheFetch;
use imap_proto::{
    Command, StatusResponse,
    protocol::{
        Sequence, fetch,
        list::{Attribute, ListItem},
        status::Status,
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use tokio::io::AsyncReadExt;
use trc::AddContext;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

impl<T: SessionStream> Session<T> {
    pub async fn handle_idle(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapIdle)?;

        let op_start = Instant::now();
        let (data, mailbox, types) = match &self.state {
            State::Authenticated { data, .. } => {
                (data.clone(), None, Bitmap::from_iter([DataType::Mailbox]))
            }
            State::Selected { data, mailbox, .. } => (
                data.clone(),
                mailbox.clone().into(),
                Bitmap::from_iter([DataType::Email, DataType::Mailbox, DataType::EmailDelivery]),
            ),
            _ => unreachable!(),
        };
        let is_rev2 = self.version.is_rev2();
        let is_utf8 = self.is_utf8;
        let is_uidonly = self.is_uidonly;
        let use_vanished = self.is_qresync || is_uidonly;

        // Register with push manager
        let mut push_rx = self
            .server
            .subscribe_push_manager(&data.access_token, types)
            .await
            .imap_ctx(&request.tag, trc::location!())?;

        data.seed_mailbox_counters()
            .await
            .imap_ctx(&request.tag, trc::location!())?;

        // Send continuation response
        self.write_bytes(b"+ Idling, send 'DONE' to stop.\r\n".to_vec())
            .await?;

        trc::event!(
            Imap(trc::ImapEvent::IdleStart),
            SpanId = self.session_id,
            Elapsed = op_start.elapsed()
        );

        let op_start = Instant::now();
        let mut buf = vec![0; 4];
        loop {
            tokio::select! {
                result = tokio::time::timeout(self.server.core.imap.timeout_idle, self.stream_rx.read_exact(&mut buf)) => {
                    match result {
                        Ok(Ok(bytes_read)) => {
                            if bytes_read > 0 {
                                if (buf[..bytes_read]).windows(4).any(|w| w == b"DONE") {
                                    trc::event!(Imap(trc::ImapEvent::IdleStop), SpanId = self.session_id, Elapsed = op_start.elapsed());
                                    return self.write_bytes(StatusResponse::completed(Command::Idle)
                                                                    .with_tag(request.tag)
                                                                    .into_bytes()).await;
                                }
                            } else {
                                return Err(trc::NetworkEvent::Closed.into_err().details("IMAP connection closed by client.").id(request.tag));
                            }
                        },
                        Ok(Err(err)) => {
                            return Err(trc::NetworkEvent::ReadError.into_err().reason(err).details("IMAP connection error.").id(request.tag));
                        },
                        Err(_) => {
                            self.write_bytes(&b"* BYE IDLE timed out.\r\n"[..]).await.ok();
                            return Err(trc::NetworkEvent::Timeout.into_err().details("IMAP IDLE timed out.").id(request.tag));
                        }
                    }
                }
                push_notification = push_rx.recv() => {
                    if let Some(push_notification) = push_notification {
                        let mut has_mailbox_changes = false;
                        let mut has_email_changes = false;

                        match push_notification {
                            PushNotification::StateChange(state_change) => {
                                for type_state in state_change.types {
                                    match type_state {
                                        DataType::Email | DataType::EmailDelivery => {
                                            has_email_changes = true;
                                        }
                                        DataType::Mailbox => {
                                            has_mailbox_changes = true;
                                        }
                                        _ => {}
                                    }
                                }
                            },
                            PushNotification::EmailPush(_) => {
                                has_email_changes = true;
                                has_mailbox_changes = true;
                            },
                            PushNotification::CalendarAlert(_) => (),
                        }

                        if has_mailbox_changes || has_email_changes {
                            data.write_changes(mailbox.as_ref(), has_mailbox_changes, has_email_changes, use_vanished, is_uidonly, is_rev2, is_utf8).await?;
                        }
                    } else {
                        self.write_bytes(&b"* BYE Server shutting down.\r\n"[..]).await.ok();
                        return Err(trc::NetworkEvent::Closed.into_err().details("IDLE channel closed.").id(request.tag));
                    }
                }
            }
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn write_changes(
        &self,
        mailbox: Option<&Arc<SelectedMailbox>>,
        check_mailboxes: bool,
        check_emails: bool,
        use_vanished: bool,
        is_uidonly: bool,
        is_rev2: bool,
        is_utf8: bool,
    ) -> trc::Result<()> {
        // Synchronize the selected mailbox first so the account counters are current
        let mut changed_uids = Vec::new();
        let cache = if check_emails && let Some(mailbox) = mailbox {
            let cache = self
                .server
                .get_cached_messages(mailbox.id.account_id)
                .await
                .caused_by(trc::location!())?;
            self.sync_view(mailbox, &cache, Some(&mut changed_uids))
                .await
                .caused_by(trc::location!())?;
            Some(cache)
        } else {
            None
        };

        // Fetch all changed mailboxes
        if check_mailboxes {
            let caches = match (mailbox, &cache) {
                (Some(mailbox), Some(cache)) => {
                    AccountCaches::with(mailbox.id.account_id, cache.clone())
                }
                _ => AccountCaches::default(),
            };
            let refresh = self
                .synchronize_mailboxes_using(true, caches)
                .await
                .caused_by(trc::location!())?;
            let changes = refresh.changes.unwrap_or_default();
            let mut caches = refresh.caches;

            let mut buf = Vec::with_capacity(64);

            // List deleted mailboxes
            for mailbox_name in changes.deleted {
                ListItem {
                    mailbox_name,
                    attributes: vec![Attribute::NonExistent],
                    tags: vec![],
                }
                .serialize(&mut buf, is_rev2, is_utf8, false);
            }

            // List added mailboxes
            for mailbox_name in changes.added {
                ListItem {
                    mailbox_name,
                    attributes: vec![],
                    tags: vec![],
                }
                .serialize(&mut buf, is_rev2, is_utf8, false);
            }
            // Obtain status of changed mailboxes
            for mailbox_name in changes.changed {
                if let Ok(status) = self
                    .status(
                        &mut caches,
                        mailbox_name,
                        &[
                            Status::Messages,
                            Status::Unseen,
                            Status::UidNext,
                            Status::UidValidity,
                        ],
                    )
                    .await
                {
                    status.serialize(&mut buf, is_utf8);
                }
            }

            if !buf.is_empty() {
                self.write_bytes(buf).await?;
            }
        }

        // Fetch selected mailbox changes
        if let (Some(mailbox), Some(cache)) = (mailbox, cache) {
            self.flush_view(mailbox, use_vanished)
                .await
                .caused_by(trc::location!())?;

            if !changed_uids.is_empty() {
                changed_uids.sort_unstable();
                changed_uids.dedup();
                let op_start = Instant::now();
                return self
                    .fetch(
                        fetch::Arguments {
                            tag: "".into(),
                            sequence_set: Sequence::List {
                                items: changed_uids
                                    .into_iter()
                                    .map(|uid| Sequence::Number { value: uid })
                                    .collect(),
                            },
                            attributes: vec![fetch::Attribute::Flags, fetch::Attribute::Uid],
                            changed_since: None,
                            include_vanished: false,
                        },
                        mailbox.clone(),
                        Some(cache),
                        true,
                        use_vanished,
                        is_uidonly,
                        false,
                        is_utf8,
                        u32::MAX,
                        op_start,
                    )
                    .await
                    .caused_by(trc::location!())
                    .map(|_| ());
            }
        }

        Ok(())
    }
}
