/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ImapContext, ToModSeq};
use crate::core::{MailboxView, SavedSearch, SelectedMailbox, Session, State};
use common::network::SessionStream;
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    protocol::{
        ImapResponse, ObjectId, Sequence, fetch,
        list::ListItem,
        select::{HighestModSeq, Response},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use tokio::sync::OwnedSemaphorePermit;
use types::id::Id;

impl<T: SessionStream> Session<T> {
    pub async fn handle_select(
        &mut self,
        request: Request<Command>,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(if request.command == Command::Select {
            Permission::ImapSelect
        } else {
            Permission::ImapExamine
        })?;

        let op_start = Instant::now();
        let is_select = request.command == Command::Select;
        let command = request.command;
        let arguments = request.parse_select(self.is_utf8)?;
        let data = self.state.session_data();

        // Activate OBJECTID+ when the OBJECTID parameter is supplied
        if arguments.objectid.is_some()
            && let Some(enabled) = self.activate_objectid()
        {
            self.write_bytes(enabled).await?;
        }

        // Once activated, every SELECT/EXAMINE returns the compound OBJECTID response code
        let want_objectid = self.is_objectid;

        // Refresh mailboxes
        let mut caches = data
            .synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
            .caches;

        // Resolve the mailbox by its object identifiers (with fallback to the name)
        let mailbox = arguments
            .objectid
            .as_ref()
            .and_then(
                |objectid| match (objectid.account_id, objectid.mailbox_id) {
                    (Some(account_id), Some(mailbox_id)) => {
                        data.get_mailbox_by_id(account_id.document_id(), mailbox_id.document_id())
                    }
                    _ => None,
                },
            )
            .or_else(|| data.get_mailbox_by_name(&arguments.mailbox_name));

        if let Some(mailbox) = mailbox {
            let cache = caches
                .fetch(&data.server, mailbox.account_id)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            let view = MailboxView::build(&cache, mailbox.mailbox_id);
            let uid_validity = data.uid_validity(&mailbox);
            let uid_next = data
                .uid_next(&cache, &mailbox)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            // Synchronize messages
            let closed_previous = self.state.close_mailbox();
            let is_condstore = self.is_condstore || arguments.condstore;

            // Build new state
            let is_rev2 = self.version.is_rev2();
            let is_utf8 = self.is_utf8;
            let total_messages = view.len();
            let highest_modseq = if is_condstore {
                HighestModSeq::new(view.change_id().to_modseq()).into()
            } else {
                None
            };
            let mailbox = Arc::new(SelectedMailbox {
                id: mailbox,
                view: parking_lot::Mutex::new(view),
                saved_search: parking_lot::Mutex::new(SavedSearch::None),
                is_select,
                is_condstore,
            });

            // Validate QRESYNC arguments
            if let Some(qresync) = arguments.qresync {
                if !self.is_qresync {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("QRESYNC is not enabled.")
                        .id(arguments.tag));
                }
                if self.is_uidonly && qresync.seq_match.is_some() {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details(concat!(
                            "The QRESYNC sequence matching parameter ",
                            "is not allowed once UIDONLY is enabled."
                        ))
                        .code(ResponseCode::UidRequired)
                        .ctx(trc::Key::Type, ResponseType::Bad)
                        .id(arguments.tag));
                }
                if qresync.uid_validity == uid_validity {
                    // Send flags for changed messages
                    data.fetch(
                        fetch::Arguments {
                            tag: "".into(),
                            sequence_set: qresync
                                .known_uids
                                .or_else(|| qresync.seq_match.map(|(_, s)| s))
                                .unwrap_or(Sequence::Range {
                                    start: 1.into(),
                                    end: None,
                                }),
                            attributes: vec![fetch::Attribute::Flags],
                            changed_since: qresync.modseq.into(),
                            include_vanished: true,
                        },
                        mailbox.clone(),
                        Some(cache),
                        true,
                        true,
                        self.is_uidonly,
                        false,
                        self.is_utf8,
                        u32::MAX,
                        Instant::now(),
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;
                }
            }

            trc::event!(
                Imap(trc::ImapEvent::Select),
                SpanId = self.session_id,
                MailboxName = arguments.mailbox_name.clone(),
                AccountId = mailbox.id.account_id,
                MailboxId = mailbox.id.mailbox_id,
                Total = total_messages,
                UidNext = uid_next,
                UidValidity = uid_validity,
                Elapsed = op_start.elapsed()
            );

            // Build response
            let response = Response {
                mailbox: ListItem::new(arguments.mailbox_name),
                total_messages,
                recent_messages: 0,
                unseen_seq: 0,
                uid_validity,
                uid_next,
                closed_previous,
                is_rev2,
                is_utf8,
                highest_modseq,
                objectid: want_objectid.then(|| ObjectId {
                    mailbox_id: Some(Id::from(mailbox.id.mailbox_id)),
                    account_id: Some(Id::from(mailbox.id.account_id)),
                    ..Default::default()
                }),
            };

            // Update state
            self.state = State::Selected { data, mailbox };

            self.write_bytes(
                StatusResponse::completed(command)
                    .with_tag(arguments.tag)
                    .with_code(if is_select {
                        ResponseCode::ReadWrite
                    } else {
                        ResponseCode::ReadOnly
                    })
                    .serialize(response.serialize()),
            )
            .await
        } else {
            Err(trc::ImapEvent::Error
                .into_err()
                .details("Mailbox does not exist.")
                .code(ResponseCode::NonExistent)
                .id(arguments.tag))
        }
    }

    pub async fn handle_unselect(
        &mut self,
        request: Request<Command>,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        self.state.close_mailbox();
        self.state = State::Authenticated {
            data: self.state.session_data(),
        };
        self.write_bytes(
            StatusResponse::completed(Command::Unselect)
                .with_tag(request.tag)
                .into_bytes(),
        )
        .await
    }
}
