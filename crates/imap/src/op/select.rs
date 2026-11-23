/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ImapContext, ToModSeq};
use crate::core::{
    MailboxRefresh, MailboxView, SavedSearch, SelectedMailbox, Session, State,
    rights::MailboxRights,
};
use common::network::SessionStream;
use email::cache::mailbox::MailboxCacheAccess;
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    protocol::{
        ImapResponse, ObjectId, Sequence, fetch,
        list::ListItem,
        select::{HighestModSeq, PermanentFlags, Response},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use tokio::sync::OwnedSemaphorePermit;
use types::acl::Acl;

impl<T: SessionStream> Session<T> {
    pub async fn handle_select(
        &mut self,
        request: Request<Command>,
        _permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        if self.state.close_mailbox() {
            self.state = State::Authenticated {
                data: self.state.session_data(),
            };
            self.write_bytes(
                StatusResponse::ok("Closed previous mailbox")
                    .with_code(ResponseCode::Closed)
                    .into_bytes(),
            )
            .await?;
        }

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
        if let Some(account_id) = arguments
            .objectid
            .as_ref()
            .and_then(|objectid| objectid.account_id)
            .and_then(|account_id| u32::try_from(account_id.id()).ok())
        {
            data.use_messages(account_id);
        }
        data.use_messages_of(&arguments.mailbox_name);
        let MailboxRefresh {
            mut caches,
            access_token,
            ..
        } = data
            .synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Resolve the mailbox by its object identifiers (with fallback to the name)
        let mailbox = arguments
            .objectid
            .as_ref()
            .and_then(|objectid| data.get_mailbox_by_object_id(objectid, &access_token))
            .or_else(|| {
                data.get_mailbox_by_name(&arguments.mailbox_name)
                    .map(|mailbox| (mailbox, arguments.mailbox_name))
            });

        if let Some((mailbox, mailbox_name)) = mailbox {
            let cache = caches
                .fetch(&data.server, mailbox.account_id)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            data.use_messages(mailbox.account_id);
            let acl = MailboxRights::new(&access_token, mailbox.account_id)
                .acl(&cache, mailbox.mailbox_id);
            if !acl.contains(Acl::ReadItems) {
                return Err(if cache.has_mailbox_id(&mailbox.mailbox_id) {
                    trc::ImapEvent::Error
                        .into_err()
                        .details("You do not have the required permissions to read this mailbox.")
                        .code(ResponseCode::NoPerm)
                        .id(arguments.tag)
                } else {
                    trc::ImapEvent::Error
                        .into_err()
                        .details("Mailbox no longer exists.")
                        .id(arguments.tag)
                });
            }
            let view = MailboxView::build(&cache, mailbox.mailbox_id);
            let uid_validity = data.uid_validity(&mailbox);
            let uid_next = data
                .uid_next(&cache, &mailbox)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            let is_condstore = self.is_condstore || arguments.condstore;

            // Build new state
            let is_rev2 = self.version.is_rev2();
            let is_utf8 = self.is_utf8;
            let is_read_write = is_select
                && acl
                    .contains_any([Acl::AddItems, Acl::RemoveItems, Acl::ModifyItems].into_iter());
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
            let qresync = match arguments.qresync {
                Some(qresync) => {
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
                    (qresync.uid_validity == uid_validity).then_some(qresync)
                }
                None => None,
            };

            // Build response
            let response = Response {
                mailbox: ListItem::new(mailbox_name.clone()),
                total_messages,
                recent_messages: 0,
                unseen_seq: 0,
                uid_validity,
                uid_next,
                is_rev2,
                is_utf8,
                highest_modseq,
                objectid: want_objectid.then(|| ObjectId::from(mailbox.id)),
                permanent_flags: PermanentFlags::from(acl),
            };

            let untagged = match qresync {
                Some(qresync) => {
                    self.write_bytes(response.serialize()).await?;
                    data.fetch(
                        fetch::Arguments {
                            tag: "".into(),
                            sequence_set: qresync.known_uids.unwrap_or(Sequence::Range {
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
                    None
                }
                None => Some(response),
            };

            trc::event!(
                Imap(trc::ImapEvent::Select),
                SpanId = self.session_id,
                MailboxName = mailbox_name,
                AccountId = mailbox.id.account_id,
                MailboxId = mailbox.id.mailbox_id,
                Total = total_messages,
                UidNext = uid_next,
                UidValidity = uid_validity,
                Elapsed = op_start.elapsed()
            );

            // Update state
            self.state = State::Selected { data, mailbox };

            let completed = StatusResponse::completed(command)
                .with_tag(arguments.tag)
                .with_code(if is_read_write {
                    ResponseCode::ReadWrite
                } else {
                    ResponseCode::ReadOnly
                });
            self.write_bytes(match untagged {
                Some(response) => completed.serialize_after(&response),
                None => completed.into_bytes(),
            })
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
