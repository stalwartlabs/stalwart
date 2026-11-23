/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{meeting_decline::DeclinedMeeting, save::SaveMode};
use crate::{
    folders::{FolderNode, SpecialFolder},
    mail::CommitOutcome,
    mapi::{
        emsmdb::{
            access::RopWrite,
            execute::{RopContext, RopError, RopResult},
            folder::stored_mailbox,
            state::{MessageObject, mail_container},
            store::StoreGuids,
        },
        ids::{IdSpace, MapiId},
    },
    submit::{
        AfterSend, DeliveryReport, ExchangeSubmit, Outgoing, Recipients, Submission, SubmitError,
        SubmitOptions,
    },
};
use common::cache::exchange::Placement;
use email::cache::{email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use exchange_proto::{
    convert::model::MessageContent,
    ids::{ReplId, entryid::EntryId, mid::ServerIdValue},
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropKeyRef, PropTag, PropType, tags},
        rop::{DecodedRop, ResponseHeader, requests::SubmitMessage, writer::RopResponse},
    },
};
use trc::AddContext;
use types::type_state::DataType;

const NEEDS_SPOOLER: u8 = 0x02;
const NO_PROPERTIES_RETURNED: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmitRoute {
    Message { submit_flags: u8 },
    Transport,
}

impl SubmitRoute {
    fn response_len(self) -> usize {
        match self {
            SubmitRoute::Message { .. } => 0,
            SubmitRoute::Transport => 1,
        }
    }
}

struct NoPropertiesReturned;

impl RopResponse for NoPropertiesReturned {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(NO_PROPERTIES_RETURNED);
    }

    fn encoded_len_hint(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SentTarget {
    Keep,
    Folder(u64),
    SentItems,
}

struct SubmitProps {
    delete_after: bool,
    outbox_target: Option<u32>,
    sent: SentTarget,
    hold_until: Option<u64>,
    delivery_report: DeliveryReport,
}

impl SubmitProps {
    fn new(content: &MessageContent, guids: &StoreGuids, folder: u64) -> Self {
        let get =
            |tag: PropTag, ptype: PropType| content.props.get(PropKeyRef::Tag(tag.id()), ptype);
        let flag =
            |tag: PropTag| matches!(get(tag, PropType::Bool), Some(OwnedPropValue::Bool(true)));
        let present = |tag: PropTag| content.props.get_any(PropKeyRef::Tag(tag.id())).is_some();
        let server_folder = match get(tags::SENT_MAIL_SVR_EID, PropType::ServerId) {
            Some(OwnedPropValue::ServerId(bytes)) => match ServerIdValue::decode(bytes) {
                Some(ServerIdValue::Ours { fid, .. }) if fid.replid == ReplId::LOCAL => {
                    Some(fid.counter.get())
                }
                _ => None,
            },
            _ => None,
        };
        let sent_folder =
            server_folder.or_else(|| match get(tags::SENT_MAIL_ENTRY_ID, PropType::Binary) {
                Some(OwnedPropValue::Binary(bytes)) => match EntryId::decode(bytes) {
                    Ok(EntryId::Folder(folder)) if folder.provider == guids.mailbox => {
                        Some(folder.gid.counter.get())
                    }
                    _ => None,
                },
                _ => None,
            });
        let delete_after = flag(tags::DELETE_AFTER_SUBMIT);
        let mirrored = !delete_after
            && MapiId::from_counter(folder).and_then(MapiId::to_node)
                == Some(FolderNode::Special(SpecialFolder::Outbox));
        SubmitProps {
            delete_after,
            outbox_target: match get(tags::TARGET_ENTRY_ID, PropType::Binary) {
                Some(OwnedPropValue::Binary(bytes)) if mirrored => match EntryId::decode(bytes) {
                    Ok(EntryId::Message(entry))
                        if entry.provider == guids.mailbox
                            && entry.folder.guid == guids.replica
                            && entry.folder.counter.get() == folder =>
                    {
                        guids
                            .local_gid(entry.message)
                            .filter(|id| id.space == IdSpace::Email)
                            .map(|id| id.id)
                    }
                    _ => None,
                },
                _ => None,
            },
            sent: match sent_folder {
                Some(folder) => SentTarget::Folder(folder),
                None if present(tags::SENT_MAIL_SVR_EID) || present(tags::SENT_MAIL_ENTRY_ID) => {
                    SentTarget::SentItems
                }
                None => SentTarget::Keep,
            },
            hold_until: match get(tags::DEFERRED_SEND_TIME, PropType::Time) {
                Some(OwnedPropValue::Time(time)) => u64::try_from(time.to_utc().0.0).ok(),
                _ => None,
            },
            delivery_report: if flag(tags::ORIGINATOR_DELIVERY_REPORT_REQUESTED) {
                DeliveryReport::Requested
            } else {
                DeliveryReport::Default
            },
        }
    }
}

impl RopContext<'_, '_> {
    pub async fn submit_message(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SubmitMessage,
    ) -> RopResult {
        self.submit_handle(
            rop,
            SubmitRoute::Message {
                submit_flags: request.submit_flags,
            },
        )
        .await?;
        self.respond_empty(rop, index)
    }

    pub async fn transport_send(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        self.submit_handle(rop, SubmitRoute::Transport).await?;
        self.respond(rop, index, &NoPropertiesReturned)
    }

    async fn submit_handle(
        &mut self,
        rop: &DecodedRop<'_>,
        route: SubmitRoute,
    ) -> Result<(), RopError> {
        if self.writer.remaining() < ResponseHeader::LEN + route.response_len() {
            return Err(RopError::Overflow);
        }
        let handle = self.input(rop.header.input_handle)?;
        let mut message = self.message_object(handle)?;
        if !message.path.is_empty() {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        if !RopWrite::MemberOnly.admits(self.logon_access(message.mailbox_id)) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        if let SubmitRoute::Message { submit_flags } = route
            && submit_flags & NEEDS_SPOOLER != 0
        {
            return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
        }
        let created = match message.staged {
            Some(_) => {
                let staged = self.staged_message(&message)?;
                if staged.associated {
                    return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
                }
                staged.base.is_none()
            }
            None => {
                check_submittable(&message)?;
                false
            }
        };
        if !self.types.contains(DataType::Email) {
            return Err(RopError::Code(ErrorCode::ACCESS_DENIED));
        }
        let content = self.message_root(&message).await?;
        let view = self.mailbox(message.mailbox_id).await?;
        let mut props = SubmitProps::new(
            &content,
            &StoreGuids::new(view.exchange.store_instance, message.mailbox_id),
            message.folder,
        );
        let declined = self
            .types
            .contains(DataType::CalendarEvent)
            .then(|| DeclinedMeeting::of(&content))
            .flatten();
        drop(content);
        if route == SubmitRoute::Transport {
            props.delete_after = true;
        }
        if let Some(staged_id) = message.staged {
            self.commit_staged(&message, staged_id, SaveMode::Checked)
                .await?;
            message = self.message_object(handle)?;
            check_submittable(&message)?;
        }
        let Err(rejected) = self.submit_stored(&message, props).await? else {
            if let Some(declined) = declined
                && let Err(err) = Box::pin(declined.apply(
                    self.request.server,
                    self.request.access_token,
                    message.mailbox_id,
                ))
                .await
            {
                trc::error!(err.details("MAPI declined meeting not removed from the calendar"));
            }
            return Ok(());
        };
        if created
            && route == SubmitRoute::Transport
            && let Some(id) = message.id()
            && let Err(RopError::Internal(err)) = self
                .remove_message_ids(message.mailbox_id, message.folder, &[id.to_eid()])
                .await
        {
            trc::error!(err.details("MAPI transport copy removal failed"));
        }
        Err(RopError::Code(rejected))
    }

    async fn submit_stored(
        &mut self,
        message: &MessageObject,
        props: SubmitProps,
    ) -> Result<Result<(), ErrorCode>, RopError> {
        let from = message.container().ok_or(ErrorCode::NOT_SUPPORTED)?;
        let id = message.id().ok_or(ErrorCode::NOT_FOUND)?;
        let view = self.mailbox(message.mailbox_id).await?;
        let messages = view.messages.as_ref().ok_or(ErrorCode::OBJECT_DELETED)?;
        let document_id = view.email_document(from, id.id);
        let data = messages
            .email_by_id(&document_id)
            .filter(|item| item.has_mailbox_id(from))
            .and_then(|_| messages.message_data(document_id))
            .ok_or(ErrorCode::OBJECT_DELETED)?;
        let chosen = match props.sent {
            SentTarget::Folder(folder) => {
                mail_container(folder).filter(|mailbox_id| messages.has_mailbox_id(mailbox_id))
            }
            SentTarget::Keep | SentTarget::SentItems => None,
        };
        let special_sent = if props.outbox_target.is_some()
            || (chosen.is_none() && !props.delete_after && props.sent != SentTarget::Keep)
        {
            self.folder_tree(message.mailbox_id)
                .await?
                .special(SpecialFolder::SentItems)
                .map(|entry| entry.node)
                .and_then(stored_mailbox)
        } else {
            None
        };
        let id_bound = match props.outbox_target {
            Some(_) => self
                .email_id_counter(message.mailbox_id)
                .await?
                .saturating_add(1),
            None => 0,
        };
        let mirror = props
            .outbox_target
            .zip(special_sent)
            .filter(|(item, sent)| {
                *sent != from
                    && i64::from(*item) < id_bound
                    && messages.has_mailbox_id(sent)
                    && messages.email_by_id(item).is_none()
                    && view.exchange.resolve_folder_key(*item).is_none()
                    && view
                        .exchange
                        .resolve_alias(Placement {
                            container: *sent,
                            item: *item,
                        })
                        .is_none()
            });
        let after = if let Some((item, to)) = mirror {
            AfterSend::MoveTo {
                from,
                to,
                alias: Some(item),
            }
        } else if props.delete_after {
            AfterSend::Delete { from }
        } else {
            match chosen.or(special_sent) {
                Some(to) if to != from => AfterSend::MoveTo {
                    from,
                    to,
                    alias: None,
                },
                _ => AfterSend::Keep,
            }
        };
        let request = self.request;
        let submitted = request
            .server
            .submit(Submission {
                access_token: request.access_token,
                account_id: message.mailbox_id,
                instance: request.instance,
                session_id: self.session_id(),
                message: Outgoing::Stored {
                    document_id,
                    data,
                    after,
                },
                recipients: Recipients::Headers,
                options: SubmitOptions {
                    hold_until: props.hold_until,
                    delivery_report: props.delivery_report,
                    once: None,
                },
            })
            .await
            .caused_by(trc::location!())?;
        self.invalidate_mailbox();
        let submitted = match submitted {
            Ok(submitted) => submitted,
            Err(err) => return Ok(Err(submit_error(err))),
        };
        match submitted.after_send {
            Some(Err(err)) => {
                trc::error!(err.caused_by(trc::location!()));
            }
            Some(Ok(CommitOutcome::Conflict)) => {
                trc::error!(
                    trc::StoreEvent::AssertValueFailed
                        .into_err()
                        .details("MAPI after-send edit conflicted")
                        .caused_by(trc::location!())
                );
            }
            Some(Ok(CommitOutcome::Committed(_))) | None => {}
        }
        Ok(Ok(()))
    }
}

fn check_submittable(message: &MessageObject) -> Result<(), RopError> {
    match message.id() {
        Some(id) if id.space == IdSpace::Email => Ok(()),
        Some(id) if id.space == IdSpace::Fai => Err(RopError::Code(ErrorCode::ACCESS_DENIED)),
        _ => Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
    }
}

fn submit_error(err: SubmitError) -> ErrorCode {
    match err {
        SubmitError::Forbidden | SubmitError::SendAsDenied => ErrorCode::ACCESS_DENIED,
        SubmitError::NotFound => ErrorCode::OBJECT_DELETED,
        SubmitError::TooLarge { .. } => ErrorCode::TOO_BIG,
        SubmitError::Malformed => ErrorCode::INVALID_PARAM,
        SubmitError::NoRecipients => ErrorCode::NO_RECIPIENTS,
        SubmitError::Recipients(_)
        | SubmitError::Sender(_)
        | SubmitError::Rejected(_)
        | SubmitError::AlreadySent
        | SubmitError::InProgress => ErrorCode::ERROR,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/message/submit/tests.rs"]
mod tests;
