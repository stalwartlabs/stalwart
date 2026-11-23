/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EasContext, EasDataKind},
    convert::email::MeetingPart,
    folder_sync::MAX_STATE_ATTEMPTS,
    response::EasResponse,
    sync::{
        estimate::mail_folder,
        groupware::{GroupwareKind, GroupwareTarget},
    },
};
use crate::{
    folders::{ExchangeFolders, FolderNode, FolderTree},
    groupware_write::{
        MeetingError, MeetingOutcome, MeetingReply, MeetingResponse, UnchangedReply,
        respond_to_meeting, uid_events,
    },
    mail::{CommitOutcome, MailEdits},
};
use ::email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    message::metadata::{AddressHeader, ArchivedMessageMetadata, MetadataRow, Occurrence},
};
use calcard::icalendar::ICalendar;
use common::{GroupwareResources, Server, auth::AccountInfo};
use compact_str::ToCompactString;
use exchange_proto::{
    common::token::TokenBuf,
    convert::ical::{
        MeetingRole, ParticipationError, RecurrenceId, event_invitation, event_meeting_role,
    },
    eas::{
        commands::meeting_response::{
            MeetingResponseItem, MeetingResponseRequest, MeetingResponseResponse,
            MeetingResponseResult, UserResponse,
        },
        http::Command,
        status::{CommonStatus, MeetingResponseStatus},
        tokens::ProtocolVersion,
        wbxml::Decoder,
    },
    ids::eas::EasServerId,
};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        itip::{ItipAutoAdd, ItipIngest, ItipIngestError, ItipOrigin},
        write::{EventWriter, ItipMode},
    },
    scheduling::ItipError,
};
use jiff::Timestamp;
use registry::schema::enums::Permission;
use std::sync::Arc;
use store::{ValueKey, roaring::RoaringBitmap};
use tokio::sync::OnceCell;
use trc::{AddContext, EventType, LimitEvent, StoreEvent};
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
    special_use::SpecialUse,
};
use utils::sanitize_email;

pub trait EasMeetingResponse: Sync + Send {
    fn eas_meeting_response(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

struct Answered {
    status: MeetingResponseStatus,
    calendar_id: Option<TokenBuf>,
    request: Option<EasServerId>,
}

enum Target {
    Calendar(u32),
    Mail(u32),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Unimported {
    Import,
    Leave,
}

struct Invited {
    calendar_id: u32,
    document_id: u32,
    instance: Option<RecurrenceId>,
    imported: Option<Arc<GroupwareResources>>,
}

struct Responder<'x> {
    server: &'x Server,
    ctx: &'x EasContext<'x>,
    tree: OnceCell<FolderTree>,
    resources: OnceCell<Arc<GroupwareResources>>,
    account_info: OnceCell<AccountInfo>,
}

impl EasMeetingResponse for Server {
    async fn eas_meeting_response(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::MeetingResponse,
                CommonStatus::INVALID_XML.into(),
            ));
        };
        let request = match MeetingResponseRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::MeetingResponse,
                    err.status(Command::MeetingResponse),
                ));
            }
        };
        let responder = Responder {
            server: self,
            ctx,
            tree: OnceCell::new(),
            resources: OnceCell::new(),
            account_info: OnceCell::new(),
        };
        let mut answers = Vec::with_capacity(request.requests.len());
        for item in &request.requests {
            answers.push(responder.answer(item).await?);
        }
        if let Err(err) = responder.retire(&answers).await {
            trc::error!(err.details("Failed to move answered meeting requests to Deleted Items"));
        }
        let response = MeetingResponseResponse {
            results: request
                .requests
                .iter()
                .zip(&answers)
                .map(|(item, answer)| MeetingResponseResult {
                    request_id: item.request_id.as_deref(),
                    status: answer.status,
                    calendar_id: answer.calendar_id.as_ref().map(TokenBuf::as_str),
                    instance_id: item.instance_id,
                })
                .collect(),
        };
        Ok(EasResponse::encode(ctx.version, |enc| response.encode(enc)))
    }
}

impl Responder<'_> {
    async fn answer(&self, item: &MeetingResponseItem<'_>) -> trc::Result<Answered> {
        let Some(target) = self.target(item).await? else {
            return Ok(Answered::status(MeetingResponseStatus::INVALID_REQUEST));
        };
        let Some(request) = item.request_id.as_deref().and_then(EasServerId::decode) else {
            return Ok(Answered::status(MeetingResponseStatus::INVALID_REQUEST));
        };
        let instance = match item.instance_id {
            Some(instance) => match Timestamp::from_second(instance.0.0) {
                Ok(start) => Some(RecurrenceId(start)),
                Err(_) => {
                    return Ok(Answered::status(CommonStatus::INVALID_DATE_TIME.into()));
                }
            },
            None => None,
        };
        let itip = if self.ctx.version >= ProtocolVersion::V160 && item.send_response.is_some() {
            ItipMode::Send
        } else {
            ItipMode::Suppress
        };
        let reply = match item.user_response {
            UserResponse::Accepted => MeetingReply::Accept,
            UserResponse::Tentative => MeetingReply::Tentative,
            UserResponse::Declined => MeetingReply::Decline,
        };
        let in_mail = matches!(target, Target::Mail(_));
        let (calendar_id, document_id, instance, imported) = match target {
            Target::Calendar(calendar_id) if request.container == calendar_id => {
                (calendar_id, request.id, instance, None)
            }
            Target::Mail(mailbox_id) if request.container == mailbox_id => {
                let unimported = if reply == MeetingReply::Decline && itip == ItipMode::Suppress {
                    Unimported::Leave
                } else {
                    Unimported::Import
                };
                match self.invited(mailbox_id, request.id, unimported).await? {
                    Ok(Some(invited)) => (
                        invited.calendar_id,
                        invited.document_id,
                        instance.or(invited.instance),
                        invited.imported,
                    ),
                    Ok(None) => {
                        return Ok(Answered {
                            request: Some(request),
                            ..Answered::status(MeetingResponseStatus::SUCCESS)
                        });
                    }
                    Err(status) => return Ok(Answered::status(status)),
                }
            }
            Target::Calendar(_) | Target::Mail(_) => {
                return Ok(Answered::status(MeetingResponseStatus::INVALID_REQUEST));
            }
        };
        let resources = match &imported {
            Some(resources) => resources,
            None => self.resources().await?,
        };
        let writer = self.writer(resources).await?;
        let response = MeetingResponse {
            calendar_id,
            document_id,
            instance,
            reply,
            itip,
            unchanged: UnchangedReply::Apply,
        };
        let outcome = match respond_to_meeting(&writer, response).await {
            Ok(outcome) => outcome,
            Err(err) => return store_status(err).map(Answered::status),
        };
        let mut answered = match outcome {
            Ok(MeetingOutcome::Updated) if reply != MeetingReply::Decline => Answered {
                status: MeetingResponseStatus::SUCCESS,
                calendar_id: Some(
                    EasServerId {
                        container: calendar_id,
                        id: document_id,
                    }
                    .encode(),
                ),
                request: None,
            },
            Ok(MeetingOutcome::Updated | MeetingOutcome::Deleted) => {
                Answered::status(MeetingResponseStatus::SUCCESS)
            }
            Err(MeetingError::Participation(ParticipationError::NotRecurring)) => {
                Answered::status(CommonStatus::NO_RECURRENCE_IN_CALENDAR.into())
            }
            Err(
                MeetingError::Participation(_) | MeetingError::TooLarge | MeetingError::Write(_),
            ) => Answered::status(MeetingResponseStatus::INVALID_REQUEST),
        };
        if in_mail && answered.status == MeetingResponseStatus::SUCCESS {
            answered.request = Some(request);
        }
        Ok(answered)
    }

    async fn retire(&self, answers: &[Answered]) -> trc::Result<()> {
        if answers.iter().all(|answer| answer.request.is_none()) {
            return Ok(());
        }
        let account_id = self.ctx.account_id;
        let mut cache = self.server.get_cached_messages(account_id).await?;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let Some(trash_id) = cache
                .mailbox_by_role(&SpecialUse::Trash)
                .map(|mailbox| mailbox.document_id)
            else {
                return Ok(());
            };
            let mut edits = MailEdits::new(account_id);
            let mut planned = RoaringBitmap::new();
            let mut queued = false;
            for request in answers.iter().filter_map(|answer| answer.request) {
                if planned.insert(request.id)
                    && let Some(data) = cache.message_data(request.id)
                {
                    queued |= edits.move_to(request.id, data, request.container, trash_id)?;
                }
            }
            if !queued {
                return Ok(());
            }
            match edits
                .commit(
                    self.server,
                    &self.ctx.access_token,
                    self.ctx.session.session_id,
                )
                .await?
            {
                CommitOutcome::Committed(_) => return Ok(()),
                CommitOutcome::Conflict => {
                    cache = self.server.get_cached_messages(account_id).await?;
                }
            }
        }
        Ok(())
    }

    async fn target(&self, item: &MeetingResponseItem<'_>) -> trc::Result<Option<Target>> {
        let Some(node) = item
            .collection_id
            .as_deref()
            .filter(|_| item.long_id.is_none())
            .and_then(FolderNode::from_eas_collection_id)
        else {
            return Ok(None);
        };
        if let Some(folder) = mail_folder(self.ctx, node) {
            return Ok(Some(Target::Mail(folder.id)));
        }
        let tree = self
            .tree
            .get_or_try_init(|| {
                self.server
                    .exchange_folder_tree(self.ctx.account_id, self.ctx.data_types)
            })
            .await?;
        Ok(GroupwareTarget::resolve(self.ctx, tree, node)
            .filter(|target| target.kind == GroupwareKind::Calendar)
            .map(|target| Target::Calendar(target.container_id)))
    }

    async fn invited(
        &self,
        mailbox_id: u32,
        document_id: u32,
        unimported: Unimported,
    ) -> trc::Result<Result<Option<Invited>, MeetingResponseStatus>> {
        const INVALID: MeetingResponseStatus = MeetingResponseStatus::INVALID_REQUEST;
        let account_id = self.ctx.account_id;
        if !self.ctx.allows(EasDataKind::Calendar) {
            return Ok(Err(INVALID));
        }
        let cache = self.server.get_cached_messages(account_id).await?;
        if !cache
            .email_by_id(&document_id)
            .is_some_and(|message| message.has_mailbox_id(mailbox_id))
        {
            return Ok(Err(INVALID));
        }
        let Some(row) = self
            .server
            .store()
            .get_value::<MetadataRow>(ValueKey::immutable(
                account_id,
                Collection::Email,
                document_id,
                EmailField::Metadata,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(INVALID));
        };
        let meta = row.unarchive().caused_by(trc::location!())?;
        let Some(part) =
            MeetingPart::find(meta, self.server.core.groupware.itip_inbound_max_ical_size)
                .filter(MeetingPart::is_request)
        else {
            return Ok(Err(INVALID));
        };
        let Some(blob) = self
            .server
            .fetch_blob(
                &meta.blob_hash(),
                0..part.blob_end(),
                Some(meta.size() as u64),
            )
            .await
            .caused_by(trc::location!())?
        else {
            return Ok(Err(INVALID));
        };
        let headers = row.raw_headers().caused_by(trc::location!())?;
        let Some(ical) = part.ical(meta, meta.raw_message(Some(&headers), &blob)) else {
            return Ok(Err(INVALID));
        };
        let Some(invitation) = event_invitation(&ical) else {
            return Ok(Err(INVALID));
        };
        let resources = self.resources().await?;
        if let Some((calendar_id, document_id)) = uid_events(resources, invitation.uid).next() {
            return Ok(Ok(Some(Invited {
                calendar_id,
                document_id,
                instance: invitation.instance,
                imported: None,
            })));
        }
        if let Err(status) = self.import(meta, &ical, unimported).await? {
            return Ok(Err(status));
        }
        if unimported == Unimported::Leave {
            return Ok(Ok(None));
        }
        let resources = self
            .server
            .fetch_groupware_resources(account_id, account_id, SyncCollection::Calendar)
            .await?;
        let found = uid_events(&resources, invitation.uid).next();
        Ok(found
            .map(|(calendar_id, document_id)| {
                Some(Invited {
                    calendar_id,
                    document_id,
                    instance: invitation.instance,
                    imported: Some(resources),
                })
            })
            .ok_or(INVALID))
    }

    async fn import(
        &self,
        meta: &ArchivedMessageMetadata,
        ical: &ICalendar,
        unimported: Unimported,
    ) -> trc::Result<Result<(), MeetingResponseStatus>> {
        const INVALID: MeetingResponseStatus = MeetingResponseStatus::INVALID_REQUEST;
        let account_id = self.ctx.account_id;
        let access_token = &self.ctx.access_token;
        if !(self.server.core.groupware.itip_enabled
            && access_token.is_member(account_id)
            && access_token.has_permission(Permission::CalendarSchedulingReceive))
        {
            return Ok(Err(INVALID));
        }
        let Some(sender) = meta
            .root()
            .envelope()
            .addresses(AddressHeader::From, Occurrence::Last)
            .mailboxes()
            .find_map(|mailbox| mailbox.address.and_then(sanitize_email))
        else {
            return Ok(Err(INVALID));
        };
        let account_info = self.account_info().await?;
        let owner = account_info.addresses();
        if event_meeting_role(ical, owner) != MeetingRole::Attendee {
            return Ok(Err(INVALID));
        }
        let Some(recipient) = owner.first() else {
            return Ok(Err(INVALID));
        };
        if unimported == Unimported::Leave {
            return Ok(Ok(()));
        }
        match self
            .server
            .itip_ingest_with(
                account_info,
                &sender,
                ItipOrigin::Delivery,
                recipient,
                &ical.to_string(),
                ItipAutoAdd::Consented,
            )
            .await
        {
            Ok(_) => Ok(Ok(())),
            Err(ItipIngestError::Message(ItipError::QuotaExceeded)) => {
                Ok(Err(MeetingResponseStatus::MAILBOX_ERROR))
            }
            Err(ItipIngestError::Message(err)) => {
                trc::event!(
                    Calendar(trc::CalendarEvent::ItipMessageError),
                    AccountId = account_id,
                    Details = err.to_compact_string(),
                );
                Ok(Err(INVALID))
            }
            Err(ItipIngestError::Internal(err)) => Err(err.caused_by(trc::location!())),
        }
    }

    async fn resources(&self) -> trc::Result<&Arc<GroupwareResources>> {
        let account_id = self.ctx.account_id;
        self.resources
            .get_or_try_init(|| {
                self.server.fetch_groupware_resources(
                    account_id,
                    account_id,
                    SyncCollection::Calendar,
                )
            })
            .await
    }

    async fn account_info(&self) -> trc::Result<&AccountInfo> {
        self.account_info
            .get_or_try_init(|| self.server.account_info(self.ctx.account_id))
            .await
    }

    async fn writer<'r>(
        &'r self,
        resources: &'r Arc<GroupwareResources>,
    ) -> trc::Result<EventWriter<'r>> {
        Ok(EventWriter {
            server: self.server,
            access_token: &self.ctx.access_token,
            account_id: self.ctx.account_id,
            resources,
            account_info: self.account_info().await?,
        })
    }
}

impl Answered {
    fn status(status: MeetingResponseStatus) -> Self {
        Answered {
            status,
            calendar_id: None,
            request: None,
        }
    }
}

fn store_status(err: trc::Error) -> trc::Result<MeetingResponseStatus> {
    match err.as_ref() {
        EventType::Limit(LimitEvent::Quota) | EventType::Store(StoreEvent::AssertValueFailed) => {
            Ok(MeetingResponseStatus::MAILBOX_ERROR)
        }
        #[cfg(feature = "enterprise")]
        EventType::Limit(LimitEvent::TenantQuota) => Ok(MeetingResponseStatus::MAILBOX_ERROR),
        _ => Err(err),
    }
}
