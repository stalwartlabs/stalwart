/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EasContext, EasDataKind},
    convert::{
        body::BodyChoice,
        compose::{
            SmartMode, SmartOutcome, SourceThread, attach_message, quote_message, smart_message,
            thread_message,
        },
        event::{EventMessage, quoted_original},
        flag::{LastVerb, MailRow, VerbState},
    },
    folder_sync::MAX_STATE_ATTEMPTS,
    response::EasResponse,
    sync::groupware::{GroupwareKind, load_item},
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::FolderNode,
    mail::{CommitOutcome, FlagEdit, FlagOutcome, MailEdits},
    store::{FolderKind, FolderRef, account::ExchangeAccountStore, object::OwnerStamp},
    submit::{
        DeliveryReport, ExchangeSubmit, Outgoing, Recipients, SaveCopy, Submission, SubmitError,
        SubmitOnce, SubmitOptions,
    },
};
use ::email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    message::metadata::MetadataRow,
};
use common::{MessageStoreCache, Server};
use exchange_proto::{
    common::time::{FileTime, UtcSeconds},
    convert::conversation::ConversationIndex,
    convert::ical::{ForwardError, Organizer, RecurrenceId, event_text, forwarded_event, publish},
    eas::{
        commands::send_mail::{ComposeCommand, ComposeRequest, Source},
        http::Command,
        status::{CommonStatus, Status},
        tokens::ProtocolVersion,
        types::EasDateTime,
        wbxml::Decoder,
    },
    ids::eas::EasServerId,
};
use groupware::cache::GroupwareCache;
use jiff::Timestamp;
use store::{ValueKey, rand, write::now};
use trc::{AddContext, EventType, LimitEvent};
use types::{
    collection::{Collection, SyncCollection},
    field::EmailField,
    special_use::SpecialUse,
};

const MERGE_MEMORY_FACTOR: usize = 4;
const TRANSIENT_REPLY: char = '4';
const TOO_MANY_RECIPIENTS: &str = ".5.3";

pub trait EasCompose: Sync + Send {
    fn eas_compose(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
        command: ComposeCommand,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

impl EasCompose for Server {
    async fn eas_compose(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
        command: ComposeCommand,
    ) -> trc::Result<EasResponse> {
        let http_command = match command {
            ComposeCommand::SendMail => Command::SendMail,
            ComposeCommand::SmartReply => Command::SmartReply,
            ComposeCommand::SmartForward => Command::SmartForward,
        };
        let failed = |status: Status| Ok(EasResponse::status(http_command, status));
        let Some(decoder) = decoder else {
            return failed(CommonStatus::INVALID_XML.into());
        };
        let request = match ComposeRequest::parse(decoder, ctx.version, command) {
            Ok(request) => request,
            Err(err) => return failed(err.status(http_command)),
        };
        if !ctx.allows(EasDataKind::Mail) {
            return failed(CommonStatus::ACCESS_DENIED.into());
        }
        if let Some(account_id) = request.account_id.as_deref()
            && !self
                .account_info(ctx.account_id)
                .await?
                .addresses()
                .iter()
                .any(|address| address.eq_ignore_ascii_case(account_id))
        {
            return failed(CommonStatus::INVALID_ACCOUNT_ID.into());
        }
        if request.template_id.is_some() {
            return failed(CommonStatus::IRM_FEATURE_DISABLED.into());
        }

        let cache = self.get_cached_messages(ctx.account_id).await?;
        let mode = match command {
            ComposeCommand::SendMail => None,
            ComposeCommand::SmartReply => Some(SmartMode::Reply),
            ComposeCommand::SmartForward => Some(SmartMode::Forward),
        };
        let source = mode
            .zip(request.source.as_ref())
            .map(|(mode, source)| (mode, SourceItem::resolve(&cache, source)));
        let source_row = match source {
            Some((_, SourceItem::Mail { document_id, .. })) => {
                source_metadata(self, ctx.account_id, document_id).await?
            }
            _ => None,
        };
        let outcome = match source {
            Some((_, SourceItem::Missing)) if !request.replace_mime => {
                Err(CommonStatus::ITEM_NOT_FOUND.into())
            }
            Some((mode, SourceItem::Mail { size, .. })) if !request.replace_mime => {
                match &source_row {
                    _ if size.saturating_add(request.mime.len())
                        > self.core.email.mail_max_size =>
                    {
                        Err(CommonStatus::ATTACHMENT_IS_TOO_LARGE.into())
                    }
                    Some(row) => merge_original(self, row, &request.mime, mode).await?,
                    None => Err(CommonStatus::ITEM_NOT_FOUND.into()),
                }
            }
            Some((
                mode,
                SourceItem::Event {
                    container_id,
                    document_id,
                },
            )) if !request.replace_mime => {
                let instance = request
                    .source
                    .as_ref()
                    .and_then(|source| source.instance_id);
                Box::pin(merge_event(
                    self,
                    ctx,
                    &request.mime,
                    instance,
                    container_id,
                    document_id,
                    mode,
                ))
                .await?
            }
            _ => Ok(SmartOutcome::Unmerged),
        };
        let raw = match outcome {
            Ok(SmartOutcome::Merged(raw)) => raw,
            Ok(SmartOutcome::Unmerged) => request.mime.into_owned(),
            Ok(SmartOutcome::InvalidClient) => return failed(CommonStatus::INVALID_MIME.into()),
            Err(status) => return failed(status),
        };
        let raw = match (source, &source_row) {
            (
                Some((
                    mode,
                    SourceItem::Mail {
                        thread_id,
                        received_at,
                        ..
                    },
                )),
                Some(row),
            ) => threaded(row, raw, mode, thread_id, received_at)?,
            _ => raw,
        };
        let save_copy = if request.save_in_sent {
            cache
                .mailbox_by_role(&SpecialUse::Sent)
                .map(|mailbox| SaveCopy {
                    mailbox_id: mailbox.document_id,
                    carried: None,
                })
        } else {
            None
        };

        match self
            .submit(Submission {
                access_token: &ctx.access_token,
                account_id: ctx.account_id,
                instance: &ctx.session.instance,
                session_id: ctx.session.session_id,
                message: Outgoing::Composed { raw, save_copy },
                recipients: Recipients::Headers,
                options: SubmitOptions {
                    once: SubmitOnce::eas(ctx.device.slot, &request.client_id),
                    delivery_report: DeliveryReport::FromMessage,
                    ..Default::default()
                },
            })
            .await?
        {
            Ok(_) => {
                if let Some((mode, SourceItem::Mail { document_id, .. })) = source {
                    mark_source(self, ctx, document_id, mode).await;
                }
                Ok(EasResponse::Empty)
            }
            Err(err) => failed(submit_status(&err, ctx.version)),
        }
    }
}

async fn mark_source(server: &Server, ctx: &EasContext<'_>, document_id: u32, mode: SmartMode) {
    let (edit, verb) = match mode {
        SmartMode::Reply => (
            FlagEdit {
                read: Some(true),
                answered: Some(true),
                ..Default::default()
            },
            LastVerb::ReplyToSender,
        ),
        SmartMode::Forward => (
            FlagEdit {
                read: Some(true),
                forwarded: Some(true),
                ..Default::default()
            },
            LastVerb::Forward,
        ),
    };
    let verb = VerbState {
        verb,
        time: Some(EasDateTime(
            UtcSeconds(i64::try_from(now()).unwrap_or(i64::MAX)),
            0,
        )),
    };
    for _ in 0..MAX_STATE_ATTEMPTS {
        match mark_source_once(server, ctx, document_id, edit, verb)
            .await
            .caused_by(trc::location!())
        {
            Ok(CommitOutcome::Conflict) => {}
            Ok(CommitOutcome::Committed(_)) => return,
            Err(err) => {
                trc::error!(err);
                return;
            }
        }
    }
}

async fn mark_source_once(
    server: &Server,
    ctx: &EasContext<'_>,
    document_id: u32,
    edit: FlagEdit,
    verb: VerbState,
) -> trc::Result<CommitOutcome> {
    let cache = server.get_cached_messages(ctx.account_id).await?;
    let Some(data) = cache.message_data(document_id) else {
        return Ok(CommitOutcome::Committed(None));
    };
    let mut edits = MailEdits::new(ctx.account_id);
    let logged = match edits.set_flags(&server.core.email.limits, document_id, &data, edit)? {
        FlagOutcome::Changed => true,
        FlagOutcome::Unchanged => false,
        FlagOutcome::KeywordLimit => return Ok(CommitOutcome::Committed(None)),
    };
    let exchange = server.get_cached_exchange(ctx.account_id).await?;
    let max_size = server.core.exchange.max_object_size;
    let mut row = MailRow::load(server, &exchange, ctx.account_id, document_id).await?;
    if verb.write(&mut row.next) && !row.next.exceeds(max_size) {
        let owner = server
            .exchange_quota_owner(&ctx.access_token, ctx.account_id)
            .await?;
        edits.write_object(row.write(
            owner,
            document_id,
            if logged {
                OwnerStamp::Logged
            } else {
                OwnerStamp::Email {
                    thread_id: data.thread_id,
                }
            },
            max_size,
        ))?;
    }
    edits
        .commit(server, &ctx.access_token, ctx.session.session_id)
        .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceItem {
    Mail {
        document_id: u32,
        size: usize,
        thread_id: u32,
        received_at: u64,
    },
    Event {
        container_id: u32,
        document_id: u32,
    },
    Other,
    Missing,
}

impl SourceItem {
    fn resolve(cache: &MessageStoreCache, source: &Source<'_>) -> Self {
        let (id, folder_id) = match (source.item_id.as_deref(), source.long_id.as_deref()) {
            (Some(item_id), _) => (EasServerId::decode(item_id), source.folder_id.as_deref()),
            (None, Some(long_id)) => (EasServerId::decode(long_id), None),
            (None, None) => (None, None),
        };
        let Some(id) = id else {
            return SourceItem::Missing;
        };
        match folder_id.map(FolderNode::from_eas_collection_id) {
            Some(Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id: folder,
            }))) if folder != id.container => return SourceItem::Missing,
            Some(Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                ..
            })))
            | Some(None)
            | None => {}
            Some(Some(FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar,
                id: folder,
            }))) => {
                return if folder == id.container {
                    SourceItem::Event {
                        container_id: folder,
                        document_id: id.id,
                    }
                } else {
                    SourceItem::Missing
                };
            }
            Some(Some(_)) => return SourceItem::Other,
        }
        cache
            .email_by_id(&id.id)
            .map_or(SourceItem::Missing, |message| SourceItem::Mail {
                document_id: message.document_id(),
                size: message.size() as usize,
                thread_id: message.thread_id(),
                received_at: message.received_at(),
            })
    }
}

async fn merge_event(
    server: &Server,
    ctx: &EasContext<'_>,
    client: &[u8],
    instance: Option<EasDateTime>,
    container_id: u32,
    document_id: u32,
    mode: SmartMode,
) -> trc::Result<Result<SmartOutcome, Status>> {
    if !ctx.allows(EasDataKind::Calendar) {
        return Ok(Err(CommonStatus::ITEM_NOT_FOUND.into()));
    }
    let instance = match instance.map(|instance| Timestamp::from_second(instance.0.0)) {
        Some(Ok(start)) => Some(RecurrenceId(start)),
        Some(Err(_)) => return Ok(Err(CommonStatus::INVALID_DATE_TIME.into())),
        None => None,
    };
    let is_member = server
        .fetch_groupware_resources(ctx.account_id, ctx.account_id, SyncCollection::Calendar)
        .await?
        .item_by_id(document_id)
        .is_some_and(|resource| {
            resource
                .child_names()
                .iter()
                .any(|name| name.parent_id == container_id)
        });
    if !is_member {
        return Ok(Err(CommonStatus::ITEM_NOT_FOUND.into()));
    }
    let Some(item) = load_item(
        server,
        ctx.account_id,
        GroupwareKind::Calendar,
        document_id,
        BodyChoice::select(None, false),
    )
    .await?
    else {
        return Ok(Ok(SmartOutcome::Unmerged));
    };
    if (item.size as usize).saturating_add(client.len()) > server.core.email.mail_max_size {
        return Ok(Err(CommonStatus::ATTACHMENT_IS_TOO_LARGE.into()));
    }
    let Some(ical) = item.event() else {
        return Ok(Ok(SmartOutcome::Unmerged));
    };
    let event = match forwarded_event(ical, instance) {
        Ok(event) => event,
        Err(ForwardError::NoInstance) => {
            return Ok(Err(CommonStatus::INVALID_DATE_TIME.into()));
        }
        Err(ForwardError::NoEvent) => return Ok(Ok(SmartOutcome::Unmerged)),
    };
    let Some(text) = event_text(&event) else {
        return Ok(Ok(SmartOutcome::Unmerged));
    };
    if mode == SmartMode::Reply {
        return Ok(Ok(quoted_original(&text)
            .map_or(SmartOutcome::Unmerged, |original| {
                quote_message(client, &original)
            })));
    }
    let account;
    let fallback = match text.organizer {
        Some(_) => None,
        None => match event_text(ical).and_then(|stored| stored.organizer) {
            Some(organizer) => Some(organizer),
            None => {
                account = server.account_info(ctx.account_id).await?;
                let Some(address) = account.addresses().first() else {
                    return Ok(Ok(SmartOutcome::Unmerged));
                };
                Some(Organizer {
                    address,
                    name: account.description(),
                })
            }
        },
    };
    let mut event = event.into_owned();
    publish(&mut event, fallback);
    let Some((text, sender)) = event_text(&event).and_then(|text| Some((text, text.organizer?)))
    else {
        return Ok(Ok(SmartOutcome::Unmerged));
    };
    let ics = event.to_string();
    Ok(Ok(EventMessage::forward(&text, sender, ics)
        .map_or(SmartOutcome::Unmerged, |message| {
            attach_message(client, &message.name, &message.raw)
        })))
}

async fn source_metadata(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<MetadataRow>> {
    server
        .store()
        .get_value::<MetadataRow>(ValueKey::immutable(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await
        .caused_by(trc::location!())
}

fn threaded(
    row: &MetadataRow,
    raw: Vec<u8>,
    mode: SmartMode,
    thread_id: u32,
    received_at: u64,
) -> trc::Result<Vec<u8>> {
    let meta = row.unarchive().caused_by(trc::location!())?;
    let headers = row.raw_headers().caused_by(trc::location!())?;
    let root = meta.root();
    let part = root.root_part();
    let list = part.headers();
    let header = |name: &str| {
        list.last_named(name, &headers)
            .and_then(|header| header.raw_value(&headers))
            .map(<[u8]>::trim_ascii)
    };
    let index = ConversationIndex::resolve(
        header("Thread-Index"),
        UtcSeconds(i64::try_from(received_at).unwrap_or(i64::MAX)),
        thread_id,
    )
    .child(
        FileTime::from_utc(UtcSeconds(i64::try_from(now()).unwrap_or(i64::MAX)), 0),
        rand::random(),
    );
    let source = SourceThread {
        message_id: root.envelope().message_id().last(),
        references: header("References").or_else(|| header("In-Reply-To")),
        index,
    };
    Ok(thread_message(raw, &source, mode))
}

async fn merge_original(
    server: &Server,
    row: &MetadataRow,
    client: &[u8],
    mode: SmartMode,
) -> trc::Result<Result<SmartOutcome, Status>> {
    let meta = row.unarchive().caused_by(trc::location!())?;
    let Some(mut blob) = server
        .fetch_blob(&meta.blob_hash(), 0..usize::MAX, Some(meta.size() as u64))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(Err(CommonStatus::ITEM_NOT_FOUND.into()));
    };
    let working_set = meta
        .size()
        .saturating_mul(MERGE_MEMORY_FACTOR - 1)
        .saturating_add(client.len().saturating_mul(MERGE_MEMORY_FACTOR));
    match blob.try_reserve_extra(working_set) {
        Ok(()) => {}
        Err(err) if err.matches(EventType::Limit(LimitEvent::MemoryBudget)) => {
            return Ok(Err(CommonStatus::SERVER_ERROR_RETRY_LATER.into()));
        }
        Err(err) => return Err(err),
    }
    let headers = row.raw_headers().caused_by(trc::location!())?;
    let raw = meta.raw_message(Some(&headers), &blob);
    Ok(raw
        .get(0..raw.len())
        .map(|original| smart_message(client, &original, mode))
        .ok_or_else(|| CommonStatus::ITEM_NOT_FOUND.into()))
}

fn submit_status(err: &SubmitError, version: ProtocolVersion) -> Status {
    match err {
        SubmitError::Forbidden | SubmitError::SendAsDenied => CommonStatus::ACCESS_DENIED,
        SubmitError::NotFound => CommonStatus::ITEM_NOT_FOUND,
        SubmitError::TooLarge { .. } => CommonStatus::ATTACHMENT_IS_TOO_LARGE,
        SubmitError::Malformed => CommonStatus::INVALID_MIME,
        SubmitError::NoRecipients => CommonStatus::MESSAGE_HAS_NO_RECIPIENT,
        SubmitError::AlreadySent => CommonStatus::MESSAGE_PREVIOUSLY_SENT,
        SubmitError::InProgress => CommonStatus::SERVER_ERROR_RETRY_LATER,
        SubmitError::Recipients(rejected)
            if rejected
                .iter()
                .all(|recipient| is_transient(&recipient.reply)) =>
        {
            CommonStatus::SERVER_ERROR_RETRY_LATER
        }
        SubmitError::Recipients(_) if version >= ProtocolVersion::V160 => {
            CommonStatus::INVALID_RECIPIENTS
        }
        SubmitError::Recipients(_) => CommonStatus::MESSAGE_RECIPIENT_UNRESOLVED,
        SubmitError::Sender(reply) | SubmitError::Rejected(reply) if is_transient(reply) => {
            CommonStatus::SERVER_ERROR_RETRY_LATER
        }
        SubmitError::Sender(_) | SubmitError::Rejected(_) => CommonStatus::MAIL_SUBMISSION_FAILED,
    }
    .into()
}

fn is_transient(reply: &str) -> bool {
    reply.starts_with(TRANSIENT_REPLY)
        && !reply
            .split_ascii_whitespace()
            .nth(1)
            .is_some_and(|code| code.ends_with(TOO_MANY_RECIPIENTS))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/eas/compose/tests.rs"]
mod tests;
