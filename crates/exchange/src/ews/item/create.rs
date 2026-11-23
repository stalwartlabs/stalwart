/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem,
    attach::with_attachments,
    get::Target as ItemTarget,
    id_only, mail_allowed, may_write_mailbox,
    props::{ItemProp, is_carried, is_ignored_tag},
    send::{SubmitSource, default_folder, sent_destination, submit_status},
    update::{
        CategoryNames, FLAG_STATUS_COMPLETED, FLAG_STATUS_FLAGGED, VERB_FORWARD, VERB_REPLY_TO_ALL,
        VERB_REPLY_TO_SENDER, stored_flag, xprop_int,
    },
    write::{file_answered_request, saved_destination},
};
use crate::{
    eas::convert::flag::{FLAG_STATUS_ACTIVE, FlagKeys, LastVerb},
    ews::{
        calendar::{
            Events,
            invitation::{InvitedEvent, mail_invitation},
            sent::{MeetingSend, SentCopies},
            write::{EventScope, calendar_destination, create_send, event_id_only},
        },
        contact::{
            Contacts,
            write::{ContactWriter, contact_destination, contact_id_only, list_id_only},
        },
        context::{EwsCaller, EwsContext},
        groupware::{items::GroupwareRef, write::CalendarWriter},
        reply::{RESPONSE_CAPACITY, ews_response},
        task::{
            Tasks,
            write::{TaskWriter, task_destination, task_id_only},
        },
    },
    folders::access::ItemWrite,
    groupware_write::MeetingReply,
    mail::{AccountCategories, CategoryOutcome},
    mapi::emsmdb::message::object_row::encode_property,
    store::{
        ExchangeProperty,
        account::ExchangeAccountStore,
        category::SpellingChanges,
        object::{CreatedEmail, ExchangeObject, ExchangeObjectStore},
    },
    submit::{
        DeliveryReport, ExchangeSubmit, Outgoing, Recipients, SaveCopy, Submission, SubmitOptions,
    },
};
use common::{Server, ipc::PushNotification};
use email::{
    cache::MessageCacheFetch,
    mailbox::JUNK_ID,
    message::ingest::{IngestEmail, IngestSource},
};
use exchange_proto::{
    ews::{
        MessageResult, Operation, Status,
        requests::item::CreateItem,
        responses::item::ItemInfoMessage,
        schema::{BodyType, Importance, MessageDisposition},
        types::{
            address::{EmailAddress, Recipients as EwsRecipients},
            ids::{BaseItemId, ItemId, TargetFolderId},
            item::{Item, ItemFields, ItemKind, MessageFields, response::ResponseObjectKind},
            value::XBinary,
            xprop::{ExtendedProperty, XPropTarget, XPropValue},
        },
    },
    mapi::prop::OwnedPropValue,
};
use http_proto::HttpResponse;
use jiff::Timestamp;
use mail_builder::{
    MessageBuilder,
    headers::{address::Address, raw::Raw},
};
use mail_parser::MessageParser;
use std::borrow::Cow;
use types::{
    keyword::Keyword,
    special_use::SpecialUse,
    type_state::{DataType, StateChange},
};

const CLASS_NOTE: &str = "IPM.Note";
const CLASS_POST: &str = "IPM.Post";
const MSGFLAG_READ: i64 = 0x01;
const MSGFLAG_UNSENT: i64 = 0x08;
const BASE64_BLOCK_LEN: usize = 3;
pub(super) const DISPOSITION_NOTIFICATION_TO: &str = "Disposition-Notification-To";
pub(super) const RETURN_RECEIPT_TO: &str = "Return-Receipt-To";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Save(u32),
    Send { save_copy: Option<u32> },
}

#[derive(Clone, Copy)]
enum EventAction {
    Respond(MeetingReply),
    Cancel,
}

#[derive(Clone, Copy)]
enum ResponseTarget {
    Event {
        account: u32,
        event: GroupwareRef,
        scope: EventScope,
    },
    Invitation,
}

#[derive(Clone, Copy)]
struct EventResponse {
    action: EventAction,
    target: ResponseTarget,
}

impl EventResponse {
    fn of(item: &Item<'_>) -> Option<Self> {
        let Item::ResponseObject(kind, _) = item else {
            return None;
        };
        let action = match kind {
            ResponseObjectKind::Accept => EventAction::Respond(MeetingReply::Accept),
            ResponseObjectKind::TentativelyAccept => EventAction::Respond(MeetingReply::Tentative),
            ResponseObjectKind::Decline => EventAction::Respond(MeetingReply::Decline),
            ResponseObjectKind::CancelCalendarItem => EventAction::Cancel,
            _ => return None,
        };
        let (account, event, scope) =
            match ItemTarget::of(&BaseItemId::Item(response_reference(item)?.clone())) {
                ItemTarget::Event(account, event) => (account, event, EventScope::Master),
                ItemTarget::Occurrence(account, event, instance) => {
                    (account, event, EventScope::Instance(instance))
                }
                ItemTarget::Indexed(account, event, index) => {
                    (account, event, EventScope::Indexed(index))
                }
                ItemTarget::Mail if matches!(action, EventAction::Respond(_)) => {
                    return Some(EventResponse {
                        action,
                        target: ResponseTarget::Invitation,
                    });
                }
                _ => return None,
            };
        Some(EventResponse {
            action,
            target: ResponseTarget::Event {
                account,
                event,
                scope,
            },
        })
    }
}

fn response_reference<'v, 'x>(item: &'v Item<'x>) -> Option<&'v ItemId<'x>> {
    match item {
        Item::ResponseObject(_, object) => object.extra.reference_item_id.as_ref(),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MessageKind {
    Message,
    Post,
}

pub(super) struct MessageView<'v> {
    pub item: &'v ItemFields<'v>,
    pub message: Cow<'v, MessageFields<'v>>,
    pub kind: MessageKind,
}

impl<'v> MessageView<'v> {
    pub(super) fn of(item: &'v Item<'v>) -> Option<Result<Self, ItemError>> {
        let (view, base) = match item {
            Item::Message(message) => {
                return Some(Ok(MessageView {
                    item: &message.item,
                    message: Cow::Borrowed(&message.message),
                    kind: MessageKind::Message,
                }));
            }
            Item::Item(fields) => (
                MessageView {
                    item: fields,
                    message: Cow::Owned(MessageFields::default()),
                    kind: MessageKind::Message,
                },
                CLASS_NOTE,
            ),
            Item::PostItem(post) => (
                MessageView {
                    item: &post.item,
                    message: Cow::Owned(MessageFields {
                        from: post.post.from.clone(),
                        is_read: post.post.is_read,
                        references: post.post.references.clone(),
                        ..MessageFields::default()
                    }),
                    kind: MessageKind::Post,
                },
                CLASS_POST,
            ),
            _ => return None,
        };
        Some(match view.item.item_class.as_deref() {
            Some(class) if !is_class_of(class, base) => Err(ItemError::ObjectTypeChanged),
            _ => Ok(view),
        })
    }
}

fn is_class_of(class: &str, base: &str) -> bool {
    class
        .split_at_checked(base.len())
        .is_some_and(|(head, rest)| {
            head.eq_ignore_ascii_case(base) && (rest.is_empty() || rest.starts_with('.'))
        })
}

pub(super) struct Stored<'x> {
    pub keywords: Vec<Keyword>,
    pub categories: CategoryNames<'x>,
    pub received_at: Option<u64>,
    pub carried: Vec<ExchangeProperty>,
    pub training: Training,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Training {
    InJunk,
    Never,
}

impl Training {
    fn trains(self, mailbox_id: u32) -> bool {
        self == Training::InJunk && mailbox_id == JUNK_ID
    }
}

pub(crate) async fn create_item(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &CreateItem<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let disposition = request
        .message_disposition
        .unwrap_or(MessageDisposition::SaveOnly);
    let save_copy = |mailbox_id| Target::Send {
        save_copy: Some(mailbox_id),
    };
    let responses: Vec<Option<EventResponse>> =
        request.items.iter().map(EventResponse::of).collect();
    let has_responses = responses.iter().any(Option::is_some);
    let has_mail = request
        .items
        .iter()
        .zip(&responses)
        .any(|(item, response)| {
            response.is_none()
                && !matches!(
                    item,
                    Item::Contact(_)
                        | Item::DistributionList(_)
                        | Item::Task(_)
                        | Item::CalendarItem(_)
                        | Item::Other(ItemKind::Network | ItemKind::RoleMember, _)
                )
        });
    let has_contacts = request
        .items
        .iter()
        .any(|item| matches!(item, Item::Contact(_) | Item::DistributionList(_)));
    let has_tasks = request
        .items
        .iter()
        .any(|item| matches!(item, Item::Task(_)));
    let has_events = request
        .items
        .iter()
        .any(|item| matches!(item, Item::CalendarItem(_)));
    let mail = if has_mail {
        let target = match (disposition, &request.saved_item_folder_id) {
            (MessageDisposition::SendOnly | MessageDisposition::SendAndSaveCopy, _)
                if !ctx.access.sends_as_owner() =>
            {
                Err(ItemError::Forbidden.status())
            }
            (MessageDisposition::SendOnly, _) => Ok(Target::Send { save_copy: None }),
            (MessageDisposition::SaveOnly, Some(id)) => {
                saved_destination(server, ctx, id).await?.map(Target::Save)
            }
            (MessageDisposition::SaveOnly, None) => {
                match default_folder(server, account_id, SpecialUse::Drafts).await? {
                    Ok(drafts) if may_write_mailbox(ctx, drafts, ItemWrite::Create) => {
                        Ok(Target::Save(drafts))
                    }
                    Ok(_) => Err(ItemError::Forbidden.status()),
                    Err(status) => Err(status),
                }
            }
            (MessageDisposition::SendAndSaveCopy, Some(id)) => {
                sent_destination(server, ctx, id).await?.map(save_copy)
            }
            (MessageDisposition::SendAndSaveCopy, None) => {
                default_folder(server, account_id, SpecialUse::Sent)
                    .await?
                    .map(save_copy)
            }
        };
        Some((target, EmailIds::load(server, ctx).await?))
    } else {
        None
    };
    let contacts = if has_contacts {
        Some(Contacts::load(server, ctx).await?)
    } else {
        None
    };
    let mut contact_side = match &contacts {
        Some(Ok(contacts)) => Some(
            contact_destination(server, ctx, request.saved_item_folder_id.as_ref())
                .await?
                .map(|book| (ContactWriter::new(server, caller, contacts), book)),
        ),
        Some(Err(err)) => Some(Err(err.status())),
        None => None,
    };
    let tasks = if has_tasks {
        Some(Tasks::load(server, ctx).await?)
    } else {
        None
    };
    let mut task_side = match &tasks {
        Some(Ok(tasks)) => Some(
            task_destination(server, ctx, caller, request.saved_item_folder_id.as_ref())
                .await?
                .map(|list| (TaskWriter::new(server, caller, tasks), list)),
        ),
        Some(Err(err)) => Some(Err(err.status())),
        None => None,
    };
    let events = if has_events || has_responses {
        Some(Events::load(server, ctx).await?)
    } else {
        None
    };
    let mut event_side = match &events {
        Some(Ok(events)) if has_events => Some(
            calendar_destination(server, ctx, caller, request.saved_item_folder_id.as_ref())
                .await?
                .map(|calendar| (CalendarWriter::new(server, caller, events), calendar)),
        ),
        Some(Err(err)) if has_events => Some(Err(err.status())),
        _ => None,
    };
    let responder = match &events {
        _ if !ctx.access.sends_as_owner() => Err(ItemError::Forbidden),
        Some(Ok(events)) => Ok(CalendarWriter::new(server, caller, events)),
        Some(Err(err)) => Err(*err),
        None => Err(ItemError::NotFound),
    };
    let response_send = match request.message_disposition {
        Some(MessageDisposition::SaveOnly) => Ok(MeetingSend::Suppress),
        Some(MessageDisposition::SendOnly) => Ok(MeetingSend::Send),
        Some(MessageDisposition::SendAndSaveCopy) => Ok(MeetingSend::SendAndSave),
        None => Err(ItemError::DispositionRequired),
    };
    let invitations = if responses
        .iter()
        .flatten()
        .any(|response| matches!(response.target, ResponseTarget::Invitation))
    {
        Some((
            EmailIds::load(server, ctx).await?,
            server.get_cached_messages(account_id).await?,
        ))
    } else {
        None
    };
    let send = create_send(request.send_meeting_invitations);

    let mut response_copies = SentFolder::new(request.saved_item_folder_id.as_ref());
    let mut event_copies = SentFolder::new(None);
    let mut results = Vec::with_capacity(request.items.len());
    for (item, response) in request.items.iter().zip(&responses) {
        if has_invalid_extended_property(item) {
            results.push(Err(ItemError::InvalidExtendedProperty.status()));
            continue;
        }
        if let Some(response) = response {
            let answered = match (&responder, &response_send) {
                (Ok(writer), &Ok(send)) => {
                    let mut invitation = None;
                    let target = match response.target {
                        ResponseTarget::Event {
                            account,
                            event,
                            scope,
                        } => writer
                            .items
                            .check(account, event)
                            .map(|event| InvitedEvent {
                                event,
                                scope,
                                imported: None,
                            }),
                        ResponseTarget::Invitation => {
                            match (&invitations, response_reference(item)) {
                                (Some((ids, cache)), Some(reference)) => {
                                    match mail_invitation(server, ctx, ids, cache, reference)
                                        .await?
                                    {
                                        Ok(mail) => {
                                            invitation = Some(mail.item());
                                            writer.invited(ctx, &mail).await?
                                        }
                                        Err(err) => Err(err),
                                    }
                                }
                                _ => Err(ItemError::NotFound),
                            }
                        }
                    };
                    let copies = match target {
                        Ok(InvitedEvent {
                            event,
                            scope,
                            imported,
                        }) => {
                            let fresh;
                            let writer = match &imported {
                                Some(events) => {
                                    fresh = CalendarWriter::new(server, caller, events);
                                    &fresh
                                }
                                None => writer,
                            };
                            match response.action {
                                EventAction::Respond(answer) => {
                                    let answered =
                                        writer.respond(event, scope, answer, send).await?;
                                    if answered.is_ok()
                                        && let Some(item) = invitation
                                    {
                                        file_answered_request(server, ctx, caller, item, send)
                                            .await;
                                    }
                                    answered.map(|copies| (copies, None))
                                }
                                EventAction::Cancel if send == MeetingSend::Suppress => {
                                    Err(ItemError::SaveOnlyCancel)
                                }
                                EventAction::Cancel => {
                                    writer.cancel(event, scope, send).await?.map(|copies| {
                                        (
                                            copies,
                                            Some(event_id_only(writer.items.unversioned_id(event))),
                                        )
                                    })
                                }
                            }
                        }
                        Err(err) => Err(err),
                    };
                    match copies {
                        Ok((copies, cancelled)) => {
                            response_copies.save(server, ctx, caller, copies).await;
                            Ok(cancelled)
                        }
                        Err(err) => Err(err),
                    }
                }
                (Err(err), _) | (_, Err(err)) => Err(*err),
            };
            results.push(answered.map_err(ItemError::status));
            continue;
        }
        results.push(match item {
            Item::Contact(contact) => match &mut contact_side {
                Some(Ok((writer, book))) => writer
                    .create(*book, contact)
                    .await?
                    .map(|id| Some(contact_id_only(id)))
                    .map_err(ItemError::status),
                Some(Err(status)) => Err(status.clone()),
                None => Err(ItemError::ContactFolder.status()),
            },
            Item::DistributionList(list) => match &mut contact_side {
                Some(Ok((writer, book))) => writer
                    .create_list(*book, list)
                    .await?
                    .map(|id| Some(list_id_only(id)))
                    .map_err(ItemError::status),
                Some(Err(status)) => Err(status.clone()),
                None => Err(ItemError::ContactFolder.status()),
            },
            Item::Task(task) => match &mut task_side {
                Some(Ok((writer, list))) => writer
                    .create(*list, task)
                    .await?
                    .map(|id| Some(task_id_only(id)))
                    .map_err(ItemError::status),
                Some(Err(status)) => Err(status.clone()),
                None => Err(ItemError::TaskFolder.status()),
            },
            Item::CalendarItem(event) => match (&mut event_side, send) {
                (Some(Ok((writer, calendar))), Ok(send)) => {
                    match writer.create(*calendar, event, send).await? {
                        Ok((id, copies)) => {
                            event_copies.save(server, ctx, caller, copies).await;
                            Ok(Some(event_id_only(id)))
                        }
                        Err(err) => Err(err.status()),
                    }
                }
                (_, Err(err)) => Err(err.status()),
                (Some(Err(status)), _) => Err(status.clone()),
                (None, _) => Err(ItemError::CalendarFolder.status()),
            },
            Item::Other(ItemKind::Network | ItemKind::RoleMember, _) => Ok(None),
            Item::Message(_)
            | Item::MeetingMessage(_)
            | Item::MeetingRequest(_)
            | Item::MeetingResponse(_)
            | Item::MeetingCancellation(_)
                if request.message_disposition.is_none() =>
            {
                Err(ItemError::DispositionRequired.status())
            }
            _ => match &mail {
                Some((Ok(target), ids)) => create_one(server, ctx, caller, ids, item, *target)
                    .await?
                    .map(|created| created.map(id_only)),
                Some((Err(status), _)) => Err(status.clone()),
                None => Err(ItemError::NotAMessage.status()),
            },
        });
    }

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::CreateItem);
    for result in results {
        match result {
            Ok(created) => messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(ItemInfoMessage {
                    items: created.into_iter().collect(),
                }),
            }),
            Err(status) => {
                messages.message(&MessageResult::<ItemInfoMessage> { status, body: None })
            }
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

async fn create_one(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    ids: &EmailIds,
    item: &Item<'_>,
    target: Target,
) -> trc::Result<Result<Option<ItemId<'static>>, Status<'static>>> {
    if let Err(err) = mail_allowed(ctx) {
        return Ok(Err(err.status()));
    }
    let message = match MessageView::of(item) {
        Some(Ok(message)) => message,
        Some(Err(err)) => return Ok(Err(err.status())),
        None => return Ok(Err(ItemError::NotAMessage.status())),
    };
    let fields = &message.message;
    if fields.conversation_index.is_some()
        || fields.conversation_topic.is_some()
        || fields.received_by.is_some()
        || fields.received_representing.is_some()
    {
        return Ok(Err(ItemError::InvalidPropertySet.status()));
    }
    let owner = if message.item.mime_content.is_none()
        && fields.from.is_none()
        && (fields.is_read_receipt_requested == Some(true)
            || fields.is_delivery_receipt_requested == Some(true))
    {
        Some(server.account_info(ctx.account.account_id).await?)
    } else {
        None
    };
    let receipt_to = owner.as_ref().and_then(|owner| {
        owner.addresses.first().map(|address| {
            Address::new_address(owner.account.description.as_deref(), address.as_str())
        })
    });
    let raw = match message_raw(&message, receipt_to, server.core.email.mail_max_size) {
        Ok(raw) => raw,
        Err(err) => return Ok(Err(err.status())),
    };
    match target {
        Target::Save(mailbox_id) => {
            let stored = match Stored::from_message(&message) {
                Ok(stored) => stored,
                Err(err) => return Ok(Err(err.status())),
            };
            Ok(save(server, ctx, caller, ids, mailbox_id, &raw, stored)
                .await?
                .map(Some)
                .map_err(ItemError::status))
        }
        Target::Send { save_copy } => {
            let stored = match Stored::from_message(&message) {
                Ok(stored) => stored,
                Err(err) => return Ok(Err(err.status())),
            };
            let carried = ExchangeObject {
                properties: stored.carried,
                conflict: None,
            };
            if save_copy.is_some()
                && usize::try_from(carried.quota_size()).unwrap_or(usize::MAX)
                    > server.core.exchange.max_object_size
            {
                return Ok(Err(ItemError::TooLarge.status()));
            }
            let recipients = match explicit_recipients(&message) {
                Ok(recipients) => recipients,
                Err(err) => return Ok(Err(err.status())),
            };
            let delivery_report = match message.message.is_delivery_receipt_requested {
                Some(true) => DeliveryReport::Requested,
                Some(false) => DeliveryReport::Default,
                None => DeliveryReport::FromMessage,
            };
            Ok(server
                .submit(Submission {
                    access_token: caller.access_token,
                    account_id: ctx.account.account_id,
                    instance: &caller.session.instance,
                    session_id: caller.session.session_id,
                    message: Outgoing::Composed {
                        raw,
                        save_copy: save_copy.map(|mailbox_id| SaveCopy {
                            mailbox_id,
                            carried: (!carried.is_empty()).then_some(carried),
                        }),
                    },
                    recipients,
                    options: SubmitOptions {
                        delivery_report,
                        ..Default::default()
                    },
                })
                .await?
                .map(|_| None)
                .map_err(|err| submit_status(err, SubmitSource::Composed)))
        }
    }
}

pub(super) async fn save(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    ids: &EmailIds,
    mailbox_id: u32,
    raw: &[u8],
    stored: Stored<'_>,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let account_id = ctx.account.account_id;
    let session_id = caller.session.session_id;
    let mut keywords = stored.keywords;
    let mut spellings = SpellingChanges::default();
    match AccountCategories::new(ids.exchange()).add_keywords(
        &server.core.email.limits,
        &stored.categories,
        &mut keywords,
        &mut spellings,
    ) {
        CategoryOutcome::Changed | CategoryOutcome::Renamed | CategoryOutcome::Unchanged => {}
        CategoryOutcome::KeywordLimit => return Ok(Err(ItemError::KeywordLimit)),
        CategoryOutcome::InvalidName => return Ok(Err(ItemError::CategoryInvalid)),
    }
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    let target_token = server
        .exchange_target_token(caller.access_token, account_id)
        .await?;
    let result = server
        .create_email(
            IngestEmail {
                raw_message: raw,
                blob_hash: None,
                message: MessageParser::new().parse(raw).as_ref(),
                access_token: target_token.as_ref().unwrap_or(caller.access_token),
                mailbox_ids: vec![mailbox_id],
                keywords,
                received_at: stored.received_at,
                source: IngestSource::Jmap {
                    train_classifier: stored.training.trains(mailbox_id),
                },
                metadata: None,
                session_id,
            },
            owner,
            CreatedEmail {
                spellings,
                carried: (!stored.carried.is_empty()).then_some(ExchangeObject {
                    properties: stored.carried,
                    conflict: None,
                }),
                ..Default::default()
            },
            server.core.exchange.max_object_size,
        )
        .await;
    let ingested = match result {
        Ok(ingested) => ingested,
        Err(err) => return ingest_error(err).map(Err),
    };
    server
        .broadcast_push_notification(PushNotification::StateChange(
            StateChange::new(account_id)
                .with_change_id(ingested.change_id)
                .with_change(DataType::Email)
                .with_change(DataType::Mailbox)
                .with_change(DataType::Thread),
        ))
        .await;
    Ok(Ok(ids.item_id(
        MailItem {
            mailbox_id,
            document_id: ingested.document_id,
        },
        ingested.change_id,
    )))
}

pub(super) struct SentFolder<'x> {
    folder: Option<&'x TargetFolderId<'x>>,
    resolved: Option<Option<(EmailIds, u32)>>,
}

impl<'x> SentFolder<'x> {
    pub fn new(folder: Option<&'x TargetFolderId<'x>>) -> Self {
        SentFolder {
            folder,
            resolved: None,
        }
    }

    pub async fn save(
        &mut self,
        server: &Server,
        ctx: &EwsContext,
        caller: EwsCaller<'_>,
        copies: SentCopies,
    ) {
        if copies.is_empty() || mail_allowed(ctx).is_err() {
            return;
        }
        if self.resolved.is_none() {
            self.resolved = Some(copy_folder(server, ctx, self.folder).await);
        }
        let Some(Some((ids, mailbox_id))) = &self.resolved else {
            return;
        };
        if !may_write_mailbox(ctx, *mailbox_id, ItemWrite::Create) {
            return;
        }
        for raw in copies.messages() {
            let stored = Stored {
                keywords: vec![Keyword::Seen],
                categories: CategoryNames::new(),
                received_at: None,
                carried: Vec::new(),
                training: Training::Never,
            };
            match save(server, ctx, caller, ids, *mailbox_id, &raw, stored).await {
                Ok(Ok(_)) => {}
                Ok(Err(err)) => copy_trouble(format!("not saved: {err:?}")),
                Err(err) => {
                    trc::error!(err.caused_by(trc::location!()));
                }
            }
        }
    }
}

async fn copy_folder(
    server: &Server,
    ctx: &EwsContext,
    folder: Option<&TargetFolderId<'_>>,
) -> Option<(EmailIds, u32)> {
    let ids = match EmailIds::load(server, ctx).await {
        Ok(ids) => ids,
        Err(err) => {
            trc::error!(err.caused_by(trc::location!()));
            return None;
        }
    };
    if let Some(folder) = folder {
        match sent_destination(server, ctx, folder).await {
            Ok(Ok(mailbox_id)) => return Some((ids, mailbox_id)),
            Ok(Err(status)) => copy_trouble(format!(
                "SavedItemFolderId unusable, using Sent Items: {status:?}"
            )),
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                return None;
            }
        }
    }
    match default_folder(server, ctx.account.account_id, SpecialUse::Sent).await {
        Ok(Ok(mailbox_id)) => Some((ids, mailbox_id)),
        Ok(Err(status)) => {
            copy_trouble(format!("not saved, no Sent Items folder: {status:?}"));
            None
        }
        Err(err) => {
            trc::error!(err.caused_by(trc::location!()));
            None
        }
    }
}

#[cold]
fn copy_trouble(details: String) {
    trc::error!(
        trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
            .into_err()
            .details(format!("EWS meeting copy {details}"))
            .caused_by(trc::location!())
    );
}

pub(super) fn ingest_error(err: trc::Error) -> trc::Result<ItemError> {
    match err.as_ref() {
        trc::EventType::Limit(trc::LimitEvent::Quota) => Ok(ItemError::Quota),
        #[cfg(feature = "enterprise")]
        trc::EventType::Limit(trc::LimitEvent::TenantQuota) => Ok(ItemError::Quota),
        trc::EventType::Limit(trc::LimitEvent::SizeRequest) => Ok(ItemError::TooLarge),
        trc::EventType::MessageIngest(trc::MessageIngestEvent::Error) => Ok(ItemError::Unparsable),
        _ => Err(err),
    }
}

pub(super) fn message_raw(
    message: &MessageView<'_>,
    receipt_to: Option<Address<'_>>,
    max_size: usize,
) -> Result<Vec<u8>, ItemError> {
    let raw = match message.item.mime_content.as_ref() {
        Some(mime) => decoded(&mime.content, max_size, ItemError::MimeInvalid)?.into_owned(),
        None => compose(message, receipt_to)?,
    };
    let raw = match message
        .item
        .attachments
        .as_ref()
        .filter(|attachments| !attachments.0.is_empty())
    {
        Some(attachments) => with_attachments(&raw, &attachments.0, max_size)?,
        None => raw,
    };
    if raw.len() > max_size {
        Err(ItemError::TooLarge)
    } else {
        Ok(raw)
    }
}

pub(super) fn decoded<'x>(
    binary: &'x XBinary<'_>,
    max_size: usize,
    invalid: ItemError,
) -> Result<Cow<'x, [u8]>, ItemError> {
    let bytes = match binary {
        XBinary::Parsed(text) => {
            let mut raw = Vec::new();
            if text
                .decode_into(&mut raw, max_size.saturating_add(BASE64_BLOCK_LEN))
                .is_err()
            {
                return Err(if raw.len() > max_size {
                    ItemError::TooLarge
                } else {
                    invalid
                });
            }
            Cow::Owned(raw)
        }
        XBinary::Bytes(bytes) => Cow::Borrowed(bytes.as_ref()),
        XBinary::Borrowed(bytes) => Cow::Borrowed(*bytes),
    };
    if bytes.len() > max_size {
        Err(ItemError::TooLarge)
    } else {
        Ok(bytes)
    }
}

fn compose(
    message: &MessageView<'_>,
    receipt_to: Option<Address<'_>>,
) -> Result<Vec<u8>, ItemError> {
    let item = &message.item;
    let mail = &message.message;
    let mut builder = MessageBuilder::new();
    let from = mail
        .from
        .as_ref()
        .map(|from| address(&from.0))
        .transpose()?;
    if let Some(from) = &from {
        builder = builder.from(from.clone());
    }
    if let Some(receipt_to) = from.clone().or(receipt_to) {
        if mail.is_delivery_receipt_requested == Some(true) {
            builder = builder.header(RETURN_RECEIPT_TO, receipt_to.clone());
        }
        if mail.is_read_receipt_requested == Some(true) {
            builder = builder.header(DISPOSITION_NOTIFICATION_TO, receipt_to);
        }
    }
    if let Some(list) = address_list(mail.to_recipients.as_ref())? {
        builder = builder.to(list);
    }
    if let Some(list) = address_list(mail.cc_recipients.as_ref())? {
        builder = builder.cc(list);
    }
    if let Some(list) = address_list(mail.bcc_recipients.as_ref())? {
        builder = builder.bcc(list);
    }
    if let Some(list) = address_list(mail.reply_to.as_ref())? {
        builder = builder.reply_to(list);
    }
    if let Some(subject) = &item.subject {
        builder = builder.subject(subject.as_ref());
    }
    match item.importance {
        Some(Importance::High) => builder = builder.header("Importance", Raw::new("high")),
        Some(Importance::Low) => builder = builder.header("Importance", Raw::new("low")),
        Some(Importance::Normal) | None => {}
    }
    if let Some(in_reply_to) = item.in_reply_to.as_deref().and_then(header_value) {
        builder = builder.header("In-Reply-To", Raw::new(in_reply_to));
    }
    if let Some(references) = mail.references.as_deref().and_then(header_value) {
        builder = builder.header("References", Raw::new(references));
    }
    builder = match &item.body {
        Some(body) if body.body_type == BodyType::Html => builder.html_body(body.text.as_ref()),
        Some(body) => builder.text_body(body.text.as_ref()),
        None => builder.text_body(""),
    };
    builder.write_to_vec().map_err(|_| ItemError::Unparsable)
}

fn header_value(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

pub(super) fn address<'x>(mailbox: &'x EmailAddress<'x>) -> Result<Address<'x>, ItemError> {
    let email = mailbox
        .email_address
        .as_deref()
        .filter(|email| !email.is_empty() && email.chars().all(is_addr_spec_char))
        .ok_or(ItemError::NoAddress)?;
    Ok(Address::new_address(mailbox.name.as_deref(), email))
}

fn is_addr_spec_char(ch: char) -> bool {
    !ch.is_control() && !ch.is_whitespace() && !matches!(ch, '<' | '>' | ',' | ';' | '"')
}

fn address_list<'x>(list: Option<&'x EwsRecipients<'x>>) -> Result<Option<Address<'x>>, ItemError> {
    match list {
        Some(list) if !list.0.is_empty() => Ok(Some(Address::new_list(
            list.0.iter().map(address).collect::<Result<_, _>>()?,
        ))),
        _ => Ok(None),
    }
}

fn explicit_recipients(message: &MessageView<'_>) -> Result<Recipients, ItemError> {
    let mail = &message.message;
    let lists = [
        &mail.to_recipients,
        &mail.cc_recipients,
        &mail.bcc_recipients,
    ];
    if message.item.mime_content.is_none()
        || lists
            .iter()
            .all(|list| list.as_ref().is_none_or(|list| list.0.is_empty()))
    {
        return Ok(Recipients::Headers);
    }
    let mut addresses = Vec::with_capacity(
        lists
            .iter()
            .filter_map(|list| list.as_ref())
            .map(|list| list.0.len())
            .sum(),
    );
    for mailbox in lists.into_iter().flatten().flat_map(|list| &list.0) {
        let email = mailbox
            .email_address
            .as_deref()
            .filter(|email| !email.is_empty())
            .ok_or(ItemError::NoAddress)?;
        addresses.push(email.to_string());
    }
    Ok(Recipients::Explicit(addresses))
}

impl<'x> Stored<'x> {
    pub(super) fn from_message(message: &MessageView<'x>) -> Result<Self, ItemError> {
        let mut seen = None;
        let mut draft = None;
        let mut flagged = false;
        let mut answered = false;
        let mut forwarded = false;
        let mut deleted = false;
        let mut received_at = None;
        let mut carried = Vec::new();
        let mut keys = None;
        let mut categories = message
            .item
            .categories
            .as_ref()
            .map(|names| names.0.iter().map(AsRef::as_ref).collect())
            .unwrap_or_default();
        let properties = message
            .item
            .extended_property
            .as_ref()
            .map_or(&[][..], |properties| properties.0.as_slice());
        if let Some(requested) = message.message.is_response_requested {
            keys.get_or_insert_with(FlagKeys::new)
                .response_requested_edit(Some(requested), stored_edit(&mut carried));
        }
        for property in properties {
            let number = || xprop_int(&property.value).ok_or(ItemError::InvalidPropertySet);
            match ItemProp::of_extended(&property.uri).map(|(_, prop)| prop) {
                Some(ItemProp::MessageFlags) => {
                    let flags = number()?;
                    seen = Some(flags & MSGFLAG_READ != 0);
                    draft = Some(flags & MSGFLAG_UNSENT != 0);
                }
                Some(ItemProp::FlagStatus) => {
                    let status = number()?;
                    flagged = status == FLAG_STATUS_FLAGGED;
                    if status == FLAG_STATUS_COMPLETED {
                        keys.get_or_insert_with(FlagKeys::new)
                            .status_edit(true, stored_edit(&mut carried));
                    }
                }
                Some(ItemProp::LastVerb) => {
                    let verb = number()?;
                    match verb {
                        VERB_REPLY_TO_SENDER | VERB_REPLY_TO_ALL => answered = true,
                        VERB_FORWARD => forwarded = true,
                        _ => return Err(ItemError::InvalidPropertySet),
                    }
                    keys.get_or_insert_with(FlagKeys::new).verb_edit(
                        i32::try_from(verb).ok().and_then(LastVerb::from_mapi),
                        stored_edit(&mut carried),
                    );
                }
                Some(ItemProp::ImapDeleted) => deleted = number()? != 0,
                Some(ItemProp::Received) => {
                    received_at = Some(received(&property.value)?);
                }
                Some(ItemProp::Keywords) => match &property.value {
                    XPropValue::Multi(names) => {
                        categories = names.iter().map(AsRef::as_ref).collect();
                    }
                    XPropValue::Single(_) => return Err(ItemError::InvalidPropertySet),
                },
                None if is_ignored_tag(&property.uri.target) => {}
                None => carried.push(carried_property(property)?),
                Some(_) => return Err(ItemError::InvalidPropertySet),
            }
        }
        let flag = stored_flag(message.item.flag.as_ref())?;
        if flag.status.is_some() {
            flagged |= flag.status == Some(FLAG_STATUS_ACTIVE);
            keys.get_or_insert_with(FlagKeys::new)
                .ews_edits(&flag, stored_edit(&mut carried));
        }
        carried.sort_by(|a, b| a.key.cmp(&b.key));
        carried.dedup_by(|a, b| a.key == b.key);
        if let Some(is_read) = message.message.is_read {
            seen = Some(is_read);
        }
        let unset_default = message.kind == MessageKind::Message;
        let mut keywords = Vec::with_capacity(6);
        for (set, keyword) in [
            (seen.unwrap_or(unset_default), Keyword::Seen),
            (draft.unwrap_or(unset_default), Keyword::Draft),
            (flagged, Keyword::Flagged),
            (answered, Keyword::Answered),
            (forwarded, Keyword::Forwarded),
            (deleted, Keyword::Deleted),
        ] {
            if set {
                keywords.push(keyword);
            }
        }
        Ok(Stored {
            keywords,
            categories,
            received_at,
            carried,
            training: Training::InJunk,
        })
    }
}

fn stored_edit(
    carried: &mut Vec<ExchangeProperty>,
) -> impl FnMut(&[u8], Option<OwnedPropValue>) + '_ {
    move |key, value| {
        if let Some(value) = value {
            let mut encoded = Vec::new();
            value.write_canonical(&mut encoded);
            carried.push(ExchangeProperty {
                key: key.to_vec(),
                value: encoded,
            });
        }
    }
}

pub(super) fn carried_property(
    property: &ExtendedProperty<'_>,
) -> Result<ExchangeProperty, ItemError> {
    let (key, ptype) = property
        .uri
        .to_prop()
        .map_err(|_| ItemError::InvalidPropertySet)?;
    if !is_carried(&property.uri, key.as_ref()) {
        return Err(ItemError::InvalidPropertySet);
    }
    let value = property
        .value
        .to_owned_value(ptype)
        .map_err(|_| ItemError::InvalidPropertySet)?;
    Ok(encode_property(key.as_ref(), &value))
}

fn has_invalid_extended_property(item: &Item<'_>) -> bool {
    item.fields()
        .extended_property
        .as_ref()
        .is_some_and(|properties| {
            properties
                .0
                .iter()
                .any(|property| property.uri.target == XPropTarget::InvalidCombination)
        })
}

fn received(value: &XPropValue<'_>) -> Result<u64, ItemError> {
    let XPropValue::Single(text) = value else {
        return Err(ItemError::InvalidPropertySet);
    };
    text.trim()
        .parse::<Timestamp>()
        .ok()
        .and_then(|time| u64::try_from(time.as_second()).ok())
        .ok_or(ItemError::InvalidPropertySet)
}
