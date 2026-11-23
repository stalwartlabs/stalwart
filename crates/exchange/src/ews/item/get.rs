/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError,
    attachment::MAX_CONTENT_BYTES,
    bulk::{AssociatedId, get_associated},
    fields::{ItemFieldSet, ShapeUse},
    recipients::RecipientNames,
    render::{DisplayNames, LoadedMail, MailShape, MailView, render},
};
use crate::ews::{
    calendar::{Events, instance::EventTarget, invitation::MeetingValues},
    contact::Contacts,
    context::EwsContext,
    delegate::Representing,
    directory::ALL_DL_MEMBERS,
    groupware::{
        GroupwareFields, GroupwareKind,
        items::{GroupwareItems, GroupwareRef, decode_item},
    },
    reply::{RESPONSE_CAPACITY, ews_response},
    task::Tasks,
};
use common::Server;
use email::cache::MessageCacheFetch;
use exchange_proto::{
    convert::vcard::is_contact_group,
    ews::{
        MessageResult, Operation, Status,
        calendar::CalendarFieldSet,
        contact::ContactFieldSet,
        envelope::MessagesWriter,
        requests::item::GetItem,
        responses::item::ItemInfoMessage,
        schema::ResponseCode,
        task::TaskFieldSet,
        types::{ids::BaseItemId, item::Item, value::List},
    },
};
use http_proto::HttpResponse;

const BATCH_STOPPED: &str =
    "The response size limit was reached; request the remaining items separately.";

pub(crate) async fn get_item(
    server: &Server,
    ctx: &EwsContext,
    request: &GetItem<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let targets = request
        .item_ids
        .iter()
        .map(Target::with_associated)
        .collect::<Vec<_>>();
    let contacts = if targets
        .iter()
        .any(|target| matches!(target, Target::Contact(..)))
    {
        Some(Contacts::load(server, ctx).await?)
    } else {
        None
    };
    let tasks = if targets
        .iter()
        .any(|target| matches!(target, Target::Task(..)))
    {
        Some(Tasks::load(server, ctx).await?)
    } else {
        None
    };
    let mut state = MailRender::default();
    if targets.iter().any(|target| {
        matches!(
            target,
            Target::Event(..) | Target::Occurrence(..) | Target::Indexed(..)
        )
    }) {
        state.events = Some(Events::load(server, ctx).await?);
    }
    let mail_side = if targets.iter().any(|target| matches!(target, Target::Mail)) {
        Some((
            EmailIds::load(server, ctx).await?,
            server.get_cached_messages(account_id).await?,
        ))
    } else {
        None
    };
    let mut shape = MailShape::new(&request.shape, ShapeUse::Get);
    if mail_side.is_some() {
        shape.load_receiver(server, account_id).await?;
    }
    let contact_fields = ContactFieldSet::from_shape(&request.shape).with_kind();
    let task_fields = TaskFieldSet::from_shape(&request.shape);
    let event_fields = CalendarFieldSet::from_shape(&request.shape);
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::GetItem);
    let budget = MAX_CONTENT_BYTES.max(server.core.email.mail_max_size);
    for (id, target) in request.item_ids.iter().zip(targets) {
        if messages.written_bytes() > budget {
            messages.message(&MessageResult::<ItemInfoMessage> {
                status: Status::warning(ResponseCode::ErrorBatchProcessingStopped, BATCH_STOPPED),
                body: None,
            });
            continue;
        }
        match target {
            Target::Contact(account, contact) => {
                contact_message(
                    server,
                    &mut messages,
                    contacts.as_ref(),
                    account,
                    contact,
                    contact_fields,
                )
                .await?
            }
            Target::Task(account, task) => {
                groupware_message(
                    server,
                    &mut messages,
                    tasks.as_ref(),
                    account,
                    task,
                    task_fields,
                )
                .await?
            }
            Target::Event(account, event) => {
                groupware_message(
                    server,
                    &mut messages,
                    state.events.as_ref(),
                    account,
                    event,
                    event_fields,
                )
                .await?
            }
            Target::Occurrence(account, event, _) | Target::Indexed(account, event, _) => {
                let item = match &state.events {
                    Some(Ok(events)) => match (events.check(account, event), target) {
                        (Ok(event), Target::Indexed(_, _, index)) => events
                            .load_indexed(server, event, index, event_fields)
                            .await?
                            .map(|loaded| (events, loaded)),
                        (Ok(event), Target::Occurrence(_, _, instance)) => events
                            .load_instance(server, event, instance, event_fields)
                            .await?
                            .map(|loaded| (events, loaded)),
                        (Ok(_), _) => Err(ItemError::NotFound),
                        (Err(err), _) => Err(err),
                    },
                    Some(Err(err)) => Err(*err),
                    None => Err(ItemError::NotFound),
                };
                item_message(
                    &mut messages,
                    item.as_ref()
                        .map(|(events, loaded)| events.render_instance(loaded, event_fields))
                        .map_err(|err| *err),
                );
            }
            Target::Associated(target) => {
                let item = match target {
                    Ok(target) => get_associated(server, ctx, target).await?,
                    Err(err) => Err(err),
                };
                item_message(&mut messages, item);
            }
            Target::Mail => {
                let Some((ids, cache)) = &mail_side else {
                    item_message(&mut messages, Err(ItemError::NotFound));
                    continue;
                };
                let loaded = match ids.resolve(ctx, cache, id) {
                    Ok(item) => LoadedMail::load(server, account_id, cache, item, &shape)
                        .await?
                        .ok_or(ItemError::NotFound),
                    Err(err) => Err(err),
                };
                let mut mail = match loaded {
                    Ok(mail) => mail,
                    Err(err) => {
                        item_message(&mut messages, Err(err));
                        continue;
                    }
                };
                mail.load_carried(server, account_id, ids.exchange(), &shape)
                    .await?;
                let headers = mail.headers()?;
                let view = MailView::new(&mail, &headers, false)?;
                let item = render_mail(server, ctx, &mut state, ids, &shape, &mail, &view).await?;
                item_message(&mut messages, Ok(item));
            }
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

#[derive(Default)]
pub(super) struct MailRender {
    pub events: Option<Result<Events, ItemError>>,
    pub representing: Representing,
    pub recipients: RecipientNames,
}

pub(super) async fn render_mail<'x>(
    server: &Server,
    ctx: &EwsContext,
    state: &mut MailRender,
    ids: &'x EmailIds,
    shape: &'x MailShape<'x>,
    mail: &'x LoadedMail<'_>,
    view: &'x MailView<'x>,
) -> trc::Result<Item<'x>> {
    let mut item = render(shape, ids, mail, view, DisplayNames::Resolved);
    state
        .recipients
        .apply(server, &ctx.caller, &mut item, view, shape.fields)
        .await?;
    let meeting_fields = match &item {
        Item::MeetingRequest(request) if request.message.is_response_requested.is_some() => Some(
            shape
                .fields
                .without(ItemFieldSet::MEETING_RESPONSE_REQUESTED),
        ),
        Item::MeetingRequest(_) => Some(shape.fields),
        Item::MeetingResponse(_) | Item::MeetingCancellation(_) => {
            Some(shape.fields.without(ItemFieldSet::MEETING_REQUEST_ONLY))
        }
        _ => None,
    };
    if let Some(fields) = meeting_fields.filter(|fields| fields.has(ItemFieldSet::MEETING)) {
        if state.events.is_none() && fields.has(ItemFieldSet::MEETING_LOOKUP) {
            state.events = Some(Events::load(server, ctx).await?);
        }
        let events = match &state.events {
            Some(Ok(events)) => Some(events),
            _ => None,
        };
        let values = MeetingValues::load(server, events, mail, view.headers(), fields).await?;
        let delegated = if fields.has(ItemFieldSet::MEETING_DELEGATED) {
            Some(match view.delegated_by() {
                Some(marker) => state
                    .representing
                    .principal(server, ids.account_id(), marker, view.recipient_addresses())
                    .await?
                    .is_some(),
                None => false,
            })
        } else {
            None
        };
        values.apply(&mut item, delegated);
    }
    if shape.fields.has(ItemFieldSet::RECEIVED_REPRESENTING)
        && let Some(address) = view.delegated_by()
    {
        let message = match &mut item {
            Item::MeetingRequest(request) => Some(&mut request.message),
            Item::MeetingResponse(response) => Some(&mut response.message),
            Item::MeetingCancellation(cancellation) => Some(&mut cancellation.message),
            _ => None,
        };
        if let Some(message) = message {
            message.received_representing = state
                .representing
                .of(
                    server,
                    ids.account_id(),
                    address,
                    view.recipient_addresses(),
                )
                .await?;
        }
    }
    Ok(item)
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Target {
    Contact(u32, GroupwareRef),
    Task(u32, GroupwareRef),
    Event(u32, GroupwareRef),
    Occurrence(u32, GroupwareRef, i64),
    Indexed(u32, GroupwareRef, usize),
    Associated(Result<AssociatedId, ItemError>),
    Mail,
}

impl Target {
    pub(super) fn with_associated(id: &BaseItemId<'_>) -> Self {
        match AssociatedId::decode(id) {
            Some(target) => Target::Associated(target),
            None => Target::of(id),
        }
    }

    pub(super) fn of(id: &BaseItemId<'_>) -> Self {
        match EventTarget::decode(id) {
            Some(EventTarget::Master(account, event)) => return Target::Event(account, event),
            Some(EventTarget::Instance(account, event, instance)) => {
                return Target::Occurrence(account, event, instance);
            }
            Some(EventTarget::Indexed(account, event, index)) => {
                return Target::Indexed(account, event, index);
            }
            None => {}
        }
        match decode_item(id) {
            Some((GroupwareKind::Contact, account, contact)) => Target::Contact(account, contact),
            Some((GroupwareKind::Task, account, task)) => Target::Task(account, task),
            Some((GroupwareKind::Event, account, event)) => Target::Event(account, event),
            None => Target::Mail,
        }
    }
}

async fn groupware_message<F: GroupwareFields>(
    server: &Server,
    messages: &mut MessagesWriter<'_>,
    items: Option<&Result<GroupwareItems<F>, ItemError>>,
    account: u32,
    item: GroupwareRef,
    fields: F,
) -> trc::Result<()> {
    match items {
        Some(Ok(items)) => {
            let loaded = match items.check(account, item) {
                Ok(item) => items.load_item(server, item, fields).await?,
                Err(err) => Err(err),
            };
            item_message(
                messages,
                loaded
                    .as_ref()
                    .map(|loaded| items.render(loaded, fields))
                    .map_err(|err| *err),
            );
        }
        Some(Err(err)) => item_message(messages, Err(*err)),
        None => item_message(messages, Err(ItemError::NotFound)),
    }
    Ok(())
}

async fn contact_message(
    server: &Server,
    messages: &mut MessagesWriter<'_>,
    contacts: Option<&Result<Contacts, ItemError>>,
    account: u32,
    contact: GroupwareRef,
    fields: ContactFieldSet,
) -> trc::Result<()> {
    let contacts = match contacts {
        Some(Ok(contacts)) if fields.has(ContactFieldSet::MEMBERS) => contacts,
        _ => return groupware_message(server, messages, contacts, account, contact, fields).await,
    };
    let opened = match contacts.check(account, contact) {
        Ok(contact) => contacts.open_card(server, contact).await?,
        Err(err) => Err(err),
    };
    let opened = match opened {
        Ok(opened) => opened,
        Err(err) => {
            item_message(messages, Err(err));
            return Ok(());
        }
    };
    let members = if is_contact_group(&opened.card) {
        Some(
            contacts
                .group_members(server, &opened.card, ALL_DL_MEMBERS)
                .await?,
        )
    } else {
        None
    };
    let mut item = contacts.render(&opened.loaded, fields);
    if let (Item::DistributionList(list), Some(members)) = (&mut item, &members) {
        list.list.members = Some(List(members.members(contacts).collect()));
    }
    item_message(messages, Ok(item));
    Ok(())
}

fn item_message(messages: &mut MessagesWriter<'_>, item: Result<Item<'_>, ItemError>) {
    match item {
        Ok(item) => messages.message(&MessageResult {
            status: Status::SUCCESS,
            body: Some(ItemInfoMessage { items: vec![item] }),
        }),
        Err(err) => messages.message(&MessageResult::<ItemInfoMessage> {
            status: err.status(),
            body: None,
        }),
    }
}
