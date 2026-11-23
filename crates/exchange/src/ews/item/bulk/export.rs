/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Parsed,
    associated::{AssociatedId, open_associated, raw_properties, record_of},
};
use crate::{
    ews::{
        calendar::Events,
        contact::Contacts,
        context::EwsContext,
        groupware::{
            GroupwareFields, GroupwareKind,
            items::{GroupwareItems, GroupwareRef},
            write::unreadable,
        },
        item::{EmailIds, ItemError, attachment::MAX_CONTENT_BYTES},
        reply::{RESPONSE_CAPACITY, ews_response},
        task::Tasks,
    },
    mail::fetch_raw_message,
    store::{
        folder::FaiMessage,
        object::{ExchangeObject, ExchangeObjectStore},
    },
};
use calcard::vcard::VCardVersion;
use common::{MessageStoreCache, Server};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::messagedata::{KEYWORD_BITS, SERVER_SET_KEYWORDS},
};
use exchange_proto::ews::{
    MessageResult, Operation, Status, bulk::BulkRecord, envelope::MessagesWriter,
    requests::bulk::ExportItems, responses::item::ExportItemsMessage, schema::ResponseCode,
    types::ids::ItemId,
};
use groupware::{calendar::CalendarEventContent, contact::ContactCardContent};
use http_proto::HttpResponse;
use smallvec::SmallVec;
use std::sync::Arc;
use trc::AddContext;
use types::{collection::Collection, keyword::Keyword};

const BATCH_STOPPED: &str =
    "The response size limit was reached; request the remaining items separately.";

pub(crate) async fn export_items(
    server: &Server,
    ctx: &EwsContext,
    request: &ExportItems<'_>,
) -> trc::Result<HttpResponse> {
    let parsed = request.item_ids.iter().map(Parsed::of).collect::<Vec<_>>();
    let wants = |kind| {
        parsed
            .iter()
            .any(|parsed| matches!(parsed, Ok(Parsed::Groupware(found, ..)) if *found == kind))
    };
    let mail = if parsed
        .iter()
        .any(|parsed| matches!(parsed, Ok(Parsed::Mail)))
    {
        Some((
            EmailIds::load(server, ctx).await?,
            server.get_cached_messages(ctx.account.account_id).await?,
        ))
    } else {
        None
    };
    let events = if wants(GroupwareKind::Event) {
        Some(Events::load(server, ctx).await?)
    } else {
        None
    };
    let tasks = if wants(GroupwareKind::Task) {
        Some(Tasks::load(server, ctx).await?)
    } else {
        None
    };
    let contacts = if wants(GroupwareKind::Contact) {
        Some(Contacts::load(server, ctx).await?)
    } else {
        None
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::ExportItems);
    let budget = MAX_CONTENT_BYTES.max(server.core.email.mail_max_size);
    for (id, parsed) in request.item_ids.iter().zip(parsed) {
        if messages.written_bytes() > budget {
            messages.message(&MessageResult::<ExportItemsMessage> {
                status: Status::warning(ResponseCode::ErrorBatchProcessingStopped, BATCH_STOPPED),
                body: None,
            });
            continue;
        }
        match parsed {
            Err(err) => failed(&mut messages, err),
            Ok(Parsed::Mail) => export_mail(server, ctx, &mut messages, mail.as_ref(), id).await?,
            Ok(Parsed::Groupware(GroupwareKind::Event, account, item)) => {
                export_calendar(server, &mut messages, events.as_ref(), account, item).await?
            }
            Ok(Parsed::Groupware(GroupwareKind::Task, account, item)) => {
                export_calendar(server, &mut messages, tasks.as_ref(), account, item).await?
            }
            Ok(Parsed::Groupware(GroupwareKind::Contact, account, item)) => {
                export_contact(server, &mut messages, contacts.as_ref(), account, item).await?
            }
            Ok(Parsed::Associated(target)) => {
                export_associated(server, ctx, &mut messages, target).await?
            }
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

async fn export_mail(
    server: &Server,
    ctx: &EwsContext,
    messages: &mut MessagesWriter<'_>,
    mail: Option<&(EmailIds, Arc<MessageStoreCache>)>,
    id: &ItemId<'_>,
) -> trc::Result<()> {
    let Some((ids, cache)) = mail else {
        failed(messages, ItemError::NotFound);
        return Ok(());
    };
    let item = match ids.resolve_item_id(ctx, cache, id) {
        Ok(item) => item,
        Err(err) => {
            failed(messages, err);
            return Ok(());
        }
    };
    let account_id = ids.account_id();
    let document_id = item.document_id;
    let (Some(data), Some((raw, _reservation))) = (
        cache.message_data(document_id),
        fetch_raw_message(server, account_id, document_id).await?,
    ) else {
        failed(messages, ItemError::NotFound);
        return Ok(());
    };
    let object = if ids.exchange().has_object(Collection::Email, document_id) {
        server
            .exchange_object(account_id, Collection::Email, document_id)
            .await
            .caused_by(trc::location!())?
    } else {
        None
    };
    let object = object
        .as_ref()
        .map(|object| object.unarchive::<ExchangeObject>())
        .transpose()?;
    let mut bits = data.keywords & KEYWORD_BITS & !SERVER_SET_KEYWORDS;
    let mut system = SmallVec::<[Keyword; 8]>::new();
    while bits != 0 {
        if let Ok(keyword) = Keyword::try_from_id(bits.trailing_zeros() as usize) {
            system.push(keyword);
        }
        bits &= bits - 1;
    }
    let keywords = system
        .iter()
        .map(Keyword::as_str)
        .chain(data.keywords_extra.iter().map(|keyword| keyword.as_str()))
        .collect();
    exported(
        messages,
        ids.item_id(item, data.change_id),
        BulkRecord::Email {
            raw: &raw,
            received_at: i64::try_from(data.received_at).ok(),
            keywords,
            properties: object.map_or_else(Vec::new, |object| {
                raw_properties(object.properties.as_slice())
            }),
        },
    );
    Ok(())
}

async fn export_calendar<F: GroupwareFields>(
    server: &Server,
    messages: &mut MessagesWriter<'_>,
    items: Option<&Result<GroupwareItems<F>, ItemError>>,
    account: u32,
    item: GroupwareRef,
) -> trc::Result<()> {
    let (items, item) = match checked(items, account, item) {
        Ok(checked) => checked,
        Err(err) => {
            failed(messages, err);
            return Ok(());
        }
    };
    let (change_id, archive) = match items.load_archive(server, item).await? {
        Ok(loaded) => loaded,
        Err(err) => {
            failed(messages, err);
            return Ok(());
        }
    };
    let content = match archive.deserialize::<CalendarEventContent>() {
        Ok(content) => content,
        Err(err) => {
            failed(messages, unreadable(err));
            return Ok(());
        }
    };
    let ical = items
        .event_view(item.document_id)
        .apply(content.data.event)
        .to_string();
    let record = match F::KIND {
        GroupwareKind::Task => BulkRecord::Task { ical: &ical },
        GroupwareKind::Event | GroupwareKind::Contact => BulkRecord::Event { ical: &ical },
    };
    exported(messages, items.item_id(item, change_id), record);
    Ok(())
}

async fn export_contact(
    server: &Server,
    messages: &mut MessagesWriter<'_>,
    contacts: Option<&Result<Contacts, ItemError>>,
    account: u32,
    item: GroupwareRef,
) -> trc::Result<()> {
    let (contacts, item) = match checked(contacts, account, item) {
        Ok(checked) => checked,
        Err(err) => {
            failed(messages, err);
            return Ok(());
        }
    };
    let (change_id, archive) = match contacts.load_archive(server, item).await? {
        Ok(loaded) => loaded,
        Err(err) => {
            failed(messages, err);
            return Ok(());
        }
    };
    let content = match archive.unarchive::<ContactCardContent>() {
        Ok(content) => content,
        Err(err) => {
            failed(messages, unreadable(err));
            return Ok(());
        }
    };
    let mut vcard = String::new();
    let _ = content.card.write_to(&mut vcard, VCardVersion::V4_0);
    exported(
        messages,
        contacts.item_id(item, change_id),
        BulkRecord::Contact { vcard: &vcard },
    );
    Ok(())
}

async fn export_associated(
    server: &Server,
    ctx: &EwsContext,
    messages: &mut MessagesWriter<'_>,
    target: AssociatedId,
) -> trc::Result<()> {
    match open_associated(server, ctx, target).await? {
        Ok(row) => {
            let fai = row.unarchive::<FaiMessage>()?;
            exported(
                messages,
                target.item_id(fai.change.to_native()),
                record_of(fai),
            );
        }
        Err(err) => failed(messages, err),
    }
    Ok(())
}

fn checked<F: GroupwareFields>(
    items: Option<&Result<GroupwareItems<F>, ItemError>>,
    account: u32,
    item: GroupwareRef,
) -> Result<(&GroupwareItems<F>, GroupwareRef), ItemError> {
    match items {
        Some(Ok(items)) => items.check(account, item).map(|item| (items, item)),
        Some(Err(err)) => Err(*err),
        None => Err(ItemError::NotFound),
    }
}

fn exported(messages: &mut MessagesWriter<'_>, item_id: ItemId<'static>, record: BulkRecord<'_>) {
    messages.message(&MessageResult {
        status: Status::SUCCESS,
        body: Some(ExportItemsMessage {
            item_id: Some(item_id),
            data: Some(record),
        }),
    });
}

fn failed(messages: &mut MessagesWriter<'_>, err: ItemError) {
    messages.message(&MessageResult::<ExportItemsMessage> {
        status: err.status(),
        body: None,
    });
}
