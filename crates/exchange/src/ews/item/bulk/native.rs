/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{associated::associated_content, parse_ical, parse_vcard};
use crate::{
    ews::{
        contact::{Contacts, write::ContactWriter},
        groupware::{GroupwareFields, contact_content, items::GroupwareRef, write::CalendarWriter},
        item::ItemError,
    },
    groupware_move::replace_card_uid,
    groupware_write::{card_name, new_uid, set_event_uid},
    mapi::emsmdb::message::{
        attach_row::{is_attachment_entry, is_valid_attachment_entry, merge_attachment_entries},
        object_row::{CarriedParts, decode_property},
    },
};
use calcard::icalendar::ICalendarComponentType;
use exchange_proto::{
    convert::{
        context::{ConvertOptions, NoDirectory},
        ical::{EventParts, event_parts_to_message, task_to_message},
        mime::mime_to_message,
        model::MessageContent,
    },
    ews::{bulk::BulkRecord, types::ids::ItemId},
};
use groupware::calendar::write::ItipMode;
use mail_parser::MessageParser;

pub(super) fn native_content(
    record: &BulkRecord<'_>,
    options: &ConvertOptions<'_>,
) -> Result<MessageContent, ItemError> {
    let converted = match record {
        BulkRecord::Email {
            raw, properties, ..
        } => {
            let parsed = MessageParser::new()
                .parse(*raw)
                .ok_or(ItemError::CorruptData)?;
            let mut content = mime_to_message(&parsed, &NoDirectory, options)
                .map_err(|_| ItemError::CorruptData)?;
            let mut parts = CarriedParts::default();
            for property in properties {
                if is_attachment_entry(property.key) {
                    if !is_valid_attachment_entry(property.key, property.value) {
                        return Err(ItemError::CorruptData);
                    }
                } else {
                    let (key, value) = decode_property(property.key, property.value)
                        .ok_or(ItemError::CorruptData)?;
                    if let Some(value) = parts.take(key.as_ref(), value) {
                        content.props.set(key, value);
                    }
                }
            }
            parts.apply_envelope(&mut content.props);
            merge_attachment_entries(
                properties
                    .iter()
                    .filter(|property| is_attachment_entry(property.key))
                    .map(|property| (property.key, property.value)),
                &mut content,
            );
            return Ok(content);
        }
        BulkRecord::Event { ical } => event_parts_to_message(
            &parse_ical(ical, &ICalendarComponentType::VEvent)?,
            None,
            EventParts::ALL,
            &NoDirectory,
            options,
        ),
        BulkRecord::Task { ical } => {
            task_to_message(&parse_ical(ical, &ICalendarComponentType::VTodo)?, options)
        }
        BulkRecord::Contact { vcard } => contact_content(&parse_vcard(vcard)?, options),
        BulkRecord::Associated {
            message_class,
            properties,
            recipients,
        } => return associated_content(message_class, properties, recipients),
    };
    converted.map_err(|_| ItemError::CorruptData)
}

pub(super) async fn create_calendar<F: GroupwareFields>(
    writer: &mut CalendarWriter<'_, F>,
    container: u32,
    text: &str,
    component: &ICalendarComponentType,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let mut ical = match parse_ical(text, component) {
        Ok(ical) => ical,
        Err(err) => return Ok(Err(err)),
    };
    if ical.uids().next().is_none() {
        set_event_uid(&mut ical, &new_uid());
    }
    if !writer.may_create(container, &ical) {
        return Ok(Err(ItemError::Forbidden));
    }
    match writer
        .create_ical(container, &new_uid(), ical, ItipMode::Suppress)
        .await?
    {
        Err(ItemError::UidConflict) => {}
        created => return Ok(created.map(|(id, _)| id)),
    }
    let mut ical = match parse_ical(text, component) {
        Ok(ical) => ical,
        Err(err) => return Ok(Err(err)),
    };
    set_event_uid(&mut ical, &new_uid());
    Ok(writer
        .create_ical(container, &new_uid(), ical, ItipMode::Suppress)
        .await?
        .map(|(id, _)| id))
}

pub(super) async fn update_calendar<F: GroupwareFields>(
    writer: &CalendarWriter<'_, F>,
    account: u32,
    item: GroupwareRef,
    container: u32,
    text: &str,
    component: &ICalendarComponentType,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let item = match writer.items.check(account, item) {
        Ok(item) if item.container == container => item,
        Ok(_) | Err(ItemError::Forbidden) => return Ok(Err(ItemError::NotFound)),
        Err(err) => return Ok(Err(err)),
    };
    let mut next = match parse_ical(text, component) {
        Ok(ical) => Some(ical),
        Err(err) => return Ok(Err(err)),
    };
    Ok(writer
        .update_ical(item, None, ItipMode::Suppress, |stored| {
            *stored = match next.take() {
                Some(ical) => ical,
                None => parse_ical(text, component)?,
            };
            Ok(())
        })
        .await?
        .map(|(change_id, _)| writer.items.item_id(item, change_id)))
}

pub(super) async fn create_contact(
    writer: &mut ContactWriter<'_>,
    address_book: u32,
    text: &str,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let mut card = match parse_vcard(text) {
        Ok(card) => card,
        Err(err) => return Ok(Err(err)),
    };
    if card.uid().is_none() {
        replace_card_uid(&mut card, &new_uid());
    }
    match writer
        .insert(address_book, card_name(&new_uid()), card)
        .await?
    {
        Err(ItemError::UidConflict) => {}
        created => return Ok(created),
    }
    let mut card = match parse_vcard(text) {
        Ok(card) => card,
        Err(err) => return Ok(Err(err)),
    };
    replace_card_uid(&mut card, &new_uid());
    writer
        .insert(address_book, card_name(&new_uid()), card)
        .await
}

pub(super) async fn update_contact(
    contacts: &Contacts,
    writer: &ContactWriter<'_>,
    account: u32,
    item: GroupwareRef,
    address_book: u32,
    text: &str,
) -> trc::Result<Result<ItemId<'static>, ItemError>> {
    let item = match contacts.check(account, item) {
        Ok(item) if item.container == address_book => item,
        Ok(_) | Err(ItemError::Forbidden) => return Ok(Err(ItemError::NotFound)),
        Err(err) => return Ok(Err(err)),
    };
    let mut next = match parse_vcard(text) {
        Ok(card) => Some(card),
        Err(err) => return Ok(Err(err)),
    };
    Ok(writer
        .replace(item, || match next.take() {
            Some(card) => Ok(card),
            None => parse_vcard(text),
        })
        .await?
        .and_then(|replaced| replaced.fields().item_id.clone().ok_or(ItemError::ItemSave)))
}
