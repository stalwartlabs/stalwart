/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Events;
use crate::ews::{
    groupware::{
        VersionedArchives,
        items::{GroupwareRef, LoadedItem},
    },
    item::ItemError,
};
use calcard::{common::timezone::Tz, icalendar::ICalendar};
use common::Server;
use exchange_proto::{
    common::XsDateTime,
    convert::{
        context::{ConvertOptions, NoDirectory},
        ical::event_parts_to_message,
    },
    ews::{
        MessageResult, Status,
        calendar::CalendarFieldSet,
        envelope::MessagesWriter,
        requests::find::FindItem,
        responses::{Paging, item::FindItemMessage},
        schema::ResponseCode,
        types::value::{M, T},
    },
};
use groupware::calendar::CalendarEventContent;
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{OverlapRule, TimeRange, collection::Collection, field::CalendarEventField};

const MAX_VIEW_INSTANCES: usize = 10_000;
const MAX_VIEW_SECONDS: i64 = 2 * 366 * 86_400;
const END_BEFORE_START: &str = "The end date of the calendar view is earlier than its start date.";
const RANGE_TOO_BIG: &str = "The calendar view range returns too many occurrences.";
const RANGE_TOO_LONG: &str = "The calendar view range is longer than two years.";
const DATE_INVALID: &str = "The calendar view dates are invalid.";

#[derive(Debug, Clone, Copy)]
pub(crate) struct CalendarView {
    pub max_entries: Option<u32>,
    pub start: XsDateTime,
    pub end: XsDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Instance {
    start: i64,
    document_id: u32,
    recurrence: Option<i64>,
}

pub(crate) async fn find_view(
    server: &Server,
    events: &Result<Events, ItemError>,
    request: &FindItem<'_>,
    calendar: u32,
    view: CalendarView,
    messages: &mut MessagesWriter<'_>,
) -> trc::Result<()> {
    let events = match events {
        Ok(events) => events,
        Err(err) => {
            messages.message(&MessageResult::<FindItemMessage> {
                status: err.status(),
                body: None,
            });
            return Ok(());
        }
    };
    let range = match (view.start.to_utc(), view.end.to_utc()) {
        (Some(start), Some(end)) if end.0 < start.0 => {
            return view_error(
                messages,
                ResponseCode::ErrorCalendarEndDateIsEarlierThanStartDate,
                END_BEFORE_START,
            );
        }
        (Some(start), Some(end)) if end.0.saturating_sub(start.0) > MAX_VIEW_SECONDS => {
            return view_error(
                messages,
                ResponseCode::ErrorCalendarViewRangeTooBig,
                RANGE_TOO_LONG,
            );
        }
        (Some(start), Some(end)) => TimeRange {
            start: start.0,
            end: end.0,
        },
        _ => {
            return view_error(messages, ResponseCode::ErrorInvalidRequest, DATE_INVALID);
        }
    };
    let Some(mut instances) = expand(server, events, calendar, range).await? else {
        return view_error(
            messages,
            ResponseCode::ErrorCalendarViewRangeTooBig,
            RANGE_TOO_BIG,
        );
    };
    instances.sort_unstable();
    let total = instances.len();
    if let Some(max) = view.max_entries {
        instances.truncate(usize::try_from(max).unwrap_or(usize::MAX));
    }
    let documents = instances
        .iter()
        .map(|instance| instance.document_id)
        .collect::<RoaringBitmap>();
    let archives = VersionedArchives::read(
        server,
        events.account_id,
        Collection::CalendarEvent,
        CalendarEventField::Content.into(),
        &documents,
        true,
    )
    .await?;
    let mut parsed = Vec::with_capacity(documents.len().try_into().unwrap_or_default());
    for document_id in &documents {
        let (Some(change_id), Some(content)) = (
            archives.change_id(document_id),
            archives.content(document_id),
        ) else {
            continue;
        };
        match content.deserialize::<CalendarEventContent>() {
            Ok(content) => parsed.push((
                document_id,
                change_id,
                events.event_view(document_id).apply(content.data.event),
            )),
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
            }
        }
    }
    let fields = CalendarFieldSet::from_shape(&request.shape).for_list();
    events.prepare(server, fields).await?;
    let options = events.options();
    let mut body = messages.begin_message(&Status::SUCCESS);
    let w = body.writer();
    w.start(M, "RootFolder");
    Paging {
        indexed_paging_offset: None,
        numerator_offset: None,
        absolute_denominator: None,
        includes_last_item_in_range: Some(instances.len() == total),
        total_items_in_view: i32::try_from(total).unwrap_or(i32::MAX),
    }
    .write_attrs(w);
    w.start(T, "Items");
    for instance in &instances {
        let Ok(at) = parsed.binary_search_by_key(&instance.document_id, |(id, ..)| *id) else {
            continue;
        };
        let Some((document_id, change_id, ical)) = parsed.get(at) else {
            continue;
        };
        let item = GroupwareRef {
            container: calendar,
            document_id: *document_id,
        };
        match instance.recurrence {
            Some(recurrence) => {
                if let Some(loaded) = events.instance(ical, item, *change_id, recurrence, fields) {
                    events.render_instance(&loaded, fields).write(w);
                }
            }
            None => {
                if let Some(loaded) = master(ical, item, *change_id, fields, &options) {
                    events.render(&loaded, fields).write(w);
                }
            }
        }
    }
    w.end(T, "Items");
    w.end(M, "RootFolder");
    body.finish();
    Ok(())
}

async fn expand(
    server: &Server,
    events: &Events,
    calendar: u32,
    range: TimeRange,
) -> trc::Result<Option<Vec<Instance>>> {
    let documents = events
        .members(calendar)
        .map(|item| item.document_id)
        .collect::<RoaringBitmap>();
    let mut instances = Vec::new();
    let mut overflow = false;
    server
        .archives(
            events.account_id,
            Collection::CalendarEvent,
            CalendarEventField::Content.into(),
            &documents,
            |document_id, archive| {
                let content = archive.unarchive::<CalendarEventContent>()?;
                let Some(expanded) = content.data.expand(Tz::UTC, range, OverlapRule::CalDav)
                else {
                    return Ok(true);
                };
                let components = &content.data.event.components;
                for expansion in expanded {
                    let Some(component) = usize::try_from(expansion.comp_id)
                        .ok()
                        .and_then(|index| components.get(index))
                        .filter(|component| component.component_type.is_event())
                    else {
                        continue;
                    };
                    if instances.len() >= MAX_VIEW_INSTANCES {
                        overflow = true;
                        return Ok(false);
                    }
                    instances.push(Instance {
                        start: expansion.start,
                        document_id,
                        recurrence: component
                            .is_recurrent_or_override()
                            .then(|| expansion.recurrence_id().utc),
                    });
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    Ok((!overflow).then_some(instances))
}

pub(crate) fn master(
    ical: &ICalendar,
    item: GroupwareRef,
    change_id: u64,
    fields: CalendarFieldSet,
    options: &ConvertOptions<'_>,
) -> Option<LoadedItem> {
    event_parts_to_message(ical, None, fields.event_parts(), &NoDirectory, options)
        .ok()
        .map(|content| LoadedItem {
            item,
            change_id,
            content: Some(content),
            occurrences: None,
            mime: None,
        })
}

fn view_error(
    messages: &mut MessagesWriter<'_>,
    code: ResponseCode,
    text: &'static str,
) -> trc::Result<()> {
    messages.message(&MessageResult::<FindItemMessage> {
        status: Status::error(code, text),
        body: None,
    });
    Ok(())
}
