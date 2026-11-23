/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    calendar::{
        Events, calendar_of,
        instance::EventTarget,
        sent::MeetingSend,
        view::master,
        write::{EventScope, scope_instance},
    },
    context::{EwsCaller, EwsContext},
    groupware::{GroupwareKind, VersionedArchives, items::decode_item, write::CalendarWriter},
    item::ItemError,
    reply::{RESPONSE_CAPACITY, ews_response},
    task::{Tasks, task_list_of, write::TaskWriter},
};
use calcard::common::timezone::Tz;
use common::Server;
use exchange_proto::{
    common::UtcSeconds,
    convert::{
        ical::{OccurrenceReminder, set_occurrence_reminder},
        model::PropBag,
    },
    ews::{
        Operation, Status,
        calendar::{CalendarFieldSet, CalendarProps},
        requests::{
            MAX_REMINDER_ITEMS,
            reminder::{GetReminders, PerformReminderAction},
        },
        responses::{
            ShapeB,
            reminder::{GetRemindersBody, PerformReminderActionBody},
        },
        schema::{ReminderActionType, ReminderKind, ResponseCode, UnindexedField},
        task::TaskProps,
        types::{
            change::ItemChange,
            ids::{BaseItemId, ItemId},
            item::{Item, ItemFields},
            path::Path,
            reminder::{Reminder, ReminderItemAction},
            value::DateTime,
        },
    },
};
use groupware::calendar::{
    CalendarEventContent, EVENT_HAS_ALARMS, EVENT_USES_DEFAULT_ALERTS, write::ItipMode,
};
use http_proto::HttpResponse;
use jiff::Timestamp;
use std::slice;
use store::{roaring::RoaringBitmap, write::now};
use types::{OverlapRule, TimeRange, collection::Collection, field::CalendarEventField};

const DEFAULT_LOOKBACK_SECONDS: i64 = 14 * 86_400;
const MAX_WINDOW_SECONDS: i64 = 2 * 366 * 86_400;
const MAX_REMINDER_LEAD_SECONDS: i64 = 14 * 86_400;
const MAX_REMINDER_INSTANCES: usize = 10_000;
const EVENT_ALERTS: u16 = EVENT_HAS_ALARMS | EVENT_USES_DEFAULT_ALERTS;
const INVALID_WINDOW: &str = "The reminder time window is invalid.";
const OLD_NEEDS_WINDOW: &str = "BeginTime and EndTime are required for Old reminders.";
const TOO_MANY_OCCURRENCES: &str = "The reminder time window returns too many occurrences.";
const MISSING_REMINDER_TIME: &str = "NewReminderTime is missing or invalid.";

#[derive(Debug, Clone, Copy)]
struct Window {
    kind: ReminderKind,
    begin: i64,
    end: i64,
    now: i64,
}

impl Window {
    fn of(request: &GetReminders, now: i64) -> Result<Self, &'static str> {
        let kind = request.reminder_type.unwrap_or(ReminderKind::All);
        let utc = |time: Option<&DateTime>| match time {
            Some(time) => time
                .to_utc()
                .map(|seconds| Some(seconds.0))
                .ok_or(INVALID_WINDOW),
            None => Ok(None),
        };
        let (begin, end) = (
            utc(request.begin_time.as_ref())?,
            utc(request.end_time.as_ref())?,
        );
        if kind == ReminderKind::Old && (begin.is_none() || end.is_none()) {
            return Err(OLD_NEEDS_WINDOW);
        }
        let end = end.unwrap_or(now);
        let begin = begin.unwrap_or_else(|| end.saturating_sub(DEFAULT_LOOKBACK_SECONDS));
        if end < begin || end.saturating_sub(begin) > MAX_WINDOW_SECONDS {
            return Err(INVALID_WINDOW);
        }
        Ok(Window {
            kind,
            begin,
            end,
            now,
        })
    }

    fn expansion(self) -> TimeRange {
        TimeRange {
            start: self.begin,
            end: self.end.saturating_add(MAX_REMINDER_LEAD_SECONDS),
        }
    }

    fn may_fire(self, signal: Option<DateTime>) -> bool {
        signal
            .and_then(|signal| signal.to_utc())
            .is_some_and(|UtcSeconds(at)| {
                at <= self.end && (at >= self.begin || self.kind == ReminderKind::Current)
            })
    }

    fn accepts(self, reminder: &Reminder<'_>) -> bool {
        let (Some(UtcSeconds(at)), Some(UtcSeconds(ends))) =
            (reminder.reminder_time.to_utc(), reminder.end_date.to_utc())
        else {
            return false;
        };
        let in_window = (self.begin..=self.end).contains(&at);
        match self.kind {
            ReminderKind::All => in_window,
            ReminderKind::Current => in_window || (at <= self.end && ends > self.now),
            ReminderKind::Old => in_window && ends <= self.now,
        }
    }
}

pub(crate) async fn get_reminders(
    server: &Server,
    ctx: &EwsContext,
    request: &GetReminders,
) -> trc::Result<HttpResponse> {
    let now = i64::try_from(now()).unwrap_or(i64::MAX);
    let outcome = match Window::of(request, now) {
        Ok(window) => collect(server, ctx, window).await?,
        Err(message) => Err(Status::error(ResponseCode::ErrorInvalidRequest, message)),
    };
    let limit = usize::from(request.max_items.unwrap_or(MAX_REMINDER_ITEMS));
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&match outcome {
        Ok(mut reminders) => {
            reminders.sort_unstable_by_key(|reminder| reminder.reminder_time.to_utc());
            reminders.truncate(limit);
            ShapeB {
                op: Operation::GetReminders,
                status: Status::SUCCESS,
                body: Some(GetRemindersBody { reminders }),
            }
        }
        Err(status) => ShapeB {
            op: Operation::GetReminders,
            status,
            body: None,
        },
    });
    Ok(ews_response(out))
}

async fn collect(
    server: &Server,
    ctx: &EwsContext,
    window: Window,
) -> trc::Result<Result<Vec<Reminder<'static>>, Status<'static>>> {
    let tree = ctx.folder_tree(server).await?;
    let mut calendars = Vec::new();
    let mut task_lists = Vec::new();
    for entry in tree
        .iter()
        .filter(|entry| ctx.access.of(entry.node).reads_items())
    {
        if let Some(calendar) = calendar_of(entry) {
            calendars.push(calendar);
        } else if let Some(task_list) = task_list_of(entry) {
            task_lists.push(task_list);
        }
    }
    let mut reminders = Vec::new();
    if !calendars.is_empty()
        && let Ok(events) = Events::load(server, ctx).await?
        && !collect_events(server, &events, &calendars, window, &mut reminders).await?
    {
        return Ok(Err(Status::error(
            ResponseCode::ErrorInvalidRequest,
            TOO_MANY_OCCURRENCES,
        )));
    }
    if !task_lists.is_empty()
        && let Ok(tasks) = Tasks::load(server, ctx).await?
    {
        for task_list in task_lists {
            tasks
                .scan(server, task_list, |item, props| {
                    let task = TaskProps::new(props);
                    if window.may_fire(task.reminder_signal())
                        && let Some(reminder) = task
                            .reminder(tasks.unversioned_id(item))
                            .filter(|reminder| window.accepts(reminder))
                    {
                        reminders.push(reminder);
                    }
                })
                .await?;
        }
    }
    Ok(Ok(reminders))
}

async fn collect_events(
    server: &Server,
    events: &Events,
    calendars: &[u32],
    window: Window,
    reminders: &mut Vec<Reminder<'static>>,
) -> trc::Result<bool> {
    let mut documents = RoaringBitmap::new();
    let mut items = Vec::new();
    for &calendar in calendars {
        for item in events.members(calendar) {
            if events
                .resources
                .item_by_id(item.document_id)
                .and_then(|cached| cached.event_flags())
                .is_some_and(|flags| flags & EVENT_ALERTS != 0)
                && documents.insert(item.document_id)
            {
                items.push(item);
            }
        }
    }
    if items.is_empty() {
        return Ok(true);
    }
    items.sort_unstable_by_key(|item| item.document_id);
    let archives = VersionedArchives::read(
        server,
        events.account_id,
        Collection::CalendarEvent,
        CalendarEventField::Content.into(),
        &documents,
        true,
    )
    .await?;
    let fields = CalendarFieldSet::id_only();
    let options = events.options();
    let range = window.expansion();
    let mut expanded = 0usize;
    let mut recurrences = Vec::new();
    for item in items {
        let (Some(change_id), Some(content)) = (
            archives.change_id(item.document_id),
            archives.content(item.document_id),
        ) else {
            continue;
        };
        recurrences.clear();
        {
            let archived = match content.unarchive::<CalendarEventContent>() {
                Ok(archived) => archived,
                Err(err) => {
                    trc::error!(err.caused_by(trc::location!()));
                    continue;
                }
            };
            let Some(expansions) = archived.data.expand(Tz::UTC, range, OverlapRule::CalDav) else {
                continue;
            };
            let components = &archived.data.event.components;
            for expansion in expansions {
                let Some(component) = usize::try_from(expansion.comp_id)
                    .ok()
                    .and_then(|index| components.get(index))
                    .filter(|component| component.component_type.is_event())
                else {
                    continue;
                };
                expanded += 1;
                if expanded > MAX_REMINDER_INSTANCES {
                    return Ok(false);
                }
                recurrences.push(
                    component
                        .is_recurrent_or_override()
                        .then(|| expansion.recurrence_id().utc),
                );
            }
        }
        if recurrences.is_empty() {
            continue;
        }
        let ical = match content.deserialize::<CalendarEventContent>() {
            Ok(content) => events
                .event_view(item.document_id)
                .apply(content.data.event),
            Err(err) => {
                trc::error!(err.caused_by(trc::location!()));
                continue;
            }
        };
        let mut seen_master = false;
        for recurrence in &recurrences {
            let reminder = match *recurrence {
                Some(recurrence) => events
                    .instance(&ical, item, change_id, recurrence, fields)
                    .and_then(|loaded| {
                        build_event(window, &loaded.loaded.content?.props, || {
                            (
                                events.occurrence_id(item, change_id, recurrence),
                                Some(events.item_id(item, change_id)),
                            )
                        })
                    }),
                None if !seen_master => {
                    seen_master = true;
                    master(&ical, item, change_id, fields, &options).and_then(|loaded| {
                        build_event(window, &loaded.content?.props, || {
                            (events.item_id(item, change_id), None)
                        })
                    })
                }
                None => None,
            };
            reminders.extend(reminder);
        }
    }
    Ok(true)
}

fn build_event(
    window: Window,
    props: &PropBag,
    ids: impl FnOnce() -> (ItemId<'static>, Option<ItemId<'static>>),
) -> Option<Reminder<'static>> {
    let event = CalendarProps::of_props(props);
    if !window.may_fire(event.reminder_signal()) {
        return None;
    }
    let (item_id, master_id) = ids();
    event
        .reminder(item_id, master_id)
        .filter(|reminder| window.accepts(reminder))
}

pub(crate) async fn perform_reminder_action(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &PerformReminderAction<'_>,
) -> trc::Result<HttpResponse> {
    let mut updated = Vec::with_capacity(request.reminder_item_actions.len());
    let mut status = Status::SUCCESS;
    let mut events = None;
    let mut tasks = None;
    for action in &request.reminder_item_actions {
        match perform(server, ctx, caller, action, &mut events, &mut tasks).await? {
            Ok(id) => updated.push(id),
            Err(err) => {
                status = err;
                break;
            }
        }
    }
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    ctx.envelope(&mut out).body(&ShapeB {
        op: Operation::PerformReminderAction,
        body: (!updated.is_empty()).then_some(PerformReminderActionBody {
            updated_item_ids: updated,
        }),
        status,
    });
    Ok(ews_response(out))
}

async fn perform(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    action: &ReminderItemAction<'_>,
    events: &mut Option<Result<Events, ItemError>>,
    tasks: &mut Option<Result<Tasks, ItemError>>,
) -> trc::Result<Result<ItemId<'static>, Status<'static>>> {
    let snooze = match action.action_type {
        ReminderActionType::Dismiss => None,
        ReminderActionType::Snooze => match action
            .new_reminder_time
            .as_deref()
            .and_then(DateTime::parse_text)
        {
            Some(time) => Some(time),
            None => {
                return Ok(Err(Status::error(
                    ResponseCode::ErrorInvalidRequest,
                    MISSING_REMINDER_TIME,
                )));
            }
        },
    };
    let id = BaseItemId::Item(action.item_id.clone());
    let (kind, account, item, scope) = match EventTarget::decode(&id) {
        Some(EventTarget::Master(account, event)) => {
            (GroupwareKind::Event, account, event, EventScope::Master)
        }
        Some(EventTarget::Instance(account, event, instance)) => (
            GroupwareKind::Event,
            account,
            event,
            EventScope::Instance(instance),
        ),
        Some(EventTarget::Indexed(account, event, index)) => (
            GroupwareKind::Event,
            account,
            event,
            EventScope::Indexed(index),
        ),
        None => match decode_item(&id) {
            Some((kind, account, item)) => (kind, account, item, EventScope::Master),
            None => return Ok(Err(ItemError::Malformed.status())),
        },
    };
    match kind {
        GroupwareKind::Event => {
            if events.is_none() {
                *events = Some(Events::load(server, ctx).await?);
            }
            let events = match events.as_ref() {
                Some(Ok(events)) => events,
                Some(Err(err)) => return Ok(Err(err.status())),
                None => return Ok(Err(ItemError::NotFound.status())),
            };
            let event = match events.check(account, item) {
                Ok(event) => event,
                Err(err) => return Ok(Err(err.status())),
            };
            let writer = CalendarWriter::new(server, caller, events);
            if scope == EventScope::Master {
                let change = item_change(snooze);
                return Ok(writer
                    .update(
                        event,
                        scope,
                        None,
                        slice::from_ref(&change),
                        MeetingSend::Suppress,
                    )
                    .await?
                    .map(|(id, _)| id)
                    .map_err(ItemError::status));
            }
            let action = match snooze.map(|time| {
                time.to_utc()
                    .and_then(|UtcSeconds(at)| Timestamp::from_second(at).ok())
            }) {
                None => OccurrenceReminder::Dismiss,
                Some(Some(at)) => OccurrenceReminder::Snooze(at),
                Some(None) => {
                    return Ok(Err(Status::error(
                        ResponseCode::ErrorInvalidRequest,
                        MISSING_REMINDER_TIME,
                    )));
                }
            };
            let now = Timestamp::from_second(i64::try_from(now()).unwrap_or(i64::MAX))
                .unwrap_or(Timestamp::MAX);
            let mut resolved = None;
            let updated = writer
                .update_ical(event, None, ItipMode::Suppress, |ical| {
                    let (instance, id) = scope_instance(ical, scope)?.ok_or(ItemError::NotFound)?;
                    resolved = Some(instance);
                    set_occurrence_reminder(ical, id, action, now).map_err(|_| ItemError::NotFound)
                })
                .await?;
            Ok(match (updated, resolved) {
                (Ok((change_id, _)), Some(instance)) => {
                    Ok(events.occurrence_id(event, change_id, instance))
                }
                (Ok(_), None) => Err(ItemError::NotFound.status()),
                (Err(err), _) => Err(err.status()),
            })
        }
        GroupwareKind::Task => {
            if tasks.is_none() {
                *tasks = Some(Tasks::load(server, ctx).await?);
            }
            let tasks = match tasks.as_ref() {
                Some(Ok(tasks)) => tasks,
                Some(Err(err)) => return Ok(Err(err.status())),
                None => return Ok(Err(ItemError::NotFound.status())),
            };
            let task = match tasks.check(account, item) {
                Ok(task) => task,
                Err(err) => return Ok(Err(err.status())),
            };
            let change = item_change(snooze);
            Ok(TaskWriter::new(server, caller, tasks)
                .update(task, None, slice::from_ref(&change))
                .await?
                .map_err(ItemError::status))
        }
        GroupwareKind::Contact => Ok(Err(ItemError::NotFound.status())),
    }
}

fn item_change(snooze: Option<DateTime>) -> ItemChange<'static> {
    let (field, fields) = match snooze {
        None => (
            UnindexedField::ItemReminderIsSet,
            ItemFields {
                reminder_is_set: Some(false),
                ..Default::default()
            },
        ),
        Some(time) => (
            UnindexedField::ItemReminderNextTime,
            ItemFields {
                reminder_next_time: Some(time),
                ..Default::default()
            },
        ),
    };
    ItemChange::Set {
        path: Path::Field(field),
        value: Item::Item(Box::new(fields)),
    }
}
