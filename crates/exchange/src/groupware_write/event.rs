/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{WriteFailure, store_failure};
use calcard::{
    common::PartialDateTime,
    icalendar::{
        ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarProperty,
        ICalendarValue,
    },
};
use common::{GroupwareResources, PROD_ID, Server};
use groupware::{SizeWriter, calendar::write::EventWriteError};
use jiff::Timestamp;
use registry::schema::enums::StorageQuota;
use smallvec::smallvec;

const ICAL_EXTENSION: &str = ".ics";
const ICAL_VERSION: &str = "2.0";

pub fn event_failure(err: EventWriteError) -> trc::Result<WriteFailure> {
    match err {
        EventWriteError::NotFound => Ok(WriteFailure::NotFound),
        EventWriteError::Forbidden => Ok(WriteFailure::Forbidden),
        EventWriteError::UidConflict { .. } => Ok(WriteFailure::UidConflict),
        EventWriteError::InvalidObject
        | EventWriteError::UidChanged(_)
        | EventWriteError::UnsupportedComponent
        | EventWriteError::ScheduleTagMismatch
        | EventWriteError::UserData(_)
        | EventWriteError::TooManyRecipients
        | EventWriteError::Scheduling(..) => Ok(WriteFailure::Invalid),
        EventWriteError::Store(err) => store_failure(err),
    }
}

pub fn ical_size(server: &Server, ical: &ICalendar) -> Option<usize> {
    let limits = &server.core.groupware;
    if limits.max_attachments_size != 0 && ical.embedded_size() > limits.max_attachments_size {
        return None;
    }
    let size = SizeWriter::ical(ical);
    (size <= limits.max_ical_size).then_some(size)
}

pub async fn assert_event_room(
    server: &Server,
    account_id: u32,
    resources: &GroupwareResources,
    created: usize,
) -> trc::Result<()> {
    if created == 0 {
        return Ok(());
    }
    let account = server.account(account_id).await?;
    server.assert_object_quota(
        &account,
        StorageQuota::MaxCalendarEvents,
        created + 1,
        || resources.resources.count(false),
    )
}

pub fn new_todo(uid: &str, now: Timestamp) -> ICalendar {
    skeleton(ICalendarComponentType::VTodo, uid, now, &[])
}

pub fn new_event(uid: &str, now: Timestamp) -> ICalendar {
    skeleton(
        ICalendarComponentType::VEvent,
        uid,
        now,
        &[ICalendarProperty::Dtstart, ICalendarProperty::Dtend],
    )
}

fn skeleton(
    component_type: ICalendarComponentType,
    uid: &str,
    now: Timestamp,
    times: &[ICalendarProperty],
) -> ICalendar {
    let text = |name, value: &str| ICalendarEntry {
        name,
        params: Vec::new(),
        values: smallvec![ICalendarValue::Text(value.to_string())],
    };
    let stamp = |name| ICalendarEntry {
        name,
        params: Vec::new(),
        values: smallvec![ICalendarValue::PartialDateTime(
            PartialDateTime::from_utc_timestamp(now.as_second())
        )],
    };
    let mut entries = Vec::with_capacity(2 + times.len());
    entries.push(text(ICalendarProperty::Uid, uid));
    entries.push(stamp(ICalendarProperty::Dtstamp));
    entries.extend(times.iter().cloned().map(stamp));
    ICalendar {
        components: vec![
            ICalendarComponent {
                component_type: ICalendarComponentType::VCalendar,
                entries: vec![
                    text(ICalendarProperty::Version, ICAL_VERSION),
                    text(ICalendarProperty::Prodid, PROD_ID),
                ],
                component_ids: vec![1],
            },
            ICalendarComponent {
                component_type,
                entries,
                component_ids: Vec::new(),
            },
        ],
    }
}

pub fn set_event_uid(ical: &mut ICalendar, uid: &str) {
    for component in ical.components.iter_mut().filter(|component| {
        matches!(
            component.component_type,
            ICalendarComponentType::VEvent | ICalendarComponentType::VTodo
        )
    }) {
        let values = smallvec![ICalendarValue::Text(uid.to_string())];
        match component
            .entries
            .iter_mut()
            .find(|entry| entry.name == ICalendarProperty::Uid)
        {
            Some(entry) => entry.values = values,
            None => component.entries.push(ICalendarEntry {
                name: ICalendarProperty::Uid,
                params: Vec::new(),
                values,
            }),
        }
    }
}

pub fn event_name(uid: &str) -> String {
    format!("{uid}{ICAL_EXTENSION}")
}
