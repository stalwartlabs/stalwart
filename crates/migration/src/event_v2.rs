/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{DavName, Server};
use groupware::calendar::{
    Alarm, CalendarEvent, CalendarEventData, CalendarEventNotification, ComponentTimeRange,
};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{collection::Collection, dead_property::DeadProperty, field::Field};

use crate::get_document_ids;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventV2 {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub data: CalendarEventDataV2,
    pub user_properties: Vec<UserPropertiesV2>,
    pub flags: u16,
    pub dead_properties: DeadProperty,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
    pub schedule_tag: Option<u32>,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct UserPropertiesV2 {
    pub account_id: u32,
    pub properties: calcard_v01::icalendar::ICalendar,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventDataV2 {
    pub event: calcard_v01::icalendar::ICalendar,
    pub time_ranges: Box<[ComponentTimeRange]>,
    pub alarms: Box<[Alarm]>,
    pub base_offset: i64,
    pub base_time_utc: u32,
    pub duration: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventNotificationV2 {
    pub itip: calcard_v01::icalendar::ICalendar,
    pub event_id: Option<u32>,
    pub flags: u16,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
}

pub(crate) async fn migrate_calendar_events_v013(
    server: &Server,
    account_id: u32,
) -> trc::Result<u64> {
    let document_ids = get_document_ids(server, account_id, Collection::CalendarEvent)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();

    let mut num_migrated = 0;

    for document_id in document_ids.iter() {
        let Some(archive) = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEvent,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };

        match archive.unarchive_untrusted::<CalendarEventV2>() {
            Ok(event) => {
                let event = rkyv_deserialize::<_, CalendarEventV2>(event).unwrap();
                let new_event = CalendarEvent {
                    names: event.names,
                    display_name: event.display_name,
                    data: CalendarEventData {
                        event: migrate_icalendar_v02(event.data.event),
                        time_ranges: event.data.time_ranges,
                        alarms: event.data.alarms,
                        base_offset: event.data.base_offset,
                        base_time_utc: event.data.base_time_utc,
                        duration: event.data.duration,
                    },
                    preferences: Default::default(),
                    flags: event.flags,
                    dead_properties: event.dead_properties,
                    size: event.size,
                    created: event.created,
                    modified: event.modified,
                    schedule_tag: None,
                };

                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::CalendarEvent)
                    .with_document(document_id)
                    .set(
                        Field::ARCHIVE,
                        Archiver::new(new_event)
                            .serialize()
                            .caused_by(trc::location!())?,
                    );
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                num_migrated += 1;
            }
            Err(err) => {
                if let Err(err_) = archive.unarchive_untrusted::<CalendarEvent>() {
                    trc::error!(err_.caused_by(trc::location!()));
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
    }

    Ok(num_migrated)
}

pub(crate) async fn migrate_calendar_scheduling_v013(
    server: &Server,
    account_id: u32,
) -> trc::Result<u64> {
    let document_ids = get_document_ids(server, account_id, Collection::CalendarEventNotification)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();

    let mut num_migrated = 0;

    for document_id in document_ids.iter() {
        let Some(archive) = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::CalendarEventNotification,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };

        match archive.unarchive_untrusted::<CalendarEventNotificationV2>() {
            Ok(event) => {
                let event = rkyv_deserialize::<_, CalendarEventNotificationV2>(event).unwrap();
                let new_event = CalendarEventNotification {
                    event: migrate_icalendar_v02(event.itip),
                    event_id: event.event_id,
                    changed_by: Default::default(),
                    flags: 0,
                    size: event.size,
                    created: event.created,
                    modified: event.modified,
                };

                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::CalendarEventNotification)
                    .with_document(document_id)
                    .set(
                        Field::ARCHIVE,
                        Archiver::new(new_event)
                            .serialize()
                            .caused_by(trc::location!())?,
                    );
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                num_migrated += 1;
            }
            Err(err) => {
                if let Err(err_) = archive.unarchive_untrusted::<CalendarEventNotification>() {
                    trc::error!(err_.caused_by(trc::location!()));
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
    }

    Ok(num_migrated)
}

pub(crate) fn migrate_icalendar_v02(
    ical: calcard_v01::icalendar::ICalendar,
) -> calcard_latest::icalendar::ICalendar {
    calcard_latest::icalendar::ICalendar::parse(ical.to_string()).unwrap_or_default()
}
