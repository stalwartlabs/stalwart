/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{DavName, Server};
use groupware::calendar::{AlarmDelta, CalendarEvent, CalendarEventData, ComponentTimeRange};
use store::{
    Serialize, ValueKey,
    rand::{self, seq::SliceRandom},
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{collection::Collection, dead_property::DeadProperty, field::Field};

use crate::{event_v2::migrate_icalendar_v02, get_document_ids};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventV1 {
    pub names: Vec<DavName>,
    pub display_name: Option<String>,
    pub data: CalendarEventDataV1,
    pub user_properties: Vec<UserProperties>,
    pub flags: u16,
    pub dead_properties: DeadProperty,
    pub size: u32,
    pub created: i64,
    pub modified: i64,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct UserProperties {
    pub account_id: u32,
    pub properties: calcard_v01::icalendar::ICalendar,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarEventDataV1 {
    pub event: calcard_v01::icalendar::ICalendar,
    pub time_ranges: Box<[ComponentTimeRange]>,
    pub alarms: Box<[AlarmV1]>,
    pub base_offset: i64,
    pub base_time_utc: u32,
    pub duration: u32,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct AlarmV1 {
    pub comp_id: u16,
    pub alarms: Box<[AlarmDelta]>,
}

pub(crate) async fn migrate_calendar_events_v012(server: &Server) -> trc::Result<()> {
    // Obtain email ids
    let account_ids = get_document_ids(server, u32::MAX, Collection::Principal)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_accounts = account_ids.len();
    if num_accounts == 0 {
        return Ok(());
    }

    let mut account_ids = account_ids.into_iter().collect::<Vec<_>>();

    account_ids.shuffle(&mut rand::rng());

    for account_id in account_ids {
        let document_ids = get_document_ids(server, account_id, Collection::CalendarEvent)
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();
        if document_ids.is_empty() {
            continue;
        }
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

            match archive.unarchive_untrusted::<CalendarEventV1>() {
                Ok(event) => {
                    let event = rkyv_deserialize::<_, CalendarEventV1>(event).unwrap();
                    let mut next_email_alarm = None;
                    let new_event = CalendarEvent {
                        names: event.names,
                        display_name: event.display_name,
                        data: CalendarEventData::new(
                            migrate_icalendar_v02(event.data.event),
                            calcard_latest::common::timezone::Tz::Floating,
                            server.core.groupware.max_ical_instances,
                            &mut next_email_alarm,
                        ),
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
                    if let Some(next_email_alarm) = next_email_alarm {
                        next_email_alarm.write_task(&mut batch);
                    }
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

        if num_migrated > 0 {
            trc::event!(
                Server(trc::ServerEvent::Startup),
                Details =
                    format!("Migrated {num_migrated} Calendar Events for account {account_id}")
            );
        }
    }

    Ok(())
}
