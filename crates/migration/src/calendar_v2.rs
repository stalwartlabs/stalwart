/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use groupware::calendar::{Calendar, CalendarPreferences, Timezone};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{acl::AclGrant, collection::Collection, dead_property::DeadProperty, field::Field};

use crate::{event_v2::migrate_icalendar_v02, get_document_ids};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarV2 {
    pub name: String,
    pub preferences: Vec<CalendarPreferencesV2>,
    pub default_alerts: Vec<DefaultAlertV2>,
    pub acls: Vec<AclGrant>,
    pub dead_properties: DeadProperty,
    pub created: i64,
    pub modified: i64,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct CalendarPreferencesV2 {
    pub account_id: u32,
    pub name: String,
    pub description: Option<String>,
    pub sort_order: u32,
    pub color: Option<String>,
    pub flags: u16,
    pub time_zone: TimezoneV2,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub enum TimezoneV2 {
    IANA(u16),
    Custom(calcard_v01::icalendar::ICalendar),
    #[default]
    Default,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct DefaultAlertV2 {
    pub account_id: u32,
    pub id: String,
    pub alert: calcard_v01::icalendar::ICalendar,
    pub with_time: bool,
}

pub(crate) async fn migrate_calendar_v013(server: &Server, account_id: u32) -> trc::Result<u64> {
    let document_ids = get_document_ids(server, account_id, Collection::Calendar)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    if document_ids.is_empty() {
        return Ok(0);
    }
    let mut num_migrated = 0;

    for document_id in document_ids.iter() {
        let Some(archive) = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::Calendar,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };

        match archive.unarchive_untrusted::<CalendarV2>() {
            Ok(calendar) => {
                let calendar = rkyv_deserialize::<_, CalendarV2>(calendar).unwrap();
                let new_calendar = Calendar {
                    name: calendar.name,
                    preferences: calendar
                        .preferences
                        .into_iter()
                        .map(|pref| CalendarPreferences {
                            account_id: pref.account_id,
                            name: pref.name,
                            description: pref.description,
                            sort_order: pref.sort_order,
                            color: pref.color,
                            flags: 0,
                            time_zone: match pref.time_zone {
                                TimezoneV2::IANA(tzid) => Timezone::IANA(tzid),
                                TimezoneV2::Custom(tz) => {
                                    Timezone::Custom(migrate_icalendar_v02(tz))
                                }
                                TimezoneV2::Default => Timezone::Default,
                            },
                            default_alerts: Vec::new(),
                        })
                        .collect(),
                    acls: calendar.acls,
                    supported_components: 0,
                    dead_properties: calendar.dead_properties,
                    created: calendar.created,
                    modified: calendar.modified,
                };

                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Calendar)
                    .with_document(document_id)
                    .set(
                        Field::ARCHIVE,
                        Archiver::new(new_calendar)
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
                if let Err(err_) = archive.unarchive_untrusted::<Calendar>() {
                    trc::error!(err_.caused_by(trc::location!()));
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
    }

    Ok(num_migrated)
}
