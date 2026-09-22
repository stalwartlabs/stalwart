/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::acl::JmapRights, calendar::Availability, changes::state::JmapCacheState};
use calcard::{
    icalendar::ICalendarDuration,
    jscalendar::{JSCalendarAlertAction, JSCalendarRelativeTo, JSCalendarType},
};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{
    cache::GroupwareCache,
    calendar::{
        ALERT_EMAIL, ALERT_RELATIVE_TO_END, ArchivedDefaultAlert, CALENDAR_INVISIBLE,
        CALENDAR_SUBSCRIBED, Calendar,
    },
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::calendar::{self, CalendarProperty, CalendarValue, IncludeInAvailability},
};
use jmap_tools::{Key, Map, Value};
use store::{
    ValueKey,
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, ValueClass},
};
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
    field::PrincipalField,
};

pub trait CalendarGet: Sync + Send {
    fn calendar_get(
        &self,
        request: GetRequest<calendar::Calendar>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<calendar::Calendar>>> + Send;
}

impl CalendarGet for Server {
    async fn calendar_get(
        &self,
        mut request: GetRequest<calendar::Calendar>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<calendar::Calendar>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::Description,
            CalendarProperty::Color,
            CalendarProperty::SortOrder,
            CalendarProperty::IsSubscribed,
            CalendarProperty::IsVisible,
            CalendarProperty::IsDefault,
            CalendarProperty::IncludeInAvailability,
            CalendarProperty::DefaultAlertsWithTime,
            CalendarProperty::DefaultAlertsWithoutTime,
            CalendarProperty::TimeZone,
            CalendarProperty::ShareWith,
            CalendarProperty::MyRights,
        ]);
        let account_id = request.account_id.document_id();
        let personal_id = access_token.personal_id(account_id, Collection::Calendar);
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let is_owner = access_token.is_member(account_id);
        let calendar_ids = if is_owner {
            cache.document_ids(true).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
        };
        let default_calendar_id = self
            .store()
            .get_value::<u32>(ValueKey {
                account_id,
                collection: Collection::Principal.into(),
                document_id: 0,
                class: ValueClass::Property(PrincipalField::DefaultCalendarId.into()),
            })
            .await
            .caused_by(trc::location!())?
            .or_else(|| cache.document_ids(true).min());

        let ids = if let Some(ids) = ids {
            ids
        } else {
            calendar_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(true).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        for id in ids {
            // Obtain the calendar object
            let document_id = id.document_id();
            if !calendar_ids.contains(document_id) {
                response.push_not_found(id);
                continue;
            }
            let _calendar = if let Some(calendar) = self
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::Calendar,
                    document_id,
                ))
                .await?
            {
                calendar
            } else {
                response.push_not_found(id);
                continue;
            };
            let calendar = _calendar
                .unarchive::<Calendar>()
                .caused_by(trc::location!())?;
            let personal_preferences = calendar.personal_preferences(personal_id);
            let personal_flags = calendar.personal_flags(personal_id, is_owner);
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    CalendarProperty::Id => {
                        result.insert_unchecked(CalendarProperty::Id, CalendarValue::Id(id));
                    }
                    CalendarProperty::Name => {
                        result.insert_unchecked(
                            CalendarProperty::Name,
                            calendar
                                .preferences(personal_id)
                                .map_or_else(String::new, |preferences| {
                                    preferences.name.to_string()
                                }),
                        );
                    }
                    CalendarProperty::Description => {
                        result.insert_unchecked(
                            CalendarProperty::Description,
                            calendar
                                .preferences(personal_id)
                                .and_then(|preferences| preferences.description.as_ref())
                                .map(|description| description.to_string()),
                        );
                    }
                    CalendarProperty::SortOrder => {
                        result.insert_unchecked(
                            CalendarProperty::SortOrder,
                            personal_preferences.map_or(0, |p| p.sort_order.to_native()),
                        );
                    }
                    CalendarProperty::IsDefault => {
                        result.insert_unchecked(
                            CalendarProperty::IsDefault,
                            default_calendar_id == Some(document_id),
                        );
                    }
                    CalendarProperty::IsSubscribed => {
                        result.insert_unchecked(
                            CalendarProperty::IsSubscribed,
                            Value::Bool(personal_flags & CALENDAR_SUBSCRIBED != 0),
                        );
                    }
                    CalendarProperty::Color => {
                        result.insert_unchecked(
                            CalendarProperty::Color,
                            calendar
                                .preferences(personal_id)
                                .and_then(|preferences| preferences.color.as_ref())
                                .map(|color| color.to_string()),
                        );
                    }
                    CalendarProperty::IsVisible => {
                        result.insert_unchecked(
                            CalendarProperty::IsVisible,
                            Value::Bool(personal_flags & CALENDAR_INVISIBLE == 0),
                        );
                    }
                    CalendarProperty::IncludeInAvailability => {
                        result.insert_unchecked(
                            CalendarProperty::IncludeInAvailability,
                            Value::Element(CalendarValue::IncludeInAvailability(
                                IncludeInAvailability::from_flags(personal_flags).unwrap_or(
                                    if is_owner {
                                        IncludeInAvailability::All
                                    } else {
                                        IncludeInAvailability::None
                                    },
                                ),
                            )),
                        );
                    }
                    CalendarProperty::DefaultAlertsWithTime => {
                        result.insert_unchecked(
                            CalendarProperty::DefaultAlertsWithTime,
                            Value::Object(Map::from_iter(
                                calendar
                                    .default_alerts(personal_id, true)
                                    .map(default_alarm_to_value),
                            )),
                        );
                    }
                    CalendarProperty::DefaultAlertsWithoutTime => {
                        result.insert_unchecked(
                            CalendarProperty::DefaultAlertsWithoutTime,
                            Value::Object(Map::from_iter(
                                calendar
                                    .default_alerts(personal_id, false)
                                    .map(default_alarm_to_value),
                            )),
                        );
                    }
                    CalendarProperty::TimeZone => {
                        result.insert_unchecked(
                            CalendarProperty::TimeZone,
                            calendar
                                .preferences(personal_id)
                                .and_then(|preferences| preferences.time_zone.tz())
                                .map(|tz| Value::Element(CalendarValue::Timezone(tz)))
                                .unwrap_or(Value::Null),
                        );
                    }
                    CalendarProperty::ShareWith => {
                        result.insert_unchecked(
                            CalendarProperty::ShareWith,
                            JmapRights::share_with::<calendar::Calendar>(
                                account_id,
                                access_token,
                                &calendar.acls.iter().map(AclGrant::from).collect::<Vec<_>>(),
                            ),
                        );
                    }
                    CalendarProperty::MyRights => {
                        result.insert_unchecked(
                            CalendarProperty::MyRights,
                            if access_token.is_shared(account_id) {
                                JmapRights::rights::<calendar::Calendar>(
                                    calendar.acls.effective_acl(access_token),
                                )
                            } else {
                                JmapRights::all_rights::<calendar::Calendar>()
                            },
                        );
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}

fn default_alarm_to_value(
    alarm: &ArchivedDefaultAlert,
) -> (
    Key<'static, CalendarProperty>,
    Value<'static, CalendarProperty, CalendarValue>,
) {
    default_alert_value(
        alarm.id.as_str(),
        alarm.offset.to_native(),
        alarm.flags.to_native(),
    )
}

pub(crate) fn default_alert_value(
    id: &str,
    offset: ICalendarDuration,
    flags: u16,
) -> (
    Key<'static, CalendarProperty>,
    Value<'static, CalendarProperty, CalendarValue>,
) {
    (
        Key::Owned(id.to_string()),
        Value::Object(Map::from(vec![
            (
                Key::Property(CalendarProperty::Type),
                Value::Element(CalendarValue::Type(JSCalendarType::Alert)),
            ),
            (
                Key::Property(CalendarProperty::Action),
                Value::Element(CalendarValue::Action(if flags & ALERT_EMAIL != 0 {
                    JSCalendarAlertAction::Email
                } else {
                    JSCalendarAlertAction::Display
                })),
            ),
            (
                Key::Property(CalendarProperty::Trigger),
                Value::Object(Map::from(vec![
                    (
                        Key::Property(CalendarProperty::Type),
                        Value::Element(CalendarValue::Type(JSCalendarType::OffsetTrigger)),
                    ),
                    (
                        Key::Property(CalendarProperty::Offset),
                        Value::Element(CalendarValue::Duration(offset)),
                    ),
                    (
                        Key::Property(CalendarProperty::RelativeTo),
                        Value::Element(CalendarValue::RelativeTo(
                            if flags & ALERT_RELATIVE_TO_END != 0 {
                                JSCalendarRelativeTo::End
                            } else {
                                JSCalendarRelativeTo::Start
                            },
                        )),
                    ),
                ])),
            ),
        ])),
    )
}
