/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::GroupwareCache,
    calendar::{
        CalendarEventContent, CalendarEventData,
        availability::{BusyLevel, ComponentBusy, PrincipalRole},
        expand::MAX_UTC_OFFSET,
        identity::CalendarAddresses,
        itip::ItipIngestError,
    },
    scheduling::{
        ItipError, ItipMessage, busy_status::adopt_intended_status, event_update::itip_update,
        recipient::RecipientPolicy,
    },
};
use calcard::{
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarEntry, ICalendarParameter, ICalendarParameterName,
        ICalendarParticipationStatus, ICalendarProperty, ICalendarTransparency, ICalendarValue,
    },
};
use common::{KV_LOCK_RESOURCE_BOOKING, Server, auth::AccountInfo};
use registry::schema::structs::{Account, AutomaticBooking, ResourceAccount, ResourceBooking};
use std::{ops::RangeInclusive, time::Duration};
use store::{
    InMemoryStore,
    rand::{self, RngExt},
    roaring::RoaringBitmap,
    write::now,
};
use trc::AddContext;
use types::{
    OverlapRule, TimeRange,
    collection::{Collection, SyncCollection},
    field::CalendarEventField,
};

const BOOKING_LOCK_EXPIRY_SECS: u64 = 30;
const BOOKING_LOCK_ATTEMPTS: u32 = 20;
const BOOKING_LOCK_RETRY_MS: RangeInclusive<u64> = 100..=500;

pub struct BookingRequest<'x> {
    pub policy: &'x AutomaticBooking,
    pub organizer_is_local: bool,
}

pub struct BookingLock {
    key: [u8; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookingDecline {
    Conflict,
    NoAuthority,
    NotSupported,
}

pub trait ResourceBookingHandler: Sync + Send {
    fn resource_booking_policy(
        &self,
        account_info: &AccountInfo,
    ) -> impl Future<Output = trc::Result<Option<AutomaticBooking>>> + Send;

    fn lock_resource_booking(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<BookingLock>> + Send;

    fn release_resource_booking(&self, lock: BookingLock) -> impl Future<Output = ()> + Send;

    fn book_resource(
        &self,
        account_info: &AccountInfo,
        ical: &mut ICalendar,
        request: &BookingRequest<'_>,
        exclude_id: Option<u32>,
    ) -> impl Future<Output = Result<Option<ItipMessage<ICalendar>>, ItipIngestError>> + Send;
}

impl ResourceBookingHandler for Server {
    async fn resource_booking_policy(
        &self,
        account_info: &AccountInfo,
    ) -> trc::Result<Option<AutomaticBooking>> {
        if account_info.account().resource_kind().is_none() {
            return Ok(None);
        }
        match self
            .registry()
            .object::<Account>(account_info.account_id().into())
            .await
            .caused_by(trc::location!())?
        {
            Some(Account::Resource(ResourceAccount {
                booking: ResourceBooking::Automatic(policy),
                ..
            })) => Ok(Some(policy)),
            _ => Ok(None),
        }
    }

    async fn lock_resource_booking(&self, account_id: u32) -> trc::Result<BookingLock> {
        let lock = BookingLock {
            key: account_id.to_be_bytes(),
        };
        let store = self.in_memory_store();
        let mut attempts = 1;
        while !store
            .try_lock(
                KV_LOCK_RESOURCE_BOOKING,
                &lock.key,
                BOOKING_LOCK_EXPIRY_SECS,
            )
            .await
            .caused_by(trc::location!())?
        {
            if attempts == BOOKING_LOCK_ATTEMPTS {
                return Err(trc::StoreEvent::AssertValueFailed
                    .into_err()
                    .account_id(account_id)
                    .details("Resource booking lock is held, request left for manual handling")
                    .caused_by(trc::location!()));
            }
            attempts += 1;
            let backoff = rand::rng().random_range(BOOKING_LOCK_RETRY_MS);
            tokio::time::sleep(Duration::from_millis(backoff)).await;
        }
        Ok(lock)
    }

    async fn release_resource_booking(&self, lock: BookingLock) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_RESOURCE_BOOKING, &lock.key)
            .await
        {
            trc::error!(
                err.details("Failed to release resource booking lock")
                    .caused_by(trc::location!())
            );
        }
    }

    async fn book_resource(
        &self,
        account_info: &AccountInfo,
        ical: &mut ICalendar,
        request: &BookingRequest<'_>,
        exclude_id: Option<u32>,
    ) -> Result<Option<ItipMessage<ICalendar>>, ItipIngestError> {
        let data = CalendarEventData::new(
            ical.clone(),
            Tz::Floating,
            self.core.groupware.max_ical_instances,
        );
        let decision = match request.evaluate(
            ical,
            &data,
            now() as i64,
            self.core.groupware.max_ical_instances,
        ) {
            Ok(slots)
                if !request.policy.allow_conflicts
                    && !slots.is_empty()
                    && self
                        .has_booking_conflict(account_info, &slots, exclude_id)
                        .await
                        .caused_by(trc::location!())? =>
            {
                Some(BookingDecline::Conflict)
            }
            Ok(_) => None,
            Err(decline) => Some(decline),
        };

        apply_booking_decision(ical, account_info.addresses(), decision);
        match itip_update(
            ical,
            &data.event,
            account_info.addresses(),
            RecipientPolicy::new(&self.core.groupware, 0),
        ) {
            Ok(messages) => Ok(messages.into_iter().next().map(|mut reply| {
                if let Some(decline) = decision {
                    decline.set_request_status(&mut reply.message);
                }
                reply
            })),
            Err(ItipError::NothingToSend) => Ok(None),
            Err(err) => Err(ItipIngestError::Message(err)),
        }
    }
}

trait BookingConflict {
    fn has_booking_conflict(
        &self,
        account_info: &AccountInfo,
        slots: &BusySlots,
        exclude_id: Option<u32>,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

impl BookingConflict for Server {
    async fn has_booking_conflict(
        &self,
        account_info: &AccountInfo,
        slots: &BusySlots,
        exclude_id: Option<u32>,
    ) -> trc::Result<bool> {
        let account_id = account_info.account_id();
        let min_change_id = if matches!(self.in_memory_store(), InMemoryStore::Local(_)) {
            0
        } else {
            u64::MAX
        };
        let resources = self
            .fetch_groupware_resources_at(
                account_id,
                account_id,
                SyncCollection::Calendar,
                min_change_id,
            )
            .await
            .caused_by(trc::location!())?;
        let window = slots.window();
        let document_ids = resources
            .resources
            .iter()
            .filter(|resource| {
                Some(resource.document_id()) != exclude_id
                    && resource
                        .event_time_range()
                        .is_some_and(|(start, end)| start < window.end && end > window.start)
            })
            .map(|resource| resource.document_id())
            .collect::<RoaringBitmap>();
        if document_ids.is_empty() {
            return Ok(false);
        }

        let identities =
            CalendarAddresses::from_emails(account_info.addresses().iter().map(String::as_str));
        let mut has_conflict = false;
        self.archives(
            account_id,
            Collection::CalendarEvent,
            CalendarEventField::Content.field(),
            &document_ids,
            |_, archive| {
                let content = archive
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?;
                let components = &content.data.event.components;
                let Some(expansion) = content.data.expand(Tz::UTC, window, OverlapRule::Jmap)
                else {
                    return Ok(true);
                };
                has_conflict = expansion.iter().any(|instance| {
                    instance.start < instance.end
                        && slots.overlaps(instance.start, instance.end)
                        && components
                            .get(instance.comp_id as usize)
                            .and_then(|component| {
                                ComponentBusy::parse(component, &identities, PrincipalRole::Owner)
                            })
                            .is_some_and(|busy| {
                                matches!(
                                    busy.busy_level(),
                                    BusyLevel::Confirmed | BusyLevel::Tentative
                                )
                            })
                });
                Ok(!has_conflict)
            },
        )
        .await
        .caused_by(trc::location!())?;

        Ok(has_conflict)
    }
}

impl BookingRequest<'_> {
    pub fn is_authorized(&self) -> bool {
        self.policy.allow_external || self.organizer_is_local
    }

    pub fn evaluate(
        &self,
        ical: &ICalendar,
        data: &CalendarEventData,
        now: i64,
        max_instances: usize,
    ) -> Result<BusySlots, BookingDecline> {
        let policy = self.policy;
        if !self.is_authorized() {
            return Err(BookingDecline::NoAuthority);
        }
        let mut is_recurring = false;
        let mut is_endless = false;
        for entry in ical
            .components
            .iter()
            .filter(|component| component.component_type.is_scheduling_object())
            .flat_map(|component| component.entries.iter())
        {
            match entry.name {
                ICalendarProperty::Rrule => {
                    is_recurring = true;
                    is_endless |= entry.values.iter().any(|value| {
                        matches!(value, ICalendarValue::RecurrenceRule(rule)
                            if rule.count.is_none() && rule.until.is_none())
                    });
                }
                ICalendarProperty::Rdate | ICalendarProperty::RecurrenceId => {
                    is_recurring = true;
                }
                _ => {}
            }
        }
        if is_recurring && !policy.allow_recurring {
            return Err(BookingDecline::NotSupported);
        }
        if let Some(window) = &policy.booking_window
            && (is_endless
                || data.event_range_end() > now.saturating_add(window.0.as_secs() as i64))
        {
            return Err(BookingDecline::NotSupported);
        }

        let instances = data
            .expand(
                Tz::UTC,
                TimeRange {
                    start: i64::MIN,
                    end: i64::MAX,
                },
                OverlapRule::Jmap,
            )
            .ok_or(BookingDecline::NotSupported)?;
        if policy.booking_window.is_some() && instances.len() >= max_instances {
            return Err(BookingDecline::NotSupported);
        }
        let max_duration = policy
            .max_duration
            .as_ref()
            .map_or(i64::MAX, |duration| duration.0.as_secs() as i64);
        let mut slots = Vec::with_capacity(instances.len());
        for instance in instances {
            if instance.end.saturating_sub(instance.start) > max_duration {
                return Err(BookingDecline::NotSupported);
            }
            if instance.start < instance.end && instance.end > now {
                slots.push((instance.start, instance.end));
            }
        }

        Ok(BusySlots::new(slots))
    }
}

pub struct BusySlots {
    slots: Vec<(i64, i64)>,
    max_end: Vec<i64>,
}

impl BusySlots {
    pub fn new(mut slots: Vec<(i64, i64)>) -> Self {
        slots.sort_unstable();
        let mut max_end = Vec::with_capacity(slots.len());
        let mut running = i64::MIN;
        for &(_, end) in &slots {
            running = running.max(end);
            max_end.push(running);
        }
        BusySlots { slots, max_end }
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn overlaps(&self, start: i64, end: i64) -> bool {
        let idx = self
            .slots
            .partition_point(|&(slot_start, _)| slot_start < end);
        idx.checked_sub(1)
            .and_then(|last| self.max_end.get(last))
            .is_some_and(|&max_end| max_end > start)
    }

    fn window(&self) -> TimeRange {
        TimeRange {
            start: self
                .slots
                .first()
                .map_or(i64::MIN, |&(start, _)| start)
                .saturating_sub(MAX_UTC_OFFSET),
            end: self
                .max_end
                .last()
                .copied()
                .unwrap_or(i64::MAX)
                .saturating_add(MAX_UTC_OFFSET),
        }
    }
}

impl BookingDecline {
    fn request_status(&self) -> [&'static str; 2] {
        match self {
            BookingDecline::Conflict => ["4.0", "Event conflict. Date/time is busy."],
            BookingDecline::NoAuthority => ["3.8", "No authority"],
            BookingDecline::NotSupported => ["5.0", "Request not supported"],
        }
    }

    fn set_request_status(&self, ical: &mut ICalendar) {
        let [code, description] = self.request_status();
        for entry in ical
            .components
            .iter_mut()
            .filter(|component| component.component_type.is_scheduling_object())
            .flat_map(|component| component.entries.iter_mut())
            .filter(|entry| entry.name == ICalendarProperty::RequestStatus)
        {
            entry.values = vec![
                ICalendarValue::Text(code.to_string()),
                ICalendarValue::Text(description.to_string()),
            ]
            .into();
        }
    }
}

pub fn apply_booking_decision(
    ical: &mut ICalendar,
    addresses: &[String],
    decision: Option<BookingDecline>,
) {
    let part_stat = if decision.is_some() {
        ICalendarParticipationStatus::Declined
    } else {
        ICalendarParticipationStatus::Accepted
    };
    for component in ical
        .components
        .iter_mut()
        .filter(|component| component.component_type.is_scheduling_object())
    {
        component
            .entries
            .retain(|entry| entry.name != ICalendarProperty::Transp);
        if decision.is_some() {
            component.entries.push(ICalendarEntry {
                name: ICalendarProperty::Transp,
                params: vec![],
                values: [ICalendarValue::Transparency(
                    ICalendarTransparency::Transparent,
                )]
                .into(),
            });
        } else {
            adopt_intended_status(&mut component.entries);
        }

        for entry in component.entries.iter_mut().filter(|entry| {
            entry.name == ICalendarProperty::Attendee
                && entry.calendar_address().is_some_and(|address| {
                    addresses
                        .iter()
                        .any(|own| own.eq_ignore_ascii_case(address))
                })
        }) {
            entry
                .params
                .retain(|param| param.name != ICalendarParameterName::Partstat);
            entry
                .params
                .push(ICalendarParameter::partstat(part_stat.clone()));
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/groupware/src/calendar/booking/tests.rs"]
mod tests;
