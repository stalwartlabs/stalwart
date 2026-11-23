/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Attachments, Body, Compact, List, Location, OrEmpty, eas_struct};
use crate::common::base64::Base64Text;
use crate::eas::tokens::tag::{airsyncbase as asb, calendar as cal, meeting_response};
use crate::eas::types::EasDateTime;

pub type Categories<'a> = List<Cow<'a, str>, { cal::CATEGORY.raw() }>;
pub type Attendees<'a> = List<Attendee<'a>, { cal::ATTENDEE.raw() }>;
pub type Exceptions<'a> = List<CalendarException<'a>, { cal::EXCEPTION.raw() }>;

eas_struct!(Calendar<'a> {
    timezone: Base64Text<'a> = cal::TIMEZONE,
    all_day_event: u8 = cal::ALL_DAY_EVENT,
    body: Body<'a> = asb::BODY,
    busy_status: u8 = cal::BUSY_STATUS,
    organizer_name: Cow<'a, str> = cal::ORGANIZER_NAME,
    organizer_email: Cow<'a, str> = cal::ORGANIZER_EMAIL,
    dt_stamp: Compact = cal::DT_STAMP,
    end_time: Compact = cal::END_TIME,
    location: Cow<'a, str> = cal::LOCATION,
    location_details: Location<'a> = asb::LOCATION,
    reminder: OrEmpty<u32> = cal::REMINDER,
    sensitivity: u8 = cal::SENSITIVITY,
    subject: Cow<'a, str> = cal::SUBJECT,
    start_time: Compact = cal::START_TIME,
    uid: Cow<'a, str> = cal::UID,
    meeting_status: u8 = cal::MEETING_STATUS,
    attendees: Attendees<'a> = cal::ATTENDEES,
    categories: Categories<'a> = cal::CATEGORIES,
    recurrence: Recurrence = cal::RECURRENCE,
    exceptions: Exceptions<'a> = cal::EXCEPTIONS,
    response_requested: bool = cal::RESPONSE_REQUESTED,
    appointment_reply_time: Compact = cal::APPOINTMENT_REPLY_TIME,
    response_type: u32 = cal::RESPONSE_TYPE,
    disallow_new_time_proposal: bool = cal::DISALLOW_NEW_TIME_PROPOSAL,
    online_meeting_conf_link: Cow<'a, str> = cal::ONLINE_MEETING_CONF_LINK,
    online_meeting_external_link: Cow<'a, str> = cal::ONLINE_MEETING_EXTERNAL_LINK,
    client_uid: Cow<'a, str> = cal::CLIENT_UID,
    native_body_type: u8 = asb::NATIVE_BODY_TYPE,
    attachments: Attachments<'a> = asb::ATTACHMENTS,
});

eas_struct!(Attendee<'a> {
    email: Cow<'a, str> = cal::EMAIL,
    name: Cow<'a, str> = cal::NAME,
    attendee_status: u8 = cal::ATTENDEE_STATUS,
    attendee_type: u8 = cal::ATTENDEE_TYPE,
    proposed_start_time: Compact = meeting_response::PROPOSED_START_TIME,
    proposed_end_time: Compact = meeting_response::PROPOSED_END_TIME,
});

eas_struct!(Recurrence {
    recurrence_type: u8 = cal::TYPE,
    occurrences: u16 = cal::OCCURRENCES,
    interval: u16 = cal::INTERVAL,
    week_of_month: u8 = cal::WEEK_OF_MONTH,
    day_of_week: u16 = cal::DAY_OF_WEEK,
    month_of_year: u8 = cal::MONTH_OF_YEAR,
    until: Compact = cal::UNTIL,
    day_of_month: u8 = cal::DAY_OF_MONTH,
    calendar_type: u8 = cal::CALENDAR_TYPE,
    is_leap_month: u8 = cal::IS_LEAP_MONTH,
    first_day_of_week: u8 = cal::FIRST_DAY_OF_WEEK,
});

eas_struct!(CalendarException<'a> {
    deleted: u8 = cal::DELETED,
    exception_start_time: Compact = cal::EXCEPTION_START_TIME,
    subject: Cow<'a, str> = cal::SUBJECT,
    start_time: Compact = cal::START_TIME,
    end_time: Compact = cal::END_TIME,
    body: Body<'a> = asb::BODY,
    location: Cow<'a, str> = cal::LOCATION,
    location_details: Location<'a> = asb::LOCATION,
    attachments: Attachments<'a> = asb::ATTACHMENTS,
    categories: Categories<'a> = cal::CATEGORIES,
    sensitivity: u8 = cal::SENSITIVITY,
    busy_status: u8 = cal::BUSY_STATUS,
    all_day_event: u8 = cal::ALL_DAY_EVENT,
    reminder: OrEmpty<u32> = cal::REMINDER,
    dt_stamp: Compact = cal::DT_STAMP,
    instance_id: EasDateTime = asb::INSTANCE_ID,
    meeting_status: u8 = cal::MEETING_STATUS,
    attendees: Attendees<'a> = cal::ATTENDEES,
    appointment_reply_time: Compact = cal::APPOINTMENT_REPLY_TIME,
    response_type: u32 = cal::RESPONSE_TYPE,
    online_meeting_conf_link: Cow<'a, str> = cal::ONLINE_MEETING_CONF_LINK,
    online_meeting_external_link: Cow<'a, str> = cal::ONLINE_MEETING_EXTERNAL_LINK,
});
