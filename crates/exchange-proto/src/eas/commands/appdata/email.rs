/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{
    Attachments, Body, BodyPart, Compact, List, Location, Opaque, RightsManagementLicense,
    eas_struct,
};
use crate::common::base64::Base64Text;
use crate::eas::tokens::tag::{
    airsyncbase as asb, calendar, compose_mail, email, email2, meeting_response,
    rights_management as rm, tasks,
};
use crate::eas::types::EasDateTime;

pub type Categories<'a> = List<Cow<'a, str>, { email::CATEGORY.raw() }>;
pub type Forwardees<'a> = List<Forwardee<'a>, { compose_mail::FORWARDEE.raw() }>;

eas_struct!(Email<'a> {
    to: Cow<'a, str> = email::TO,
    cc: Cow<'a, str> = email::CC,
    from: Cow<'a, str> = email::FROM,
    subject: Cow<'a, str> = email::SUBJECT,
    reply_to: Cow<'a, str> = email::REPLY_TO,
    date_received: EasDateTime = email::DATE_RECEIVED,
    display_to: Cow<'a, str> = email::DISPLAY_TO,
    thread_topic: Cow<'a, str> = email::THREAD_TOPIC,
    importance: u8 = email::IMPORTANCE,
    read: bool = email::READ,
    attachments: Attachments<'a> = asb::ATTACHMENTS,
    body: Body<'a> = asb::BODY,
    message_class: Cow<'a, str> = email::MESSAGE_CLASS,
    meeting_request: MeetingRequest<'a> = email::MEETING_REQUEST,
    internet_cpid: Cow<'a, str> = email::INTERNET_CPID,
    flag: EmailFlag<'a> = email::FLAG,
    content_class: Cow<'a, str> = email::CONTENT_CLASS,
    native_body_type: u8 = asb::NATIVE_BODY_TYPE,
    categories: Categories<'a> = email::CATEGORIES,
    um_caller_id: Cow<'a, str> = email2::UM_CALLER_ID,
    um_user_notes: Cow<'a, str> = email2::UM_USER_NOTES,
    conversation_id: Opaque<'a> = email2::CONVERSATION_ID,
    conversation_index: Opaque<'a> = email2::CONVERSATION_INDEX,
    last_verb_executed: i32 = email2::LAST_VERB_EXECUTED,
    last_verb_execution_time: EasDateTime = email2::LAST_VERB_EXECUTION_TIME,
    received_as_bcc: bool = email2::RECEIVED_AS_BCC,
    sender: Cow<'a, str> = email2::SENDER,
    account_id: Cow<'a, str> = email2::ACCOUNT_ID,
    bcc: Cow<'a, str> = email2::BCC,
    is_draft: bool = email2::IS_DRAFT,
    body_part: BodyPart<'a> = asb::BODY_PART,
    rights_management_license: RightsManagementLicense<'a> = rm::RIGHTS_MANAGEMENT_LICENSE,
});

eas_struct!(MeetingRequest<'a> {
    all_day_event: u8 = email::ALL_DAY_EVENT,
    start_time: EasDateTime = email::START_TIME,
    dt_stamp: EasDateTime = email::DT_STAMP,
    end_time: EasDateTime = email::END_TIME,
    instance_type: u8 = email::INSTANCE_TYPE,
    location: Cow<'a, str> = email::LOCATION,
    location_details: Location<'a> = asb::LOCATION,
    organizer: Cow<'a, str> = email::ORGANIZER,
    recurrence_id: EasDateTime = email::RECURRENCE_ID,
    reminder: u32 = email::REMINDER,
    response_requested: u8 = email::RESPONSE_REQUESTED,
    recurrences: List<MeetingRecurrence<'a>, { email::RECURRENCE.raw() }> = email::RECURRENCES,
    sensitivity: u8 = email::SENSITIVITY,
    busy_status: u8 = email::BUSY_STATUS,
    time_zone: Base64Text<'a> = email::TIME_ZONE,
    global_obj_id: Cow<'a, str> = email::GLOBAL_OBJ_ID,
    disallow_new_time_proposal: u8 = email::DISALLOW_NEW_TIME_PROPOSAL,
    meeting_message_type: u8 = email2::MEETING_MESSAGE_TYPE,
    uid: Cow<'a, str> = calendar::UID,
    proposed_start_time: Compact = meeting_response::PROPOSED_START_TIME,
    proposed_end_time: Compact = meeting_response::PROPOSED_END_TIME,
    forwardees: Forwardees<'a> = compose_mail::FORWARDEES,
});

eas_struct!(MeetingRecurrence<'a> {
    recurrence_type: u8 = email::TYPE,
    interval: u32 = email::INTERVAL,
    until: Cow<'a, str> = email::UNTIL,
    occurrences: u32 = email::OCCURRENCES,
    week_of_month: u32 = email::WEEK_OF_MONTH,
    day_of_month: u32 = email::DAY_OF_MONTH,
    day_of_week: u32 = email::DAY_OF_WEEK,
    month_of_year: u32 = email::MONTH_OF_YEAR,
    calendar_type: u8 = email2::CALENDAR_TYPE,
    is_leap_month: u8 = email2::IS_LEAP_MONTH,
    first_day_of_week: u8 = email2::FIRST_DAY_OF_WEEK,
});

eas_struct!(EmailFlag<'a> {
    subject: Cow<'a, str> = tasks::SUBJECT,
    status: u8 = email::STATUS,
    flag_type: Cow<'a, str> = email::FLAG_TYPE,
    date_completed: EasDateTime = tasks::DATE_COMPLETED,
    complete_time: EasDateTime = email::COMPLETE_TIME,
    start_date: EasDateTime = tasks::START_DATE,
    due_date: EasDateTime = tasks::DUE_DATE,
    utc_start_date: EasDateTime = tasks::UTC_START_DATE,
    utc_due_date: EasDateTime = tasks::UTC_DUE_DATE,
    reminder_set: bool = tasks::REMINDER_SET,
    reminder_time: EasDateTime = tasks::REMINDER_TIME,
    ordinal_date: EasDateTime = tasks::ORDINAL_DATE,
    sub_ordinal_date: Cow<'a, str> = tasks::SUB_ORDINAL_DATE,
});

eas_struct!(Forwardee<'a> {
    email: Cow<'a, str> = compose_mail::EMAIL,
    name: Cow<'a, str> = compose_mail::NAME,
});
