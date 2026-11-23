/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Body, List, eas_struct};
use crate::eas::tokens::tag::{airsyncbase as asb, tasks};
use crate::eas::types::EasDateTime;

pub type Categories<'a> = List<Cow<'a, str>, { tasks::CATEGORY.raw() }>;

eas_struct!(Task<'a> {
    body: Body<'a> = asb::BODY,
    categories: Categories<'a> = tasks::CATEGORIES,
    complete: bool = tasks::COMPLETE,
    date_completed: EasDateTime = tasks::DATE_COMPLETED,
    due_date: EasDateTime = tasks::DUE_DATE,
    utc_due_date: EasDateTime = tasks::UTC_DUE_DATE,
    importance: u8 = tasks::IMPORTANCE,
    recurrence: TaskRecurrence = tasks::RECURRENCE,
    reminder_set: bool = tasks::REMINDER_SET,
    reminder_time: EasDateTime = tasks::REMINDER_TIME,
    sensitivity: u8 = tasks::SENSITIVITY,
    start_date: EasDateTime = tasks::START_DATE,
    utc_start_date: EasDateTime = tasks::UTC_START_DATE,
    subject: Cow<'a, str> = tasks::SUBJECT,
    ordinal_date: EasDateTime = tasks::ORDINAL_DATE,
    sub_ordinal_date: Cow<'a, str> = tasks::SUB_ORDINAL_DATE,
    native_body_type: u8 = asb::NATIVE_BODY_TYPE,
});

eas_struct!(TaskRecurrence {
    recurrence_type: u8 = tasks::TYPE,
    start: EasDateTime = tasks::START,
    until: EasDateTime = tasks::UNTIL,
    occurrences: u16 = tasks::OCCURRENCES,
    interval: u16 = tasks::INTERVAL,
    day_of_month: u8 = tasks::DAY_OF_MONTH,
    day_of_week: u16 = tasks::DAY_OF_WEEK,
    week_of_month: u8 = tasks::WEEK_OF_MONTH,
    month_of_year: u8 = tasks::MONTH_OF_YEAR,
    regenerate: bool = tasks::REGENERATE,
    dead_occur: bool = tasks::DEAD_OCCUR,
    calendar_type: u8 = tasks::CALENDAR_TYPE,
    is_leap_month: u8 = tasks::IS_LEAP_MONTH,
    first_day_of_week: u8 = tasks::FIRST_DAY_OF_WEEK,
});
