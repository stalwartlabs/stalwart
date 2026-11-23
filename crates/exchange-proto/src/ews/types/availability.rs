/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::{DateTime, ews_struct};
use crate::ews::schema::{DayOfWeek, FreeBusyViewKind, MeetingAttendeeType, SuggestionQuality};
use std::borrow::Cow;

ews_struct! {
    pub struct SerializableTimeZoneTime<'x> {
        bias: req "Bias" => i32,
        time: req "Time" => Cow<'x, str>,
        day_order: req "DayOrder" => i16,
        month: req "Month" => i16,
        day_of_week: req "DayOfWeek" => DayOfWeek,
        year: opt "Year" => Cow<'x, str>,
    }
}

ews_struct! {
    pub struct SerializableTimeZone<'x> {
        bias: req "Bias" => i32,
        standard_time: opt "StandardTime" => SerializableTimeZoneTime<'x>,
        daylight_time: opt "DaylightTime" => SerializableTimeZoneTime<'x>,
    }
}

ews_struct! {
    pub struct AvailabilityAddress<'x> {
        name: opt "Name" => Cow<'x, str>,
        address: req "Address" => Cow<'x, str>,
        routing_type: opt "RoutingType" => Cow<'x, str>,
    }
}

ews_struct! {
    pub struct MailboxData<'x> {
        email: req "Email" => AvailabilityAddress<'x>,
        attendee_type: req "AttendeeType" => MeetingAttendeeType,
        exclude_conflicts: opt "ExcludeConflicts" => bool,
    }
}

ews_struct! {
    pub struct TimeWindow {
        start_time: req "StartTime" => DateTime,
        end_time: req "EndTime" => DateTime,
    }
}

ews_struct! {
    pub struct FreeBusyViewOptions {
        time_window: req "TimeWindow" => TimeWindow,
        merged_free_busy_interval_in_minutes: opt "MergedFreeBusyIntervalInMinutes" => i32,
        requested_view: opt "RequestedView" => FreeBusyViewKind,
    }
}

ews_struct! {
    pub struct SuggestionsViewOptions<'x> {
        good_threshold: opt "GoodThreshold" => i32,
        maximum_results_by_day: opt "MaximumResultsByDay" => i32,
        maximum_non_work_hour_results_by_day: opt "MaximumNonWorkHourResultsByDay" => i32,
        meeting_duration_in_minutes: opt "MeetingDurationInMinutes" => i32,
        minimum_suggestion_quality: opt "MinimumSuggestionQuality" => SuggestionQuality,
        detailed_suggestions_window: req "DetailedSuggestionsWindow" => TimeWindow,
        current_meeting_time: opt "CurrentMeetingTime" => DateTime,
        global_object_id: opt "GlobalObjectId" => Cow<'x, str>,
    }
}
