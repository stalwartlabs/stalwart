/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::{
    schema::{CalendarItemType, LegacyFreeBusy, LocationSource, MeetingRequestType, ResponseType},
    types::{
        address::{EmailAddress, SingleRecipient},
        ids::ItemId,
        recurrence::Recurrence,
        timezone::{TimeZone, TimeZoneDefinition},
        value::{DateTime, List, ListItem, ews_fields, fields_value},
    },
};
use std::borrow::Cow;

ews_fields! {
    pub struct Attendee<'x> {
        mailbox: "Mailbox" => EmailAddress<'x>,
        response_type: "ResponseType" => ResponseType,
        last_response_time: "LastResponseTime" => DateTime,
        proposed_start: "ProposedStart" => DateTime,
        proposed_end: "ProposedEnd" => DateTime,
    }
}

fields_value!(Attendee<'x>);

impl ListItem for Attendee<'_> {
    const ITEM: &'static str = "Attendee";
}

ews_fields! {
    pub struct OccurrenceInfo<'x> {
        item_id: "ItemId" => ItemId<'x>,
        start: "Start" => DateTime,
        end: "End" => DateTime,
        original_start: "OriginalStart" => DateTime,
    }
}

fields_value!(OccurrenceInfo<'x>);

impl ListItem for OccurrenceInfo<'_> {
    const ITEM: &'static str = "Occurrence";
}

ews_fields! {
    pub struct DeletedOccurrence {
        start: "Start" => DateTime,
    }
}

fields_value!(DeletedOccurrence);

impl ListItem for DeletedOccurrence {
    const ITEM: &'static str = "DeletedOccurrence";
}

ews_fields! {
    pub struct PostalAddress<'x> {
        street: "Street" => Cow<'x, str>,
        city: "City" => Cow<'x, str>,
        state: "State" => Cow<'x, str>,
        country: "Country" => Cow<'x, str>,
        postal_code: "PostalCode" => Cow<'x, str>,
        post_office_box: "PostOfficeBox" => Cow<'x, str>,
        address_type: "Type" => Cow<'x, str>,
        latitude: "Latitude" => f64,
        longitude: "Longitude" => f64,
        accuracy: "Accuracy" => f64,
        altitude: "Altitude" => f64,
        altitude_accuracy: "AltitudeAccuracy" => f64,
        formatted_address: "FormattedAddress" => Cow<'x, str>,
        location_uri: "LocationUri" => Cow<'x, str>,
        location_source: "LocationSource" => LocationSource,
    }
}

fields_value!(PostalAddress<'x>);

ews_fields! {
    pub struct EnhancedLocation<'x> {
        display_name: "DisplayName" => Cow<'x, str>,
        annotation: "Annotation" => Cow<'x, str>,
        postal_address: "PostalAddress" => PostalAddress<'x>,
    }
}

fields_value!(EnhancedLocation<'x>);

pub type Attendees<'x> = List<Attendee<'x>>;

ews_fields! {
    pub struct CalendarFields<'x> {
        uid: "UID" => Cow<'x, str>,
        recurrence_id: "RecurrenceId" => DateTime,
        date_time_stamp: "DateTimeStamp" => DateTime,
        start: "Start" => DateTime,
        end: "End" => DateTime,
        original_start: "OriginalStart" => DateTime,
        is_all_day_event: "IsAllDayEvent" => bool,
        legacy_free_busy_status: "LegacyFreeBusyStatus" => LegacyFreeBusy,
        location: "Location" => Cow<'x, str>,
        when: "When" => Cow<'x, str>,
        is_meeting: "IsMeeting" => bool,
        is_cancelled: "IsCancelled" => bool,
        is_recurring: "IsRecurring" => bool,
        meeting_request_was_sent: "MeetingRequestWasSent" => bool,
        is_response_requested: "IsResponseRequested" => bool,
        calendar_item_type: "CalendarItemType" => CalendarItemType,
        my_response_type: "MyResponseType" => ResponseType,
        organizer: "Organizer" => SingleRecipient<'x>,
        required_attendees: "RequiredAttendees" => Attendees<'x>,
        optional_attendees: "OptionalAttendees" => Attendees<'x>,
        resources: "Resources" => Attendees<'x>,
        conflicting_meeting_count: "ConflictingMeetingCount" => i32,
        adjacent_meeting_count: "AdjacentMeetingCount" => i32,
        duration: "Duration" => Cow<'x, str>,
        time_zone: "TimeZone" => Cow<'x, str>,
        appointment_reply_time: "AppointmentReplyTime" => DateTime,
        appointment_sequence_number: "AppointmentSequenceNumber" => i32,
        appointment_state: "AppointmentState" => i32,
        recurrence: "Recurrence" => Box<Recurrence>,
        first_occurrence: "FirstOccurrence" => OccurrenceInfo<'x>,
        last_occurrence: "LastOccurrence" => OccurrenceInfo<'x>,
        modified_occurrences: "ModifiedOccurrences" => List<OccurrenceInfo<'x>>,
        deleted_occurrences: "DeletedOccurrences" => List<DeletedOccurrence>,
        meeting_time_zone: "MeetingTimeZone" => Box<TimeZone<'x>>,
        start_time_zone: "StartTimeZone" => Box<TimeZoneDefinition<'x>>,
        end_time_zone: "EndTimeZone" => Box<TimeZoneDefinition<'x>>,
        conference_type: "ConferenceType" => i32,
        allow_new_time_proposal: "AllowNewTimeProposal" => bool,
        is_online_meeting: "IsOnlineMeeting" => bool,
        meeting_workspace_url: "MeetingWorkspaceUrl" => Cow<'x, str>,
        net_show_url: "NetShowUrl" => Cow<'x, str>,
        enhanced_location: "EnhancedLocation" => Box<EnhancedLocation<'x>>,
        start_wall_clock: "StartWallClock" => DateTime,
        end_wall_clock: "EndWallClock" => DateTime,
        start_time_zone_id: "StartTimeZoneId" => Cow<'x, str>,
        end_time_zone_id: "EndTimeZoneId" => Cow<'x, str>,
        intended_free_busy_status: "IntendedFreeBusyStatus" => LegacyFreeBusy,
        join_online_meeting_url: "JoinOnlineMeetingUrl" => Cow<'x, str>,
        is_organizer: "IsOrganizer" => bool,
        do_not_forward_meeting: "DoNotForwardMeeting" => bool,
    }
    skip {
        "InboxReminders", "ConflictingMeetings", "AdjacentMeetings", "OnlineMeetingSettings",
        "CalendarActivityData",
    }
}

ews_fields! {
    pub struct MeetingFields<'x> {
        associated_calendar_item_id: "AssociatedCalendarItemId" => ItemId<'x>,
        is_delegated: "IsDelegated" => bool,
        is_out_of_date: "IsOutOfDate" => bool,
        has_been_processed: "HasBeenProcessed" => bool,
        response_type: "ResponseType" => ResponseType,
        uid: "UID" => Cow<'x, str>,
        recurrence_id: "RecurrenceId" => DateTime,
        date_time_stamp: "DateTimeStamp" => DateTime,
        is_organizer: "IsOrganizer" => bool,
    }
}

ews_fields! {
    pub struct MeetingRequestFields<'x> {
        meeting_request_type: "MeetingRequestType" => MeetingRequestType,
        intended_free_busy_status: "IntendedFreeBusyStatus" => LegacyFreeBusy,
        start: "Start" => DateTime,
        end: "End" => DateTime,
        original_start: "OriginalStart" => DateTime,
        is_all_day_event: "IsAllDayEvent" => bool,
        legacy_free_busy_status: "LegacyFreeBusyStatus" => LegacyFreeBusy,
        location: "Location" => Cow<'x, str>,
        when: "When" => Cow<'x, str>,
        is_meeting: "IsMeeting" => bool,
        is_cancelled: "IsCancelled" => bool,
        is_recurring: "IsRecurring" => bool,
        meeting_request_was_sent: "MeetingRequestWasSent" => bool,
        calendar_item_type: "CalendarItemType" => CalendarItemType,
        my_response_type: "MyResponseType" => ResponseType,
        organizer: "Organizer" => SingleRecipient<'x>,
        required_attendees: "RequiredAttendees" => Attendees<'x>,
        optional_attendees: "OptionalAttendees" => Attendees<'x>,
        resources: "Resources" => Attendees<'x>,
        conflicting_meeting_count: "ConflictingMeetingCount" => i32,
        adjacent_meeting_count: "AdjacentMeetingCount" => i32,
        duration: "Duration" => Cow<'x, str>,
        time_zone: "TimeZone" => Cow<'x, str>,
        appointment_reply_time: "AppointmentReplyTime" => DateTime,
        appointment_sequence_number: "AppointmentSequenceNumber" => i32,
        appointment_state: "AppointmentState" => i32,
        recurrence: "Recurrence" => Box<Recurrence>,
        first_occurrence: "FirstOccurrence" => OccurrenceInfo<'x>,
        last_occurrence: "LastOccurrence" => OccurrenceInfo<'x>,
        modified_occurrences: "ModifiedOccurrences" => List<OccurrenceInfo<'x>>,
        deleted_occurrences: "DeletedOccurrences" => List<DeletedOccurrence>,
        meeting_time_zone: "MeetingTimeZone" => Box<TimeZone<'x>>,
        start_time_zone: "StartTimeZone" => Box<TimeZoneDefinition<'x>>,
        end_time_zone: "EndTimeZone" => Box<TimeZoneDefinition<'x>>,
        conference_type: "ConferenceType" => i32,
        allow_new_time_proposal: "AllowNewTimeProposal" => bool,
        is_online_meeting: "IsOnlineMeeting" => bool,
        meeting_workspace_url: "MeetingWorkspaceUrl" => Cow<'x, str>,
        net_show_url: "NetShowUrl" => Cow<'x, str>,
        enhanced_location: "EnhancedLocation" => Box<EnhancedLocation<'x>>,
        start_wall_clock: "StartWallClock" => DateTime,
        end_wall_clock: "EndWallClock" => DateTime,
        start_time_zone_id: "StartTimeZoneId" => Cow<'x, str>,
        end_time_zone_id: "EndTimeZoneId" => Cow<'x, str>,
        do_not_forward_meeting: "DoNotForwardMeeting" => bool,
    }
    skip { "ConflictingMeetings", "AdjacentMeetings", "ChangeHighlights" }
}

ews_fields! {
    pub struct MeetingResponseFields<'x> {
        start: "Start" => DateTime,
        end: "End" => DateTime,
        location: "Location" => Cow<'x, str>,
        recurrence: "Recurrence" => Box<Recurrence>,
        calendar_item_type: "CalendarItemType" => Cow<'x, str>,
        proposed_start: "ProposedStart" => DateTime,
        proposed_end: "ProposedEnd" => DateTime,
        enhanced_location: "EnhancedLocation" => Box<EnhancedLocation<'x>>,
    }
}

ews_fields! {
    pub struct MeetingCancellationFields<'x> {
        start: "Start" => DateTime,
        end: "End" => DateTime,
        location: "Location" => Cow<'x, str>,
        recurrence: "Recurrence" => Box<Recurrence>,
        calendar_item_type: "CalendarItemType" => Cow<'x, str>,
        enhanced_location: "EnhancedLocation" => Box<EnhancedLocation<'x>>,
        do_not_forward_meeting: "DoNotForwardMeeting" => bool,
    }
}
