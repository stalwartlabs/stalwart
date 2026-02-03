/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::structs::{
    AddressBook, Calendar, CalendarAlarm, CalendarScheduling, DataRetention, FileStorage, Sharing,
    WebDav,
};
use std::str::FromStr;
use store::registry::bootstrap::Bootstrap;
use utils::template::Template;

#[derive(Debug, Clone, Default)]
pub struct GroupwareConfig {
    // DAV settings
    pub max_request_size: usize,
    pub dead_property_size: Option<usize>,
    pub live_property_size: usize,
    pub max_lock_timeout: u64,
    pub max_locks_per_user: usize,
    pub max_results: usize,
    pub assisted_discovery: bool,

    // Calendar settings
    pub max_ical_size: usize,
    pub max_ical_instances: usize,
    pub max_ical_attendees_per_instance: usize,
    pub default_calendar_name: Option<String>,
    pub default_calendar_display_name: Option<String>,
    pub alarms_enabled: bool,
    pub alarms_minimum_interval: i64,
    pub alarms_allow_external_recipients: bool,
    pub alarms_from_name: String,
    pub alarms_from_email: Option<String>,
    pub alarms_template: Template<CalendarTemplateVariable>,
    pub itip_enabled: bool,
    pub itip_auto_add: bool,
    pub itip_inbound_max_ical_size: usize,
    pub itip_outbound_max_recipients: usize,
    pub itip_http_rsvp_url: Option<String>,
    pub itip_http_rsvp_expiration: u64,
    pub itip_inbox_auto_expunge: Option<u64>,
    pub itip_template: Template<CalendarTemplateVariable>,

    // Addressbook settings
    pub max_vcard_size: usize,
    pub default_addressbook_name: Option<String>,
    pub default_addressbook_display_name: Option<String>,

    // File storage settings
    pub max_file_size: usize,

    // Sharing settings
    pub max_shares_per_item: usize,
    pub allow_directory_query: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub enum CalendarTemplateVariable {
    #[default]
    PageTitle,
    Header,
    Footer,
    EventTitle,
    EventDescription,
    EventDetails,
    Actions,
    ActionUrl,
    ActionName,
    AttendeesTitle,
    Attendees,
    Key,
    Color,
    Changed,
    Value,
    LogoCid,
    OldValue,
    Rsvp,
}

impl GroupwareConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let calendar = bp.setting_infallible::<Calendar>().await;
        let alarm = bp.setting_infallible::<CalendarAlarm>().await;
        let sched = bp.setting_infallible::<CalendarScheduling>().await;
        let book = bp.setting_infallible::<AddressBook>().await;
        let dav = bp.setting_infallible::<WebDav>().await;
        let file = bp.setting_infallible::<FileStorage>().await;
        let share = bp.setting_infallible::<Sharing>().await;
        let dr = bp.setting_infallible::<DataRetention>().await;

        GroupwareConfig {
            max_request_size: dav.request_max_size as usize,
            dead_property_size: dav.dead_property_max_size.map(|v| v as usize),
            live_property_size: dav.live_property_max_size as usize,
            assisted_discovery: dav.enable_assisted_discovery,
            max_lock_timeout: dav.max_lock_timeout.into_inner().as_secs(),
            max_locks_per_user: dav.max_locks as usize,
            max_results: dav.max_results as usize,
            default_calendar_name: calendar.default_href_name,
            default_calendar_display_name: calendar.default_display_name,
            default_addressbook_name: book.default_href_name,
            default_addressbook_display_name: book.default_display_name,
            max_ical_size: calendar.max_i_calendar_size as usize,
            max_ical_instances: calendar.max_recurrence_expansions as usize,
            max_ical_attendees_per_instance: calendar.max_attendees as usize,
            max_vcard_size: book.max_v_card_size as usize,
            max_file_size: file.max_size as usize,
            alarms_enabled: alarm.enable,
            alarms_minimum_interval: alarm.min_trigger_interval.into_inner().as_secs() as i64,
            alarms_allow_external_recipients: alarm.allow_external_rcpts,
            alarms_from_name: alarm.from_name,
            alarms_from_email: alarm.from_email,
            alarms_template: Template::parse(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../resources/html-templates/calendar-alarm.html.min"
            )))
            .expect("Failed to parse calendar template"),
            itip_enabled: sched.enable,
            itip_auto_add: sched.auto_add_invitations,
            itip_inbound_max_ical_size: sched.itip_max_size as usize,
            itip_outbound_max_recipients: sched.max_recipients as usize,
            itip_inbox_auto_expunge: dr
                .expunge_scheduling_inbox_after
                .map(|d| d.into_inner().as_secs()),
            itip_http_rsvp_url: if sched.http_rsvp_enable {
                if let Some(url) = sched
                    .http_rsvp_template
                    .as_deref()
                    .map(|v| v.trim().trim_end_matches('/'))
                    .filter(|v| !v.is_empty())
                {
                    Some(url.to_string())
                } else {
                    Some(format!("https://{}/calendar/rsvp", bp.hostname()))
                }
            } else {
                None
            },
            max_shares_per_item: share.max_shares as usize,
            allow_directory_query: share.allow_directory_queries,
            itip_http_rsvp_expiration: sched.http_rsvp_link_expiry.into_inner().as_secs(),
            itip_template: Template::parse(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../resources/html-templates/calendar-invite.html.min"
            )))
            .expect("Failed to parse calendar template"),
        }
    }
}

impl FromStr for CalendarTemplateVariable {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "page_title" => Ok(CalendarTemplateVariable::PageTitle),
            "header" => Ok(CalendarTemplateVariable::Header),
            "footer" => Ok(CalendarTemplateVariable::Footer),
            "event_title" => Ok(CalendarTemplateVariable::EventTitle),
            "event_description" => Ok(CalendarTemplateVariable::EventDescription),
            "event_details" => Ok(CalendarTemplateVariable::EventDetails),
            "action_url" => Ok(CalendarTemplateVariable::ActionUrl),
            "action_name" => Ok(CalendarTemplateVariable::ActionName),
            "attendees" => Ok(CalendarTemplateVariable::Attendees),
            "attendees_title" => Ok(CalendarTemplateVariable::AttendeesTitle),
            "key" => Ok(CalendarTemplateVariable::Key),
            "value" => Ok(CalendarTemplateVariable::Value),
            "logo_cid" => Ok(CalendarTemplateVariable::LogoCid),
            "actions" => Ok(CalendarTemplateVariable::Actions),
            "changed" => Ok(CalendarTemplateVariable::Changed),
            "old_value" => Ok(CalendarTemplateVariable::OldValue),
            "rsvp" => Ok(CalendarTemplateVariable::Rsvp),
            "color" => Ok(CalendarTemplateVariable::Color),
            _ => Err(format!("Unknown calendar template variable: {}", s)),
        }
    }
}
