/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::settings::JmapConfig;
use crate::config::groupware::GroupwareConfig;
use ahash::AHashSet;
use calcard::icalendar::ICalendarDuration;
use chrono::{DateTime, Utc};
use jmap_proto::{
    object::email::EmailComparator,
    request::capability::{
        BlobCapabilities, CalendarCapabilities, Capabilities, Capability, ContactsCapabilities,
        CoreCapabilities, EmptyCapabilities, FileNodeCapabilities, MailCapabilities,
        PrincipalAvailabilityCapabilities, PrincipalCapabilities, SieveAccountCapabilities,
        SieveSessionCapabilities, SubmissionCapabilities,
    },
    types::date::UTCDate,
};
use types::{collection::Collection, type_state::DataType};
use utils::{config::Config, map::vec_map::VecMap};

impl JmapConfig {
    pub fn add_capabilities(&mut self, config: &mut Config, groupware_config: &GroupwareConfig) {
        // Add core capabilities
        self.capabilities.session.append(
            Capability::Core,
            Capabilities::Core(CoreCapabilities {
                max_size_upload: self.upload_max_size,
                max_concurrent_upload: self.upload_max_concurrent.unwrap_or(u32::MAX as u64)
                    as usize,
                max_size_request: self.request_max_size,
                max_concurrent_requests: self.request_max_concurrent.unwrap_or(u32::MAX as u64)
                    as usize,
                max_calls_in_request: self.request_max_calls,
                max_objects_in_get: self.get_max_objects,
                max_objects_in_set: self.set_max_objects,
                collation_algorithms: vec![
                    "i;ascii-numeric".to_string(),
                    "i;ascii-casemap".to_string(),
                    "i;unicode-casemap".to_string(),
                ],
            }),
        );

        // Add email capabilities
        self.capabilities.session.append(
            Capability::Mail,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Mail,
            Capabilities::Mail(MailCapabilities {
                max_mailboxes_per_email: None,
                max_mailbox_depth: self.mailbox_max_depth,
                max_size_mailbox_name: self.mailbox_name_max_len,
                max_size_attachments_per_email: self.mail_attachments_max_size,
                email_query_sort_options: vec![
                    EmailComparator::ReceivedAt,
                    EmailComparator::Size,
                    EmailComparator::From,
                    EmailComparator::To,
                    EmailComparator::Subject,
                    EmailComparator::SentAt,
                    EmailComparator::HasKeyword(Default::default()),
                    EmailComparator::AllInThreadHaveKeyword(Default::default()),
                    EmailComparator::SomeInThreadHaveKeyword(Default::default()),
                ],
                may_create_top_level_mailbox: true,
            }),
        );

        // Add calendar capabilities
        self.capabilities.session.append(
            Capability::Calendars,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Calendars,
            Capabilities::Calendar(CalendarCapabilities {
                max_calendars_per_event: None,
                min_date_time: UTCDate::from_timestamp(DateTime::<Utc>::MIN_UTC.timestamp()),
                max_date_time: UTCDate::from_timestamp(DateTime::<Utc>::MAX_UTC.timestamp()),
                max_expanded_query_duration: ICalendarDuration::from_seconds(86400 * 365)
                    .to_string(),
                max_participants_per_event: groupware_config.max_ical_attendees_per_instance.into(),
                may_create_calendar: true,
            }),
        );

        self.capabilities.session.append(
            Capability::CalendarsParse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::CalendarsParse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );

        // Add contacts capabilities
        self.capabilities.session.append(
            Capability::Contacts,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Contacts,
            Capabilities::Contacts(ContactsCapabilities {
                max_address_books_per_card: None,
                may_create_address_book: true,
            }),
        );
        self.capabilities.session.append(
            Capability::ContactsParse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::ContactsParse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );

        // Add file node capabilities
        self.capabilities.session.append(
            Capability::FileNode,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::FileNode,
            Capabilities::FileNode(FileNodeCapabilities {
                max_file_node_depth: None,
                max_size_file_node_name: 255,
                file_node_query_sort_options: vec![],
                may_create_top_level_file_node: true,
            }),
        );

        // Add principal capabilities
        self.capabilities.session.append(
            Capability::Principals,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Principals,
            Capabilities::Principals(PrincipalCapabilities {
                current_user_principal_id: None,
            }),
        );
        self.capabilities.session.append(
            Capability::PrincipalsAvailability,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::PrincipalsAvailability,
            Capabilities::PrincipalsAvailability(PrincipalAvailabilityCapabilities {
                max_availability_duration: ICalendarDuration::from_seconds(86400 * 365).to_string(),
            }),
        );

        // Add submission capabilities
        self.capabilities.session.append(
            Capability::Submission,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Submission,
            Capabilities::Submission(SubmissionCapabilities {
                max_delayed_send: 86400 * 30,
                submission_extensions: VecMap::from_iter([
                    ("FUTURERELEASE".to_string(), Vec::new()),
                    ("SIZE".to_string(), Vec::new()),
                    ("DSN".to_string(), Vec::new()),
                    ("DELIVERYBY".to_string(), Vec::new()),
                    ("MT-PRIORITY".to_string(), vec!["MIXER".to_string()]),
                    ("REQUIRETLS".to_string(), vec![]),
                ]),
            }),
        );

        // Add vacation response capabilities
        self.capabilities.session.append(
            Capability::VacationResponse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::VacationResponse,
            Capabilities::Empty(EmptyCapabilities::default()),
        );

        // Add Sieve capabilities
        let mut notification_methods = Vec::new();

        for (_, uri) in config.values("sieve.untrusted.notification-uris") {
            notification_methods.push(uri.to_string());
        }
        if notification_methods.is_empty() {
            notification_methods.push("mailto".to_string());
        }

        let mut capabilities: AHashSet<sieve::compiler::grammar::Capability> =
            AHashSet::from_iter(sieve::compiler::grammar::Capability::all().iter().cloned());

        for (_, capability) in config.values("sieve.untrusted.disabled-capabilities") {
            capabilities.remove(&sieve::compiler::grammar::Capability::parse(capability));
        }

        let mut extensions = capabilities
            .into_iter()
            .map(|c| c.to_string())
            .collect::<Vec<String>>();
        extensions.sort_unstable();

        self.capabilities.session.append(
            Capability::Sieve,
            Capabilities::SieveSession(SieveSessionCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Sieve,
            Capabilities::SieveAccount(SieveAccountCapabilities {
                max_script_name: self.sieve_max_script_name,
                max_script_size: config
                    .property("sieve.untrusted.max-script-size")
                    .unwrap_or(1024 * 1024),
                max_scripts: self.max_objects[Collection::SieveScript as usize] as usize,
                max_redirects: config
                    .property("sieve.untrusted.max-redirects")
                    .unwrap_or(1),
                extensions,
                notification_methods: if !notification_methods.is_empty() {
                    notification_methods.into()
                } else {
                    None
                },
                ext_lists: None,
            }),
        );

        // Add Blob capabilities
        self.capabilities.session.append(
            Capability::Blob,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Blob,
            Capabilities::Blob(BlobCapabilities {
                max_size_blob_set: (self.request_max_size * 3 / 4) - 512,
                max_data_sources: self.request_max_calls,
                supported_type_names: vec![
                    DataType::Email,
                    DataType::Thread,
                    DataType::SieveScript,
                ],
                supported_digest_algorithms: vec!["sha", "sha-256", "sha-512"],
            }),
        );

        // Add Quota capabilities
        self.capabilities.session.append(
            Capability::Quota,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Quota,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
    }
}
