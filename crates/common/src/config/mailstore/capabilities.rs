/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::mailstore::jmap::JmapConfig;
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
use registry::{
    schema::structs::{Calendar, Email, SieveUserInterpreter},
    types::EnumType,
};
use store::registry::bootstrap::Bootstrap;
use types::type_state::DataType;
use utils::map::vec_map::VecMap;

impl JmapConfig {
    pub async fn add_capabilities(&mut self, bp: &mut Bootstrap) {
        // Add core capabilities
        self.capabilities.session.append(
            Capability::Core,
            Capabilities::Core(CoreCapabilities {
                max_size_upload: self.upload_max_size as u64,
                max_concurrent_upload: self.upload_max_concurrent.unwrap_or(u32::MAX as u64),
                max_size_request: self.request_max_size as u64,
                max_concurrent_requests: self.request_max_concurrent.unwrap_or(u32::MAX as u64),
                max_calls_in_request: self.request_max_calls as u64,
                max_objects_in_get: self.get_max_objects as u64,
                max_objects_in_set: self.set_max_objects as u64,
                collation_algorithms: vec![
                    "i;ascii-numeric".to_string(),
                    "i;ascii-casemap".to_string(),
                    "i;unicode-casemap".to_string(),
                ],
            }),
        );

        // Add email capabilities
        let email = bp.setting_infallible::<Email>().await;
        self.capabilities.session.append(
            Capability::Mail,
            Capabilities::Empty(EmptyCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Mail,
            Capabilities::Mail(MailCapabilities {
                max_mailboxes_per_email: None,
                max_mailbox_depth: email.max_mailbox_depth,
                max_size_mailbox_name: email.max_mailbox_name_length,
                max_size_attachments_per_email: email.max_attachment_size,
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
                max_participants_per_event: bp
                    .setting_infallible::<Calendar>()
                    .await
                    .max_attendees
                    .into(),
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
        let sieve = bp.setting_infallible::<SieveUserInterpreter>().await;
        let disabled_capabilities = sieve
            .disable_capabilities
            .into_iter()
            .map(|v| v.as_str())
            .collect::<AHashSet<&str>>();
        let mut extensions = sieve::compiler::grammar::Capability::all()
            .iter()
            .map(|c| c.to_string())
            .filter(|c| !disabled_capabilities.contains(c.as_str()))
            .collect::<Vec<String>>();
        extensions.sort_unstable();

        self.capabilities.session.append(
            Capability::Sieve,
            Capabilities::SieveSession(SieveSessionCapabilities::default()),
        );
        self.capabilities.account.insert(
            Capability::Sieve,
            Capabilities::SieveAccount(SieveAccountCapabilities {
                max_script_name: sieve.max_script_name_length as u64,
                max_script_size: sieve.max_script_size,
                max_scripts: sieve.max_scripts.unwrap_or(u32::MAX as u64),
                max_redirects: sieve.max_redirects,
                extensions,
                notification_methods: if !sieve.allowed_notify_uris.is_empty() {
                    sieve.allowed_notify_uris.into()
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
                max_size_blob_set: (self.request_max_size as u64 * 3 / 4) - 512,
                max_data_sources: self.request_max_calls as u64,
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
