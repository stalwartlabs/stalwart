/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};
use nlp::language::Language;
use registry::{
    schema::{
        enums::{SearchCalendarField, SearchContactField, SearchEmailField, StorageQuota},
        structs::{
            AddressBook, Calendar, DataRetention, Email, Jmap, OidcProvider, Search,
            SieveUserInterpreter,
        },
    },
    types::EnumType,
};
use std::time::Duration;
use store::{
    registry::bootstrap::Bootstrap,
    search::{CalendarSearchField, ContactSearchField, EmailSearchField, SearchField},
    write::SearchIndex,
};
use types::special_use::SpecialUse;
use utils::cron::SimpleCron;

use crate::storage::ObjectQuota;

#[derive(Clone)]
pub struct EmailConfig {
    pub default_language: Language,

    pub mailbox_max_depth: usize,
    pub mailbox_name_max_len: usize,

    pub mail_attachments_max_size: usize,
    pub mail_max_size: usize,
    pub mail_autoexpunge_after: Option<u64>,
    pub email_submission_autoexpunge_after: Option<u64>,

    pub changes_max_history: Option<usize>,
    pub share_notification_max_history: Option<Duration>,

    pub sieve_max_script_name: usize,

    pub default_folders: Vec<DefaultFolder>,
    pub shared_folder: String,

    pub encrypt: bool,
    pub encrypt_append: bool,

    pub index_batch_size: usize,
    pub index_fields: AHashMap<SearchIndex, AHashSet<SearchField>>,

    pub max_objects: ObjectQuota,

    pub account_purge_frequency: SimpleCron,
}

#[derive(Clone, Debug)]
pub struct DefaultFolder {
    pub name: String,
    pub aliases: Vec<String>,
    pub special_use: SpecialUse,
    pub subscribe: bool,
    pub create: bool,
}

impl EmailConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let email = bp.setting_infallible::<Email>().await;
        let dr = bp.setting_infallible::<DataRetention>().await;
        let sieve = bp.setting_infallible::<SieveUserInterpreter>().await;
        let search = bp.setting_infallible::<Search>().await;
        let jmap = bp.setting_infallible::<Jmap>().await;
        let calendar = bp.setting_infallible::<Calendar>().await;
        let address_book = bp.setting_infallible::<AddressBook>().await;
        let oidc = bp.setting_infallible::<OidcProvider>().await;

        // Parse default object quotas
        let mut max_objects = ObjectQuota::default();
        for (item, max) in [
            (StorageQuota::MaxMailboxes, email.max_mailboxes),
            (StorageQuota::MaxSieveScripts, sieve.max_scripts),
            (StorageQuota::MaxIdentities, email.max_identities),
            (StorageQuota::MaxEmailSubmissions, email.max_submissions),
            (StorageQuota::MaxMaskedAddresses, email.max_masked_addresses),
            (StorageQuota::MaxAppPasswords, oidc.max_app_passwords),
            (StorageQuota::MaxPushSubscriptions, jmap.max_subscriptions),
            (StorageQuota::MaxCalendars, calendar.max_calendars),
            (StorageQuota::MaxCalendarEvents, calendar.max_events),
            (
                StorageQuota::MaxAddressBooks,
                address_book.max_address_books,
            ),
            (StorageQuota::MaxContactCards, address_book.max_contacts),
        ] {
            if let Some(max) = max {
                max_objects.set(item, max as u32);
            }
        }

        // Parse default folders
        let mut default_folders = Vec::new();
        let mut shared_folder = "Shared Folders".to_string();
        for (special_use, folder) in email.default_folders {
            let special_use = match special_use {
                registry::schema::enums::SpecialUse::Inbox => SpecialUse::Inbox,
                registry::schema::enums::SpecialUse::Trash => SpecialUse::Trash,
                registry::schema::enums::SpecialUse::Junk => SpecialUse::Junk,
                registry::schema::enums::SpecialUse::Drafts => SpecialUse::Drafts,
                registry::schema::enums::SpecialUse::Archive => SpecialUse::Archive,
                registry::schema::enums::SpecialUse::Sent => SpecialUse::Sent,
                registry::schema::enums::SpecialUse::Important => SpecialUse::Important,
                registry::schema::enums::SpecialUse::Memos => SpecialUse::Memos,
                registry::schema::enums::SpecialUse::Scheduled => SpecialUse::Scheduled,
                registry::schema::enums::SpecialUse::Snoozed => SpecialUse::Snoozed,
                registry::schema::enums::SpecialUse::Shared => {
                    shared_folder = folder.name;
                    continue;
                }
            };
            default_folders.push(DefaultFolder {
                name: folder.name,
                aliases: folder.aliases,
                special_use,
                subscribe: folder.subscribe,
                create: folder.create
                    || matches!(
                        special_use,
                        SpecialUse::Inbox | SpecialUse::Trash | SpecialUse::Junk
                    ),
            });
        }
        for (special_use, name) in [
            (SpecialUse::Inbox, "Inbox"),
            (SpecialUse::Trash, "Deleted Items"),
            (SpecialUse::Junk, "Junk Mail"),
            (SpecialUse::Drafts, "Drafts"),
            (SpecialUse::Sent, "Sent Items"),
        ] {
            if !default_folders.iter().any(|f| f.special_use == special_use) {
                default_folders.push(DefaultFolder {
                    name: name.to_string(),
                    aliases: Vec::new(),
                    special_use,
                    subscribe: true,
                    create: true,
                });
            }
        }

        // Search Index settings
        let mut index_fields = AHashMap::new();
        if search.index_email {
            index_fields.insert(
                SearchIndex::Email,
                search
                    .index_email_fields
                    .into_iter()
                    .map(|field| {
                        SearchField::Email(match field {
                            SearchEmailField::From => EmailSearchField::From,
                            SearchEmailField::To => EmailSearchField::To,
                            SearchEmailField::Cc => EmailSearchField::Cc,
                            SearchEmailField::Bcc => EmailSearchField::Bcc,
                            SearchEmailField::Subject => EmailSearchField::Subject,
                            SearchEmailField::Body => EmailSearchField::Body,
                            SearchEmailField::Attachment => EmailSearchField::Attachment,
                            SearchEmailField::ReceivedAt => EmailSearchField::ReceivedAt,
                            SearchEmailField::SentAt => EmailSearchField::SentAt,
                            SearchEmailField::Size => EmailSearchField::Size,
                            SearchEmailField::HasAttachment => EmailSearchField::HasAttachment,
                            SearchEmailField::Headers => EmailSearchField::Headers,
                        })
                    })
                    .collect(),
            );
        }
        if search.index_contacts {
            index_fields.insert(
                SearchIndex::Contacts,
                search
                    .index_contact_fields
                    .into_iter()
                    .map(|field| {
                        SearchField::Contact(match field {
                            SearchContactField::Member => ContactSearchField::Member,
                            SearchContactField::Kind => ContactSearchField::Kind,
                            SearchContactField::Name => ContactSearchField::Name,
                            SearchContactField::Nickname => ContactSearchField::Nickname,
                            SearchContactField::Organization => ContactSearchField::Organization,
                            SearchContactField::Email => ContactSearchField::Email,
                            SearchContactField::Phone => ContactSearchField::Phone,
                            SearchContactField::OnlineService => ContactSearchField::OnlineService,
                            SearchContactField::Address => ContactSearchField::Address,
                            SearchContactField::Note => ContactSearchField::Note,
                            SearchContactField::Uid => ContactSearchField::Uid,
                        })
                    })
                    .collect(),
            );
        }
        if search.index_calendar {
            index_fields.insert(
                SearchIndex::Calendar,
                search
                    .index_calendar_fields
                    .into_iter()
                    .map(|field| {
                        SearchField::Calendar(match field {
                            SearchCalendarField::Title => CalendarSearchField::Title,
                            SearchCalendarField::Description => CalendarSearchField::Description,
                            SearchCalendarField::Location => CalendarSearchField::Location,
                            SearchCalendarField::Owner => CalendarSearchField::Owner,
                            SearchCalendarField::Attendee => CalendarSearchField::Attendee,
                            SearchCalendarField::Start => CalendarSearchField::Start,
                            SearchCalendarField::Uid => CalendarSearchField::Uid,
                        })
                    })
                    .collect(),
            );
        }

        EmailConfig {
            default_language: Language::from_iso_639(search.default_language.as_str())
                .unwrap_or(Language::English),
            mailbox_max_depth: email.max_mailbox_depth as usize,
            mailbox_name_max_len: email.max_mailbox_name_length as usize,
            mail_attachments_max_size: email.max_attachment_size as usize,
            mail_max_size: email.max_message_size as usize,
            mail_autoexpunge_after: dr.expunge_trash_after.map(|d| d.into_inner().as_secs()),
            email_submission_autoexpunge_after: dr
                .expunge_submissions_after
                .map(|d| d.into_inner().as_secs()),
            changes_max_history: dr.max_changes_history.map(|v| v as usize),
            share_notification_max_history: dr.expunge_share_notify_after.map(|v| v.into_inner()),
            sieve_max_script_name: sieve.max_script_name_length as usize,
            encrypt: email.encrypt_at_rest,
            encrypt_append: email.encrypt_on_append,
            index_batch_size: search.index_batch_size as usize,
            index_fields,
            max_objects,
            account_purge_frequency: dr.expunge_schedule.into(),
            default_folders,
            shared_folder,
        }
    }
}
