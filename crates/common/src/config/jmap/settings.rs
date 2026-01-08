/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::groupware::GroupwareConfig;
use ahash::{AHashMap, AHashSet};
use jmap_proto::request::capability::BaseCapabilities;
use nlp::language::Language;
use std::{str::FromStr, time::Duration};
use store::{search::SearchField, write::SearchIndex};
use types::{collection::Collection, special_use::SpecialUse};
use utils::{
    config::{Config, Rate, cron::SimpleCron, utils::ParseValue},
    map::bitmap::Bitmap,
};

#[derive(Default, Clone)]
pub struct JmapConfig {
    pub default_language: Language,
    pub query_max_results: usize,
    pub snippet_max_results: usize,

    pub changes_max_results: Option<usize>,
    pub changes_max_history: Option<usize>,
    pub share_notification_max_history: Option<Duration>,

    pub request_max_size: usize,
    pub request_max_calls: usize,
    pub request_max_concurrent: Option<u64>,

    pub get_max_objects: usize,
    pub set_max_objects: usize,

    pub upload_max_size: usize,
    pub upload_max_concurrent: Option<u64>,

    pub upload_tmp_quota_size: usize,
    pub upload_tmp_quota_amount: usize,
    pub upload_tmp_ttl: u64,

    pub mailbox_max_depth: usize,
    pub mailbox_name_max_len: usize,
    pub mail_attachments_max_size: usize,
    pub mail_parse_max_items: usize,
    pub mail_max_size: usize,
    pub mail_autoexpunge_after: Option<u64>,
    pub email_submission_autoexpunge_after: Option<u64>,

    pub contact_parse_max_items: usize,
    pub calendar_parse_max_items: usize,

    pub sieve_max_script_name: usize,
    pub max_objects: [u32; Collection::MAX],

    pub rate_authenticated: Option<Rate>,
    pub rate_anonymous: Option<Rate>,

    pub event_source_throttle: Duration,
    pub push_attempt_interval: Duration,
    pub push_attempts_max: u32,
    pub push_retry_interval: Duration,
    pub push_timeout: Duration,
    pub push_verify_timeout: Duration,
    pub push_throttle: Duration,

    pub web_socket_throttle: Duration,
    pub web_socket_timeout: Duration,
    pub web_socket_heartbeat: Duration,

    pub fallback_admin: Option<(String, String)>,
    pub master_user: Option<(String, String)>,

    pub default_folders: Vec<DefaultFolder>,
    pub shared_folder: String,

    pub http_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    pub http_use_forwarded: bool,

    pub encrypt: bool,
    pub encrypt_append: bool,

    pub index_batch_size: usize,
    pub index_fields: AHashMap<SearchIndex, AHashSet<SearchField>>,

    pub capabilities: BaseCapabilities,
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

impl JmapConfig {
    pub fn parse(config: &mut Config, groupware_config: &GroupwareConfig) -> Self {
        // Parse HTTP headers
        let mut http_headers = config
            .values("http.headers")
            .map(|(_, v)| {
                if let Some((k, v)) = v.split_once(':') {
                    Ok((
                        hyper::header::HeaderName::from_str(k.trim()).map_err(|err| {
                            format!("Invalid header found in property \"http.headers\": {}", err)
                        })?,
                        hyper::header::HeaderValue::from_str(v.trim()).map_err(|err| {
                            format!("Invalid header found in property \"http.headers\": {}", err)
                        })?,
                    ))
                } else {
                    Err(format!(
                        "Invalid header found in property \"http.headers\": {}",
                        v
                    ))
                }
            })
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| config.new_parse_error("http.headers", e))
            .unwrap_or_default();

        // Parse default folders
        let mut default_folders = Vec::new();
        let mut shared_folder = "Shared Folders".to_string();
        for key in config.sub_keys("email.folders", ".name") {
            match SpecialUse::parse_value(&key) {
                Ok(SpecialUse::Shared) => {
                    if let Some(value) = config.value(("email.folders", key.as_str(), "name")) {
                        shared_folder = value.to_string();
                    }
                }
                Ok(special_use) => {
                    let subscribe = config
                        .property_or_default(("email.folders", key.as_str(), "subscribe"), "true")
                        .unwrap_or(true);
                    let create = config
                        .property_or_default(("email.folders", key.as_str(), "create"), "true")
                        .unwrap_or(true)
                        | [SpecialUse::Inbox, SpecialUse::Trash, SpecialUse::Junk]
                            .contains(&special_use);
                    if let Some(name) = config
                        .value(("email.folders", key.as_str(), "name"))
                        .map(|name| name.trim())
                        .filter(|name| !name.is_empty())
                    {
                        default_folders.push(DefaultFolder {
                            name: name.to_string(),
                            aliases: config
                                .value(("email.folders", key.as_str(), "aliases"))
                                .unwrap_or_default()
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect(),
                            special_use,
                            subscribe,
                            create,
                        });
                    }
                }
                Err(err) => {
                    config.new_parse_error(key, err);
                }
            }
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

        // Add permissive CORS headers
        if config
            .property::<bool>("http.permissive-cors")
            .unwrap_or(false)
        {
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                hyper::header::HeaderValue::from_static("*"),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
                hyper::header::HeaderValue::from_static(
                    "Authorization, Content-Type, Accept, X-Requested-With",
                ),
            ));
            http_headers.push((
                hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
                hyper::header::HeaderValue::from_static(
                    "POST, GET, PATCH, PUT, DELETE, HEAD, OPTIONS",
                ),
            ));
        }

        // Add HTTP Strict Transport Security
        if config.property::<bool>("http.hsts").unwrap_or(false) {
            http_headers.push((
                hyper::header::STRICT_TRANSPORT_SECURITY,
                hyper::header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            ));
        }

        let mut jmap = JmapConfig {
            default_language: Language::from_iso_639(
                config
                    .value("storage.search-index.default-language")
                    .unwrap_or("en"),
            )
            .unwrap_or(Language::English),
            query_max_results: config
                .property("jmap.protocol.query.max-results")
                .unwrap_or(5000),
            changes_max_results: config
                .property_or_default::<Option<usize>>("jmap.protocol.changes.max-results", "5000")
                .unwrap_or_default(),
            changes_max_history: config
                .property_or_default::<Option<usize>>("changes.max-history", "10000")
                .unwrap_or_default(),
            share_notification_max_history: config
                .property_or_default::<Option<Duration>>("sharing.max-history", "30d")
                .unwrap_or_default(),
            snippet_max_results: config
                .property("jmap.protocol.search-snippet.max-results")
                .unwrap_or(100),
            request_max_size: config
                .property("jmap.protocol.request.max-size")
                .unwrap_or(10000000),
            request_max_calls: config
                .property("jmap.protocol.request.max-calls")
                .unwrap_or(16),
            request_max_concurrent: config
                .property_or_default::<Option<u64>>("jmap.protocol.request.max-concurrent", "4")
                .unwrap_or(Some(4)),
            get_max_objects: config
                .property("jmap.protocol.get.max-objects")
                .unwrap_or(500),
            set_max_objects: config
                .property("jmap.protocol.set.max-objects")
                .unwrap_or(500),
            upload_max_size: config
                .property("jmap.protocol.upload.max-size")
                .unwrap_or(50000000),
            upload_max_concurrent: config
                .property_or_default::<Option<u64>>("jmap.protocol.upload.max-concurrent", "4")
                .unwrap_or(Some(4)),
            upload_tmp_quota_size: config
                .property("jmap.protocol.upload.quota.size")
                .unwrap_or(50000000),
            upload_tmp_quota_amount: config
                .property("jmap.protocol.upload.quota.files")
                .unwrap_or(1000),
            upload_tmp_ttl: config
                .property_or_default::<Duration>("jmap.protocol.upload.ttl", "1h")
                .unwrap_or_else(|| Duration::from_secs(3600))
                .as_secs(),
            mailbox_max_depth: config.property("jmap.mailbox.max-depth").unwrap_or(10),
            mailbox_name_max_len: config
                .property("jmap.mailbox.max-name-length")
                .unwrap_or(255),
            mail_attachments_max_size: config
                .property("jmap.email.max-attachment-size")
                .unwrap_or(50000000),
            mail_max_size: config.property("jmap.email.max-size").unwrap_or(75000000),
            mail_parse_max_items: config.property("jmap.email.parse.max-items").unwrap_or(10),
            mail_autoexpunge_after: config
                .property_or_default::<Option<Duration>>("email.auto-expunge", "30d")
                .map(|d| d.map(|d| d.as_secs()))
                .unwrap_or_default(),
            email_submission_autoexpunge_after: config
                .property_or_default::<Option<Duration>>("email-submission.auto-expunge", "3d")
                .map(|d| d.map(|d| d.as_secs()))
                .unwrap_or_default(),
            sieve_max_script_name: config
                .property("sieve.untrusted.limits.name-length")
                .unwrap_or(512),
            max_objects: [u32::MAX; Collection::MAX],
            capabilities: BaseCapabilities::default(),
            rate_authenticated: config
                .property_or_default::<Option<Rate>>("http.rate-limit.account", "1000/1m")
                .unwrap_or_default(),
            rate_anonymous: config
                .property_or_default::<Option<Rate>>("http.rate-limit.anonymous", "100/1m")
                .unwrap_or_default(),
            event_source_throttle: config
                .property_or_default("jmap.event-source.throttle", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            web_socket_throttle: config
                .property_or_default("jmap.web-socket.throttle", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            web_socket_timeout: config
                .property_or_default("jmap.web-socket.timeout", "10m")
                .unwrap_or_else(|| Duration::from_secs(10 * 60)),
            web_socket_heartbeat: config
                .property_or_default("jmap.web-socket.heartbeat", "1m")
                .unwrap_or_else(|| Duration::from_secs(60)),
            encrypt: config
                .property_or_default("email.encryption.enable", "true")
                .unwrap_or(true),
            encrypt_append: config
                .property_or_default("email.encryption.append", "false")
                .unwrap_or(false),
            http_use_forwarded: config.property("http.use-x-forwarded").unwrap_or(false),
            http_headers,
            push_attempt_interval: config
                .property_or_default("jmap.push.attempts.interval", "1m")
                .unwrap_or_else(|| Duration::from_secs(60)),
            push_attempts_max: config
                .property_or_default("jmap.push.attempts.max", "3")
                .unwrap_or(3),
            push_retry_interval: config
                .property_or_default("jmap.push.retry.interval", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            push_timeout: config
                .property_or_default("jmap.push.timeout.request", "10s")
                .unwrap_or_else(|| Duration::from_secs(10)),
            push_verify_timeout: config
                .property_or_default("jmap.push.timeout.verify", "1m")
                .unwrap_or_else(|| Duration::from_secs(60)),
            push_throttle: config
                .property_or_default("jmap.push.throttle", "1s")
                .unwrap_or_else(|| Duration::from_secs(1)),
            account_purge_frequency: config
                .property_or_default::<SimpleCron>("account.purge.frequency", "0 0 *")
                .unwrap_or_else(|| SimpleCron::parse_value("0 0 *").unwrap()),
            fallback_admin: config
                .value("authentication.fallback-admin.user")
                .and_then(|u| {
                    config
                        .value("authentication.fallback-admin.secret")
                        .map(|p| (u.to_string(), p.to_string()))
                }),
            master_user: config.value("authentication.master.user").and_then(|u| {
                config
                    .value("authentication.master.secret")
                    .map(|p| (u.to_string(), p.to_string()))
            }),
            contact_parse_max_items: config
                .property("jmap.contact.parse.max-items")
                .unwrap_or(10),
            calendar_parse_max_items: config
                .property("jmap.calendar.parse.max-items")
                .unwrap_or(10),
            index_batch_size: config
                .property("storage.search-index.batch-size")
                .unwrap_or(100),
            index_fields: AHashMap::new(),
            default_folders,
            shared_folder,
        };

        // Parse index fields
        for index in [
            SearchIndex::Email,
            SearchIndex::Contacts,
            SearchIndex::Calendar,
            SearchIndex::Tracing,
        ] {
            let mut fields = AHashSet::new();
            let index_name = match index {
                SearchIndex::Email => "email",
                SearchIndex::Contacts => "contacts",
                SearchIndex::Calendar => "calendar",
                SearchIndex::Tracing => "tracing",
                _ => unreachable!(),
            };

            if !config
                .property_or_default::<bool>(
                    &format!("storage.search-index.{index_name}.enabled"),
                    "true",
                )
                .unwrap_or(true)
            {
                continue;
            }

            for (_, field) in config
                .properties::<SearchField>(&format!("storage.search-index.{index_name}.fields"))
            {
                fields.insert(field);
            }
            jmap.index_fields.insert(index, fields);
        }

        for collection in Bitmap::<Collection>::all() {
            let key = format!("object-quota.{}", collection.as_config_case());
            jmap.max_objects[collection as usize] =
                if let Some(value) = config.property::<u32>(&key) {
                    value
                } else {
                    match collection {
                        Collection::Mailbox => 250,
                        Collection::SieveScript => 100,
                        Collection::Identity => 20,
                        Collection::EmailSubmission => 500,
                        Collection::PushSubscription => 15,
                        Collection::Calendar => 250,
                        Collection::AddressBook => 250,
                        Collection::Principal
                        | Collection::None
                        | Collection::CalendarEventNotification
                        | Collection::CalendarEvent
                        | Collection::ContactCard
                        | Collection::FileNode
                        | Collection::Email
                        | Collection::Thread => u32::MAX,
                    }
                };
        }

        // Add capabilities
        jmap.add_capabilities(config, groupware_config);
        jmap
    }
}
