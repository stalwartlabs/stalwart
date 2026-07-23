/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::network::webpush::{Vapid, VapidKey};
use jmap_proto::request::capability::BaseCapabilities;
use registry::schema::{prelude::ObjectType, structs::Jmap};
use std::{sync::Arc, time::Duration};
use store::registry::bootstrap::Bootstrap;

#[derive(Default, Clone)]
pub struct JmapConfig {
    pub query_max_results: usize,
    pub snippet_max_results: usize,
    pub changes_max_results: usize,

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

    pub mail_parse_max_items: usize,
    pub contact_parse_max_items: usize,
    pub calendar_parse_max_items: usize,

    pub event_source_throttle: Duration,
    pub push_attempt_interval: Duration,
    pub push_attempts_max: u32,
    pub push_retry_interval: Duration,
    pub push_timeout: Duration,
    pub push_verify_timeout: Duration,
    pub push_throttle: Duration,
    pub push_total_shards: u32,

    pub web_socket_throttle: Duration,
    pub web_socket_timeout: Duration,
    pub web_socket_heartbeat: Duration,

    pub vapid: Option<Arc<Vapid>>,

    pub capabilities: BaseCapabilities,
}

impl JmapConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let jmap = bp.setting_infallible::<Jmap>().await;
        let web_push_key = jmap
            .web_push_key
            .secret()
            .await
            .map_err(|err| {
                bp.build_error(
                    ObjectType::Jmap.singleton(),
                    format!("Unable to retrieve Web Push key: {err}"),
                );
            })
            .unwrap_or_default()
            .map(|k| k.into_owned());
        let web_push_contact = jmap.web_push_contact;

        let mut jmap = JmapConfig {
            query_max_results: jmap.query_max_results as usize,
            changes_max_results: jmap.changes_max_results as usize,
            snippet_max_results: jmap.snippet_max_results as usize,
            request_max_size: jmap.max_request_size as usize,
            request_max_calls: jmap.max_method_calls as usize,
            request_max_concurrent: jmap.max_concurrent_requests,
            get_max_objects: jmap.get_max_results as usize,
            set_max_objects: jmap.set_max_objects as usize,
            upload_max_size: jmap.max_upload_size as usize,
            upload_max_concurrent: jmap.max_concurrent_uploads,
            upload_tmp_quota_size: jmap.upload_quota as usize,
            upload_tmp_quota_amount: jmap.max_upload_count as usize,
            upload_tmp_ttl: jmap.upload_ttl.into_inner().as_secs(),
            mail_parse_max_items: jmap.parse_limit_email as usize,
            contact_parse_max_items: jmap.parse_limit_contact as usize,
            calendar_parse_max_items: jmap.parse_limit_event as usize,
            event_source_throttle: jmap.event_source_throttle.into_inner(),
            web_socket_throttle: jmap.websocket_throttle.into_inner(),
            web_socket_timeout: jmap.websocket_timeout.into_inner(),
            web_socket_heartbeat: jmap.websocket_heartbeat.into_inner(),
            push_attempt_interval: jmap.push_attempt_wait.into_inner(),
            push_attempts_max: jmap.push_max_attempts as u32,
            push_retry_interval: jmap.push_retry_wait.into_inner(),
            push_timeout: jmap.push_request_timeout.into_inner(),
            push_verify_timeout: jmap.push_verify_timeout.into_inner(),
            push_throttle: jmap.push_throttle.into_inner(),
            push_total_shards: jmap.push_shards_total as u32,
            vapid: None,
            capabilities: BaseCapabilities::default(),
        };

        // Enable Web Push VAPID only when a signing key is configured
        jmap.vapid = web_push_key
            .as_deref()
            .map(str::trim)
            .filter(|pem| !pem.is_empty())
            .and_then(|pem| match VapidKey::from_pkcs8_pem(pem) {
                Ok(key) => Some(key),
                Err(err) => {
                    bp.build_error(
                        ObjectType::Jmap.singleton(),
                        format!("Invalid Web Push VAPID key: {err}"),
                    );
                    None
                }
            })
            .map(|key| {
                let contact = web_push_contact.or_else(|| {
                    let hostname = bp.registry.local_hostname();
                    (!hostname.is_empty()).then(|| format!("mailto:postmaster@{hostname}"))
                });
                Arc::new(Vapid::new(key, contact))
            });

        // Add capabilities
        jmap.add_capabilities(bp).await;
        jmap
    }
}
