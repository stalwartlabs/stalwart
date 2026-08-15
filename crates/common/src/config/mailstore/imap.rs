/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use registry::schema::structs::{Imap, Rate};
use std::time::Duration;
use store::registry::bootstrap::Bootstrap;

#[derive(Default, Clone)]
pub struct ImapConfig {
    pub max_request_size: usize,
    pub max_auth_failures: u32,
    pub allow_plain_auth: bool,

    pub timeout_auth: Duration,
    pub timeout_unauth: Duration,
    pub timeout_idle: Duration,

    pub rate_requests: Option<Rate>,
    pub rate_concurrent: Option<u64>,

    pub max_messages_per_command: u32,
    pub max_messages_per_save: u32,
    pub min_uid_batch_size: u32,
    pub max_uid_batches: u32,
}

impl ImapConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        let imap = bp.setting_infallible::<Imap>().await;

        ImapConfig {
            max_request_size: imap.max_request_size as usize,
            max_auth_failures: imap.max_auth_failures as u32,
            timeout_auth: imap.timeout_authenticated.into_inner(),
            timeout_unauth: imap.timeout_anonymous.into_inner(),
            timeout_idle: imap.timeout_idle.into_inner(),
            rate_requests: imap.max_request_rate,
            rate_concurrent: imap.max_concurrent,
            allow_plain_auth: imap.allow_plain_text_auth,
            max_messages_per_command: imap.max_messages_per_command.min(u32::MAX as u64) as u32,
            max_messages_per_save: imap.max_messages_per_save.min(u32::MAX as u64) as u32,
            min_uid_batch_size: imap.min_uid_batch_size.min(u32::MAX as u64) as u32,
            max_uid_batches: imap.max_uid_batches.min(u32::MAX as u64) as u32,
        }
    }
}
