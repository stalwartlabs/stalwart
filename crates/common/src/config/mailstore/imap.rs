/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::manager::bootstrap::Bootstrap;
use registry::schema::structs::{Imap, Rate};
use std::time::Duration;

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
        }
    }
}
