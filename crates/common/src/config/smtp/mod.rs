/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::{Config, Rate};

pub mod auth;
pub mod queue;
pub mod report;
pub mod resolver;
pub mod session;
pub mod throttle;

use crate::expr::{Expression, tokenizer::TokenMap};

use self::{
    auth::MailAuthConfig, queue::QueueConfig, report::ReportConfig, resolver::Resolvers,
    session::SessionConfig,
};

use super::*;

#[derive(Default, Clone)]
pub struct SmtpConfig {
    pub session: SessionConfig,
    pub queue: QueueConfig,
    pub resolvers: Resolvers,
    pub mail_auth: MailAuthConfig,
    pub report: ReportConfig,
}

#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct QueueRateLimiter {
    pub id: String,
    pub expr: Expression,
    pub keys: u16,
    pub rate: Rate,
}

pub const THROTTLE_RCPT: u16 = 1 << 0;
pub const THROTTLE_RCPT_DOMAIN: u16 = 1 << 1;
pub const THROTTLE_SENDER: u16 = 1 << 2;
pub const THROTTLE_SENDER_DOMAIN: u16 = 1 << 3;
pub const THROTTLE_AUTH_AS: u16 = 1 << 4;
pub const THROTTLE_LISTENER: u16 = 1 << 5;
pub const THROTTLE_MX: u16 = 1 << 6;
pub const THROTTLE_REMOTE_IP: u16 = 1 << 7;
pub const THROTTLE_LOCAL_IP: u16 = 1 << 8;
pub const THROTTLE_HELO_DOMAIN: u16 = 1 << 9;

impl SmtpConfig {
    pub async fn parse(bp: &mut Bootstrap) -> Self {
        Self {
            session: SessionConfig::parse(config),
            queue: QueueConfig::parse(config),
            resolvers: Resolvers::parse(config).await,
            mail_auth: MailAuthConfig::parse(config),
            report: ReportConfig::parse(config),
        }
    }
}
