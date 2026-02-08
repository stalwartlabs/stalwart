/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    schema::{
        enums::{TracingLevel, TracingLevelOpt},
        prelude::{Account, Duration, HttpAuth, NodeRange, Property, UserAccount},
    },
    types::EnumType,
};
use std::{collections::HashMap, fmt::Display};
use utils::{
    Client, HeaderMap,
    cron::SimpleCron,
    http::{build_http_client, build_http_headers},
};

#[allow(clippy::derivable_impls)]
pub mod enums;
pub mod enums_impl;
pub mod prelude;
pub mod properties;
pub mod properties_impl;
#[allow(clippy::large_enum_variant)]
pub mod structs;
#[allow(clippy::derivable_impls)]
pub mod structs_impl;

impl From<prelude::Cron> for SimpleCron {
    fn from(value: prelude::Cron) -> Self {
        match value {
            prelude::Cron::Daily(cron) => SimpleCron::Day {
                hour: cron.hour as u32,
                minute: cron.minute as u32,
            },
            prelude::Cron::Weekly(cron) => SimpleCron::Week {
                day: cron.day as u32,
                hour: cron.hour as u32,
                minute: cron.minute as u32,
            },
            prelude::Cron::Hourly(cron) => SimpleCron::Hour {
                minute: cron.minute as u32,
            },
        }
    }
}

impl NodeRange {
    pub fn contains(&self, node_id: u64) -> bool {
        node_id >= self.from_node_id && node_id <= self.to_node_id
    }
}

impl Account {
    pub fn into_user(self) -> Option<UserAccount> {
        if let Account::User(user) = self {
            Some(user)
        } else {
            None
        }
    }
}

impl HttpAuth {
    pub fn build_headers(
        &self,
        extra_headers: HashMap<String, String>,
        content_type: Option<&str>,
    ) -> Result<HeaderMap, String> {
        match self {
            HttpAuth::Unauthenticated => {
                build_http_headers(extra_headers, None, None, None, content_type)
            }
            HttpAuth::Basic(auth) => build_http_headers(
                extra_headers,
                auth.username.as_str().into(),
                auth.secret.as_str().into(),
                None,
                content_type,
            ),
            HttpAuth::Bearer(auth) => build_http_headers(
                extra_headers,
                None,
                None,
                auth.bearer_token.as_str().into(),
                content_type,
            ),
        }
    }

    pub fn build_http_client(
        &self,
        extra_headers: HashMap<String, String>,
        content_type: Option<&str>,
        timeout: Duration,
        allow_invalid_certs: bool,
    ) -> Result<Client, String> {
        match self {
            HttpAuth::Unauthenticated => build_http_client(
                extra_headers,
                None,
                None,
                None,
                content_type,
                timeout.into_inner(),
                allow_invalid_certs,
            ),
            HttpAuth::Basic(auth) => build_http_client(
                extra_headers,
                auth.username.as_str().into(),
                auth.secret.as_str().into(),
                None,
                content_type,
                timeout.into_inner(),
                allow_invalid_certs,
            ),
            HttpAuth::Bearer(auth) => build_http_client(
                extra_headers,
                None,
                None,
                auth.bearer_token.as_str().into(),
                content_type,
                timeout.into_inner(),
                allow_invalid_certs,
            ),
        }
    }
}

impl Display for Property {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<TracingLevelOpt> for trc::Level {
    fn from(level: TracingLevelOpt) -> Self {
        match level {
            TracingLevelOpt::Error => trc::Level::Error,
            TracingLevelOpt::Warn => trc::Level::Warn,
            TracingLevelOpt::Info => trc::Level::Info,
            TracingLevelOpt::Debug => trc::Level::Debug,
            TracingLevelOpt::Trace => trc::Level::Trace,
            TracingLevelOpt::Disable => trc::Level::Disable,
        }
    }
}

impl From<TracingLevel> for trc::Level {
    fn from(level: TracingLevel) -> Self {
        match level {
            TracingLevel::Error => trc::Level::Error,
            TracingLevel::Warn => trc::Level::Warn,
            TracingLevel::Info => trc::Level::Info,
            TracingLevel::Debug => trc::Level::Debug,
            TracingLevel::Trace => trc::Level::Trace,
        }
    }
}
