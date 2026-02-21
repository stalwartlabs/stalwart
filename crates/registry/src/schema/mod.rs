/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    pickle::Pickle,
    schema::{
        enums::{TracingLevel, TracingLevelOpt},
        prelude::{
            Account, Duration, GroupAccount, HashedObject, HttpAuth, NodeRange, Object,
            ObjectInner, ObjectType, Property, UserAccount,
        },
    },
    types::{EnumImpl, ObjectImpl},
};
use std::{cmp::Ordering, fmt::Display};
use trc::TOTAL_EVENT_COUNT;
use utils::{
    Client, HeaderMap,
    cron::SimpleCron,
    http::{build_http_client, build_http_headers},
    map::vec_map::VecMap,
};

#[allow(clippy::derivable_impls)]
pub mod enums;
pub mod enums_impl;
pub mod prelude;
pub mod properties;
pub mod properties_impl;
#[allow(clippy::large_enum_variant)]
pub mod structs;
#[allow(clippy::needless_borrows_for_generic_args)]
#[allow(clippy::len_zero)]
#[allow(clippy::collapsible_if)]
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

    pub fn into_group(self) -> Option<GroupAccount> {
        if let Account::Group(group) = self {
            Some(group)
        } else {
            None
        }
    }
}

impl HttpAuth {
    pub fn build_headers(
        &self,
        extra_headers: VecMap<String, String>,
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
        extra_headers: VecMap<String, String>,
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

impl EnumImpl for trc::EventType {
    const COUNT: usize = TOTAL_EVENT_COUNT;

    fn parse(s: &str) -> Option<Self> {
        trc::EventType::parse(s)
    }

    fn as_str(&self) -> &'static str {
        trc::EventType::as_str(self)
    }

    fn from_id(id: u16) -> Option<Self> {
        trc::EventType::from_id(id)
    }

    fn to_id(&self) -> u16 {
        trc::EventType::to_id(self)
    }
}

impl EnumImpl for trc::MetricType {
    const COUNT: usize = TOTAL_EVENT_COUNT;

    fn parse(s: &str) -> Option<Self> {
        trc::MetricType::parse(s)
    }

    fn as_str(&self) -> &'static str {
        trc::MetricType::as_str(self)
    }

    fn from_id(id: u16) -> Option<Self> {
        trc::MetricType::from_id(id)
    }

    fn to_id(&self) -> u16 {
        trc::MetricType::to_id(self)
    }
}

impl PartialOrd for Property {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Property {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_id().cmp(&other.to_id())
    }
}

impl<T: Into<ObjectInner>> From<T> for Object {
    fn from(value: T) -> Self {
        Object {
            inner: value.into(),
            revision: 0,
        }
    }
}

impl<T: ObjectImpl + From<Object>> From<Object> for HashedObject<T> {
    fn from(value: Object) -> Self {
        HashedObject {
            revision: value.revision,
            object: T::from(value),
        }
    }
}

impl<T: ObjectImpl> ObjectImpl for HashedObject<T> {
    const FLAGS: u64 = T::FLAGS;
    const OBJECT: ObjectType = T::OBJECT;

    fn validate(&self, errors: &mut Vec<prelude::ValidationError>) -> bool {
        self.object.validate(errors)
    }

    fn index<'x>(&'x self, builder: &mut prelude::IndexBuilder<'x>) {
        self.object.index(builder)
    }
}

impl<T: ObjectImpl> Pickle for HashedObject<T> {
    fn pickle(&self, out: &mut Vec<u8>) {
        T::OBJECT.pickle(out);
        self.object.pickle(out);
        (xxhash_rust::xxh3::xxh3_64(out) as u32).pickle(out);
    }

    fn unpickle(stream: &mut crate::pickle::PickledStream<'_>) -> Option<Self> {
        let _ = u16::unpickle(stream)?;
        Some(Self {
            object: T::unpickle(stream)?,
            revision: u32::unpickle(stream)?,
        })
    }
}

impl<'de, T: ObjectImpl> serde::Deserialize<'de> for HashedObject<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|object| Self {
            object,
            revision: 0,
        })
    }
}
