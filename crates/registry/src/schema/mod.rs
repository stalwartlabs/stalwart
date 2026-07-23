/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    schema::{
        enums::{TracingLevel, TracingLevelOpt},
        prelude::{Object, ObjectInner, Property},
    },
    types::EnumImpl,
};
use std::{cmp::Ordering, fmt::Display};
use trc::TOTAL_EVENT_COUNT;

#[allow(clippy::derivable_impls)]
pub mod enums;
pub mod enums_impl;
pub mod prelude;
#[allow(clippy::large_enum_variant)]
pub mod properties;
pub mod properties_impl;
#[allow(clippy::large_enum_variant)]
pub mod structs;
#[allow(clippy::needless_borrows_for_generic_args)]
#[allow(clippy::len_zero)]
#[allow(clippy::collapsible_if)]
#[allow(clippy::derivable_impls)]
#[allow(clippy::field_reassign_with_default)]
pub mod structs_impl;

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

impl Object {
    pub fn new(inner: ObjectInner) -> Self {
        Object { inner, revision: 0 }
    }

    pub fn with_revision(inner: ObjectInner, revision: u64) -> Self {
        Object { inner, revision }
    }
}

impl From<Property> for String {
    fn from(value: Property) -> Self {
        value.as_str().to_string()
    }
}
