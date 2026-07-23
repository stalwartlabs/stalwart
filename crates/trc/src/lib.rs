/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

pub mod atomics;
pub mod event;
pub mod ipc;
pub mod macros;
pub mod serializers;

pub use crate::event::enums::*;
pub use crate::ipc::collector::Collector;
use compact_str::CompactString;
pub use event_macro::event;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Error(Box<Event<EventType>>);

#[derive(Debug, Clone)]
pub struct Event<T> {
    pub inner: T,
    pub keys: Vec<(Key, Value)>,
}

#[derive(Debug, Clone)]
pub struct EventDetails {
    pub typ: EventType,
    pub timestamp: u64,
    pub level: Level,
    pub span: Option<Arc<Event<EventDetails>>>,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
#[repr(usize)]
pub enum Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Disable = 5,
}

#[derive(Debug, Default, Clone)]
pub enum Value {
    String(CompactString),
    UInt(u64),
    Int(i64),
    Float(f64),
    Timestamp(u64),
    Duration(u64),
    Bytes(Vec<u8>),
    Bool(bool),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Event(Error),
    Array(Vec<Value>),
    #[default]
    None,
}

pub trait AddContext<T> {
    fn caused_by(self, location: &'static str) -> Result<T>;
    fn add_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce(Error) -> Error;
}

#[allow(clippy::derivable_impls)]
impl Default for MetricType {
    fn default() -> Self {
        MetricType::UserCount
    }
}

impl Default for EventType {
    fn default() -> Self {
        EventType::Store(StoreEvent::UnexpectedError)
    }
}
