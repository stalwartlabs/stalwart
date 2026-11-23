/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]
#![recursion_limit = "256"]

use jmap_proto::object::JmapObjectId;
use jmap_tools::{Element, Property, Value};
use std::str::FromStr;
use types::id::Id;

pub(crate) fn matches_id<P: Property, E: Element + JmapObjectId>(
    value: &Value<'_, P, E>,
    id: Id,
) -> bool {
    match value {
        Value::Element(element) => element.as_id() == Some(id),
        Value::Str(value) => Id::from_str(value.as_ref()).is_ok_and(|value| value == id),
        _ => false,
    }
}

pub(crate) fn generate_uid() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

pub mod addressbook;
pub mod api;
pub mod blob;
pub mod calendar;
pub mod calendar_event;
pub mod calendar_event_notification;
pub mod changes;
pub mod contact;
pub mod email;
pub mod file;
pub mod identity;
pub mod mailbox;
pub mod mdn;
pub mod participant_identity;
pub mod principal;
pub mod push;
pub mod quota;
pub mod registry;
pub mod share_notification;
pub mod sieve;
pub mod submission;
pub mod thread;
pub mod vacation;
pub mod websocket;
