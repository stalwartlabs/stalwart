/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::ipc::{
    BroadcastEvent, CacheInvalidation, CalendarAlert, PushNotification, RegistryChange,
};
use registry::{
    schema::prelude::ObjectType,
    types::{EnumImpl, id::ObjectId},
};
use std::{borrow::Borrow, io::Write};
use types::{id::Id, type_state::StateChange};
use utils::{
    codec::leb128::{Leb128Iterator, Leb128Writer},
    map::bitmap::Bitmap,
};

pub mod publisher;
pub mod subscriber;

#[derive(Debug)]
pub(crate) struct BroadcastBatch<T> {
    messages: T,
}

const MAX_BATCH_SIZE: usize = 100;
pub(crate) const BROADCAST_TOPIC: &str = "stwt.agora";

impl BroadcastBatch<Vec<BroadcastEvent>> {
    pub fn init() -> Self {
        Self {
            messages: Vec::with_capacity(MAX_BATCH_SIZE),
        }
    }

    pub fn insert(&mut self, message: BroadcastEvent) -> bool {
        self.messages.push(message);
        self.messages.len() < MAX_BATCH_SIZE
    }

    pub fn serialize(&self, node_id: u16) -> Vec<u8> {
        let mut serialized =
            Vec::with_capacity((self.messages.len() * 10) + std::mem::size_of::<u16>());
        let _ = serialized.write_leb128(node_id);
        for message in &self.messages {
            match message {
                BroadcastEvent::PushNotification(notification) => match notification {
                    PushNotification::StateChange(state_change) => {
                        serialized.push(0u8);
                        let _ = serialized.write_leb128(state_change.change_id);
                        let _ = serialized.write_leb128(*state_change.types.as_ref());
                        let _ = serialized.write_leb128(state_change.account_id);
                    }
                    PushNotification::CalendarAlert(calendar_alert) => {
                        serialized.push(1u8);
                        let _ = serialized.write_leb128(calendar_alert.account_id);
                        let _ = serialized.write_leb128(calendar_alert.event_id);
                        let _ = serialized
                            .write_leb128(calendar_alert.recurrence_id.unwrap_or_default() as u64);
                        let _ = serialized.write_leb128(calendar_alert.uid.len());
                        let _ = serialized.write(calendar_alert.uid.as_bytes());
                        let _ = serialized.write_leb128(calendar_alert.alert_id.len());
                        let _ = serialized.write(calendar_alert.alert_id.as_bytes());
                    }
                    PushNotification::EmailPush(email_push) => {
                        serialized.push(2u8);
                        let _ = serialized.write_leb128(email_push.account_id);
                        let _ = serialized.write_leb128(email_push.email_id);
                        let _ = serialized.write_leb128(email_push.change_id);
                    }
                },
                BroadcastEvent::PushServerUpdate(account_id) => {
                    serialized.push(3u8);
                    let _ = serialized.write_leb128(*account_id);
                }
                BroadcastEvent::RegistryChange(items) => match items {
                    RegistryChange::Insert(id) => {
                        serialized.push(4u8);
                        let _ = serialized.write_leb128(id.object().to_id());
                        let _ = serialized.write_leb128(id.id().id());
                    }
                    RegistryChange::Delete(id) => {
                        serialized.push(5u8);
                        let _ = serialized.write_leb128(id.object().to_id());
                        let _ = serialized.write_leb128(id.id().id());
                    }
                    RegistryChange::Reload(object) => {
                        serialized.push(6u8);
                        let _ = serialized.write_leb128(object.to_id());
                    }
                },
                BroadcastEvent::CacheInvalidation(items) => {
                    serialized.push(7u8);
                    let _ = serialized.write_leb128(items.len());
                    for item in items {
                        let (marker, id) = match item {
                            CacheInvalidation::AccessToken(id) => (0u8, *id),
                            CacheInvalidation::DavResources(id) => (1u8, *id),
                            CacheInvalidation::Domain(id) => (2u8, *id),
                            CacheInvalidation::Account(id) => (3u8, *id),
                            CacheInvalidation::DkimSignature(id) => (4u8, *id),
                            CacheInvalidation::Tenant(id) => (5u8, *id),
                            CacheInvalidation::Role(id) => (6u8, *id),
                            CacheInvalidation::List(id) => (7u8, *id),
                        };

                        serialized.push(marker);
                        let _ = serialized.write_leb128(id);
                    }
                }
            }
        }
        serialized
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl<T, I> BroadcastBatch<T>
where
    T: Iterator<Item = I> + Leb128Iterator<I>,
    I: Borrow<u8>,
{
    pub fn node_id(&mut self) -> Option<u16> {
        self.messages.next_leb128::<u16>()
    }

    pub fn next_event(&mut self) -> Result<Option<BroadcastEvent>, ()> {
        if let Some(id) = self.messages.next() {
            match id.borrow() {
                0 => Ok(Some(BroadcastEvent::PushNotification(
                    PushNotification::StateChange(StateChange {
                        change_id: self.messages.next_leb128().ok_or(())?,
                        types: Bitmap::from(self.messages.next_leb128::<u64>().ok_or(())?),
                        account_id: self.messages.next_leb128().ok_or(())?,
                    }),
                ))),

                1 => {
                    let account_id = self.messages.next_leb128().ok_or(())?;
                    let event_id = self.messages.next_leb128().ok_or(())?;
                    let recurrence_id = self.messages.next_leb128::<u64>().ok_or(())? as i64;
                    let uid_len = self.messages.next_leb128::<usize>().ok_or(())?;
                    let mut uid_bytes = vec![0u8; uid_len];
                    for byte in uid_bytes.iter_mut() {
                        *byte = self.messages.next().ok_or(())?.borrow().to_owned();
                    }
                    let uid = String::from_utf8(uid_bytes).map_err(|_| ())?;
                    let alert_id_len = self.messages.next_leb128::<usize>().ok_or(())?;
                    let mut alert_id_bytes = vec![0u8; alert_id_len];
                    for byte in alert_id_bytes.iter_mut() {
                        *byte = self.messages.next().ok_or(())?.borrow().to_owned();
                    }
                    let alert_id = String::from_utf8(alert_id_bytes).map_err(|_| ())?;
                    Ok(Some(BroadcastEvent::PushNotification(
                        PushNotification::CalendarAlert(CalendarAlert {
                            account_id,
                            event_id,
                            recurrence_id: if recurrence_id == 0 {
                                None
                            } else {
                                Some(recurrence_id)
                            },
                            uid,
                            alert_id,
                        }),
                    )))
                }
                3 => {
                    let account_id = self.messages.next_leb128().ok_or(())?;
                    Ok(Some(BroadcastEvent::PushServerUpdate(account_id)))
                }
                4 => {
                    let object_id = self.messages.next_leb128().ok_or(())?;
                    let id = self.messages.next_leb128::<u64>().ok_or(())?;
                    Ok(Some(BroadcastEvent::RegistryChange(
                        RegistryChange::Insert(ObjectId::new(
                            ObjectType::from_id(object_id).ok_or(())?,
                            Id::new(id),
                        )),
                    )))
                }
                5 => {
                    let object_id = self.messages.next_leb128().ok_or(())?;
                    let id = self.messages.next_leb128::<u64>().ok_or(())?;
                    Ok(Some(BroadcastEvent::RegistryChange(
                        RegistryChange::Delete(ObjectId::new(
                            ObjectType::from_id(object_id).ok_or(())?,
                            Id::new(id),
                        )),
                    )))
                }
                6 => {
                    let object_id = self.messages.next_leb128().ok_or(())?;
                    Ok(Some(BroadcastEvent::RegistryChange(
                        RegistryChange::Reload(ObjectType::from_id(object_id).ok_or(())?),
                    )))
                }
                7 => {
                    let count = self.messages.next_leb128::<usize>().ok_or(())?;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        let marker = self.messages.next().ok_or(())?.borrow().to_owned();
                        let id = self.messages.next_leb128::<u32>().ok_or(())?;
                        items.push(match marker {
                            0 => CacheInvalidation::AccessToken(id),
                            1 => CacheInvalidation::DavResources(id),
                            2 => CacheInvalidation::Domain(id),
                            3 => CacheInvalidation::Account(id),
                            4 => CacheInvalidation::DkimSignature(id),
                            5 => CacheInvalidation::Tenant(id),
                            6 => CacheInvalidation::Role(id),
                            7 => CacheInvalidation::List(id),
                            _ => return Err(()),
                        });
                    }
                    Ok(Some(BroadcastEvent::CacheInvalidation(items)))
                }

                _ => Err(()),
            }
        } else {
            Ok(None)
        }
    }
}

impl<T> BroadcastBatch<T> {
    pub fn new(messages: T) -> Self {
        Self { messages }
    }
}
