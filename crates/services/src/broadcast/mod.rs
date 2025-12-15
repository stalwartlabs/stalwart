/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::ipc::{BroadcastEvent, CalendarAlert, EmailPush, PushNotification};
use std::{borrow::Borrow, io::Write};
use types::type_state::StateChange;
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
                BroadcastEvent::InvalidateAccessTokens(items) => {
                    serialized.push(3u8);
                    let _ = serialized.write_leb128(items.len());
                    for item in items {
                        let _ = serialized.write_leb128(*item);
                    }
                }
                BroadcastEvent::InvalidateGroupwareCache(items) => {
                    serialized.push(4u8);
                    let _ = serialized.write_leb128(items.len());
                    for item in items {
                        let _ = serialized.write_leb128(*item);
                    }
                }
                BroadcastEvent::ReloadSettings => {
                    serialized.push(5u8);
                }
                BroadcastEvent::ReloadBlockedIps => {
                    serialized.push(6u8);
                }
                BroadcastEvent::ReloadPushServers(account_id) => {
                    serialized.push(7u8);
                    let _ = serialized.write_leb128(*account_id);
                }
                BroadcastEvent::ReloadSpamFilter => {
                    serialized.push(8u8);
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

                2 => Ok(Some(BroadcastEvent::PushNotification(
                    PushNotification::EmailPush(EmailPush {
                        account_id: self.messages.next_leb128().ok_or(())?,
                        email_id: self.messages.next_leb128().ok_or(())?,
                        change_id: self.messages.next_leb128().ok_or(())?,
                    }),
                ))),

                3 => {
                    let count = self.messages.next_leb128::<usize>().ok_or(())?;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        items.push(self.messages.next_leb128().ok_or(())?);
                    }
                    Ok(Some(BroadcastEvent::InvalidateAccessTokens(items)))
                }

                4 => {
                    let count = self.messages.next_leb128::<usize>().ok_or(())?;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        items.push(self.messages.next_leb128().ok_or(())?);
                    }
                    Ok(Some(BroadcastEvent::InvalidateGroupwareCache(items)))
                }

                5 => Ok(Some(BroadcastEvent::ReloadSettings)),

                6 => Ok(Some(BroadcastEvent::ReloadBlockedIps)),

                7 => {
                    let account_id = self.messages.next_leb128().ok_or(())?;
                    Ok(Some(BroadcastEvent::ReloadPushServers(account_id)))
                }

                8 => Ok(Some(BroadcastEvent::ReloadSpamFilter)),

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
