/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    config::smtp::queue::QueueName,
    ipc::{
        BroadcastEvent, CacheInvalidation, CalendarAlert, EmailPush, PushNotification, QueueNames,
        RegistryChange, ViewerStateChange,
    },
};
use registry::{
    schema::prelude::ObjectType,
    types::{EnumImpl, id::ObjectId},
};
use std::{collections::VecDeque, time::Duration};
use store::write::TaskTypes;
use tokio::sync::mpsc;
use types::{id::Id, type_state::StateChange};
use utils::{
    codec::leb128::{Leb128Reader, Leb128Writer},
    map::bitmap::Bitmap,
};

pub mod backlog;
pub mod publisher;
pub mod subscriber;

#[derive(Debug)]
pub(crate) struct BroadcastBatch<T> {
    messages: T,
}

pub(crate) const MAX_BATCH_SIZE: usize = 100;
pub(crate) const BROADCAST_TOPIC: &str = "stwt.agora";
pub(crate) const RETRY_INITIAL: Duration = Duration::from_millis(100);
pub(crate) const RETRY_MAX: Duration = Duration::from_secs(5);

const STATE_CHANGE: u8 = 0;
const VIEWER_STATE_CHANGE: u8 = 15;

impl BroadcastBatch<Vec<BroadcastEvent>> {
    pub fn init() -> Self {
        Self {
            messages: Vec::with_capacity(MAX_BATCH_SIZE),
        }
    }

    pub async fn recv(&mut self, rx: &mut mpsc::Receiver<BroadcastEvent>) -> bool {
        if rx.recv_many(&mut self.messages, MAX_BATCH_SIZE).await == 0 {
            return false;
        }
        self.dedup_refreshes();
        true
    }

    pub fn take_from(&mut self, queue: &mut VecDeque<BroadcastEvent>) {
        let count = queue.len().min(MAX_BATCH_SIZE);
        self.messages.extend(queue.drain(..count));
        self.dedup_refreshes();
    }

    fn dedup_refreshes(&mut self) {
        let mut seen_refreshes = 0u8;
        let mut task_types = TaskTypes::default();
        let mut queues = QueueNames::default();
        self.messages.retain(|message| {
            let refresh = match message {
                BroadcastEvent::TaskQueueRefresh(types) => {
                    task_types.union(*types);
                    REFRESH_TASK
                }
                BroadcastEvent::QueueRefresh(names) => {
                    queues.merge(names);
                    REFRESH_QUEUE
                }
                BroadcastEvent::IndexQueueRefresh => REFRESH_INDEX,
                _ => return true,
            };
            let is_first = seen_refreshes & refresh == 0;
            seen_refreshes |= refresh;
            is_first
        });

        if seen_refreshes & (REFRESH_TASK | REFRESH_QUEUE) != 0 {
            for message in &mut self.messages {
                match message {
                    BroadcastEvent::TaskQueueRefresh(types) => *types = task_types,
                    BroadcastEvent::QueueRefresh(names) => *names = std::mem::take(&mut queues),
                    _ => {}
                }
            }
        }
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl<T: AsRef<[BroadcastEvent]>> BroadcastBatch<T> {
    pub fn serialize(&self, node_id: u16, read_version: Option<u64>, serialized: &mut Vec<u8>) {
        let messages = self.messages.as_ref();
        serialized.clear();
        serialized.reserve(
            (messages.len() * 10) + std::mem::size_of::<u16>() + std::mem::size_of::<u64>(),
        );
        serialized.push_leb128(node_id);
        serialized.push_leb128(read_version.unwrap_or_default());
        for message in messages {
            match message {
                BroadcastEvent::PushNotification(notification) => match notification {
                    PushNotification::StateChange(state_change) => {
                        serialized.push(STATE_CHANGE);
                        serialized.push_leb128(state_change.change_id);
                        serialized.push_leb128(*state_change.types.as_ref());
                        serialized.push_leb128(state_change.account_id);
                    }
                    PushNotification::ViewerStateChange(viewer_change) => {
                        serialized.push(VIEWER_STATE_CHANGE);
                        serialized.push_leb128(viewer_change.change.change_id);
                        serialized.push_leb128(*viewer_change.change.types.as_ref());
                        serialized.push_leb128(viewer_change.change.account_id);
                        serialized.push_leb128(viewer_change.viewer_id);
                    }
                    PushNotification::CalendarAlert(calendar_alert) => {
                        serialized.push(1u8);
                        serialized.push_leb128(calendar_alert.account_id);
                        serialized.push_leb128(calendar_alert.event_account_id);
                        serialized.push_leb128(calendar_alert.event_id);
                        serialized
                            .push_leb128(calendar_alert.recurrence_id.unwrap_or_default() as u64);
                        serialized.push_leb128(calendar_alert.uid.len());
                        serialized.extend_from_slice(calendar_alert.uid.as_bytes());
                        serialized.push_leb128(calendar_alert.alert_id.len());
                        serialized.extend_from_slice(calendar_alert.alert_id.as_bytes());
                    }
                    PushNotification::EmailPush(email_push) => {
                        serialized.push(2u8);
                        serialized.push_leb128(email_push.account_id);
                        serialized.push_leb128(email_push.email_id);
                        serialized.push_leb128(email_push.change_id);
                    }
                },
                BroadcastEvent::PushServerUpdate(account_id) => {
                    serialized.push(3u8);
                    serialized.push_leb128(*account_id);
                }
                BroadcastEvent::RegistryChange(items) => match items {
                    RegistryChange::Insert(id) => {
                        serialized.push(4u8);
                        serialized.push_leb128(id.object().to_id());
                        serialized.push_leb128(id.id().id());
                    }
                    RegistryChange::Delete(id) => {
                        serialized.push(5u8);
                        serialized.push_leb128(id.object().to_id());
                        serialized.push_leb128(id.id().id());
                    }
                    RegistryChange::Reload(object) => {
                        serialized.push(6u8);
                        serialized.push_leb128(object.to_id());
                    }
                },
                BroadcastEvent::CacheInvalidate(items) => {
                    serialized.push(7u8);
                    serialized.push_leb128(items.len());
                    for item in items {
                        let (marker, id) = match item {
                            CacheInvalidation::AccessToken(id) => (0u8, *id),
                            CacheInvalidation::GroupwareResources(id) => (1u8, *id),
                            CacheInvalidation::Domain(id) => (2u8, *id),
                            CacheInvalidation::Account(id) => (3u8, *id),
                            CacheInvalidation::DkimSignature(id) => (4u8, *id),
                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            CacheInvalidation::Tenant(id) => (5u8, *id),
                            // SPDX-SnippetEnd
                            CacheInvalidation::Role(id) => (6u8, *id),
                            CacheInvalidation::List(id) => (7u8, *id),
                            CacheInvalidation::DomainLogo(id) => (8u8, *id),
                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            CacheInvalidation::TenantLogo(id) => (9u8, *id),
                            // SPDX-SnippetEnd
                            CacheInvalidation::EmailNegative {
                                domain_id,
                                local_part_hash,
                            } => {
                                serialized.push(10u8);
                                serialized.push_leb128(*domain_id);
                                serialized.push_leb128(*local_part_hash);
                                continue;
                            }
                            CacheInvalidation::DomainNegative => (11u8, 0),
                            CacheInvalidation::MessageCache(id) => (12u8, *id),
                            CacheInvalidation::PrivateMetadata(id) => (13u8, *id),
                            CacheInvalidation::OAuthGrant {
                                account_id,
                                grant_id,
                            } => {
                                serialized.push(14u8);
                                serialized.push_leb128(*account_id);
                                serialized.push_leb128(*grant_id);
                                continue;
                            }
                            CacheInvalidation::ActiveSieveScript(id) => (15u8, *id),
                            CacheInvalidation::ExternalPublicKey(address_hash) => {
                                (16u8, *address_hash)
                            }
                        };

                        serialized.push(marker);
                        serialized.push_leb128(id);
                    }
                }
                BroadcastEvent::CacheInvalidateAll => {
                    serialized.push(8u8);
                }
                BroadcastEvent::CacheInvalidateNegative => {
                    serialized.push(9u8);
                }
                BroadcastEvent::MtaQueueStatus { is_running } => {
                    if *is_running {
                        serialized.push(10u8);
                    } else {
                        serialized.push(11u8);
                    }
                }
                BroadcastEvent::QueueRefresh(queues) => {
                    serialized.push(12u8);
                    serialized.push_leb128(queues.len());
                    for queue in queues.iter() {
                        serialized.extend_from_slice(queue.as_slice());
                    }
                }
                BroadcastEvent::TaskQueueRefresh(task_types) => {
                    serialized.push(13u8);
                    serialized.push_leb128(task_types.bits());
                }
                BroadcastEvent::IndexQueueRefresh => {
                    serialized.push(14u8);
                }
            }
        }
    }
}

const REFRESH_TASK: u8 = 1;
const REFRESH_INDEX: u8 = 2;
const REFRESH_QUEUE: u8 = 4;

impl BroadcastBatch<&[u8]> {
    pub fn node_id(&mut self) -> Option<u16> {
        self.messages.read_leb128::<u16>()
    }

    pub fn read_version(&mut self) -> Option<Option<u64>> {
        self.messages
            .read_leb128::<u64>()
            .map(|version| Some(version).filter(|version| *version > 0))
    }

    pub fn next_event(&mut self) -> Result<Option<BroadcastEvent>, ()> {
        if let Some(id) = self.next_byte() {
            match id {
                tag @ (STATE_CHANGE | VIEWER_STATE_CHANGE) => {
                    let change_id = self.messages.read_leb128().ok_or(())?;
                    let types = Bitmap::from(self.messages.read_leb128::<u64>().ok_or(())?);
                    let account_id = self.messages.read_leb128().ok_or(())?;
                    let change = StateChange {
                        account_id,
                        change_id,
                        types,
                    };
                    let notification = if tag == VIEWER_STATE_CHANGE {
                        PushNotification::ViewerStateChange(ViewerStateChange {
                            viewer_id: self.messages.read_leb128().ok_or(())?,
                            change,
                        })
                    } else {
                        PushNotification::StateChange(change)
                    };
                    Ok(Some(BroadcastEvent::PushNotification(notification)))
                }

                1 => {
                    let account_id = self.messages.read_leb128().ok_or(())?;
                    let event_account_id = self.messages.read_leb128().ok_or(())?;
                    let event_id = self.messages.read_leb128().ok_or(())?;
                    let recurrence_id = self.messages.read_leb128::<u64>().ok_or(())? as i64;
                    let uid = self.next_string()?;
                    let alert_id = self.next_string()?;
                    Ok(Some(BroadcastEvent::PushNotification(
                        PushNotification::CalendarAlert(CalendarAlert {
                            account_id,
                            event_account_id,
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
                        account_id: self.messages.read_leb128().ok_or(())?,
                        email_id: self.messages.read_leb128().ok_or(())?,
                        change_id: self.messages.read_leb128().ok_or(())?,
                    }),
                ))),
                3 => {
                    let account_id = self.messages.read_leb128().ok_or(())?;
                    Ok(Some(BroadcastEvent::PushServerUpdate(account_id)))
                }
                4 => {
                    let object_id = self.messages.read_leb128().ok_or(())?;
                    let id = self.messages.read_leb128::<u64>().ok_or(())?;
                    Ok(Some(BroadcastEvent::RegistryChange(
                        RegistryChange::Insert(ObjectId::new(
                            ObjectType::from_id(object_id).ok_or(())?,
                            Id::new(id),
                        )),
                    )))
                }
                5 => {
                    let object_id = self.messages.read_leb128().ok_or(())?;
                    let id = self.messages.read_leb128::<u64>().ok_or(())?;
                    Ok(Some(BroadcastEvent::RegistryChange(
                        RegistryChange::Delete(ObjectId::new(
                            ObjectType::from_id(object_id).ok_or(())?,
                            Id::new(id),
                        )),
                    )))
                }
                6 => {
                    let object_id = self.messages.read_leb128().ok_or(())?;
                    Ok(Some(BroadcastEvent::RegistryChange(
                        RegistryChange::Reload(ObjectType::from_id(object_id).ok_or(())?),
                    )))
                }
                7 => {
                    let count = self.messages.read_leb128::<usize>().ok_or(())?;
                    let mut items = Vec::with_capacity(count.min(self.messages.len()));
                    for _ in 0..count {
                        let marker = self.next_byte().ok_or(())?;
                        let id = self.messages.read_leb128::<u32>().ok_or(())?;
                        items.push(match marker {
                            0 => CacheInvalidation::AccessToken(id),
                            1 => CacheInvalidation::GroupwareResources(id),
                            2 => CacheInvalidation::Domain(id),
                            3 => CacheInvalidation::Account(id),
                            4 => CacheInvalidation::DkimSignature(id),
                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            5 => CacheInvalidation::Tenant(id),
                            // SPDX-SnippetEnd
                            6 => CacheInvalidation::Role(id),
                            7 => CacheInvalidation::List(id),
                            8 => CacheInvalidation::DomainLogo(id),
                            // SPDX-SnippetBegin
                            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                            // SPDX-License-Identifier: LicenseRef-SEL
                            #[cfg(feature = "enterprise")]
                            9 => CacheInvalidation::TenantLogo(id),
                            // SPDX-SnippetEnd
                            10 => {
                                let local_part_hash =
                                    self.messages.read_leb128::<u32>().ok_or(())?;
                                CacheInvalidation::EmailNegative {
                                    domain_id: id,
                                    local_part_hash,
                                }
                            }
                            11 => CacheInvalidation::DomainNegative,
                            12 => CacheInvalidation::MessageCache(id),
                            13 => CacheInvalidation::PrivateMetadata(id),
                            14 => CacheInvalidation::OAuthGrant {
                                account_id: id,
                                grant_id: self.messages.read_leb128::<u64>().ok_or(())?,
                            },
                            15 => CacheInvalidation::ActiveSieveScript(id),
                            16 => CacheInvalidation::ExternalPublicKey(id),
                            _ => return Err(()),
                        });
                    }
                    Ok(Some(BroadcastEvent::CacheInvalidate(items)))
                }
                8 => Ok(Some(BroadcastEvent::CacheInvalidateAll)),
                9 => Ok(Some(BroadcastEvent::CacheInvalidateNegative)),
                10 => Ok(Some(BroadcastEvent::MtaQueueStatus { is_running: true })),
                11 => Ok(Some(BroadcastEvent::MtaQueueStatus { is_running: false })),
                12 => {
                    let count = self.messages.read_leb128::<usize>().ok_or(())?;
                    if count > self.messages.len() / size_of::<QueueName>() {
                        return Err(());
                    }
                    let mut queues = QueueNames::default();
                    for _ in 0..count {
                        let (name, rest) = self.messages.split_first_chunk::<8>().ok_or(())?;
                        self.messages = rest;
                        queues.insert(QueueName::from(*name));
                    }
                    Ok(Some(BroadcastEvent::QueueRefresh(queues)))
                }
                13 => Ok(Some(BroadcastEvent::TaskQueueRefresh(
                    TaskTypes::from_bits(self.messages.read_leb128::<u32>().ok_or(())?),
                ))),
                14 => Ok(Some(BroadcastEvent::IndexQueueRefresh)),
                _ => Err(()),
            }
        } else {
            Ok(None)
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        let (&byte, rest) = self.messages.split_first()?;
        self.messages = rest;
        Some(byte)
    }

    fn next_string(&mut self) -> Result<String, ()> {
        let len = self.messages.read_leb128::<usize>().ok_or(())?;
        let (bytes, rest) = self.messages.split_at_checked(len).ok_or(())?;
        self.messages = rest;
        String::from_utf8(bytes.to_vec()).map_err(|_| ())
    }
}

impl<T> BroadcastBatch<T> {
    pub fn new(messages: T) -> Self {
        Self { messages }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/services/src/broadcast/tests.rs"]
mod tests;
