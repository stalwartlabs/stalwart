/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::smtp::{
    queue::QueueName,
    report::AggregateFrequency,
    resolver::{Policy, Tlsa},
};
use ahash::RandomState;
use mail_auth::{
    dmarc::Dmarc,
    mta_sts::TlsRpt,
    report::{Record, tlsrpt::FailureDetails},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use store::{BlobStore, InMemoryStore, Store};
use tokio::sync::{Semaphore, SemaphorePermit, mpsc};
use types::type_state::{DataType, StateChange};
use utils::map::bitmap::Bitmap;

pub enum HousekeeperEvent {
    AcmeReschedule {
        provider_id: String,
        renew_at: Instant,
    },
    Purge(PurgeType),
    ReloadSettings,
    Exit,
}

pub enum PurgeType {
    Data(Store),
    Blobs {
        store: Store,
        blob_store: BlobStore,
    },
    Lookup {
        store: InMemoryStore,
        prefix: Option<Vec<u8>>,
    },
    Account {
        account_id: Option<u32>,
        use_roles: bool,
    },
}

#[derive(Debug)]
pub enum PushEvent {
    Subscribe {
        account_ids: Vec<u32>,
        types: Bitmap<DataType>,
        tx: mpsc::Sender<PushNotification>,
    },
    Publish {
        notification: PushNotification,
        broadcast: bool,
    },
    PushServerRegister {
        activate: Vec<u32>,
        expired: Vec<u32>,
    },
    PushServerUpdate {
        account_id: u32,
        broadcast: bool,
    },
    Stop,
}

#[derive(Debug, Clone)]
pub enum PushNotification {
    StateChange(StateChange),
    CalendarAlert(CalendarAlert),
    EmailPush(EmailPush),
}

#[derive(Debug, Clone)]
pub struct EmailPush {
    pub account_id: u32,
    pub email_id: u32,
    pub change_id: u64,
}

#[derive(Debug, Clone)]
pub struct CalendarAlert {
    pub account_id: u32,
    pub event_id: u32,
    pub recurrence_id: Option<i64>,
    pub uid: String,
    pub alert_id: String,
}

#[derive(Debug)]
pub enum BroadcastEvent {
    PushNotification(PushNotification),
    InvalidateAccessTokens(Vec<u32>),
    InvalidateGroupwareCache(Vec<u32>),
    ReloadPushServers(u32),
    ReloadSettings,
    ReloadBlockedIps,
    ReloadSpamFilter,
}

#[derive(Debug)]
pub enum QueueEvent {
    Refresh,
    WorkerDone {
        queue_id: u64,
        queue_name: QueueName,
        status: QueueEventStatus,
    },
    Paused(bool),
    ReloadSettings,
    Stop,
}

#[derive(Debug)]
pub enum QueueEventStatus {
    Completed,
    Locked,
    Deferred,
}

#[derive(Debug)]
pub enum ReportingEvent {
    Dmarc(Box<DmarcEvent>),
    Tls(Box<TlsEvent>),
    Stop,
}

#[derive(Debug)]
pub struct DmarcEvent {
    pub domain: String,
    pub report_record: Record,
    pub dmarc_record: Arc<Dmarc>,
    pub interval: AggregateFrequency,
}

#[derive(Debug)]
pub struct TlsEvent {
    pub domain: String,
    pub policy: PolicyType,
    pub failure: Option<FailureDetails>,
    pub tls_record: Arc<TlsRpt>,
    pub interval: AggregateFrequency,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum PolicyType {
    Tlsa(Option<Arc<Tlsa>>),
    Sts(Option<Arc<Policy>>),
    None,
}

pub struct TrainTaskController {
    semaphore: Semaphore,
    stop_flag: AtomicBool,
}

impl Default for TrainTaskController {
    fn default() -> Self {
        Self {
            semaphore: Semaphore::new(1),
            stop_flag: AtomicBool::new(false),
        }
    }
}

impl TrainTaskController {
    pub fn try_run(&self) -> Option<SemaphorePermit<'_>> {
        let permit = self.semaphore.try_acquire().ok()?;

        self.stop_flag.store(false, Ordering::SeqCst);

        Some(permit)
    }

    pub fn is_running(&self) -> bool {
        self.semaphore.available_permits() == 0
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    pub fn should_stop(&self) -> bool {
        self.stop_flag.load(Ordering::SeqCst)
    }
}

pub trait ToHash {
    fn to_hash(&self) -> u64;
}

impl ToHash for Dmarc {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
    }
}

impl ToHash for PolicyType {
    fn to_hash(&self) -> u64 {
        RandomState::with_seeds(1, 9, 7, 9).hash_one(self)
    }
}

impl From<DmarcEvent> for ReportingEvent {
    fn from(value: DmarcEvent) -> Self {
        ReportingEvent::Dmarc(Box::new(value))
    }
}

impl From<TlsEvent> for ReportingEvent {
    fn from(value: TlsEvent) -> Self {
        ReportingEvent::Tls(Box::new(value))
    }
}

impl From<Arc<Tlsa>> for PolicyType {
    fn from(value: Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value))
    }
}

impl From<Arc<Policy>> for PolicyType {
    fn from(value: Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value))
    }
}

impl From<&Arc<Tlsa>> for PolicyType {
    fn from(value: &Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value.clone()))
    }
}

impl From<&Arc<Policy>> for PolicyType {
    fn from(value: &Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value.clone()))
    }
}

impl From<(&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)> for PolicyType {
    fn from(value: (&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)) -> Self {
        match value {
            (Some(value), _) => PolicyType::Sts(Some(value.clone())),
            (_, Some(value)) => PolicyType::Tlsa(Some(value.clone())),
            _ => PolicyType::None,
        }
    }
}

impl PushNotification {
    pub fn account_id(&self) -> u32 {
        match self {
            PushNotification::StateChange(state_change) => state_change.account_id,
            PushNotification::CalendarAlert(calendar_alert) => calendar_alert.account_id,
            PushNotification::EmailPush(email_push) => email_push.account_id,
        }
    }

    pub fn filter_types(&self, types: &Bitmap<DataType>) -> Option<PushNotification> {
        match self {
            PushNotification::StateChange(state_change) => {
                let mut filtered_types = state_change.types;
                filtered_types.intersection(types);
                if !filtered_types.is_empty() {
                    Some(PushNotification::StateChange(StateChange {
                        account_id: state_change.account_id,
                        change_id: state_change.change_id,
                        types: filtered_types,
                    }))
                } else {
                    None
                }
            }
            PushNotification::CalendarAlert(_) => {
                if types.contains(DataType::CalendarAlert) {
                    Some(self.clone())
                } else {
                    None
                }
            }
            PushNotification::EmailPush(_) => {
                if types.contains_any(
                    [
                        DataType::EmailDelivery,
                        DataType::Email,
                        DataType::Mailbox,
                        DataType::Thread,
                    ]
                    .into_iter(),
                ) {
                    Some(self.clone())
                } else {
                    None
                }
            }
        }
    }
}

impl EmailPush {
    pub fn to_state_change(&self) -> StateChange {
        StateChange {
            account_id: self.account_id,
            change_id: self.change_id,
            types: Bitmap::from_iter([
                DataType::EmailDelivery,
                DataType::Email,
                DataType::Mailbox,
                DataType::Thread,
            ]),
        }
    }
}
