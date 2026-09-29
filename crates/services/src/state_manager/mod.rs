/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod ece;
pub mod email_push;
pub mod http;
pub mod manager;
pub mod push;

use common::ipc::PushNotification;
use email::push::PushSubscription;
use jmap_proto::types::state::State;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use types::{id::Id, type_state::DataType};
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

const PURGE_EVERY: Duration = Duration::from_secs(3600);
const SEND_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug)]
struct IpcSubscriber {
    types: Bitmap<DataType>,
    tx: mpsc::Sender<PushNotification>,
}

#[derive(Debug)]
pub struct PushRegistration {
    server: Arc<PushSubscription>,
    member_account_ids: Vec<u32>,
    num_attempts: u32,
    last_request: Instant,
    pending: PushBatch,
    in_flight: bool,
}

#[derive(Debug, Default)]
pub struct PushBatch {
    state_changes: VecMap<Id, VecMap<DataType, State>>,
    notifications: Vec<PushNotification>,
}

#[derive(Debug)]
pub enum Event {
    Push { notification: PushNotification },
    Update { account_id: u32 },
    DeliverySuccess { id: Id },
    DeliveryFailure { id: Id, failed: PushBatch },
    Reset,
}

impl IpcSubscriber {
    fn is_valid(&self) -> bool {
        !self.tx.is_closed()
    }
}

impl PushBatch {
    pub fn push(&mut self, notification: PushNotification) {
        match notification {
            PushNotification::StateChange(state_change) => {
                if !state_change.types.is_empty() {
                    let states = self
                        .state_changes
                        .get_mut_or_insert(Id::from(state_change.account_id));
                    for data_type in state_change.types {
                        merge_state(states, data_type, state_change.change_id);
                    }
                }
            }
            notification => self.notifications.push(notification),
        }
    }

    pub fn merge_failed(&mut self, failed: PushBatch) {
        for (account_id, failed_states) in failed.state_changes {
            let states = self.state_changes.get_mut_or_insert(account_id);
            for (data_type, state) in failed_states {
                if let State::Exact(change_id) = state {
                    merge_state(states, data_type, change_id);
                }
            }
        }

        if !failed.notifications.is_empty() {
            let mut notifications = failed.notifications;
            notifications.append(&mut self.notifications);
            self.notifications = notifications;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.state_changes.is_empty() && self.notifications.is_empty()
    }

    pub fn clear(&mut self) {
        self.state_changes.clear();
        self.notifications.clear();
    }
}

fn merge_state(states: &mut VecMap<DataType, State>, data_type: DataType, change_id: u64) {
    match states.get_mut(&data_type) {
        Some(State::Exact(current)) if *current >= change_id => {}
        Some(state) => *state = State::Exact(change_id),
        None => states.append(data_type, State::Exact(change_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::PushBatch;
    use common::ipc::{EmailPush, PushNotification};
    use jmap_proto::types::state::State;
    use types::{
        id::Id,
        type_state::{DataType, StateChange},
    };
    use utils::map::bitmap::Bitmap;

    fn state_change<const N: usize>(change_id: u64, types: [DataType; N]) -> PushNotification {
        PushNotification::StateChange(StateChange {
            account_id: 1,
            change_id,
            types: Bitmap::from_iter(types),
        })
    }

    fn email_push(email_id: u32) -> PushNotification {
        PushNotification::EmailPush(EmailPush {
            account_id: 1,
            email_id,
            change_id: email_id.into(),
        })
    }

    #[test]
    fn batch_keeps_newest_state_per_type() {
        let mut batch = PushBatch::default();
        batch.push(state_change(5, [DataType::Email]));
        batch.push(state_change(7, [DataType::Email, DataType::Mailbox]));
        batch.push(state_change(6, [DataType::Mailbox]));

        let mut failed = PushBatch::default();
        failed.push(state_change(
            4,
            [DataType::Email, DataType::Mailbox, DataType::Thread],
        ));
        batch.merge_failed(failed);

        let states = batch.state_changes.get(&Id::from(1u32)).unwrap();
        assert_eq!(states.len(), 3);
        assert_eq!(states.get(&DataType::Email), Some(&State::Exact(7)));
        assert_eq!(states.get(&DataType::Mailbox), Some(&State::Exact(7)));
        assert_eq!(states.get(&DataType::Thread), Some(&State::Exact(4)));

        assert!(!batch.is_empty());
        batch.clear();
        assert!(batch.is_empty());
    }

    #[test]
    fn failed_notifications_are_retried_first() {
        let mut batch = PushBatch::default();
        batch.push(email_push(3));

        let mut failed = PushBatch::default();
        failed.push(email_push(1));
        failed.push(email_push(2));
        batch.merge_failed(failed);

        let email_ids = batch
            .notifications
            .iter()
            .filter_map(|notification| match notification {
                PushNotification::EmailPush(email_push) => Some(email_push.email_id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(email_ids, [1, 2, 3]);
        assert!(batch.state_changes.is_empty());
    }
}
