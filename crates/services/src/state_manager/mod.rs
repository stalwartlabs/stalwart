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

use common::ipc::{PushNotification, ViewerStateChange};
use email::push::PushSubscription;
use jmap_proto::types::state::State;
use std::{sync::Arc, time::Instant};
use types::{id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

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
    DeliveryGone { id: Id },
    Reset,
}

impl PushBatch {
    pub fn push(&mut self, notification: PushNotification) {
        match notification {
            PushNotification::StateChange(state_change)
            | PushNotification::ViewerStateChange(ViewerStateChange {
                change: state_change,
                ..
            }) => {
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

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/services/src/state_manager/tests.rs"]
mod tests;
