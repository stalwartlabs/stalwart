/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::context::EasContext;
use crate::push::{ExchangePush, ExchangeReceiver};
use common::{
    Server,
    ipc::{PushNotification, ViewerStateChange},
};
use std::time::Duration;
use tokio::time::{Instant, sleep_until};
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

const WATCHED_TYPES: [DataType; 6] = [
    DataType::Email,
    DataType::Mailbox,
    DataType::Calendar,
    DataType::CalendarEvent,
    DataType::AddressBook,
    DataType::ContactCard,
];

pub struct ChangeWait {
    receiver: ExchangeReceiver,
    notifications: Vec<PushNotification>,
    account_id: u32,
    types: Bitmap<DataType>,
    deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Changed(Bitmap<DataType>),
    Expired,
}

impl ChangeWait {
    pub fn new(server: &Server, ctx: &EasContext<'_>, heartbeat: u32) -> Self {
        let mut types = Bitmap::from_iter(WATCHED_TYPES);
        types.intersection(&ctx.data_types);
        ChangeWait {
            receiver: server.subscribe_exchange(&ctx.access_token, types),
            notifications: Vec::new(),
            account_id: ctx.account_id,
            types,
            deadline: Instant::now() + Duration::from_secs(u64::from(heartbeat)),
        }
    }

    pub async fn next(&mut self) -> WaitOutcome {
        loop {
            self.notifications.clear();
            tokio::select! {
                is_open = self.receiver.recv(&mut self.notifications) => {
                    if !is_open {
                        return WaitOutcome::Expired;
                    }
                    let changed = self.changed_types();
                    if !changed.is_empty() {
                        return WaitOutcome::Changed(changed);
                    }
                }
                _ = sleep_until(self.deadline) => return WaitOutcome::Expired,
            }
        }
    }

    fn changed_types(&self) -> Bitmap<DataType> {
        let mut changed = Bitmap::new();
        for notification in &self.notifications {
            match notification {
                PushNotification::StateChange(change)
                | PushNotification::ViewerStateChange(ViewerStateChange { change, .. })
                    if change.account_id == self.account_id =>
                {
                    changed.union(&change.types);
                }
                PushNotification::EmailPush(push) if push.account_id == self.account_id => {
                    changed.insert(DataType::Email);
                }
                _ => {}
            }
        }
        changed.intersection(&self.types);
        changed
    }
}
