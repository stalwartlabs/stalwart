/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::cache::mark_stale;
use common::{
    Inner, Server,
    auth::AccessToken,
    ipc::{PushNotification, subscribers::PushReceiver},
};
use std::sync::Arc;
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

pub struct ExchangeReceiver {
    receiver: PushReceiver,
    inner: Arc<Inner>,
}

pub trait ExchangePush: Sync + Send {
    fn subscribe_exchange(
        &self,
        access_token: &AccessToken,
        types: Bitmap<DataType>,
    ) -> ExchangeReceiver;

    fn subscribe_exchange_account(
        &self,
        account_id: u32,
        types: Bitmap<DataType>,
    ) -> ExchangeReceiver;

    fn subscribe_exchange_accounts(
        &self,
        account_ids: &[u32],
        types: Bitmap<DataType>,
    ) -> ExchangeReceiver;
}

impl ExchangePush for Server {
    fn subscribe_exchange(
        &self,
        access_token: &AccessToken,
        types: Bitmap<DataType>,
    ) -> ExchangeReceiver {
        ExchangeReceiver {
            receiver: self
                .inner
                .ipc
                .push_subscribers
                .subscribe(access_token.all_ids(), types),
            inner: self.inner.clone(),
        }
    }

    fn subscribe_exchange_account(
        &self,
        account_id: u32,
        types: Bitmap<DataType>,
    ) -> ExchangeReceiver {
        self.subscribe_exchange_accounts(&[account_id], types)
    }

    fn subscribe_exchange_accounts(
        &self,
        account_ids: &[u32],
        types: Bitmap<DataType>,
    ) -> ExchangeReceiver {
        ExchangeReceiver {
            receiver: self
                .inner
                .ipc
                .push_subscribers
                .subscribe(account_ids.iter().copied(), types),
            inner: self.inner.clone(),
        }
    }
}

impl ExchangeReceiver {
    pub async fn recv(&mut self, notifications: &mut Vec<PushNotification>) -> bool {
        let start = notifications.len();
        let is_open = self.receiver.recv(notifications).await;
        let mut last = None;
        for notification in notifications.get(start..).unwrap_or_default() {
            let account_id = match notification {
                PushNotification::StateChange(change) => change.account_id,
                PushNotification::ViewerStateChange(change) => change.change.account_id,
                PushNotification::EmailPush(push) => push.account_id,
                PushNotification::CalendarAlert(_) => continue,
            };
            if last != Some(account_id) {
                mark_stale(&self.inner, account_id);
                last = Some(account_id);
            }
        }
        is_open
    }
}
