/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod ece;
pub mod http;
pub mod manager;
pub mod push;

use common::ipc::PushNotification;
use email::push::PushSubscription;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use types::{id::Id, type_state::DataType};
use utils::map::bitmap::Bitmap;

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
    notifications: Vec<PushNotification>,
    in_flight: bool,
}

#[derive(Debug)]
pub enum Event {
    Push {
        notification: PushNotification,
    },
    Update {
        account_id: u32,
    },
    DeliverySuccess {
        id: Id,
    },
    DeliveryFailure {
        id: Id,
        notifications: Vec<PushNotification>,
    },
    Reset,
}

impl IpcSubscriber {
    fn is_valid(&self) -> bool {
        !self.tx.is_closed()
    }
}
