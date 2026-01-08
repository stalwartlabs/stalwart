/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    config::smtp::queue::{QueueExpiry, QueueName},
};
use smtp::queue::{
    Recipient, Schedule, Status,
    manager::Queue,
    spool::{QueuedMessages, SmtpSpool},
};
use tokio::sync::mpsc;

pub mod concurrent;
pub mod dsn;
pub mod manager;
pub mod retry;
pub mod virtualq;

pub fn build_rcpt(address: &str, retry: u64, notify: u64, expires: u64) -> Recipient {
    Recipient {
        address: address.into(),
        retry: Schedule::later(retry),
        notify: Schedule::later(notify),
        expires: QueueExpiry::Ttl(expires),
        status: Status::Scheduled,
        flags: 0,
        orcpt: None,
        queue: QueueName::default(),
    }
}

pub trait QueuedEvents: Sync + Send {
    fn all_queued_messages(&self) -> impl Future<Output = QueuedMessages> + Send;
}

impl QueuedEvents for Server {
    async fn all_queued_messages(&self) -> QueuedMessages {
        self.next_event(&mut Queue::new(self.inner.clone(), mpsc::channel(100).1))
            .await
    }
}
