/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use common::{
    Inner,
    ipc::QueueEvent,
    manager::boot::{BootManager, IpcReceivers},
};
use queue::manager::{QUEUE_DRAIN_TIMEOUT, SpawnQueue};
use reporting::scheduler::SpawnReport;
use std::{sync::Arc, time::Duration};

pub mod core;
pub mod inbound;
pub mod outbound;
pub mod queue;
pub mod reporting;
pub mod scripts;

pub trait StartQueueManager {
    fn start_queue_manager(&mut self);
}

const QUEUE_DRAIN_GRACE: Duration = Duration::from_secs(1);

pub async fn drain_queue_manager(inner: &Inner) {
    if inner.shared_core.load().storage.registry.is_recovery_mode() {
        return;
    }
    let queue_tx = &inner.ipc.queue_tx;
    if queue_tx.send(QueueEvent::Stop).await.is_ok() {
        let _ =
            tokio::time::timeout(QUEUE_DRAIN_TIMEOUT + QUEUE_DRAIN_GRACE, queue_tx.closed()).await;
    }
}

pub trait SpawnQueueManager {
    fn spawn_queue_manager(&mut self, inner: Arc<Inner>);
}

impl StartQueueManager for BootManager {
    fn start_queue_manager(&mut self) {
        self.ipc_rxs.spawn_queue_manager(self.inner.clone());
    }
}

impl SpawnQueueManager for IpcReceivers {
    fn spawn_queue_manager(&mut self, inner: Arc<Inner>) {
        let core = inner.shared_core.load();
        if core.storage.registry.is_recovery_mode() {
            return;
        }

        // Spawn queue manager
        let queue_rx = self.queue_rx.take().unwrap();
        if core.network.roles.outbound_mta {
            queue_rx.spawn(inner.clone());
        } else {
            queue_rx.discard();
        }

        // Spawn report manager
        self.report_rx.take().unwrap().spawn(inner);
    }
}
