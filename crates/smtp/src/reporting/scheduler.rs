/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{dmarc::DmarcReporting, tls::TlsReporting};
use common::{BuildServer, Inner, ipc::ReportingEvent};
use std::sync::Arc;
use tokio::sync::mpsc;

pub trait SpawnReport {
    fn spawn(self, core: Arc<Inner>);
}

impl SpawnReport for mpsc::Receiver<ReportingEvent> {
    fn spawn(mut self, inner: Arc<Inner>) {
        tokio::spawn(async move {
            while let Some(event) = self.recv().await {
                let server = inner.build_server();
                match event {
                    ReportingEvent::Dmarc(event) => server.schedule_dmarc(event).await,
                    ReportingEvent::Tls(event) => server.schedule_tls(event).await,
                    ReportingEvent::Stop => break,
                }
            }
        });
    }
}
