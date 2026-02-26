/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::task_manager::TaskResult;
use common::Server;
use smtp::reporting::{dmarc::DmarcReporting, tls::TlsReporting};

pub enum ReportId {
    Dmarc(u64),
    Tls(u64),
}

pub(crate) trait SubmitReportTask: Sync + Send {
    fn submit_report(&self, report_id: ReportId) -> impl Future<Output = TaskResult> + Send;
}

impl SubmitReportTask for Server {
    async fn submit_report(&self, report_id: ReportId) -> TaskResult {
        match submit_report(self, report_id).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(err.details("Failed to submit report"));
                result
            }
        }
    }
}

async fn submit_report(server: &Server, report_id: ReportId) -> trc::Result<TaskResult> {
    match report_id {
        ReportId::Dmarc(item_id) => server
            .send_dmarc_aggregate_report(item_id)
            .await
            .map(|_| TaskResult::Success),
        ReportId::Tls(item_id) => server
            .send_tls_aggregate_report(item_id)
            .await
            .map(|_| TaskResult::Success),
    }
}
