/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{OtlpConfig, unix_nanos, unix_nanos_now};
use crate::{
    otlp::{metrics::encode_metrics, request::RequestBuilder, resource::Resource},
    transport::{
        TransportError,
        endpoint::Signal,
        sender::{Outcome, Sender},
    },
};
use std::time::{Duration, SystemTime};
use tokio::time::Instant;
use trc::TelemetryEvent;

pub struct OtlpMetricsExporter {
    sender: Sender,
    resource: Resource,
    builder: RequestBuilder,
    timeout: Duration,
}

impl OtlpMetricsExporter {
    pub fn new(config: OtlpConfig, resource: Resource) -> Result<Self, TransportError> {
        let seed = u64::from_be_bytes(resource.trace_prefix) ^ Signal::Metrics as u64;
        Ok(Self {
            sender: config.sender(Signal::Metrics, seed)?,
            builder: RequestBuilder::new(&resource, config.framing()),
            timeout: config.timeout(),
            resource,
        })
    }

    pub async fn push(&mut self, is_enterprise: bool, start_time: SystemTime, interval: Duration) {
        encode_metrics(
            &mut self.builder,
            is_enterprise,
            unix_nanos(start_time),
            unix_nanos_now(),
        );
        let Some(request) = self.builder.seal(&self.resource) else {
            return;
        };
        let deadline = Instant::now() + self.timeout.min(interval);
        match self.sender.send(request.body, deadline).await {
            Outcome::Delivered => {}
            Outcome::PartialSuccess { rejected, message } => {
                trc::event!(
                    Telemetry(TelemetryEvent::OtelMetricsExporterError),
                    Details = "Metrics partially rejected by the collector",
                    Total = rejected,
                    Reason = message,
                );
            }
            Outcome::Rejected { reason } | Outcome::Deferred { reason } => {
                trc::event!(
                    Telemetry(TelemetryEvent::OtelMetricsExporterError),
                    Details = "Failed to export metrics",
                    Reason = reason,
                );
            }
        }
    }
}
