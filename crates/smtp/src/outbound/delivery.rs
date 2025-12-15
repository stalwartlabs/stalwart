/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{NextHop, lookup::ToNextHop, mta_sts, session::SessionParams};
use crate::outbound::DeliveryResult;
use crate::outbound::client::{
    SmtpClient, from_error_details, from_error_status, from_mail_send_error,
};
use crate::outbound::dane::dnssec::TlsaLookup;
use crate::outbound::lookup::{DnsLookup, SourceIp};
use crate::outbound::mta_sts::lookup::MtaStsLookup;
use crate::outbound::mta_sts::verify::VerifyPolicy;
use crate::outbound::{client::StartTlsResult, dane::verify::TlsaVerify};
use crate::queue::dsn::SendDsn;
use crate::queue::spool::SmtpSpool;
use crate::queue::throttle::IsAllowed;
use crate::queue::{
    Error, FROM_REPORT, HostResponse, MessageWrapper, QueueEnvelope, QueuedMessage, Status,
};
use crate::reporting::SmtpReporting;
use crate::{queue::ErrorDetails, reporting::tls::TlsRptOptions};
use ahash::AHashMap;
use common::Server;
use common::config::smtp::queue::RoutingStrategy;
use common::config::{server::ServerProtocol, smtp::report::AggregateFrequency};
use common::ipc::{PolicyType, QueueEvent, QueueEventStatus, TlsEvent};
use compact_str::ToCompactString;
use mail_auth::{
    mta_sts::TlsRpt,
    report::tlsrpt::{FailureDetails, ResultType},
};
use smtp_proto::MAIL_REQUIRETLS;
use std::sync::Arc;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Instant,
};
use store::write::{BatchBuilder, QueueClass, ValueClass, now};
use trc::{DaneEvent, DeliveryEvent, MtaStsEvent, ServerEvent, TlsRptEvent};

impl QueuedMessage {
    pub fn try_deliver(self, server: Server) {
        #![allow(clippy::large_futures)]
        tokio::spawn(async move {
            // Lock queue event
            let queue_id = self.queue_id;
            let status = if server.try_lock_event(queue_id, self.queue_name).await {
                if let Some(mut message) = server.read_message(queue_id, self.queue_name).await {
                    // Generate span id
                    message.span_id = server.inner.data.span_id_gen.generate();
                    let span_id = message.span_id;

                    trc::event!(
                        Delivery(DeliveryEvent::AttemptStart),
                        SpanId = message.span_id,
                        QueueId = message.queue_id,
                        QueueName = message.queue_name.to_string(),
                        From = if !message.message.return_path.is_empty() {
                            trc::Value::String(message.message.return_path.as_ref().into())
                        } else {
                            trc::Value::String("<>".into())
                        },
                        To = message
                            .message
                            .recipients
                            .iter()
                            .filter_map(|r| {
                                if matches!(
                                    r.status,
                                    Status::Scheduled | Status::TemporaryFailure(_)
                                ) && r.queue == message.queue_name
                                {
                                    Some(trc::Value::String(r.address().into()))
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>(),
                        Size = message.message.size,
                        Total = message.message.recipients.len(),
                    );

                    // Attempt delivery
                    let start_time = Instant::now();
                    let queue_event = self.deliver_task(server.clone(), message).await;

                    trc::event!(
                        Delivery(DeliveryEvent::AttemptEnd),
                        SpanId = span_id,
                        Elapsed = start_time.elapsed(),
                    );

                    // Unlock event
                    server.unlock_event(queue_id, self.queue_name).await;

                    queue_event
                } else {
                    // Message no longer exists, delete queue event.
                    let mut batch = BatchBuilder::new();
                    batch.clear(ValueClass::Queue(QueueClass::MessageEvent(
                        store::write::QueueEvent {
                            due: self.due,
                            queue_id: self.queue_id,
                            queue_name: self.queue_name.into_inner(),
                        },
                    )));

                    if let Err(err) = server.store().write(batch.build_all()).await {
                        trc::error!(
                            err.details("Failed to delete queue event.")
                                .caused_by(trc::location!())
                        );
                    }

                    // Unlock event
                    server.unlock_event(queue_id, self.queue_name).await;

                    QueueEventStatus::Completed
                }
            } else {
                QueueEventStatus::Locked
            };

            // Notify queue manager
            if server
                .inner
                .ipc
                .queue_tx
                .send(QueueEvent::WorkerDone {
                    queue_id,
                    queue_name: self.queue_name,
                    status,
                })
                .await
                .is_err()
            {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Reason = "Channel closed.",
                    CausedBy = trc::location!(),
                );
            }
        });
    }

    async fn deliver_task(self, server: Server, mut message: MessageWrapper) -> QueueEventStatus {
        // Check that the message still has recipients to be delivered
        let has_pending_delivery = message.has_pending_delivery();
        let span_id = message.span_id;

        // Send any due Delivery Status Notifications
        server.send_dsn(&mut message).await;

        match has_pending_delivery {
            PendingDelivery::Yes(true)
                if message
                    .message
                    .next_delivery_event(self.queue_name.into())
                    .is_some_and(|due| due <= now()) => {}
            PendingDelivery::No => {
                trc::event!(
                    Delivery(DeliveryEvent::Completed),
                    SpanId = span_id,
                    Elapsed = trc::Value::Duration((now() - message.message.created) * 1000)
                );

                // All message recipients expired, do not re-queue. (DSN has been already sent)
                message.remove(&server, self.due.into()).await;

                return QueueEventStatus::Completed;
            }
            _ => {
                // Re-queue the message if its not yet due for delivery
                message.save_changes(&server, self.due.into()).await;
                return QueueEventStatus::Deferred;
            }
        }

        // Throttle sender
        for throttle in &server.core.smtp.queue.outbound_limiters.sender {
            if let Err(retry_at) = server
                .is_allowed(throttle, &message.message, message.span_id)
                .await
            {
                trc::event!(
                    Delivery(DeliveryEvent::RateLimitExceeded),
                    Id = throttle.id.clone(),
                    SpanId = span_id,
                    NextRetry = trc::Value::Timestamp(retry_at)
                );

                let now = now();
                for rcpt in message.message.recipients.iter_mut() {
                    if matches!(
                        &rcpt.status,
                        Status::Scheduled | Status::TemporaryFailure(_)
                    ) && rcpt.retry.due <= now
                        && rcpt.queue == message.queue_name
                    {
                        rcpt.retry.due = retry_at;
                        rcpt.status = Status::TemporaryFailure(ErrorDetails {
                            entity: "localhost".into(),
                            details: Error::RateLimited,
                        });
                    }
                }

                message.save_changes(&server, self.due.into()).await;

                return QueueEventStatus::Deferred;
            }
        }

        // Group recipients by route
        let queue_config = &server.core.smtp.queue;
        let now_ = now();
        let mut routes: AHashMap<(&str, &RoutingStrategy), Vec<usize>> = AHashMap::new();
        for (rcpt_idx, rcpt) in message.message.recipients.iter().enumerate() {
            if matches!(
                &rcpt.status,
                Status::Scheduled | Status::TemporaryFailure(_)
            ) && rcpt.retry.due <= now_
                && rcpt.queue == message.queue_name
            {
                let envelope = QueueEnvelope::new(&message.message, rcpt);
                let route = server.get_route_or_default(
                    &server
                        .eval_if::<String, _>(&queue_config.route, &envelope, message.span_id)
                        .await
                        .unwrap_or_else(|| "default".to_string()),
                    message.span_id,
                );

                routes
                    .entry((rcpt.domain_part(), route))
                    .or_default()
                    .push(rcpt_idx);
            }
        }

        let no_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let mut delivery_results: Vec<DeliveryResult> = Vec::new();
        'next_route: for ((domain, route), rcpt_idxs) in routes {
            trc::event!(
                Delivery(DeliveryEvent::DomainDeliveryStart),
                SpanId = message.span_id,
                Domain = domain.to_string(),
            );

            // Build envelope
            let mut envelope =
                QueueEnvelope::new(&message.message, &message.message.recipients[rcpt_idxs[0]]);

            // Throttle recipient domain
            for throttle in &queue_config.outbound_limiters.rcpt {
                if let Err(retry_at) = server
                    .is_allowed(throttle, &envelope, message.span_id)
                    .await
                {
                    trc::event!(
                        Delivery(DeliveryEvent::RateLimitExceeded),
                        Id = throttle.id.clone(),
                        SpanId = span_id,
                        Domain = domain.to_string(),
                    );

                    delivery_results.push(DeliveryResult::rate_limited(rcpt_idxs, retry_at));
                    continue 'next_route;
                }
            }

            // Obtain next hop
            let (mut remote_hosts, mx_config, is_smtp) = match route {
                RoutingStrategy::Local => {
                    // Deliver message locally
                    message
                        .deliver_local(&rcpt_idxs, &mut delivery_results, &server)
                        .await;
                    continue 'next_route;
                }
                RoutingStrategy::Mx(mx_config) => (Vec::with_capacity(0), Some(mx_config), true),
                RoutingStrategy::Relay(relay_config) => (
                    vec![NextHop::Relay(relay_config)],
                    None,
                    relay_config.protocol == ServerProtocol::Smtp,
                ),
            };

            // Prepare TLS strategy
            let mut tls_strategy = server.get_tls_or_default(
                &server
                    .eval_if::<String, _>(&queue_config.tls, &envelope, message.span_id)
                    .await
                    .unwrap_or_else(|| "default".to_string()),
                message.span_id,
            );

            // Obtain TLS reporting
            let tls_report =
                if is_smtp && mx_config.is_some() && (message.message.flags & FROM_REPORT == 0) {
                    match server
                        .eval_if(
                            &server.core.smtp.report.tls.send,
                            &envelope,
                            message.span_id,
                        )
                        .await
                        .unwrap_or(AggregateFrequency::Never)
                    {
                        interval @ (AggregateFrequency::Hourly
                        | AggregateFrequency::Daily
                        | AggregateFrequency::Weekly) => {
                            let time = Instant::now();
                            match server
                                .core
                                .smtp
                                .resolvers
                                .dns
                                .txt_lookup::<TlsRpt>(
                                    format!("_smtp._tls.{domain}."),
                                    Some(&server.inner.cache.dns_txt),
                                )
                                .await
                            {
                                Ok(record) => {
                                    trc::event!(
                                        TlsRpt(TlsRptEvent::RecordFetch),
                                        SpanId = message.span_id,
                                        Domain = domain.to_string(),
                                        Details = record
                                            .rua
                                            .iter()
                                            .map(|uri| trc::Value::from(match uri {
                                                mail_auth::mta_sts::ReportUri::Mail(uri)
                                                | mail_auth::mta_sts::ReportUri::Http(uri) =>
                                                    uri.to_string(),
                                            }))
                                            .collect::<Vec<_>>(),
                                        Elapsed = time.elapsed(),
                                    );

                                    TlsRptOptions { record, interval }.into()
                                }
                                Err(mail_auth::Error::DnsRecordNotFound(_)) => {
                                    trc::event!(
                                        TlsRpt(TlsRptEvent::RecordNotFound),
                                        SpanId = message.span_id,
                                        Domain = domain.to_string(),
                                        Elapsed = time.elapsed(),
                                    );
                                    None
                                }
                                Err(err) => {
                                    trc::event!(
                                        TlsRpt(TlsRptEvent::RecordFetchError),
                                        SpanId = message.span_id,
                                        Domain = domain.to_string(),
                                        CausedBy = trc::Error::from(err),
                                        Elapsed = time.elapsed(),
                                    );
                                    None
                                }
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                };

            // Obtain MTA-STS policy for domain
            let mta_sts_policy = if mx_config.is_some() && tls_strategy.try_mta_sts() && is_smtp {
                let time = Instant::now();
                match server
                    .lookup_mta_sts_policy(domain, tls_strategy.timeout_mta_sts)
                    .await
                {
                    Ok(mta_sts_policy) => {
                        trc::event!(
                            MtaSts(MtaStsEvent::PolicyFetch),
                            SpanId = message.span_id,
                            Domain = domain.to_string(),
                            Strict = mta_sts_policy.enforce(),
                            Details = mta_sts_policy
                                .mx
                                .iter()
                                .map(|mx| trc::Value::String(mx.to_compact_string()))
                                .collect::<Vec<_>>(),
                            Elapsed = time.elapsed(),
                        );

                        mta_sts_policy.into()
                    }
                    Err(err) => {
                        // Report MTA-STS error
                        let strict = tls_strategy.is_mta_sts_required();
                        if let Some(tls_report) = &tls_report {
                            match &err {
                                mta_sts::Error::Dns(mail_auth::Error::DnsRecordNotFound(_)) => {
                                    if strict {
                                        server.schedule_report(TlsEvent {
                                            policy: PolicyType::Sts(None),
                                            domain: domain.to_string(),
                                            failure: FailureDetails::new(ResultType::Other)
                                                .with_failure_reason_code(
                                                    "MTA-STS is required and no policy was found.",
                                                )
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }
                                }
                                mta_sts::Error::Dns(mail_auth::Error::DnsError(_)) => (),
                                _ => {
                                    server
                                        .schedule_report(TlsEvent {
                                            policy: PolicyType::Sts(None),
                                            domain: domain.to_string(),
                                            failure: FailureDetails::new(&err)
                                                .with_failure_reason_code(err.to_string())
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                }
                            }
                        }

                        match &err {
                            mta_sts::Error::Dns(mail_auth::Error::DnsRecordNotFound(_)) => {
                                trc::event!(
                                    MtaSts(MtaStsEvent::PolicyNotFound),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );
                            }
                            mta_sts::Error::Dns(err) => {
                                trc::event!(
                                    MtaSts(MtaStsEvent::PolicyFetchError),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    CausedBy = trc::Error::from(err.clone()),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );
                            }
                            mta_sts::Error::Http(err) => {
                                trc::event!(
                                    MtaSts(MtaStsEvent::PolicyFetchError),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Reason = err.to_string(),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );
                            }
                            mta_sts::Error::InvalidPolicy(reason) => {
                                trc::event!(
                                    MtaSts(MtaStsEvent::InvalidPolicy),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Reason = reason.clone(),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );
                            }
                        }

                        if strict {
                            delivery_results.push(DeliveryResult::domain(
                                Status::from_mta_sts_error(domain, err),
                                rcpt_idxs,
                            ));
                            continue 'next_route;
                        }

                        None
                    }
                }
            } else {
                None
            };

            // Obtain remote hosts list
            let mx_list;
            if let Some(mx_config) = mx_config {
                // Lookup MX
                let time = Instant::now();
                mx_list = match server
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .mx_lookup(domain, Some(&server.inner.cache.dns_mx))
                    .await
                {
                    Ok(mx) => mx,
                    Err(mail_auth::Error::DnsRecordNotFound(_)) => {
                        trc::event!(
                            Delivery(DeliveryEvent::MxLookupFailed),
                            SpanId = message.span_id,
                            Domain = domain.to_string(),
                            Details = "No MX records were found, attempting implicit MX.",
                            Elapsed = time.elapsed(),
                        );

                        Arc::new(vec![])
                    }
                    Err(err) => {
                        trc::event!(
                            Delivery(DeliveryEvent::MxLookupFailed),
                            SpanId = message.span_id,
                            Domain = domain.to_string(),
                            CausedBy = trc::Error::from(err.clone()),
                            Elapsed = time.elapsed(),
                        );

                        delivery_results.push(DeliveryResult::domain(
                            Status::from_mail_auth_error(domain, err),
                            rcpt_idxs,
                        ));
                        continue 'next_route;
                    }
                };

                if let Some(remote_hosts_) = mx_list.to_remote_hosts(domain, mx_config) {
                    trc::event!(
                        Delivery(DeliveryEvent::MxLookup),
                        SpanId = message.span_id,
                        Domain = domain.to_string(),
                        Details = remote_hosts_
                            .iter()
                            .map(|h| trc::Value::String(h.hostname().into()))
                            .collect::<Vec<_>>(),
                        Elapsed = time.elapsed(),
                    );
                    remote_hosts = remote_hosts_;
                } else {
                    trc::event!(
                        Delivery(DeliveryEvent::NullMx),
                        SpanId = message.span_id,
                        Domain = domain.to_string(),
                        Elapsed = time.elapsed(),
                    );

                    delivery_results.push(DeliveryResult::domain(
                        Status::PermanentFailure(ErrorDetails {
                            entity: domain.into(),
                            details: Error::DnsError(
                                "Domain does not accept messages (null MX)".into(),
                            ),
                        }),
                        rcpt_idxs,
                    ));
                    continue 'next_route;
                }
            }

            // Try delivering message
            let mut last_status: Status<HostResponse<Box<str>>, ErrorDetails> = Status::Scheduled;
            'next_host: for remote_host in &remote_hosts {
                // Validate MTA-STS
                envelope.mx = remote_host.hostname();
                if let Some(mta_sts_policy) = &mta_sts_policy {
                    let strict = mta_sts_policy.enforce();
                    if !mta_sts_policy.verify(envelope.mx) {
                        // Report MTA-STS failed verification
                        if let Some(tls_report) = &tls_report {
                            server
                                .schedule_report(TlsEvent {
                                    policy: mta_sts_policy.into(),
                                    domain: domain.to_string(),
                                    failure: FailureDetails::new(ResultType::ValidationFailure)
                                        .with_receiving_mx_hostname(envelope.mx)
                                        .with_failure_reason_code("MX not authorized by policy.")
                                        .into(),
                                    tls_record: tls_report.record.clone(),
                                    interval: tls_report.interval,
                                })
                                .await;
                        }

                        trc::event!(
                            MtaSts(MtaStsEvent::NotAuthorized),
                            SpanId = message.span_id,
                            Domain = domain.to_string(),
                            Hostname = envelope.mx.to_string(),
                            Details = mta_sts_policy
                                .mx
                                .iter()
                                .map(|mx| trc::Value::String(mx.to_compact_string()))
                                .collect::<Vec<_>>(),
                            Strict = strict,
                        );

                        if strict {
                            last_status = Status::PermanentFailure(ErrorDetails {
                                entity: envelope.mx.into(),
                                details: Error::MtaStsError(
                                    format!("MX {:?} not authorized by policy.", envelope.mx)
                                        .into_boxed_str(),
                                ),
                            });
                            continue 'next_host;
                        }
                    } else {
                        trc::event!(
                            MtaSts(MtaStsEvent::Authorized),
                            SpanId = message.span_id,
                            Domain = domain.to_string(),
                            Hostname = envelope.mx.to_string(),
                            Details = mta_sts_policy
                                .mx
                                .iter()
                                .map(|mx| trc::Value::String(mx.to_compact_string()))
                                .collect::<Vec<_>>(),
                            Strict = strict,
                        );
                    }
                }

                // Obtain source and remote IPs
                let time = Instant::now();
                let resolve_result = match server.resolve_host(remote_host, &envelope).await {
                    Ok(result) => {
                        trc::event!(
                            Delivery(DeliveryEvent::IpLookup),
                            SpanId = message.span_id,
                            Domain = domain.to_string(),
                            Hostname = envelope.mx.to_string(),
                            Details = result
                                .remote_ips
                                .iter()
                                .map(|ip| trc::Value::from(*ip))
                                .collect::<Vec<_>>(),
                            Limit = remote_host.max_multi_homed(),
                            Elapsed = time.elapsed(),
                        );

                        result
                    }
                    Err(status) => {
                        trc::event!(
                            Delivery(DeliveryEvent::IpLookupFailed),
                            SpanId = message.span_id,
                            Domain = domain.to_string(),
                            Hostname = envelope.mx.to_string(),
                            Details = status.to_string(),
                            Elapsed = time.elapsed(),
                        );

                        last_status = status;
                        continue 'next_host;
                    }
                };

                // Update TLS strategy
                tls_strategy = server.get_tls_or_default(
                    &server
                        .eval_if::<String, _>(&queue_config.tls, &envelope, message.span_id)
                        .await
                        .unwrap_or_else(|| "default".to_string()),
                    message.span_id,
                );

                // Lookup DANE policy
                let dane_policy = if tls_strategy.try_dane() && is_smtp {
                    let time = Instant::now();
                    let strict = tls_strategy.is_dane_required();
                    match server
                        .tlsa_lookup(format!("_25._tcp.{}.", envelope.mx))
                        .await
                    {
                        Ok(Some(tlsa)) => {
                            if tlsa.has_end_entities {
                                trc::event!(
                                    Dane(DaneEvent::TlsaRecordFetch),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Hostname = envelope.mx.to_string(),
                                    Details = format!("{tlsa:?}"),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );

                                tlsa.into()
                            } else {
                                trc::event!(
                                    Dane(DaneEvent::TlsaRecordInvalid),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Hostname = envelope.mx.to_string(),
                                    Details = format!("{tlsa:?}"),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );

                                // Report invalid TLSA record
                                if let Some(tls_report) = &tls_report {
                                    server
                                        .schedule_report(TlsEvent {
                                            policy: tlsa.into(),
                                            domain: domain.to_string(),
                                            failure: FailureDetails::new(ResultType::TlsaInvalid)
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_failure_reason_code("Invalid TLSA record.")
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                }

                                if strict {
                                    last_status = Status::PermanentFailure(ErrorDetails {
                                        entity: envelope.mx.into(),
                                        details: Error::DaneError(
                                            "No valid TLSA records were found".into(),
                                        ),
                                    });
                                    continue 'next_host;
                                }
                                None
                            }
                        }
                        Ok(None) => {
                            trc::event!(
                                Dane(DaneEvent::TlsaRecordNotDnssecSigned),
                                SpanId = message.span_id,
                                Domain = domain.to_string(),
                                Hostname = envelope.mx.to_string(),
                                Strict = strict,
                                Elapsed = time.elapsed(),
                            );

                            if strict {
                                // Report DANE required
                                if let Some(tls_report) = &tls_report {
                                    server
                                        .schedule_report(TlsEvent {
                                            policy: PolicyType::Tlsa(None),
                                            domain: domain.to_string(),
                                            failure: FailureDetails::new(ResultType::DaneRequired)
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_failure_reason_code(
                                                    "No TLSA DNSSEC records found.",
                                                )
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                }

                                last_status = Status::PermanentFailure(ErrorDetails {
                                    entity: envelope.mx.into(),
                                    details: Error::DaneError(
                                        "No TLSA DNSSEC records found".into(),
                                    ),
                                });
                                continue 'next_host;
                            }
                            None
                        }
                        Err(err) => {
                            let not_found = matches!(&err, mail_auth::Error::DnsRecordNotFound(_));

                            if not_found {
                                trc::event!(
                                    Dane(DaneEvent::TlsaRecordNotFound),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Hostname = envelope.mx.to_string(),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );
                            } else {
                                trc::event!(
                                    Dane(DaneEvent::TlsaRecordFetchError),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Hostname = envelope.mx.to_string(),
                                    CausedBy = trc::Error::from(err.clone()),
                                    Strict = strict,
                                    Elapsed = time.elapsed(),
                                );
                            }

                            if strict {
                                last_status = if not_found {
                                    // Report DANE required
                                    if let Some(tls_report) = &tls_report {
                                        server
                                            .schedule_report(TlsEvent {
                                                policy: PolicyType::Tlsa(None),
                                                domain: domain.to_string(),
                                                failure: FailureDetails::new(
                                                    ResultType::DaneRequired,
                                                )
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_failure_reason_code(
                                                    "No TLSA records found for MX.",
                                                )
                                                .into(),
                                                tls_record: tls_report.record.clone(),
                                                interval: tls_report.interval,
                                            })
                                            .await;
                                    }

                                    Status::PermanentFailure(ErrorDetails {
                                        entity: envelope.mx.into(),
                                        details: Error::DaneError("No TLSA records found".into()),
                                    })
                                } else {
                                    Status::from_mail_auth_error(envelope.mx, err)
                                };
                                continue 'next_host;
                            }
                            None
                        }
                    }
                } else {
                    None
                };

                // Try each IP address
                'next_ip: for remote_ip in resolve_result.remote_ips {
                    // Throttle remote host
                    envelope.remote_ip = remote_ip;
                    for throttle in &queue_config.outbound_limiters.remote {
                        if let Err(retry_at) = server
                            .is_allowed(throttle, &envelope, message.span_id)
                            .await
                        {
                            trc::event!(
                                Delivery(DeliveryEvent::RateLimitExceeded),
                                SpanId = message.span_id,
                                Id = throttle.id.clone(),
                                RemoteIp = remote_ip,
                            );
                            delivery_results
                                .push(DeliveryResult::rate_limited(rcpt_idxs, retry_at));
                            continue 'next_route;
                        }
                    }

                    // Obtain connection parameters
                    let conn_strategy = server.get_connection_or_default(
                        &server
                            .eval_if::<String, _>(
                                &queue_config.connection,
                                &envelope,
                                message.span_id,
                            )
                            .await
                            .unwrap_or_else(|| "default".to_string()),
                        message.span_id,
                    );

                    // Set source IP, if any
                    let ip_host = conn_strategy.source_ip(remote_ip.is_ipv4());

                    // Connect
                    let time = Instant::now();
                    let mut smtp_client = match if let Some(ip_host) = ip_host {
                        envelope.local_ip = ip_host.ip;
                        SmtpClient::connect_using(
                            ip_host.ip,
                            SocketAddr::new(remote_ip, remote_host.port()),
                            conn_strategy.timeout_connect,
                            span_id,
                        )
                        .await
                    } else {
                        envelope.local_ip = no_ip;
                        SmtpClient::connect(
                            SocketAddr::new(remote_ip, remote_host.port()),
                            conn_strategy.timeout_connect,
                            span_id,
                        )
                        .await
                    } {
                        Ok(smtp_client) => {
                            trc::event!(
                                Delivery(DeliveryEvent::Connect),
                                SpanId = message.span_id,
                                Domain = domain.to_string(),
                                Hostname = envelope.mx.to_string(),
                                LocalIp = envelope.local_ip,
                                RemoteIp = remote_ip,
                                RemotePort = remote_host.port(),
                                Elapsed = time.elapsed(),
                            );

                            smtp_client
                        }
                        Err(err) => {
                            trc::event!(
                                Delivery(DeliveryEvent::ConnectError),
                                SpanId = message.span_id,
                                Domain = domain.to_string(),
                                Hostname = envelope.mx.to_string(),
                                LocalIp = envelope.local_ip,
                                RemoteIp = remote_ip,
                                RemotePort = remote_host.port(),
                                CausedBy = from_mail_send_error(&err),
                                Elapsed = time.elapsed(),
                            );

                            last_status = Status::from_smtp_error(envelope.mx, "", err);
                            continue 'next_ip;
                        }
                    };

                    // Obtain session parameters
                    let local_hostname = ip_host
                        .and_then(|ip| ip.host.as_deref())
                        .or(conn_strategy.ehlo_hostname.as_deref())
                        .unwrap_or(server.core.network.server_name.as_str());
                    let mut params = SessionParams {
                        session_id: message.span_id,
                        server: &server,
                        credentials: remote_host.credentials(),
                        is_smtp: remote_host.is_smtp(),
                        hostname: envelope.mx,
                        local_hostname,
                        conn_strategy,
                        capabilities: None,
                    };

                    // Prepare TLS connector
                    let is_strict_tls = tls_strategy.is_tls_required()
                        || (message.message.flags & MAIL_REQUIRETLS) != 0
                        || mta_sts_policy.is_some()
                        || dane_policy.is_some();
                    // As per RFC7671 Section 5.1, DANE-EE(3) allows name mismatch
                    let tls_connector = if tls_strategy.allow_invalid_certs
                        || remote_host.allow_invalid_certs()
                        || dane_policy.as_ref().is_some_and(|t| t.has_end_entities)
                    {
                        &server.inner.data.smtp_connectors.dummy_verify
                    } else {
                        &server.inner.data.smtp_connectors.pki_verify
                    };

                    if !remote_host.implicit_tls() {
                        // Read greeting
                        smtp_client.timeout = conn_strategy.timeout_greeting;
                        if let Err(status) = smtp_client.read_greeting(envelope.mx).await {
                            trc::event!(
                                Delivery(DeliveryEvent::GreetingFailed),
                                SpanId = message.span_id,
                                Domain = domain.to_string(),
                                Hostname = envelope.mx.to_string(),
                                Details = status.to_string(),
                            );

                            last_status = status;
                            continue 'next_host;
                        }

                        // Say EHLO
                        let time = Instant::now();
                        let capabilities = match smtp_client.say_helo(&params).await {
                            Ok(capabilities) => {
                                trc::event!(
                                    Delivery(DeliveryEvent::Ehlo),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Hostname = envelope.mx.to_string(),
                                    Details = capabilities.capabilities(),
                                    Elapsed = time.elapsed(),
                                );

                                capabilities
                            }
                            Err(status) => {
                                trc::event!(
                                    Delivery(DeliveryEvent::EhloRejected),
                                    SpanId = message.span_id,
                                    Domain = domain.to_string(),
                                    Hostname = envelope.mx.to_string(),
                                    Details = status.to_string(),
                                    Elapsed = time.elapsed(),
                                );

                                last_status = status;
                                continue 'next_host;
                            }
                        };

                        // Try starting TLS
                        if tls_strategy.try_start_tls() {
                            let time = Instant::now();
                            smtp_client.timeout = tls_strategy.timeout_tls;
                            match smtp_client
                                .try_start_tls(tls_connector, envelope.mx, &capabilities)
                                .await
                            {
                                StartTlsResult::Success { smtp_client } => {
                                    trc::event!(
                                        Delivery(DeliveryEvent::StartTls),
                                        SpanId = message.span_id,
                                        Domain = domain.to_string(),
                                        Hostname = envelope.mx.to_string(),
                                        Version = format!(
                                            "{:?}",
                                            smtp_client
                                                .tls_connection()
                                                .protocol_version()
                                                .unwrap()
                                        ),
                                        Details = format!(
                                            "{:?}",
                                            smtp_client
                                                .tls_connection()
                                                .negotiated_cipher_suite()
                                                .unwrap()
                                        ),
                                        Elapsed = time.elapsed(),
                                    );

                                    // Verify DANE
                                    if let Some(dane_policy) = &dane_policy
                                        && let Err(status) = dane_policy.verify(
                                            message.span_id,
                                            envelope.mx,
                                            smtp_client.tls_connection().peer_certificates(),
                                        )
                                    {
                                        // Report DANE verification failure
                                        if let Some(tls_report) = &tls_report {
                                            server
                                                .schedule_report(TlsEvent {
                                                    policy: dane_policy.into(),
                                                    domain: domain.to_string(),
                                                    failure: FailureDetails::new(
                                                        ResultType::ValidationFailure,
                                                    )
                                                    .with_receiving_mx_hostname(envelope.mx)
                                                    .with_receiving_ip(remote_ip)
                                                    .with_failure_reason_code(
                                                        "No matching certificates found.",
                                                    )
                                                    .into(),
                                                    tls_record: tls_report.record.clone(),
                                                    interval: tls_report.interval,
                                                })
                                                .await;
                                        }

                                        last_status = status;
                                        continue 'next_host;
                                    }

                                    // Report TLS success
                                    if let Some(tls_report) = &tls_report {
                                        server
                                            .schedule_report(TlsEvent {
                                                policy: (&mta_sts_policy, &dane_policy).into(),
                                                domain: domain.to_string(),
                                                failure: None,
                                                tls_record: tls_report.record.clone(),
                                                interval: tls_report.interval,
                                            })
                                            .await;
                                    }

                                    // Deliver message over TLS
                                    message
                                        .deliver(
                                            smtp_client,
                                            rcpt_idxs,
                                            &mut delivery_results,
                                            params,
                                        )
                                        .await
                                }
                                StartTlsResult::Unavailable {
                                    response,
                                    smtp_client,
                                } => {
                                    // Report unavailable STARTTLS
                                    let reason =
                                        response.as_ref().map(|r| r.to_string()).unwrap_or_else(
                                            || "STARTTLS was not advertised by host".to_string(),
                                        );

                                    trc::event!(
                                        Delivery(DeliveryEvent::StartTlsUnavailable),
                                        SpanId = message.span_id,
                                        Domain = domain.to_string(),
                                        Hostname = envelope.mx.to_string(),
                                        Code = response.as_ref().map(|r| r.code()),
                                        Details = response
                                            .as_ref()
                                            .map(|r| r.message().as_ref())
                                            .unwrap_or("STARTTLS was not advertised by host")
                                            .to_string(),
                                        Elapsed = time.elapsed(),
                                    );

                                    if let Some(tls_report) = &tls_report {
                                        server
                                            .schedule_report(TlsEvent {
                                                policy: (&mta_sts_policy, &dane_policy).into(),
                                                domain: domain.to_string(),
                                                failure: FailureDetails::new(
                                                    ResultType::StartTlsNotSupported,
                                                )
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_receiving_ip(remote_ip)
                                                .with_failure_reason_code(reason)
                                                .into(),
                                                tls_record: tls_report.record.clone(),
                                                interval: tls_report.interval,
                                            })
                                            .await;
                                    }

                                    if is_strict_tls {
                                        last_status =
                                            Status::from_starttls_error(envelope.mx, response);
                                        continue 'next_host;
                                    } else {
                                        // TLS is not required, proceed in plain-text
                                        params.capabilities = Some(capabilities);
                                        message
                                            .deliver(
                                                smtp_client,
                                                rcpt_idxs,
                                                &mut delivery_results,
                                                params,
                                            )
                                            .await
                                    }
                                }
                                StartTlsResult::Error { error } => {
                                    trc::event!(
                                        Delivery(DeliveryEvent::StartTlsError),
                                        SpanId = message.span_id,
                                        Domain = domain.to_string(),
                                        Hostname = envelope.mx.to_string(),
                                        Reason = from_mail_send_error(&error),
                                        Elapsed = time.elapsed(),
                                    );

                                    // Report TLS failure
                                    if let (Some(tls_report), mail_send::Error::Tls(error)) =
                                        (&tls_report, &error)
                                    {
                                        server
                                            .schedule_report(TlsEvent {
                                                policy: (&mta_sts_policy, &dane_policy).into(),
                                                domain: domain.to_string(),
                                                failure: FailureDetails::new(
                                                    ResultType::CertificateNotTrusted,
                                                )
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_receiving_ip(remote_ip)
                                                .with_failure_reason_code(error.to_string())
                                                .into(),
                                                tls_record: tls_report.record.clone(),
                                                interval: tls_report.interval,
                                            })
                                            .await;
                                    }

                                    last_status = if is_strict_tls {
                                        Status::from_tls_error(envelope.mx, error)
                                    } else {
                                        Status::from_tls_error(envelope.mx, error).into_temporary()
                                    };
                                    continue 'next_host;
                                }
                            }
                        } else {
                            // TLS has been disabled
                            trc::event!(
                                Delivery(DeliveryEvent::StartTlsDisabled),
                                SpanId = message.span_id,
                                Domain = domain.to_string(),
                                Hostname = envelope.mx.to_string(),
                            );

                            message
                                .deliver(smtp_client, rcpt_idxs, &mut delivery_results, params)
                                .await
                        }
                    } else {
                        // Start TLS
                        smtp_client.timeout = tls_strategy.timeout_tls;
                        let mut smtp_client =
                            match smtp_client.into_tls(tls_connector, envelope.mx).await {
                                Ok(smtp_client) => smtp_client,
                                Err(error) => {
                                    trc::event!(
                                        Delivery(DeliveryEvent::ImplicitTlsError),
                                        SpanId = message.span_id,
                                        Domain = domain.to_string(),
                                        Hostname = envelope.mx.to_string(),
                                        Reason = from_mail_send_error(&error),
                                    );

                                    last_status = Status::from_tls_error(envelope.mx, error);
                                    continue 'next_host;
                                }
                            };

                        // Read greeting
                        smtp_client.timeout = conn_strategy.timeout_greeting;
                        if let Err(status) = smtp_client.read_greeting(envelope.mx).await {
                            trc::event!(
                                Delivery(DeliveryEvent::GreetingFailed),
                                SpanId = message.span_id,
                                Domain = domain.to_string(),
                                Hostname = envelope.mx.to_string(),
                                Details = from_error_status(&status),
                            );

                            last_status = status;
                            continue 'next_host;
                        }

                        // Deliver message
                        message
                            .deliver(smtp_client, rcpt_idxs, &mut delivery_results, params)
                            .await
                    }

                    // Continue with the next domain/route
                    continue 'next_route;
                }
            }

            // Update status
            delivery_results.push(DeliveryResult::domain(last_status, rcpt_idxs));
        }

        // Apply status changes
        for delivery_result in delivery_results {
            match delivery_result {
                DeliveryResult::Domain { status, rcpt_idxs } => {
                    for rcpt_idx in rcpt_idxs {
                        message
                            .set_rcpt_status(status.clone(), rcpt_idx, &server)
                            .await;
                    }
                }
                DeliveryResult::Account { status, rcpt_idx } => {
                    message.set_rcpt_status(status, rcpt_idx, &server).await;
                }
                DeliveryResult::RateLimited {
                    rcpt_idxs,
                    retry_at,
                } => {
                    for rcpt_idx in rcpt_idxs {
                        message.set_rcpt_rate_limit(rcpt_idx, retry_at);
                    }
                }
            }
        }

        // Send Delivery Status Notifications
        server.send_dsn(&mut message).await;

        // Notify queue manager
        if message.message.next_event(None).is_some() {
            trc::event!(
                Queue(trc::QueueEvent::Rescheduled),
                SpanId = span_id,
                NextRetry = message
                    .message
                    .next_delivery_event(None)
                    .map(trc::Value::Timestamp),
                NextDsn = message.message.next_dsn(None).map(trc::Value::Timestamp),
                Expires = message.message.expires(None).map(trc::Value::Timestamp),
            );

            // Save changes to disk
            message.save_changes(&server, self.due.into()).await;

            QueueEventStatus::Deferred
        } else {
            trc::event!(
                Delivery(DeliveryEvent::Completed),
                SpanId = span_id,
                Elapsed = trc::Value::Duration((now() - message.message.created) * 1000)
            );

            // Delete message from queue
            message.remove(&server, self.due.into()).await;

            QueueEventStatus::Completed
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDelivery {
    Yes(bool),
    No,
}

impl MessageWrapper {
    /// Marks as failed all domains that reached their expiration time
    pub fn has_pending_delivery(&mut self) -> PendingDelivery {
        let now = now();
        let mut has_pending_delivery = false;
        let mut matches_queue = false;

        for rcpt in self.message.recipients.iter_mut() {
            match &rcpt.status {
                Status::TemporaryFailure(err) if rcpt.is_expired(self.message.created, now) => {
                    trc::event!(
                        Delivery(DeliveryEvent::Failed),
                        SpanId = self.span_id,
                        QueueId = self.queue_id,
                        QueueName = self.queue_name.as_str().to_string(),
                        To = rcpt.address().to_string(),
                        Reason = from_error_details(&err.details),
                        Details = trc::Value::Timestamp(now),
                        Expires = rcpt
                            .expiration_time(self.message.created)
                            .map(trc::Value::Timestamp),
                        NextRetry = trc::Value::Timestamp(rcpt.retry.due),
                        NextDsn = trc::Value::Timestamp(rcpt.notify.due),
                    );

                    rcpt.status =
                        std::mem::replace(&mut rcpt.status, Status::Scheduled).into_permanent();
                }
                Status::Scheduled if rcpt.is_expired(self.message.created, now) => {
                    trc::event!(
                        Delivery(DeliveryEvent::Failed),
                        SpanId = self.span_id,
                        QueueId = self.queue_id,
                        QueueName = self.queue_name.as_str().to_string(),
                        To = rcpt.address().to_string(),
                        Reason = "Message expired without any delivery attempts made.",
                        Details = trc::Value::Timestamp(now),
                        Expires = rcpt
                            .expiration_time(self.message.created)
                            .map(trc::Value::Timestamp),
                        NextRetry = trc::Value::Timestamp(rcpt.retry.due),
                        NextDsn = trc::Value::Timestamp(rcpt.notify.due),
                    );

                    rcpt.status = Status::PermanentFailure(ErrorDetails {
                        entity: rcpt.domain_part().into(),
                        details: Error::Io(
                            "Message expired without any delivery attempts made.".into(),
                        ),
                    });
                }
                Status::Completed(_) | Status::PermanentFailure(_) => (),
                _ => {
                    has_pending_delivery = true;
                    matches_queue = matches_queue || rcpt.queue == self.queue_name;
                }
            }
        }

        if has_pending_delivery {
            PendingDelivery::Yes(matches_queue)
        } else {
            PendingDelivery::No
        }
    }

    pub async fn set_rcpt_status(
        &mut self,
        status: Status<HostResponse<Box<str>>, ErrorDetails>,
        rcpt_idx: usize,
        server: &Server,
    ) {
        let needs_retry = matches!(&status, Status::TemporaryFailure(_) | Status::Scheduled);
        self.message.recipients[rcpt_idx].status = status;

        if needs_retry {
            let envelope = QueueEnvelope::new(&self.message, &self.message.recipients[rcpt_idx]);
            let queue = server.get_queue_or_default(
                &server
                    .eval_if::<String, _>(&server.core.smtp.queue.queue, &envelope, self.span_id)
                    .await
                    .unwrap_or_else(|| "default".to_string()),
                self.span_id,
            );
            let rcpt = &mut self.message.recipients[rcpt_idx];
            rcpt.retry.due = now()
                + queue.retry[std::cmp::min(rcpt.retry.inner as usize, queue.retry.len() - 1)];
            rcpt.retry.inner += 1;
            rcpt.expires = queue.expiry;
            rcpt.queue = queue.virtual_queue;
        }
    }

    pub fn set_rcpt_rate_limit(&mut self, rcpt_idx: usize, retry_at: u64) {
        let rcpt = &mut self.message.recipients[rcpt_idx];
        rcpt.retry.due = retry_at;
        rcpt.status = Status::TemporaryFailure(ErrorDetails {
            entity: "localhost".into(),
            details: Error::RateLimited,
        });
    }
}
