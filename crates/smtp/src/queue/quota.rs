/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{QueueEnvelope, QuotaKey, Status};
use crate::{core::throttle::NewKey, queue::MessageWrapper};
use ahash::AHashSet;
use common::{Server, config::smtp::queue::QueueQuota, expr::functions::ResolveVariable};
use std::future::Future;
use store::{
    ValueKey,
    write::{BatchBuilder, QueueClass, ValueClass},
};
use trc::QueueEvent;
use utils::DomainPart;

pub trait HasQueueQuota: Sync + Send {
    fn has_quota(&self, message: &mut MessageWrapper) -> impl Future<Output = bool> + Send;
    fn check_quota<'x>(
        &'x self,
        quota: &'x QueueQuota,
        envelope: &impl ResolveVariable,
        size: u64,
        id: u64,
        refs: &mut Vec<QuotaKey>,
        session_id: u64,
    ) -> impl Future<Output = bool> + Send;
}

impl HasQueueQuota for Server {
    async fn has_quota(&self, message: &mut MessageWrapper) -> bool {
        let mut quota_keys = Vec::new();

        if !self.core.smtp.queue.quota.sender.is_empty() {
            for quota in &self.core.smtp.queue.quota.sender {
                if !self
                    .check_quota(
                        quota,
                        &message.message,
                        message.message.size,
                        0,
                        &mut quota_keys,
                        message.span_id,
                    )
                    .await
                {
                    trc::event!(
                        Queue(QueueEvent::QuotaExceeded),
                        SpanId = message.span_id,
                        Id = quota.id.clone(),
                        Type = "Sender"
                    );

                    return false;
                }
            }
        }

        if !self.core.smtp.queue.quota.rcpt_domain.is_empty() {
            let mut seen_domains = AHashSet::new();
            for quota in &self.core.smtp.queue.quota.rcpt_domain {
                for (rcpt_idx, rcpt) in message.message.recipients.iter().enumerate() {
                    if seen_domains.insert(rcpt.address.domain_part())
                        && !self
                            .check_quota(
                                quota,
                                &QueueEnvelope::new(&message.message, rcpt),
                                message.message.size,
                                ((rcpt_idx + 1) << 32) as u64,
                                &mut quota_keys,
                                message.span_id,
                            )
                            .await
                    {
                        trc::event!(
                            Queue(QueueEvent::QuotaExceeded),
                            SpanId = message.span_id,
                            Id = quota.id.clone(),
                            Type = "Domain"
                        );

                        return false;
                    }
                }
            }
        }

        for quota in &self.core.smtp.queue.quota.rcpt {
            for (rcpt_idx, rcpt) in message.message.recipients.iter().enumerate() {
                if !self
                    .check_quota(
                        quota,
                        &QueueEnvelope::new(&message.message, rcpt),
                        message.message.size,
                        (rcpt_idx + 1) as u64,
                        &mut quota_keys,
                        message.span_id,
                    )
                    .await
                {
                    trc::event!(
                        Queue(QueueEvent::QuotaExceeded),
                        SpanId = message.span_id,
                        Id = quota.id.clone(),
                        Type = "Recipient"
                    );

                    return false;
                }
            }
        }

        message.message.quota_keys = quota_keys.into_boxed_slice();

        true
    }

    async fn check_quota<'x>(
        &'x self,
        quota: &'x QueueQuota,
        envelope: &impl ResolveVariable,
        size: u64,
        id: u64,
        refs: &mut Vec<QuotaKey>,
        session_id: u64,
    ) -> bool {
        if !quota.expr.is_empty()
            && self
                .eval_expr(&quota.expr, envelope, "check_quota", session_id)
                .await
                .unwrap_or(false)
        {
            let key = quota.new_key(envelope, "");
            if let Some(max_size) = quota.size {
                let used_size = self
                    .core
                    .storage
                    .data
                    .get_counter(ValueKey::from(ValueClass::Queue(QueueClass::QuotaSize(
                        key.as_ref().to_vec(),
                    ))))
                    .await
                    .unwrap_or(0) as u64;
                if used_size + size > max_size {
                    return false;
                } else {
                    refs.push(QuotaKey::Size {
                        key: key.as_ref().into(),
                        id,
                    });
                }
            }

            if let Some(max_messages) = quota.messages {
                let total_messages = self
                    .core
                    .storage
                    .data
                    .get_counter(ValueKey::from(ValueClass::Queue(QueueClass::QuotaCount(
                        key.as_ref().to_vec(),
                    ))))
                    .await
                    .unwrap_or(0) as u64;
                if total_messages + 1 > max_messages {
                    return false;
                } else {
                    refs.push(QuotaKey::Count {
                        key: key.as_ref().into(),
                        id,
                    });
                }
            }
        }
        true
    }
}

impl MessageWrapper {
    pub fn release_quota(&mut self, batch: &mut BatchBuilder) {
        if self.message.quota_keys.is_empty() {
            return;
        }
        let mut quota_ids = Vec::with_capacity(self.message.recipients.len());

        let mut seen_domains = AHashSet::new();
        for (pos, rcpt) in self.message.recipients.iter().enumerate() {
            if matches!(
                &rcpt.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                if seen_domains.insert(rcpt.address.domain_part()) {
                    quota_ids.push(((pos + 1) as u64) << 32);
                }
                quota_ids.push((pos + 1) as u64);
            }
        }

        if !quota_ids.is_empty() {
            let mut quota_keys = Vec::new();
            for quota_key in std::mem::take(&mut self.message.quota_keys) {
                match quota_key {
                    QuotaKey::Count { id, key } if quota_ids.contains(&id) => {
                        batch.add(
                            ValueClass::Queue(QueueClass::QuotaCount(key.into_vec())),
                            -1,
                        );
                    }
                    QuotaKey::Size { id, key } if quota_ids.contains(&id) => {
                        batch.add(
                            ValueClass::Queue(QueueClass::QuotaSize(key.into_vec())),
                            -(self.message.size as i64),
                        );
                    }
                    _ => {
                        quota_keys.push(quota_key);
                    }
                }
            }
            self.message.quota_keys = quota_keys.into_boxed_slice();
        }
    }
}
