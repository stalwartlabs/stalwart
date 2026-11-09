/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Metadata, QueueEnvelope, Status};
use crate::{core::throttle::NewKey, queue::MessageWrapper};
use ahash::AHashSet;
use common::{
    Server,
    config::smtp::queue::QueueQuota,
    expr::{Bump, functions::ResolveVariable},
};
use std::future::Future;
use store::write::{BatchBuilder, QueueClass, QueueCounter, ValueClass};
use utils::DomainPart;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaReservation {
    Size { key: u128, id: u64, max: u64 },
    Count { key: u128, id: u64, max: u64 },
}

pub trait HasQueueQuota: Sync + Send {
    fn queue_quotas(
        &self,
        message: &MessageWrapper,
    ) -> impl Future<Output = Vec<QuotaReservation>> + Send;
}

impl HasQueueQuota for Server {
    async fn queue_quotas(&self, message: &MessageWrapper) -> Vec<QuotaReservation> {
        let quotas = &self.core.smtp.queue.quota;
        let mut reservations = Vec::new();
        let mut arena = Bump::new();

        for quota in &quotas.sender {
            if matches_quota(self, quota, &message.message, &mut arena, message.span_id).await {
                push_reservations(quota, &message.message, 0, &mut reservations);
            }
        }

        if !quotas.rcpt_domain.is_empty() {
            let mut seen_domains = AHashSet::new();
            for quota in &quotas.rcpt_domain {
                seen_domains.clear();
                for (rcpt_idx, rcpt) in message.message.recipients.iter().enumerate() {
                    if seen_domains.insert(rcpt.address.domain_part()) {
                        let envelope = QueueEnvelope::new(&message.message, rcpt);
                        if matches_quota(self, quota, &envelope, &mut arena, message.span_id).await
                        {
                            push_reservations(
                                quota,
                                &envelope,
                                ((rcpt_idx + 1) as u64) << 32,
                                &mut reservations,
                            );
                        }
                    }
                }
            }
        }

        for quota in &quotas.rcpt {
            for (rcpt_idx, rcpt) in message.message.recipients.iter().enumerate() {
                let envelope = QueueEnvelope::new(&message.message, rcpt);
                if matches_quota(self, quota, &envelope, &mut arena, message.span_id).await {
                    push_reservations(quota, &envelope, (rcpt_idx + 1) as u64, &mut reservations);
                }
            }
        }

        reservations
    }
}

async fn matches_quota(
    server: &Server,
    quota: &QueueQuota,
    envelope: &impl ResolveVariable,
    arena: &mut Bump,
    session_id: u64,
) -> bool {
    if quota.expr.is_empty() {
        return true;
    }
    arena.reset();
    server
        .eval_if(&quota.expr, envelope, arena, session_id)
        .await
        .unwrap_or(false)
}

fn push_reservations(
    quota: &QueueQuota,
    envelope: &impl ResolveVariable,
    id: u64,
    reservations: &mut Vec<QuotaReservation>,
) {
    let key = quota.new_key(envelope, "").quota_key();
    if let Some(max) = quota.size {
        reservations.push(QuotaReservation::Size { key, id, max });
    }
    if let Some(max) = quota.messages {
        reservations.push(QuotaReservation::Count { key, id, max });
    }
}

impl QuotaReservation {
    pub fn metadata(&self) -> Metadata {
        match *self {
            QuotaReservation::Size { key, id, .. } => Metadata::QueueSize { key, id },
            QuotaReservation::Count { key, id, .. } => Metadata::QueueCount { key, id },
        }
    }

    pub fn reserve(&self, batch: &mut BatchBuilder, size: u64) {
        match *self {
            QuotaReservation::Size { key, max, .. } => {
                let key = key.into();
                batch.limit_queue_counter(QueueCounter::Size(key), max).add(
                    ValueClass::Queue(QueueClass::QuotaSize(key)),
                    i64::try_from(size).unwrap_or(i64::MAX),
                );
            }
            QuotaReservation::Count { key, max, .. } => {
                let key = key.into();
                batch
                    .limit_queue_counter(QueueCounter::Count(key), max)
                    .add(ValueClass::Queue(QueueClass::QuotaCount(key)), 1);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct ReleasedQuota {
    ids: Vec<u64>,
    entries: Vec<Metadata>,
    queued_bytes: u64,
}

impl ReleasedQuota {
    pub fn ids(&self) -> &[u64] {
        &self.ids
    }

    pub fn has_entries(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn write(&self, batch: &mut BatchBuilder) {
        for entry in &self.entries {
            match entry {
                Metadata::QueueCount { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount((*key).into())), -1);
                }
                Metadata::QueueSize { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize((*key).into())),
                        -(self.queued_bytes as i64),
                    );
                }
                Metadata::Headers { .. } | Metadata::Submission { .. } | Metadata::Blob(_) => {}
            }
        }
    }

    pub fn is_pending(&self, metadata: &[Metadata]) -> bool {
        metadata.iter().any(|current| match current {
            Metadata::QueueCount { id, key } | Metadata::QueueSize { id, key } => {
                self.entries.iter().any(|entry| {
                    matches!(entry, Metadata::QueueCount { id: rid, key: rkey }
                        | Metadata::QueueSize { id: rid, key: rkey } if rid == id && rkey == key)
                })
            }
            _ => false,
        })
    }
}

impl MessageWrapper {
    pub fn release_quota(&mut self, batch: &mut BatchBuilder) -> Vec<u64> {
        let released = self.take_released_quota();
        released.write(batch);
        released.ids
    }

    pub fn take_released_quota(&mut self) -> ReleasedQuota {
        if !self.message.metadata.iter().any(|metadata| {
            matches!(
                metadata,
                Metadata::QueueSize { .. } | Metadata::QueueCount { .. }
            )
        }) {
            return ReleasedQuota::default();
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

        let mut entries = Vec::new();
        if !quota_ids.is_empty() {
            quota_ids.sort_unstable();
            let mut metadata = Vec::new();
            for entry in std::mem::take(&mut self.message.metadata) {
                match entry {
                    Metadata::QueueCount { id, .. } | Metadata::QueueSize { id, .. }
                        if quota_ids.binary_search(&id).is_ok() =>
                    {
                        entries.push(entry);
                    }
                    _ => {
                        metadata.push(entry);
                    }
                }
            }
            self.message.metadata = metadata.into_boxed_slice();
        }

        let queued_bytes = if entries.is_empty() {
            0
        } else {
            self.message.queued_bytes()
        };
        ReleasedQuota {
            ids: quota_ids,
            entries,
            queued_bytes,
        }
    }
}
