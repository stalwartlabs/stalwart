/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedMessage, ArchivedStatus, Message, MessageSource, Metadata, QueueEnvelope, QueueId,
    Recipient, Schedule, eval_strategy,
};
use crate::inbound::dkim::{DkimSign, SignedMessage};
use crate::queue::encrypt::{OutboundEncryption, QueueEncryption};
use crate::queue::quota::QuotaReservation;
use crate::queue::{FROM_DKIM2_SIGNED, MessageWrapper};
use ahash::{AHashMap, AHashSet};
use common::config::smtp::auth::DkimSigners;
use common::config::smtp::queue::{ArchivedQueueExpiry, QueueName};
use common::ipc::{BroadcastEvent, QueueEvent, QueueRefresh, QueuedEvent, QueuedEvents};
use common::network::RcptResolution;
use common::{KV_LOCK_QUEUE_MESSAGE, Server, expr::Bump};
use compact_str::{CompactString, ToCompactString};
use mail_auth::{AuthenticatedMessage, dkim2::Dkim2Output};
use registry::schema::prelude::{ObjectType, Property};
use registry::schema::structs::SpamTrainingSample;
use registry::types::datetime::UTCDateTime;
use registry::types::id::ObjectId;
use registry::types::{EnumImpl, ObjectImpl};
use std::borrow::Cow;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::SystemTime;
use store::write::{
    Archive, ArchiveBytes, ArchiveVersion, Archiver, AssignedIds, BatchBuilder, BlobLink, BlobOp,
    MergeResult, QueueClass, RegistryClass, ValueClass, assert::AssertValue, blob::BlobLinkValue,
    now,
};
use store::{Deserialize, Serialize, SerializeInfallible, ValueKey};
use trc::{AddContext, EventType, LimitEvent, ServerEvent, SpamEvent};
use types::blob::BlobId;
use types::blob_hash::BlobHash;
use utils::DomainPart;

pub const LOCK_EXPIRY: u64 = 10 * 60; // 10 minutes
pub const QUEUE_REFRESH: u64 = 5 * 60; // 5 minutes
pub const DSN_RETRY: u64 = 5 * 60; // 5 minutes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueOutcome {
    Queued,
    QuotaExceeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryWrite {
    Written,
    Locked,
    Changed,
    Failed,
}

struct LockedWrite {
    queue_id: QueueId,
    span_id: u64,
    queues: Vec<QueueName>,
    batch: BatchBuilder,
}

pub trait SmtpSpool: Sync + Send {
    fn new_message(
        &self,
        return_path: impl AsRef<str>,
        source: MessageSource,
        span_id: u64,
    ) -> MessageWrapper;

    fn try_lock_event(
        &self,
        queue_id: QueueId,
        queue_name: QueueName,
    ) -> impl Future<Output = bool> + Send;

    fn unlock_event(
        &self,
        queue_id: QueueId,
        queue_name: QueueName,
    ) -> impl Future<Output = ()> + Send;

    fn read_message(
        &self,
        id: QueueId,
        queue_name: QueueName,
    ) -> impl Future<Output = trc::Result<Option<MessageWrapper>>> + Send;

    fn read_message_versioned(
        &self,
        id: QueueId,
        queue_name: QueueName,
    ) -> impl Future<Output = Option<(MessageWrapper, ArchiveVersion)>> + Send;

    fn read_message_archive(
        &self,
        id: QueueId,
    ) -> impl Future<Output = trc::Result<Option<Archive<ArchiveBytes>>>> + Send;
}

impl SmtpSpool for Server {
    fn new_message(
        &self,
        return_path: impl AsRef<str>,
        source: MessageSource,
        span_id: u64,
    ) -> MessageWrapper {
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        MessageWrapper {
            queue_id: self.inner.data.queue_id_gen.generate(),
            queue_name: QueueName::default(),
            is_multi_queue: false,
            span_id,
            message: Message {
                created,
                return_path: return_path.to_lowercase_address(false).into_boxed_str(),
                recipients: Vec::with_capacity(1),
                flags: source.flags(),
                env_id: None,
                priority: 0,
                size: 0,
                blob_hash: Default::default(),
                metadata: Default::default(),
                received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                received_via_port: 0,
                // SPDX-SnippetBegin
                // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                // SPDX-License-Identifier: LicenseRef-SEL
                #[cfg(feature = "enterprise")]
                tenant_ids: Default::default(),
                // SPDX-SnippetEnd
            },
        }
    }

    async fn try_lock_event(&self, queue_id: QueueId, queue_name: QueueName) -> bool {
        match self
            .in_memory_store()
            .try_lock(
                KV_LOCK_QUEUE_MESSAGE,
                &lock_id(queue_id, queue_name),
                LOCK_EXPIRY,
            )
            .await
        {
            Ok(result) => {
                if !result {
                    trc::event!(
                        Queue(trc::QueueEvent::Locked),
                        QueueId = queue_id,
                        QueueName = queue_name.to_compact_string()
                    );
                }
                result
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to lock event.")
                        .caused_by(trc::location!())
                );
                false
            }
        }
    }

    async fn unlock_event(&self, queue_id: QueueId, queue_name: QueueName) {
        if let Err(err) = self
            .in_memory_store()
            .remove_lock(KV_LOCK_QUEUE_MESSAGE, &lock_id(queue_id, queue_name))
            .await
        {
            trc::error!(
                err.details("Failed to unlock event.")
                    .caused_by(trc::location!())
            );
        }
    }

    async fn read_message(
        &self,
        queue_id: QueueId,
        queue_name: QueueName,
    ) -> trc::Result<Option<MessageWrapper>> {
        match self.read_message_archive(queue_id).await? {
            Some(archive) => archive
                .deserialize::<Message>()
                .map(|message| Some(MessageWrapper::new(message, queue_id, queue_name))),
            None => Ok(None),
        }
    }

    async fn read_message_versioned(
        &self,
        queue_id: QueueId,
        queue_name: QueueName,
    ) -> Option<(MessageWrapper, ArchiveVersion)> {
        match self
            .read_message_archive(queue_id)
            .await
            .and_then(|a| match a {
                Some(a) => a
                    .deserialize::<Message>()
                    .map(|message| Some((message, a.version))),
                None => Ok(None),
            }) {
            Ok(Some((message, version))) => {
                Some((MessageWrapper::new(message, queue_id, queue_name), version))
            }
            Ok(None) => None,
            Err(err) => {
                trc::error!(
                    err.details("Failed to read message.")
                        .caused_by(trc::location!())
                );

                None
            }
        }
    }

    async fn read_message_archive(
        &self,
        id: QueueId,
    ) -> trc::Result<Option<Archive<ArchiveBytes>>> {
        self.store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(id),
            )))
            .await
    }
}

impl MessageWrapper {
    pub fn new(message: Message, queue_id: QueueId, queue_name: QueueName) -> Self {
        MessageWrapper {
            is_multi_queue: message
                .recipients
                .iter()
                .any(|rcpt| rcpt.queue != queue_name),
            queue_id,
            queue_name,
            span_id: 0,
            message,
        }
    }

    fn event_class(&self, queue_name: QueueName, due: u64) -> ValueClass {
        ValueClass::Queue(QueueClass::MessageEvent(store::write::QueueEvent {
            due,
            queue_id: self.queue_id,
            queue_name: queue_name.into_inner(),
        }))
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    fn tenant_classes(&self) -> impl Iterator<Item = ValueClass> + '_ {
        let queue_id = self.queue_id;
        self.message.tenant_ids.iter().map(move |&tenant_id| {
            ValueClass::Queue(QueueClass::TenantMessage {
                tenant_id,
                queue_id,
            })
        })
    }
    // SPDX-SnippetEnd
}

impl LockedWrite {
    fn new(queue_id: QueueId, span_id: u64, message: &Message) -> Self {
        let mut queues = Vec::with_capacity(1);
        for rcpt in &message.recipients {
            if !queues.contains(&rcpt.queue) {
                queues.push(rcpt.queue);
            }
        }

        LockedWrite {
            queue_id,
            span_id,
            queues,
            batch: BatchBuilder::new(),
        }
    }

    async fn commit(self, server: &Server) -> RegistryWrite {
        let span_id = self.span_id;
        tokio::spawn(self.write(server.clone()))
            .await
            .unwrap_or_else(|err| {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Reason = err.to_string(),
                    CausedBy = trc::location!(),
                    SpanId = span_id,
                );
                RegistryWrite::Failed
            })
    }

    async fn write(mut self, server: Server) -> RegistryWrite {
        let mut locked = 0;
        let mut status = None;
        for queue_name in &self.queues {
            match server
                .in_memory_store()
                .try_lock(
                    KV_LOCK_QUEUE_MESSAGE,
                    &lock_id(self.queue_id, *queue_name),
                    LOCK_EXPIRY,
                )
                .await
            {
                Ok(true) => locked += 1,
                Ok(false) => {
                    status = Some(RegistryWrite::Locked);
                    break;
                }
                Err(err) => {
                    trc::error!(
                        err.details("Failed to lock queued message.")
                            .ctx(trc::Key::QueueId, self.queue_id)
                            .span_id(self.span_id)
                            .caused_by(trc::location!())
                    );
                    status = Some(RegistryWrite::Failed);
                    break;
                }
            }
        }

        let status = match status {
            Some(status) => status,
            None => RegistryWrite::from_result(
                server.store().write_batch(&mut self.batch).await,
                self.span_id,
            ),
        };

        for queue_name in self.queues.iter().take(locked) {
            server.unlock_event(self.queue_id, *queue_name).await;
        }

        status
    }
}

impl RegistryWrite {
    pub fn failure(self, failed: &'static str) -> Option<&'static str> {
        match self {
            RegistryWrite::Written => None,
            RegistryWrite::Locked => {
                Some("The message is being delivered or modified, retry later.")
            }
            RegistryWrite::Changed => {
                Some("The message was modified during the update, retry later.")
            }
            RegistryWrite::Failed => Some(failed),
        }
    }

    fn from_result(result: trc::Result<AssignedIds>, span_id: u64) -> Self {
        match result {
            Ok(_) => RegistryWrite::Written,
            Err(err) if err.is_assertion_failure() => RegistryWrite::Changed,
            Err(err) => {
                trc::error!(
                    err.details("Failed to update queued message.")
                        .span_id(span_id)
                        .caused_by(trc::location!())
                );
                RegistryWrite::Failed
            }
        }
    }
}

fn lock_id(queue_id: QueueId, queue_name: QueueName) -> [u8; 16] {
    let mut id = [0; 16];
    id[..8].copy_from_slice(&queue_id.to_be_bytes());
    id[8..].copy_from_slice(queue_name.as_ref());
    id
}

pub(crate) struct QueueParams<'x, 'y> {
    pub raw_message: &'x [u8],
    pub raw_headers: Option<&'x [u8]>,
    pub metadata: Vec<Metadata>,
    pub encrypted_recipients: Vec<u64>,
    pub dkim2_signed: bool,
    pub quotas: Vec<QuotaReservation>,
    pub original_raw_message: Option<&'x [u8]>,
    pub original_authenticated_message: Option<&'x AuthenticatedMessage<'x>>,
    pub dkim2_verified: Option<&'x Dkim2Output<'x>>,
    pub exploded: bool,
    pub dkim1_only: bool,
    pub dkim_signers: Option<Arc<DkimSigners>>,
    pub session_id: u64,
    pub server: &'y Server,
    pub train_spam: Option<(bool, String)>,
}

impl MessageWrapper {
    #[must_use]
    pub(crate) async fn queue<'x, 'y>(mut self, mut params: QueueParams<'x, 'y>) -> QueueOutcome {
        // Encrypt and sign the copies of recipients with a known key
        let mut encryption = if params.server.core.email.gateway_outbound_enabled() {
            match Box::pin(params.server.encrypt_recipients(&self, &params)).await {
                Ok(encryption) => {
                    params.encrypted_recipients =
                        encryption.blobs.iter().map(|blob| blob.rcpt_idx).collect();
                    encryption
                }
                Err(err) => {
                    trc::error!(
                        err.details("Failed to prepare encrypted copies.")
                            .span_id(params.session_id)
                            .caused_by(trc::location!())
                    );
                    return QueueOutcome::Failed;
                }
            }
        } else {
            QueueEncryption::default()
        };

        // Add DKIM signatures
        let SignedMessage {
            headers: dkim_headers,
            dkim2_signed,
            stripped_message,
        } = if encryption.covers(self.message.recipients.len()) && !params.signs_dkim2() {
            SignedMessage::default()
        } else {
            params.server.sign_message(&mut self, &mut params).await
        };
        if dkim2_signed || encryption.dkim2_signed {
            self.message.flags |= FROM_DKIM2_SIGNED;
        }

        // Fetch params
        let QueueParams {
            raw_message,
            raw_headers,
            session_id,
            server,
            train_spam,
            mut metadata,
            quotas,
            ..
        } = params;
        let event = self.message.queued_event();

        // Write blob
        if let Some(stripped_message) = &stripped_message {
            self.message.size = self
                .message
                .size
                .saturating_sub(raw_message.len().saturating_sub(stripped_message.len()) as u64);
        }
        let raw_message = stripped_message.as_deref().unwrap_or(raw_message);
        let raw_headers = raw_headers.unwrap_or_default();
        let message = if !raw_headers.is_empty() || !dkim_headers.is_empty() {
            let mut message =
                Vec::with_capacity(raw_headers.len() + dkim_headers.len() + raw_message.len());
            message.extend_from_slice(&dkim_headers);
            message.extend_from_slice(raw_headers);
            message.extend_from_slice(raw_message);
            Cow::Owned(message)
        } else if let Some(stripped_message) = stripped_message {
            Cow::Owned(stripped_message)
        } else {
            raw_message.into()
        };
        self.message.blob_hash = BlobHash::generate(message.as_ref());
        let blob_size = message.len();

        // Update size
        if self.message.size == 0 {
            self.message.size = message.len() as u64;
        }
        metadata.extend(quotas.iter().map(QuotaReservation::metadata));
        let reserved_until = encryption.reserved_until;
        if !encryption.blobs.is_empty() {
            metadata.extend(
                encryption
                    .blobs
                    .into_iter()
                    .map(|blob| Metadata::Blob(Box::new(blob))),
            );
        }
        self.message.metadata = metadata.into_boxed_slice();

        // Reserve and write blob
        let mut batch = BatchBuilder::new();
        let now = now();
        let reserve_until = now + 120;
        batch.set(
            BlobOp::Link {
                hash: self.message.blob_hash.clone(),
                to: BlobLink::Temporary {
                    until: reserve_until,
                },
            },
            BlobLinkValue::new(blob_size),
        );
        encryption.pending.link(&mut batch, reserved_until);
        if let Err(err) = server.store().write_batch(&mut batch).await {
            trc::error!(
                err.details("Failed to write to store.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return QueueOutcome::Failed;
        }
        let blobs_written = match server
            .blob_store()
            .put_blob(
                self.message.blob_hash.as_slice(),
                message.as_ref(),
                &server.core.blob.email,
            )
            .await
        {
            Ok(()) => encryption.pending.put(server).await,
            Err(err) => Err(err),
        };
        if let Err(err) = blobs_written {
            trc::error!(
                err.details("Failed to write blob.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return QueueOutcome::Failed;
        }

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        self.message.assign_tenants(server, session_id).await;
        // SPDX-SnippetEnd

        // Write message to queue
        let mut batch = BatchBuilder::new();

        // Reserve quotas
        let queued_bytes = self.message.queued_bytes();
        for quota in &quotas {
            quota.reserve(&mut batch, queued_bytes);
        }

        let mut events = QueuedEvents::new();
        for (queue_name, due) in self.message.next_events() {
            batch.set(self.event_class(queue_name, due), Vec::new());
            events.push(QueuedEvent {
                queue_name,
                due,
                queue_id: self.queue_id,
            });
        }
        if !encryption.rejected.is_empty() {
            self.reject_recipients(&encryption.rejected);
        }
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        for class in self.tenant_classes() {
            batch.set(class, Vec::new());
        }
        // SPDX-SnippetEnd

        if let Some((is_spam, subject)) = train_spam
            && let Some(config) = &server.core.spam.classifier
        {
            let hold_period = now + config.hold_samples_for;
            let sample = SpamTrainingSample {
                account_id: None,
                blob_id: BlobId::new(self.message.blob_hash.clone(), Default::default()),
                delete_after_use: false,
                expires_at: UTCDateTime::from_timestamp(hold_period as i64),
                from: self.message.return_path.to_string(),
                is_spam,
                subject,
            }
            .to_pickled_vec();

            let object_id = ObjectType::SpamTrainingSample.to_id();
            let item_id = server.inner.data.registry_id_gen.generate();
            batch
                .set(
                    BlobOp::Link {
                        hash: self.message.blob_hash.clone(),
                        to: BlobLink::Temporary { until: hold_period },
                    },
                    BlobLinkValue::new(blob_size).with_object_id(ObjectId::new(
                        ObjectType::SpamTrainingSample,
                        item_id.into(),
                    )),
                )
                .set(
                    ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                    sample,
                )
                .set(
                    ValueClass::Registry(RegistryClass::Index {
                        index_id: Property::AccountId.to_id(),
                        object_id,
                        item_id,
                        key: (u32::MAX as u64).serialize(),
                    }),
                    vec![],
                );

            trc::event!(
                Spam(SpamEvent::TrainSampleAdded),
                Details = if is_spam { "spam" } else { "ham" },
                Expires = trc::Value::Timestamp(hold_period),
                SpanId = self.span_id,
            );
        }

        let archiver = Archiver::new(self.message);
        let serialized = match archiver.serialize() {
            Ok(data) => data,
            Err(err) => {
                trc::error!(
                    err.details("Failed to serialize message.")
                        .span_id(session_id)
                        .caused_by(trc::location!())
                );
                return QueueOutcome::Failed;
            }
        };
        self.message = archiver.into_inner();

        for blob in self.message.recipient_blobs() {
            batch
                .clear(BlobOp::Link {
                    hash: blob.hash.clone(),
                    to: BlobLink::Temporary {
                        until: reserved_until,
                    },
                })
                .set(
                    BlobOp::Link {
                        hash: blob.hash.clone(),
                        to: BlobLink::Id { id: self.queue_id },
                    },
                    BlobLinkValue::new(blob.size as usize),
                )
                .set(
                    BlobOp::Commit {
                        hash: blob.hash.clone(),
                    },
                    vec![],
                );
        }
        batch
            .clear(BlobOp::Link {
                hash: self.message.blob_hash.clone(),
                to: BlobLink::Temporary {
                    until: reserve_until,
                },
            })
            .set(
                BlobOp::Link {
                    hash: self.message.blob_hash.clone(),
                    to: BlobLink::Id { id: self.queue_id },
                },
                BlobLinkValue::new(blob_size),
            )
            .set(
                BlobOp::Commit {
                    hash: self.message.blob_hash.clone(),
                },
                vec![],
            )
            .set(
                ValueClass::Queue(QueueClass::Message(self.queue_id)),
                serialized,
            );

        if let Err(err) = server.store().write_batch(&mut batch).await {
            if err.matches(EventType::Limit(LimitEvent::Quota)) {
                trc::event!(
                    Queue(trc::QueueEvent::QuotaExceeded),
                    SpanId = session_id,
                    QueueId = self.queue_id,
                    From = trc::Value::String(self.message.return_path.as_ref().into()),
                    To = self
                        .message
                        .recipients
                        .iter()
                        .map(|r| trc::Value::String(r.address.as_ref().into()))
                        .collect::<Vec<_>>(),
                    CausedBy = err
                );

                return QueueOutcome::QuotaExceeded;
            }

            trc::error!(
                err.details("Failed to write to store.")
                    .span_id(session_id)
                    .caused_by(trc::location!())
            );

            return QueueOutcome::Failed;
        }

        trc::event!(
            Queue(event),
            SpanId = session_id,
            QueueId = self.queue_id,
            From = if !self.message.return_path.is_empty() {
                trc::Value::String(self.message.return_path.as_ref().into())
            } else {
                trc::Value::String("<>".into())
            },
            To = self
                .message
                .recipients
                .iter()
                .map(|r| trc::Value::String(r.address.as_ref().into()))
                .collect::<Vec<_>>(),
            Size = self.message.size,
            NextRetry = self
                .message
                .next_delivery_event(None)
                .map(trc::Value::Timestamp),
            NextDsn = self.message.next_dsn(None).map(trc::Value::Timestamp),
            Expires = self.message.expires(None).map(trc::Value::Timestamp),
        );

        // Queue the message
        let queues = server
            .inner
            .ipc
            .broadcast_tx
            .is_some()
            .then(|| events.iter().map(|event| event.queue_name).collect());
        if server
            .inner
            .ipc
            .queue_tx
            .send(QueueEvent::Refresh(QueueRefresh::Queued(events)))
            .await
            .is_err()
        {
            trc::event!(
                Server(ServerEvent::ThreadError),
                Reason = "Channel closed.",
                CausedBy = trc::location!(),
                SpanId = session_id,
            );
        }

        if let Some(queues) = queues {
            server
                .cluster_broadcast(BroadcastEvent::QueueRefresh(queues))
                .await;
        }

        QueueOutcome::Queued
    }

    pub async fn expand_and_add_recipient(&mut self, rcpt: impl AsRef<str>, server: &Server) {
        let rcpt = rcpt.as_ref();
        match server
            .rcpt_resolve(&rcpt.to_lowercase(), true, self.span_id)
            .await
        {
            Ok(RcptResolution::Rewrite(rewritten)) => {
                self.add_expanded_recipient(&rewritten, server).await;
            }
            Ok(RcptResolution::Expand(addrs)) => {
                for addr in addrs.as_ref() {
                    self.add_expanded_recipient(addr, server).await;
                }
            }
            Ok(_) => {
                self.add_expanded_recipient(rcpt, server).await;
            }
            Err(err) => {
                trc::error!(
                    err.span_id(self.span_id)
                        .caused_by(trc::location!())
                        .details("Failed to resolve recipient.")
                        .ctx(trc::Key::To, CompactString::from(rcpt))
                );
                self.add_expanded_recipient(rcpt, server).await;
            }
        }
    }

    pub async fn add_expanded_recipient(&mut self, rcpt: impl AsRef<str>, server: &Server) {
        self.message.recipients.push(Recipient::new(rcpt.as_ref()));
        let mut arena = Bump::new();
        let queue = eval_strategy(
            server,
            &server.core.smtp.queue.queue,
            &QueueEnvelope::new(&self.message, self.message.recipients.last().unwrap()),
            &mut arena,
            self.span_id,
            Server::get_queue_or_default,
        )
        .await;

        // Update expiration
        let recipient = self.message.recipients.last_mut().unwrap();
        recipient.notify = Schedule::later(queue.notify.first().copied().unwrap_or(86400));
        recipient.expires = queue.expiry;
        recipient.queue = queue.virtual_queue;
    }

    pub async fn save_changes(
        mut self,
        server: &Server,
        prev_event: Option<u64>,
        retry_at: Option<u64>,
    ) -> bool {
        // Release quota for completed deliveries
        let mut batch = BatchBuilder::new();
        let released_quotas = self.release_quota(&mut batch);

        // Update message queue
        if let Some(prev_event) = prev_event {
            batch.clear(self.event_class(self.queue_name, prev_event));
        }
        let mut next_events = self.message.next_events();
        if let Some(retry_at) = retry_at {
            let due = next_events.entry(self.queue_name).or_insert(retry_at);
            *due = std::cmp::min(*due, retry_at);
        }
        for (queue_name, due) in next_events {
            batch.set(self.event_class(queue_name, due), Vec::new());
        }

        if self.is_multi_queue {
            let queue_id = self.queue_id;
            let queue_name = self.queue_name;
            let new_message = self.message;

            batch.merge_fnc(
                ValueClass::Queue(QueueClass::Message(queue_id)),
                move |_, bytes| {
                    let mut cur_message = <Archive<ArchiveBytes> as Deserialize>::deserialize(
                        bytes.ok_or_else(|| {
                            trc::StoreEvent::NotFound
                                .into_err()
                                .details("Message no longer exists.")
                                .caused_by(trc::location!())
                                .ctx(trc::Key::QueueId, queue_id)
                        })?,
                    )
                    .and_then(|archive| archive.deserialize::<Message>())
                    .caused_by(trc::location!())?;

                    if cur_message.blob_hash.as_slice() == new_message.blob_hash.as_slice()
                        && cur_message.recipients.len() == new_message.recipients.len()
                    {
                        for (cur_rcpt, rcpt) in cur_message
                            .recipients
                            .iter_mut()
                            .zip(new_message.recipients.iter())
                            .filter(|(cur_rcpt, _)| cur_rcpt.queue == queue_name)
                        {
                            *cur_rcpt = rcpt.clone();
                        }

                        if !released_quotas.is_empty() {
                            let mut metadata = std::mem::take(&mut cur_message.metadata).into_vec();
                            metadata.retain(|entry| match entry {
                                Metadata::QueueCount { id, .. }
                                | Metadata::QueueSize { id, .. } => {
                                    released_quotas.binary_search(id).is_err()
                                }
                                _ => true,
                            });
                            cur_message.metadata = metadata.into_boxed_slice();
                        }

                        Archiver::new(cur_message)
                            .serialize()
                            .caused_by(trc::location!())
                            .map(MergeResult::Update)
                    } else {
                        Err(trc::StoreEvent::UnexpectedError
                            .into_err()
                            .details("Message blob hash or recipient count mismatch.")
                            .caused_by(trc::location!())
                            .ctx(trc::Key::QueueId, queue_id))
                    }
                },
            );
        } else {
            let message_bytes = match Archiver::new(self.message).serialize() {
                Ok(data) => data,
                Err(err) => {
                    trc::error!(
                        err.details("Failed to serialize message.")
                            .span_id(self.span_id)
                            .caused_by(trc::location!())
                    );
                    return false;
                }
            };

            batch.set(
                ValueClass::Queue(QueueClass::Message(self.queue_id)),
                message_bytes,
            );
        }

        if let Err(err) = server.store().write_batch(&mut batch).await {
            trc::error!(
                err.details("Failed to save changes.")
                    .span_id(self.span_id)
                    .caused_by(trc::location!())
            );
            false
        } else {
            true
        }
    }

    pub async fn remove(self, server: &Server, prev_event: Option<u64>) -> bool {
        let mut batch = BatchBuilder::new();
        if self.is_multi_queue {
            batch.assert_value(
                ValueClass::Queue(QueueClass::Message(self.queue_id)),
                AssertValue::Some,
            );
        }
        self.clear_events(&mut batch, prev_event);
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        for class in self.tenant_classes() {
            batch.clear(class);
        }
        // SPDX-SnippetEnd

        // Release all quotas
        let queued_bytes = self.message.queued_bytes();
        for metadata in &self.message.metadata {
            match metadata {
                Metadata::QueueCount { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount((*key).into())), -1);
                }
                Metadata::QueueSize { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize((*key).into())),
                        -(queued_bytes as i64),
                    );
                }
                Metadata::Blob(blob) => {
                    batch.clear(BlobOp::Link {
                        hash: blob.hash.clone(),
                        to: BlobLink::Id { id: self.queue_id },
                    });
                }
                Metadata::Headers { .. } | Metadata::Submission { .. } => {}
            }
        }

        batch
            .clear(BlobOp::Link {
                hash: self.message.blob_hash.clone(),
                to: BlobLink::Id { id: self.queue_id },
            })
            .clear(ValueClass::Queue(QueueClass::Message(self.queue_id)));
        self.write_delivery_results(&mut batch);

        let result = match server.store().write_batch(&mut batch).await {
            Err(err) if err.is_assertion_failure() => {
                let mut batch = BatchBuilder::new();
                self.clear_events(&mut batch, prev_event);
                server.store().write_batch(&mut batch).await
            }
            result => result,
        };

        if let Err(err) = result {
            trc::error!(
                err.details("Failed to write to update queue.")
                    .span_id(self.span_id)
                    .caused_by(trc::location!())
            );
            false
        } else {
            true
        }
    }

    fn clear_events(&self, batch: &mut BatchBuilder, prev_event: Option<u64>) {
        if let Some(prev_event) = prev_event {
            batch.clear(self.event_class(self.queue_name, prev_event));
        } else {
            for (queue_name, due) in self.message.next_events() {
                batch.clear(self.event_class(queue_name, due));
            }
        }
    }

    pub async fn save_registry_changes(
        mut self,
        server: &Server,
        prev_events: AHashMap<QueueName, u64>,
        modified_rcpts: AHashSet<usize>,
    ) -> RegistryWrite {
        let mut write = LockedWrite::new(self.queue_id, self.span_id, &self.message);
        let batch = &mut write.batch;
        let released_quotas = self.release_quota(batch);

        for (queue_name, due) in prev_events {
            batch.clear(self.event_class(queue_name, due));
        }
        for (queue_name, due) in self.message.next_events() {
            batch.set(self.event_class(queue_name, due), Vec::new());
        }

        let queue_id = self.queue_id;
        let new_message = self.message;

        batch.merge_fnc(
            ValueClass::Queue(QueueClass::Message(queue_id)),
            move |_, bytes| {
                let mut cur_message = <Archive<ArchiveBytes> as Deserialize>::deserialize(
                    bytes.ok_or_else(|| {
                        trc::StoreEvent::NotFound
                            .into_err()
                            .details("Message no longer exists.")
                            .caused_by(trc::location!())
                            .ctx(trc::Key::QueueId, queue_id)
                    })?,
                )
                .and_then(|archive| archive.deserialize::<Message>())
                .caused_by(trc::location!())?;

                if cur_message.blob_hash.as_slice() == new_message.blob_hash.as_slice()
                    && cur_message.recipients.len() == new_message.recipients.len()
                {
                    cur_message.priority = new_message.priority;
                    cur_message.env_id = new_message.env_id.clone();

                    for &rcpt_idx in &modified_rcpts {
                        if let Some(rcpt) = new_message.recipients.get(rcpt_idx) {
                            cur_message.recipients[rcpt_idx] = rcpt.clone();
                        }
                    }

                    if !released_quotas.is_empty() {
                        let mut metadata = std::mem::take(&mut cur_message.metadata).into_vec();
                        metadata.retain(|entry| match entry {
                            Metadata::QueueCount { id, .. } | Metadata::QueueSize { id, .. } => {
                                released_quotas.binary_search(id).is_err()
                            }
                            _ => true,
                        });
                        cur_message.metadata = metadata.into_boxed_slice();
                    }

                    Archiver::new(cur_message)
                        .serialize()
                        .caused_by(trc::location!())
                        .map(MergeResult::Update)
                } else {
                    Err(trc::StoreEvent::UnexpectedError
                        .into_err()
                        .details("Message blob hash or recipient count mismatch.")
                        .caused_by(trc::location!())
                        .ctx(trc::Key::QueueId, queue_id))
                }
            },
        );

        write.commit(server).await
    }

    pub async fn remove_registry(
        self,
        server: &Server,
        prev_events: AHashMap<QueueName, u64>,
        version: ArchiveVersion,
    ) -> RegistryWrite {
        let mut write = LockedWrite::new(self.queue_id, self.span_id, &self.message);
        let batch = &mut write.batch;
        batch.assert_value(
            ValueClass::Queue(QueueClass::Message(self.queue_id)),
            AssertValue::Archive(version),
        );

        for (queue_name, due) in prev_events {
            batch.clear(self.event_class(queue_name, due));
        }
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        for class in self.tenant_classes() {
            batch.clear(class);
        }
        // SPDX-SnippetEnd

        self.write_delivery_results(batch);
        let queued_bytes = self.message.queued_bytes();
        for metadata in self.message.metadata {
            match metadata {
                Metadata::QueueCount { key, .. } => {
                    batch.add(ValueClass::Queue(QueueClass::QuotaCount(key.into())), -1);
                }
                Metadata::QueueSize { key, .. } => {
                    batch.add(
                        ValueClass::Queue(QueueClass::QuotaSize(key.into())),
                        -(queued_bytes as i64),
                    );
                }
                Metadata::Blob(blob) => {
                    batch.clear(BlobOp::Link {
                        hash: blob.hash.clone(),
                        to: BlobLink::Id { id: self.queue_id },
                    });
                }
                Metadata::Headers { .. } | Metadata::Submission { .. } => {}
            }
        }

        batch
            .clear(BlobOp::Link {
                hash: self.message.blob_hash.clone(),
                to: BlobLink::Id { id: self.queue_id },
            })
            .clear(ValueClass::Queue(QueueClass::Message(self.queue_id)));

        write.commit(server).await
    }

    pub fn has_domain(&self, domains: &[String]) -> bool {
        self.message.recipients.iter().any(|r| {
            let domain = r.address.domain_part();
            domains.iter().any(|dd| dd == domain)
        }) || self
            .message
            .return_path
            .rsplit_once('@')
            .is_some_and(|(_, domain)| domains.iter().any(|dd| dd == domain))
    }
}

impl ArchivedMessage {
    pub fn next_delivery_event(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_delivery = None;

        for rcpt in self.recipients.iter().filter(|d| {
            matches!(
                d.status,
                ArchivedStatus::Scheduled | ArchivedStatus::TemporaryFailure(_)
            ) && queue.is_none_or(|q| d.queue == q)
        }) {
            let retry_due = rcpt.retry.due.to_native();
            if let Some(next_delivery) = &mut next_delivery {
                if retry_due < *next_delivery {
                    *next_delivery = retry_due;
                }
            } else {
                next_delivery = Some(retry_due);
            }
        }

        next_delivery
    }

    pub fn next_event(&self, queue: Option<QueueName>) -> Option<u64> {
        let created = self.created.to_native();
        let mut next_event = None;

        for rcpt in self.recipients.iter().filter(|d| {
            matches!(
                d.status,
                ArchivedStatus::Scheduled | ArchivedStatus::TemporaryFailure(_)
            ) && queue.is_none_or(|q| d.queue == q)
        }) {
            let mut earlier_event =
                std::cmp::min(rcpt.retry.due.to_native(), rcpt.notify.due.to_native());

            if let ArchivedQueueExpiry::Ttl(ttl) = &rcpt.expires {
                earlier_event = std::cmp::min(earlier_event, created + ttl.to_native());
            }

            if let Some(next_event) = &mut next_event {
                if earlier_event < *next_event {
                    *next_event = earlier_event;
                }
            } else {
                next_event = Some(earlier_event);
            }
        }

        next_event
    }

    pub fn next_notify_event(&self, queue: Option<QueueName>) -> Option<u64> {
        let mut next_notify = None;

        for rcpt in self.recipients.iter().filter(|d| {
            matches!(
                d.status,
                ArchivedStatus::Scheduled | ArchivedStatus::TemporaryFailure(_)
            ) && queue.is_none_or(|q| d.queue == q)
        }) {
            let notify_due = rcpt.notify.due.to_native();
            if let Some(next_notify) = &mut next_notify {
                if notify_due < *next_notify {
                    *next_notify = notify_due;
                }
            } else {
                next_notify = Some(notify_due);
            }
        }

        next_notify
    }
}

impl<'x, 'y> QueueParams<'x, 'y> {
    pub fn new(raw_message: &'x [u8], session_id: u64, server: &'y Server) -> Self {
        QueueParams {
            raw_message,
            dkim_signers: None,
            raw_headers: None,
            session_id,
            server,
            train_spam: None,
            original_raw_message: None,
            original_authenticated_message: None,
            dkim2_verified: None,
            exploded: false,
            dkim1_only: false,
            metadata: Vec::new(),
            encrypted_recipients: Vec::new(),
            dkim2_signed: false,
            quotas: Vec::new(),
        }
    }

    fn signs_dkim2(&self) -> bool {
        !self.dkim1_only
            && self
                .dkim_signers
                .as_ref()
                .is_some_and(|signers| signers.dkim2.is_some())
    }

    pub fn with_train_spam(mut self, train_spam: Option<(bool, String)>) -> Self {
        self.train_spam = train_spam;
        self
    }

    pub fn with_original_authenticated_message(
        mut self,
        authenticated_message: &'x AuthenticatedMessage<'x>,
    ) -> Self {
        self.original_authenticated_message = Some(authenticated_message);
        self
    }

    pub fn with_dkim2_verified(mut self, verified: Option<&'x Dkim2Output<'x>>) -> Self {
        self.dkim2_verified = verified;
        self
    }

    pub fn with_exploded(mut self, exploded: bool) -> Self {
        self.exploded = exploded;
        self
    }

    pub fn with_original_raw_message(mut self, raw_message: &'x [u8]) -> Self {
        self.original_raw_message = Some(raw_message);
        self
    }

    pub fn with_dkim_signers(mut self, dkim_signers: Option<Arc<DkimSigners>>) -> Self {
        self.dkim_signers = dkim_signers;
        self
    }

    pub fn with_dkim1_only(mut self) -> Self {
        self.dkim1_only = true;
        self
    }

    pub fn with_raw_headers(mut self, raw_headers: &'x [u8]) -> Self {
        self.raw_headers = Some(raw_headers);
        self
    }

    pub fn with_raw_headers_opt(mut self, raw_headers: Option<&'x [u8]>) -> Self {
        self.raw_headers = raw_headers;
        self
    }

    pub fn with_quotas(mut self, quotas: Vec<QuotaReservation>) -> Self {
        self.quotas = quotas;
        self
    }

    pub fn with_metadata(mut self, metadata: Option<Metadata>) -> Self {
        self.metadata.extend(metadata);
        self
    }
}
