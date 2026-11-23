/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::ExchangeCacheFetch,
    mail::metadata_row,
    store::{
        QuotaOwner,
        account::ExchangeAccountStore,
        object::{
            ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite, ObjectVersion, OwnerStamp,
        },
    },
};
use common::{
    MessageStoreCache, Server, auth::AccessToken, cache::exchange::ExchangeAccountCache,
    ipc::PushNotification, network::memory::MemoryReservation, storage::blob::FetchedBlob,
};
use email::{
    cache::email::MessageCacheAccess,
    mailbox::{JUNK_ID, TRASH_ID},
    message::ingest::{
        EmailIngest, IngestEmail, IngestSource, PendingIngest, recheck::ThreadRecheck,
    },
};
use mail_parser::MessageParser;
use std::{mem, sync::Arc, vec};
use store::write::BatchBuilder;
use trc::{AddContext, EventType, LimitEvent, MessageIngestEvent};
use types::{
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    keyword::Keyword,
    type_state::{DataType, StateChange},
};

const MAX_GROUP_EMAILS: usize = 32;
const MAX_GROUP_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct CopyOrigin {
    pub document_id: u32,
    pub from: u32,
}

pub enum Copied {
    Created { document_id: u32, change_id: u64 },
    NotFound,
    OverQuota,
    Rejected(trc::Error),
    CommitFailed,
    Failed(trc::Error),
}

pub struct MailCopier<'x> {
    server: &'x Server,
    access_token: &'x AccessToken,
    target: Option<AccessToken>,
    owner: QuotaOwner,
    objects: Arc<ExchangeAccountCache>,
    account_id: u32,
    session_id: u64,
    batch: BatchBuilder,
    queued: Vec<Queued>,
    queued_bytes: usize,
    exchange_rows: bool,
    settled: Vec<(usize, Copied)>,
    over_quota: bool,
}

struct Queued {
    slot: usize,
    origin: CopyOrigin,
    to: u32,
    pending: PendingIngest,
}

enum Queueing {
    Queued,
    Settled(Copied),
    Poisoned(trc::Error),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    Quota,
    Rejection,
    Fatal,
}

struct Source {
    raw: Vec<u8>,
    reused: Option<BlobHash>,
    carried: Option<ExchangeObject>,
    keywords: Vec<Keyword>,
    received_at: u64,
    training: Training,
    _reservation: MemoryReservation,
}

impl<'x> MailCopier<'x> {
    pub async fn new(
        server: &'x Server,
        access_token: &'x AccessToken,
        account_id: u32,
        session_id: u64,
    ) -> trc::Result<Self> {
        Ok(MailCopier {
            server,
            access_token,
            target: server
                .exchange_target_token(access_token, account_id)
                .await?,
            owner: server
                .exchange_quota_owner(access_token, account_id)
                .await?,
            objects: server
                .get_cached_exchange(account_id)
                .await
                .caused_by(trc::location!())?,
            account_id,
            session_id,
            batch: BatchBuilder::new(),
            queued: Vec::new(),
            queued_bytes: 0,
            exchange_rows: false,
            settled: Vec::new(),
            over_quota: false,
        })
    }

    pub async fn copy(
        &mut self,
        cache: &MessageStoreCache,
        origin: CopyOrigin,
        to: u32,
        slot: usize,
    ) {
        let copied = match self.prepare(cache, origin, to).await {
            Ok(Ok(source)) => {
                if self.must_flush_before(source.raw.len()) {
                    self.flush(cache).await;
                }
                if self.over_quota {
                    Some(Copied::OverQuota)
                } else {
                    match self.queue(source, origin, to, slot).await {
                        Queueing::Queued => None,
                        Queueing::Settled(copied) => Some(copied),
                        Queueing::Poisoned(err) => {
                            let earlier = self.discard();
                            self.commit_each(cache, earlier).await;
                            Some(Copied::Rejected(err))
                        }
                    }
                }
            }
            Ok(Err(copied)) => Some(copied),
            Err(err) => Some(Copied::Failed(err)),
        };
        if let Some(copied) = copied {
            self.settled.push((slot, copied));
        }
    }

    pub fn settled(&mut self) -> vec::Drain<'_, (usize, Copied)> {
        self.settled.drain(..)
    }

    pub async fn finish(&mut self, cache: &MessageStoreCache) {
        self.flush(cache).await;
    }

    async fn prepare(
        &self,
        cache: &MessageStoreCache,
        origin: CopyOrigin,
        to: u32,
    ) -> trc::Result<Result<Source, Copied>> {
        if self.over_quota {
            return Ok(Err(Copied::OverQuota));
        }
        let Some(message) = cache
            .email_by_id(&origin.document_id)
            .filter(|message| message.has_mailbox_id(origin.from))
        else {
            return Ok(Err(Copied::NotFound));
        };
        let Some(row) = metadata_row(self.server, self.account_id, origin.document_id).await?
        else {
            return Ok(Err(Copied::NotFound));
        };
        let carried = stored_email_object(
            self.server,
            &self.objects,
            self.account_id,
            origin.document_id,
        )
        .await?
        .filter(|carried| !carried.is_empty());
        if let Some(carried) = &carried
            && let Err(err) = carried.sized_within(self.server.core.exchange.max_object_size)
        {
            return Ok(Err(Copied::Rejected(err)));
        }
        let metadata = row.unarchive().caused_by(trc::location!())?;
        let blob_hash = metadata.blob_hash();
        let Some((raw, reservation)) = self
            .server
            .fetch_blob(&blob_hash, 0..usize::MAX, Some(metadata.blob_size() as u64))
            .await
            .caused_by(trc::location!())?
            .map(FetchedBlob::into_parts)
        else {
            return Ok(Err(Copied::NotFound));
        };
        let (raw, reused) = match metadata.extra_headers_len() {
            0 => (raw, Some(blob_hash)),
            extra_len => {
                let headers = row.raw_headers().caused_by(trc::location!())?;
                let extra = headers.get(..extra_len).unwrap_or_default();
                let mut full = Vec::with_capacity(extra.len() + raw.len());
                full.extend_from_slice(extra);
                full.extend_from_slice(&raw);
                drop(raw);
                (full, None)
            }
        };
        let training = Training::of(origin.from, to);
        let mut keywords = cache
            .expand_keywords(message)
            .filter(|keyword| training.keeps(keyword))
            .collect::<Vec<_>>();
        if let Some(verdict) = training.verdict()
            && keywords.len() < self.server.core.email.limits.keywords_per_email
        {
            keywords.push(verdict);
        }
        Ok(Ok(Source {
            raw,
            reused,
            carried,
            keywords,
            received_at: message.received_at(),
            training,
            _reservation: reservation,
        }))
    }

    async fn queue(
        &mut self,
        source: Source,
        origin: CopyOrigin,
        to: u32,
        slot: usize,
    ) -> Queueing {
        let Source {
            raw,
            reused,
            carried,
            keywords,
            received_at,
            training,
            _reservation,
        } = source;
        let message = MessageParser::new().parse(&raw);
        let mut params = IngestEmail {
            raw_message: &raw,
            blob_hash: reused.as_ref(),
            message: message.as_ref(),
            access_token: self.target.as_ref().unwrap_or(self.access_token),
            mailbox_ids: vec![to],
            keywords,
            received_at: Some(received_at),
            source: IngestSource::Jmap {
                train_classifier: training != Training::None,
            },
            metadata: None,
            session_id: self.session_id,
        };
        let pending = match self
            .server
            .email_ingest_into(&mut params, &mut self.batch, None)
            .await
        {
            Ok(pending) => pending,
            Err(err) => {
                return match Failure::of(&err) {
                    Failure::Quota => {
                        self.over_quota = true;
                        Queueing::Settled(Copied::Rejected(err))
                    }
                    Failure::Rejection => Queueing::Settled(Copied::Rejected(err)),
                    Failure::Fatal => Queueing::Poisoned(err),
                };
            }
        };
        if let (Some(carried), PendingIngest::Queued(email)) = (carried, &pending) {
            if let Err(err) = (ExchangeObjectWrite {
                owner: self.owner,
                collection: Collection::Email,
                document_id: email.document_id(),
                stamp: OwnerStamp::Logged,
                version: ObjectVersion::Server,
                previous: None,
                next: Some(carried),
                max_size: self.server.core.exchange.max_object_size,
            })
            .build(&mut self.batch)
            {
                return Queueing::Poisoned(err);
            }
            self.exchange_rows = true;
        }
        self.queued.push(Queued {
            slot,
            origin,
            to,
            pending,
        });
        self.queued_bytes = self.queued_bytes.saturating_add(raw.len());
        Queueing::Queued
    }

    fn must_flush_before(&self, size: usize) -> bool {
        !self.queued.is_empty()
            && (self.queued.len() >= MAX_GROUP_EMAILS
                || self.queued_bytes.saturating_add(size) > MAX_GROUP_BYTES
                || self.batch.is_large_batch())
    }

    async fn flush(&mut self, cache: &MessageStoreCache) {
        if self.queued.is_empty() {
            return;
        }
        let Err(err) = self.commit().await else {
            return;
        };
        let mut failed = mem::take(&mut self.queued);
        match Failure::of(&err) {
            Failure::Quota if failed.len() > 1 => {
                self.commit_each(cache, failed).await;
                return;
            }
            Failure::Quota => {
                self.over_quota = true;
                if let Some(queued) = failed.pop() {
                    self.settled.push((queued.slot, Copied::Rejected(err)));
                }
            }
            Failure::Rejection | Failure::Fatal => {
                trc::error!(err.span_id(self.session_id));
                self.settled.extend(
                    failed
                        .drain(..)
                        .map(|queued| (queued.slot, Copied::CommitFailed)),
                );
            }
        }
        self.queued = failed;
    }

    async fn commit_each(&mut self, cache: &MessageStoreCache, mut failed: Vec<Queued>) {
        for Queued {
            slot, origin, to, ..
        } in failed.drain(..)
        {
            let copied = match self.prepare(cache, origin, to).await {
                Ok(Ok(source)) => match self.queue(source, origin, to, slot).await {
                    Queueing::Queued => match self.commit().await {
                        Ok(()) => None,
                        Err(err) => {
                            self.queued.clear();
                            self.over_quota = Failure::of(&err) == Failure::Quota;
                            Some(Copied::Rejected(err))
                        }
                    },
                    Queueing::Settled(copied) => Some(copied),
                    Queueing::Poisoned(err) => {
                        self.discard();
                        Some(Copied::Rejected(err))
                    }
                },
                Ok(Err(copied)) => Some(copied),
                Err(err) => Some(Copied::Failed(err)),
            };
            if let Some(copied) = copied {
                self.settled.push((slot, copied));
            }
        }
        self.queued = failed;
    }

    async fn commit(&mut self) -> trc::Result<()> {
        let mut batch = mem::take(&mut self.batch);
        let exchange_rows = mem::take(&mut self.exchange_rows);
        self.queued_bytes = 0;
        let queues = batch.queue_notify();
        let server = self.server;
        let assigned_ids = match server.store().write_batch(&mut batch).await {
            Ok(assigned_ids) => assigned_ids,
            Err(err) => {
                if err.is_assertion_failure() {
                    server
                        .inner
                        .mark_cache_stale(self.account_id, SyncCollection::Email);
                    if exchange_rows {
                        server.mark_exchange_stale(self.account_id);
                    }
                }
                return Err(err.caused_by(trc::location!()));
            }
        };
        server.inner.mark_caches_stale_from(&assigned_ids);
        if exchange_rows {
            server.mark_exchange_stale(self.account_id);
        }
        if let Some(change_id) = assigned_ids.change_id(self.account_id, SyncCollection::Email) {
            server
                .broadcast_push_notification(PushNotification::StateChange(
                    StateChange::new(self.account_id)
                        .with_change_id(change_id)
                        .with_change(DataType::Email)
                        .with_change(DataType::Mailbox)
                        .with_change(DataType::Thread),
                ))
                .await;
        }
        let mut recheck = ThreadRecheck::default();
        for Queued { slot, pending, .. } in self.queued.drain(..) {
            let email = match pending {
                PendingIngest::Queued(pending) => {
                    let mut email = server.email_ingest_finish(pending, &assigned_ids).await;
                    recheck.push(self.account_id, &mut email);
                    email
                }
                PendingIngest::Duplicate(email) => email,
            };
            self.settled.push((
                slot,
                Copied::Created {
                    document_id: email.document_id,
                    change_id: email.change_id,
                },
            ));
        }
        server.notify_queues(queues).await;
        recheck.finish(server, self.session_id).await;
        Ok(())
    }

    fn discard(&mut self) -> Vec<Queued> {
        self.batch = BatchBuilder::new();
        self.queued_bytes = 0;
        self.exchange_rows = false;
        mem::take(&mut self.queued)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Training {
    None,
    Spam,
    Ham,
}

impl Training {
    fn of(from: u32, to: u32) -> Self {
        if from == to {
            Training::None
        } else if to == JUNK_ID {
            Training::Spam
        } else if from == JUNK_ID && to != TRASH_ID {
            Training::Ham
        } else {
            Training::None
        }
    }

    fn keeps(self, keyword: &Keyword) -> bool {
        match keyword {
            Keyword::HasAttachment | Keyword::HasNoAttachment => false,
            Keyword::Junk | Keyword::NotJunk => self == Training::None,
            _ => true,
        }
    }

    fn verdict(self) -> Option<Keyword> {
        match self {
            Training::None => None,
            Training::Spam => Some(Keyword::Junk),
            Training::Ham => Some(Keyword::NotJunk),
        }
    }
}

impl Failure {
    fn of(err: &trc::Error) -> Self {
        match err.as_ref() {
            EventType::Limit(LimitEvent::Quota) => Failure::Quota,
            #[cfg(feature = "enterprise")]
            EventType::Limit(LimitEvent::TenantQuota) => Failure::Quota,
            EventType::MessageIngest(MessageIngestEvent::Error) => Failure::Rejection,
            _ => Failure::Fatal,
        }
    }
}

pub async fn stored_email_object(
    server: &Server,
    objects: &ExchangeAccountCache,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<ExchangeObject>> {
    if !objects.has_object(Collection::Email, document_id) {
        return Ok(None);
    }
    let Some(archive) = server
        .exchange_object(account_id, Collection::Email, document_id)
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    let mut object = archive
        .deserialize::<ExchangeObject>()
        .caused_by(trc::location!())?;
    object.conflict = None;
    Ok(Some(object))
}
