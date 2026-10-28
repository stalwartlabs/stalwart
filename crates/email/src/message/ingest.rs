/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::crypto::{EncryptMessage, EncryptMessageError};
use crate::{
    mailbox::{INBOX_ID, JUNK_ID, TRASH_ID},
    message::{
        crypto::EncryptionFlags,
        delivery::SenderAuthentication,
        index::IndexMessage,
        ingest_metadata::IngestMetadata,
        messagedata::{EmailMessageData, MessageData, PendingMessageData},
        metadata::{AddressHeader, ExtraHeaders, HeaderId, MetadataStructure, Occurrence},
        thread::ThreadFields,
    },
};
use common::{
    MAX_RECEIVED_AT, MessageUid, Server, auth::AccessToken,
    storage::metadata::PrivateMetadataCommit,
};
use compact_str::{CompactString, ToCompactString};
use groupware::{
    calendar::itip::{ItipIngest, ItipIngestError},
    scheduling::{ItipError, ItipMessages},
};
use mail_parser::{Message, MessageParser, thread_name};
use recheck::PendingThread;
use registry::{
    schema::{
        enums::StorageQuota,
        prelude::{ObjectType, Permission, Property},
        structs::{SpamTrainingSample, Task, TaskMergeThreads, TaskStatus},
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId, map::Map},
};
use std::future::Future;
use std::{borrow::Cow, cmp::Ordering, time::Instant};
use store::{
    Deserialize, IterateParams, SerializeInfallible, U32_LEN, U128_LEN, ValueKey,
    ahash::AHashMap,
    roaring::RoaringBitmap,
    write::{
        AssignedIds, BatchBuilder, BlobLink, BlobOp, IndexPropertyClass, Patch, PatchSource,
        PendingId, QueueDocumentId, SearchIndex, SizedSetValue, Slot, SlotRange, ValueClass,
        blob::BlobLinkValue, key::DeserializeBigEndian, now,
    },
};
use store::{write::RegistryClass, xxhash_rust::xxh3::xxh3_128};
use tinyvec::TinyVec;
use trc::{AddContext, MessageIngestEvent, SpamEvent};
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::{ContactField, EmailField},
    id::Id,
    keyword::Keyword,
};
use utils::{hash128::Hash128, sanitize_email, snowflake::SnowflakeIdGenerator};

#[derive(Default)]
pub struct IngestedEmail {
    pub document_id: u32,
    pub thread_id: u32,
    pub change_id: u64,
    pub blob_id: BlobId,
    pub size: usize,
    pub imap_uids: Vec<u32>,
    pub thread_recheck: Option<PendingThread>,
}

pub enum PendingIngest {
    Queued(PendingEmail),
    Duplicate(IngestedEmail),
}

pub struct PendingEmail {
    account_id: u32,
    document_slot: Slot,
    uid_slots: SlotRange,
    thread_id: PendingId,
    blob_hash: BlobHash,
    size: u64,
    thread_recheck: Option<PendingThread>,
    private_commit: PrivateMetadataCommit,
    event: MessageIngestEvent,
    mailbox_ids: Vec<u32>,
    message_id: Option<String>,
    session_id: u64,
    start_time: Instant,
}

pub struct IngestEmail<'x> {
    pub raw_message: &'x [u8],
    pub blob_hash: Option<&'x BlobHash>,
    pub message: Option<Message<'x>>,
    pub access_token: &'x AccessToken,
    pub mailbox_ids: Vec<u32>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<u64>,
    pub source: IngestSource<'x>,
    pub metadata: Option<Box<IngestMetadata>>,
    pub session_id: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngestSource<'x> {
    Smtp {
        deliver_to: &'x str,
        envelope_from: &'x str,
        sender_authentication: SenderAuthentication,
        is_spam: bool,
    },
    Jmap {
        train_classifier: bool,
    },
    Imap {
        train_classifier: bool,
    },
    Restore,
}

pub trait EmailIngest: Sync + Send {
    fn email_ingest(
        &self,
        params: IngestEmail,
    ) -> impl Future<Output = trc::Result<IngestedEmail>> + Send;
    fn email_ingest_into(
        &self,
        params: &mut IngestEmail,
        batch: &mut BatchBuilder,
        group_thread: Option<PendingId>,
    ) -> impl Future<Output = trc::Result<PendingIngest>> + Send;
    fn email_ingest_finish(
        &self,
        pending: PendingEmail,
        assigned_ids: &AssignedIds,
    ) -> impl Future<Output = IngestedEmail> + Send;
    fn find_thread_id(
        &self,
        account_id: u32,
        thread_name: &str,
        message_ids: &[u128],
    ) -> impl Future<Output = trc::Result<ThreadResult>> + Send;
    fn add_account_spam_samples(
        &self,
        batch: &mut BatchBuilder,
        account_id: u32,
        samples: SpamSamples,
        span_id: u64,
    ) -> impl Future<Output = trc::Result<()>> + Send;

    #[allow(clippy::too_many_arguments)]
    fn add_spam_sample(
        &self,
        account_id: u32,
        batch: &mut BatchBuilder,
        hash: BlobHash,
        size: u64,
        from: String,
        subject: String,
        is_spam: bool,
        hold_sample: bool,
        span_id: u64,
    );
}

#[derive(Default)]
pub struct SpamSamples {
    documents: RoaringBitmap,
    spam: RoaringBitmap,
    prepared: Vec<SpamSample>,
}

pub struct SpamSample {
    hash: BlobHash,
    size: u64,
    from: String,
    subject: String,
    is_spam: bool,
}

impl SpamSample {
    pub fn from_metadata(bytes: &[u8], is_spam: bool) -> trc::Result<Self> {
        let structure = MetadataStructure::deserialize(bytes)?;
        let metadata = structure.unarchive().caused_by(trc::location!())?;
        let envelope = metadata.root().envelope();
        Ok(SpamSample {
            hash: metadata.blob_hash(),
            size: metadata.blob_size() as u64,
            from: envelope
                .addresses(AddressHeader::From, Occurrence::Last)
                .first()
                .and_then(|mailbox| mailbox.address)
                .unwrap_or_default()
                .to_string(),
            subject: thread_name(envelope.subject().unwrap_or_default()).to_string(),
            is_spam,
        })
    }
}

impl SpamSamples {
    pub fn add(&mut self, document_id: u32, is_spam: bool) {
        self.documents.insert(document_id);
        if is_spam {
            self.spam.insert(document_id);
        } else {
            self.spam.remove(document_id);
        }
    }

    pub fn add_sample(&mut self, sample: SpamSample) {
        self.prepared.push(sample);
    }

    pub fn is_empty(&self) -> bool {
        self.documents.is_empty() && self.prepared.is_empty()
    }
}

pub struct ThreadResult {
    pub thread_id: Option<u32>,
    pub thread_hash: Hash128,
    pub merge_ids: Vec<u32>,
    pub duplicate_ids: Vec<u32>,
    pub matched_ids: Vec<u32>,
    pub bucket_full: bool,
}

impl EmailIngest for Server {
    async fn email_ingest(&self, mut params: IngestEmail<'_>) -> trc::Result<IngestedEmail> {
        let mut batch = BatchBuilder::new();
        let pending = match self
            .email_ingest_into(&mut params, &mut batch, None)
            .await?
        {
            PendingIngest::Queued(pending) => pending,
            PendingIngest::Duplicate(email) => return Ok(email),
        };
        let queues = batch.queue_notify();
        let assigned_ids = self
            .store()
            .write_batch(&mut batch)
            .await
            .caused_by(trc::location!())?;
        self.inner.mark_caches_stale_from(&assigned_ids);
        let email = self.email_ingest_finish(pending, &assigned_ids).await;
        self.notify_queues(queues).await;
        Ok(email)
    }

    #[allow(clippy::blocks_in_conditions)]
    async fn email_ingest_into(
        &self,
        params: &mut IngestEmail<'_>,
        batch: &mut BatchBuilder,
        group_thread: Option<PendingId>,
    ) -> trc::Result<PendingIngest> {
        // Check quota
        let start_time = Instant::now();
        let account_id = params.access_token.account_id();
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let tenant_id = params.access_token.tenant_id();
        // SPDX-SnippetEnd
        let mut raw_message_len = params.raw_message.len() as u64;
        let account = self.account(account_id).await.caused_by(trc::location!())?;
        let limits = &self.core.email.limits;
        if matches!(
            params.source,
            IngestSource::Smtp { .. } | IngestSource::Restore
        ) {
            params.mailbox_ids.truncate(limits.mailboxes_per_email);
            if !params.keywords.is_empty() {
                params.keywords = Keyword::unique(
                    std::mem::take(&mut params.keywords)
                        .into_iter()
                        .filter(|keyword| limits.is_keyword_allowed(keyword)),
                );
                params.keywords.truncate(limits.keywords_per_email);
            }
        } else if let Err(err) = limits.validate_email(params.mailbox_ids.len(), &params.keywords) {
            return Err(
                trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                    .ctx(trc::Key::Code, 550)
                    .ctx(trc::Key::Reason, err.to_string()),
            );
        }
        let mut metadata = params.metadata.take();
        if let Some(metadata) = metadata.as_deref_mut() {
            metadata.shared = metadata
                .shared
                .take()
                .filter(|container| container.kinds().intersects(MessageData::TRACKED_METADATA));
        }
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        self.has_available_tenant_quota(
            &account,
            raw_message_len
                + metadata
                    .as_deref()
                    .and_then(|metadata| metadata.shared.as_ref())
                    .map_or(0, |container| container.len() as u64),
        )
        .await
        .caused_by(trc::location!())?;
        // SPDX-SnippetEnd

        // Parse message
        let mut raw_message = Cow::from(params.raw_message);
        let mut message = params.message.take().ok_or_else(|| {
            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                .ctx(trc::Key::Code, 550)
                .ctx(trc::Key::Reason, "Failed to parse e-mail message.")
        })?;

        // Obtain message references and thread name
        let fields = ThreadFields::scan(&message);
        let mut thread_result = self
            .find_thread_id(account_id, fields.subject, &fields.message_ids)
            .await?;
        let group_slot = match group_thread {
            Some(PendingId::Slot(slot)) if thread_result.thread_id.is_none() => Some(slot),
            Some(PendingId::Assigned(thread_id)) if thread_result.thread_id.is_none() => {
                thread_result.thread_id = Some(thread_id);
                None
            }
            _ => None,
        };
        let ThreadFields {
            message_id,
            sent_at,
            message_ids,
            ..
        } = fields;

        // Skip duplicate messages for SMTP ingestion
        if !thread_result.duplicate_ids.is_empty()
            && params.source.is_smtp()
            && Box::pin(checks::has_duplicate_in(
                self,
                account_id,
                &thread_result.duplicate_ids,
                params.mailbox_ids.first().copied().unwrap_or(INBOX_ID),
            ))
            .await
            .caused_by(trc::location!())?
        {
            trc::event!(
                MessageIngest(MessageIngestEvent::Duplicate),
                SpanId = params.session_id,
                AccountId = account_id,
                MessageId = message_id,
            );

            return Ok(PendingIngest::Duplicate(IngestedEmail {
                document_id: 0,
                thread_id: 0,
                change_id: u64::MAX,
                blob_id: BlobId::default(),
                imap_uids: Vec::new(),
                size: 0,
                thread_recheck: None,
            }));
        }

        // Spam classification and training
        let mut train_spam = None;
        let mut extra_headers = ExtraHeaders::default();
        let mut itip_messages = Vec::new();
        let is_spam = match params.source {
            IngestSource::Smtp {
                deliver_to,
                envelope_from,
                sender_authentication,
                mut is_spam,
            } => {
                // Add delivered to header
                if self.core.smtp.session.data.add_delivered_to {
                    extra_headers.push(HeaderId::DELIVERED_TO, deliver_to);
                }

                // Spam training on confirmed false positives
                if self.core.spam.enabled {
                    let mut overridden = None;
                    // If the message is classified as spam, check whether the
                    // sender address is present in the user's address book.
                    if is_spam
                        && self.core.spam.card_is_ham
                        && let Some(sender) = message
                            .from()
                            .and_then(|s| s.first())
                            .and_then(|s| s.address())
                            .and_then(sanitize_email)
                        && sender != deliver_to
                        && sender_authentication.is_authenticated()
                        && self
                            .document_exists(
                                account_id,
                                Collection::ContactCard,
                                ContactField::Email,
                                sender.as_bytes(),
                            )
                            .await
                            .caused_by(trc::location!())?
                    {
                        is_spam = false;
                        if self
                            .core
                            .spam
                            .classifier
                            .as_ref()
                            .is_some_and(|c| c.auto_learn_card_is_ham)
                        {
                            train_spam = Some(false);
                        }
                        overridden = Some("card-exists");
                    }

                    // Check if the message is a trusted reply to a previous message
                    if is_spam
                        && self.core.spam.trusted_reply
                        && let Some(thread_id) = thread_result.thread_id
                        && Box::pin(checks::is_trusted_reply(
                            self,
                            account_id,
                            thread_id,
                            &thread_result.matched_ids,
                        ))
                        .await
                        .caused_by(trc::location!())?
                    {
                        is_spam = false;
                        if self
                            .core
                            .spam
                            .classifier
                            .as_ref()
                            .is_some_and(|c| c.auto_learn_reply_ham)
                        {
                            train_spam = Some(false);
                        }
                        overridden = Some("trusted-reply");
                    }

                    // Add Spam-Status header
                    let result = if is_spam { "Yes" } else { "No" };
                    if let Some(reason) = overridden {
                        extra_headers.push(
                            HeaderId::X_SPAM_STATUS,
                            &format!("{result}, reason={reason}"),
                        );
                    } else {
                        extra_headers.push(HeaderId::X_SPAM_STATUS, result);
                    }

                    if is_spam && params.mailbox_ids == [INBOX_ID] {
                        params.mailbox_ids[0] = JUNK_ID;
                        params.keywords.push(Keyword::Junk);
                    }
                }

                // iMIP processing
                if self.core.groupware.itip_enabled
                    && !is_spam
                    && sender_authentication.is_authenticated()
                    && params
                        .access_token
                        .has_permission(Permission::CalendarSchedulingReceive)
                {
                    let mut account_info = None;
                    let mut sender = None;
                    for part in message.root().parts() {
                        if part.content_type().is_some_and(|ct| {
                            ct.ctype().eq_ignore_ascii_case("text")
                                && ct
                                    .subtype()
                                    .is_some_and(|st| st.eq_ignore_ascii_case("calendar"))
                                && ct.has_attribute("method")
                        }) && let Some(itip_message) = part.text()
                        {
                            if itip_message.len() < self.core.groupware.itip_inbound_max_ical_size {
                                if let Some(sender) = sender.get_or_insert_with(|| {
                                    if sender_authentication == SenderAuthentication::Submission {
                                        sanitize_email(envelope_from)
                                    } else {
                                        message
                                            .from()
                                            .and_then(|s| s.first())
                                            .and_then(|s| s.address())
                                            .and_then(sanitize_email)
                                    }
                                }) {
                                    let account_info = match &account_info {
                                        Some(account_info) => account_info,
                                        None => account_info.insert(
                                            self.build_account_info(account.clone())
                                                .await
                                                .caused_by(trc::location!())?,
                                        ),
                                    };
                                    match Box::pin(self.itip_ingest(
                                        account_info,
                                        sender,
                                        deliver_to,
                                        &itip_message,
                                    ))
                                    .await
                                    {
                                        Ok(message) => {
                                            if let Some(message) = message {
                                                itip_messages.push(message);
                                            }
                                            trc::event!(
                                                Calendar(trc::CalendarEvent::ItipMessageReceived),
                                                SpanId = params.session_id,
                                                From = CompactString::from(&*sender),
                                                AccountId = account_id,
                                            );
                                        }
                                        Err(ItipIngestError::Message(itip_error)) => {
                                            match itip_error {
                                                ItipError::NothingToSend
                                                | ItipError::OtherSchedulingAgent => (),
                                                err => {
                                                    trc::event!(
                                                        Calendar(
                                                            trc::CalendarEvent::ItipMessageError
                                                        ),
                                                        SpanId = params.session_id,
                                                        From = CompactString::from(&*sender),
                                                        AccountId = account_id,
                                                        Details = err.to_compact_string(),
                                                    )
                                                }
                                            }
                                        }
                                        Err(ItipIngestError::Internal(err)) => {
                                            trc::error!(err.caused_by(trc::location!()));
                                        }
                                    }
                                }
                            } else {
                                trc::event!(
                                    Calendar(trc::CalendarEvent::ItipMessageError),
                                    SpanId = params.session_id,
                                    From = message
                                        .from()
                                        .and_then(|a| a.first())
                                        .and_then(|a| a.address())
                                        .map(CompactString::from),
                                    AccountId = account_id,
                                    Details = "iMIP message too large",
                                    Limit = self.core.groupware.itip_inbound_max_ical_size,
                                    Size = itip_message.len(),
                                )
                            }
                        }
                    }
                }

                is_spam
            }
            IngestSource::Jmap { train_classifier } | IngestSource::Imap { train_classifier } => {
                // Determine spam training
                if train_classifier && self.core.spam.enabled {
                    if params.keywords.contains(&Keyword::Junk) {
                        train_spam = Some(true);
                    } else if params.keywords.contains(&Keyword::NotJunk) {
                        if !params.mailbox_ids.contains(&TRASH_ID) {
                            train_spam = Some(false);
                        }
                    } else if params.mailbox_ids[0] == JUNK_ID {
                        train_spam = Some(true);
                    } else if params.mailbox_ids[0] == INBOX_ID {
                        train_spam = Some(false);
                    }
                }

                // Set receivedAt if not present
                if params.received_at.is_none() {
                    params.received_at = message
                        .root_part()
                        .headers()
                        .all_received()
                        .filter_map(|received| {
                            received
                                .date()
                                .filter(|dt| dt.is_valid())
                                .map(|dt| dt.to_timestamp() as u64)
                        })
                        .max();
                }

                false
            }
            _ => false,
        };

        // Encrypt message
        let do_encrypt = match params.source {
            IngestSource::Jmap { .. } if params.keywords.contains(&Keyword::Draft) => false,
            IngestSource::Jmap { .. } | IngestSource::Imap { .. } => {
                self.core.email.encrypt
                    && self.core.email.encrypt_append
                    && account.flags.encrypt_on_append()
            }
            IngestSource::Smtp { .. } => self.core.email.encrypt,
            IngestSource::Restore => false,
        };
        let is_encrypted = if do_encrypt
            && !message.is_encrypted()
            && let Some(encrypt_keys) = account.encryption_key()
        {
            match message.encrypt(encrypt_keys, account.flags).await {
                Ok(new_raw_message) => {
                    raw_message = Cow::from(new_raw_message);
                    raw_message_len = raw_message.len() as u64;
                    message = MessageParser::default()
                        .parse(raw_message.as_ref())
                        .ok_or_else(|| {
                            trc::EventType::MessageIngest(trc::MessageIngestEvent::Error)
                                .ctx(trc::Key::Code, 550)
                                .ctx(
                                    trc::Key::Reason,
                                    "Failed to parse encrypted e-mail message.",
                                )
                        })?;

                    // Disable spam training if requested
                    if !account.flags.can_train_spam_filter() {
                        train_spam = None;
                    }

                    true
                }
                Err(EncryptMessageError::Error(err)) => {
                    trc::bail!(
                        trc::StoreEvent::CryptoError
                            .into_err()
                            .caused_by(trc::location!())
                            .reason(err)
                    );
                }
                _ => unreachable!(),
            }
        } else {
            false
        };

        // Store blob
        let (blob_hash, blob_hold) = if !is_encrypted && let Some(blob_hash) = params.blob_hash {
            (blob_hash.clone(), None)
        } else {
            self.hold_blob(
                account_id,
                BlobHash::generate(raw_message.as_ref()),
                raw_message.as_ref(),
                60,
            )
            .await
            .map(|(hash, hold)| (hash, Some(hold)))
            .caused_by(trc::location!())?
        };

        // Build write batch
        batch.with_account_id(account_id);
        self.limit_disk_quota(batch, &account);
        self.limit_object_quota(batch, &account, StorageQuota::MaxEmails);

        // Reserve a document id and one IMAP UID per target mailbox
        let document_slot = batch.reserve_document_id(account_id, Collection::Email);
        let uid_slots = batch.reserve_uids(account_id, params.mailbox_ids.iter().copied());
        let mailbox_ids: TinyVec<[MessageUid; 2]> = params
            .mailbox_ids
            .iter()
            .copied()
            .map(MessageUid::new_unassigned)
            .collect();

        // Determine thread id
        let thread_slot = match (thread_result.thread_id, group_slot) {
            (_, Some(slot)) => Some(slot),
            (None, None) => {
                batch
                    .with_collection(Collection::Thread)
                    .create_document(document_slot)
                    .log_container_insert(SyncCollection::Thread);
                Some(document_slot)
            }
            (Some(_), None) => None,
        };

        let mut keywords = 0;
        let mut keywords_extra = Vec::new();
        let received_at = params.received_at.unwrap_or_else(now).min(MAX_RECEIVED_AT);
        for keyword in std::mem::take(&mut params.keywords) {
            match keyword.into_id() {
                Ok(id) => keywords |= 1 << id,
                Err(name) => keywords_extra.push(name),
            }
        }
        let mut data = PendingMessageData {
            data: MessageData {
                mailboxes: mailbox_ids,
                keywords,
                keywords_extra,
                thread_id: thread_result.thread_id.unwrap_or_default(),
                size: (message.raw().len() + extra_headers.len()) as u32,
                received_at,
                sent_at: MessageData::sent_at_offset(sent_at, received_at),
                change_id: 0,
            },
            uid_slots,
            thread_slot,
            change_id: None,
        };
        if let Some(container) = metadata
            .as_deref()
            .and_then(|metadata| metadata.shared.as_ref())
        {
            data.data.set_metadata_kinds(container.kinds());
        }
        let thread_ref = data.thread_id();

        // Request spam training
        if let Some(learn_spam) = train_spam {
            self.add_spam_sample(
                account_id,
                batch,
                params.blob_hash.unwrap_or(&blob_hash).clone(),
                if params.blob_hash.is_some() {
                    params.raw_message.len()
                } else {
                    raw_message.len()
                } as u64,
                message
                    .from()
                    .and_then(|s| s.first())
                    .and_then(|s| s.address())
                    .unwrap_or_default()
                    .to_string(),
                thread_name(message.subject().unwrap_or_default()).to_string(),
                learn_spam,
                !is_encrypted,
                params.session_id,
            );
        }

        let thread_info = ThreadInfo {
            thread_id: thread_ref,
            ref_ids: &message_ids,
        };
        batch
            .with_collection(Collection::Email)
            .create_document(document_slot);
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        batch
            .index_message(tenant_id, &message, &extra_headers, blob_hash.clone(), data)
            .caused_by(trc::location!())?;
        // SPDX-SnippetEnd
        #[cfg(not(feature = "enterprise"))]
        batch
            .index_message(&message, &extra_headers, blob_hash.clone(), data)
            .caused_by(trc::location!())?;
        batch
            .set(
                ValueClass::IndexProperty(IndexPropertyClass::Hash {
                    property: EmailField::Threading.into(),
                    hash: thread_result.thread_hash,
                }),
                thread_info,
            )
            .queue_document_index(SearchIndex::Email, account_id, QueueDocumentId::Current);

        let mut private_commit = PrivateMetadataCommit::default();
        if let Some(metadata) = metadata {
            metadata
                .build(
                    batch,
                    account_id,
                    // SPDX-SnippetBegin
                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                    // SPDX-License-Identifier: LicenseRef-SEL
                    #[cfg(feature = "enterprise")]
                    tenant_id,
                    // SPDX-SnippetEnd
                    PendingId::Slot(document_slot),
                    &mut private_commit,
                )
                .caused_by(trc::location!())?;
        }

        if let Some(blob_hold) = blob_hold {
            blob_hold.release(batch);
        }

        // Merge threads if necessary
        let thread_recheck = if !thread_result.merge_ids.is_empty() {
            batch.schedule_task(Task::MergeThreads(TaskMergeThreads {
                account_id: account_id.into(),
                status: TaskStatus::now(),
                thread_name: thread_result.thread_hash.to_string(),
                message_ids: Map::new(message_ids.into_iter().map(|id| id.to_string()).collect()),
            }));
            None
        } else if !message_ids.is_empty()
            && matches!(
                params.source,
                IngestSource::Jmap { .. } | IngestSource::Imap { .. }
            )
        {
            Some(PendingThread::new(
                thread_result.thread_hash,
                message_ids,
                thread_result.bucket_full,
            ))
        } else {
            None
        };

        // Add iTIP responses to batch
        if !itip_messages.is_empty() {
            ItipMessages::new(itip_messages)
                .queue(batch)
                .caused_by(trc::location!())?;
        }

        Ok(PendingIngest::Queued(PendingEmail {
            account_id,
            document_slot,
            uid_slots,
            thread_id: thread_ref,
            blob_hash,
            size: raw_message_len,
            thread_recheck,
            private_commit,
            event: match params.source {
                IngestSource::Smtp { .. } => {
                    if !is_spam {
                        MessageIngestEvent::Ham
                    } else {
                        MessageIngestEvent::Spam
                    }
                }
                IngestSource::Jmap { .. } | IngestSource::Restore => MessageIngestEvent::JmapAppend,
                IngestSource::Imap { .. } => MessageIngestEvent::ImapAppend,
            },
            mailbox_ids: std::mem::take(&mut params.mailbox_ids),
            message_id,
            session_id: params.session_id,
            start_time,
        }))
    }

    async fn email_ingest_finish(
        &self,
        pending: PendingEmail,
        assigned_ids: &AssignedIds,
    ) -> IngestedEmail {
        let PendingEmail {
            account_id,
            document_slot,
            uid_slots,
            thread_id,
            blob_hash,
            size,
            thread_recheck,
            private_commit,
            event,
            mailbox_ids,
            message_id,
            session_id,
            start_time,
        } = pending;
        self.private_metadata_committed(private_commit, assigned_ids)
            .await;
        let change_id = assigned_ids.last_change_id(account_id, SyncCollection::Email);
        let document_id = assigned_ids.slot(document_slot);
        let thread_id = match thread_id {
            PendingId::Assigned(thread_id) => thread_id,
            PendingId::Slot(slot) => assigned_ids.slot(slot),
        };
        let imap_uids = assigned_ids.slots(uid_slots).collect::<Vec<_>>();

        trc::event!(
            MessageIngest(event),
            SpanId = session_id,
            AccountId = account_id,
            DocumentId = document_id,
            MailboxId = mailbox_ids
                .iter()
                .map(|mailbox_id| trc::Value::from(*mailbox_id))
                .collect::<Vec<_>>(),
            BlobId = blob_hash.to_hex(),
            ChangeId = change_id,
            MessageId = message_id,
            Size = size,
            Elapsed = start_time.elapsed(),
        );

        IngestedEmail {
            document_id,
            thread_id,
            change_id,
            blob_id: BlobId {
                hash: blob_hash,
                class: BlobClass::Linked {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id,
                },
                section: None,
            },
            size: size as usize,
            imap_uids,
            thread_recheck,
        }
    }

    async fn find_thread_id(
        &self,
        account_id: u32,
        thread_name: &str,
        message_ids: &[u128],
    ) -> trc::Result<ThreadResult> {
        let mut result = ThreadResult {
            thread_id: None,
            thread_hash: thread_hash(thread_name),
            merge_ids: vec![],
            duplicate_ids: vec![],
            matched_ids: vec![],
            bucket_full: false,
        };

        if message_ids.is_empty() {
            return Ok(result);
        }

        // Find thread ids
        let thread_class = IndexPropertyClass::Hash {
            property: EmailField::Threading.into(),
            hash: result.thread_hash,
        };
        let key_len = thread_class.key_len();
        let document_id_pos = key_len - U32_LEN;
        let mut thread_merge = ThreadMerge::new();
        let mut rows = 0;
        self.store()
            .iterate(
                IterateParams::new(
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: u32::MAX,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
                            property: EmailField::Threading.into(),
                            hash: result.thread_hash,
                        }),
                    },
                    ValueKey {
                        account_id,
                        collection: Collection::Email.into(),
                        document_id: 0,
                        class: ValueClass::IndexProperty(IndexPropertyClass::Hash {
                            property: EmailField::Threading.into(),
                            hash: result.thread_hash,
                        }),
                    },
                )
                .limit(THREAD_SCAN_WINDOW),
                |key, value| {
                    rows += 1;
                    if key.len() == key_len {
                        // Find matching references
                        let references = value.get(U32_LEN..).unwrap_or_default();

                        if has_message_id(message_ids, references) {
                            let document_id = !key.deserialize_be_u32(document_id_pos)?;
                            let thread_id = value.deserialize_be_u32(0)?;

                            if message_ids.len() == references.len() / U128_LEN
                                && references
                                    .as_chunks::<U128_LEN>()
                                    .0
                                    .iter()
                                    .zip(message_ids.iter())
                                    .all(|(a, b)| u128::from_be_bytes(*a) == *b)
                            {
                                result.duplicate_ids.push(document_id);
                            }

                            thread_merge.add(thread_id, document_id);
                            result.matched_ids.push(document_id);
                        }
                    }

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        result.bucket_full = rows >= THREAD_SCAN_WINDOW;

        match thread_merge.num_thread_ids() {
            0 => Ok(result),
            1 => {
                // Happy path, only one thread id
                result.thread_id = thread_merge.thread_ids().next().copied();
                Ok(result)
            }
            _ => {
                // Multiple thread ids that this message belongs to, merge them
                let thread_merge = thread_merge.merge();
                result.merge_ids = thread_merge.merge_ids;
                result.thread_id = Some(thread_merge.thread_id);
                Ok(result)
            }
        }
    }

    async fn add_account_spam_samples(
        &self,
        batch: &mut BatchBuilder,
        account_id: u32,
        samples: SpamSamples,
        span_id: u64,
    ) -> trc::Result<()> {
        if self.core.spam.classifier.is_none() || samples.is_empty() {
            return Ok(());
        }

        let SpamSamples {
            documents,
            spam,
            prepared,
        } = samples;
        batch.with_account_id(account_id);
        for sample in prepared {
            self.add_spam_sample(
                account_id,
                batch,
                sample.hash,
                sample.size,
                sample.from,
                sample.subject,
                sample.is_spam,
                true,
                span_id,
            );
            batch.commit_point();
        }
        if documents.is_empty() {
            return Ok(());
        }

        self.message_metadata(account_id, &documents, |document_id, bytes| {
            let sample = SpamSample::from_metadata(bytes, spam.contains(document_id))?;
            self.add_spam_sample(
                account_id,
                batch,
                sample.hash,
                sample.size,
                sample.from,
                sample.subject,
                sample.is_spam,
                true,
                span_id,
            );
            batch.commit_point();
            Ok(true)
        })
        .await
        .caused_by(trc::location!())
    }

    fn add_spam_sample(
        &self,
        account_id: u32,
        batch: &mut BatchBuilder,
        hash: BlobHash,
        size: u64,
        from: String,
        subject: String,
        is_spam: bool,
        hold_sample: bool,
        span_id: u64,
    ) {
        if let Some(config) = &self.core.spam.classifier {
            let until = now() + config.hold_samples_for;

            let sample = SpamTrainingSample {
                account_id: Some(Id::from(account_id)),
                blob_id: BlobId::new(hash.clone(), BlobClass::default()),
                delete_after_use: !hold_sample,
                expires_at: UTCDateTime::from_timestamp(until as i64),
                from,
                is_spam,
                subject,
            }
            .to_pickled_vec();

            let object_id = ObjectType::SpamTrainingSample.to_id();
            let item_id = SnowflakeIdGenerator::global_id().unwrap_or_default();
            batch
                .set(
                    BlobOp::Link {
                        hash,
                        to: BlobLink::Temporary { until },
                    },
                    BlobLinkValue::new(size).with_object_id(ObjectId::new(
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
                        key: (account_id as u64).serialize(),
                    }),
                    vec![],
                );

            trc::event!(
                Spam(SpamEvent::TrainSampleAdded),
                AccountId = batch.last_account_id(),
                Details = if is_spam { "spam" } else { "ham" },
                Expires = trc::Value::Timestamp(until),
                SpanId = span_id,
            );
        }
    }
}

pub fn thread_hash(thread_name: &str) -> Hash128 {
    Hash128::from(xxh3_128(
        if !thread_name.is_empty() {
            thread_name
        } else {
            "!"
        }
        .as_bytes(),
    ))
}

pub fn has_message_id(a: &[u128], b: &[u8]) -> bool {
    sorted_intersect(
        a.iter().copied(),
        b.as_chunks::<U128_LEN>()
            .0
            .iter()
            .map(|chunk| u128::from_be_bytes(*chunk)),
    )
}

fn sorted_intersect(mut a: impl Iterator<Item = u128>, mut b: impl Iterator<Item = u128>) -> bool {
    let (Some(mut left), Some(mut right)) = (a.next(), b.next()) else {
        return false;
    };

    loop {
        match left.cmp(&right) {
            Ordering::Equal => return true,
            Ordering::Less => match a.next() {
                Some(next) => left = next,
                None => return false,
            },
            Ordering::Greater => match b.next() {
                Some(next) => right = next,
                None => return false,
            },
        }
    }
}

impl IngestSource<'_> {
    pub fn is_smtp(&self) -> bool {
        matches!(self, Self::Smtp { .. })
    }
}

pub struct ThreadInfo<'x> {
    pub thread_id: PendingId,
    pub ref_ids: &'x [u128],
}

impl From<ThreadInfo<'_>> for SizedSetValue {
    fn from(info: ThreadInfo<'_>) -> Self {
        let mut buf = Vec::with_capacity(U32_LEN + 1 + info.ref_ids.len() * U128_LEN);
        buf.extend_from_slice(&info.thread_id.assigned().unwrap_or_default().to_be_bytes());
        for ref_id in info.ref_ids {
            buf.extend_from_slice(ref_id.to_be_bytes().as_slice());
        }

        match info.thread_id {
            PendingId::Slot(slot) => (
                buf,
                vec![Patch {
                    offset: 0,
                    source: PatchSource::SlotBeU32(slot),
                }],
            )
                .into(),
            PendingId::Assigned(_) => buf.into(),
        }
    }
}

const THREAD_SCAN_WINDOW: usize = 256;

pub struct ThreadMerge {
    entries: AHashMap<u32, Vec<u32>>,
}

pub struct ThreadMergeResult {
    pub thread_id: u32,
    pub merge_ids: Vec<u32>,
}

impl ThreadMerge {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            entries: AHashMap::with_capacity(8),
        }
    }

    pub fn add(&mut self, thread_id: u32, document_id: u32) {
        self.entries.entry(thread_id).or_default().push(document_id);
    }

    pub fn num_thread_ids(&self) -> usize {
        self.entries.len()
    }

    pub fn thread_ids(&self) -> impl Iterator<Item = &u32> {
        self.entries.keys()
    }

    pub fn thread_groups(&self) -> impl Iterator<Item = (&u32, &Vec<u32>)> {
        self.entries.iter()
    }

    pub fn merge_thread_id(&self) -> u32 {
        let mut max_thread_id = u32::MAX;
        let mut max_count = 0;

        for (thread_id, ids) in &self.entries {
            match ids.len().cmp(&max_count) {
                Ordering::Greater => {
                    max_count = ids.len();
                    max_thread_id = *thread_id;
                }
                Ordering::Equal => {
                    if *thread_id < max_thread_id {
                        max_thread_id = *thread_id;
                    }
                }
                Ordering::Less => (),
            }
        }

        max_thread_id
    }

    pub fn merge(self) -> ThreadMergeResult {
        let mut max_thread_id = u32::MAX;
        let mut max_count = 0;
        let mut merge_ids = Vec::with_capacity(self.entries.len());

        for (thread_id, ids) in self.entries {
            match ids.len().cmp(&max_count) {
                Ordering::Greater => {
                    max_count = ids.len();
                    max_thread_id = thread_id;
                }
                Ordering::Equal => {
                    if thread_id < max_thread_id {
                        max_thread_id = thread_id;
                    }
                }
                Ordering::Less => (),
            }
            merge_ids.push(thread_id);
        }

        ThreadMergeResult {
            thread_id: max_thread_id,
            merge_ids,
        }
    }
}

mod checks;
pub mod group;
pub mod recheck;
#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/message/ingest/tests.rs"]
mod tests;
