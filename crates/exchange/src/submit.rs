/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::ExchangeCacheFetch,
    mail::{CommitOutcome, MailEdits, fetch_raw_message, keywords_fit},
    mail_copy::stored_email_object,
    store::{
        account::ExchangeAccountStore,
        object::{CreatedEmail, ExchangeObject, ExchangeObjectStore},
    },
};
use common::{
    KV_EXCHANGE_SUBMIT, KV_LOCK_EXCHANGE_SUBMIT, Server,
    auth::{AccessToken, AccountInfo, oauth::scope::data_type_scopes},
    network::{ServerInstance, memory::MemoryReservation, stream::NullIo},
};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        ingest::{IngestEmail, IngestSource},
        messagedata::{KEYWORD_BITS, MessageData, SERVER_SET_KEYWORDS},
    },
};
use mail_builder::headers::{Header, address::Address, date::Date};
use mail_parser::{AddressList, HeaderName, MessageParser};
use registry::schema::enums::Permission;
use smallvec::SmallVec;
use smtp::{
    core::{Session, SessionData, State},
    inbound::data::MessageOrigin,
    queue::QueueId,
};
use smtp_proto::{MailFrom, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_SUCCESS, RcptTo};
use std::{ops::Range, sync::Arc, time::Duration};
use store::{dispatch::lookup::KeyValue, write::now};
use trc::AddContext;
use types::{
    keyword::{DRAFT, Keyword, SEEN},
    type_state::DataType,
};
use utils::{sanitize_email, sanitize_envelope_address};

pub struct Submission<'x> {
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub instance: &'x Arc<ServerInstance>,
    pub session_id: u64,
    pub message: Outgoing,
    pub recipients: Recipients,
    pub options: SubmitOptions,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubmitOptions {
    pub hold_until: Option<u64>,
    pub delivery_report: DeliveryReport,
    pub once: Option<SubmitOnce>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmitOnce {
    device_slot: u16,
    len: u8,
    client_id: [u8; CLIENT_ID_MAX_LEN],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeliveryReport {
    #[default]
    Default,
    Requested,
    FromMessage,
}

impl DeliveryReport {
    fn is_requested(self, return_receipt: bool) -> bool {
        match self {
            DeliveryReport::Requested => true,
            DeliveryReport::Default => false,
            DeliveryReport::FromMessage => return_receipt,
        }
    }
}

pub enum Outgoing {
    Composed {
        raw: Vec<u8>,
        save_copy: Option<SaveCopy>,
    },
    Stored {
        document_id: u32,
        data: MessageData,
        after: AfterSend,
    },
}

pub struct SaveCopy {
    pub mailbox_id: u32,
    pub carried: Option<ExchangeObject>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterSend {
    Keep,
    MoveTo {
        from: u32,
        to: u32,
        alias: Option<u32>,
    },
    Delete {
        from: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipients {
    Headers,
    Explicit(Vec<String>),
}

#[derive(Debug)]
pub struct Submitted {
    pub queue_id: QueueId,
    pub sent_copy: Option<trc::Result<u32>>,
    pub after_send: Option<trc::Result<CommitOutcome>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    Forbidden,
    NotFound,
    TooLarge { max: usize },
    Malformed,
    NoRecipients,
    SendAsDenied,
    Sender(Box<str>),
    Recipients(Vec<RejectedRecipient>),
    Rejected(Box<str>),
    AlreadySent,
    InProgress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRecipient {
    pub address: Box<str>,
    pub reply: Box<str>,
}

struct Envelope {
    mail_from: String,
    rcpt_to: Vec<String>,
    prefix: Vec<u8>,
    bcc: SmallVec<[Range<usize>; 1]>,
    sender: SmallVec<[Range<usize>; 1]>,
    return_receipt: bool,
}

struct Wire {
    mail_from: String,
    rcpt_to: Vec<String>,
    message: Vec<u8>,
    return_receipt: bool,
}

struct SentCopy {
    prefix: Vec<u8>,
    raw: Vec<u8>,
    draft: DraftCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DraftCopy {
    Unchanged,
    Rewritten,
}

struct SubmitTask {
    server: Server,
    access_token: AccessToken,
    account_id: u32,
    instance: Arc<ServerInstance>,
    session_id: u64,
    options: SubmitOptions,
}

enum Disposition {
    Discard,
    SaveCopy(SaveCopy),
    Stored {
        document_id: u32,
        data: MessageData,
        after: AfterSend,
    },
}

enum AfterQueue {
    Nothing,
    Save {
        target: SaveCopy,
        copy: SentCopy,
    },
    Edit {
        document_id: u32,
        data: MessageData,
        after: AfterSend,
    },
    Replace {
        document_id: u32,
        data: MessageData,
        from: u32,
        to: u32,
        alias: Option<u32>,
        copy: SentCopy,
    },
}

const SEEN_BIT: u32 = 1 << SEEN;
const DRAFT_BIT: u32 = 1 << DRAFT;
const INVALID_ADDRESS: &str = "501 5.1.3 Invalid recipient address.";
const CLIENT_ID_MAX_LEN: usize = 64;
const SUBMIT_ONCE_TTL_SECS: u64 = 86_400;
const SUBMIT_ONCE_LOCK_SECS: u64 = 600;
const AFTER_SEND_ATTEMPTS: usize = 5;

enum Claim {
    Acquired(Vec<u8>),
    AlreadySent,
    InProgress,
}

pub trait ExchangeSubmit: Sync + Send {
    fn submit(
        &self,
        submission: Submission<'_>,
    ) -> impl Future<Output = trc::Result<Result<Submitted, SubmitError>>> + Send;
}

impl ExchangeSubmit for Server {
    async fn submit(
        &self,
        submission: Submission<'_>,
    ) -> trc::Result<Result<Submitted, SubmitError>> {
        let Submission {
            access_token,
            account_id,
            instance,
            session_id,
            message,
            recipients,
            options,
        } = submission;
        if !access_token.is_member(account_id)
            || !access_token.has_permission(Permission::EmailSend)
            || !access_token.allows_oauth_scopes(data_type_scopes(DataType::EmailSubmission))
        {
            return Ok(Err(SubmitError::Forbidden));
        }
        let task = SubmitTask {
            server: self.clone(),
            access_token: access_token.clone(),
            account_id,
            instance: instance.clone(),
            session_id,
            options,
        };
        match tokio::spawn(task.run(message, recipients)).await {
            Ok(result) => result,
            Err(_) => Err(trc::EventType::Server(trc::ServerEvent::ThreadError)
                .into_err()
                .caused_by(trc::location!())),
        }
    }
}

impl SubmitOnce {
    pub fn eas(device_slot: u16, bytes: &[u8]) -> Option<Self> {
        let len = u8::try_from(bytes.len()).ok().filter(|len| *len > 0)?;
        let mut once = SubmitOnce {
            device_slot,
            len,
            client_id: [0; CLIENT_ID_MAX_LEN],
        };
        once.client_id
            .get_mut(..bytes.len())?
            .copy_from_slice(bytes);
        Some(once)
    }

    fn key(&self, account_id: u32) -> Vec<u8> {
        let client_id = self
            .client_id
            .get(..usize::from(self.len))
            .unwrap_or_default();
        let mut key = Vec::with_capacity(size_of::<u32>() + size_of::<u16>() + client_id.len());
        key.extend_from_slice(&account_id.to_be_bytes());
        key.extend_from_slice(&self.device_slot.to_be_bytes());
        key.extend_from_slice(client_id);
        key
    }

    async fn claim(&self, server: &Server, account_id: u32) -> trc::Result<Claim> {
        let store = server.in_memory_store();
        let key = self.key(account_id);
        if !store
            .try_lock(KV_LOCK_EXCHANGE_SUBMIT, &key, SUBMIT_ONCE_LOCK_SECS)
            .await
            .caused_by(trc::location!())?
        {
            return Ok(Claim::InProgress);
        }
        match store
            .key_exists(KeyValue::<()>::build_key(KV_EXCHANGE_SUBMIT, &key))
            .await
        {
            Ok(false) => Ok(Claim::Acquired(key)),
            Ok(true) => {
                SubmitOnce::unlock(server, &key).await;
                Ok(Claim::AlreadySent)
            }
            Err(err) => {
                SubmitOnce::unlock(server, &key).await;
                Err(err.caused_by(trc::location!()))
            }
        }
    }

    async fn mark_sent(server: &Server, key: &[u8]) {
        if let Err(err) = server
            .in_memory_store()
            .key_set(
                KeyValue::with_prefix(KV_EXCHANGE_SUBMIT, key, vec![])
                    .expires(SUBMIT_ONCE_TTL_SECS),
            )
            .await
        {
            trc::error!(err.caused_by(trc::location!()));
        }
    }

    async fn unlock(server: &Server, key: &[u8]) {
        if let Err(err) = server
            .in_memory_store()
            .remove_lock(KV_LOCK_EXCHANGE_SUBMIT, key)
            .await
        {
            trc::error!(err.caused_by(trc::location!()));
        }
    }
}

impl SubmitTask {
    async fn run(
        self,
        message: Outgoing,
        recipients: Recipients,
    ) -> trc::Result<Result<Submitted, SubmitError>> {
        let claim = match self.options.once {
            Some(once) => match once.claim(&self.server, self.account_id).await? {
                Claim::Acquired(key) => Some(key),
                Claim::AlreadySent => return Ok(Err(SubmitError::AlreadySent)),
                Claim::InProgress => return Ok(Err(SubmitError::InProgress)),
            },
            None => None,
        };
        let queued = self.enqueue(message, recipients).await;
        if let Some(key) = &claim {
            if matches!(queued, Ok(Ok(_))) {
                SubmitOnce::mark_sent(&self.server, key).await;
            }
            SubmitOnce::unlock(&self.server, key).await;
        }
        let (queue_id, after_queue) = match queued? {
            Ok(queued) => queued,
            Err(err) => return Ok(Err(err)),
        };
        Ok(Ok(self.finish(queue_id, after_queue).await))
    }

    async fn enqueue(
        &self,
        message: Outgoing,
        recipients: Recipients,
    ) -> trc::Result<Result<(QueueId, AfterQueue), SubmitError>> {
        let server = &self.server;
        let account_id = self.account_id;
        let (raw, reservation, disposition) = match message {
            Outgoing::Composed { raw, save_copy } => (
                raw,
                None,
                save_copy.map_or(Disposition::Discard, Disposition::SaveCopy),
            ),
            Outgoing::Stored {
                document_id,
                data,
                after,
            } => match fetch_raw_message(server, account_id, document_id).await? {
                Some((raw, reservation)) => (
                    raw,
                    Some(reservation),
                    Disposition::Stored {
                        document_id,
                        data,
                        after,
                    },
                ),
                None => return Ok(Err(SubmitError::NotFound)),
            },
        };
        let max = server.core.email.mail_max_size;
        if raw.len() > max {
            return Ok(Err(SubmitError::TooLarge { max }));
        }

        let account = server
            .account_info(account_id)
            .await
            .caused_by(trc::location!())?;
        let caller = if self.access_token.is_account_id(account_id) {
            None
        } else {
            Some(
                server
                    .account_info(self.access_token.account_id())
                    .await
                    .caused_by(trc::location!())?,
            )
        };
        let envelope = match Envelope::parse(&raw, &account, caller.as_ref(), recipients, || {
            server.core.network.message_id()
        }) {
            Ok(envelope) => envelope,
            Err(err) => {
                if let SubmitError::Recipients(invalid) = &err {
                    for recipient in invalid {
                        trc::event!(
                            Smtp(trc::SmtpEvent::InvalidRecipientAddress),
                            SpanId = self.session_id,
                            AccountId = account_id,
                            To = recipient.address.clone(),
                            Reason = recipient.reply.clone(),
                        );
                    }
                }
                return Ok(Err(err));
            }
        };
        let (wire, retained) = envelope.into_wire(raw);
        let after_queue = disposition.after_queue(retained, &wire.message);
        Ok(self
            .queue(account, wire, reservation)
            .await
            .map(|queue_id| (queue_id, after_queue)))
    }

    async fn queue(
        &self,
        account: AccountInfo,
        wire: Wire,
        reservation: Option<MemoryReservation>,
    ) -> Result<QueueId, SubmitError> {
        let mut session = Session::<NullIo>::local(
            self.server.clone(),
            self.instance.clone(),
            SessionData::local(account, None, vec![], vec![], self.session_id),
        );
        let _ = session
            .handle_mail_from(MailFrom {
                address: wire.mail_from.into(),
                hold_until: self
                    .options
                    .hold_until
                    .filter(|hold_until| *hold_until > now())
                    .unwrap_or_default(),
                ..Default::default()
            })
            .await;
        if let Some(reply) = session.has_failed() {
            return Err(SubmitError::Sender(reply.into_boxed_str()));
        }

        session.params.rcpt_errors_wait = Duration::ZERO;
        let notify = if self
            .options
            .delivery_report
            .is_requested(wire.return_receipt)
        {
            RCPT_NOTIFY_SUCCESS | RCPT_NOTIFY_FAILURE
        } else {
            0
        };
        let mut rejected = Vec::new();
        for address in wire.rcpt_to {
            let _ = session
                .handle_rcpt_to(RcptTo {
                    address: address.as_str().into(),
                    flags: notify,
                    ..Default::default()
                })
                .await;
            if let Some(reply) = session.has_failed() {
                rejected.push(RejectedRecipient {
                    address: address.into_boxed_str(),
                    reply: reply.into_boxed_str(),
                });
            }
        }
        if !rejected.is_empty() {
            return Err(SubmitError::Recipients(rejected));
        }

        session.data.message = wire.message;
        session.data.message_memory = reservation;
        let response = session.queue_message(MessageOrigin::Internal).await;
        if let State::Accepted(queue_id) = session.state {
            Ok(queue_id)
        } else {
            Err(SubmitError::Rejected(
                String::from_utf8_lossy(&response).trim_end().into(),
            ))
        }
    }

    async fn finish(&self, queue_id: QueueId, after_queue: AfterQueue) -> Submitted {
        let mut submitted = Submitted {
            queue_id,
            sent_copy: None,
            after_send: None,
        };
        match after_queue {
            AfterQueue::Nothing => {}
            AfterQueue::Save { target, copy } => {
                submitted.sent_copy = Some(
                    self.save_sent(
                        target.mailbox_id,
                        copy,
                        (target.carried, None),
                        vec![Keyword::Seen],
                    )
                    .await,
                );
            }
            AfterQueue::Edit {
                document_id,
                data,
                after,
            } => {
                submitted.after_send = self.edit(document_id, data, after).await;
            }
            AfterQueue::Replace {
                document_id,
                data,
                from,
                to,
                alias,
                copy,
            } => {
                let sent_copy = match self.draft_object(document_id).await {
                    Ok(carried) => {
                        let mut bits =
                            data.keywords & KEYWORD_BITS & !SERVER_SET_KEYWORDS & !DRAFT_BIT;
                        if keywords_fit(&self.server.core.email.limits, &data, SEEN_BIT, DRAFT_BIT)
                        {
                            bits |= SEEN_BIT;
                        }
                        let keywords = (0..u32::BITS)
                            .filter(|bit| bits & (1 << bit) != 0)
                            .filter_map(|bit| Keyword::try_from_id(bit as usize).ok())
                            .chain(data.keywords_extra.iter().cloned().map(Keyword::Other))
                            .collect();
                        self.save_sent(to, copy, (carried, alias), keywords).await
                    }
                    Err(err) => Err(err),
                };
                let after = if sent_copy.is_ok() {
                    AfterSend::Delete { from }
                } else {
                    AfterSend::MoveTo { from, to, alias }
                };
                submitted.sent_copy = Some(sent_copy);
                submitted.after_send = self.edit(document_id, data, after).await;
            }
        }
        submitted
    }

    async fn edit(
        &self,
        document_id: u32,
        data: MessageData,
        after: AfterSend,
    ) -> Option<trc::Result<CommitOutcome>> {
        let mut outcome = self.edit_once(document_id, data, after).await;
        for _ in 1..AFTER_SEND_ATTEMPTS {
            if !matches!(outcome, Some(Ok(CommitOutcome::Conflict))) {
                break;
            }
            let data = match self.server.get_cached_messages(self.account_id).await {
                Ok(cache) => cache.message_data(document_id),
                Err(err) => return Some(Err(err.caused_by(trc::location!()))),
            };
            outcome = Some(match data {
                Some(data) => self
                    .edit_once(document_id, data, after)
                    .await
                    .unwrap_or(Ok(CommitOutcome::Committed(None))),
                None => Ok(CommitOutcome::Committed(None)),
            });
        }
        outcome
    }

    async fn edit_once(
        &self,
        document_id: u32,
        data: MessageData,
        after: AfterSend,
    ) -> Option<trc::Result<CommitOutcome>> {
        let mut edits = MailEdits::new(self.account_id);
        let seen = if keywords_fit(&self.server.core.email.limits, &data, SEEN_BIT, DRAFT_BIT) {
            SEEN_BIT
        } else {
            0
        };
        let queued = match after {
            AfterSend::MoveTo { from, to, alias } if from != to => {
                edits.move_with_keywords(document_id, data, (from, to), (seen, DRAFT_BIT), alias)
            }
            AfterSend::Keep | AfterSend::MoveTo { .. } => {
                edits.patch_keywords(document_id, &data, (seen, DRAFT_BIT))
            }
            AfterSend::Delete { from } => edits.remove_from(document_id, data, from),
        };
        match queued {
            Ok(true) => Some(
                edits
                    .commit(&self.server, &self.access_token, self.session_id)
                    .await,
            ),
            Ok(false) => None,
            Err(err) => Some(Err(err)),
        }
    }

    async fn draft_object(&self, document_id: u32) -> trc::Result<Option<ExchangeObject>> {
        let objects = self
            .server
            .get_cached_exchange(self.account_id)
            .await
            .caused_by(trc::location!())?;
        stored_email_object(&self.server, &objects, self.account_id, document_id).await
    }

    async fn save_sent(
        &self,
        mailbox_id: u32,
        copy: SentCopy,
        (carried, alias): (Option<ExchangeObject>, Option<u32>),
        keywords: Vec<Keyword>,
    ) -> trc::Result<u32> {
        let raw = copy.build();
        let owner = self
            .server
            .exchange_quota_owner(&self.access_token, self.account_id)
            .await?;
        let target = self
            .server
            .exchange_target_token(&self.access_token, self.account_id)
            .await?;
        self.server
            .create_email(
                IngestEmail {
                    raw_message: &raw,
                    blob_hash: None,
                    message: MessageParser::new().parse(&raw).as_ref(),
                    access_token: target.as_ref().unwrap_or(&self.access_token),
                    mailbox_ids: vec![mailbox_id],
                    keywords,
                    received_at: None,
                    source: IngestSource::Jmap {
                        train_classifier: false,
                    },
                    metadata: None,
                    session_id: self.session_id,
                },
                owner,
                CreatedEmail {
                    carried,
                    alias,
                    ..Default::default()
                },
                self.server.core.exchange.max_object_size,
            )
            .await
            .map(|email| email.document_id)
            .caused_by(trc::location!())
    }
}

impl Envelope {
    fn parse(
        raw: &[u8],
        account: &AccountInfo,
        caller: Option<&AccountInfo>,
        recipients: Recipients,
        message_id: impl FnOnce() -> String,
    ) -> Result<Self, SubmitError> {
        let message = MessageParser::new()
            .parse(raw)
            .filter(|message| message.headers().has_known())
            .ok_or(SubmitError::Malformed)?;
        let headers = message.headers();

        let mut from = None;
        for list in headers.all_from() {
            let address = own_address(&list, account)?;
            if from.is_none() {
                from = address;
            }
        }
        let mut sender = None;
        let mut replaced = SmallVec::new();
        for header in headers.all(HeaderName::Sender) {
            let list = header.value().as_address().ok_or(SubmitError::Malformed)?;
            match own_address(&list, account) {
                Ok(address) => {
                    if sender.is_none() {
                        sender = address;
                    }
                }
                Err(SubmitError::SendAsDenied)
                    if caller.is_some_and(|caller| own_address(&list, caller).is_ok()) =>
                {
                    replaced.push(header.offset_field() as usize..header.offset_end() as usize);
                }
                Err(err) => return Err(err),
            }
        }

        let mut prefix = Vec::new();
        let from = match from {
            Some(from) => from,
            None if headers.contains(HeaderName::From) => return Err(SubmitError::Malformed),
            None => {
                let primary = account.addresses.first().ok_or(SubmitError::SendAsDenied)?;
                prefix.extend_from_slice(b"From: ");
                Address::new_address(account.account.description.as_deref(), primary.as_str())
                    .write_header(&mut prefix, 6);
                primary.to_ascii_lowercase()
            }
        };
        let mail_from = sender.unwrap_or(from);
        if !headers.contains(HeaderName::Date) {
            prefix.extend_from_slice(b"Date: ");
            Date::now().write_header(&mut prefix, 6);
        }
        if !headers.contains(HeaderName::MessageId) {
            prefix.extend_from_slice(b"Message-ID: <");
            prefix.extend_from_slice(message_id().as_bytes());
            prefix.extend_from_slice(b">\r\n");
        }

        let mut rcpt_to = Vec::new();
        let mut invalid = Vec::new();
        match recipients {
            Recipients::Headers => {
                for list in headers
                    .all_to()
                    .chain(headers.all_cc())
                    .chain(headers.all_bcc())
                {
                    for mailbox in list.mailboxes() {
                        match mailbox.address().and_then(sanitize_envelope_address) {
                            Some(address) => rcpt_to.push(address),
                            None => invalid.push(RejectedRecipient::invalid(
                                mailbox
                                    .address()
                                    .or(mailbox.name())
                                    .unwrap_or_default()
                                    .into(),
                            )),
                        }
                    }
                }
            }
            Recipients::Explicit(addresses) => {
                rcpt_to.reserve(addresses.len());
                for address in addresses {
                    match sanitize_envelope_address(&address) {
                        Some(address) => rcpt_to.push(address),
                        None => invalid.push(RejectedRecipient::invalid(address.into_boxed_str())),
                    }
                }
            }
        }
        if !invalid.is_empty() {
            return Err(SubmitError::Recipients(invalid));
        }
        rcpt_to.sort_unstable();
        rcpt_to.dedup();
        if rcpt_to.is_empty() {
            return Err(SubmitError::NoRecipients);
        }

        let bcc = headers
            .all(HeaderName::Bcc)
            .map(|header| header.offset_field() as usize..header.offset_end() as usize)
            .collect();

        Ok(Envelope {
            mail_from,
            rcpt_to,
            prefix,
            bcc,
            sender: replaced,
            return_receipt: headers.contains(HeaderName::ReturnReceiptTo),
        })
    }

    fn into_wire(self, raw: Vec<u8>) -> (Wire, Option<SentCopy>) {
        if self.prefix.is_empty() && self.bcc.is_empty() && self.sender.is_empty() {
            let wire = Wire {
                mail_from: self.mail_from,
                rcpt_to: self.rcpt_to,
                message: raw,
                return_receipt: self.return_receipt,
            };
            return (wire, None);
        }
        let mut message = Vec::with_capacity(self.prefix.len() + raw.len());
        message.extend_from_slice(&self.prefix);
        if self.sender.is_empty() {
            extend_without(&mut message, &raw, &self.bcc);
        } else {
            let mut removed: SmallVec<[Range<usize>; 2]> =
                self.bcc.iter().chain(&self.sender).cloned().collect();
            removed.sort_unstable_by_key(|range| range.start);
            extend_without(&mut message, &raw, &removed);
        }
        let wire = Wire {
            mail_from: self.mail_from,
            rcpt_to: self.rcpt_to,
            message,
            return_receipt: self.return_receipt,
        };
        let retained = if self.sender.is_empty() {
            let draft = if self.prefix.is_empty() {
                DraftCopy::Unchanged
            } else {
                DraftCopy::Rewritten
            };
            SentCopy {
                prefix: self.prefix,
                raw,
                draft,
            }
        } else {
            let mut kept = Vec::with_capacity(raw.len());
            extend_without(&mut kept, &raw, &self.sender);
            SentCopy {
                prefix: self.prefix,
                raw: kept,
                draft: DraftCopy::Rewritten,
            }
        };
        (wire, Some(retained))
    }
}

fn extend_without(out: &mut Vec<u8>, raw: &[u8], removed: &[Range<usize>]) {
    let mut position = 0;
    for range in removed {
        if let Some(kept) = raw.get(position..range.start) {
            out.extend_from_slice(kept);
        }
        position = position.max(range.end);
    }
    if let Some(kept) = raw.get(position..) {
        out.extend_from_slice(kept);
    }
}

impl SentCopy {
    fn build(self) -> Vec<u8> {
        let SentCopy {
            mut prefix, raw, ..
        } = self;
        if prefix.is_empty() {
            return raw;
        }
        prefix.extend_from_slice(&raw);
        prefix
    }
}

impl RejectedRecipient {
    fn invalid(address: Box<str>) -> Self {
        RejectedRecipient {
            address,
            reply: INVALID_ADDRESS.into(),
        }
    }
}

impl Disposition {
    fn after_queue(self, retained: Option<SentCopy>, wire: &[u8]) -> AfterQueue {
        match self {
            Disposition::Discard => AfterQueue::Nothing,
            Disposition::SaveCopy(target) => AfterQueue::Save {
                target,
                copy: retained.unwrap_or_else(|| SentCopy {
                    prefix: Vec::new(),
                    raw: wire.to_vec(),
                    draft: DraftCopy::Unchanged,
                }),
            },
            Disposition::Stored {
                document_id,
                data,
                after,
            } => match (after, retained) {
                (AfterSend::MoveTo { from, to, alias }, Some(copy))
                    if copy.draft == DraftCopy::Rewritten =>
                {
                    AfterQueue::Replace {
                        document_id,
                        data,
                        from,
                        to,
                        alias,
                        copy,
                    }
                }
                _ => AfterQueue::Edit {
                    document_id,
                    data,
                    after,
                },
            },
        }
    }
}

fn own_address(
    list: &AddressList<'_>,
    account: &AccountInfo,
) -> Result<Option<String>, SubmitError> {
    let mut first = None;
    for mailbox in list.mailboxes() {
        let address = mailbox
            .address()
            .and_then(sanitize_email)
            .ok_or(SubmitError::Malformed)?;
        if !account
            .addresses
            .iter()
            .any(|own| own.eq_ignore_ascii_case(&address))
        {
            return Err(SubmitError::SendAsDenied);
        }
        if first.is_none() {
            first = Some(address);
        }
    }
    Ok(first)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/submit/tests.rs"]
mod tests;
