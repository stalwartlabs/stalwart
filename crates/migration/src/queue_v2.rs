/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Server,
    config::smtp::queue::{QueueExpiry, QueueName},
};
use smtp::queue::{
    Error, ErrorDetails, HostResponse, Message, QuotaKey, Recipient, Schedule, Status,
    UnexpectedResponse,
};
use smtp_proto::Response;
use std::net::IpAddr;
use store::{
    Deserialize, IterateParams, Serialize, ValueKey,
    write::{
        AlignedBytes, Archive, Archiver, BatchBuilder, QueueClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use types::blob_hash::BlobHash;

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, Clone, PartialEq, Eq)]
pub struct LegacyMessage {
    pub created: u64,
    pub blob_hash: BlobHash,

    pub return_path: String,
    pub recipients: Vec<LegacyRecipient>,

    pub received_from_ip: IpAddr,
    pub received_via_port: u16,

    pub flags: u64,
    pub env_id: Option<String>,
    pub priority: i16,

    pub size: u64,
    pub quota_keys: Vec<LegacyQuotaKey>,
}

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Deserialize,
)]
pub struct LegacyRecipient {
    pub address: String,

    pub retry: Schedule<u32>,
    pub notify: Schedule<u32>,
    pub expires: QueueExpiry,

    pub queue: QueueName,
    pub status: Status<LegacyHostResponse<String>, LegacyErrorDetails>,
    pub flags: u64,
    pub orcpt: Option<String>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    serde::Deserialize,
)]
pub struct LegacyHostResponse<T> {
    pub hostname: T,
    pub response: Response<String>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    serde::Deserialize,
)]
pub struct LegacyUnexpectedResponse {
    pub command: String,
    pub response: Response<String>,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Default,
    serde::Deserialize,
)]
pub struct LegacyErrorDetails {
    pub entity: String,
    pub details: LegacyError,
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    serde::Deserialize,
    Default,
)]
pub enum LegacyError {
    DnsError(String),
    UnexpectedResponse(LegacyUnexpectedResponse),
    ConnectionError(String),
    TlsError(String),
    DaneError(String),
    MtaStsError(String),
    RateLimited,
    #[default]
    ConcurrencyLimited,
    Io(String),
}

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Deserialize,
)]
pub enum LegacyQuotaKey {
    Size { key: Vec<u8>, id: u64 },
    Count { key: Vec<u8>, id: u64 },
}

pub(crate) async fn migrate_queue_v014(server: &Server) -> trc::Result<()> {
    let mut messages = Vec::new();
    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::Queue(QueueClass::Message(0))),
                ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX))),
            ),
            |key, value| {
                let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(value)
                    .caused_by(trc::location!())?;
                match archive.deserialize_untrusted::<LegacyMessage>() {
                    Ok(message) => {
                        messages.push((key.deserialize_be_u64(0)?, Message::from(message)));
                    }
                    Err(err) => {
                        if archive.deserialize_untrusted::<Message>().is_err() {
                            return Err(err.caused_by(trc::location!()));
                        }
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let mut batch = BatchBuilder::new();
    let count = messages.len();
    for (queue_id, message) in messages {
        batch.set(
            ValueClass::Queue(QueueClass::Message(queue_id)),
            Archiver::new(message)
                .serialize()
                .caused_by(trc::location!())?,
        );

        if batch.is_large_batch() {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
        }
    }

    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!("Migrated {count} queued messages",)
    );

    Ok(())
}

impl From<LegacyMessage> for Message {
    fn from(legacy: LegacyMessage) -> Self {
        Message {
            created: legacy.created,
            blob_hash: legacy.blob_hash,

            return_path: legacy.return_path.into_boxed_str(),
            recipients: legacy.recipients.into_iter().map(|r| r.into()).collect(),

            received_from_ip: legacy.received_from_ip,
            received_via_port: legacy.received_via_port,

            flags: legacy.flags,
            env_id: legacy.env_id.map(|s| s.into_boxed_str()),
            priority: legacy.priority,

            size: legacy.size,
            quota_keys: legacy.quota_keys.into_iter().map(|qk| qk.into()).collect(),
        }
    }
}

impl From<LegacyRecipient> for Recipient {
    fn from(legacy: LegacyRecipient) -> Self {
        Recipient {
            address: legacy.address.into_boxed_str(),
            retry: legacy.retry,
            notify: legacy.notify,
            expires: legacy.expires,
            queue: legacy.queue,
            status: match legacy.status {
                Status::Scheduled => Status::Scheduled,
                Status::Completed(status) => Status::Completed(status.into()),
                Status::TemporaryFailure(status) => Status::TemporaryFailure(status.into()),
                Status::PermanentFailure(status) => Status::PermanentFailure(status.into()),
            },
            flags: legacy.flags,
            orcpt: legacy.orcpt.map(|s| s.into_boxed_str()),
        }
    }
}

impl From<LegacyErrorDetails> for ErrorDetails {
    fn from(legacy: LegacyErrorDetails) -> Self {
        ErrorDetails {
            entity: legacy.entity.into_boxed_str(),
            details: legacy.details.into(),
        }
    }
}

impl From<LegacyQuotaKey> for QuotaKey {
    fn from(legacy: LegacyQuotaKey) -> Self {
        match legacy {
            LegacyQuotaKey::Size { key, id } => QuotaKey::Size {
                key: key.into(),
                id,
            },
            LegacyQuotaKey::Count { key, id } => QuotaKey::Count {
                key: key.into(),
                id,
            },
        }
    }
}

impl From<LegacyError> for Error {
    fn from(legacy: LegacyError) -> Self {
        match legacy {
            LegacyError::DnsError(s) => Error::DnsError(s.into_boxed_str()),
            LegacyError::UnexpectedResponse(ur) => Error::UnexpectedResponse(ur.into()),
            LegacyError::ConnectionError(s) => Error::ConnectionError(s.into_boxed_str()),
            LegacyError::TlsError(s) => Error::TlsError(s.into_boxed_str()),
            LegacyError::DaneError(s) => Error::DaneError(s.into_boxed_str()),
            LegacyError::MtaStsError(s) => Error::MtaStsError(s.into_boxed_str()),
            LegacyError::RateLimited => Error::RateLimited,
            LegacyError::ConcurrencyLimited => Error::ConcurrencyLimited,
            LegacyError::Io(s) => Error::Io(s.into_boxed_str()),
        }
    }
}

impl From<LegacyUnexpectedResponse> for UnexpectedResponse {
    fn from(legacy: LegacyUnexpectedResponse) -> Self {
        UnexpectedResponse {
            command: legacy.command.into_boxed_str(),
            response: Response {
                code: legacy.response.code,
                esc: legacy.response.esc,
                message: legacy.response.message.into_boxed_str(),
            },
        }
    }
}

impl From<LegacyHostResponse<String>> for HostResponse<Box<str>> {
    fn from(legacy: LegacyHostResponse<String>) -> Self {
        HostResponse {
            hostname: legacy.hostname.into_boxed_str(),
            response: Response {
                code: legacy.response.code,
                esc: legacy.response.esc,
                message: legacy.response.message.into_boxed_str(),
            },
        }
    }
}
