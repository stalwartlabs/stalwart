/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    LegacyBincode,
    queue_v2::{LegacyHostResponse, LegacyQuotaKey},
};
use common::{
    Server,
    config::smtp::queue::{DEFAULT_QUEUE_NAME, QueueExpiry, QueueName},
};
use smtp::queue::{
    Error, ErrorDetails, HostResponse, Message, QueueId, Recipient, Schedule, Status,
    UnexpectedResponse,
};
use smtp_proto::Response;
use std::net::{IpAddr, Ipv4Addr};
use store::{
    IterateParams, SUBSPACE_QUEUE_EVENT, Serialize, U64_LEN, ValueKey,
    ahash::AHashMap,
    write::{
        AlignedBytes, AnyClass, Archive, Archiver, BatchBuilder, QueueClass, ValueClass,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use trc::AddContext;
use types::blob_hash::BlobHash;

pub(crate) async fn migrate_queue_v011(server: &Server) -> trc::Result<()> {
    let mut count = 0;
    let now = now();

    for (queue_id, due) in get_queue_events(server).await? {
        match server
            .store()
            .get_value::<LegacyBincode<MessageV011>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(queue_id),
            )))
            .await
        {
            Ok(Some(bincoded)) => {
                let mut batch = BatchBuilder::new();
                let message = Message::from(bincoded.inner);
                if let Some(due) = due {
                    batch.clear(ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_QUEUE_EVENT,
                        key: KeySerializer::new(16).write(due).write(queue_id).finalize(),
                    }));
                }
                batch
                    .set(
                        ValueClass::Queue(QueueClass::MessageEvent(store::write::QueueEvent {
                            due: due.unwrap_or(now),
                            queue_id,
                            queue_name: DEFAULT_QUEUE_NAME.into_inner(),
                        })),
                        vec![],
                    )
                    .set(
                        ValueClass::Queue(QueueClass::Message(queue_id)),
                        Archiver::new(message)
                            .serialize()
                            .caused_by(trc::location!())?,
                    );
                count += 1;
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => {
                if let Some(due) = due {
                    let mut batch = BatchBuilder::new();
                    batch.clear(ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_QUEUE_EVENT,
                        key: KeySerializer::new(16).write(due).write(queue_id).finalize(),
                    }));
                    server
                        .store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }
            }
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                        QueueClass::Message(queue_id),
                    )))
                    .await
                    .is_err()
                {
                    return Err(err
                        .ctx(trc::Key::QueueId, queue_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    if count > 0 {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {count} queued messages",)
        );
    }

    Ok(())
}

pub(crate) async fn migrate_queue_v012(server: &Server) -> trc::Result<()> {
    let mut count = 0;
    let now = now();

    for (queue_id, due) in get_queue_events(server).await? {
        match server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                QueueClass::Message(queue_id),
            )))
            .await
            .and_then(|archive| {
                if let Some(archive) = archive {
                    archive.deserialize_untrusted::<MessageV012>().map(Some)
                } else {
                    Ok(None)
                }
            }) {
            Ok(Some(archive)) => {
                let message = Message::from(archive);
                let mut batch = BatchBuilder::new();
                if let Some(due) = due {
                    batch.clear(ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_QUEUE_EVENT,
                        key: KeySerializer::new(16).write(due).write(queue_id).finalize(),
                    }));
                }
                batch
                    .set(
                        ValueClass::Queue(QueueClass::MessageEvent(store::write::QueueEvent {
                            due: due.unwrap_or(now),
                            queue_id,
                            queue_name: DEFAULT_QUEUE_NAME.into_inner(),
                        })),
                        vec![],
                    )
                    .set(
                        ValueClass::Queue(QueueClass::Message(queue_id)),
                        Archiver::new(message)
                            .serialize()
                            .caused_by(trc::location!())?,
                    );
                count += 1;
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => {
                if let Some(due) = due {
                    let mut batch = BatchBuilder::new();
                    batch.clear(ValueClass::Any(AnyClass {
                        subspace: SUBSPACE_QUEUE_EVENT,
                        key: KeySerializer::new(16).write(due).write(queue_id).finalize(),
                    }));
                    server
                        .store()
                        .write(batch.build_all())
                        .await
                        .caused_by(trc::location!())?;
                }
            }
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::Queue(
                        QueueClass::Message(queue_id),
                    )))
                    .await
                    .and_then(|archive| {
                        if let Some(archive) = archive {
                            archive.deserialize_untrusted::<Message>().map(Some)
                        } else {
                            Ok(None)
                        }
                    })
                    .is_err()
                {
                    return Err(err
                        .ctx(trc::Key::QueueId, queue_id)
                        .caused_by(trc::location!()));
                }
            }
        }
    }

    if count > 0 {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {count} queued messages",)
        );
    }

    Ok(())
}

async fn get_queue_events(server: &Server) -> trc::Result<AHashMap<u64, Option<u64>>> {
    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
        store::write::QueueEvent {
            due: 0,
            queue_id: 0,
            queue_name: [0; 8],
        },
    )));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::MessageEvent(
        store::write::QueueEvent {
            due: u64::MAX,
            queue_id: u64::MAX,
            queue_name: [u8::MAX; 8],
        },
    )));

    let mut queue_ids: AHashMap<u64, Option<u64>> = AHashMap::new();
    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                queue_ids.insert(
                    key.deserialize_be_u64(U64_LEN)?,
                    Some(key.deserialize_be_u64(0)?),
                );

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(0)));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX)));
    server
        .store()
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                let queue_id = key.deserialize_be_u64(0)?;

                if !queue_ids.contains_key(&queue_id) {
                    queue_ids.insert(queue_id, None);
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    Ok(queue_ids)
}

impl<SIZE, IDX> From<LegacyMessage<SIZE, IDX>> for Message
where
    SIZE: AsU64,
    IDX: AsU64,
{
    fn from(message: LegacyMessage<SIZE, IDX>) -> Self {
        let domains = message.domains;
        Message {
            created: message.created,
            blob_hash: message.blob_hash,
            return_path: message.return_path_lcase.into_boxed_str(),
            recipients: message
                .recipients
                .into_iter()
                .map(|r| {
                    let domain = &domains[r.domain_idx.as_u64() as usize];
                    let mut rcpt = Recipient::new(r.address);
                    rcpt.status = match r.status {
                        Status::Scheduled => match &domain.status {
                            Status::Scheduled | Status::Completed(_) => Status::Scheduled,
                            Status::TemporaryFailure(err) => {
                                Status::TemporaryFailure(migrate_legacy_error(&domain.domain, err))
                            }
                            Status::PermanentFailure(err) => {
                                Status::PermanentFailure(migrate_legacy_error(&domain.domain, err))
                            }
                        },
                        Status::Completed(details) => Status::Completed(HostResponse {
                            hostname: details.hostname.into_boxed_str(),
                            response: Response {
                                code: details.response.code,
                                esc: details.response.esc,
                                message: details.response.message.into_boxed_str(),
                            },
                        }),
                        Status::TemporaryFailure(err) => {
                            Status::TemporaryFailure(migrate_host_response(err))
                        }
                        Status::PermanentFailure(err) => {
                            Status::PermanentFailure(migrate_host_response(err))
                        }
                    };
                    rcpt.flags = r.flags;
                    rcpt.orcpt = r.orcpt.map(|o| o.into_boxed_str());
                    rcpt.retry = domain.retry.clone();
                    rcpt.notify = domain.notify.clone();
                    rcpt.queue = QueueName::default();
                    rcpt.expires = QueueExpiry::Ttl(domain.expires.saturating_sub(now()));
                    rcpt
                })
                .collect(),
            flags: message.flags,
            env_id: message.env_id.map(|e| e.into_boxed_str()),
            priority: message.priority,
            size: message.size.as_u64(),
            quota_keys: message.quota_keys.into_iter().map(Into::into).collect(),
            received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_via_port: 0,
        }
    }
}

trait AsU64 {
    fn as_u64(&self) -> u64;
}
impl AsU64 for usize {
    fn as_u64(&self) -> u64 {
        *self as u64
    }
}
impl AsU64 for u32 {
    fn as_u64(&self) -> u64 {
        *self as u64
    }
}
impl AsU64 for u64 {
    fn as_u64(&self) -> u64 {
        *self
    }
}

fn migrate_legacy_error(domain: &str, err: &LegacyError) -> ErrorDetails {
    match err {
        LegacyError::DnsError(err) => ErrorDetails {
            entity: domain.into(),
            details: Error::DnsError(err.as_str().into()),
        },
        LegacyError::UnexpectedResponse(err) => ErrorDetails {
            entity: err.hostname.entity.as_str().into(),
            details: Error::UnexpectedResponse(UnexpectedResponse {
                command: err.hostname.details.as_str().into(),
                response: Response {
                    code: err.response.code,
                    esc: err.response.esc,
                    message: err.response.message.as_str().into(),
                },
            }),
        },
        LegacyError::ConnectionError(err) => ErrorDetails {
            entity: err.entity.as_str().into(),
            details: Error::ConnectionError(err.details.as_str().into()),
        },
        LegacyError::TlsError(err) => ErrorDetails {
            entity: err.entity.as_str().into(),
            details: Error::TlsError(err.details.as_str().into()),
        },
        LegacyError::DaneError(err) => ErrorDetails {
            entity: err.entity.as_str().into(),
            details: Error::DaneError(err.details.as_str().into()),
        },
        LegacyError::MtaStsError(err) => ErrorDetails {
            entity: domain.into(),
            details: Error::MtaStsError(err.as_str().into()),
        },
        LegacyError::RateLimited => ErrorDetails {
            entity: domain.into(),
            details: Error::RateLimited,
        },
        LegacyError::ConcurrencyLimited => ErrorDetails {
            entity: domain.into(),
            details: Error::ConcurrencyLimited,
        },
        LegacyError::Io(err) => ErrorDetails {
            entity: domain.into(),
            details: Error::Io(err.as_str().into()),
        },
    }
}

fn migrate_host_response(response: LegacyHostResponse<LegacyErrorDetails>) -> ErrorDetails {
    ErrorDetails {
        entity: response.hostname.entity.into_boxed_str(),
        details: Error::UnexpectedResponse(UnexpectedResponse {
            command: response.hostname.details.into_boxed_str(),
            response: Response {
                code: response.response.code,
                esc: response.response.esc,
                message: response.response.message.into_boxed_str(),
            },
        }),
    }
}

pub type MessageV011 = LegacyMessage<usize, usize>;
pub type MessageV012 = LegacyMessage<u64, u32>;

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
pub struct LegacyMessage<SIZE, IDX> {
    pub queue_id: QueueId,
    pub created: u64,
    pub blob_hash: BlobHash,

    pub return_path: String,
    pub return_path_lcase: String,
    pub return_path_domain: String,
    pub recipients: Vec<LegacyRecipient<IDX>>,
    pub domains: Vec<LegacyDomain>,

    pub flags: u64,
    pub env_id: Option<String>,
    pub priority: i16,

    pub size: SIZE,
    pub quota_keys: Vec<LegacyQuotaKey>,

    #[serde(skip)]
    #[rkyv(with = rkyv::with::Skip)]
    pub span_id: u64,
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
pub struct LegacyRecipient<IDX> {
    pub domain_idx: IDX,
    pub address: String,
    pub address_lcase: String,
    pub status: Status<LegacyHostResponse<String>, LegacyHostResponse<LegacyErrorDetails>>,
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
pub struct LegacyDomain {
    pub domain: String,
    pub retry: Schedule<u32>,
    pub notify: Schedule<u32>,
    pub expires: u64,
    pub status: Status<(), LegacyError>,
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
pub enum LegacyError {
    DnsError(String),
    UnexpectedResponse(LegacyHostResponse<LegacyErrorDetails>),
    ConnectionError(LegacyErrorDetails),
    TlsError(LegacyErrorDetails),
    DaneError(LegacyErrorDetails),
    MtaStsError(String),
    RateLimited,
    ConcurrencyLimited,
    Io(String),
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
pub struct LegacyErrorDetails {
    pub entity: String,
    pub details: String,
}
