/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{LegacyBincode, get_properties};
use crate::{email_v2::LegacyKeyword, get_bitmap, get_document_ids, v014::SUBSPACE_BITMAP_TAG};
use common::Server;
use email::{
    mailbox::*,
    message::{
        index::extractors::VisitTextArchived,
        ingest::ThreadInfo,
        metadata::{
            MESSAGE_HAS_ATTACHMENT, MESSAGE_RECEIVED_MASK, MessageDataBuilder, MessageMetadata,
            MessageMetadataContents, MessageMetadataPart, MetadataHeader, MetadataHeaderName,
            MetadataHeaderValue, MetadataPartType, PART_ENCODING_BASE64, PART_ENCODING_PROBLEM,
            PART_ENCODING_QP, PART_SIZE_MASK,
        },
    },
};
use mail_parser::{
    Address, Attribute, ContentType, DateTime, Encoding, HeaderName, HeaderValue, Received,
    parsers::fields::thread::thread_name,
};
use std::{borrow::Cow, collections::VecDeque};
use store::{
    Deserialize, SUBSPACE_INDEXES, SUBSPACE_PROPERTY, Serialize, SerializeInfallible, U32_LEN,
    U64_LEN, ValueKey,
    ahash::AHashMap,
    write::{
        AlignedBytes, AnyKey, Archive, Archiver, BatchBuilder, IndexPropertyClass, ValueClass,
        key::KeySerializer,
    },
};
use trc::AddContext;
use types::{
    blob_hash::BlobHash,
    collection::Collection,
    field::{EmailField, Field},
    keyword::*,
};
use utils::{cheeky_hash::CheekyHash, codec::leb128::Leb128Iterator};

const FIELD_KEYWORDS: u8 = 4;
const FIELD_THREAD_ID: u8 = 33;
const FIELD_CID: u8 = 76;
pub(crate) const FIELD_MAILBOX_IDS: u8 = 7;

const BM_MARKER: u8 = 1 << 7;

pub(crate) async fn migrate_emails_v011(server: &Server, account_id: u32) -> trc::Result<u64> {
    // Obtain email ids
    let mut document_ids = get_document_ids(server, account_id, Collection::Email)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_emails = document_ids.len();
    if num_emails == 0 {
        return Ok(0);
    }
    let tombstoned_ids = get_bitmap(
        server,
        AnyKey {
            subspace: SUBSPACE_BITMAP_TAG,
            key: KeySerializer::new(U64_LEN + U32_LEN + 1)
                .write(account_id)
                .write(u8::from(Collection::Email))
                .write(FIELD_MAILBOX_IDS)
                .write_leb128(u32::MAX - 1)
                .finalize(),
        },
        AnyKey {
            subspace: SUBSPACE_BITMAP_TAG,
            key: KeySerializer::new(U64_LEN + U32_LEN + 1)
                .write(account_id)
                .write(u8::from(Collection::Email))
                .write(FIELD_MAILBOX_IDS)
                .write_leb128(u32::MAX - 1)
                .finalize(),
        },
    )
    .await
    .caused_by(trc::location!())?
    .unwrap_or_default();

    let mut message_data: AHashMap<u32, MessageDataBuilder> =
        AHashMap::with_capacity(num_emails as usize);
    let mut did_migrate = false;

    // Obtain mailboxes
    for (message_id, uid_mailbox) in get_properties::<Mailboxes, _>(
        server,
        account_id,
        Collection::Email,
        &(),
        FIELD_MAILBOX_IDS,
    )
    .await
    .caused_by(trc::location!())?
    {
        message_data.entry(message_id).or_default().mailboxes = uid_mailbox.0;
    }

    // Obtain keywords
    for (message_id, keywords) in
        get_properties::<Keywords, _>(server, account_id, Collection::Email, &(), FIELD_KEYWORDS)
            .await
            .caused_by(trc::location!())?
    {
        message_data.entry(message_id).or_default().keywords =
            keywords.0.into_iter().map(Into::into).collect();
    }

    // Obtain threadIds
    for (message_id, thread_id) in
        get_properties::<u32, _>(server, account_id, Collection::Email, &(), FIELD_THREAD_ID)
            .await
            .caused_by(trc::location!())?
    {
        message_data.entry(message_id).or_default().thread_id = thread_id;
    }

    // Write message data
    for (message_id, mut data) in message_data {
        if !tombstoned_ids.contains(message_id) {
            let (size, metadata) = match server
                .store()
                .get_value::<LegacyBincode<LegacyMessageMetadata>>(ValueKey {
                    account_id,
                    collection: Collection::Email.into(),
                    document_id: message_id,
                    class: ValueClass::Property(EmailField::Metadata.into()),
                })
                .await
            {
                Ok(Some(legacy_metadata)) => (
                    legacy_metadata.inner.size as u32,
                    MessageMetadata::from_legacy(legacy_metadata.inner),
                ),
                Ok(None) => {
                    continue;
                }
                Err(err) => {
                    match server
                        .store()
                        .get_value::<Archive<AlignedBytes>>(ValueKey {
                            account_id,
                            collection: Collection::Email.into(),
                            document_id: message_id,
                            class: ValueClass::Property(EmailField::Metadata.into()),
                        })
                        .await
                    {
                        Ok(Some(archive)) => {
                            let metadata: MessageMetadata = archive
                                .deserialize_untrusted()
                                .caused_by(trc::location!())?;
                            (metadata.root_part().offset_end, metadata)
                        }
                        _ => {
                            return Err(err
                                .account_id(account_id)
                                .document_id(message_id)
                                .caused_by(trc::location!()));
                        }
                    }
                }
            };

            did_migrate = true;
            document_ids.insert(message_id);

            let mut message_ids = Vec::new();
            let mut subject = "";
            for header in &metadata.contents[0].parts[0].headers {
                match &header.name {
                    MetadataHeaderName::MessageId => {
                        header.value.visit_text(|id| {
                            if !id.is_empty() {
                                message_ids.push(CheekyHash::new(id.as_bytes()));
                            }
                        });
                    }
                    MetadataHeaderName::InReplyTo
                    | MetadataHeaderName::References
                    | MetadataHeaderName::ResentMessageId => {
                        header.value.visit_text(|id| {
                            if !id.is_empty() {
                                message_ids.push(CheekyHash::new(id.as_bytes()));
                            }
                        });
                    }
                    MetadataHeaderName::Subject if subject.is_empty() => {
                        subject = thread_name(match &header.value {
                            MetadataHeaderValue::Text(text) => text.as_ref(),
                            MetadataHeaderValue::TextList(list) if !list.is_empty() => {
                                list.first().unwrap().as_ref()
                            }
                            _ => "",
                        });
                    }
                    _ => (),
                }
            }

            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(account_id)
                .with_collection(Collection::Email)
                .with_document(message_id);

            if data
                .mailboxes
                .iter()
                .any(|mailbox| mailbox.mailbox_id == TRASH_ID || mailbox.mailbox_id == JUNK_ID)
            {
                batch.set(
                    ValueClass::Property(EmailField::DeletedAt.into()),
                    (metadata.rcvd_attach & MESSAGE_RECEIVED_MASK).serialize(),
                );
            }
            data.size = size;
            batch
                .set(
                    ValueClass::IndexProperty(IndexPropertyClass::Hash {
                        property: EmailField::Threading.into(),
                        hash: CheekyHash::new(if !subject.is_empty() { subject } else { "!" }),
                    }),
                    ThreadInfo::serialize(data.thread_id, &message_ids),
                )
                .set(
                    Field::ARCHIVE,
                    Archiver::new(data.seal())
                        .serialize()
                        .caused_by(trc::location!())?,
                )
                .set(
                    EmailField::Metadata,
                    Archiver::new(metadata)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
        }
    }

    // Delete keyword bitmaps
    for field in [FIELD_KEYWORDS, FIELD_KEYWORDS | BM_MARKER] {
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace: SUBSPACE_BITMAP_TAG,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(field)
                        .finalize(),
                },
                AnyKey {
                    subspace: SUBSPACE_BITMAP_TAG,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(field)
                        .write(&[u8::MAX; 8][..])
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    // Delete messageId index, now in References
    const MESSAGE_ID_FIELD: u8 = 11;
    server
        .store()
        .delete_range(
            AnyKey {
                subspace: SUBSPACE_INDEXES,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::Email))
                    .write(MESSAGE_ID_FIELD)
                    .finalize(),
            },
            AnyKey {
                subspace: SUBSPACE_INDEXES,
                key: KeySerializer::new(U64_LEN)
                    .write(account_id)
                    .write(u8::from(Collection::Email))
                    .write(MESSAGE_ID_FIELD)
                    .write(&[u8::MAX; 8][..])
                    .finalize(),
            },
        )
        .await
        .caused_by(trc::location!())?;

    // Delete values
    for property in [
        FIELD_MAILBOX_IDS,
        FIELD_KEYWORDS,
        FIELD_THREAD_ID,
        FIELD_CID,
    ] {
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace: SUBSPACE_PROPERTY,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(property)
                        .finalize(),
                },
                AnyKey {
                    subspace: SUBSPACE_PROPERTY,
                    key: KeySerializer::new(U64_LEN)
                        .write(account_id)
                        .write(u8::from(Collection::Email))
                        .write(property)
                        .write(&[u8::MAX; 8][..])
                        .finalize(),
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    // Increment document id counter
    if did_migrate {
        server
            .store()
            .assign_document_ids(
                account_id,
                Collection::Email,
                document_ids.max().map(|id| id as u64).unwrap_or(num_emails) + 1,
            )
            .await
            .caused_by(trc::location!())?;
        Ok(num_emails)
    } else {
        Ok(0)
    }
}

pub trait FromLegacy {
    fn from_legacy(legacy: LegacyMessageMetadata<'_>) -> Self;
}

impl FromLegacy for MessageMetadata {
    fn from_legacy(legacy: LegacyMessageMetadata<'_>) -> Self {
        let mut contents = Vec::new();
        let mut messages = VecDeque::from([legacy.contents]);
        let mut message_id = 0;

        while let Some(message) = messages.pop_front() {
            let mut parts = Vec::new();

            for part in message.parts {
                let body = match part.body {
                    LegacyMetadataPartType::Text => MetadataPartType::Text,
                    LegacyMetadataPartType::Html => MetadataPartType::Html,
                    LegacyMetadataPartType::Binary => MetadataPartType::Binary,
                    LegacyMetadataPartType::InlineBinary => MetadataPartType::InlineBinary,
                    LegacyMetadataPartType::Message(message) => {
                        messages.push_back(message);
                        message_id += 1;
                        MetadataPartType::Message(message_id)
                    }
                    LegacyMetadataPartType::Multipart(parts) => {
                        MetadataPartType::Multipart(parts.into_iter().map(|p| p as u16).collect())
                    }
                };

                let flags = match part.encoding {
                    Encoding::None => 0,
                    Encoding::QuotedPrintable => PART_ENCODING_QP,
                    Encoding::Base64 => PART_ENCODING_BASE64,
                } | (if part.is_encoding_problem {
                    PART_ENCODING_PROBLEM
                } else {
                    0
                }) | (part.size as u32 & PART_SIZE_MASK);

                parts.push(MessageMetadataPart {
                    headers: part
                        .headers
                        .into_iter()
                        .map(|hdr| MetadataHeader {
                            value: if matches!(
                                &hdr.name,
                                HeaderName::Subject
                                    | HeaderName::From
                                    | HeaderName::To
                                    | HeaderName::Cc
                                    | HeaderName::Date
                                    | HeaderName::Bcc
                                    | HeaderName::ReplyTo
                                    | HeaderName::Sender
                                    | HeaderName::Comments
                                    | HeaderName::InReplyTo
                                    | HeaderName::Keywords
                                    | HeaderName::MessageId
                                    | HeaderName::References
                                    | HeaderName::ResentMessageId
                                    | HeaderName::ContentDescription
                                    | HeaderName::ContentId
                                    | HeaderName::ContentLanguage
                                    | HeaderName::ContentLocation
                                    | HeaderName::ContentTransferEncoding
                                    | HeaderName::ContentType
                                    | HeaderName::ContentDisposition
                                    | HeaderName::ListId
                            ) {
                                HeaderValue::from(hdr.value)
                            } else {
                                HeaderValue::Empty
                            }
                            .into(),
                            name: hdr.name.into(),
                            base_offset: hdr.offset_field as u32,
                            start: (hdr.offset_start - hdr.offset_field) as u16,
                            end: (hdr.offset_end - hdr.offset_field) as u16,
                        })
                        .collect(),
                    flags,
                    body,
                    offset_header: part.offset_header as u32,
                    offset_body: part.offset_body as u32,
                    offset_end: part.offset_end as u32,
                });
            }

            contents.push(MessageMetadataContents {
                html_body: message.html_body.into_iter().map(|c| c as u16).collect(),
                text_body: message.text_body.into_iter().map(|c| c as u16).collect(),
                attachments: message.attachments.into_iter().map(|c| c as u16).collect(),
                parts: parts.into_boxed_slice(),
            });
        }

        MessageMetadata {
            blob_body_offset: contents.first().unwrap().root_part().offset_body,
            contents: contents.into_boxed_slice(),
            blob_hash: legacy.blob_hash,
            preview: legacy.preview.into_boxed_str(),
            raw_headers: legacy.raw_headers.into_boxed_slice(),
            rcvd_attach: (if legacy.has_attachments {
                MESSAGE_HAS_ATTACHMENT
            } else {
                0
            }) | (legacy.received_at & MESSAGE_RECEIVED_MASK),
        }
    }
}

pub struct Mailboxes(Vec<UidMailbox>);
pub struct Keywords(Vec<LegacyKeyword>);

impl Deserialize for Mailboxes {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut bytes = bytes.iter();
        let len: usize = bytes
            .next_leb128()
            .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(UidMailbox {
                mailbox_id: bytes
                    .next_leb128()
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
                uid: bytes
                    .next_leb128()
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
            });
        }
        Ok(Mailboxes(list))
    }
}

impl Deserialize for Keywords {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        let mut bytes = bytes.iter();
        let len: usize = bytes
            .next_leb128()
            .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?;
        let mut list = Vec::with_capacity(len);
        for _ in 0..len {
            list.push(
                deserialize_keyword(&mut bytes)
                    .ok_or_else(|| trc::StoreEvent::DataCorruption.caused_by(trc::location!()))?,
            );
        }
        Ok(Keywords(list))
    }
}

fn deserialize_keyword(bytes: &mut std::slice::Iter<'_, u8>) -> Option<LegacyKeyword> {
    match bytes.next_leb128::<usize>()? {
        SEEN => Some(LegacyKeyword::Seen),
        DRAFT => Some(LegacyKeyword::Draft),
        FLAGGED => Some(LegacyKeyword::Flagged),
        ANSWERED => Some(LegacyKeyword::Answered),
        RECENT => Some(LegacyKeyword::Recent),
        IMPORTANT => Some(LegacyKeyword::Important),
        PHISHING => Some(LegacyKeyword::Phishing),
        JUNK => Some(LegacyKeyword::Junk),
        NOTJUNK => Some(LegacyKeyword::NotJunk),
        DELETED => Some(LegacyKeyword::Deleted),
        FORWARDED => Some(LegacyKeyword::Forwarded),
        MDN_SENT => Some(LegacyKeyword::MdnSent),
        other => {
            let len = other - OTHER;
            let mut keyword = Vec::with_capacity(len);
            for _ in 0..len {
                keyword.push(*bytes.next()?);
            }
            Some(LegacyKeyword::Other(String::from_utf8(keyword).ok()?))
        }
    }
}

pub type LegacyMessagePartId = usize;
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyMessageMetadata<'x> {
    pub contents: LegacyMessageMetadataContents<'x>,
    pub blob_hash: BlobHash,
    pub size: usize,
    pub received_at: u64,
    pub preview: String,
    pub has_attachments: bool,
    pub raw_headers: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyMessageMetadataContents<'x> {
    pub html_body: Vec<LegacyMessagePartId>,
    pub text_body: Vec<LegacyMessagePartId>,
    pub attachments: Vec<LegacyMessagePartId>,
    pub parts: Vec<LegacyMessageMetadataPart<'x>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyMessageMetadataPart<'x> {
    pub headers: Vec<LegacyHeader<'x>>,
    pub is_encoding_problem: bool,
    pub body: LegacyMetadataPartType<'x>,
    pub encoding: Encoding,
    pub size: usize,
    pub offset_header: usize,
    pub offset_body: usize,
    pub offset_end: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyHeader<'x> {
    pub name: HeaderName<'x>,
    pub value: LegacyHeaderValue<'x>,
    pub offset_field: usize,
    pub offset_start: usize,
    pub offset_end: usize,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub enum LegacyHeaderValue<'x> {
    /// Address list or group
    Address(Address<'x>),

    /// String
    Text(Cow<'x, str>),

    /// List of strings
    TextList(Vec<Cow<'x, str>>),

    /// Datetime
    DateTime(DateTime),

    /// Content-Type or Content-Disposition header
    ContentType(LegacyContentType<'x>),

    /// Received header
    Received(Box<Received<'x>>),

    #[default]
    Empty,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct LegacyContentType<'x> {
    pub c_type: Cow<'x, str>,
    pub c_subtype: Option<Cow<'x, str>>,
    pub attributes: Option<Vec<(Cow<'x, str>, Cow<'x, str>)>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum LegacyMetadataPartType<'x> {
    Text,
    Html,
    Binary,
    InlineBinary,
    Message(LegacyMessageMetadataContents<'x>),
    Multipart(Vec<LegacyMessagePartId>),
}

impl From<LegacyHeaderValue<'_>> for HeaderValue<'static> {
    fn from(value: LegacyHeaderValue<'_>) -> Self {
        match value {
            LegacyHeaderValue::Address(address) => HeaderValue::Address(address.into_owned()),
            LegacyHeaderValue::Text(cow) => HeaderValue::Text(cow.into_owned().into()),
            LegacyHeaderValue::TextList(cows) => HeaderValue::TextList(
                cows.into_iter()
                    .map(|cow| cow.into_owned().into())
                    .collect(),
            ),
            LegacyHeaderValue::DateTime(date_time) => HeaderValue::DateTime(date_time),
            LegacyHeaderValue::ContentType(legacy_content_type) => {
                HeaderValue::ContentType(ContentType {
                    c_type: legacy_content_type.c_type.into_owned().into(),
                    c_subtype: legacy_content_type.c_subtype.map(|s| s.into_owned().into()),
                    attributes: legacy_content_type.attributes.map(|attrs| {
                        attrs
                            .into_iter()
                            .map(|(k, v)| Attribute {
                                name: k.into_owned().into(),
                                value: v.into_owned().into(),
                            })
                            .collect()
                    }),
                })
            }
            LegacyHeaderValue::Received(received) => {
                HeaderValue::Received(Box::new(received.into_owned()))
            }
            LegacyHeaderValue::Empty => HeaderValue::Empty,
        }
    }
}

/*pub(crate) fn encode_message_id(message_id: &str) -> Vec<u8> {
    let mut msg_id = Vec::with_capacity(message_id.len() + 1);
    msg_id.extend_from_slice(message_id.as_bytes());
    msg_id.push(0);
    msg_id
}*/
