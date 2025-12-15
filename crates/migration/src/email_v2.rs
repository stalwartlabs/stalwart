/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{email_v1::FIELD_MAILBOX_IDS, get_bitmap, v014::SUBSPACE_BITMAP_TAG};
use common::Server;
use email::{
    mailbox::{JUNK_ID, TRASH_ID, UidMailbox},
    message::{
        index::extractors::VisitTextArchived,
        ingest::ThreadInfo,
        metadata::{
            MESSAGE_HAS_ATTACHMENT, MESSAGE_RECEIVED_MASK, MessageData, MessageMetadata,
            MessageMetadataContents, MessageMetadataPart, MetadataHeader, MetadataHeaderName,
            MetadataHeaderValue, MetadataPartType, PART_ENCODING_BASE64, PART_ENCODING_PROBLEM,
            PART_ENCODING_QP, PART_SIZE_MASK,
        },
    },
};
use mail_parser::{Encoding, Header, parsers::fields::thread::thread_name};
use store::{
    Serialize, SerializeInfallible, U32_LEN, U64_LEN, ValueKey,
    rand::{self, seq::SliceRandom},
    write::{
        AlignedBytes, AnyKey, Archive, Archiver, BatchBuilder, IndexPropertyClass, ValueClass,
        key::KeySerializer,
    },
};
use trc::AddContext;
use types::{blob_hash::BlobHash, collection::Collection, field::EmailField, keyword::*};
use utils::cheeky_hash::CheekyHash;

pub(crate) async fn migrate_emails_v014(server: &Server, account_id: u32) -> trc::Result<u64> {
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

    let mut migrate = Vec::new();

    server
        .archives(
            account_id,
            Collection::Email,
            &(),
            |document_id, archive| {
                match archive.deserialize_untrusted::<LegacyMessageData>() {
                    Ok(metadata) => {
                        migrate.push((document_id, metadata));
                    }
                    Err(err) => {
                        if archive.deserialize_untrusted::<MessageData>().is_err() {
                            return Err(err
                                .account_id(account_id)
                                .document_id(document_id)
                                .caused_by(trc::location!()));
                        }
                    }
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    migrate.shuffle(&mut rand::rng());

    let num_emails = migrate.len();
    for (document_id, legacy_data) in migrate {
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::Email)
            .with_document(document_id);

        if !tombstoned_ids.contains(document_id) {
            let (size, metadata) = match server
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                    account_id,
                    Collection::Email,
                    document_id,
                    EmailField::Metadata,
                ))
                .await?
            {
                Some(metadata) => match metadata.deserialize_untrusted::<LegacyMessageMetadata>() {
                    Ok(legacy) => (legacy.size, MessageMetadata::from(legacy)),
                    Err(err) => match metadata.deserialize_untrusted::<MessageMetadata>() {
                        Ok(metadata) => (metadata.root_part().offset_end, metadata),
                        Err(_) => {
                            return Err(err
                                .account_id(account_id)
                                .document_id(document_id)
                                .caused_by(trc::location!()));
                        }
                    },
                },
                None => {
                    batch.clear(EmailField::Archive).clear(EmailField::Metadata);
                    continue;
                }
            };
            let data = MessageData {
                mailboxes: legacy_data.mailboxes.into_boxed_slice(),
                keywords: legacy_data.keywords.into_iter().map(Into::into).collect(),
                thread_id: legacy_data.thread_id,
                size,
            };
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

            batch
                .set(
                    ValueClass::IndexProperty(IndexPropertyClass::Hash {
                        property: EmailField::Threading.into(),
                        hash: CheekyHash::new(if !subject.is_empty() { subject } else { "!" }),
                    }),
                    ThreadInfo::serialize(data.thread_id, &message_ids),
                )
                .set(
                    EmailField::Archive,
                    Archiver::new(data)
                        .serialize()
                        .caused_by(trc::location!())?,
                )
                .set(
                    EmailField::Metadata,
                    Archiver::new(metadata)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
        } else {
            batch.clear(EmailField::Archive).clear(EmailField::Metadata);
        }

        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(num_emails as u64)
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug, Default)]
pub struct LegacyMessageData {
    pub mailboxes: Vec<UidMailbox>,
    pub keywords: Vec<LegacyKeyword>,
    pub thread_id: u32,
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct LegacyMessageMetadata {
    pub contents: Vec<LegacyMessageMetadataContents>,
    pub blob_hash: BlobHash,
    pub size: u32,
    pub received_at: u64,
    pub preview: String,
    pub has_attachments: bool,
    pub raw_headers: Vec<u8>,
}

impl From<LegacyMessageMetadata> for MessageMetadata {
    fn from(legacy: LegacyMessageMetadata) -> Self {
        MessageMetadata {
            blob_body_offset: legacy
                .contents
                .first()
                .unwrap()
                .parts
                .first()
                .unwrap()
                .offset_body,
            contents: legacy.contents.into_iter().map(Into::into).collect(),
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

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct LegacyMessageMetadataContents {
    pub html_body: Vec<u16>,
    pub text_body: Vec<u16>,
    pub attachments: Vec<u16>,
    pub parts: Vec<LegacyMessageMetadataPart>,
}

impl From<LegacyMessageMetadataContents> for MessageMetadataContents {
    fn from(contents: LegacyMessageMetadataContents) -> Self {
        MessageMetadataContents {
            html_body: contents.html_body.into_boxed_slice(),
            text_body: contents.text_body.into_boxed_slice(),
            attachments: contents.attachments.into_boxed_slice(),
            parts: contents.parts.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub struct LegacyMessageMetadataPart {
    pub headers: Vec<Header<'static>>,
    pub is_encoding_problem: bool,
    pub body: LegacyMetadataPartType,
    pub encoding: Encoding,
    pub size: u32,
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
}

impl From<LegacyMessageMetadataPart> for MessageMetadataPart {
    fn from(part: LegacyMessageMetadataPart) -> Self {
        let flags = match part.encoding {
            Encoding::None => 0,
            Encoding::QuotedPrintable => PART_ENCODING_QP,
            Encoding::Base64 => PART_ENCODING_BASE64,
        } | (if part.is_encoding_problem {
            PART_ENCODING_PROBLEM
        } else {
            0
        }) | (part.size & PART_SIZE_MASK);

        MessageMetadataPart {
            headers: part
                .headers
                .into_iter()
                .map(|hdr| MetadataHeader {
                    value: hdr.value.into(),
                    name: hdr.name.into(),
                    base_offset: hdr.offset_field,
                    start: (hdr.offset_start - hdr.offset_field) as u16,
                    end: (hdr.offset_end - hdr.offset_field) as u16,
                })
                .collect(),
            flags,
            body: part.body.into(),
            offset_header: part.offset_header,
            offset_body: part.offset_body,
            offset_end: part.offset_end,
        }
    }
}

#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, Debug)]
pub enum LegacyMetadataPartType {
    Text,
    Html,
    Binary,
    InlineBinary,
    Message(u16),
    Multipart(Vec<u16>),
}

impl From<LegacyMetadataPartType> for MetadataPartType {
    fn from(value: LegacyMetadataPartType) -> Self {
        match value {
            LegacyMetadataPartType::Text => MetadataPartType::Text,
            LegacyMetadataPartType::Html => MetadataPartType::Html,
            LegacyMetadataPartType::Binary => MetadataPartType::Binary,
            LegacyMetadataPartType::InlineBinary => MetadataPartType::InlineBinary,
            LegacyMetadataPartType::Message(id) => MetadataPartType::Message(id),
            LegacyMetadataPartType::Multipart(children) => {
                MetadataPartType::Multipart(children.into_boxed_slice())
            }
        }
    }
}

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    PartialOrd,
    Ord,
    serde::Serialize,
)]
#[serde(untagged)]
#[rkyv(derive(PartialEq), compare(PartialEq))]
pub enum LegacyKeyword {
    #[serde(rename(serialize = "$seen"))]
    Seen,
    #[serde(rename(serialize = "$draft"))]
    Draft,
    #[serde(rename(serialize = "$flagged"))]
    Flagged,
    #[serde(rename(serialize = "$answered"))]
    Answered,
    #[default]
    #[serde(rename(serialize = "$recent"))]
    Recent,
    #[serde(rename(serialize = "$important"))]
    Important,
    #[serde(rename(serialize = "$phishing"))]
    Phishing,
    #[serde(rename(serialize = "$junk"))]
    Junk,
    #[serde(rename(serialize = "$notjunk"))]
    NotJunk,
    #[serde(rename(serialize = "$deleted"))]
    Deleted,
    #[serde(rename(serialize = "$forwarded"))]
    Forwarded,
    #[serde(rename(serialize = "$mdnsent"))]
    MdnSent,
    Other(String),
}

impl From<LegacyKeyword> for Keyword {
    fn from(kw: LegacyKeyword) -> Self {
        match kw {
            LegacyKeyword::Seen => Keyword::Seen,
            LegacyKeyword::Draft => Keyword::Draft,
            LegacyKeyword::Flagged => Keyword::Flagged,
            LegacyKeyword::Answered => Keyword::Answered,
            LegacyKeyword::Recent => Keyword::Recent,
            LegacyKeyword::Important => Keyword::Important,
            LegacyKeyword::Phishing => Keyword::Phishing,
            LegacyKeyword::Junk => Keyword::Junk,
            LegacyKeyword::NotJunk => Keyword::NotJunk,
            LegacyKeyword::Deleted => Keyword::Deleted,
            LegacyKeyword::Forwarded => Keyword::Forwarded,
            LegacyKeyword::MdnSent => Keyword::MdnSent,
            LegacyKeyword::Other(s) => Keyword::Other(s.into_boxed_str()),
        }
    }
}
