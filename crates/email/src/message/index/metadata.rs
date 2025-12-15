/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::message::{
    index::{IndexMessage, MAX_MESSAGE_PARTS, PREVIEW_LENGTH},
    metadata::{
        ArchivedMessageMetadata, ArchivedMessageMetadataPart, ArchivedMetadataHeaderName,
        MESSAGE_HAS_ATTACHMENT, MESSAGE_RECEIVED_MASK, MessageData, MessageMetadata,
        MessageMetadataPart, build_metadata_contents,
    },
};
use common::storage::index::ObjectIndexBuilder;
use mail_parser::{
    PartType,
    decoders::html::html_to_text,
    parsers::{fields::thread::thread_name, preview::preview_text},
};
use store::{
    Serialize,
    write::{Archiver, BatchBuilder, BlobLink, BlobOp, IndexPropertyClass, ValueClass},
};
use trc::AddContext;
use types::{blob_hash::BlobHash, field::EmailField};
use utils::cheeky_hash::CheekyHash;

impl MessageMetadata {
    #[inline(always)]
    pub fn root_part(&self) -> &MessageMetadataPart {
        &self.contents[0].parts[0]
    }

    pub fn index(self, batch: &mut BatchBuilder, set: bool) -> trc::Result<()> {
        if set {
            batch
                .set(
                    BlobOp::Link {
                        hash: self.blob_hash.clone(),
                        to: BlobLink::Document,
                    },
                    Vec::new(),
                )
                .set(EmailField::Metadata, Archiver::new(self).serialize()?);
        } else {
            batch
                .clear(BlobOp::Link {
                    hash: self.blob_hash.clone(),
                    to: BlobLink::Document,
                })
                .clear(EmailField::Metadata);
        }

        Ok(())
    }
}

impl ArchivedMessageMetadata {
    #[inline(always)]
    pub fn root_part(&self) -> &ArchivedMessageMetadataPart {
        &self.contents[0].parts[0]
    }

    pub fn unindex(&self, batch: &mut BatchBuilder) {
        // Delete metadata
        let thread_name = self
            .contents
            .first()
            .and_then(|c| c.parts.first())
            .and_then(|p| {
                p.headers.iter().rev().find_map(|h| {
                    if let ArchivedMetadataHeaderName::Subject = &h.name {
                        h.value.as_text()
                    } else {
                        None
                    }
                })
            })
            .map(thread_name)
            .unwrap_or_default();

        batch
            .clear(EmailField::Metadata)
            .clear(ValueClass::IndexProperty(IndexPropertyClass::Hash {
                property: EmailField::Threading.into(),
                hash: CheekyHash::new(if !thread_name.is_empty() {
                    thread_name
                } else {
                    "!"
                }),
            }))
            .clear(BlobOp::Link {
                hash: BlobHash::from(&self.blob_hash),
                to: BlobLink::Document,
            });
    }
}

impl IndexMessage for BatchBuilder {
    fn index_message<'x>(
        &mut self,
        tenant_id: Option<u32>,
        mut message: mail_parser::Message<'x>,
        extra_headers: Vec<u8>,
        mut extra_headers_parsed: Vec<mail_parser::Header<'x>>,
        blob_hash: BlobHash,
        data: MessageData,
        received_at: u64,
    ) -> trc::Result<&mut Self> {
        let mut has_attachments = false;
        let mut preview = None;
        let preview_part_id = message
            .text_body
            .first()
            .or_else(|| message.html_body.first())
            .copied()
            .unwrap_or(u32::MAX);

        for (part_id, part) in message.parts.iter().take(MAX_MESSAGE_PARTS).enumerate() {
            let part_id = part_id as u32;
            match &part.body {
                mail_parser::PartType::Text(text) => {
                    if part_id == preview_part_id {
                        preview =
                            preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
                    }

                    if !message.text_body.contains(&part_id)
                        && !message.html_body.contains(&part_id)
                    {
                        has_attachments = true;
                    }
                }
                mail_parser::PartType::Html(html) => {
                    let text = html_to_text(html);
                    if part_id == preview_part_id {
                        preview =
                            preview_text(text.replace('\r', "").into(), PREVIEW_LENGTH).into();
                    }

                    if !message.text_body.contains(&part_id)
                        && !message.html_body.contains(&part_id)
                    {
                        has_attachments = true;
                    }
                }
                mail_parser::PartType::Binary(_) | mail_parser::PartType::Message(_)
                    if !has_attachments =>
                {
                    has_attachments = true;
                }
                _ => {}
            }
        }

        // Build raw headers
        let root_part = message.root_part();
        let mut raw_headers = Vec::with_capacity(
            (root_part.offset_body - root_part.offset_header) as usize + extra_headers.len(),
        );
        raw_headers.extend_from_slice(&extra_headers);
        raw_headers.extend_from_slice(
            message
                .raw_message
                .as_ref()
                .get(root_part.offset_header as usize..root_part.offset_body as usize)
                .unwrap_or_default(),
        );

        // Add additional headers to message
        let blob_body_offset = if !extra_headers.is_empty() {
            // Add extra headers to root part
            let offset_start = extra_headers.len() as u32;
            let mut part_iter_stack = Vec::new();
            let mut part_iter = message.parts.iter_mut();

            loop {
                if let Some(part) = part_iter.next() {
                    // Increment header offsets
                    for header in part.headers.iter_mut() {
                        header.offset_field += offset_start;
                        header.offset_start += offset_start;
                        header.offset_end += offset_start;
                    }

                    // Adjust part offsets
                    part.offset_body += offset_start;
                    part.offset_end += offset_start;
                    part.offset_header += offset_start;

                    if let PartType::Message(sub_message) = &mut part.body
                        && sub_message.root_part().offset_header != 0
                    {
                        part_iter_stack.push(part_iter);
                        part_iter = sub_message.parts.iter_mut();
                    }
                } else if let Some(iter) = part_iter_stack.pop() {
                    part_iter = iter;
                } else {
                    break;
                }
            }

            // Add extra headers to root part
            let root_part = &mut message.parts[0];
            extra_headers_parsed.append(&mut root_part.headers);
            root_part.offset_header = 0;
            root_part.headers = extra_headers_parsed;
            root_part.offset_body - offset_start
        } else {
            message.root_part().offset_body
        };

        // Build metadata
        let metadata = MessageMetadata {
            preview: preview.unwrap_or_default().into_owned().into_boxed_str(),
            raw_headers: raw_headers.into_boxed_slice(),
            contents: build_metadata_contents(message),
            blob_hash,
            blob_body_offset,
            rcvd_attach: (if has_attachments {
                MESSAGE_HAS_ATTACHMENT
            } else {
                0
            }) | (received_at & MESSAGE_RECEIVED_MASK),
        };

        self.set(
            BlobOp::Link {
                hash: metadata.blob_hash.clone(),
                to: BlobLink::Document,
            },
            Vec::new(),
        )
        .custom(
            ObjectIndexBuilder::<(), _>::new()
                .with_tenant_id(tenant_id)
                .with_changes(data),
        )
        .caused_by(trc::location!())?
        .set(
            EmailField::Metadata,
            Archiver::new(metadata)
                .serialize()
                .caused_by(trc::location!())?,
        );

        Ok(self)
    }
}
