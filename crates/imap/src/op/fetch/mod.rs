/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod section;
pub mod source;
pub mod structure;

use super::{FromModSeq, ImapContext};
use crate::{
    core::{SelectedMailbox, Session, SessionData, session::OUTPUT_FLUSH_THRESHOLD},
    spawn_op,
};
use common::{MessageStoreCache, network::SessionStream};
use compact_str::format_compact;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        messagedata::{KeywordDiff, merge_keywords},
        metadata::{HeaderMatcher, MetadataRow, MetadataStructure},
    },
};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    parser::PushUnique,
    protocol::{
        Flag, ObjectId,
        expunge::Vanished,
        fetch::{Arguments, Attribute, DataItem, FetchItem, Section},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use source::DecodedSources;
use std::{borrow::Cow, fmt::Write, iter, sync::Arc, time::Instant};
use store::{
    ValueKey,
    query::log::{Change, Query},
    write::BatchBuilder,
};
use structure::{Binary, ImapMetadata};
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::EmailField,
    id::Id,
    keyword::Keyword,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_fetch(&mut self, requests: Vec<Request<Command>>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapFetch)?;

        let (data, mailbox) = self.state.select_data();
        let is_qresync = self.is_qresync;
        let is_uidonly = self.is_uidonly;
        let is_utf8 = self.is_utf8;
        let message_limit = self.server.core.imap.max_messages_per_command;

        let mut ops = Vec::with_capacity(requests.len());
        let mut activate_objectid = false;

        for request in requests {
            let is_uid = matches!(request.command, Command::Fetch(true));
            match request.parse_fetch() {
                Ok(arguments) => {
                    let enabled_condstore = if !self.is_condstore
                        && arguments.changed_since.is_some()
                        || arguments.attributes.contains(&Attribute::ModSeq)
                    {
                        self.is_condstore = true;
                        true
                    } else {
                        false
                    };

                    if arguments.attributes.contains(&Attribute::ObjectId) {
                        activate_objectid = true;
                    }

                    ops.push(Ok((is_uid, enabled_condstore, arguments)));
                }
                Err(err) => {
                    ops.push(Err(err));
                }
            }
        }

        if activate_objectid && let Some(enabled) = self.activate_objectid() {
            self.write_bytes(enabled).await?;
        }

        // A non-peek fetch sets \Seen, which makes it a write for the purposes of
        // RFC 9051 5.5 ordering. Draining the readers keeps it behind them.
        let sets_seen = ops.iter().any(|op| {
            op.as_ref()
                .is_ok_and(|(_, _, arguments)| arguments.sets_seen())
        });
        let _write_permit;
        let permit = if sets_seen {
            _write_permit = self.acquire_write_permit().await;
            None
        } else {
            self.acquire_read_permit().await
        };

        spawn_op!(permit, data, {
            for op in ops {
                match op {
                    Ok((is_uid, enabled_condstore, arguments)) => {
                        match data
                            .fetch(
                                arguments,
                                mailbox.clone(),
                                None,
                                is_uid,
                                is_qresync,
                                is_uidonly,
                                enabled_condstore,
                                is_utf8,
                                message_limit,
                                Instant::now(),
                            )
                            .await
                        {
                            Ok(response) => {
                                data.write_bytes(response.into_bytes()).await?;
                            }
                            Err(err) => data.write_error(err).await?,
                        }
                    }
                    Err(err) => data.write_error(err).await?,
                }
            }

            Ok(())
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch(
        &self,
        mut arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        cache: Option<Arc<MessageStoreCache>>,
        is_uid: bool,
        is_qresync: bool,
        is_uidonly: bool,
        enabled_condstore: bool,
        is_utf8: bool,
        message_limit: u32,
        op_start: Instant,
    ) -> trc::Result<StatusResponse> {
        // Validate VANISHED parameter
        if arguments.include_vanished {
            if !is_qresync {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Enable QRESYNC first to use the VANISHED parameter.")
                    .ctx(trc::Key::Type, ResponseType::Bad)
                    .id(arguments.tag));
            } else if !is_uid {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("VANISHED parameter is only available for UID FETCH.")
                    .ctx(trc::Key::Type, ResponseType::Bad)
                    .id(arguments.tag));
            }
        }

        // Resync messages if needed
        let account_id = mailbox.id.account_id;
        let cache = match cache {
            Some(cache) => cache,
            None => self
                .server
                .get_cached_messages(account_id)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?,
        };
        let mut modseq = self
            .sync_view(&mailbox, &cache, None)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert IMAP ids to JMAP ids.
        let mut ids = mailbox
            .resolve(&arguments.sequence_set, is_uid)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert state to modseq
        if let Some(changed_since) = arguments.changed_since {
            // Send vanished UIDs
            if arguments.include_vanished
                && self
                    .server
                    .store()
                    .changes(
                        account_id,
                        SyncCollection::Email.into(),
                        Query::from_modseq(changed_since),
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
                    .changes
                    .iter()
                    .any(|change| matches!(change, Change::UpdateItem(_) | Change::DeleteItem(_)))
            {
                // Add to vanished all known destroyed Ids
                let vanished = self
                    .server
                    .store()
                    .vanished_uids(
                        account_id,
                        mailbox.id.mailbox_id,
                        Query::from_modseq(changed_since),
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;

                if !vanished.is_empty() {
                    let mut buf = Vec::with_capacity(vanished.len() * 3);
                    Vanished {
                        earlier: true,
                        ids: vanished,
                    }
                    .serialize(&mut buf);
                    self.write_bytes(buf).await?;
                }
            }

            // Filter out ids without changes
            ids.retain(|resolved| {
                cache
                    .email_by_id(&resolved.id)
                    .is_some_and(|message| message.change_id() >= changed_since)
            });
            if ids.is_empty() {
                // Condstore was just enabled, return highest modseq.
                if enabled_condstore {
                    self.write_bytes(
                        StatusResponse::ok("Highest Modseq")
                            .with_code(ResponseCode::highest_modseq(modseq))
                            .into_bytes(),
                    )
                    .await?;
                }

                trc::event!(
                    Imap(trc::ImapEvent::Fetch),
                    SpanId = self.session_id,
                    AccountId = account_id,
                    MailboxId = mailbox.id.mailbox_id,
                    Elapsed = op_start.elapsed()
                );

                return Ok(
                    StatusResponse::completed(Command::Fetch(is_uid)).with_tag(arguments.tag)
                );
            }
            arguments.attributes.push_unique(Attribute::ModSeq);
        }

        let needs = FetchNeeds::new(&arguments.attributes);
        let mut set_seen_flags = mailbox.is_select && arguments.sets_seen();

        if set_seen_flags
            && !self
                .check_mailbox_acl(
                    Some(&cache),
                    mailbox.id.account_id,
                    mailbox.id.mailbox_id,
                    Acl::ModifyItems,
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?
        {
            set_seen_flags = false;
        }

        if is_uid {
            if arguments.attributes.is_empty() {
                arguments.attributes.push(Attribute::Flags);
            } else if !arguments.attributes.contains(&Attribute::Uid) {
                arguments.attributes.insert(0, Attribute::Uid);
            }
        }
        let matchers = arguments
            .attributes
            .iter()
            .map(|attribute| {
                attribute
                    .header_fields()
                    .map(|fields| HeaderMatcher::new(fields.iter().map(String::as_str)))
            })
            .collect::<Vec<_>>();

        // Process each message
        let mut batch = BatchBuilder::new();
        // RFC 9738 requires the highest UIDs to be processed first when truncating
        let message_limit = message_limit as usize;
        let limited_uid = if ids.len() > message_limit {
            let cutoff = ids.len() - message_limit;
            ids.select_nth_unstable_by_key(cutoff, |resolved| resolved.uid);
            ids.drain(..cutoff);
            ids.sort_unstable_by_key(|resolved| resolved.uid);
            ids.first().map(|resolved| resolved.uid)
        } else {
            ids.sort_unstable_by_key(|resolved| resolved.uid);
            None
        };

        let mut output = Vec::with_capacity((ids.len() * 64).min(OUTPUT_FLUSH_THRESHOLD));
        for resolved in &ids {
            let (seqnum, uid, id) = (resolved.seqnum, resolved.uid, resolved.id);
            let Some(data) = cache.email_by_id(&id) else {
                trc::event!(
                    Store(trc::StoreEvent::NotFound),
                    AccountId = account_id,
                    DocumentId = id,
                    Collection = Collection::Email,
                    Details = "Message data not found.",
                    CausedBy = trc::location!(),
                );
                continue;
            };
            let set_seen_flag = set_seen_flags && !cache.has_keyword(data, &Keyword::Seen);

            let metadata_key =
                ValueKey::immutable(account_id, Collection::Email, id, EmailField::Metadata);
            let structure = if needs.structure && !needs.headers {
                self.server
                    .store()
                    .get_value::<MetadataStructure>(metadata_key.clone())
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
            } else {
                None
            };
            let structure_metadata = structure
                .as_ref()
                .map(MetadataStructure::unarchive)
                .transpose()
                .imap_ctx(&arguments.tag, trc::location!())?;
            let row = if needs.headers {
                self.server
                    .store()
                    .get_value::<MetadataRow>(metadata_key)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
            } else {
                None
            };
            let headers = row
                .as_ref()
                .map(MetadataRow::raw_headers)
                .transpose()
                .imap_ctx(&arguments.tag, trc::location!())?;
            let metadata = match &row {
                Some(row) => Some(row.unarchive().imap_ctx(&arguments.tag, trc::location!())?),
                None => structure_metadata,
            };
            if needs.structure && metadata.is_none() {
                trc::event!(
                    Store(trc::StoreEvent::NotFound),
                    AccountId = account_id,
                    DocumentId = id,
                    Collection = Collection::Email,
                    Details = "Message metadata not found.",
                    CausedBy = trc::location!(),
                );
                continue;
            }

            let blob = match metadata.filter(|_| needs.blob) {
                Some(metadata) => {
                    let blob = self
                        .server
                        .blob_store()
                        .get_blob(metadata.blob_hash.0.as_slice(), 0..usize::MAX)
                        .await
                        .imap_ctx(&arguments.tag, trc::location!())?;
                    if blob.is_none() {
                        trc::event!(
                            Store(trc::StoreEvent::NotFound),
                            AccountId = account_id,
                            DocumentId = id,
                            Collection = Collection::Email,
                            BlobId = metadata.blob_hash.0.as_slice(),
                            Details = "Blob not found.",
                            CausedBy = trc::location!(),
                        );
                        continue;
                    }
                    blob
                }
                None => None,
            };
            let raw = metadata
                .map(|metadata| {
                    metadata.raw_message(headers.as_deref(), blob.as_deref().unwrap_or_default())
                })
                .unwrap_or_default();

            let mut sources = DecodedSources::default();
            let mut message_start = output.len();
            let mut has_items = false;
            FetchItem::write_open(
                &mut output,
                if is_uidonly { uid } else { seqnum },
                is_uidonly,
            );

            for (attribute, matcher) in arguments.attributes.iter().zip(&matchers) {
                match attribute {
                    Attribute::Flags => {
                        separate(&mut output, &mut has_items);
                        Flag::write_fetch_item(
                            &mut output,
                            cache
                                .expand_keywords(data)
                                .map(Flag::from)
                                .chain(set_seen_flag.then_some(Flag::Seen)),
                        );
                    }
                    Attribute::InternalDate => {
                        separate(&mut output, &mut has_items);
                        DataItem::InternalDate {
                            date: data.received_at() as i64,
                        }
                        .serialize(&mut output);
                    }
                    Attribute::Rfc822Size => {
                        separate(&mut output, &mut has_items);
                        DataItem::Rfc822Size {
                            size: data.size() as usize,
                        }
                        .serialize(&mut output);
                    }
                    Attribute::Uid => {
                        separate(&mut output, &mut has_items);
                        DataItem::Uid { uid }.serialize(&mut output);
                    }
                    Attribute::ModSeq => {
                        separate(&mut output, &mut has_items);
                        DataItem::ModSeq {
                            modseq: data.change_id() + 1,
                        }
                        .serialize(&mut output);
                    }
                    Attribute::ObjectId => {
                        separate(&mut output, &mut has_items);
                        DataItem::ObjectId(ObjectId {
                            email_id: Some(Id::from_parts(data.thread_id(), id)),
                            thread_id: Some(Id::from(data.thread_id())),
                            ..Default::default()
                        })
                        .serialize(&mut output);
                    }
                    Attribute::Envelope => {
                        if let Some(metadata) = metadata {
                            separate(&mut output, &mut has_items);
                            output.extend_from_slice(b"ENVELOPE ");
                            metadata.write_envelope(&mut output, is_utf8);
                        }
                    }
                    Attribute::Body | Attribute::BodyStructure => {
                        if let Some(metadata) = metadata {
                            let is_extended = matches!(attribute, Attribute::BodyStructure);
                            separate(&mut output, &mut has_items);
                            output.extend_from_slice(if is_extended {
                                b"BODYSTRUCTURE ".as_slice()
                            } else {
                                b"BODY ".as_slice()
                            });
                            metadata.write_structure(&mut output, is_extended, is_utf8);
                        }
                    }
                    Attribute::Preview { .. } => {
                        if let Some(metadata) = metadata {
                            separate(&mut output, &mut has_items);
                            let preview = metadata.preview();
                            DataItem::Preview {
                                contents: (!preview.is_empty()).then(|| preview.as_bytes().into()),
                            }
                            .serialize(&mut output);
                        }
                    }
                    Attribute::Rfc822 => {
                        if let Some(contents) = raw.whole() {
                            separate(&mut output, &mut has_items);
                            DataItem::Rfc822 { contents }.serialize(&mut output);
                        }
                    }
                    Attribute::Rfc822Header => {
                        if let Some(contents) = metadata.and_then(|metadata| metadata.header(raw)) {
                            separate(&mut output, &mut has_items);
                            DataItem::Rfc822Header { contents }.serialize(&mut output);
                        }
                    }
                    Attribute::Rfc822Text => {
                        if let Some(contents) = metadata
                            .and_then(|metadata| raw.view(metadata.headers_len()..raw.len()))
                        {
                            separate(&mut output, &mut has_items);
                            DataItem::Rfc822Text { contents }.serialize(&mut output);
                        }
                    }
                    Attribute::BodySection {
                        sections, partial, ..
                    } => {
                        let Some(metadata) = metadata else {
                            continue;
                        };
                        if let (Some(matcher), Some(headers), [section], None) =
                            (matcher, &headers, sections.as_slice(), partial)
                        {
                            separate(&mut output, &mut has_items);
                            metadata.write_header_fields(&mut output, headers, section, matcher);
                        } else if let Some(contents) = metadata.body_section(
                            raw,
                            &mut sources,
                            sections,
                            *partial,
                            matcher.as_ref(),
                        ) {
                            separate(&mut output, &mut has_items);
                            DataItem::BodySection {
                                sections: Cow::Borrowed(sections),
                                origin_octet: partial.map(|(start, _)| start),
                                contents,
                            }
                            .serialize(&mut output);
                        }
                    }
                    Attribute::Binary {
                        sections, partial, ..
                    } => {
                        let Some(metadata) = metadata else {
                            continue;
                        };
                        match metadata.binary(raw, &mut sources, sections, *partial) {
                            Binary::Found(contents) => {
                                separate(&mut output, &mut has_items);
                                DataItem::Binary {
                                    sections: Cow::Borrowed(sections),
                                    offset: partial.map(|(start, _)| start),
                                    contents,
                                }
                                .serialize(&mut output);
                            }
                            Binary::Missing => (),
                            Binary::UnknownCte => {
                                self.write_unknown_cte(
                                    &mut output,
                                    message_start,
                                    sections,
                                    if is_uid { uid } else { seqnum },
                                )
                                .await?;
                                message_start = 0;
                            }
                        }
                    }
                    Attribute::BinarySize { sections } => {
                        let Some(metadata) = metadata else {
                            continue;
                        };
                        match metadata.binary_size(sections) {
                            Binary::Found(size) => {
                                separate(&mut output, &mut has_items);
                                DataItem::BinarySize {
                                    sections: Cow::Borrowed(sections),
                                    size,
                                }
                                .serialize(&mut output);
                            }
                            Binary::Missing => (),
                            Binary::UnknownCte => {
                                self.write_unknown_cte(
                                    &mut output,
                                    message_start,
                                    sections,
                                    if is_uid { uid } else { seqnum },
                                )
                                .await?;
                                message_start = 0;
                            }
                        }
                    }
                }
            }

            // Add flags to the response if the message was unseen
            if set_seen_flag && !arguments.attributes.contains(&Attribute::Flags) {
                separate(&mut output, &mut has_items);
                Flag::write_fetch_item(
                    &mut output,
                    cache
                        .expand_keywords(data)
                        .map(Flag::from)
                        .chain(iter::once(Flag::Seen)),
                );
            }

            FetchItem::write_close(&mut output);
            self.flush_output(&mut output, false).await?;

            // Add to set flags
            if set_seen_flag {
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email)
                    .with_document(id);
                merge_keywords(
                    &mut batch,
                    data.thread_id(),
                    KeywordDiff::added(Keyword::Seen),
                );
                batch.commit_point();
            }
        }

        // Set Seen ids
        if !batch.is_empty() {
            match self
                .server
                .commit_batch(batch)
                .await
                .map(|ids| ids.last_change_id(account_id, SyncCollection::Email))
                .imap_ctx(&arguments.tag, trc::location!())
            {
                Ok(change_id) => {
                    modseq = change_id;
                }
                Err(err) => {
                    if !err.is_assertion_failure() {
                        return Err(err.id(arguments.tag));
                    }
                }
            }
        }

        self.flush_output(&mut output, true).await?;

        trc::event!(
            Imap(trc::ImapEvent::Fetch),
            SpanId = self.session_id,
            AccountId = account_id,
            MailboxId = mailbox.id.mailbox_id,
            DocumentId = ids
                .iter()
                .map(|resolved| trc::Value::from(resolved.id))
                .collect::<Vec<_>>(),
            Details = arguments
                .attributes
                .iter()
                .map(|c| trc::Value::from(format_compact!("{c:?}")))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        // Condstore was enabled with this command
        if enabled_condstore {
            self.write_bytes(
                StatusResponse::ok("Highest Modseq")
                    .with_code(ResponseCode::highest_modseq(modseq))
                    .into_bytes(),
            )
            .await?;
        }

        let response = StatusResponse::completed(Command::Fetch(is_uid)).with_tag(arguments.tag);
        Ok(match limited_uid {
            Some(uid) => response.with_code(ResponseCode::MessageLimit {
                limit: message_limit as u32,
                uid: uid.into(),
            }),
            None => response,
        })
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FetchNeeds {
    pub structure: bool,
    pub headers: bool,
    pub blob: bool,
}

impl FetchNeeds {
    pub fn new(attributes: &[Attribute]) -> Self {
        let mut needs = FetchNeeds::default();
        for attribute in attributes {
            let (structure, headers, blob) = match attribute {
                Attribute::Envelope
                | Attribute::Body
                | Attribute::BodyStructure
                | Attribute::BinarySize { .. }
                | Attribute::Preview { .. } => (true, false, false),
                Attribute::Rfc822 => (true, true, true),
                Attribute::Rfc822Header => (true, true, false),
                Attribute::Rfc822Text => (true, false, true),
                Attribute::BodySection { sections, .. } => match sections.as_slice() {
                    [] | [Section::Part { num: 1 }, Section::Mime] => (true, true, true),
                    [
                        Section::Header | Section::HeaderFields { .. } | Section::Mime,
                        ..,
                    ] => (true, true, false),
                    _ => (true, false, true),
                },
                Attribute::Binary { sections, .. } => (true, sections.is_empty(), true),
                Attribute::Flags
                | Attribute::InternalDate
                | Attribute::Rfc822Size
                | Attribute::Uid
                | Attribute::ModSeq
                | Attribute::ObjectId => (false, false, false),
            };
            needs.structure |= structure;
            needs.headers |= headers;
            needs.blob |= blob;
        }
        needs
    }
}

impl<T: SessionStream> SessionData<T> {
    async fn write_unknown_cte(
        &self,
        output: &mut Vec<u8>,
        message_start: usize,
        sections: &[u32],
        id: u32,
    ) -> trc::Result<()> {
        let pending = output.split_off(message_start);
        self.flush_output(output, true).await?;
        let mut part = String::with_capacity(sections.len() * 3);
        for (pos, section) in sections.iter().enumerate() {
            if pos > 0 {
                part.push('.');
            }
            let _ = write!(part, "{section}");
        }
        let err = trc::ImapEvent::Error
            .into_err()
            .details(format_compact!(
                "Failed to decode part {part} of message {id}."
            ))
            .code(ResponseCode::UnknownCte);
        self.write_error(err).await?;
        output.extend_from_slice(&pending);
        Ok(())
    }
}

fn separate(output: &mut Vec<u8>, has_items: &mut bool) {
    if *has_items {
        output.push(b' ');
    } else {
        *has_items = true;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FetchNeeds,
        structure::{Binary, tests::Stored},
    };
    use email::message::metadata::{ExtraHeaders, HeaderId};
    use imap_proto::{
        Command,
        protocol::fetch::{Attribute, Section},
        receiver::Receiver,
    };

    const MESSAGES: &[&str] = &[
        concat!(
            "From: a@example.com\r\n",
            "Subject: fwd\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: message/rfc822\r\n",
            "Content-Description: forwarded\r\n",
            "\r\n",
            "From: inner@example.com\r\n",
            "Subject: inner\r\n",
            "Content-Type: multipart/mixed; boundary=\"i\"\r\n",
            "\r\n",
            "--i\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "inner body\r\n",
            "--i--\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Subject: single\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Language: en\r\n",
            "\r\n",
            "single part\r\n"
        ),
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "cover\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: inner@example.com\r\n",
            "Subject: inner\r\n",
            "\r\n",
            "inner body\r\n",
            "--b\r\n",
            "Content-Type: multipart/alternative; boundary=\"a\"\r\n",
            "\r\n",
            "--a\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "alt\r\n",
            "--a--\r\n",
            "--b--\r\n"
        ),
    ];

    #[test]
    fn fetch_needs_section_b_for_root_mime() {
        let sections = vec![Section::Part { num: 1 }, Section::Mime];
        let needs = FetchNeeds::new(&[Attribute::BodySection {
            peek: true,
            sections: sections.clone(),
            partial: None,
        }]);
        assert!(needs.headers && needs.blob && needs.structure);

        let stored = Stored::new(MESSAGES[0]);
        assert_eq!(
            stored.section(&sections, None),
            Some(
                b"Content-Type: message/rfc822\r\nContent-Description: forwarded\r\n\r\n".to_vec()
            )
        );
        let single = Stored::new(MESSAGES[1]);
        let expected =
            b"Content-Type: text/plain; charset=utf-8\r\nContent-Language: en\r\n\r\n".to_vec();
        assert_eq!(single.section(&sections, None), Some(expected.clone()));
        assert_ne!(single.body_only_section(&sections, None), Some(expected));
    }

    fn parsed_attribute(receiver: &mut Receiver<Command>, item: &str) -> Option<Attribute> {
        let command = format!("A1 FETCH 1 {item}\r\n");
        receiver
            .parse(&mut command.as_bytes().iter())
            .expect("command is framed")
            .parse_fetch()
            .ok()
            .map(|mut arguments| arguments.attributes.remove(0))
    }

    #[test]
    fn fetch_needs_covers_every_section_the_parser_accepts() {
        let mut extra = ExtraHeaders::default();
        extra
            .push(HeaderId::DELIVERED_TO, "jdoe@example.org")
            .push(HeaderId::X_SPAM_STATUS, "No");
        let encoded = encodify::base64::STANDARD.encode(
            concat!(
                "From: inner@example.com\r\n",
                "Subject: inner\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "inner body\r\n"
            )
            .as_bytes(),
        );
        let mut messages = MESSAGES
            .iter()
            .map(|message| message.to_string())
            .collect::<Vec<_>>();
        messages.extend([
            concat!(
                "From: a@example.com\r\n",
                "Content-Type: message/rfc822\r\n",
                "\r\n",
                "From: mid@example.com\r\n",
                "Content-Type: message/rfc822\r\n",
                "\r\n",
                "From: deep@example.com\r\n",
                "Subject: deep\r\n",
                "\r\n",
                "deep body\r\n"
            )
            .to_string(),
            format!(
                concat!(
                    "From: a@example.com\r\n",
                    "Content-Type: message/rfc822\r\n",
                    "Content-Transfer-Encoding: base64\r\n",
                    "\r\n",
                    "{}\r\n"
                ),
                encoded
            ),
            concat!(
                "From: a@example.com\r\n",
                "Content-Type: multipart/digest; boundary=\"d\"\r\n",
                "\r\n",
                "--d\r\n",
                "\r\n",
                "From: m1@example.com\r\n",
                "Subject: e1\r\n",
                "\r\n",
                "body 1\r\n",
                "--d--\r\n"
            )
            .to_string(),
            concat!(
                "From user@domain  Fri Feb 22 17:06:23 2008\r\n",
                "From: user@domain.org\r\n",
                "Subject: s\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "body\r\n"
            )
            .to_string(),
            concat!(
                "From: a@example.com\r\n",
                "Content-Type: message/rfc822\r\n",
                "\r\n"
            )
            .to_string(),
        ]);
        let stored = messages
            .iter()
            .flat_map(|message| [Stored::new(message), Stored::with_extra(message, &extra)])
            .collect::<Vec<_>>();

        let mut specs = vec![String::new()];
        let parts = ["0", "1", "2", "3"];
        let texts = [
            "HEADER",
            "TEXT",
            "MIME",
            "HEADER.FIELDS (Subject Content-Type Delivered-To)",
            "HEADER.FIELDS.NOT (Subject)",
        ];
        let mut paths = vec![String::new()];
        let mut level = vec![String::new()];
        for _ in 0..3 {
            level = level
                .iter()
                .flat_map(|path| {
                    parts.iter().map(move |part| {
                        if path.is_empty() {
                            part.to_string()
                        } else {
                            format!("{path}.{part}")
                        }
                    })
                })
                .collect();
            paths.extend(level.iter().cloned());
        }
        for path in &paths {
            if !path.is_empty() {
                specs.push(path.clone());
            }
            for text in texts {
                specs.push(if path.is_empty() {
                    text.to_string()
                } else {
                    format!("{path}.{text}")
                });
                for tail in texts.iter().chain(&parts) {
                    specs.push(if path.is_empty() {
                        format!("{text}.{tail}")
                    } else {
                        format!("{path}.{text}.{tail}")
                    });
                }
            }
        }

        let mut receiver = Receiver::new();
        let mut accepted = 0;
        let mut checked = 0;
        for spec in &specs {
            for partial in ["", "<1.4>"] {
                let Some(attribute) =
                    parsed_attribute(&mut receiver, &format!("BODY.PEEK[{spec}]{partial}"))
                else {
                    continue;
                };
                accepted += 1;
                let Attribute::BodySection {
                    sections, partial, ..
                } = &attribute
                else {
                    panic!("{attribute:?}");
                };
                let needs = FetchNeeds::new(std::slice::from_ref(&attribute));
                for message in &stored {
                    let full = message.section(sections, *partial);
                    if !needs.headers {
                        checked += 1;
                        assert_eq!(
                            message.body_only_section(sections, *partial),
                            full,
                            "{spec}{partial:?} without section B"
                        );
                    }
                    if !needs.blob {
                        checked += 1;
                        assert_eq!(
                            message.header_only_section(sections, *partial),
                            full,
                            "{spec}{partial:?} without the blob"
                        );
                    }
                }
            }
        }
        for path in &paths {
            let Some(attribute) = parsed_attribute(&mut receiver, &format!("BINARY.PEEK[{path}]"))
            else {
                continue;
            };
            let Attribute::Binary { sections, .. } = &attribute else {
                panic!("{attribute:?}");
            };
            let needs = FetchNeeds::new(std::slice::from_ref(&attribute));
            for message in &stored {
                if !needs.headers {
                    checked += 1;
                    assert_eq!(
                        message.binary(sections, None),
                        message.binary_with_headers(sections, None),
                        "BINARY[{path}]"
                    );
                }
            }
        }
        for rejected in ["1.MIME.TEXT", "TEXT.1.MIME", "0.MIME", "1.MIME.HEADER"] {
            assert!(
                parsed_attribute(&mut receiver, &format!("BODY.PEEK[{rejected}]")).is_none(),
                "{rejected}"
            );
        }
        assert!(accepted > 400, "{accepted}");
        assert!(checked > 5_000, "{checked}");
    }

    #[test]
    fn root_mime_selects_content_fields_in_any_case() {
        let single = Stored::new(concat!(
            "From: a@example.com\r\n",
            "Content-Type: text/plain\r\n",
            "content-foo: lower\r\n",
            "X-Content-Bar: not mime\r\n",
            "CONTENT-BAR: upper\r\n",
            "Content-Baz: proper\r\n",
            "\r\n",
            "x\r\n"
        ));
        assert_eq!(
            single.section(&[Section::Part { num: 1 }, Section::Mime], None),
            Some(
                concat!(
                    "Content-Type: text/plain\r\n",
                    "content-foo: lower\r\n",
                    "CONTENT-BAR: upper\r\n",
                    "Content-Baz: proper\r\n",
                    "\r\n"
                )
                .as_bytes()
                .to_vec()
            )
        );
    }

    #[test]
    fn sections_agree_without_section_b_when_fetch_needs_skips_it() {
        let suffixes = [
            None,
            Some(Section::Header),
            Some(Section::Text),
            Some(Section::Mime),
            Some(Section::HeaderFields {
                not: false,
                fields: vec!["Subject".to_string(), "Content-Type".to_string()],
            }),
        ];
        let mut checked = 0;
        for raw in MESSAGES {
            let stored = Stored::new(raw);
            for first in 1..4u32 {
                for second in 0..4u32 {
                    let parts = [first, second]
                        .into_iter()
                        .filter(|num| *num > 0)
                        .collect::<Vec<_>>();
                    for suffix in &suffixes {
                        let mut sections = parts
                            .iter()
                            .map(|num| Section::Part { num: *num })
                            .collect::<Vec<_>>();
                        sections.extend(suffix.clone());
                        let needs = FetchNeeds::new(&[Attribute::BodySection {
                            peek: true,
                            sections: sections.clone(),
                            partial: None,
                        }]);
                        if !needs.headers {
                            checked += 1;
                            assert_eq!(
                                stored.body_only_section(&sections, None),
                                stored.section(&sections, None),
                                "{raw:?} {sections:?}"
                            );
                        }
                    }
                    let needs = FetchNeeds::new(&[Attribute::Binary {
                        peek: true,
                        sections: parts.clone(),
                        partial: None,
                    }]);
                    if !needs.headers {
                        checked += 1;
                        let with_headers = stored.binary_with_headers(&parts, None);
                        assert_eq!(
                            stored.binary(&parts, None),
                            with_headers,
                            "{raw:?} {parts:?}"
                        );
                        assert_ne!(with_headers, Binary::UnknownCte);
                    }
                }
            }
        }
        assert!(checked > 100, "{checked}");
    }
}
