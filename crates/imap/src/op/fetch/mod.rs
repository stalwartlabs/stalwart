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
    core::{
        SelectedMailbox, Session, SessionData, rights::MailboxRights,
        session::OUTPUT_FLUSH_THRESHOLD,
    },
    spawn_op,
};
use common::{
    MessageStoreCache,
    network::SessionStream,
    storage::batch::{DocumentBatch, Lookup, MAX_BATCH_BYTES, MAX_BATCH_DOCUMENTS},
};
use compact_str::{CompactString, format_compact};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::{
        messagedata::{EmailMessageData, KeywordDiff, MetadataForm, MetadataValue, merge_keywords},
        metadata::HeaderMatcher,
    },
};
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse,
    parser::PushUnique,
    protocol::{
        Flag, ObjectId,
        expunge::{Vanished, VanishedFilter},
        fetch::{Arguments, Attribute, DataItem, FetchItem, Section},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use source::DecodedSources;
use std::{borrow::Cow, fmt::Write, iter, sync::Arc, time::Instant};
use store::{query::log::Query, write::BatchBuilder};
use structure::{Binary, ImapMetadata};
use types::{
    collection::{Collection, SyncCollection},
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
        let changed_ids = arguments.changed_since.and_then(|changed_since| {
            mailbox.view.lock().changed_since_scan(
                &cache.emails,
                changed_since,
                &arguments.sequence_set,
                is_uid,
            )
        });
        let is_changed_only = changed_ids.is_some();
        let mut ids = match changed_ids {
            Some(ids) => ids,
            None => mailbox
                .resolve(&arguments.sequence_set, is_uid)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?,
        };

        // Convert state to modseq
        if let Some(changed_since) = arguments.changed_since {
            // Send vanished UIDs
            if arguments.include_vanished && cache.last_change_id >= changed_since {
                // Add to vanished all known destroyed Ids
                let mut vanished = self
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
                    let last_uid = mailbox.view.lock().uid_max();
                    if let Some(filter) = VanishedFilter::new(&arguments.sequence_set, last_uid) {
                        vanished.retain(|uid| filter.contains(*uid));
                    }
                }

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
            if !is_changed_only {
                ids.retain(|resolved| {
                    cache
                        .email_by_id(&resolved.id)
                        .is_some_and(|message| message.change_id() >= changed_since)
                });
            }
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
        let access_token = if mailbox.is_select && arguments.sets_seen() {
            Some(
                self.refresh_access_token()
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?,
            )
        } else {
            None
        };
        let mut seen_rights = access_token.as_ref().and_then(|access_token| {
            let mut rights = MailboxRights::new(access_token, mailbox.id.account_id);
            rights
                .permanent_flags(&cache, [mailbox.id.mailbox_id])
                .permits(&Flag::Seen)
                .then_some(rights)
        });

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

        let form = if needs.headers {
            MetadataForm::Row
        } else {
            MetadataForm::Structure
        };
        let mut metadata_batch = DocumentBatch::new(MAX_BATCH_BYTES);
        let mut output = Vec::with_capacity((ids.len() * 64).min(OUTPUT_FLUSH_THRESHOLD));
        let mut windows = ids.chunks(MAX_BATCH_DOCUMENTS).peekable();
        let mut budget_error = None;
        let mut unknown_cte = Vec::new();
        'windows: while let Some(window) = windows.next() {
            metadata_batch.reset();
            if needs.structure {
                for resolved in window {
                    if cache.has_email_id(&resolved.id) {
                        metadata_batch.request(resolved.id);
                    }
                }
            }

            loop {
                self.server
                    .read_metadata_batch(account_id, form, &mut metadata_batch)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;

                for resolved in window {
                    let (seqnum, uid, id) = (resolved.seqnum, resolved.uid, resolved.id);
                    let Some(data) = cache.email_by_id(&id) else {
                        if metadata_batch.is_first_round() {
                            trc::event!(
                                Store(trc::StoreEvent::NotFound),
                                AccountId = account_id,
                                DocumentId = id,
                                Collection = Collection::Email,
                                Details = "Message data not found.",
                                CausedBy = trc::location!(),
                            );
                        }
                        continue;
                    };
                    let stored = if needs.structure {
                        Some(match metadata_batch.lookup(id) {
                            Lookup::Found(stored) => stored,
                            Lookup::Missing => {
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
                            Lookup::Skip => continue,
                        })
                    } else if metadata_batch.is_first_round() {
                        None
                    } else {
                        continue;
                    };
                    let set_seen_flag = !cache.has_keyword(data, &Keyword::Seen)
                        && seen_rights.as_mut().is_some_and(|rights| {
                            rights
                                .permanent_flags(
                                    &cache,
                                    data.mailboxes()
                                        .iter()
                                        .map(|membership| membership.mailbox_id),
                                )
                                .permits(&Flag::Seen)
                        });
                    let headers = stored
                        .map(MetadataValue::raw_headers)
                        .transpose()
                        .imap_ctx(&arguments.tag, trc::location!())?
                        .flatten();
                    let metadata = stored
                        .map(MetadataValue::unarchive)
                        .transpose()
                        .imap_ctx(&arguments.tag, trc::location!())?;

                    let blob = match metadata.filter(|_| needs.blob) {
                        Some(metadata) => {
                            let blob = match self
                                .server
                                .fetch_blob(
                                    &metadata.blob_hash(),
                                    0..usize::MAX,
                                    Some(metadata.size() as u64),
                                )
                                .await
                                .and_then(|blob| {
                                    blob.map(|mut blob| {
                                        blob.try_reserve_extra(blob.len()).map(|_| blob)
                                    })
                                    .transpose()
                                }) {
                                Ok(blob) => blob,
                                Err(err)
                                    if err.matches(trc::EventType::Limit(
                                        trc::LimitEvent::MemoryBudget,
                                    )) =>
                                {
                                    budget_error = Some(err);
                                    break 'windows;
                                }
                                Err(err) => {
                                    return Err(err).imap_ctx(&arguments.tag, trc::location!());
                                }
                            };
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
                            metadata.raw_message(
                                headers.as_deref(),
                                blob.as_deref().unwrap_or_default(),
                            )
                        })
                        .unwrap_or_default();

                    let mut sources = DecodedSources::default();
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
                                        contents: (!preview.is_empty())
                                            .then(|| preview.as_bytes().into()),
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
                                if let Some(contents) =
                                    metadata.and_then(|metadata| metadata.header(raw))
                                {
                                    separate(&mut output, &mut has_items);
                                    DataItem::Rfc822Header { contents }.serialize(&mut output);
                                }
                            }
                            Attribute::Rfc822Text => {
                                if let Some(contents) = metadata.and_then(|metadata| {
                                    raw.view(metadata.headers_len()..raw.len())
                                }) {
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
                                    metadata.write_header_fields(
                                        &mut output,
                                        headers,
                                        section,
                                        matcher,
                                    );
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
                                    Binary::UnknownCte => unknown_cte.push(sections.as_slice()),
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
                                    Binary::UnknownCte => unknown_cte.push(sections.as_slice()),
                                }
                            }
                        }
                        if output.len() >= OUTPUT_FLUSH_THRESHOLD {
                            self.flush_output(&mut output, false).await?;
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
                    self.flush_output(&mut output, !unknown_cte.is_empty())
                        .await?;
                    for sections in unknown_cte.drain(..) {
                        self.write_unknown_cte(sections, if is_uid { uid } else { seqnum })
                            .await?;
                    }

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

                if !metadata_batch.next_round() {
                    break;
                }
            }

            if needs.structure && windows.peek().is_some() {
                self.flush_output(&mut output, true).await?;
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

        if let Some(err) = budget_error {
            return Err(err.ctx(trc::Key::Id, CompactString::from(arguments.tag.as_str())));
        }

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

        let mut buf = Vec::new();
        mailbox.announce_appended(&mut buf);
        if enabled_condstore {
            buf = StatusResponse::ok("Highest Modseq")
                .with_code(ResponseCode::highest_modseq(modseq))
                .serialize(buf);
        }
        if !buf.is_empty() {
            self.write_bytes(buf).await?;
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
    async fn write_unknown_cte(&self, sections: &[u32], id: u32) -> trc::Result<()> {
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
        self.write_error(err).await
    }
}

fn separate(output: &mut Vec<u8>, has_items: &mut bool) {
    if *has_items {
        output.push(b' ');
    } else {
        *has_items = true;
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/imap/src/op/fetch/tests.rs"]
mod tests;
