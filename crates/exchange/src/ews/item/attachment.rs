/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem, mail_allowed, readable_mailbox,
    render::{
        HtmlContent, LoadedMail, MESSAGE_CLASS, MailShape, MailView, body, date_time, recipients,
        single,
    },
};
use crate::ews::{
    context::EwsContext,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use bytes::Bytes;
use common::Server;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::metadata::{
        AddressHeader, ArchivedMessageMetadata, MAX_PROTECTED_VALUE_LEN, MessageView, Occurrence,
        PartKind, PartView, RawMessage,
    },
};
use exchange_proto::{
    ews::{
        MessageResult, Operation, Status,
        requests::attachment::GetAttachment,
        responses::attachment::AttachmentInfoMessage,
        schema::{BodyTypeResponse, ResponseCode, UnindexedField},
        types::{
            ids::AttachmentId,
            item::{
                Item, ItemFields, MessageFields, MessageItem, MimeContent,
                attachment::{Attachment, AttachmentFields, Attachments, FileAttachmentFields},
            },
            path::Path,
            shape::AttachmentShape,
            value::{DateTime, XBinary},
        },
    },
    ids::{
        ews::{AttachmentPath, EwsObjectId},
        token::ObjectKind,
    },
};
use http_proto::HttpResponse;
use mail_parser::MessagePart;
use std::borrow::Cow;

pub(super) const DEFAULT_NAME: &str = "attachment";
pub(super) const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";
const MIME_CHARSET: &str = "UTF-8";
pub(super) const MAX_CONTENT_BYTES: usize = 64 << 20;
const BATCH_STOPPED: &str =
    "The response size limit was reached; request the remaining attachments separately.";
const FNV_OFFSET: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;
const FIELD_SEPARATOR: u8 = 0xff;

pub(crate) struct AttachmentRef {
    pub item: MailItem,
    pub fingerprint: PartFingerprint,
    pub path: AttachmentPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PartFingerprint(u32);

impl AttachmentRef {
    pub fn decode(
        ctx: &EwsContext,
        ids: &EmailIds,
        id: &AttachmentId<'_>,
    ) -> Result<Self, ItemError> {
        if id.id.as_str().is_empty() {
            return Err(ItemError::IdEmpty);
        }
        match EwsObjectId::decode(id.id.as_str()).ok_or(ItemError::Malformed)? {
            EwsObjectId::Attachment {
                account,
                kind: ObjectKind::Email,
                container,
                id,
                fingerprint,
                path,
            } if account == ids.account_id() => {
                mail_allowed(ctx)?;
                Ok(AttachmentRef {
                    item: ids.current(container, id),
                    fingerprint: PartFingerprint(fingerprint),
                    path,
                })
            }
            EwsObjectId::Attachment { .. } => Err(ItemError::AttachmentNotFound),
            _ => Err(ItemError::Malformed),
        }
    }
}

impl PartFingerprint {
    pub fn of_view(part: PartView<'_>) -> Self {
        let content_type = part.content_type();
        Self::new(
            part.attachment_name(),
            content_type
                .as_ref()
                .map(|content_type| (content_type.ctype(), content_type.subtype())),
            part.decoded_size(),
        )
    }

    pub fn of_parsed(part: &MessagePart<'_>) -> Self {
        let content_type = part.content_type();
        Self::new(
            part.attachment_name(),
            content_type
                .as_ref()
                .map(|content_type| (content_type.ctype(), content_type.subtype())),
            u32::try_from(part.decoded_len()).unwrap_or(u32::MAX),
        )
    }

    pub fn value(self) -> u32 {
        self.0
    }

    pub fn find<T>(
        self,
        mut parts: impl Iterator<Item = T>,
        preferred: usize,
        of: impl Fn(&T) -> Option<Self>,
    ) -> Option<(usize, T)> {
        let mut first = None;
        for (index, part) in parts.by_ref().enumerate() {
            if of(&part) == Some(self) {
                if index == preferred {
                    return Some((index, part));
                }
                if first.is_none() {
                    first = Some((index, part));
                }
            }
        }
        first
    }

    fn new(name: Option<&str>, content_type: Option<(&str, Option<&str>)>, size: u32) -> Self {
        let mut hash = Fnv(FNV_OFFSET)
            .feed(protected(name.unwrap_or_default()).bytes())
            .feed([FIELD_SEPARATOR]);
        if let Some((ctype, subtype)) = content_type {
            hash = hash
                .feed(
                    protected(ctype)
                        .bytes()
                        .map(|byte| byte.to_ascii_lowercase()),
                )
                .feed(*b"/")
                .feed(
                    protected(subtype.unwrap_or_default())
                        .bytes()
                        .map(|byte| byte.to_ascii_lowercase()),
                );
        }
        PartFingerprint(hash.feed([FIELD_SEPARATOR]).feed(size.to_le_bytes()).0)
    }
}

fn protected(value: &str) -> &str {
    value
        .get(..value.floor_char_boundary(MAX_PROTECTED_VALUE_LEN))
        .unwrap_or(value)
}

struct Fnv(u32);

impl Fnv {
    fn feed(self, bytes: impl IntoIterator<Item = u8>) -> Self {
        Fnv(bytes.into_iter().fold(self.0, |hash, byte| {
            (hash ^ u32::from(byte)).wrapping_mul(FNV_PRIME)
        }))
    }
}

struct AttachedShape {
    mime: bool,
    body_type: BodyTypeResponse,
    html: HtmlContent,
}

impl AttachedShape {
    fn new(shape: Option<&AttachmentShape<'_>>) -> Self {
        let body_type = shape
            .and_then(|shape| shape.body_type)
            .unwrap_or(BodyTypeResponse::Text);
        AttachedShape {
            mime: shape.is_some_and(|shape| {
                shape.include_mime
                    || shape
                        .additional
                        .iter()
                        .any(|path| matches!(path, Path::Field(UnindexedField::ItemMimeContent)))
            }),
            body_type,
            html: HtmlContent::requested(
                body_type != BodyTypeResponse::Text && shape.is_some_and(|shape| shape.filter_html),
            ),
        }
    }
}

pub(crate) async fn get_attachment(
    server: &Server,
    ctx: &EwsContext,
    request: &GetAttachment<'_>,
) -> trc::Result<HttpResponse> {
    let account_id = ctx.account.account_id;
    let ids = EmailIds::load(server, ctx).await?;
    let cache = server.get_cached_messages(account_id).await?;
    let shape = AttachedShape::new(request.shape.as_ref());
    let probe = MailShape::mime_only();
    let budget = MAX_CONTENT_BYTES.max(server.core.email.mail_max_size);
    let targets = request
        .attachment_ids
        .iter()
        .map(|id| {
            AttachmentRef::decode(ctx, &ids, id).and_then(|mut target| {
                let message = cache
                    .email_by_id(&target.item.document_id)
                    .filter(|message| message.has_mailbox_id(target.item.mailbox_id))
                    .ok_or(ItemError::AttachmentNotFound)?;
                target.item = readable_mailbox(
                    ctx,
                    target.item,
                    message.mailboxes().iter().map(|uid| uid.mailbox_id),
                )
                .map_err(|err| match err {
                    ItemError::NotFound => ItemError::AttachmentNotFound,
                    err => err,
                })?;
                Ok(target)
            })
        })
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::GetAttachment);
    let mut served = 0usize;
    for run in targets.chunk_by(|a, b| match (a, b) {
        (Ok(a), Ok(b)) => a.item == b.item,
        _ => false,
    }) {
        let Some(Ok(first)) = run.first() else {
            for target in run {
                if let Err(err) = target {
                    messages.message(&MessageResult::<AttachmentInfoMessage> {
                        status: err.status(),
                        body: None,
                    });
                }
            }
            continue;
        };
        let mail = LoadedMail::load(server, account_id, &cache, first.item, &probe).await?;
        let headers = mail.as_ref().map(LoadedMail::headers).transpose()?;
        let view = match (&mail, &headers) {
            (Some(mail), Some(headers)) => Some(MailView::new(mail, headers, false)?),
            _ => None,
        };
        let source = mail
            .as_ref()
            .zip(view.as_ref())
            .and_then(|(mail, view)| view.source(mail));
        for target in run.iter().flatten() {
            let Some((part, path)) = source
                .as_ref()
                .and_then(|(meta, _)| locate(meta.root(), target))
            else {
                messages.message(&not_found());
                continue;
            };
            let size = usize::try_from(part.decoded_size()).unwrap_or(usize::MAX);
            if served > 0 && served.saturating_add(size) > budget {
                messages.message(&MessageResult::<AttachmentInfoMessage> {
                    status: Status::warning(
                        ResponseCode::ErrorBatchProcessingStopped,
                        BATCH_STOPPED,
                    ),
                    body: None,
                });
                continue;
            }
            let Some(attachment) = source
                .as_ref()
                .and_then(|(meta, raw)| attached(&ids, target.item, path, meta, part, raw, &shape))
            else {
                messages.message(&not_found());
                continue;
            };
            served = served.saturating_add(size);
            messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(AttachmentInfoMessage {
                    attachments: vec![attachment],
                }),
            });
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

pub(super) fn attachment_list<'x>(
    ids: &EmailIds,
    item: MailItem,
    message: MessageView<'x>,
    parent: Option<&AttachmentPath>,
    last_modified: Option<DateTime>,
) -> Option<Attachments<'x>> {
    let list = message
        .attachments()
        .enumerate()
        .filter_map(|(index, part)| {
            let path = child_path(parent, index)?;
            let id = ids.attachment_id(item, PartFingerprint::of_view(part).value(), path);
            let mut fields = common_fields(id, part);
            fields.last_modified_time = last_modified;
            Some(if part.nested().is_some() {
                Attachment::Item(fields, None)
            } else {
                Attachment::File(
                    file_fields(fields, part),
                    FileAttachmentFields {
                        is_contact_photo: Some(false),
                        ..Default::default()
                    },
                )
            })
        })
        .collect::<Vec<_>>();
    (!list.is_empty()).then_some(Attachments(list))
}

fn locate<'x>(
    root: MessageView<'x>,
    target: &AttachmentRef,
) -> Option<(PartView<'x>, AttachmentPath)> {
    let (last, parents) = target.path.as_slice().split_last()?;
    let mut message = root;
    for index in parents {
        message = message.attachments().nth(usize::from(*index))?.nested()?;
    }
    let (index, part) =
        target
            .fingerprint
            .find(message.attachments(), usize::from(*last), |part| {
                Some(PartFingerprint::of_view(*part))
            })?;
    Some((part, sibling_path(parents, index)?))
}

pub(super) fn sibling_path(parents: &[u16], index: usize) -> Option<AttachmentPath> {
    let index = u16::try_from(index).ok()?;
    let Some((first, rest)) = parents.split_first() else {
        return Some(AttachmentPath::new(index));
    };
    let mut path = AttachmentPath::new(*first);
    for parent in rest {
        path.try_push(*parent)?;
    }
    path.try_push(index)?;
    Some(path)
}

fn attached<'x>(
    ids: &EmailIds,
    item: MailItem,
    path: AttachmentPath,
    meta: &'x ArchivedMessageMetadata,
    part: PartView<'x>,
    raw: &RawMessage<'x>,
    shape: &AttachedShape,
) -> Option<Attachment<'x>> {
    let fields = common_fields(
        ids.attachment_id(item, PartFingerprint::of_view(part).value(), path.clone()),
        part,
    );
    let source = meta.source(part.message(), *raw)?;
    Some(match part.nested() {
        Some(message) => {
            let nested = meta.source(message, *raw)?;
            let envelope = message.envelope();
            let addresses = |header| envelope.addresses(header, Occurrence::Last);
            let sent = envelope
                .datetime()
                .and_then(|sent| date_time(sent.to_timestamp()));
            let attachments = attachment_list(ids, item, message, Some(&path), None);
            let item = ItemFields {
                mime_content: shape.mime.then(|| MimeContent {
                    character_set: Some(Cow::Borrowed(MIME_CHARSET)),
                    content: binary(part.decoded(&source)),
                }),
                item_class: Some(Cow::Borrowed(MESSAGE_CLASS)),
                subject: envelope.subject().map(Cow::Borrowed),
                body: Some(body(message, &nested, shape.body_type, &shape.html, None)),
                has_attachments: Some(attachments.is_some()),
                attachments,
                date_time_sent: sent,
                date_time_created: sent,
                size: fields.size,
                ..Default::default()
            };
            let message = MessageFields {
                sender: single(addresses(AddressHeader::Sender))
                    .or_else(|| single(addresses(AddressHeader::From))),
                to_recipients: recipients(addresses(AddressHeader::To)),
                cc_recipients: recipients(addresses(AddressHeader::Cc)),
                from: single(addresses(AddressHeader::From)),
                internet_message_id: envelope.message_id().last_bracketed().map(Cow::Borrowed),
                ..Default::default()
            };
            Attachment::Item(
                fields,
                Some(Box::new(Item::Message(Box::new(MessageItem {
                    item,
                    message,
                })))),
            )
        }
        None => Attachment::File(
            file_fields(fields, part),
            FileAttachmentFields {
                content: Some(binary(part.decoded(&source))),
                ..Default::default()
            },
        ),
    })
}

fn common_fields<'x>(id: AttachmentId<'static>, part: PartView<'x>) -> AttachmentFields<'x> {
    AttachmentFields {
        attachment_id: Some(id),
        name: Some(Cow::Borrowed(
            part.attachment_name()
                .or_else(|| part.nested()?.envelope().subject())
                .unwrap_or(DEFAULT_NAME),
        )),
        size: Some(i32::try_from(part.decoded_size()).unwrap_or(i32::MAX)),
        is_inline: Some(part.kind() == PartKind::InlineBinary),
        content_id: part.content_id().map(Cow::Borrowed),
        content_location: part.content_location().map(Cow::Borrowed),
        ..Default::default()
    }
}

fn file_fields<'x>(fields: AttachmentFields<'x>, part: PartView<'x>) -> AttachmentFields<'x> {
    AttachmentFields {
        content_type: Some(
            part.content_type()
                .map_or(Cow::Borrowed(DEFAULT_CONTENT_TYPE), |content_type| {
                    content_type.mime_type()
                }),
        ),
        ..fields
    }
}

fn child_path(parent: Option<&AttachmentPath>, index: usize) -> Option<AttachmentPath> {
    let index = u16::try_from(index).ok()?;
    match parent {
        Some(parent) => {
            let mut path = parent.clone();
            path.try_push(index)?;
            Some(path)
        }
        None => Some(AttachmentPath::new(index)),
    }
}

fn binary(content: Cow<'_, [u8]>) -> XBinary<'_> {
    match content {
        Cow::Borrowed(bytes) => XBinary::Borrowed(bytes),
        Cow::Owned(bytes) => XBinary::Bytes(Bytes::from(bytes)),
    }
}

fn not_found() -> MessageResult<'static, AttachmentInfoMessage<'static>> {
    MessageResult {
        status: ItemError::AttachmentNotFound.status(),
        body: None,
    }
}
