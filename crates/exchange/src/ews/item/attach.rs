/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    EmailIds, ItemError, MailItem, MailWrite,
    attachment::{AttachmentRef, DEFAULT_CONTENT_TYPE, DEFAULT_NAME, PartFingerprint},
    content::DraftEdit,
    create::{MessageView, decoded, ingest_error, message_raw},
    edit::apply_carried,
    writable_mail,
};
use crate::{
    cache::ExchangeCacheFetch,
    eas::convert::compose::{NewPart, Overrides, Rebuilt, rebuild_message},
    ews::{
        context::{EwsCaller, EwsContext},
        reply::{RESPONSE_CAPACITY, ews_response},
    },
    mail::{fetch_raw_message, keywords_fit},
    store::{
        account::ExchangeAccountStore,
        object::{ExchangeObject, ExchangeObjectStore, ReplacedEmail, StoredPlacement},
    },
};
use ahash::AHashMap;
use common::Server;
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::ingest::{IngestEmail, IngestSource},
};
use exchange_proto::{
    ews::{
        MessageResult, Operation, Status,
        requests::attachment::{CreateAttachment, DeleteAttachment},
        responses::attachment::{AttachmentInfoMessage, DeleteAttachmentMessage},
        types::{
            ids::{AttachmentId, ItemId},
            item::attachment::{Attachment, AttachmentFields, FileAttachmentFields},
        },
    },
    ids::ews::AttachmentPath,
};
use http_proto::HttpResponse;
use mail_parser::{MessageParser, MessageRef, PartId};
use smallvec::SmallVec;
use std::borrow::Cow;
use trc::AddContext;
use types::{collection::Collection, keyword::DRAFT};

const MAX_ATTEMPTS: usize = 5;
const MESSAGE_RFC822: &str = "message/rfc822";

type AddedParts = SmallVec<[Option<(AttachmentPath, PartFingerprint)>; 4]>;

pub(super) struct Rewritten {
    item: MailItem,
    identity: u32,
    change_id: u64,
    missing: SmallVec<[usize; 4]>,
    added: AddedParts,
}

struct Removal {
    item: MailItem,
    entries: SmallVec<[(usize, u16, PartFingerprint); 4]>,
}

pub(crate) async fn create_attachment(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &CreateAttachment<'_>,
) -> trc::Result<HttpResponse> {
    let max_size = server.core.email.mail_max_size;
    let mut accepted = Vec::with_capacity(request.attachments.len());
    let mut outcomes = Vec::with_capacity(request.attachments.len());
    for attachment in &request.attachments {
        outcomes.push(new_part(attachment, max_size).map(|part| {
            accepted.push(part);
            accepted.len() - 1
        }));
    }
    let ids = EmailIds::load(server, ctx).await?;
    let rewritten = match ids.decode_item_id(ctx, &request.parent_item_id) {
        Ok(_) if accepted.is_empty() => Ok(None),
        Ok(item) => rewrite_draft(
            server,
            ctx,
            caller,
            item,
            &[],
            &accepted,
            &DraftEdit::default(),
        )
        .await?
        .map(Some),
        Err(err) => Err(err),
    };

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::CreateAttachment);
    for (attachment, outcome) in request.attachments.iter().zip(outcomes) {
        let created = match (outcome, &rewritten) {
            (_, Err(err)) => Err(*err),
            (Err(err), Ok(_)) => Err(err),
            (Ok(slot), Ok(rewritten)) => Ok(rewritten
                .as_ref()
                .and_then(|rewritten| rewritten.created_id(&ids, slot))),
        };
        match created {
            Ok(id) => {
                let fields = AttachmentFields {
                    attachment_id: id,
                    ..Default::default()
                };
                messages.message(&MessageResult {
                    status: Status::SUCCESS,
                    body: Some(AttachmentInfoMessage {
                        attachments: vec![match attachment {
                            Attachment::File(..) => {
                                Attachment::File(fields, FileAttachmentFields::default())
                            }
                            _ => Attachment::Item(fields, None),
                        }],
                    }),
                })
            }
            Err(err) => messages.message(&MessageResult::<AttachmentInfoMessage> {
                status: err.status(),
                body: None,
            }),
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

pub(crate) async fn delete_attachment(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    request: &DeleteAttachment<'_>,
) -> trc::Result<HttpResponse> {
    let mut outcomes = vec![Err(ItemError::NotFound); request.attachment_ids.len()];
    let mut removals: Vec<Removal> = Vec::new();
    let mut by_item = AHashMap::new();
    let ids = EmailIds::load(server, ctx).await?;
    for ((slot, id), outcome) in request
        .attachment_ids
        .iter()
        .enumerate()
        .zip(outcomes.iter_mut())
    {
        let target = match AttachmentRef::decode(ctx, &ids, id) {
            Ok(target) => target,
            Err(err) => {
                *outcome = Err(err);
                continue;
            }
        };
        let &[index] = target.path.as_slice() else {
            *outcome = Err(ItemError::NestedAttachment);
            continue;
        };
        let group = *by_item.entry(target.item).or_insert_with(|| {
            removals.push(Removal {
                item: target.item,
                entries: SmallVec::new(),
            });
            removals.len() - 1
        });
        let Some(removal) = removals.get_mut(group) else {
            continue;
        };
        if removal
            .entries
            .iter()
            .any(|(_, listed, fingerprint)| *listed == index && *fingerprint == target.fingerprint)
        {
            *outcome = Err(ItemError::Duplicate);
        } else {
            removal.entries.push((slot, index, target.fingerprint));
        }
    }
    let mut removed = SmallVec::<[(u16, PartFingerprint); 4]>::new();
    for removal in &removals {
        removed.clear();
        removed.extend(
            removal
                .entries
                .iter()
                .map(|(_, index, fingerprint)| (*index, *fingerprint)),
        );
        let rewritten = rewrite_draft(
            server,
            ctx,
            caller,
            removal.item,
            &removed,
            &[],
            &DraftEdit::default(),
        )
        .await?;
        for (position, (slot, _, _)) in removal.entries.iter().enumerate() {
            if let Some(outcome) = outcomes.get_mut(*slot) {
                *outcome = match &rewritten {
                    Ok(rewritten) if rewritten.missing.contains(&position) => {
                        Err(ItemError::AttachmentNotFound)
                    }
                    Ok(rewritten) => Ok((
                        rewritten.item.mailbox_id,
                        rewritten.identity,
                        rewritten.change_id,
                    )),
                    Err(ItemError::NotFound) => Err(ItemError::AttachmentNotFound),
                    Err(err) => Err(*err),
                };
            }
        }
    }

    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::DeleteAttachment);
    for outcome in outcomes {
        match outcome {
            Ok((mailbox_id, identity, change_id)) => messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(DeleteAttachmentMessage {
                    root_item_id: Some(ids.identity_item_id(mailbox_id, identity, change_id)),
                }),
            }),
            Err(err) => messages.message(&MessageResult::<DeleteAttachmentMessage> {
                status: err.status(),
                body: None,
            }),
        }
    }
    messages.finish();
    Ok(ews_response(out))
}

impl Rewritten {
    pub(super) fn root_id(&self, ids: &EmailIds) -> ItemId<'static> {
        ids.identity_item_id(self.item.mailbox_id, self.identity, self.change_id)
    }

    pub(super) fn item(&self) -> MailItem {
        self.item
    }

    pub(super) fn with_change_id(self, change_id: u64) -> Self {
        Rewritten { change_id, ..self }
    }

    fn created_id(&self, ids: &EmailIds, slot: usize) -> Option<AttachmentId<'static>> {
        let (path, fingerprint) = self.added.get(slot)?.clone()?;
        let root = self.root_id(ids);
        let mut id = ids.identity_attachment_id(
            self.item.mailbox_id,
            self.identity,
            fingerprint.value(),
            path,
        );
        id.root_item_id = Some(root.id);
        id.root_item_change_key = root.change_key;
        Some(id)
    }
}

pub(super) async fn rewrite_draft(
    server: &Server,
    ctx: &EwsContext,
    caller: EwsCaller<'_>,
    item: MailItem,
    removed: &[(u16, PartFingerprint)],
    added: &[NewPart<'_>],
    edit: &DraftEdit<'_>,
) -> trc::Result<Result<Rewritten, ItemError>> {
    let document_id = item.document_id;
    let account_id = ctx.account.account_id;
    let owner = server
        .exchange_quota_owner(caller.access_token, account_id)
        .await?;
    let target_token = server
        .exchange_target_token(caller.access_token, account_id)
        .await?;
    for _ in 0..MAX_ATTEMPTS {
        let cache = server.get_cached_messages(account_id).await?;
        let Some(data) = cache
            .message_data(document_id)
            .filter(|data| data.has_mailbox_id(item.mailbox_id))
        else {
            return Ok(Err(ItemError::NotFound));
        };
        let item = match writable_mail(ctx, &cache, item, MailWrite::Edit) {
            Ok(item) => item,
            Err(err) => return Ok(Err(err)),
        };
        if data.keywords & (1 << DRAFT) == 0 {
            return Ok(Err(ItemError::NotADraft));
        }
        if edit
            .expected_change
            .is_some_and(|change_id| change_id != data.change_id)
        {
            return Ok(Err(ItemError::Stale));
        }
        let (added_keywords, removed_keywords) = edit.flags.diff(data.keywords);
        if (added_keywords | removed_keywords) != 0
            && !keywords_fit(
                &server.core.email.limits,
                &data,
                added_keywords,
                removed_keywords,
            )
        {
            return Ok(Err(ItemError::KeywordLimit));
        }
        let Some((raw, _reservation)) = fetch_raw_message(server, account_id, document_id).await?
        else {
            return Ok(Err(ItemError::NotFound));
        };
        let Some(original) = MessageParser::new().parse(&raw) else {
            return Ok(Err(ItemError::Unparsable));
        };
        let root = original.root();
        let exchange = server.get_cached_exchange(account_id).await?;
        let identity = StoredPlacement {
            container: item.mailbox_id,
            item: exchange.email_item(item.mailbox_id, document_id),
        };
        let mut dropped = SmallVec::<[PartId; 4]>::new();
        let mut unresolved = SmallVec::<[(usize, u16, PartFingerprint); 4]>::new();
        for (position, &(index, fingerprint)) in removed.iter().enumerate() {
            match root.attachments().nth(usize::from(index)) {
                Some(part)
                    if PartFingerprint::of_parsed(&part) == fingerprint
                        && !dropped.contains(&part.id()) =>
                {
                    dropped.push(part.id())
                }
                _ => unresolved.push((position, index, fingerprint)),
            }
        }
        let mut missing = SmallVec::new();
        for (position, index, fingerprint) in unresolved {
            match fingerprint.find(root.attachments(), usize::from(index), |part| {
                (!dropped.contains(&part.id())).then(|| PartFingerprint::of_parsed(part))
            }) {
                Some((_, part)) => dropped.push(part.id()),
                None => missing.push(position),
            }
        }
        if dropped.is_empty() && added.is_empty() && edit.content.is_empty() {
            return Ok(Ok(Rewritten {
                item,
                identity: identity.item,
                change_id: data.change_id,
                missing,
                added: SmallVec::new(),
            }));
        }
        let overrides = match edit.content.overrides(root) {
            Ok(overrides) => overrides,
            Err(err) => return Ok(Err(err)),
        };
        let Some(rebuilt) = rebuild_message(root, &dropped, added, &overrides) else {
            return Ok(Err(ItemError::Unparsable));
        };
        if rebuilt.raw.len() > server.core.email.mail_max_size {
            return Ok(Err(ItemError::TooLarge));
        }
        let parsed = MessageParser::new().parse(&rebuilt.raw);
        let paths = parsed
            .as_ref()
            .map(|message| added_paths(message.root(), &rebuilt))
            .unwrap_or_default();
        let object = if exchange.has_object(Collection::Email, document_id) {
            server
                .exchange_object(account_id, Collection::Email, document_id)
                .await
                .caused_by(trc::location!())?
        } else {
            None
        };
        let mut carried = object
            .as_ref()
            .map(|object| object.deserialize::<ExchangeObject>())
            .transpose()?;
        if !edit.carried.is_empty() {
            apply_carried(
                carried.get_or_insert_with(ExchangeObject::default),
                &edit.carried,
            );
        }
        match server
            .replace_email(
                IngestEmail {
                    raw_message: &rebuilt.raw,
                    blob_hash: None,
                    message: parsed.as_ref(),
                    access_token: target_token.as_ref().unwrap_or(caller.access_token),
                    mailbox_ids: Vec::new(),
                    keywords: Vec::new(),
                    received_at: None,
                    source: IngestSource::Jmap {
                        train_classifier: false,
                    },
                    metadata: None,
                    session_id: caller.session.session_id,
                },
                caller.access_token.changed_by(),
                owner,
                ReplacedEmail {
                    document_id,
                    data: &data,
                    identity,
                    alias: exchange.alias_of(document_id).map(StoredPlacement::from),
                    object: object.as_ref(),
                    added_keywords,
                    removed_keywords,
                    keywords_extra: None,
                },
                carried,
                server.core.exchange.max_object_size,
            )
            .await
        {
            Ok(email) => {
                return Ok(Ok(Rewritten {
                    item: MailItem {
                        mailbox_id: item.mailbox_id,
                        document_id: email.document_id,
                    },
                    identity: identity.item,
                    change_id: email.change_id,
                    missing,
                    added: paths,
                }));
            }
            Err(err) if err.is_assertion_failure() => {}
            Err(err) => return ingest_error(err).map(Err),
        }
    }
    Ok(Err(ItemError::Conflict))
}

pub(super) fn with_attachments(
    raw: &[u8],
    attachments: &[Attachment<'_>],
    max_size: usize,
) -> Result<Vec<u8>, ItemError> {
    let parts = attachments
        .iter()
        .map(|attachment| new_part(attachment, max_size))
        .collect::<Result<Vec<_>, _>>()?;
    let message = MessageParser::new()
        .parse(raw)
        .ok_or(ItemError::Unparsable)?;
    rebuild_message(message.root(), &[], &parts, &Overrides::default())
        .map(|rebuilt| rebuilt.raw)
        .ok_or(ItemError::Unparsable)
}

pub(super) fn added_paths(message: MessageRef<'_>, rebuilt: &Rebuilt) -> AddedParts {
    if message.attachments().len() != rebuilt.attachments {
        return SmallVec::from_elem(None, rebuilt.added.len());
    }
    rebuilt
        .added
        .iter()
        .map(|&index| {
            let path = AttachmentPath::new(u16::try_from(index).ok()?);
            let part = message.attachments().nth(index)?;
            Some((path, PartFingerprint::of_parsed(&part)))
        })
        .collect()
}

pub(super) fn new_part<'x>(
    attachment: &'x Attachment<'_>,
    max_size: usize,
) -> Result<NewPart<'x>, ItemError> {
    match attachment {
        Attachment::File(fields, file) => Ok(NewPart {
            content_type: Cow::Borrowed(
                fields
                    .content_type
                    .as_deref()
                    .filter(|value| is_mime_type(value))
                    .unwrap_or(DEFAULT_CONTENT_TYPE),
            ),
            name: printable(fields.name.as_deref().unwrap_or(DEFAULT_NAME)),
            content_id: fields
                .content_id
                .as_deref()
                .and_then(content_id)
                .map(Cow::Borrowed),
            content_location: content_location(fields),
            inline: fields.is_inline == Some(true),
            data: match &file.content {
                Some(content) => decoded(content, max_size, ItemError::ContentInvalid)?,
                None => Cow::Borrowed(&[]),
            },
        }),
        Attachment::Item(fields, Some(item)) => match MessageView::of(item) {
            Some(Err(err)) => Err(err),
            Some(Ok(message)) => Ok(NewPart {
                content_type: Cow::Borrowed(MESSAGE_RFC822),
                name: printable(
                    fields
                        .name
                        .as_deref()
                        .or(message.item.subject.as_deref())
                        .unwrap_or(DEFAULT_NAME),
                ),
                content_id: fields
                    .content_id
                    .as_deref()
                    .and_then(content_id)
                    .map(Cow::Borrowed),
                content_location: content_location(fields),
                inline: false,
                data: Cow::Owned(message_raw(&message, None, max_size)?),
            }),
            None => Err(ItemError::AttachedItemType),
        },
        Attachment::Item(_, None) => Err(ItemError::MissingAttachedItem),
        Attachment::Reference(..) => Err(ItemError::ReferenceAttachment),
    }
}

fn is_mime_type(value: &str) -> bool {
    value
        .split_once('/')
        .is_some_and(|(kind, subtype)| is_token(kind) && is_token(subtype))
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&byte))
}

fn content_location<'x>(fields: &'x AttachmentFields<'_>) -> Option<Cow<'x, str>> {
    fields
        .content_location
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(printable)
}

fn content_id(value: &str) -> Option<&str> {
    let value = value.trim();
    let value = value.strip_prefix('<').unwrap_or(value);
    let value = value.strip_suffix('>').unwrap_or(value);
    (!value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'<' && byte != b'>'))
    .then_some(value)
}

pub(super) fn printable(value: &str) -> Cow<'_, str> {
    if value.chars().any(char::is_control) {
        Cow::Owned(value.chars().filter(|ch| !ch.is_control()).collect())
    } else {
        Cow::Borrowed(value)
    }
}
