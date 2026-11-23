/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::{EasContext, EasDataKind},
    convert::{
        body::BodyChoice,
        email::{conversation_thread_id, listed_attachments},
        flag::StoredFlags,
    },
    folder_id::is_listed,
    folder_sync::MAX_STATE_ATTEMPTS,
    folder_write::{forget_folder_states, stored_subtree},
    response::{EasResponse, MAX_RESPONSE_BYTES},
    sync::{
        email::{LoadedMail, load_mail, mail_class, mail_flags},
        estimate::mail_folder,
        groupware::{GroupwareItem, GroupwareKind, GroupwareTarget, load_item, render_context},
        groupware_write::empty_container,
        meetings::resolve_meetings,
    },
};
use crate::{
    cache::ExchangeCacheFetch,
    folders::{
        ExchangeFolders, FolderContents, FolderNode, FolderTree, FolderWriteError, FolderWrites,
    },
    mail::{CommitOutcome, MailEdits},
    store::{FolderKind, FolderRef},
};
use ::email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    message::metadata::{MetadataRow, PartSource},
};
use bytes::Bytes;
use common::{MessageStoreCache, Server, cache::exchange::ExchangeAccountCache};
use exchange_proto::{
    eas::{
        commands::{
            ItemRange,
            appdata::{ApplicationData, Blob, base::Body},
            item_operations::{
                FetchOptions, FetchProperties, FetchRequest, FetchResult, FileProperties,
                ItemOperation, ItemOperationResult, ItemOperationsRequest, ItemOperationsResponse,
                MoveAlways,
            },
            sync::SyncOptions,
        },
        http::Command,
        multipart::write_multipart_header,
        status::{CommonStatus, HttpOutcome, ItemOperationsStatus},
        types::Class,
        wbxml::Decoder,
    },
    ids::eas::EasServerId,
};
use groupware::cache::GroupwareCache;
use hyper::header::HeaderValue;
use smallvec::SmallVec;
use std::{borrow::Cow, sync::Arc};
use store::{ValueKey, roaring::RoaringBitmap};
use trc::AddContext;
use types::{collection::Collection, field::EmailField, special_use::SpecialUse};

const MAILBOX_STORE: &str = "Mailbox";
const EMPTY_BATCH: usize = 512;
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

pub trait EasItemOperations: Sync + Send {
    fn eas_item_operations(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;

    fn eas_get_attachment(
        &self,
        ctx: &EasContext<'_>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

enum Prepared {
    Mail(ItemOperationsStatus, Option<(LoadedMail, Class)>),
    Groupware(GroupwareKind, Result<GroupwareItem, ItemOperationsStatus>),
    File(Result<Attachment, ItemOperationsStatus>),
    Empty(ItemOperationsStatus),
    Move(ItemOperationsStatus),
}

struct Attachment {
    content_type: String,
    data: Bytes,
    total: usize,
    range: Option<ItemRange>,
}

struct FetchBudget(usize);

impl FetchBudget {
    fn charge(&mut self, size: u32) -> bool {
        if self.0 == 0 {
            return false;
        }
        self.0 = self.0.saturating_sub(size as usize);
        true
    }
}

impl EasItemOperations for Server {
    async fn eas_get_attachment(&self, ctx: &EasContext<'_>) -> trc::Result<EasResponse> {
        let Some(reference) = ctx.params.attachment_name.as_deref() else {
            return Ok(EasResponse::Http(HttpOutcome::BadRequest));
        };
        let cache = self.get_cached_messages(ctx.account_id).await?;
        let mut budget = FetchBudget(MAX_RESPONSE_BYTES);
        Ok(
            match load_attachment(self, ctx, &cache, reference, None, &mut budget).await? {
                Ok(attachment) => EasResponse::Raw {
                    content_type: HeaderValue::try_from(attachment.content_type)
                        .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_CONTENT_TYPE)),
                    data: attachment.data,
                },
                Err(_) => EasResponse::Http(HttpOutcome::ServerError),
            },
        )
    }

    async fn eas_item_operations(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::ItemOperations,
                CommonStatus::INVALID_XML.into(),
            ));
        };
        let request = match ItemOperationsRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::ItemOperations,
                    err.status(Command::ItemOperations),
                ));
            }
        };

        let mut cache = self.get_cached_messages(ctx.account_id).await?;
        let mut budget = FetchBudget(MAX_RESPONSE_BYTES);
        let mut prepared = Vec::with_capacity(request.operations.len());
        let mut exchange = None;
        let mut tree = None;
        for operation in &request.operations {
            prepared.push(match operation {
                ItemOperation::Fetch(fetch) => {
                    prepare_fetch(
                        self,
                        ctx,
                        &cache,
                        fetch,
                        &mut budget,
                        &mut exchange,
                        &mut tree,
                    )
                    .await?
                }
                ItemOperation::EmptyFolderContents {
                    collection_id,
                    delete_sub_folders,
                } => Prepared::Empty(
                    empty_folder(
                        self,
                        ctx,
                        &mut cache,
                        collection_id,
                        *delete_sub_folders,
                        &mut tree,
                    )
                    .await?,
                ),
                ItemOperation::Move {
                    conversation_id,
                    dst_fld_id,
                    move_always,
                } => Prepared::Move(
                    move_conversation(
                        self,
                        ctx,
                        &mut cache,
                        conversation_id,
                        dst_fld_id,
                        *move_always,
                        &mut exchange,
                    )
                    .await?,
                ),
            });
        }

        let (stored, owner) = match exchange.as_deref() {
            Some(exchange) => {
                let documents = prepared
                    .iter()
                    .filter_map(|prepared| match prepared {
                        Prepared::Mail(_, Some((mail, class))) if *class != Class::Notes => {
                            Some(mail.document_id)
                        }
                        _ => None,
                    })
                    .collect::<RoaringBitmap>();
                let stored = StoredFlags::load(self, exchange, ctx.account_id, &documents).await?;
                let owner = resolve_meetings(
                    self,
                    &ctx.access_token,
                    ctx.account_id,
                    ctx.version,
                    exchange,
                    &stored,
                    prepared.iter_mut().filter_map(|prepared| match prepared {
                        Prepared::Mail(_, Some((mail, class))) if *class != Class::Notes => {
                            Some(mail)
                        }
                        _ => None,
                    }),
                )
                .await?;
                (stored, owner)
            }
            None => (StoredFlags::default(), Vec::new()),
        };
        let render = if prepared
            .iter()
            .any(|prepared| matches!(prepared, Prepared::Groupware(_, Ok(_))))
        {
            Some(render_context(self, ctx.account_id, ctx.version).await?)
        } else {
            None
        };
        let multipart = ctx.params.accept_multipart;
        let mut parts: Vec<Bytes> = Vec::new();
        let mut results = Vec::with_capacity(prepared.len());
        for (operation, prepared) in request.operations.iter().zip(&prepared) {
            results.push(match (operation, prepared) {
                (ItemOperation::Fetch(fetch), Prepared::Mail(status, mail)) => {
                    let class = mail.as_ref().map_or(Class::Email, |(_, class)| *class);
                    let schema = fetch
                        .options
                        .schema
                        .as_deref()
                        .filter(|schema| !schema.is_empty());
                    let properties = match mail {
                        Some((mail, Class::Notes)) => exchange
                            .as_deref()
                            .and_then(|exchange| {
                                mail_flags(&cache, exchange, &stored, mail.document_id)
                            })
                            .map(|flags| {
                                mail.note(flags).map(|mut note| {
                                    if let Some(schema) = schema {
                                        note.retain_fields(schema);
                                    }
                                    if multipart && let Some(body) = note.body.as_mut() {
                                        move_body_to_part(body, &mut parts);
                                    }
                                    FetchProperties::Item(ApplicationData::Note(Box::new(note)))
                                })
                            })
                            .transpose()?,
                        Some((mail, _)) => match exchange.as_deref().and_then(|exchange| {
                            mail_flags(&cache, exchange, &stored, mail.document_id)
                        }) {
                            Some(flags) => {
                                let mut email = mail.email(flags, &owner, ctx.version)?;
                                if let Some(schema) = schema {
                                    email.retain_fields(schema);
                                }
                                if multipart && let Some(body) = email.body.as_mut() {
                                    move_body_to_part(body, &mut parts);
                                }
                                Some(FetchProperties::Item(ApplicationData::Email(Box::new(
                                    email,
                                ))))
                            }
                            None => None,
                        },
                        None => None,
                    };
                    ItemOperationResult::Fetch(FetchResult {
                        status: if properties.is_some() || *status != ItemOperationsStatus::SUCCESS
                        {
                            *status
                        } else {
                            ItemOperationsStatus::NOT_FOUND
                        },
                        collection_id: fetch.collection_id.as_deref(),
                        server_id: fetch.server_id.as_deref(),
                        long_id: fetch.long_id.as_deref(),
                        class: Some(class),
                        link_id: None,
                        file_reference: None,
                        properties,
                    })
                }
                (ItemOperation::Fetch(fetch), Prepared::Groupware(kind, item)) => {
                    let mut data = item
                        .as_ref()
                        .ok()
                        .zip(render.as_ref())
                        .and_then(|(item, render)| item.render(render));
                    if let Some((data, schema)) = data.as_mut().zip(
                        fetch
                            .options
                            .schema
                            .as_deref()
                            .filter(|schema| !schema.is_empty()),
                    ) {
                        data.retain_fields(schema);
                    }
                    if multipart
                        && let Some(body) = data.as_mut().and_then(|data| match data {
                            ApplicationData::Calendar(item) => item.body.as_mut(),
                            ApplicationData::Task(item) => item.body.as_mut(),
                            ApplicationData::Contact(item) => item.body.as_mut(),
                            _ => None,
                        })
                    {
                        move_body_to_part(body, &mut parts);
                    }
                    ItemOperationResult::Fetch(FetchResult {
                        status: match item {
                            Ok(_) if data.is_some() => ItemOperationsStatus::SUCCESS,
                            Ok(_) => ItemOperationsStatus::NOT_FOUND,
                            Err(status) => *status,
                        },
                        collection_id: fetch.collection_id.as_deref(),
                        server_id: fetch.server_id.as_deref(),
                        long_id: fetch.long_id.as_deref(),
                        class: Some(kind.class()),
                        link_id: None,
                        file_reference: None,
                        properties: data.map(FetchProperties::Item),
                    })
                }
                (ItemOperation::Fetch(fetch), Prepared::File(file)) => {
                    let (status, properties) = match file {
                        Ok(file) => {
                            let part = if multipart {
                                parts.push(file.data.clone());
                                u32::try_from(parts.len()).ok()
                            } else {
                                None
                            };
                            (
                                ItemOperationsStatus::SUCCESS,
                                Some(FetchProperties::File(FileProperties {
                                    content_type: Some(&file.content_type),
                                    range: file.range,
                                    total: u64::try_from(file.total).ok(),
                                    data: part.is_none().then_some(file.data.as_ref()),
                                    part,
                                    version: None,
                                })),
                            )
                        }
                        Err(status) => (*status, None),
                    };
                    ItemOperationResult::Fetch(FetchResult {
                        status,
                        collection_id: None,
                        server_id: None,
                        long_id: None,
                        class: None,
                        link_id: None,
                        file_reference: fetch.file_reference.as_deref(),
                        properties,
                    })
                }
                (
                    ItemOperation::EmptyFolderContents { collection_id, .. },
                    Prepared::Empty(status),
                ) => ItemOperationResult::EmptyFolderContents {
                    status: *status,
                    collection_id,
                },
                (
                    ItemOperation::Move {
                        conversation_id, ..
                    },
                    Prepared::Move(status),
                ) => ItemOperationResult::Move {
                    status: *status,
                    conversation_id,
                },
                _ => {
                    return Ok(EasResponse::status(
                        Command::ItemOperations,
                        ItemOperationsStatus::SERVER_ERROR.into(),
                    ));
                }
            });
        }

        let response = ItemOperationsResponse {
            status: ItemOperationsStatus::SUCCESS,
            results,
        };
        let wbxml = EasResponse::encode(ctx.version, |encoder| response.encode(encoder));
        if !multipart {
            return Ok(wbxml);
        }
        let EasResponse::Wbxml(segments) = wbxml else {
            return Ok(wbxml);
        };
        let wbxml_len = segments.len();
        let wbxml = segments.into_parts();
        let mut lens = Vec::with_capacity(parts.len() + 1);
        for len in std::iter::once(wbxml_len).chain(parts.iter().map(Bytes::len)) {
            match u32::try_from(len) {
                Ok(len) => lens.push(len),
                Err(_) => {
                    return Ok(EasResponse::status(
                        Command::ItemOperations,
                        ItemOperationsStatus::TOO_LARGE.into(),
                    ));
                }
            }
        }
        let mut header = Vec::new();
        if write_multipart_header(&mut header, &lens).is_err() {
            return Ok(EasResponse::status(
                Command::ItemOperations,
                ItemOperationsStatus::TOO_LARGE.into(),
            ));
        }
        let mut body = Vec::with_capacity(parts.len() + 2);
        body.push(Bytes::from(header));
        body.extend(wbxml);
        body.extend(parts);
        Ok(EasResponse::Multipart(body))
    }
}

async fn prepare_fetch(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &MessageStoreCache,
    fetch: &FetchRequest<'_>,
    budget: &mut FetchBudget,
    exchange: &mut Option<Arc<ExchangeAccountCache>>,
    tree: &mut Option<FolderTree>,
) -> trc::Result<Prepared> {
    if !fetch.store.eq_ignore_ascii_case(MAILBOX_STORE) {
        return Ok(Prepared::Mail(ItemOperationsStatus::UNKNOWN_STORE, None));
    }
    if let Some(reference) = &fetch.file_reference {
        return load_attachment(server, ctx, cache, reference, fetch.options.range, budget)
            .await
            .map(Prepared::File);
    }
    if let (Some(collection_id), Some(server_id)) = (&fetch.collection_id, &fetch.server_id)
        && let Some(
            node @ FolderNode::Stored(FolderRef {
                kind: FolderKind::Calendar | FolderKind::AddressBook,
                ..
            }),
        ) = FolderNode::from_eas_collection_id(collection_id)
    {
        return prepare_groupware_fetch(server, ctx, fetch, node, server_id, budget, tree).await;
    }
    let target = match (&fetch.collection_id, &fetch.server_id, &fetch.long_id) {
        (Some(collection_id), Some(server_id), _) => {
            FolderNode::from_eas_collection_id(collection_id)
                .and_then(|node| mail_folder(ctx, node))
                .zip(EasServerId::decode(server_id))
                .filter(|(folder, id)| id.container == folder.id)
        }
        (_, _, Some(long_id)) => EasServerId::decode(long_id).and_then(|id| {
            mail_folder(
                ctx,
                FolderNode::Stored(FolderRef {
                    kind: FolderKind::Mailbox,
                    id: id.container,
                }),
            )
            .map(|folder| (folder, id))
        }),
        _ => None,
    };
    let message = target.and_then(|(folder, id)| {
        cache
            .email_by_id(&id.id)
            .filter(|message| message.has_mailbox_id(folder.id))
            .map(|message| (folder, message))
    });
    let Some((folder, message)) = message else {
        return Ok(Prepared::Mail(ItemOperationsStatus::NOT_FOUND, None));
    };
    if !budget.charge(message.size()) {
        return Ok(Prepared::Mail(ItemOperationsStatus::TOO_LARGE, None));
    }
    let document_id = message.document_id();
    let options = mail_options(&fetch.options);
    if options.has_unsupported_body_part() {
        return Ok(Prepared::Mail(
            CommonStatus::BODY_PART_PREFERENCE_TYPE_NOT_SUPPORTED.into(),
            None,
        ));
    }
    let Some(mail) = load_mail(server, ctx.account_id, cache, document_id, Some(&options)).await?
    else {
        return Ok(Prepared::Mail(ItemOperationsStatus::SUCCESS, None));
    };
    let exchange = match exchange {
        Some(exchange) => exchange,
        None => exchange.insert(server.get_cached_exchange(ctx.account_id).await?),
    };
    let class = mail_class(server, ctx.account_id, cache, exchange, folder.id).await?;
    Ok(Prepared::Mail(
        ItemOperationsStatus::SUCCESS,
        Some((mail, class)),
    ))
}

async fn prepare_groupware_fetch(
    server: &Server,
    ctx: &EasContext<'_>,
    fetch: &FetchRequest<'_>,
    node: FolderNode,
    server_id: &str,
    budget: &mut FetchBudget,
    tree: &mut Option<FolderTree>,
) -> trc::Result<Prepared> {
    let Some(target) = GroupwareTarget::resolve(ctx, cached_tree(server, ctx, tree).await?, node)
    else {
        return Ok(Prepared::Mail(ItemOperationsStatus::NOT_FOUND, None));
    };
    let kind = target.kind;
    let Some(id) = EasServerId::decode(server_id).filter(|id| id.container == target.container_id)
    else {
        return Ok(Prepared::Groupware(
            kind,
            Err(ItemOperationsStatus::NOT_FOUND),
        ));
    };
    let resources = server
        .fetch_groupware_resources(ctx.account_id, ctx.account_id, kind.collection())
        .await?;
    let is_member = resources.item_by_id(id.id).is_some_and(|resource| {
        resource
            .child_names()
            .iter()
            .any(|name| name.parent_id == target.container_id)
    });
    if !is_member {
        return Ok(Prepared::Groupware(
            kind,
            Err(ItemOperationsStatus::NOT_FOUND),
        ));
    }
    if budget.0 == 0 {
        return Ok(Prepared::Groupware(
            kind,
            Err(ItemOperationsStatus::TOO_LARGE),
        ));
    }
    let body = BodyChoice::select(Some(&mail_options(&fetch.options)), false);
    let item = load_item(server, ctx.account_id, kind, id.id, body).await?;
    if let Some(item) = &item {
        budget.charge(item.size);
    }
    Ok(Prepared::Groupware(
        kind,
        item.ok_or(ItemOperationsStatus::NOT_FOUND),
    ))
}

async fn load_attachment(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &MessageStoreCache,
    reference: &str,
    range: Option<ItemRange>,
    budget: &mut FetchBudget,
) -> trc::Result<Result<Attachment, ItemOperationsStatus>> {
    const NOT_FOUND: ItemOperationsStatus = ItemOperationsStatus::ATTACHMENT_FETCH_FAILED;
    let Some((id, message)) = EasServerId::decode(reference)
        .filter(|_| ctx.allows(EasDataKind::Mail))
        .and_then(|id| Some((id, cache.email_by_id(&id.container)?)))
    else {
        return Ok(Err(NOT_FOUND));
    };
    if !budget.charge(message.size()) {
        return Ok(Err(ItemOperationsStatus::TOO_LARGE));
    }
    let Some(row) = server
        .store()
        .get_value::<MetadataRow>(ValueKey::immutable(
            ctx.account_id,
            Collection::Email,
            id.container,
            EmailField::Metadata,
        ))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(Err(NOT_FOUND));
    };
    let meta = row.unarchive().caused_by(trc::location!())?;
    let Some(part) = listed_attachments(meta.root()).find(|part| part.id() == id.id) else {
        return Ok(Err(NOT_FOUND));
    };
    let Some(blob) = server
        .fetch_blob(&meta.blob_hash(), 0..usize::MAX, Some(meta.size() as u64))
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(Err(NOT_FOUND));
    };
    let headers = row.raw_headers().caused_by(trc::location!())?;
    let raw = meta.raw_message(Some(&headers), &blob);
    let decoded = part.decoded(&PartSource::Raw(raw));
    let total = decoded.len();
    let span = match range {
        Some(range) => {
            let start = usize::try_from(range.start).unwrap_or(usize::MAX);
            let end = usize::try_from(range.end)
                .unwrap_or(usize::MAX)
                .saturating_add(1)
                .min(total);
            if start >= end {
                return Ok(Err(ItemOperationsStatus::INVALID_RANGE));
            }
            start..end
        }
        None => 0..total,
    };
    let data = match decoded {
        Cow::Owned(decoded) => Bytes::from(decoded).slice(span),
        Cow::Borrowed(decoded) => match decoded.get(span) {
            Some(data) => Bytes::copy_from_slice(data),
            None => return Ok(Err(ItemOperationsStatus::INVALID_RANGE)),
        },
    };
    let range = range.map(|range| ItemRange {
        start: range.start,
        end: range
            .start
            .saturating_add(u32::try_from(data.len()).unwrap_or(u32::MAX))
            .saturating_sub(1),
    });
    Ok(Ok(Attachment {
        content_type: part.content_type().map_or_else(
            || DEFAULT_CONTENT_TYPE.to_string(),
            |ctype| ctype.mime_type().into_owned(),
        ),
        data,
        total,
        range,
    }))
}

async fn cached_tree<'t>(
    server: &Server,
    ctx: &EasContext<'_>,
    tree: &'t mut Option<FolderTree>,
) -> trc::Result<&'t mut FolderTree> {
    Ok(match tree {
        Some(tree) => tree,
        None => tree.insert(
            server
                .exchange_folder_tree(ctx.account_id, ctx.data_types)
                .await?,
        ),
    })
}

async fn empty_folder(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &mut Arc<MessageStoreCache>,
    collection_id: &str,
    delete_sub_folders: bool,
    tree: &mut Option<FolderTree>,
) -> trc::Result<ItemOperationsStatus> {
    let Some(node) = FolderNode::from_eas_collection_id(collection_id) else {
        return Ok(ItemOperationsStatus::NOT_FOUND);
    };
    let status = match mail_folder(ctx, node) {
        Some(folder) => empty_mailbox(server, ctx, cache, folder).await?,
        None => {
            let Some(target) =
                GroupwareTarget::resolve(ctx, cached_tree(server, ctx, tree).await?, node)
            else {
                return Ok(ItemOperationsStatus::NOT_FOUND);
            };
            empty_container(server, ctx, target).await?
        }
    };
    if status != ItemOperationsStatus::SUCCESS || !delete_sub_folders {
        return Ok(status);
    }
    delete_child_folders(server, ctx, cache, node, tree).await
}

async fn delete_child_folders(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &mut Arc<MessageStoreCache>,
    node: FolderNode,
    tree: &mut Option<FolderTree>,
) -> trc::Result<ItemOperationsStatus> {
    *tree = None;
    let children = {
        let folders = &*cached_tree(server, ctx, tree).await?;
        folders
            .children(node)
            .filter(|entry| is_listed(entry) && matches!(entry.node, FolderNode::Stored(_)))
            .map(|entry| {
                (
                    entry.node,
                    stored_subtree(folders, entry.node).collect::<SmallVec<[FolderRef; 4]>>(),
                )
            })
            .collect::<SmallVec<[(FolderNode, SmallVec<[FolderRef; 4]>); 4]>>()
    };
    let mut complete = true;
    for (child, subtree) in &children {
        match server
            .folder_destroy(
                &ctx.access_token,
                ctx.account_id,
                *child,
                FolderContents::Remove,
            )
            .await?
        {
            Ok(_) | Err(FolderWriteError::NotFound) => {
                if let Err(err) = forget_folder_states(server, ctx, subtree).await {
                    trc::error!(err.details("Failed to clear EAS folder states"));
                }
            }
            Err(_) => complete = false,
        }
    }
    if !children.is_empty() {
        *tree = None;
        *cache = server.get_cached_messages(ctx.account_id).await?;
    }
    Ok(if complete {
        ItemOperationsStatus::SUCCESS
    } else {
        ItemOperationsStatus::PARTIAL_SUCCESS
    })
}

async fn empty_mailbox(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &mut Arc<MessageStoreCache>,
    folder: FolderRef,
) -> trc::Result<ItemOperationsStatus> {
    let mut attempts = 0;
    let rounds = cache.in_mailbox(folder.id).count() / EMPTY_BATCH + MAX_STATE_ATTEMPTS + 1;
    for _ in 0..rounds {
        if !cache.mailboxes.index.contains_key(&folder.id) {
            return Ok(ItemOperationsStatus::NOT_FOUND);
        }
        let mut edits = MailEdits::new(ctx.account_id);
        let mut planned = 0;
        for message in cache.in_mailbox(folder.id).take(EMPTY_BATCH) {
            if let Some(data) = cache.message_data(message.document_id())
                && edits.remove_from(message.document_id(), data, folder.id)?
            {
                planned += 1;
            }
        }
        if planned == 0 {
            return Ok(ItemOperationsStatus::SUCCESS);
        }
        if edits
            .commit(server, &ctx.access_token, ctx.session.session_id)
            .await?
            == CommitOutcome::Conflict
        {
            attempts += 1;
            if attempts >= MAX_STATE_ATTEMPTS {
                return Ok(ItemOperationsStatus::SERVER_ERROR);
            }
        }
        *cache = server.get_cached_messages(ctx.account_id).await?;
    }
    Ok(ItemOperationsStatus::SERVER_ERROR)
}

async fn move_conversation(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &mut Arc<MessageStoreCache>,
    conversation_id: &[u8],
    dst_fld_id: &str,
    move_always: MoveAlways,
    exchange: &mut Option<Arc<ExchangeAccountCache>>,
) -> trc::Result<ItemOperationsStatus> {
    match move_always {
        MoveAlways::Set => {}
        MoveAlways::Missing => {
            return Ok(CommonStatus::MOVE_COMMAND_DISALLOWED_FOR_NON_PERSISTENT_MOVE_ACTION.into());
        }
        MoveAlways::Malformed => return Ok(ItemOperationsStatus::PROTOCOL_ERROR),
    }
    let Some(node) = FolderNode::from_eas_collection_id(dst_fld_id) else {
        return Ok(ItemOperationsStatus::NOT_FOUND);
    };
    let Some(to) = mail_folder(ctx, node) else {
        return Ok(CommonStatus::MOVE_COMMAND_INVALID_DESTINATION_FOLDER.into());
    };
    if !cache.mailboxes.index.contains_key(&to.id) {
        return Ok(ItemOperationsStatus::NOT_FOUND);
    }
    if cache
        .mailbox_by_role(&SpecialUse::Drafts)
        .is_some_and(|drafts| drafts.document_id == to.id)
    {
        return Ok(CommonStatus::MOVE_COMMAND_INVALID_DESTINATION_FOLDER.into());
    }
    let exchange = match exchange {
        Some(exchange) => exchange,
        None => exchange.insert(server.get_cached_exchange(ctx.account_id).await?),
    };
    if mail_class(server, ctx.account_id, cache, exchange, to.id).await? != Class::Email {
        return Ok(CommonStatus::MOVE_COMMAND_INVALID_DESTINATION_FOLDER.into());
    }
    let Some(thread_id) = conversation_thread_id(conversation_id) else {
        return Ok(ItemOperationsStatus::NOT_FOUND);
    };
    let (placements, widest) =
        cache
            .in_thread(thread_id)
            .fold((0usize, 0usize), |(total, widest), message| {
                let count = message.mailboxes().len();
                (total + count, widest.max(count))
            });
    if placements == 0 {
        return Ok(ItemOperationsStatus::NOT_FOUND);
    }
    let sent = cache
        .mailbox_by_role(&SpecialUse::Sent)
        .map(|folder| folder.document_id);
    let mut attempts = 0;
    let mut committed = false;
    for _ in 0..placements / EMPTY_BATCH + widest + MAX_STATE_ATTEMPTS + 1 {
        let mut edits = MailEdits::new(ctx.account_id);
        let mut planned = 0;
        for (message, from) in cache
            .in_thread(thread_id)
            .filter_map(|message| {
                message
                    .mailboxes()
                    .iter()
                    .map(|mailbox| mailbox.mailbox_id)
                    .find(|id| *id != to.id && Some(*id) != sent)
                    .map(|from| (message, from))
            })
            .take(EMPTY_BATCH)
        {
            if let Some(data) = cache.message_data(message.document_id())
                && edits.move_to(message.document_id(), data, from, to.id)?
            {
                planned += 1;
            }
        }
        if planned == 0 {
            return Ok(ItemOperationsStatus::SUCCESS);
        }
        match edits
            .commit(server, &ctx.access_token, ctx.session.session_id)
            .await?
        {
            CommitOutcome::Conflict => {
                attempts += 1;
                if attempts >= MAX_STATE_ATTEMPTS {
                    return Ok(move_failure(committed));
                }
            }
            CommitOutcome::Committed(_) => committed = true,
        }
        *cache = server.get_cached_messages(ctx.account_id).await?;
    }
    Ok(move_failure(committed))
}

fn move_failure(committed: bool) -> ItemOperationsStatus {
    if committed {
        ItemOperationsStatus::PARTIAL_SUCCESS
    } else {
        CommonStatus::FAILURE_IN_MOVE_OPERATION.into()
    }
}

fn move_body_to_part(body: &mut Body<'_>, parts: &mut Vec<Bytes>) {
    if let Some(data) = body.data.take() {
        parts.push(match data {
            Blob::Shared(bytes) => bytes,
            Blob::Slice(slice) => Bytes::from(slice.into_owned()),
        });
        body.part = u32::try_from(parts.len()).ok();
    }
}

fn mail_options(options: &FetchOptions<'_>) -> SyncOptions {
    SyncOptions {
        class: Some(Class::Email),
        body_preferences: options.body_preferences.clone(),
        body_part_preferences: options.body_part_preferences.clone(),
        mime_support: options.mime_support,
        rights_management_support: options.rights_management_support,
        ..Default::default()
    }
}
