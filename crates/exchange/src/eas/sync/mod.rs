/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod changes;
pub mod email;
pub mod estimate;
pub mod groupware;
pub(super) mod groupware_write;
pub mod meetings;
mod note_write;
pub mod state;

use self::{
    changes::{ChangeScope, ServerItem, Watermark},
    email::{
        ItemReply, LoadedMail, MailCommands, MailTarget, apply_mail_commands, load_mail,
        mail_class, mail_flags,
    },
    estimate::{MailProbes, Prepared, mail_folder, prepare_probe},
    groupware::{
        GroupwareItem, GroupwareKind, GroupwareProbe, GroupwareProbes, GroupwareTarget, Hierarchy,
        RenderContext, sync_groupware, sync_virtual_list,
    },
    meetings::resolve_meetings,
    state::{ClientView, CollectionOptions},
};
use super::{
    context::{EasContext, EasDataKind},
    response::{EasResponse, MAX_RESPONSE_BYTES},
    wait::{ChangeWait, WaitOutcome},
};
use crate::{
    cache::ExchangeCacheFetch,
    eas::convert::{email::MailFlags, flag::StoredFlags},
    folders::{ExchangeFolders, FolderNode, FolderTree, SpecialFolder},
    store::{
        FolderKind, FolderRef,
        eas::{
            EasDeviceState, EasDeviceWrite, EasFolderState, EasFolderWrite, EasStore,
            EasSyncRequest,
        },
    },
};
use ::email::cache::email::MessageCacheAccess;
use ::email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use ahash::AHashSet;
use common::{MessageStoreCache, Server, cache::exchange::ExchangeAccountCache};
use exchange_proto::{
    common::token::TokenBuf,
    eas::{
        commands::{
            MAX_PING_FOLDERS, SyncKeyStr,
            appdata::{ApplicationData, Calendar},
            sync::{
                ClientCommand, ServerCommand, SyncBody, SyncCollection, SyncItemResponse,
                SyncOptions, SyncRequest, SyncResponse, SyncResponseBody, SyncResponseCollection,
                SyncWait, options::FILTER_INCOMPLETE_TASKS,
            },
        },
        http::Command,
        status::{CommonStatus, SyncStatus},
        tokens::ProtocolVersion,
        types::Class,
        wbxml::{Decoder, Encoder},
    },
    ids::eas::{EasServerId, EasSyncKey},
};
use futures::{StreamExt, TryStreamExt, stream};
use std::{borrow::Cow, sync::Arc};
use store::{
    rand::{self, RngExt},
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, BatchBuilder, now},
};
use trc::AddContext;
use types::special_use::SpecialUse;

const DEFAULT_WINDOW: u32 = 100;
const MAX_WINDOW: u32 = 512;
pub const MIN_HEARTBEAT: u32 = 60;
const MAX_HEARTBEAT: u32 = 3540;
const SECONDS_PER_MINUTE: u32 = 60;
const SECONDS_PER_DAY: u64 = 86_400;
const INITIAL_KEY: &str = "0";
const LOAD_CONCURRENCY: usize = 8;
const EMPTY_COLLECTION_KEY: EasSyncKey = EasSyncKey {
    nonce: 0,
    generation: 1,
    change_id: 0,
    page: None,
};

pub trait EasSync: Sync + Send {
    fn eas_sync(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

pub enum KeyInput<'x> {
    Sent(&'x str),
    Current,
}

struct Job<'x> {
    collection_id: Cow<'x, str>,
    key: KeyInput<'x>,
    request: Option<&'x SyncCollection<'x>>,
}

enum KeyState {
    Initial,
    Current,
    Replay,
}

struct JobResult {
    collection_id: String,
    sync_key: TokenBuf,
    status: SyncStatus,
    cache: Option<Arc<MessageStoreCache>>,
    replies: Vec<ItemReply>,
    fetched: Vec<Fetched>,
    commands: Vec<OutItem>,
    more_available: bool,
    render: Option<RenderContext>,
    class: Class,
}

enum Fetched {
    Loaded(LoadedMail),
    Item(Box<GroupwareItem>),
    Missing,
    Deferred,
}

struct ResponseBudget {
    items: usize,
    bytes: usize,
}

enum JobsOutcome {
    Collections(Vec<JobResult>),
    Global(SyncStatus),
}

enum OutItem {
    Add(TokenBuf, LoadedMail),
    Replace(TokenBuf, LoadedMail),
    Put {
        server_id: TokenBuf,
        item: Box<GroupwareItem>,
        added: bool,
    },
    Change(TokenBuf, u32),
    Delete(TokenBuf),
    SoftDelete(TokenBuf),
}

impl EasSync for Server {
    async fn eas_sync(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let request = match decoder {
            Some(decoder) => match SyncRequest::parse(decoder, ctx.version) {
                Ok(request) => request,
                Err(err) => {
                    return Ok(EasResponse::status(
                        Command::Sync,
                        err.status(Command::Sync),
                    ));
                }
            },
            None => SyncRequest::Empty,
        };

        let (device_archive, device_state) = self
            .eas_device_state_seen(ctx.account_id, ctx.device.slot)
            .await?;

        let empty_body;
        let (body, cached) = match &request {
            SyncRequest::Full(body) => (body, device_state.sync.as_ref()),
            SyncRequest::Empty => match &device_state.sync {
                Some(cached) => {
                    empty_body = SyncBody {
                        window_size: (cached.window_size != 0).then_some(cached.window_size),
                        wait: (cached.heartbeat != 0)
                            .then_some(SyncWait::HeartbeatSeconds(cached.heartbeat)),
                        ..Default::default()
                    };
                    (&empty_body, Some(cached))
                }
                None => return Ok(status(SyncStatus::INCOMPLETE_REQUEST)),
            },
        };

        let heartbeat = match body.wait {
            Some(SyncWait::Both) => return Ok(status(SyncStatus::PROTOCOL_ERROR)),
            Some(SyncWait::Minutes(minutes)) => {
                let max = max_heartbeat(self) / SECONDS_PER_MINUTE;
                if minutes == 0 {
                    return Ok(limit(ctx.version, 1));
                } else if minutes > max {
                    return Ok(limit(ctx.version, max));
                }
                minutes * SECONDS_PER_MINUTE
            }
            Some(SyncWait::HeartbeatSeconds(seconds)) => {
                let max = max_heartbeat(self);
                if seconds < MIN_HEARTBEAT {
                    return Ok(limit(ctx.version, MIN_HEARTBEAT));
                } else if seconds > max {
                    return Ok(limit(ctx.version, max));
                }
                seconds
            }
            None => 0,
        };

        let mut jobs = Vec::with_capacity(body.collections.len());
        let mut requested = AHashSet::with_capacity(body.collections.len());
        for collection in &body.collections {
            let Some(collection_id) = &collection.collection_id else {
                return Ok(status(SyncStatus::PROTOCOL_ERROR));
            };
            if collection.protocol_error.is_some() || !requested.insert(collection_id.as_ref()) {
                return Ok(status(SyncStatus::PROTOCOL_ERROR));
            }
            if ctx.version >= ProtocolVersion::V141
                && collection
                    .options
                    .iter()
                    .any(SyncOptions::has_unsupported_body_part)
            {
                return Ok(status(
                    CommonStatus::BODY_PART_PREFERENCE_TYPE_NOT_SUPPORTED.into(),
                ));
            }
            jobs.push(Job {
                collection_id: Cow::Borrowed(collection_id.as_ref()),
                key: KeyInput::Sent(collection.sync_key.as_str()),
                request: Some(collection),
            });
        }
        let replay_cached = matches!(request, SyncRequest::Empty) || body.partial;
        if replay_cached && let Some(cached) = cached {
            for folder in &cached.folders {
                let Some(node) = FolderNode::from_eas_stored(*folder) else {
                    continue;
                };
                let collection_id = node.eas_collection_id();
                if !requested.contains(collection_id.as_str()) {
                    jobs.push(Job {
                        collection_id: Cow::Owned(collection_id.as_str().to_string()),
                        key: KeyInput::Current,
                        request: None,
                    });
                }
            }
        }
        if jobs.is_empty() {
            return Ok(status(match &request {
                SyncRequest::Full(body)
                    if !body.partial && body.wait.is_none() && body.window_size.is_none() =>
                {
                    SyncStatus::PROTOCOL_ERROR
                }
                _ => SyncStatus::INCOMPLETE_REQUEST,
            }));
        }
        if jobs.len() > MAX_PING_FOLDERS as usize {
            return Ok(status(SyncStatus::TOO_MANY_COLLECTIONS));
        }

        if !matches!(request, SyncRequest::Empty) {
            let next = EasSyncRequest {
                folders: jobs
                    .iter()
                    .filter(
                        |job| !matches!(job.key, KeyInput::Sent(key) if key == SyncKeyStr::INITIAL),
                    )
                    .filter_map(|job| FolderNode::from_eas_collection_id(&job.collection_id))
                    .map(|node| node.to_stored())
                    .collect(),
                window_size: body.window_size.unwrap_or_default(),
                heartbeat,
            };
            let changed = match &device_state.sync {
                Some(cached) => *cached != next,
                None => !next.folders.is_empty(),
            };
            if changed {
                let mut state = device_state;
                state.sync = Some(next);
                write_device(self, ctx, device_archive.as_ref(), state).await?;
            }
        }

        let mut wait = (heartbeat != 0).then(|| ChangeWait::new(self, ctx, heartbeat));
        let mut seen = match wait {
            Some(_) => {
                self.get_cached_messages(ctx.account_id)
                    .await?
                    .last_change_id
            }
            None => 0,
        };
        let mut probes = MailProbes::default();
        let mut groupware = GroupwareProbes::default();
        loop {
            match run_jobs(self, ctx, &jobs, body.window_size).await? {
                JobsOutcome::Global(status_code) => return Ok(status(status_code)),
                JobsOutcome::Collections(mut results) if !results.is_empty() => {
                    if results.iter().all(|result| result.cache.is_none()) {
                        return build_response(ctx, &results, None, &StoredFlags::default(), &[]);
                    }
                    let exchange = self.get_cached_exchange(ctx.account_id).await?;
                    let mut documents = RoaringBitmap::new();
                    for result in &results {
                        result.flag_documents(&mut documents);
                    }
                    let stored =
                        StoredFlags::load(self, &exchange, ctx.account_id, &documents).await?;
                    let owner = resolve_meetings(
                        self,
                        &ctx.access_token,
                        ctx.account_id,
                        ctx.version,
                        &exchange,
                        &stored,
                        results
                            .iter_mut()
                            .filter(|result| result.class != Class::Notes)
                            .flat_map(JobResult::mails_mut),
                    )
                    .await?;
                    return build_response(ctx, &results, Some(&exchange), &stored, &owner);
                }
                JobsOutcome::Collections(_) => {}
            }
            let Some(wait) = &mut wait else {
                return Ok(EasResponse::Empty);
            };
            probe_jobs(self, ctx, &jobs, &mut probes, &mut groupware).await?;
            loop {
                let WaitOutcome::Changed(woken) = wait.next().await else {
                    return Ok(EasResponse::Empty);
                };
                let mut pending = false;
                if !groupware.is_empty()
                    && groupware
                        .scan(self, ctx.account_id, woken, |_, count| pending |= count > 0)
                        .await?
                        == Hierarchy::Changed
                {
                    pending = true;
                }
                if !pending {
                    let cache = self.get_cached_messages(ctx.account_id).await?;
                    if cache.last_change_id != seen {
                        seen = cache.last_change_id;
                        pending = probes.has_missing_mailbox(&cache);
                        if !pending {
                            probes.scan(&cache, |_| pending = true);
                        }
                    }
                }
                if pending {
                    break;
                }
            }
        }
    }
}

async fn run_jobs(
    server: &Server,
    ctx: &EasContext<'_>,
    jobs: &[Job<'_>],
    window: Option<u32>,
) -> trc::Result<JobsOutcome> {
    let mut budget = ResponseBudget {
        items: window.map_or(usize::MAX, |window| window_size(Some(window))),
        bytes: MAX_RESPONSE_BYTES,
    };
    let mut results = Vec::with_capacity(jobs.len());
    let mut exchange = None;
    let mut tree = None;
    for job in jobs {
        if let Some(result) =
            sync_job(server, ctx, job, &mut budget, &mut exchange, &mut tree).await?
        {
            if matches!(
                result.status,
                SyncStatus::FOLDER_HIERARCHY_CHANGED
                    | SyncStatus::RETRY
                    | SyncStatus::PROTOCOL_ERROR
            ) {
                return Ok(JobsOutcome::Global(result.status));
            }
            results.push(result);
        }
    }
    Ok(JobsOutcome::Collections(results))
}

async fn probe_jobs(
    server: &Server,
    ctx: &EasContext<'_>,
    jobs: &[Job<'_>],
    probes: &mut MailProbes,
    groupware: &mut GroupwareProbes,
) -> trc::Result<()> {
    probes.clear();
    groupware.clear();
    let mut tree = None;
    for job in jobs {
        let Some(node) = FolderNode::from_eas_collection_id(&job.collection_id) else {
            continue;
        };
        let options = job
            .request
            .map(|request| request.options.as_slice())
            .unwrap_or_default();
        if let Some(folder) = mail_folder(ctx, node) {
            if let Prepared::Ready(probe) =
                prepare_probe(server, ctx, folder, &job.key, options, Class::Email).await?
            {
                probes.push(probe);
            }
            continue;
        }
        let FolderNode::Stored(folder) = node else {
            continue;
        };
        let tree = match &tree {
            Some(tree) => tree,
            None => tree.insert(
                server
                    .exchange_folder_tree(ctx.account_id, ctx.data_types)
                    .await?,
            ),
        };
        if let Some(target) = GroupwareTarget::resolve(ctx, tree, node)
            && let Prepared::Ready(probe) =
                prepare_probe(server, ctx, folder, &job.key, options, target.kind.class()).await?
        {
            groupware.push(GroupwareProbe::new(target, probe));
        }
    }
    Ok(())
}

pub fn max_heartbeat(server: &Server) -> u32 {
    u32::try_from(server.core.exchange.max_heartbeat.as_secs())
        .unwrap_or(MAX_HEARTBEAT)
        .clamp(MIN_HEARTBEAT, MAX_HEARTBEAT)
}

async fn sync_job(
    server: &Server,
    ctx: &EasContext<'_>,
    job: &Job<'_>,
    budget: &mut ResponseBudget,
    exchange: &mut Option<Arc<ExchangeAccountCache>>,
    tree: &mut Option<FolderTree>,
) -> trc::Result<Option<JobResult>> {
    let mut result = JobResult {
        collection_id: job.collection_id.to_string(),
        sync_key: match job.key {
            KeyInput::Sent(key) => sent_key(key),
            KeyInput::Current => initial_key(),
        },
        status: SyncStatus::SUCCESS,
        cache: None,
        replies: Vec::new(),
        fetched: Vec::new(),
        commands: Vec::new(),
        more_available: false,
        render: None,
        class: Class::Email,
    };
    let folder = match FolderNode::from_eas_collection_id(&job.collection_id) {
        Some(FolderNode::Stored(
            folder @ FolderRef {
                kind: FolderKind::Mailbox,
                ..
            },
        )) if ctx.allows(EasDataKind::Mail) => folder,
        Some(FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            ..
        })) => {
            result.status = SyncStatus::SERVER_ERROR;
            return Ok(Some(result));
        }
        Some(FolderNode::Stored(
            folder @ FolderRef {
                kind: FolderKind::Calendar | FolderKind::AddressBook,
                ..
            },
        )) => {
            return sync_groupware(server, ctx, job, folder, result, budget, tree).await;
        }
        Some(FolderNode::Special(SpecialFolder::Calendar)) if ctx.allows(EasDataKind::Calendar) => {
            return sync_virtual_list(server, ctx, job, GroupwareKind::Calendar, result).await;
        }
        Some(FolderNode::Special(SpecialFolder::Tasks)) if ctx.allows(EasDataKind::Calendar) => {
            return sync_virtual_list(server, ctx, job, GroupwareKind::Tasks, result).await;
        }
        Some(FolderNode::Stored(_) | FolderNode::Special(_)) => {
            return Ok(empty_collection(job, result));
        }
        None => {
            result.status = SyncStatus::FOLDER_HIERARCHY_CHANGED;
            return Ok(Some(result));
        }
    };
    let cache = server.get_cached_messages(ctx.account_id).await?;
    if !cache.mailboxes.index.contains_key(&folder.id) {
        result.status = SyncStatus::FOLDER_HIERARCHY_CHANGED;
        return Ok(Some(result));
    }
    let trash_id = cache
        .mailbox_by_role(&SpecialUse::Trash)
        .map(|mailbox| mailbox.document_id);
    let exchange = match exchange {
        Some(exchange) => exchange,
        None => exchange.insert(server.get_cached_exchange(ctx.account_id).await?),
    };
    result.class = mail_class(server, ctx.account_id, &cache, exchange, folder.id).await?;
    let class = result.class;
    if class == Class::Notes
        && job
            .request
            .is_some_and(|request| request.supported.is_some())
    {
        result.status = SyncStatus::PROTOCOL_ERROR;
        return Ok(Some(result));
    }

    let archive = server
        .eas_folder_state(ctx.account_id, ctx.device.slot, folder)
        .await?;
    let mut state = match &archive {
        Some(archive) => Some(
            archive
                .deserialize::<EasFolderState>()
                .caused_by(trc::location!())?,
        ),
        None => None,
    };
    let stored_options = state
        .as_ref()
        .and_then(|state| CollectionOptions::decode(&state.options))
        .unwrap_or_default();
    let mut view = state
        .as_ref()
        .and_then(|state| ClientView::decode(&state.synced))
        .unwrap_or_default();

    let (key_state, key) = match resolve_key(&job.key, state.as_ref(), &view) {
        Some(resolved) => resolved,
        None => {
            result.status = SyncStatus::INVALID_SYNC_KEY;
            result.sync_key = initial_key();
            return Ok(Some(result));
        }
    };
    if matches!(job.key, KeyInput::Current)
        && let Some(current) = key.encode()
    {
        result.sync_key = current;
    }

    let mut options = match key_state {
        KeyState::Initial => CollectionOptions::default(),
        _ => stored_options.clone(),
    };
    if let Some(request) = job.request {
        if (class == Class::Notes && request.conversation_mode.is_some())
            || request.options.iter().any(|options| {
                options.has_bad_filter()
                    || (class == Class::Email
                        && options.filter_type == Some(FILTER_INCOMPLETE_TASKS))
                    || options.class.is_some_and(|item_class| match class {
                        Class::Notes => item_class != Class::Notes,
                        _ => !matches!(item_class, Class::Email | Class::Sms),
                    })
            })
        {
            result.status = SyncStatus::PROTOCOL_ERROR;
            return Ok(Some(result));
        }
        if !request.options.is_empty() {
            options.options = request.options.clone();
        }
        if request.window_size.is_some() {
            options.window_size = request.window_size;
        }
        if request.deletes_as_moves.is_some() {
            options.deletes_as_moves = request.deletes_as_moves;
        }
        if request.conversation_mode.is_some() {
            options.conversation_mode = request.conversation_mode;
        }
    }
    let mail_options = options
        .options
        .iter()
        .find(|options| options.class.is_none_or(|item_class| item_class == class));

    let (nonce, generation, mut watermark) = match key_state {
        KeyState::Initial => {
            view = ClientView::default();
            (
                rand::rng().random(),
                0,
                Watermark {
                    change_id: cache.last_change_id,
                    page: None,
                },
            )
        }
        KeyState::Current | KeyState::Replay => {
            if matches!(key_state, KeyState::Replay) {
                view.rewind();
            } else {
                view.advance();
            }
            (
                key.nonce,
                key.generation,
                Watermark {
                    change_id: key.change_id,
                    page: key.page,
                },
            )
        }
    };
    let previous_change_id = watermark.change_id;

    let target = MailTarget {
        mailbox_id: folder.id,
        trash_id,
        deletes_as_moves: options.deletes_as_moves.unwrap_or(true),
    };
    let commands = job
        .request
        .map(|request| request.commands.as_slice())
        .unwrap_or_default();
    let initial = matches!(key_state, KeyState::Initial);
    let replayed = match (&key_state, &state) {
        (KeyState::Replay, Some(state)) => state.client_ids.as_slice(),
        _ => &[],
    };
    let before_commands = cache.last_change_id;
    let mut client = if initial {
        None
    } else {
        Some(
            apply_mail_commands(
                server,
                ctx,
                cache.clone(),
                MailCommands {
                    target,
                    class,
                    commands,
                    replayed,
                },
                &mut view,
            )
            .await?,
        )
    };
    if matches!(key_state, KeyState::Replay)
        && let Some(client) = &mut client
    {
        client.own.change_id = client.own.change_id.max(Some(before_commands));
    }
    let cache = client
        .as_ref()
        .map_or_else(|| cache.clone(), |client| client.cache.clone());

    if let Some(client) = &client {
        let mut planned = Vec::new();
        for (index, reply) in client.replies.iter().enumerate() {
            result.fetched.push(match reply {
                ItemReply::Fetch {
                    document_id: Some(document_id),
                    ..
                } if budget.bytes > 0 => {
                    budget.bytes = budget
                        .bytes
                        .saturating_sub(message_size(&cache, *document_id));
                    planned.push((index, *document_id));
                    Fetched::Missing
                }
                ItemReply::Fetch {
                    document_id: Some(_),
                    ..
                } => Fetched::Deferred,
                _ => Fetched::Missing,
            });
        }
        let mut loaded = stream::iter(planned)
            .map(|(index, document_id)| {
                let cache = &cache;
                async move {
                    load_mail(server, ctx.account_id, cache, document_id, mail_options)
                        .await
                        .map(|mail| (index, mail))
                }
            })
            .buffered(LOAD_CONCURRENCY);
        while let Some((index, mail)) = loaded.try_next().await? {
            if let (Some(slot), Some(mail)) = (result.fetched.get_mut(index), mail) {
                *slot = Fetched::Loaded(mail);
            }
        }
    }

    let mut items = Vec::new();
    let get_changes = job
        .request
        .is_none_or(|request| request.get_changes.unwrap_or(true));
    let own = client.as_ref().map(|client| &client.own);
    if !initial && (get_changes || own.is_some_and(|own| !own.documents.is_empty())) {
        let window = window_size(options.window_size).min(budget.items);
        let entries = target.entries(&cache);
        let scope = ChangeScope {
            current: &entries,
            cutoff: filter_cutoff(mail_options),
            snapshot: cache.last_change_id,
            window,
            bytes: budget.bytes,
            own,
        };
        if get_changes {
            let changes = scope.collect(&mut view, &mut watermark);
            budget.items = budget.items.saturating_sub(changes.items.len());
            budget.bytes = budget.bytes.saturating_sub(changes.bytes);
            result.more_available = changes.more_available;
            items = changes.items;
        } else {
            scope.defer(&mut view, &mut watermark);
        }
    }

    let loads: fn(&ServerItem) -> Option<u32> = match class {
        Class::Notes => ServerItem::with_data,
        _ => ServerItem::added,
    };
    let mut loaded = stream::iter(items.iter().filter_map(loads))
        .map(|document_id| load_mail(server, ctx.account_id, &cache, document_id, mail_options))
        .buffered(LOAD_CONCURRENCY);
    for item in &items {
        result.commands.push(match *item {
            ServerItem::Add(document_id) => match loaded.try_next().await?.flatten() {
                Some(mail) => OutItem::Add(server_id(folder.id, document_id), mail),
                None => {
                    view.held.remove(document_id);
                    view.added.remove(document_id);
                    continue;
                }
            },
            ServerItem::Change(document_id) if class == Class::Notes => {
                match loaded.try_next().await?.flatten() {
                    Some(mail) => OutItem::Replace(server_id(folder.id, document_id), mail),
                    None => continue,
                }
            }
            ServerItem::Change(document_id) => {
                OutItem::Change(server_id(folder.id, document_id), document_id)
            }
            ServerItem::Delete(document_id) => OutItem::Delete(server_id(folder.id, document_id)),
            ServerItem::SoftDelete(document_id) => {
                OutItem::SoftDelete(server_id(folder.id, document_id))
            }
        });
    }
    drop(loaded);
    let mut client_ids = Vec::new();
    if let Some(client) = client {
        result.replies = client.replies;
        client_ids = client.client_ids;
    }

    let options_changed = options != stored_options;
    let has_output = initial
        || !result.commands.is_empty()
        || !result.replies.is_empty()
        || !commands.is_empty()
        || result.more_available;
    if !has_output {
        if options_changed && let Some(state) = state.as_mut() {
            state.options = options.encode();
            if !write_folder(server, ctx, folder, archive.as_ref(), state.clone()).await? {
                trc::event!(
                    Store(trc::StoreEvent::AssertValueFailed),
                    AccountId = ctx.account_id,
                    Details = "Exchange ActiveSync collection options not saved.",
                );
            }
        }
        return Ok(None);
    }

    let next_key = EasSyncKey {
        nonce,
        generation: generation.wrapping_add(1),
        change_id: watermark.change_id,
        page: watermark.page,
    };
    let Some(token) = next_key.encode() else {
        result.status = SyncStatus::SERVER_ERROR;
        return Ok(Some(result));
    };
    view.page = watermark.page;
    let next_state = EasFolderState {
        nonce,
        generation: next_key.generation,
        change_id: watermark.change_id,
        previous_change_id,
        options: options.encode(),
        supported: Vec::new(),
        synced: view.encode(),
        client_ids,
    };
    if !write_folder(server, ctx, folder, archive.as_ref(), next_state).await? {
        result.status = SyncStatus::RETRY;
        result.commands.clear();
        result.replies.clear();
        result.fetched.clear();
        result.more_available = false;
        return Ok(Some(result));
    }

    result.sync_key = token;
    result.cache = Some(cache);
    Ok(Some(result))
}

fn resolve_key(
    input: &KeyInput<'_>,
    state: Option<&EasFolderState>,
    view: &ClientView,
) -> Option<(KeyState, EasSyncKey)> {
    match input {
        KeyInput::Sent(key) if *key == SyncKeyStr::INITIAL => Some((
            KeyState::Initial,
            EasSyncKey {
                nonce: 0,
                generation: 0,
                change_id: 0,
                page: None,
            },
        )),
        KeyInput::Sent(key) => {
            let state = state?;
            let key = EasSyncKey::decode(key)?;
            if key.nonce != state.nonce || state.generation == 0 {
                None
            } else if key.generation == state.generation {
                Some((KeyState::Current, key))
            } else if key.generation.wrapping_add(1) == state.generation {
                Some((KeyState::Replay, key))
            } else {
                None
            }
        }
        KeyInput::Current => {
            let state = state.filter(|state| state.generation != 0)?;
            Some((
                KeyState::Current,
                EasSyncKey {
                    nonce: state.nonce,
                    generation: state.generation,
                    change_id: state.change_id,
                    page: view.page,
                },
            ))
        }
    }
}

fn window_size(window: Option<u32>) -> usize {
    let window = match window {
        None => DEFAULT_WINDOW,
        Some(0) => MAX_WINDOW,
        Some(window) => window.min(MAX_WINDOW),
    };
    window as usize
}

fn message_size(cache: &MessageStoreCache, document_id: u32) -> usize {
    cache
        .email_by_id(&document_id)
        .map_or(0, |message| message.size() as usize)
}

fn sent_key(key: &str) -> TokenBuf {
    let mut token = TokenBuf::new();
    if token.try_push_ascii(key.as_bytes()) {
        token
    } else {
        initial_key()
    }
}

fn empty_collection(job: &Job<'_>, mut result: JobResult) -> Option<JobResult> {
    let KeyInput::Sent(key) = job.key else {
        return None;
    };
    let initial = key == SyncKeyStr::INITIAL;
    if !initial && EasSyncKey::decode(key) != Some(EMPTY_COLLECTION_KEY) {
        result.status = SyncStatus::INVALID_SYNC_KEY;
        result.sync_key = initial_key();
        return Some(result);
    }
    let commands = job
        .request
        .map(|request| request.commands.as_slice())
        .unwrap_or_default();
    if !initial && commands.is_empty() {
        return None;
    }
    if let Some(key) = EMPTY_COLLECTION_KEY.encode() {
        result.sync_key = key;
    }
    for command in commands {
        result.replies.push(missing_reply(command));
        result.fetched.push(Fetched::Missing);
    }
    Some(result)
}

fn missing_reply(command: &ClientCommand<'_>) -> ItemReply {
    match command {
        ClientCommand::Add {
            client_id, class, ..
        } => ItemReply::Add {
            class: *class,
            client_id: client_id.to_string(),
            server_id: None,
            status: SyncStatus::CONVERSION_ERROR,
            uid: None,
        },
        ClientCommand::Change {
            server_id,
            instance_id,
            ..
        } => ItemReply::Change {
            server_id: server_id.to_string(),
            instance_id: *instance_id,
            status: SyncStatus::OBJECT_NOT_FOUND,
        },
        ClientCommand::Delete {
            server_id,
            instance_id,
        } => ItemReply::Delete {
            server_id: server_id.to_string(),
            instance_id: *instance_id,
            status: SyncStatus::OBJECT_NOT_FOUND,
        },
        ClientCommand::Fetch { server_id } => ItemReply::Fetch {
            server_id: server_id.to_string(),
            document_id: None,
        },
    }
}

fn filter_cutoff(options: Option<&SyncOptions>) -> Option<u64> {
    let days = match options.and_then(|options| options.filter_type)? {
        1 => 1,
        2 => 3,
        3 => 7,
        4 => 14,
        5 => 30,
        6 => 90,
        7 => 180,
        _ => return None,
    };
    Some(now().saturating_sub(days * SECONDS_PER_DAY))
}

fn server_id(mailbox_id: u32, document_id: u32) -> TokenBuf {
    EasServerId {
        container: mailbox_id,
        id: document_id,
    }
    .encode()
}

fn initial_key() -> TokenBuf {
    let mut key = TokenBuf::new();
    key.try_push_ascii(INITIAL_KEY.as_bytes());
    key
}

impl JobResult {
    fn flags<'a>(
        &'a self,
        exchange: Option<&'a ExchangeAccountCache>,
        stored: &'a StoredFlags,
        document_id: u32,
    ) -> Option<MailFlags<'a>> {
        mail_flags(self.cache.as_deref()?, exchange?, stored, document_id)
    }

    fn flag_documents(&self, documents: &mut RoaringBitmap) {
        if self.cache.is_none() || self.class == Class::Notes {
            return;
        }
        documents.extend(self.commands.iter().filter_map(|command| match command {
            OutItem::Add(_, mail) | OutItem::Replace(_, mail) => Some(mail.document_id),
            OutItem::Change(_, document_id) => Some(*document_id),
            _ => None,
        }));
        documents.extend(self.fetched.iter().filter_map(|fetched| match fetched {
            Fetched::Loaded(mail) => Some(mail.document_id),
            _ => None,
        }));
    }

    fn mails_mut(&mut self) -> impl Iterator<Item = &mut LoadedMail> {
        self.commands
            .iter_mut()
            .filter_map(|command| match command {
                OutItem::Add(_, mail) | OutItem::Replace(_, mail) => Some(mail),
                _ => None,
            })
            .chain(self.fetched.iter_mut().filter_map(|fetched| match fetched {
                Fetched::Loaded(mail) => Some(mail),
                _ => None,
            }))
    }

    fn mail_data<'a>(
        &'a self,
        exchange: Option<&'a ExchangeAccountCache>,
        stored: &'a StoredFlags,
        mail: &'a LoadedMail,
        owner: &[String],
        version: ProtocolVersion,
    ) -> trc::Result<Option<ApplicationData<'a>>> {
        let Some(flags) = self.flags(exchange, stored, mail.document_id) else {
            return Ok(None);
        };
        Ok(Some(match self.class {
            Class::Notes => ApplicationData::Note(Box::new(mail.note(flags)?)),
            _ => ApplicationData::Email(Box::new(mail.email(flags, owner, version)?)),
        }))
    }
}

fn build_response(
    ctx: &EasContext<'_>,
    results: &[JobResult],
    exchange: Option<&ExchangeAccountCache>,
    stored: &StoredFlags,
    owner: &[String],
) -> trc::Result<EasResponse> {
    let mut collections = Vec::with_capacity(results.len());
    for result in results {
        let mut commands = Vec::with_capacity(result.commands.len());
        for command in &result.commands {
            commands.push(match command {
                OutItem::Add(server_id, mail) => {
                    let Some(data) =
                        result.mail_data(exchange, stored, mail, owner, ctx.version)?
                    else {
                        continue;
                    };
                    ServerCommand::Add {
                        server_id: server_id.as_str(),
                        data,
                    }
                }
                OutItem::Replace(server_id, mail) => {
                    let Some(data) =
                        result.mail_data(exchange, stored, mail, owner, ctx.version)?
                    else {
                        continue;
                    };
                    ServerCommand::Change {
                        server_id: server_id.as_str(),
                        data,
                    }
                }
                OutItem::Change(server_id, document_id) => {
                    let Some(flags) = result.flags(exchange, stored, *document_id) else {
                        continue;
                    };
                    ServerCommand::Change {
                        server_id: server_id.as_str(),
                        data: ApplicationData::Email(Box::new(flags.change())),
                    }
                }
                OutItem::Put {
                    server_id,
                    item,
                    added,
                } => {
                    let Some(data) = result
                        .render
                        .as_ref()
                        .and_then(|render| item.render(render))
                    else {
                        continue;
                    };
                    if *added {
                        ServerCommand::Add {
                            server_id: server_id.as_str(),
                            data,
                        }
                    } else {
                        ServerCommand::Change {
                            server_id: server_id.as_str(),
                            data,
                        }
                    }
                }
                OutItem::Delete(server_id) => ServerCommand::Delete {
                    server_id: server_id.as_str(),
                },
                OutItem::SoftDelete(server_id) => ServerCommand::SoftDelete {
                    server_id: server_id.as_str(),
                },
            });
        }
        let mut responses = Vec::with_capacity(result.replies.len());
        for (reply, fetched) in result.replies.iter().zip(
            result
                .fetched
                .iter()
                .chain(std::iter::repeat(&Fetched::Missing)),
        ) {
            responses.push(match reply {
                ItemReply::Add {
                    class,
                    client_id,
                    server_id,
                    status,
                    uid,
                } => SyncItemResponse::Add {
                    class: class.filter(|class| *class != result.class),
                    client_id,
                    server_id: server_id.as_ref().map(TokenBuf::as_str),
                    status: *status,
                    data: uid.as_deref().map(|uid| {
                        ApplicationData::Calendar(Box::new(Calendar {
                            uid: Some(Cow::Borrowed(uid)),
                            ..Default::default()
                        }))
                    }),
                },
                ItemReply::Change {
                    server_id,
                    instance_id,
                    status,
                } => SyncItemResponse::Change {
                    server_id,
                    instance_id: *instance_id,
                    status: *status,
                },
                ItemReply::Delete {
                    server_id,
                    instance_id,
                    status,
                } => SyncItemResponse::Delete {
                    server_id,
                    instance_id: *instance_id,
                    status: *status,
                },
                ItemReply::Fetch { server_id, .. } => {
                    let (status, data) = match fetched {
                        Fetched::Loaded(mail) => {
                            match result.mail_data(exchange, stored, mail, owner, ctx.version)? {
                                Some(data) => (SyncStatus::SUCCESS, Some(data)),
                                None => (SyncStatus::OBJECT_NOT_FOUND, None),
                            }
                        }
                        Fetched::Item(item) => match result
                            .render
                            .as_ref()
                            .and_then(|render| item.render(render))
                        {
                            Some(data) => (SyncStatus::SUCCESS, Some(data)),
                            None => (SyncStatus::OBJECT_NOT_FOUND, None),
                        },
                        Fetched::Missing => (SyncStatus::OBJECT_NOT_FOUND, None),
                        Fetched::Deferred => (SyncStatus::SERVER_ERROR, None),
                    };
                    SyncItemResponse::Fetch {
                        server_id: Some(server_id),
                        status,
                        data,
                    }
                }
            });
        }
        collections.push(SyncResponseCollection {
            sync_key: result.sync_key.as_str(),
            collection_id: &result.collection_id,
            status: result.status,
            responses,
            more_available: result.more_available,
            commands,
        });
    }
    let response = SyncResponse {
        status: None,
        body: SyncResponseBody::Collections(collections),
    };
    Ok(EasResponse::encode(ctx.version, |encoder| {
        response.encode(encoder)
    }))
}

pub async fn write_device(
    server: &Server,
    ctx: &EasContext<'_>,
    previous: Option<&Archive<ArchiveBytes>>,
    next: EasDeviceState,
) -> trc::Result<bool> {
    let mut batch = BatchBuilder::new();
    EasDeviceWrite {
        account_id: ctx.account_id,
        slot: ctx.device.slot,
        previous,
        next,
    }
    .build(&mut batch)?;
    commit_state(server, batch).await
}

async fn write_folder(
    server: &Server,
    ctx: &EasContext<'_>,
    folder: FolderRef,
    previous: Option<&Archive<ArchiveBytes>>,
    next: EasFolderState,
) -> trc::Result<bool> {
    let mut batch = BatchBuilder::new();
    EasFolderWrite {
        account_id: ctx.account_id,
        slot: ctx.device.slot,
        folder,
        previous,
        next: Some(next),
    }
    .build(&mut batch)?;
    commit_state(server, batch).await
}

async fn commit_state(server: &Server, mut batch: BatchBuilder) -> trc::Result<bool> {
    match server.store().write_batch(&mut batch).await {
        Ok(_) => Ok(true),
        Err(err) if err.is_assertion_failure() => Ok(false),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

fn status(status: SyncStatus) -> EasResponse {
    EasResponse::status(Command::Sync, status.into())
}

fn limit(version: ProtocolVersion, value: u32) -> EasResponse {
    let response = SyncResponse {
        status: Some(SyncStatus::INVALID_WAIT_OR_HEARTBEAT),
        body: SyncResponseBody::Limit(value),
    };
    EasResponse::encode(version, |encoder: &mut Encoder| response.encode(encoder))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/sync/tests.rs"]
mod tests;
