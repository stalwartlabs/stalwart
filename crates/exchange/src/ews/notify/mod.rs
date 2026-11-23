/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod groupware_log;
pub mod scan;
pub mod stream;
pub mod subscription;

use super::{
    context::EwsContext,
    folder::{FolderSelector, folder_id, resolve_folder},
    item::{EmailIds, mail_allowed},
    reply::{RESPONSE_CAPACITY, ews_response},
};
use crate::{
    folders::{ContainerClass, FolderNode, FolderTree},
    session::ExchangeSessionSlot,
    store::{FolderKind, FolderRef},
};
use common::{
    MessageStoreCache, Server, cache::exchange_sessions::ExchangeSessionLimit,
    network::memory::MemoryClass,
};
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use exchange_proto::{
    common::time::UtcSeconds,
    ews::{
        MessageResult, Operation, Status,
        requests::notification::{GetEvents, Subscribe, Unsubscribe},
        responses::notification::{
            Event, EventObject, GetEventsMessage, MovedEvent, Notification, ObjectEvent,
            SubscribeMessage,
        },
        schema::ResponseCode,
        types::{
            ids::{
                BaseFolderId, DistinguishedFolderId, EwsIdStr, FolderId, ItemId, SubscriptionId,
                Watermark,
            },
            subscription::{EventTypes, SubscriptionFolders, SubscriptionRequest},
            value::DateTime,
        },
    },
    ids::{
        ews::{EwsObjectId, EwsSubscriptionId, EwsSubscriptionKind, EwsWatermark},
        token::ObjectKind,
    },
};
use groupware::cache::GroupwareCache;
use groupware_log::{GROUPWARE_KINDS, GroupwareScan, KINDS};
use http_proto::HttpResponse;
use hyper::header::SET_COOKIE;
use scan::{Cursor, Place, ScanEvent, ScanInput, ScanObject, Scope};
use smallvec::SmallVec;
use std::{borrow::Cow, slice, sync::Arc, time::Duration};
use store::{rand, write::now};
use subscription::{
    Batch, Delivery, EwsSubscription, EwsTombstone, NewSubscription, Next, STREAMING_IDLE_TTL,
    ServerBusy, TOMBSTONE_TTL,
};

const PUSH_UNSUPPORTED: &str =
    "Push notifications are not supported; use pull or streaming subscriptions.";
const NOT_FOUND: &str = "The specified subscription was not found.";
const ACCESS_DENIED: &str =
    "The subscription was created by another account or with another data scope.";
const DELEGATE_ACCESS: &str = "Subscriptions can only be created on the caller's own mailbox.";
const INVALID_WATERMARK: &str = "The watermark is invalid.";
const NOT_PULL: &str = "The subscription is not a pull subscription.";
const TOO_MANY: &str = "The account has too many subscriptions.";
const BUSY: &str = "The server cannot hold more subscription state right now.";
const AFFINITY_COOKIE: &str = "X-BackEndOverrideCookie";
const SECONDS_PER_MINUTE: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    NotFound,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InvalidWatermark;

enum Found {
    Live(Arc<EwsSubscription>),
    Tombstone(Arc<EwsSubscription>),
    Gone,
}

pub(crate) struct Snapshot {
    pub messages: Arc<MessageStoreCache>,
    pub ids: EmailIds,
    pub tree: Arc<FolderTree>,
    pub groupware: [Option<GroupwareScan>; GROUPWARE_KINDS],
}

impl Snapshot {
    pub async fn load(server: &Server, ctx: &EwsContext) -> trc::Result<Self> {
        let account_id = ctx.account.account_id;
        let mut groupware = [None, None];
        for (slot, (kind, collection, data_type)) in groupware.iter_mut().zip(KINDS) {
            if ctx.account.data_types.contains(data_type) {
                *slot = Some(GroupwareScan {
                    kind,
                    collection,
                    resources: server
                        .fetch_groupware_resources(account_id, account_id, collection)
                        .await?,
                    log: None,
                });
            }
        }
        Ok(Snapshot {
            tree: ctx.folder_tree(server).await?,
            messages: server.get_cached_messages(account_id).await?,
            ids: EmailIds::load(server, ctx).await?,
            groupware,
        })
    }

    pub async fn load_logs(
        &mut self,
        server: &Server,
        account_id: u32,
        subscriptions: &[Arc<EwsSubscription>],
    ) -> trc::Result<()> {
        for (index, slot) in self.groupware.iter_mut().enumerate() {
            if let Some(scan) = slot {
                let windows = subscriptions
                    .iter()
                    .map(|subscription| subscription.groupware_window(index));
                scan.load_log(server, account_id, windows).await?;
            }
        }
        Ok(())
    }

    pub fn is_behind(&self) -> bool {
        self.groupware
            .iter()
            .flatten()
            .any(GroupwareScan::is_behind)
    }

    pub fn input<'x>(&'x self, subscription: &'x EwsSubscription, now: u64) -> ScanInput<'x> {
        self.scoped_input(&subscription.scope, subscription.mail, now)
    }

    fn scoped_input<'x>(&'x self, scope: &'x Scope, mail: bool, now: u64) -> ScanInput<'x> {
        ScanInput {
            messages: &self.messages,
            exchange: self.ids.exchange(),
            tree: &self.tree,
            scope,
            mail,
            now,
            groupware: self
                .groupware
                .each_ref()
                .map(|slot| slot.as_ref().map(GroupwareScan::input)),
        }
    }

    pub fn notification(
        &self,
        subscription: &EwsSubscription,
        batch: &Batch,
    ) -> Notification<'static> {
        let watermark = |seq| {
            Some(Watermark(Cow::Owned(
                subscription.watermark(seq).encode().as_str().into(),
            )))
        };
        let timestamp = DateTime::utc(UtcSeconds(
            i64::try_from(batch.timestamp).unwrap_or(i64::MAX),
        ));
        let events = if batch.events.is_empty() {
            vec![Event::Status {
                watermark: watermark(batch.watermark(0)),
            }]
        } else {
            batch
                .events
                .iter()
                .enumerate()
                .map(|(index, event)| {
                    let object = |place: &Place, live: bool| ObjectEvent {
                        watermark: watermark(batch.watermark(index)),
                        timestamp,
                        object: self.object(place.object, live),
                        parent_folder_id: self.folder(place.parent, true),
                    };
                    match event {
                        ScanEvent::Created(place) => Event::Created(object(place, true)),
                        ScanEvent::NewMail(place) => Event::NewMail(object(place, true)),
                        ScanEvent::Deleted(place) => Event::Deleted(object(place, false)),
                        ScanEvent::Modified { place, unread } => Event::Modified {
                            event: object(place, true),
                            unread_count: unread
                                .map(|unread| i32::try_from(unread).unwrap_or(i32::MAX)),
                        },
                        ScanEvent::Moved { to, from } => Event::Moved(MovedEvent {
                            event: object(to, true),
                            old_object: self.object(from.object, false),
                            old_parent_folder_id: self.folder(from.parent, true),
                        }),
                    }
                })
                .collect()
        };
        Notification {
            subscription_id: SubscriptionId(Cow::Owned(subscription.id.encode().as_str().into())),
            previous_watermark: watermark(batch.previous),
            more_events: Some(batch.more),
            events,
        }
    }

    fn object(&self, object: ScanObject, live: bool) -> EventObject<'static> {
        match object {
            ScanObject::Item { mailbox, identity } if live => {
                let document_id = self.ids.current(mailbox, identity).document_id;
                let change_id = self
                    .messages
                    .email_by_id(&document_id)
                    .map_or(0, |message| message.change_id());
                EventObject::Item(self.ids.identity_item_id(mailbox, identity, change_id))
            }
            ScanObject::Item { mailbox, identity } => {
                EventObject::Item(self.ids.deleted_id(mailbox, identity))
            }
            ScanObject::Groupware {
                kind,
                container,
                document,
            } => EventObject::Item(ItemId {
                id: EwsIdStr::Minted(
                    EwsObjectId::Item {
                        account: self.ids.account_id(),
                        kind: self.groupware_object_kind(kind, container),
                        container,
                        id: document,
                    }
                    .encode(),
                ),
                change_key: None,
            }),
            ScanObject::Folder(node) => EventObject::Folder(self.folder(node, live)),
        }
    }

    fn groupware_object_kind(&self, kind: FolderKind, container: u32) -> ObjectKind {
        let node = FolderNode::Stored(FolderRef {
            kind,
            id: container,
        });
        match (kind, self.tree.get(node).map(|entry| &entry.class)) {
            (FolderKind::AddressBook, _) => ObjectKind::Contact,
            (_, Some(ContainerClass::Task)) => ObjectKind::Task,
            _ => ObjectKind::Event,
        }
    }

    fn folder(&self, node: FolderNode, live: bool) -> FolderId<'static> {
        let change_id = self.tree.get(node).map_or(0, |entry| entry.change_id);
        let id = folder_id(self.ids.account_id(), node, change_id);
        if live && self.tree.get(node).is_some() {
            id
        } else {
            FolderId {
                change_key: None,
                ..id
            }
        }
    }
}

pub(crate) fn lookup(
    server: &Server,
    ctx: &EwsContext,
    principal: u32,
    id: &SubscriptionId<'_>,
) -> Result<Arc<EwsSubscription>, Lookup> {
    let key = EwsSubscriptionId::decode(id.0.as_ref())
        .filter(|key| key.account == ctx.account.account_id)
        .ok_or(Lookup::NotFound)?;
    let subscription = match find(server, key.account, key.id, now()) {
        Found::Live(subscription) if subscription.id == key => subscription,
        Found::Live(_) | Found::Tombstone(_) | Found::Gone => return Err(Lookup::NotFound),
    };
    if subscription.owner == principal && subscription.data_types == ctx.account.data_types {
        Ok(subscription)
    } else {
        Err(Lookup::Denied)
    }
}

fn find(server: &Server, account_id: u32, id: u128, now: u64) -> Found {
    if let Some(subscription) = server.exchange_session::<EwsSubscription>(account_id, id)
        && !subscription.is_closed()
    {
        if subscription.touch(now) {
            return Found::Live(subscription);
        }
        server.remove_exchange_session::<EwsSubscription>(account_id, id);
        bury(server, subscription, now);
    }
    match server.exchange_session::<EwsTombstone>(account_id, id) {
        Some(tombstone) if now < tombstone.until => {
            Found::Tombstone(tombstone.subscription.clone())
        }
        Some(_) => {
            server.remove_exchange_session::<EwsTombstone>(account_id, id);
            Found::Gone
        }
        None => Found::Gone,
    }
}

fn bury(server: &Server, subscription: Arc<EwsSubscription>, now: u64) {
    subscription.bury(now);
    let until = subscription.tombstone_until();
    if until > now {
        let (account_id, id) = (subscription.id.account, subscription.id.id);
        let _ = server.insert_exchange_session_evicting(
            account_id,
            id,
            Arc::new(EwsTombstone {
                subscription,
                until,
            }),
            Duration::from_secs(until - now),
        );
    }
}

impl Lookup {
    fn status(self) -> Status<'static> {
        match self {
            Lookup::NotFound => Status::error(ResponseCode::ErrorSubscriptionNotFound, NOT_FOUND),
            Lookup::Denied => {
                Status::error(ResponseCode::ErrorSubscriptionAccessDenied, ACCESS_DENIED)
            }
        }
    }
}

pub(crate) async fn subscribe(
    server: &Server,
    ctx: &EwsContext,
    principal: u32,
    request: &Subscribe<'_>,
) -> trc::Result<HttpResponse> {
    let outcome = match &request.subscription {
        SubscriptionRequest::Push { .. } => Err(Status::error(
            ResponseCode::ErrorInvalidOperation,
            PUSH_UNSUPPORTED,
        )),
        SubscriptionRequest::Pull {
            folders,
            events,
            watermark,
            timeout,
        } => {
            create(
                server,
                ctx,
                principal,
                Requested {
                    folders,
                    events: *events,
                    kind: EwsSubscriptionKind::Pull,
                    watermark: watermark.as_ref(),
                    ttl: Duration::from_secs(u64::from(*timeout) * SECONDS_PER_MINUTE),
                },
            )
            .await?
        }
        SubscriptionRequest::Streaming { folders, events } => {
            create(
                server,
                ctx,
                principal,
                Requested {
                    folders,
                    events: *events,
                    kind: EwsSubscriptionKind::Streaming,
                    watermark: None,
                    ttl: STREAMING_IDLE_TTL,
                },
            )
            .await?
        }
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::Subscribe);
    let created = match outcome {
        Ok(subscription) => {
            messages.message(&MessageResult {
                status: Status::SUCCESS,
                body: Some(SubscribeMessage {
                    subscription_id: SubscriptionId(Cow::Owned(
                        subscription.id.encode().as_str().into(),
                    )),
                    watermark: (!subscription.is_streaming()).then(|| {
                        Watermark(Cow::Owned(
                            subscription
                                .watermark(subscription.current_seq())
                                .encode()
                                .as_str()
                                .into(),
                        ))
                    }),
                }),
            });
            true
        }
        Err(status) => {
            messages.message(&MessageResult::<SubscribeMessage> { status, body: None });
            false
        }
    };
    messages.finish();
    let response = ews_response(out);
    Ok(if created {
        response.with_header(
            SET_COOKIE,
            format!(
                "{AFFINITY_COOKIE}={}; Path=/; Secure; HttpOnly",
                server.core.network.node_id
            ),
        )
    } else {
        response
    })
}

struct Requested<'r, 'a> {
    folders: &'r SubscriptionFolders<'a>,
    events: EventTypes,
    kind: EwsSubscriptionKind,
    watermark: Option<&'r Watermark<'a>>,
    ttl: Duration,
}

async fn create(
    server: &Server,
    ctx: &EwsContext,
    principal: u32,
    requested: Requested<'_, '_>,
) -> trc::Result<Result<Arc<EwsSubscription>, Status<'static>>> {
    let account_id = ctx.account.account_id;
    let snapshot = Snapshot::load(server, ctx).await?;
    let scope = match requested.folders {
        SubscriptionFolders::All => Scope::All,
        SubscriptionFolders::Some(ids) => {
            let mut nodes = SmallVec::with_capacity(ids.len().min(snapshot.tree.len()));
            let mut verified: Option<&str> = None;
            for id in ids {
                let local;
                let selector = match id {
                    BaseFolderId::Distinguished(id) => {
                        if let Some(address) = id
                            .mailbox
                            .as_ref()
                            .and_then(|mailbox| mailbox.email_address.as_deref())
                            .filter(|address| !address.is_empty())
                            && verified.is_none_or(|known| !known.eq_ignore_ascii_case(address))
                        {
                            if server.account_id_from_email(address, false).await?
                                != Some(account_id)
                            {
                                return Ok(Err(Status::error(
                                    ResponseCode::ErrorSubscriptionDelegateAccessNotSupported,
                                    DELEGATE_ACCESS,
                                )));
                            }
                            verified = Some(address);
                        }
                        local = DistinguishedFolderId {
                            name: id.name,
                            change_key: None,
                            mailbox: None,
                        };
                        FolderSelector::Distinguished(&local)
                    }
                    BaseFolderId::Folder(id) => FolderSelector::Id(id),
                };
                match resolve_folder(server, ctx, &snapshot.tree, selector).await? {
                    Ok(entry) => nodes.push(entry.node),
                    Err(status) => return Ok(Err(status)),
                }
            }
            Scope::folders(nodes)
        }
    };
    let subscription = NewSubscription {
        owner: principal,
        id: EwsSubscriptionId {
            kind: requested.kind,
            account: account_id,
            id: rand::random::<u128>(),
        },
        scope,
        events: requested.events,
        mail: mail_allowed(ctx).is_ok(),
        data_types: ctx.account.data_types,
        ttl: requested.ttl,
    };
    let now = now();
    let resumed = match requested.watermark {
        Some(watermark) => match resume(server, principal, watermark, &subscription, now) {
            Ok(resumed) => Some(resumed),
            Err(InvalidWatermark) => return Ok(Err(invalid_watermark())),
        },
        None => None,
    };
    let (cursor, source) = resumed.unzip();
    let cursor = cursor.unwrap_or_else(|| {
        Cursor::baseline(&snapshot.scoped_input(&subscription.scope, subscription.mail, now))
    });
    let (id, ttl) = (subscription.id, subscription.ttl);
    let Ok(subscription) = EwsSubscription::new(
        subscription,
        cursor,
        server.memory_reservation(MemoryClass::Read),
        now,
    ) else {
        return Ok(Err(busy()));
    };
    let subscription = Arc::new(subscription);
    Ok(
        match server.insert_exchange_session(
            account_id,
            id.id,
            subscription.clone(),
            ttl.saturating_add(TOMBSTONE_TTL),
        ) {
            Ok(()) => {
                if let Some(source) = source {
                    server.remove_exchange_session::<EwsTombstone>(account_id, source);
                }
                Ok(subscription)
            }
            Err(ExchangeSessionLimit::Account) => Err(Status::error(
                ResponseCode::ErrorExceededSubscriptionCount,
                TOO_MANY,
            )),
            Err(ExchangeSessionLimit::Node) => Err(busy()),
        },
    )
}

fn resume(
    server: &Server,
    principal: u32,
    watermark: &Watermark<'_>,
    subscription: &NewSubscription,
    now: u64,
) -> Result<(Cursor, u128), InvalidWatermark> {
    let watermark = EwsWatermark::decode(watermark.0.as_ref())
        .filter(|watermark| watermark.account == subscription.id.account)
        .ok_or(InvalidWatermark)?;
    match find(server, watermark.account, watermark.subscription, now) {
        Found::Live(source) | Found::Tombstone(source)
            if source.owner == principal
                && source.scope == subscription.scope
                && source.mail == subscription.mail
                && source.data_types == subscription.data_types =>
        {
            source
                .cursor_at(watermark.seq)
                .map(|cursor| (cursor, watermark.subscription))
                .ok_or(InvalidWatermark)
        }
        Found::Live(_) | Found::Tombstone(_) | Found::Gone => Err(InvalidWatermark),
    }
}

pub(crate) fn busy() -> Status<'static> {
    Status::error(ResponseCode::ErrorServerBusy, BUSY)
}

pub(crate) async fn unsubscribe(
    server: &Server,
    ctx: &EwsContext,
    principal: u32,
    request: &Unsubscribe<'_>,
) -> trc::Result<HttpResponse> {
    let status = match lookup(server, ctx, principal, &request.subscription_id) {
        Ok(subscription) => {
            server.remove_exchange_session::<EwsSubscription>(
                subscription.id.account,
                subscription.id.id,
            );
            bury(server, subscription, now());
            Status::SUCCESS
        }
        Err(err) => err.status(),
    };
    Ok(single(ctx, Operation::Unsubscribe, &status))
}

pub(crate) async fn get_events(
    server: &Server,
    ctx: &EwsContext,
    principal: u32,
    request: &GetEvents<'_>,
) -> trc::Result<HttpResponse> {
    let outcome = match lookup(server, ctx, principal, &request.subscription_id) {
        Ok(subscription) if subscription.is_streaming() => Err(Status::error(
            ResponseCode::ErrorInvalidPullSubscriptionId,
            NOT_PULL,
        )),
        Ok(subscription) => match EwsWatermark::decode(request.watermark.0.as_ref())
            .filter(|watermark| subscription.accepts(watermark))
        {
            Some(watermark) => {
                let mut snapshot = Snapshot::load(server, ctx).await?;
                snapshot
                    .load_logs(
                        server,
                        ctx.account.account_id,
                        slice::from_ref(&subscription),
                    )
                    .await?;
                match subscription.next_batch(
                    &snapshot.input(&subscription, now()),
                    Delivery::Pull {
                        expected: watermark.seq,
                    },
                ) {
                    Ok(Next::Batch(batch) | Next::Replay(batch)) => {
                        Ok(snapshot.notification(&subscription, &batch))
                    }
                    Ok(Next::InvalidWatermark) => Err(invalid_watermark()),
                    Ok(Next::Closed) => Err(Lookup::NotFound.status()),
                    Ok(Next::Empty) | Err(ServerBusy) => Err(busy()),
                }
            }
            None => Err(invalid_watermark()),
        },
        Err(err) => Err(err.status()),
    };
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::GetEvents);
    match outcome {
        Ok(notification) => messages.message(&MessageResult {
            status: Status::SUCCESS,
            body: Some(GetEventsMessage {
                notification: Some(notification),
            }),
        }),
        Err(status) => messages.message(&MessageResult::<GetEventsMessage> { status, body: None }),
    }
    messages.finish();
    Ok(ews_response(out))
}

fn invalid_watermark() -> Status<'static> {
    Status::error(ResponseCode::ErrorInvalidWatermark, INVALID_WATERMARK)
}

fn single(ctx: &EwsContext, op: Operation, status: &Status<'_>) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(op);
    messages.begin_message(status).finish();
    messages.finish();
    ews_response(out)
}
