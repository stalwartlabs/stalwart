/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{
    Inner, MailboxCache, MailboxesCache, MessageStoreCache, Server,
    auth::AccessToken,
    cache::email::MessageRef,
    config::mailstore::email::DefaultFolder,
    network::{ServerInstance, SessionStream, limiter::InFlight},
};
use email::cache::MessageCacheFetch;
use imap_proto::{
    Command,
    protocol::{MailboxObjectId, ObjectId, ProtocolVersion, id::ClientId, list::Attribute},
    receiver::Receiver,
};
use std::{
    net::IpAddr,
    sync::{Arc, atomic::AtomicU32},
};
use store::roaring::RoaringBitmap;
use tokio::{
    io::{ReadHalf, WriteHalf},
    sync::{Semaphore, watch},
};
use trc::AddContext;
use types::{keyword::Keyword, special_use::SpecialUse};

pub mod client;
pub mod mailbox;
pub mod rights;
pub mod session;
pub mod view;

pub use view::{ItemChanges, MailboxView, Resolved, Row};

#[derive(Clone)]
pub struct ImapSessionManager {
    pub inner: Arc<Inner>,
}

impl ImapSessionManager {
    pub fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }
}

pub const MAX_CONCURRENT_OPS: u32 = 5;

pub struct Session<T: SessionStream> {
    pub server: Server,
    pub op_semaphore: Arc<Semaphore>,
    pub instance: Arc<ServerInstance>,
    pub receiver: Receiver<Command>,
    pub version: ProtocolVersion,
    pub state: State<T>,
    pub is_tls: bool,
    pub is_condstore: bool,
    pub is_qresync: bool,
    pub is_utf8: bool,
    pub is_objectid: bool,
    pub is_uidonly: bool,
    pub client: ClientId,
    pub stream_rx: ReadHalf<T>,
    pub stream_tx: Arc<tokio::sync::Mutex<WriteHalf<T>>>,
    pub in_flight: InFlight,
    pub remote_addr: IpAddr,
    pub session_id: u64,
}

pub struct SessionData<T: SessionStream> {
    pub account_id: u32,
    pub access_token: AccessToken,
    pub server: Server,
    pub session_id: u64,
    pub mailboxes: parking_lot::Mutex<Vec<AccountView>>,
    pub stream_tx: Arc<tokio::sync::Mutex<WriteHalf<T>>>,
    pub state: AtomicU32,
    pub remote_addr: IpAddr,
    pub in_flight: Option<InFlight>,
}

pub struct SelectedMailbox {
    pub id: MailboxId,
    pub view: parking_lot::Mutex<MailboxView>,
    pub saved_search: parking_lot::Mutex<SavedSearch>,
    pub is_select: bool,
    pub is_condstore: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct MailboxId {
    pub account_id: u32,
    pub mailbox_id: u32,
}

pub struct AccountView {
    pub account_id: u32,
    pub prefix: Option<String>,
    pub mailboxes: Arc<MailboxesCache>,
    pub source: MailboxSource,
    pub visible: Option<RoaringBitmap>,
    pub names: Vec<MailboxName>,
    pub parents: RoaringBitmap,
    pub counters: Option<MailboxCounters>,
    pub previous_counters: Option<Vec<Counters>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxSource {
    Messages,
    Folders { change_id: u64, verified_at: u64 },
}

#[derive(Debug, Clone)]
pub struct MailboxName {
    pub name: String,
    pub mailbox_id: u32,
    pub is_alias: bool,
}

const _: () = assert!(size_of::<MailboxName>() <= 32);

#[derive(Debug)]
pub struct MailboxChange {
    pub account_id: u32,
    pub name: String,
    pub objectid: MailboxObjectId,
}

impl MailboxName {
    pub fn object_id(&self, account_id: u32) -> MailboxObjectId {
        if self.is_alias {
            MailboxObjectId::Empty
        } else {
            MailboxObjectId::Mailbox {
                account_id,
                mailbox_id: self.mailbox_id,
            }
        }
    }

    pub fn to_change(&self, account_id: u32) -> MailboxChange {
        MailboxChange {
            account_id,
            name: self.name.clone(),
            objectid: self.object_id(account_id),
        }
    }

    pub fn into_change(self, account_id: u32) -> MailboxChange {
        MailboxChange {
            account_id,
            objectid: self.object_id(account_id),
            name: self.name,
        }
    }
}

impl From<MailboxId> for MailboxObjectId {
    fn from(mailbox: MailboxId) -> Self {
        MailboxObjectId::Mailbox {
            account_id: mailbox.account_id,
            mailbox_id: mailbox.mailbox_id,
        }
    }
}

impl From<MailboxId> for ObjectId {
    fn from(mailbox: MailboxId) -> Self {
        MailboxObjectId::from(mailbox).into()
    }
}

#[derive(Debug, Clone)]
pub struct MailboxCounters {
    pub change_id: u64,
    pub by_mailbox: Vec<Counters>,
}

#[derive(Debug, Clone, Copy)]
pub struct CounterDelta {
    pub mailbox_id: u32,
    pub size: u32,
    pub is_unseen: bool,
    pub is_deleted: bool,
    pub add: bool,
}

#[derive(Clone, Copy)]
pub struct KeywordBits {
    seen: u32,
    deleted: u32,
}

#[derive(Default)]
pub struct AccountCaches(Vec<(u32, Arc<MessageStoreCache>)>);

pub struct MailboxRefresh {
    pub changes: Option<MailboxSync>,
    pub caches: AccountCaches,
    pub access_token: AccessToken,
}

pub enum SelectedAccess {
    Readable {
        access_token: AccessToken,
        cache: Arc<MessageStoreCache>,
    },
    Revoked,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub total: u32,
    pub unseen: u32,
    pub deleted: u32,
    pub size: u64,
    pub deleted_size: u64,
}

#[derive(Debug, Default)]
pub struct MailboxSync {
    pub added: Vec<MailboxChange>,
    pub changed: Vec<String>,
    pub deleted: Vec<MailboxChange>,
}

pub enum SavedSearch {
    InFlight { rx: watch::Receiver<Arc<Vec<Row>>> },
    Results { items: Arc<Vec<Row>> },
    None,
}

pub enum State<T: SessionStream> {
    NotAuthenticated {
        auth_failures: u32,
        sasl_failure: Option<trc::Error>,
    },
    Authenticated {
        data: Arc<SessionData<T>>,
    },
    Selected {
        data: Arc<SessionData<T>>,
        mailbox: Arc<SelectedMailbox>,
    },
}

impl<T: SessionStream> State<T> {
    pub fn try_replace_stream_tx<U: SessionStream>(
        self,
        new_stream: Arc<tokio::sync::Mutex<WriteHalf<U>>>,
    ) -> Option<State<U>> {
        match self {
            State::NotAuthenticated { auth_failures, .. } => State::NotAuthenticated {
                auth_failures,
                sasl_failure: None,
            }
            .into(),
            State::Authenticated { data } => {
                Arc::try_unwrap(data).ok().map(|data| State::Authenticated {
                    data: Arc::new(data.replace_stream_tx(new_stream)),
                })
            }
            State::Selected { data, mailbox } => {
                Arc::try_unwrap(data).ok().map(|data| State::Selected {
                    data: Arc::new(data.replace_stream_tx(new_stream)),
                    mailbox,
                })
            }
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn refresh_access_token(&self) -> trc::Result<AccessToken> {
        self.server
            .renew_access_token(&self.access_token, self.remote_addr)
            .await
            .caused_by(trc::location!())
    }

    pub fn replace_stream_tx<U: SessionStream>(
        self,
        new_stream: Arc<tokio::sync::Mutex<WriteHalf<U>>>,
    ) -> SessionData<U> {
        SessionData {
            account_id: self.account_id,
            server: self.server,
            session_id: self.session_id,
            mailboxes: self.mailboxes,
            stream_tx: new_stream,
            state: self.state,
            in_flight: self.in_flight,
            access_token: self.access_token,
            remote_addr: self.remote_addr,
        }
    }
}

impl AccountView {
    pub fn mailbox(&self, mailbox_id: u32) -> Option<&MailboxCache> {
        self.mailboxes
            .index
            .get(&mailbox_id)
            .and_then(|idx| self.mailboxes.items.get(*idx as usize))
    }

    pub fn is_visible(&self, mailbox_id: u32) -> bool {
        self.visible
            .as_ref()
            .is_none_or(|visible| visible.contains(mailbox_id))
    }

    pub fn has_children(&self, mailbox_id: u32) -> bool {
        self.parents.contains(mailbox_id)
    }

    pub fn entry_by_name(&self, name: &str) -> Option<&MailboxName> {
        self.names
            .binary_search_by(|entry| entry.name.as_str().cmp(name))
            .ok()
            .and_then(|idx| self.names.get(idx))
    }

    pub fn id_by_name(&self, name: &str) -> Option<u32> {
        self.entry_by_name(name).map(|entry| entry.mailbox_id)
    }

    pub fn alias_target(&self, default_folders: &[DefaultFolder], name: &str) -> Option<u32> {
        let role = AccountView::default_folder_role(default_folders, name)
            .filter(|role| !matches!(role, SpecialUse::None))?;
        self.mailboxes
            .items
            .iter()
            .find(|mailbox| mailbox.role == role && self.is_visible(mailbox.document_id))
            .map(|mailbox| mailbox.document_id)
    }

    pub fn default_folder_role(
        default_folders: &[DefaultFolder],
        name: &str,
    ) -> Option<SpecialUse> {
        default_folders
            .iter()
            .find(|folder| folder.name == name || folder.aliases.iter().any(|alias| alias == name))
            .map(|folder| folder.special_use)
    }

    pub fn has_mailbox_id(&self, mailbox_id: u32) -> bool {
        self.names
            .iter()
            .any(|entry| entry.mailbox_id == mailbox_id)
    }

    pub fn holds_name(&self, mailbox_name: &str) -> bool {
        self.prefix
            .as_deref()
            .and_then(|prefix| mailbox_name.strip_prefix(prefix))
            .and_then(|rest| rest.strip_prefix('/'))
            .is_some_and(|folder| !folder.is_empty())
    }

    pub fn expire_folders(&mut self) {
        if let MailboxSource::Folders { verified_at, .. } = &mut self.source {
            *verified_at = 0;
        }
    }

    pub fn is_subscribed(&self, mailbox_id: u32, subscriber: u32) -> bool {
        self.mailbox(mailbox_id)
            .is_some_and(|mailbox| mailbox.subscribers.contains(&subscriber))
    }

    pub fn special_use(&self, mailbox_id: u32) -> Option<Attribute> {
        self.mailbox(mailbox_id)
            .and_then(|mailbox| Self::special_use_attribute(&mailbox.role))
    }

    pub fn uid_validity(&self, mailbox_id: u32) -> u32 {
        self.mailbox(mailbox_id)
            .map_or(0, |mailbox| mailbox.uid_validity)
    }

    pub fn special_use_attribute(role: &SpecialUse) -> Option<Attribute> {
        match role {
            SpecialUse::Trash => Some(Attribute::Trash),
            SpecialUse::Junk => Some(Attribute::Junk),
            SpecialUse::Drafts => Some(Attribute::Drafts),
            SpecialUse::Archive => Some(Attribute::Archive),
            SpecialUse::Sent => Some(Attribute::Sent),
            SpecialUse::Important => Some(Attribute::Important),
            SpecialUse::Memos => Some(Attribute::Memos),
            SpecialUse::Scheduled => Some(Attribute::Scheduled),
            SpecialUse::Snoozed => Some(Attribute::Snoozed),
            _ => None,
        }
    }

    pub fn counters_of(&self, mailbox_id: u32) -> Counters {
        self.counters
            .as_ref()
            .map_or_else(Counters::default, |counters| counters.get(mailbox_id))
    }
}

impl MailboxCounters {
    pub fn compute(cache: &MessageStoreCache) -> Self {
        let slots = cache
            .mailboxes
            .items
            .iter()
            .map(|mailbox| mailbox.document_id as usize + 1)
            .max()
            .unwrap_or(0);
        let mut counters = MailboxCounters {
            change_id: cache.emails.change_id,
            by_mailbox: vec![Counters::default(); slots],
        };
        let bits = KeywordBits::new();
        for message in cache.emails.iter() {
            counters.adjust(message, bits, true);
        }
        counters
    }

    pub fn apply_deltas(&mut self, deltas: &[CounterDelta], change_id: u64) {
        for delta in deltas {
            let slot = delta.mailbox_id as usize;
            if slot >= self.by_mailbox.len() {
                if delta.add {
                    self.by_mailbox.resize(slot + 1, Counters::default());
                } else {
                    continue;
                }
            }
            if let Some(counters) = self.by_mailbox.get_mut(slot) {
                counters.apply(
                    delta.add,
                    delta.is_unseen,
                    delta.is_deleted,
                    delta.size as u64,
                );
            }
        }
        self.change_id = change_id;
    }

    fn adjust(&mut self, message: MessageRef<'_>, bits: KeywordBits, add: bool) {
        let keywords = message.keywords();
        let is_unseen = keywords & bits.seen == 0;
        let is_deleted = keywords & bits.deleted != 0;
        let size = message.size() as u64;

        for membership in message.mailboxes() {
            if let Some(counters) = self.by_mailbox.get_mut(membership.mailbox_id as usize) {
                counters.apply(add, is_unseen, is_deleted, size);
            }
        }
    }

    pub fn get(&self, mailbox_id: u32) -> Counters {
        self.by_mailbox
            .get(mailbox_id as usize)
            .copied()
            .unwrap_or_default()
    }
}

impl KeywordBits {
    pub fn new() -> Self {
        KeywordBits {
            seen: Keyword::Seen.id().map_or(0, |id| 1u32 << id),
            deleted: Keyword::Deleted.id().map_or(0, |id| 1u32 << id),
        }
    }
}

impl Default for KeywordBits {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterDelta {
    pub fn push_for(
        message: MessageRef<'_>,
        bits: KeywordBits,
        add: bool,
        out: &mut Vec<CounterDelta>,
    ) {
        let keywords = message.keywords();
        let is_unseen = keywords & bits.seen == 0;
        let is_deleted = keywords & bits.deleted != 0;
        let size = message.size();
        out.extend(message.mailboxes().iter().map(|membership| CounterDelta {
            mailbox_id: membership.mailbox_id,
            size,
            is_unseen,
            is_deleted,
            add,
        }));
    }
}

impl Counters {
    fn apply(&mut self, add: bool, is_unseen: bool, is_deleted: bool, size: u64) {
        if add {
            self.total += 1;
            self.size += size;
            if is_unseen {
                self.unseen += 1;
            }
            if is_deleted {
                self.deleted += 1;
                self.deleted_size += size;
            }
        } else {
            self.total = self.total.saturating_sub(1);
            self.size = self.size.saturating_sub(size);
            if is_unseen {
                self.unseen = self.unseen.saturating_sub(1);
            }
            if is_deleted {
                self.deleted = self.deleted.saturating_sub(1);
                self.deleted_size = self.deleted_size.saturating_sub(size);
            }
        }
    }
}

impl AccountCaches {
    pub fn with(account_id: u32, cache: Arc<MessageStoreCache>) -> Self {
        AccountCaches(vec![(account_id, cache)])
    }

    pub async fn fetch(
        &mut self,
        server: &Server,
        account_id: u32,
    ) -> trc::Result<Arc<MessageStoreCache>> {
        if let Some((_, cache)) = self.0.iter().find(|(id, _)| *id == account_id) {
            return Ok(cache.clone());
        }
        let cache = server
            .get_cached_messages(account_id)
            .await
            .caused_by(trc::location!())?;
        self.0.push((account_id, cache.clone()));
        Ok(cache)
    }
}
