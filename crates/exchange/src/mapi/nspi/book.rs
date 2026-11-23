/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    page::{
        AbKind, Anchor, Page, RowKey, RowRef, Seek, Strategy, Window, display_name, fold, fraction,
        select, target,
    },
    scan::{
        AbView, Addresses, Detail, DirectoryScan, ScanScope, directory_ref_from_email, visible_key,
        visible_ref,
    },
};
use crate::identity::{DirectoryRef, deployment_guid, directory_dn, legacy_dn};
use ahash::AHashSet;
use common::{
    Server,
    auth::{AccessToken, AccountCache, EmailAddress},
    network::memory::{MemoryClass, MemoryReservation},
};
use exchange_proto::{
    common::Guid,
    ids::entryid::{AddressBookEntryId, EntryId, EphemeralEntryId},
    mapi::nspi::{MinimalId, NspiStatus, tags::DT_MAILUSER},
};
use registry::schema::{enums::ResourceKind, structs::Account};
use std::{borrow::Cow, sync::Arc};
use trc::AddContext;

const SEARCH_KEY_PREFIX: &[u8] = b"EX:";
const PRIMARY_PROXY: &str = "SMTP:";
const SECONDARY_PROXY: &str = "smtp:";
const KEY_BYTES: u64 = size_of::<RowKey>() as u64;
const ADDRESS_ENTRY_OVERHEAD: usize = size_of::<Box<str>>() + 1;

#[derive(Debug)]
pub enum BookError {
    OutOfMemory,
    Store(trc::Error),
}

impl From<trc::Error> for BookError {
    fn from(err: trc::Error) -> Self {
        BookError::Store(err)
    }
}

pub type BookResult<T> = Result<T, BookError>;

#[derive(Debug)]
pub struct AbEntry {
    pub principal: DirectoryRef,
    pub mid: MinimalId,
    pub kind: AbKind,
    pub display_name: Box<str>,
    pub sort_key: Box<str>,
    pub account: Box<str>,
    pub smtp: Box<str>,
    pub proxies: Box<[Box<str>]>,
    pub dn: Box<str>,
    pub permanent_id: Box<[u8]>,
    pub ephemeral_id: Box<[u8]>,
    pub search_key: Box<[u8]>,
    pub instance_key: [u8; 4],
    pub resource: Option<AbResource>,
}

#[derive(Debug)]
pub struct AbResource {
    pub kind: ResourceKind,
    pub details: Option<Box<ResourceDetails>>,
}

#[derive(Debug)]
pub struct ResourceDetails {
    pub capacity: Option<i32>,
    pub location: Option<Box<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDetail {
    Kind,
    Full,
}

impl AbResource {
    pub fn details(&self) -> Option<&ResourceDetails> {
        self.details.as_deref()
    }
}

impl AbEntry {
    pub fn view(&self) -> AbView<'_> {
        AbView {
            principal: self.principal,
            kind: self.kind,
            display_name: &self.display_name,
            account: &self.account,
            smtp: &self.smtp,
            addresses: Addresses::Proxies(&self.proxies),
            dn: Some(&self.dn),
        }
    }

    fn heap_bytes(&self) -> u64 {
        let texts = self.display_name.len()
            + self.sort_key.len()
            + self.account.len()
            + self.smtp.len()
            + self.dn.len()
            + self.permanent_id.len()
            + self.ephemeral_id.len()
            + self.search_key.len()
            + self.proxies.len() * size_of::<Box<str>>()
            + self.proxies.iter().map(|proxy| proxy.len()).sum::<usize>()
            + self
                .resource
                .as_ref()
                .and_then(AbResource::details)
                .map_or(0, |details| {
                    size_of::<ResourceDetails>()
                        + details
                            .location
                            .as_ref()
                            .map_or(0, |location| location.len())
                });
        u64::try_from(size_of::<(DirectoryRef, u32)>() + texts).unwrap_or(u64::MAX)
    }
}

pub struct Book<'x> {
    server: &'x Server,
    access_token: &'x AccessToken,
    server_guid: Guid,
    memory: MemoryReservation,
    charged: u64,
    scope: ScanScope,
    resource_detail: ResourceDetail,
}

#[derive(Debug, Default)]
pub struct Matches {
    pub rows: Vec<RowKey>,
    pub truncated: bool,
}

#[derive(Debug, Default)]
pub struct Members {
    pub rows: Vec<RowKey>,
    pub truncated: bool,
    recipients: Arc<[Box<str>]>,
    external: Vec<usize>,
}

impl Members {
    pub fn external(&self) -> impl Iterator<Item = &str> {
        self.external
            .iter()
            .filter_map(|index| self.recipients.get(*index))
            .map(AsRef::as_ref)
    }
}

impl<'x> Book<'x> {
    pub fn new(server: &'x Server, access_token: &'x AccessToken) -> Self {
        Book {
            server,
            access_token,
            server_guid: deployment_guid(&server.core.network.server_name),
            memory: server.memory_reservation(MemoryClass::Read),
            charged: 0,
            scope: ScanScope::All,
            resource_detail: ResourceDetail::Kind,
        }
    }

    pub fn with_scope(mut self, scope: ScanScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn set_scope(&mut self, scope: ScanScope) {
        self.scope = scope;
    }

    pub fn set_resource_detail(&mut self, detail: ResourceDetail) {
        self.resource_detail = detail;
    }

    pub fn server(&self) -> &'x Server {
        self.server
    }

    fn charge(&mut self, bytes: u64) -> BookResult<()> {
        let total = self.charged.saturating_add(bytes);
        if self.memory.reserve_to(total) {
            self.charged = total;
            Ok(())
        } else {
            Err(BookError::OutOfMemory)
        }
    }

    fn charge_keys(&mut self, keys: usize) -> BookResult<()> {
        self.charge(
            u64::try_from(keys)
                .unwrap_or(u64::MAX)
                .saturating_mul(KEY_BYTES),
        )
    }

    fn charge_accounts<'k>(&mut self, keys: impl Iterator<Item = &'k RowKey>) -> BookResult<()> {
        self.charge(keys.map(RowKey::weight).sum())
    }

    pub async fn keys_of(
        &mut self,
        mids: impl Iterator<Item = MinimalId>,
    ) -> BookResult<Vec<Option<RowKey>>> {
        let mut keys = Vec::with_capacity(mids.size_hint().0);
        for mid in mids {
            let key = self.key_of(mid).await?;
            if let Some(key) = &key {
                self.charge(KEY_BYTES.saturating_add(key.weight()))?;
            }
            keys.push(key);
        }
        Ok(keys)
    }

    pub async fn scan(&self) -> trc::Result<DirectoryScan> {
        DirectoryScan::open(self.server, self.access_token, self.scope).await
    }

    pub async fn key(&self, account_id: u32) -> trc::Result<Option<RowKey>> {
        visible_key(self.server, self.access_token, account_id).await
    }

    pub async fn principal_key(&self, principal: DirectoryRef) -> trc::Result<Option<RowKey>> {
        visible_ref(self.server, self.access_token, principal).await
    }

    pub async fn key_of(&self, mid: MinimalId) -> trc::Result<Option<RowKey>> {
        match mid.principal() {
            Some((MinimalId::KIND_ADDRESS, account_id)) => self.key(account_id).await,
            Some((MinimalId::KIND_LIST, list_id)) => {
                self.principal_key(DirectoryRef::List(list_id)).await
            }
            _ => Ok(None),
        }
    }

    pub async fn members(&mut self, key: &RowKey, limit: usize) -> BookResult<Members> {
        let RowRef::List(list) = key.subject() else {
            return Ok(Members::default());
        };
        let recipients = list.recipients.clone();
        let capacity = limit.saturating_add(1).min(recipients.len());
        self.charge_keys(capacity)?;
        let mut members = Members {
            rows: Vec::with_capacity(capacity),
            external: Vec::new(),
            recipients: recipients.clone(),
            truncated: false,
        };
        let mut seen = AHashSet::with_capacity(capacity);
        for (index, recipient) in recipients.iter().enumerate() {
            let member = match directory_ref_from_email(self.server, recipient).await? {
                Some(principal) => self.principal_key(principal).await?,
                None => {
                    members.external.push(index);
                    continue;
                }
            };
            let Some(member) = member.filter(|member| seen.insert(member.mid())) else {
                continue;
            };
            if members.rows.len() == limit {
                members.truncated = true;
                break;
            }
            self.charge(member.weight())?;
            members.rows.push(member);
        }
        members.rows.sort_unstable();
        Ok(members)
    }

    pub async fn entry(&mut self, key: &RowKey) -> BookResult<Option<AbEntry>> {
        let entry = entry(self.server, &self.server_guid, key, self.resource_detail).await?;
        if let Some(entry) = &entry {
            self.charge(entry.heap_bytes())?;
        }
        Ok(entry)
    }

    pub fn entries<'k>(
        &mut self,
        keys: impl IntoIterator<Item = Option<&'k RowKey>>,
    ) -> impl Future<Output = BookResult<Vec<Option<AbEntry>>>> {
        self.entries_of(keys.into_iter().collect())
    }

    async fn entries_of(&mut self, keys: Vec<Option<&RowKey>>) -> BookResult<Vec<Option<AbEntry>>> {
        let mut entries = Vec::with_capacity(keys.len());
        for key in keys {
            entries.push(match key {
                Some(key) => self.entry(key).await?,
                None => None,
            });
        }
        Ok(entries)
    }

    pub async fn page(&mut self, seek: Seek, delta: i32, count: usize) -> BookResult<Page> {
        let mut scan = self.scan().await?;
        match (seek.strategy(delta, count), &seek) {
            (Strategy::Window { back, forward }, Seek::At(anchor)) => {
                self.charge_keys(back.saturating_add(forward))?;
                let mut window = Window::new(anchor, back, forward);
                while let Some(key) = scan.next(self.server, Detail::Key).await? {
                    window.push(key);
                }
                self.charge_accounts(window.kept())?;
                Ok(window.finish(delta, count))
            }
            _ => {
                self.charge_keys(scan.remaining())?;
                let mut keys = Vec::with_capacity(scan.remaining());
                let mut below = 0;
                while let Some(key) = scan.next(self.server, Detail::Key).await? {
                    if let Seek::At(anchor) = &seek
                        && anchor.is_below(&key)
                    {
                        below += 1;
                    }
                    self.charge(key.weight())?;
                    keys.push(key);
                }
                let anchor = match seek {
                    Seek::At(_) => below,
                    Seek::Fraction {
                        num_pos,
                        total_recs,
                    } => fraction(keys.len(), num_pos, total_recs),
                };
                let start = target(anchor, delta, keys.len());
                Ok(select(keys, start, count, anchor))
            }
        }
    }

    pub async fn matches(
        &mut self,
        detail: Detail,
        limit: usize,
        mut filter: impl FnMut(&RowKey, &AbView<'_>) -> bool,
    ) -> BookResult<Matches> {
        let mut scan = self.scan().await?;
        let capacity = limit.saturating_add(1).min(scan.remaining());
        self.charge_keys(capacity)?;
        let mut rows = Vec::with_capacity(capacity);
        let mut truncated = false;
        while let Some(key) = scan.next(self.server, detail).await? {
            if filter(&key, &scan.view(&key)) {
                if rows.len() == limit {
                    truncated = true;
                    break;
                }
                self.charge(key.weight())?;
                rows.push(key);
            }
        }
        rows.sort_unstable();
        Ok(Matches { rows, truncated })
    }

    pub async fn addresses(&mut self) -> BookResult<AHashSet<Box<str>>> {
        let mut scan = self.scan().await?;
        let mut addresses = AHashSet::new();
        while let Some(key) = scan.next(self.server, Detail::Addresses).await? {
            for address in scan.view(&key).addresses() {
                self.charge(
                    u64::try_from(address.len() + ADDRESS_ENTRY_OVERHEAD).unwrap_or(u64::MAX),
                )?;
                addresses.insert(address.to_ascii_lowercase().into_boxed_str());
            }
        }
        Ok(addresses)
    }

    pub async fn window(
        &mut self,
        detail: Detail,
        first: usize,
        count: usize,
        mut filter: impl FnMut(&RowKey, &AbView<'_>) -> bool,
    ) -> BookResult<Page> {
        let mut scan = self.scan().await?;
        let forward = first.saturating_add(count);
        self.charge_keys(forward.min(scan.remaining()))?;
        let mut window = Window::new(&Anchor::Start, 0, forward);
        while let Some(key) = scan.next(self.server, detail).await? {
            if filter(&key, &scan.view(&key)) {
                window.push(key);
            }
        }
        self.charge_accounts(window.kept())?;
        Ok(window.finish(i32::try_from(first).unwrap_or(i32::MAX), count))
    }
}

#[derive(Debug, Default)]
pub struct AddressBook {
    pub entries: Vec<AbEntry>,
    memory: Option<MemoryReservation>,
}

impl AddressBook {
    pub async fn build(
        server: &Server,
        access_token: &AccessToken,
    ) -> trc::Result<Result<AddressBook, NspiStatus>> {
        match AddressBook::collect(server, access_token).await {
            Ok(book) => Ok(Ok(book)),
            Err(BookError::OutOfMemory) => Ok(Err(NspiStatus::OUT_OF_RESOURCES)),
            Err(BookError::Store(err)) => Err(err),
        }
    }

    async fn collect(server: &Server, access_token: &AccessToken) -> BookResult<AddressBook> {
        let mut book = Book::new(server, access_token);
        book.set_resource_detail(ResourceDetail::Full);
        let mut scan = book.scan().await?;
        book.charge(
            u64::try_from(scan.remaining().saturating_mul(size_of::<AbEntry>()))
                .unwrap_or(u64::MAX),
        )?;
        let mut entries = Vec::with_capacity(scan.remaining());
        while let Some(key) = scan.next(server, Detail::Key).await? {
            if let Some(entry) = book.entry(&key).await? {
                entries.push(entry);
            }
        }
        let mut collected = AddressBook::from_entries(entries);
        collected.memory = Some(book.memory);
        Ok(collected)
    }

    pub fn from_entries(mut entries: Vec<AbEntry>) -> Self {
        entries.sort_unstable_by(|a, b| a.sort_key.cmp(&b.sort_key).then(a.mid.cmp(&b.mid)));
        AddressBook {
            entries,
            memory: None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub async fn principal_entry(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<Option<AbEntry>> {
    directory_entry(server, access_token, DirectoryRef::Account(account_id)).await
}

pub async fn directory_entry(
    server: &Server,
    access_token: &AccessToken,
    principal: DirectoryRef,
) -> trc::Result<Option<AbEntry>> {
    let Some(key) = visible_ref(server, access_token, principal).await? else {
        return Ok(None);
    };
    entry(
        server,
        &deployment_guid(&server.core.network.server_name),
        &key,
        ResourceDetail::Kind,
    )
    .await
}

pub struct AclMember {
    account: Arc<AccountCache>,
    pub permanent_id: Vec<u8>,
}

impl AclMember {
    pub fn display_name(&self) -> &str {
        display_name(&self.account)
    }
}

pub async fn acl_member(server: &Server, account_id: u32) -> trc::Result<Option<AclMember>> {
    let Some(account) = server.try_account(account_id).await? else {
        return Ok(None);
    };
    let tail = account
        .addresses
        .first()
        .map_or(account.name(), |address| address.local_part.as_str());
    let Some(dn) = legacy_dn(account_id, tail) else {
        return Ok(None);
    };
    let mut permanent_id = Vec::with_capacity(32 + dn.as_str().len());
    let encoded = EntryId::AddressBook(AddressBookEntryId {
        flags: 0,
        display_type: DT_MAILUSER,
        dn: Cow::Borrowed(dn.as_str().as_bytes()),
    })
    .encode(&mut permanent_id);
    Ok(encoded.is_ok().then_some(AclMember {
        account,
        permanent_id,
    }))
}

pub(crate) async fn entry(
    server: &Server,
    server_guid: &Guid,
    key: &RowKey,
    detail: ResourceDetail,
) -> trc::Result<Option<AbEntry>> {
    let subject = key.subject();
    let addresses: &[EmailAddress] = match subject {
        RowRef::Account(account) => &account.addresses,
        RowRef::List(list) => &list.addresses,
    };
    let mid = key.mid();
    let principal = key.principal();
    let kind = subject.kind();
    let mut proxies = Vec::with_capacity(addresses.len());
    for address in addresses {
        let Some(domain) = server.domain_by_id(address.domain_id).await? else {
            continue;
        };
        for name in domain.names.iter() {
            let prefix = if proxies.is_empty() {
                PRIMARY_PROXY
            } else {
                SECONDARY_PROXY
            };
            let mut proxy =
                String::with_capacity(prefix.len() + address.local_part.len() + 1 + name.len());
            proxy.push_str(prefix);
            proxy.push_str(&address.local_part);
            proxy.push('@');
            proxy.push_str(name);
            proxies.push(proxy.into_boxed_str());
        }
    }
    let Some(smtp) = proxies
        .first()
        .and_then(|proxy| proxy.strip_prefix(PRIMARY_PROXY))
        .map(Box::<str>::from)
    else {
        return Ok(None);
    };
    let Some(dn) = directory_dn(principal, &smtp) else {
        return Ok(None);
    };
    let display_type = kind.display_type();
    let display_name: Box<str> = subject.display_name().into();
    let mut permanent_id = Vec::with_capacity(32 + dn.as_str().len());
    let mut ephemeral_id = Vec::with_capacity(32);
    let encoded = EntryId::AddressBook(AddressBookEntryId {
        flags: 0,
        display_type,
        dn: Cow::Borrowed(dn.as_str().as_bytes()),
    })
    .encode(&mut permanent_id)
    .and_then(|_| {
        EntryId::Ephemeral(EphemeralEntryId {
            server: *server_guid,
            display_type,
            mid,
        })
        .encode(&mut ephemeral_id)
    });
    if encoded.is_err() {
        return Ok(None);
    }
    let resource = match subject {
        RowRef::Account(account) => load_resource(server, account, detail).await?,
        RowRef::List(_) => None,
    };
    let mut search_key = Vec::with_capacity(SEARCH_KEY_PREFIX.len() + dn.as_str().len() + 1);
    search_key.extend_from_slice(SEARCH_KEY_PREFIX);
    search_key.extend(dn.as_str().bytes().map(|b| b.to_ascii_uppercase()));
    search_key.push(0);
    Ok(Some(AbEntry {
        principal,
        mid,
        kind,
        sort_key: fold(&display_name).into_boxed_str(),
        display_name,
        account: subject.account_name().into(),
        smtp,
        proxies: proxies.into_boxed_slice(),
        dn: dn.as_str().into(),
        permanent_id: permanent_id.into_boxed_slice(),
        ephemeral_id: ephemeral_id.into_boxed_slice(),
        search_key: search_key.into_boxed_slice(),
        instance_key: mid.0.to_le_bytes(),
        resource,
    }))
}

async fn load_resource(
    server: &Server,
    account: &AccountCache,
    detail: ResourceDetail,
) -> trc::Result<Option<AbResource>> {
    let Some(kind) = account.resource_kind() else {
        return Ok(None);
    };
    let details = match detail {
        ResourceDetail::Kind => None,
        ResourceDetail::Full => match server
            .registry()
            .object::<Account>(account.account_id().into())
            .await
            .caused_by(trc::location!())?
        {
            Some(Account::Resource(resource)) => Some(Box::new(ResourceDetails {
                capacity: resource
                    .capacity
                    .map(|capacity| i32::try_from(capacity).unwrap_or(i32::MAX)),
                location: resource.location.map(String::into_boxed_str),
            })),
            _ => None,
        },
    };
    Ok(Some(AbResource { kind, details }))
}
