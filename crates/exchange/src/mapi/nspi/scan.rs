/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::page::{AbKind, DirectoryList, RowKey};
use crate::identity::{DirectoryRef, directory_dn};
use common::{
    Server,
    auth::{AccessToken, EmailAddress, EmailCache},
};
use registry::{
    schema::{
        enums::ResourceKind,
        prelude::{ObjectType, Permission, Property},
        structs::MailingList,
    },
    types::EnumImpl,
};
use std::{
    borrow::Cow,
    iter::{Take, once},
    sync::Arc,
};
use store::{
    registry::RegistryQuery,
    roaring::{RoaringBitmap, bitmap::IntoIter},
};
use trc::{AddContext, LimitEvent};

pub const MAX_BOOK_ENTRIES: usize = 100_000;
const ADDRESS_SEPARATOR: char = '\n';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    Key,
    Addresses,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanScope {
    All,
    Accounts,
    Lists,
    Rooms,
}

impl ScanScope {
    fn accounts(self) -> Option<RegistryQuery> {
        let query = RegistryQuery::new(ObjectType::Account);
        match self {
            ScanScope::All | ScanScope::Accounts => Some(query),
            ScanScope::Rooms => Some(query.equal(Property::Kind, ResourceKind::Room.to_id())),
            ScanScope::Lists => None,
        }
    }

    fn lists(self) -> bool {
        matches!(self, ScanScope::All | ScanScope::Lists)
    }
}

pub struct DirectoryScan {
    accounts: IntoIter,
    lists: Take<IntoIter>,
    remaining: usize,
    #[cfg(feature = "enterprise")]
    tenant_id: Option<u32>,
    addresses: String,
}

impl DirectoryScan {
    pub async fn open(
        server: &Server,
        access_token: &AccessToken,
        scope: ScanScope,
    ) -> trc::Result<Self> {
        let (accounts, lists) = if directory_visible(server, access_token) {
            let accounts = match scope.accounts() {
                Some(accounts) => query(server, access_token, accounts).await?,
                None => RoaringBitmap::new(),
            };
            let lists = if scope.lists() && accounts.len() < MAX_BOOK_ENTRIES as u64 {
                query(
                    server,
                    access_token,
                    RegistryQuery::new(ObjectType::MailingList),
                )
                .await?
            } else {
                RoaringBitmap::new()
            };
            (accounts, lists)
        } else {
            let ids = access_token.all_ids().take(MAX_BOOK_ENTRIES);
            let accounts = match scope {
                ScanScope::All | ScanScope::Accounts => ids.collect::<RoaringBitmap>(),
                ScanScope::Rooms => {
                    let mut rooms = RoaringBitmap::new();
                    for account_id in ids {
                        if server
                            .try_account(account_id)
                            .await?
                            .is_some_and(|account| {
                                account.resource_kind() == Some(ResourceKind::Room)
                            })
                        {
                            rooms.insert(account_id);
                        }
                    }
                    rooms
                }
                ScanScope::Lists => RoaringBitmap::new(),
            };
            (accounts, RoaringBitmap::new())
        };
        let accounts_len = usize::try_from(accounts.len()).unwrap_or(MAX_BOOK_ENTRIES);
        let lists_budget = MAX_BOOK_ENTRIES.saturating_sub(accounts_len);
        let lists_len = usize::try_from(lists.len())
            .unwrap_or(usize::MAX)
            .min(lists_budget);
        let remaining = accounts_len.saturating_add(lists_len);
        if remaining >= MAX_BOOK_ENTRIES {
            trc::event!(
                Limit(LimitEvent::SizeRequest),
                AccountId = access_token.account_id(),
                Limit = MAX_BOOK_ENTRIES,
                Details = "Address book scan truncated",
            );
        }
        Ok(DirectoryScan {
            remaining,
            accounts: accounts.into_iter(),
            lists: lists.into_iter().take(lists_budget),
            #[cfg(feature = "enterprise")]
            tenant_id: access_token.tenant_id(),
            addresses: String::new(),
        })
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }

    pub async fn next(&mut self, server: &Server, detail: Detail) -> trc::Result<Option<RowKey>> {
        for id in self.accounts.by_ref() {
            self.remaining = self.remaining.saturating_sub(1);
            let Some(account) = server.try_account(id).await? else {
                continue;
            };
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            if self
                .tenant_id
                .is_some_and(|tenant_id| account.tenant_id() != Some(tenant_id))
            {
                continue;
            }
            // SPDX-SnippetEnd
            if !addresses(server, &account.addresses, detail, &mut self.addresses).await? {
                continue;
            }
            if let Some(key) = RowKey::new(account) {
                return Ok(Some(key));
            }
        }
        for id in self.lists.by_ref() {
            self.remaining = self.remaining.saturating_sub(1);
            let Some((list, _list_tenant)) = load_list(server, id).await? else {
                continue;
            };
            // SPDX-SnippetBegin
            // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
            // SPDX-License-Identifier: LicenseRef-SEL
            #[cfg(feature = "enterprise")]
            if self
                .tenant_id
                .is_some_and(|tenant_id| _list_tenant != Some(tenant_id))
            {
                continue;
            }
            // SPDX-SnippetEnd
            if !addresses(server, &list.addresses, detail, &mut self.addresses).await? {
                continue;
            }
            if let Some(key) = RowKey::list(id, list) {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    pub fn view<'a>(&'a self, key: &'a RowKey) -> AbView<'a> {
        let subject = key.subject();
        AbView {
            principal: key.principal(),
            kind: subject.kind(),
            display_name: subject.display_name(),
            account: subject.account_name(),
            smtp: self
                .addresses
                .split(ADDRESS_SEPARATOR)
                .next()
                .unwrap_or_default(),
            addresses: Addresses::Lines(&self.addresses),
            dn: None,
        }
    }
}

async fn query(
    server: &Server,
    access_token: &AccessToken,
    query: RegistryQuery,
) -> trc::Result<RoaringBitmap> {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let query = query.with_tenant(access_token.tenant_id());
    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    let _ = access_token;
    server
        .registry()
        .query::<RoaringBitmap>(query.with_limit(MAX_BOOK_ENTRIES))
        .await
        .caused_by(trc::location!())
}

pub fn directory_visible(server: &Server, access_token: &AccessToken) -> bool {
    server.core.groupware.allow_directory_query
        || access_token.has_permission(Permission::SysAccountQuery)
}

pub async fn directory_ref_from_email(
    server: &Server,
    address: &str,
) -> trc::Result<Option<DirectoryRef>> {
    Ok(match server.rcpt_id_from_email(address).await? {
        Some(EmailCache::Account(id)) => Some(DirectoryRef::Account(id)),
        Some(EmailCache::MailingList(id)) => Some(DirectoryRef::List(id)),
        Some(EmailCache::DisabledAccountAddress(_) | EmailCache::DisabledListAddress(_)) | None => {
            None
        }
    })
}

pub async fn visible_ref(
    server: &Server,
    access_token: &AccessToken,
    principal: DirectoryRef,
) -> trc::Result<Option<RowKey>> {
    match principal {
        DirectoryRef::Account(account_id) => visible_key(server, access_token, account_id).await,
        DirectoryRef::List(list_id) => visible_list(server, access_token, list_id).await,
    }
}

async fn visible_list(
    server: &Server,
    access_token: &AccessToken,
    list_id: u32,
) -> trc::Result<Option<RowKey>> {
    if !directory_visible(server, access_token) {
        return Ok(None);
    }
    let Some((list, _list_tenant)) = load_list(server, list_id).await? else {
        return Ok(None);
    };
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if access_token
        .tenant_id()
        .is_some_and(|tenant_id| _list_tenant != Some(tenant_id))
    {
        return Ok(None);
    }
    // SPDX-SnippetEnd
    if !addresses(server, &list.addresses, Detail::Key, &mut String::new()).await? {
        return Ok(None);
    }
    Ok(RowKey::list(list_id, list))
}

async fn load_list(
    server: &Server,
    list_id: u32,
) -> trc::Result<Option<(Arc<DirectoryList>, Option<u32>)>> {
    let Some(list) = server
        .registry()
        .object::<MailingList>(list_id.into())
        .await
        .caused_by(trc::location!())?
    else {
        return Ok(None);
    };
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    let tenant_id = list.member_tenant_id.map(|id| id.document_id());
    // SPDX-SnippetEnd
    #[cfg(not(feature = "enterprise"))]
    let tenant_id = None;
    let addresses = once(EmailAddress {
        local_part: list.name.into(),
        domain_id: list.domain_id.document_id(),
    })
    .chain(
        list.aliases
            .into_iter()
            .filter(|alias| alias.enable)
            .map(|alias| EmailAddress {
                local_part: alias.name.into(),
                domain_id: alias.domain_id.document_id(),
            }),
    )
    .collect();
    Ok(Some((
        Arc::new(DirectoryList {
            addresses,
            recipients: list.recipients.into_iter().map(Into::into).collect(),
            description: list.description.map(Into::into),
        }),
        tenant_id,
    )))
}

pub async fn visible_key(
    server: &Server,
    access_token: &AccessToken,
    account_id: u32,
) -> trc::Result<Option<RowKey>> {
    let visible = directory_visible(server, access_token)
        || access_token.all_ids().any(|id| id == account_id);
    if !visible {
        return Ok(None);
    }
    let Some(account) = server.try_account(account_id).await? else {
        return Ok(None);
    };
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    if access_token
        .tenant_id()
        .is_some_and(|tenant_id| account.tenant_id() != Some(tenant_id))
    {
        return Ok(None);
    }
    // SPDX-SnippetEnd
    if !addresses(server, &account.addresses, Detail::Key, &mut String::new()).await? {
        return Ok(None);
    }
    Ok(RowKey::new(account))
}

pub(super) async fn addresses(
    server: &Server,
    addresses: &[EmailAddress],
    detail: Detail,
    out: &mut String,
) -> trc::Result<bool> {
    out.clear();
    for address in addresses {
        let Some(domain) = server.domain_by_id(address.domain_id).await? else {
            continue;
        };
        if detail == Detail::Key {
            if domain.names.is_empty() {
                continue;
            }
            return Ok(true);
        }
        for name in domain.names.iter() {
            if !out.is_empty() {
                out.push(ADDRESS_SEPARATOR);
            }
            out.push_str(&address.local_part);
            out.push('@');
            out.push_str(name);
        }
    }
    Ok(!out.is_empty())
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Addresses<'a> {
    Proxies(&'a [Box<str>]),
    Lines(&'a str),
}

#[derive(Debug, Clone, Copy)]
pub struct AbView<'a> {
    pub principal: DirectoryRef,
    pub kind: AbKind,
    pub display_name: &'a str,
    pub account: &'a str,
    pub smtp: &'a str,
    pub(super) addresses: Addresses<'a>,
    pub(super) dn: Option<&'a str>,
}

impl<'a> AbView<'a> {
    pub fn addresses(&self) -> impl Iterator<Item = &'a str> + 'a {
        let (proxies, lines) = match self.addresses {
            Addresses::Proxies(proxies) => (proxies, ""),
            Addresses::Lines(lines) => (&[][..], lines),
        };
        proxies
            .iter()
            .filter_map(|proxy| proxy.split_once(':').map(|(_, address)| address))
            .chain(
                lines
                    .split(ADDRESS_SEPARATOR)
                    .filter(|line| !line.is_empty()),
            )
    }

    pub fn dn(&self) -> Option<Cow<'a, str>> {
        match self.dn {
            Some(dn) => Some(Cow::Borrowed(dn)),
            None => {
                directory_dn(self.principal, self.smtp).map(|dn| Cow::Owned(dn.as_str().into()))
            }
        }
    }
}
