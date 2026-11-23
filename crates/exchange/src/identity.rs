/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccountCache};
use exchange_proto::{
    common::Guid,
    ids::{
        ReplGuid,
        essdn::{DnKind, LegacyDn, OrgDn, ParsedDn, parse_dn},
    },
};
use store::blake3;

pub const ORG_DN: &str = "Stalwart";

const MAILBOX_CONTEXT: &str = "Stalwart Exchange 2026-10-30 mailbox GUID";
const REPLICA_CONTEXT: &str = "Stalwart Exchange 2026-10-30 replica GUID";
const DEPLOYMENT_CONTEXT: &str = "Stalwart Exchange 2026-10-30 deployment GUID";
const DIRECTORY_CONTEXT: &str = "Stalwart Exchange 2026-10-30 directory entry GUID";

fn derive_guid(context: &str, material: &[u8]) -> Guid {
    let key = blake3::derive_key(context, material);
    let mut bytes = key.first_chunk::<16>().copied().unwrap_or_default();
    bytes[7] = (bytes[7] & 0x0F) | 0x80;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Guid(bytes)
}

fn account_material(prefix: [u8; 8], account_id: u32) -> [u8; 12] {
    let mut material = [0u8; 12];
    let (head, tail) = material.split_at_mut(8);
    head.copy_from_slice(&prefix);
    tail.copy_from_slice(&account_id.to_be_bytes());
    material
}

pub fn mailbox_guid(store_instance: u64, account_id: u32) -> Guid {
    derive_guid(
        MAILBOX_CONTEXT,
        &account_material(store_instance.to_be_bytes(), account_id),
    )
}

pub fn replica_guid(store_instance: u64, account_id: u32) -> ReplGuid {
    ReplGuid(derive_guid(
        REPLICA_CONTEXT,
        &account_material(store_instance.to_be_bytes(), account_id),
    ))
}

pub fn deployment_guid(hostname: &str) -> Guid {
    derive_guid(DEPLOYMENT_CONTEXT, hostname.as_bytes())
}

pub fn directory_guid(deployment: &Guid, account_id: u32) -> Guid {
    let mut material = [0u8; 20];
    let (head, tail) = material.split_at_mut(16);
    head.copy_from_slice(&deployment.0);
    tail.copy_from_slice(&account_id.to_be_bytes());
    derive_guid(DIRECTORY_CONTEXT, &material)
}

pub fn org_dn() -> Option<OrgDn> {
    OrgDn::new(ORG_DN)
}

const LIST_DN_TAG: u64 = 1 << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DirectoryRef {
    Account(u32),
    List(u32),
}

impl DirectoryRef {
    fn dn_id(self) -> u64 {
        match self {
            DirectoryRef::Account(id) => u64::from(id),
            DirectoryRef::List(id) => LIST_DN_TAG | u64::from(id),
        }
    }

    pub fn account_id(self) -> Option<u32> {
        match self {
            DirectoryRef::Account(id) => Some(id),
            DirectoryRef::List(_) => None,
        }
    }
}

pub fn legacy_dn(account_id: u32, primary_address: &str) -> Option<LegacyDn> {
    directory_dn(DirectoryRef::Account(account_id), primary_address)
}

pub fn directory_dn(principal: DirectoryRef, primary_address: &str) -> Option<LegacyDn> {
    let tail = primary_address
        .split_once('@')
        .map_or(primary_address, |(local, _)| local);
    org_dn().map(|org| LegacyDn::for_principal(&org, DnKind::Recipient, principal.dn_id(), tail))
}

pub fn principal_from_dn(dn: &[u8]) -> Option<u32> {
    directory_ref_from_dn(dn).and_then(DirectoryRef::account_id)
}

pub fn directory_ref_from_dn(dn: &[u8]) -> Option<DirectoryRef> {
    let ParsedDn { org, kind, id, .. } = parse_dn(dn)?;
    if kind != DnKind::Recipient || !org.eq_ignore_ascii_case(ORG_DN) {
        return None;
    }
    match u32::try_from(id) {
        Ok(id) => Some(DirectoryRef::Account(id)),
        Err(_) => id
            .checked_sub(LIST_DN_TAG)
            .and_then(|id| u32::try_from(id).ok())
            .map(DirectoryRef::List),
    }
}

pub(crate) async fn primary_address(
    server: &Server,
    account: &AccountCache,
) -> trc::Result<Option<String>> {
    for address in account.addresses.iter() {
        let Some(domain) = server.domain_by_id(address.domain_id).await? else {
            continue;
        };
        if let Some(name) = domain.names.first() {
            let mut smtp = String::with_capacity(address.local_part.len() + 1 + name.len());
            smtp.push_str(&address.local_part);
            smtp.push('@');
            smtp.push_str(name);
            return Ok(Some(smtp));
        }
    }
    Ok(None)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/identity/tests.rs"]
mod tests;
