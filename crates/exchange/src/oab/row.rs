/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::store::exchange_key;
use common::{Server, auth::AccessToken};
use exchange_proto::{
    common::Guid,
    oab::{ManifestFile, manifest::SHA1_LEN},
};
use store::{
    Deserialize, U32_LEN, U64_LEN, ValueKey,
    write::{ValueClass, metadata::ExchangeClass},
};
use trc::AddContext;
use types::{
    blob_hash::{BLOB_HASH_LEN, BlobHash},
    collection::Collection,
};

pub const OAB_OWNER: u32 = u32::MAX - 1;
pub const OAB_COLLECTION: Collection = Collection::Principal;
const NO_TENANT: u32 = u32::MAX;
const GUID_LEN: usize = 16;
const BLOB_LEN: usize = BLOB_HASH_LEN + U32_LEN * 2 + SHA1_LEN;
const GENERATION_LEN: usize = U32_LEN + U64_LEN + BLOB_LEN * 2;
const FIXED_LEN: usize = GUID_LEN + SHA1_LEN + U64_LEN * 2 + 1;
const MAX_ROW_LEN: usize = FIXED_LEN + GENERATION_LEN * 2 + U64_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OabTenant(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OabBlob {
    pub hash: BlobHash,
    pub size: u32,
    pub uncompressed: u32,
    pub sha1: [u8; SHA1_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OabGeneration {
    pub seq: u32,
    pub assigned_at: u64,
    pub full: OabBlob,
    pub template: OabBlob,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OabSlots {
    Empty,
    Current(OabGeneration),
    Rotated {
        current: OabGeneration,
        previous: OabGeneration,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OabRow {
    pub guid: Guid,
    pub fingerprint: [u8; SHA1_LEN],
    pub refreshed_at: u64,
    pub lease_until: u64,
    pub slots: OabSlots,
    pub revision: u64,
}

impl OabTenant {
    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn of(access_token: &AccessToken) -> Self {
        OabTenant(access_token.tenant_id().unwrap_or(NO_TENANT))
    }
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    pub fn of(_: &AccessToken) -> Self {
        OabTenant(NO_TENANT)
    }

    pub fn id(self) -> u32 {
        self.0
    }

    pub fn class(self) -> ExchangeClass {
        ExchangeClass::OfflineAddressBook { tenant: self.0 }
    }

    pub fn key(self) -> ValueKey<ValueClass> {
        exchange_key(OAB_OWNER, OAB_COLLECTION, self.0, self.class())
    }
}

impl OabBlob {
    pub fn manifest(&self, seq: u32) -> ManifestFile {
        ManifestFile {
            seq,
            size: self.size,
            uncompressed: self.uncompressed,
            sha1: self.sha1,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.hash.as_slice());
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.uncompressed.to_be_bytes());
        out.extend_from_slice(&self.sha1);
    }

    fn read(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (hash, rest) = bytes.split_first_chunk::<BLOB_HASH_LEN>()?;
        let (size, rest) = rest.split_first_chunk::<U32_LEN>()?;
        let (uncompressed, rest) = rest.split_first_chunk::<U32_LEN>()?;
        let (sha1, rest) = rest.split_first_chunk::<SHA1_LEN>()?;
        Some((
            OabBlob {
                hash: BlobHash::try_from_hash_slice(hash).ok()?,
                size: u32::from_be_bytes(*size),
                uncompressed: u32::from_be_bytes(*uncompressed),
                sha1: *sha1,
            },
            rest,
        ))
    }
}

impl OabGeneration {
    pub fn blobs(&self) -> [&OabBlob; 2] {
        [&self.full, &self.template]
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.assigned_at.to_be_bytes());
        self.full.write(out);
        self.template.write(out);
    }

    fn read(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (seq, rest) = bytes.split_first_chunk::<U32_LEN>()?;
        let (assigned_at, rest) = rest.split_first_chunk::<U64_LEN>()?;
        let (full, rest) = OabBlob::read(rest)?;
        let (template, rest) = OabBlob::read(rest)?;
        Some((
            OabGeneration {
                seq: u32::from_be_bytes(*seq),
                assigned_at: u64::from_be_bytes(*assigned_at),
                full,
                template,
            },
            rest,
        ))
    }
}

impl OabSlots {
    pub fn current(&self) -> Option<&OabGeneration> {
        match self {
            OabSlots::Empty => None,
            OabSlots::Current(current) | OabSlots::Rotated { current, .. } => Some(current),
        }
    }

    pub fn previous(&self) -> Option<&OabGeneration> {
        match self {
            OabSlots::Rotated { previous, .. } => Some(previous),
            OabSlots::Empty | OabSlots::Current(_) => None,
        }
    }

    pub fn find(&self, seq: u32) -> Option<&OabGeneration> {
        self.current()
            .into_iter()
            .chain(self.previous())
            .find(|generation| generation.seq == seq)
    }

    pub fn push(self, next: OabGeneration) -> Self {
        match self {
            OabSlots::Empty => OabSlots::Current(next),
            OabSlots::Current(current) | OabSlots::Rotated { current, .. } => OabSlots::Rotated {
                current: next,
                previous: current,
            },
        }
    }

    pub fn holds(&self, hash: &BlobHash) -> bool {
        self.current()
            .into_iter()
            .chain(self.previous())
            .any(|generation| generation.blobs().iter().any(|blob| &blob.hash == hash))
    }

    fn count(&self) -> u8 {
        match self {
            OabSlots::Empty => 0,
            OabSlots::Current(_) => 1,
            OabSlots::Rotated { .. } => 2,
        }
    }
}

impl OabRow {
    pub fn new(guid: Guid) -> Self {
        OabRow {
            guid,
            fingerprint: [0; SHA1_LEN],
            refreshed_at: 0,
            lease_until: 0,
            slots: OabSlots::Empty,
            revision: 0,
        }
    }

    pub async fn read(server: &Server, tenant: OabTenant) -> trc::Result<Option<Self>> {
        server
            .store()
            .get_value::<OabRow>(tenant.key())
            .await
            .caused_by(trc::location!())
    }

    pub fn is_stale(&self, now: u64, refresh: u64) -> bool {
        self.refreshed_at.saturating_add(refresh) <= now
    }

    pub fn is_leased(&self, now: u64) -> bool {
        self.lease_until > now
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_ROW_LEN);
        out.extend_from_slice(self.guid.as_bytes());
        out.extend_from_slice(&self.fingerprint);
        out.extend_from_slice(&self.refreshed_at.to_be_bytes());
        out.extend_from_slice(&self.lease_until.to_be_bytes());
        out.push(self.slots.count());
        for generation in self
            .slots
            .current()
            .into_iter()
            .chain(self.slots.previous())
        {
            generation.write(&mut out);
        }
        out.extend_from_slice(&self.revision.to_be_bytes());
        out
    }

    fn parse(bytes: &[u8]) -> Option<Self> {
        let (guid, rest) = bytes.split_first_chunk::<GUID_LEN>()?;
        let (fingerprint, rest) = rest.split_first_chunk::<SHA1_LEN>()?;
        let (refreshed_at, rest) = rest.split_first_chunk::<U64_LEN>()?;
        let (lease_until, rest) = rest.split_first_chunk::<U64_LEN>()?;
        let (count, rest) = rest.split_first()?;
        let (slots, rest) = match count {
            0 => (OabSlots::Empty, rest),
            1 => {
                let (current, rest) = OabGeneration::read(rest)?;
                (OabSlots::Current(current), rest)
            }
            2 => {
                let (current, rest) = OabGeneration::read(rest)?;
                let (previous, rest) = OabGeneration::read(rest)?;
                (OabSlots::Rotated { current, previous }, rest)
            }
            _ => return None,
        };
        let revision: &[u8; U64_LEN] = rest.try_into().ok()?;
        Some(OabRow {
            guid: Guid::from_wire(*guid),
            fingerprint: *fingerprint,
            refreshed_at: u64::from_be_bytes(*refreshed_at),
            lease_until: u64::from_be_bytes(*lease_until),
            slots,
            revision: u64::from_be_bytes(*revision),
        })
    }
}

impl Deserialize for OabRow {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        OabRow::parse(bytes).ok_or_else(|| {
            trc::StoreEvent::DataCorruption
                .into_err()
                .details("Invalid offline address book row")
                .ctx(trc::Key::Value, bytes)
                .caused_by(trc::location!())
        })
    }
}
