/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::Sieve;
use store::{
    SerializeInfallible, U32_LEN, ValueKey, blake3,
    write::{Archive, ArchiveBytes, ArchiveVersion, BatchBuilder, IndexPropertyClass, ValueClass},
};
use trc::AddContext;
use types::{blob_hash::BlobHash, collection::Collection, field::SieveField};
use utils::hash128::Hash128;

mod addrbook;
pub mod delete;
pub mod index;
pub mod ingest;
pub mod rules;

#[derive(Debug)]
pub struct ActiveScript {
    pub document_id: u32,
    pub version: ArchiveVersion,
    pub script: Bytecode,
}

#[derive(Debug)]
pub enum Bytecode {
    Stored(Archive<ArchiveBytes>),
    Compiled(Vec<u8>),
}

impl ActiveScript {
    pub fn bytecode(&self) -> trc::Result<&[u8]> {
        match &self.script {
            Bytecode::Stored(archive) => archive
                .unarchive::<SieveScript>()
                .caused_by(trc::location!())
                .map(|script| script.script.as_ref()),
            Bytecode::Compiled(bytes) => Ok(bytes),
        }
    }
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct SieveScript {
    pub name: String,
    pub blob_hash: BlobHash,
    pub size: u32,
    pub _vacation: Option<VacationResponse>,
    pub script: Vec<u8>,
    pub metadata_flags: u8,
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct VacationResponse {
    pub from_date: Option<u64>,
    pub to_date: Option<u64>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
}

impl SieveScript {
    pub fn new(name: impl Into<String>, blob_hash: BlobHash) -> Self {
        SieveScript {
            name: name.into(),
            blob_hash,
            _vacation: None,
            size: 0,
            script: Vec::new(),
            metadata_flags: 0,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_blob_hash(mut self, blob_hash: BlobHash) -> Self {
        self.blob_hash = blob_hash;
        self
    }

    pub fn with_size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    pub fn with_script(mut self, script: &Sieve<'_>) -> Self {
        self.set_script(script);
        self
    }

    pub fn set_script(&mut self, script: &Sieve<'_>) {
        self.script = script.to_bytes();
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SeenIdHash(pub Hash128);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenId {
    pub hash: SeenIdHash,
    pub expires_at: u64,
}

const SEEN_ID_DOCUMENT_ID: u32 = 0;
const SEEN_ID_HASH_OFFSET: usize = U32_LEN + 3;

impl SeenIdHash {
    pub fn new(script_hash: u32, id: &str) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&script_hash.to_be_bytes());
        hasher.update(id.as_bytes());
        let mut hash = [0u8; Hash128::LEN];
        hasher.finalize_xof().fill(&mut hash);
        SeenIdHash(Hash128::from_be_bytes(hash))
    }

    pub fn class(&self) -> ValueClass {
        ValueClass::IndexProperty(IndexPropertyClass::Hash {
            property: SieveField::SeenId.into(),
            hash: self.0,
        })
    }

    pub fn key(&self, account_id: u32) -> ValueKey<ValueClass> {
        ValueKey {
            account_id,
            collection: Collection::SieveScript.into(),
            document_id: SEEN_ID_DOCUMENT_ID,
            class: self.class(),
        }
    }

    pub fn account_range(account_id: u32) -> (ValueKey<ValueClass>, ValueKey<ValueClass>) {
        (
            SeenIdHash(Hash128::default()).key(account_id),
            SeenIdHash(Hash128::from(u128::MAX)).key(account_id),
        )
    }

    pub fn from_key(key: &[u8]) -> Option<Self> {
        key.get(SEEN_ID_HASH_OFFSET..SEEN_ID_HASH_OFFSET + Hash128::LEN)
            .and_then(Hash128::from_be_slice)
            .map(SeenIdHash)
    }

    pub fn with_context(account_id: u32, batch: &mut BatchBuilder) -> &mut BatchBuilder {
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript)
            .with_document(SEEN_ID_DOCUMENT_ID)
    }
}

impl SeenId {
    pub fn write_all(seen_ids: &[SeenId], account_id: u32, batch: &mut BatchBuilder) {
        let batch = SeenIdHash::with_context(account_id, batch);
        for seen_id in seen_ids {
            batch.set(seen_id.hash.class(), seen_id.expires_at.serialize());
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/email/src/sieve/tests.rs"]
mod tests;
