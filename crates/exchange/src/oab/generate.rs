/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::row::{OAB_COLLECTION, OAB_OWNER, OabBlob, OabGeneration, OabRow, OabTenant};
use crate::{
    identity::deployment_guid,
    mapi::nspi::{
        book::{ResourceDetail, entry},
        page::AbKind,
        props::{AbValue, EntryIdForm},
        scan::{Detail, DirectoryScan, ScanScope, directory_visible},
    },
};
use common::{
    Server,
    auth::AccessToken,
    network::memory::{MemoryClass, MemoryReservation},
};
use exchange_proto::{
    common::{Braces, Guid, HexCase},
    ids::essdn::GAL_DN,
    oab::{
        ADDRESS_BOOK_MEMBER, GAL_NAME, HEADER_PROPS, OBJECT_PROPS, OabError, OabHeader, OabValue,
        TEMPLATE, full_head, manifest::SHA1_LEN, wrap, wrapped_len, write_record,
    },
};
use sha1::{Digest, Sha1};
use store::{
    rand,
    write::{BatchBuilder, BlobLink, BlobOp, assert::AssertValue, blob::BlobLinkValue, now},
};
use trc::AddContext;
use types::blob_hash::BlobHash;

#[cfg(not(stalwart_tests))]
pub const OAB_REFRESH: u64 = 3600;
#[cfg(stalwart_tests)]
pub const OAB_REFRESH: u64 = 0;
pub const OAB_LEASE: u64 = 600;
pub const OAB_BLOB_HOLD: u64 = OAB_LEASE + 300;

const EPOCH_2020: u64 = 1_577_836_800;
const SECONDS_PER_HOUR: u64 = 3600;
const MAX_SEQ: u32 = i32::MAX.cast_unsigned();
const RECORD_ESTIMATE: usize = 256;
const GUID_TEXT_LEN: usize = 36;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    Fresh,
    Busy,
    Unchanged,
    Generated { seq: u32 },
    Lost,
}

pub fn spawn_refresh(server: &Server, access_token: &AccessToken) {
    let server = server.clone();
    let access_token = access_token.clone();
    tokio::spawn(async move {
        if let Err(err) = refresh(&server, &access_token).await {
            trc::error!(err.details("Offline address book generation failed"));
        }
    });
}

pub async fn refresh(server: &Server, access_token: &AccessToken) -> trc::Result<RefreshOutcome> {
    let tenant = OabTenant::of(access_token);
    let row = OabRow::read(server, tenant).await?;
    let now = now();
    let (mut leased, assert) = match row {
        Some(row) if !row.is_stale(now, OAB_REFRESH) => return Ok(RefreshOutcome::Fresh),
        Some(row) if row.is_leased(now) => return Ok(RefreshOutcome::Busy),
        Some(row) => {
            let assert = AssertValue::U64(row.revision);
            (row, assert)
        }
        None => (
            OabRow::new(Guid::from_wire(rand::random())),
            AssertValue::None,
        ),
    };
    leased.lease_until = now.saturating_add(OAB_LEASE);
    leased.revision = leased.revision.wrapping_add(1);
    if !commit(server, row_batch(tenant, &leased, assert)).await? {
        return Ok(RefreshOutcome::Busy);
    }
    generate(server, access_token, tenant, leased).await
}

async fn generate(
    server: &Server,
    access_token: &AccessToken,
    tenant: OabTenant,
    leased: OabRow,
) -> trc::Result<RefreshOutcome> {
    let mut memory = server.memory_reservation(MemoryClass::Read);
    let Some((records, count)) = encode_records(server, access_token, &mut memory).await? else {
        return Ok(RefreshOutcome::Lost);
    };
    let fingerprint: [u8; SHA1_LEN] = Sha1::digest(&records).into();
    let assert = AssertValue::U64(leased.revision);
    let revision = leased.revision.wrapping_add(1);
    let started = now();
    if leased.slots.current().is_some() && fingerprint == leased.fingerprint {
        let row = OabRow {
            refreshed_at: started,
            lease_until: 0,
            revision,
            ..leased
        };
        return Ok(if commit(server, row_batch(tenant, &row, assert)).await? {
            RefreshOutcome::Unchanged
        } else {
            RefreshOutcome::Lost
        });
    }

    let seq = leased.slots.current().map_or_else(
        || first_seq(started),
        |current| current.seq.saturating_add(1),
    );
    let mut guid = Vec::with_capacity(GUID_TEXT_LEN);
    leased
        .guid
        .write_text(&mut guid, HexCase::Lower, Braces::None);
    let header = OabHeader {
        name: GAL_NAME,
        distinguished_name: GAL_DN,
        sequence: seq,
        container_guid: std::str::from_utf8(&guid).unwrap_or_default(),
    };
    let head =
        full_head(&header, &HEADER_PROPS, &OBJECT_PROPS, &records, count).map_err(too_large)?;
    let full_len = head.len() + records.len();
    memory
        .try_reserve_to(as_u64(records.capacity() + wrapped_len(full_len)))
        .caused_by(trc::location!())?;
    let mut full = Vec::new();
    wrap(&[&head, &records], &mut full).map_err(too_large)?;
    drop(records);
    let mut template = Vec::new();
    wrap(&[&TEMPLATE], &mut template).map_err(too_large)?;

    if now() >= leased.lease_until {
        return Ok(RefreshOutcome::Lost);
    }
    let opts = &server.core.blob.file;
    let (full_hash, full_hold) = server
        .put_temporary_blob(OAB_OWNER, &full, OAB_BLOB_HOLD, opts)
        .await
        .caused_by(trc::location!())?;
    let (template_hash, template_hold) = server
        .put_temporary_blob(OAB_OWNER, &template, OAB_BLOB_HOLD, opts)
        .await
        .caused_by(trc::location!())?;
    let generation = OabGeneration {
        seq,
        assigned_at: started,
        full: oab_blob(full_hash, &full, full_len)?,
        template: oab_blob(template_hash, &template, TEMPLATE.len())?,
    };
    drop(full);

    let expired = leased.slots.previous().cloned();
    let lease_until = leased.lease_until;
    let row = OabRow {
        guid: leased.guid,
        fingerprint,
        refreshed_at: started,
        lease_until: 0,
        slots: leased.slots.push(generation),
        revision,
    };
    if now() >= lease_until {
        return Ok(RefreshOutcome::Lost);
    }
    let mut batch = row_batch(tenant, &row, assert);
    for blob in row
        .slots
        .current()
        .into_iter()
        .flat_map(OabGeneration::blobs)
    {
        batch.set(
            BlobOp::Link {
                hash: blob.hash.clone(),
                to: BlobLink::Document,
            },
            BlobLinkValue::new(blob.size),
        );
    }
    batch.clear(full_hold).clear(template_hold);
    for blob in expired.iter().flat_map(OabGeneration::blobs) {
        if !row.slots.holds(&blob.hash) {
            batch.clear(BlobOp::Link {
                hash: blob.hash.clone(),
                to: BlobLink::Document,
            });
        }
    }
    Ok(if commit(server, batch).await? {
        RefreshOutcome::Generated { seq }
    } else {
        RefreshOutcome::Lost
    })
}

async fn encode_records(
    server: &Server,
    access_token: &AccessToken,
    memory: &mut MemoryReservation,
) -> trc::Result<Option<(Vec<u8>, u32)>> {
    if !directory_visible(server, access_token) {
        return Ok(None);
    }
    let server_guid = deployment_guid(&server.core.network.server_name);
    let mut scan = DirectoryScan::open(server, access_token, ScanScope::All).await?;
    let capacity = scan.remaining().saturating_mul(RECORD_ESTIMATE);
    memory
        .try_reserve_to(as_u64(capacity))
        .caused_by(trc::location!())?;
    let mut records = Vec::with_capacity(capacity);
    let mut count = 0u32;
    while let Some(key) = scan.next(server, Detail::Key).await? {
        let Some(entry) = entry(server, &server_guid, &key, ResourceDetail::Full).await? else {
            continue;
        };
        write_record(&mut records, &OBJECT_PROPS, |tag| {
            if tag == ADDRESS_BOOK_MEMBER && entry.kind == AbKind::List {
                Some(OabValue::Online)
            } else {
                AbValue::of(&entry, tag, EntryIdForm::Permanent).and_then(AbValue::oab)
            }
        })
        .map_err(too_large)?;
        count = count.saturating_add(1);
        memory
            .try_reserve_to(as_u64(records.capacity()))
            .caused_by(trc::location!())?;
    }
    Ok(Some((records, count)))
}

fn row_batch(tenant: OabTenant, row: &OabRow, assert: AssertValue) -> BatchBuilder {
    let mut batch = BatchBuilder::new();
    batch
        .with_account_id(OAB_OWNER)
        .with_collection(OAB_COLLECTION)
        .with_document(tenant.id())
        .assert_value(tenant.class(), assert)
        .set(tenant.class(), row.serialize());
    batch
}

async fn commit(server: &Server, mut batch: BatchBuilder) -> trc::Result<bool> {
    match server.store().write_batch(&mut batch).await {
        Ok(_) => Ok(true),
        Err(err) if err.is_assertion_failure() => Ok(false),
        Err(err) => Err(err.caused_by(trc::location!())),
    }
}

fn oab_blob(hash: BlobHash, file: &[u8], uncompressed: usize) -> trc::Result<OabBlob> {
    Ok(OabBlob {
        hash,
        size: u32::try_from(file.len()).map_err(|_| too_large(OabError::TooLarge))?,
        uncompressed: u32::try_from(uncompressed).map_err(|_| too_large(OabError::TooLarge))?,
        sha1: Sha1::digest(file).into(),
    })
}

fn first_seq(now: u64) -> u32 {
    u32::try_from(now.saturating_sub(EPOCH_2020) / SECONDS_PER_HOUR)
        .unwrap_or(MAX_SEQ)
        .clamp(1, MAX_SEQ)
}

fn as_u64(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

#[cold]
fn too_large(_: OabError) -> trc::Error {
    trc::LimitEvent::SizeRequest
        .into_err()
        .details("Offline address book too large")
}
