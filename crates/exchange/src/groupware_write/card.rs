/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::vcard::{VCard, VCardEntry, VCardProperty, VCardValue};
use common::{GroupwareResources, Server};
use groupware::{SizeWriter, contact::write::CardWriteError};
use registry::schema::enums::StorageQuota;
use smallvec::smallvec;
use store::rand::{self, RngExt};
use trc::{EventType, LimitEvent, StoreEvent};

const UUID_VERSION_MASK: u128 = 0xF << 76;
const UUID_VERSION_4: u128 = 0x4 << 76;
const UUID_VARIANT_MASK: u128 = 0x3 << 62;
const UUID_VARIANT_RFC: u128 = 0x2 << 62;
const VCARD_EXTENSION: &str = ".vcf";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFailure {
    NotFound,
    Forbidden,
    Invalid,
    UidConflict,
    Quota,
    Conflict,
}

pub fn card_failure(err: CardWriteError) -> trc::Result<WriteFailure> {
    match err {
        CardWriteError::NotFound => Ok(WriteFailure::NotFound),
        CardWriteError::Forbidden => Ok(WriteFailure::Forbidden),
        CardWriteError::UidChanged(_) => Ok(WriteFailure::Invalid),
        CardWriteError::UidConflict { .. } => Ok(WriteFailure::UidConflict),
        CardWriteError::Store(err) => store_failure(err),
    }
}

pub fn store_failure(err: trc::Error) -> trc::Result<WriteFailure> {
    match err.as_ref() {
        EventType::Limit(LimitEvent::Quota) => Ok(WriteFailure::Quota),
        #[cfg(feature = "enterprise")]
        EventType::Limit(LimitEvent::TenantQuota) => Ok(WriteFailure::Quota),
        EventType::Store(StoreEvent::AssertValueFailed) => Ok(WriteFailure::Conflict),
        _ => Err(err),
    }
}

pub fn card_size(server: &Server, card: &VCard) -> Option<usize> {
    let limits = &server.core.groupware;
    if limits.max_media_size != 0 && card.embedded_size() > limits.max_media_size {
        return None;
    }
    let size = SizeWriter::vcard(card, limits.vcard_version);
    (size <= limits.max_vcard_size).then_some(size)
}

pub async fn assert_card_room(
    server: &Server,
    account_id: u32,
    resources: &GroupwareResources,
    created: usize,
) -> trc::Result<()> {
    if created == 0 {
        return Ok(());
    }
    let account = server.account(account_id).await?;
    server.assert_object_quota(&account, StorageQuota::MaxContactCards, created + 1, || {
        resources.resources.count(false)
    })
}

pub fn new_card(uid: String) -> VCard {
    VCard {
        entries: vec![VCardEntry {
            group: None,
            name: VCardProperty::Uid,
            params: Vec::new(),
            values: smallvec![VCardValue::Text(uid)],
        }],
    }
}

pub fn card_name(uid: &str) -> String {
    format!("{uid}{VCARD_EXTENSION}")
}

pub fn new_uid() -> String {
    let bits = rand::rng().random::<u128>();
    let bits = (bits & !UUID_VERSION_MASK & !UUID_VARIANT_MASK) | UUID_VERSION_4 | UUID_VARIANT_RFC;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        bits >> 96,
        (bits >> 80) & 0xFFFF,
        (bits >> 64) & 0xFFFF,
        (bits >> 48) & 0xFFFF,
        bits & 0xFFFF_FFFF_FFFF
    )
}
