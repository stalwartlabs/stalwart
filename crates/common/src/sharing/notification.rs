/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{Deserialize, SerializeInfallible, U32_LEN, U64_LEN, write::key::KeySerializer};
use types::{acl::Acl, collection::Collection};
use utils::map::bitmap::Bitmap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShareNotification {
    pub object_account_id: u32,
    pub object_id: u32,
    pub object_type: Collection,
    pub changed_by: u32,
    pub old_rights: Bitmap<Acl>,
    pub new_rights: Bitmap<Acl>,
    pub name: String,
}

impl SerializeInfallible for ShareNotification {
    fn serialize(&self) -> Vec<u8> {
        KeySerializer::new(U64_LEN * 2 + U32_LEN * 3 + 1 + self.name.len())
            .write(self.object_account_id)
            .write(self.object_id)
            .write(self.object_type as u8)
            .write(self.changed_by)
            .write(self.old_rights.bitmap)
            .write(self.new_rights.bitmap)
            .write(self.name.as_bytes())
            .finalize()
    }
}

impl Deserialize for ShareNotification {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        Self::deserialize_from_slice(bytes)
            .ok_or(trc::StoreEvent::DataCorruption.caused_by(trc::location!()))
    }
}

impl ShareNotification {
    fn deserialize_from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            object_account_id: bytes
                .get(..U32_LEN)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_be_bytes)?,
            object_id: bytes
                .get(U32_LEN..U32_LEN * 2)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_be_bytes)?,
            object_type: bytes.get(U32_LEN * 2).copied().map(Collection::from)?,
            changed_by: bytes
                .get(U32_LEN * 2 + 1..U32_LEN * 3 + 1)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_be_bytes)?,
            old_rights: bytes
                .get(U32_LEN * 3 + 1..U32_LEN * 3 + U64_LEN + 1)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_be_bytes)
                .map(Bitmap::from)?,
            new_rights: bytes
                .get(U32_LEN * 3 + U64_LEN + 1..U32_LEN * 3 + U64_LEN * 2 + 1)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_be_bytes)
                .map(Bitmap::from)?,
            name: bytes
                .get(U32_LEN * 3 + U64_LEN * 2 + 1..)
                .and_then(|b| String::from_utf8(b.to_vec()).ok())
                .unwrap_or_default(),
        })
    }
}
