/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub use super::seed_table::SeedName;

use super::{
    name::{FIRST_NAMED_ID, PropKey, PropKeyRef, StaticNamedPropMap},
    seed_table::SEED,
    tag::PropId,
};
use crate::common::Guid;

pub const SEED_LEN: usize = SEED.len();

const fn seed_ref(set: Guid, name: SeedName) -> PropKeyRef<'static> {
    match name {
        SeedName::Lid(lid) => PropKeyRef::Lid { set, lid },
        SeedName::Name(name) => PropKeyRef::Name { set, name },
    }
}

fn seed_id_at(index: usize) -> Option<PropId> {
    let offset = u16::try_from(index).ok()?;
    FIRST_NAMED_ID.0.checked_add(offset).map(PropId)
}

pub fn seed_entries() -> impl Iterator<Item = (PropKeyRef<'static>, PropId)> {
    SEED.iter()
        .zip(FIRST_NAMED_ID.0..)
        .map(|((set, name), id)| (seed_ref(*set, *name), PropId(id)))
}

pub fn seed_map() -> StaticNamedPropMap {
    StaticNamedPropMap::new(seed_entries().map(|(key, id)| (key.to_key(), id)))
}

pub fn seed_id(key: PropKeyRef<'_>) -> Option<PropId> {
    let index = SEED
        .binary_search_by(|(set, name)| seed_ref(*set, *name).cmp(&key))
        .ok()?;
    seed_id_at(index)
}

pub fn seed_key(id: PropId) -> Option<PropKeyRef<'static>> {
    let index = usize::from(id.0.checked_sub(FIRST_NAMED_ID.0)?);
    SEED.get(index).map(|(set, name)| seed_ref(*set, *name))
}

impl SeedName {
    pub fn to_key(self, set: Guid) -> PropKey {
        seed_ref(set, self).to_key()
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/mapi/prop/seed/tests.rs"]
mod tests;
