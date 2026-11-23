/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use super::{GlobSet, GlobsetError, IcsLimits};
use crate::{
    common::{Guid, LeReader, LeWriter},
    ids::{Eid, Globcnt, ReplGuid, ReplId},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdSetForm {
    ReplGuid,
    ReplId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReplKey {
    Guid(ReplGuid),
    Id(ReplId),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdSet {
    replicas: SmallVec<[(ReplKey, GlobSet); 1]>,
}

impl IdSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.replicas.iter().all(|(_, set)| set.is_empty())
    }

    pub fn get(&self, key: ReplKey) -> Option<&GlobSet> {
        let index = self.position(key).ok()?;
        self.replicas.get(index).map(|(_, set)| set)
    }

    #[allow(clippy::indexing_slicing)]
    pub fn get_mut(&mut self, key: ReplKey) -> &mut GlobSet {
        let index = match self.position(key) {
            Ok(index) => index,
            Err(index) => {
                self.replicas.insert(index, (key, GlobSet::new()));
                index
            }
        };
        &mut self.replicas[index].1
    }

    pub fn contains(&self, key: ReplKey, v: Globcnt) -> bool {
        self.get(key).is_some_and(|set| set.contains(v))
    }

    pub fn contains_eid(&self, eid: Eid) -> bool {
        self.contains(ReplKey::Id(eid.replid), eid.counter)
    }

    pub fn insert_eid(&mut self, eid: Eid) {
        self.get_mut(ReplKey::Id(eid.replid)).insert(eid.counter);
    }

    pub fn replicas(&self) -> impl Iterator<Item = (ReplKey, &GlobSet)> + '_ {
        self.replicas
            .iter()
            .filter(|(_, set)| !set.is_empty())
            .map(|(key, set)| (*key, set))
    }

    pub fn union_with(&mut self, other: &IdSet) {
        for (key, set) in other.replicas() {
            self.get_mut(key).union_with(set);
        }
    }

    pub fn difference_with(&mut self, other: &IdSet) {
        for (key, set) in self.replicas.iter_mut() {
            if let Some(cut) = other.get(*key) {
                set.difference_with(cut);
            }
        }
    }

    pub fn is_subset_of(&self, other: &IdSet) -> bool {
        self.replicas()
            .all(|(key, set)| other.get(key).is_some_and(|outer| set.is_subset_of(outer)))
    }

    pub fn intersects(&self, other: &IdSet) -> bool {
        self.replicas()
            .any(|(key, set)| other.get(key).is_some_and(|o| set.intersects(o)))
    }

    pub fn total_ranges(&self) -> usize {
        self.replicas.iter().map(|(_, set)| set.range_count()).sum()
    }

    fn position(&self, key: ReplKey) -> Result<usize, usize> {
        if self.replicas.len() <= 8 {
            for (index, (k, _)) in self.replicas.iter().enumerate() {
                match k.cmp(&key) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => return Ok(index),
                    std::cmp::Ordering::Greater => return Err(index),
                }
            }
            Err(self.replicas.len())
        } else {
            self.replicas.binary_search_by(|(k, _)| k.cmp(&key))
        }
    }

    pub fn decode(b: &[u8], form: IdSetForm, limits: &IcsLimits) -> Result<Self, GlobsetError> {
        let mut r = LeReader::new(b);
        let mut replicas: SmallVec<[(ReplKey, GlobSet); 1]> = SmallVec::new();
        let mut budget = usize::try_from(limits.max_ranges).unwrap_or(usize::MAX);
        let mut normalized = true;
        while !r.is_empty() {
            let key = match form {
                IdSetForm::ReplGuid => {
                    ReplKey::Guid(ReplGuid(r.guid().map_err(|_| GlobsetError::Truncated)?))
                }
                IdSetForm::ReplId => {
                    ReplKey::Id(ReplId(r.u16().map_err(|_| GlobsetError::Truncated)?))
                }
            };
            let globset = GlobSet::decode(&mut r, budget)?;
            budget = budget
                .checked_sub(globset.range_count().max(1))
                .ok_or(GlobsetError::TooManyRanges)?;
            if globset.is_empty() {
                continue;
            }
            if replicas.last().is_some_and(|(last, _)| *last >= key) {
                normalized = false;
            }
            replicas.push((key, globset));
        }
        if !normalized {
            replicas.sort_by_key(|(key, _)| *key);
            let mut merged: SmallVec<[(ReplKey, GlobSet); 1]> = SmallVec::new();
            let mut dirty = false;
            for (key, globset) in replicas {
                match merged.last_mut() {
                    Some((last, slot)) if *last == key => {
                        slot.append_unsorted(globset);
                        dirty = true;
                    }
                    Some((_, slot)) => {
                        if std::mem::take(&mut dirty) {
                            slot.normalize();
                        }
                        merged.push((key, globset));
                    }
                    None => merged.push((key, globset)),
                }
            }
            if let Some((_, slot)) = merged.last_mut().filter(|_| dirty) {
                slot.normalize();
            }
            replicas = merged;
        }
        Ok(IdSet { replicas })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        for (key, set) in self.replicas() {
            match key {
                ReplKey::Guid(guid) => out.put_guid(&guid.0),
                ReplKey::Id(id) => out.put_u16(id.0),
            }
            set.encode(out);
        }
    }

    pub fn to_repl_guid(&self, map: impl Fn(ReplId) -> Option<ReplGuid>) -> IdSet {
        let mut result = IdSet::new();
        for (key, set) in self.replicas() {
            let key = match key {
                ReplKey::Id(id) => match map(id) {
                    Some(guid) => ReplKey::Guid(guid),
                    None => continue,
                },
                guid => guid,
            };
            result.get_mut(key).union_with(set);
        }
        result
    }

    pub fn to_repl_id(&self, map: impl Fn(ReplGuid) -> Option<ReplId>) -> IdSet {
        let mut result = IdSet::new();
        for (key, set) in self.replicas() {
            let key = match key {
                ReplKey::Guid(guid) => match map(guid) {
                    Some(id) => ReplKey::Id(id),
                    None => continue,
                },
                id => id,
            };
            result.get_mut(key).union_with(set);
        }
        result
    }
}

impl ReplKey {
    pub fn guid(&self) -> Option<Guid> {
        match self {
            ReplKey::Guid(guid) => Some(guid.0),
            ReplKey::Id(_) => None,
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ics/idset/tests.rs"]
mod tests;
