/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FxError, IcsLimits, IdSet, IdSetForm, ReplKey, fx::meta};
use crate::{
    ids::{Globcnt, ReplGuid},
    mapi::prop::PropTag,
};

const STATE_RESERVE_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IcsState {
    pub given: IdSet,
    pub seen: IdSet,
    pub seen_fai: IdSet,
    pub read: IdSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    Contents,
    Hierarchy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateProp {
    Given,
    Seen,
    SeenFai,
    Read,
}

impl StateProp {
    fn from_tag(tag: PropTag) -> Option<Self> {
        let id = tag.id();
        if id == meta::IDSET_GIVEN.id() {
            Some(StateProp::Given)
        } else if tag == meta::CNSET_SEEN {
            Some(StateProp::Seen)
        } else if tag == meta::CNSET_SEEN_FAI {
            Some(StateProp::SeenFai)
        } else if tag == meta::CNSET_READ {
            Some(StateProp::Read)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct StateUpload {
    current: Option<StateProp>,
    buf: Vec<u8>,
    state: IcsState,
    limits: IcsLimits,
}

impl StateUpload {
    pub fn new(limits: &IcsLimits) -> Self {
        StateUpload {
            current: None,
            buf: Vec::new(),
            state: IcsState::default(),
            limits: *limits,
        }
    }

    pub fn is_streaming(&self) -> bool {
        self.current.is_some()
    }

    pub fn begin(&mut self, prop: PropTag, total: u32) -> Result<(), FxError> {
        if self.current.is_some() {
            return Err(FxError::StateSequence);
        }
        let which = StateProp::from_tag(prop).ok_or(FxError::StateProperty)?;
        if prop.id() == meta::IDSET_GIVEN.id()
            && prop != meta::IDSET_GIVEN
            && prop != meta::IDSET_GIVEN_BINARY
        {
            return Err(FxError::StateProperty);
        }
        if total > self.limits.max_state_len {
            return Err(FxError::TooLarge { offset: 0 });
        }
        self.buf.clear();
        self.buf
            .reserve(usize::try_from(total).unwrap_or(0).min(STATE_RESERVE_CAP));
        self.current = Some(which);
        Ok(())
    }

    pub fn append(&mut self, data: &[u8]) -> Result<(), FxError> {
        if self.current.is_none() {
            return Err(FxError::StateSequence);
        }
        let new_len = self.buf.len().saturating_add(data.len());
        if new_len > usize::try_from(self.limits.max_state_len).unwrap_or(usize::MAX) {
            return Err(FxError::TooLarge {
                offset: u32::try_from(self.buf.len()).unwrap_or(u32::MAX),
            });
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    pub fn end(&mut self) -> Result<(), FxError> {
        let which = self.current.take().ok_or(FxError::StateSequence)?;
        let set = IdSet::decode(&self.buf, IdSetForm::ReplGuid, &self.limits)?;
        self.buf.clear();
        let slot = match which {
            StateProp::Given => &mut self.state.given,
            StateProp::Seen => &mut self.state.seen,
            StateProp::SeenFai => &mut self.state.seen_fai,
            StateProp::Read => &mut self.state.read,
        };
        *slot = set;
        Ok(())
    }

    pub fn state(&self) -> &IcsState {
        &self.state
    }

    pub fn into_state(self) -> IcsState {
        self.state
    }
}

impl IcsState {
    pub fn collapse_seen(&mut self, replguid: ReplGuid, last_cn: Globcnt) {
        collapse(&mut self.seen, replguid, last_cn);
        collapse(&mut self.seen_fai, replguid, last_cn);
    }

    pub fn collapse_read(&mut self, replguid: ReplGuid, last_read_cn: Globcnt) {
        collapse(&mut self.read, replguid, last_read_cn);
    }
}

fn collapse(set: &mut IdSet, replguid: ReplGuid, last: Globcnt) {
    if let Some(first) = Globcnt::new(1)
        && last >= first
    {
        set.get_mut(ReplKey::Guid(replguid))
            .insert_range(first, last);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeltaSummary {
    pub changed_ids: IdSet,
    pub changed_normal_cns: IdSet,
    pub changed_fai_cns: IdSet,
    pub changed_partial_ids: IdSet,
    pub read_state_ids: IdSet,
    pub read_state_cns: IdSet,
    pub idset_read: IdSet,
    pub idset_unread: IdSet,
    pub deleted: IdSet,
    pub no_longer_in_scope: IdSet,
    pub expired: IdSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantViolation {
    Given,
    Seen,
    SeenFai,
    Read,
    PartialNotGiven,
    ReadNotGiven,
    ReadSet,
    ChangedDeleted,
    ResentCn,
    ReadDeleted,
    ReadAndChanged,
}

pub fn check_delta_invariants(
    before: &IcsState,
    after: &IcsState,
    sent: &DeltaSummary,
) -> Result<(), InvariantViolation> {
    let mut all_deleted = sent.deleted.clone();
    all_deleted.union_with(&sent.no_longer_in_scope);
    all_deleted.union_with(&sent.expired);

    let mut given = before.given.clone();
    given.union_with(&sent.changed_ids);
    given.difference_with(&all_deleted);
    if !same_members(&given, &after.given) {
        return Err(InvariantViolation::Given);
    }
    if !covers(&after.seen, &before.seen, &sent.changed_normal_cns) {
        return Err(InvariantViolation::Seen);
    }
    if !covers(&after.seen_fai, &before.seen_fai, &sent.changed_fai_cns) {
        return Err(InvariantViolation::SeenFai);
    }
    if !covers(&after.read, &before.read, &sent.read_state_cns) {
        return Err(InvariantViolation::Read);
    }
    if !sent.changed_partial_ids.is_subset_of(&before.given) {
        return Err(InvariantViolation::PartialNotGiven);
    }
    let mut read_changes = sent.idset_read.clone();
    read_changes.union_with(&sent.idset_unread);
    if !read_changes.is_subset_of(&before.given) {
        return Err(InvariantViolation::ReadNotGiven);
    }
    if !same_members(&read_changes, &sent.read_state_ids) {
        return Err(InvariantViolation::ReadSet);
    }
    if sent.changed_ids.intersects(&all_deleted) {
        return Err(InvariantViolation::ChangedDeleted);
    }
    let mut changed_cns = sent.changed_normal_cns.clone();
    changed_cns.union_with(&sent.changed_fai_cns);
    if changed_cns.intersects(&before.seen) || changed_cns.intersects(&before.seen_fai) {
        return Err(InvariantViolation::ResentCn);
    }
    if sent.read_state_ids.intersects(&all_deleted) {
        return Err(InvariantViolation::ReadDeleted);
    }
    if sent.read_state_ids.intersects(&sent.changed_ids) {
        return Err(InvariantViolation::ReadAndChanged);
    }
    Ok(())
}

fn same_members(a: &IdSet, b: &IdSet) -> bool {
    a.is_subset_of(b) && b.is_subset_of(a)
}

fn covers(after: &IdSet, before: &IdSet, sent: &IdSet) -> bool {
    before.is_subset_of(after) && sent.is_subset_of(after)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ics/state/tests.rs"]
mod tests;
