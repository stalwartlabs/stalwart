/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cmp::Ordering;

use smallvec::SmallVec;

use super::FxError;
use crate::{common::LeReader, ids::Xid};

const MIN_XID_SIZE: u8 = 17;
const MAX_XID_SIZE: u8 = 24;
const MAX_PCL_ENTRIES: usize = 4096;
const NORMALIZE_AT: usize = MAX_PCL_ENTRIES * 2;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pcl {
    xids: SmallVec<[Xid; 2]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PclOrder {
    Newer,
    OlderOrEqual,
    Conflict,
}

impl Pcl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_xid(xid: Xid) -> Self {
        let mut xids = SmallVec::new();
        xids.push(xid);
        Pcl { xids }
    }

    pub fn xids(&self) -> &[Xid] {
        &self.xids
    }

    pub fn is_empty(&self) -> bool {
        self.xids.is_empty()
    }

    pub fn decode(b: &[u8]) -> Result<Self, FxError> {
        let mut r = LeReader::new(b);
        let mut pcl = Pcl::new();
        let mut sorted = true;
        while !r.is_empty() {
            let size = r.u8().map_err(|_| FxError::Pcl)?;
            if !(MIN_XID_SIZE..=MAX_XID_SIZE).contains(&size) {
                return Err(FxError::Pcl);
            }
            let bytes = r.bytes(usize::from(size)).map_err(|_| FxError::Pcl)?;
            let xid = Xid::decode(bytes).ok_or(FxError::Pcl)?;
            if !sorted && pcl.xids.len() >= NORMALIZE_AT {
                pcl.normalize()?;
                sorted = true;
            }
            match pcl.xids.last_mut() {
                Some(last) if last.namespace == xid.namespace => {
                    if local_cmp(&xid, last) == Ordering::Greater {
                        *last = xid;
                    }
                    continue;
                }
                Some(last) if last.namespace > xid.namespace => sorted = false,
                _ => {}
            }
            pcl.xids.push(xid);
            if sorted && pcl.xids.len() > MAX_PCL_ENTRIES {
                return Err(FxError::Pcl);
            }
        }
        if !sorted {
            pcl.normalize()?;
        }
        Ok(pcl)
    }

    fn normalize(&mut self) -> Result<(), FxError> {
        self.xids
            .sort_unstable_by(|a, b| a.namespace.cmp(&b.namespace).then_with(|| local_cmp(b, a)));
        self.xids
            .dedup_by(|next, kept| next.namespace == kept.namespace);
        if self.xids.len() > MAX_PCL_ENTRIES {
            Err(FxError::Pcl)
        } else {
            Ok(())
        }
    }

    pub fn encode(&self, out: &mut impl Extend<u8>) {
        for xid in &self.xids {
            xid.encode_sized(out);
        }
    }

    pub fn encoded_len(&self) -> usize {
        self.xids
            .iter()
            .map(|xid| usize::from(xid.encoded_len()).saturating_add(1))
            .sum()
    }

    pub fn merge(&mut self, xid: &Xid) {
        match self
            .xids
            .binary_search_by(|probe| probe.namespace.cmp(&xid.namespace))
        {
            Ok(index) => {
                if let Some(current) = self.xids.get_mut(index)
                    && local_cmp(xid, current) == Ordering::Greater
                {
                    *current = xid.clone();
                }
            }
            Err(index) => self.xids.insert(index, xid.clone()),
        }
    }

    pub fn merge_pcl(&mut self, other: &Pcl) {
        for xid in &other.xids {
            self.merge(xid);
        }
    }

    pub fn includes(&self, other: &Pcl) -> bool {
        let mut mine = self.xids.iter().peekable();
        other.xids.iter().all(|theirs| {
            while mine
                .peek()
                .is_some_and(|candidate| candidate.namespace < theirs.namespace)
            {
                mine.next();
            }
            mine.peek().is_some_and(|candidate| {
                candidate.namespace == theirs.namespace
                    && local_cmp(candidate, theirs) != Ordering::Less
            })
        })
    }

    pub fn includes_xid(&self, xid: &Xid) -> bool {
        self.xids
            .binary_search_by(|probe| probe.namespace.cmp(&xid.namespace))
            .ok()
            .and_then(|index| self.xids.get(index))
            .is_some_and(|candidate| local_cmp(candidate, xid) != Ordering::Less)
    }

    pub fn compare(&self, other: &Pcl) -> PclOrder {
        if other.includes(self) {
            PclOrder::OlderOrEqual
        } else if self.includes(other) {
            PclOrder::Newer
        } else {
            PclOrder::Conflict
        }
    }
}

fn local_cmp(a: &Xid, b: &Xid) -> Ordering {
    let a = a.local_id();
    let b = b.local_id();
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ics/pcl/tests.rs"]
mod tests;
