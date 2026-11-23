/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::eid::{Globcnt, ReplGuid};
use crate::common::Guid;

const MAX_LOCAL_ID: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Xid {
    pub namespace: Guid,
    local: [u8; MAX_LOCAL_ID],
    local_len: u8,
}

impl Xid {
    pub fn new(namespace: Guid, local_id: &[u8]) -> Option<Self> {
        if local_id.is_empty() {
            return None;
        }
        let mut local = [0u8; MAX_LOCAL_ID];
        local.get_mut(..local_id.len())?.copy_from_slice(local_id);
        Some(Xid {
            namespace,
            local,
            local_len: u8::try_from(local_id.len()).ok()?,
        })
    }

    pub fn from_cn(guid: ReplGuid, cn: Globcnt) -> Self {
        let [c0, c1, c2, c3, c4, c5] = cn.to_wire();
        Xid {
            namespace: guid.0,
            local: [c0, c1, c2, c3, c4, c5, 0, 0],
            local_len: 6,
        }
    }

    pub fn local_id(&self) -> &[u8] {
        self.local
            .get(..usize::from(self.local_len))
            .unwrap_or_default()
    }

    pub fn encoded_len(&self) -> u8 {
        self.local_len.saturating_add(16)
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let (namespace, local_id) = b.split_first_chunk::<16>()?;
        Self::new(Guid(*namespace), local_id)
    }

    pub fn encode(&self, out: &mut impl Extend<u8>) {
        out.extend(self.namespace.as_bytes().iter().copied());
        out.extend(self.local_id().iter().copied());
    }

    pub fn encode_sized(&self, out: &mut impl Extend<u8>) {
        out.extend([self.encoded_len()]);
        self.encode(out);
    }
}
