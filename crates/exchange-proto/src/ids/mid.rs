/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::eid::{Eid, Fid, Mid};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerIdValue<'a> {
    Ours { fid: Fid, mid: Mid, instance: u32 },
    Client(&'a [u8]),
}

const OURS: u8 = 0x01;
const CLIENT: u8 = 0x00;
const OURS_LEN: usize = 21;

impl<'a> ServerIdValue<'a> {
    pub fn decode(b: &'a [u8]) -> Option<Self> {
        match b.split_first()? {
            (&OURS, rest) => {
                let (fid, rest) = rest.split_first_chunk::<8>()?;
                let (mid, rest) = rest.split_first_chunk::<8>()?;
                let instance: [u8; 4] = rest.try_into().ok()?;
                Some(ServerIdValue::Ours {
                    fid: Eid::from_wire(*fid),
                    mid: Eid::from_wire(*mid),
                    instance: u32::from_le_bytes(instance),
                })
            }
            (&CLIENT, rest) => Some(ServerIdValue::Client(rest)),
            _ => None,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            ServerIdValue::Ours { fid, mid, instance } => {
                out.reserve(OURS_LEN);
                out.push(OURS);
                out.extend_from_slice(&fid.to_wire());
                out.extend_from_slice(&mid.to_wire());
                out.extend_from_slice(&instance.to_le_bytes());
            }
            ServerIdValue::Client(data) => {
                out.reserve(data.len().saturating_add(1));
                out.push(CLIENT);
                out.extend_from_slice(data);
            }
        }
    }
}
