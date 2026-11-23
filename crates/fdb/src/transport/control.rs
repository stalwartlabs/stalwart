/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::codec::{Uid, read};

pub(crate) const ENDPOINT_NOT_FOUND: Uid = Uid::well_known(0);
pub(crate) const PING: Uid = Uid::well_known(1);
pub(crate) const UNAUTHORIZED_ENDPOINT: Uid = Uid::well_known(2);

const PING_REQUEST_FILE_ID: u32 = 4707015;
const UID_FILE_ID: u32 = 15597147;

const PING_REQUEST_PREFIX: [u8; 40] = [
    0x14, 0x00, 0x00, 0x00, 0xc7, 0xd2, 0x47, 0x00, 0x06, 0x00, 0x08, 0x00, 0x04, 0x00, 0x06, 0x00,
    0x14, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
];

pub(crate) const VOID_REPLY: [u8; 48] = [
    0x20, 0x00, 0x00, 0x00, 0x4a, 0xad, 0x1e, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x06, 0x00, 0x06, 0x00, 0x04, 0x00, 0x08, 0x00, 0x09, 0x00, 0x08, 0x00, 0x04, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00,
];

pub(crate) fn encode_ping_request(reply: Uid, out: &mut Vec<u8>) {
    out.extend_from_slice(&PING_REQUEST_PREFIX);
    out.extend_from_slice(&reply.to_le_bytes());
}

pub(crate) fn ping_reply_token(message: &[u8]) -> Option<Uid> {
    let request = read::root(message, PING_REQUEST_FILE_ID).ok()?;
    let reply = request.table(0).ok()??.table(0).ok()??;
    reply.uid(0).ok().filter(|token| *token != Uid::ZERO)
}

pub(crate) fn uid_message(message: &[u8]) -> Option<Uid> {
    read::root(message, UID_FILE_ID)
        .ok()?
        .uid(0)
        .ok()
        .filter(|token| *token != Uid::ZERO)
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/transport/control/tests.rs"]
mod tests;
