/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{
        Uid,
        write::{self, Encode, Pos, Sink, TableSink},
    },
    wire::{Dialect, PingRequest, vt},
};

pub(crate) struct VtA {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) ping_request: usize,
    pub(crate) root: usize,
}

struct A {
    reply: Uid,
    vt: &'static VtA,
}

impl Encode for A {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        4707015
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let reply = self.reply;
        let vt = self.vt;
        let t1 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t2 = {
            let mut t = s.table::<8, 4>(vt.ping_request);
            t.offset::<4>(t1);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t2);
        root.end()
    }
}

impl PingRequest {
    pub fn encode(&self, dialect: Dialect, reply: Uid, out: &mut Vec<u8>) -> usize {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                write::encode(
                    &A {
                        reply,
                        vt: &vt::PING_REQUEST_V71,
                    },
                    out,
                )
            }
        }
    }
}
