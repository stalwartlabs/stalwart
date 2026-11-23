/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::write::{self, Encode, Pos, Sink, TableSink},
    wire::{AcknowledgementReply, Dialect, vt},
};

pub(crate) struct VtA {
    pub(crate) block: &'static [u8],
    pub(crate) acknowledgement_reply: usize,
    pub(crate) root: usize,
}

struct A<'r> {
    m: &'r AcknowledgementReply,
    vt: &'static VtA,
}

impl Encode for A<'_> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        34944361
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let vt = self.vt;
        let t1 = {
            let mut t = s.table::<12, 8>(vt.acknowledgement_reply);
            t.i64::<4>(m.bytes);
            t.end()
        };
        let mut root = s.table::<9, 4>(vt.root);
        root.union::<8, 4>(Some((2, t1)));
        root.end()
    }
}

impl AcknowledgementReply {
    pub fn encode(&self, dialect: Dialect, out: &mut Vec<u8>) -> usize {
        match dialect {
            Dialect::V71 | Dialect::V72 | Dialect::V73 | Dialect::V74 | Dialect::V80 => {
                write::encode(
                    &A {
                        m: self,
                        vt: &vt::ACKNOWLEDGEMENT_REPLY_V71,
                    },
                    out,
                )
            }
        }
    }
}
