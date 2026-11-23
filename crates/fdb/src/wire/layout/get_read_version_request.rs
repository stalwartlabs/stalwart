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
    wire::{Dialect, GetReadVersionRequest, vt},
};

pub(crate) struct VtA {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) get_read_version_request: usize,
    pub(crate) root: usize,
}

struct A<'r> {
    m: &'r GetReadVersionRequest,
    reply: Uid,
    vt: &'static VtA,
}

impl Encode for A<'_> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        838566
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let vector = s.vector_begin(0);
            s.vector_end(vector)
        };
        let t2 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t3 = {
            let mut t = s.table::<49, 8>(vt.get_read_version_request);
            t.u32::<28>(m.transaction_count);
            t.u32::<32>(m.flags);
            t.offset::<36>(v1);
            t.offset::<44>(t2);
            t.i64::<20>(-1);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t3);
        root.end()
    }
}

pub(crate) struct VtB {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) span_context: usize,
    pub(crate) get_read_version_request: usize,
    pub(crate) root: usize,
}

struct B<'r> {
    m: &'r GetReadVersionRequest,
    reply: Uid,
    vt: &'static VtB,
}

impl Encode for B<'_> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        838566
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let vector = s.vector_begin(0);
            s.vector_end(vector)
        };
        let t2 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t3 = s.table::<29, 8>(vt.span_context).end();
        let t4 = {
            let mut t = s.table::<37, 8>(vt.get_read_version_request);
            t.u32::<12>(m.transaction_count);
            t.u32::<16>(m.flags);
            t.offset::<20>(v1);
            t.offset::<28>(t2);
            t.offset::<32>(t3);
            t.i64::<4>(-1);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t4);
        root.end()
    }
}

struct C<'r> {
    m: &'r GetReadVersionRequest,
    reply: Uid,
    vt: &'static VtB,
}

impl Encode for C<'_> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        838566
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let vector = s.vector_begin(0);
            s.vector_end(vector)
        };
        let t2 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t3 = s.table::<29, 8>(vt.span_context).end();
        let t4 = {
            let mut t = s.table::<42, 8>(vt.get_read_version_request);
            t.u32::<12>(m.transaction_count);
            t.u32::<16>(m.flags);
            t.offset::<20>(v1);
            t.offset::<28>(t2);
            t.offset::<32>(t3);
            t.i64::<4>(-1);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t4);
        root.end()
    }
}

impl GetReadVersionRequest {
    pub fn encode(&self, dialect: Dialect, reply: Uid, out: &mut Vec<u8>) -> usize {
        match dialect {
            Dialect::V71 => write::encode(
                &A {
                    m: self,
                    reply,
                    vt: &vt::GET_READ_VERSION_REQUEST_V71,
                },
                out,
            ),
            Dialect::V72 | Dialect::V73 | Dialect::V74 => write::encode(
                &B {
                    m: self,
                    reply,
                    vt: &vt::GET_READ_VERSION_REQUEST_V72,
                },
                out,
            ),
            Dialect::V80 => write::encode(
                &C {
                    m: self,
                    reply,
                    vt: &vt::GET_READ_VERSION_REQUEST_V80,
                },
                out,
            ),
        }
    }
}
