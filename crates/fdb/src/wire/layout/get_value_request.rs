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
    wire::{Dialect, GetValueRequest, vt},
};

pub(crate) struct VtA {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) tenant_info: usize,
    pub(crate) version_vector: usize,
    pub(crate) get_value_request: usize,
    pub(crate) root: usize,
}

struct A<'r, 'a> {
    m: &'r GetValueRequest<'a>,
    reply: Uid,
    vt: &'static VtA,
}

impl<'a> Encode for A<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        8454530
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.key);
        let t2 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t3 = {
            let mut t = s.table::<17, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let v4 = {
            let vector = s.vector_begin(0);
            s.vector_end(vector)
        };
        let t5 = {
            let mut t = s.table::<16, 8>(vt.version_vector);
            t.offset::<12>(v4);
            t.i64::<4>(-1);
            t.end()
        };
        let t6 = {
            let mut t = s.table::<54, 8>(vt.get_value_request);
            t.offset::<28>(b1);
            t.i64::<20>(m.version);
            t.offset::<40>(t2);
            t.offset::<44>(t3);
            t.offset::<48>(t5);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t6);
        root.end()
    }
}

pub(crate) struct VtB {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) span_context: usize,
    pub(crate) tenant_info: usize,
    pub(crate) get_value_request: usize,
    pub(crate) root: usize,
}

struct B<'r, 'a> {
    m: &'r GetValueRequest<'a>,
    reply: Uid,
    vt: &'static VtB,
}

impl<'a> Encode for B<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        8454530
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.key);
        let t2 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t3 = s.table::<29, 8>(vt.span_context).end();
        let t4 = {
            let mut t = s.table::<22, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let b5 = s.bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
        ]);
        let t6 = {
            let mut t = s.table::<42, 8>(vt.get_value_request);
            t.offset::<12>(b1);
            t.i64::<4>(m.version);
            t.offset::<20>(t2);
            t.offset::<24>(t3);
            t.offset::<28>(t4);
            t.offset::<36>(b5);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t6);
        root.end()
    }
}

struct C<'r, 'a> {
    m: &'r GetValueRequest<'a>,
    reply: Uid,
    vt: &'static VtB,
}

impl<'a> Encode for C<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        8454530
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.key);
        let t2 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t3 = s.table::<29, 8>(vt.span_context).end();
        let t4 = {
            let mut t = s.table::<17, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let b5 = s.bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
        ]);
        let t6 = {
            let mut t = s.table::<42, 8>(vt.get_value_request);
            t.offset::<12>(b1);
            t.i64::<4>(m.version);
            t.offset::<20>(t2);
            t.offset::<24>(t3);
            t.offset::<28>(t4);
            t.offset::<36>(b5);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t6);
        root.end()
    }
}

pub(crate) struct VtC {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) span_context: usize,
    pub(crate) get_value_request: usize,
    pub(crate) root: usize,
}

struct D<'r, 'a> {
    m: &'r GetValueRequest<'a>,
    reply: Uid,
    vt: &'static VtC,
}

impl<'a> Encode for D<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        8454530
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.key);
        let t2 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t3 = s.table::<29, 8>(vt.span_context).end();
        let b4 = s.bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
        ]);
        let t5 = {
            let mut t = s.table::<38, 8>(vt.get_value_request);
            t.offset::<12>(b1);
            t.i64::<4>(m.version);
            t.offset::<20>(t2);
            t.offset::<24>(t3);
            t.offset::<32>(b4);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t5);
        root.end()
    }
}

impl<'a> GetValueRequest<'a> {
    pub fn encode(&self, dialect: Dialect, reply: Uid, out: &mut Vec<u8>) -> usize {
        match dialect {
            Dialect::V71 => write::encode(
                &A {
                    m: self,
                    reply,
                    vt: &vt::GET_VALUE_REQUEST_V71,
                },
                out,
            ),
            Dialect::V72 => write::encode(
                &B {
                    m: self,
                    reply,
                    vt: &vt::GET_VALUE_REQUEST_V72,
                },
                out,
            ),
            Dialect::V73 | Dialect::V74 => write::encode(
                &C {
                    m: self,
                    reply,
                    vt: &vt::GET_VALUE_REQUEST_V73,
                },
                out,
            ),
            Dialect::V80 => write::encode(
                &D {
                    m: self,
                    reply,
                    vt: &vt::GET_VALUE_REQUEST_V80,
                },
                out,
            ),
        }
    }
}
