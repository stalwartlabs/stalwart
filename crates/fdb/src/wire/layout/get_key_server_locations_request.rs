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
    wire::{Dialect, GetKeyServerLocationsRequest, vt},
};

pub(crate) struct VtA {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) get_key_server_locations_request: usize,
    pub(crate) root: usize,
}

struct A<'r, 'a> {
    m: &'r GetKeyServerLocationsRequest<'a>,
    reply: Uid,
    vt: &'static VtA,
}

impl<'a> Encode for A<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        9144680
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.begin);
        let o3 = m.end.map(|x2| s.bytes(x2));
        let t4 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t5 = {
            let mut t = s.table::<51, 8>(vt.get_key_server_locations_request);
            t.offset::<28>(b1);
            t.optional::<48, 32>(o3);
            t.i32::<36>(m.limit);
            t.bool::<49>(m.reverse);
            t.offset::<40>(t4);
            t.i64::<20>(m.version);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t5);
        root.end()
    }
}

pub(crate) struct VtB {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) span_context: usize,
    pub(crate) tenant_info: usize,
    pub(crate) get_key_server_locations_request: usize,
    pub(crate) root: usize,
}

struct B<'r, 'a> {
    m: &'r GetKeyServerLocationsRequest<'a>,
    reply: Uid,
    vt: &'static VtB,
}

impl<'a> Encode for B<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        9144680
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.begin);
        let o3 = m.end.map(|x2| s.bytes(x2));
        let t4 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t5 = s.table::<29, 8>(vt.span_context).end();
        let t6 = {
            let mut t = s.table::<22, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let t7 = {
            let mut t = s.table::<38, 8>(vt.get_key_server_locations_request);
            t.offset::<12>(b1);
            t.optional::<36, 16>(o3);
            t.i32::<20>(m.limit);
            t.bool::<37>(m.reverse);
            t.offset::<24>(t4);
            t.offset::<28>(t5);
            t.offset::<32>(t6);
            t.i64::<4>(m.version);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t7);
        root.end()
    }
}

struct C<'r, 'a> {
    m: &'r GetKeyServerLocationsRequest<'a>,
    reply: Uid,
    vt: &'static VtB,
}

impl<'a> Encode for C<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        9144680
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.begin);
        let o3 = m.end.map(|x2| s.bytes(x2));
        let t4 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t5 = s.table::<29, 8>(vt.span_context).end();
        let t6 = {
            let mut t = s.table::<17, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let t7 = {
            let mut t = s.table::<38, 8>(vt.get_key_server_locations_request);
            t.offset::<12>(b1);
            t.optional::<36, 16>(o3);
            t.i32::<20>(m.limit);
            t.bool::<37>(m.reverse);
            t.offset::<24>(t4);
            t.offset::<28>(t5);
            t.offset::<32>(t6);
            t.i64::<4>(m.version);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t7);
        root.end()
    }
}

pub(crate) struct VtC {
    pub(crate) block: &'static [u8],
    pub(crate) reply_promise: usize,
    pub(crate) span_context: usize,
    pub(crate) get_key_server_locations_request: usize,
    pub(crate) root: usize,
}

struct D<'r, 'a> {
    m: &'r GetKeyServerLocationsRequest<'a>,
    reply: Uid,
    vt: &'static VtC,
}

impl<'a> Encode for D<'_, 'a> {
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        9144680
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let b1 = s.bytes(m.begin);
        let o3 = m.end.map(|x2| s.bytes(x2));
        let t4 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t5 = s.table::<29, 8>(vt.span_context).end();
        let t6 = {
            let mut t = s.table::<34, 8>(vt.get_key_server_locations_request);
            t.offset::<12>(b1);
            t.optional::<32, 16>(o3);
            t.i32::<20>(m.limit);
            t.bool::<33>(m.reverse);
            t.offset::<24>(t4);
            t.offset::<28>(t5);
            t.i64::<4>(m.version);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t6);
        root.end()
    }
}

impl<'a> GetKeyServerLocationsRequest<'a> {
    pub fn encode(&self, dialect: Dialect, reply: Uid, out: &mut Vec<u8>) -> usize {
        match dialect {
            Dialect::V71 => write::encode(
                &A {
                    m: self,
                    reply,
                    vt: &vt::GET_KEY_SERVER_LOCATIONS_REQUEST_V71,
                },
                out,
            ),
            Dialect::V72 => write::encode(
                &B {
                    m: self,
                    reply,
                    vt: &vt::GET_KEY_SERVER_LOCATIONS_REQUEST_V72,
                },
                out,
            ),
            Dialect::V73 | Dialect::V74 => write::encode(
                &C {
                    m: self,
                    reply,
                    vt: &vt::GET_KEY_SERVER_LOCATIONS_REQUEST_V73,
                },
                out,
            ),
            Dialect::V80 => write::encode(
                &D {
                    m: self,
                    reply,
                    vt: &vt::GET_KEY_SERVER_LOCATIONS_REQUEST_V80,
                },
                out,
            ),
        }
    }
}
