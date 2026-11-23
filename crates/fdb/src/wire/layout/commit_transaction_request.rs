/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{
        Uid, transform,
        write::{self, Encode, Pos, Sink, TableSink},
    },
    wire::{CommitTransactionRequest, Dialect, KeyRange, Mutation, vt},
};

pub(crate) struct VtA {
    pub(crate) block: &'static [u8],
    pub(crate) key_range_ref: usize,
    pub(crate) mutation_ref: usize,
    pub(crate) commit_transaction_ref: usize,
    pub(crate) reply_promise: usize,
    pub(crate) tenant_info: usize,
    pub(crate) commit_transaction_request: usize,
    pub(crate) root: usize,
}

struct A<'r, ReadConflictRanges, WriteConflictRanges, Mutations> {
    m: &'r CommitTransactionRequest<ReadConflictRanges, WriteConflictRanges, Mutations>,
    reply: Uid,
    vt: &'static VtA,
}

impl<'a, ReadConflictRanges, WriteConflictRanges, Mutations> Encode
    for A<'_, ReadConflictRanges, WriteConflictRanges, Mutations>
where
    ReadConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    WriteConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    Mutations: Iterator<Item = Mutation<'a>> + ExactSizeIterator + Clone,
{
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        93948
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let items8 = m.read_conflict_ranges.clone();
            let mut vector9 = s.vector_begin(items8.len());
            for e2 in items8 {
                let (begin_3, end_4) = transform::single_key_range(e2.begin, e2.end);
                let b5 = s.bytes(begin_3);
                let b6 = s.bytes(end_4);
                let t7 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b5);
                    t.offset::<8>(b6);
                    t.end()
                };
                s.vector_item(&mut vector9, t7);
            }
            s.vector_end(vector9)
        };
        let v10 = {
            let items17 = m.write_conflict_ranges.clone();
            let mut vector18 = s.vector_begin(items17.len());
            for e11 in items17 {
                let (begin_12, end_13) = transform::single_key_range(e11.begin, e11.end);
                let b14 = s.bytes(begin_12);
                let b15 = s.bytes(end_13);
                let t16 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b14);
                    t.offset::<8>(b15);
                    t.end()
                };
                s.vector_item(&mut vector18, t16);
            }
            s.vector_end(vector18)
        };
        let v19 = {
            let items26 = m.mutations.clone();
            let mut vector27 = s.vector_begin(items26.len());
            for e20 in items26 {
                let (param1_21, param2_22) =
                    transform::single_key_clear(e20.kind, e20.param1, e20.param2);
                let b23 = s.bytes(param1_21);
                let b24 = s.bytes(param2_22);
                let t25 = {
                    let mut t = s.table::<13, 4>(vt.mutation_ref);
                    t.u8::<12>(e20.kind);
                    t.offset::<4>(b23);
                    t.offset::<8>(b24);
                    t.end()
                };
                s.vector_item(&mut vector27, t25);
            }
            s.vector_end(vector27)
        };
        let t28 = {
            let mut t = s.table::<31, 8>(vt.commit_transaction_ref);
            t.offset::<12>(v1);
            t.offset::<16>(v10);
            t.offset::<20>(v19);
            t.i64::<4>(m.read_snapshot);
            t.bool::<28>(m.report_conflicting_keys);
            t.bool::<29>(m.lock_aware);
            t.end()
        };
        let t29 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t30 = {
            let mut t = s.table::<17, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let t31 = {
            let mut t = s.table::<51, 8>(vt.commit_transaction_request);
            t.offset::<20>(t28);
            t.offset::<24>(t29);
            t.u32::<28>(m.flags);
            t.offset::<44>(t30);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t31);
        root.end()
    }
}

pub(crate) struct VtB {
    pub(crate) block: &'static [u8],
    pub(crate) key_range_ref: usize,
    pub(crate) mutation_ref: usize,
    pub(crate) commit_transaction_ref: usize,
    pub(crate) reply_promise: usize,
    pub(crate) span_context: usize,
    pub(crate) tenant_info: usize,
    pub(crate) commit_transaction_request: usize,
    pub(crate) root: usize,
}

struct B<'r, ReadConflictRanges, WriteConflictRanges, Mutations> {
    m: &'r CommitTransactionRequest<ReadConflictRanges, WriteConflictRanges, Mutations>,
    reply: Uid,
    vt: &'static VtB,
}

impl<'a, ReadConflictRanges, WriteConflictRanges, Mutations> Encode
    for B<'_, ReadConflictRanges, WriteConflictRanges, Mutations>
where
    ReadConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    WriteConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    Mutations: Iterator<Item = Mutation<'a>> + ExactSizeIterator + Clone,
{
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        93948
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let items8 = m.read_conflict_ranges.clone();
            let mut vector9 = s.vector_begin(items8.len());
            for e2 in items8 {
                let (begin_3, end_4) = transform::single_key_range(e2.begin, e2.end);
                let b5 = s.bytes(begin_3);
                let b6 = s.bytes(end_4);
                let t7 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b5);
                    t.offset::<8>(b6);
                    t.end()
                };
                s.vector_item(&mut vector9, t7);
            }
            s.vector_end(vector9)
        };
        let v10 = {
            let items17 = m.write_conflict_ranges.clone();
            let mut vector18 = s.vector_begin(items17.len());
            for e11 in items17 {
                let (begin_12, end_13) = transform::single_key_range(e11.begin, e11.end);
                let b14 = s.bytes(begin_12);
                let b15 = s.bytes(end_13);
                let t16 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b14);
                    t.offset::<8>(b15);
                    t.end()
                };
                s.vector_item(&mut vector18, t16);
            }
            s.vector_end(vector18)
        };
        let v19 = {
            let items26 = m.mutations.clone();
            let mut vector27 = s.vector_begin(items26.len());
            for e20 in items26 {
                let (param1_21, param2_22) =
                    transform::single_key_clear(e20.kind, e20.param1, e20.param2);
                let b23 = s.bytes(param1_21);
                let b24 = s.bytes(param2_22);
                let t25 = {
                    let mut t = s.table::<13, 4>(vt.mutation_ref);
                    t.u8::<12>(e20.kind);
                    t.offset::<4>(b23);
                    t.offset::<8>(b24);
                    t.end()
                };
                s.vector_item(&mut vector27, t25);
            }
            s.vector_end(vector27)
        };
        let t28 = {
            let mut t = s.table::<31, 8>(vt.commit_transaction_ref);
            t.offset::<12>(v1);
            t.offset::<16>(v10);
            t.offset::<20>(v19);
            t.i64::<4>(m.read_snapshot);
            t.bool::<28>(m.report_conflicting_keys);
            t.bool::<29>(m.lock_aware);
            t.end()
        };
        let t29 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t30 = s.table::<29, 8>(vt.span_context).end();
        let t31 = {
            let mut t = s.table::<22, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let b32 = s.bytes(&[]);
        let t33 = {
            let mut t = s.table::<43, 4>(vt.commit_transaction_request);
            t.offset::<4>(t28);
            t.offset::<8>(t29);
            t.u32::<12>(m.flags);
            t.offset::<28>(t30);
            t.offset::<32>(t31);
            t.offset::<36>(b32);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t33);
        root.end()
    }
}

struct C<'r, ReadConflictRanges, WriteConflictRanges, Mutations> {
    m: &'r CommitTransactionRequest<ReadConflictRanges, WriteConflictRanges, Mutations>,
    reply: Uid,
    vt: &'static VtB,
}

impl<'a, ReadConflictRanges, WriteConflictRanges, Mutations> Encode
    for C<'_, ReadConflictRanges, WriteConflictRanges, Mutations>
where
    ReadConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    WriteConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    Mutations: Iterator<Item = Mutation<'a>> + ExactSizeIterator + Clone,
{
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        93948
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let items8 = m.read_conflict_ranges.clone();
            let mut vector9 = s.vector_begin(items8.len());
            for e2 in items8 {
                let (begin_3, end_4) = transform::single_key_range(e2.begin, e2.end);
                let b5 = s.bytes(begin_3);
                let b6 = s.bytes(end_4);
                let t7 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b5);
                    t.offset::<8>(b6);
                    t.end()
                };
                s.vector_item(&mut vector9, t7);
            }
            s.vector_end(vector9)
        };
        let v10 = {
            let items17 = m.write_conflict_ranges.clone();
            let mut vector18 = s.vector_begin(items17.len());
            for e11 in items17 {
                let (begin_12, end_13) = transform::single_key_range(e11.begin, e11.end);
                let b14 = s.bytes(begin_12);
                let b15 = s.bytes(end_13);
                let t16 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b14);
                    t.offset::<8>(b15);
                    t.end()
                };
                s.vector_item(&mut vector18, t16);
            }
            s.vector_end(vector18)
        };
        let v19 = {
            let items26 = m.mutations.clone();
            let mut vector27 = s.vector_begin(items26.len());
            for e20 in items26 {
                let (param1_21, param2_22) =
                    transform::single_key_clear(e20.kind, e20.param1, e20.param2);
                let b23 = s.bytes(param1_21);
                let b24 = s.bytes(param2_22);
                let t25 = {
                    let mut t = s.table::<13, 4>(vt.mutation_ref);
                    t.u8::<12>(e20.kind);
                    t.offset::<4>(b23);
                    t.offset::<8>(b24);
                    t.end()
                };
                s.vector_item(&mut vector27, t25);
            }
            s.vector_end(vector27)
        };
        let t28 = {
            let mut t = s.table::<36, 8>(vt.commit_transaction_ref);
            t.offset::<12>(v1);
            t.offset::<16>(v10);
            t.offset::<20>(v19);
            t.i64::<4>(m.read_snapshot);
            t.bool::<32>(m.report_conflicting_keys);
            t.bool::<33>(m.lock_aware);
            t.end()
        };
        let t29 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t30 = s.table::<29, 8>(vt.span_context).end();
        let t31 = {
            let mut t = s.table::<17, 8>(vt.tenant_info);
            t.i64::<4>(-1);
            t.end()
        };
        let b32 = s.bytes(&[]);
        let t33 = {
            let mut t = s.table::<43, 4>(vt.commit_transaction_request);
            t.offset::<4>(t28);
            t.offset::<8>(t29);
            t.u32::<12>(m.flags);
            t.offset::<28>(t30);
            t.offset::<32>(t31);
            t.offset::<36>(b32);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t33);
        root.end()
    }
}

pub(crate) struct VtC {
    pub(crate) block: &'static [u8],
    pub(crate) key_range_ref: usize,
    pub(crate) mutation_ref: usize,
    pub(crate) commit_transaction_ref: usize,
    pub(crate) reply_promise: usize,
    pub(crate) span_context: usize,
    pub(crate) commit_transaction_request: usize,
    pub(crate) root: usize,
}

struct D<'r, ReadConflictRanges, WriteConflictRanges, Mutations> {
    m: &'r CommitTransactionRequest<ReadConflictRanges, WriteConflictRanges, Mutations>,
    reply: Uid,
    vt: &'static VtC,
}

impl<'a, ReadConflictRanges, WriteConflictRanges, Mutations> Encode
    for D<'_, ReadConflictRanges, WriteConflictRanges, Mutations>
where
    ReadConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    WriteConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    Mutations: Iterator<Item = Mutation<'a>> + ExactSizeIterator + Clone,
{
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        93948
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let items8 = m.read_conflict_ranges.clone();
            let mut vector9 = s.vector_begin(items8.len());
            for e2 in items8 {
                let (begin_3, end_4) = transform::single_key_range(e2.begin, e2.end);
                let b5 = s.bytes(begin_3);
                let b6 = s.bytes(end_4);
                let t7 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b5);
                    t.offset::<8>(b6);
                    t.end()
                };
                s.vector_item(&mut vector9, t7);
            }
            s.vector_end(vector9)
        };
        let v10 = {
            let items17 = m.write_conflict_ranges.clone();
            let mut vector18 = s.vector_begin(items17.len());
            for e11 in items17 {
                let (begin_12, end_13) = transform::single_key_range(e11.begin, e11.end);
                let b14 = s.bytes(begin_12);
                let b15 = s.bytes(end_13);
                let t16 = {
                    let mut t = s.table::<12, 4>(vt.key_range_ref);
                    t.offset::<4>(b14);
                    t.offset::<8>(b15);
                    t.end()
                };
                s.vector_item(&mut vector18, t16);
            }
            s.vector_end(vector18)
        };
        let v19 = {
            let items26 = m.mutations.clone();
            let mut vector27 = s.vector_begin(items26.len());
            for e20 in items26 {
                let (param1_21, param2_22) =
                    transform::single_key_clear(e20.kind, e20.param1, e20.param2);
                let b23 = s.bytes(param1_21);
                let b24 = s.bytes(param2_22);
                let t25 = {
                    let mut t = s.table::<13, 4>(vt.mutation_ref);
                    t.u8::<12>(e20.kind);
                    t.offset::<4>(b23);
                    t.offset::<8>(b24);
                    t.end()
                };
                s.vector_item(&mut vector27, t25);
            }
            s.vector_end(vector27)
        };
        let t28 = {
            let mut t = s.table::<36, 8>(vt.commit_transaction_ref);
            t.offset::<12>(v1);
            t.offset::<16>(v10);
            t.offset::<20>(v19);
            t.i64::<4>(m.read_snapshot);
            t.bool::<32>(m.report_conflicting_keys);
            t.bool::<33>(m.lock_aware);
            t.end()
        };
        let t29 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let t30 = s.table::<29, 8>(vt.span_context).end();
        let b31 = s.bytes(&[]);
        let t32 = {
            let mut t = s.table::<39, 4>(vt.commit_transaction_request);
            t.offset::<4>(t28);
            t.offset::<8>(t29);
            t.u32::<12>(m.flags);
            t.offset::<28>(t30);
            t.offset::<32>(b31);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t32);
        root.end()
    }
}

impl<'a, ReadConflictRanges, WriteConflictRanges, Mutations>
    CommitTransactionRequest<ReadConflictRanges, WriteConflictRanges, Mutations>
where
    ReadConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    WriteConflictRanges: Iterator<Item = KeyRange<'a>> + ExactSizeIterator + Clone,
    Mutations: Iterator<Item = Mutation<'a>> + ExactSizeIterator + Clone,
{
    pub fn encode(&self, dialect: Dialect, reply: Uid, out: &mut Vec<u8>) -> usize {
        match dialect {
            Dialect::V71 => write::encode(
                &A {
                    m: self,
                    reply,
                    vt: &vt::COMMIT_TRANSACTION_REQUEST_V71,
                },
                out,
            ),
            Dialect::V72 => write::encode(
                &B {
                    m: self,
                    reply,
                    vt: &vt::COMMIT_TRANSACTION_REQUEST_V72,
                },
                out,
            ),
            Dialect::V73 | Dialect::V74 => write::encode(
                &C {
                    m: self,
                    reply,
                    vt: &vt::COMMIT_TRANSACTION_REQUEST_V73,
                },
                out,
            ),
            Dialect::V80 => write::encode(
                &D {
                    m: self,
                    reply,
                    vt: &vt::COMMIT_TRANSACTION_REQUEST_V80,
                },
                out,
            ),
        }
    }
}
