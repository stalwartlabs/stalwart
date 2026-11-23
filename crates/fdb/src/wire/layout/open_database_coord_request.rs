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
    wire::{Dialect, Hostname, IpAddressValue, NetworkAddress, OpenDatabaseCoordRequest, vt},
};

pub(crate) struct VtA {
    pub(crate) block: &'static [u8],
    pub(crate) ipaddress: usize,
    pub(crate) network_address: usize,
    pub(crate) reply_promise: usize,
    pub(crate) hostname: usize,
    pub(crate) open_database_coord_request: usize,
    pub(crate) root: usize,
}

struct A<'r, 'a, Coordinators, Hostnames> {
    m: &'r OpenDatabaseCoordRequest<'a, Coordinators, Hostnames>,
    reply: Uid,
    vt: &'static VtA,
}

impl<'a, Coordinators, Hostnames> Encode for A<'_, 'a, Coordinators, Hostnames>
where
    Coordinators: Iterator<Item = NetworkAddress> + ExactSizeIterator + Clone,
    Hostnames: Iterator<Item = Hostname<'a>> + ExactSizeIterator + Clone,
{
    fn vtables(&self) -> &'static [u8] {
        self.vt.block
    }

    fn file_identifier(&self) -> u32 {
        214728
    }

    fn layout<S: Sink>(&self, s: &mut S) -> Pos {
        let m = self.m;
        let reply = self.reply;
        let vt = self.vt;
        let v1 = {
            let vector = s.vector_begin(0);
            s.vector_end(vector)
        };
        let v2 = {
            let vector = s.vector_begin(0);
            s.vector_end(vector)
        };
        let b3 = s.bytes(b"default");
        let b4 = s.bytes(m.cluster_key);
        let v5 = {
            let items11 = m.coordinators.clone();
            let mut vector12 = s.vector_begin(items11.len());
            for e6 in items11 {
                let alt8 = match &e6.ip.addr {
                    IpAddressValue::V4(x7) => (1, s.scalar::<4>(x7.to_le_bytes())),
                    IpAddressValue::V6(x7) => {
                        (2, s.scalar_vector::<1, 4>(16, x7.iter().map(|b| [*b])))
                    }
                };
                let t9 = {
                    let mut t = s.table::<9, 4>(vt.ipaddress);
                    t.union::<8, 4>(Some(alt8));
                    t.end()
                };
                let t10 = {
                    let mut t = s.table::<13, 4>(vt.network_address);
                    t.offset::<4>(t9);
                    t.u16::<8>(e6.port);
                    t.u16::<10>(e6.flags);
                    t.bool::<12>(e6.from_hostname);
                    t.end()
                };
                s.vector_item(&mut vector12, t10);
            }
            s.vector_end(vector12)
        };
        let t13 = {
            let mut t = s.table::<20, 8>(vt.reply_promise);
            t.uid::<4>(reply);
            t.end()
        };
        let v14 = {
            let items19 = m.hostnames.clone();
            let mut vector20 = s.vector_begin(items19.len());
            for e15 in items19 {
                let b16 = s.bytes(e15.host);
                let b17 = s.bytes(e15.service);
                let t18 = {
                    let mut t = s.table::<13, 4>(vt.hostname);
                    t.offset::<4>(b16);
                    t.offset::<8>(b17);
                    t.bool::<12>(e15.is_tls);
                    t.end()
                };
                s.vector_item(&mut vector20, t18);
            }
            s.vector_end(vector20)
        };
        let t21 = {
            let mut t = s.table::<49, 8>(vt.open_database_coord_request);
            t.offset::<20>(v1);
            t.offset::<24>(v2);
            t.offset::<28>(b3);
            t.uid::<4>(m.known_client_info_id);
            t.offset::<32>(b4);
            t.offset::<36>(v5);
            t.offset::<40>(t13);
            t.offset::<44>(v14);
            t.end()
        };
        let mut root = s.table::<8, 4>(vt.root);
        root.offset::<4>(t21);
        root.end()
    }
}

impl<'a, Coordinators, Hostnames> OpenDatabaseCoordRequest<'a, Coordinators, Hostnames>
where
    Coordinators: Iterator<Item = NetworkAddress> + ExactSizeIterator + Clone,
    Hostnames: Iterator<Item = Hostname<'a>> + ExactSizeIterator + Clone,
{
    pub fn encode(&self, dialect: Dialect, reply: Uid, out: &mut Vec<u8>) -> usize {
        match dialect {
            Dialect::V71 | Dialect::V72 => write::encode(
                &A {
                    m: self,
                    reply,
                    vt: &vt::OPEN_DATABASE_COORD_REQUEST_V71,
                },
                out,
            ),
            Dialect::V73 | Dialect::V74 | Dialect::V80 => write::encode(
                &A {
                    m: self,
                    reply,
                    vt: &vt::OPEN_DATABASE_COORD_REQUEST_V73,
                },
                out,
            ),
        }
    }
}
