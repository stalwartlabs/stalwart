/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::resource::Resource;
use crate::proto::{SliceCursor, varint_len, writer::ProtoWriter};
use bytes::{Buf, Bytes, BytesMut};

pub const GRPC_PREFIX_LEN: usize = 5;
const MAX_LEN_VARINT: usize = 5;
const TAG_RESOURCE_ITEMS: u8 = 0x0a;
const TAG_SCOPE_ITEMS: u8 = 0x12;
const MIN_REQUEST_CAPACITY: usize = 4096;
const HEADROOM_SHIFT: u32 = 6;
const MIN_COMPACT_SLACK: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Http,
    Grpc,
}

pub struct RequestBuilder {
    w: ProtoWriter,
    gap: usize,
    records: usize,
    last_start: usize,
    records_end: usize,
    framing: Framing,
    capacity_hint: usize,
}

pub struct SealedRequest {
    pub body: Bytes,
    pub records: usize,
    pub capacity: usize,
}

impl RequestBuilder {
    pub fn new(resource: &Resource, framing: Framing) -> Self {
        let gap = GRPC_PREFIX_LEN
            + 1
            + MAX_LEN_VARINT
            + resource.resource.len()
            + 1
            + MAX_LEN_VARINT
            + resource.scope.len();
        let mut builder = Self {
            w: ProtoWriter::with_capacity(0),
            gap,
            records: 0,
            last_start: gap,
            records_end: gap,
            framing,
            capacity_hint: MIN_REQUEST_CAPACITY,
        };
        builder.reset();
        builder
    }

    fn reset(&mut self) {
        let capacity = self.capacity_hint + (self.capacity_hint >> HEADROOM_SHIFT);
        self.w = ProtoWriter::with_capacity(capacity.max(self.gap + MIN_REQUEST_CAPACITY));
        self.w.inner_mut().resize(self.gap, 0);
        self.records = 0;
        self.last_start = self.gap;
        self.records_end = self.gap;
    }

    #[inline(always)]
    pub fn writer(&mut self) -> &mut ProtoWriter {
        &mut self.w
    }

    #[inline(always)]
    pub fn commit(&mut self) {
        self.records += 1;
        self.last_start = self.records_end;
        self.records_end = self.w.len();
    }

    #[inline(always)]
    pub fn records(&self) -> usize {
        self.records
    }

    #[inline(always)]
    pub fn body_len_bound(&self) -> usize {
        self.w.len()
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.w.capacity()
    }

    pub fn discard(&mut self) {
        self.w.inner_mut().truncate(self.gap);
        self.records = 0;
        self.last_start = self.gap;
        self.records_end = self.gap;
    }

    pub fn seal(&mut self, resource: &Resource) -> Option<SealedRequest> {
        if self.records == 0 {
            return None;
        }
        let records = self.records;
        let buf = self.take_buffer();
        self.capacity_hint = buf.len();
        self.reset();
        Some(self.finish(buf, resource, records))
    }

    pub fn seal_before_last(&mut self, resource: &Resource) -> Option<SealedRequest> {
        if self.records < 2 {
            return None;
        }
        let records = self.records - 1;
        let last_start = self.last_start;
        let mut buf = self.take_buffer();
        self.capacity_hint = last_start;
        self.reset();
        if let Some(last) = buf.get(last_start..) {
            self.w.raw(last);
            self.commit();
        }
        buf.truncate(last_start);
        Some(self.finish(buf, resource, records))
    }

    fn take_buffer(&mut self) -> BytesMut {
        std::mem::replace(&mut self.w, ProtoWriter::with_capacity(0)).into_inner()
    }

    fn finish(&self, mut buf: BytesMut, resource: &Resource, records: usize) -> SealedRequest {
        let records_len = buf.len() - self.gap;
        let scope_items_len = resource.scope.len() + records_len;
        let resource_items_len =
            resource.resource.len() + 1 + varint_len(scope_items_len as u64) + scope_items_len;
        let header_len = 1
            + varint_len(resource_items_len as u64)
            + resource.resource.len()
            + 1
            + varint_len(scope_items_len as u64)
            + resource.scope.len();
        let header_start = self.gap - header_len;
        let message_len = (buf.len() - header_start) as u32;

        let start = match self.framing {
            Framing::Http => header_start,
            Framing::Grpc => header_start - GRPC_PREFIX_LEN,
        };
        if let Some(header) = buf.get_mut(start..self.gap) {
            let mut cursor = SliceCursor::new(header);
            if self.framing == Framing::Grpc {
                cursor.put(&[0]);
                cursor.put(&message_len.to_be_bytes());
            }
            cursor.put(&[TAG_RESOURCE_ITEMS]);
            cursor.put_varint(resource_items_len as u64);
            cursor.put(&resource.resource);
            cursor.put(&[TAG_SCOPE_ITEMS]);
            cursor.put_varint(scope_items_len as u64);
            cursor.put(&resource.scope);
        }

        let slack = buf.capacity() - buf.len();
        if slack > buf.len().max(MIN_COMPACT_SLACK) {
            let body = Bytes::copy_from_slice(buf.get(start..).unwrap_or_default());
            return SealedRequest {
                capacity: body.len(),
                body,
                records,
            };
        }
        let capacity = buf.capacity();
        let mut body = buf.freeze();
        body.advance(start);
        SealedRequest {
            body,
            records,
            capacity,
        }
    }
}
