/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::codec::{
    CHUNK_TARGET_BYTES, Reader, SearchDocId, WAL_ADDS, WAL_TOMBSTONES, WAL_VALUE_LIMIT, push_term,
};
use utils::{cheeky_hash::CheekyHash, codec::leb128::Leb128Vec, snowflake::SnowflakeIdGenerator};

pub(crate) struct ChunkBuilder<Id: SearchDocId> {
    pub buf: Vec<u8>,
    pub first_document_id: Id,
    prev: Id,
}

impl<Id: SearchDocId> ChunkBuilder<Id> {
    pub fn new() -> Self {
        ChunkBuilder {
            buf: Vec::new(),
            first_document_id: Id::ZERO,
            prev: Id::ZERO,
        }
    }

    pub fn push(&mut self, document_id: Id, payload: &[u8]) -> Option<(Id, Vec<u8>)> {
        if self.buf.is_empty() {
            self.first_document_id = document_id;
            Id::write_delta(&mut self.buf, Id::ZERO);
        } else {
            Id::write_delta(&mut self.buf, document_id.delta_since(self.prev));
        }
        self.prev = document_id;
        self.buf.extend_from_slice(payload);
        if self.buf.len() >= CHUNK_TARGET_BYTES {
            let first_document_id = self.first_document_id;
            Some((first_document_id, std::mem::take(&mut self.buf)))
        } else {
            None
        }
    }

    pub fn finish(self) -> Option<(Id, Vec<u8>)> {
        if !self.buf.is_empty() {
            Some((self.first_document_id, self.buf))
        } else {
            None
        }
    }
}

pub(crate) fn walk_chunk<Id: SearchDocId>(
    first_document_id: Id,
    value: &[u8],
    mut cb: impl FnMut(Id, &[u8]) -> bool,
) -> Option<()> {
    let mut reader = Reader::new(value);
    let mut document_id = first_document_id;
    while !reader.is_empty() {
        document_id = document_id.add_delta(Id::read_delta(&mut reader)?)?;
        if !cb(document_id, Id::read_payload(&mut reader)?) {
            return Some(());
        }
    }
    Some(())
}

pub(crate) struct WalWriter<Id: SearchDocId> {
    op: u8,
    buf: Vec<u8>,
    entries: Vec<u8>,
    entry_count: u32,
    document_id: Id,
    pub values: Vec<(u64, Vec<u8>)>,
}

impl<Id: SearchDocId> WalWriter<Id> {
    pub fn new(op: u8) -> Self {
        WalWriter {
            op,
            buf: vec![op],
            entries: Vec::new(),
            entry_count: 0,
            document_id: Id::ZERO,
            values: Vec::new(),
        }
    }

    pub fn begin_document(&mut self, document_id: Id) {
        self.document_id = document_id;
        self.entry_count = 0;
        self.entries.clear();
    }

    pub fn push_entry(&mut self, entry: impl FnOnce(&mut Vec<u8>)) {
        let start = self.entries.len();
        entry(&mut self.entries);
        if self.entries.len() + 16 > WAL_VALUE_LIMIT {
            let tail = self.entries.split_off(start);
            self.end_document();
            self.entries = tail;
            self.entry_count = 1;
        } else {
            self.entry_count += 1;
        }
    }

    pub fn end_document(&mut self) {
        if self.entry_count == 0 {
            return;
        }
        let record_len = self.entries.len() + Id::WAL_DOCUMENT_OVERHEAD;
        if self.buf.len() > 1 && self.buf.len() + record_len > WAL_VALUE_LIMIT {
            self.flush_value();
        }
        Id::write_wal_id(&mut self.buf, self.document_id);
        self.buf.push_leb128(self.entry_count);
        self.buf.extend_from_slice(&self.entries);
        self.entries.clear();
        self.entry_count = 0;
    }

    fn flush_value(&mut self) {
        if self.buf.len() > 1 {
            let value = std::mem::replace(&mut self.buf, vec![self.op]);
            self.values
                .push((SnowflakeIdGenerator::global_id().unwrap(), value));
        }
    }

    pub fn finish(mut self) -> Vec<(u64, Vec<u8>)> {
        self.end_document();
        self.flush_value();
        self.values
    }
}

pub(crate) enum WalEvent<'x, Id: SearchDocId> {
    Add {
        document_id: Id,
        field: u8,
        term: CheekyHash,
        payload: &'x [u8],
    },
    TombstoneDocument {
        document_id: Id,
    },
    Tombstone {
        document_id: Id,
        mask: u32,
        term: CheekyHash,
    },
}

pub(crate) fn walk_wal<'x, Id: SearchDocId>(
    value: &'x [u8],
    mut cb: impl FnMut(WalEvent<'x, Id>) -> bool,
) -> Option<()> {
    let mut reader = Reader::new(value);
    match reader.u8()? {
        WAL_ADDS => {
            while !reader.is_empty() {
                let document_id = Id::read_wal_id(&mut reader)?;
                let term_count = reader.leb128::<u32>()?;
                for _ in 0..term_count {
                    let field = reader.u8()?;
                    let term = reader.term()?;
                    let payload = Id::read_payload(&mut reader)?;
                    if !cb(WalEvent::Add {
                        document_id,
                        field,
                        term,
                        payload,
                    }) {
                        return Some(());
                    }
                }
            }
        }
        WAL_TOMBSTONES => {
            while !reader.is_empty() {
                let document_id = Id::read_wal_id(&mut reader)?;
                let term_count = reader.leb128::<u32>()?;
                if !cb(WalEvent::TombstoneDocument { document_id }) {
                    return Some(());
                }
                for _ in 0..term_count {
                    let mask = reader.leb128::<u32>()?;
                    let term = reader.term()?;
                    if !cb(WalEvent::Tombstone {
                        document_id,
                        mask,
                        term,
                    }) {
                        return Some(());
                    }
                }
            }
        }
        _ => return None,
    }
    Some(())
}

pub(crate) fn walk_document_record(
    value: &[u8],
    mut cb: impl FnMut(CheekyHash, u32),
) -> Option<()> {
    let mut reader = Reader::new(value);
    let term_count = reader.leb128::<u32>()?;
    for _ in 0..term_count {
        let term = reader.term()?;
        let mask = reader.leb128::<u32>()?;
        cb(term, mask);
    }
    Some(())
}

pub(crate) fn tombstones_from_record(
    writer: &mut WalWriter<u32>,
    document_id: u32,
    record: &[u8],
) -> Option<()> {
    writer.begin_document(document_id);
    let result = walk_document_record(record, |term, mask| {
        writer.push_entry(|buf| {
            buf.push_leb128(mask);
            push_term(buf, &term);
        });
    });
    writer.end_document();
    result
}
