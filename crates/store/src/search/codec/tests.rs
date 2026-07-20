/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::write::{SearchIndex, SearchIndexClass, ValueClass};
use utils::{cheeky_hash::CheekyHash, codec::leb128::Leb128Vec};

fn sample_terms() -> Vec<CheekyHash> {
    vec![
        CheekyHash::new(b"a"),
        CheekyHash::new(b"quarterly"),
        CheekyHash::new(b"sixteenbyteterms"),
        CheekyHash::new(b"internationalization"),
        CheekyHash::new("x".repeat(300).as_bytes()),
    ]
}

#[test]
fn positions_roundtrip() {
    for positions in [
        vec![],
        vec![0u32],
        vec![5],
        vec![0, 1, 2, 500, 100_000, 4_000_000],
        (0..MAX_TERM_POSITIONS as u32).map(|n| n * 3).collect(),
    ] {
        let mut buf = Vec::new();
        push_positions(&positions, &mut buf);
        let mut reader = Reader::new(&buf);
        let payload = reader.payload().unwrap();
        assert!(reader.is_empty());
        let mut decoded = Vec::new();
        decode_positions(payload, &mut decoded).unwrap();
        assert_eq!(decoded, positions);
    }
}

#[test]
fn chunk_roundtrip() {
    let mut entries = Vec::new();
    let mut document_id = 0u32;
    for n in 0..10_000u32 {
        document_id += 1 + (n % 70);
        let mut payload = Vec::new();
        encode_positions(&[n, n + 2, n + 500], &mut payload);
        entries.push((document_id, payload));
    }

    let mut builder = ChunkBuilder::new();
    let mut chunks = Vec::new();
    for (document_id, payload) in &entries {
        if let Some(chunk) = builder.push(*document_id, payload) {
            assert!(chunk.1.len() >= CHUNK_TARGET_BYTES);
            chunks.push(chunk);
        }
    }
    if let Some(chunk) = builder.finish() {
        chunks.push(chunk);
    }
    assert!(chunks.len() > 1);

    let mut decoded = Vec::new();
    for (first_document_id, value) in &chunks {
        walk_chunk(*first_document_id, value, |document_id, payload| {
            decoded.push((document_id, payload.to_vec()));
            true
        })
        .unwrap();
    }
    assert_eq!(decoded, entries);
}

#[test]
fn global_chunk_roundtrip() {
    let mut entries = Vec::new();
    let mut document_id = 1_800_000_000_000u64 << 21;
    for n in 0..200_000u64 {
        document_id += ((n % 900) + 1) << 21 | (n % 4096);
        entries.push(document_id);
    }

    let mut builder = ChunkBuilder::new();
    let mut chunks = Vec::new();
    for document_id in &entries {
        if let Some(chunk) = builder.push(*document_id, &[]) {
            assert!(chunk.1.len() >= CHUNK_TARGET_BYTES);
            assert!(chunk.1.len() < 100_000);
            chunks.push(chunk);
        }
    }
    if let Some(chunk) = builder.finish() {
        chunks.push(chunk);
    }
    assert!(chunks.len() > 1);

    let mut decoded = Vec::new();
    for (first_document_id, value) in &chunks {
        walk_chunk::<u64>(*first_document_id, value, |document_id, payload| {
            assert!(payload.is_empty());
            decoded.push(document_id);
            true
        })
        .unwrap();
    }
    assert_eq!(decoded, entries);
}

#[test]
fn wal_writer_split_roundtrip() {
    let terms = sample_terms();
    let mut expected: Vec<(u32, u8, CheekyHash, Vec<u8>)> = Vec::new();
    let mut writer = WalWriter::new(WAL_ADDS);
    for document_id in 0..4u32 {
        writer.begin_document(document_id);
        let entry_count = if document_id == 2 { 12_000 } else { 100 };
        for n in 0..entry_count {
            let field = (n % 5) as u8;
            let term = terms[n % terms.len()];
            let positions = (0..(n % 40) as u32).collect::<Vec<_>>();
            writer.push_entry(|buf| {
                buf.push(field);
                push_term(buf, &term);
                push_positions(&positions, buf);
            });
            let mut payload = Vec::new();
            encode_positions(&positions, &mut payload);
            expected.push((document_id, field, term, payload));
        }
        writer.end_document();
    }

    let values = writer.finish();
    assert!(values.len() > 1);
    let mut last_id = 0;
    let mut decoded = Vec::new();
    for (id, value) in &values {
        assert!(*id > last_id);
        last_id = *id;
        assert!(value.len() < 100_000);
        walk_wal::<u32>(value, |event| {
            if let WalEvent::Add {
                document_id,
                field,
                term,
                payload,
            } = event
            {
                decoded.push((document_id, field, term, payload.to_vec()));
            }
            true
        })
        .unwrap();
    }
    assert_eq!(decoded, expected);
}

#[test]
fn global_wal_writer_roundtrip() {
    let terms = sample_terms();
    let mut expected: Vec<(u64, u8, CheekyHash)> = Vec::new();
    let mut writer = WalWriter::new(WAL_ADDS);
    for n in 0..2000u64 {
        let document_id = (1_700_000_000_000u64 + n * 1000) << 21 | n;
        writer.begin_document(document_id);
        for m in 0..(n % 20) as usize + 1 {
            let field = (m % 5) as u8 + 3;
            let term = terms[m % terms.len()];
            writer.push_entry(|buf| {
                buf.push(field);
                push_term(buf, &term);
            });
            expected.push((document_id, field, term));
        }
        writer.end_document();
    }

    let values = writer.finish();
    let mut decoded = Vec::new();
    for (_, value) in &values {
        assert!(value.len() < 100_000);
        walk_wal::<u64>(value, |event| {
            if let WalEvent::Add {
                document_id,
                field,
                term,
                payload,
            } = event
            {
                assert!(payload.is_empty());
                decoded.push((document_id, field, term));
            }
            true
        })
        .unwrap();
    }
    assert_eq!(decoded, expected);
}

#[test]
fn document_record_roundtrip() {
    let mut record = Vec::new();
    let terms = sample_terms()
        .into_iter()
        .enumerate()
        .map(|(n, term)| (term, 1u32 << (n + 3)))
        .collect::<Vec<_>>();
    record.push_leb128(terms.len() as u32);
    for (term, mask) in &terms {
        push_term(&mut record, term);
        record.push_leb128(*mask);
    }

    let mut decoded = Vec::new();
    walk_document_record(&record, |term, mask| {
        decoded.push((term, mask));
    })
    .unwrap();
    assert_eq!(decoded, terms);

    let mut writer = WalWriter::new(WAL_TOMBSTONES);
    tombstones_from_record(&mut writer, 42, &record).unwrap();
    let values = writer.finish();
    assert_eq!(values.len(), 1);
    let mut tombstoned_document = false;
    let mut decoded = Vec::new();
    walk_wal::<u32>(&values[0].1, |event| {
        match event {
            WalEvent::TombstoneDocument { document_id } => {
                assert_eq!(document_id, 42);
                tombstoned_document = true;
            }
            WalEvent::Tombstone {
                document_id,
                mask,
                term,
            } => {
                assert_eq!(document_id, 42);
                decoded.push((term, mask));
            }
            WalEvent::Add { .. } => unreachable!(),
        }
        true
    })
    .unwrap();
    assert!(tombstoned_document);
    assert_eq!(decoded, terms);
}

#[test]
fn key_roundtrips() {
    for term in sample_terms() {
        let key = ValueClass::SearchIndex(SearchIndexClass::Term {
            index: SearchIndex::Email,
            account_id: 1234,
            field: 7,
            term,
            first_document_id: 567,
        })
        .serialize(0, 0, 0, 0);
        assert_eq!(parse_term_key::<u32>(&key), Some((7, term, 567)));
    }

    let key = ValueClass::SearchIndex(SearchIndexClass::Wal {
        index: SearchIndex::Calendar,
        account_id: 99,
        id: u64::MAX - 3,
    })
    .serialize(0, 0, 0, 0);
    assert_eq!(parse_wal_key(&key), Some((99, u64::MAX - 3)));

    let key = ValueClass::SearchIndex(SearchIndexClass::Document {
        index: SearchIndex::Contacts,
        account_id: 7,
        document_id: 8,
    })
    .serialize(0, 0, 0, 0);
    assert_eq!(parse_document_key(&key), Some((7, 8)));
}

#[test]
fn global_key_roundtrips() {
    for term in sample_terms() {
        let key = ValueClass::SearchIndex(SearchIndexClass::GlobalTerm {
            index: SearchIndex::Tracing,
            field: 4,
            term,
            first_document_id: u64::MAX - 567,
        })
        .serialize(0, 0, 0, 0);
        assert_eq!(parse_term_key::<u64>(&key), Some((4, term, u64::MAX - 567)));
    }

    let key = ValueClass::SearchIndex(SearchIndexClass::GlobalWal {
        index: SearchIndex::Tracing,
        id: u64::MAX - 3,
    })
    .serialize(0, 0, 0, 0);
    assert_eq!(parse_global_id_key(&key), Some(u64::MAX - 3));

    let key = ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
        index: SearchIndex::Tracing,
        document_id: 1 << 58,
    })
    .serialize(0, 0, 0, 0);
    assert_eq!(parse_global_id_key(&key), Some(1 << 58));
    assert_eq!(key, global_document_key(SearchIndex::Tracing, 1 << 58));

    let key = ValueClass::SearchIndex(SearchIndexClass::GlobalMeta {
        index: SearchIndex::Tracing,
        kind: GLOBAL_META_WATERMARK,
    })
    .serialize(0, 0, 0, 0);
    assert_eq!(
        key,
        global_meta_key(SearchIndex::Tracing, GLOBAL_META_WATERMARK)
    );
}

#[test]
fn corrupted_input_is_rejected() {
    let mut decoded = Vec::new();
    assert_eq!(decode_positions(&[0x80], &mut decoded), None);
    assert_eq!(decode_positions(&[1, 1, 0x80], &mut decoded), None);

    assert_eq!(walk_chunk(0u32, &[0, 200, 1], |_, _| true), None);
    assert_eq!(walk_chunk(0u64, &[0x80], |_, _| true), None);
    assert_eq!(walk_wal::<u32>(&[9], |_| true), None);
    assert_eq!(
        walk_wal::<u32>(&[WAL_ADDS, 1, 1, 0, 20, b'x'], |_| true),
        None
    );
    assert_eq!(walk_wal::<u64>(&[WAL_ADDS, 1, 2, 3], |_| true), None);
    assert_eq!(walk_document_record(&[3, 10, b'a'], |_, _| ()), None);

    let mut reader = Reader::new(&[10, b'a', b'b', b'c']);
    assert_eq!(reader.term(), None);

    assert_eq!(parse_term_key::<u32>(&[1, 2, 3]), None);
    assert_eq!(parse_term_key::<u64>(&[1, 2, 3]), None);
    assert_eq!(parse_wal_key(&[0; 12]), None);
    assert_eq!(parse_document_key(&[0; 8]), None);
    assert_eq!(parse_global_id_key(&[0; 8]), None);
}
