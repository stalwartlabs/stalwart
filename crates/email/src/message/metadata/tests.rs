/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AddressHeader, AddressItem, Completeness, EnvelopeView, ExtraHeaders, HeaderId, HeaderMatcher,
    HeaderSelection, MAX_FIELD_ADDRESSES, MAX_HEADER_ENTRIES, MAX_PARAMS, MAX_PART_ENTRIES,
    MAX_POOL_LEN, MAX_PROTECTED_VALUE_LEN, MAX_TEXT_ITEMS, MAX_VALUE_LEN, MessageMetadata,
    MetadataRow, MetadataStructure, Occurrence, PartFlags, PartInfo, PartKind, PartSource,
    PartView, TransferEncoding, TzMinute,
};
use crate::message::index::PREVIEW_LENGTH;
use mail_parser::{
    Address, HeaderName, HeaderValue, Message, MessageParser, MessageRef, PartKind as ParsedKind,
};
use std::{borrow::Cow, fmt::Write as _, fs, path::PathBuf};
use store::Deserialize;
use types::blob_hash::BlobHash;

const DELIVER_TO: &str = "jdoe@example.org";

fn read_row(row: &[u8]) -> MetadataRow {
    MetadataRow::deserialize(row).expect("row reads")
}

impl ExtraHeaders {
    fn delivery() -> Self {
        let mut extra = ExtraHeaders::default();
        extra
            .push(HeaderId::DELIVERED_TO, DELIVER_TO)
            .push(HeaderId::X_SPAM_STATUS, "No");
        extra
    }

    fn encode(&self, message: &Message<'_>) -> (Vec<u8>, Vec<u8>) {
        let built = MessageMetadata::build(message, self, BlobHash::generate(message.raw()));
        let headers = built.raw_headers.clone();
        (built.encode().expect("row encodes"), headers)
    }

    fn encode_raw(&self, raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.encode(&MessageParser::new().parse(raw).expect("message parses"))
    }
}

fn sample(header_lines: usize) -> Vec<u8> {
    let mut raw = String::new();
    for line in 0..header_lines {
        let _ = write!(raw, "X-Line-{line}: value number {line}\r\n");
    }
    raw.push_str("Subject: codec\r\nFrom: a@example.com\r\n\r\nbody\r\n");
    raw.into_bytes()
}

fn incompressible_sample() -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut raw = String::from("Subject: ");
    for _ in 0..56 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        raw.push(char::from(b'!' + ((state >> 33) % 94) as u8));
    }
    raw.push_str("\r\n\r\nbody\r\n");
    raw.into_bytes()
}

#[test]
fn round_trips_plain_and_compressed_headers() {
    for (raw, extra, compressed) in [
        (sample(0), ExtraHeaders::default(), false),
        (incompressible_sample(), ExtraHeaders::default(), false),
        (sample(0), ExtraHeaders::delivery(), true),
        (sample(40), ExtraHeaders::default(), true),
        (sample(40), ExtraHeaders::delivery(), true),
    ] {
        let message = MessageParser::new().parse(&raw).expect("parses");
        let (row, headers) = extra.encode(&message);
        let decoded = read_row(&row);
        assert_eq!(decoded.headers_compressed(), compressed);
        assert_eq!(decoded.raw_headers().expect("headers").as_ref(), headers);
        let structure = MetadataStructure::deserialize(&row).expect("structure");
        let stored = row.len() - structure.archive().inner.len() - 5 * 2;
        if compressed {
            assert!(stored < headers.len());
        } else {
            assert_eq!(stored, headers.len());
            assert!(matches!(decoded.raw_headers(), Ok(Cow::Borrowed(_))));
        }
        let archived = decoded.unarchive().expect("archive");
        assert_eq!(archived.headers_len(), headers.len());
        assert_eq!(archived.blob_hash(), BlobHash::generate(&raw));

        let archived = structure.unarchive().expect("archive");
        assert!(archived.root().envelope().subject().is_some());
        assert_eq!(archived.headers_len(), headers.len());
    }
    assert!(incompressible_sample().len() > 64);
}

#[test]
fn rejects_malformed_rows() {
    for raw in [sample(10), sample(0)] {
        let (row, _) = ExtraHeaders::delivery().encode_raw(&raw);
        for cut in 0..row.len() {
            let truncated = row.get(..cut).unwrap_or_default();
            assert!(MetadataRow::deserialize(truncated).is_err(), "cut {cut}");
            assert!(
                MetadataStructure::deserialize(truncated).is_err(),
                "cut {cut}"
            );
        }

        let mut bad_len = row.clone();
        let len = bad_len.len();
        if let Some(byte) = bad_len.get_mut(len - 2) {
            *byte = 0xff;
        }
        assert!(MetadataRow::deserialize(&bad_len).is_err());
        assert!(MetadataStructure::deserialize(&bad_len).is_err());

        for flags in [0x42, 0x00, 0x01, 0x82, 0xff] {
            let mut bad_flags = row.clone();
            if let Some(byte) = bad_flags.last_mut() {
                *byte = flags;
            }
            assert!(MetadataRow::deserialize(&bad_flags).is_err());
            assert!(MetadataStructure::deserialize(&bad_flags).is_err());
        }

        let mut bad_structure = row.clone();
        if let Some(byte) = bad_structure.first_mut() {
            *byte ^= 0xff;
        }
        assert!(MetadataRow::deserialize(&bad_structure).is_err());
        assert!(MetadataStructure::deserialize(&bad_structure).is_err());
    }

    let (mut row, _) = ExtraHeaders::default().encode_raw(&sample(40));
    let structure_len = MetadataStructure::deserialize(&row)
        .expect("structure")
        .archive()
        .inner
        .len();
    let middle = structure_len + (row.len() - structure_len) / 2;
    if let Some(byte) = row.get_mut(middle) {
        *byte ^= 0xff;
    }
    let decoded = read_row(&row);
    assert!(decoded.headers_compressed());
    assert!(decoded.raw_headers().is_err());

    assert!(MetadataRow::deserialize(&[]).is_err());
    assert!(MetadataStructure::deserialize(&[]).is_err());
    assert!(MetadataRow::deserialize(&[0, 0, 0, 0, 0x80]).is_err());
}

#[test]
fn header_entries_are_capped() {
    let mut raw = String::with_capacity(100_000 * 16);
    for index in 0..100_000 {
        let _ = write!(raw, "X-Field-{}: value\r\n", index % 97);
    }
    raw.push_str("Subject: after the flood\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let structure = MetadataStructure::deserialize(&row).expect("structure");
    let meta = structure.unarchive().expect("archive");
    let root = meta.root().root_part();
    assert_eq!(root.headers().len(), MAX_HEADER_ENTRIES);
    assert!(root.flags().contains(PartFlags::HEADERS_TRUNCATED));
    assert_eq!(meta.root().envelope().subject(), Some("after the flood"));
    assert!(structure.archive().inner.len() < 4 * 1024 * 1024);
}

#[test]
fn address_entries_are_capped() {
    let mut raw = String::from("To: ");
    for index in 0..50_000 {
        if index > 0 {
            raw.push_str(", ");
        }
        let _ = write!(raw, "user{index}@example.com");
    }
    raw.push_str("\r\nFrom: sender@example.com\r\nSubject: many\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let envelope = meta.root().envelope();
    let to = envelope.addresses(AddressHeader::To, Occurrence::All);
    assert_eq!(to.mailboxes().count(), MAX_FIELD_ADDRESSES);
    assert_eq!(
        to.mailboxes().last().and_then(|mailbox| mailbox.address),
        Some(format!("user{}@example.com", MAX_FIELD_ADDRESSES - 1).as_str())
    );
    assert_eq!(meta.completeness(), Completeness::Truncated);
    assert_eq!(
        envelope
            .addresses(AddressHeader::From, Occurrence::Last)
            .first()
            .and_then(|mailbox| mailbox.address),
        Some("sender@example.com")
    );
    assert_eq!(envelope.subject(), Some("many"));
}

#[test]
fn values_are_cut_on_char_boundaries() {
    let subject = "é".repeat(MAX_VALUE_LEN);
    let raw = format!("Subject: {subject}\r\nFrom: a@example.com\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let stored = meta.root().envelope().subject().expect("subject");
    assert!(stored.len() <= MAX_VALUE_LEN);
    assert!(stored.len() > MAX_VALUE_LEN - 4);
    assert!(stored.chars().all(|ch| ch == 'é'));
}

#[test]
fn pool_is_capped() {
    let long = "x".repeat(MAX_VALUE_LEN);
    let mut raw = String::from("To: ");
    for index in 0..(MAX_POOL_LEN / MAX_VALUE_LEN + 64) {
        if index > 0 {
            raw.push_str(", ");
        }
        let _ = write!(raw, "\"{long}\" <u{index}@example.com>");
    }
    raw.push_str("\r\nSubject: pool\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let structure = MetadataStructure::deserialize(&row).expect("structure");
    assert!(structure.archive().inner.len() < MAX_POOL_LEN + 1024 * 1024);
    let meta = structure.unarchive().expect("archive");
    assert!(meta.pool().len() <= MAX_POOL_LEN);
    let to = meta
        .root()
        .envelope()
        .addresses(AddressHeader::To, Occurrence::All);
    assert!(to.mailboxes().count() > MAX_POOL_LEN / MAX_VALUE_LEN / 2);
    assert!(
        to.mailboxes()
            .all(|mailbox| { mailbox.name.is_none_or(|name| name.len() <= MAX_VALUE_LEN) })
    );
}

#[test]
fn identifier_layout_serves_imap_forms() {
    let raw = concat!(
        "Message-ID: <first@example.com>\r\n",
        "Message-ID: <a@example.com> <b@example.com>\r\n",
        "In-Reply-To: <x@example.com> <y@example.com> <z@example.com>\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "Content-ID: <part@example.com>\r\n",
        "Content-Language: en, de\r\n",
        "\r\n",
        "text\r\n",
        "--b--\r\n",
    );
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let envelope = meta.root().envelope();
    assert_eq!(
        envelope.message_id().iter().collect::<Vec<_>>(),
        ["a@example.com", "b@example.com"]
    );
    assert_eq!(
        envelope.message_id().last_bracketed(),
        Some("<b@example.com>")
    );
    assert_eq!(
        envelope.in_reply_to().joined_bracketed(),
        Some("<x@example.com> <y@example.com> <z@example.com>")
    );
    let part = meta.part(1).expect("text part");
    assert_eq!(part.content_id(), Some("part@example.com"));
    assert_eq!(part.content_id_bracketed(), Some("<part@example.com>"));
    assert!(matches!(
        part.content_type().map(|ct| ct.mime_type()),
        Some(Cow::Borrowed("text/plain"))
    ));
    assert_eq!(
        part.content_language().iter().collect::<Vec<_>>(),
        ["en", "de"]
    );

    let raw = "Subject: none\r\n\r\nbody\r\n";
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let envelope = meta.root().envelope();
    assert!(!envelope.message_id().is_present());
    assert_eq!(envelope.message_id().last_bracketed(), None);
    assert_eq!(envelope.in_reply_to().joined_bracketed(), None);
}

#[test]
fn envelope_distinguishes_absent_and_empty_fields() {
    let raw =
        "In-Reply-To:\r\nMessage-ID: \r\nDate:\r\nSubject:\r\nFrom: a@example.com\r\n\r\nbody\r\n";
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let envelope = meta.root().envelope();
    for ids in [envelope.in_reply_to(), envelope.message_id()] {
        assert!(ids.is_present());
        assert!(ids.is_empty());
        assert_eq!(ids.joined_bracketed(), None);
        assert_eq!(ids.last_bracketed(), None);
    }
    assert!(envelope.date().is_none());
    assert_eq!(envelope.date_raw(), Some(""));
    assert_eq!(envelope.subject(), Some(""));

    let raw = "From: a@example.com\r\n\r\nbody\r\n";
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let envelope = meta.root().envelope();
    assert!(!envelope.in_reply_to().is_present());
    assert!(!envelope.message_id().is_present());
    assert!(envelope.date().is_none());
    assert_eq!(envelope.date_raw(), None);
    assert_eq!(envelope.subject(), None);

    for (raw, date_raw, parsed) in [
        (
            "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\nDate: not a date\r\n\tat all \r\n\r\nbody\r\n",
            Some("not a date\tat all"),
            false,
        ),
        (
            "Date: not a date\r\nDate: Mon, 1 Jan 2024 10:00:00 +0000\r\n\r\nbody\r\n",
            None,
            true,
        ),
        (
            "Date: Mon, 1 Jan 2024 10:00:00 +0000\r\n\r\nbody\r\n",
            None,
            true,
        ),
    ] {
        let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
        let row = read_row(&row);
        let meta = row.unarchive().expect("archive");
        let envelope = meta.root().envelope();
        assert_eq!(envelope.date_raw(), date_raw, "{raw:?}");
        assert_eq!(envelope.date().is_some(), parsed, "{raw:?}");
    }

    let long = "x".repeat(MAX_VALUE_LEN * 2);
    let raw = format!("Date: {long}\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    assert_eq!(
        meta.root().envelope().date_raw().map(str::len),
        Some(MAX_VALUE_LEN)
    );
}

#[test]
fn matcher_handles_known_unknown_and_obsolete_names() {
    let raw = concat!(
        "Subject : obsolete syntax\r\n",
        "x-custom: lower\r\n",
        "X-CUSTOM: upper\r\n",
        "From: a@example.com\r\n",
        "\r\n",
        "body\r\n",
    );
    let (row, headers) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let matcher = HeaderMatcher::new(["subject", "X-Custom"]);
    let root = meta.root().root_part();
    let matched = root
        .headers()
        .iter()
        .filter(|header| matcher.matches(*header, &headers))
        .map(|header| String::from_utf8_lossy(header.raw_name(&headers)).into_owned())
        .collect::<Vec<_>>();
    assert_eq!(matched, ["Subject", "x-custom", "X-CUSTOM"]);
    let matched_fields = root
        .headers()
        .iter()
        .filter(|header| {
            headers
                .get(header.field_range())
                .is_some_and(|field| matcher.matches_field(*header, field))
        })
        .map(|header| {
            let field = headers.get(header.field_range()).unwrap_or_default();
            String::from_utf8_lossy(header.raw_name_in(field)).into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(matched_fields, matched);
    assert_eq!(
        root.headers().last(HeaderId::SUBJECT).map(|h| h.id()),
        Some(HeaderId::SUBJECT)
    );
}

#[test]
fn extra_headers_are_sanitised_and_mapped_to_the_blob() {
    let raw = b"Subject: extra\r\nFrom: a@example.com\r\n\r\nbody\r\n";
    let mut extra = ExtraHeaders::default();
    extra
        .push(HeaderId::DELIVERED_TO, "user@example.org\r\nX-Injected: 1")
        .push(HeaderId::X_SPAM_STATUS, "No")
        .push(HeaderId::OTHER, "dropped");
    let (row, headers) = extra.encode_raw(raw);
    assert!(
        headers
            .starts_with(b"Delivered-To: user@example.orgX-Injected: 1\r\nX-Spam-Status: No\r\n")
    );
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let root = meta.root().root_part();
    assert_eq!(root.offset_header(), 0);
    assert_eq!(root.offset_body(), headers.len());
    assert_eq!(root.headers().len(), 4);
    let subject = root
        .headers()
        .last(HeaderId::SUBJECT)
        .expect("subject header");
    let blob_range = meta.blob_range(subject.field_range()).expect("in blob");
    assert_eq!(raw.get(blob_range), headers.get(subject.field_range()));
    let body = meta.blob_range(root.body_range()).expect("body in blob");
    assert_eq!(raw.get(body), Some(&b"body\r\n"[..]));
    for header in root.headers().iter().take(2) {
        assert_eq!(meta.blob_range(header.field_range()), None);
    }
}

#[test]
fn unknown_transfer_encoding_sets_the_flag() {
    let raw = concat!(
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Transfer-Encoding: x-uuencode\r\n",
        "\r\n",
        "begin 644 file\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Transfer-Encoding: Base64 (comment)\r\n",
        "\r\n",
        "SGVsbG8=\r\n",
        "--b--\r\n",
    );
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let unknown = meta.part(1).expect("uuencoded part");
    let known = meta.part(2).expect("base64 part");
    assert!(
        unknown
            .flags()
            .contains(PartFlags::UNKNOWN_TRANSFER_ENCODING)
    );
    assert!(!known.flags().contains(PartFlags::UNKNOWN_TRANSFER_ENCODING));
    assert_eq!(known.decoded_size(), 5);
    let source = meta
        .source(meta.root(), meta.raw_message(None, raw.as_bytes()))
        .expect("source");
    assert_eq!(known.decoded(&source).as_ref(), b"Hello");
    let text = known.text(&source).expect("text");
    assert_eq!(text.text, "Hello");
    assert!(!text.has_problems);
}

#[test]
fn header_longer_than_64_kib() {
    let mut raw = String::from("To: ");
    let mut index = 0;
    while raw.len() < 70_000 {
        if index > 0 {
            raw.push_str(",\r\n ");
        }
        let _ = write!(raw, "recipient{index}@example.com");
        index += 1;
    }
    raw.push_str("\r\nSubject: after the long field\r\nX-After: 1\r\n\r\nbody\r\n");
    let message = MessageParser::new().parse(raw.as_bytes()).expect("parses");
    for extra in [ExtraHeaders::default(), ExtraHeaders::delivery()] {
        let (row, headers) = extra.encode(&message);
        let row = read_row(&row);
        let meta = row.unarchive().expect("archive");
        let root = meta.root().root_part();
        let parsed = message.root().root_part();
        for (header, parsed_header) in root
            .headers()
            .iter()
            .skip(root.headers().len() - parsed.headers().len())
            .zip(parsed.headers().iter())
        {
            assert_eq!(header.raw_value(&headers), Some(parsed_header.raw_value()));
            let blob_range = meta.blob_range(header.field_range()).expect("in blob");
            assert_eq!(
                raw.as_bytes().get(blob_range),
                headers.get(header.field_range())
            );
        }
        let subject = root.headers().last(HeaderId::SUBJECT).expect("subject");
        assert!(subject.field_range().start > usize::from(u16::MAX));
        assert_eq!(
            subject.raw_value(&headers),
            Some(&b" after the long field\r\n"[..])
        );
        assert_eq!(
            meta.root().envelope().subject(),
            Some("after the long field")
        );
        assert_eq!(
            meta.root()
                .envelope()
                .addresses(AddressHeader::To, Occurrence::All)
                .mailboxes()
                .count(),
            index.min(MAX_FIELD_ADDRESSES)
        );
    }
}

#[test]
fn part_entries_are_capped() {
    const PARTS: usize = 66_000;
    let mut raw = String::with_capacity(PARTS * 16 + 256);
    raw.push_str("Subject: many parts\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");
    for index in 0..PARTS {
        let _ = write!(raw, "--b\r\n\r\npart {index}\r\n");
    }
    raw.push_str(concat!(
        "--b\r\nContent-Type: message/rfc822\r\n\r\n",
        "Subject: nested\r\nContent-Type: multipart/mixed; boundary=\"n\"\r\n\r\n",
        "--n\r\n\r\none\r\n--n\r\n\r\ntwo\r\n--n--\r\n",
        "--b--\r\n"
    ));
    let message = MessageParser::new()
        .max_parts(70_000)
        .parse(raw.as_bytes())
        .expect("parses");
    assert!(message.parts().len() > MAX_PART_ENTRIES);
    assert_eq!(message.messages().len(), 2);
    let (row, _) = ExtraHeaders::default().encode(&message);
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    assert_eq!(meta.completeness(), Completeness::Truncated);
    assert_eq!(meta.parts().len(), MAX_PART_ENTRIES);
    assert_eq!(meta.root().parts().len(), MAX_PART_ENTRIES);
    assert!(meta.part(MAX_PART_ENTRIES as u32).is_none());
    let root = meta.root().root_part();
    assert_eq!(root.children().len(), MAX_PART_ENTRIES - 1);
    assert!(root.child(MAX_PART_ENTRIES - 1).is_none());
    assert!(
        root.children()
            .all(|child| (child.id() as usize) < MAX_PART_ENTRIES)
    );
    let source = meta
        .source(meta.root(), meta.raw_message(None, raw.as_bytes()))
        .expect("source");
    for index in [0, 32_767, 32_768, MAX_PART_ENTRIES - 2] {
        let child = root.child(index).expect("child");
        assert_eq!(child.id() as usize, index + 1);
        assert_eq!(
            child.decoded(&source).as_ref(),
            format!("part {index}").as_bytes()
        );
    }
    let last = meta
        .part(MAX_PART_ENTRIES as u32 - 1)
        .expect("last stored part");
    assert_eq!(last.message().id(), 0);
    assert_eq!(meta.root().text_body().len(), MAX_PART_ENTRIES - 1);
    assert!(
        meta.root()
            .text_body()
            .all(|part| (part.id() as usize) < MAX_PART_ENTRIES)
    );
    let nested = meta.message(1).expect("nested message");
    assert_eq!(nested.parts().len(), 0);
    assert!(nested.container().is_none());
    assert_eq!(nested.envelope().subject(), None);
}

#[test]
fn part_info_packs_kind_encoding_and_flags() {
    let kinds = [
        PartKind::Text,
        PartKind::Html,
        PartKind::Binary,
        PartKind::InlineBinary,
        PartKind::Multipart,
        PartKind::Message,
    ];
    let encodings = [
        TransferEncoding::None,
        TransferEncoding::QuotedPrintable,
        TransferEncoding::Base64,
    ];
    for kind in kinds {
        for encoding in encodings {
            for bits in 0..=u8::MAX {
                let mut info = PartInfo::new(kind, encoding, PartFlags(bits));
                assert_eq!(info.kind(), kind);
                assert_eq!(info.encoding(), encoding);
                assert_eq!(info.flags(), PartFlags(bits));
                info |= PartFlags::TRUNCATED;
                assert_eq!(info.kind(), kind);
                assert_eq!(info.encoding(), encoding);
                assert_eq!(info.flags(), PartFlags(bits) | PartFlags::TRUNCATED);
            }
        }
    }
    for kind_bits in 6..8u16 {
        for encoding_bits in 0..4u16 {
            let info = PartInfo((kind_bits << 8) | (encoding_bits << 11) | 0x2a);
            assert_eq!(info.kind(), PartKind::Binary);
            assert_eq!(info.flags(), PartFlags(0x2a));
            if encoding_bits == 3 {
                assert_eq!(info.encoding(), TransferEncoding::None);
            }
        }
    }
    assert_eq!(PartInfo(u16::MAX).flags(), PartFlags(u8::MAX));
}

#[test]
fn time_zone_sign_shares_the_minute_byte() {
    for (zone, before_gmt, hour, minute) in [
        ("+0000", false, 0, 0),
        ("-0000", true, 0, 0),
        ("-0730", true, 7, 30),
        ("+0545", false, 5, 45),
        ("+1459", false, 14, 59),
        ("-1159", true, 11, 59),
    ] {
        let raw = format!("Date: Tue, 1 Jul 2003 10:52:37 {zone}\r\nSubject: tz\r\n\r\nbody\r\n");
        let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
        let row = read_row(&row);
        let meta = row.unarchive().expect("archive");
        let date = meta.root().envelope().datetime().expect("date");
        let parsed = MessageParser::new()
            .parse(raw.as_bytes())
            .and_then(|message| message.root().headers().date())
            .expect("parsed date");
        assert_eq!(date, parsed, "{zone}");
        assert_eq!(
            (date.tz_before_gmt, date.tz_hour, date.tz_minute),
            (before_gmt, hour, minute),
            "{zone}"
        );
    }
    for minute in 0..=u8::MAX {
        for before_gmt in [false, true] {
            let packed = TzMinute::new(minute, before_gmt);
            assert_eq!(packed.is_before_gmt(), before_gmt);
            assert_eq!(packed.minute(), minute.min(0x7f));
        }
    }
}

#[test]
fn extra_header_fields_are_capped() {
    let raw = b"Subject: extra flood\r\nFrom: a@example.com\r\n\r\nbody\r\n";
    let mut extra = ExtraHeaders::default();
    for _ in 0..MAX_HEADER_ENTRIES + 10 {
        extra.push(HeaderId::X_SPAM_STATUS, "No");
    }
    let (row, headers) = extra.encode_raw(raw);
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let root = meta.root().root_part();
    assert_eq!(root.headers().len(), MAX_HEADER_ENTRIES);
    assert!(root.is_headers_truncated());
    assert_eq!(meta.completeness(), Completeness::Truncated);
    let complete = root.selected_headers(&headers, HeaderSelection::All);
    assert!(complete.is_parsed());
    assert_eq!(complete.list().len(), MAX_HEADER_ENTRIES + 12);
    let subject = complete
        .list()
        .last(HeaderId::SUBJECT)
        .expect("subject header");
    assert_eq!(subject.raw_value(&headers), Some(&b" extra flood\r\n"[..]));
    assert_eq!(meta.root().envelope().subject(), Some("extra flood"));
}

#[test]
fn group_members_fit_the_packed_count() {
    let mut raw = String::from("To: team: ");
    for index in 0..2 * MAX_FIELD_ADDRESSES {
        if index > 0 {
            raw.push_str(", ");
        }
        let _ = write!(raw, "user{index}@example.com");
    }
    raw.push_str(";, solo@example.com\r\nSubject: group\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let to = meta
        .root()
        .envelope()
        .addresses(AddressHeader::To, Occurrence::All);
    assert!(to.has_groups());
    let items = to.iter().collect::<Vec<_>>();
    assert_eq!(items.len(), 1);
    let Some(AddressItem::Group(group)) = items.first() else {
        panic!("expected a group");
    };
    assert_eq!(group.name, Some("team"));
    assert_eq!(group.members.mailboxes().count(), MAX_FIELD_ADDRESSES - 1);
    assert_eq!(
        group
            .members
            .mailboxes()
            .last()
            .and_then(|mailbox| mailbox.address),
        Some(format!("user{}@example.com", MAX_FIELD_ADDRESSES - 2).as_str())
    );
    assert_eq!(meta.completeness(), Completeness::Truncated);
}

#[test]
fn longest_values_keep_their_length() {
    let subject = "s".repeat(MAX_VALUE_LEN);
    let raw = format!("Subject: {subject}\r\nFrom: a@example.com\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    assert_eq!(meta.root().envelope().subject(), Some(subject.as_str()));
    assert_eq!(meta.completeness(), Completeness::Complete);
    let longer = format!("Subject: {subject}tail\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(longer.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    assert_eq!(meta.root().envelope().subject(), Some(subject.as_str()));
    assert_eq!(meta.completeness(), Completeness::Truncated);
}

fn digest(messages: usize, padding: usize) -> String {
    let mut inner = String::with_capacity(padding + messages * 48 + 256);
    inner.push_str(concat!(
        "From: digest@example.com\r\n",
        "Subject: digest\r\n",
        "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
        "\r\n",
        "--outer\r\n",
        "Content-Type: application/octet-stream\r\n",
        "\r\n",
    ));
    for line in 0..padding / 64 {
        let _ = write!(inner, "{line:062}\r\n");
    }
    inner.push_str("--outer\r\nContent-Type: multipart/digest; boundary=\"d\"\r\n\r\n");
    for index in 0..messages {
        let _ = write!(
            inner,
            "--d\r\n\r\nSubject: m{index}\r\nFrom: m{index}@example.com\r\n\r\nbody {index}\r\n"
        );
    }
    inner.push_str("--d--\r\n--outer--\r\n");
    format!(
        concat!(
            "From: a@example.com\r\n",
            "Subject: encoded digest\r\n",
            "Content-Type: multipart/mixed; boundary=\"root\"\r\n",
            "\r\n",
            "--root\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "see attached\r\n",
            "--root\r\n",
            "Content-Type: message/rfc822\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "{}",
            "--root--\r\n",
        ),
        encodify::base64::MIME.encode(inner.as_bytes())
    )
}

#[test]
fn encoded_digest_resolves_to_one_buffer() {
    const MESSAGES: usize = 2_000;
    let raw = digest(MESSAGES, 1024 * 1024);
    let message = MessageParser::new().parse(raw.as_bytes()).expect("parses");
    let (row, headers) = ExtraHeaders::delivery().encode(&message);
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    assert_eq!(meta.messages().len(), MESSAGES + 2);
    let raw_message = meta.raw_message(Some(&headers), raw.as_bytes());
    let container = meta
        .message(1)
        .and_then(|nested| nested.container())
        .expect("container");
    assert_eq!(container.encoding(), super::TransferEncoding::Base64);
    let decoded_len = container.decoded_size() as usize;
    assert!(decoded_len > 1024 * 1024);

    for id in (2..MESSAGES as u32 + 2)
        .step_by(333)
        .chain([MESSAGES as u32 + 1])
    {
        let nested = meta.message(id).expect("digest message");
        let index = id - 2;
        assert_eq!(
            nested.envelope().subject(),
            Some(format!("m{index}").as_str())
        );
        let source = meta.source(nested, raw_message).expect("source");
        let PartSource::Decoded(bytes) = &source else {
            panic!("digest message {id} has a raw source");
        };
        assert_eq!(bytes.len(), decoded_len);
        let text = nested.text_body().next().expect("text body");
        assert_eq!(
            text.decoded(&source).as_ref(),
            format!("body {index}").as_bytes()
        );
        let parsed = message.messages().nth(id as usize).expect("parsed message");
        assert_eq!(bytes.as_slice(), parsed.source_bytes());
    }
}

#[test]
fn strip_root_fields_with_extra_headers() {
    let raw = concat!(
        "From: sender@example.com\r\n",
        "Bcc: first@example.com\r\n",
        "To: rcpt@example.com\r\n",
        "Bcc: second@example.com,\r\n",
        " third@example.com\r\n",
        "Subject: blind copies\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: message/rfc822\r\n",
        "\r\n",
        "Bcc: nested@example.com\r\n",
        "Subject: nested\r\n",
        "\r\n",
        "nested body\r\n",
        "--b--\r\n",
    );
    let expected = raw
        .replace("Bcc: first@example.com\r\n", "")
        .replace("Bcc: second@example.com,\r\n third@example.com\r\n", "");
    for extra in [ExtraHeaders::default(), ExtraHeaders::delivery()] {
        let (row, _) = extra.encode_raw(raw.as_bytes());
        let row = read_row(&row);
        let meta = row.unarchive().expect("archive");
        let stripped = meta.strip_root_fields(raw.as_bytes(), HeaderId::BCC);
        assert!(matches!(stripped, Cow::Owned(_)));
        assert_eq!(stripped.as_ref(), expected.as_bytes());
        let parsed = MessageParser::new()
            .parse(stripped.as_ref())
            .expect("stripped message parses");
        assert!(parsed.root().headers().get(HeaderName::Bcc).is_none());
        assert_eq!(parsed.root().headers().subject(), Some("blind copies"));
        assert_eq!(parsed.messages().len(), 2);

        let unchanged = meta.strip_root_fields(raw.as_bytes(), HeaderId::RESENT_BCC);
        assert!(matches!(unchanged, Cow::Borrowed(_)));
        assert_eq!(unchanged.as_ref(), raw.as_bytes());
    }
}

#[test]
fn leading_block_and_extra_headers_map_to_blob() {
    for raw in [
        &b"not a header line\r\nSubject: leading\r\nFrom: a@example.com\r\n\r\nbody\r\n"[..],
        &b" folded start\r\nSubject: leading\r\n\r\nbody\r\n"[..],
        &b"Subject: leading\r\n\r\nbody\r\n"[..],
    ] {
        let extra = ExtraHeaders::delivery();
        let (row, headers) = extra.encode_raw(raw);
        let row = read_row(&row);
        let meta = row.unarchive().expect("archive");
        let body_offset = meta.blob_body_offset();
        assert_eq!(headers.get(..extra.len()), Some(extra.as_bytes()));
        assert_eq!(headers.get(extra.len()..), raw.get(..body_offset));
        assert_eq!(meta.headers_len(), headers.len());
        assert_eq!(meta.size(), extra.len() + raw.len());

        let root = meta.root().root_part();
        for header in root.headers().iter().take(2) {
            assert_eq!(meta.blob_range(header.field_range()), None);
        }
        let subject = root.headers().last(HeaderId::SUBJECT).expect("subject");
        let blob_range = meta.blob_range(subject.field_range()).expect("in blob");
        assert_eq!(raw.get(blob_range), Some(&b"Subject: leading\r\n"[..]));
        assert_eq!(meta.blob_range(0..extra.len()), None);
        assert_eq!(
            meta.blob_range(extra.len()..meta.size()),
            Some(0..raw.len())
        );

        let raw_message = meta.raw_message(Some(&headers), raw);
        let whole = raw_message.whole().expect("whole message");
        assert_eq!(whole.len(), extra.len() + raw.len());
        assert_eq!(whole.to_vec(), [extra.as_bytes(), raw].concat());
        assert_eq!(raw_message.len(), meta.size());
        let body_only = meta.raw_message(None, raw);
        assert!(body_only.whole().is_none());
        assert_eq!(body_only.len(), meta.size());
        assert_eq!(
            body_only.get(root.body_range()).as_deref(),
            Some(&b"body\r\n"[..])
        );
        assert_eq!(body_only.get(0..1), None);
    }
}

fn nested_encoded(depth: usize, encoding: &str) -> String {
    let mut message = concat!(
        "From: Inner <inner@example.com>\r\n",
        "To: a@example.com, Group: b@example.com, c@example.com;\r\n",
        "Subject: =?utf-8?q?inn=C3=A9r?=\r\n",
        "Message-ID: <inner@example.com>\r\n",
        "Content-Type: multipart/alternative; boundary=\"in\"\r\n",
        "\r\n",
        "--in\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "Content-Transfer-Encoding: quoted-printable\r\n",
        "\r\n",
        "caf=C3=A9 nested\r\n",
        "--in\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>nested</p>\r\n",
        "--in--\r\n",
    )
    .to_string();
    for level in 0..depth {
        let encoded = match encoding {
            "base64" => encodify::base64::MIME.encode(message.as_bytes()),
            _ => encodify::qp::BODY.encode(message.as_bytes()),
        };
        message = format!(
            concat!(
                "From: level{level}@example.com\r\n",
                "Subject: level {level}\r\n",
                "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n",
                "\r\n",
                "--b{level}\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "text {level}\r\n",
                "--b{level}\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: {encoding}\r\n",
                "\r\n",
                "{encoded}\r\n",
                "--b{level}\r\n",
                "Content-Type: application/pdf; name=\"doc.pdf\"\r\n",
                "Content-Disposition: attachment; filename=\"doc.pdf\"\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\r\n",
                "\r\n",
                "JVBERi0xLjQK\r\n",
                "--b{level}--\r\n",
            ),
            level = level,
            encoding = encoding,
            encoded = encoded,
        );
    }
    message
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/resources");
    let mut samples = Vec::new();
    for (directory, extension) in [
        ("imap", "txt"),
        ("jmap/email_get", "eml"),
        ("jmap/email_parse", "eml"),
    ] {
        let Ok(entries) = fs::read_dir(resources.join(directory)) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == extension)
                && let Ok(bytes) = fs::read(&path)
            {
                samples.push((path.display().to_string(), bytes));
            }
        }
    }
    for depth in [1, 2] {
        for encoding in ["base64", "quoted-printable"] {
            samples.push((
                format!("generated {encoding} depth {depth}"),
                nested_encoded(depth, encoding).into_bytes(),
            ));
        }
    }
    samples
}

#[test]
fn builder_matches_parser() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for (name, bytes) in corpus() {
        let Some(message) = MessageParser::new().parse(&bytes) else {
            continue;
        };
        for extra in [ExtraHeaders::default(), ExtraHeaders::delivery()] {
            if let Err(err) = extra.compare(&message, &bytes) {
                failures.push(format!("{name}: {err}"));
            }
            checked += 1;
        }
    }
    assert!(checked > 40, "only {checked} messages checked");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

impl ExtraHeaders {
    fn compare(&self, message: &Message<'_>, blob: &[u8]) -> Result<(), String> {
        let (row, raw_headers) = self.encode(message);
        let row = MetadataRow::deserialize(&row).map_err(|err| err.to_string())?;
        let meta = row.unarchive().map_err(|err| err.to_string())?;
        let raw = meta.raw_message(Some(&raw_headers), blob);
        let extra_fields = self.as_bytes().split(|&byte| byte == b'\n').count() - 1;

        if meta.parts().len() != message.parts().len()
            || meta.messages().len() != message.messages().len()
        {
            return Err("part or message count".into());
        }
        if raw.len() != self.len() + blob.len() {
            return Err("virtual message length".into());
        }
        if meta.preview()
            != message
                .root()
                .body_preview(PREVIEW_LENGTH)
                .as_deref()
                .unwrap_or_default()
        {
            return Err("preview".into());
        }

        let mut expected_parts = Vec::new();
        for parsed_message in message.messages() {
            let view = meta.message(parsed_message.id()).ok_or("missing message")?;
            let parsed_parts = parsed_message.parts().collect::<Vec<_>>();
            if view.parts().len() != parsed_parts.len() {
                return Err(format!("message {} part count", parsed_message.id()));
            }
            let source = meta.source(view, raw).ok_or("source")?;
            if !view.is_raw_source() {
                let decoded = source.get(0..source.len()).ok_or("source bytes")?;
                if decoded.as_ref() != parsed_message.source_bytes() {
                    return Err(format!("message {} source bytes", parsed_message.id()));
                }
            }
            view.envelope().compare(parsed_message)?;
            for (part, parsed) in view.parts().zip(parsed_parts.iter()) {
                expected_parts.push((part.id(), parsed.id()));
                part.compare(*parsed, &source, extra_fields)?;
            }
            for (part, parsed) in view.parts().zip(parsed_parts) {
                let children = part.children().map(|child| child.id()).collect::<Vec<_>>();
                let expected = parsed
                    .children()
                    .map(|child| {
                        expected_parts
                            .iter()
                            .find(|(_, old)| *old == child.id())
                            .map(|(new, _)| *new)
                    })
                    .collect::<Option<Vec<_>>>();
                if expected.as_ref() != Some(&children) {
                    return Err(format!("part {} children", parsed.id()));
                }
            }
            for (list, parsed) in [
                (
                    view.text_body().map(|p| p.id()).collect::<Vec<_>>(),
                    parsed_message
                        .text_body()
                        .map(|p| p.id())
                        .collect::<Vec<_>>(),
                ),
                (
                    view.html_body().map(|p| p.id()).collect(),
                    parsed_message.html_body().map(|p| p.id()).collect(),
                ),
                (
                    view.attachments().map(|p| p.id()).collect(),
                    parsed_message.attachments().map(|p| p.id()).collect(),
                ),
            ] {
                let mapped = parsed
                    .iter()
                    .map(|id| {
                        expected_parts
                            .iter()
                            .find(|(_, old)| old == id)
                            .map(|(new, _)| *new)
                    })
                    .collect::<Option<Vec<_>>>();
                if mapped.as_ref() != Some(&list) {
                    return Err(format!("body list of message {}", parsed_message.id()));
                }
            }
        }
        Ok(())
    }
}

impl EnvelopeView<'_> {
    fn compare(&self, message: MessageRef<'_>) -> Result<(), String> {
        let headers = message.headers();
        if self.subject() != headers.subject() {
            return Err("subject".into());
        }
        if self.datetime() != headers.date() {
            return Err("date".into());
        }
        for (field, name) in [
            (AddressHeader::From, HeaderName::From),
            (AddressHeader::Sender, HeaderName::Sender),
            (AddressHeader::ReplyTo, HeaderName::ReplyTo),
            (AddressHeader::To, HeaderName::To),
            (AddressHeader::Cc, HeaderName::Cc),
            (AddressHeader::Bcc, HeaderName::Bcc),
        ] {
            let expected = headers
                .all(name.clone())
                .filter_map(|header| header.value().as_address())
                .flat_map(|list| list.mailboxes().collect::<Vec<_>>())
                .map(|mailbox| (mailbox.name(), mailbox.address()))
                .collect::<Vec<_>>();
            let found = self
                .addresses(field, Occurrence::All)
                .mailboxes()
                .map(|mailbox| (mailbox.name, mailbox.address))
                .collect::<Vec<_>>();
            if expected != found {
                return Err(format!("addresses {name:?}"));
            }
            let expected_items = headers
                .all(name.clone())
                .filter_map(|header| header.value().as_address())
                .flat_map(|list| {
                    list.iter()
                        .map(|item| match item {
                            Address::Mailbox(mailbox) => {
                                (false, mailbox.name(), mailbox.address(), Vec::new())
                            }
                            Address::Group(group) => (
                                true,
                                group.name(),
                                None,
                                group
                                    .mailboxes()
                                    .map(|mailbox| (mailbox.name(), mailbox.address()))
                                    .collect::<Vec<_>>(),
                            ),
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let found_items = self
                .addresses(field, Occurrence::All)
                .iter()
                .map(|item| match item {
                    AddressItem::Mailbox(mailbox) => {
                        (false, mailbox.name, mailbox.address, Vec::new())
                    }
                    AddressItem::Group(group) => (
                        true,
                        group.name,
                        None,
                        group
                            .members
                            .mailboxes()
                            .map(|mailbox| (mailbox.name, mailbox.address))
                            .collect::<Vec<_>>(),
                    ),
                })
                .collect::<Vec<_>>();
            if expected_items != found_items {
                return Err(format!("address items {name:?}"));
            }
            let last = headers
                .get(name.clone())
                .and_then(|header| header.value().as_address())
                .map(|list| {
                    list.mailboxes()
                        .map(|mailbox| (mailbox.name(), mailbox.address()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let found_last = self
                .addresses(field, Occurrence::Last)
                .mailboxes()
                .map(|mailbox| (mailbox.name, mailbox.address))
                .collect::<Vec<_>>();
            if last != found_last {
                return Err(format!("last addresses {name:?}"));
            }
        }
        for (name, items) in [
            (HeaderName::MessageId, self.message_id()),
            (HeaderName::InReplyTo, self.in_reply_to()),
        ] {
            let expected = headers
                .get(name.clone())
                .map(|header| match header.value() {
                    HeaderValue::TextList(list) => list.iter().collect::<Vec<_>>(),
                    HeaderValue::Text(text) => vec![text],
                    _ => Vec::new(),
                });
            let found = items.is_present().then(|| items.iter().collect::<Vec<_>>());
            if expected != found {
                return Err(format!("{name:?} items"));
            }
        }
        let has_date = headers.get(HeaderName::Date).is_some();
        if self.date_raw().is_some() != (has_date && self.date().is_none()) {
            return Err("date raw".into());
        }
        if self.message_id().last().is_some()
            && self.message_id().last_bracketed()
                != self
                    .message_id()
                    .last()
                    .map(|id| format!("<{id}>"))
                    .as_deref()
        {
            return Err("message-id bracket layout".into());
        }
        let joined = self
            .in_reply_to()
            .iter()
            .map(|id| format!("<{id}>"))
            .collect::<Vec<_>>()
            .join(" ");
        if !self.in_reply_to().is_empty()
            && self.in_reply_to().joined_bracketed() != Some(joined.as_str())
        {
            return Err("in-reply-to bracket layout".into());
        }
        Ok(())
    }
}

impl PartView<'_> {
    fn compare(
        &self,
        parsed: mail_parser::MessagePart<'_>,
        source: &PartSource<'_>,
        extra_fields: usize,
    ) -> Result<(), String> {
        let id = parsed.id();
        let body = source.get(self.body_range()).ok_or("body range")?;
        if body.as_ref() != parsed.raw_body() {
            return Err(format!("part {id} raw body"));
        }
        if self.encoding().as_u8() != u8::from(parsed.encoding()) {
            return Err(format!("part {id} encoding"));
        }
        let kind = match parsed.kind() {
            ParsedKind::Text => PartKind::Text,
            ParsedKind::Html => PartKind::Html,
            ParsedKind::Binary => PartKind::Binary,
            ParsedKind::InlineBinary => PartKind::InlineBinary,
            ParsedKind::Multipart => PartKind::Multipart,
            ParsedKind::Message(_) => PartKind::Message,
        };
        if self.kind() != kind {
            return Err(format!("part {id} exact kind"));
        }
        if !parsed.is_multipart() {
            if self.decoded_size() as usize != parsed.decoded_len() {
                return Err(format!("part {id} decoded size"));
            }
            if self.decoded(source).len() != self.decoded_size() as usize {
                return Err(format!("part {id} decoded size against decoded()"));
            }
        }
        if matches!(
            self.kind(),
            PartKind::Text | PartKind::Html | PartKind::Message
        ) && self.lines() as usize != bytecount::count(parsed.raw_body(), b'\n')
        {
            return Err(format!("part {id} lines"));
        }
        let skip = if self.id() == 0 { extra_fields } else { 0 };
        let headers = self.headers();
        if headers.len() != parsed.headers().len() + skip {
            return Err(format!("part {id} header count"));
        }
        for (header, parsed_header) in headers.iter().skip(skip).zip(parsed.headers().iter()) {
            if header.id() != HeaderId::parse(parsed_header.name().as_str().as_bytes()) {
                return Err(format!(
                    "part {id} header id {:?}",
                    parsed_header.raw_name()
                ));
            }
            let field = source.get(header.field_range()).ok_or("field range")?;
            if String::from_utf8_lossy(header.raw_name_in(&field)) != parsed_header.raw_name() {
                return Err(format!(
                    "part {id} header name {:?}",
                    parsed_header.raw_name()
                ));
            }
            let value = source.get(header.value_range()).ok_or("value range")?;
            if value.as_ref() != parsed_header.raw_value() {
                return Err(format!(
                    "part {id} header value {:?}",
                    parsed_header.raw_name()
                ));
            }
        }
        let content_type = parsed.content_type();
        if self.content_type().map(|ct| {
            (
                ct.ctype(),
                ct.subtype(),
                ct.attributes().collect::<Vec<_>>(),
            )
        }) != content_type.map(|ct| {
            (
                ct.ctype(),
                ct.subtype(),
                ct.attributes().collect::<Vec<_>>(),
            )
        }) {
            return Err(format!("part {id} content type"));
        }
        if self
            .content_disposition()
            .map(|cd| (cd.ctype(), cd.attributes().collect::<Vec<_>>()))
            != parsed
                .content_disposition()
                .map(|cd| (cd.ctype(), cd.attributes().collect::<Vec<_>>()))
        {
            return Err(format!("part {id} content disposition"));
        }
        if self.content_id() != parsed.content_id()
            || self.content_description() != parsed.content_description()
            || self.content_location() != parsed.content_location()
            || self.content_transfer_encoding() != parsed.content_transfer_encoding()
        {
            return Err(format!("part {id} MIME fields"));
        }
        let languages = parsed
            .content_language()
            .map(|list| list.iter().collect::<Vec<_>>());
        let found = self
            .content_language()
            .is_present()
            .then(|| self.content_language().iter().collect::<Vec<_>>());
        if languages != found {
            return Err(format!("part {id} content language"));
        }
        if self.content_id().is_some()
            && self.content_id_bracketed().map(|id| id.len())
                != self.content_id().map(|id| id.len() + 2)
        {
            return Err(format!("part {id} content id brackets"));
        }
        let content_md5 = parsed
            .headers()
            .get(HeaderName::ContentMd5)
            .and_then(|header| header.value().as_text());
        if self.content_md5() != content_md5 {
            return Err(format!("part {id} content md5"));
        }
        let flags = self.flags();
        let known = PartFlags::IN_TEXT_BODY
            | PartFlags::IN_HTML_BODY
            | PartFlags::ATTACHMENT
            | PartFlags::UNKNOWN_TRANSFER_ENCODING
            | PartFlags::HEADERS_TRUNCATED
            | PartFlags::TRUNCATED;
        if flags.0 & !known.0 != 0 || (self.id() != 0 && flags.contains(PartFlags::TRUNCATED)) {
            return Err(format!("part {id} unknown flags"));
        }
        if flags.contains(PartFlags::IN_TEXT_BODY) != parsed.in_text_body()
            || flags.contains(PartFlags::IN_HTML_BODY) != parsed.in_html_body()
            || flags.contains(PartFlags::ATTACHMENT) != parsed.is_attachment()
            || flags.contains(PartFlags::UNKNOWN_TRANSFER_ENCODING)
                == parsed.has_known_transfer_encoding()
        {
            return Err(format!("part {id} flags"));
        }
        if self.is_message() != parsed.is_message()
            || self.is_multipart() != parsed.is_multipart()
            || self.is_text() != parsed.is_text()
        {
            return Err(format!("part {id} kind"));
        }
        if let (Some(nested), Some(parsed_nested)) = (self.nested(), parsed.nested())
            && nested.id() != parsed_nested.id()
        {
            return Err(format!("part {id} nested id"));
        }
        if self.message().id() != parsed.message().id() {
            return Err(format!("part {id} message"));
        }
        Ok(())
    }
}

#[test]
fn complete_messages_keep_stored_headers() {
    let raw = sample(3);
    for extra in [ExtraHeaders::default(), ExtraHeaders::delivery()] {
        let (row, headers) = extra.encode_raw(&raw);
        let row = read_row(&row);
        let meta = row.unarchive().expect("archive");
        assert_eq!(meta.completeness(), Completeness::Complete);
        let root = meta.root().root_part();
        assert!(!root.is_headers_truncated());
        let complete = root.selected_headers(&headers, HeaderSelection::All);
        assert!(!complete.is_parsed());
        assert_eq!(complete.list().len(), root.headers().len());
    }
}

#[test]
fn truncated_header_blocks_are_parsed_again() {
    const JUNK: usize = MAX_HEADER_ENTRIES + 16;
    let mut raw = String::with_capacity(JUNK * 24 + 512);
    for index in 0..JUNK {
        let _ = write!(raw, "X-Junk-{}: value\r\n", index % 97);
    }
    raw.push_str(concat!(
        "Subject: hidden\r\n",
        "Bcc: blind@example.com\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain; charset=iso-8859-1\r\n",
        "Content-Transfer-Encoding: quoted-printable\r\n",
        "\r\n",
        "caf=E9\r\n",
        "--b--\r\n",
    ));
    for (extra, extra_fields) in [(ExtraHeaders::default(), 0), (ExtraHeaders::delivery(), 2)] {
        let (row, headers) = extra.encode_raw(raw.as_bytes());
        let row = read_row(&row);
        let meta = row.unarchive().expect("archive");
        assert_eq!(meta.completeness(), Completeness::Truncated);
        let root = meta.root().root_part();
        assert!(root.is_headers_truncated());
        assert_eq!(root.headers().len(), MAX_HEADER_ENTRIES);
        assert!(root.headers().last(HeaderId::SUBJECT).is_none());

        let complete = root.selected_headers(&headers, HeaderSelection::All);
        assert!(complete.is_parsed());
        let list = complete.list();
        assert_eq!(list.len(), extra_fields + JUNK + 3);
        for (stored, parsed) in root.headers().iter().zip(list.iter()) {
            assert_eq!(stored.id(), parsed.id());
            assert_eq!(stored.field_range(), parsed.field_range());
            assert_eq!(stored.value_range(), parsed.value_range());
        }
        let subject = list.last(HeaderId::SUBJECT).expect("subject");
        assert_eq!(subject.raw_value(&headers), Some(&b" hidden\r\n"[..]));
        assert_eq!(list.all(HeaderId::BCC).count(), 1);
        assert_eq!(
            meta.strip_root_fields(raw.as_bytes(), HeaderId::BCC)
                .as_ref(),
            raw.replace("Bcc: blind@example.com\r\n", "").as_bytes()
        );

        let raw_message = meta.raw_message(Some(&headers), raw.as_bytes());
        let source = PartSource::Raw(raw_message);
        let text = meta.part(1).expect("text part");
        assert!(text.is_headers_truncated());
        assert!(text.headers().is_empty());
        let block = source.get(text.header_range()).expect("part header block");
        let complete = text.selected_headers(&block, HeaderSelection::All);
        let content_type = complete
            .list()
            .last(HeaderId::CONTENT_TYPE)
            .and_then(|header| source.get(header.value_range()))
            .expect("content type");
        assert_eq!(
            content_type.as_ref(),
            b" text/plain; charset=iso-8859-1\r\n"
        );
        assert_eq!(text.charset(), Some("iso-8859-1"));
        let decoded = text.text(&source).expect("text");
        assert_eq!(decoded.text, "café");
        assert!(!decoded.has_problems);
    }
}

#[test]
fn message_id_is_stored_before_in_reply_to() {
    let mut raw = String::from("In-Reply-To:");
    for index in 0..MAX_TEXT_ITEMS + 8 {
        let _ = write!(raw, "\r\n <r{index}@example.com>");
    }
    raw.push_str("\r\nMessage-ID: <self@example.com>\r\nSubject: ids\r\n\r\nbody\r\n");
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let envelope = meta.root().envelope();
    assert_eq!(envelope.message_id().last(), Some("self@example.com"));
    assert_eq!(envelope.in_reply_to().len(), MAX_TEXT_ITEMS - 1);
    assert_eq!(meta.completeness(), Completeness::Truncated);
}

#[test]
fn each_address_field_has_its_own_budget() {
    let mut raw = String::from("From: ");
    for index in 0..MAX_FIELD_ADDRESSES * 9 {
        if index > 0 {
            raw.push_str(",\r\n ");
        }
        let _ = write!(raw, "sender{index}@example.com");
    }
    raw.push_str(
        "\r\nTo: rcpt@example.com\r\nCc: copy@example.com\r\nSubject: flood\r\n\r\nbody\r\n",
    );
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    let meta = row.unarchive().expect("archive");
    let envelope = meta.root().envelope();
    assert_eq!(
        envelope
            .addresses(AddressHeader::From, Occurrence::All)
            .mailboxes()
            .count(),
        MAX_FIELD_ADDRESSES
    );
    for (header, address) in [
        (AddressHeader::To, "rcpt@example.com"),
        (AddressHeader::Cc, "copy@example.com"),
    ] {
        assert_eq!(
            envelope
                .addresses(header, Occurrence::Last)
                .first()
                .and_then(|mailbox| mailbox.address),
            Some(address)
        );
    }
    assert_eq!(meta.completeness(), Completeness::Truncated);
}

fn late_text_part(flood: impl Fn(&mut String)) -> String {
    let mut raw = String::from("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");
    flood(&mut raw);
    raw.push_str(concat!(
        "--b\r\n",
        "Content-Type: text/plain; charset=iso-8859-1; name=late.txt\r\n",
        "Content-Disposition: attachment; filename=late.txt\r\n",
        "Content-Transfer-Encoding: quoted-printable\r\n",
        "\r\n",
        "caf=E9\r\n",
        "--b--\r\n",
    ));
    raw
}

#[test]
fn earlier_params_never_starve_a_later_charset() {
    let count_flood = late_text_part(|raw| {
        for part in 0..5 {
            let _ = write!(raw, "--b\r\nContent-Type: application/x-{part}");
            for index in 0..1_000 {
                let _ = write!(raw, ";\r\n p{index}=v{index}");
            }
            raw.push_str("\r\n\r\nx\r\n");
        }
    });
    let long = "y".repeat(MAX_VALUE_LEN);
    let pool_flood = late_text_part(|raw| {
        for part in 0..5 {
            let _ = write!(raw, "--b\r\nContent-Type: application/x-{part}");
            for index in 0..60 {
                let _ = write!(raw, ";\r\n p{index}=\"{long}\"");
            }
            raw.push_str("\r\n\r\nx\r\n");
        }
    });
    for raw in [count_flood, pool_flood] {
        let (row, headers) = ExtraHeaders::default().encode_raw(raw.as_bytes());
        let structure = MetadataStructure::deserialize(&row).expect("structure");
        let meta = structure.unarchive().expect("archive");
        assert_eq!(meta.completeness(), Completeness::Truncated);
        assert!(meta.params.len() <= MAX_PARAMS + 3 * meta.parts.len());
        assert!(
            meta.pool().len() <= MAX_POOL_LEN + meta.parts.len() * 16 * MAX_PROTECTED_VALUE_LEN
        );
        let text = meta.parts().last().expect("text part");
        let content_type = text.content_type().expect("content type");
        assert_eq!(content_type.mime_type(), "text/plain");
        assert_eq!(text.charset(), Some("iso-8859-1"));
        assert_eq!(content_type.attribute("name"), Some("late.txt"));
        assert_eq!(text.attachment_name(), Some("late.txt"));
        assert!(
            text.content_disposition()
                .expect("disposition")
                .is_attachment()
        );
        let source = PartSource::Raw(meta.raw_message(Some(&headers), raw.as_bytes()));
        let decoded = text.text(&source).expect("text");
        assert_eq!(decoded.text, "café");
        assert!(!decoded.has_problems);
    }
}

#[test]
fn binary_leaves_store_line_counts() {
    let raw = concat!(
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: image/png\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "AAAA\r\n",
        "BBBB\r\n",
        "CCCC\r\n",
        "--b\r\n",
        "Content-Type: foo\r\n",
        "\r\n",
        "one\r\n",
        "two\r\n",
        "--b--\r\n",
    );
    let (row, _) = ExtraHeaders::default().encode_raw(raw.as_bytes());
    let structure = MetadataStructure::deserialize(&row).expect("structure");
    let meta = structure.unarchive().expect("archive");
    let image = meta.part(1).expect("image");
    assert!(matches!(
        image.kind(),
        PartKind::Binary | PartKind::InlineBinary
    ));
    assert_eq!(image.lines(), 2);
    let bare = meta.part(2).expect("subtype-less part");
    assert_eq!(bare.lines(), 1);
    assert_eq!(meta.part(0).expect("root").lines(), 0);
}

fn mixed_with(part: &str) -> String {
    format!(
        concat!(
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "see below\r\n",
            "--b\r\n",
            "{}",
            "--b--\r\n",
        ),
        part
    )
}

#[test]
fn embedded_messages_count_as_attachments_whatever_their_disposition() {
    let forwarded = concat!(
        "Content-Disposition: inline\r\n",
        "\r\n",
        "From: a@example.com\r\n",
        "Subject: forwarded\r\n",
        "\r\n",
        "body\r\n",
    );
    let inline_cid_image = concat!(
        "Content-Type: multipart/alternative; boundary=\"a\"\r\n",
        "\r\n",
        "--a\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "plain\r\n",
        "--a\r\n",
        "Content-Type: multipart/related; boundary=\"r\"\r\n",
        "\r\n",
        "--r\r\n",
        "Content-Type: text/html\r\n",
        "\r\n",
        "<img src=\"cid:logo\">\r\n",
        "--r\r\n",
        "Content-Type: image/png\r\n",
        "Content-ID: <logo>\r\n",
        "Content-Disposition: inline\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "iVBORw0KGgo=\r\n",
        "--r--\r\n",
        "--a--\r\n",
    );
    let cases = [
        (
            "inline message/rfc822",
            mixed_with(&format!("Content-Type: message/rfc822\r\n{forwarded}")),
            true,
        ),
        (
            "inline message/global",
            mixed_with(&format!("Content-Type: message/global\r\n{forwarded}")),
            true,
        ),
        ("inline cid image", inline_cid_image.to_string(), false),
        (
            "file without disposition",
            mixed_with("Content-Type: application/pdf\r\n\r\nJVBERi0=\r\n"),
            true,
        ),
        (
            "file with attachment disposition",
            mixed_with(concat!(
                "Content-Type: application/pdf\r\n",
                "Content-Disposition: attachment; filename=\"a.pdf\"\r\n",
                "\r\n",
                "JVBERi0=\r\n",
            )),
            true,
        ),
    ];
    for (name, raw, expected) in cases {
        let message = MessageParser::new()
            .parse(raw.as_bytes())
            .expect("message parses");
        assert_eq!(message.root().attachments().len(), 1, "{name}");
        let built = MessageMetadata::build(
            &message,
            &ExtraHeaders::default(),
            BlobHash::generate(message.raw()),
        );
        assert_eq!(built.has_attachments, expected, "{name}");
    }
}

#[test]
fn header_blocks_above_the_archive_limit_inflate() {
    const PAD_LINES: usize = 900_000;
    let line = "a".repeat(76);
    let mut raw = String::with_capacity(PAD_LINES * (line.len() + 3) + 256);
    raw.push_str("Subject: large\r\nX-Pad: start");
    for _ in 0..PAD_LINES {
        raw.push_str("\r\n ");
        raw.push_str(&line);
    }
    raw.push_str("\r\nFrom: a@example.com\r\n\r\nbody\r\n");
    assert!(raw.len() > 64 * 1024 * 1024);
    let (row, headers) = ExtraHeaders::delivery().encode_raw(raw.as_bytes());
    let row = read_row(&row);
    assert!(row.headers_compressed());
    let meta = row.unarchive().expect("archive");
    assert_eq!(meta.headers_len(), headers.len());
    let inflated = row.raw_headers().expect("headers inflate");
    assert_eq!(inflated.len(), headers.len());
    assert!(inflated.as_ref() == headers.as_slice());
}

#[test]
fn inflation_is_bounded_by_the_stored_header_length() {
    let raw = sample(40);
    let (row, headers) = ExtraHeaders::default().encode_raw(&raw);
    assert!(read_row(&row).headers_compressed());
    let trailer = row.get(row.len() - 5..).expect("trailer").to_vec();
    let section_a = trailer
        .first_chunk::<4>()
        .map(|len| u32::from_le_bytes(*len) as usize)
        .expect("section a length");
    let bomb = store::write::compress::compress(
        Some(store::write::Dictionary::Email),
        &vec![b'x'; headers.len() * 64],
        0,
    )
    .expect("compress");
    let mut forged = row.get(..section_a).expect("section a").to_vec();
    forged.extend_from_slice(&bomb);
    forged.extend_from_slice(&trailer);
    let forged = read_row(&forged);
    assert!(forged.raw_headers().is_err());
}
