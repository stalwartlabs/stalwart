/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ExtraHeaders, HeaderId, HeaderMatcher, HeaderScan, HeaderSelection, MAX_HEADER_ENTRIES,
    MessageMetadata, MetadataRow,
};
use mail_parser::MessageParser;
use std::fmt::Write as _;
use store::Deserialize;
use types::blob_hash::BlobHash;

type Entry = (HeaderId, u32, u32, u32);

fn parsed(block: &[u8], base: u32) -> Vec<Entry> {
    MessageParser::new()
        .parse_headers(block)
        .map(|message| {
            message
                .root_part()
                .headers()
                .iter()
                .map(|header| {
                    (
                        HeaderId::parse(header.name().as_str().as_bytes()),
                        base + header.offset_field(),
                        base + header.offset_start(),
                        base + header.offset_end(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn scanned(scan: HeaderScan<'_>) -> Vec<Entry> {
    scan.map(|header| {
        let view = header.view();
        let field = view.field_range();
        let value = view.value_range();
        (
            view.id(),
            field.start as u32,
            value.start as u32,
            field.end as u32,
        )
    })
    .collect()
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }
}

fn shapes() -> Vec<Vec<u8>> {
    let mut shapes: Vec<Vec<u8>> = [
        &b"Subject: x\r\n\r\nbody"[..],
        b"Subject: x\r\nFrom: a@b\r\n",
        b"not a header line\r\nSubject: x\r\n\r\n",
        b" folded start\r\nSubject: x\r\n\r\n",
        b"From mbox line\r\nFrom: a@b\r\n\r\n",
        b"garbage\r\n next: value\r\nSubject: y\r\n\r\n",
        b"garbage\r\n \r\nSubject: hidden\r\n\r\n",
        b"::  From: v\r\n: only colon\r\n next: x\r\n\r\n",
        b"From\r: x\r\nSubject \t: y\r\nX-Other : z\r\n\r\n",
        b"SUBJECT: a\nsubject:b\n\tcontinued\n\n",
        b"X-\xff\xfe: v\r\ncaf\xc3\xa9: w\r\n\r\n",
        b"Subject: no newline at end",
        b"\r\n\r\nSubject: after blank",
        b"\x0c\rSubject: odd lead\r\n\r\n",
        b"",
        b"   \r\n",
        b"a:\r\na:\r\na:",
    ]
    .iter()
    .map(|shape| shape.to_vec())
    .collect();
    let long = format!("X-Long: {}\r\n\r\n", "v".repeat(70_000));
    shapes.push(long.into_bytes());
    let mut name = "X-".repeat(40);
    name.push_str(": v\r\n\r\n");
    shapes.push(name.into_bytes());
    shapes
}

#[test]
fn header_scan_matches_the_parser() {
    for shape in shapes() {
        assert_eq!(
            scanned(HeaderScan::new(&shape, 7, HeaderSelection::All)),
            parsed(&shape, 7),
            "{:?}",
            String::from_utf8_lossy(&shape)
        );
    }
    let alphabet = b"aZ-:: \t\r\n\x00\x80\xc3\xa9!~";
    let names = ["Subject", "From", "X-Junk", "content-type", "To", ""];
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..40_000 {
        let mut block = Vec::new();
        for _ in 0..rng.below(6) {
            if rng.below(3) == 0 {
                block.extend((0..rng.below(24)).map(|_| alphabet[rng.below(alphabet.len())]));
            } else {
                block.extend_from_slice(names[rng.below(names.len())].as_bytes());
                block.push(b':');
                block.extend((0..rng.below(12)).map(|_| alphabet[rng.below(alphabet.len())]));
                block.extend_from_slice(if rng.below(2) == 0 { b"\r\n" } else { b"\n" });
            }
        }
        assert_eq!(
            scanned(HeaderScan::new(&block, 0, HeaderSelection::All)),
            parsed(&block, 0),
            "{block:?}"
        );
    }
}

#[test]
fn selections_keep_only_their_fields() {
    let block = concat!(
        "From: a@example.com\r\n",
        "X-Custom: one\r\n",
        "Subject: s\r\n",
        "content-type: text/plain\r\n",
        "Content-Baz: proper\r\n",
        "CONTENT-ID: <c@d>\r\n",
        "Contentless: no\r\n",
        "x-custom: two\r\n",
        "To: b@example.com\r\n",
        "\r\n",
    )
    .as_bytes();
    let names = |selection: HeaderSelection<'_>| -> Vec<String> {
        HeaderScan::new(block, 0, selection)
            .map(|header| String::from_utf8_lossy(header.view().raw_name(block)).into_owned())
            .collect()
    };
    let matcher = HeaderMatcher::new(["x-custom", "subject"]);
    assert_eq!(
        names(HeaderSelection::Named(&matcher)),
        ["X-Custom", "Subject", "x-custom"]
    );
    assert_eq!(
        names(HeaderSelection::Except(&matcher)),
        [
            "From",
            "content-type",
            "Content-Baz",
            "CONTENT-ID",
            "Contentless",
            "To"
        ]
    );
    assert_eq!(
        names(HeaderSelection::Content),
        ["content-type", "Content-Baz", "CONTENT-ID"]
    );
    assert_eq!(names(HeaderSelection::ENVELOPE), ["From", "Subject", "To"]);
    assert_eq!(
        names(HeaderSelection::Ids(&[HeaderId::TO, HeaderId::FROM])),
        ["From", "To"]
    );
    for header in HeaderScan::new(block, 0, HeaderSelection::All) {
        let view = header.view();
        for selection in [
            HeaderSelection::Named(&matcher),
            HeaderSelection::Except(&matcher),
            HeaderSelection::Content,
            HeaderSelection::ENVELOPE,
        ] {
            let scanned = HeaderScan::new(block, 0, selection)
                .any(|other| other.view().field_range() == view.field_range());
            assert_eq!(selection.matches(view, block), scanned);
        }
    }
}

#[test]
fn root_scans_split_extra_headers_from_the_message() {
    let mut raw = String::from("not a header line\r\n");
    for index in 0..MAX_HEADER_ENTRIES + 8 {
        let _ = write!(raw, "X-Junk: {index}\r\n");
    }
    raw.push_str("Subject: hidden\r\nContent-Type: text/plain\r\n\r\nbody\r\n");
    let mut extra = ExtraHeaders::default();
    extra
        .push(HeaderId::DELIVERED_TO, "jdoe@example.org")
        .push(HeaderId::X_SPAM_STATUS, "No");
    let message = MessageParser::new()
        .parse(raw.as_bytes())
        .expect("message parses");
    let built = MessageMetadata::build(&message, &extra, BlobHash::generate(raw.as_bytes()));
    let headers = built.raw_headers.clone();
    let row = MetadataRow::deserialize(&built.encode().expect("row encodes")).expect("row");
    let meta = row.unarchive().expect("archive");
    let root = meta.root().root_part();
    assert!(root.is_headers_truncated());
    let mut expected = parsed(extra.as_bytes(), 0);
    expected.extend(parsed(
        headers.get(extra.len()..).unwrap_or_default(),
        extra.len() as u32,
    ));
    assert_eq!(
        scanned(root.scan_headers(&headers, HeaderSelection::All)),
        expected
    );
    for (stored, scanned) in root
        .headers()
        .iter()
        .zip(root.scan_headers(&headers, HeaderSelection::All))
    {
        let scanned = scanned.view();
        assert_eq!(stored.id(), scanned.id());
        assert_eq!(stored.field_range(), scanned.field_range());
        assert_eq!(stored.value_range(), scanned.value_range());
    }
    let subject = root.selected_headers(&headers, HeaderSelection::Ids(&[HeaderId::SUBJECT]));
    assert!(subject.is_parsed());
    assert_eq!(subject.list().len(), 1);
    assert_eq!(
        subject
            .list()
            .last(HeaderId::SUBJECT)
            .and_then(|header| header.raw_value(&headers)),
        Some(&b" hidden\r\n"[..])
    );
}
