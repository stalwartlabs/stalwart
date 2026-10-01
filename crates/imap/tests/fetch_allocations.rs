/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::metadata::{
    ExtraHeaders, HeaderId, HeaderMatcher, MessageMetadata, MetadataRow, MetadataStructure,
};
use imap::op::fetch::{
    source::DecodedSources,
    structure::{Binary, ImapMetadata},
};
use imap_proto::protocol::{
    Flag,
    fetch::{DataItem, Section},
};
use mail_parser::MessageParser;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    borrow::Cow,
    cell::Cell,
    fmt::Write,
};
use store::Deserialize;
use types::blob_hash::BlobHash;

const ENVELOPE_AND_STRUCTURE_BUDGET: usize = 1;
const HEADER_FIELDS_BUDGET: usize = 3;
const DECODED_ITEMS: u32 = 32;
const DECODED_SOURCES_BUDGET: usize = 8;
const NESTED_HEADER_FIELDS_BUDGET: usize = 1;
const OUTPUT_CAPACITY: usize = 1024 * 1024;
const ROUNDS: usize = 16;
const INCOMPRESSIBLE_SUBJECT_LEN: usize = 56;
const THUNDERBIRD_FIELDS: [&str; 5] = ["From", "To", "Subject", "Date", "Message-ID"];

struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

impl CountingAllocator {
    fn record() {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
    }

    fn count() -> usize {
        ALLOCATIONS.try_with(Cell::get).unwrap_or_default()
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        CountingAllocator::record();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        CountingAllocator::record();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        CountingAllocator::record();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Sample {
    name: &'static str,
    row: Vec<u8>,
    headers_compressed: bool,
}

impl Sample {
    fn new(name: &'static str, raw: &str, extra: &ExtraHeaders) -> Self {
        let message = MessageParser::new()
            .parse(raw.as_bytes())
            .expect("message parses");
        let row = MessageMetadata::build(&message, extra, BlobHash::generate(raw.as_bytes()))
            .encode()
            .expect("row encodes");
        let headers_compressed = MetadataRow::deserialize(&row)
            .expect("row reads")
            .headers_compressed();
        Sample {
            name,
            row,
            headers_compressed,
        }
    }

    fn envelope_and_structure(&self, output: &mut Vec<u8>) -> usize {
        let before = CountingAllocator::count();
        let structure = MetadataStructure::deserialize(&self.row).expect("structure reads");
        let metadata = structure.unarchive().expect("unarchives");
        DataItem::Uid { uid: 7 }.serialize(output);
        output.push(b' ');
        Flag::write_fetch_item(output, [Flag::Seen, Flag::Flagged]);
        output.extend_from_slice(b" ENVELOPE ");
        metadata.write_envelope(output, false);
        output.extend_from_slice(b" BODYSTRUCTURE ");
        metadata.write_structure(output, true, false);
        drop(structure);
        CountingAllocator::count() - before
    }

    fn header_fields(
        &self,
        output: &mut Vec<u8>,
        section: &Section,
        matcher: &HeaderMatcher,
    ) -> usize {
        let before = CountingAllocator::count();
        let row = MetadataRow::deserialize(&self.row).expect("row reads");
        let metadata = row.unarchive().expect("unarchives");
        let headers = row.raw_headers().expect("headers inflate");
        DataItem::Uid { uid: 7 }.serialize(output);
        output.push(b' ');
        metadata.write_header_fields(output, &headers, section, matcher);
        drop(headers);
        drop(row);
        CountingAllocator::count() - before
    }
}

fn incompressible_message() -> String {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut raw = String::from("Subject: ");
    for _ in 0..INCOMPRESSIBLE_SUBJECT_LEN {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        raw.push(char::from(b'!' + ((state >> 33) % 94) as u8));
    }
    raw.push_str("\r\n\r\nbody\r\n");
    raw
}

fn thunderbird_message(received_hops: usize) -> String {
    let mut raw = String::new();
    for hop in 0..received_hops {
        let _ = write!(
            raw,
            concat!(
                "Received: from relay{hop}.example.net (relay{hop}.example.net [192.0.2.{hop}])\r\n",
                "\tby mx.example.org (Stalwart SMTP) with ESMTPS id {hop:08}\r\n",
                "\tfor <jdoe@example.org>; Mon, 28 Sep 2026 10:{hop:02}:00 +0000\r\n"
            ),
            hop = hop % 100
        );
    }
    raw.push_str(concat!(
        "From: \"Art Vandelay\" <art@vandelay.com>\r\n",
        "To: Friends: jane@example.com, John Smith <john@example.com>;\r\n",
        "Cc: George Costanza <george@example.com>\r\n",
        "Subject: =?utf-8?q?Importing_and_exporting_=E2=98=BA?=\r\n",
        "Date: Sat, 20 Nov 2021 14:22:01 -0800\r\n",
        "Message-ID: <outer@vandelay.com>\r\n",
        "In-Reply-To: <parent@vandelay.com>\r\n",
        "References: <root@vandelay.com> <parent@vandelay.com>\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"outer\"\r\n",
        "\r\n",
        "--outer\r\n",
        "Content-Type: multipart/alternative; boundary=\"alt\"\r\n",
        "\r\n",
        "--alt\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "Content-Transfer-Encoding: quoted-printable\r\n",
        "\r\n",
        "Caf=C3=A9 au lait\r\n",
        "--alt\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>Caf&eacute; au lait</p>\r\n",
        "--alt--\r\n",
        "--outer\r\n",
        "Content-Type: message/rfc822\r\n",
        "\r\n",
        "From: Cosmo Kramer <kramer@kramerica.com>\r\n",
        "Subject: Coffee tables\r\n",
        "\r\n",
        "A book about coffee tables.\r\n",
        "--outer\r\n",
        "Content-Type: image/gif; name=\"table.gif\"\r\n",
        "Content-Disposition: attachment; filename=\"table.gif\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "R0lGODlhAQABAAAAACw=\r\n",
        "--outer--\r\n"
    ));
    raw
}

#[test]
fn fetch_items_stay_within_the_allocation_budget() {
    let mut delivery = ExtraHeaders::default();
    delivery
        .push(HeaderId::DELIVERED_TO, "jdoe@example.org")
        .push(HeaderId::X_SPAM_STATUS, "No, score=-1.2");
    let samples = [
        Sample::new(
            "incompressible header block",
            &incompressible_message(),
            &ExtraHeaders::default(),
        ),
        Sample::new("list message", &thunderbird_message(0), &delivery),
        Sample::new("relayed list message", &thunderbird_message(40), &delivery),
    ];
    assert!(samples.iter().any(|sample| sample.headers_compressed));
    assert!(samples.iter().any(|sample| !sample.headers_compressed));

    let fields = THUNDERBIRD_FIELDS.map(String::from).to_vec();
    let matcher = HeaderMatcher::new(THUNDERBIRD_FIELDS);
    let section = Section::HeaderFields { not: false, fields };
    let mut output = Vec::with_capacity(OUTPUT_CAPACITY);

    for sample in &samples {
        output.clear();
        sample.envelope_and_structure(&mut output);
        output.clear();
        sample.header_fields(&mut output, &section, &matcher);
        let mut structure_max = 0;
        let mut fields_max = 0;
        for _ in 0..ROUNDS {
            output.clear();
            structure_max = structure_max.max(sample.envelope_and_structure(&mut output));
            output.clear();
            fields_max = fields_max.max(sample.header_fields(&mut output, &section, &matcher));
        }
        println!(
            "{} (section B {}): UID FLAGS ENVELOPE BODYSTRUCTURE {structure_max} allocations, UID BODY.PEEK[HEADER.FIELDS] {fields_max} allocations",
            sample.name,
            if sample.headers_compressed {
                "compressed"
            } else {
                "plain"
            }
        );
        assert!(
            structure_max <= ENVELOPE_AND_STRUCTURE_BUDGET,
            "{}: {structure_max}",
            sample.name
        );
        assert!(
            fields_max <= HEADER_FIELDS_BUDGET,
            "{}: {fields_max}",
            sample.name
        );
    }
}

fn encoded_forward() -> String {
    let inner = format!(
        concat!(
            "From: inner@example.com\r\n",
            "Subject: inner\r\n",
            "X-Unknown-A: a\r\n",
            "Content-Type: multipart/mixed; boundary=\"i\"\r\n",
            "\r\n",
            "--i\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "{}\r\n",
            "--i--\r\n"
        ),
        encodify::base64::STANDARD.encode("0123456789abcdef\r\n".repeat(2048).as_bytes())
    );
    format!(
        concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "cover\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "{}\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "{}",
            "--b--\r\n"
        ),
        encodify::base64::STANDARD.encode(inner.as_bytes()),
        inner
    )
}

#[test]
fn decoded_sources_are_decoded_once_per_message() {
    let raw = encoded_forward();
    let message = MessageParser::new()
        .parse(raw.as_bytes())
        .expect("message parses");
    let row = MessageMetadata::build(
        &message,
        &ExtraHeaders::default(),
        BlobHash::generate(raw.as_bytes()),
    )
    .encode()
    .expect("row encodes");
    let structure = MetadataStructure::deserialize(&row).expect("structure reads");
    let metadata = structure.unarchive().expect("unarchives");
    let body = metadata.raw_message(None, raw.as_bytes());
    let text = [Section::Part { num: 2 }, Section::Text];
    let mut output = Vec::with_capacity(OUTPUT_CAPACITY);

    let mut worst = 0;
    for _ in 0..ROUNDS {
        output.clear();
        let before = CountingAllocator::count();
        let mut sources = DecodedSources::default();
        for offset in 0..DECODED_ITEMS {
            let partial = Some((offset * 64, 16));
            if let Some(contents) = metadata.body_section(body, &mut sources, &text, partial, None)
            {
                DataItem::BodySection {
                    sections: Cow::Borrowed(&text),
                    origin_octet: Some(offset * 64),
                    contents,
                }
                .serialize(&mut output);
            }
            if let Binary::Found(contents) = metadata.binary(body, &mut sources, &[2, 1], partial) {
                DataItem::Binary {
                    sections: Cow::Borrowed(&[2, 1]),
                    offset: Some(offset * 64),
                    contents,
                }
                .serialize(&mut output);
            }
        }
        assert_eq!(sources.len(), 2);
        drop(sources);
        worst = worst.max(CountingAllocator::count() - before);
    }
    println!(
        "{} decoded BODY and BINARY partials: {worst} allocations",
        DECODED_ITEMS * 2
    );
    assert!(worst <= DECODED_SOURCES_BUDGET, "{worst}");
}

#[test]
fn nested_header_fields_reuse_the_command_matcher() {
    let raw = encoded_forward();
    let message = MessageParser::new()
        .parse(raw.as_bytes())
        .expect("message parses");
    let row = MessageMetadata::build(
        &message,
        &ExtraHeaders::default(),
        BlobHash::generate(raw.as_bytes()),
    )
    .encode()
    .expect("row encodes");
    let structure = MetadataStructure::deserialize(&row).expect("structure reads");
    let metadata = structure.unarchive().expect("unarchives");
    let body = metadata.raw_message(None, raw.as_bytes());
    let names = ["Subject", "X-Unknown-A", "X-Unknown-B"];
    let sections = [
        Section::Part { num: 3 },
        Section::HeaderFields {
            not: false,
            fields: names.map(String::from).to_vec(),
        },
    ];
    let matcher = HeaderMatcher::new(names);
    let mut output = Vec::with_capacity(OUTPUT_CAPACITY);

    let mut worst = 0;
    for _ in 0..ROUNDS {
        output.clear();
        let before = CountingAllocator::count();
        let mut sources = DecodedSources::default();
        let contents = metadata
            .body_section(body, &mut sources, &sections, None, Some(&matcher))
            .expect("fields");
        DataItem::BodySection {
            sections: Cow::Borrowed(&sections),
            origin_octet: None,
            contents,
        }
        .serialize(&mut output);
        drop(sources);
        worst = worst.max(CountingAllocator::count() - before);
    }
    assert!(output.ends_with(b"Subject: inner\r\nX-Unknown-A: a\r\n\r\n"));
    println!("nested BODY[3.HEADER.FIELDS]: {worst} allocations");
    assert!(worst <= NESTED_HEADER_FIELDS_BUDGET, "{worst}");
}
