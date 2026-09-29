/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::{
    jmap::{BodyValueOptions, EmailRender, HeaderNeeds},
    metadata::{
        Completeness, ExtraHeaders, HeaderId, HeaderMatcher, HeaderSelection, MessageMetadata,
        MetadataRow,
    },
};
use jmap_proto::object::email::{EmailProperty, HeaderForm, HeaderProperty};
use mail_parser::MessageParser;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    fmt::Write,
};
use store::Deserialize;
use types::{blob::BlobId, blob_hash::BlobHash};

const PEAK_BUDGET: usize = 64 * 1024;

struct PeakAllocator;

thread_local! {
    static CURRENT: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

impl PeakAllocator {
    fn grow(bytes: usize) {
        let _ = CURRENT.try_with(|current| {
            let now = current.get().saturating_add(bytes);
            current.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    fn shrink(bytes: usize) {
        let _ = CURRENT.try_with(|current| current.set(current.get().saturating_sub(bytes)));
    }

    fn start() -> usize {
        let now = CURRENT.try_with(Cell::get).unwrap_or_default();
        let _ = PEAK.try_with(|peak| peak.set(now));
        now
    }

    fn peak_since(base: usize) -> usize {
        PEAK.try_with(Cell::get)
            .unwrap_or_default()
            .saturating_sub(base)
    }
}

unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        PeakAllocator::grow(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        PeakAllocator::grow(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        PeakAllocator::grow(new_size);
        PeakAllocator::shrink(layout.size());
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        PeakAllocator::shrink(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator;

struct Stored {
    row: MetadataRow,
    headers: Vec<u8>,
}

impl Stored {
    fn new(raw: &str) -> Self {
        let message = MessageParser::new()
            .parse(raw.as_bytes())
            .expect("message parses");
        let built = MessageMetadata::build(
            &message,
            &ExtraHeaders::default(),
            BlobHash::generate(raw.as_bytes()),
        );
        let row = MetadataRow::deserialize(&built.encode().expect("row encodes")).expect("row");
        let headers = row.raw_headers().expect("headers").into_owned();
        Stored { row, headers }
    }

    fn render_values(&self, properties: &[EmailProperty]) -> (Vec<String>, usize) {
        let meta = self.row.unarchive().expect("archive");
        let needs = HeaderNeeds::new(properties, &[]);
        let options = BodyValueOptions::default();
        let blob_id = BlobId::default();
        let base = PeakAllocator::start();
        let values = {
            let render = EmailRender::new(
                meta,
                Some(&self.headers),
                None,
                &blob_id,
                &needs,
                &[],
                &options,
            );
            properties
                .iter()
                .map(|property| format!("{:?}", render.value(property)))
                .collect::<Vec<_>>()
        };
        (values, PeakAllocator::peak_since(base))
    }

    fn scanned_fields(&self, selection: HeaderSelection<'_>) -> (Vec<String>, usize) {
        let meta = self.row.unarchive().expect("archive");
        let root = meta.root().root_part();
        let mut fields = Vec::with_capacity(16);
        let base = PeakAllocator::start();
        let mut count = 0usize;
        for header in root.scan_headers(&self.headers, selection) {
            if fields.len() < fields.capacity() {
                fields.push(header.view().field_range());
            }
            count += 1;
        }
        let envelope = root
            .selected_headers(&self.headers, HeaderSelection::ENVELOPE)
            .list()
            .iter()
            .filter(|header| HeaderSelection::ENVELOPE.matches(*header, &self.headers))
            .count();
        let peak = PeakAllocator::peak_since(base);
        let text = fields
            .into_iter()
            .map(|range| {
                String::from_utf8_lossy(self.headers.get(range).unwrap_or_default()).into_owned()
            })
            .chain([format!("count {count} envelope {envelope}")])
            .collect();
        (text, peak)
    }
}

fn header(name: &str, form: HeaderForm, all: bool) -> EmailProperty {
    EmailProperty::Header(HeaderProperty {
        form,
        header: name.to_string(),
        all,
    })
}

fn properties() -> Vec<EmailProperty> {
    vec![
        EmailProperty::Subject,
        EmailProperty::From,
        EmailProperty::SentAt,
        header("Subject", HeaderForm::Raw, false),
        header("Content-Type", HeaderForm::Raw, true),
        header("X-Absent", HeaderForm::Text, true),
    ]
}

fn assert_bounded_and_equal(label: &str, truncated: &Stored, twin: &Stored) {
    assert_eq!(
        truncated.row.unarchive().expect("archive").completeness(),
        Completeness::Truncated,
        "{label}"
    );
    assert_eq!(
        twin.row.unarchive().expect("archive").completeness(),
        Completeness::Complete,
        "{label}"
    );
    let properties = properties();
    let (values, peak) = truncated.render_values(&properties);
    assert_eq!(values, twin.render_values(&properties).0, "{label}");
    assert!(
        peak <= PEAK_BUDGET,
        "{label}: EmailRender peak {peak} bytes for a {} byte header block",
        truncated.headers.len()
    );
    for (name, selection) in [
        (
            "fields",
            HeaderSelection::Ids(&[HeaderId::SUBJECT, HeaderId::FROM]),
        ),
        ("content", HeaderSelection::Content),
    ] {
        let (fields, peak) = truncated.scanned_fields(selection);
        let (twin_fields, _) = twin.scanned_fields(selection);
        assert_eq!(fields, twin_fields, "{label} {name}");
        assert!(
            peak <= PEAK_BUDGET,
            "{label} {name}: scan peak {peak} bytes for a {} byte header block",
            truncated.headers.len()
        );
    }
    let matcher = HeaderMatcher::new(["subject", "content-type"]);
    let (fields, _) = truncated.scanned_fields(HeaderSelection::Named(&matcher));
    assert_eq!(
        fields,
        twin.scanned_fields(HeaderSelection::Named(&matcher)).0,
        "{label} named"
    );
}

#[test]
fn five_million_empty_fields_render_in_bounded_memory() {
    const LINES: usize = 5_000_000;
    let tail = "Subject: hi\r\n\r\nbody\r\n";
    let mut raw = String::with_capacity(LINES * 4 + tail.len());
    for _ in 0..LINES {
        raw.push_str("a:\r\n");
    }
    raw.push_str(tail);
    let truncated = Stored::new(&raw);
    assert!(truncated.headers.len() > 20_000_000);
    drop(raw);
    assert_bounded_and_equal("5,000,000 fields", &truncated, &Stored::new(tail));
}

#[test]
fn two_hundred_thousand_junk_fields_render_in_bounded_memory() {
    const LINES: usize = 200_000;
    let mut raw = String::from("From: a@example.com\r\n");
    for index in 0..LINES {
        let _ = write!(raw, "X-Junk: {index}\r\n");
    }
    let tail = "Subject: hidden\r\nContent-Type: text/plain\r\n\r\nbody\r\n";
    raw.push_str(tail);
    let twin = format!("From: a@example.com\r\n{tail}");
    assert_bounded_and_equal("200,000 fields", &Stored::new(&raw), &Stored::new(&twin));
}
