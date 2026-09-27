/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod common;

use common::{
    pdf::{Document, Pdf, zlib},
    *,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    fmt::Write as _,
    sync::{Mutex, MutexGuard, PoisonError},
    thread,
    time::{Duration, Instant},
};
use text_extract::{Error, Extraction, Extractor, Format, Hints, Limits};

const SMALL_STACK: usize = 256 << 10;
const TIME_LIMIT: Duration = Duration::from_secs(20);
const GROWTH: usize = 4;
const MAX_GROWTH_RATIO: u32 = 8;
const GROWTH_SLACK: Duration = Duration::from_millis(50);
const GROWTH_RUNS: usize = 3;

static TIMED: Mutex<()> = Mutex::new(());

fn exclusive() -> MutexGuard<'static, ()> {
    TIMED.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Tracking;

thread_local! {
    static LIVE: Cell<usize> = const { Cell::new(0) };
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        shrink(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        shrink(layout.size());
        grow(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

fn grow(bytes: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get().saturating_add(bytes);
        live.set(now);
        let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
    });
}

fn shrink(bytes: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(bytes)));
}

struct Measured {
    result: Result<Extraction, Error>,
    elapsed: Duration,
    peak: usize,
}

fn measure_with(data: Vec<u8>, limits: Limits) -> Measured {
    let _timed = exclusive();
    thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(move || {
            LIVE.with(|live| live.set(0));
            PEAK.with(|peak| peak.set(0));
            let started = Instant::now();
            let (result, text) = run_with(&data, Hints::new(), &limits);
            let elapsed = started.elapsed();
            drop(text);
            Measured {
                result,
                elapsed,
                peak: PEAK.with(Cell::get),
            }
        })
        .unwrap_or_else(|err| panic!("spawn: {err}"))
        .join()
        .unwrap_or_else(|_| panic!("extraction panicked or overflowed the stack"))
}

fn hostile(name: &str, data: Vec<u8>, max_peak: usize) -> Result<Extraction, Error> {
    hostile_with(name, data, Limits::default(), max_peak)
}

fn hostile_with(
    name: &str,
    data: Vec<u8>,
    limits: Limits,
    max_peak: usize,
) -> Result<Extraction, Error> {
    let measured = measure_with(data, limits);
    assert!(
        measured.elapsed < TIME_LIMIT,
        "{name}: took {:?}",
        measured.elapsed
    );
    assert!(
        measured.peak <= max_peak,
        "{name}: peak heap {} > {max_peak}",
        measured.peak
    );
    if let Ok(extraction) = &measured.result {
        assert_eq!(extraction.format, Format::Pdf, "{name}");
    }
    measured.result
}

fn elapsed(data: &[u8]) -> Duration {
    measure_with(data.to_vec(), Limits::default()).elapsed
}

fn assert_linear(name: &str, base: usize, build: impl Fn(usize) -> Vec<u8>) {
    let small_data = build(base);
    let small = (0..GROWTH_RUNS)
        .map(|_| elapsed(&small_data))
        .min()
        .unwrap_or_default();
    let limit = small * MAX_GROWTH_RATIO + GROWTH_SLACK;
    let large_size = base * GROWTH;
    let large_data = build(large_size);
    let mut large = Duration::MAX;
    for _ in 0..GROWTH_RUNS {
        large = large.min(elapsed(&large_data));
        if large < limit {
            return;
        }
    }
    panic!("{name}: {small:?} at {base}, {large:?} at {large_size}");
}

fn tree(pdf: &mut Pdf, content: &[u8]) {
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
        .stream(4, "", content);
}

fn nested(levels: usize, pattern: &[&str]) -> String {
    pattern.iter().copied().cycle().take(levels).collect()
}

fn trailer_raw(pdf: &mut Pdf, xref_at: usize) {
    pdf.raw(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());
}

#[test]
fn nesting_never_recurses() {
    const LEVELS: usize = 1_000_000;
    for pattern in [&["["][..], &["<<"], &["[", "<<", "[", "<<"]] {
        let deep = nested(LEVELS, pattern);
        let mut pdf = Pdf::new();
        pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(
                2,
                &format!("<< /Type /Pages /Kids [3 0 R {deep}] /Count 1 >>"),
            )
            .object(
                3,
                &format!("<< /Type /Page /Parent 2 0 R /Contents 4 0 R /X {deep} >>"),
            )
            .stream(4, "", format!("BT {deep} TJ ET").as_bytes())
            .object_stream(10, &[(20, &deep)], true)
            .xref_stream(11, &format!("/Root 1 0 R /Deep {deep}"));
        let result = hostile("nesting", pdf.build(), 16 << 20);
        assert!(result.is_ok(), "{result:?}");

        let mut classic = Pdf::new();
        tree(&mut classic, deep.as_bytes());
        classic.xref_table(&format!("/Root 1 0 R /Deep {deep}"));
        assert!(hostile("nesting trailer", classic.build(), 16 << 20).is_ok());
    }
    let strings = format!("{}{}", "(".repeat(LEVELS), ")".repeat(LEVELS));
    let mut pdf = Pdf::new();
    tree(&mut pdf, strings.as_bytes());
    pdf.object(5, &strings).xref_table("/Root 1 0 R");
    assert!(hostile("parentheses", pdf.build(), 16 << 20).is_ok());
}

#[test]
fn cross_reference_claims_are_not_trusted() {
    let mut pdf = Pdf::new();
    tree(&mut pdf, b"BT ET");
    let xref_at = pdf.offset();
    pdf.raw(b"xref\n0 5\n0000000000 65535 f\r\n");
    for num in 1..5 {
        let offset = pdf
            .data
            .windows(8)
            .position(|window| window == format!("\n{num} 0 obj").as_bytes())
            .unwrap_or_default()
            + 1;
        pdf.raw(format!("{offset:010} 00000 n\r\n").as_bytes());
    }
    pdf.raw(b"8388000 3\n0000000009 00000 n\r\n0000000009 00000 n\r\n4294967295 1\n9999999999 00000 n\r\n");
    pdf.raw(b"trailer\n<< /Size 4000000000 /Root 1 0 R >>\n");
    trailer_raw(&mut pdf, xref_at);
    assert!(hostile("xref claims", pdf.build(), 2 << 20).is_ok());

    for (widths, index, data) in [
        ("[0 0 0]", "[0 4000000000]", vec![]),
        ("[0 0 0]", "[0 5]", vec![0u8; 64]),
        ("[1 9 0]", "[0 5]", vec![1u8; 64]),
        ("[8 8 8]", "[4294967295 10 0 1]", vec![0xFFu8; 240]),
        ("[1 4 2]", "[4294967290 100 -5 2 1 2 3]", vec![1u8; 700]),
        ("[1 1 1]", "[0 99999999999]", vec![2u8; 3 << 18]),
        ("[1 2 3 4]", "[]", vec![1u8; 10]),
    ] {
        let mut pdf = Pdf::new();
        tree(&mut pdf, b"BT ET");
        let at = pdf.offset();
        let compressed = zlib(&data);
        let mut body = format!(
            "<< /Type /XRef /W {widths} /Index {index} /Size 4000000000 /Root 1 0 R /Filter /FlateDecode /Length {} >>\nstream\n",
            compressed.len()
        )
        .into_bytes();
        body.extend_from_slice(&compressed);
        body.extend_from_slice(b"\nendstream");
        pdf.object_bytes(9, &body);
        trailer_raw(&mut pdf, at);
        let result = hostile(widths, pdf.build(), 8 << 20);
        assert!(result.is_ok(), "{widths} {index}: {result:?}");
    }
}

#[test]
fn previous_section_chains_are_bounded() {
    let mut looping = Pdf::new();
    tree(&mut looping, b"BT ET");
    let first = looping.offset();
    looping.raw(format!("xref\n0 1\n0000000000 65535 f\r\ntrailer\n<< /Root 1 0 R /Prev {first} /XRefStm {first} >>\n").as_bytes());
    let second = looping.offset();
    looping.raw(
        format!("xref\n0 1\n0000000000 65535 f\r\ntrailer\n<< /Root 1 0 R /Prev {first} >>\n")
            .as_bytes(),
    );
    trailer_raw(&mut looping, second);
    assert!(hostile("prev loop", looping.build(), 1 << 20).is_ok());

    let mut long = Pdf::new();
    tree(&mut long, b"BT ET");
    long.xref_table("/Root 1 0 R");
    for _ in 0..2000 {
        long.xref_table("/Root 1 0 R");
    }
    assert!(hostile("long chain", long.build(), 4 << 20).is_ok());
}

#[test]
fn reference_cycles_resolve_to_null() {
    let mut chain = Pdf::new();
    chain.object(1, "<< /Type /Catalog /Pages 1000 0 R >>");
    for num in 1000..3000 {
        chain.object(num, &format!("{} 0 R", num + 1));
    }
    chain
        .object(3000, "<< /Type /Pages /Kids [5 0 R] /Count 1 >>")
        .object(5, "<< /Type /Page /Contents 6 0 R >>")
        .stream(6, "", b"BT ET")
        .object(7, "8 0 R")
        .object(8, "7 0 R")
        .xref_table("/Root 1 0 R /Info 7 0 R");
    let result = hostile("reference chain", chain.build(), 4 << 20);
    assert!(result.is_ok(), "{result:?}");

    let mut lengths = Pdf::new();
    lengths
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R 5 0 R 7 0 R] /Count 3 >>")
        .object(3, "<< /Type /Page /Contents 4 0 R >>")
        .stream_with_length(4, "", b"BT (self) Tj ET", "4 0 R")
        .object(5, "<< /Type /Page /Contents 6 0 R >>")
        .stream_with_length(6, "", b"BT (stream) Tj ET", "4 0 R")
        .object(7, "<< /Type /Page /Contents 8 0 R >>")
        .stream_with_length(8, "", b"BT (neg) Tj ET", "-99999999999999999999")
        .xref_table("/Root 1 0 R");
    assert!(hostile("length refs", lengths.build(), 1 << 20).is_ok());
}

#[test]
fn page_tree_graphs_are_walked_once() {
    let mut dag = Pdf::new();
    dag.object(1, "<< /Type /Catalog /Pages 10 0 R >>");
    for level in 10..70 {
        dag.object(
            level,
            &format!(
                "<< /Type /Pages /Kids [{0} 0 R {0} 0 R {0} 0 R] /Count 3 >>",
                level + 1
            ),
        );
    }
    dag.object(70, "<< /Type /Page /Contents 71 0 R >>")
        .stream(71, "", b"BT ET")
        .xref_table("/Root 1 0 R");
    let result = hostile("dag fan-out", dag.build(), 1 << 20);
    assert_eq!(
        result.map(|extraction| extraction.bytes_decompressed),
        Ok(5)
    );

    let mut deep = Pdf::new();
    deep.object(1, "<< /Type /Catalog /Pages 10 0 R >>");
    for level in 10..20_010 {
        deep.object(
            level,
            &format!("<< /Type /Pages /Kids [{} 0 R] >>", level + 1),
        );
    }
    deep.object(20_010, "<< /Type /Page /Contents 2 0 R >>")
        .stream(2, "", b"BT ET")
        .xref_table("/Root 1 0 R");
    assert!(hostile("deep tree", deep.build(), 8 << 20).is_ok());

    let mut cycles = Pdf::new();
    cycles
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(
            2,
            "<< /Type /Pages /Kids [2 0 R 3 0 R 1 0 R] /Parent 3 0 R >>",
        )
        .object(3, "<< /Type /Pages /Kids [2 0 R 4 0 R] /Parent 2 0 R >>")
        .object(4, "<< /Type /Page /Parent 4 0 R /Contents 5 0 R >>")
        .stream(5, "", b"BT ET")
        .xref_table("/Root 1 0 R");
    let result = hostile("cycles", cycles.build(), 1 << 20);
    assert_eq!(
        result.map(|extraction| extraction.bytes_decompressed),
        Ok(5)
    );

    let mut parents = Pdf::new();
    parents
        .object(1, "<< /Type /Catalog /Pages 9 0 R >>")
        .object(2, "<< /Type /Pages /Kids [] /Parent 3 0 R >>")
        .object(3, "<< /Type /Pages /Kids [] /Parent 2 0 R >>")
        .object(4, "<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>")
        .stream(5, "", b"BT ET")
        .xref_table("/Root 1 0 R");
    assert!(hostile("parent loop", parents.build(), 4 << 20).is_ok());

    let pages = 20_000;
    let mut many = Pdf::new();
    let kids: String = (0..pages)
        .map(|page| format!("{} 0 R ", 10 + page))
        .collect();
    many.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, &format!("<< /Type /Pages /Kids [{kids}] >>"))
        .stream(3, "", b"BT ET");
    for page in 0..pages {
        many.object(
            10 + page,
            "<< /Type /Page /Parent 2 0 R /Contents [3 0 R] >>",
        );
    }
    many.xref_table("/Root 1 0 R");
    let result = hostile("many pages", many.build(), 8 << 20);
    assert_eq!(
        result.map(|extraction| extraction.bytes_decompressed),
        Ok(5 * u64::from(pages))
    );
}

#[test]
fn object_stream_attacks() {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R 6 0 R] >>")
        .object_stream(
            10,
            &[(10, "<< /Type /Page >>"), (3, "<< /Type /Page >>")],
            false,
        )
        .object_stream(
            11,
            &[(12, "<< /Type /ObjStm >>"), (4, "<< /Type /Page >>")],
            true,
        )
        .object_stream(
            12,
            &[(11, "<< /Type /ObjStm >>"), (5, "<< /Type /Page >>")],
            true,
        );
    pdf.stream_with_length(
        13,
        "/Type /ObjStm /N 9999999999 /First 99999",
        b"6 0 7 1000000 (x)",
        "14 0 R",
    )
    .object(14, "17")
    .xref_stream(20, "/Root 1 0 R");
    let result = hostile("object streams", pdf.build(), 2 << 20);
    assert!(result.is_ok(), "{result:?}");

    let mut indirect = Pdf::new();
    indirect
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] >>")
        .stream_with_length(
            10,
            "/Type /ObjStm /N 2 /First 8",
            b"3 0 4 20<< /Type /Page >> 30",
            "4 0 R",
        )
        .xref_stream(20, "/Root 1 0 R");
    assert!(hostile("objstm length cycle", indirect.build(), 2 << 20).is_ok());
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Packing {
    Plain,
    RunLength,
}

fn padded_object_streams(streams: u32, packing: Packing) -> Vec<u8> {
    let padding = format!("({})", "p".repeat(1 << 20));
    let mut pdf = Pdf::new();
    let kids: String = (0..streams)
        .map(|index| format!("{} 0 R ", 1000 + index))
        .collect();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, &format!("<< /Type /Pages /Kids [{kids}] >>"));
    for index in 0..streams {
        let page = format!(
            "<< /Type /Page /Contents {} 0 R /Resources << /Font << /F1 << \
             /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>",
            3000 + index
        );
        let members = [(1000 + index, page.as_str()), (5000 + index, &padding)];
        pdf.stream(
            3000 + index,
            "",
            format!("BT /F1 12 Tf 72 700 Td (page{index}) Tj ET").as_bytes(),
        );
        match packing {
            Packing::Plain => pdf.object_stream(100 + index, &members, false),
            Packing::RunLength => pdf.run_length_object_stream(100 + index, &members),
        };
    }
    pdf.xref_stream(99, "/Root 1 0 R");
    pdf.build()
}

#[test]
fn retained_object_streams_are_capped() {
    let data = padded_object_streams(40, Packing::RunLength);
    assert!(data.len() < 4 << 20);
    let result = hostile("retained objstm", data, 64 << 20);
    let extraction = result.unwrap_or_else(|err| panic!("{err:?}"));
    assert!(extraction.truncated);
}

#[test]
fn object_streams_beyond_the_floor_resolve_in_large_inputs() {
    const STREAMS: u32 = 40;
    let data = padded_object_streams(STREAMS, Packing::Plain);
    assert!(data.len() > 32 << 20);
    let (result, text) = run(&data);
    let extraction = result.unwrap_or_else(|err| panic!("{err:?}"));
    assert!(!extraction.truncated);
    for index in 0..STREAMS {
        assert!(
            text.contains(&format!("page{index}")),
            "page{index} missing"
        );
    }
}

#[test]
fn object_scan_budget_stops_quadratic_lookups() {
    let big: String = (0..200_000)
        .map(|index| format!("/K{index} {index} "))
        .collect();
    let refs = "5 0 R ".repeat(30_000);
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] >>")
        .object(3, &format!("<< /Type /Page /Contents [{refs}] >>"))
        .object(5, &format!("<< {big} >>"))
        .xref_table("/Root 1 0 R");
    let data = pdf.build();
    assert!(data.len() < 4 << 20);
    let started = Instant::now();
    let result = measure_with(data, Limits::default());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert!(result.result.is_ok_and(|extraction| extraction.truncated));
}

#[test]
fn decompression_bombs_stop_at_the_budget() {
    let limits = Limits {
        max_part_bytes: 4 << 20,
        max_total_bytes: 16 << 20,
        ..Limits::default()
    };
    let bomb = zlib(&vec![b'0'; 64 << 20]);
    let nested = zlib(&zlib(&vec![b' '; 64 << 20]));
    for (name, filters, data) in [
        ("flate", "/Filter /FlateDecode", bomb.clone()),
        (
            "flate of flate",
            "/Filter [/FlateDecode /FlateDecode]",
            nested,
        ),
        (
            "hex then flate",
            "/Filter [/ASCIIHexDecode /FlateDecode]",
            {
                let mut hex = String::with_capacity(bomb.len() * 2);
                for byte in &bomb {
                    let _ = write!(hex, "{byte:02x}");
                }
                hex.into_bytes()
            },
        ),
        (
            "run length",
            "/Filter /RunLengthDecode",
            [0x81u8, b'x'].repeat(200_000),
        ),
    ] {
        let mut pdf = Pdf::new();
        pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(
                2,
                "<< /Type /Pages /Kids [3 0 R 5 0 R 6 0 R 7 0 R 8 0 R] >>",
            )
            .object(3, "<< /Type /Page /Contents [4 0 R 4 0 R] >>")
            .stream(4, filters, &data);
        for page in 5..9 {
            pdf.object(page, "<< /Type /Page /Contents 4 0 R >>");
        }
        pdf.xref_table("/Root 1 0 R");
        let result = hostile_with(name, pdf.build(), limits.clone(), 64 << 20);
        let extraction = result.unwrap_or_else(|err| panic!("{name}: {err:?}"));
        assert!(
            extraction.bytes_decompressed <= limits.max_total_bytes,
            "{name}"
        );
        if name != "run length" {
            assert!(extraction.truncated, "{name}");
        }
    }
}

#[test]
fn predictor_and_filter_parameters() {
    let data = zlib(&[2u8; 1000]);
    for params in [
        "/Predictor 12 /Columns 0",
        "/Predictor 12 /Columns 1099511627776",
        "/Predictor 15 /Colors 1000000000 /BitsPerComponent 16",
        "/Predictor 2 /BitsPerComponent 3 /Columns -4",
        "/Predictor -1",
        "/EarlyChange 7",
    ] {
        let mut pdf = Pdf::new();
        pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(2, "<< /Type /Pages /Kids [3 0 R] >>")
            .object(3, "<< /Type /Page /Contents 4 0 R >>")
            .stream(
                4,
                &format!(
                    "/Filter [/FlateDecode /LZWDecode] /DecodeParms [<< {params} >> << {params} >>]"
                ),
                &data,
            )
            .xref_table("/Root 1 0 R");
        assert!(hostile(params, pdf.build(), 1 << 20).is_ok(), "{params}");
    }
}

#[test]
fn missing_endstream_everywhere_is_linear() {
    let build = |count: usize| {
        let count = count as u32;
        let mut pdf = Pdf::new();
        let kids: String = (0..count)
            .map(|index| format!("{} 0 R ", 100 + index * 2))
            .collect();
        pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(2, &format!("<< /Type /Pages /Kids [{kids}] >>"));
        for index in 0..count {
            let num = 100 + index * 2;
            pdf.object(num, &format!("<< /Type /Page /Contents {} 0 R >>", num + 1));
            pdf.object_bytes(
                num + 1,
                b"<< /Length 999999999 >>\nstream\nBT (no end) Tj ET",
            );
        }
        pdf.xref_table("/Root 1 0 R");
        let text = String::from_utf8_lossy(&pdf.build()).replace("endobj", "enddbj");
        text.into_bytes()
    };
    let result = hostile("missing endstream", build(20_000), 300 << 20);
    assert!(result.is_ok(), "{result:?}");
    assert_linear("missing endstream", 2_500, build);
}

#[test]
fn repair_scan_is_linear() {
    let garbage = |bytes: usize| {
        let mut garbage = Vec::with_capacity(bytes + 64);
        garbage.extend_from_slice(b"%PDF-1.4\n");
        let mut rng = Rng::new(7);
        let pieces: [&[u8]; 10] = [
            b"<<",
            b">>",
            b"[",
            b"(",
            b"1 0 obj ",
            b"12 0 R ",
            b"stream\n",
            b"trailer ",
            b"/Type /Page ",
            b"999",
        ];
        while garbage.len() < bytes {
            garbage.extend_from_slice(pieces[rng.below(pieces.len())]);
            garbage.push(rng.below(256) as u8);
        }
        garbage
    };
    assert_eq!(
        hostile("garbage", garbage(2 << 20), 64 << 20),
        Err(Error::Unsupported)
    );
    assert_linear("garbage", 256 << 10, garbage);

    let tiny = |count: usize| {
        let mut tiny = Vec::with_capacity(count * 24 + 256);
        tiny.extend_from_slice(b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj 2 0 obj << /Type /Pages /Kids [3 0 R] >> endobj 3 0 obj << /Type /Page >> endobj\n");
        for num in 4..count {
            tiny.extend_from_slice(format!("{num} 0 obj null endobj\n").as_bytes());
        }
        tiny.extend_from_slice(b"trailer << /Root 1 0 R >>\n%%EOF\n");
        tiny
    };
    let result = hostile("many tiny objects", tiny(200_000), 40 << 20);
    assert!(result.is_ok(), "{result:?}");
    assert_linear("many tiny objects", 25_000, tiny);
}

#[test]
fn huge_numbers_and_offsets() {
    let digits = "9".repeat(1000);
    let mut pdf = Pdf::new();
    pdf.object(
        1,
        &format!("<< /Type /Catalog /Pages 2 0 R /N {digits} /R -{digits}.{digits} >>"),
    )
    .object(
        2,
        &format!("<< /Type /Pages /Kids [3 0 R 99999999 0 R {digits} 0 R 4 {digits} R] >>"),
    )
    .object(
        3,
        &format!("<< /Type /Page /Contents 4 0 R /Rotate {digits} >>"),
    )
    .stream_with_length(4, "", b"BT ET", &digits)
    .xref_table(&format!("/Root 1 0 R /Prev {digits} /XRefStm -5"));
    assert!(hostile("huge numbers", pdf.build(), 1 << 20).is_ok());
}

#[test]
fn contents_repetition_and_truncated_files() {
    let refs = "4 0 R ".repeat(100_000);
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] >>")
        .object(3, &format!("<< /Type /Page /Contents [{refs}] >>"))
        .stream(4, "", b"BT ET")
        .xref_table("/Root 1 0 R");
    let result = hostile("contents repetition", pdf.build(), 2 << 20);
    assert_eq!(
        result.map(|extraction| extraction.bytes_decompressed),
        Ok(500_000)
    );

    let mut document = Document::new(&[b"BT (one) Tj ET", b"BT (two) Tj ET"]);
    document.compress = true;
    document.object_streams = true;
    let full = document.build();
    let started = Instant::now();
    for cut in (0..full.len()).step_by(7) {
        let (result, _) = run(full.get(..cut).unwrap_or_default());
        if let Ok(extraction) = result {
            assert_eq!(extraction.format, Format::Pdf);
        }
    }
    assert!(started.elapsed() < Duration::from_secs(10));

    let mut padded = full.clone();
    padded.extend(std::iter::repeat_n(0u8, 1 << 20));
    assert!(hostile("nul padding", padded, 4 << 20).is_ok());
    let at = full
        .windows(10)
        .rposition(|window| window == b"startxref\n")
        .unwrap_or_default();
    let mut zeroed = full.clone();
    zeroed.splice(at..at, b"startxref\n0\n%%EOF\n".iter().copied());
    assert!(hostile("startxref zero", zeroed, 4 << 20).is_ok());
}

#[test]
fn structure_aware_mutations() {
    let mut document = Document::new(&[b"BT (mutate me) Tj ET", b"BT (again) Tj ET"]);
    document.compress = true;
    document.object_streams = true;
    let seeds = [
        document.build(),
        Document::new(&[b"BT (plain) Tj ET"]).build(),
    ];
    let mut rng = Rng::new(0x5eed);
    let started = Instant::now();
    for round in 0..3000 {
        let seed = &seeds[round % seeds.len()];
        let mutated = mutate(seed, &mut rng);
        let (result, text) = run(&mutated);
        assert!(text.len() < 1 << 16);
        if let Ok(extraction) = result {
            assert!(matches!(extraction.format, Format::Pdf | Format::Rtf));
        }
    }
    assert!(started.elapsed() < Duration::from_secs(20));
}

#[test]
fn unfiltered_content_is_borrowed_not_copied() {
    let content = b"0 0 m\n".repeat(2 << 20);
    let mut pdf = Pdf::new();
    tree(&mut pdf, &content);
    pdf.xref_table("/Root 1 0 R");
    let result = hostile("long unfiltered content", pdf.build(), 1 << 20);
    assert_eq!(
        result.map(|extraction| extraction.bytes_decompressed),
        Ok(content.len() as u64)
    );
}

fn text_page(resources: &str, content: &[u8], extra: impl FnOnce(&mut Pdf)) -> Vec<u8> {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(
            3,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << {resources} >> /Contents 4 0 R >>"
            ),
        )
        .stream(4, "", content);
    extra(&mut pdf);
    pdf.xref_table("/Root 1 0 R");
    pdf.build()
}

const HELVETICA: &str = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >>";

#[test]
fn text_layer_cmaps_and_widths_are_bounded() {
    let mut to_unicode = String::from(
        "2147483647 beginbfrange <00000000> <FFFFFFFF> <0041> <0000> <FFFF> [<0041> <0042>] endbfrange\n\
         99999999 begincidrange <0000> <FFFF> 2147483647 endcidrange\n2147483647 beginbfchar\n",
    );
    for code in 0..150_000u32 {
        let _ = writeln!(
            to_unicode,
            "<{:04X}> <{:04X}>",
            code % 0x10000,
            0x41 + code % 26
        );
    }
    to_unicode.push_str("endbfchar\nbeginbfrange\n");
    for code in 0..50_000u32 {
        let _ = writeln!(to_unicode, "<0000> <FFFF> <{:04X}>", code % 0xD000);
    }
    to_unicode.push_str("endbfrange");
    let mut widths = String::from("[0 4294967295 500 0 [");
    for _ in 0..400_000 {
        widths.push_str("1 ");
    }
    widths.push_str("] -1 -9 5 1e308 1e308 1e308]");
    let data = text_page(
        "/Font << /F1 10 0 R /F2 13 0 R >>",
        b"BT /F1 12 Tf 72 700 Td <0041004200FF> Tj /F2 12 Tf (abc) Tj ET",
        |pdf| {
            pdf.object(
                10,
                "<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [11 0 R] /ToUnicode 12 0 R >>",
            )
            .object(
                11,
                &format!("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /X /DW 2147483647 /W {widths} /W2 {widths} >>"),
            )
            .flate_stream(12, "", to_unicode.as_bytes())
            .object(
                13,
                "<< /Type /Font /Subtype /Type1 /BaseFont /Y /FirstChar 2147483647 /LastChar -4 /Widths [1e308 -1e308 3] /Encoding << /Differences [2147483647 /a -5 /b 97 /c] >> >>",
            );
        },
    );
    let result = hostile("hostile cmaps and widths", data, 32 << 20);
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn forms_that_draw_themselves_and_fan_out() {
    let data = text_page("/XObject << /Fm0 10 0 R >>", b"/Fm0 Do /Fm0 Do", |pdf| {
        for level in 0..40u32 {
            let next = 11 + level;
            pdf.stream(
                10 + level,
                &format!(
                    "/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << {HELVETICA} /XObject << /A {next} 0 R /B {next} 0 R /Self {} 0 R >> >>",
                    10 + level
                ),
                format!("/A Do /B Do /Self Do BT /F1 12 Tf {level} 700 Td (level {level}) Tj ET").as_bytes(),
            );
        }
        pdf.stream(
            50,
            "/Type /XObject /Subtype /Form /BBox [0 0 1 1]",
            b"0 0 m",
        );
    });
    let result = hostile("form fan-out", data, 8 << 20);
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn million_operators_and_unbalanced_state() {
    let mut content = Vec::with_capacity(16 << 20);
    for _ in 0..1_000_000 {
        content.extend_from_slice(b"q ");
    }
    for _ in 0..250_000 {
        content.extend_from_slice(b"BT ET Q EMC /P BMC ");
    }
    content.extend_from_slice(b"BT /F1 12 Tf 72 700 Td (survived) Tj ET");
    let (result, text) = measured_text(text_page(HELVETICA, &content, |_| {}), 16 << 20);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(text, "survived");
}

#[test]
fn deep_operand_nesting_and_huge_tj_arrays() {
    let mut content = b"BT /F1 12 Tf 72 700 Td ".to_vec();
    content.extend(std::iter::repeat_n(b'[', 1_000_000));
    content.extend_from_slice(b" TJ ");
    content.extend(std::iter::repeat_n(b"<<".as_slice(), 200_000).flatten());
    content.extend_from_slice(b" /Span exch BDC [");
    for _ in 0..300_000 {
        content.extend_from_slice(b"(a)-9 ");
    }
    content.extend_from_slice(b"] TJ ET");
    let result = hostile(
        "deep operands and huge TJ",
        text_page(HELVETICA, &content, |_| {}),
        32 << 20,
    );
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn inline_images_without_end_markers() {
    let build = |count: usize| {
        let mut content = b"BT /F1 12 Tf 72 700 Td (before) Tj ET ".to_vec();
        for _ in 0..count {
            content.extend_from_slice(b"BI /W 1 /H 1 ");
        }
        content.extend_from_slice(b"BI /W 100000 /H 100000 /BPC 8 /CS /RGB /L 99999999999 ID ");
        for _ in 0..count * 2 {
            content.extend_from_slice(b" EI \x01\x02");
        }
        text_page(HELVETICA, &content, |_| {})
    };
    let (result, text) = measured_text(build(100_000), 16 << 20);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(text, "before");
    assert_linear("inline images without end markers", 25_000, build);
}

#[test]
fn self_referencing_fonts_and_many_fonts() {
    let data = text_page(
        "/Font << /F1 10 0 R /F2 11 0 R >>",
        b"BT /F1 12 Tf 72 700 Td (A) Tj /F2 12 Tf <0041> Tj ET",
        |pdf| {
            pdf.object(
                10,
                "<< /Type /Font /Subtype /Type3 /FontMatrix [0.001 0 0 0.001 0 0] /FontBBox [0 0 1 1] \
                 /CharProcs << /A 12 0 R >> /Encoding << /Differences [65 /A] >> /Resources << /Font << /F1 10 0 R >> >> \
                 /FirstChar 65 /LastChar 65 /Widths [500] >>",
            )
            .object(
                11,
                "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /DescendantFonts [11 0 R] /ToUnicode 11 0 R >>",
            )
            .stream(12, "", b"/F1 12 Tf (A) Tj 500 0 d0");
        },
    );
    let (result, text) = measured_text(data, 4 << 20);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(text, "A");

    let many_fonts = |fonts: usize| {
        let fonts = fonts as u32;
        let mut resources = String::from("/Font <<");
        let mut content = String::from("BT 72 700 Td ");
        for index in 0..fonts {
            let _ = write!(resources, " /F{index} {} 0 R", 10 + index);
            let _ = write!(content, "/F{index} 12 Tf (x) Tj ");
        }
        resources.push_str(" >>");
        content.push_str("ET");
        text_page(&resources, content.as_bytes(), |pdf| {
            for index in 0..fonts {
                pdf.object(
                    10 + index,
                    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Differences [120 /x] >> >>",
                );
            }
        })
    };
    let result = hostile("many fonts", many_fonts(4_500), 48 << 20);
    assert!(result.is_ok(), "{result:?}");
    assert_linear("many fonts", 1_125, many_fonts);
}

fn measured_text(data: Vec<u8>, max_peak: usize) -> (Result<Extraction, Error>, String) {
    let limits = Limits::default();
    let copy = data.clone();
    let result = hostile_with("text", data, limits.clone(), max_peak);
    let (_, text) = run_with(&copy, Hints::new(), &limits);
    (result, text)
}

fn feature_rich_document() -> Vec<u8> {
    let to_unicode = b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange \
        2 beginbfrange <0041> <005A> <0061> <0100> <0102> [<0066> /fi <D835DC00>] endbfrange 1 beginbfchar <0020> <0020> endbfchar endcmap";
    let encoding =
        b"begincmap /WMode 0 def 2 begincodespacerange <00> <7F> <8140> <9FFC> endcodespacerange \
        1 begincidrange <20> <7E> 1 endcidrange 1 begincidchar <8140> 633 endcidchar endcmap";
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [20 0 R 21 0 R] >> >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(
            3,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [22 0 R] /Contents 4 0 R /Resources << \
             /Font << /F1 10 0 R /F2 11 0 R /F3 13 0 R /F4 15 0 R >> /XObject << /Fm 16 0 R >> \
             /Properties << /P1 << /ActualText (named) >> >> >> >>",
        )
        .stream(
            4,
            "",
            b"BT /F1 12 Tf 72 700 Td [(Kerned) -250 (words)] TJ 0 -14 Td /F2 10 Tf <0041004200430101> Tj \
              /F3 11 Tf 2 Tc (\x41\x81\x40BC) Tj 0 Tc /F4 9 Tf (\x01\x02) ' /Span /P1 BDC (xx) Tj EMC ET \
              q 0.5 0 0 0.5 72 400 cm /Fm Do Q BI /W 2 /H 2 /BPC 8 /CS /G ID abcd EI",
        )
        .object(
            10,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman /Encoding << /BaseEncoding /WinAnsiEncoding /Differences [1 /fi /fl] >> >>",
        )
        .object(
            11,
            "<< /Type /Font /Subtype /Type0 /BaseFont /Sub /Encoding /Identity-H /DescendantFonts [12 0 R] /ToUnicode 14 0 R >>",
        )
        .object(
            12,
            "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Sub /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> /DW 1000 /W [65 [500 600] 100 200 700] /DW2 [880 -1000] >>",
        )
        .object(
            13,
            "<< /Type /Font /Subtype /Type0 /BaseFont /Ryumin /Encoding 17 0 R /DescendantFonts [<< /Subtype /CIDFontType0 /CIDSystemInfo << /Registry (Adobe) /Ordering (Japan1) /Supplement 2 >> >>] >>",
        )
        .stream(14, "", to_unicode)
        .object(
            15,
            "<< /Type /Font /Subtype /Type3 /FontMatrix [0.001 0 0 0.001 0 0] /FontBBox [0 0 1 1] /CharProcs << >> /Encoding << /Differences [1 /a65 /a66] >> /FirstChar 1 /LastChar 2 /Widths [500 500] >>",
        )
        .stream(
            16,
            "/Type /XObject /Subtype /Form /BBox [0 0 100 100] /Resources << /Font << /F1 10 0 R >> >>",
            b"BT /F1 12 Tf (inside the form) Tj ET",
        )
        .stream(17, "/Type /CMap /CMapName /Test", encoding)
        .object(20, "<< /FT /Tx /T (name) /V (Field value) >>")
        .object(21, "<< /FT /Ch /T (choice) /Opt [[(a) (Alpha)]] /V (a) >>")
        .object(22, "<< /Type /Annot /Subtype /Text /Rect [0 0 1 1] /Contents (Comment) >>")
        .xref_table("/Root 1 0 R");
    pdf.build()
}

#[test]
fn text_layer_mutations() {
    let seed = feature_rich_document();
    let (result, text) = run(&seed);
    assert!(result.is_ok(), "{result:?}");
    for phrase in [
        "Kerned words",
        "inside the form",
        "Field value",
        "Alpha",
        "Comment",
        "named",
    ] {
        assert!(text.contains(phrase), "{phrase} missing from {text:?}");
    }
    let mut rng = Rng::new(0x7e27);
    let started = Instant::now();
    for _ in 0..3000 {
        let mutated = mutate(&seed, &mut rng);
        let (result, text) = run(&mutated);
        assert!(text.len() < 1 << 16);
        if let Ok(extraction) = result {
            assert_eq!(extraction.bytes_written, text.len());
        }
    }
    assert!(started.elapsed() < Duration::from_secs(30));
}

fn nested_heavy_forms(bytes: usize) -> Vec<u8> {
    let filler = |tail: &str| {
        let mut content = "0 0 m 1 1 l\n".repeat(bytes / 12);
        content.push_str(tail);
        content.into_bytes()
    };
    let font = "/Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >>";
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(
            3,
            &format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
                 /Resources << {font} /XObject << /A 5 0 R >> >> >>"
            ),
        )
        .flate_stream(4, "", &filler("BT /F1 12 Tf 72 700 Td (outer) Tj ET /A Do"))
        .flate_stream(
            5,
            &format!(
                "/Type /XObject /Subtype /Form /BBox [0 0 612 792] \
                 /Resources << {font} /XObject << /B 6 0 R >> >>"
            ),
            &filler("BT /F1 12 Tf 72 680 Td (middle) Tj ET /B Do"),
        )
        .flate_stream(
            6,
            &format!("/Type /XObject /Subtype /Form /BBox [0 0 612 792] /Resources << {font} >>"),
            &filler("BT /F1 12 Tf 72 660 Td (inner) Tj ET"),
        )
        .xref_table("/Root 1 0 R");
    pdf.build()
}

#[test]
fn extractor_scratch_shrinks_after_a_large_document() {
    const RETAINED_LIMIT: usize = 6 << 20;
    let large = nested_heavy_forms(4 << 20);
    let small = Document::new(&[b"BT /F1 12 Tf 72 700 Td (small) Tj ET"]).build();
    let _timed = exclusive();
    let (texts, retained) = thread::spawn(move || {
        LIVE.with(|live| live.set(0));
        let mut extractor = Extractor::new(Limits::default());
        let mut texts = Vec::new();
        for data in [&large, &small] {
            let mut out = String::new();
            let result = extractor.extract(data, Hints::new(), &mut out);
            assert!(result.is_ok(), "{result:?}");
            texts.push(words(&out));
        }
        let retained = LIVE.with(Cell::get)
            - texts.iter().map(String::capacity).sum::<usize>()
            - texts.capacity() * std::mem::size_of::<String>();
        (texts, retained)
    })
    .join()
    .unwrap_or_else(|_| panic!("extraction panicked"));
    assert_eq!(
        texts.first().map(String::as_str),
        Some("outer middle inner")
    );
    assert_eq!(texts.get(1).map(String::as_str), Some("small"));
    assert!(retained < RETAINED_LIMIT, "retained {retained} bytes");
}

fn repeated(prefix: &[u8], unit: &[u8], count: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(prefix.len() + unit.len() * count);
    data.extend_from_slice(prefix);
    for _ in 0..count {
        data.extend_from_slice(unit);
    }
    data
}

fn broken_xref_with_payload(count: usize) -> Vec<u8> {
    let mut pdf = Pdf::new();
    tree(&mut pdf, b"BT /F1 12 Tf 72 700 Td (intact) Tj ET");
    for _ in 0..count {
        pdf.raw(b"9 0 obj<<(\n");
    }
    pdf.xref_table("/Root 1 0 R");
    let mut data = pdf.build();
    let marker = b"startxref\n";
    if let Some(at) = data
        .windows(marker.len())
        .rposition(|window| window == marker)
    {
        data.truncate(at);
        data.extend_from_slice(b"startxref\n13\n%%EOF\n");
    }
    data
}

#[test]
fn repair_of_unterminated_strings_is_linear() {
    let header = b"%PDF-1.4\n";
    for (name, unit) in [
        ("literal bodies", &b"1 0 obj<<(\n"[..]),
        ("hex bodies", b"1 0 obj<< <\n"),
        ("literal trailers", b"trailer<<(\n"),
    ] {
        assert_linear(name, 8_000, |count| repeated(header, unit, count));
        let result = hostile(name, repeated(header, unit, 16_000), 16 << 20);
        assert_eq!(result, Err(Error::Unsupported), "{name}");
    }
    assert_linear("broken xref", 8_000, broken_xref_with_payload);
    let (result, text) = measured_text(broken_xref_with_payload(16_000), 16 << 20);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(text, "intact");
}

fn endstream_after_whitespace(count: usize) -> Vec<u8> {
    let width = count.to_string().len();
    let prefix =
        |num: usize, length: usize| format!("{num:width$} 0 obj <</Length {length:010}>> stream\n");
    let suffix = b"endstream endobj\n";
    let mut data = b"%PDF-1.4\n".to_vec();
    let end = data.len() + (prefix(0, 0).len() + suffix.len()) * count;
    for num in 1..=count {
        let start = data.len() + prefix(num, 0).len();
        data.extend_from_slice(prefix(num, end - start + 10).as_bytes());
        data.extend_from_slice(suffix);
    }
    data.resize(data.len() + count * 20, b' ');
    data.push(b'x');
    data
}

fn dense_xref_harvest(count: usize) -> Vec<u8> {
    let mut data = b"%PDF-1.4\n".to_vec();
    for num in 1..=count {
        data.extend_from_slice(
            format!(
                "{num} 0 obj <</Type/XRef /W [1 1 1] /Index [{} 1] /Length 3>> stream\n",
                16_000 + count * 20
            )
            .as_bytes(),
        );
        data.extend_from_slice(b"\x02\x01\x00\nendstream endobj\n");
    }
    data
}

fn object_stream_members(count: usize) -> Vec<u8> {
    let mut members = String::new();
    for index in 0..count {
        let _ = write!(members, "{} 0 ", 100 + index);
    }
    let mut body = members.clone().into_bytes();
    body.push(b'(');
    body.resize(body.len() + count * 8, b'x');
    let compressed = zlib(&body);
    let mut data = b"%PDF-1.4\n1 0 obj <</Type/Catalog/Pages 2 0 R>> endobj\n".to_vec();
    data.extend_from_slice(
        format!(
            "5 0 obj <</Type/ObjStm /N {count} /First {} /Length {} /Filter/FlateDecode>> stream\n",
            members.len(),
            compressed.len()
        )
        .as_bytes(),
    );
    data.extend_from_slice(&compressed);
    data.extend_from_slice(b"\nendstream endobj\n");
    data
}

#[test]
fn repair_side_scans_are_linear() {
    assert_linear(
        "endstream after whitespace",
        4_000,
        endstream_after_whitespace,
    );
    assert_linear("dense xref harvest", 3_000, dense_xref_harvest);
    assert_linear("object stream members", 20_000, object_stream_members);
}

fn kids_with_trailing_strings(count: usize, body: &str) -> Vec<u8> {
    let mut pdf = Pdf::new();
    let kids: String = (0..count)
        .map(|index| format!("{} 0 R ", 10 + index))
        .collect();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>").object(
        2,
        &format!("<< /Type /Pages /Kids [{kids}] /Count {count} >>"),
    );
    for index in 0..count {
        pdf.object(10 + index as u32, body);
    }
    pdf.xref_table("/Root 1 0 R");
    pdf.build()
}

#[test]
fn object_probes_do_not_rescan_unterminated_strings() {
    for body in ["1 (", "<< /Type /Page >> ("] {
        assert_linear(body, 4_000, |count| kids_with_trailing_strings(count, body));
    }
}

fn inline_page(prefix: &[u8], unit: &[u8], count: usize) -> Vec<u8> {
    let mut content = b"BT /F1 12 Tf 72 700 Td (ok) Tj ET ".to_vec();
    content.extend_from_slice(&repeated(prefix, unit, count));
    text_page(HELVETICA, &content, |_| {})
}

fn inline_lengths_into_whitespace(count: usize) -> Vec<u8> {
    let mut content = b"BT /F1 12 Tf 72 700 Td (ok) Tj ET ".to_vec();
    let unit_len = format!("BI /L {:010} ID EI ", 0).len();
    let end = content.len() + unit_len * count;
    for _ in 0..count {
        let start = content.len() + format!("BI /L {:010} ID ", 0).len();
        content.extend_from_slice(format!("BI /L {:010} ID EI ", end - start + 10).as_bytes());
    }
    content.resize(content.len() + count * 20, b' ');
    content.push(b'x');
    text_page(HELVETICA, &content, |_| {})
}

fn inline_scan_fallbacks(blob: usize) -> Vec<u8> {
    let mut content = b"BT /F1 12 Tf 72 700 Td (ok) Tj ET ".to_vec();
    for _ in 0..255 {
        content.extend_from_slice(b"BI /F /Fl ID ");
        content.extend_from_slice(&b"xEI".repeat(blob));
        content.extend_from_slice(b" EI \x01 ");
    }
    content.extend_from_slice(&b"xEI".repeat(blob * 255));
    text_page(HELVETICA, &content, |_| {})
}

#[test]
fn inline_image_markers_are_linear() {
    for (name, unit) in [
        ("hex data without end", &b"BI /F /AHx ID EI "[..]),
        ("ascii85 data without end", b"BI /F /A85 ID EI "),
    ] {
        assert_linear(name, 16_000, |count| inline_page(b"", unit, count));
        let (result, text) = measured_text(inline_page(b"", unit, 16_000), 16 << 20);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(text, "ok", "{name}");
    }
    let long_dict = [&b"BI "[..], &b"1 ".repeat(130)].concat();
    assert_linear("dictionary without ID", 1_000, |count| {
        inline_page(b"", &long_dict, count)
    });
    assert_linear(
        "lengths into whitespace",
        4_000,
        inline_lengths_into_whitespace,
    );
    assert_linear("end marker fallbacks", 400, inline_scan_fallbacks);
}

fn amplifying_truetype(glyphs: u16) -> Vec<u8> {
    let mut post = 0x0002_0000u32.to_be_bytes().to_vec();
    post.resize(32, 0);
    post.extend_from_slice(&glyphs.to_be_bytes());
    for _ in 0..glyphs {
        post.extend_from_slice(&258u16.to_be_bytes());
    }
    let name = [&b"uni"[..], &b"0041".repeat(63)].concat();
    post.push(name.len() as u8);
    post.extend_from_slice(&name);
    let mut maxp = vec![0u8, 1, 0, 0];
    maxp.extend_from_slice(&glyphs.to_be_bytes());
    let mut sfnt = 0x0001_0000u32.to_be_bytes().to_vec();
    sfnt.extend_from_slice(&2u16.to_be_bytes());
    sfnt.resize(12, 0);
    let maxp_at = 12 + 2 * 16;
    for (tag, at, table) in [
        (b"maxp", maxp_at, &maxp),
        (b"post", maxp_at + maxp.len(), &post),
    ] {
        sfnt.extend_from_slice(tag);
        sfnt.extend_from_slice(&[0; 4]);
        sfnt.extend_from_slice(&(at as u32).to_be_bytes());
        sfnt.extend_from_slice(&(table.len() as u32).to_be_bytes());
    }
    sfnt.extend_from_slice(&maxp);
    sfnt.extend_from_slice(&post);
    sfnt
}

fn amplifying_fonts(count: u32) -> Vec<u8> {
    let program = amplifying_truetype(u16::MAX);
    let mut resources = String::from("/Font <<");
    let mut content = String::from("BT ");
    for index in 0..count {
        let _ = write!(resources, " /F{index} {} 0 R", 10 + index * 4);
        let _ = write!(content, "/F{index} 12 Tf <00000001> Tj ");
    }
    resources.push_str(" >>");
    content.push_str("ET");
    text_page(&resources, content.as_bytes(), |pdf| {
        for index in 0..count {
            let base = 10 + index * 4;
            pdf.object(
                base,
                &format!(
                    "<< /Type /Font /Subtype /Type0 /BaseFont /X{index} /Encoding /Identity-H /DescendantFonts [{} 0 R] >>",
                    base + 1
                ),
            )
            .object(
                base + 1,
                &format!(
                    "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /X{index} /FontDescriptor {} 0 R >>",
                    base + 2
                ),
            )
            .object(
                base + 2,
                &format!(
                    "<< /Type /FontDescriptor /FontName /X{index} /FontFile2 {} 0 R >>",
                    base + 3
                ),
            )
            .stream(base + 3, "", &program);
        }
    })
}

#[test]
fn amplified_glyph_names_stay_bounded() {
    let (_, text) = measured_text(amplifying_fonts(1), 8 << 20);
    assert!(text.starts_with("AAAA"), "{text:?}");
    for fonts in [16, 64, 128] {
        let peak = measure_with(amplifying_fonts(fonts), Limits::default()).peak;
        assert!(peak < 48 << 20, "{fonts} fonts: peak heap {peak}");
    }
}
