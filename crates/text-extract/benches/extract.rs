/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[path = "../tests/common/mod.rs"]
mod common;
#[path = "support/prototype.rs"]
mod prototype;

use common::{Rng, ZipBuilder, ZipEntry, deflate_bomb, docx, fixture};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use text_extract::{Extractor, Hints, Limits};

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        let current = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(current, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        if new_size > layout.size() {
            let current = CURRENT.fetch_add(new_size - layout.size(), Ordering::Relaxed) + new_size
                - layout.size();
            PEAK.fetch_max(current, Ordering::Relaxed);
        } else {
            CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

const WORDS: &[&str] = &[
    "the",
    "quick",
    "brown",
    "fox",
    "jumps",
    "over",
    "lazy",
    "dog",
    "mail",
    "server",
    "invoice",
    "contact",
    "calendar",
    "r\u{e9}sum\u{e9}",
    "\u{65e5}\u{672c}",
    "stalwart",
];

fn sentence(rng: &mut Rng, words: usize) -> String {
    (0..words)
        .map(|_| WORDS[rng.below(WORDS.len())])
        .collect::<Vec<_>>()
        .join(" ")
}

fn rels(target: &str) -> String {
    format!(
        "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"{target}\"/></Relationships>"
    )
}

fn large_docx(rng: &mut Rng) -> Vec<u8> {
    large_docx_with(rng, false)
}

fn large_docx_with(rng: &mut Rng, stored: bool) -> Vec<u8> {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>",
    );
    for _ in 0..40_000 {
        xml.push_str("<w:p><w:pPr><w:pStyle w:val=\"Normal\"/></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t xml:space=\"preserve\">");
        xml.push_str(&sentence(rng, 12));
        xml.push_str("</w:t></w:r></w:p>");
    }
    xml.push_str("</w:body></w:document>");
    let builder = ZipBuilder::new().file("_rels/.rels", rels("word/document.xml").as_bytes());
    if stored {
        builder.stored("word/document.xml", xml.as_bytes()).build()
    } else {
        builder.file("word/document.xml", xml.as_bytes()).build()
    }
}

fn large_xlsx(rng: &mut Rng) -> Vec<u8> {
    let mut shared = String::from("<sst>");
    for _ in 0..20_000 {
        shared.push_str("<si><t>");
        shared.push_str(&sentence(rng, 3));
        shared.push_str("</t></si>");
    }
    shared.push_str("</sst>");
    let mut sheet = String::from("<worksheet><sheetData>");
    for row in 0..50_000 {
        sheet.push_str(&format!(
            "<row r=\"{row}\"><c r=\"A{row}\" t=\"s\"><v>{}</v></c><c r=\"B{row}\"><v>{}</v></c><c r=\"C{row}\" s=\"2\"><v>{}.25</v></c><c r=\"D{row}\" t=\"inlineStr\"><is><t>{}</t></is></c></row>",
            rng.below(20_000),
            rng.below(1_000_000),
            rng.below(1000),
            WORDS[rng.below(WORDS.len())]
        ));
    }
    sheet.push_str("</sheetData></worksheet>");
    ZipBuilder::new()
        .file("_rels/.rels", rels("xl/workbook.xml").as_bytes())
        .file("xl/workbook.xml", b"<workbook xmlns:r=\"r\"><sheets><sheet name=\"Data\" r:id=\"rId1\"/></sheets></workbook>")
        .file(
            "xl/_rels/workbook.xml.rels",
            b"<Relationships><Relationship Id=\"rId1\" Type=\"x/worksheet\" Target=\"worksheets/sheet1.xml\"/><Relationship Id=\"rId2\" Type=\"x/sharedStrings\" Target=\"sharedStrings.xml\"/></Relationships>",
        )
        .file("xl/sharedStrings.xml", shared.as_bytes())
        .file("xl/worksheets/sheet1.xml", sheet.as_bytes())
        .build()
}

fn large_pptx(rng: &mut Rng) -> Vec<u8> {
    let slides = 300;
    let ids: String = (0..slides)
        .map(|index| format!("<p:sldId id=\"{}\" r:id=\"rId{index}\"/>", 256 + index))
        .collect();
    let slide_rels: String = (0..slides)
        .map(|index| format!("<Relationship Id=\"rId{index}\" Type=\"x/slide\" Target=\"slides/slide{index}.xml\"/>"))
        .collect();
    let mut builder = ZipBuilder::new()
        .file("_rels/.rels", rels("ppt/presentation.xml").as_bytes())
        .file(
            "ppt/presentation.xml",
            format!("<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldIdLst>{ids}</p:sldIdLst></p:presentation>").as_bytes(),
        )
        .file("ppt/_rels/presentation.xml.rels", format!("<Relationships>{slide_rels}</Relationships>").as_bytes());
    for index in 0..slides {
        let mut xml =
            String::from("<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><p:cSld><p:spTree><p:sp><p:txBody>");
        for _ in 0..20 {
            xml.push_str("<a:p><a:r><a:rPr lang=\"en-US\" dirty=\"0\"/><a:t>");
            xml.push_str(&sentence(rng, 10));
            xml.push_str("</a:t></a:r></a:p>");
        }
        xml.push_str("</p:txBody></p:sp></p:spTree></p:cSld></p:sld>");
        builder = builder.file(&format!("ppt/slides/slide{index}.xml"), xml.as_bytes());
    }
    builder.build()
}

fn large_odt(rng: &mut Rng) -> Vec<u8> {
    let mut xml = String::from(
        "<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><office:body><office:text>",
    );
    for _ in 0..40_000 {
        xml.push_str("<text:p text:style-name=\"P1\">");
        xml.push_str(&sentence(rng, 6));
        xml.push_str("<text:s/><text:span text:style-name=\"T1\">");
        xml.push_str(&sentence(rng, 6));
        xml.push_str("</text:span></text:p>");
    }
    xml.push_str("</office:text></office:body></office:document-content>");
    ZipBuilder::new()
        .stored("mimetype", b"application/vnd.oasis.opendocument.text")
        .file("content.xml", xml.as_bytes())
        .build()
}

fn large_epub(rng: &mut Rng) -> Vec<u8> {
    let chapters = 200;
    let manifest: String = (0..chapters)
        .map(|index| format!("<item id=\"c{index}\" href=\"chapter{index}.xhtml\" media-type=\"application/xhtml+xml\"/>"))
        .collect();
    let spine: String = (0..chapters)
        .map(|index| format!("<itemref idref=\"c{index}\"/>"))
        .collect();
    let mut builder = ZipBuilder::new()
        .stored("mimetype", b"application/epub+zip")
        .file(
            "META-INF/container.xml",
            b"<container><rootfiles><rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\"/></rootfiles></container>",
        )
        .file(
            "OEBPS/content.opf",
            format!("<package><manifest>{manifest}</manifest><spine>{spine}</spine></package>").as_bytes(),
        );
    for index in 0..chapters {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><html xmlns=\"http://www.w3.org/1999/xhtml\"><head><title>Chapter</title><link rel=\"stylesheet\" href=\"s.css\"/></head><body><h1>Chapter</h1>",
        );
        for _ in 0..200 {
            xml.push_str("<p class=\"body\">");
            xml.push_str(&sentence(rng, 8));
            xml.push_str(" &amp; <em>");
            xml.push_str(&sentence(rng, 4));
            xml.push_str("</em></p>\n");
        }
        xml.push_str("</body></html>");
        builder = builder.file(&format!("OEBPS/chapter{index}.xhtml"), xml.as_bytes());
    }
    builder.build()
}

fn large_rtf(rng: &mut Rng) -> Vec<u8> {
    let mut rtf = String::from(
        "{\\rtf1\\ansi\\ansicpg1252\\deff0{\\fonttbl{\\f0\\fswiss\\fcharset0 Arial;}{\\f1\\fcharset204 Times;}}{\\colortbl;\\red0\\green0\\blue0;}\n",
    );
    for _ in 0..40_000 {
        rtf.push_str("\\pard\\plain\\f0\\fs20 ");
        rtf.push_str(
            &sentence(rng, 8)
                .replace('\u{e9}', "\\'e9")
                .replace("\u{65e5}\u{672c}", "\\u26085?\\u26412?"),
        );
        rtf.push_str(" {\\b\\f1 \\'cf\\'f0\\'e8} caf\\'e9\\par\n");
    }
    rtf.push('}');
    rtf.into_bytes()
}

struct Measurement {
    per_run: Duration,
    allocations: usize,
    peak_bytes: usize,
    output_bytes: usize,
}

fn measure(mut run: impl FnMut() -> usize) -> Measurement {
    let output_bytes = run();
    let started = Instant::now();
    let mut warmup = 0u32;
    while started.elapsed() < Duration::from_millis(200) {
        black_box(run());
        warmup += 1;
    }
    let iterations = warmup.max(1);
    let mut samples = Vec::with_capacity(5);
    for _ in 0..5 {
        let started = Instant::now();
        for _ in 0..iterations {
            black_box(run());
        }
        samples.push(started.elapsed() / iterations);
    }
    samples.sort();
    let baseline_current = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline_current, Ordering::Relaxed);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    black_box(run());
    Measurement {
        per_run: samples[2],
        allocations: ALLOCATIONS.load(Ordering::Relaxed) - before,
        peak_bytes: PEAK.load(Ordering::Relaxed) - baseline_current,
        output_bytes,
    }
}

fn report(name: &str, variant: &str, input: usize, measurement: &Measurement) {
    let seconds = measurement.per_run.as_secs_f64();
    println!(
        "| {name:<18} | {variant:<26} | {:>8.3} ms | {:>9.1} MB/s | {:>8} | {:>9.1} KiB | {:>8} |",
        seconds * 1000.0,
        input as f64 / seconds / 1_000_000.0,
        measurement.allocations,
        measurement.peak_bytes as f64 / 1024.0,
        measurement.output_bytes,
    );
}

fn inflated_size(data: &[u8]) -> usize {
    let limits = Limits {
        max_output_bytes: usize::MAX,
        ..Limits::default()
    };
    let mut out = String::new();
    text_extract::extract(data, Hints::new(), &limits, &mut out)
        .map(|extraction| extraction.bytes_decompressed as usize)
        .unwrap_or(0)
}

fn raw_members(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(data)) else {
        return Vec::new();
    };
    (0..archive.len())
        .filter_map(|index| {
            let mut file = archive.by_index_raw(index).ok()?;
            if file.compression() != zip::CompressionMethod::Deflated {
                return None;
            }
            let mut raw = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut raw).ok()?;
            Some(raw)
        })
        .collect()
}

fn inflate_only(members: &[Vec<u8>], window: &mut [u8]) -> usize {
    let mut inflater = flate2::Decompress::new(false);
    let mut total = 0;
    for member in members {
        inflater.reset(false);
        let mut input = member.as_slice();
        loop {
            let before_in = inflater.total_in();
            let before_out = inflater.total_out();
            let status = inflater.decompress(input, window, flate2::FlushDecompress::None);
            let consumed = (inflater.total_in() - before_in) as usize;
            let produced = (inflater.total_out() - before_out) as usize;
            input = &input[consumed..];
            total += produced;
            if !matches!(status, Ok(flate2::Status::Ok)) || (produced == 0 && consumed == 0) {
                break;
            }
        }
    }
    total
}

fn main() {
    let filter = std::env::args().nth(1).filter(|arg| !arg.starts_with('-'));
    let mut rng = Rng::new(0xBE7C_4000);
    let corpus: Vec<(&str, Vec<u8>, bool)> = vec![
        ("docx-40k-paras", large_docx(&mut rng), true),
        ("docx-stored-xml", large_docx_with(&mut rng, true), false),
        ("xlsx-50k-rows", large_xlsx(&mut rng), true),
        ("pptx-300-slides", large_pptx(&mut rng), true),
        ("odt-40k-paras", large_odt(&mut rng), true),
        ("epub-200-chapters", large_epub(&mut rng), true),
        ("rtf-40k-paras", large_rtf(&mut rng), false),
    ];
    let limits = Limits::default();
    let mut extractor = Extractor::new(limits.clone());
    let mut out = String::with_capacity(limits.max_output_bytes);
    if let Some(seconds) = std::env::var("TEXT_EXTRACT_PROFILE_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(seconds) {
            for (name, data, _) in &corpus {
                if filter.as_deref().is_none_or(|filter| name.contains(filter)) {
                    out.clear();
                    let _ = black_box(extractor.extract(black_box(data), Hints::new(), &mut out));
                }
            }
        }
        return;
    }

    println!(
        "| corpus | variant | time | MB/s (decompressed or raw) | allocs | peak heap | output bytes |"
    );
    println!("|---|---|---|---|---|---|---|");
    for (name, data, zipped) in &corpus {
        if filter
            .as_deref()
            .is_some_and(|filter| !name.contains(filter))
        {
            continue;
        }
        let inflated = if *zipped {
            inflated_size(data)
        } else {
            data.len()
        };
        println!(
            "| {name} | input {} KiB, XML {} KiB | | | | | |",
            data.len() / 1024,
            inflated / 1024
        );
        let reused = measure(|| {
            out.clear();
            let _ = black_box(extractor.extract(black_box(data), Hints::new(), &mut out));
            out.len()
        });
        report(name, "extractor (reused)", inflated, &reused);
        let fresh = measure(|| {
            let mut text = String::new();
            let _ = black_box(text_extract::extract(
                black_box(data),
                Hints::new(),
                &limits,
                &mut text,
            ));
            text.len()
        });
        report(name, "extract (fresh)", inflated, &fresh);
        if *zipped {
            let baseline = measure(|| {
                black_box(prototype::extract(black_box(data)))
                    .map(|text| text.len())
                    .unwrap_or(0)
            });
            report(name, "prototype zip+quick-xml", inflated, &baseline);
        }
        if *zipped {
            let members = raw_members(data);
            let mut window = vec![0u8; 1 << 16];
            let inflate = measure(|| black_box(inflate_only(black_box(&members), &mut window)));
            report(name, "inflate only (reference)", inflated, &inflate);
        }
        if name.starts_with("epub") {
            let html = measure(|| {
                black_box(prototype::epub_html_to_text(black_box(data)))
                    .map(|text| text.len())
                    .unwrap_or(0)
            });
            report(name, "zip + html_to_text", inflated, &html);
        }
    }

    if filter
        .as_deref()
        .is_none_or(|filter| "hostile".contains(filter))
    {
        let namespace = "xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"";
        let header = format!("<w:document {namespace}><w:body>");
        let paragraph =
            b"<w:p><w:r><w:t>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</w:t></w:r></w:p>";
        let chunk = paragraph.repeat(16_000);
        let with_document = |entry: ZipEntry| {
            let mut builder = docx("");
            builder
                .entries
                .retain(|existing| existing.name != b"word/document.xml");
            builder.entry(entry).build()
        };
        let text_bomb = with_document(ZipEntry::from_bomb(
            "word/document.xml",
            deflate_bomb(
                header.as_bytes(),
                &chunk,
                (2usize << 30) / chunk.len() + 1,
                b"",
            ),
        ));
        let markup_bomb = with_document(ZipEntry::from_bomb(
            "word/document.xml",
            deflate_bomb(header.as_bytes(), &b"<w:p/>".repeat(1 << 16), 16_384, b""),
        ));
        let mut deep_rtf = b"{\\rtf1\\ansi ".to_vec();
        deep_rtf.extend(std::iter::repeat_n(b'{', 1_000_000));
        deep_rtf.push(b'x');
        deep_rtf.extend(std::iter::repeat_n(b'}', 1_000_000));
        deep_rtf.push(b'}');
        for (name, data) in [
            ("docx-text-bomb-2gib", text_bomb),
            ("docx-markup-bomb-6gib", markup_bomb),
            (
                "docx-deep-nesting",
                fixture("hostile/docx_deep_nesting.docx"),
            ),
            ("rtf-deep-groups-1m", deep_rtf),
            (
                "ods-repeated-rows",
                fixture("hostile/ods_repeated_rows.ods"),
            ),
            (
                "xlsx-sparse-corners",
                fixture("hostile/xlsx_sparse_corners.xlsx"),
            ),
        ] {
            let mut decompressed = 0;
            let fresh = measure(|| {
                let mut text = String::new();
                decompressed =
                    text_extract::extract(black_box(&data), Hints::new(), &limits, &mut text)
                        .map(|extraction| extraction.bytes_decompressed)
                        .unwrap_or(0);
                text.len()
            });
            println!(
                "| {name} | input {} KiB, decompressed {} KiB | | | | | |",
                data.len() / 1024,
                decompressed / 1024
            );
            report(name, "extract (fresh, defaults)", data.len(), &fresh);
        }
    }

    if filter
        .as_deref()
        .is_none_or(|filter| "real".contains(filter))
    {
        let real: Vec<Vec<u8>> = [
            "real/testWORD.docx",
            "real/testWORD_various.docx",
            "real/textutil.docx",
            "real/testEXCEL.xlsx",
            "real/testPPT.pptx",
            "real/testPPT_various.pptx",
            "real/testOpenOffice2.odt",
            "real/testODFwithOOo3.odt",
            "real/textutil.odt",
            "real/gen.odp",
            "real/testEPUB.epub",
            "real/testRTF.rtf",
            "real/testRTFVarious.rtf",
            "real/textutil.rtf",
        ]
        .iter()
        .map(|path| fixture(path))
        .collect();
        let total: usize = real.iter().map(Vec::len).sum();
        println!(
            "| real-14-docs | input {} KiB total | | | | | |",
            total / 1024
        );
        let reused = measure(|| {
            real.iter()
                .map(|data| {
                    out.clear();
                    let _ = black_box(extractor.extract(black_box(data), Hints::new(), &mut out));
                    out.len()
                })
                .sum()
        });
        report("real-14-docs", "extractor (reused)", total, &reused);
        let fresh = measure(|| {
            real.iter()
                .map(|data| {
                    let mut text = String::new();
                    let _ = black_box(text_extract::extract(
                        black_box(data),
                        Hints::new(),
                        &limits,
                        &mut text,
                    ));
                    text.len()
                })
                .sum()
        });
        report("real-14-docs", "extract (fresh)", total, &fresh);
        let baseline = measure(|| {
            real.iter()
                .filter_map(|data| black_box(prototype::extract(black_box(data))))
                .map(|text| text.len())
                .sum()
        });
        report(
            "real-14-docs",
            "prototype (zip docs only)",
            total,
            &baseline,
        );
    }
}
