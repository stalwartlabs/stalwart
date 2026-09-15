/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod common;

use common::*;
use std::{
    io::{Cursor, Read},
    time::{Duration, Instant},
};
use text_extract::{Error, Extraction, Failure, Format, Hints, Limits};

const RELS_NS: &str = "xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"";
const REL_TYPE: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const DEBUG_TIME_BUDGET: Duration = Duration::from_secs(20);

fn timed(data: &[u8], limits: &Limits) -> (Result<Extraction, Error>, String) {
    let started = Instant::now();
    let (result, text) = run_with(data, Hints::new(), limits);
    assert!(
        started.elapsed() < DEBUG_TIME_BUDGET,
        "took {:?}",
        started.elapsed()
    );
    assert!(text.len() <= limits.max_output_bytes);
    if let Ok(extraction) = &result {
        assert!(extraction.bytes_decompressed <= limits.max_total_bytes + (1 << 16));
        assert_eq!(extraction.bytes_written, text.len());
    }
    (result, text)
}

fn ok(result: Result<Extraction, Error>) -> Extraction {
    result.unwrap_or_else(|err| panic!("expected extraction, got {err:?}"))
}

fn docx_document(entry: ZipEntry) -> Vec<u8> {
    let mut builder = docx("");
    builder
        .entries
        .retain(|existing| existing.name != b"word/document.xml");
    builder.entry(entry).build()
}

#[test]
fn docx_zip_bomb_two_gib() {
    let paragraph =
        b"<w:p><w:r><w:t>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</w:t></w:r></w:p>";
    let chunk = paragraph.repeat(16_000);
    let repeats = (2usize << 30) / chunk.len() + 1;
    let header = format!("<?xml version=\"1.0\"?><w:document {W_NS}><w:body>");
    let bomb = deflate_bomb(
        header.as_bytes(),
        &chunk,
        repeats,
        b"</w:body></w:document>",
    );
    assert!(bomb.uncompressed_size >= 2 << 30);
    let data = docx_document(ZipEntry::from_bomb("word/document.xml", bomb));
    assert!(data.len() < 16 << 20);

    let limits = Limits::default();
    let (result, text) = timed(&data, &limits);
    let extraction = ok(result);
    assert_eq!(extraction.format, Format::Docx);
    assert!(extraction.truncated);
    assert_eq!(text.len(), limits.max_output_bytes);
    assert!(extraction.bytes_decompressed < 16 << 20);

    let limits = Limits {
        max_output_bytes: usize::MAX,
        max_part_bytes: 8 << 20,
        ..Limits::default()
    };
    let (result, _) = run_with(&data, Hints::new(), &limits);
    let extraction = ok(result);
    assert!(extraction.truncated);
    assert!(extraction.bytes_decompressed <= (8 << 20) + 4096);
}

#[test]
fn markup_only_bomb_stops_at_total_budget() {
    let header = format!("<w:document {W_NS}><w:body>");
    let bomb = deflate_bomb(header.as_bytes(), &b"<w:p/>".repeat(1 << 16), 4096, b"");
    let data = docx_document(ZipEntry::from_bomb("word/document.xml", bomb));
    let limits = Limits {
        max_total_bytes: 24 << 20,
        ..Limits::default()
    };
    let (result, text) = timed(&data, &limits);
    let extraction = ok(result);
    assert!(extraction.truncated);
    assert!(text.is_empty());
    assert!(extraction.bytes_decompressed <= 24 << 20);
}

#[test]
fn evaluation_hostile_corpus() {
    let limits = Limits::default();

    let (result, text) = timed(&fixture("hostile/docx_deep_nesting.docx"), &limits);
    assert_eq!(ok(result).format, Format::Docx);
    assert_eq!(words(&text), "x");

    let (result, text) = timed(&fixture("hostile/docx_billion_laughs.docx"), &limits);
    assert_eq!(ok(result).format, Format::Docx);
    assert!(text.len() < 16, "{text:?}");

    let (result, _) = timed(&fixture("hostile/docx_lzma_member.docx"), &limits);
    assert_eq!(result, Err(Error::Unsupported));

    let (result, text) = timed(&fixture("hostile/xlsx_sparse_corners.xlsx"), &limits);
    assert_eq!(ok(result).format, Format::Xlsx);
    assert_eq!(words(&text), "S first last");

    let (result, text) = timed(&fixture("hostile/xlsx_sst_uniquecount.xlsx"), &limits);
    assert_eq!(ok(result).format, Format::Xlsx);
    assert_eq!(words(&text), "S hi");

    let (result, text) = timed(&fixture("hostile/ods_repeated_rows.ods"), &limits);
    assert_eq!(ok(result).format, Format::Ods);
    assert!(text.len() < 64, "{text:?}");
    assert!(words(&text).contains("Total amount"));
}

#[test]
fn rtf_deep_groups_and_binary() {
    let limits = Limits::default();
    let mut data = b"{\\rtf1\\ansi ".to_vec();
    data.extend(std::iter::repeat_n(b'{', 1_000_000));
    data.push(b'x');
    data.extend(std::iter::repeat_n(b'}', 1_000_000));
    data.extend_from_slice(b" tail}");
    let (result, text) = timed(&data, &limits);
    assert_eq!(ok(result).format, Format::Rtf);
    assert_eq!(words(&text), "x tail");

    let mut data = b"{\\rtf1 ".to_vec();
    data.extend(b"{\\*\\pict ".repeat(200_000));
    data.extend(b"\\'ff\\u-1\\uc100000000 \\bin-5 ".repeat(50_000));
    data.extend_from_slice(b"\\bin18446744073709551615 ");
    let (result, text) = timed(&data, &limits);
    assert_eq!(ok(result).format, Format::Rtf);
    assert!(text.is_empty());

    let mut data = b"{\\rtf1\\ansicpg932 ".to_vec();
    data.extend(b"\\'82\\'a0".repeat(2 << 20));
    let (result, text) = timed(&data, &limits);
    let extraction = ok(result);
    assert!(extraction.truncated);
    assert!(text.chars().all(|ch| ch == '\u{3042}'));
}

#[test]
fn overlapping_entries_are_read_once() {
    let mut kernel = format!("<w:hdr {W_NS}><w:p><w:r><w:t>kernel</w:t></w:r></w:p>").into_bytes();
    kernel.extend(b"<w:p/>".repeat(1 << 16));
    let rels: String = (0..1000)
        .map(|index| format!("<Relationship Id=\"h{index}\" Type=\"{REL_TYPE}/header\" Target=\"header{index}.xml\"/>"))
        .collect();
    let mut builder = docx("<w:p><w:r><w:t>body</w:t></w:r></w:p>")
        .file(
            "word/_rels/document.xml.rels",
            format!("<Relationships {RELS_NS}>{rels}</Relationships>").as_bytes(),
        )
        .file("word/header0.xml", &kernel);
    let kernel_index = builder.entries.len() - 1;
    for index in 1..1000 {
        builder = builder.entry(ZipEntry::alias(
            &format!("word/header{index}.xml"),
            kernel_index,
        ));
    }
    let limits = Limits::default();
    let (result, text) = timed(&builder.build(), &limits);
    let extraction = ok(result);
    assert_eq!(words(&text), "body kernel");
    assert!(extraction.bytes_decompressed < 2 * kernel.len() as u64);
}

#[test]
fn zip_structure_attacks() {
    let limits = Limits::default();
    let body = "<w:p><w:r><w:t>survivor</w:t></w:r></w:p>";

    let mut data = docx(body);
    if let Some(entry) = data
        .entries
        .iter_mut()
        .find(|entry| entry.name == b"word/document.xml")
    {
        entry.local_sizes_zero = true;
        entry.flags = 0x0008;
    }
    assert_eq!(words(&timed(&data.build(), &limits).1), "survivor");

    let mut data = docx(body);
    if let Some(entry) = data
        .entries
        .iter_mut()
        .find(|entry| entry.name == b"word/document.xml")
    {
        entry.central_uncompressed_size = Some(1);
    }
    assert_eq!(words(&timed(&data.build(), &limits).1), "survivor");

    let mut data = docx(body);
    if let Some(entry) = data
        .entries
        .iter_mut()
        .find(|entry| entry.name == b"word/document.xml")
    {
        entry.central_compressed_size = Some(u32::MAX as u64 - 1);
    }
    assert_eq!(timed(&data.build(), &limits).0, Err(Error::Unsupported));

    let mut data = docx(body);
    if let Some(entry) = data
        .entries
        .iter_mut()
        .find(|entry| entry.name == b"word/document.xml")
    {
        entry.flags = 0x0001;
    }
    assert_eq!(timed(&data.build(), &limits).0, Err(Error::Unsupported));

    let mut data = docx(body);
    if let Some(entry) = data
        .entries
        .iter_mut()
        .find(|entry| entry.name == b"word/document.xml")
    {
        entry.zip64 = true;
        entry.central_compressed_size = Some(u64::MAX);
        entry.central_uncompressed_size = Some(u64::MAX);
    }
    assert_eq!(timed(&data.build(), &limits).0, Err(Error::Unsupported));

    let mut data = docx(body);
    if let Some(entry) = data
        .entries
        .iter_mut()
        .find(|entry| entry.name == b"word/document.xml")
    {
        entry.payload = (0..4096u32)
            .map(|index| (index.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
    }
    let (result, text) = timed(&data.build(), &limits);
    assert!(text.is_empty());
    assert!(matches!(result, Ok(_) | Err(Error::Unsupported)));

    let mut data = docx(body);
    data.prefix = b"MZ self extracting stub ".repeat(64);
    data.comment =
        b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\xff\xff\x00\x00\x00\x00\x00\x00".to_vec();
    assert_eq!(words(&timed(&data.build(), &limits).1), "survivor");

    let valid = docx(body).build();
    for cut in (0..valid.len()).step_by(3) {
        let (result, text) = timed(&valid[..cut], &limits);
        assert!(result.is_err() || text.len() <= "survivor".len());
    }
    let mut garbage = valid.clone();
    for (index, byte) in garbage.iter_mut().enumerate().skip(30).step_by(5) {
        *byte ^= index as u8;
    }
    let _ = timed(&garbage, &limits);
}

#[test]
fn entry_and_part_caps() {
    let mut builder = docx("<w:p><w:r><w:t>capped</w:t></w:r></w:p>");
    for index in 0..30_000 {
        builder = builder.stored(&format!("padding/{index}.bin"), b"");
    }
    let limits = Limits::default();
    let (result, _) = timed(&builder.build(), &limits);
    assert!(matches!(
        result,
        Ok(Extraction {
            truncated: true,
            ..
        }) | Err(Error::Unsupported)
    ));

    let slides: String = (0..20_000)
        .map(|index| format!("<p:sldId id=\"{index}\" r:id=\"rId{}\"/>", index % 5))
        .collect();
    let rels: String = (0..5000)
        .map(|index| format!("<Relationship Id=\"rId{index}\" Type=\"{REL_TYPE}/slide\" Target=\"slides/slide{index}.xml\"/>"))
        .collect();
    let mut builder = ZipBuilder::new()
        .file(
            "_rels/.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>").as_bytes(),
        )
        .file(
            "ppt/presentation.xml",
            format!("<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldIdLst>{slides}</p:sldIdLst></p:presentation>").as_bytes(),
        )
        .file("ppt/_rels/presentation.xml.rels", format!("<Relationships {RELS_NS}>{rels}</Relationships>").as_bytes());
    for index in 0..5 {
        builder = builder.file(
            &format!("ppt/slides/slide{index}.xml"),
            format!("<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><a:p><a:r><a:t>slide{index}</a:t></a:r></a:p></p:sld>").as_bytes(),
        );
    }
    let limits = Limits {
        max_parts: 50,
        ..Limits::default()
    };
    let (result, text) = timed(&builder.build(), &limits);
    ok(result);
    assert_eq!(words(&text), "slide0 slide1 slide2 slide3 slide4");
}

#[test]
fn xml_attribute_and_nesting_attacks() {
    let limits = Limits::default();
    let huge_attribute = format!(
        "<w:p w:rsid=\"{}\"><w:r><w:t a=\"{}\">attr</w:t></w:r></w:p>",
        "9".repeat(8 << 20),
        "&amp;".repeat(1 << 20)
    );
    let (result, text) = timed(&docx(&huge_attribute).build(), &limits);
    ok(result);
    assert_eq!(words(&text), "attr");

    let many_attributes: String = (0..200_000)
        .map(|index| format!(" a{index}=\"{index}\""))
        .collect();
    let sheet = format!("<row><c{many_attributes} t=\"s\"><v>1</v></c><c><v>2</v></c></row>");
    let data = ZipBuilder::new()
        .file(
            "_rels/.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>").as_bytes(),
        )
        .file("xl/workbook.xml", b"<workbook xmlns:r=\"r\"><sheets><sheet name=\"s\" r:id=\"rId1\"/></sheets></workbook>")
        .file(
            "xl/_rels/workbook.xml.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/worksheet\" Target=\"sheet.xml\"/></Relationships>").as_bytes(),
        )
        .file("xl/sheet.xml", format!("<worksheet><sheetData>{sheet}</sheetData></worksheet>").as_bytes())
        .build();
    let (result, text) = timed(&data, &limits);
    ok(result);
    assert_eq!(words(&text), "s 2");

    let nested_head = format!(
        "<html><body>{}visible{}<p>after</p></body></html>",
        "<head>".repeat(500_000),
        "</head>".repeat(500_000)
    );
    let data = ZipBuilder::new()
        .stored("mimetype", b"application/epub+zip")
        .file("chapter.xhtml", nested_head.as_bytes())
        .build();
    let (result, text) = timed(&data, &limits);
    ok(result);
    assert_eq!(words(&text), "after");

    let comment_bomb = format!(
        "<w:p><w:r><w:t>a</w:t></w:r></w:p><!--{}<w:p><w:r><w:t>b</w:t></w:r></w:p>",
        "-".repeat(4 << 20)
    );
    let (result, text) = timed(&docx(&comment_bomb).build(), &limits);
    ok(result);
    assert_eq!(words(&text), "a");

    let doctype =
        "<!DOCTYPE w:document [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;\">]>";
    let mut builder = docx("");
    builder
        .entries
        .retain(|entry| entry.name != b"word/document.xml");
    let data = builder
        .file(
            "word/document.xml",
            format!("{doctype}<w:document {W_NS}><w:body><w:p><w:r><w:t>&b;&b;ok</w:t></w:r></w:p></w:body></w:document>").as_bytes(),
        )
        .build();
    let (result, text) = timed(&data, &limits);
    ok(result);
    assert_eq!(words(&text), "ok");
}

fn zip_members(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return Vec::new();
    };
    (0..archive.len())
        .filter_map(|index| {
            let mut file = archive.by_index(index).ok()?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).ok()?;
            Some((file.name().to_string(), contents))
        })
        .collect()
}

const SEEDS: &[&str] = &[
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
    "hostile/docx_billion_laughs.docx",
    "hostile/xlsx_sparse_corners.xlsx",
    "hostile/xlsx_sst_uniquecount.xlsx",
    "hostile/ods_repeated_rows.ods",
];

#[test]
fn byte_mutations() {
    let limits = Limits {
        max_output_bytes: 1 << 20,
        ..Limits::default()
    };
    let mut rng = Rng::new(0x5EED_1234_ABCD_0001);
    for seed in SEEDS {
        let original = fixture(seed);
        for _ in 0..300 {
            let _ = timed(&mutate(&original, &mut rng), &limits);
        }
    }
}

#[test]
fn structure_aware_mutations() {
    let limits = Limits {
        max_output_bytes: 1 << 20,
        ..Limits::default()
    };
    let mut rng = Rng::new(0x5EED_1234_ABCD_0002);
    let mut extractor = text_extract::Extractor::new(limits.clone());
    let mut out = String::new();
    for seed in SEEDS.iter().filter(|seed| !seed.ends_with(".rtf")) {
        let members = zip_members(&fixture(seed));
        assert!(!members.is_empty(), "{seed}");
        for _ in 0..300 {
            let mut builder = ZipBuilder::new();
            let target = rng.below(members.len());
            for (index, (name, contents)) in members.iter().enumerate() {
                let contents = if index == target || rng.below(8) == 0 {
                    mutate(contents, &mut rng)
                } else {
                    contents.clone()
                };
                builder = if rng.below(4) == 0 {
                    builder.stored(name, &contents)
                } else {
                    builder.file(name, &contents)
                };
            }
            out.clear();
            let started = Instant::now();
            let result = extractor.extract(&builder.build(), Hints::new(), &mut out);
            assert!(started.elapsed() < DEBUG_TIME_BUDGET);
            assert!(out.len() <= limits.max_output_bytes);
            if let Ok(extraction) = result {
                assert_eq!(extraction.bytes_written, out.len());
            }
        }
    }
}

const PREFIX: &str = "kept ";

fn extract_after_prefix(data: &[u8], limits: &Limits) -> (Result<Extraction, Failure>, String) {
    let mut out = String::from(PREFIX);
    let result = text_extract::extract(data, Hints::new(), limits, &mut out);
    (result, out)
}

fn ooxml_with_main(name: &str, contents: &[u8]) -> Vec<u8> {
    ZipBuilder::new()
        .file(
            "_rels/.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/officeDocument\" Target=\"{name}\"/></Relationships>").as_bytes(),
        )
        .file(name, contents)
        .build()
}

#[test]
fn failed_extraction_reports_decompression_and_restores_output() {
    let limits = Limits::default();
    let padding = b"<w:p><w:r><w:t>padding</w:t></w:r></w:p>".repeat(1 << 16);

    let mut unknown_root = format!("<x:unknown {W_NS}>").into_bytes();
    unknown_root.extend_from_slice(&padding);
    unknown_root.extend_from_slice(b"</x:unknown>");
    let (result, out) = extract_after_prefix(
        &ooxml_with_main("word/document.xml", &unknown_root),
        &limits,
    );
    let failure = result
        .err()
        .unwrap_or_else(|| panic!("unknown OOXML root must fail"));
    assert_eq!(failure.error, Error::Unsupported);
    assert!(failure.bytes_decompressed > 0);
    assert!(
        failure.bytes_decompressed < 1 << 20,
        "{} of {} bytes decompressed",
        failure.bytes_decompressed,
        unknown_root.len()
    );
    assert_eq!(out, PREFIX);

    let mut drawing = b"<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><office:body><office:drawing>".to_vec();
    drawing.extend_from_slice(&b"<text:p>shape</text:p>".repeat(1 << 18));
    drawing.extend_from_slice(b"</office:drawing></office:body></office:document-content>");
    let data = ZipBuilder::new().file("content.xml", &drawing).build();
    let (result, out) = extract_after_prefix(&data, &limits);
    let failure = result
        .err()
        .unwrap_or_else(|| panic!("unsupported ODF body must fail"));
    assert_eq!(failure.error, Error::Unsupported);
    assert!(failure.bytes_decompressed > 0);
    assert!(failure.bytes_decompressed < 1 << 20);
    assert_eq!(out, PREFIX);

    let declared = ZipBuilder::new()
        .stored("mimetype", b"application/vnd.oasis.opendocument.text")
        .file("content.xml", b"<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><office:body><office:drawing><text:p>shape</text:p></office:drawing></office:body></office:document-content>")
        .build();
    let (result, out) = extract_after_prefix(&declared, &limits);
    assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Odt));
    assert_eq!(out, "kept shape");

    let written_then_failed = ZipBuilder::new()
        .file("content.xml", b"<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><office:body><office:text><text:p>written</text:p></office:text></office:body><office:body><office:drawing><text:p>shape</text:p></office:drawing></office:body></office:document-content>")
        .build();
    let (result, out) = extract_after_prefix(&written_then_failed, &limits);
    let failure = result
        .err()
        .unwrap_or_else(|| panic!("second unsupported body must fail"));
    assert_eq!(failure.error, Error::Unsupported);
    assert!(failure.bytes_decompressed > 0);
    assert_eq!(out, PREFIX);

    let (result, out) = extract_after_prefix(
        &ZipBuilder::new().file("readme.txt", b"hello").build(),
        &limits,
    );
    assert_eq!(
        result,
        Err(Failure {
            error: Error::Unsupported,
            bytes_decompressed: 0
        })
    );
    assert_eq!(out, PREFIX);
}

fn part_capped(data: &[u8], max_parts: usize) -> (Extraction, String) {
    let limits = Limits {
        max_parts,
        ..Limits::default()
    };
    let (result, text) = timed(data, &limits);
    (ok(result), words(&text))
}

#[test]
fn part_cap_marks_extraction_truncated() {
    let headers: String = (1..=3)
        .map(|index| format!("<Relationship Id=\"rId{index}\" Type=\"{REL_TYPE}/header\" Target=\"header{index}.xml\"/>"))
        .collect();
    let mut docx = docx("<w:p><w:r><w:t>body</w:t></w:r></w:p>").file(
        "word/_rels/document.xml.rels",
        format!("<Relationships {RELS_NS}>{headers}</Relationships>").as_bytes(),
    );
    for index in 1..=3 {
        docx = docx.file(
            &format!("word/header{index}.xml"),
            format!("<w:hdr {W_NS}><w:p><w:r><w:t>header{index}</w:t></w:r></w:p></w:hdr>")
                .as_bytes(),
        );
    }
    let docx = docx.build();
    let (extraction, text) = part_capped(&docx, 4);
    assert!(extraction.truncated);
    assert_eq!(text, "body header1");
    let (extraction, text) = part_capped(&docx, 100);
    assert!(!extraction.truncated);
    assert_eq!(text, "body header1 header2 header3");

    let rels: String = (0..3)
        .map(|index| format!("<Relationship Id=\"rId{index}\" Type=\"{REL_TYPE}/slide\" Target=\"slides/slide{index}.xml\"/>"))
        .collect();
    let slides: String = (0..3)
        .map(|index| format!("<p:sldId id=\"{index}\" r:id=\"rId{index}\"/>"))
        .collect();
    let mut pptx = ZipBuilder::new()
        .file(
            "_rels/.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>").as_bytes(),
        )
        .file(
            "ppt/presentation.xml",
            format!("<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldIdLst>{slides}</p:sldIdLst></p:presentation>").as_bytes(),
        )
        .file("ppt/_rels/presentation.xml.rels", format!("<Relationships {RELS_NS}>{rels}</Relationships>").as_bytes());
    for index in 0..3 {
        pptx = pptx.file(
            &format!("ppt/slides/slide{index}.xml"),
            format!("<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><a:p><a:r><a:t>slide{index}</a:t></a:r></a:p></p:sld>").as_bytes(),
        );
    }
    let pptx = pptx.build();
    let (extraction, text) = part_capped(&pptx, 4);
    assert!(extraction.truncated);
    assert_eq!(text, "slide0");
    let (extraction, _) = part_capped(&pptx, 100);
    assert!(!extraction.truncated);

    let epub = ZipBuilder::new()
        .stored("mimetype", b"application/epub+zip")
        .file(
            "META-INF/container.xml",
            b"<container><rootfiles><rootfile full-path=\"package.opf\" media-type=\"application/oebps-package+xml\"/></rootfiles></container>",
        )
        .file(
            "package.opf",
            b"<package><manifest><item id=\"a\" href=\"a.xhtml\"/><item id=\"b\" href=\"b.xhtml\"/></manifest><spine><itemref idref=\"a\"/><itemref idref=\"b\"/></spine></package>",
        )
        .file("a.xhtml", b"<html><body><p>first</p></body></html>")
        .file("b.xhtml", b"<html><body><p>second</p></body></html>")
        .build();
    let (extraction, text) = part_capped(&epub, 3);
    assert!(extraction.truncated);
    assert_eq!(text, "first");
    let (extraction, _) = part_capped(&epub, 100);
    assert!(!extraction.truncated);

    let fallback_epub = ZipBuilder::new()
        .stored("mimetype", b"application/epub+zip")
        .file("a.xhtml", b"<html><body><p>first</p></body></html>")
        .file("b.xhtml", b"<html><body><p>second</p></body></html>")
        .build();
    let (extraction, text) = part_capped(&fallback_epub, 1);
    assert!(extraction.truncated);
    assert_eq!(text, "first");

    let odt = ZipBuilder::new()
        .file("content.xml", b"<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><office:body><office:text><text:p>content</text:p></office:text></office:body></office:document-content>")
        .file("styles.xml", b"<office:document-styles xmlns:office=\"o\" xmlns:style=\"s\" xmlns:text=\"t\"><office:master-styles><style:master-page><style:header><text:p>styled</text:p></style:header></style:master-page></office:master-styles></office:document-styles>")
        .build();
    let (extraction, text) = part_capped(&odt, 1);
    assert!(extraction.truncated);
    assert_eq!(text, "content");
    let (extraction, text) = part_capped(&odt, 100);
    assert!(!extraction.truncated);
    assert_eq!(text, "content styled");
}

#[test]
fn epub_fallback_scans_members_directly() {
    const METHOD_UNSUPPORTED: u16 = 99;
    let mut builder = ZipBuilder::new().stored("mimetype", b"application/epub+zip");
    for index in 0..5000 {
        builder = builder.entry(ZipEntry::new(
            &format!("{}/unsupported{index}.xhtml", "d".repeat(512)),
            METHOD_UNSUPPORTED,
            b"<html><body><p>hidden</p></body></html>",
        ));
    }
    let data = builder
        .file("Chapter.xhtml", b"<html><body><p>upper</p></body></html>")
        .file("chapter.xhtml", b"<html><body><p>lower</p></body></html>")
        .entry(ZipEntry::new("lzma.xhtml", METHOD_LZMA, b"<p>lzma</p>"))
        .build();
    let limits = Limits::default();
    let (result, text) = timed(&data, &limits);
    let extraction = ok(result);
    assert_eq!(extraction.format, Format::Epub);
    assert!(!extraction.truncated);
    let text = words(&text);
    assert!(text.contains("upper") && text.contains("lower"), "{text}");
    assert!(!text.contains("hidden") && !text.contains("lzma"), "{text}");
}
