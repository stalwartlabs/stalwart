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
    let (extraction, text) = part_capped(&docx, 2);
    assert!(extraction.truncated);
    assert_eq!(text, "body header1");
    let (extraction, text) = part_capped(&docx, 4);
    assert!(!extraction.truncated);
    assert_eq!(text, "body header1 header2 header3");
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
    let (extraction, text) = part_capped(&pptx, 2);
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
    let (extraction, text) = part_capped(&epub, 1);
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

fn package_rels(entries: &[(&str, &str, &str)]) -> String {
    let body: String = entries
        .iter()
        .map(|(id, kind, target)| {
            format!("<Relationship Id=\"{id}\" Type=\"{REL_TYPE}/{kind}\" Target=\"{target}\"/>")
        })
        .collect();
    format!("<Relationships {RELS_NS}>{body}</Relationships>")
}

fn renamed(entry: &ZipEntry, name: &str) -> ZipEntry {
    let mut copy = entry.clone();
    copy.name = name.as_bytes().to_vec();
    copy
}

#[test]
fn chart_caches_and_drawings_are_bounded() {
    let point = b"<c:pt idx=\"0\"><c:v>4.4000000000000004</c:v></c:pt>".repeat(1000);
    let bomb = deflate_bomb(
        b"<c:chartSpace xmlns:c=\"c\"><c:chart><c:plotArea><c:barChart><c:ser><c:val><c:numRef><c:numCache>",
        &point,
        20_000,
        b"</c:numCache></c:numRef></c:val></c:ser></c:barChart></c:plotArea></c:chart></c:chartSpace>",
    );
    let data = ZipBuilder::new()
        .file(
            "_rels/.rels",
            package_rels(&[("rId1", "officeDocument", "ppt/presentation.xml")]).as_bytes(),
        )
        .file(
            "ppt/presentation.xml",
            b"<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldIdLst><p:sldId id=\"256\" r:id=\"rId1\"/></p:sldIdLst></p:presentation>",
        )
        .file(
            "ppt/_rels/presentation.xml.rels",
            package_rels(&[("rId1", "slide", "slides/slide1.xml")]).as_bytes(),
        )
        .file("ppt/slides/slide1.xml", b"<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><a:p><a:r><a:t>slide</a:t></a:r></a:p></p:sld>")
        .file(
            "ppt/slides/_rels/slide1.xml.rels",
            package_rels(&[("rId1", "chart", "../charts/chart1.xml")]).as_bytes(),
        )
        .entry(ZipEntry::from_bomb("ppt/charts/chart1.xml", bomb))
        .build();
    let limits = Limits::default();
    let (result, text) = timed(&data, &limits);
    let extraction = ok(result);
    assert!(extraction.truncated);
    assert!(text.starts_with("slide\n4.4 4.4 4.4"));
    assert_eq!(text.len(), limits.max_output_bytes);

    let limits = Limits {
        max_output_bytes: usize::MAX,
        ..Limits::default()
    };
    let (result, _) = timed(&data, &limits);
    assert!(ok(result).truncated);

    let nesting = deflate_bomb(
        b"<xdr:wsDr xmlns:xdr=\"x\" xmlns:a=\"a\">",
        &b"<xdr:grpSp><xdr:sp><xdr:txBody><a:p><a:r><a:t>".repeat(1000),
        2000,
        b"deep</a:t></a:r></a:p></xdr:txBody></xdr:sp></xdr:wsDr>",
    );
    let data = ZipBuilder::new()
        .file(
            "_rels/.rels",
            package_rels(&[("rId1", "officeDocument", "xl/workbook.xml")]).as_bytes(),
        )
        .file(
            "xl/workbook.xml",
            b"<workbook xmlns:r=\"r\"><sheets><sheet name=\"S\" r:id=\"rId1\"/></sheets></workbook>",
        )
        .file(
            "xl/_rels/workbook.xml.rels",
            package_rels(&[("rId1", "worksheet", "worksheets/sheet1.xml")]).as_bytes(),
        )
        .file("xl/worksheets/sheet1.xml", b"<worksheet><sheetData/></worksheet>")
        .file(
            "xl/worksheets/_rels/sheet1.xml.rels",
            package_rels(&[("rId1", "drawing", "../drawings/drawing1.xml")]).as_bytes(),
        )
        .entry(ZipEntry::from_bomb("xl/drawings/drawing1.xml", nesting))
        .build();
    let limits = Limits::default();
    let (result, text) = timed(&data, &limits);
    ok(result);
    assert!(text.len() <= limits.max_output_bytes);
}

#[test]
fn many_sheets_with_many_relationships() {
    let sheets = 400;
    let rel_count = 2000;
    let workbook: String = (0..sheets)
        .map(|index| format!("<sheet name=\"s{index}\" r:id=\"rId{index}\"/>"))
        .collect();
    let workbook_rels: Vec<(String, String)> = (0..sheets)
        .map(|index| {
            (
                format!("rId{index}"),
                format!("worksheets/sheet{index}.xml"),
            )
        })
        .collect();
    let workbook_rels: Vec<(&str, &str, &str)> = workbook_rels
        .iter()
        .rev()
        .map(|(id, target)| (id.as_str(), "worksheet", target.as_str()))
        .collect();
    let sheet_rels: Vec<(String, &str, String)> = (0..rel_count)
        .map(|index| {
            let kind = if index % 2 == 0 {
                "comments"
            } else {
                "drawing"
            };
            (
                format!("rId{index}"),
                kind,
                format!("../shared{}.xml", index % 7),
            )
        })
        .collect();
    let sheet_rels: Vec<(&str, &str, &str)> = sheet_rels
        .iter()
        .map(|(id, kind, target)| (id.as_str(), *kind, target.as_str()))
        .collect();
    let rels_entry = ZipEntry::new(
        "rels",
        METHOD_DEFLATED,
        package_rels(&sheet_rels).as_bytes(),
    );
    let sheet_entry = ZipEntry::new(
        "sheet",
        METHOD_DEFLATED,
        b"<worksheet><sheetData><row><c><v>1</v></c></row></sheetData></worksheet>",
    );
    let mut builder = ZipBuilder::new()
        .file(
            "_rels/.rels",
            package_rels(&[("rId1", "officeDocument", "xl/workbook.xml")]).as_bytes(),
        )
        .file(
            "xl/workbook.xml",
            format!("<workbook xmlns:r=\"r\"><sheets>{workbook}</sheets></workbook>").as_bytes(),
        )
        .file(
            "xl/_rels/workbook.xml.rels",
            package_rels(&workbook_rels).as_bytes(),
        );
    for index in 0..sheets {
        builder = builder
            .entry(renamed(
                &sheet_entry,
                &format!("xl/worksheets/sheet{index}.xml"),
            ))
            .entry(renamed(
                &rels_entry,
                &format!("xl/worksheets/_rels/sheet{index}.xml.rels"),
            ));
    }
    for index in 0..7 {
        builder = builder.file(
            &format!("xl/shared{index}.xml"),
            format!("<comments><commentList><comment><text><r><t>note{index}</t></r></text></comment></commentList></comments>").as_bytes(),
        );
    }
    let limits = Limits::default();
    let (result, text) = timed(&builder.build(), &limits);
    ok(result);
    let text = words(&text);
    for index in 0..7 {
        assert_eq!(text.matches(&format!("note{index}")).count(), 1, "{text}");
    }
}

#[test]
fn hostile_styles_values_and_header_codes() {
    let formats: String = (0..20_000)
        .map(|index| {
            format!(
                "<numFmt numFmtId=\"{}\" formatCode=\"{}\"/>",
                164 + index,
                "&quot;y".repeat(200)
            )
        })
        .collect();
    let xfs = "<xf numFmtId=\"14\"/>".repeat(100_000);
    let long_value = "9".repeat(1 << 20);
    let header = format!(
        "&amp;K{}&amp;\"unterminated {}",
        "&amp;".repeat(100_000),
        "x".repeat(100_000)
    );
    let sheet = format!(
        "<worksheet><sheetData><row><c s=\"5\"><v>45000</v></c><c s=\"99999\"><v>12.5</v></c><c s=\"0\"><v>{long_value}</v></c><c s=\"4294967296\"><v>1e308</v></c><c t=\"b\"><v>{long_value}</v></c></row></sheetData><headerFooter><oddHeader>{header}</oddHeader><oddFooter>&amp;99999999999999999999tail</oddFooter></headerFooter></worksheet>"
    );
    let data = ZipBuilder::new()
        .file(
            "_rels/.rels",
            package_rels(&[("rId1", "officeDocument", "xl/workbook.xml")]).as_bytes(),
        )
        .file(
            "xl/workbook.xml",
            b"<workbook xmlns:r=\"r\"><workbookPr date1904=\"yes\"/><sheets><sheet name=\"S\" r:id=\"rId1\"/></sheets></workbook>",
        )
        .file(
            "xl/_rels/workbook.xml.rels",
            package_rels(&[
                ("rId1", "worksheet", "worksheets/sheet1.xml"),
                ("rId2", "styles", "styles.xml"),
            ])
            .as_bytes(),
        )
        .file(
            "xl/styles.xml",
            format!("<styleSheet><numFmts>{formats}</numFmts><cellXfs>{xfs}</cellXfs></styleSheet>").as_bytes(),
        )
        .file("xl/worksheets/sheet1.xml", sheet.as_bytes())
        .build();
    let limits = Limits::default();
    let (result, text) = timed(&data, &limits);
    ok(result);
    assert!(text.contains("2023-03-15 12.5"), "{}", &text[..64]);
    assert!(text.contains(&long_value));
    assert!(text.contains("1e308"));
    assert!(text.ends_with("tail"), "{}", &text[text.len() - 32..]);
}

#[test]
fn rtf_annotation_and_html_tag_attacks() {
    let mut source = b"{\\rtf1\\ansi\\fromhtml1 ".to_vec();
    for _ in 0..200_000 {
        source.extend_from_slice(b"{\\*\\annotation a");
    }
    source.extend_from_slice(&b"}".repeat(200_000));
    source.extend_from_slice(b"{\\*\\htmltag0 ");
    source.extend(std::iter::repeat_n(b'<', 1 << 20));
    source.extend_from_slice(b"}{\\*\\htmltag0 ");
    source.extend(b"&nbsp;".repeat(100_000));
    source.extend_from_slice(b"}");
    source.extend(b"\\*".repeat(100_000));
    source.extend_from_slice(b" tail}");
    let limits = Limits::default();
    let (result, text) = timed(&source, &limits);
    assert_eq!(ok(result).format, Format::Rtf);
    let (body, note) = text
        .split_once(" tail ")
        .unwrap_or_else(|| panic!("{}", &text[text.len().saturating_sub(64)..]));
    assert!(!body.contains("tail"));
    assert!(note.bytes().all(|byte| byte == b'a' || byte == b' '));
    assert!(note.len() <= 1 << 16, "{}", note.len());
}

#[test]
fn odf_object_flood_is_bounded() {
    let object = ZipEntry::new(
        "object",
        METHOD_DEFLATED,
        b"<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><office:body><office:chart><text:p>obj</text:p></office:chart></office:body></office:document-content>",
    );
    let mut builder = ZipBuilder::new()
        .stored("mimetype", b"application/vnd.oasis.opendocument.text")
        .file("content.xml", b"<office:document-content xmlns:office=\"o\" xmlns:text=\"t\"><office:body><office:text><text:p>main</text:p></office:text></office:body></office:document-content>");
    for index in 0..9000 {
        builder = builder.entry(renamed(&object, &format!("Object {index}/content.xml")));
    }
    let limits = Limits {
        max_parts: 500,
        ..Limits::default()
    };
    let (result, text) = timed(&builder.build(), &limits);
    let extraction = ok(result);
    assert!(extraction.truncated);
    assert_eq!(words(&text).matches("obj").count(), 499);
}

#[test]
fn reverse_ordered_parts_are_claimed_quickly() {
    let slides = 9000;
    let ids: String = (0..slides)
        .map(|index| format!("<p:sldId id=\"{}\" r:id=\"rId{index}\"/>", 256 + index))
        .collect();
    let rels: String = (0..slides)
        .map(|index| format!("<Relationship Id=\"rId{index}\" Type=\"{REL_TYPE}/slide\" Target=\"slides/slide{index}.xml\"/>"))
        .collect();
    let mut builder = ZipBuilder::new()
        .file(
            "_rels/.rels",
            package_rels(&[("rId1", "officeDocument", "ppt/presentation.xml")]).as_bytes(),
        )
        .file(
            "ppt/presentation.xml",
            format!("<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldIdLst>{ids}</p:sldIdLst></p:presentation>").as_bytes(),
        )
        .file(
            "ppt/_rels/presentation.xml.rels",
            format!("<Relationships {RELS_NS}>{rels}</Relationships>").as_bytes(),
        );
    for index in (0..slides).rev() {
        builder = builder.stored(
            &format!("ppt/slides/slide{index}.xml"),
            format!("<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><a:t>s{index}</a:t></p:sld>").as_bytes(),
        );
    }
    let limits = Limits::default();
    let (result, text) = timed(&builder.build(), &limits);
    assert!(!ok(result).truncated);
    assert!(words(&text).ends_with("s8999"));
}

#[test]
fn styles_end_tag_flood_and_duplicate_relationship_ids() {
    let formats: String = (0..4096)
        .map(|index| {
            format!(
                "<numFmt numFmtId=\"{}\" formatCode=\"0.00\"/>",
                164 + (index * 7919) % 4096
            )
        })
        .collect();
    let interleaved = "<numFmts><numFmt numFmtId=\"99\" formatCode=\"0%\"/></numFmts><cellXfs><xf numFmtId=\"9\"/>".repeat(20_000);
    let styles = format!(
        "<styleSheet><numFmts>{formats}</numFmts>{}{interleaved}<cellXfs><xf numFmtId=\"0\"/><xf numFmtId=\"164\"/></cellXfs></styleSheet>",
        "</numFmts>".repeat(1_000_000)
    );
    let rels: String = (0..9999)
        .map(|index| format!("<Relationship Id=\"rId1\" Type=\"{REL_TYPE}/worksheet\" Target=\"worksheets/sheet{index}.xml\"/>"))
        .collect();
    let sheets: String = (0..3000)
        .map(|_| "<sheet name=\"S\" r:id=\"rId1\"/>")
        .collect();
    let data = ZipBuilder::new()
        .file(
            "_rels/.rels",
            package_rels(&[("rId1", "officeDocument", "xl/workbook.xml")]).as_bytes(),
        )
        .file(
            "xl/workbook.xml",
            format!("<workbook xmlns:r=\"r\"><sheets>{sheets}</sheets></workbook>").as_bytes(),
        )
        .file(
            "xl/_rels/workbook.xml.rels",
            format!("<Relationships {RELS_NS}>{rels}<Relationship Id=\"rId2\" Type=\"{REL_TYPE}/styles\" Target=\"styles.xml\"/></Relationships>").as_bytes(),
        )
        .file("xl/styles.xml", styles.as_bytes())
        .file(
            "xl/worksheets/sheet0.xml",
            b"<worksheet><sheetData><row><c s=\"1\"><v>2.5</v></c></row></sheetData></worksheet>",
        )
        .file(
            "xl/worksheets/sheet1.xml",
            b"<worksheet><sheetData><row><c><v>second</v></c></row></sheetData></worksheet>",
        )
        .build();
    let started = Instant::now();
    let (result, text) = timed(&data, &Limits::default());
    ok(result);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(
        words(&text).ends_with("250%"),
        "{}",
        &text[text.len().saturating_sub(64)..]
    );
    assert!(!text.contains("second"));
}
