/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod common;

use common::{pdf::Document, pdf::Pdf, *};
use std::path::Path;
use text_extract::{Error, Extraction, Extractor, Format, Hints, Limits};

fn ok(result: Result<Extraction, Error>) -> Extraction {
    result.unwrap_or_else(|err| panic!("expected extraction, got {err:?}"))
}

fn pages() -> [&'static [u8]; 2] {
    [b"BT (alpha) Tj ET", b"BT (beta gamma) Tj ET"]
}

fn crypt_fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pdf/crypt")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

#[test]
fn synthetic_documents_are_recognised_and_decoded() {
    for (compress, object_streams, xref_stream) in [
        (false, false, false),
        (true, false, false),
        (true, true, true),
    ] {
        let mut document = Document::new(&pages());
        document.compress = compress;
        document.object_streams = object_streams;
        document.xref_stream = xref_stream;
        let (result, text) = run(&document.build());
        let extraction = ok(result);
        assert_eq!(extraction.format, Format::Pdf);
        assert!(!extraction.truncated);
        assert_eq!(text, "alpha\nbeta gamma");
        assert!(extraction.bytes_decompressed >= document.content_bytes());
    }
}

#[test]
fn detection_prefers_pdf_signature_over_embedded_zip() {
    let docx_bytes = docx("<w:p><w:r><w:t>inside</w:t></w:r></w:p>").build();
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
        .stream(4, "", b"BT (x) Tj ET")
        .stream(5, "/Type /EmbeddedFile", &docx_bytes)
        .xref_table("/Root 1 0 R");
    let data = pdf.build();
    for hints in [
        Hints::new(),
        Hints::new().with_file_name("report.docx"),
        Hints::new().with_media_type(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
    ] {
        let (result, _) = run_with(&data, hints, &Limits::default());
        assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Pdf));
    }

    let mut junk_prefixed = b"Content-Type: application/pdf\r\n\r\n".to_vec();
    junk_prefixed.extend_from_slice(&data);
    assert_eq!(
        run(&junk_prefixed).0.map(|extraction| extraction.format),
        Ok(Format::Pdf)
    );

    let zip_with_pdf = ZipBuilder::new().stored("a.pdf", &data).build();
    assert_eq!(run(&zip_with_pdf).0, Err(Error::Unsupported));
    let docx_with_pdf = docx("<w:p><w:r><w:t>word</w:t></w:r></w:p>")
        .stored("word/media/a.pdf", &data)
        .build();
    let (result, text) = run(&docx_with_pdf);
    assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Docx));
    assert_eq!(text, "word");

    let mut late = vec![b' '; 2000];
    late.extend_from_slice(&data);
    assert_ne!(
        run(&late).0.map(|extraction| extraction.format),
        Ok(Format::Pdf)
    );
}

#[test]
fn encrypted_documents() {
    for name in [
        "r2_rc4_40.pdf",
        "r4_aes_128.pdf",
        "r6_aes_256.pdf",
        "r6_empty_owner.pdf",
    ] {
        let extraction = ok(run(&crypt_fixture(name)).0);
        assert_eq!(extraction.format, Format::Pdf, "{name}");
        assert!(extraction.bytes_decompressed > 100, "{name}");
    }
    for name in ["r3_user_pw.pdf", "r6_user_pw.pdf"] {
        assert_eq!(
            run(&crypt_fixture(name)).0,
            Err(Error::Unsupported),
            "{name}"
        );
    }
    let mut unsupported = Pdf::new();
    unsupported
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [] /Count 0 >>")
        .object(3, "<< /Filter /Adobe.PubSec /V 4 /R 4 >>")
        .xref_table("/Root 1 0 R /Encrypt 3 0 R /ID [<00> <00>]");
    assert_eq!(run(&unsupported.build()).0, Err(Error::Unsupported));
}

#[test]
fn unusable_documents_are_unsupported() {
    for data in [
        &b"%PDF-1.4\n%%EOF\n"[..],
        b"%PDF-",
        b"%PDF-1.7\n1 0 obj << /Type /Foo >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF",
    ] {
        let (result, text) = run(data);
        assert_eq!(result, Err(Error::Unsupported));
        assert_eq!(text, "");
    }
}

#[test]
fn budgets_mark_truncation() {
    let big = vec![b'x'; 200_000];
    let mut document = Document::new(&[&big, &big, &big]);
    document.compress = true;
    let data = document.build();
    let limits = Limits {
        max_total_bytes: 250_000,
        ..Limits::default()
    };
    let (result, _) = run_with(&data, Hints::new(), &limits);
    let extraction = ok(result);
    assert!(extraction.truncated);
    assert!(extraction.bytes_decompressed <= 250_000);
    let limits = Limits {
        max_part_bytes: 1000,
        ..Limits::default()
    };
    let extraction = ok(run_with(&data, Hints::new(), &limits).0);
    assert!(extraction.truncated);
    assert_eq!(extraction.bytes_decompressed, 3000);
}

#[test]
fn extractor_reuses_scratch_across_formats() {
    let mut extractor = Extractor::new(Limits::default());
    let pdf = Document::new(&pages()).build();
    let docx_bytes = docx("<w:p><w:r><w:t>after pdf</w:t></w:r></w:p>").build();
    for _ in 0..3 {
        let mut out = String::new();
        let extraction = extractor
            .extract(&pdf, Hints::new(), &mut out)
            .unwrap_or_else(|err| panic!("{err:?}"));
        assert_eq!(extraction.format, Format::Pdf);
        out.clear();
        extractor
            .extract(&docx_bytes, Hints::new(), &mut out)
            .unwrap_or_else(|err| panic!("{err:?}"));
        assert_eq!(out, "after pdf");
    }
}

fn placed_glyphs(glyphs: &[(f64, &str)]) -> Vec<u8> {
    glyphs
        .iter()
        .map(|(x, glyph)| format!("BT 12 0 0 12 {x} 700 Tm /F1 1 Tf ({glyph}) Tj ET\n"))
        .collect::<String>()
        .into_bytes()
}

#[test]
fn line_spacing_state_does_not_leak_across_pages_or_documents() {
    let tight = placed_glyphs(&[(0.0, "H"), (10.4, "e"), (18.8, "r"), (24.2, "e")]);
    let spaced_tail = placed_glyphs(&[(0.0, "a"), (7.0, "b"), (14.0, " ")]);
    let fresh = |data: &[u8]| {
        let (result, out) = run(data);
        ok(result);
        out
    };
    let tight_only = Document::new(&[&tight]).build();
    let expected = fresh(&tight_only);
    let both = fresh(&Document::new(&[&spaced_tail, &tight]).build());
    assert!(both.ends_with(&expected), "{both:?} vs {expected:?}");

    let tail_only = Document::new(&[&spaced_tail]).build();
    let mut extractor = Extractor::new(Limits::default());
    for data in [&tail_only, &tight_only, &tight_only] {
        let mut out = String::new();
        ok(extractor
            .extract(data, Hints::new(), &mut out)
            .map_err(|failure| failure.error));
        assert_eq!(out, fresh(data));
    }
}

const FIXTURE_PHRASES: &[(&str, bool, &[&str])] = &[
    (
        "gen/type1-winansi-std14.pdf",
        false,
        &[
            "Quillbrook",
            "Café crème à la française",
            "Größenwahn and smørrebrød",
            "per-mille ‰ trademark ™",
            "Marrowby lighthouse keeper",
        ],
    ),
    (
        "gen/truetype-subset-multiscript.pdf",
        false,
        &[
            "Zażółć gęślą jaźń",
            "мягких французских булок",
            "ψυχοφθόρα βδελυγμία",
            "Tiếng Việt",
            "İstanbul",
        ],
    ),
    (
        "gen/identity-h-cairo-ligatures.pdf",
        false,
        &[
            "official affluent fjord",
            "efficient office workflows",
            "ffi and ffl",
        ],
    ),
    (
        "gen/cjk-cid-predefined-cmap.pdf",
        true,
        &[
            "日本語の全文検索テスト",
            "中文全文检索测试",
            "한국어 전문 검색 시험",
        ],
    ),
    (
        "gen/cjk-vertical-writing.pdf",
        true,
        &[
            "縦書きの日本語テキストです",
            "右から左へ列が進みます",
            "横書きの見出し",
        ],
    ),
    (
        "gen/cjk-korean-cairo.pdf",
        false,
        &["한국어 텍스트 추출 테스트입니다", "서울의 겨울은 춥습니다"],
    ),
    (
        "gen/cjk-chinese-cairo.pdf",
        true,
        &[
            "全文检索的中文文本提取测试",
            "北京的秋天天气晴朗",
            "臺灣的夜市非常熱鬧",
        ],
    ),
    (
        "gen/cjk-japanese-weasyprint.pdf",
        true,
        &[
            "東京の春は桜がとても美しい",
            "カタカナのコンピューター",
            "注文番号 58213",
        ],
    ),
    ("gen/arabic-cairo.pdf", true, &["العربي", "بالعالم", "4821"]),
    (
        "gen/hebrew-cairo.pdf",
        true,
        &["חילוץ טקסט בעברית", "שלום עולם מירושלים", "7730"],
    ),
    (
        "gen/actualtext-spans.pdf",
        false,
        &[
            "Straße",
            "naïve café in Zürich",
            "ActualText replaces the glyphs",
            "Oakhollow Trading Company",
        ],
    ),
    (
        "gen/form-xobject-and-inline-image.pdf",
        false,
        &[
            "Harrowgate Mapping Cooperative",
            "gazetteers since 1911",
            "Wendlebury Fen and Otterscombe",
        ],
    ),
    (
        "gen/rotated-pages.pdf",
        false,
        &[
            "Rotate 90 entry in its page dictionary",
            "mentions Brackenfold",
            "Landscape media box",
            "Upside down footer sentence",
        ],
    ),
    (
        "gen/differences-encoding-no-tounicode.pdf",
        false,
        &[
            "The quick brown fox",
            "fine fish baked at the fire",
            "the épée and the straße",
        ],
    ),
    (
        "gen/spacing-kerning-geometry.pdf",
        false,
        &[
            "Kerned words separated only by TJ offsets",
            "Waterfowl nest kerning",
            "Positioned word by word with Td",
            "Justified line with generous word spacing",
            "Condensed horizontal scaling at fifty percent",
        ],
    ),
    (
        "gen/annotations-comments.pdf",
        false,
        &[
            "Lindqvist account",
            "APPROVED BY FINANCE DEPARTMENT",
            "Reviewer note: please verify the Lindqvist totals",
            "Highlighted because the revenue figure changed",
            "Strike this clause per legal",
        ],
    ),
    (
        "gen/acroform-filled.pdf",
        false,
        &[
            "Ottoline Merriweather",
            "17 Juniper Row",
            "Night watch",
            "Volunteer Registration Form",
            "Cartography",
        ],
    ),
    (
        "gen/acroform-values-without-appearances.pdf",
        false,
        &[
            "Barnaby Quillfeather",
            "Flat 3, Heron Quay",
            "Saltmere SM1 2AB",
            "Afternoon",
        ],
    ),
    (
        "gen/type3-matplotlib-chart.pdf",
        false,
        &[
            "Seasonal rainfall at Kestrel Ridge",
            "Observed rainfall 2023",
            "Rainfall (mm)",
        ],
    ),
    (
        "gen/scanned-ocr-invisible-text.pdf",
        false,
        &[
            "WEXCOMBE PARISH COUNCIL",
            "Councillor Hartwell proposed",
            "three quotations before March",
        ],
    ),
    (
        "gen/invoice-weasyprint.pdf",
        false,
        &[
            "Invoice INV-2024-0457",
            "Fernhollow Theatre Company",
            "€1,284.50",
            "DE89 3704 0044 0532 0130 00",
        ],
    ),
    (
        "gen/libreoffice-writer-letter.pdf",
        false,
        &[
            "Brackenfold Allotment Society",
            "heaviest marrow",
            "Mrs Pennyworth",
            "herzlich eingeladen",
        ],
    ),
    (
        "gen/chromium-skia-two-column.pdf",
        false,
        &[
            "Tidewater Survey Bulletin",
            "forty-one wading bird species",
            "Willkommen zur",
        ],
    ),
    (
        "gen/filters-lzw-ascii85-hex-rle.pdf",
        false,
        &[
            "Quenby filter test",
            "Thistlewood filter test",
            "Marlpit filter test",
            "Brindlecombe filter test",
            "Yarrowby filter test",
        ],
    ),
    (
        "gen/xref-stream-object-streams.pdf",
        false,
        &[
            "Notes from the Kestrel Ridge ledger",
            "Line 30 of page 6",
            "recorded plate 529",
        ],
    ),
    (
        "gen/broken-xref-and-trailer-missing.pdf",
        false,
        &["Pellingham parish register", "Saltmere ferry"],
    ),
    (
        "gen/broken-xref-wrong-offsets.pdf",
        false,
        &["Pellingham parish register", "Saltmere ferry"],
    ),
    (
        "gen/encrypted-aes-128.pdf",
        false,
        &[
            "Wexcombe bridge repairs",
            "418,250 pounds sterling",
            "Encrypted annotation comment about the tender",
        ],
    ),
    (
        "gen/encrypted-rc4-40.pdf",
        false,
        &[
            "Wexcombe bridge repairs",
            "418,250 pounds sterling",
            "Encrypted annotation comment about the tender",
        ],
    ),
    (
        "gen/linearized.pdf",
        false,
        &[
            "Chapter 6: Notes from the Kestrel Ridge ledger",
            "Line 01 of page 1",
            "recorded plate 529",
        ],
    ),
    (
        "gen/incremental-update-prev-chain.pdf",
        false,
        &[
            "Harrow quarry reopened in May",
            "Lowmoor surveyor",
            "Auditor note added in revision three",
        ],
    ),
    (
        "tika/testExtraSpaces.pdf",
        false,
        &["Here is some formatted text"],
    ),
    ("tika/testOptionalHyphen.pdf", false, &["optionalhyphen"]),
    (
        "tika/testAnnotations.pdf",
        false,
        &["Here is some text", "Here is a comment"],
    ),
    (
        "tika/testPDF_acroform3.pdf",
        false,
        &[
            "contains a form with a signature field",
            "TIKA-1226",
            "comboItemB",
            "listItemC",
        ],
    ),
    (
        "pdfbox/GlyphLayoutBidi.pdf",
        false,
        &["Good afternoon", "Guten Tag", "1447"],
    ),
    (
        "pdfbox/GlyphLayoutLigaturesAndKerning_ActualText.pdf",
        true,
        &[
            "AVATAR, effective, affiliation, float, film, affluent",
            "(Ligatures and kerning)",
            "กูกินก้งปิ้งอยู่ในถ้ำ",
        ],
    ),
    (
        "pdfbox/sampleForSpec.pdf",
        false,
        &["Underline 5", "BoldLine 6", "ItalicLine 8"],
    ),
];

fn text_fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pdf/text")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn collapse(text: &str, remove_spaces: bool) -> String {
    let separator = if remove_spaces { "" } else { " " };
    text.split_whitespace().collect::<Vec<_>>().join(separator)
}

#[test]
fn real_fixtures_contain_their_phrases() {
    let mut extractor = Extractor::new(Limits::default());
    let mut missing = Vec::new();
    for (name, remove_spaces, phrases) in FIXTURE_PHRASES {
        let mut out = String::new();
        let extraction = extractor
            .extract(&text_fixture(name), Hints::new(), &mut out)
            .unwrap_or_else(|err| panic!("{name}: {err:?}"));
        assert_eq!(extraction.format, Format::Pdf, "{name}");
        assert!(!extraction.truncated, "{name}");
        let haystack = collapse(&out, *remove_spaces);
        missing.extend(
            phrases
                .iter()
                .filter(|phrase| !haystack.contains(&collapse(phrase, *remove_spaces)))
                .map(|phrase| format!("{name}: {phrase}")),
        );
    }
    assert!(missing.is_empty(), "missing phrases: {missing:#?}");
}

#[test]
fn fixture_text_is_stable_across_output_limits() {
    let data = text_fixture("gen/libreoffice-writer-letter.pdf");
    let (result, full) = run(&data);
    ok(result);
    for limit in [0, 1, 17, 100, full.len() / 2] {
        let limits = Limits {
            max_output_bytes: limit,
            ..Limits::default()
        };
        let (result, text) = run_with(&data, Hints::new(), &limits);
        ok(result);
        assert!(text.len() <= limit, "{limit}");
        assert!(full.starts_with(&text), "{limit}");
    }
}
