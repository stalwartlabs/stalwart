/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod common;

use common::*;
use text_extract::{Error, Extractor, Format, Hints, Limits};

const RELS_NS: &str = "xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"";
const REL_TYPE: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

fn extracted(data: &[u8], format: Format) -> String {
    let (result, text) = run(data);
    let extraction = result.unwrap_or_else(|err| panic!("extraction failed: {err:?}"));
    assert_eq!(extraction.format, format);
    assert!(!extraction.truncated);
    words(&text)
}

fn assert_in_order(text: &str, needles: &[&str]) {
    let mut from = 0;
    for needle in needles {
        match text[from..].find(needle) {
            Some(at) => from += at + needle.len(),
            None => panic!("{needle:?} missing or out of order in {text:?}"),
        }
    }
}

#[test]
fn real_docx_documents() {
    let text = extracted(&fixture("real/testWORD.docx"), Format::Docx);
    assert_in_order(
        &text,
        &[
            "Sample Word Document Title",
            "This document includes text that is BOLD and ITALIC.",
            "Nested table",
            "That\u{2019}s it!",
            "This is the footer for our document",
            "This is the header for our document",
        ],
    );

    let text = extracted(&fixture("real/testWORD_various.docx"), Format::Docx);
    assert_eq!(text.matches("Here is a text box").count(), 1);
    assert_in_order(
        &text,
        &[
            "Footnote appears here",
            "Row 1 Col 1 Row 1 Col 2",
            "\u{30be}\u{30eb}\u{30b2}\u{3068}\u{5c3e}\u{5d0e}",
            "\u{10332}\u{1033f}\u{10344}\u{10339}\u{10343}\u{1033a}",
            "This is the header text.",
            "This is a footnote.",
        ],
    );

    let text = extracted(&fixture("real/textutil.docx"), Format::Docx);
    assert_eq!(
        text,
        "Hello r\u{e9}sum\u{e9} na\u{ef}ve caf\u{e9} \u{fb01}nance office. \u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30c6}\u{30ad}\u{30b9}\u{30c8} \u{4e2d}\u{6587}\u{6587}\u{672c} \u{d55c}\u{ad6d}\u{c5b4} Second paragraph with the word Stalwart."
    );
}

#[test]
fn docx_runs_breaks_and_revisions() {
    let body = String::from(
        "<w:p><w:pPr><w:tabs><w:tab w:val=\"left\" w:pos=\"720\"/></w:tabs></w:pPr>\
         <w:r><w:t>Hel</w:t></w:r><w:r><w:t xml:space=\"preserve\">lo</w:t></w:r><w:r><w:tab/><w:t>tabbed</w:t><w:br/><w:t>broken</w:t></w:r></w:p>\
         <w:p><w:del><w:r><w:delText>deleted</w:delText></w:r></w:del><w:ins><w:r><w:t>inserted</w:t></w:r></w:ins>\
         <w:r><w:instrText> HYPERLINK \"http://x\" </w:instrText></w:r><w:r><w:t>link</w:t></w:r>\
         <w:moveFrom><w:r><w:t>movedaway</w:t></w:r></w:moveFrom><w:moveTo><w:r><w:t>moved</w:t></w:r></w:moveTo></w:p>\
         <w:p><w:r><mc:AlternateContent><mc:Choice Requires=\"wps\"><w:txbxContent><w:p><w:r><w:t>boxed</w:t></w:r></w:p></w:txbxContent></mc:Choice>\
         <mc:Fallback><w:txbxContent><w:p><w:r><w:t>boxed</w:t></w:r></w:p></w:txbxContent></mc:Fallback></mc:AlternateContent></w:r></w:p>\
         <w:p><w:r><w:t>non</w:t><w:noBreakHyphen/><w:t>breaking &amp; &#x263A; &lt;ok&gt;</w:t></w:r></w:p>",
    );
    let (result, text) = run(&docx(&body).build());
    assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Docx));
    assert_eq!(
        text,
        "Hello tabbed\nbroken\ninsertedlinkmoved\nboxed\nnon-breaking & \u{263a} <ok>"
    );
}

#[test]
fn docx_parts_follow_relationships() {
    let document = format!(
        "<?xml version=\"1.0\"?><w:document {W_NS}><w:body><w:p><w:r><w:t>body</w:t></w:r></w:p></w:body></w:document>"
    );
    let part = |root: &str, text: &str| {
        format!(
            "<?xml version=\"1.0\"?><w:{root} {W_NS}><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:{root}>"
        )
    };
    let data = ZipBuilder::new()
        .file(
            "_rels/.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/officeDocument\" Target=\"/Word/Document2.xml\"/></Relationships>").as_bytes(),
        )
        .file("word/document2.xml", document.as_bytes())
        .file(
            "word/_rels/document2.xml.rels",
            format!(
                "<Relationships {RELS_NS}>\
                 <Relationship Id=\"rId1\" Type=\"{REL_TYPE}/footnotes\" Target=\"notes/foot%20notes.xml\"/>\
                 <Relationship Id=\"rId2\" Type=\"{REL_TYPE}/header\" Target=\"../word/header1.xml\"/>\
                 <Relationship Id=\"rId3\" Type=\"{REL_TYPE}/hyperlink\" Target=\"http://example.com/\" TargetMode=\"External\"/>\
                 <Relationship Id=\"rId4\" Type=\"{REL_TYPE}/comments\" Target=\"comments.xml\"/>\
                 <Relationship Id=\"rId5\" Type=\"{REL_TYPE}/glossaryDocument\" Target=\"glossary/document.xml\"/>\
                 </Relationships>"
            )
            .as_bytes(),
        )
        .file("word/notes/foot notes.xml", part("footnotes", "footnote").as_bytes())
        .file("WORD/HEADER1.XML", part("hdr", "header").as_bytes())
        .file("word/comments.xml", part("comments", "comment").as_bytes())
        .file("word/glossary/document.xml", part("document", "glossary").as_bytes())
        .file("word/header2.xml", part("hdr", "orphan").as_bytes())
        .build();
    assert_eq!(
        extracted(&data, Format::Docx),
        "body footnote header comment"
    );
}

#[test]
fn docx_utf16_and_declared_encodings() {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?><w:document {W_NS}><w:body><w:p><w:r><w:t>utf16 caf\u{e9} \u{4e2d}</w:t></w:r></w:p></w:body></w:document>"
    );
    let mut utf16 = vec![0xFF, 0xFE];
    utf16.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    let mut builder = docx("");
    builder
        .entries
        .retain(|entry| entry.name != b"word/document.xml");
    let data = builder.clone().file("word/document.xml", &utf16).build();
    assert_eq!(extracted(&data, Format::Docx), "utf16 caf\u{e9} \u{4e2d}");

    let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><w:document xmlns:w=\"x\"><w:body><w:p><w:r><w:t>caf\xe9</w:t></w:r></w:p></w:body></w:document>";
    let data = builder.clone().stored("word/document.xml", latin1).build();
    assert_eq!(extracted(&data, Format::Docx), "caf\u{e9}");

    let strict = b"<w:document xmlns:w=\"http://purl.oclc.org/ooxml/wordprocessingml/main\"><w:body><w:p><w:r><w:t>strict</w:t></w:r></w:p></w:body></w:document>";
    let data = builder.file("word/document.xml", strict).build();
    assert_eq!(extracted(&data, Format::Docx), "strict");
}

#[test]
fn real_xlsx_documents() {
    let text = extracted(&fixture("real/testEXCEL.xlsx"), Format::Xlsx);
    assert_in_order(
        &text,
        &[
            "Feuil1 Feuil2 Feuil3",
            "Sample Excel Worksheet - Numbers and their Squares",
            "Written and saved in Microsoft Excel X for Mac Service Release 1.",
            "1 1 2 4 3 9",
            "15 225",
        ],
    );
}

fn xlsx(sheets: &[(&str, &str)], shared_strings: Option<&str>) -> Vec<u8> {
    let workbook: String = sheets
        .iter()
        .enumerate()
        .map(|(index, (name, _))| {
            format!(
                "<sheet name=\"{name}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
                index + 1,
                index + 1
            )
        })
        .collect();
    let rels: String = sheets
        .iter()
        .enumerate()
        .rev()
        .map(|(index, _)| format!("<Relationship Id=\"rId{}\" Type=\"{REL_TYPE}/worksheet\" Target=\"worksheets/sheet{}.xml\"/>", index + 1, sheets.len() - index))
        .collect();
    let mut builder = ZipBuilder::new()
        .file(
            "_rels/.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>").as_bytes(),
        )
        .file(
            "xl/workbook.xml",
            format!("<workbook xmlns=\"main\" xmlns:r=\"rel\"><sheets>{workbook}</sheets></workbook>").as_bytes(),
        )
        .file(
            "xl/_rels/workbook.xml.rels",
            format!("<Relationships {RELS_NS}>{rels}<Relationship Id=\"rIdS\" Type=\"{REL_TYPE}/sharedStrings\" Target=\"/xl/sharedStrings.xml\"/></Relationships>").as_bytes(),
        );
    for (index, (_, cells)) in sheets.iter().enumerate() {
        builder = builder.file(
            &format!("xl/worksheets/sheet{}.xml", sheets.len() - index),
            format!("<worksheet xmlns=\"main\"><sheetData>{cells}</sheetData></worksheet>")
                .as_bytes(),
        );
    }
    if let Some(shared_strings) = shared_strings {
        builder = builder.file(
            "xl/sharedStrings.xml",
            format!("<sst xmlns=\"main\" count=\"4000000000\" uniqueCount=\"4000000000\">{shared_strings}</sst>").as_bytes(),
        );
    }
    builder.build()
}

#[test]
fn xlsx_cells_and_shared_strings() {
    let data = xlsx(
        &[
            (
                "First &amp; Only",
                "<row r=\"1\"><c r=\"A1\" t=\"s\"><v>0</v></c><c r=\"B1\"><v>42.5</v></c><c r=\"C1\" t=\"b\"><v>1</v></c>\
                 <c r=\"D1\" t=\"inlineStr\"><is><t>inline</t><rPh><t>ignored</t></rPh></is></c><c r=\"E1\" t=\"str\"><f>A1&amp;\"x\"</f><v>formula</v></c>\
                 <c r=\"F1\" t=\"e\"><v>#DIV/0!</v></c></row><row r=\"1048576\"><c r=\"XFD1048576\" t=\"d\"><v>2024-01-02</v></c></row>",
            ),
            (
                "Second",
                "<row><c><v>7</v></c><c t=\"s\"><v/></c></row><extLst><ext><v>hidden</v></ext></extLst>",
            ),
        ],
        Some(
            "<si><t>plain</t></si><si><r><t>ri</t></r><r><t>ch</t></r><rPh sb=\"0\" eb=\"1\"><t>\u{3075}\u{308a}</t></rPh></si>",
        ),
    );
    assert_eq!(
        extracted(&data, Format::Xlsx),
        "First & Only Second plain rich 42.5 inline formula 2024-01-02 7"
    );
}

#[test]
fn real_pptx_documents() {
    let text = extracted(&fixture("real/testPPT.pptx"), Format::Pptx);
    assert_in_order(
        &text,
        &[
            "Attachment Test",
            "Rajiv",
            "Different words to test against",
            "Investment",
        ],
    );

    let text = extracted(&fixture("real/testPPT_various.pptx"), Format::Pptx);
    assert_in_order(
        &text,
        &[
            "Row 1 Col 1",
            "Here is a text box",
            "Number bullet 3",
            "\u{30be}\u{30eb}\u{30b2}",
            "This is the footer text.",
            "This is the header text.",
        ],
    );
}

#[test]
fn pptx_slide_order_and_notes() {
    let slide = |text: &str| {
        format!(
            "<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r><a:br/><a:r><a:t>line</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
        )
    };
    let data = ZipBuilder::new()
        .file(
            "_rels/.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/officeDocument\" Target=\"ppt/presentation.xml\"/></Relationships>").as_bytes(),
        )
        .file(
            "ppt/presentation.xml",
            b"<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldIdLst><p:sldId id=\"256\" r:id=\"rId9\"/><p:sldId id=\"257\" r:id=\"rId2\"/><p:sldId id=\"258\" r:id=\"rId2\"/><p:sldId id=\"259\" r:id=\"rId404\"/></p:sldIdLst></p:presentation>",
        )
        .file(
            "ppt/_rels/presentation.xml.rels",
            format!(
                "<Relationships {RELS_NS}><Relationship Id=\"rId2\" Type=\"{REL_TYPE}/slide\" Target=\"slides/slide1.xml\"/>\
                 <Relationship Id=\"rId9\" Type=\"{REL_TYPE}/slide\" Target=\"slides/slide2.xml\"/>\
                 <Relationship Id=\"rId3\" Type=\"{REL_TYPE}/slideLayout\" Target=\"slideLayouts/slideLayout1.xml\"/></Relationships>"
            )
            .as_bytes(),
        )
        .file("ppt/slides/slide1.xml", slide("second").as_bytes())
        .file("ppt/slides/slide2.xml", slide("first").as_bytes())
        .file("ppt/slideLayouts/slideLayout1.xml", slide("layout").as_bytes())
        .file(
            "ppt/slides/_rels/slide2.xml.rels",
            format!("<Relationships {RELS_NS}><Relationship Id=\"rId1\" Type=\"{REL_TYPE}/notesSlide\" Target=\"../notesSlides/notesSlide7.xml\"/></Relationships>").as_bytes(),
        )
        .file("ppt/notesSlides/notesSlide7.xml", slide("speaker").as_bytes())
        .build();
    assert_eq!(
        extracted(&data, Format::Pptx),
        "first line speaker line second line"
    );
}

#[test]
fn real_odf_documents() {
    let text = extracted(&fixture("real/testOpenOffice2.odt"), Format::Odt);
    assert_eq!(
        text,
        "This is a sample Open Office document, written in NeoOffice 2.2.1 for the Mac."
    );

    let text = extracted(&fixture("real/testODFwithOOo3.odt"), Format::Odt);
    assert!(!text.contains("Bart Hanssens"));
    assert_in_order(
        &text,
        &[
            "Apache Tika",
            "This is a rather 1 This is of course a simple footnote",
            "difficult test document, with interesting features.",
            "Rectangle Title This is a rectangle",
            "Third item",
            "Solr: Various, Solr website, 2009",
        ],
    );

    let text = extracted(&fixture("real/textutil.odt"), Format::Odt);
    assert_in_order(
        &text,
        &[
            "Hello r\u{e9}sum\u{e9}",
            "\u{d55c}\u{ad6d}\u{c5b4}",
            "Stalwart.",
        ],
    );
    assert_eq!(
        extracted(&fixture("real/gen.odp"), Format::Odp),
        "Quarterly roadmap slide"
    );
}

fn odf(mimetype: Option<&str>, content: &str, styles: &str) -> Vec<u8> {
    let mut builder = ZipBuilder::new();
    if let Some(mimetype) = mimetype {
        builder = builder.stored("mimetype", mimetype.as_bytes());
    }
    builder
        .file("content.xml", format!("<office:document-content xmlns:office=\"o\" xmlns:text=\"t\" xmlns:table=\"ta\" xmlns:number=\"n\" xmlns:dc=\"dc\"><office:automatic-styles><number:date-style><number:text>/</number:text></number:date-style></office:automatic-styles><office:body>{content}</office:body></office:document-content>").as_bytes())
        .file("styles.xml", format!("<office:document-styles xmlns:office=\"o\" xmlns:style=\"s\" xmlns:text=\"t\" xmlns:number=\"n\"><office:styles><number:text>noise</number:text></office:styles><office:master-styles><style:master-page>{styles}</style:master-page></office:master-styles></office:document-styles>").as_bytes())
        .file("META-INF/manifest.xml", b"<manifest/>")
        .build()
}

#[test]
fn odf_spacing_changes_and_repeats() {
    let data = odf(
        Some("application/vnd.oasis.opendocument.text"),
        "<office:text><text:tracked-changes><text:changed-region><text:deletion><text:p>removed</text:p></text:deletion></text:changed-region></text:tracked-changes>\
         <text:p>many<text:s text:c=\"1000000000\"/>spaces<text:tab/>tab<text:line-break/>next \
         <text:span>sp</text:span>an <text:date>2024</text:date></text:p>\
         <office:annotation><dc:creator>Author</dc:creator><dc:date>2020</dc:date><text:p>remark</text:p></office:annotation>\
         <text:h>Heading</text:h></office:text>",
        "<style:header><text:p>Top</text:p></style:header><style:footer-left><text:p>Bottom</text:p></style:footer-left>",
    );
    let (result, text) = run(&data);
    assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Odt));
    assert_eq!(
        text,
        "many spaces tab\nnext span 2024\nremark\nHeading\nTop\nBottom"
    );

    let data = odf(
        None,
        "<office:spreadsheet><table:table table:name=\"Sheet &amp; One\"><table:table-column table:number-columns-repeated=\"16384\"/>\
         <table:table-row table:number-rows-repeated=\"1048575\"><table:table-cell table:number-columns-repeated=\"16384\"><text:p>Total</text:p></table:table-cell></table:table-row>\
         </table:table></office:spreadsheet>",
        "",
    );
    assert_eq!(extracted(&data, Format::Ods), "Sheet & One Total");
}

#[test]
fn real_epub_document() {
    let text = extracted(&fixture("real/testEPUB.epub"), Format::Epub);
    assert_in_order(
        &text,
        &[
            "Table of Contents",
            "This is the text for chapter One",
            "First item Second item",
            "Plus a simple div, and a span",
            "This is the text for chapter Two",
            "Table header Table data",
        ],
    );
}

fn epub(opf: &str, files: &[(&str, &str)]) -> ZipBuilder {
    let mut builder = ZipBuilder::new()
        .stored("mimetype", b"application/epub+zip")
        .file(
            "META-INF/container.xml",
            b"<container><rootfiles><rootfile full-path=\"OEBPS/content%20dir/package.opf\" media-type=\"application/oebps-package+xml\"/></rootfiles></container>",
        )
        .file("OEBPS/content%20dir/package.opf", opf.as_bytes());
    for (name, contents) in files {
        builder = builder.file(name, contents.as_bytes());
    }
    builder
}

#[test]
fn epub_spine_order_and_html() {
    let opf = "<package><manifest>\
        <item id=\"c2\" href=\"../text/chapter%202.xhtml#start\" media-type=\"application/xhtml+xml\"/>\
        <item id=\"c1\" href=\"chapter1.html\" media-type=\"text/html\"/>\
        <item id=\"css\" href=\"style.css\" media-type=\"text/css\"/>\
        <item id=\"noext\" href=\"chapter3\"/>\
        </manifest><spine><itemref idref=\"c1\"/><itemref idref=\"css\"/><itemref idref=\"c2\"/><itemref idref=\"missing\"/><itemref idref=\"c1\"/></spine></package>";
    let data = epub(
        opf,
        &[
            (
                "OEBPS/content%20dir/chapter1.html",
                "<!DOCTYPE html><html><HEAD><title>Title</title><meta charset=\"utf-8\"><style>p{}</style></HEAD><body><h1>One</h1><p>caf&eacute;&nbsp;bar &#8212; &unknown; x<br>y</p><script>if (a < b) {}</script><div>div</div><div>block</div></body></html>",
            ),
            ("OEBPS/text/chapter 2.xhtml", "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body><p>Two<ruby>\u{6f22}<rt>kan</rt></ruby></p><table><tr><td>a</td><td>b</td></tr></table></body></html>"),
            ("OEBPS/content%20dir/style.css", "p { color: red }"),
        ],
    )
    .build();
    let (result, text) = run(&data);
    assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Epub));
    assert_eq!(
        words(&text),
        "One caf\u{e9} bar \u{2014} x y div block Two\u{6f22} a b"
    );

    let data = ZipBuilder::new()
        .stored("mimetype", b"application/epub+zip")
        .file(
            "b.xhtml",
            "<html><body><p>second</p></body></html>".as_bytes(),
        )
        .file(
            "a.xhtml",
            "<html><body><p>first</p></body></html>".as_bytes(),
        )
        .build();
    assert_eq!(extracted(&data, Format::Epub), "first second");
}

#[test]
fn real_rtf_documents() {
    assert_eq!(
        extracted(&fixture("real/testRTF.rtf"), Format::Rtf),
        "Test d\u{2019}indexation Word"
    );
    let text = extracted(&fixture("real/testRTFVarious.rtf"), Format::Rtf);
    assert_in_order(
        &text,
        &[
            "This is the header text.",
            "Here is a text box",
            "Footnote appears here This is a footnote.",
            "Row 1 Col 1 Row 1 Col 2 Row 1 Col 3",
            "\u{30be}\u{30eb}\u{30b2}\u{3068}\u{5c3e}\u{5d0e}",
            "\u{10332}\u{1033f}\u{10344}\u{10339}\u{10343}\u{1033a}",
            "Figure 1 This is a caption for Figure 1",
        ],
    );
    assert!(!text.contains("HYPERLINK"));
    let text = extracted(&fixture("real/textutil.rtf"), Format::Rtf);
    assert!(text.starts_with("Hello r\u{e9}sum\u{e9} na\u{ef}ve caf\u{e9}"));
}

fn rtf(source: &[u8]) -> String {
    let (result, text) = run(source);
    assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Rtf));
    text
}

#[test]
fn rtf_encodings_and_unicode() {
    assert_eq!(
        rtf(b"{\\rtf1\\ansi\\ansicpg1251\\deff0{\\fonttbl{\\f0\\fnil Arial;}{\\f1\\fcharset128 MS Gothic;}{\\f2\\fcharset0 Times;}}\\f0 \\'cf\\'f0\\'e8\\'e2\\'e5\\'f2 {\\f1 \\'93\\'fa\\'96\\'7b}\\f2 caf\\'e9\\par}"),
        "\u{41f}\u{440}\u{438}\u{432}\u{435}\u{442} \u{65e5}\u{672c}caf\u{e9}"
    );
    assert_eq!(
        rtf(b"{\\rtf1{\\fonttbl\\f0\\fcharset204 A;\\f1\\fnil B;}\\deff0 \\'e0{\\f1\\'e0}}"),
        "\u{430}\u{430}"
    );
    assert_eq!(
        rtf(b"{\\rtf1\\uc1 caf\\u233?\\u-3913?\\uc2\\u-10179\\'3f\\'3f\\u-8704 ??{\\uc0\\u8212}\\u26085\\'93\\'fa end}"),
        "caf\u{e9}\u{f0b7}\u{1f600}\u{2014}\u{65e5} end"
    );
    assert_eq!(
        rtf(b"{\\rtf1 {\\upr{ansi version}{\\*\\ud{unicode \\u20013?}}} \\emdash\\lquote q\\rquote\\~x\\_y\\-z\\{\\}\\\\}"),
        "unicode \u{4e2d} \u{2014}\u{2018}q\u{2019}\u{a0}x-yz{}\\"
    );
}

#[test]
fn rtf_destinations_and_binary() {
    assert_eq!(
        rtf(b"{\\rtf1\\ansi{\\info{\\title secret}}{\\colortbl;\\red0;}{\\stylesheet{\\s1 Normal;}}{\\*\\generator gen;}\
               before {\\pict\\pngblip 89504e47}{\\*\\shppict{\\pict ff}}{\\nonshppict{\\pict aa}}\
               {\\field{\\*\\fldinst HYPERLINK \"http://x\"}{\\fldrslt shown}}{\\*\\unknowndest hidden}\
               \\bin4 {}\\x after\\par{\\pntext 1.}{\\listtext 2.}item\\cell cell\\row}"),
        "before shown after\nitem cell"
    );
    assert_eq!(
        rtf(b"{\\rtf1\\ansi\\fromhtml1{\\*\\htmltag19 <html>}\\htmlrtf {\\htmlrtf0 visible\\htmlrtf rtfonly\\par\\htmlrtf0 }\\htmlrtf0 text}"),
        "visible\ntext"
    );
    assert_eq!(rtf(b"{\\rtf1 a}}}} trailing {b}"), "a");
    assert_eq!(rtf(b"{\\rtf1 unterminated {group"), "unterminated group");
    assert_eq!(rtf(b"\xEF\xBB\xBF  {\\rtf1 \\bin99999999999 x}"), "");
    assert_eq!(
        rtf(b"{\\rtf1\\u99999999999999999999 \\ucN\\uc-5 ok\\'zz}"),
        "okzz"
    );
}

#[test]
fn detection_uses_bytes_not_hints() {
    let data = docx("<w:p><w:r><w:t>bytes win</w:t></w:r></w:p>").build();
    for hints in [
        Hints::new().with_media_type("text/plain; charset=utf-8"),
        Hints::new().with_file_name("report.pdf"),
        Hints::new().with_media_type("application/vnd.oasis.opendocument.text"),
    ] {
        let (result, text) = run_with(&data, hints, &Limits::default());
        assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Docx));
        assert_eq!(text, "bytes win");
    }
    assert_eq!(run(b"%PDF-1.7 not supported").0, Err(Error::Unsupported));
    assert_eq!(run(b"").0, Err(Error::Unsupported));
    let plain_zip = ZipBuilder::new().file("readme.txt", b"hello").build();
    assert_eq!(run(&plain_zip).0, Err(Error::Unsupported));
    let limits = Limits {
        max_input_bytes: 10,
        ..Limits::default()
    };
    assert_eq!(
        run_with(&data, Hints::new(), &limits).0,
        Err(Error::TooLarge)
    );
}

#[test]
fn hints_prefilter() {
    assert!(Hints::new().may_be_supported());
    assert!(
        Hints::new()
            .with_media_type("application/octet-stream")
            .may_be_supported()
    );
    assert!(
        Hints::new()
            .with_media_type("image/png")
            .with_file_name("scan.DOCX")
            .may_be_supported()
    );
    assert!(
        !Hints::new()
            .with_media_type("image/png")
            .with_file_name("scan.png")
            .may_be_supported()
    );
    assert!(
        !Hints::new()
            .with_media_type("application/pdf")
            .may_be_supported()
    );
    assert!(
        !Hints::new()
            .with_file_name("archive.tar.gz")
            .may_be_supported()
    );
    assert!(
        !Hints::new()
            .with_media_type("application/octet-stream")
            .with_file_name("setup.exe")
            .may_be_supported()
    );
    assert!(
        Hints::new()
            .with_media_type("application/octet-stream")
            .with_file_name("report")
            .may_be_supported()
    );
    assert!(
        Hints::new()
            .with_media_type("application/octet-stream")
            .with_file_name("report.odt")
            .may_be_supported()
    );
    assert_eq!(
        Hints::new()
            .with_media_type_parts(
                "APPLICATION",
                "vnd.openxmlformats-officedocument.presentationml.presentation"
            )
            .format(),
        Some(Format::Pptx)
    );
    assert_eq!(
        Hints::new().with_media_type("text/rtf").format(),
        Some(Format::Rtf)
    );
    assert_eq!(
        Hints::new().with_file_name("book.epub").format(),
        Some(Format::Epub)
    );
}

#[test]
fn output_is_appended_and_capped() {
    let data = docx(
        "<w:p><w:r><w:t>0123456789</w:t></w:r></w:p><w:p><w:r><w:t>abcdefghij</w:t></w:r></w:p>",
    )
    .build();
    let mut extractor = Extractor::new(Limits {
        max_output_bytes: 15,
        ..Limits::default()
    });
    let mut out = String::from("existing ");
    let extraction = extractor
        .extract(&data, Hints::new(), &mut out)
        .unwrap_or_else(|err| panic!("{err:?}"));
    assert!(extraction.truncated);
    assert_eq!(extraction.bytes_written, 15);
    assert_eq!(out, "existing 0123456789\nabcd");

    extractor.limits_mut().max_output_bytes = usize::MAX;
    out.clear();
    let extraction = extractor
        .extract(&data, Hints::new(), &mut out)
        .unwrap_or_else(|err| panic!("{err:?}"));
    assert!(!extraction.truncated);
    assert_eq!(out, "0123456789\nabcdefghij");
    assert!(extraction.bytes_decompressed > 0);
}

#[test]
fn extractor_can_move_across_threads() {
    fn assert_send<T: Send + 'static>(_: &T) {}
    let extractor = Extractor::new(Limits::default());
    assert_send(&extractor);
    let handle = std::thread::spawn(move || {
        let mut extractor = extractor;
        let mut out = String::new();
        extractor
            .extract(
                &docx("<w:p><w:r><w:t>threaded</w:t></w:r></w:p>").build(),
                Hints::new(),
                &mut out,
            )
            .map(|_| out)
    });
    assert_eq!(
        handle.join().ok().and_then(Result::ok).as_deref(),
        Some("threaded")
    );
}
