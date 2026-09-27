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
        "First & Only Second plain rich 42.5 TRUE inline formula 2024-01-02 7"
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
    assert_eq!(
        run(b"%PDF-1.7 no objects at all").0,
        Err(Error::Unsupported)
    );
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
        Hints::new()
            .with_media_type("application/pdf")
            .may_be_supported()
    );
    for media_type in [
        "application/pdf",
        "application/x-pdf",
        "application/acrobat",
        "application/vnd.pdf",
        "text/pdf",
        "text/x-pdf; charset=binary",
    ] {
        assert_eq!(
            Hints::new().with_media_type(media_type).format(),
            Some(Format::Pdf),
            "{media_type}"
        );
    }
    assert_eq!(
        Hints::new().with_file_name("Scan.PDF").format(),
        Some(Format::Pdf)
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

fn relationships(entries: &[(&str, &str, &str)]) -> String {
    let body: String = entries
        .iter()
        .map(|(id, kind, target)| {
            let kind = if kind.starts_with("http") {
                (*kind).to_string()
            } else {
                format!("{REL_TYPE}/{kind}")
            };
            format!("<Relationship Id=\"{id}\" Type=\"{kind}\" Target=\"{target}\"/>")
        })
        .collect();
    format!("<Relationships {RELS_NS}>{body}</Relationships>")
}

fn root_rels(main: &str) -> String {
    relationships(&[("rId1", "officeDocument", main)])
}

const CHART_NS: &str = "xmlns:c=\"http://schemas.openxmlformats.org/drawingml/2006/chart\" xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:c15=\"c15\"";

fn chart(title: &str, series: &str, categories: &[&str], values: &[&str]) -> String {
    let points = |items: &[&str]| -> String {
        items
            .iter()
            .enumerate()
            .map(|(index, value)| format!("<c:pt idx=\"{index}\"><c:v>{value}</c:v></c:pt>"))
            .collect()
    };
    format!(
        "<c:chartSpace {CHART_NS}><c:date1904 val=\"0\"/><c:chart><c:title><c:tx><c:rich><a:bodyPr/><a:p><a:r><a:t>{title}</a:t></a:r></a:p></c:rich></c:tx></c:title>\
         <c:plotArea><c:barChart><c:ser><c:tx><c:strRef><c:f>Sheet1!$B$1</c:f><c:strCache><c:ptCount val=\"1\"/>{}</c:strCache></c:strRef></c:tx>\
         <c:cat><c:strRef><c:f>Sheet1!$A$2:$A$9</c:f><c:strCache>{}</c:strCache></c:strRef></c:cat>\
         <c:val><c:numRef><c:f>Sheet1!$B$2:$B$9</c:f><c:numCache><c:formatCode>General</c:formatCode>{}</c:numCache></c:numRef></c:val>\
         <c:extLst><c:ext><c15:filteredSeriesTitle><c15:tx><c:strRef><c:strCache><c:pt idx=\"0\"><c:v>hiddenext</c:v></c:pt></c:strCache></c:strRef></c15:tx></c15:filteredSeriesTitle></c:ext></c:extLst>\
         </c:ser></c:barChart></c:plotArea></c:chart></c:chartSpace>",
        points(&[series]),
        points(categories),
        points(values)
    )
}

#[test]
fn real_xlsx_comments_drawings_headers_and_formats() {
    let text = extracted(&fixture("real/48539.xlsx"), Format::Xlsx);
    assert_in_order(
        &text,
        &[
            "Basic Operators and Functions",
            "-2.3 8",
            "0.785398163397448 0.707106781186547",
            "Round to the nearest integer. If equidistant from two integers, then round to the nearest even integer.",
        ],
    );
    assert!(!text.contains("0.78539816339744828"), "{text}");

    let text = extracted(&fixture("real/testEXCEL_textbox.xlsx"), Format::Xlsx);
    assert!(text.contains("this is some autoshape text"), "{text}");

    let text = extracted(
        &fixture("real/testEXCEL_headers_footers.xlsx"),
        Format::Xlsx,
    );
    assert_in_order(
        &text,
        &[
            "John Smith1",
            "Header - Corporate Spreadsheet Header - For Internal Use Only Header - Author: John Smith",
            "Footer - Corporate Spreadsheet Footer - For Internal Use Only Footer - Author: John Smith",
        ],
    );
    assert!(!text.contains("&L") && !text.contains("&C"), "{text}");
}

#[test]
fn xlsx_comments_drawings_charts_headers_and_number_formats() {
    let data = ZipBuilder::new()
        .file("_rels/.rels", root_rels("xl/workbook.xml").as_bytes())
        .file(
            "xl/workbook.xml",
            b"<workbook xmlns:r=\"r\"><workbookPr date1904=\"1\"/><sheets><sheet name=\"Data\" r:id=\"rId1\"/><sheet name=\"Chart\" r:id=\"rId2\"/></sheets></workbook>",
        )
        .file(
            "xl/_rels/workbook.xml.rels",
            relationships(&[
                ("rId3", "styles", "styles.xml"),
                ("rId2", "chartsheet", "chartsheets/sheet1.xml"),
                ("rId1", "worksheet", "worksheets/sheet1.xml"),
            ])
            .as_bytes(),
        )
        .file(
            "xl/styles.xml",
            b"<styleSheet><numFmts count=\"2\"><numFmt numFmtId=\"164\" formatCode=\"yyyy\\-mm\\-dd\"/><numFmt numFmtId=\"165\" formatCode=\"&quot;$&quot;#,##0.00\"/></numFmts>\
              <cellStyleXfs><xf numFmtId=\"10\"/></cellStyleXfs>\
              <cellXfs><xf numFmtId=\"0\"/><xf numFmtId=\"164\"/><xf numFmtId=\"165\"/><xf numFmtId=\"10\"/><xf numFmtId=\"21\"/><xf numFmtId=\"22\"/></cellXfs>\
              <dxfs><dxf><numFmt numFmtId=\"166\" formatCode=\"0.0%\"/></dxf></dxfs></styleSheet>",
        )
        .file(
            "xl/worksheets/sheet1.xml",
            b"<worksheet><sheetData><row r=\"1\"><c r=\"A1\" s=\"1\"><v>43661</v></c><c r=\"B1\" s=\"2\"><v>1234.5</v></c><c r=\"C1\" s=\"3\"><v>0.1234</v></c>\
              <c r=\"D1\" s=\"4\"><v>0.75</v></c><c r=\"E1\" s=\"5\"><v>43661.5</v></c><c r=\"F1\"><v>0.30000000000000004</v></c><c r=\"G1\" t=\"b\"><v>0</v></c>\
              <c r=\"H1\" t=\"e\"><v>#N/A</v></c><c r=\"I1\" s=\"99\"><v>7.25</v></c></row></sheetData>\
              <headerFooter><oddHeader>&amp;L&amp;\"Arial,Bold\"&amp;14Quarterly &amp;&amp; Annual&amp;RPage &amp;P of &amp;N</oddHeader>\
              <oddFooter>&amp;C&amp;K00FF00Confidential&amp;\"-,Italic\"&amp;12 draft</oddFooter></headerFooter></worksheet>",
        )
        .file(
            "xl/worksheets/_rels/sheet1.xml.rels",
            relationships(&[
                ("rId1", "comments", "../comments1.xml"),
                ("rId2", "drawing", "../drawings/drawing1.xml"),
                ("rId3", "vmlDrawing", "../drawings/vmlDrawing1.vml"),
                (
                    "rId4",
                    "http://schemas.microsoft.com/office/2017/10/relationships/threadedComment",
                    "../threadedComments/threadedComment1.xml",
                ),
            ])
            .as_bytes(),
        )
        .file(
            "xl/comments1.xml",
            b"<comments><authors><author>Secret Author</author></authors><commentList><comment ref=\"A1\" authorId=\"0\"><text><r><t>Check this date</t></r></text></comment></commentList></comments>",
        )
        .file(
            "xl/drawings/vmlDrawing1.vml",
            b"<xml><v:shape><v:textbox><div>vmlnoise</div></v:textbox></v:shape></xml>",
        )
        .file(
            "xl/threadedComments/threadedComment1.xml",
            b"<ThreadedComments><threadedComment><text>threadedtext</text></threadedComment></ThreadedComments>",
        )
        .file(
            "xl/drawings/drawing1.xml",
            b"<xdr:wsDr xmlns:xdr=\"x\" xmlns:a=\"a\" xmlns:c=\"c\" xmlns:r=\"r\"><xdr:twoCellAnchor><xdr:sp><xdr:nvSpPr><xdr:cNvPr id=\"2\" name=\"TextBox 1\"/></xdr:nvSpPr><xdr:txBody><a:p><a:r><a:t>Shape note</a:t></a:r></a:p></xdr:txBody></xdr:sp></xdr:twoCellAnchor>\
              <xdr:twoCellAnchor><xdr:graphicFrame><a:graphic><a:graphicData><c:chart r:id=\"rId1\"/></a:graphicData></a:graphic></xdr:graphicFrame></xdr:twoCellAnchor></xdr:wsDr>",
        )
        .file(
            "xl/drawings/_rels/drawing1.xml.rels",
            relationships(&[("rId1", "chart", "../charts/chart1.xml")]).as_bytes(),
        )
        .file(
            "xl/charts/chart1.xml",
            chart("Revenue by region", "Sales", &["North", "South"], &["987654", "123"]).as_bytes(),
        )
        .file(
            "xl/chartsheets/sheet1.xml",
            b"<chartsheet xmlns:r=\"r\"><drawing r:id=\"rId1\"/></chartsheet>",
        )
        .file(
            "xl/chartsheets/_rels/sheet1.xml.rels",
            relationships(&[("rId1", "drawing", "../drawings/drawing2.xml")]).as_bytes(),
        )
        .file("xl/drawings/drawing2.xml", b"<xdr:wsDr xmlns:xdr=\"x\"/>")
        .file(
            "xl/drawings/_rels/drawing2.xml.rels",
            relationships(&[("rId1", "chart", "../charts/chart2.xml")]).as_bytes(),
        )
        .file(
            "xl/charts/chart2.xml",
            chart("Chartsheet title", "Units", &["East"], &["55"]).as_bytes(),
        )
        .build();
    assert_eq!(
        extracted(&data, Format::Xlsx),
        "Data Chart 2023-07-16 1234.50 12.34% 18:00:00 2023-07-16 12:00:00 0.3 FALSE 7.25 \
         Quarterly & Annual Page of Confidential draft Check this date Shape note \
         Revenue by region Sales threadedtext Chartsheet title Units"
    );
}

#[test]
fn real_pptx_charts_and_master_text() {
    let text = extracted(&fixture("real/testPPT_charts.pptx"), Format::Pptx);
    assert_eq!(
        text,
        "wants a peach NUMBER January February March April May June July August 5 8 4 7 4 2 5 6"
    );
    let text = extracted(&fixture("real/testPPT_masterText.pptx"), Format::Pptx);
    assert_eq!(text, "Text that I added to the master slide");
}

#[test]
fn pptx_charts_layouts_and_masters() {
    let shape = |placeholder: &str, text: &str| {
        format!(
            "<p:sp><p:nvSpPr><p:cNvPr id=\"2\" name=\"s\"/><p:nvPr>{placeholder}</p:nvPr></p:nvSpPr><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>"
        )
    };
    let part = |root: &str, shapes: &str| {
        format!(
            "<p:{root} xmlns:p=\"p\" xmlns:a=\"a\"><p:cSld><p:spTree>{shapes}</p:spTree></p:cSld></p:{root}>"
        )
    };
    let layout = part(
        "sldLayout",
        &format!(
            "{}{}<p:grpSp>{}{}</p:grpSp><p:pic><p:nvPicPr><p:nvPr><p:ph type=\"pic\"/></p:nvPr></p:nvPicPr></p:pic>{}",
            shape("<p:ph type=\"title\"/>", "Click to edit Master title style"),
            shape("", "Confidential notice"),
            shape("<p:ph type=\"dt\" idx=\"10\"/>", "9/24/2011"),
            shape("", "Grouped footer"),
            shape("", "Layout tail"),
        ),
    );
    let master = part(
        "sldMaster",
        &format!(
            "{}{}",
            shape(
                "<p:ph type=\"body\" idx=\"1\"/>",
                "Click to edit Master text styles"
            ),
            shape("", "Company logo text"),
        ),
    );
    let slide_rels = |index: usize| {
        let mut entries = vec![("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml")];
        if index == 1 {
            entries.push(("rId2", "chart", "../charts/chart1.xml"));
            entries.push(("rId3", "notesSlide", "../notesSlides/notesSlide1.xml"));
        }
        relationships(&entries)
    };
    let data = ZipBuilder::new()
        .file("_rels/.rels", root_rels("ppt/presentation.xml").as_bytes())
        .file(
            "ppt/presentation.xml",
            b"<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldMasterIdLst><p:sldMasterId r:id=\"rId1\"/></p:sldMasterIdLst><p:sldIdLst><p:sldId id=\"256\" r:id=\"rId2\"/><p:sldId id=\"257\" r:id=\"rId3\"/></p:sldIdLst></p:presentation>",
        )
        .file(
            "ppt/_rels/presentation.xml.rels",
            relationships(&[
                ("rId1", "slideMaster", "slideMasters/slideMaster1.xml"),
                ("rId3", "slide", "slides/slide2.xml"),
                ("rId2", "slide", "slides/slide1.xml"),
            ])
            .as_bytes(),
        )
        .file("ppt/slides/slide1.xml", part("sld", &shape("<p:ph type=\"title\"/>", "Body text")).as_bytes())
        .file("ppt/slides/_rels/slide1.xml.rels", slide_rels(1).as_bytes())
        .file("ppt/slides/slide2.xml", part("sld", &shape("", "Second slide")).as_bytes())
        .file("ppt/slides/_rels/slide2.xml.rels", slide_rels(2).as_bytes())
        .file(
            "ppt/charts/chart1.xml",
            chart("Units sold", "Units", &["Q1", "Q2"], &["3", "4.4000000000000004"]).as_bytes(),
        )
        .file("ppt/notesSlides/notesSlide1.xml", part("notes", &shape("", "Speaker notes")).as_bytes())
        .file("ppt/slideLayouts/slideLayout1.xml", layout.as_bytes())
        .file(
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels",
            relationships(&[("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")]).as_bytes(),
        )
        .file("ppt/slideMasters/slideMaster1.xml", master.as_bytes())
        .build();
    assert_eq!(
        extracted(&data, Format::Pptx),
        "Body text Units sold Units Q1 Q2 3 4.4 Speaker notes Confidential notice Grouped footer \
         Layout tail Company logo text Second slide"
    );
}

#[test]
fn docx_charts_ruby_symbols_and_math() {
    let body = "<w:p><w:r><w:t>Before</w:t></w:r><w:r><w:sym w:font=\"Wingdings\" w:char=\"F0E0\"/></w:r><w:r><w:t>after</w:t></w:r></w:p>\
                <w:p><w:r><w:ruby><w:rubyPr/><w:rt><w:r><w:t>kan</w:t></w:r></w:rt><w:rubyBase><w:r><w:t>\u{6f22}</w:t></w:r></w:rubyBase></w:ruby></w:r><w:r><w:t>\u{5b57}</w:t></w:r></w:p>\
                <w:p><m:oMath xmlns:m=\"m\"><m:f><m:num><m:r><m:t>a</m:t></m:r></m:num><m:den><m:r><m:t>b</m:t></m:r></m:den></m:f></m:oMath></w:p>";
    let chart_ex = "<cx:chartSpace xmlns:cx=\"cx\" xmlns:a=\"a\"><cx:chartData><cx:data id=\"0\"><cx:strDim type=\"cat\"><cx:f>Sheet1!$A$2</cx:f><cx:lvl ptCount=\"1\"><cx:pt idx=\"0\">Leaf</cx:pt></cx:lvl></cx:strDim>\
                    <cx:numDim type=\"size\"><cx:f>Sheet1!$B$2</cx:f><cx:lvl ptCount=\"1\" formatCode=\"General\"><cx:pt idx=\"0\">7.5</cx:pt></cx:lvl></cx:numDim></cx:data></cx:chartData>\
                    <cx:chart><cx:title><cx:tx><cx:txData><cx:v>Sunburst</cx:v></cx:txData></cx:tx></cx:title></cx:chart></cx:chartSpace>";
    let direct_name = "<c:chartSpace xmlns:c=\"c\"><c:chart><c:plotArea><c:lineChart><c:ser><c:tx><c:v>Direct name</c:v></c:tx><c:val><c:numLit><c:pt idx=\"0\"><c:v>12</c:v></c:pt></c:numLit></c:val></c:ser></c:lineChart></c:plotArea></c:chart></c:chartSpace>";
    let data = docx(body)
        .file(
            "word/_rels/document.xml.rels",
            relationships(&[
                ("rId7", "chart", "charts/chart1.xml"),
                ("rId8", "http://schemas.microsoft.com/office/2014/relationships/chartEx", "charts/chartEx1.xml"),
                ("rId9", "chart", "charts/chart2.xml"),
                ("rId10", "styles", "styles.xml"),
            ])
            .as_bytes(),
        )
        .file(
            "word/charts/chart1.xml",
            chart("Line chart", "Series 1", &["Q1"], &["4.4000000000000004"]).as_bytes(),
        )
        .file("word/charts/chartEx1.xml", chart_ex.as_bytes())
        .file("word/charts/chart2.xml", direct_name.as_bytes())
        .file("word/styles.xml", format!("<w:styles {W_NS}><w:style><w:name w:val=\"stylenoise\"/><w:t>stylenoise</w:t></w:style></w:styles>").as_bytes())
        .build();
    assert_eq!(
        extracted(&data, Format::Docx),
        "Before after kan \u{6f22}\u{5b57} a b Line chart Series 1 Q1 4.4 Leaf 7.5 Sunburst Direct name 12"
    );
}

#[test]
fn odf_chart_objects_ruby_and_master_pages() {
    let object = "<office:document-content xmlns:office=\"o\" xmlns:chart=\"c\" xmlns:table=\"ta\" xmlns:text=\"t\"><office:body><office:chart><chart:chart>\
                  <chart:title><text:p>Sales chart</text:p></chart:title><chart:plot-area><chart:axis><chart:title><text:p>Years</text:p></chart:title></chart:axis></chart:plot-area>\
                  <table:table table:name=\"local-table\"><table:table-row><table:table-cell><text:p>1984</text:p></table:table-cell><table:table-cell office:value-type=\"float\"><text:p>42</text:p></table:table-cell></table:table-row></table:table>\
                  </chart:chart></office:chart></office:body></office:document-content>";
    let mut builder =
        ZipBuilder::new().stored("mimetype", b"application/vnd.oasis.opendocument.text");
    for (name, contents) in zip_members_of(&odf(
        None,
        "<office:text><text:p>Body<draw:frame><draw:object xlink:href=\"./Object 1\"/></draw:frame></text:p>\
         <text:p><text:ruby><text:ruby-base>\u{6f22}</text:ruby-base><text:ruby-text>kan</text:ruby-text></text:ruby>\u{5b57}</text:p></office:text>",
        "<style:footer><text:p>Page <text:page-number>3</text:page-number></text:p></style:footer>",
    )) {
        builder = builder.file(&name, &contents);
    }
    let data = builder
        .file("Object 1/content.xml", object.as_bytes())
        .file("Object 1/styles.xml", b"<office:document-styles><office:master-styles><style:master-page><style:header><text:p>objectstyle</text:p></style:header></style:master-page></office:master-styles></office:document-styles>")
        .file("ObjectReplacements/Object 1", b"\x00\x01binary")
        .build();
    assert_eq!(
        extracted(&data, Format::Odt),
        "Body \u{6f22} kan \u{5b57} Page Sales chart Years 1984 42"
    );

    let data = odf(
        Some("application/vnd.oasis.opendocument.presentation"),
        "<office:presentation><draw:page><draw:frame><draw:text-box><text:p>Slide text</text:p></draw:text-box></draw:frame></draw:page></office:presentation>",
        "<draw:frame presentation:class=\"title\" presentation:placeholder=\"true\"><draw:text-box/></draw:frame>\
         <draw:frame presentation:class=\"footer\"><draw:text-box><text:p>Master footer</text:p></draw:text-box></draw:frame>\
         <draw:frame presentation:class=\"page-number\"><draw:text-box><text:p><text:page-number>&lt;number&gt;</text:page-number></text:p></draw:text-box></draw:frame>\
         </style:master-page><style:handout-master><draw:frame><draw:text-box><text:p>Handout header</text:p></draw:text-box></draw:frame></style:handout-master><style:master-page>",
    );
    assert_eq!(
        extracted(&data, Format::Odp),
        "Slide text Master footer Handout header"
    );
}

fn zip_members_of(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(data)).unwrap_or_else(|err| panic!("zip: {err}"));
    (0..archive.len())
        .map(|index| {
            let mut file = archive
                .by_index(index)
                .unwrap_or_else(|err| panic!("zip entry: {err}"));
            let mut contents = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut contents)
                .unwrap_or_else(|err| panic!("zip read: {err}"));
            (file.name().to_string(), contents)
        })
        .filter(|(name, _)| name != "mimetype")
        .collect()
}

#[test]
fn epub_details_summary_and_noscript_are_blocks() {
    let data = epub(
        "<package><manifest><item id=\"c1\" href=\"c1.xhtml\" media-type=\"application/xhtml+xml\"/></manifest><spine><itemref idref=\"c1\"/></spine></package>",
        &[(
            "OEBPS/content%20dir/c1.xhtml",
            "<html><body><p>Hello world</p><details><summary>Sum</summary>mary</details><noscript>No</noscript>script</body></html>",
        )],
    )
    .build();
    let (result, text) = run(&data);
    assert_eq!(result.map(|extraction| extraction.format), Ok(Format::Epub));
    assert_eq!(text, "Hello world\nSum\nmary\nNo\nscript");
}

#[test]
fn rtf_ignorable_destinations_annotations_and_html_tags() {
    assert_eq!(
        rtf(b"{\\rtf1 {\\field{\\*\\fldinst HYPERLINK x}{\\fldrslt \\*\\cs12 link text}} after {\\*\\unknown hidden}\r\n{\r\n\\*\\alsohidden gone}}"),
        "link text after "
    );
    let text = extracted(&fixture("real/testRTFIgnoredControlWord.rtf"), Format::Rtf);
    assert!(
        text.contains("The quick brown fox jumps over the lazy dog"),
        "{text}"
    );

    assert_eq!(
        words(&rtf(
            b"{\\rtf1 super{\\*\\annotation mid-word note}cali\\par}"
        )),
        "supercali mid-word note"
    );
    assert_eq!(
        words(&rtf(b"{\\rtf1 He heard quiet {\\*\\atrfstart 1}steps{\\*\\atrfend 1}{\\*\\atnid MM}{\\*\\atnauthor Max Mustermann}\\chatn {\\*\\annotation{\\*\\atnref 1}{\\*\\atndate 2}\\pard\\plain {Comment} {\\b text}} behind him.\\par Next {\\*\\annotation cell note}word\\cell after}")),
        "He heard quiet steps behind him. Comment text Next word cell note after"
    );

    assert_eq!(
        rtf(b"{\\rtf1\\ansi\\fromhtml1 {\\*\\htmltag0 <td>}A{\\*\\htmltag0 </td><TD class=x>}B{\\*\\htmltag0 <b>}C{\\*\\htmltag0 </b>}D{\\*\\htmltag84 &nbsp;}E{\\*\\htmltag0 <br>}F}"),
        "A BCD E\nF"
    );
    assert_eq!(rtf(b"{\\rtf1 {\\*\\htmltag0 <td>hidden}A}"), "A");
    let text = extracted(&fixture("real/testRTFTIKA_1713.rtf"), Format::Rtf);
    assert_in_order(&text, &["REDACTED.pptx (1.2 MB)", "REDACTED.docx (35 KB)"]);

    assert_eq!(
        words(&rtf(b"{\\rtf1 {\\*\\nesttableprops\\trowd\\nestrow}{\\nonesttables fallback text}inner\\nestcell outer\\cell}")),
        "inner outer"
    );
}

#[test]
fn default_part_limit_counts_content_parts_only() {
    assert_eq!(Limits::default().max_parts, 10_000);
    let slides = 1200;
    let ids: String = (0..slides)
        .map(|index| format!("<p:sldId id=\"{}\" r:id=\"rId{index}\"/>", 256 + index))
        .collect();
    let rels: Vec<(String, String)> = (0..slides)
        .map(|index| (format!("rId{index}"), format!("slides/slide{index}.xml")))
        .collect();
    let rel_refs: Vec<(&str, &str, &str)> = rels
        .iter()
        .map(|(id, target)| (id.as_str(), "slide", target.as_str()))
        .collect();
    let mut builder = ZipBuilder::new()
        .file("_rels/.rels", root_rels("ppt/presentation.xml").as_bytes())
        .file(
            "ppt/presentation.xml",
            format!("<p:presentation xmlns:p=\"p\" xmlns:r=\"r\"><p:sldIdLst>{ids}</p:sldIdLst></p:presentation>").as_bytes(),
        )
        .file("ppt/_rels/presentation.xml.rels", relationships(&rel_refs).as_bytes());
    for index in 0..slides {
        builder = builder
            .file(
                &format!("ppt/slides/slide{index}.xml"),
                format!("<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><a:p><a:r><a:t>slide{index}</a:t></a:r></a:p></p:sld>").as_bytes(),
            )
            .file(
                &format!("ppt/slides/_rels/slide{index}.xml.rels"),
                relationships(&[("rId1", "notesSlide", &format!("../notesSlides/notes{index}.xml"))]).as_bytes(),
            )
            .file(
                &format!("ppt/notesSlides/notes{index}.xml"),
                format!("<p:notes xmlns:p=\"p\" xmlns:a=\"a\"><a:p><a:r><a:t>notes{index}</a:t></a:r></a:p></p:notes>").as_bytes(),
            );
    }
    let text = extracted(&builder.build(), Format::Pptx);
    assert!(
        text.ends_with("slide1199 notes1199"),
        "{}",
        &text[text.len() - 64..]
    );
}

#[test]
fn output_capacity_is_clamped_to_the_limit() {
    let body: String = (0..5000)
        .map(|index| format!("<w:p><w:r><w:t>paragraph number {index}</w:t></w:r></w:p>"))
        .collect();
    let data = docx(&body).build();
    for limit in [1000, 50_000] {
        let mut extractor = Extractor::new(Limits {
            max_output_bytes: limit,
            ..Limits::default()
        });
        let mut out = String::from("prefix");
        let extraction = extractor
            .extract(&data, Hints::new(), &mut out)
            .unwrap_or_else(|err| panic!("{err:?}"));
        assert!(extraction.truncated);
        assert_eq!(out.len(), limit + 6);
        assert!(
            out.capacity() <= limit + 6,
            "{} > {}",
            out.capacity(),
            limit + 6
        );
    }
}

#[test]
fn chart_number_caches_use_their_format_codes() {
    let chart = format!(
        "<c:chartSpace {CHART_NS}><c:date1904 val=\"1\"/><c:chart><c:plotArea><c:lineChart><c:ser>\
         <c:cat><c:numRef><c:numCache><c:formatCode>m/d/yyyy</c:formatCode><c:pt idx=\"0\"><c:v>43661</c:v></c:pt></c:numCache></c:numRef></c:cat>\
         <c:val><c:numRef><c:numCache><c:formatCode>0.0%</c:formatCode><c:pt idx=\"0\"><c:v>0.79626390103711074</c:v></c:pt></c:numCache></c:numRef></c:val>\
         </c:ser><c:ser><c:val><c:numRef><c:numCache><c:pt idx=\"0\"><c:v>0.60000000000000009</c:v></c:pt></c:numCache></c:numRef></c:val></c:ser>\
         </c:lineChart></c:plotArea></c:chart></c:chartSpace>"
    );
    let chart_ex = "<cx:chartSpace xmlns:cx=\"cx\"><cx:chartData><cx:data id=\"0\"><cx:numDim type=\"val\"><cx:lvl ptCount=\"1\" formatCode=\"&quot;day &quot;0.00\"><cx:pt idx=\"0\">2.5</cx:pt></cx:lvl></cx:numDim></cx:data></cx:chartData></cx:chartSpace>";
    let data = docx("<w:p><w:r><w:t>Body</w:t></w:r></w:p>")
        .file(
            "word/_rels/document.xml.rels",
            relationships(&[
                ("rId1", "chart", "charts/chart1.xml"),
                (
                    "rId2",
                    "http://schemas.microsoft.com/office/2014/relationships/chartEx",
                    "charts/chartEx1.xml",
                ),
            ])
            .as_bytes(),
        )
        .file("word/charts/chart1.xml", chart.as_bytes())
        .file("word/charts/chartEx1.xml", chart_ex.as_bytes())
        .build();
    assert_eq!(
        extracted(&data, Format::Docx),
        "Body 2023-07-16 79.6% 0.6 2.50"
    );
}

fn styled_xlsx(styles: &str, cells: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    let mut builder = ZipBuilder::new()
        .file("_rels/.rels", root_rels("xl/workbook.xml").as_bytes())
        .file(
            "xl/workbook.xml",
            b"<workbook xmlns:r=\"r\"><sheets><sheet name=\"S\" r:id=\"rId1\"/></sheets></workbook>",
        )
        .file(
            "xl/_rels/workbook.xml.rels",
            relationships(&[
                ("rId1", "worksheet", "worksheets/sheet1.xml"),
                ("rId2", "styles", "styles.xml"),
            ])
            .as_bytes(),
        )
        .file("xl/styles.xml", styles.as_bytes())
        .file(
            "xl/worksheets/sheet1.xml",
            format!("<worksheet><sheetData>{cells}</sheetData></worksheet>").as_bytes(),
        );
    for (name, contents) in extra {
        builder = builder.file(name, contents.as_bytes());
    }
    builder.build()
}

#[test]
fn xlsx_values_split_across_scanner_windows() {
    let rows = 20_000;
    let cells: String = (1..=rows)
        .map(|row| {
            format!("<row r=\"{row}\"><c r=\"A{row}\" s=\"1\"><v>123456789012</v></c><c r=\"B{row}\" s=\"1\"><v>12&#51;.5</v></c></row>")
        })
        .collect();
    let data = styled_xlsx(
        "<styleSheet><cellXfs><xf numFmtId=\"0\"/><xf numFmtId=\"2\"/></cellXfs></styleSheet>",
        &cells,
        &[],
    );
    let text = extracted(&data, Format::Xlsx);
    assert_eq!(text.matches("123456789012.00").count(), rows);
    assert_eq!(text.matches("123.50").count(), rows);
    assert_eq!(text.split(' ').count(), 1 + 2 * rows);
}

#[test]
fn xlsx_threaded_comments_replace_their_legacy_mirror() {
    let sheet_rels = relationships(&[
        (
            "rId3",
            "http://schemas.microsoft.com/office/2017/10/relationships/threadedComment",
            "../threadedComments/threadedComment1.xml",
        ),
        ("rId2", "comments", "../comments1.xml"),
    ]);
    let data = styled_xlsx(
        "<styleSheet/>",
        "<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>cell</t></is></c></row>",
        &[
            ("xl/worksheets/_rels/sheet1.xml.rels", &sheet_rels),
            (
                "xl/threadedComments/threadedComment1.xml",
                "<ThreadedComments><threadedComment ref=\"A1\" id=\"{1}\"><text>Thread start</text></threadedComment><threadedComment ref=\"A1\" parentId=\"{1}\"><text>Thread reply</text></threadedComment></ThreadedComments>",
            ),
            (
                "xl/comments1.xml",
                "<comments><commentList><comment ref=\"A1\"><text><t>[Threaded comment]\n\nYour version of Excel allows you to read this threaded comment; however, any edits to it will get removed if the file is opened in a newer version of Excel.\n\nComment:\n    Thread start</t></text></comment><comment ref=\"B2\"><text><r><t>Plain note</t></r></text></comment></commentList></comments>",
            ),
        ],
    );
    assert_eq!(
        extracted(&data, Format::Xlsx),
        "S cell Thread start Thread reply Plain note"
    );
}

#[test]
fn chart_categories_are_emitted_once_per_chart() {
    let series = |name: &str, value: &str| {
        format!(
            "<c:ser><c:tx><c:strRef><c:strCache><c:pt idx=\"0\"><c:v>{name}</c:v></c:pt></c:strCache></c:strRef></c:tx>\
             <c:cat><c:strRef><c:strCache><c:pt idx=\"0\"><c:v>Alpha</c:v></c:pt><c:pt idx=\"1\"><c:v>Beta</c:v></c:pt></c:strCache></c:strRef></c:cat>\
             <c:val><c:numRef><c:numCache><c:pt idx=\"0\"><c:v>{value}</c:v></c:pt></c:numCache></c:numRef></c:val></c:ser>"
        )
    };
    let chart = format!(
        "<c:chartSpace {CHART_NS}><c:chart><c:plotArea><c:barChart>{}{}{}</c:barChart></c:plotArea></c:chart></c:chartSpace>",
        series("One", "1"),
        series("Two", "2"),
        series("Three", "3")
    );
    let data = docx("<w:p><w:r><w:t>Body</w:t></w:r></w:p>")
        .file(
            "word/_rels/document.xml.rels",
            relationships(&[("rId1", "chart", "charts/chart1.xml")]).as_bytes(),
        )
        .file("word/charts/chart1.xml", chart.as_bytes())
        .build();
    assert_eq!(
        extracted(&data, Format::Docx),
        "Body One Alpha Beta 1 Two 2 Three 3"
    );
}

#[test]
fn odp_master_prompt_frames_are_skipped() {
    let data = odf(
        Some("application/vnd.oasis.opendocument.presentation"),
        "<office:presentation><draw:page><draw:frame><draw:text-box><text:p>Slide</text:p></draw:text-box></draw:frame></draw:page></office:presentation>",
        "<draw:frame presentation:class=\"title\"><draw:text-box><text:p>Click to edit Master title style</text:p></draw:text-box></draw:frame>\
         <draw:frame presentation:class=\"outline\"><draw:text-box><text:p>Click to edit Master text styles</text:p></draw:text-box></draw:frame>\
         <draw:frame presentation:class=\"notes\" presentation:placeholder=\"true\"><draw:text-box><text:p>notes prompt</text:p></draw:text-box></draw:frame>\
         <draw:frame presentation:class=\"footer\"><draw:text-box><text:p>Company footer</text:p></draw:text-box></draw:frame>\
         <draw:frame><draw:text-box><text:p>Logo text</text:p></draw:text-box></draw:frame>",
    );
    assert_eq!(
        extracted(&data, Format::Odp),
        "Slide Company footer Logo text"
    );
}

#[test]
fn rtf_split_html_tags_and_nested_rows() {
    assert_eq!(
        rtf(b"{\\rtf1\\ansi\\fromhtml1 {\\*\\htmltag19 <body>}Hel{\\*\\htmltag84 <span\r\nstyle='font-size:11.0pt; color:red'>}lo{\\*\\htmltag92 </span>} wor{\\*\\htmltag84 <b title=\"a \\{x\\} b\">}ld{\\*\\htmltag92 </b>}}"),
        "Hello world"
    );
    assert_eq!(
        rtf(b"{\\rtf1 \\pard\\intbl\\itap2 A\\nestcell B\\nestcell{\\*\\nesttableprops\\trowd\\nestrow}{\\nonesttables fallback\\par}C\\nestcell D\\nestcell{\\*\\nesttableprops\\trowd\\nestrow}}"),
        "A B\nC D"
    );
}
