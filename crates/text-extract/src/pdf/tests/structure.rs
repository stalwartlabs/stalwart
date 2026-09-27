/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    budget,
    builder::{Document as Synthetic, HEADER, Pdf},
    pages, walk, walk_with,
};
use crate::{
    Limits,
    pdf::{
        decode::DecodeOutcome,
        document::{DocScratch, Document, OpenError},
        lexer::Lexer,
        object::{ObjRef, Object},
        pages::{Pages, Visited},
        text_string::decode_text_string,
    },
};
use std::{
    path::Path,
    time::{Duration, Instant},
};

#[test]
fn classic_and_stream_cross_references() {
    for (compress, object_streams, xref_stream) in [
        (false, false, false),
        (true, false, false),
        (false, false, true),
        (true, true, true),
        (false, true, true),
    ] {
        let mut synthetic = Synthetic::new(&pages());
        synthetic.compress = compress;
        synthetic.object_streams = object_streams;
        synthetic.xref_stream = xref_stream;
        let result = walk(&synthetic.build());
        assert_eq!(result.pages, 3, "{compress} {object_streams} {xref_stream}");
        assert!(
            !result.repaired,
            "{compress} {object_streams} {xref_stream}"
        );
        assert_eq!(result.contents, pages().map(<[u8]>::to_vec).to_vec());
        assert_eq!(result.failures, 0);
        if !compress && !xref_stream {
            assert_eq!(result.decoded, Synthetic::new(&pages()).content_bytes());
        }
    }
}

#[test]
fn header_offset_both_conventions() {
    let clean = Synthetic::new(&pages()).build();
    let mut relative = b"From: mail gateway\r\n\r\n".to_vec();
    relative.extend_from_slice(&clean);
    let result = walk(&relative);
    assert_eq!((result.pages, result.repaired), (3, false));

    let mut absolute = Pdf::with_prefix(b"junk before header\n");
    absolute
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
        .stream(4, "", b"BT (x) Tj ET")
        .xref_table("/Root 1 0 R");
    let result = walk(&absolute.build());
    assert_eq!((result.pages, result.repaired), (1, false));
}

#[test]
fn damaged_cross_references_are_repaired() {
    let clean = Synthetic::new(&pages()).build();
    let mut shifted = clean.clone();
    let insert_at = shifted
        .windows(7)
        .position(|window| window == b"2 0 obj")
        .unwrap_or_default();
    shifted.splice(insert_at..insert_at, b"% padding comment\n".iter().copied());
    let result = walk(&shifted);
    assert_eq!(result.pages, 3);
    assert!(result.repaired);

    let truncated_xref: Vec<u8> = {
        let cut = clean
            .windows(4)
            .rposition(|window| window == b"xref")
            .unwrap_or(clean.len());
        clean.get(..cut).unwrap_or_default().to_vec()
    };
    let result = walk(&truncated_xref);
    assert_eq!((result.pages, result.repaired), (3, true));

    let startxref_at = clean
        .windows(10)
        .rposition(|window| window == b"startxref\n")
        .unwrap_or_default();
    let mut wrong_startxref = clean.clone();
    wrong_startxref.truncate(startxref_at);
    wrong_startxref.extend_from_slice(b"startxref\n99999\n%%EOF\n");
    let result = walk(&wrong_startxref);
    assert_eq!(result.pages, 3);

    let mut near = clean.clone();
    let xref_at = clean
        .windows(6)
        .rposition(|window| window == b"\nxref\n")
        .unwrap_or_default()
        + 1;
    near.truncate(startxref_at);
    near.extend_from_slice(format!("startxref\n{}\n%%EOF\n", xref_at + 20).as_bytes());
    let result = walk(&near);
    assert_eq!((result.pages, result.repaired), (3, false));
}

#[test]
fn stream_lengths_are_verified() {
    let content = b"BT (length check) Tj ET";
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(
            2,
            "<< /Type /Pages /Kids [3 0 R 5 0 R 7 0 R 9 0 R] /Count 4 >>",
        )
        .object(3, "<< /Type /Page /Contents 4 0 R >>")
        .stream_with_length(4, "", content, "5")
        .object(5, "<< /Type /Page /Contents 6 0 R >>")
        .stream_with_length(6, "", content, "11 0 R")
        .object(7, "<< /Type /Page /Contents 8 0 R >>")
        .stream_with_length(8, "", content, "8 0 R")
        .object(9, "<< /Type /Page /Contents 10 0 R >>")
        .stream_with_length(10, "", content, "999999")
        .object(11, &content.len().to_string())
        .xref_table("/Root 1 0 R");
    let result = walk(&pdf.build());
    assert_eq!(result.pages, 4);
    assert!(
        result.contents.iter().all(|page| page == content),
        "{result:?}"
    );
}

#[test]
fn incremental_updates_and_hybrid_files() {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(3, "<< /Type /Page /Contents 4 0 R >>")
        .stream(4, "", b"old content")
        .xref_table("/Root 1 0 R")
        .stream(4, "", b"new content")
        .xref_table("/Root 1 0 R");
    let result = walk(&pdf.build());
    assert_eq!(result.contents, vec![b"new content".to_vec()]);

    let mut hybrid = Pdf::new();
    hybrid
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object_stream(10, &[(3, "<< /Type /Page /Contents 4 0 R >>")], true)
        .stream(4, "", b"hybrid");
    hybrid.xref_stream(11, "");
    let stream_offset = hybrid
        .data
        .windows(6)
        .rposition(|window| window == b"11 0 o")
        .unwrap_or_default();
    let mut classic = hybrid.build();
    classic.extend_from_slice(
        format!(
            "xref\n0 3\n0000000000 65535 f\r\n{:010} 00000 n\r\n{:010} 00000 n\r\ntrailer\n<< /Size 12 /Root 1 0 R /XRefStm {stream_offset} >>\nstartxref\n{}\n%%EOF\n",
            HEADER_LEN,
            classic
                .windows(7)
                .position(|window| window == b"2 0 obj")
                .unwrap_or_default(),
            classic.len()
        )
        .as_bytes(),
    );
    let result = walk(&classic);
    assert_eq!(result.contents, vec![b"hybrid".to_vec()]);
    assert!(!result.repaired);
}

const HEADER_LEN: usize = HEADER.len();

#[test]
fn first_subsection_off_by_one() {
    let clean = Synthetic::new(&pages()).build();
    let mut fixed = clean.clone();
    let at = clean
        .windows(7)
        .position(|window| window == b"\nxref\n0")
        .unwrap_or_default();
    if let Some(digit) = fixed.get_mut(at + 6) {
        *digit = b'1';
    }
    let result = walk(&fixed);
    assert_eq!((result.pages, result.repaired), (3, false));
}

#[test]
fn broken_page_trees_fall_back_to_scanned_pages() {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [2 0 R 3 0 R 3 0 R] /Count 3 >>")
        .object(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
        .stream(4, "", b"only once")
        .xref_table("/Root 1 0 R");
    let result = walk(&pdf.build());
    assert_eq!(result.pages, 1);

    let mut orphaned = Pdf::new();
    orphaned
        .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids 9 0 R /Count 2 >>")
        .object(3, "<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>")
        .object(4, "<< /Type /Page /Parent 2 0 R /Contents 6 0 R >>")
        .stream(5, "", b"orphan one")
        .stream(6, "", b"orphan two")
        .xref_table("/Root 1 0 R");
    let result = walk(&orphaned.build());
    assert_eq!(
        result.contents,
        vec![b"orphan one".to_vec(), b"orphan two".to_vec()]
    );

    let mut rootless = Pdf::new();
    rootless
        .object(
            2,
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << >> >> >>",
        )
        .object(3, "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>")
        .stream(4, "", b"rootless")
        .xref_table("");
    let result = walk(&rootless.build());
    assert_eq!(result.contents, vec![b"rootless".to_vec()]);

    let direct_root = b"%PDF-1.\n1 0 obj\n<</Kids[<</Parent 1 0 R/Contents[2 0 R]>>]/Resources<<>>>>\n2 0 obj\n<<>>\nstream\nBT (direct) Tj ET\nendstream\nendobj\ntrailer<</Root<</Pages 1 0 R>>>>";
    let result = walk(direct_root);
    assert_eq!(result.contents, vec![b"BT (direct) Tj ET".to_vec()]);

    let mut nothing = Pdf::new();
    nothing.object(1, "<< /Foo 1 >>").xref_table("");
    assert_eq!(
        walk_with(&nothing.build(), &Limits::default()),
        Err(OpenError::Unusable)
    );
}

#[test]
fn inherited_attributes_and_contents_arrays() {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Rotate 90 /Resources << /Font << /F1 9 0 R >> >> >>")
        .object(3, "<< /Type /Page /Parent 2 0 R /Contents [4 0 R 4 0 R 5 0 R] >>")
        .stream(4, "", b"part")
        .flate_stream(5, "", b"tail")
        .xref_table("/Root 1 0 R");
    let data = pdf.build();
    let mut scratch = DocScratch::default();
    let mut visited = Visited::default();
    let document = Document::open(&data, &mut scratch, budget(&Limits::default()), 1 << 20)
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    let page = Pages::new(&document, &mut visited)
        .next()
        .unwrap_or_else(|| panic!("page"));
    assert_eq!(page.rotate, 90);
    let fonts = page
        .resources
        .and_then(|resources| document.get_dict(resources, b"Font"));
    assert!(fonts.is_some_and(|fonts| fonts.get(b"F1").is_some()));
    let mut contents = Vec::new();
    let (data, outcome) = page.contents(&document, &mut contents);
    assert_eq!(data, b"part\npart\ntail");
    assert_eq!(outcome.streams, 3);
}

#[test]
fn encrypted_documents_decrypt_strings_and_streams() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdf/crypt");
    for name in [
        "r2_rc4_40.pdf",
        "r3_rc4_128.pdf",
        "r3_empty_owner.pdf",
        "r4_rc4_128.pdf",
        "r4_aes_128.pdf",
        "r4_aes_128_nometa.pdf",
        "r5_aes_256.pdf",
        "r6_aes_256.pdf",
        "r6_empty_owner.pdf",
    ] {
        let data = std::fs::read(dir.join(name)).unwrap_or_else(|err| panic!("{name}: {err}"));
        let result = walk(&data);
        assert_eq!(result.pages, 1, "{name}");
        let text = String::from_utf8_lossy(result.contents.first().map_or(&[][..], Vec::as_slice))
            .into_owned();
        assert!(text.contains("Encrypted stream text"), "{name}: {text}");

        let mut scratch = DocScratch::default();
        let document = Document::open(&data, &mut scratch, budget(&Limits::default()), 1 << 20)
            .unwrap_or_else(|failure| panic!("{name}: {failure:?}"));
        let title = (1..16)
            .filter_map(|num| {
                document
                    .get(ObjRef { num, generation: 0 })
                    .as_dict()?
                    .get(b"Title")?
                    .as_str()
            })
            .next()
            .unwrap_or_else(|| panic!("{name}: title"));
        let mut decoded = String::new();
        decode_text_string(&document.string(title), &mut decoded);
        assert_eq!(decoded, "Hello, encrypted world", "{name}");
    }
    for name in ["r3_user_pw.pdf", "r6_user_pw.pdf"] {
        let data = std::fs::read(dir.join(name)).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(
            walk_with(&data, &Limits::default()),
            Err(OpenError::Encrypted),
            "{name}"
        );
    }
}

#[test]
fn decode_outcomes_and_budget() {
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R 5 0 R 7 0 R] /Count 3 >>")
        .object(3, "<< /Type /Page /Contents 4 0 R >>")
        .stream(4, "/Filter /DCTDecode", b"\xFF\xD8image")
        .object(5, "<< /Type /Page /Contents 6 0 R >>")
        .stream(6, "/Filter /NoSuchFilter", b"data")
        .object(7, "<< /Type /Page /Contents 8 0 R >>")
        .flate_stream(8, "", &[b'x'; 10_000])
        .xref_table("/Root 1 0 R");
    let data = pdf.build();
    let result = walk(&data);
    assert_eq!(result.contents.first().map(Vec::len), Some(0));
    assert_eq!(result.contents.get(1).map(Vec::len), Some(0));
    assert_eq!(result.failures, 1);
    assert_eq!(result.decoded, 10_000);

    let limits = Limits {
        max_part_bytes: 1000,
        ..Limits::default()
    };
    let result = walk_with(&data, &limits).unwrap_or_default();
    assert_eq!(result.contents.get(2).map(Vec::len), Some(1000));

    let mut scratch = DocScratch::default();
    let document = Document::open(&data, &mut scratch, budget(&limits), 1 << 20)
        .unwrap_or_else(|failure| panic!("{failure:?}"));
    let stream = document
        .get(ObjRef {
            num: 8,
            generation: 0,
        })
        .as_stream()
        .unwrap_or_else(|| panic!("stream"));
    let mut out = Vec::new();
    assert_eq!(
        document.decode_stream(stream, &mut out),
        DecodeOutcome::Truncated
    );
    assert!(document.truncated());
}

#[test]
fn hostile_structures_stay_bounded() {
    let deep = |levels: usize| -> String {
        (0..levels)
            .map(|level| if level % 2 == 0 { "[" } else { "<<" })
            .collect()
    };
    let nested = deep(1_000_000);
    let mut pdf = Pdf::new();
    pdf.object(1, "<< /Type /Catalog /Pages 2 0 R >>")
        .object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        .object(
            3,
            &format!("<< /Type /Page /Contents 4 0 R /Deep {nested} >>"),
        )
        .stream(4, "", nested.as_bytes())
        .object_stream(10, &[(20, &nested)], true)
        .xref_table(&format!("/Root 1 0 R /Deep {nested}"));
    let data = pdf.build();
    let handle = std::thread::Builder::new()
        .stack_size(256 << 10)
        .spawn(move || {
            let started = Instant::now();
            let result = walk(&data);
            let mut scratch = DocScratch::default();
            let document = Document::open(&data, &mut scratch, budget(&Limits::default()), 1 << 20)
                .unwrap_or_else(|failure| panic!("{failure:?}"));
            let member = document.get(ObjRef {
                num: 20,
                generation: 0,
            });
            let mut lexer = Lexer::new(nested.as_bytes());
            let operand = Object::read(&mut lexer, None);
            (
                result.pages,
                member.as_array().is_some(),
                operand.is_some(),
                started.elapsed(),
            )
        })
        .unwrap_or_else(|err| panic!("spawn: {err}"));
    let (pages, member, operand, elapsed) = handle.join().unwrap_or_else(|_| panic!("stack"));
    assert_eq!(pages, 1);
    assert!(member && operand);
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[test]
fn many_pages_in_object_streams() {
    let content: Vec<Vec<u8>> = (0..2000)
        .map(|page| format!("BT ({page}) Tj ET").into_bytes())
        .collect();
    let refs: Vec<&[u8]> = content.iter().map(Vec::as_slice).collect();
    let mut synthetic = Synthetic::new(&refs);
    synthetic.compress = true;
    synthetic.object_streams = true;
    synthetic.xref_stream = true;
    let result = walk_with(&synthetic.build(), &Limits::default());
    let result = result.unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!((result.pages, result.repaired), (2000, false));
}
