/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::{base64, qp};
use mail_parser::{Encoding, MessagePart};
use std::borrow::Cow;

pub const SNIFF_WINDOW: usize = 64 * 1024;
const SNIFF_MIN: usize = 8 * 1024;
const OLE2_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ZIP_MAGIC: &[u8; 4] = b"PK\x03\x04";
const OOXML_SCAN: usize = 49 + 3 * (6000 + 4 + 26) + 26 + 8;
const ZSTD_SKIPPABLE: u32 = 0x184D_2A50;
const ZSTD_SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
const HTML_SIGNATURE_LEN: usize = b"<!DOCTYPE HTML".len() + 1;
const XML_SIGNATURE_LEN: usize = b"<?xml".len();

pub enum Sniffed<'m> {
    Prefix(Cow<'m, [u8]>),
    Whole(Cow<'m, [u8]>),
}

pub trait SniffPrefix<'m> {
    fn sniff(&self) -> Sniffed<'m>;

    fn sniff_prefix(&self) -> Cow<'m, [u8]> {
        match self.sniff() {
            Sniffed::Prefix(bytes) | Sniffed::Whole(bytes) => bytes,
        }
    }
}

impl<'m> SniffPrefix<'m> for MessagePart<'m> {
    fn sniff(&self) -> Sniffed<'m> {
        let Some((window, _)) = self
            .raw_body()
            .split_at_checked(SNIFF_WINDOW)
            .filter(|(_, rest)| !rest.is_empty())
        else {
            return Sniffed::Whole(self.decoded());
        };
        let prefix = match self.encoding() {
            Encoding::None => Cow::Borrowed(window),
            Encoding::Base64 => {
                let mut decoded = Vec::with_capacity(window.len() / 4 * 3 + 3);
                base64::MIME.decode_prefix(window, &mut decoded);
                Cow::Owned(decoded)
            }
            Encoding::QuotedPrintable => {
                let lines = window
                    .iter()
                    .rposition(|&byte| byte == b'\n')
                    .and_then(|end| window.get(..=end))
                    .unwrap_or_default();
                qp::BODY.decode(lines).unwrap_or(Cow::Borrowed(lines))
            }
        };
        if is_enough_to_sniff(&prefix) {
            Sniffed::Prefix(prefix)
        } else {
            Sniffed::Whole(self.decoded())
        }
    }
}

fn is_enough_to_sniff(prefix: &[u8]) -> bool {
    let Some(&[b0, b1, b2, b3, b4, b5, b6, b7]) = prefix.first_chunk::<8>() else {
        return false;
    };
    let magic = [b0, b1, b2, b3];
    if prefix.len() < SNIFF_MIN
        || prefix.starts_with(OLE2_MAGIC)
        || u32::from_le_bytes(magic) & ZSTD_SKIPPABLE_MASK == ZSTD_SKIPPABLE
        || ([b4, b5, b6, b7] == *b"ftyp" && u32::from_be_bytes(magic) as usize > prefix.len())
    {
        false
    } else if magic == *ZIP_MAGIC {
        prefix
            .get(18..22)
            .and_then(|size| size.try_into().ok())
            .is_some_and(|size: [u8; 4]| {
                (u32::from_le_bytes(size) as usize).saturating_add(OOXML_SCAN) < prefix.len()
            })
    } else {
        let text = trim_blanks(prefix);
        text.len() >= HTML_SIGNATURE_LEN && trim_byte_order_marks(text).len() >= XML_SIGNATURE_LEN
    }
}

fn trim_blanks(bytes: &[u8]) -> &[u8] {
    let blanks = bytes
        .iter()
        .take_while(|byte| matches!(byte, 0x09 | 0x0A | 0x0C | 0x0D | 0x20))
        .count();
    bytes.get(blanks..).unwrap_or_default()
}

fn trim_byte_order_marks(mut bytes: &[u8]) -> &[u8] {
    loop {
        bytes = match bytes {
            [0xEF, 0xBB, 0xBF, rest @ ..] => rest,
            [0xFE, 0xFF, _, ..] | [0xFF, 0xFE, _, ..] => bytes.get(2..).unwrap_or_default(),
            _ => return bytes,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{SNIFF_WINDOW, SniffPrefix};
    use crate::scripts::functions::image::ImageMetadata;
    use mail_parser::MessageParser;
    use std::borrow::Cow;

    fn samples() -> Vec<Vec<u8>> {
        let padding = |mut head: Vec<u8>, byte: u8| {
            head.resize(SNIFF_WINDOW * 3, byte);
            head
        };
        let mut docx = b"PK\x03\x04\x14\x00\x00\x00\x08\x00".to_vec();
        docx.resize(0x1E, 0);
        docx.extend_from_slice(b"word/document.xml");
        let mut ooxml = b"PK\x03\x04\x14\x00\x00\x00\x08\x00".to_vec();
        ooxml.resize(18, 0);
        ooxml.extend_from_slice(&(SNIFF_WINDOW as u32 * 2).to_le_bytes());
        ooxml.resize(0x1E, 0);
        ooxml.extend_from_slice(b"[Content_Types].xml");
        let mut ole2 = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        ole2.resize(512, 0);
        vec![
            padding(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec(), 0x41),
            padding(b"%PDF-1.7\n".to_vec(), b'x'),
            padding(vec![0xFF, 0xD8, 0xFF, 0xE0], 0x20),
            padding(vec![0x1F, 0x8B, 0x08, 0x00], 0x7F),
            padding(docx, 0),
            padding(ooxml, 0),
            padding(ole2, 0),
            padding(b"\x50\x2A\x4D\x18\x10\x00\x00\x00".to_vec(), 0),
            padding(Vec::new(), b' '),
            b"\x89PNG\r\n\x1a\n short".to_vec(),
        ]
    }

    fn message(body: &[u8], encoding: &str) -> Vec<u8> {
        let encoded = match encoding {
            "base64" => encodify::base64::MIME.encode(body).into_bytes(),
            "quoted-printable" => encodify::qp::BODY.encode(body).into_bytes(),
            _ => body.to_vec(),
        };
        let mut raw = format!(
            "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n"
        )
        .into_bytes();
        raw.extend_from_slice(&encoded);
        raw
    }

    #[test]
    fn sniffing_a_prefix_matches_the_whole_body() {
        for body in samples() {
            for encoding in ["base64", "quoted-printable", "binary"] {
                let raw = message(&body, encoding);
                let parsed = MessageParser::new().parse(&raw).expect("parses");
                let part = parsed.root_part();
                let prefix = part.sniff_prefix();
                assert_eq!(
                    infer::get(&prefix).map(|kind| kind.mime_type()),
                    infer::get(&part.decoded()).map(|kind| kind.mime_type()),
                    "{encoding} {:?}",
                    body.get(..8)
                );
                assert!(prefix.len() <= SNIFF_WINDOW || prefix.len() == body.len());
            }
        }
    }

    #[test]
    fn text_signatures_split_by_the_window_match_the_whole_body() {
        let mut cases = 0;
        for tag in [
            &b"<HTML>"[..],
            b"<?xml version",
            b"<B>",
            b"<!DOCTYPE HTML>",
            b"\xEF\xBB\xBF\xEF\xBB\xBF<?xml ",
        ] {
            for cut in 1..tag.len() {
                let mut body = vec![b' '; SNIFF_WINDOW - cut];
                body.extend_from_slice(tag);
                body.resize(body.len() + 4_096, b'x');
                for encoding in ["8bit", "base64", "quoted-printable"] {
                    let raw = message(&body, encoding);
                    let parsed = MessageParser::new().parse(&raw).expect("parses");
                    let part = parsed.root_part();
                    let whole = infer::get(&part.decoded()).map(|kind| kind.mime_type());
                    assert!(whole.is_some(), "{encoding} {tag:?} {cut}");
                    assert_eq!(
                        infer::get(&part.sniff_prefix()).map(|kind| kind.mime_type()),
                        whole,
                        "{encoding} {tag:?} cut {cut}"
                    );
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 3 * (5 + 12 + 2 + 14 + 11));
    }

    #[test]
    fn image_metadata_reads_trailing_footers() {
        let mut tga = vec![
            0u8, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0x10, 0, 24, 0,
        ];
        tga.resize(100_000, 0x55);
        tga.extend_from_slice(b"TRUEVISION-XFILE.\0");
        for encoding in ["8bit", "base64", "quoted-printable"] {
            let raw = message(&tga, encoding);
            let parsed = MessageParser::new().parse(&raw).expect("parses");
            let part = parsed.root_part();
            assert_eq!(
                imagesize::image_type(&part.decoded())
                    .ok()
                    .map(|kind| format!("{kind:?}")),
                Some("Tga".to_string()),
                "{encoding}"
            );
            assert_eq!(
                part.image_metadata("type")
                    .map(|kind| kind.to_string().into_owned()),
                Some("tga".to_string()),
                "{encoding}"
            );
            assert_eq!(
                part.image_metadata("width")
                    .map(|width| width.to_string().into_owned()),
                Some("16".to_string()),
                "{encoding}"
            );
        }
    }

    #[test]
    fn large_bodies_are_not_decoded_whole() {
        let body = samples().swap_remove(0);
        for encoding in ["base64", "quoted-printable", "binary"] {
            let raw = message(&body, encoding);
            let parsed = MessageParser::new().parse(&raw).expect("parses");
            let part = parsed.root_part();
            let prefix = part.sniff_prefix();
            let whole = part.decoded();
            assert!(prefix.len() < whole.len() / 2, "{encoding}");
            assert_eq!(prefix.get(..1024), whole.get(..1024), "{encoding}");
            if encoding == "binary" {
                assert!(matches!(prefix, Cow::Borrowed(_)));
            }
        }
    }
}
