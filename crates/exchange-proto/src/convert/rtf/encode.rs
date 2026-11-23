/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::lzfu::{COMP_TYPE_MELA, HEADER_TAIL_LEN};
use crate::convert::ConvertError;
use std::io::Write;

const HTML_HEADER: &[u8] =
    b"{\\rtf1\\ansi\\ansicpg1252\\fromhtml1 \\deff0{\\fonttbl{\\f0\\fswiss Arial;}}\\uc1{\\*\\htmltag64}{\\*\\htmltag0 ";
const HTML_TRAILER: &[u8] = b"}}";
const TEXT_HEADER: &[u8] =
    b"{\\rtf1\\ansi\\ansicpg1252\\fromtext \\deff0{\\fonttbl{\\f0\\fswiss Arial;}}\\uc1\\f0 ";
const TEXT_TRAILER: &[u8] = b"}";
const ESCAPE_GROWTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtfSource<'a> {
    Html(&'a str),
    Text(&'a str),
}

pub fn rtf_encapsulate(source: RtfSource<'_>, out: &mut Vec<u8>) {
    let (header, body, trailer) = match source {
        RtfSource::Html(html) => (HTML_HEADER, html, HTML_TRAILER),
        RtfSource::Text(text) => (TEXT_HEADER, text, TEXT_TRAILER),
    };
    out.reserve(
        header
            .len()
            .saturating_add(body.len())
            .saturating_add(body.len() / ESCAPE_GROWTH)
            .saturating_add(trailer.len()),
    );
    out.extend_from_slice(header);
    escape(body, out);
    out.extend_from_slice(trailer);
}

fn escape(text: &str, out: &mut Vec<u8>) {
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match u8::try_from(ch) {
            Ok(byte @ (b'\\' | b'{' | b'}')) => {
                out.push(b'\\');
                out.push(byte);
            }
            Ok(b'\r') => {
                chars.next_if_eq(&'\n');
                out.extend_from_slice(b"\\par\r\n");
            }
            Ok(b'\n') => out.extend_from_slice(b"\\par\r\n"),
            Ok(b'\t') => out.extend_from_slice(b"\\tab "),
            Ok(byte @ b' '..=b'~') => out.push(byte),
            Ok(byte) if byte.is_ascii() => {}
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units).iter() {
                    let _ = write!(out, "\\u{}?", i16::from_ne_bytes(unit.to_ne_bytes()));
                }
            }
        }
    }
}

pub fn rtf_compress(rtf: &[u8], out: &mut Vec<u8>) -> Result<(), ConvertError> {
    let raw_size = u32::try_from(rtf.len()).map_err(|_| ConvertError::TooLarge)?;
    let comp_size = raw_size
        .checked_add(HEADER_TAIL_LEN)
        .ok_or(ConvertError::TooLarge)?;
    out.reserve(rtf.len().saturating_add(16));
    out.extend_from_slice(&comp_size.to_le_bytes());
    out.extend_from_slice(&raw_size.to_le_bytes());
    out.extend_from_slice(&COMP_TYPE_MELA.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(rtf);
    Ok(())
}
