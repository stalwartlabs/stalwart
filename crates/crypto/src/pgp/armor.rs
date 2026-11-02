/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use encodify::base64::STANDARD;
use memchr::memmem;

use crate::{backend::crc24::crc24, error::KeyError};

pub(crate) const BEGIN_MESSAGE: &[u8] = b"-----BEGIN PGP MESSAGE-----\r\n\r\n";
pub(crate) const END_MESSAGE: &[u8] = b"-----END PGP MESSAGE-----\r\n";
pub(crate) const CHECKSUM_LINE_LEN: usize = 7;
const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArmorLabel {
    PublicKey,
    PrivateKey,
    Message,
    Signature,
    Other,
}

impl ArmorLabel {
    fn parse(label: &[u8]) -> Self {
        hashify::map!(
            label,
            ArmorLabel,
            "PGP PUBLIC KEY BLOCK" => ArmorLabel::PublicKey,
            "PGP PRIVATE KEY BLOCK" => ArmorLabel::PrivateKey,
            "PGP SECRET KEY BLOCK" => ArmorLabel::PrivateKey,
            "PGP MESSAGE" => ArmorLabel::Message,
            "PGP SIGNATURE" => ArmorLabel::Signature,
        )
        .copied()
        .unwrap_or(ArmorLabel::Other)
    }
}

pub(crate) struct ArmorBlock<'x> {
    pub label: ArmorLabel,
    pub raw_label: &'x [u8],
    pub body: &'x [u8],
}

pub(crate) fn checksum_line(data: &[u8]) -> [u8; CHECKSUM_LINE_LEN] {
    let [_, b0, b1, b2] = crc24(data).to_be_bytes();
    let mut line = *b"=XXXX\r\n";
    let _ = STANDARD.encode_slice([b0, b1, b2], &mut line[1..5]);
    line
}

pub(crate) fn split_line(data: &[u8]) -> (&[u8], &[u8]) {
    match memchr::memchr(b'\n', data) {
        Some(pos) => {
            let (line, rest) = data.split_at(pos);
            (line.strip_suffix(b"\r").unwrap_or(line), &rest[1..])
        }
        None => (data.strip_suffix(b"\r").unwrap_or(data), &[]),
    }
}

pub(crate) fn next_block(data: &[u8]) -> Result<Option<(ArmorBlock<'_>, &[u8])>, KeyError> {
    let data = data.trim_ascii_start();
    if data.is_empty() {
        return Ok(None);
    }
    let (line, rest) = split_line(data);
    let label = line
        .trim_ascii_end()
        .strip_prefix(BEGIN)
        .and_then(|l| l.strip_suffix(DASHES))
        .ok_or(KeyError::MalformedArmor)?;
    let finder = memmem::Finder::new(END);
    let end = finder.find(rest).ok_or(KeyError::MalformedArmor)?;
    let (body, tail) = rest.split_at(end);
    let (end_line, after) = split_line(tail);
    let end_label = end_line
        .trim_ascii_end()
        .strip_prefix(END)
        .and_then(|l| l.strip_suffix(DASHES))
        .ok_or(KeyError::MalformedArmor)?;
    if end_label != label {
        return Err(KeyError::MalformedArmor);
    }
    Ok(Some((
        ArmorBlock {
            label: ArmorLabel::parse(label),
            raw_label: label,
            body,
        },
        after,
    )))
}

pub(crate) fn decode_body(body: &[u8], out: &mut Vec<u8>) -> Result<(), KeyError> {
    let mut rest = body;
    let mut in_headers = true;
    let mut text = Vec::with_capacity(body.len());
    while !rest.is_empty() {
        let (line, next) = split_line(rest);
        rest = next;
        let line = line.trim_ascii();
        if in_headers {
            if line.is_empty() {
                in_headers = false;
                continue;
            }
            if memchr::memchr(b':', line).is_some() {
                continue;
            }
            in_headers = false;
        }
        if line.first() == Some(&b'=') && line.len() == 5 {
            break;
        }
        text.extend_from_slice(line);
    }
    STANDARD
        .decode_append(&text, out)
        .map(drop)
        .map_err(|_| KeyError::MalformedArmor)
}

pub(crate) fn is_armored(input: &[u8]) -> bool {
    input.trim_ascii_start().starts_with(BEGIN)
}

pub(crate) fn dearmor_public_keys(input: &[u8]) -> Result<Cow<'_, [u8]>, KeyError> {
    if !is_armored(input) {
        return Ok(Cow::Borrowed(input));
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut rest = input;
    while let Some((block, next)) = next_block(rest)? {
        match block.label {
            ArmorLabel::PublicKey => decode_body(block.body, &mut out)?,
            ArmorLabel::PrivateKey => return Err(KeyError::SecretKey),
            ArmorLabel::Other if block.raw_label.ends_with(b"CERTIFICATE") => {
                return Err(KeyError::MixedKeyKinds);
            }
            _ => return Err(KeyError::MalformedArmor),
        }
        rest = next;
    }
    Ok(Cow::Owned(out))
}
