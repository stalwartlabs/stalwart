/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::der::{oid, reader::Reader, tag};
use encodify::base64::LENIENT;
use mail_parser::{Message, MessagePart};
use memchr::memmem;

const PGP_MESSAGE: &[u8] = b"-----BEGIN PGP MESSAGE-----";
const PGP_MESSAGE_END: &[u8] = b"-----END PGP MESSAGE-----";
const TAG_PKESK: u8 = 1;
const TAG_SKESK: u8 = 3;
const PGP_ENCRYPTED_PART: u32 = 2;
const PGP_MIME_PARTS: usize = 3;
const MAX_INLINE_PARTS: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protection {
    None,
    Signed,
    Encrypted,
}

#[derive(Clone, Copy)]
enum MediaType {
    MultipartEncrypted,
    MultipartSigned,
    Pkcs7Mime,
    PgpEncrypted,
    OctetStream,
    Text,
}

#[derive(Clone, Copy)]
enum SmimeType {
    Enveloped,
    Signed,
    Other,
}

fn media_type(main: &str, sub: &str) -> Option<MediaType> {
    if main.eq_ignore_ascii_case("text") {
        return Some(MediaType::Text);
    }
    if main.eq_ignore_ascii_case("multipart") {
        return hashify::map_ignore_case!(
            sub.as_bytes(),
            MediaType,
            "encrypted" => MediaType::MultipartEncrypted,
            "signed" => MediaType::MultipartSigned,
        )
        .copied();
    }
    if main.eq_ignore_ascii_case("application") {
        return hashify::map_ignore_case!(
            sub.as_bytes(),
            MediaType,
            "pkcs7-mime" => MediaType::Pkcs7Mime,
            "x-pkcs7-mime" => MediaType::Pkcs7Mime,
            "pgp-encrypted" => MediaType::PgpEncrypted,
            "octet-stream" => MediaType::OctetStream,
        )
        .copied();
    }
    None
}

fn smime_type(value: &str) -> SmimeType {
    hashify::map_ignore_case!(
        value.as_bytes(),
        SmimeType,
        "enveloped-data" => SmimeType::Enveloped,
        "authenveloped-data" => SmimeType::Enveloped,
        "signed-data" => SmimeType::Signed,
    )
    .copied()
    .unwrap_or(SmimeType::Other)
}

fn has_p7m_name(part: &MessagePart<'_>) -> bool {
    let ends_p7m = |name: &str| {
        name.len() > 4
            && name
                .get(name.len() - 4..)
                .is_some_and(|ext| ext.eq_ignore_ascii_case(".p7m"))
    };
    part.content_type()
        .and_then(|ct| ct.attribute("name"))
        .is_some_and(ends_p7m)
        || part
            .content_disposition()
            .and_then(|cd| cd.attribute("filename"))
            .is_some_and(ends_p7m)
}

fn starts_with_pgp_message(part: &MessagePart<'_>) -> bool {
    part.raw_body().trim_ascii_start().starts_with(PGP_MESSAGE)
}

pub fn protection(message: &Message<'_>) -> Protection {
    let root = message.root_part();
    let Some(ct) = root.content_type() else {
        return inline_protection(message);
    };
    match media_type(ct.ctype(), ct.subtype().unwrap_or_default()) {
        Some(MediaType::MultipartEncrypted) => {
            if ct
                .attribute("protocol")
                .is_some_and(|p| p.eq_ignore_ascii_case("application/pgp-encrypted"))
            {
                Protection::Encrypted
            } else {
                Protection::None
            }
        }
        Some(MediaType::MultipartSigned) => Protection::Signed,
        Some(MediaType::Pkcs7Mime) => match ct.attribute("smime-type").map(smime_type) {
            Some(SmimeType::Enveloped) => Protection::Encrypted,
            Some(SmimeType::Signed) => Protection::Signed,
            Some(SmimeType::Other) => Protection::None,
            None if has_p7m_name(&root) => Protection::Encrypted,
            None => Protection::None,
        },
        Some(MediaType::PgpEncrypted) => Protection::Encrypted,
        Some(MediaType::OctetStream) if has_p7m_name(&root) => Protection::Encrypted,
        _ => inline_protection(message),
    }
}

pub fn is_encrypted_media(main: &str, sub: &str, smime: Option<&str>) -> bool {
    match media_type(main, sub) {
        Some(MediaType::MultipartEncrypted | MediaType::PgpEncrypted) => true,
        Some(MediaType::Pkcs7Mime) => {
            matches!(smime.map(smime_type), Some(SmimeType::Enveloped))
        }
        _ => false,
    }
}

pub fn is_ciphertext(message: &Message<'_>) -> bool {
    let root = message.root_part();
    let Some(ct) = root.content_type() else {
        return inline_ciphertext(message);
    };
    match media_type(ct.ctype(), ct.subtype().unwrap_or_default()) {
        Some(MediaType::MultipartEncrypted) => {
            message.parts().len() == PGP_MIME_PARTS
                && message
                    .part(PGP_ENCRYPTED_PART)
                    .is_some_and(|part| armored_ciphertext(&part.decoded()))
        }
        Some(MediaType::Pkcs7Mime) => cms_ciphertext(&root.decoded()),
        Some(MediaType::OctetStream) if has_p7m_name(&root) => cms_ciphertext(&root.decoded()),
        Some(MediaType::PgpEncrypted) => armored_ciphertext(&root.decoded()),
        _ => inline_ciphertext(message),
    }
}

fn inline_ciphertext(message: &Message<'_>) -> bool {
    let mut found = false;
    for part in message.parts() {
        match part.content_type() {
            Some(ct) if ct.ctype().eq_ignore_ascii_case("multipart") => {}
            Some(ct)
                if !matches!(
                    media_type(ct.ctype(), ct.subtype().unwrap_or_default()),
                    Some(MediaType::Text)
                ) =>
            {
                return false;
            }
            _ if armored_ciphertext(&part.decoded()) => found = true,
            _ => return false,
        }
    }
    found
}

fn armored_ciphertext(body: &[u8]) -> bool {
    let Some(armor) = body
        .trim_ascii()
        .strip_prefix(PGP_MESSAGE)
        .and_then(|armor| armor.strip_suffix(PGP_MESSAGE_END))
    else {
        return false;
    };
    if memmem::find(armor, b"-----").is_some() {
        return false;
    }
    armor
        .split(|&ch| ch == b'\n')
        .map(<[u8]>::trim_ascii)
        .skip(1)
        .skip_while(|line| !line.is_empty())
        .find(|line| !line.is_empty())
        .and_then(|line| LENIENT.decode(line).ok())
        .and_then(|data| data.first().copied())
        .is_some_and(is_encrypted_packet)
}

fn is_encrypted_packet(header: u8) -> bool {
    let tag = if header & 0x40 != 0 {
        header & 0x3f
    } else {
        (header >> 2) & 0x0f
    };
    header & 0x80 != 0 && matches!(tag, TAG_PKESK | TAG_SKESK)
}

fn cms_ciphertext(body: &[u8]) -> bool {
    Reader::new(body)
        .read_sequence()
        .ok()
        .and_then(|mut content_info| content_info.read_content(tag::OID).ok())
        .is_some_and(|id| id == oid::ENVELOPED_DATA || id == oid::AUTH_ENVELOPED_DATA)
}

fn inline_protection(message: &Message<'_>) -> Protection {
    let parts = message.parts();
    if parts.len() > MAX_INLINE_PARTS {
        return Protection::None;
    }
    let inline = message.parts().any(|part| {
        let is_text = match part.content_type() {
            Some(ct) => matches!(
                media_type(ct.ctype(), ct.subtype().unwrap_or_default()),
                Some(MediaType::Text)
            ),
            None => true,
        };
        is_text && starts_with_pgp_message(&part)
    });
    if inline {
        Protection::Encrypted
    } else {
        Protection::None
    }
}
