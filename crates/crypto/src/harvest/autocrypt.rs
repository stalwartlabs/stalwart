/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base64::LENIENT;

pub(crate) const MAX_HEADER_LEN: usize = 10 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attribute {
    Addr,
    PreferEncrypt,
    Keydata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutocryptHeader<'x> {
    pub addr: &'x [u8],
    pub prefer_encrypt: bool,
    pub keydata: Vec<u8>,
}

pub fn parse_autocrypt(value: &[u8]) -> Option<AutocryptHeader<'_>> {
    if value.len() > MAX_HEADER_LEN {
        return None;
    }
    let mut addr = None;
    let mut prefer_encrypt = None;
    let mut keydata = None;
    for attribute in value.split(|b| *b == b';') {
        let attribute = attribute.trim_ascii();
        if attribute.is_empty() {
            continue;
        }
        if keydata.is_some() {
            return None;
        }
        let mut parts = attribute.splitn(2, |b| *b == b'=');
        let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
            return None;
        };
        let name = name.trim_ascii();
        let value = value.trim_ascii();
        let known = hashify::map_ignore_case!(
            name,
            Attribute,
            "addr" => Attribute::Addr,
            "prefer-encrypt" => Attribute::PreferEncrypt,
            "keydata" => Attribute::Keydata,
        );
        match known {
            Some(Attribute::Addr) if addr.is_none() => addr = Some(value),
            Some(Attribute::PreferEncrypt) if prefer_encrypt.is_none() => {
                prefer_encrypt = Some(value.eq_ignore_ascii_case(b"mutual"))
            }
            Some(Attribute::Keydata) => keydata = Some(LENIENT.decode(value).ok()?),
            None if name.starts_with(b"_") => {}
            _ => return None,
        }
    }
    let keydata = keydata.filter(|k| !k.is_empty())?;
    Some(AutocryptHeader {
        addr: addr.filter(|a| !a.is_empty())?,
        prefer_encrypt: prefer_encrypt.unwrap_or(false),
        keydata,
    })
}
