/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use crate::common::token::{TOKEN_MAX, TokenBuf};

pub const TOKEN_VERSION: u8 = 1;
pub const EAS_TOKEN_MAX: usize = 64;
pub const EAS_CHANGE_ID_MAX: u64 = (1 << 56) - 1;
pub const MAX_TOKEN_BYTES: usize = 96;

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const EAS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const PAD: u8 = b'=';
const LEB_MAX_BYTES: usize = 10;

pub(crate) mod kind {
    pub(crate) const EWS_FOLDER: u8 = 1;
    pub(crate) const EWS_ITEM: u8 = 2;
    pub(crate) const EWS_OCCURRENCE: u8 = 3;
    pub(crate) const EWS_ATTACHMENT: u8 = 4;
    pub(crate) const EWS_CHANGE_KEY: u8 = 5;
    pub(crate) const EWS_ITEMS_SYNC: u8 = 6;
    pub(crate) const EWS_HIERARCHY_SYNC: u8 = 7;
    pub(crate) const EWS_SUBSCRIPTION: u8 = 8;
    pub(crate) const EWS_WATERMARK: u8 = 9;
    pub(crate) const EWS_CONVERSATION: u8 = 10;
    pub(crate) const EWS_PERSONA_CONTACT: u8 = 11;
    pub(crate) const EWS_PERSONA_DIRECTORY: u8 = 12;
    pub(crate) const EWS_ASSOCIATED: u8 = 13;
    pub(crate) const EAS_SYNC_KEY: u8 = 16;
    pub(crate) const EAS_HIERARCHY_KEY: u8 = 17;
    pub(crate) const EAS_SERVER_ID: u8 = 18;
    pub(crate) const EAS_COLLECTION_ID: u8 = 19;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    MailFolder,
    Calendar,
    AddressBook,
    TaskList,
    NotesFolder,
    VirtualFolder,
    Email,
    Event,
    Contact,
    Task,
    Note,
    Attachment,
    Occurrence,
}

impl ObjectKind {
    const ALL: [ObjectKind; 13] = [
        ObjectKind::MailFolder,
        ObjectKind::Calendar,
        ObjectKind::AddressBook,
        ObjectKind::TaskList,
        ObjectKind::NotesFolder,
        ObjectKind::VirtualFolder,
        ObjectKind::Email,
        ObjectKind::Event,
        ObjectKind::Contact,
        ObjectKind::Task,
        ObjectKind::Note,
        ObjectKind::Attachment,
        ObjectKind::Occurrence,
    ];

    pub fn code(self) -> u64 {
        match self {
            ObjectKind::MailFolder => 0,
            ObjectKind::Calendar => 1,
            ObjectKind::AddressBook => 2,
            ObjectKind::TaskList => 3,
            ObjectKind::NotesFolder => 4,
            ObjectKind::VirtualFolder => 5,
            ObjectKind::Email => 6,
            ObjectKind::Event => 7,
            ObjectKind::Contact => 8,
            ObjectKind::Task => 9,
            ObjectKind::Note => 10,
            ObjectKind::Attachment => 11,
            ObjectKind::Occurrence => 12,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        usize::try_from(code)
            .ok()
            .and_then(|code| Self::ALL.get(code))
            .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Alphabet {
    Standard,
    Eas,
}

impl Alphabet {
    fn table(self) -> &'static [u8; 64] {
        match self {
            Alphabet::Standard => STANDARD,
            Alphabet::Eas => EAS,
        }
    }

    fn padded(self) -> bool {
        self == Alphabet::Standard
    }

    fn limit(self) -> usize {
        match self {
            Alphabet::Standard => TOKEN_MAX,
            Alphabet::Eas => EAS_TOKEN_MAX,
        }
    }

    fn value(self, byte: u8) -> Option<u8> {
        let value = match byte {
            b'A'..=b'Z' => byte.wrapping_sub(b'A'),
            b'a'..=b'z' => byte.wrapping_sub(b'a').wrapping_add(26),
            b'0'..=b'9' => byte.wrapping_sub(b'0').wrapping_add(52),
            b'+' if self == Alphabet::Standard => 62,
            b'/' if self == Alphabet::Standard => 63,
            b'-' if self == Alphabet::Eas => 62,
            b'_' if self == Alphabet::Eas => 63,
            _ => return None,
        };
        Some(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenWriter {
    buf: SmallVec<[u8; 64]>,
}

impl TokenWriter {
    pub fn new(kind: u8) -> Self {
        let mut buf = SmallVec::new();
        buf.extend_from_slice(&[TOKEN_VERSION, kind]);
        TokenWriter { buf }
    }

    pub fn u64(&mut self, mut value: u64) -> &mut Self {
        loop {
            let byte = u8::try_from(value & 0x7f).unwrap_or_default();
            value >>= 7;
            if value == 0 {
                self.buf.push(byte);
                return self;
            }
            self.buf.push(byte | 0x80);
        }
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.u64(u64::from(value))
    }

    pub fn flag(&mut self, value: bool) -> &mut Self {
        self.buf.push(u8::from(value));
        self
    }

    pub fn object_kind(&mut self, kind: ObjectKind) -> &mut Self {
        self.u64(kind.code())
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.u64(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.buf.extend_from_slice(bytes);
        self
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn finish_base64(&self) -> Option<TokenBuf> {
        encode(&self.buf, Alphabet::Standard)
    }

    pub fn finish_eas(&self) -> Option<TokenBuf> {
        encode(&self.buf, Alphabet::Eas)
    }
}

fn encode(bytes: &[u8], alphabet: Alphabet) -> Option<TokenBuf> {
    let table = alphabet.table();
    let symbol = |index: u32| -> u8 {
        table
            .get(usize::try_from(index & 0x3f).unwrap_or_default())
            .copied()
            .unwrap_or(PAD)
    };
    let mut out = TokenBuf::new();
    let (chunks, remainder) = bytes.as_chunks::<3>();
    for &[a, b, c] in chunks {
        let group = u32::from(a) << 16 | u32::from(b) << 8 | u32::from(c);
        let quad = [
            symbol(group >> 18),
            symbol(group >> 12),
            symbol(group >> 6),
            symbol(group),
        ];
        if !out.try_push_ascii(&quad) {
            return None;
        }
    }
    let tail = match *remainder {
        [a] => {
            let group = u32::from(a) << 16;
            Some((2, [symbol(group >> 18), symbol(group >> 12), PAD, PAD]))
        }
        [a, b] => {
            let group = u32::from(a) << 16 | u32::from(b) << 8;
            Some((
                3,
                [
                    symbol(group >> 18),
                    symbol(group >> 12),
                    symbol(group >> 6),
                    PAD,
                ],
            ))
        }
        _ => None,
    };
    if let Some((len, quad)) = tail {
        let quad = if alphabet.padded() {
            quad.as_slice()
        } else {
            quad.get(..len)?
        };
        if !out.try_push_ascii(quad) {
            return None;
        }
    }
    (out.len() <= alphabet.limit()).then_some(out)
}

fn decode(text: &str, alphabet: Alphabet, out: &mut SmallVec<[u8; 64]>) -> Option<()> {
    out.clear();
    let text = text.as_bytes();
    if text.is_empty() || text.len() > alphabet.limit() {
        return None;
    }
    let (body, padding) = if alphabet.padded() {
        if !text.len().is_multiple_of(4) {
            return None;
        }
        match text {
            [body @ .., PAD, PAD] => (body, 2),
            [body @ .., PAD] => (body, 1),
            body => (body, 0),
        }
    } else {
        (text, 0)
    };
    let mut acc: u32 = 0;
    let mut sextets: u8 = 0;
    for &byte in body {
        let value = alphabet.value(byte)?;
        acc = acc << 6 | u32::from(value);
        sextets = sextets.wrapping_add(1);
        if sextets == 4 {
            let [_, a, b, c] = acc.to_be_bytes();
            out.extend_from_slice(&[a, b, c]);
            acc = 0;
            sextets = 0;
        }
    }
    let (expected_padding, spare_mask) = match sextets {
        0 => (0, 0),
        2 => (2, 0x0f),
        3 => (1, 0x03),
        _ => return None,
    };
    if acc & spare_mask != 0 || (alphabet.padded() && padding != expected_padding) {
        return None;
    }
    match sextets {
        2 => {
            let [_, _, _, a] = (acc >> 4).to_be_bytes();
            out.push(a);
        }
        3 => {
            let [_, _, a, b] = (acc >> 2).to_be_bytes();
            out.extend_from_slice(&[a, b]);
        }
        _ => {}
    }
    Some(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenReader<'a> {
    rest: &'a [u8],
}

impl<'a> TokenReader<'a> {
    pub fn decode_base64(text: &str, scratch: &'a mut SmallVec<[u8; 64]>) -> Option<(u8, Self)> {
        decode(text, Alphabet::Standard, scratch)?;
        Self::from_bytes(scratch)
    }

    pub fn decode_eas(text: &str, scratch: &'a mut SmallVec<[u8; 64]>) -> Option<(u8, Self)> {
        decode(text, Alphabet::Eas, scratch)?;
        Self::from_bytes(scratch)
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Option<(u8, Self)> {
        match bytes {
            [TOKEN_VERSION, kind, rest @ ..] => Some((*kind, TokenReader { rest })),
            _ => None,
        }
    }

    pub fn u64(&mut self) -> Option<u64> {
        let mut value: u64 = 0;
        for (index, &byte) in self.rest.iter().enumerate().take(LEB_MAX_BYTES) {
            let shift = u32::try_from(index).ok()?.checked_mul(7)?;
            let bits = u64::from(byte & 0x7f);
            if shift == 63 && bits > 1 {
                return None;
            }
            value |= bits.checked_shl(shift)?;
            if byte & 0x80 == 0 {
                if byte == 0 && index > 0 {
                    return None;
                }
                self.rest = self.rest.get(index.checked_add(1)?..)?;
                return Some(value);
            }
        }
        None
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.u64().and_then(|value| u32::try_from(value).ok())
    }

    pub fn change_id(&mut self) -> Option<u64> {
        self.u64()
            .filter(|change_id| *change_id <= EAS_CHANGE_ID_MAX)
    }

    pub fn flag(&mut self) -> Option<bool> {
        let (&byte, rest) = self.rest.split_first()?;
        self.rest = rest;
        match byte {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    pub fn object_kind(&mut self) -> Option<ObjectKind> {
        self.u64().and_then(ObjectKind::from_code)
    }

    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u64()?).ok()?;
        let (bytes, rest) = self.rest.split_at_checked(len)?;
        self.rest = rest;
        Some(bytes)
    }

    pub fn end(self) -> bool {
        self.rest.is_empty()
    }

    pub fn into_rest(self) -> &'a [u8] {
        self.rest
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ids/token/tests.rs"]
mod tests;
