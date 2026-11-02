/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DerError, tag};

const MAX_DEPTH: usize = 32;
const HIGH_TAG_NUMBER: u8 = 0x1F;
const INDEFINITE_LENGTH: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    Definite,
    Indefinite,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'x> {
    pub tag: u8,
    pub content: &'x [u8],
    pub raw: &'x [u8],
    pub encoding: Encoding,
}

impl<'x> Tlv<'x> {
    pub(crate) fn reader(&self) -> Reader<'x> {
        Reader::new(self.content)
    }

    pub(crate) fn expect(self, tag: u8) -> Result<Self, DerError> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(DerError::UnexpectedTag)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'x> {
    data: &'x [u8],
}

impl<'x> Reader<'x> {
    pub(crate) const fn new(data: &'x [u8]) -> Self {
        Reader { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    pub(crate) fn finish(&self) -> Result<(), DerError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(DerError::TrailingData)
        }
    }

    pub(crate) fn read(&mut self) -> Result<Tlv<'x>, DerError> {
        let (tlv, rest) = parse_tlv(self.data, 0)?;
        self.data = rest;
        Ok(tlv)
    }

    pub(crate) fn read_tag(&mut self, tag: u8) -> Result<Tlv<'x>, DerError> {
        self.read()?.expect(tag)
    }

    pub(crate) fn read_optional(&mut self, tag: u8) -> Result<Option<Tlv<'x>>, DerError> {
        if self.peek_tag() == Some(tag) {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn read_sequence(&mut self) -> Result<Reader<'x>, DerError> {
        self.read_tag(tag::SEQUENCE).map(|tlv| tlv.reader())
    }

    pub(crate) fn read_content(&mut self, tag: u8) -> Result<&'x [u8], DerError> {
        self.read_tag(tag).map(|tlv| tlv.content)
    }

    pub(crate) fn read_small_unsigned(&mut self) -> Result<u32, DerError> {
        let content = match self.read_content(tag::INTEGER)? {
            [0, rest @ ..] if !rest.is_empty() => rest,
            [first, ..] if first & 0x80 != 0 => return Err(DerError::InvalidValue),
            [] => return Err(DerError::InvalidValue),
            content => content,
        };
        if content.len() > 4 {
            return Err(DerError::InvalidValue);
        }
        Ok(content
            .iter()
            .fold(0u32, |acc, b| (acc << 8) | u32::from(*b)))
    }

    pub(crate) fn read_bool_default_false(&mut self) -> Result<bool, DerError> {
        match self.read_optional(tag::BOOLEAN)? {
            Some(tlv) => match tlv.content {
                [value] => Ok(*value != 0),
                _ => Err(DerError::InvalidValue),
            },
            None => Ok(false),
        }
    }
}

impl<'x> Iterator for Reader<'x> {
    type Item = Result<Tlv<'x>, DerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            None
        } else {
            let result = self.read();
            if result.is_err() {
                self.data = &[];
            }
            Some(result)
        }
    }
}

fn parse_tlv(data: &[u8], depth: usize) -> Result<(Tlv<'_>, &[u8]), DerError> {
    let [tag, len_byte, after_len @ ..] = data else {
        return Err(DerError::Truncated);
    };
    if tag & HIGH_TAG_NUMBER == HIGH_TAG_NUMBER {
        return Err(DerError::UnsupportedTag);
    }
    if *len_byte == INDEFINITE_LENGTH {
        if tag & tag::CONSTRUCTED == 0 {
            return Err(DerError::InvalidLength);
        }
        if depth >= MAX_DEPTH {
            return Err(DerError::TooDeep);
        }
        let mut rest = after_len;
        loop {
            match rest {
                [0, 0, after_eoc @ ..] => {
                    let content_len = after_len.len() - rest.len();
                    let raw_len = data.len() - after_eoc.len();
                    return Ok((
                        Tlv {
                            tag: *tag,
                            content: &after_len[..content_len],
                            raw: &data[..raw_len],
                            encoding: Encoding::Indefinite,
                        },
                        after_eoc,
                    ));
                }
                _ => {
                    let (_, next) = parse_tlv(rest, depth + 1)?;
                    rest = next;
                }
            }
        }
    }
    let (len, body) = if len_byte & 0x80 == 0 {
        (usize::from(*len_byte), after_len)
    } else {
        let count = usize::from(len_byte & 0x7F);
        if count == 0 || count > 4 {
            return Err(DerError::InvalidLength);
        }
        let (len_bytes, body) = after_len
            .split_at_checked(count)
            .ok_or(DerError::Truncated)?;
        let len = len_bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, body)
    };
    let (content, rest) = body.split_at_checked(len).ok_or(DerError::Truncated)?;
    let raw_len = data.len() - rest.len();
    Ok((
        Tlv {
            tag: *tag,
            content,
            raw: &data[..raw_len],
            encoding: Encoding::Definite,
        },
        rest,
    ))
}
