/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod number;

#[cfg(test)]
mod tests;

use memchr::{memchr, memchr2, memchr3};

const WHITESPACE: u8 = 1;
const DELIMITER: u8 = 2;
static CLASSES: [u8; 256] = {
    let mut table = [0u8; 256];
    table[0x00] = WHITESPACE;
    table[0x09] = WHITESPACE;
    table[0x0A] = WHITESPACE;
    table[0x0C] = WHITESPACE;
    table[0x0D] = WHITESPACE;
    table[0x20] = WHITESPACE;
    table[b'(' as usize] = DELIMITER;
    table[b')' as usize] = DELIMITER;
    table[b'<' as usize] = DELIMITER;
    table[b'>' as usize] = DELIMITER;
    table[b'[' as usize] = DELIMITER;
    table[b']' as usize] = DELIMITER;
    table[b'{' as usize] = DELIMITER;
    table[b'}' as usize] = DELIMITER;
    table[b'/' as usize] = DELIMITER;
    table[b'%' as usize] = DELIMITER;
    table
};

#[inline]
pub(crate) fn is_whitespace(byte: u8) -> bool {
    CLASSES[byte as usize] == WHITESPACE
}

#[inline]
pub(crate) fn is_regular(byte: u8) -> bool {
    CLASSES[byte as usize] == 0
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Token<'a> {
    Int(i64),
    Real(f64),
    Name(&'a [u8]),
    Literal(&'a [u8]),
    Hex(&'a [u8]),
    ArrayOpen,
    ArrayClose,
    DictOpen,
    DictClose,
    BraceOpen,
    BraceClose,
    Keyword(&'a [u8]),
    Error,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Lexer { data, pos: 0 }
    }

    pub(crate) fn at(data: &'a [u8], pos: usize) -> Self {
        Lexer {
            data,
            pos: pos.min(data.len()),
        }
    }

    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    pub(crate) fn data(&self) -> &'a [u8] {
        self.data
    }

    #[inline]
    pub(crate) fn set_pos(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
    }

    #[inline]
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }

    #[inline]
    pub(crate) fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    #[inline]
    fn byte(&self, pos: usize) -> Option<u8> {
        self.data.get(pos).copied()
    }

    pub(crate) fn skip_whitespace(&mut self) {
        while let Some(byte) = self.byte(self.pos) {
            if is_whitespace(byte) {
                self.pos += 1;
            } else if byte == b'%' {
                self.pos = match memchr2(b'\r', b'\n', self.rest()) {
                    Some(offset) => self.pos + offset,
                    None => self.data.len(),
                };
            } else {
                break;
            }
        }
    }

    pub(crate) fn peek(&self) -> Option<Token<'a>> {
        let mut probe = *self;
        probe.next()
    }

    #[allow(clippy::should_implement_trait)]
    pub(crate) fn next(&mut self) -> Option<Token<'a>> {
        self.skip_whitespace();
        let start = self.pos;
        let byte = self.byte(start)?;
        self.pos += 1;
        Some(match byte {
            b'0'..=b'9' | b'+' | b'-' | b'.' => self.number(start),
            b'/' => {
                let end = self.regular_run(self.pos);
                let name = self.data.get(self.pos..end).unwrap_or_default();
                self.pos = end;
                Token::Name(name)
            }
            b'(' => self.literal(),
            b'<' => {
                if self.byte(self.pos) == Some(b'<') {
                    self.pos += 1;
                    Token::DictOpen
                } else {
                    self.hex()
                }
            }
            b'>' => {
                if self.byte(self.pos) == Some(b'>') {
                    self.pos += 1;
                    Token::DictClose
                } else {
                    Token::Error
                }
            }
            b'[' => Token::ArrayOpen,
            b']' => Token::ArrayClose,
            b'{' => Token::BraceOpen,
            b'}' => Token::BraceClose,
            b')' => Token::Error,
            _ => {
                if !(0x20..=0x7F).contains(&byte)
                    && self
                        .byte(self.pos)
                        .is_some_and(|next| (0x21..0x7F).contains(&next) && is_regular(next))
                {
                    return Some(Token::Keyword(
                        self.data.get(start..self.pos).unwrap_or_default(),
                    ));
                }
                let end = self.regular_run(self.pos);
                self.pos = end;
                Token::Keyword(self.data.get(start..end).unwrap_or_default())
            }
        })
    }

    fn regular_run(&self, from: usize) -> usize {
        self.data
            .get(from..)
            .unwrap_or_default()
            .iter()
            .position(|&byte| !is_regular(byte))
            .map_or(self.data.len(), |offset| from + offset)
    }

    fn literal(&mut self) -> Token<'a> {
        let start = self.pos;
        let mut depth = 1u32;
        let mut pos = start;
        loop {
            let Some(offset) = memchr3(b'(', b')', b'\\', self.data.get(pos..).unwrap_or_default())
            else {
                self.pos = self.data.len();
                return Token::Literal(self.data.get(start..).unwrap_or_default());
            };
            pos += offset;
            match self.byte(pos) {
                Some(b'\\') => pos += 2,
                Some(b'(') => {
                    depth = depth.saturating_add(1);
                    pos += 1;
                }
                _ => {
                    depth -= 1;
                    if depth == 0 {
                        self.pos = pos + 1;
                        return Token::Literal(self.data.get(start..pos).unwrap_or_default());
                    }
                    pos += 1;
                }
            }
        }
    }

    fn hex(&mut self) -> Token<'a> {
        let start = self.pos;
        match memchr(b'>', self.rest()) {
            Some(offset) => {
                self.pos = start + offset + 1;
                Token::Hex(self.data.get(start..start + offset).unwrap_or_default())
            }
            None => {
                self.pos = self.data.len();
                Token::Hex(self.data.get(start..).unwrap_or_default())
            }
        }
    }
}
