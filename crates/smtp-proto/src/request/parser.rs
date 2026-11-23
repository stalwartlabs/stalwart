/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::char;
use std::slice::Iter;
use std::str::from_utf8;

use crate::{xtext::XText, *};

use super::scan::{
    MEMCHR_MIN_LEN, TOKEN_UPPER, find_any3, find_any4, find_lf, find_non_atext, preceding_byte,
    split_at_index,
};
use super::*;

const MAX_ADDRESS_LEN: usize = 256;
pub const POSTMASTER: &str = "postmaster";
const POSTMASTER_LEN: usize = POSTMASTER.len();
const MAX_DOMAIN_LEN: usize = 255;
const MAX_FUTURE_RELEASE_INTERVAL: usize = 999_999_999;
const MAX_EXACT_SIZE_DIGITS: u32 = usize::MAX.ilog10();
const MAX_EXACT_INTEGER_DIGITS: u32 = i64::MAX.ilog10();

impl<'a> Request<Cow<'a, str>> {
    pub fn parse(bytes: &mut Iter<'a, u8>) -> Result<Request<Cow<'a, str>>, Error> {
        let mut parser = Rfc5321Parser::new(bytes);
        let command = parser.hashed_value()?;
        if !parser.stop_char.is_ascii_whitespace() {
            parser.seek_lf()?;
            return Err(Error::UnknownCommand);
        }

        match command {
            RCPT => {
                if !(parser.stop_char == LF
                    || parser.hashed_value()? != TO
                    || parser.stop_char != b':' && parser.next_char()? != b':')
                    && parser.next_char()? == b'<'
                {
                    if let Some(to) = parser.address()? {
                        if parser.stop_char == b'>' {
                            return Ok(Request::Rcpt {
                                to: parser.rcpt_to_parameters(to)?,
                            });
                        }
                    } else {
                        parser.seek_lf()?;
                        return Err(Error::InvalidRecipientAddress);
                    }
                }
                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "RCPT TO:<forward-path> [parameters]",
                })
            }
            MAIL => {
                if !(parser.stop_char == LF
                    || parser.hashed_value()? != FROM
                    || parser.stop_char != b':' && parser.next_char()? != b':')
                    && parser.next_char()? == b'<'
                {
                    if let Some(from) = parser.address()? {
                        if parser.stop_char == b'>' {
                            let from = if from.eq_ignore_ascii_case(POSTMASTER) {
                                Cow::Borrowed("")
                            } else {
                                from
                            };
                            return Ok(Request::Mail {
                                from: parser.mail_from_parameters(from)?,
                            });
                        }
                    } else {
                        parser.seek_lf()?;
                        return Err(Error::InvalidSenderAddress);
                    }
                }

                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "MAIL FROM:<reverse-path> [parameters]",
                })
            }
            DATA => {
                parser.seek_lf()?;
                Ok(Request::Data)
            }
            EHLO => {
                if parser.stop_char != LF {
                    let host = parser.text()?;
                    parser.seek_lf()?;
                    if (1..=MAX_DOMAIN_LEN).contains(&host.len()) {
                        return Ok(Request::Ehlo { host });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "EHLO domain",
                })
            }
            BDAT => {
                if parser.stop_char != LF {
                    let chunk_size = parser.size()?;
                    if chunk_size != usize::MAX && parser.stop_char.is_ascii_whitespace() {
                        if parser.stop_char != LF {
                            match parser.hashed_value()? {
                                LAST => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Bdat {
                                        chunk_size,
                                        is_last: true,
                                    });
                                }
                                0 => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Bdat {
                                        chunk_size,
                                        is_last: false,
                                    });
                                }
                                _ => (),
                            }
                        } else {
                            return Ok(Request::Bdat {
                                chunk_size,
                                is_last: false,
                            });
                        }
                    }
                }
                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "BDAT chunk-size [LAST]",
                })
            }
            AUTH => {
                if parser.stop_char != LF
                    && let Some(mechanism) = parser.mechanism()?
                {
                    let initial_response = if parser.stop_char != LF {
                        while let Some(rest) = parser.bytes.as_slice().strip_prefix(b" ") {
                            *parser.bytes = rest.iter();
                        }
                        parser.text()?
                    } else {
                        Cow::Borrowed("")
                    };
                    parser.seek_lf()?;
                    return Ok(Request::Auth {
                        mechanism,
                        initial_response,
                    });
                }
                if parser.stop_char != LF {
                    parser.seek_lf()?;
                }
                Err(Error::SyntaxError {
                    syntax: "AUTH mechanism [initial-response]",
                })
            }
            EXPN => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    if (1..=MAX_ADDRESS_LEN).contains(&value.len()) {
                        return Ok(Request::Expn { value });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "EXPN string",
                })
            }
            NOOP => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    Ok(Request::Noop { value })
                } else {
                    Ok(Request::Noop {
                        value: Cow::Borrowed(""),
                    })
                }
            }
            QUIT => {
                parser.seek_lf()?;
                Ok(Request::Quit)
            }
            LHLO => {
                if parser.stop_char != LF {
                    let host = parser.text()?;
                    parser.seek_lf()?;
                    if (1..=MAX_DOMAIN_LEN).contains(&host.len()) {
                        return Ok(Request::Lhlo { host });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "LHLO domain",
                })
            }
            RSET => {
                parser.seek_lf()?;
                Ok(Request::Rset)
            }
            VRFY => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    if (1..=MAX_ADDRESS_LEN).contains(&value.len()) {
                        return Ok(Request::Vrfy { value });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "VRFY string",
                })
            }
            HELP => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    Ok(Request::Help { value })
                } else {
                    Ok(Request::Help {
                        value: Cow::Borrowed(""),
                    })
                }
            }
            STARTTLS => {
                parser.seek_lf()?;
                Ok(Request::StartTls)
            }
            ETRN => {
                if parser.stop_char != LF {
                    let name = parser.string()?;
                    parser.seek_lf()?;
                    if !name.is_empty() {
                        return Ok(Request::Etrn { name });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "ETRN name",
                })
            }
            ATRN => {
                if parser.stop_char != LF {
                    let mut domains = Vec::new();
                    loop {
                        let domain = parser.seek_char(b',')?;
                        if !domain.is_empty() {
                            domains.push(domain);
                        }
                        if parser.stop_char != b',' {
                            parser.seek_lf()?;
                            if !domains.is_empty() {
                                return Ok(Request::Atrn { domains });
                            } else {
                                break;
                            }
                        }
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "ATRN domain[,domain]",
                })
            }
            BURL => {
                if parser.stop_char != LF {
                    let uri = parser.text()?;
                    if !uri.is_empty() && parser.stop_char.is_ascii_whitespace() {
                        if parser.stop_char != LF {
                            match parser.hashed_value()? {
                                LAST => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Burl { uri, is_last: true });
                                }
                                0 => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Burl {
                                        uri,
                                        is_last: false,
                                    });
                                }
                                _ => (),
                            }
                        } else {
                            return Ok(Request::Burl {
                                uri,
                                is_last: false,
                            });
                        }
                    }
                }
                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "BURL absolute-uri [LAST]",
                })
            }
            HELO => {
                if parser.stop_char != LF {
                    let host = parser.text()?;
                    parser.seek_lf()?;
                    if (1..=MAX_DOMAIN_LEN).contains(&host.len()) {
                        return Ok(Request::Helo { host });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "HELO domain",
                })
            }
            _ => {
                parser.seek_lf()?;
                Err(Error::UnknownCommand)
            }
        }
    }
}

pub struct Rfc5321Parser<'x, 'y> {
    bytes: &'x mut Iter<'y, u8>,
    pub stop_char: u8,
    pub bytes_left: usize,
}

impl<'x, 'y> Rfc5321Parser<'x, 'y> {
    pub fn new(bytes: &'x mut Iter<'y, u8>) -> Self {
        let (bytes_left, _) = bytes.size_hint();
        Rfc5321Parser {
            bytes,
            bytes_left,
            stop_char: 0,
        }
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn hashed_value(&mut self) -> Result<u64, Error> {
        let mut value: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.bytes.next() {
            let token = TOKEN_UPPER[ch as usize];
            if token != 0 && shift < 64 {
                value |= (token as u64) << shift;
                shift += 8;
            } else if ch != b'\r' && (ch != b' ' || value != 0) {
                self.stop_char = ch;
                return Ok(value);
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn hashed_value_long(&mut self) -> Result<u128, Error> {
        let mut low: u64 = 0;
        let mut high: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.bytes.next() {
            let token = TOKEN_UPPER[ch as usize];
            if token != 0 && shift < 128 {
                let bits = (token as u64) << (shift & 63);
                if shift < 64 {
                    low |= bits;
                } else {
                    high |= bits;
                }
                shift += 8;
            } else if ch != b'\r' && (ch != b' ' || (low | high) != 0) {
                self.stop_char = ch;
                return Ok(low as u128 | (high as u128) << 64);
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn address(&mut self) -> Result<Option<Cow<'y, str>>, Error> {
        let mut value = self.start_zero_copy();
        let mut last_ch = 0;
        let mut in_quote = false;
        let mut at_count = 0;
        let mut lp_len = 0;

        loop {
            let slice = self.bytes.as_slice();
            let pos = if in_quote {
                find_any4(slice, LF, b'"', b'\\', b'\r')
            } else {
                find_non_atext(slice)
            };
            let (found, rest) = split_at_index(slice, pos);
            if let Some(prev) = preceding_byte(slice, rest) {
                last_ch = prev;
            }
            *self.bytes = rest.iter();

            let Some(ch) = found else {
                return Err(Error::NeedsMoreData {
                    bytes_left: self.bytes_left,
                });
            };

            match ch {
                b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
                | 0x7f..=u8::MAX => {}
                b'.' if !in_quote => {
                    if last_ch == b'.' || last_ch == b'@' || self.len_excluding_current(&value) == 0
                    {
                        self.stop_char = ch;
                        return Ok(None);
                    }
                }
                b'@' if !in_quote => {
                    at_count += 1;
                    lp_len = self.len_excluding_current(&value);
                }
                b'>' if !in_quote => {
                    self.stop_char = ch;
                    self.flush_excluding_current(&mut value);
                    let value = value.data;

                    return Ok(match value.len() {
                        1..=MAX_ADDRESS_LEN if at_count == 1 && lp_len > 0 => Some(value),
                        POSTMASTER_LEN
                            if at_count == 0 && value.eq_ignore_ascii_case(POSTMASTER) =>
                        {
                            Some(value)
                        }
                        0 => Some("".into()),
                        _ => None,
                    });
                }
                b'\r' => self.flush_excluding_current(&mut value),
                b':' if !in_quote && self.first_excluding_current(&value) == Some(b'@') => {
                    // Remove source route
                    value = self.start_zero_copy();
                    at_count = 0;
                    lp_len = 0;
                }
                // Note that if there is an @ at the start, we require `:` a to be in the string
                // later, since otherwise `at_count == 1 && lp_len > 0` cannot be satisfied. So it
                // doesn't matter what we do here (other than not error).
                b',' if !in_quote && self.first_excluding_current(&value) == Some(b'@') => (),
                b' ' if !in_quote => {
                    self.flush_excluding_current(&mut value);
                    if !value.data.is_empty() {
                        self.stop_char = b' ';
                        let value = value.data;

                        let is_valid = value.is_empty()
                            || value.len() <= MAX_ADDRESS_LEN && at_count == 1 && lp_len > 0;

                        return Ok(is_valid.then_some(value));
                    }
                }
                b'\n' => {
                    self.stop_char = b'\n';
                    self.flush_excluding_current(&mut value);
                    let value = value.data;

                    let is_valid = value.is_empty()
                        || value.len() <= MAX_ADDRESS_LEN && at_count == 1 && lp_len > 0;

                    return Ok(is_valid.then_some(value));
                }
                b'\"' if !in_quote || last_ch != b'\\' => {
                    in_quote = !in_quote;
                    self.flush_excluding_current(&mut value);
                }
                b'\\' if in_quote => {
                    if last_ch != b'\\' {
                        self.flush_excluding_current(&mut value);
                    } else {
                        // Escaped backslash
                        last_ch = 0;
                        continue;
                    }
                }
                _ if in_quote => {}
                _ => {
                    self.stop_char = ch;
                    return Ok(None);
                }
            }

            last_ch = ch;
        }
    }

    pub fn string(&mut self) -> Result<Cow<'y, str>, Error> {
        let mut in_quote = false;
        let mut value = self.start_zero_copy();
        let mut last_ch = 0;

        loop {
            let slice = self.bytes.as_slice();
            let pos = if in_quote {
                find_any4(slice, LF, b'"', b'\\', b'\r')
            } else {
                find_any4(slice, LF, b' ', b'"', b'\r')
            };
            let (found, rest) = split_at_index(slice, pos);
            if let Some(prev) = preceding_byte(slice, rest) {
                last_ch = prev;
            }
            *self.bytes = rest.iter();

            let Some(ch) = found else {
                return Err(Error::NeedsMoreData {
                    bytes_left: self.bytes_left,
                });
            };

            match ch {
                b' ' if !in_quote => {
                    self.flush_excluding_current(&mut value);
                    if !value.data.is_empty() {
                        self.stop_char = b' ';
                        return Ok(value.data);
                    }
                }
                b'\n' => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = b'\n';
                    return Ok(value.data);
                }
                b'\"' if !in_quote || last_ch != b'\\' => {
                    in_quote = !in_quote;
                    self.flush_excluding_current(&mut value);
                }
                b'\\' if in_quote => {
                    if last_ch != b'\\' {
                        self.flush_excluding_current(&mut value);
                    } else {
                        last_ch = 0;
                        continue;
                    }
                }
                b'\r' => self.flush_excluding_current(&mut value),
                _ => {}
            }

            last_ch = ch;
        }
    }

    pub fn text(&mut self) -> Result<Cow<'y, str>, Error> {
        let mut value = self.start_zero_copy();
        loop {
            let slice = self.bytes.as_slice();
            let (found, rest) = split_at_index(slice, find_any3(slice, LF, b' ', b'\r'));
            *self.bytes = rest.iter();

            let Some(ch) = found else {
                return Err(Error::NeedsMoreData {
                    bytes_left: self.bytes_left,
                });
            };

            self.flush_excluding_current(&mut value);
            if ch != b'\r' {
                self.stop_char = ch;
                return Ok(value.data);
            }
        }
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn xtext(&mut self) -> Result<Cow<'y, str>, Error> {
        let mut value = self.start_zero_copy();
        loop {
            let slice = self.bytes.as_slice();
            let (found, rest) = split_at_index(slice, find_any4(slice, LF, b' ', b'+', b'\r'));
            *self.bytes = rest.iter();

            let Some(ch) = found else {
                return Err(Error::NeedsMoreData {
                    bytes_left: self.bytes_left,
                });
            };

            match ch {
                b'\n' | b' ' => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = ch;
                    return Ok(value.data);
                }
                b'+' => {
                    self.flush_excluding_current(&mut value);

                    let mut hex1 = None;

                    while let Some(&ch) = self.bytes.next() {
                        if let Some(digit) = char::from(ch).to_digit(16) {
                            if let Some(hex1) = hex1 {
                                let data = value.data.to_mut();
                                data.push(char::from(((hex1 as u8) << 4) | digit as u8));
                                break;
                            } else {
                                hex1 = Some(digit);
                            }
                        } else if ch == LF {
                            self.stop_char = b'\n';
                            return Ok(value.data);
                        } else {
                            break;
                        }
                    }

                    self.drop_extra(&mut value);
                }
                b'\r' => self.flush_excluding_current(&mut value),
                _ => {}
            }
        }
    }

    pub fn seek_char(&mut self, stop_char: u8) -> Result<Cow<'y, str>, Error> {
        let mut value = self.start_zero_copy();
        loop {
            let slice = self.bytes.as_slice();
            let (found, rest) = split_at_index(slice, find_any4(slice, LF, b' ', b'\r', stop_char));
            *self.bytes = rest.iter();

            let Some(ch) = found else {
                return Err(Error::NeedsMoreData {
                    bytes_left: self.bytes_left,
                });
            };

            match ch {
                b'\n' => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = b'\n';
                    return Ok(value.data);
                }
                b' ' => {
                    self.flush_excluding_current(&mut value);
                    if !value.data.is_empty() {
                        self.stop_char = b' ';
                        return Ok(value.data);
                    }
                }
                b'\r' => self.flush_excluding_current(&mut value),
                _ if ch == stop_char => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = ch;
                    return Ok(value.data);
                }
                _ => {}
            }
        }
    }

    #[inline(always)]
    pub fn seek_lf(&mut self) -> Result<(), Error> {
        if self.stop_char != LF {
            if self.bytes.len() >= MEMCHR_MIN_LEN {
                return self.seek_lf_bulk();
            }

            for &ch in &mut self.bytes {
                if ch == LF {
                    return Ok(());
                }
            }

            Err(Error::NeedsMoreData {
                bytes_left: self.bytes_left,
            })
        } else {
            Ok(())
        }
    }

    #[inline(never)]
    fn seek_lf_bulk(&mut self) -> Result<(), Error> {
        let slice = self.bytes.as_slice();
        let (found, rest) = split_at_index(slice, find_lf(slice));
        *self.bytes = rest.iter();

        if found.is_some() {
            Ok(())
        } else {
            Err(Error::NeedsMoreData {
                bytes_left: self.bytes_left,
            })
        }
    }

    #[inline(always)]
    pub fn next_char(&mut self) -> Result<u8, Error> {
        for &ch in &mut self.bytes {
            match ch {
                b' ' | b'\r' => (),
                _ => {
                    self.stop_char = ch;
                    return Ok(ch);
                }
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[inline(always)]
    pub fn read_char(&mut self) -> Result<u8, Error> {
        self.bytes.next().copied().ok_or(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn size(&mut self) -> Result<usize, Error> {
        let mut value: usize = 0;
        let mut digits = 0;

        while let Some(&ch) = self.bytes.next() {
            let digit = ch.wrapping_sub(b'0');
            if digit < 10 {
                if digits == MAX_EXACT_SIZE_DIGITS {
                    return self.size_saturating(value, digit);
                }
                value = value * 10 + digit as usize;
                digits += 1;
            } else if ch != b'\r' && (ch != b' ' || digits != 0) {
                self.stop_char = ch;
                return Ok(if digits != 0 { value } else { usize::MAX });
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[inline(never)]
    fn size_saturating(&mut self, value: usize, digit: u8) -> Result<usize, Error> {
        let mut value = value.saturating_mul(10).saturating_add(digit as usize);
        for &ch in &mut self.bytes {
            match ch {
                b'0'..=b'9' => {
                    value = if value != usize::MAX {
                        value
                            .saturating_mul(10)
                            .saturating_add((ch - b'0') as usize)
                    } else {
                        (ch - b'0') as usize
                    };
                }
                b'\r' => (),
                b' ' => {
                    if value != usize::MAX {
                        self.stop_char = b' ';
                        return Ok(value);
                    }
                }
                _ => {
                    self.stop_char = ch;
                    return Ok(value);
                }
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn integer(&mut self) -> Result<i64, Error> {
        let mut value: i64 = 0;
        let mut digits = 0;
        let mut multiplier = 1;

        while let Some(&ch) = self.bytes.next() {
            let digit = ch.wrapping_sub(b'0');
            if digit < 10 {
                if digits == MAX_EXACT_INTEGER_DIGITS {
                    return self.integer_saturating(value, digit, multiplier);
                }
                value = value * 10 + digit as i64;
                digits += 1;
            } else if digits == 0 && (ch == b'-' || ch == b'+') {
                if ch == b'-' {
                    multiplier = -1;
                }
            } else if ch != b'\r' && (ch != b' ' || digits != 0) {
                self.stop_char = ch;
                return Ok(if digits != 0 {
                    value * multiplier
                } else {
                    i64::MAX
                });
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[inline(never)]
    fn integer_saturating(&mut self, value: i64, digit: u8, multiplier: i64) -> Result<i64, Error> {
        let mut value = value.saturating_mul(10).saturating_add(digit as i64);
        let mut multiplier = multiplier;

        for &ch in &mut self.bytes {
            match ch {
                b'0'..=b'9' => {
                    value = if value != i64::MAX {
                        value.saturating_mul(10).saturating_add((ch - b'0') as i64)
                    } else {
                        (ch - b'0') as i64
                    };
                }
                b' ' => {
                    if value != i64::MAX {
                        self.stop_char = b' ';
                        return Ok(value * multiplier);
                    }
                }
                b'-' if value == i64::MAX => {
                    multiplier = -1;
                }
                b'+' if value == i64::MAX => (),
                b'\r' => (),
                _ => {
                    self.stop_char = ch;
                    return Ok(if value != i64::MAX {
                        value * multiplier
                    } else {
                        i64::MAX
                    });
                }
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn timestamp(&mut self) -> Result<i64, Error> {
        let mut dt = [0u32; 8];
        let mut zone_multiplier = 1;
        let mut pos = 0;
        let mut in_secfrac = false;

        for &ch in &mut self.bytes {
            match ch {
                b'0'..=b'9' if in_secfrac => (),
                b'0'..=b'9' if pos < 8 => {
                    dt[pos] = dt[pos]
                        .saturating_mul(10)
                        .saturating_add((ch - b'0') as u32);
                }
                b'-' if pos <= 1 || pos == 5 => {
                    pos += 1;
                    in_secfrac = false;
                }
                b'+' if pos == 5 => {
                    zone_multiplier = -1;
                    pos += 1;
                    in_secfrac = false;
                }
                b'T' | b't' if pos == 2 => {
                    pos += 1;
                }
                b':' if pos == 3 || pos == 4 || pos == 6 => {
                    pos += 1;
                }
                b'.' if pos == 5 && !in_secfrac => {
                    in_secfrac = true;
                }
                b'Z' | b'z' if pos == 5 => {
                    pos = 8;
                }
                _ => {
                    self.stop_char = ch;
                    return Ok(
                        if pos >= 7
                            && (1..=12).contains(&dt[1])
                            && (1..=31).contains(&dt[2])
                            && dt[3] <= 23
                            && dt[4] <= 59
                            && dt[5] <= 60
                            && dt[6] <= 23
                            && dt[7] <= 59
                        {
                            // Ported from https://github.com/protocolbuffers/upb/blob/22182e6e/upb/json_decode.c#L982-L992
                            let month = dt[1];
                            let year_base = 4800; /* Before min year, multiple of 400. */
                            let m_adj = month.wrapping_sub(3); /* March-based month. */
                            let carry = i64::from(m_adj > month);
                            let adjust = if carry > 0 { 12 } else { 0 };
                            let y_adj = dt[0] as i64 + year_base - carry;
                            let month_days =
                                ((m_adj.wrapping_add(adjust)).wrapping_mul(62719) + 769) / 2048;
                            let leap_days = y_adj / 4 - y_adj / 100 + y_adj / 400;
                            (y_adj * 365 + leap_days + month_days as i64 + (dt[2] as i64 - 1)
                                - 2472632)
                                * 86400
                                + dt[3] as i64 * 3600
                                + dt[4] as i64 * 60
                                + dt[5] as i64
                                + ((dt[6] as i64 * 3600 + dt[7] as i64 * 60) * zone_multiplier)
                        } else {
                            i64::MAX
                        },
                    );
                }
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn mail_from_parameters(
        &mut self,
        address: Cow<'y, str>,
    ) -> Result<MailFrom<Cow<'y, str>>, Error> {
        let mut params = MailFrom {
            address,
            flags: 0,
            size: 0,
            trans_id: None,
            by: 0,
            env_id: None,
            solicit: None,
            mtrk: None,
            auth: None,
            hold_for: 0,
            hold_until: 0,
            mt_priority: 0,
        };
        while self.stop_char != LF {
            let key = self.hashed_value_long()?;
            match key {
                SMTPUTF8 if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= MAIL_SMTPUTF8;
                }
                BODY if self.stop_char == b'=' => {
                    params.flags |= match self.hashed_value_long()? {
                        EIGHBITMIME if self.stop_char.is_ascii_whitespace() => MAIL_BODY_8BITMIME,
                        BINARYMIME if self.stop_char.is_ascii_whitespace() => MAIL_BODY_BINARYMIME,
                        SEVENBIT if self.stop_char.is_ascii_whitespace() => MAIL_BODY_7BIT,
                        _ => {
                            self.seek_lf()?;
                            return Err(Error::InvalidParameter { param: "BODY" });
                        }
                    }
                }
                SIZE if self.stop_char == b'=' => {
                    let size = self.size()?;
                    if size != usize::MAX && self.stop_char.is_ascii_whitespace() {
                        params.size = size;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "SIZE" });
                    }
                }
                BY if self.stop_char == b'=' => {
                    let time = self.integer()?;
                    if time != i64::MAX && self.stop_char == b';' {
                        params.flags |= match self.hashed_value()? {
                            N if self.stop_char.is_ascii_whitespace() => MAIL_BY_NOTIFY,
                            NT if self.stop_char.is_ascii_whitespace() => {
                                MAIL_BY_NOTIFY | MAIL_BY_TRACE
                            }
                            R if self.stop_char.is_ascii_whitespace() => MAIL_BY_RETURN,
                            RT if self.stop_char.is_ascii_whitespace() => {
                                MAIL_BY_RETURN | MAIL_BY_TRACE
                            }
                            _ => {
                                self.seek_lf()?;
                                return Err(Error::InvalidParameter { param: "BY" });
                            }
                        };
                        params.by = time;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "BY" });
                    }
                }
                HOLDUNTIL if self.stop_char == b'=' => {
                    let hold = self.timestamp()?;
                    if hold != i64::MAX && hold >= 0 && self.stop_char.is_ascii_whitespace() {
                        params.hold_until = hold as u64;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "HOLDUNTIL" });
                    }
                }
                HOLDFOR if self.stop_char == b'=' => {
                    let hold = self.size()?;
                    if (1..=MAX_FUTURE_RELEASE_INTERVAL).contains(&hold)
                        && self.stop_char.is_ascii_whitespace()
                    {
                        params.hold_for = hold as u64;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "HOLDFOR" });
                    }
                }
                RET if self.stop_char == b'=' => {
                    params.flags |= match self.hashed_value()? {
                        FULL if self.stop_char.is_ascii_whitespace() => MAIL_RET_FULL,
                        HDRS if self.stop_char.is_ascii_whitespace() => MAIL_RET_HDRS,
                        _ => {
                            self.seek_lf()?;
                            return Err(Error::InvalidParameter { param: "RET" });
                        }
                    };
                }
                ENVID if self.stop_char == b'=' => {
                    let env_id = self.xtext()?;
                    if self.stop_char.is_ascii_whitespace()
                        && (1..=100).contains(&env_id.len())
                        && XText(&env_id).is_printable()
                    {
                        params.env_id = env_id.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ENVID" });
                    }
                }
                REQUIRETLS if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= MAIL_REQUIRETLS;
                }
                SOLICIT if self.stop_char == b'=' => {
                    let solicit = self.text()?;
                    if !solicit.is_empty() && self.stop_char.is_ascii_whitespace() {
                        params.solicit = solicit.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "SOLICIT" });
                    }
                }
                TRANSID if self.stop_char == b'=' => {
                    if self.next_char()? == b'<' {
                        let transid = self.seek_char(b'>')?;
                        if self.stop_char == b'>' && !transid.is_empty() {
                            params.trans_id = transid.into();
                            self.stop_char = SP;
                            continue;
                        }
                    }
                    self.seek_lf()?;
                    return Err(Error::InvalidParameter { param: "TRANSID" });
                }
                MTRK if self.stop_char == b'=' => {
                    let certifier = self.seek_char(b':')?;
                    let timeout = if self.stop_char == b':' {
                        self.size()?
                    } else {
                        0
                    };

                    if !certifier.is_empty()
                        && self.stop_char.is_ascii_whitespace()
                        && timeout != usize::MAX
                    {
                        params.mtrk = Mtrk {
                            certifier,
                            timeout: timeout as u64,
                        }
                        .into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "MTRK" });
                    }
                }
                AUTH_ if self.stop_char == b'=' => {
                    let mailbox = self.xtext()?;
                    if (1..=MAX_ADDRESS_LEN).contains(&mailbox.len())
                        && self.stop_char.is_ascii_whitespace()
                    {
                        params.auth = mailbox.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "AUTH" });
                    }
                }
                MT_PRIORITY if self.stop_char == b'=' => {
                    let priority = self.integer()?;
                    if priority != i64::MAX && self.stop_char.is_ascii_whitespace() {
                        params.mt_priority = priority;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter {
                            param: "MT-PRIORITY",
                        });
                    }
                }
                CONPERM if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= MAIL_CONPERM;
                }
                0 => {
                    // hashed_value_long() returned 0, meaning no alphanumeric
                    // characters were found before hitting a non-keyword char.
                    // If stop_char is whitespace/LF this is just extra spacing
                    // between parameters (harmless). Otherwise it's garbage
                    // like ">", "!", etc. that should be rejected.
                    if !self.stop_char.is_ascii_whitespace() {
                        self.seek_lf()?;
                        return Err(Error::SyntaxError {
                            syntax: "MAIL FROM:<reverse-path> [parameters]",
                        });
                    }
                }
                unknown => {
                    let mut param = Vec::with_capacity(16);
                    for ch in unknown.to_le_bytes() {
                        if ch != 0 {
                            param.push(ch.to_ascii_uppercase());
                        }
                    }
                    if !self.stop_char.is_ascii_whitespace() {
                        param.push(self.stop_char.to_ascii_uppercase());
                        for &ch in &mut self.bytes {
                            if !ch.is_ascii_whitespace() {
                                param.push(ch.to_ascii_uppercase());
                            } else {
                                self.stop_char = ch;
                                break;
                            }
                        }
                    }

                    self.seek_lf()?;
                    return Err(Error::UnsupportedParameter {
                        param: param.into_string(),
                    });
                }
            }
        }

        Ok(params)
    }

    pub fn rcpt_to_parameters(
        &mut self,
        address: Cow<'y, str>,
    ) -> Result<RcptTo<Cow<'y, str>>, Error> {
        let mut params = RcptTo {
            address,
            orcpt: None,
            rrvs: 0,
            flags: 0,
        };
        while self.stop_char != LF {
            let key = self.hashed_value_long()?;
            match key {
                NOTIFY if self.stop_char == b'=' => loop {
                    match self.hashed_value_long()? {
                        NEVER
                            if (params.flags
                                & (RCPT_NOTIFY_NEVER
                                    | RCPT_NOTIFY_SUCCESS
                                    | RCPT_NOTIFY_FAILURE
                                    | RCPT_NOTIFY_DELAY))
                                == 0 =>
                        {
                            params.flags |= RCPT_NOTIFY_NEVER;
                        }
                        SUCCESS => {
                            params.flags |= RCPT_NOTIFY_SUCCESS;
                        }
                        FAILURE => {
                            params.flags |= RCPT_NOTIFY_FAILURE;
                        }
                        DELAY => {
                            params.flags |= RCPT_NOTIFY_DELAY;
                        }
                        _ => {
                            self.seek_lf()?;
                            return Err(Error::InvalidParameter { param: "NOTIFY" });
                        }
                    }
                    if self.stop_char.is_ascii_whitespace() {
                        break;
                    } else if self.stop_char != b',' {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "NOTIFY" });
                    }
                },
                ORCPT if self.stop_char == b'=' => {
                    let v = self.hashed_value()?;
                    if v != RFC822 || self.stop_char != b';' {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ORCPT" });
                    }
                    let addr = self.xtext()?;
                    if self.stop_char.is_ascii_whitespace()
                        && (1..=MAX_ADDRESS_LEN).contains(&addr.len())
                        && XText(&addr).is_printable()
                    {
                        params.orcpt = addr.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ORCPT" });
                    }
                }
                RRVS if self.stop_char == b'=' => {
                    let time = self.timestamp()?;
                    if time != i64::MAX && self.stop_char.is_ascii_whitespace()
                        || self.stop_char == b';'
                    {
                        let is_reject = self.stop_char != b';'
                            || match self.hashed_value()? {
                                C if self.stop_char.is_ascii_whitespace() => false,
                                R if self.stop_char.is_ascii_whitespace() => true,
                                _ => {
                                    self.seek_lf()?;
                                    return Err(Error::InvalidParameter { param: "RRVS" });
                                }
                            };
                        params.rrvs = time;
                        params.flags |= if is_reject {
                            RCPT_RRVS_REJECT
                        } else {
                            RCPT_RRVS_CONTINUE
                        };
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "RRVS" });
                    }
                }
                CONNEG if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= RCPT_CONNEG;
                }
                0 => {
                    if !self.stop_char.is_ascii_whitespace() {
                        self.seek_lf()?;
                        return Err(Error::SyntaxError {
                            syntax: "RCPT TO:<forward-path> [parameters]",
                        });
                    }
                }
                unknown => {
                    let mut param = Vec::with_capacity(16);
                    for ch in unknown.to_le_bytes() {
                        if ch != 0 {
                            param.push(ch.to_ascii_uppercase());
                        }
                    }
                    if !self.stop_char.is_ascii_whitespace() {
                        param.push(self.stop_char.to_ascii_uppercase());
                        for &ch in &mut self.bytes {
                            if !ch.is_ascii_whitespace() {
                                param.push(ch.to_ascii_uppercase());
                            } else {
                                self.stop_char = ch;
                                break;
                            }
                        }
                    }

                    self.seek_lf()?;
                    return Err(Error::UnsupportedParameter {
                        param: param.into_string(),
                    });
                }
            }
        }

        Ok(params)
    }

    pub fn mechanism(&mut self) -> Result<Option<u64>, Error> {
        let mut trailing_chars = [0u8; 8];
        let mut pos = 0;
        let mechanism = self.hashed_value_long()?;
        if !self.stop_char.is_ascii_whitespace() {
            trailing_chars[0] = self.stop_char;
            pos += 1;
            for &ch in &mut self.bytes {
                if !ch.is_ascii_whitespace() {
                    if let Some(tch) = trailing_chars.get_mut(pos) {
                        *tch = ch.to_ascii_uppercase();
                    }
                    pos += 1;
                } else {
                    self.stop_char = ch;
                    break;
                }
            }
            if !self.stop_char.is_ascii_whitespace() {
                return Err(Error::NeedsMoreData {
                    bytes_left: self.bytes_left,
                });
            } else if pos > 8 {
                return Ok(0.into());
            }
        }
        Ok(match (mechanism, &trailing_chars[..pos]) {
            (_9798_M_DSA_SHA1, b"") => AUTH_9798_M_DSA_SHA1.into(),
            (_9798_M_ECDSA_SHA, b"1") => AUTH_9798_M_ECDSA_SHA1.into(),
            (_9798_M_RSA_SHA1_, b"ENC") => AUTH_9798_M_RSA_SHA1_ENC.into(),
            (_9798_U_DSA_SHA1, b"") => AUTH_9798_U_DSA_SHA1.into(),
            (_9798_U_ECDSA_SHA, b"1") => AUTH_9798_U_ECDSA_SHA1.into(),
            (_9798_U_RSA_SHA1_, b"ENC") => AUTH_9798_U_RSA_SHA1_ENC.into(),
            (ANONYMOUS, b"") => AUTH_ANONYMOUS.into(),
            (CRAM_MD5, b"") => AUTH_CRAM_MD5.into(),
            (DIGEST_MD5, b"") => AUTH_DIGEST_MD5.into(),
            (EAP_AES128, b"") => AUTH_EAP_AES128.into(),
            (EAP_AES128_PLUS, b"") => AUTH_EAP_AES128_PLUS.into(),
            (ECDH_X25519_CHAL, b"LENGE") => AUTH_ECDH_X25519_CHALLENGE.into(),
            (ECDSA_NIST256P_C, b"HALLENGE") => AUTH_ECDSA_NIST256P_CHALLENGE.into(),
            (EXTERNAL, b"") => AUTH_EXTERNAL.into(),
            (GS2_KRB5, b"") => AUTH_GS2_KRB5.into(),
            (GS2_KRB5_PLUS, b"") => AUTH_GS2_KRB5_PLUS.into(),
            (GSS_SPNEGO, b"") => AUTH_GSS_SPNEGO.into(),
            (GSSAPI, b"") => AUTH_GSSAPI.into(),
            (KERBEROS_V4, b"") => AUTH_KERBEROS_V4.into(),
            (KERBEROS_V5, b"") => AUTH_KERBEROS_V5.into(),
            (LOGIN, b"") => AUTH_LOGIN.into(),
            (NMAS_SAMBA_AUTH, b"") => AUTH_NMAS_SAMBA_AUTH.into(),
            (NMAS_AUTHEN, b"") => AUTH_NMAS_AUTHEN.into(),
            (NMAS_LOGIN, b"") => AUTH_NMAS_LOGIN.into(),
            (NTLM, b"") => AUTH_NTLM.into(),
            (OAUTH10A, b"") => AUTH_OAUTH10A.into(),
            (OAUTHBEARER, b"") => AUTH_OAUTHBEARER.into(),
            (OPENID20, b"") => AUTH_OPENID20.into(),
            (OTP, b"") => AUTH_OTP.into(),
            (PLAIN, b"") => AUTH_PLAIN.into(),
            (SAML20, b"") => AUTH_SAML20.into(),
            (SCRAM_SHA_1, b"") => AUTH_SCRAM_SHA_1.into(),
            (SCRAM_SHA_1_PLUS, b"") => AUTH_SCRAM_SHA_1_PLUS.into(),
            (SCRAM_SHA_256, b"") => AUTH_SCRAM_SHA_256.into(),
            (SCRAM_SHA_256_PL, b"US") => AUTH_SCRAM_SHA_256_PLUS.into(),
            (SECURID, b"") => AUTH_SECURID.into(),
            (SKEY, b"") => AUTH_SKEY.into(),
            (SPNEGO, b"") => AUTH_SPNEGO.into(),
            (SPNEGO_PLUS, b"") => AUTH_SPNEGO_PLUS.into(),
            (SXOVER_PLUS, b"") => AUTH_SXOVER_PLUS.into(),
            (XOAUTH, b"") => AUTH_XOAUTH.into(),
            (XOAUTH2, b"") => AUTH_XOAUTH2.into(),
            (0, b"") => None,
            _ => 0.into(),
        })
    }

    /// Construct a new `MaybeZeroCopy`, beginning a potentially zero-copy read from the input.
    #[inline(always)]
    fn start_zero_copy(&self) -> MaybeZeroCopy<'y> {
        MaybeZeroCopy {
            remaining: self.bytes.as_slice(),
            data: Cow::Borrowed(""),
        }
    }

    /// Get the slice starting at the last time `MaybeZeroCopy` was flushed and ending one byte
    /// before where `Self` currently is. This is what will be pushed to the `MaybeZeroCopy` on
    /// flush.
    fn extra_before_current(&self, out: &MaybeZeroCopy<'y>) -> &'y [u8] {
        // Calculate the number of bytes we have advanced our iterator from the start of the
        // `MaybeZeroCopy`. Subtract one to remove the current byte.
        let new_len = self.bytes.as_slice().as_ptr().addr() - out.remaining.as_ptr().addr() - 1;
        &out.remaining[..new_len]
    }

    /// Get the length of a `MaybeZeroCopy`.
    fn len_excluding_current(&self, out: &MaybeZeroCopy<'y>) -> usize {
        out.data.len() + self.extra_before_current(out).len()
    }

    /// Get the first byte of a `MaybeZeroCopy`.
    fn first_excluding_current(&self, out: &MaybeZeroCopy<'y>) -> Option<u8> {
        out.data
            .bytes()
            .next()
            .or_else(|| self.extra_before_current(out).first().copied())
    }

    /// Drop data up to the current cursor from the `MaybeZeroCopy`.
    #[inline(always)]
    fn drop_extra(&self, out: &mut MaybeZeroCopy<'y>) {
        out.remaining = self.bytes.as_slice();
    }

    /// Extend a `MaybeZeroCopy` with new bytes.
    fn flush_excluding_current(&self, out: &mut MaybeZeroCopy<'y>) {
        let extra = self.extra_before_current(out);
        self.drop_extra(out);

        if extra.is_empty() {
            return;
        }

        if out.data.is_empty() {
            out.data = match from_utf8(extra) {
                Ok(valid) => Cow::Borrowed(valid),
                Err(_) => String::from_utf8_lossy(extra),
            };
        } else {
            if let Cow::Borrowed(s) = out.data {
                let mut buf = String::with_capacity(32);
                buf.push_str(s);
                out.data = Cow::Owned(buf);
            }

            // The same algorithm as `String::from_utf8_lossy`, but appending to an existing
            // buffer.
            let out = out.data.to_mut();
            for chunk in extra.utf8_chunks() {
                out.push_str(chunk.valid());
                if !chunk.invalid().is_empty() {
                    out.push(char::REPLACEMENT_CHARACTER);
                }
            }
        }
    }
}

/// A state machine enabling parsing to be potentially zero-copy.
struct MaybeZeroCopy<'y> {
    /// Slice from where we start parsing to the end of the input.
    remaining: &'y [u8],
    /// The data itself.
    data: Cow<'y, str>,
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/smtp-proto/src/request/parser/tests.rs"]
mod tests;
