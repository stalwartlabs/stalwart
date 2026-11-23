/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;

use memchr::{memchr2, memchr3};

use crate::convert::{code_page_charset, hex_value};

const MAX_DEPTH: usize = 256;
const MAX_WORD_LEN: usize = 32;
const MAX_PARAM_DIGITS: usize = 10;
const DETECT_TOKENS: usize = 10;
const MAX_FONTS: usize = 256;
const DEFAULT_CODE_PAGE: u16 = 1252;
const DEFAULT_UC: u8 = 1;
const UNICODE_WRAP: i32 = 0x1_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deencapsulated {
    Html,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Html,
    Text,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    Word { name: &'a [u8], param: Option<i32> },
    Symbol(u8),
    Hex(u8),
    Text(&'a [u8]),
}

struct Lexer<'a> {
    rest: &'a [u8],
}

impl<'a> Lexer<'a> {
    fn next(&mut self) -> Option<Token<'a>> {
        loop {
            let (&first, tail) = self.rest.split_first()?;
            match first {
                b'\r' | b'\n' => self.rest = tail,
                b'{' => {
                    self.rest = tail;
                    return Some(Token::Open);
                }
                b'}' => {
                    self.rest = tail;
                    return Some(Token::Close);
                }
                b'\\' => {
                    self.rest = tail;
                    return self.control();
                }
                _ => {
                    let end = memchr3(b'\\', b'{', b'}', self.rest).unwrap_or(self.rest.len());
                    let end = self
                        .rest
                        .get(..end)
                        .and_then(|run| memchr2(b'\r', b'\n', run))
                        .unwrap_or(end);
                    let (text, rest) = self.rest.split_at_checked(end)?;
                    self.rest = rest;
                    return Some(Token::Text(text));
                }
            }
        }
    }

    fn control(&mut self) -> Option<Token<'a>> {
        let (&first, tail) = self.rest.split_first()?;
        if first.is_ascii_alphabetic() {
            let len = self
                .rest
                .iter()
                .take_while(|b| b.is_ascii_alphabetic())
                .count();
            let (name, rest) = self.rest.split_at_checked(len)?;
            self.rest = rest;
            let param = self.param();
            if let Some(rest) = self.rest.strip_prefix(b" ") {
                self.rest = rest;
            }
            let name = name.get(..MAX_WORD_LEN).unwrap_or(name);
            return Some(Token::Word { name, param });
        }
        self.rest = tail;
        match first {
            b'\'' => {
                let Some((&[high, low], rest)) = self.rest.split_first_chunk::<2>() else {
                    return Some(Token::Symbol(first));
                };
                match (hex_value(high), hex_value(low)) {
                    (Some(high), Some(low)) => {
                        self.rest = rest;
                        Some(Token::Hex((high << 4) | low))
                    }
                    _ => Some(Token::Symbol(first)),
                }
            }
            b'\r' | b'\n' => Some(Token::Word {
                name: b"par",
                param: None,
            }),
            other => Some(Token::Symbol(other)),
        }
    }

    fn param(&mut self) -> Option<i32> {
        let (negative, digits_start) = match self.rest.strip_prefix(b"-") {
            Some(rest) if rest.first().is_some_and(u8::is_ascii_digit) => (true, rest),
            _ => (false, self.rest),
        };
        let len = digits_start
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        if len == 0 {
            return None;
        }
        let (digits, rest) = digits_start.split_at_checked(len)?;
        self.rest = rest;
        let value = digits.iter().take(MAX_PARAM_DIGITS).fold(0i64, |acc, d| {
            acc.saturating_mul(10)
                .saturating_add(i64::from(d.saturating_sub(b'0')))
        });
        let value = if negative {
            value.saturating_neg()
        } else {
            value
        };
        Some(i32::try_from(value.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0))
    }

    fn skip_bytes(&mut self, n: usize) {
        self.rest = self.rest.get(n..).unwrap_or_default();
    }
}

#[derive(Debug, Clone, Copy)]
struct Group {
    skip: bool,
    suppress: bool,
    font_table: bool,
    code_page: u16,
    uc: u8,
}

struct Extractor<'o> {
    mode: Mode,
    group: Group,
    stack: Vec<Group>,
    overflow: u32,
    fonts: Vec<(i32, u16)>,
    font_entry: Option<i32>,
    default_code_page: u16,
    pending: Vec<u8>,
    pending_code_page: u16,
    unicode_skip: u32,
    high_surrogate: Option<u16>,
    group_start: bool,
    star: bool,
    out: &'o mut String,
}

impl<'o> Extractor<'o> {
    fn new(mode: Mode, out: &'o mut String) -> Self {
        Extractor {
            mode,
            group: Group {
                skip: false,
                suppress: false,
                font_table: false,
                code_page: DEFAULT_CODE_PAGE,
                uc: DEFAULT_UC,
            },
            stack: Vec::new(),
            overflow: 0,
            fonts: Vec::new(),
            font_entry: None,
            default_code_page: DEFAULT_CODE_PAGE,
            pending: Vec::new(),
            pending_code_page: DEFAULT_CODE_PAGE,
            unicode_skip: 0,
            high_surrogate: None,
            group_start: false,
            star: false,
            out,
        }
    }

    fn run(&mut self, rtf: &[u8]) {
        let mut lexer = Lexer { rest: rtf };
        while let Some(token) = lexer.next() {
            let group_start = std::mem::take(&mut self.group_start);
            match token {
                Token::Open => self.open(),
                Token::Close => self.close(),
                Token::Symbol(b'*') if group_start => {
                    self.star = true;
                    self.group_start = true;
                }
                Token::Word { name, param } => {
                    let star = std::mem::take(&mut self.star);
                    if star {
                        self.destination(name);
                    }
                    if self.consume_skip() {
                        continue;
                    }
                    if name == b"bin" {
                        let len = param.and_then(|p| usize::try_from(p).ok()).unwrap_or(0);
                        lexer.skip_bytes(len);
                        continue;
                    }
                    self.word(name, param);
                }
                other => {
                    if std::mem::take(&mut self.star) {
                        self.group.skip = true;
                    }
                    match other {
                        Token::Symbol(symbol) => self.symbol(symbol),
                        Token::Hex(byte) => {
                            if !self.consume_skip() {
                                self.byte(byte);
                            }
                        }
                        Token::Text(text) => self.text(text),
                        Token::Open | Token::Close | Token::Word { .. } => {}
                    }
                }
            }
        }
        self.flush();
    }

    fn emitting(&self) -> bool {
        !self.group.skip && !self.group.suppress
    }

    fn consume_skip(&mut self) -> bool {
        if self.unicode_skip > 0 {
            self.unicode_skip = self.unicode_skip.saturating_sub(1);
            true
        } else {
            false
        }
    }

    fn open(&mut self) {
        self.flush();
        if self.stack.len() < MAX_DEPTH {
            self.stack.push(self.group);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
        self.unicode_skip = 0;
        self.star = false;
        self.group_start = true;
    }

    fn close(&mut self) {
        self.flush();
        self.unicode_skip = 0;
        self.star = false;
        if self.overflow > 0 {
            self.overflow = self.overflow.saturating_sub(1);
        } else if let Some(group) = self.stack.pop() {
            if self.group.font_table && !group.font_table {
                self.font_entry = None;
            }
            self.group = group;
        }
    }

    fn destination(&mut self, name: &[u8]) {
        if self.mode == Mode::Html && name == b"htmltag" {
            self.group.skip = false;
            self.group.suppress = false;
            self.group.code_page = self.default_code_page;
        } else {
            self.group.skip = true;
        }
    }

    fn word(&mut self, name: &[u8], param: Option<i32>) {
        hashify::fnc_map!(name,
            b"par" => self.emit_str("\r\n"),
            b"line" => self.emit_str("\r\n"),
            b"row" => self.emit_str("\r\n"),
            b"sect" => self.emit_str("\r\n"),
            b"page" => self.emit_str("\r\n"),
            b"tab" => self.emit_char('\t'),
            b"cell" => self.emit_char('\t'),
            b"emdash" => self.emit_char('\u{2014}'),
            b"endash" => self.emit_char('\u{2013}'),
            b"emspace" => self.emit_char('\u{2003}'),
            b"enspace" => self.emit_char('\u{2002}'),
            b"bullet" => self.emit_char('\u{2022}'),
            b"lquote" => self.emit_char('\u{2018}'),
            b"rquote" => self.emit_char('\u{2019}'),
            b"ldblquote" => self.emit_char('\u{201C}'),
            b"rdblquote" => self.emit_char('\u{201D}'),
            b"u" => self.unicode(param),
            b"uc" => {
                self.group.uc = param
                    .and_then(|p| u8::try_from(p.clamp(0, i32::from(u8::MAX))).ok())
                    .unwrap_or(DEFAULT_UC);
            },
            b"f" => self.font(param),
            b"fcharset" => {
                if let Some(code_page) = param.and_then(charset_code_page) {
                    self.set_font_code_page(code_page);
                }
            },
            b"cpg" => {
                if let Some(code_page) = param.and_then(|p| u16::try_from(p).ok()) {
                    self.set_font_code_page(code_page);
                }
            },
            b"ansicpg" => {
                if let Some(code_page) = param.and_then(|p| u16::try_from(p).ok()) {
                    self.default_code_page = code_page;
                    self.group.code_page = code_page;
                }
            },
            b"htmlrtf" => {
                if self.mode != Mode::Plain {
                    self.group.suppress = param != Some(0);
                }
            },
            b"fonttbl" => {
                self.group.font_table = true;
                self.group.skip = true;
            },
            _ => {
                if is_skipped_destination(name) {
                    self.group.skip = true;
                }
            }
        );
    }

    fn symbol(&mut self, symbol: u8) {
        if self.consume_skip() {
            return;
        }
        match symbol {
            b'\\' | b'{' | b'}' => self.byte(symbol),
            b'~' => self.emit_char('\u{A0}'),
            b'_' => self.emit_char('\u{2011}'),
            _ => {}
        }
    }

    fn text(&mut self, text: &[u8]) {
        let skip = usize::try_from(self.unicode_skip)
            .unwrap_or(usize::MAX)
            .min(text.len());
        self.unicode_skip = self
            .unicode_skip
            .saturating_sub(u32::try_from(skip).unwrap_or(u32::MAX));
        let text = text.get(skip..).unwrap_or_default();
        if text.is_empty() || !self.emitting() {
            return;
        }
        self.high_surrogate = None;
        if self.pending_code_page != self.group.code_page {
            self.flush();
            self.pending_code_page = self.group.code_page;
        }
        self.pending.extend_from_slice(text);
    }

    fn byte(&mut self, byte: u8) {
        self.text(std::slice::from_ref(&byte));
    }

    fn font(&mut self, param: Option<i32>) {
        if self.group.font_table {
            self.font_entry = param;
            return;
        }
        let code_page = param
            .and_then(|id| {
                self.fonts
                    .iter()
                    .find(|(font, _)| *font == id)
                    .map(|(_, cp)| *cp)
            })
            .unwrap_or(self.default_code_page);
        self.group.code_page = code_page;
    }

    fn set_font_code_page(&mut self, code_page: u16) {
        if !self.group.font_table {
            return;
        }
        let Some(id) = self.font_entry else {
            return;
        };
        if let Some(entry) = self.fonts.iter_mut().find(|(font, _)| *font == id) {
            entry.1 = code_page;
        } else if self.fonts.len() < MAX_FONTS {
            self.fonts.push((id, code_page));
        }
    }

    fn unicode(&mut self, param: Option<i32>) {
        self.unicode_skip = u32::from(self.group.uc);
        let Some(param) = param else {
            return;
        };
        if !self.emitting() {
            return;
        }
        let value = if param < 0 {
            param.saturating_add(UNICODE_WRAP)
        } else {
            param
        };
        let Ok(unit) = u16::try_from(value) else {
            return;
        };
        self.flush();
        match unit {
            0xD800..=0xDBFF => self.high_surrogate = Some(unit),
            0xDC00..=0xDFFF => {
                if let Some(high) = self.high_surrogate.take() {
                    let ch = char::decode_utf16([high, unit])
                        .next()
                        .and_then(Result::ok)
                        .unwrap_or(char::REPLACEMENT_CHARACTER);
                    self.out.push(ch);
                }
            }
            _ => {
                self.high_surrogate = None;
                self.out
                    .push(char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER));
            }
        }
    }

    fn emit_char(&mut self, ch: char) {
        if self.emitting() {
            self.flush();
            self.high_surrogate = None;
            self.out.push(ch);
        }
    }

    fn emit_str(&mut self, s: &str) {
        if self.emitting() {
            self.flush();
            self.high_surrogate = None;
            self.out.push_str(s);
        }
    }

    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        code_page_charset(self.pending_code_page).decode_append(&self.pending, self.out);
        self.pending.clear();
    }
}

fn is_skipped_destination(name: &[u8]) -> bool {
    hashify::set!(
        name,
        b"colortbl",
        b"stylesheet",
        b"info",
        b"pict",
        b"object",
        b"objdata",
        b"nonshppict",
        b"header",
        b"headerl",
        b"headerr",
        b"headerf",
        b"footer",
        b"footerl",
        b"footerr",
        b"footerf",
        b"footnote",
        b"fldinst",
        b"listtable",
        b"listoverridetable",
        b"rsidtbl",
        b"generator",
        b"xmlnstbl",
        b"themedata",
        b"colorschememapping",
        b"datastore",
        b"latentstyles",
        b"revtbl",
        b"filetbl",
        b"pgdsctbl",
        b"mmathPr",
        b"private",
        b"userprops",
        b"docvar",
        b"background",
        b"shpinst",
        b"template",
        b"xe",
        b"tc",
        b"txe",
        b"bkmkstart",
        b"bkmkend",
        b"falt",
        b"panose",
        b"protusertbl",
        b"wgrffmtfilter",
        b"author",
        b"operator",
        b"title",
        b"subject",
        b"keywords",
        b"comment",
        b"company",
        b"doccomm"
    )
}

fn charset_code_page(charset: i32) -> Option<u16> {
    Some(match charset {
        0 | 2 => 1252,
        1 => return None,
        77 => 10000,
        128 => 932,
        129 => 949,
        134 => 936,
        136 => 950,
        161 => 1253,
        162 => 1254,
        163 => 1258,
        177 => 1255,
        178 => 1256,
        186 => 1257,
        204 => 1251,
        222 => 874,
        238 => 1250,
        255 => 850,
        _ => return None,
    })
}

fn detect(rtf: &[u8]) -> Option<Deencapsulated> {
    let mut lexer = Lexer { rest: rtf };
    for _ in 0..DETECT_TOKENS {
        match lexer.next()? {
            Token::Word {
                name: b"fromhtml",
                param: Some(1),
            } => return Some(Deencapsulated::Html),
            Token::Word {
                name: b"fromtext", ..
            } => return Some(Deencapsulated::Text),
            _ => {}
        }
    }
    None
}

pub fn rtf_deencapsulate(rtf: &[u8], out: &mut Vec<u8>) -> Option<Deencapsulated> {
    let kind = detect(rtf)?;
    let mode = match kind {
        Deencapsulated::Html => Mode::Html,
        Deencapsulated::Text => Mode::Text,
    };
    if out.is_empty() {
        let mut text = String::from_utf8(mem::take(out)).unwrap_or_default();
        Extractor::new(mode, &mut text).run(rtf);
        *out = text.into_bytes();
    } else {
        let mut text = String::new();
        Extractor::new(mode, &mut text).run(rtf);
        out.extend_from_slice(text.as_bytes());
    }
    Some(kind)
}

pub fn rtf_to_plain(rtf: &[u8], out: &mut String) {
    let mode = match detect(rtf) {
        Some(Deencapsulated::Text) => Mode::Text,
        Some(Deencapsulated::Html) | None => Mode::Plain,
    };
    Extractor::new(mode, out).run(rtf);
}
