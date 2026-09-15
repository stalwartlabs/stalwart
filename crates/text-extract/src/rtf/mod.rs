/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod codepage;
mod words;

use crate::output::{Output, Separator};
use encoding_rs::{CoderResult, Decoder, Encoding, WINDOWS_1252};
use memchr::memchr3;
use words::Word;

const SIGNATURE: &[u8] = b"{\\rtf";
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
const MAX_WORD: usize = 32;
const MAX_DIGITS: usize = 10;
const MAX_PENDING: usize = 4096;
const MAX_FONTS: usize = 4096;
const MAX_SKIP: i64 = 64;
const DECODE_CHUNK: usize = 256;

pub(crate) fn is_rtf(data: &[u8]) -> bool {
    body(data).starts_with(SIGNATURE)
}

fn body(data: &[u8]) -> &[u8] {
    data.strip_prefix(UTF8_BOM)
        .unwrap_or(data)
        .trim_ascii_start()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Destination {
    Text,
    FontTable,
    Ignored,
}

#[derive(Debug, Clone, Copy)]
struct Group {
    destination: Destination,
    skip_after_unicode: u32,
    encoding: Option<&'static Encoding>,
    html_rtf: bool,
}

#[derive(Default)]
pub(crate) struct Scratch {
    stack: Vec<Group>,
    fonts: Vec<(i64, &'static Encoding)>,
    pending: Vec<u8>,
}

struct Parser<'s, 'o, 'b> {
    scratch: &'s mut Scratch,
    out: &'o mut Output<'b>,
    group: Group,
    overflow: u64,
    max_depth: usize,
    document_encoding: &'static Encoding,
    default_font: Option<i64>,
    table_font: Option<i64>,
    from_html: bool,
    ignorable: bool,
    skip: u32,
    high_surrogate: Option<u16>,
    decoder: Option<Decoder>,
}

pub(crate) fn extract(data: &[u8], scratch: &mut Scratch, max_depth: usize, out: &mut Output<'_>) {
    scratch.stack.clear();
    scratch.fonts.clear();
    scratch.pending.clear();
    let mut parser = Parser {
        scratch,
        out,
        group: Group {
            destination: Destination::Text,
            skip_after_unicode: 1,
            encoding: None,
            html_rtf: false,
        },
        overflow: 0,
        max_depth: max_depth.max(1),
        document_encoding: WINDOWS_1252,
        default_font: None,
        table_font: None,
        from_html: false,
        ignorable: false,
        skip: 0,
        high_surrogate: None,
        decoder: None,
    };
    parser.run(body(data));
    parser.flush();
}

impl Parser<'_, '_, '_> {
    fn run(&mut self, mut rest: &[u8]) {
        while let Some((&byte, tail)) = rest.split_first() {
            if self.out.is_full() {
                return;
            }
            rest = match byte {
                b'{' => {
                    self.open_group();
                    tail
                }
                b'}' => {
                    if !self.close_group() {
                        return;
                    }
                    tail
                }
                b'\\' => self.control(tail),
                b'\r' | b'\n' => tail,
                _ => self.text(rest),
            };
        }
    }

    fn open_group(&mut self) {
        self.flush();
        self.skip = 0;
        self.ignorable = false;
        if self.scratch.stack.len() < self.max_depth {
            self.scratch.stack.push(self.group);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    fn close_group(&mut self) -> bool {
        self.flush();
        self.skip = 0;
        self.ignorable = false;
        if self.overflow > 0 {
            self.overflow -= 1;
            return true;
        }
        let Some(parent) = self.scratch.stack.pop() else {
            return false;
        };
        self.group = parent;
        !self.scratch.stack.is_empty()
    }

    fn suppressed(&self) -> bool {
        self.group.destination != Destination::Text || (self.from_html && self.group.html_rtf)
    }

    fn text<'a>(&mut self, rest: &'a [u8]) -> &'a [u8] {
        self.ignorable = false;
        let run_len = memchr3(b'\\', b'{', b'}', rest).unwrap_or(rest.len());
        let (run, tail) = rest.split_at(run_len);
        let mut run = run;
        while self.skip > 0 {
            match run.split_first() {
                Some((b'\r' | b'\n', remaining)) => run = remaining,
                Some((_, remaining)) => {
                    run = remaining;
                    self.skip -= 1;
                }
                None => break,
            }
        }
        if self.suppressed() {
            return tail;
        }
        for line in run.split(|&byte| byte == b'\r' || byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if self.scratch.pending.is_empty() && line.is_ascii() {
                self.out.push_utf8(line);
            } else {
                self.scratch.pending.extend_from_slice(line);
                if self.scratch.pending.len() > MAX_PENDING {
                    self.decode_pending(false);
                }
            }
        }
        tail
    }

    fn control<'a>(&mut self, rest: &'a [u8]) -> &'a [u8] {
        let Some((&first, tail)) = rest.split_first() else {
            return rest;
        };
        if first.is_ascii_alphabetic() {
            return self.control_word(rest);
        }
        if first == b'\'' {
            return self.hex_byte(tail);
        }
        self.flush();
        if self.skip > 0 {
            self.skip -= 1;
            return tail;
        }
        match first {
            b'*' => {
                self.ignorable = true;
                return tail;
            }
            b'\\' | b'{' | b'}' => {
                if !self.suppressed() {
                    self.out.push_char(char::from(first));
                }
            }
            b'~' => self.push_char('\u{a0}'),
            b'_' => self.push_char('-'),
            b'\r' | b'\n' => self.separator(Separator::Newline),
            _ => {}
        }
        self.ignorable = false;
        tail
    }

    fn hex_byte<'a>(&mut self, rest: &'a [u8]) -> &'a [u8] {
        self.ignorable = false;
        let value = rest.get(..2).and_then(|hex| {
            let high = char::from(*hex.first()?).to_digit(16)?;
            let low = char::from(*hex.get(1)?).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        });
        let Some(value) = value else {
            return rest;
        };
        let tail = rest.get(2..).unwrap_or_default();
        if self.skip > 0 {
            self.skip -= 1;
        } else if !self.suppressed() {
            self.scratch.pending.push(value);
            if self.scratch.pending.len() > MAX_PENDING {
                self.decode_pending(false);
            }
        }
        tail
    }

    fn control_word<'a>(&mut self, rest: &'a [u8]) -> &'a [u8] {
        let letters = rest
            .iter()
            .position(|byte| !byte.is_ascii_alphabetic())
            .unwrap_or(rest.len());
        let (name, mut tail) = rest.split_at(letters);
        let negative = tail.first() == Some(&b'-');
        if negative {
            tail = tail.get(1..).unwrap_or_default();
        }
        let digits = tail
            .iter()
            .position(|byte| !byte.is_ascii_digit())
            .unwrap_or(tail.len());
        let (number, after) = tail.split_at(digits);
        let parameter = (!number.is_empty()).then(|| {
            let magnitude = number
                .iter()
                .take(MAX_DIGITS)
                .fold(0i64, |value, &digit| value * 10 + i64::from(digit - b'0'));
            if negative { -magnitude } else { magnitude }
        });
        let tail = match after.split_first() {
            Some((b' ', remaining)) => remaining,
            _ => after,
        };
        let word = if name.len() <= MAX_WORD {
            Word::parse(name)
        } else {
            None
        };
        if word == Some(Word::Bin) {
            let skip = usize::try_from(parameter.unwrap_or(0).max(0)).unwrap_or(usize::MAX);
            let tail = tail.get(skip..).unwrap_or_default();
            if self.skip > 0 {
                self.skip -= 1;
            }
            self.ignorable = false;
            return tail;
        }
        self.flush();
        if self.skip > 0 {
            self.skip -= 1;
            self.ignorable = false;
            return tail;
        }
        let ignorable = std::mem::replace(&mut self.ignorable, false);
        self.apply(word, parameter, ignorable);
        tail
    }

    fn apply(&mut self, word: Option<Word>, parameter: Option<i64>, ignorable: bool) {
        let Some(word) = word.filter(|word| {
            !ignorable || matches!(word, Word::UnicodeDestination | Word::ShapeInstructions)
        }) else {
            if ignorable {
                self.group.destination = Destination::Ignored;
            }
            return;
        };
        match word {
            Word::AnsiCodePage => {
                if let Some(encoding) = parameter.and_then(codepage::from_codepage) {
                    self.document_encoding = encoding;
                }
            }
            Word::Mac => self.document_encoding = encoding_rs::MACINTOSH,
            Word::Ansi => self.document_encoding = WINDOWS_1252,
            Word::DefaultFont => self.default_font = parameter,
            Word::FromHtml => self.from_html = true,
            Word::HtmlRtf => self.group.html_rtf = parameter != Some(0),
            Word::FontTable => self.group.destination = Destination::FontTable,
            Word::Font => {
                if self.group.destination == Destination::FontTable {
                    self.table_font = parameter;
                } else if let Some(font) = parameter {
                    self.group.encoding = self.font_encoding(font);
                }
            }
            Word::FontCharset | Word::FontCodePage => {
                if self.group.destination == Destination::FontTable
                    && let (Some(font), Some(value)) = (self.table_font, parameter)
                {
                    let encoding = if word == Word::FontCharset {
                        codepage::from_charset(value)
                    } else {
                        codepage::from_codepage(value)
                    };
                    if let Some(encoding) = encoding {
                        self.insert_font(font, encoding);
                    }
                }
            }
            Word::Plain => self.group.encoding = None,
            Word::UnicodeSkip => {
                self.group.skip_after_unicode =
                    u32::try_from(parameter.unwrap_or(1).clamp(0, MAX_SKIP)).unwrap_or(1)
            }
            Word::Unicode => self.unicode(parameter.unwrap_or(0)),
            Word::Paragraph => self.separator(Separator::Newline),
            Word::Tab => self.separator(Separator::Space),
            Word::Character(ch) => self.push_char(ch),
            Word::UnicodeDestination => {
                if self.group.destination == Destination::Ignored {
                    self.group.destination = Destination::Text;
                }
            }
            Word::ShapeInstructions | Word::Bin => {}
            Word::Destination => self.group.destination = Destination::Ignored,
        }
    }

    fn unicode(&mut self, parameter: i64) {
        self.skip = self.group.skip_after_unicode;
        let Ok(unit) = u16::try_from(if parameter < 0 {
            parameter + 0x10000
        } else {
            parameter
        }) else {
            return;
        };
        let ch = match unit {
            0xD800..=0xDBFF => {
                self.high_surrogate = Some(unit);
                return;
            }
            0xDC00..=0xDFFF => self.high_surrogate.take().and_then(|high| {
                char::from_u32(
                    0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00),
                )
            }),
            _ => {
                self.high_surrogate = None;
                char::from_u32(u32::from(unit))
            }
        };
        if let Some(ch) = ch {
            self.flush();
            self.push_char(ch);
        }
    }

    fn push_char(&mut self, ch: char) {
        if !self.suppressed() {
            self.out.push_char(ch);
        }
    }

    fn separator(&mut self, separator: Separator) {
        if self.group.destination == Destination::Text {
            self.out.separator(separator);
        }
    }

    fn font_encoding(&self, font: i64) -> Option<&'static Encoding> {
        self.scratch
            .fonts
            .binary_search_by_key(&font, |&(number, _)| number)
            .ok()
            .and_then(|index| self.scratch.fonts.get(index))
            .map(|&(_, encoding)| encoding)
    }

    fn insert_font(&mut self, font: i64, encoding: &'static Encoding) {
        match self
            .scratch
            .fonts
            .binary_search_by_key(&font, |&(number, _)| number)
        {
            Ok(index) => {
                if let Some(slot) = self.scratch.fonts.get_mut(index) {
                    slot.1 = encoding;
                }
            }
            Err(index) if self.scratch.fonts.len() < MAX_FONTS => {
                self.scratch.fonts.insert(index, (font, encoding))
            }
            Err(_) => {}
        }
    }

    fn flush(&mut self) {
        if !self.scratch.pending.is_empty() || self.decoder.is_some() {
            self.decode_pending(true);
        }
    }

    fn decode_pending(&mut self, last: bool) {
        let encoding = self
            .group
            .encoding
            .or_else(|| self.default_font.and_then(|font| self.font_encoding(font)))
            .unwrap_or(self.document_encoding);
        let decoder = self
            .decoder
            .get_or_insert_with(|| encoding.new_decoder_without_bom_handling());
        let mut buffer = [0u8; DECODE_CHUNK];
        let mut source = self.scratch.pending.as_slice();
        loop {
            let (result, read, written, _) = decoder.decode_to_utf8(source, &mut buffer, last);
            self.out
                .push_utf8(buffer.get(..written).unwrap_or_default());
            source = source.get(read..).unwrap_or_default();
            if result == CoderResult::InputEmpty {
                break;
            }
        }
        self.scratch.pending.clear();
        if last {
            self.decoder = None;
        }
    }
}
