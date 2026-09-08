/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::decoders::html::add_html_token;
use std::borrow::Cow;

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum HtmlToken<'x> {
    StartTag {
        name: u64,
        attributes: Vec<(u64, Option<Cow<'x, str>>)>,
        is_self_closing: bool,
    },
    EndTag {
        name: u64,
    },
    Comment {
        text: Cow<'x, str>,
    },
    Text {
        text: Cow<'x, str>,
    },
}

pub(crate) const A: u64 = b'a' as u64;
pub(crate) const IMG: u64 = (b'i' as u64) | ((b'm' as u64) << 8) | ((b'g' as u64) << 16);
pub(crate) const HEAD: u64 =
    (b'h' as u64) | ((b'e' as u64) << 8) | ((b'a' as u64) << 16) | ((b'd' as u64) << 24);
pub(crate) const BODY: u64 =
    (b'b' as u64) | ((b'o' as u64) << 8) | ((b'd' as u64) << 16) | ((b'y' as u64) << 24);
pub(crate) const META: u64 =
    (b'm' as u64) | ((b'e' as u64) << 8) | ((b't' as u64) << 16) | ((b'a' as u64) << 24);
pub(crate) const LINK: u64 =
    (b'l' as u64) | ((b'i' as u64) << 8) | ((b'n' as u64) << 16) | ((b'k' as u64) << 24);
pub(crate) const ALT: u64 = (b'a' as u64) | ((b'l' as u64) << 8) | ((b't' as u64) << 16);
pub(crate) const TITLE: u64 = (b't' as u64)
    | ((b'i' as u64) << 8)
    | ((b't' as u64) << 16)
    | ((b'l' as u64) << 24)
    | ((b'e' as u64) << 32);

pub(crate) const HREF: u64 =
    (b'h' as u64) | ((b'r' as u64) << 8) | ((b'e' as u64) << 16) | ((b'f' as u64) << 24);
pub(crate) const SRC: u64 = (b's' as u64) | ((b'r' as u64) << 8) | ((b'c' as u64) << 16);
pub(crate) const WIDTH: u64 = (b'w' as u64)
    | ((b'i' as u64) << 8)
    | ((b'd' as u64) << 16)
    | ((b't' as u64) << 24)
    | ((b'h' as u64) << 32);
pub(crate) const HEIGHT: u64 = (b'h' as u64)
    | ((b'e' as u64) << 8)
    | ((b'i' as u64) << 16)
    | ((b'g' as u64) << 24)
    | ((b'h' as u64) << 32)
    | ((b't' as u64) << 40);
pub(crate) const REL: u64 = (b'r' as u64) | ((b'e' as u64) << 8) | ((b'l' as u64) << 16);
pub(crate) const CONTENT: u64 = (b'c' as u64)
    | ((b'o' as u64) << 8)
    | ((b'n' as u64) << 16)
    | ((b't' as u64) << 24)
    | ((b'e' as u64) << 32)
    | ((b'n' as u64) << 40)
    | ((b't' as u64) << 48);
pub(crate) const HTTP_EQUIV: u64 = (b'h' as u64)
    | ((b't' as u64) << 8)
    | ((b't' as u64) << 16)
    | ((b'p' as u64) << 24)
    | ((b'-' as u64) << 32)
    | ((b'e' as u64) << 40)
    | ((b'q' as u64) << 48)
    | ((b'u' as u64) << 56);

pub(crate) const fn byte_table(bytes: &[u8]) -> [bool; 256] {
    let mut table = [false; 256];
    let mut index = 0;
    while index < bytes.len() {
        table[bytes[index] as usize] = true;
        index += 1;
    }
    table
}

pub(crate) static TEXT_STOP: [bool; 256] = byte_table(b"<&; \t\r\n");
static COMMENT_SPACE: [bool; 256] = byte_table(b" \t\r\n");
static VALUE_STOP: [bool; 256] = byte_table(b">\" \t\r\n");
static TAG_KEY_STOP: [bool; 256] = key_stop_table();
static TAG_KEY_FOLD: [u8; 256] = key_fold_table();

const REUSE_BUFFER_LEN: usize = 1024;

const fn key_fold_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        let ch = index as u8;
        table[index] = if ch.is_ascii_uppercase() {
            ch - b'A' + b'a'
        } else {
            ch
        };
        index += 1;
    }
    table
}

const fn key_stop_table() -> [bool; 256] {
    let mut table = [true; 256];
    let mut index = 0;
    while index < 256 {
        let ch = index as u8;
        if ch.is_ascii_lowercase()
            || ch.is_ascii_uppercase()
            || ch.is_ascii_digit()
            || ch == b'-'
            || ch == b'_'
        {
            table[index] = false;
        }
        index += 1;
    }
    table
}

#[inline(always)]
pub(crate) fn scan_until(bytes: &[u8], from: usize, stop: &[bool; 256]) -> usize {
    match bytes.get(from..) {
        Some(rest) => rest
            .iter()
            .position(|&ch| stop[ch as usize])
            .map_or(bytes.len(), |offset| from + offset),
        None => bytes.len(),
    }
}

const SWAR_ONES: u64 = 0x0101_0101_0101_0101;
const SWAR_HIGH: u64 = 0x8080_8080_8080_8080;

#[inline(always)]
fn scan_until_byte(bytes: &[u8], from: usize, needle: u8) -> usize {
    let mut pos = from;
    let broadcast = SWAR_ONES.wrapping_mul(needle as u64);
    while let Some(chunk) = bytes.get(pos..).and_then(|rest| rest.first_chunk::<8>()) {
        let word = u64::from_le_bytes(*chunk) ^ broadcast;
        let found = word.wrapping_sub(SWAR_ONES) & !word & SWAR_HIGH;
        if found != 0 {
            return pos + (found.trailing_zeros() / 8) as usize;
        }
        pos += 8;
    }
    match bytes.get(pos..) {
        Some(rest) => rest
            .iter()
            .position(|&ch| ch == needle)
            .map_or(bytes.len(), |offset| pos + offset),
        None => bytes.len(),
    }
}

#[inline(always)]
fn find_comment_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut pos = from;
    loop {
        pos = scan_until_byte(bytes, pos, b'-');
        match bytes.get(pos..pos + 3) {
            Some(b"-->") => return Some(pos + 2),
            Some(_) => pos += 1,
            None => return None,
        }
    }
}

#[inline(always)]
pub(crate) fn push_span(text: &mut String, input: &str, start: usize, end: usize, add_space: bool) {
    let span = &input.as_bytes()[start..end];
    if matches!(span, [b'&', .., b';']) {
        add_html_token(text, span, add_space);
    } else {
        if add_space {
            text.push(' ');
        }
        text.push_str(&input[start..end]);
    }
}

struct TextBuilder {
    owned: String,
    hint: usize,
    start: usize,
    end: usize,
}

impl TextBuilder {
    #[inline(always)]
    fn new() -> Self {
        Self {
            owned: String::new(),
            hint: 16,
            start: 0,
            end: 0,
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.end == self.start && self.owned.is_empty()
    }

    #[inline(always)]
    fn push(&mut self, input: &str, start: usize, end: usize, add_space: bool) {
        let bytes = input.as_bytes();
        let span = &bytes[start..end];
        let is_entity = matches!(span, [b'&', .., b';']);

        if self.end > self.start {
            if !is_entity {
                if !add_space {
                    if start == self.end {
                        self.end = end;
                        return;
                    }
                } else if start == self.end + 1 && bytes[self.end] == b' ' {
                    self.end = end;
                    return;
                }
            }
            let pending_start = self.start;
            let pending_end = self.end;
            self.start = 0;
            self.end = 0;
            if self.owned.capacity() == 0 {
                self.owned.reserve(
                    self.hint
                        .max((pending_end - pending_start) + (end - start) + 1),
                );
            }
            self.owned.push_str(&input[pending_start..pending_end]);
        } else if self.owned.is_empty() {
            if !is_entity {
                if !add_space {
                    self.start = start;
                    self.end = end;
                    return;
                } else if start > 0 && bytes[start - 1] == b' ' {
                    self.start = start - 1;
                    self.end = end;
                    return;
                }
            }
            if self.owned.capacity() == 0 {
                self.owned.reserve(self.hint.max((end - start) + 1));
            }
        }

        if is_entity {
            add_html_token(&mut self.owned, span, add_space);
        } else {
            if add_space {
                self.owned.push(' ');
            }
            self.owned.push_str(&input[start..end]);
        }
    }

    #[inline(always)]
    fn take<'x>(&mut self, input: &'x str) -> Cow<'x, str> {
        if self.end > self.start {
            let text = &input[self.start..self.end];
            self.start = 0;
            self.end = 0;
            Cow::Borrowed(text)
        } else if self.owned.len() <= REUSE_BUFFER_LEN {
            let text = String::from(self.owned.as_str());
            self.owned.clear();
            Cow::Owned(text)
        } else {
            self.hint = self.owned.len();
            Cow::Owned(std::mem::take(&mut self.owned))
        }
    }
}

fn parse_comment<'x>(input: &'x str, start: usize, tags: &mut Vec<HtmlToken<'x>>) -> usize {
    let bytes = input.as_bytes();
    let (end, is_terminated) = match find_comment_end(bytes, start + 1) {
        Some(end) => (end, true),
        None => (bytes.len(), false),
    };

    let mut pos = scan_until(bytes, start, &COMMENT_SPACE).min(end);
    let text = if pos >= end {
        Cow::Borrowed(&input[start..end])
    } else {
        let mut comment = String::with_capacity(end - start);
        comment.push_str(&input[start..pos]);
        while pos < end {
            comment.push(' ');
            pos += 1;
            let stop = scan_until(bytes, pos, &COMMENT_SPACE).min(end);
            comment.push_str(&input[pos..stop]);
            pos = stop;
        }
        Cow::Owned(comment)
    };

    tags.push(HtmlToken::Comment { text });

    if is_terminated { end + 1 } else { end }
}

fn parse_value<'x>(
    input: &'x str,
    mut pos: usize,
    in_quote: &mut bool,
    attributes: &mut Vec<(u64, Option<Cow<'x, str>>)>,
) -> (usize, bool) {
    let bytes = input.as_bytes();
    let mut first_start = 0;
    let mut first_end = 0;
    let mut owned: Option<String> = None;
    let mut is_tag_end = false;

    loop {
        let stop = if *in_quote {
            scan_until_byte(bytes, pos, b'"')
        } else {
            scan_until(bytes, pos, &VALUE_STOP)
        };
        if stop > pos {
            if first_end == first_start {
                first_start = pos;
                first_end = stop;
            } else {
                match &mut owned {
                    Some(owned) => owned.push_str(&input[pos..stop]),
                    None => {
                        let mut value =
                            String::with_capacity((first_end - first_start) + (stop - pos));
                        value.push_str(&input[first_start..first_end]);
                        value.push_str(&input[pos..stop]);
                        owned = Some(value);
                    }
                }
            }
        }
        pos = stop;
        match bytes.get(pos) {
            None => break,
            Some(b'"') => {
                pos += 1;
                if *in_quote {
                    *in_quote = false;
                    break;
                }
                *in_quote = true;
            }
            Some(b'>') => {
                pos += 1;
                is_tag_end = true;
                break;
            }
            Some(_) => {
                pos += 1;
                break;
            }
        }
    }

    let value = match owned {
        Some(owned) => Some(Cow::Owned(owned)),
        None if first_end > first_start => Some(Cow::Borrowed(&input[first_start..first_end])),
        None => None,
    };
    if let Some(value) = value {
        if let Some((_, slot)) = attributes.last_mut() {
            *slot = Some(value);
        } else {
            attributes.push((0, Some(value)));
        }
    }

    (pos, is_tag_end)
}

fn parse_tag<'x>(input: &'x str, mut pos: usize, tags: &mut Vec<HtmlToken<'x>>) -> usize {
    let bytes = input.as_bytes();
    let mut is_end_tag = false;

    while let Some(&ch) = bytes.get(pos) {
        if ch == b'/' {
            is_end_tag = true;
        } else if !ch.is_ascii_whitespace() {
            break;
        }
        pos += 1;
    }

    let mut in_quote = false;
    let mut is_self_closing = false;
    let mut key: u64 = 0;
    let mut shift = 0;
    let mut tag = 0;
    let mut attributes: Vec<(u64, Option<Cow<'x, str>>)> = Vec::new();

    while let Some(&ch) = bytes.get(pos) {
        if !TAG_KEY_STOP[ch as usize] {
            if shift < 64 {
                key |= (TAG_KEY_FOLD[ch as usize] as u64) << shift;
                shift += 8;
            }
            pos += 1;
            continue;
        }
        pos += 1;
        match ch {
            b'/' if !in_quote => {
                is_self_closing = true;
            }
            b'>' if !in_quote => {
                if shift != 0 {
                    if tag == 0 {
                        tag = key;
                    } else {
                        attributes.push((key, None));
                    }
                }
                break;
            }
            b'"' => {
                in_quote = !in_quote;
            }
            b'=' if !in_quote => {
                while matches!(bytes.get(pos), Some(ch) if ch.is_ascii_whitespace()) {
                    pos += 1;
                }

                if shift != 0 {
                    attributes.push((key, None));
                    key = 0;
                    shift = 0;
                }

                let (next, is_tag_end) = parse_value(input, pos, &mut in_quote, &mut attributes);
                pos = next;
                if is_tag_end {
                    break;
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' if shift != 0 => {
                if tag == 0 {
                    tag = key;
                } else {
                    attributes.push((key, None));
                }
                key = 0;
                shift = 0;
            }
            _ => {}
        }
    }

    if tag != 0 {
        if is_end_tag {
            tags.push(HtmlToken::EndTag { name: tag });
        } else {
            tags.push(HtmlToken::StartTag {
                name: tag,
                attributes,
                is_self_closing,
            });
        }
    }

    pos
}

pub fn html_to_tokens(input: &str) -> Vec<HtmlToken<'_>> {
    let bytes = input.as_bytes();
    let mut tags = Vec::new();

    let mut is_token_start = true;
    let mut is_after_space = false;
    let mut is_new_line = true;

    let mut token_start = 0;
    let mut token_end = 0;

    let mut text = TextBuilder::new();
    let mut pos = 0;

    while let Some(&ch) = bytes.get(pos) {
        match ch {
            b'<' => {
                if !is_token_start {
                    text.push(input, token_start, token_end + 1, is_after_space);
                    is_after_space = false;
                    is_token_start = true;
                }
                if !text.is_empty() {
                    tags.push(HtmlToken::Text {
                        text: text.take(input),
                    });
                }

                pos += 1;
                while matches!(bytes.get(pos), Some(ch) if ch.is_ascii_whitespace()) {
                    pos += 1;
                }

                pos = if matches!(bytes.get(pos..pos + 3), Some(b"!--")) {
                    parse_comment(input, pos, &mut tags)
                } else {
                    parse_tag(input, pos, &mut tags)
                };
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                if !is_token_start {
                    text.push(
                        input,
                        token_start,
                        token_end + 1,
                        is_after_space && !is_new_line,
                    );
                    is_new_line = false;
                }
                is_after_space = true;
                is_token_start = true;
                pos += 1;
                while matches!(bytes.get(pos), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                    pos += 1;
                }
                continue;
            }
            b'&' if !is_token_start => {
                text.push(
                    input,
                    token_start,
                    token_end + 1,
                    is_after_space && !is_new_line,
                );
                is_new_line = false;
                is_token_start = true;
                is_after_space = false;
            }
            b';' if !is_token_start => {
                text.push(input, token_start, pos + 1, is_after_space && !is_new_line);
                is_token_start = true;
                is_after_space = false;
                is_new_line = false;
                pos += 1;
                continue;
            }
            _ => (),
        }

        if is_token_start {
            token_start = pos;
            is_token_start = false;
        }
        let run_end = scan_until(bytes, pos + 1, &TEXT_STOP);
        token_end = run_end - 1;
        pos = run_end;
    }

    if !is_token_start {
        text.push(
            input,
            token_start,
            token_end + 1,
            is_after_space && !is_new_line,
        );
    }
    if !text.is_empty() {
        tags.push(HtmlToken::Text {
            text: text.take(input),
        });
    }

    tags
}

pub fn html_text_body(html_tokens: &[HtmlToken<'_>]) -> String {
    let text_body_len = html_tokens
        .iter()
        .filter_map(|t| match t {
            HtmlToken::Text { text } => text.len().into(),
            _ => None,
        })
        .sum();
    let mut text_body = String::with_capacity(text_body_len);
    let mut in_head = false;
    for token in html_tokens {
        match token {
            HtmlToken::StartTag { name: HEAD, .. } => {
                in_head = true;
            }
            HtmlToken::EndTag { name: HEAD } => {
                in_head = false;
            }
            HtmlToken::Text { text } if !in_head => {
                if !text_body.is_empty() && !text_body.ends_with(' ') && !text.starts_with(' ') {
                    text_body.push(' ');
                }
                text_body.push_str(text)
            }
            _ => {}
        }
    }
    text_body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str) -> u64 {
        name.bytes().take(8).enumerate().fold(0u64, |acc, (i, b)| {
            acc | ((b.to_ascii_lowercase() as u64) << (8 * i))
        })
    }

    #[test]
    fn comment_whitespace_and_broken_attributes() {
        assert_eq!(
            html_to_tokens("<!-- a  b\t-->"),
            vec![HtmlToken::Comment {
                text: "!-- a  b --".into()
            }]
        );
        assert_eq!(
            html_to_tokens("<a b=1 =2>"),
            vec![HtmlToken::StartTag {
                name: key("a"),
                attributes: vec![(key("b"), Some("2".into()))],
                is_self_closing: false
            }]
        );
        assert_eq!(
            html_to_tokens("<abcdefghijk>"),
            vec![HtmlToken::StartTag {
                name: key("abcdefgh"),
                attributes: vec![],
                is_self_closing: false
            }]
        );
        assert_eq!(
            html_to_tokens("<BR/>"),
            vec![HtmlToken::StartTag {
                name: key("br"),
                attributes: vec![],
                is_self_closing: true
            }]
        );
        assert_eq!(
            html_to_tokens("<A HREF=\"X y\" Title=z>t</A>"),
            vec![
                HtmlToken::StartTag {
                    name: key("a"),
                    attributes: vec![
                        (key("href"), Some("X y".into())),
                        (key("title"), Some("z".into()))
                    ],
                    is_self_closing: false
                },
                HtmlToken::Text { text: "t".into() },
                HtmlToken::EndTag { name: key("a") }
            ]
        );
        assert_eq!(html_to_tokens("<>< >"), vec![]);
        assert_eq!(
            html_to_tokens("<!--"),
            vec![HtmlToken::Comment { text: "!--".into() }]
        );
        assert_eq!(
            html_to_tokens("a&amp;b &#65;&#x42; &bogus;"),
            vec![HtmlToken::Text {
                text: "a&b AB &bogus;".into()
            }]
        );
    }

    #[test]
    fn text_body_skips_head() {
        let tokens =
            html_to_tokens("<html><head><title>T</title></head><body>a <b>b</b>c</body></html>");
        assert_eq!(html_text_body(&tokens), "a b c");
    }

    #[test]
    fn test_html_to_tokens_text() {
        let input = "Hello, world!";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![HtmlToken::Text {
                text: "Hello, world!".into()
            }]
        );
    }

    #[test]
    fn test_html_to_tokens_start_tag() {
        let input = "<div>";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![HtmlToken::StartTag {
                name: 7760228,
                attributes: vec![],
                is_self_closing: false
            }]
        );
    }

    #[test]
    fn test_html_to_tokens_end_tag() {
        let input = "</div>";
        let tokens = html_to_tokens(input);
        assert_eq!(tokens, vec![HtmlToken::EndTag { name: 7760228 }]);
    }

    #[test]
    fn test_html_to_tokens_comment() {
        let input = "<!-- This is a comment -->";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![HtmlToken::Comment {
                text: "!-- This is a comment --".into()
            }]
        );
    }

    #[test]
    fn test_html_to_tokens_mixed() {
        let input = "<div>Hello, <span>&quot; world &quot; </span>!</div>";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![
                HtmlToken::StartTag {
                    name: 7760228,
                    attributes: vec![],
                    is_self_closing: false
                },
                HtmlToken::Text {
                    text: "Hello,".into()
                },
                HtmlToken::StartTag {
                    name: 1851879539,
                    attributes: vec![],
                    is_self_closing: false
                },
                HtmlToken::Text {
                    text: " \" world \"".into()
                },
                HtmlToken::EndTag { name: 1851879539 },
                HtmlToken::Text { text: " !".into() },
                HtmlToken::EndTag { name: 7760228 }
            ]
        );
    }

    #[test]
    fn test_html_to_tokens_with_attributes() {
        let input = r#"<input type="text" value="test"><single/><one attr/><a b=1 b c="123">"#;
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![
                HtmlToken::StartTag {
                    name: 500186508905,
                    attributes: vec![
                        (1701869940, Some("text".into())),
                        (435761734006, Some("test".into()))
                    ],
                    is_self_closing: false
                },
                HtmlToken::StartTag {
                    name: 111516266162547,
                    attributes: vec![],
                    is_self_closing: true
                },
                HtmlToken::StartTag {
                    name: 6647407,
                    attributes: vec![(1920234593, None)],
                    is_self_closing: true
                },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(98, Some("1".into())), (98, None), (99, Some("123".into()))],
                    is_self_closing: false
                }
            ]
        );
    }
}
