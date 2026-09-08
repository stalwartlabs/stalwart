/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Token;

const ASCII_SPACE: [bool; 256] = {
    let mut table = [false; 256];
    let mut byte = 0x09u8;
    while byte <= 0x0d {
        table[byte as usize] = true;
        byte += 1;
    }
    table[0x20] = true;
    table
};

const QUEUE_COMPACTION_HEAD: usize = 1024;
const CLASS_ALPHA: u8 = 1;
const CLASS_DIGIT: u8 = 2;

const ASCII_ALNUM: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut byte = b'A';
    while byte <= b'Z' {
        table[byte as usize] = CLASS_ALPHA;
        table[(byte + 32) as usize] = CLASS_ALPHA;
        byte += 1;
    }
    let mut byte = b'0';
    while byte <= b'9' {
        table[byte as usize] = CLASS_DIGIT;
        byte += 1;
    }
    table
};

#[cfg(test)]
pub(super) fn ascii_alnum_class(byte: u8) -> u8 {
    ASCII_ALNUM[byte as usize]
}

#[cfg(test)]
pub(super) fn ascii_space_class(byte: u8) -> bool {
    ASCII_SPACE[byte as usize]
}

#[derive(Debug)]
pub struct TypesTokenizer<'x> {
    text: &'x str,
    pos: usize,
    tokens: Vec<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>>,
    head: usize,
    peek_pos: usize,
    last_ch_is_space: bool,
    last_token_is_dot: bool,
    eof: bool,
    tokenize_urls: bool,
    tokenize_urls_without_scheme: bool,
    tokenize_emails: bool,
    tokenize_numbers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType<T, E, U, I> {
    Alphabetic(T),
    Alphanumeric(T),
    Integer(T),
    Other(char),
    Punctuation(char),
    Space,

    // Detected types
    Url(U),
    UrlNoScheme(U),
    UrlNoHost(T),
    IpAddr(I),
    Email(E),
    Float(T),
}

impl Copy for Token<TokenType<&'_ str, &'_ str, &'_ str, &'_ str>> {}

impl<'x> Iterator for TypesTokenizer<'x> {
    type Item = Token<TokenType<&'x str, &'x str, &'x str, &'x str>>;

    fn next(&mut self) -> Option<Self::Item> {
        let token = self.peek()?;
        let last_is_dot = self.last_token_is_dot;
        self.last_token_is_dot = matches!(token.word, TokenType::Punctuation('.'));

        // Try parsing URL with scheme
        if self.tokenize_urls
            && let TokenType::Alphabetic(scheme) | TokenType::Alphanumeric(scheme) = token.word
            && scheme_may_follow(self.text, token.to)
            && scheme.len() <= 8
            && scheme.is_ascii()
            && self.try_skip_url_scheme()
        {
            if let Some(url) = self.try_parse_url(token.into()) {
                self.peek_advance();
                return Some(url);
            } else {
                self.peek_rewind();
            }
        }

        // Try parsing email
        if self.tokenize_emails
            && token.word.is_email_atom()
            && email_may_follow(self.text, token.to)
            && email_at_reachable(self.text, token.from, token.to)
        {
            self.peek_rewind();
            if let Some(email) = self.try_parse_email() {
                self.peek_advance();
                return Some(email);
            }
            self.peek_rewind();
        }

        // Try parsing URL without scheme
        if self.tokenize_urls_without_scheme
            && token.word.is_domain_atom(true)
            && host_may_follow(self.text, token.to)
            && host_dot_reachable(self.text, token.from, token.to)
        {
            self.peek_rewind();
            if let Some(url) = self.try_parse_url(None) {
                self.peek_advance();
                return Some(url);
            }
            self.peek_rewind();
        }

        // Try parsing currencies and floating point numbers
        if self.tokenize_numbers
            && !last_is_dot
            && let Some(num) = self.try_parse_number()
        {
            self.peek_advance();
            return Some(num);
        }

        self.peek_rewind();
        self.next_()
    }
}

impl<'x> TypesTokenizer<'x> {
    pub fn new(text: &'x str) -> Self {
        Self {
            text,
            pos: 0,
            tokens: Vec::new(),
            eof: false,
            head: 0,
            peek_pos: 0,
            last_ch_is_space: false,
            last_token_is_dot: false,
            tokenize_urls: true,
            tokenize_urls_without_scheme: true,
            tokenize_emails: true,
            tokenize_numbers: true,
        }
    }

    pub fn tokenize_urls(mut self, tokenize: bool) -> Self {
        self.tokenize_urls = tokenize;
        self
    }

    pub fn tokenize_urls_without_scheme(mut self, tokenize: bool) -> Self {
        self.tokenize_urls_without_scheme = tokenize;
        self
    }

    pub fn tokenize_emails(mut self, tokenize: bool) -> Self {
        self.tokenize_emails = tokenize;
        self
    }

    pub fn tokenize_numbers(mut self, tokenize: bool) -> Self {
        self.tokenize_numbers = tokenize;
        self
    }

    #[inline(always)]
    fn char_at(&self, pos: usize) -> Option<char> {
        self.text.get(pos..).and_then(|rest| rest.chars().next())
    }

    fn consume(&mut self) -> bool {
        if self.head == self.tokens.len() {
            self.tokens.clear();
            self.head = 0;
        } else if self.head >= QUEUE_COMPACTION_HEAD {
            self.tokens.drain(..self.head);
            self.head = 0;
        }

        let bytes = self.text.as_bytes();
        let mut pos = self.pos;

        if self.last_ch_is_space {
            while let Some(&byte) = bytes.get(pos) {
                if byte < 0x80 {
                    if !ASCII_SPACE[byte as usize] {
                        break;
                    }
                    pos += 1;
                } else {
                    match self.char_at(pos) {
                        Some(ch) if ch.is_whitespace() => pos += ch.len_utf8(),
                        _ => break,
                    }
                }
            }
        }

        let start_pos = pos;
        let mut classes = 0u8;
        let stop_char = loop {
            while let Some(&byte) = bytes.get(pos) {
                let class = ASCII_ALNUM[byte as usize];
                if class == 0 {
                    break;
                }
                classes |= class;
                pos += 1;
            }
            match bytes.get(pos) {
                None => break None,
                Some(&byte) if byte < 0x80 => {
                    let is_space = ASCII_SPACE[byte as usize];
                    break Some((
                        if is_space {
                            TokenType::Space
                        } else {
                            TokenType::Punctuation(byte as char)
                        },
                        1usize,
                        is_space,
                    ));
                }
                Some(_) => match self.char_at(pos) {
                    Some(ch) if ch.is_alphabetic() => {
                        classes |= CLASS_ALPHA;
                        pos += ch.len_utf8();
                    }
                    Some(ch) => {
                        let is_space = ch.is_whitespace();
                        break Some((
                            if is_space {
                                TokenType::Space
                            } else {
                                TokenType::Other(ch)
                            },
                            ch.len_utf8(),
                            is_space,
                        ));
                    }
                    None => break None,
                },
            }
        };

        let end_pos = pos;
        if end_pos != start_pos {
            self.last_ch_is_space = false;
        }

        let stop_char = stop_char.map(|(word, len, is_space)| {
            let from = pos;
            pos += len;
            self.last_ch_is_space = is_space;
            Token {
                word,
                from,
                to: from + len,
            }
        });
        self.pos = pos;

        if end_pos != start_pos {
            let text = &self.text[start_pos..end_pos];

            self.tokens.push(Token {
                word: if classes == CLASS_ALPHA | CLASS_DIGIT {
                    TokenType::Alphanumeric(text)
                } else if classes == CLASS_ALPHA {
                    TokenType::Alphabetic(text)
                } else {
                    TokenType::Integer(text)
                },
                from: start_pos,
                to: end_pos,
            });
            if let Some(stop_char) = stop_char {
                self.tokens.push(stop_char);
            }
            true
        } else if let Some(stop_char) = stop_char {
            self.tokens.push(stop_char);
            true
        } else {
            self.eof = true;
            false
        }
    }

    fn next_(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        if self.head == self.tokens.len() && !self.eof {
            self.consume();
        }
        match self.tokens.get(self.head) {
            Some(&token) => {
                self.head += 1;
                Some(token)
            }
            None => None,
        }
    }

    fn peek(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        while self.tokens.len() - self.head <= self.peek_pos && !self.eof {
            self.consume();
        }
        debug_assert!(self.head + self.peek_pos <= self.tokens.len());
        match self.tokens.get(self.head + self.peek_pos) {
            Some(&token) => {
                self.peek_pos += 1;
                Some(token)
            }
            None => None,
        }
    }

    fn peek_advance(&mut self) {
        debug_assert!(self.head + self.peek_pos <= self.tokens.len());
        self.head += self.peek_pos;
        self.peek_pos = 0;
    }

    #[inline(always)]
    fn peek_rewind(&mut self) {
        self.peek_pos = 0;
    }

    fn try_parse_url(
        &mut self,
        scheme_token: Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>>,
    ) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        let (has_scheme, allow_blank_host) = scheme_token.as_ref().map_or((false, false), |t| {
            (
                true,
                matches!(t.word, TokenType::Alphabetic(s) if s.eq_ignore_ascii_case("file")),
            )
        });
        if has_scheme {
            let restore_pos = self.peek_pos;
            let mut has_user_info = false;
            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Punctuation('@') => {
                        has_user_info = true;
                        break;
                    }
                    TokenType::Alphabetic(_)
                    | TokenType::Alphanumeric(_)
                    | TokenType::Integer(_)
                    | TokenType::Punctuation(
                        '-' | '.' | '_' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+'
                        | ',' | ';' | '=' | ':',
                    ) => (),
                    _ => break,
                }
            }

            if !has_user_info {
                self.peek_pos = restore_pos;
            }
        }

        // Try parsing hostname
        let mut is_valid_host = true;
        let (host_start_pos, mut end_pos, is_ip) = if has_scheme {
            let mut start_pos = usize::MAX;
            let mut end_pos = usize::MAX;
            let mut restore_pos = self.peek_pos;

            let mut text_count = 0;
            let mut int_count = 0;
            let mut dot_count = 0;
            let mut is_ipv6 = false;

            let mut last_label = None;

            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Alphabetic(text) | TokenType::Alphanumeric(text) => {
                        last_label = Some(text);
                        text_count += 1;
                    }
                    TokenType::Integer(text) => {
                        if text.len() <= 3 {
                            int_count += 1;
                        }
                    }
                    TokenType::Punctuation('.') => {
                        dot_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('[') if start_pos == usize::MAX => {
                        let (_, to) = self.try_parse_ipv6(token.from)?;
                        start_pos = token.from;
                        end_pos = to;
                        restore_pos = self.peek_pos;
                        is_ipv6 = true;
                        break;
                    }
                    TokenType::Punctuation(
                        '-' | '_' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ','
                        | ';' | '=' | ':' | '%',
                    ) => {
                        continue;
                    }
                    TokenType::Punctuation('/') if allow_blank_host => {
                        // Allow file://../ urls
                        end_pos = token.from;
                        restore_pos = self.peek_pos - 1;
                        break;
                    }
                    _ => break,
                }

                if start_pos == usize::MAX {
                    start_pos = token.from;
                }
                end_pos = token.to;
                restore_pos = self.peek_pos;
            }

            self.peek_pos = restore_pos;
            let is_ip = is_ipv6 || (int_count == 4 && dot_count == 3 && text_count == 0);
            if end_pos != usize::MAX {
                is_valid_host = is_ip
                    || (dot_count >= 1
                        && (text_count + int_count) >= 2
                        && last_label_is_tld(last_label));
                (start_pos, end_pos, is_ip)
            } else {
                return None;
            }
        } else {
            // Strict hostname parsing
            self.try_parse_hostname()?
        };

        // Try parsing port
        let start_pos = scheme_token.map(|t| t.from).unwrap_or(host_start_pos);
        let mut restore_pos = self.peek_pos;
        let mut has_port = false;
        let mut last_is_colon = false;
        let mut found_query_start = false;
        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation(':') if !last_is_colon && !has_port => {
                    last_is_colon = true;
                }
                TokenType::Integer(_) if last_is_colon => {
                    has_port = true;
                    last_is_colon = false;
                    restore_pos = self.peek_pos;
                    end_pos = token.to;
                }
                TokenType::Punctuation('/' | '?') if !last_is_colon => {
                    found_query_start = true;
                    end_pos = token.to;
                    break;
                }
                _ => {
                    self.peek_pos = restore_pos;
                    break;
                }
            }
        }

        // Try parsing query
        if found_query_start {
            restore_pos = self.peek_pos;
            let mut p_count = 0;
            let mut b_count = 0;
            let mut c_count = 0;
            let mut seen_quote = false;
            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Alphabetic(_)
                    | TokenType::Alphanumeric(_)
                    | TokenType::Integer(_)
                    | TokenType::Other(_) => {}
                    TokenType::Punctuation('(') => {
                        p_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('[') => {
                        b_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('{') => {
                        c_count += 1;
                        continue;
                    }
                    TokenType::Punctuation(')') if p_count > 0 => {
                        p_count -= 1;
                    }
                    TokenType::Punctuation(']') if b_count > 0 => {
                        b_count -= 1;
                    }
                    TokenType::Punctuation('}') if c_count > 0 => {
                        c_count -= 1;
                    }
                    TokenType::Punctuation('\'') => {
                        if !seen_quote {
                            seen_quote = true;
                            continue;
                        } else {
                            seen_quote = false;
                        }
                    }
                    TokenType::Punctuation('/') => {}
                    TokenType::Punctuation(
                        '-' | '_' | '~' | '!' | '$' | '&' | '*' | '+' | ',' | ';' | '=' | ':' | '%'
                        | '?' | '.' | '@',
                    ) => {
                        continue;
                    }
                    _ => break,
                }
                end_pos = token.to;
                restore_pos = self.peek_pos;
            }
            self.peek_pos = restore_pos;
        }

        let word = &self.text[start_pos..end_pos];
        Token {
            word: if has_scheme {
                if is_valid_host {
                    TokenType::Url(word)
                } else {
                    TokenType::UrlNoHost(word)
                }
            } else if is_ip && !found_query_start {
                TokenType::IpAddr(word)
            } else {
                TokenType::UrlNoScheme(word)
            },
            from: start_pos,
            to: end_pos,
        }
        .into()
    }

    fn try_parse_email(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        // Start token is a valid local part atom
        let start_token = self.peek()?;
        let mut last_is_dot = false;

        // Find local part
        loop {
            let token = self.peek()?;
            if token.to - start_token.from > 255 {
                return None;
            }
            match token.word {
                word if word.is_email_atom() => {
                    last_is_dot = false;
                }
                TokenType::Punctuation('@') if !last_is_dot => {
                    break;
                }
                TokenType::Punctuation('.') if !last_is_dot => {
                    last_is_dot = true;
                }
                _ => {
                    return None;
                }
            }
        }

        // Obtain domain part
        let (_, end_pos, _) = self.try_parse_hostname()?;

        Token {
            word: TokenType::Email(&self.text[start_token.from..end_pos]),
            from: start_token.from,
            to: end_pos,
        }
        .into()
    }

    fn try_parse_hostname(&mut self) -> Option<(usize, usize, bool)> {
        let mut last_ch = u8::MAX;
        let mut has_int = false;
        let mut has_alpha = false;
        let mut last_label = None;

        let mut dot_count = 0;
        let mut start_pos = usize::MAX;
        let mut end_pos = usize::MAX;
        let mut restore_pos = self.peek_pos;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation('.') if last_ch == 0 && start_pos != usize::MAX => {
                    last_ch = b'.';
                    dot_count += 1;
                    continue;
                }
                TokenType::Punctuation('-') if last_ch == 0 || last_ch == b'-' => {
                    last_ch = b'-';
                    continue;
                }
                TokenType::Punctuation('[') if start_pos == usize::MAX => {
                    return self
                        .try_parse_ipv6(token.from)
                        .map(|(from, to)| (from, to, true));
                }
                TokenType::Alphabetic(text) | TokenType::Alphanumeric(text) if text.len() <= 63 => {
                    last_label = Some(text);
                    has_alpha = true;
                    last_ch = 0;
                }
                TokenType::Other(_) => {
                    has_alpha = true;
                    last_label = None;
                    last_ch = 0;
                }
                TokenType::Integer(text) => {
                    if text.len() <= 3 {
                        has_int = true;
                    }
                    last_label = None;
                    last_ch = 0;
                }
                _ => {
                    break;
                }
            }

            if start_pos == usize::MAX {
                start_pos = token.from;
            }
            end_pos = token.to;
            restore_pos = self.peek_pos;

            if end_pos - start_pos > 255 {
                return None;
            }
        }
        self.peek_pos = restore_pos;

        if last_ch == b'.' {
            dot_count -= 1;
        }

        let is_ipv4 = has_int && !has_alpha && dot_count == 3;
        if end_pos != usize::MAX && dot_count >= 1 && (is_ipv4 || last_label_is_tld(last_label)) {
            (start_pos, end_pos, is_ipv4).into()
        } else {
            None
        }
    }

    fn try_parse_ipv6(&mut self, start_pos: usize) -> Option<(usize, usize)> {
        let mut found_colon = false;
        let mut last_ch = u8::MAX;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Integer(_) | TokenType::Alphanumeric(_) => {
                    last_ch = 0;
                }
                TokenType::Punctuation(':') if last_ch != b'.' => {
                    found_colon = true;
                    last_ch = b':';
                }
                TokenType::Punctuation('.') if last_ch == 0 => {
                    last_ch = b'.';
                }
                TokenType::Punctuation(']') if found_colon && last_ch == 0 => {
                    return (start_pos, token.to).into();
                }
                _ => return None,
            }
        }

        None
    }

    fn try_parse_number(&mut self) -> Option<Token<TokenType<&'x str, &'x str, &'x str, &'x str>>> {
        self.peek_rewind();
        if let Some(token) = self.tokens.get(self.head)
            && !matches!(
                token.word,
                TokenType::Integer(_) | TokenType::Punctuation('-')
            )
        {
            return None;
        }

        let mut start_pos = usize::MAX;
        let mut end_pos = usize::MAX;
        let mut restore_pos = self.peek_pos;

        let mut seen_integer = 0;
        let mut seen_dot = false;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation('-') if start_pos == usize::MAX => {}
                TokenType::Integer(_) if seen_integer == 0 || seen_dot => {
                    seen_integer += 1;
                }
                TokenType::Punctuation('.') if seen_integer != 0 => {
                    if !seen_dot {
                        seen_dot = true;
                        continue;
                    } else {
                        // Avoid parsing num.num.num as floats
                        return None;
                    }
                }
                _ => break,
            }

            if start_pos == usize::MAX {
                start_pos = token.from;
            }
            end_pos = token.to;
            restore_pos = self.peek_pos;
        }

        self.peek_pos = restore_pos;

        if seen_integer > 0 {
            let text = &self.text[start_pos..end_pos];

            Token {
                word: if seen_integer == 2 {
                    TokenType::Float(text)
                } else {
                    TokenType::Integer(text)
                },
                from: start_pos,
                to: end_pos,
            }
            .into()
        } else {
            None
        }
    }

    fn try_skip_url_scheme(&mut self) -> bool {
        if let Some(token) = self.tokens.get(self.head + self.peek_pos)
            && !matches!(token.word, TokenType::Punctuation(':' | '+'))
        {
            self.peek_pos = 0;
            return false;
        }

        enum State {
            None,
            PlusAlpha,
            Colon,
            Slash1,
            Slash2,
        }
        let mut state = State::None;

        while let Some(token) = self.peek() {
            state = match (token.word, state) {
                (TokenType::Punctuation(':'), State::None | State::Colon) => State::Slash1,
                (TokenType::Punctuation('/'), State::Slash1) => State::Slash2,
                (TokenType::Punctuation('/'), State::Slash2) => return true,
                (TokenType::Punctuation('+'), State::None) => State::PlusAlpha,
                (TokenType::Alphabetic(t) | TokenType::Alphanumeric(t), State::PlusAlpha)
                    if t.is_ascii() =>
                {
                    State::Colon
                }
                _ => break,
            };
        }
        self.peek_rewind();
        false
    }
}

const FOLLOW_RUN: u8 = 1 << 0;
const FOLLOW_EMAIL_PUNCT: u8 = 1 << 1;
const FOLLOW_DOT: u8 = 1 << 2;
const FOLLOW_AT: u8 = 1 << 3;
const FOLLOW_HYPHEN: u8 = 1 << 4;
const FOLLOW_NON_ASCII: u8 = 1 << 5;

const FOLLOW_CLASS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        let byte = index as u8;
        let mut class = 0;
        if byte.is_ascii_alphanumeric() {
            class |= FOLLOW_RUN;
        }
        if matches!(
            byte,
            b'!' | b'#'
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
        ) {
            class |= FOLLOW_EMAIL_PUNCT;
        }
        if byte == b'.' {
            class |= FOLLOW_DOT;
        }
        if byte == b'@' {
            class |= FOLLOW_AT;
        }
        if byte == b'-' {
            class |= FOLLOW_HYPHEN;
        }
        if byte >= 0x80 {
            class |= FOLLOW_NON_ASCII;
        }
        table[index] = class;
        index += 1;
    }
    table
};

#[inline(always)]
fn follow_class(text: &str, at: usize) -> u8 {
    match text.as_bytes().get(at) {
        Some(&byte) => FOLLOW_CLASS[byte as usize],
        None => 0,
    }
}

const FOLLOW_EMAILISH: u8 = FOLLOW_RUN | FOLLOW_EMAIL_PUNCT | FOLLOW_DOT | FOLLOW_NON_ASCII;
const FOLLOW_HOSTISH: u8 = FOLLOW_RUN | FOLLOW_DOT | FOLLOW_HYPHEN | FOLLOW_NON_ASCII;

const REACH_SCAN: usize = 8;

#[inline(always)]
fn reachable_before_stop(text: &str, from: usize, at: usize, wanted: u8, allowed: u8) -> bool {
    let bytes = text.as_bytes();
    let limit = bytes.len().min(from.saturating_add(255));
    let Some(window) = bytes.get(at..limit) else {
        return false;
    };
    for &byte in window.iter().take(REACH_SCAN) {
        if byte == wanted {
            return true;
        }
        if FOLLOW_CLASS[byte as usize] & allowed == 0 {
            return false;
        }
    }
    window
        .get(REACH_SCAN..)
        .and_then(|tail| {
            memchr::memchr(wanted, tail).map(|pos| {
                tail.iter()
                    .take(pos)
                    .all(|&byte| FOLLOW_CLASS[byte as usize] & allowed != 0)
            })
        })
        .unwrap_or(false)
}

#[inline(always)]
fn email_at_reachable(text: &str, from: usize, at: usize) -> bool {
    reachable_before_stop(text, from, at, b'@', FOLLOW_EMAILISH)
}

#[inline(always)]
fn host_dot_reachable(text: &str, from: usize, at: usize) -> bool {
    reachable_before_stop(text, from, at, b'.', FOLLOW_HOSTISH)
}

#[inline(always)]
fn scheme_may_follow(text: &str, at: usize) -> bool {
    matches!(text.as_bytes().get(at), Some(b':' | b'+'))
}

#[inline(always)]
fn email_may_follow(text: &str, at: usize) -> bool {
    let class = follow_class(text, at);
    if class & (FOLLOW_RUN | FOLLOW_EMAIL_PUNCT | FOLLOW_AT | FOLLOW_NON_ASCII) != 0 {
        true
    } else {
        class & FOLLOW_DOT != 0
            && follow_class(text, at + 1) & (FOLLOW_RUN | FOLLOW_EMAIL_PUNCT | FOLLOW_NON_ASCII)
                != 0
    }
}

#[inline(always)]
fn host_may_follow(text: &str, at: usize) -> bool {
    let class = follow_class(text, at);
    if class & (FOLLOW_RUN | FOLLOW_HYPHEN | FOLLOW_NON_ASCII) != 0 {
        true
    } else {
        class & FOLLOW_DOT != 0 && follow_class(text, at + 1) & (FOLLOW_RUN | FOLLOW_NON_ASCII) != 0
    }
}

#[inline(always)]
fn last_label_is_tld(label: Option<&str>) -> bool {
    match label {
        Some(text) if text.len() >= 2 => is_public_suffix(text),
        _ => false,
    }
}

#[inline(never)]
fn is_public_suffix(text: &str) -> bool {
    let bytes = text.as_bytes();
    if !bytes.iter().any(u8::is_ascii_uppercase) {
        return has_suffix_type(bytes);
    }
    let mut buf = [0u8; 64];
    match buf.get_mut(..bytes.len()) {
        Some(lowered) => {
            for (dst, src) in lowered.iter_mut().zip(bytes) {
                *dst = src.to_ascii_lowercase();
            }
            has_suffix_type(lowered)
        }
        None => has_suffix_type(text.to_ascii_lowercase().as_bytes()),
    }
}

#[inline(always)]
fn has_suffix_type(label: &[u8]) -> bool {
    psl::Psl::find(&psl::List, [label].into_iter())
        .typ
        .is_some()
}

impl<T, E, U, I> TokenType<T, E, U, I> {
    fn is_email_atom(&self) -> bool {
        matches!(
            self,
            TokenType::Alphabetic(_)
                | TokenType::Integer(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Other(_)
                | TokenType::Punctuation(
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~',
                )
        )
    }

    fn is_domain_atom(&self, is_start: bool) -> bool {
        matches!(
            self,
            TokenType::Alphabetic(_)
                | TokenType::Integer(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Other(_)
        ) || (!is_start && matches!(self, TokenType::Punctuation('-')))
    }
}

#[cfg(test)]
mod test {

    use super::{TokenType, TypesTokenizer};

    #[test]
    fn ascii_class_tables_match_predicates() {
        for byte in 0..=255u8 {
            let expected_alnum = if byte < 0x80 {
                let ch = byte as char;
                if ch.is_alphabetic() {
                    super::CLASS_ALPHA
                } else if ch.is_ascii_digit() {
                    super::CLASS_DIGIT
                } else {
                    0
                }
            } else {
                0
            };
            assert_eq!(super::ascii_alnum_class(byte), expected_alnum, "{byte:#x}");
            let expected_space = byte < 0x80 && (byte as char).is_whitespace();
            assert_eq!(super::ascii_space_class(byte), expected_space, "{byte:#x}");
        }
    }

    #[test]
    fn character_classes() {
        for (text, expected) in [
            ("\u{663}", vec![TokenType::Other('\u{663}')]),
            (
                "a\u{663}",
                vec![TokenType::Alphabetic("a"), TokenType::Other('\u{663}')],
            ),
            (
                "\u{85}x",
                vec![TokenType::Space, TokenType::Alphabetic("x")],
            ),
            ("\u{a0}\u{3000}", vec![TokenType::Space]),
            (
                "\0\u{7f}",
                vec![
                    TokenType::Punctuation('\0'),
                    TokenType::Punctuation('\u{7f}'),
                ],
            ),
            (
                "\u{9f}\u{200b}",
                vec![TokenType::Other('\u{9f}'), TokenType::Other('\u{200b}')],
            ),
            ("BUL\u{212a}", vec![TokenType::Alphabetic("BUL\u{212a}")]),
            ("\u{1c5}1", vec![TokenType::Alphanumeric("\u{1c5}1")]),
            (
                "a \t b",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Space,
                    TokenType::Alphabetic("b"),
                ],
            ),
        ] {
            let tokens = TypesTokenizer::new(text)
                .map(|t| t.word)
                .collect::<Vec<_>>();
            assert_eq!(tokens, expected, "{text:?}");
        }
    }

    #[test]
    fn number_and_scheme_edges() {
        for (text, expected) in [
            (
                "5.",
                vec![TokenType::Integer("5"), TokenType::Punctuation('.')],
            ),
            (
                "1.5.5",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("5"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("5"),
                ],
            ),
            ("1.5", vec![TokenType::Float("1.5")]),
            (
                "-7 x",
                vec![
                    TokenType::Integer("-7"),
                    TokenType::Space,
                    TokenType::Alphabetic("x"),
                ],
            ),
            (
                "--5",
                vec![TokenType::Punctuation('-'), TokenType::Integer("-5")],
            ),
            ("a+b://x", vec![TokenType::UrlNoHost("a+b://x")]),
            ("http://a.com.5", vec![TokenType::Url("http://a.com.5")]),
            ("http://[::1]/", vec![TokenType::Url("http://[::1]/")]),
            (
                "x.com.",
                vec![TokenType::UrlNoScheme("x.com"), TokenType::Punctuation('.')],
            ),
            (
                "x.y.",
                vec![
                    TokenType::Alphabetic("x"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("y"),
                    TokenType::Punctuation('.'),
                ],
            ),
        ] {
            let tokens = TypesTokenizer::new(text)
                .map(|t| t.word)
                .collect::<Vec<_>>();
            assert_eq!(tokens, expected, "{text:?}");
        }
    }

    #[test]
    fn queue_stays_bounded_on_long_peek_chains() {
        let text = "a.".repeat(20_000);
        let mut tokenizer = TypesTokenizer::new(&text);
        let mut count = 0;
        while tokenizer.next().is_some() {
            count += 1;
            assert!(
                tokenizer.tokens.len() < 4096,
                "queue grew to {}",
                tokenizer.tokens.len()
            );
        }
        assert_eq!(count, 40_000);
    }

    #[test]
    fn type_tokenizer() {
        // Credits: test suite from linkify crate
        for (text, expected) in [
            ("", vec![]),
            ("foo", vec![TokenType::Alphabetic("foo")]),
            (":", vec![TokenType::Punctuation(':')]),
            (
                "://",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                ":::",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                "://foo",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "1://foo",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "123://foo",
                vec![
                    TokenType::Integer("123"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "+://foo",
                vec![
                    TokenType::Punctuation('+'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "-://foo",
                vec![
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                ".://foo",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            ("1abc://foo", vec![TokenType::UrlNoHost("1abc://foo")]),
            ("a://foo", vec![TokenType::UrlNoHost("a://foo")]),
            ("a123://foo", vec![TokenType::UrlNoHost("a123://foo")]),
            ("a123b://foo", vec![TokenType::UrlNoHost("a123b://foo")]),
            ("a+b://foo", vec![TokenType::UrlNoHost("a+b://foo")]),
            (
                "a-b://foo",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('-'),
                    TokenType::UrlNoHost("b://foo"),
                ],
            ),
            (
                "a.b://foo",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::UrlNoHost("b://foo"),
                ],
            ),
            ("ABC://foo", vec![TokenType::UrlNoHost("ABC://foo")]),
            (
                ".http://example.org/",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Url("http://example.org/"),
                ],
            ),
            (
                "1.http://example.org/",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Url("http://example.org/"),
                ],
            ),
            (
                "ab://",
                vec![
                    TokenType::Alphabetic("ab"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "file://",
                vec![
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "file:// ",
                vec![
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Space,
                ],
            ),
            (
                "\"file://\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "\"file://...\", ",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation(','),
                    TokenType::Space,
                ],
            ),
            (
                "file://somefile",
                vec![TokenType::UrlNoHost("file://somefile")],
            ),
            (
                "file://../relative",
                vec![TokenType::UrlNoHost("file://../relative")],
            ),
            (
                "http://a.",
                vec![
                    TokenType::UrlNoHost("http://a"),
                    TokenType::Punctuation('.'),
                ],
            ),
            ("http://127.0.0.1", vec![TokenType::Url("http://127.0.0.1")]),
            (
                "http://127.0.0.1/",
                vec![TokenType::Url("http://127.0.0.1/")],
            ),
            ("ab://c", vec![TokenType::UrlNoHost("ab://c")]),
            (
                "http://example.org/",
                vec![TokenType::Url("http://example.org/")],
            ),
            (
                "http://example.org/123",
                vec![TokenType::Url("http://example.org/123")],
            ),
            (
                "http://example.org/?foo=test&bar=123",
                vec![TokenType::Url("http://example.org/?foo=test&bar=123")],
            ),
            (
                "http://example.org/?foo=%20",
                vec![TokenType::Url("http://example.org/?foo=%20")],
            ),
            (
                "http://example.org/%3C",
                vec![TokenType::Url("http://example.org/%3C")],
            ),
            ("example.org/", vec![TokenType::UrlNoScheme("example.org/")]),
            (
                "example.org/123",
                vec![TokenType::UrlNoScheme("example.org/123")],
            ),
            (
                "example.org/?foo=test&bar=123",
                vec![TokenType::UrlNoScheme("example.org/?foo=test&bar=123")],
            ),
            (
                "example.org/?foo=%20",
                vec![TokenType::UrlNoScheme("example.org/?foo=%20")],
            ),
            (
                "example.org/%3C",
                vec![TokenType::UrlNoScheme("example.org/%3C")],
            ),
            (
                "foo http://example.org/",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Space,
                    TokenType::Url("http://example.org/"),
                ],
            ),
            (
                "http://example.org/ bar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\tbar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\nbar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\u{b}bar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\u{c}bar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\rbar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "foo example.org/",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("example.org/"),
                ],
            ),
            (
                "example.org/ bar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\tbar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\nbar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\u{b}bar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\u{c}bar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\rbar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/<",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('<'),
                ],
            ),
            (
                "http://example.org/>",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org/<>",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org/\0",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\0'),
                ],
            ),
            (
                "http://example.org/\u{e}",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\u{e}'),
                ],
            ),
            (
                "http://example.org/\u{7f}",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\u{7f}'),
                ],
            ),
            (
                "http://example.org/\u{9f}",
                vec![TokenType::Url("http://example.org/\u{9f}")],
            ),
            (
                "http://example.org/foo|bar",
                vec![
                    TokenType::Url("http://example.org/foo"),
                    TokenType::Punctuation('|'),
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/<",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('<'),
                ],
            ),
            (
                "example.org/>",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org/<>",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org/\0",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\0'),
                ],
            ),
            (
                "example.org/\u{e}",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\u{e}'),
                ],
            ),
            (
                "example.org/\u{7f}",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\u{7f}'),
                ],
            ),
            (
                "example.org/\u{9f}",
                vec![TokenType::UrlNoScheme("example.org/\u{9f}")],
            ),
            (
                "http://example.org/.",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/..",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/,",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(','),
                ],
            ),
            (
                "http://example.org/:",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                "http://example.org/?",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('?'),
                ],
            ),
            (
                "http://example.org/!",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "http://example.org/;",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "example.org/.",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/..",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/,",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(','),
                ],
            ),
            (
                "example.org/:",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                "example.org/?",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('?'),
                ],
            ),
            (
                "example.org/!",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "example.org/;",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "http://example.org/a(b)",
                vec![TokenType::Url("http://example.org/a(b)")],
            ),
            (
                "http://example.org/a[b]",
                vec![TokenType::Url("http://example.org/a[b]")],
            ),
            (
                "http://example.org/a{b}",
                vec![TokenType::Url("http://example.org/a{b}")],
            ),
            (
                "http://example.org/a'b'",
                vec![TokenType::Url("http://example.org/a'b'")],
            ),
            (
                "(http://example.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[http://example.org/]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "{http://example.org/}",
                vec![
                    TokenType::Punctuation('{'),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('}'),
                ],
            ),
            (
                "\"http://example.org/\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "'http://example.org/'",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "example.org/a(b)",
                vec![TokenType::UrlNoScheme("example.org/a(b)")],
            ),
            (
                "example.org/a[b]",
                vec![TokenType::UrlNoScheme("example.org/a[b]")],
            ),
            (
                "example.org/a{b}",
                vec![TokenType::UrlNoScheme("example.org/a{b}")],
            ),
            (
                "example.org/a'b'",
                vec![TokenType::UrlNoScheme("example.org/a'b'")],
            ),
            (
                "(example.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[example.org/]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "{example.org/}",
                vec![
                    TokenType::Punctuation('{'),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('}'),
                ],
            ),
            (
                "\"example.org/\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "'example.org/'",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "((http://example.org/))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "((http://example.org/a(b)))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/a(b)"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[(http://example.org/)]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "(http://example.org/).",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "(http://example.org/.)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "http://example.org/>",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org/(",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('('),
                ],
            ),
            (
                "http://example.org/(.",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/]()",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(']'),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "((example.org/))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "((example.org/a(b)))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/a(b)"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[(example.org/)]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "(example.org/).",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "(example.org/.)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "example.org/>",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org/(",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('('),
                ],
            ),
            (
                "example.org/(.",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/]()",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(']'),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "'https://example.org'",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "\"https://example.org\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "''https://example.org''",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "'https://example.org''",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "'https://example.org",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                ],
            ),
            (
                "http://example.org/'_(foo)",
                vec![TokenType::Url("http://example.org/'_(foo)")],
            ),
            (
                "http://example.org/'_(foo)'",
                vec![TokenType::Url("http://example.org/'_(foo)'")],
            ),
            (
                "http://example.org/''",
                vec![TokenType::Url("http://example.org/''")],
            ),
            (
                "http://example.org/'''",
                vec![
                    TokenType::Url("http://example.org/''"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "http://example.org/'.",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/'a",
                vec![TokenType::Url("http://example.org/'a")],
            ),
            (
                "http://example.org/it's",
                vec![TokenType::Url("http://example.org/it's")],
            ),
            (
                "example.org/'_(foo)",
                vec![TokenType::UrlNoScheme("example.org/'_(foo)")],
            ),
            (
                "example.org/'_(foo)'",
                vec![TokenType::UrlNoScheme("example.org/'_(foo)'")],
            ),
            (
                "example.org/''",
                vec![TokenType::UrlNoScheme("example.org/''")],
            ),
            (
                "example.org/'''",
                vec![
                    TokenType::UrlNoScheme("example.org/''"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "example.org/'.",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/'a",
                vec![TokenType::UrlNoScheme("example.org/'a")],
            ),
            (
                "example.org/it's",
                vec![TokenType::UrlNoScheme("example.org/it's")],
            ),
            (
                "http://example.org/\"a",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("a"),
                ],
            ),
            (
                "http://example.org/\"a\"",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "http://example.org/`a",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                ],
            ),
            (
                "http://example.org/`a`",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('`'),
                ],
            ),
            (
                "https://example.org*",
                vec![
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('*'),
                ],
            ),
            (
                "https://example.org/*",
                vec![
                    TokenType::Url("https://example.org/"),
                    TokenType::Punctuation('*'),
                ],
            ),
            (
                "https://example.org/**",
                vec![
                    TokenType::Url("https://example.org/"),
                    TokenType::Punctuation('*'),
                    TokenType::Punctuation('*'),
                ],
            ),
            (
                "https://example.org/*/a",
                vec![TokenType::Url("https://example.org/*/a")],
            ),
            (
                "example.org/`a",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                ],
            ),
            (
                "example.org/`a`",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('`'),
                ],
            ),
            (
                "http://example.org\">",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org'>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org\"/>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org'/>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org<p>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org</p>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org\">",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org'>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org\"/>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org'/>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org<p>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org</p>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org\");",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "http://example.org');",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "<img src=\"http://example.org/test.svg\">",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("img"),
                    TokenType::Space,
                    TokenType::Alphabetic("src"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org/test.svg"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "<div><a href=\"http://example.org\"></a></div>",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("a"),
                    TokenType::Space,
                    TokenType::Alphabetic("href"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "<div><a href=\"http://example.org\"\n        ></a></div>",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("a"),
                    TokenType::Space,
                    TokenType::Alphabetic("href"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Space,
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "<div>\n       <img\n         src=\"http://example.org/test3.jpg\" />\n     </div>",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                    TokenType::Space,
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("img"),
                    TokenType::Space,
                    TokenType::Alphabetic("src"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org/test3.jpg"),
                    TokenType::Punctuation('"'),
                    TokenType::Space,
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                    TokenType::Space,
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org\");",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "example.org');",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "http://example.org/",
                vec![TokenType::Url("http://example.org/")],
            ),
            (
                "http://example.org/a/",
                vec![TokenType::Url("http://example.org/a/")],
            ),
            (
                "http://example.org//",
                vec![TokenType::Url("http://example.org//")],
            ),
            ("example.org/", vec![TokenType::UrlNoScheme("example.org/")]),
            (
                "example.org/a/",
                vec![TokenType::UrlNoScheme("example.org/a/")],
            ),
            (
                "example.org//",
                vec![TokenType::UrlNoScheme("example.org//")],
            ),
            (
                "http://one.org/ http://two.org/",
                vec![
                    TokenType::Url("http://one.org/"),
                    TokenType::Space,
                    TokenType::Url("http://two.org/"),
                ],
            ),
            (
                "http://one.org/ : http://two.org/",
                vec![
                    TokenType::Url("http://one.org/"),
                    TokenType::Space,
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::Url("http://two.org/"),
                ],
            ),
            (
                "(http://one.org/)(http://two.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://one.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://two.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "one.org/ two.org/",
                vec![
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("two.org/"),
                ],
            ),
            (
                "one.org/ : two.org/",
                vec![
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Space,
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::UrlNoScheme("two.org/"),
                ],
            ),
            (
                "(one.org/)(two.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("two.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "http://one.org/ two.org/",
                vec![
                    TokenType::Url("http://one.org/"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("two.org/"),
                ],
            ),
            (
                "one.org/ : http://two.org/",
                vec![
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Space,
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::Url("http://two.org/"),
                ],
            ),
            (
                "(http://one.org/)(two.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://one.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("two.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "http://üñîçøðé.com",
                vec![TokenType::Url("http://üñîçøðé.com")],
            ),
            (
                "http://üñîçøðé.com/ä",
                vec![TokenType::Url("http://üñîçøðé.com/ä")],
            ),
            (
                "http://example.org/¡",
                vec![TokenType::Url("http://example.org/¡")],
            ),
            (
                "http://example.org/¢",
                vec![TokenType::Url("http://example.org/¢")],
            ),
            (
                "http://example.org/😀",
                vec![TokenType::Url("http://example.org/😀")],
            ),
            (
                "http://example.org/¢/",
                vec![TokenType::Url("http://example.org/¢/")],
            ),
            (
                "http://xn--c1h.example.com/",
                vec![TokenType::Url("http://xn--c1h.example.com/")],
            ),
            ("üñîçøðé.com", vec![TokenType::UrlNoScheme("üñîçøðé.com")]),
            (
                "üñîçøðé.com/ä",
                vec![TokenType::UrlNoScheme("üñîçøðé.com/ä")],
            ),
            (
                "example.org/¡",
                vec![TokenType::UrlNoScheme("example.org/¡")],
            ),
            (
                "example.org/¢",
                vec![TokenType::UrlNoScheme("example.org/¢")],
            ),
            (
                "example.org/😀",
                vec![TokenType::UrlNoScheme("example.org/😀")],
            ),
            (
                "example.org/¢/",
                vec![TokenType::UrlNoScheme("example.org/¢/")],
            ),
            (
                "xn--c1h.example.com/",
                vec![TokenType::UrlNoScheme("xn--c1h.example.com/")],
            ),
            (
                "example.",
                vec![
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example./",
                vec![
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "foo.com.",
                vec![
                    TokenType::UrlNoScheme("foo.com"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.c",
                vec![
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("c"),
                ],
            ),
            ("example.co", vec![TokenType::UrlNoScheme("example.co")]),
            ("example.com", vec![TokenType::UrlNoScheme("example.com")]),
            ("e.com", vec![TokenType::UrlNoScheme("e.com")]),
            (
                "exampl.e.c",
                vec![
                    TokenType::Alphabetic("exampl"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("e"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("c"),
                ],
            ),
            ("exampl.e.co", vec![TokenType::UrlNoScheme("exampl.e.co")]),
            (
                "e.xample.c",
                vec![
                    TokenType::Alphabetic("e"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("xample"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("c"),
                ],
            ),
            ("e.xample.co", vec![TokenType::UrlNoScheme("e.xample.co")]),
            (
                "v1.1.1",
                vec![
                    TokenType::Alphanumeric("v1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                ],
            ),
            (
                "foo.bar@example.org",
                vec![TokenType::Email("foo.bar@example.org")],
            ),
            (
                "example.com@example.com",
                vec![TokenType::Email("example.com@example.com")],
            ),
            (
                "Look, no scheme: example.org/foo email@foo.com",
                vec![
                    TokenType::Alphabetic("Look"),
                    TokenType::Punctuation(','),
                    TokenType::Space,
                    TokenType::Alphabetic("no"),
                    TokenType::Space,
                    TokenType::Alphabetic("scheme"),
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::UrlNoScheme("example.org/foo"),
                    TokenType::Space,
                    TokenType::Email("email@foo.com"),
                ],
            ),
            (
                "Web:\nwww.foobar.co\nE-Mail:\n      bar@foobar.co (bla bla bla)",
                vec![
                    TokenType::Alphabetic("Web"),
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::UrlNoScheme("www.foobar.co"),
                    TokenType::Space,
                    TokenType::Alphabetic("E"),
                    TokenType::Punctuation('-'),
                    TokenType::Alphabetic("Mail"),
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::Email("bar@foobar.co"),
                    TokenType::Space,
                    TokenType::Punctuation('('),
                    TokenType::Alphabetic("bla"),
                    TokenType::Space,
                    TokenType::Alphabetic("bla"),
                    TokenType::Space,
                    TokenType::Alphabetic("bla"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "upi://pay?pa=XXXXXXX&pn=XXXXX",
                vec![TokenType::UrlNoHost("upi://pay?pa=XXXXXXX&pn=XXXXX")],
            ),
            (
                "https://example.org?pa=XXXXXXX&pn=XXXXX",
                vec![TokenType::Url("https://example.org?pa=XXXXXXX&pn=XXXXX")],
            ),
            (
                "website https://domain.com",
                vec![
                    TokenType::Alphabetic("website"),
                    TokenType::Space,
                    TokenType::Url("https://domain.com"),
                ],
            ),
            ("a12.b-c.com", vec![TokenType::UrlNoScheme("a12.b-c.com")]),
            (
                "v1.2.3",
                vec![
                    TokenType::Alphanumeric("v1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("2"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("3"),
                ],
            ),
            (
                "https://12-7.0.0.1/",
                vec![TokenType::UrlNoHost("https://12-7.0.0.1/")],
            ),
            (
                "https://user:pass@example.com/",
                vec![TokenType::Url("https://user:pass@example.com/")],
            ),
            (
                "https://user:-.!$@example.com/",
                vec![TokenType::Url("https://user:-.!$@example.com/")],
            ),
            (
                "https://user:!$&'()*+,;=@example.com/",
                vec![TokenType::Url("https://user:!$&'()*+,;=@example.com/")],
            ),
            (
                "https://user:pass@ex@mple.com/",
                vec![
                    TokenType::UrlNoHost("https://user:pass@ex"),
                    TokenType::Punctuation('@'),
                    TokenType::UrlNoScheme("mple.com/"),
                ],
            ),
            (
                "https://localhost:8080!",
                vec![
                    TokenType::UrlNoHost("https://localhost:8080"),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "https://localhost:8080/",
                vec![TokenType::UrlNoHost("https://localhost:8080/")],
            ),
            (
                "https://user:pass@example.com:8080/hi",
                vec![TokenType::Url("https://user:pass@example.com:8080/hi")],
            ),
            (
                "https://127.0.0.1/",
                vec![TokenType::Url("https://127.0.0.1/")],
            ),
            ("1.0.0.0", vec![TokenType::IpAddr("1.0.0.0")]),
            (
                "1.0.0.0/foo/bar",
                vec![TokenType::UrlNoScheme("1.0.0.0/foo/bar")],
            ),
            ("1.0 ", vec![TokenType::Float("1.0"), TokenType::Space]),
            (
                "1.0.0",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                ],
            ),
            (
                "1.0.0.0.0",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::IpAddr("0.0.0.0"),
                ],
            ),
            (
                "1.0.0.",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "https://example.com.:8080/test",
                vec![TokenType::Url("https://example.com.:8080/test")],
            ),
            (
                "https://example.org'",
                vec![
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "https://example.org'a@example.com",
                vec![TokenType::Url("https://example.org'a@example.com")],
            ),
            (
                "https://a.com'https://b.com",
                vec![
                    TokenType::UrlNoHost("https://a.com'https"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::UrlNoScheme("b.com"),
                ],
            ),
            (
                "https://example.com...",
                vec![
                    TokenType::Url("https://example.com"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "www.example..com",
                vec![
                    TokenType::Alphabetic("www"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("com"),
                ],
            ),
            (
                "https://.www.example.com",
                vec![TokenType::Url("https://.www.example.com")],
            ),
            (
                "-a.com",
                vec![TokenType::Punctuation('-'), TokenType::UrlNoScheme("a.com")],
            ),
            ("https://a.-b.com", vec![TokenType::Url("https://a.-b.com")]),
            (
                "a-.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("com"),
                ],
            ),
            (
                "a.b-.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("com"),
                ],
            ),
            ("https://a.b-.com", vec![TokenType::Url("https://a.b-.com")]),
            (
                "https://example.com-/",
                vec![
                    TokenType::Url("https://example.com"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "https://example.org-",
                vec![
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('-'),
                ],
            ),
            (
                "example.com@about",
                vec![
                    TokenType::UrlNoScheme("example.com"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("about"),
                ],
            ),
            (
                "example.com/@about",
                vec![TokenType::UrlNoScheme("example.com/@about")],
            ),
            (
                "https://example.com/@about",
                vec![TokenType::Url("https://example.com/@about")],
            ),
            (
                "info@v1.1.1",
                vec![
                    TokenType::Alphabetic("info"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphanumeric("v1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                ],
            ),
            ("file:///", vec![TokenType::UrlNoHost("file:///")]),
            (
                "file:///home/foo",
                vec![TokenType::UrlNoHost("file:///home/foo")],
            ),
            (
                "file://localhost/home/foo",
                vec![TokenType::UrlNoHost("file://localhost/home/foo")],
            ),
            (
                "facetime://+19995551234",
                vec![TokenType::UrlNoHost("facetime://+19995551234")],
            ),
            (
                "test://123'456!!!",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "test://123'456...",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "test://123'456!!!/",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "test://123'456.../",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "1abc://example.com",
                vec![TokenType::Url("1abc://example.com")],
            ),
            (
                "¡¢example.com",
                vec![TokenType::UrlNoScheme("¡¢example.com")],
            ),
            ("foo", vec![TokenType::Alphabetic("foo")]),
            ("@", vec![TokenType::Punctuation('@')]),
            (
                "a@",
                vec![TokenType::Alphabetic("a"), TokenType::Punctuation('@')],
            ),
            (
                "@a",
                vec![TokenType::Punctuation('@'), TokenType::Alphabetic("a")],
            ),
            (
                "@@@",
                vec![
                    TokenType::Punctuation('@'),
                    TokenType::Punctuation('@'),
                    TokenType::Punctuation('@'),
                ],
            ),
            ("foo@example.com", vec![TokenType::Email("foo@example.com")]),
            (
                "foo.bar@example.com",
                vec![TokenType::Email("foo.bar@example.com")],
            ),
            (
                "#!$%&'*+-/=?^_`{}|~@example.org",
                vec![TokenType::Email("#!$%&'*+-/=?^_`{}|~@example.org")],
            ),
            (
                "foo a@b.com",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Space,
                    TokenType::Email("a@b.com"),
                ],
            ),
            (
                "a@b.com foo",
                vec![
                    TokenType::Email("a@b.com"),
                    TokenType::Space,
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "\na@b.com",
                vec![TokenType::Space, TokenType::Email("a@b.com")],
            ),
            (
                "a@b.com\n",
                vec![TokenType::Email("a@b.com"), TokenType::Space],
            ),
            (
                "(a@example.com)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "\"a@example.com\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "\"a@example.com\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                ",a@example.com,",
                vec![
                    TokenType::Punctuation(','),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(','),
                ],
            ),
            (
                ":a@example.com:",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                ";a@example.com;",
                vec![
                    TokenType::Punctuation(';'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                ".@example.com",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('@'),
                    TokenType::UrlNoScheme("example.com"),
                ],
            ),
            (
                "foo.@example.com",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('@'),
                    TokenType::UrlNoScheme("example.com"),
                ],
            ),
            (
                ".foo@example.com",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Email("foo@example.com"),
                ],
            ),
            (
                ".foo@example.com",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Email("foo@example.com"),
                ],
            ),
            (
                "a..b@example.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Email("b@example.com"),
                ],
            ),
            (
                "a@example.com.",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@b",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                ],
            ),
            (
                "a@b.",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@b.com.",
                vec![TokenType::Email("a@b.com"), TokenType::Punctuation('.')],
            ),
            (
                "a@example.com-",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('-'),
                ],
            ),
            ("a@foo-bar.com", vec![TokenType::Email("a@foo-bar.com")]),
            (
                "a@-foo.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Punctuation('-'),
                    TokenType::UrlNoScheme("foo.com"),
                ],
            ),
            (
                "a@b-.",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@b",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                ],
            ),
            (
                "a@b.",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@example.com b@example.com",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Space,
                    TokenType::Email("b@example.com"),
                ],
            ),
            (
                "a@example.com @ b@example.com",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Space,
                    TokenType::Punctuation('@'),
                    TokenType::Space,
                    TokenType::Email("b@example.com"),
                ],
            ),
            (
                "a@xy.com;b@xy.com,c@xy.com",
                vec![
                    TokenType::Email("a@xy.com"),
                    TokenType::Punctuation(';'),
                    TokenType::Email("b@xy.com"),
                    TokenType::Punctuation(','),
                    TokenType::Email("c@xy.com"),
                ],
            ),
            (
                "üñîçøðé@example.com",
                vec![TokenType::Email("üñîçøðé@example.com")],
            ),
            (
                "üñîçøðé@üñîçøðé.com",
                vec![TokenType::Email("üñîçøðé@üñîçøðé.com")],
            ),
            ("www@example.com", vec![TokenType::Email("www@example.com")]),
            (
                "a@a.xyϸ",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("xyϸ"),
                ],
            ),
            (
                "100 -100 100.00 -100.00 $100 $100.00",
                vec![
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Integer("-100"),
                    TokenType::Space,
                    TokenType::Float("100.00"),
                    TokenType::Space,
                    TokenType::Float("-100.00"),
                    TokenType::Space,
                    TokenType::Punctuation('$'),
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Punctuation('$'),
                    TokenType::Float("100.00"),
                ],
            ),
            (
                " - 100 100 . 00",
                vec![
                    TokenType::Space,
                    TokenType::Punctuation('-'),
                    TokenType::Space,
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Punctuation('.'),
                    TokenType::Space,
                    TokenType::Integer("00"),
                ],
            ),
            (
                "send $100.00 to user@domain.com or visit domain.com/pay-me!",
                vec![
                    TokenType::Alphabetic("send"),
                    TokenType::Space,
                    TokenType::Punctuation('$'),
                    TokenType::Float("100.00"),
                    TokenType::Space,
                    TokenType::Alphabetic("to"),
                    TokenType::Space,
                    TokenType::Email("user@domain.com"),
                    TokenType::Space,
                    TokenType::Alphabetic("or"),
                    TokenType::Space,
                    TokenType::Alphabetic("visit"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("domain.com/pay-me"),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "vＥⓡ𝔂 𝔽𝕌Ňℕｙ ţ乇𝕏𝓣 wWiIiIIttHh l133t5p3/-\\|<",
                vec![
                    TokenType::Alphabetic("vＥⓡ𝔂"),
                    TokenType::Space,
                    TokenType::Alphabetic("𝔽𝕌Ňℕｙ"),
                    TokenType::Space,
                    TokenType::Alphabetic("ţ乇𝕏𝓣"),
                    TokenType::Space,
                    TokenType::Alphabetic("wWiIiIIttHh"),
                    TokenType::Space,
                    TokenType::Alphanumeric("l133t5p3"),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('\\'),
                    TokenType::Punctuation('|'),
                    TokenType::Punctuation('<'),
                ],
            ),
        ] {
            let result = TypesTokenizer::new(text)
                .map(|t| t.word)
                .collect::<Vec<_>>();

            assert_eq!(result, expected, "text: {:?}", text);

            /*print!("({text:?}, ");
            print!("vec![");
            for (pos, item) in result.into_iter().enumerate() {
                if pos > 0 {
                    print!(", ");
                }
                print!("TokenType::{:?}", item);
            }
            println!("]),");*/
        }
    }
}
