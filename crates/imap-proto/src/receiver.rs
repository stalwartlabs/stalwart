/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ResponseCode, ResponseType};
use compact_str::{CompactString, format_compact};
use encodify::utf7::IMAP;
use smallvec::SmallVec;
use std::fmt::Display;

pub type ArgumentBytes = SmallVec<[u8; TOKEN_INLINE_LEN]>;

const TOKEN_INLINE_LEN: usize = 22;

#[derive(Debug, Clone)]
pub enum Error {
    NeedsMoreData,
    NeedsLiteral { size: u32 },
    Error { response: trc::Error },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<T: CommandParser> {
    pub tag: CompactString,
    pub command: T,
    pub tokens: Vec<Token>,
}

pub trait CommandParser: Sized + Default {
    fn parse(bytes: &[u8], is_uid: bool) -> Option<Self>;
    fn tokenize_brackets(&self) -> bool;
    fn tokenize_nil(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Argument(ArgumentBytes),
    ParenthesisOpen,  // (
    ParenthesisClose, // )
    BracketOpen,      // [
    BracketClose,     // ]
    Lt,               // <
    Gt,               // >
    Dot,              // .
    Nil,              // NIL
    NilString(ArgumentBytes),
}

impl<T: CommandParser> Default for Request<T> {
    fn default() -> Self {
        Self {
            tag: CompactString::const_new(""),
            command: T::default(),
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum State {
    Start,
    Tag,
    Command { is_uid: bool },
    Argument { last_ch: u8 },
    ArgumentQuoted { escaped: bool },
    Literal { non_sync: bool },
    LiteralSeek { size: u32, non_sync: bool },
    LiteralData { remaining: u32 },
    LiteralDiscard { remaining: u32 },
}

pub struct Receiver<T: CommandParser> {
    buf: ArgumentBuffer,
    pub request: Request<T>,
    pub state: State,
    pub max_request_size: usize,
    pub current_request_size: usize,
    pub start_state: State,
    skipping: bool,
}

pub const MAX_UNAUTHENTICATED_REQUEST_SIZE: usize = 64 * 1024;

const ARG_MAX_LEN: usize = 8000;
const ARG_INIT_LEN: usize = 64;
const TAG_MAX_LEN: usize = 128;
const COMMAND_MAX_LEN: usize = 15;
const LITERAL_MAX_DIGITS: usize = 15;
const TOKENS_INIT_LEN: usize = 32;
const TOKEN_COST: usize = size_of::<Token>();

struct ArgumentBuffer {
    buf: Vec<u8>,
}

const CLASS_ARGUMENT: u8 = 0b0000_0001;
const CLASS_BRACKET: u8 = 0b0000_0010;
const CLASS_QUOTED: u8 = 0b0000_0100;
const CLASS_TAG: u8 = 0b0000_1000;
const CLASS_COMMAND: u8 = 0b0001_0000;
const CLASS_START: u8 = 0b0010_0000;

const BYTE_CLASS: [u8; 256] = byte_class_table();

const fn byte_class_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < 256 {
        let ch = index as u8;
        let is_whitespace = matches!(ch, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r');
        let mut class = 0;
        if is_whitespace || matches!(ch, b'"' | b'{' | b'(' | b')') {
            class |= CLASS_ARGUMENT;
        }
        if matches!(ch, b'[' | b']' | b'<' | b'>' | b'.') {
            class |= CLASS_BRACKET;
        }
        if matches!(ch, b'"' | b'\\' | b'\n') {
            class |= CLASS_QUOTED;
        }
        if matches!(ch, b' ' | b'\t' | b'\r' | b'\n') {
            class |= CLASS_TAG;
        }
        if !matches!(ch, b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z') {
            class |= CLASS_COMMAND;
        }
        if !is_whitespace {
            class |= CLASS_START;
        }
        table[index] = class;
        index += 1;
    }
    table
}

#[inline(always)]
fn run_len(bytes: &[u8], class: u8) -> usize {
    bytes
        .iter()
        .position(|&ch| BYTE_CLASS[ch as usize] & class != 0)
        .unwrap_or(bytes.len())
}

impl<T: CommandParser> Receiver<T> {
    pub fn new() -> Self {
        Receiver {
            max_request_size: 25 * 1024 * 1024, // 25MB
            ..Default::default()
        }
    }

    pub fn with_start_state(mut self, state: State) -> Self {
        self.state = state;
        self.start_state = state;
        self
    }

    pub fn with_max_request_size(max_request_size: usize) -> Self {
        Receiver {
            max_request_size,
            ..Default::default()
        }
    }

    pub fn is_discarding(&self) -> bool {
        matches!(self.state, State::LiteralDiscard { .. })
    }

    pub fn error_reset(&mut self, message: impl Into<trc::Value>) -> Error {
        self.error_reset_with(message, ResponseCode::Parse)
    }

    fn error_reset_with(&mut self, message: impl Into<trc::Value>, code: ResponseCode) -> Error {
        let request = std::mem::take(&mut self.request);
        let err = Error::err(
            if !request.tag.is_empty() {
                request.tag.into()
            } else {
                None
            },
            message,
            code,
        );
        self.buf = ArgumentBuffer::default();
        self.state = self.start_state;
        self.current_request_size = 0;
        self.skipping = false;
        err
    }

    fn end_skipped_command(&mut self) {
        self.skipping = false;
        self.request = Request::default();
        self.buf.clear();
        self.current_request_size = 0;
    }

    #[cold]
    #[inline(never)]
    fn literal_size_error(&mut self) -> Error {
        self.error_reset_with(
            format_compact!(
                "Literal exceeds the maximum request size of {} bytes.",
                self.max_request_size
            ),
            ResponseCode::TooBig,
        )
    }

    #[inline(never)]
    fn request_size_error(&mut self) -> Error {
        self.error_reset(format_compact!(
            "Request exceeds maximum limit of {} bytes.",
            self.max_request_size
        ))
    }

    #[inline(always)]
    fn push_request_token(&mut self, token: Token, len: usize) -> Result<(), Error> {
        if self.skipping {
            return Ok(());
        }
        self.current_request_size += len + TOKEN_COST;
        if self.current_request_size > self.max_request_size {
            return Err(self.request_size_error());
        }
        if self.request.tokens.is_empty() {
            self.request.tokens.reserve(TOKENS_INIT_LEN);
        }
        self.request.tokens.push(token);
        Ok(())
    }

    fn push_argument(&mut self, in_quote: bool) -> Result<(), Error> {
        if !self.buf.is_empty() {
            let token = Token::Argument(ArgumentBytes::from_slice(self.buf.as_ref()));
            self.push_request_token(token, self.buf.len())?;
            self.buf.clear();
        } else if in_quote {
            self.push_request_token(Token::Nil, 0)?;
        }
        Ok(())
    }

    fn push_literal(&mut self) -> Result<(), Error> {
        if !self.buf.is_empty() {
            if self.request.command.tokenize_nil() && self.is_nil() {
                return self.push_nil_string();
            }
            let len = self.buf.len();
            let token = Token::Argument(ArgumentBytes::from_vec(self.buf.take_moved()));
            self.push_request_token(token, len)?;
        }
        Ok(())
    }

    fn is_nil(&self) -> bool {
        self.buf.as_ref().eq_ignore_ascii_case(b"NIL")
    }

    #[cold]
    fn push_nil_string(&mut self) -> Result<(), Error> {
        let token = Token::NilString(ArgumentBytes::from_slice(self.buf.as_ref()));
        self.push_request_token(token, self.buf.len())?;
        self.buf.clear();
        Ok(())
    }

    fn push_token(&mut self, token: Token) -> Result<(), Error> {
        self.push_request_token(token, 0)
    }

    pub fn parse(&mut self, bytes: &mut std::slice::Iter<'_, u8>) -> Result<Request<T>, Error> {
        let mut state = self.state;

        'outer: loop {
            match state {
                State::Start => {
                    match bytes.find(|&&ch| BYTE_CLASS[ch as usize] & CLASS_START != 0) {
                        Some(&ch) => {
                            self.buf.push_unchecked(ch);
                            state = State::Tag;
                        }
                        None => break,
                    }
                }
                State::Tag => {
                    let slice = bytes.as_slice();
                    let (run, tail) = slice.split_at(run_len(slice, CLASS_TAG));
                    if let Err(allowed) = self.buf.extend_checked(run, TAG_MAX_LEN) {
                        *bytes = slice.split_at(allowed + 1).1.iter();
                        return Err(
                            self.error_reset("Tag exceeds maximum length of 128 characters.")
                        );
                    }
                    let Some((&ch, rest)) = tail.split_first() else {
                        *bytes = tail.iter();
                        break;
                    };
                    *bytes = rest.iter();
                    match ch {
                        b' ' => {
                            if !self.buf.is_empty() {
                                match CompactString::from_utf8(self.buf.as_ref()) {
                                    Ok(tag) => {
                                        self.request.tag = tag;
                                        self.buf.clear();
                                    }
                                    Err(_) => {
                                        return Err(
                                            self.error_reset("Tag is not a valid UTF-8 string.")
                                        );
                                    }
                                }
                                state = State::Command { is_uid: false };
                            }
                        }
                        b'\n' => {
                            return Err(self.error_reset(format_compact!(
                                "Missing command after tag {:?}, found CRLF instead.",
                                self.buf.as_str()
                            )));
                        }
                        _ => {}
                    }
                }
                State::Command { is_uid } => {
                    let slice = bytes.as_slice();
                    let (run, tail) = slice.split_at(run_len(slice, CLASS_COMMAND));
                    if let Err(allowed) = self.buf.extend_checked_uppercase(run, COMMAND_MAX_LEN) {
                        *bytes = slice.split_at(allowed + 1).1.iter();
                        return Err(
                            self.error_reset("Command exceeds maximum length of 15 characters.")
                        );
                    }
                    let Some((&ch, rest)) = tail.split_first() else {
                        *bytes = tail.iter();
                        break;
                    };
                    *bytes = rest.iter();
                    if !ch.is_ascii_whitespace() {
                        return Err(self.error_reset(format_compact!(
                            "Invalid character {:?} in command name.",
                            ch as char
                        )));
                    }
                    if !self.buf.is_empty() {
                        if !self.buf.as_ref().eq_ignore_ascii_case(b"UID") {
                            self.request.command =
                                T::parse(self.buf.as_ref(), is_uid).ok_or_else(|| {
                                    let err = format_compact!(
                                        "Unrecognized command '{}'.",
                                        String::from_utf8_lossy(self.buf.as_ref())
                                    );
                                    self.error_reset(err)
                                })?;
                            self.buf.clear();
                            if ch != b'\n' {
                                state = State::Argument { last_ch: b' ' };
                            } else {
                                self.state = self.start_state;
                                self.current_request_size = 0;
                                return Ok(std::mem::take(&mut self.request));
                            }
                        } else {
                            self.buf.clear();
                            state = State::Command { is_uid: true };
                        }
                    }
                }
                State::Argument { last_ch } => {
                    let mut last_ch = last_ch;
                    let class = if self.request.command.tokenize_brackets() {
                        CLASS_ARGUMENT | CLASS_BRACKET
                    } else {
                        CLASS_ARGUMENT
                    };
                    loop {
                        let slice = bytes.as_slice();
                        let (run, tail) = slice.split_at(run_len(slice, class));
                        if let Some(&last) = run.last() {
                            if let Err(allowed) = self.buf.extend_checked(run, ARG_MAX_LEN) {
                                *bytes = slice.split_at(allowed + 1).1.iter();
                                return Err(self.error_reset(
                                    "Argument exceeds maximum length of 8000 bytes.",
                                ));
                            }
                            last_ch = last;
                        }
                        let Some((&ch, rest)) = tail.split_first() else {
                            *bytes = tail.iter();
                            state = State::Argument { last_ch };
                            break 'outer;
                        };
                        *bytes = rest.iter();
                        match ch {
                            b'\"' if last_ch.is_ascii_whitespace() => {
                                self.push_argument(false)?;
                                state = State::ArgumentQuoted { escaped: false };
                                continue 'outer;
                            }
                            b'{' if last_ch.is_ascii_whitespace()
                                || (last_ch == b'~' && self.buf.len() == 1) =>
                            {
                                if last_ch != b'~' {
                                    self.push_argument(false)?;
                                } else {
                                    self.buf.clear();
                                }
                                state = State::Literal { non_sync: false };
                                continue 'outer;
                            }
                            b'(' => {
                                self.push_argument(false)?;
                                self.push_token(Token::ParenthesisOpen)?;
                            }
                            b')' => {
                                self.push_argument(false)?;
                                self.push_token(Token::ParenthesisClose)?;
                            }
                            b'[' => {
                                self.push_argument(false)?;
                                self.push_token(Token::BracketOpen)?;
                            }
                            b']' => {
                                self.push_argument(false)?;
                                self.push_token(Token::BracketClose)?;
                            }
                            b'<' => {
                                self.push_argument(false)?;
                                self.push_token(Token::Lt)?;
                            }
                            b'>' => {
                                self.push_argument(false)?;
                                self.push_token(Token::Gt)?;
                            }
                            b'.' => {
                                self.push_argument(false)?;
                                self.push_token(Token::Dot)?;
                            }
                            b'\n' if self.skipping => {
                                self.end_skipped_command();
                                state = self.start_state;
                                continue 'outer;
                            }
                            b'\n' => {
                                self.push_argument(false)?;
                                self.state = self.start_state;
                                self.current_request_size = 0;
                                return Ok(std::mem::take(&mut self.request));
                            }
                            _ if ch.is_ascii_whitespace() => {
                                self.push_argument(false)?;
                                last_ch = ch;
                            }
                            _ => {
                                self.buf.push_checked(ch, ARG_MAX_LEN).map_err(|_| {
                                    self.error_reset(
                                        "Argument exceeds maximum length of 8000 bytes.",
                                    )
                                })?;
                                last_ch = ch;
                            }
                        }
                    }
                }
                State::ArgumentQuoted { escaped } => {
                    if escaped {
                        let Some(&ch) = bytes.next() else { break };
                        match ch {
                            b'\n' => {
                                return Err(self.error_reset("Unterminated quoted argument."));
                            }
                            b'\"' | b'\\' => {
                                self.buf
                                    .push_checked(ch, ARG_MAX_LEN)
                                    .map_err(|_| self.error_reset("Quoted argument too long."))?;
                            }
                            _ => {
                                self.buf.push_unchecked(b'\\');
                                self.buf
                                    .push_checked(ch, ARG_MAX_LEN)
                                    .map_err(|_| self.error_reset("Quoted argument too long."))?;
                            }
                        }
                        state = State::ArgumentQuoted { escaped: false };
                        continue;
                    }
                    let slice = bytes.as_slice();
                    let (run, tail) = slice.split_at(run_len(slice, CLASS_QUOTED));
                    if let Err(allowed) = self.buf.extend_checked(run, ARG_MAX_LEN) {
                        *bytes = slice.split_at(allowed + 1).1.iter();
                        return Err(self.error_reset("Quoted argument too long."));
                    }
                    let Some((&ch, rest)) = tail.split_first() else {
                        *bytes = tail.iter();
                        break;
                    };
                    *bytes = rest.iter();
                    match ch {
                        b'\"' => {
                            if self.request.command.tokenize_nil() && self.is_nil() {
                                self.push_nil_string()?;
                            } else {
                                self.push_argument(true)?;
                            }
                            state = State::Argument { last_ch: b' ' };
                        }
                        b'\\' => {
                            state = State::ArgumentQuoted { escaped: true };
                        }
                        _ => {
                            return Err(self.error_reset("Unterminated quoted argument."));
                        }
                    }
                }
                State::Literal { non_sync } => {
                    let Some(&ch) = bytes.next() else { break };
                    match ch {
                        b'}' => {
                            if !self.buf.is_empty() {
                                let size = self.buf.as_str().parse::<u32>().map_err(|_| {
                                    self.error_reset("Literal size is not a valid number.")
                                })?;
                                if self.skipping {
                                    self.buf.clear();
                                    if non_sync {
                                        state = State::LiteralSeek { size, non_sync };
                                    } else {
                                        self.end_skipped_command();
                                        state = self.start_state;
                                    }
                                    continue;
                                }
                                let oversize = self.current_request_size + size as usize
                                    > self.max_request_size;
                                if oversize && !non_sync {
                                    return Err(self.literal_size_error());
                                }
                                state = State::LiteralSeek { size, non_sync };
                                if !oversize {
                                    self.buf.resize_buffer(size as usize);
                                }
                                self.buf.clear();
                            } else {
                                return Err(self.error_reset("Invalid empty literal."));
                            }
                        }
                        b'+' => {
                            if !self.buf.is_empty() {
                                state = State::Literal { non_sync: true };
                            } else {
                                return Err(self.error_reset("Invalid non-sync literal."));
                            }
                        }
                        _ if ch.is_ascii_digit() => {
                            if !non_sync {
                                self.buf.push_checked(ch, LITERAL_MAX_DIGITS).map_err(|_| {
                                    self.error_reset("Literal size exceeds maximum of 15 digits.")
                                })?;
                            } else {
                                return Err(self.error_reset("Invalid literal."));
                            }
                        }
                        _ => {
                            return Err(self.error_reset(format_compact!(
                                "Invalid character {:?} in literal.",
                                ch as char
                            )));
                        }
                    }
                }
                State::LiteralSeek { size, non_sync } => {
                    let Some(&ch) = bytes.next() else { break };
                    if ch == b'\n' {
                        if self.skipping {
                            state = State::LiteralDiscard { remaining: size };
                        } else if non_sync
                            && self.current_request_size + size as usize > self.max_request_size
                        {
                            let err = self.literal_size_error();
                            self.skipping = true;
                            self.state = State::LiteralDiscard { remaining: size };
                            return Err(err);
                        } else if size > 0 {
                            state = State::LiteralData { remaining: size };
                            if !non_sync {
                                self.state = state;
                                return Err(Error::NeedsLiteral { size });
                            }
                        } else {
                            state = State::Argument { last_ch: b' ' };
                            self.push_token(Token::Nil)?;
                            if !non_sync {
                                self.state = state;
                                return Err(Error::NeedsLiteral { size });
                            }
                        }
                    } else if !ch.is_ascii_whitespace() {
                        return Err(
                            self.error_reset("Expected CRLF after literal, found an invalid char.")
                        );
                    }
                }
                State::LiteralDiscard { remaining } => {
                    let available = bytes.as_slice();
                    let taken = (remaining as usize).min(available.len());
                    *bytes = available.split_at(taken).1.iter();
                    let remaining = remaining - taken as u32;
                    if remaining > 0 {
                        state = State::LiteralDiscard { remaining };
                        break;
                    }
                    state = State::Argument { last_ch: b' ' };
                }
                State::LiteralData { remaining } => {
                    let Some(&ch) = bytes.next() else { break };
                    self.buf.push_unchecked(ch);
                    let mut remaining = remaining - 1;

                    if remaining > 0 {
                        let available = bytes.as_slice();
                        let taken = (remaining as usize).min(available.len());
                        if taken > 0 {
                            let (run, tail) = available.split_at(taken);
                            self.buf.extend_from_slice(run);
                            *bytes = tail.iter();
                            remaining -= taken as u32;
                        }
                    }

                    if remaining > 0 {
                        state = State::LiteralData { remaining };
                    } else {
                        self.push_literal()?;
                        state = State::Argument { last_ch: b' ' };
                    }
                }
            }
        }

        self.state = state;
        Err(Error::NeedsMoreData)
    }
}

impl ArgumentBuffer {
    pub fn new() -> Self {
        ArgumentBuffer {
            buf: Vec::with_capacity(ARG_INIT_LEN),
        }
    }

    pub fn resize_buffer(&mut self, size: usize) {
        self.buf.reserve(size.saturating_sub(self.buf.len()));
    }

    #[inline(always)]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    #[inline(always)]
    pub fn extend_checked(&mut self, bytes: &[u8], limit: usize) -> Result<(), usize> {
        let allowed = limit.saturating_sub(self.buf.len());
        if bytes.len() <= allowed {
            self.buf.extend_from_slice(bytes);
            Ok(())
        } else {
            Err(allowed)
        }
    }

    #[inline(always)]
    pub fn extend_checked_uppercase(&mut self, bytes: &[u8], limit: usize) -> Result<(), usize> {
        let allowed = limit.saturating_sub(self.buf.len());
        if bytes.len() <= allowed {
            let appended_from = self.buf.len();
            self.buf.extend_from_slice(bytes);
            if let Some(appended) = self.buf.get_mut(appended_from..) {
                appended.make_ascii_uppercase();
            }
            Ok(())
        } else {
            Err(allowed)
        }
    }

    #[inline(always)]
    pub fn push_checked(&mut self, byte: u8, limit: usize) -> Result<(), ()> {
        if self.buf.len() < limit {
            self.buf.push(byte);
            Ok(())
        } else {
            Err(())
        }
    }

    #[inline(always)]
    pub fn push_unchecked(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    pub fn take_moved(&mut self) -> Vec<u8> {
        std::mem::replace(&mut self.buf, Vec::with_capacity(ARG_INIT_LEN))
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    #[inline(always)]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf).unwrap_or_default()
    }
}

impl Token {
    pub fn unwrap_string(self) -> crate::parser::Result<CompactString> {
        match self {
            Token::Argument(value) if value.spilled() => String::from_utf8(value.into_vec())
                .map(CompactString::from_string_buffer)
                .map_err(|_| "Invalid UTF-8 in argument.".into()),
            Token::Argument(value) => CompactString::from_utf8(value.as_slice())
                .map_err(|_| "Invalid UTF-8 in argument.".into()),
            other => Ok(CompactString::from(other.to_string())),
        }
    }

    pub fn unwrap_mailbox_name(self, is_utf8: bool) -> crate::parser::Result<CompactString> {
        let name = self.unwrap_string()?;
        if is_utf8 || !name.contains('&') {
            Ok(name)
        } else {
            Ok(IMAP
                .lenient()
                .decode(name.as_bytes())
                .map(CompactString::from_string_buffer)
                .unwrap_or(name))
        }
    }

    pub fn unwrap_mailbox_name_strict(self, is_utf8: bool) -> crate::parser::Result<CompactString> {
        let name = self.unwrap_string()?;
        if is_utf8 || !name.contains('&') {
            Ok(name)
        } else {
            IMAP.decode(name.as_bytes())
                .map(CompactString::from_string_buffer)
                .map_err(|err| format!("Invalid modified UTF-7 in mailbox name: {err}.").into())
        }
    }

    pub fn unwrap_bytes(self) -> ArgumentBytes {
        match self {
            Token::Argument(value) | Token::NilString(value) => value,
            other => ArgumentBytes::from_slice(other.as_bytes()),
        }
    }

    pub fn eq_ignore_ascii_case(&self, bytes: &[u8]) -> bool {
        match self {
            Token::Argument(argument) => argument.eq_ignore_ascii_case(bytes),
            Token::ParenthesisOpen => bytes.eq(b"("),
            Token::ParenthesisClose => bytes.eq(b")"),
            Token::BracketOpen => bytes.eq(b"["),
            Token::BracketClose => bytes.eq(b"]"),
            Token::Gt => bytes.eq(b">"),
            Token::Lt => bytes.eq(b"<"),
            Token::Dot => bytes.eq(b"."),
            Token::Nil => bytes.is_empty(),
            Token::NilString(value) => value.eq_ignore_ascii_case(bytes),
        }
    }

    pub fn is_parenthesis_open(&self) -> bool {
        matches!(self, Token::ParenthesisOpen)
    }

    pub fn is_parenthesis_close(&self) -> bool {
        matches!(self, Token::ParenthesisClose)
    }

    pub fn is_bracket_open(&self) -> bool {
        matches!(self, Token::BracketOpen)
    }

    pub fn is_bracket_close(&self) -> bool {
        matches!(self, Token::BracketClose)
    }

    pub fn is_dot(&self) -> bool {
        matches!(self, Token::Dot)
    }

    pub fn is_lt(&self) -> bool {
        matches!(self, Token::Lt)
    }

    pub fn is_gt(&self) -> bool {
        matches!(self, Token::Gt)
    }
}

impl AsRef<[u8]> for ArgumentBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Default for ArgumentBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(self.as_bytes()))
    }
}

impl Token {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Token::Argument(value) => value.as_slice(),
            Token::ParenthesisOpen => b"(",
            Token::ParenthesisClose => b")",
            Token::BracketOpen => b"[",
            Token::BracketClose => b"]",
            Token::Gt => b">",
            Token::Lt => b"<",
            Token::Dot => b".",
            Token::Nil => b"",
            Token::NilString(value) => value.as_slice(),
        }
    }
}

impl Error {
    pub fn err(
        tag: Option<impl Into<CompactString>>,
        message: impl Into<trc::Value>,
        code: ResponseCode,
    ) -> Self {
        Error::Error {
            response: trc::ImapEvent::Error
                .ctx(trc::Key::Details, message)
                .ctx_opt(trc::Key::Id, tag.map(Into::into))
                .ctx(trc::Key::Type, ResponseType::Bad)
                .code(code),
        }
    }
}

impl<T: CommandParser> Default for Receiver<T> {
    fn default() -> Self {
        Self {
            buf: Default::default(),
            request: Default::default(),
            state: State::Start,
            start_state: State::Start,
            max_request_size: 25 * 1024 * 1024,
            current_request_size: 0,
            skipping: false,
        }
    }
}

impl<T: CommandParser> Request<T> {
    pub fn into_error(self, message: impl Into<trc::Value>) -> trc::Error {
        trc::ImapEvent::Error
            .ctx(trc::Key::Details, message)
            .ctx(trc::Key::Id, self.tag)
    }

    pub fn into_parse_error(self, message: impl Into<trc::Value>) -> trc::Error {
        trc::ImapEvent::Error
            .ctx(trc::Key::Details, message)
            .ctx(trc::Key::Id, self.tag)
            .ctx(trc::Key::Code, ResponseCode::Parse)
            .ctx(trc::Key::Type, ResponseType::Bad)
    }
}

pub(crate) fn bad(tag: impl Into<trc::Value>, message: impl Into<trc::Value>) -> trc::Error {
    trc::ImapEvent::Error
        .ctx(trc::Key::Details, message)
        .ctx(trc::Key::Id, tag)
        .ctx(trc::Key::Type, ResponseType::Bad)
}

/*

astring         = 1*ASTRING-CHAR / string

string          = quoted / literal

literal         = "{" number64 ["+"] "}" CRLF *CHAR8

quoted          = DQUOTE *QUOTED-CHAR DQUOTE

ASTRING-CHAR   = ATOM-CHAR / resp-specials

atom            = 1*ATOM-CHAR

ATOM-CHAR       = <any CHAR except atom-specials>

atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
                  quoted-specials / resp-specials

resp-specials   = "]"

list-wildcards  = "%" / "*"

quoted-specials = DQUOTE / "\"

DQUOTE         =  %x22 ; " (Double Quote)

*/

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/imap-proto/src/receiver/tests.rs"]
mod tests;
