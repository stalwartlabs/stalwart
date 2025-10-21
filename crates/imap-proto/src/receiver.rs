/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ResponseCode, ResponseType};
use compact_str::{CompactString, format_compact};
use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum Error {
    NeedsMoreData,
    NeedsLiteral { size: u32 },
    Error { response: trc::Error },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<T: CommandParser> {
    pub tag: String,
    pub command: T,
    pub tokens: Vec<Token>,
}

pub trait CommandParser: Sized + Default {
    fn parse(bytes: &[u8], is_uid: bool) -> Option<Self>;
    fn tokenize_brackets(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Argument(Vec<u8>),
    ParenthesisOpen,  // (
    ParenthesisClose, // )
    BracketOpen,      // [
    BracketClose,     // ]
    Lt,               // <
    Gt,               // >
    Dot,              // .
    Nil,              // NIL
}

impl<T: CommandParser> Default for Request<T> {
    fn default() -> Self {
        Self {
            tag: String::new(),
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
}

pub struct Receiver<T: CommandParser> {
    buf: ArgumentBuffer,
    pub request: Request<T>,
    pub state: State,
    pub max_request_size: usize,
    pub current_request_size: usize,
    pub start_state: State,
}

const ARG_MAX_LEN: usize = 4096;

struct ArgumentBuffer {
    buf: Vec<u8>,
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

    pub fn error_reset(&mut self, message: impl Into<trc::Value>) -> Error {
        let request = std::mem::take(&mut self.request);
        let err = Error::err(
            if !request.tag.is_empty() {
                request.tag.into()
            } else {
                None
            },
            message,
        );
        self.buf = ArgumentBuffer::default();
        self.state = self.start_state;
        self.current_request_size = 0;
        err
    }

    fn push_argument(&mut self, in_quote: bool) -> Result<(), Error> {
        if !self.buf.is_empty() {
            self.current_request_size += self.buf.len();
            if self.current_request_size > self.max_request_size {
                return Err(self.error_reset(format_compact!(
                    "Request exceeds maximum limit of {} bytes.",
                    self.max_request_size
                )));
            }
            self.request.tokens.push(Token::Argument(self.buf.take()));
        } else if in_quote {
            self.request.tokens.push(Token::Nil);
        }
        Ok(())
    }

    fn push_token(&mut self, token: Token) -> Result<(), Error> {
        self.current_request_size += 1;
        if self.current_request_size > self.max_request_size {
            return Err(self.error_reset(format_compact!(
                "Request exceeds maximum limit of {} bytes.",
                self.max_request_size
            )));
        }
        self.request.tokens.push(token);
        Ok(())
    }

    pub fn parse(&mut self, bytes: &mut std::slice::Iter<'_, u8>) -> Result<Request<T>, Error> {
        #[allow(clippy::while_let_on_iterator)]
        while let Some(&ch) = bytes.next() {
            match self.state {
                State::Start => {
                    if !ch.is_ascii_whitespace() {
                        // SAFETY: This called just once
                        self.buf.push_unchecked(ch);
                        self.state = State::Tag;
                    }
                }
                State::Tag => match ch {
                    b' ' => {
                        if !self.buf.is_empty() {
                            self.request.tag =
                                String::from_utf8(self.buf.take()).map_err(|_| {
                                    self.error_reset("Tag is not a valid UTF-8 string.")
                                })?;
                            self.state = State::Command { is_uid: false };
                        }
                    }
                    b'\t' | b'\r' => {}
                    b'\n' => {
                        return Err(self.error_reset(format_compact!(
                            "Missing command after tag {:?}, found CRLF instead.",
                            self.buf.as_str()
                        )));
                    }
                    _ => {
                        self.buf.push_checked(ch, 128).map_err(|_| {
                            self.error_reset("Tag exceeds maximum length of 128 characters.")
                        })?;
                    }
                },
                State::Command { is_uid } => {
                    if ch.is_ascii_alphanumeric() {
                        self.buf
                            .push_checked(ch.to_ascii_uppercase(), 15)
                            .map_err(|_| {
                                self.error_reset("Command exceeds maximum length of 15 characters.")
                            })?;
                    } else if ch.is_ascii_whitespace() {
                        if !self.buf.is_empty() {
                            if !self.buf.as_ref().eq_ignore_ascii_case(b"UID") {
                                self.request.command = T::parse(self.buf.as_ref(), is_uid)
                                    .ok_or_else(|| {
                                        let err = format_compact!(
                                            "Unrecognized command '{}'.",
                                            String::from_utf8_lossy(self.buf.as_ref())
                                        );
                                        self.error_reset(err)
                                    })?;
                                self.buf.clear();
                                if ch != b'\n' {
                                    self.state = State::Argument { last_ch: b' ' };
                                } else {
                                    self.state = self.start_state;
                                    self.current_request_size = 0;
                                    return Ok(std::mem::take(&mut self.request));
                                }
                            } else {
                                self.buf.clear();
                                self.state = State::Command { is_uid: true };
                            }
                        }
                    } else {
                        return Err(self.error_reset(format_compact!(
                            "Invalid character {:?} in command name.",
                            ch as char
                        )));
                    }
                }
                State::Argument { last_ch } => match ch {
                    b'\"' if last_ch.is_ascii_whitespace() => {
                        self.push_argument(false)?;
                        self.state = State::ArgumentQuoted { escaped: false };
                    }
                    b'{' if last_ch.is_ascii_whitespace()
                        || (last_ch == b'~' && self.buf.len() == 1) =>
                    {
                        if last_ch != b'~' {
                            self.push_argument(false)?;
                        } else {
                            self.buf.clear();
                        }
                        self.state = State::Literal { non_sync: false };
                    }
                    b'(' => {
                        self.push_argument(false)?;
                        self.push_token(Token::ParenthesisOpen)?;
                    }
                    b')' => {
                        self.push_argument(false)?;
                        self.push_token(Token::ParenthesisClose)?;
                    }
                    b'[' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::BracketOpen)?;
                    }
                    b']' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::BracketClose)?;
                    }
                    b'<' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Lt)?;
                    }
                    b'>' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Gt)?;
                    }
                    b'.' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Dot)?;
                    }
                    b'\n' => {
                        self.push_argument(false)?;
                        self.state = self.start_state;
                        self.current_request_size = 0;
                        return Ok(std::mem::take(&mut self.request));
                    }
                    _ if ch.is_ascii_whitespace() => {
                        self.push_argument(false)?;
                        self.state = State::Argument { last_ch: ch };
                    }
                    _ => {
                        self.buf.push_checked(ch, ARG_MAX_LEN).map_err(|_| {
                            self.error_reset("Argument exceeds maximum length of 4096 bytes.")
                        })?;
                        self.state = State::Argument { last_ch: ch };
                    }
                },
                State::ArgumentQuoted { escaped } => match ch {
                    b'\"' => {
                        if !escaped {
                            self.push_argument(true)?;
                            self.state = State::Argument { last_ch: b' ' };
                        } else {
                            self.buf
                                .push_checked(ch, ARG_MAX_LEN)
                                .map_err(|_| self.error_reset("Quoted argument too long."))?;
                            self.state = State::ArgumentQuoted { escaped: false };
                        }
                    }
                    b'\\' => {
                        if escaped {
                            self.buf
                                .push_checked(ch, ARG_MAX_LEN)
                                .map_err(|_| self.error_reset("Quoted argument too long."))?;
                        }
                        self.state = State::ArgumentQuoted { escaped: !escaped };
                    }
                    b'\n' => {
                        return Err(self.error_reset("Unterminated quoted argument."));
                    }
                    _ => {
                        if escaped {
                            // SAFETY: We check the size below
                            self.buf.push_unchecked(b'\\');
                        }
                        self.buf
                            .push_checked(ch, ARG_MAX_LEN)
                            .map_err(|_| self.error_reset("Quoted argument too long."))?;
                        self.state = State::ArgumentQuoted { escaped: false };
                    }
                },
                State::Literal { non_sync } => {
                    match ch {
                        b'}' => {
                            if !self.buf.is_empty() {
                                let size = self.buf.as_str().parse::<u32>().map_err(|_| {
                                    self.error_reset("Literal size is not a valid number.")
                                })?;
                                if self.current_request_size + size as usize > self.max_request_size
                                {
                                    return Err(self.error_reset(format_compact!(
                                        "Literal exceeds the maximum request size of {} bytes.",
                                        self.max_request_size
                                    )));
                                }
                                self.state = State::LiteralSeek { size, non_sync };
                                self.buf.resize_buffer(size as usize);
                                self.buf.clear();
                            } else {
                                return Err(self.error_reset("Invalid empty literal."));
                            }
                        }
                        b'+' => {
                            if !self.buf.is_empty() {
                                self.state = State::Literal { non_sync: true };
                            } else {
                                return Err(self.error_reset("Invalid non-sync literal."));
                            }
                        }
                        _ if ch.is_ascii_digit() => {
                            if !non_sync {
                                self.buf.push_checked(ch, 15).map_err(|_| {
                                    self.error_reset("Literal size exceeds maximum of 15 digits.")
                                })?;
                            } else {
                                // Digit found after non-sync '+' flag
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
                    if ch == b'\n' {
                        if size > 0 {
                            self.state = State::LiteralData { remaining: size };
                        } else {
                            self.state = State::Argument { last_ch: b' ' };
                            self.push_token(Token::Nil)?;
                        }
                        if !non_sync {
                            return Err(Error::NeedsLiteral { size });
                        }
                    } else if !ch.is_ascii_whitespace() {
                        return Err(
                            self.error_reset("Expected CRLF after literal, found an invalid char.")
                        );
                    }
                }
                State::LiteralData { remaining } => {
                    // SAFETY: We checked the size before entering this state
                    self.buf.push_unchecked(ch);

                    if remaining > 1 {
                        self.state = State::LiteralData {
                            remaining: remaining - 1,
                        };
                    } else {
                        self.push_argument(false)?;
                        self.state = State::Argument { last_ch: b' ' };
                    }
                }
            }
        }

        Err(Error::NeedsMoreData)
    }
}

impl ArgumentBuffer {
    pub fn new() -> Self {
        ArgumentBuffer {
            buf: Vec::with_capacity(10),
        }
    }

    pub fn resize_buffer(&mut self, size: usize) {
        if self.buf.capacity() < size {
            self.buf.reserve(size - self.buf.capacity());
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

    pub fn take(&mut self) -> Vec<u8> {
        let buf = self.buf.clone();
        self.buf.clear();
        buf
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
    pub fn unwrap_string(self) -> crate::parser::Result<String> {
        match self {
            Token::Argument(value) => {
                String::from_utf8(value).map_err(|_| "Invalid UTF-8 in argument.".into())
            }
            other => Ok(other.to_string()),
        }
    }

    pub fn unwrap_bytes(self) -> Vec<u8> {
        match self {
            Token::Argument(value) => value,
            other => other.as_bytes().to_vec(),
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
            Token::Argument(value) => value,
            Token::ParenthesisOpen => b"(",
            Token::ParenthesisClose => b")",
            Token::BracketOpen => b"[",
            Token::BracketClose => b"]",
            Token::Gt => b">",
            Token::Lt => b"<",
            Token::Dot => b".",
            Token::Nil => b"",
        }
    }
}

impl Error {
    pub fn err(tag: Option<impl Into<CompactString>>, message: impl Into<trc::Value>) -> Self {
        Error::Error {
            response: trc::ImapEvent::Error
                .ctx(trc::Key::Details, message)
                .ctx_opt(trc::Key::Id, tag.map(Into::into))
                .ctx(trc::Key::Type, ResponseType::Bad)
                .code(ResponseCode::Parse),
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
        }
    }
}

impl<T: CommandParser> Request<T> {
    pub fn into_error(self, message: impl Into<trc::Value>) -> trc::Error {
        trc::ImapEvent::Error
            .ctx(trc::Key::Details, message)
            .ctx(trc::Key::Id, CompactString::from_string_buffer(self.tag))
    }

    pub fn into_parse_error(self, message: impl Into<trc::Value>) -> trc::Error {
        trc::ImapEvent::Error
            .ctx(trc::Key::Details, message)
            .ctx(trc::Key::Id, CompactString::from_string_buffer(self.tag))
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

#[cfg(test)]
mod tests {

    use crate::Command;

    use super::{Error, Receiver, Request, Token};

    #[test]
    fn receiver_parse_ok() {
        let mut receiver = Receiver::new();

        for (frames, expected_requests) in [
            (
                vec!["abcd CAPABILITY\r\n"],
                vec![Request {
                    tag: "abcd".into(),
                    command: Command::Capability,
                    tokens: vec![],
                }],
            ),
            (
                vec!["A023 LO", "GOUT\r\n"],
                vec![Request {
                    tag: "A023".into(),
                    command: Command::Logout,
                    tokens: vec![],
                }],
            ),
            (
                vec!["  A001 AUTHENTICATE GSSAPI  \r\n"],
                vec![Request {
                    tag: "A001".into(),
                    command: Command::Authenticate,
                    tokens: vec![Token::Argument(b"GSSAPI".to_vec())],
                }],
            ),
            (
                vec!["A03   AUTHENTICATE ", "PLAIN dGVzdAB0ZXN", "0AHRlc3Q=\r\n"],
                vec![Request {
                    tag: "A03".into(),
                    command: Command::Authenticate,
                    tokens: vec![
                        Token::Argument(b"PLAIN".to_vec()),
                        Token::Argument(b"dGVzdAB0ZXN0AHRlc3Q=".to_vec()),
                    ],
                }],
            ),
            (
                vec!["A003 CREATE owatagusiam/\r\n"],
                vec![Request {
                    tag: "A003".into(),
                    command: Command::Create,
                    tokens: vec![Token::Argument(b"owatagusiam/".to_vec())],
                }],
            ),
            (
                vec!["A682 LIST \"\" *\r\n"],
                vec![Request {
                    tag: "A682".into(),
                    command: Command::List,
                    tokens: vec![Token::Nil, Token::Argument(b"*".to_vec())],
                }],
            ),
            (
                vec!["A03 LIST () \"\" \"%\" RETURN (CHILDREN)\r\n"],
                vec![Request {
                    tag: "A03".into(),
                    command: Command::List,
                    tokens: vec![
                        Token::ParenthesisOpen,
                        Token::ParenthesisClose,
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"CHILDREN".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A05 LIST (REMOTE SUBSCRIBED) \"\" \"*\"\r\n"],
                vec![Request {
                    tag: "A05".into(),
                    command: Command::List,
                    tokens: vec![
                        Token::ParenthesisOpen,
                        Token::Argument(b"REMOTE".to_vec()),
                        Token::Argument(b"SUBSCRIBED".to_vec()),
                        Token::ParenthesisClose,
                        Token::Nil,
                        Token::Argument(b"*".to_vec()),
                    ],
                }],
            ),
            (
                vec!["a1 list \"\" (\"foo\")\r\n"],
                vec![Request {
                    tag: "a1".into(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::ParenthesisOpen,
                        Token::Argument(b"foo".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["a3.1 LIST \"\" (% music/rock)\r\n"],
                vec![Request {
                    tag: "a3.1".into(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::ParenthesisOpen,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"music/rock".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A01 LIST \"\" % RETURN (STATUS (MESSAGES UNSEEN))\r\n"],
                vec![Request {
                    tag: "A01".into(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"STATUS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MESSAGES".to_vec()),
                        Token::Argument(b"UNSEEN".to_vec()),
                        Token::ParenthesisClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec![" A01 LiSt \"\"  % RETURN ( STATUS ( MESSAGES UNSEEN ) ) \r\n"],
                vec![Request {
                    tag: "A01".into(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"STATUS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MESSAGES".to_vec()),
                        Token::Argument(b"UNSEEN".to_vec()),
                        Token::ParenthesisClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A02 LIST (SUBSCRIBED RECURSIVEMATCH) \"\" % RETURN (STATUS (MESSAGES))\r\n"],
                vec![Request {
                    tag: "A02".into(),
                    command: Command::List,
                    tokens: vec![
                        Token::ParenthesisOpen,
                        Token::Argument(b"SUBSCRIBED".to_vec()),
                        Token::Argument(b"RECURSIVEMATCH".to_vec()),
                        Token::ParenthesisClose,
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"STATUS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MESSAGES".to_vec()),
                        Token::ParenthesisClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A002 CREATE \"INBOX.Sent Mail\"\r\n"],
                vec![Request {
                    tag: "A002".into(),
                    command: Command::Create,
                    tokens: vec![Token::Argument(b"INBOX.Sent Mail".to_vec())],
                }],
            ),
            (
                vec!["A002 CREATE \"Maibox \\\"quo\\\\ted\\\" \"\r\n"],
                vec![Request {
                    tag: "A002".into(),
                    command: Command::Create,
                    tokens: vec![Token::Argument(b"Maibox \"quo\\ted\" ".to_vec())],
                }],
            ),
            (
                vec!["A004 COPY 2:4 meeting\r\n"],
                vec![Request {
                    tag: "A004".into(),
                    command: Command::Copy(false),
                    tokens: vec![
                        Token::Argument(b"2:4".to_vec()),
                        Token::Argument(b"meeting".to_vec()),
                    ],
                }],
            ),
            (
                vec![
                    "A282 SEARCH RETURN (MIN COU",
                    "NT) FLAGGED SINCE 1-Feb-1994 ",
                    "NOT FROM \"Smith\"\r\n",
                ],
                vec![Request {
                    tag: "A282".into(),
                    command: Command::Search(false),
                    tokens: vec![
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MIN".to_vec()),
                        Token::Argument(b"COUNT".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"FLAGGED".to_vec()),
                        Token::Argument(b"SINCE".to_vec()),
                        Token::Argument(b"1-Feb-1994".to_vec()),
                        Token::Argument(b"NOT".to_vec()),
                        Token::Argument(b"FROM".to_vec()),
                        Token::Argument(b"Smith".to_vec()),
                    ],
                }],
            ),
            (
                vec!["F284 UID STORE $ +FLAGS.Silent (\\Deleted)\r\n"],
                vec![Request {
                    tag: "F284".into(),
                    command: Command::Store(true),
                    tokens: vec![
                        Token::Argument(b"$".to_vec()),
                        Token::Argument(b"+FLAGS.Silent".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"\\Deleted".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n"],
                vec![Request {
                    tag: "A654".into(),
                    command: Command::Fetch(false),
                    tokens: vec![
                        Token::Argument(b"2:4".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"FLAGS".to_vec()),
                        Token::Argument(b"BODY".to_vec()),
                        Token::BracketOpen,
                        Token::Argument(b"HEADER".to_vec()),
                        Token::Dot,
                        Token::Argument(b"FIELDS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"DATE".to_vec()),
                        Token::Argument(b"FROM".to_vec()),
                        Token::ParenthesisClose,
                        Token::BracketClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec![
                    "B283 UID SEARCH RETURN (SAVE) CHARSET ",
                    "KOI8-R (OR $ 1,3000:3021) TEXT \"hello world\"\r\n",
                ],
                vec![Request {
                    tag: "B283".into(),
                    command: Command::Search(true),
                    tokens: vec![
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"SAVE".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"CHARSET".to_vec()),
                        Token::Argument(b"KOI8-R".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"OR".to_vec()),
                        Token::Argument(b"$".to_vec()),
                        Token::Argument(b"1,3000:3021".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"TEXT".to_vec()),
                        Token::Argument(b"hello world".to_vec()),
                    ],
                }],
            ),
            (
                vec![
                    "P283 SEARCH CHARSET UTF-8 (OR $ 1,3000:3021) ",
                    "TEXT {8+}\r\nмать\r\n",
                ],
                vec![Request {
                    tag: "P283".into(),
                    command: Command::Search(false),
                    tokens: vec![
                        Token::Argument(b"CHARSET".to_vec()),
                        Token::Argument(b"UTF-8".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"OR".to_vec()),
                        Token::Argument(b"$".to_vec()),
                        Token::Argument(b"1,3000:3021".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"TEXT".to_vec()),
                        Token::Argument("мать".to_string().into_bytes()),
                    ],
                }],
            ),
            (
                vec!["A001 LOGIN {11}\r\n", "FRED FOOBAR {7}\r\n", "fat man\r\n"],
                vec![Request {
                    tag: "A001".into(),
                    command: Command::Login,
                    tokens: vec![
                        Token::Argument(b"FRED FOOBAR".to_vec()),
                        Token::Argument(b"fat man".to_vec()),
                    ],
                }],
            ),
            (
                vec!["TAG3 CREATE \"Test-ąęć-Test\"\r\n"],
                vec![Request {
                    tag: "TAG3".into(),
                    command: Command::Create,
                    tokens: vec![Token::Argument("Test-ąęć-Test".as_bytes().to_vec())],
                }],
            ),
            (
                vec!["abc LOGIN {0}\r\n", "\r\n"],
                vec![Request {
                    tag: "abc".into(),
                    command: Command::Login,
                    tokens: vec![Token::Nil],
                }],
            ),
            (
                vec!["abc LOGIN {0+}\r\n\r\n"],
                vec![Request {
                    tag: "abc".into(),
                    command: Command::Login,
                    tokens: vec![Token::Nil],
                }],
            ),
            (
                vec![
                    "A003 APPEND saved-messages (\\Seen) {297+}\r\n",
                    "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                    "From: Fred Foobar <foobar@example.com>\r\n",
                    "Subject: afternoon meeting\r\n",
                    "To: mooch@example.com\r\n",
                    "Message-Id: <B27397-0100000@example.com>\r\n",
                    "MIME-Version: 1.0\r\n",
                    "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                    "\r\n",
                    "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n\r\n",
                ],
                vec![Request {
                    tag: "A003".into(),
                    command: Command::Append,
                    tokens: vec![
                        Token::Argument(b"saved-messages".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"\\Seen".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(
                            concat!(
                                "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                                "From: Fred Foobar <foobar@example.com>\r\n",
                                "Subject: afternoon meeting\r\n",
                                "To: mooch@example.com\r\n",
                                "Message-Id: <B27397-0100000@example.com>\r\n",
                                "MIME-Version: 1.0\r\n",
                                "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                                "\r\n",
                                "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n"
                            )
                            .as_bytes()
                            .to_vec(),
                        ),
                    ],
                }],
            ),
            (
                vec![
                    "A003 APPEND saved-messages (\\Seen) {326}\r\n",
                    "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                    "From: Fred Foobar <foobar@Blurdybloop.example>\r\n",
                    "Subject: afternoon meeting\r\n",
                    "To: mooch@owatagu.siam.edu.example\r\n",
                    "Message-Id: <B27397-0100000@Blurdybloop.example>\r\n",
                    "MIME-Version: 1.0\r\n",
                    "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                    "\r\n",
                    "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n\r\n",
                ],
                vec![Request {
                    tag: "A003".into(),
                    command: Command::Append,
                    tokens: vec![
                        Token::Argument(b"saved-messages".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"\\Seen".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(
                            concat!(
                                "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                                "From: Fred Foobar <foobar@Blurdybloop.example>\r\n",
                                "Subject: afternoon meeting\r\n",
                                "To: mooch@owatagu.siam.edu.example\r\n",
                                "Message-Id: <B27397-0100000@Blurdybloop.example>\r\n",
                                "MIME-Version: 1.0\r\n",
                                "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                                "\r\n",
                                "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n",
                            )
                            .as_bytes()
                            .to_vec(),
                        ),
                    ],
                }],
            ),
            (
                vec!["001 NOOP\r\n002 CAPABILITY\r\nabc LOGIN hello world\r\n"],
                vec![
                    Request {
                        tag: "001".into(),
                        command: Command::Noop,
                        tokens: vec![],
                    },
                    Request {
                        tag: "002".into(),
                        command: Command::Capability,
                        tokens: vec![],
                    },
                    Request {
                        tag: "abc".into(),
                        command: Command::Login,
                        tokens: vec![
                            Token::Argument(b"hello".to_vec()),
                            Token::Argument(b"world".to_vec()),
                        ],
                    },
                ],
            ),
        ] {
            let mut requests = Vec::new();
            for frame in &frames {
                let mut bytes = frame.as_bytes().iter();
                loop {
                    match receiver.parse(&mut bytes) {
                        Ok(request) => requests.push(request),
                        Err(Error::NeedsMoreData | Error::NeedsLiteral { .. }) => break,
                        Err(err) => panic!("{:?} for frames {:#?}", err, frames),
                    }
                }
            }
            assert_eq!(requests, expected_requests, "{:#?}", frames);
        }
    }

    #[test]
    fn receiver_parse_invalid() {
        let mut receiver = Receiver::<Command>::new();
        for invalid in [
            //"\r\n",
            //"  \r \n",
            "a001\r\n",
            "a001 unknown\r\n",
            "a001 login {abc}\r\n",
            "a001 login {+30}\r\n",
            "a001 login {30} junk\r\n",
        ] {
            match receiver.parse(&mut invalid.as_bytes().iter()) {
                Err(Error::Error { .. }) => {}
                result => panic!("Expecter error, got: {:?}", result),
            }
        }
    }
}
