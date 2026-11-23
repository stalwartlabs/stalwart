/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::HeaderName;
use std::fmt::Display;

use self::{expr::Expression, instruction::CompilerState};

use super::{
    CompileError, ErrorType, Glob, RawValue, Regex, Value,
    lexer::{Token, tokenizer::TokenInfo, word::Word},
};

pub mod actions;
pub mod expr;
pub mod instruction;
pub mod test;
pub mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Capability {
    Envelope = 0,
    EnvelopeDsn = 1,
    EnvelopeDeliverBy = 2,
    FileInto = 3,
    EncodedCharacter = 4,
    Comparator(Comparator) = 5,
    Other(String) = 6,
    Body = 7,
    Convert = 8,
    Copy = 9,
    Relational = 10,
    Date = 11,
    Index = 12,
    Duplicate = 13,
    Variables = 14,
    EditHeader = 15,
    ForEveryPart = 16,
    Mime = 17,
    Replace = 18,
    Enclose = 19,
    ExtractText = 20,
    Enotify = 21,
    RedirectDsn = 22,
    RedirectDeliverBy = 23,
    Environment = 24,
    Reject = 25,
    Ereject = 26,
    ExtLists = 27,
    SubAddress = 28,
    Vacation = 29,
    VacationSeconds = 30,
    Fcc = 31,
    Mailbox = 32,
    MailboxId = 33,
    MboxMetadata = 34,
    ServerMetadata = 35,
    SpecialUse = 36,
    Imap4Flags = 37,
    Ihave = 38,
    ImapSieve = 39,
    Include = 40,
    Regex = 41,
    SpamTest = 42,
    SpamTestPlus = 43,
    VirusTest = 44,

    // Extensions
    Expressions = 45,
    While = 46,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum AddressPart {
    LocalPart = 0,
    Domain = 1,
    All = 2,
    User = 3,
    Detail = 4,
    Name = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum MatchType {
    Is = 0,
    Contains = 1,
    Matches(u64) = 2,
    Regex(u64) = 3,
    Value(RelationalMatch) = 4,
    Count(RelationalMatch) = 5,
    List = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum RelationalMatch {
    Gt = 0,
    Ge = 1,
    Lt = 2,
    Le = 3,
    Eq = 4,
    Ne = 5,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Comparator {
    Elbonia = 0,
    Octet = 1,
    AsciiCaseMap = 2,
    AsciiNumeric = 3,
    Other(String) = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Clear {
    pub(crate) local_vars_idx: u32,
    pub(crate) local_vars_num: u32,
    pub(crate) match_vars: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Invalid {
    pub(crate) name: String,
    pub(crate) line_num: u32,
    pub(crate) line_pos: u32,
}

#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct While {
    pub expr: Box<[Expression]>,
    pub jz_pos: u32,
}

impl CompilerState<'_> {
    #[inline(always)]
    pub fn expect_instruction_end(&mut self) -> Result<(), CompileError> {
        self.tokens.expect_token(Token::Semicolon)
    }

    pub fn ignore_instruction(&mut self) -> Result<(), CompileError> {
        // Skip entire instruction
        let mut curly_count = 0;
        loop {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Semicolon if curly_count == 0 => {
                    break;
                }
                Token::CurlyOpen => {
                    curly_count += 1;
                }
                Token::CurlyClose => match curly_count {
                    0 => {
                        return Err(token_info.expected("instruction"));
                    }
                    1 => {
                        break;
                    }
                    _ => curly_count -= 1,
                },
                _ => (),
            }
        }

        Ok(())
    }

    pub fn ignore_test(&mut self) -> Result<(), CompileError> {
        let mut d_count = 0;
        while let Some(token_info) = self.tokens.peek() {
            match token_info?.token {
                Token::ParenthesisOpen => {
                    d_count += 1;
                }
                Token::ParenthesisClose => {
                    if d_count == 0 {
                        break;
                    } else {
                        d_count -= 1;
                    }
                }
                Token::Comma if d_count == 0 => {
                    break;
                }
                Token::CurlyOpen => {
                    break;
                }
                _ => (),
            }
            self.tokens.next();
        }

        Ok(())
    }

    pub fn parse_match_type(&mut self, word: Word) -> Result<MatchType, CompileError> {
        match word {
            Word::Is => Ok(MatchType::Is),
            Word::Contains => Ok(MatchType::Contains),
            Word::Matches => {
                self.block.match_test_pos.push(self.instructions.len());
                Ok(MatchType::Matches(0))
            }
            Word::Regex => {
                self.block.match_test_pos.push(self.instructions.len());
                Ok(MatchType::Regex(0))
            }
            Word::List => Ok(MatchType::List),
            _ => {
                let token_info = self.tokens.unwrap_next()?;
                if let Token::StringConstant(text) = &token_info.token
                    && let Some(relational) = lookup_relational(text.to_string().as_ref())
                {
                    return Ok(if word == Word::Value {
                        MatchType::Value(relational)
                    } else {
                        MatchType::Count(relational)
                    });
                }
                Err(token_info.expected("relational match"))
            }
        }
    }

    pub(crate) fn parse_comparator(&mut self) -> Result<Comparator, CompileError> {
        let comparator = self.tokens.expect_static_string()?;
        Ok(if let Some(comparator) = lookup_comparator(&comparator) {
            comparator
        } else {
            Comparator::Other(comparator)
        })
    }

    pub(crate) fn parse_static_strings(&mut self) -> Result<Vec<String>, CompileError> {
        let token_info = self.tokens.unwrap_next()?;
        match token_info.token {
            Token::BracketOpen => {
                let mut strings = Vec::new();
                loop {
                    let token_info = self.tokens.unwrap_next()?;
                    match token_info.token {
                        Token::StringConstant(string) => {
                            strings.push(string.into_string());
                        }
                        Token::Comma => (),
                        Token::BracketClose if !strings.is_empty() => break,
                        _ => return Err(token_info.expected("constant string")),
                    }
                }
                Ok(strings)
            }
            Token::StringConstant(string) => Ok(vec![string.into_string()]),
            _ => Err(token_info.expected("'[' or constant string")),
        }
    }

    pub fn parse_string(&mut self) -> Result<Value, CompileError> {
        let value = self.parse_raw_string()?;
        Ok(self.intern_raw(value))
    }

    pub(crate) fn parse_strings(&mut self, allow_empty: bool) -> Result<Vec<Value>, CompileError> {
        let values = self.parse_raw_strings(allow_empty)?;
        Ok(self.intern_raw_list(values))
    }

    pub(crate) fn parse_string_token(
        &mut self,
        token_info: TokenInfo,
    ) -> Result<Value, CompileError> {
        let value = self.parse_raw_string_token(token_info)?;
        Ok(self.intern_raw(value))
    }

    pub(crate) fn parse_strings_token(
        &mut self,
        token_info: TokenInfo,
    ) -> Result<Vec<Value>, CompileError> {
        let values = self.parse_raw_strings_token(token_info)?;
        Ok(self.intern_raw_list(values))
    }

    pub(crate) fn parse_raw_string(&mut self) -> Result<RawValue, CompileError> {
        let next_token = self.tokens.unwrap_next()?;
        match next_token.token {
            Token::StringConstant(s) => Ok(s.into()),
            Token::StringVariable(s) => self
                .tokenize_string(&s, true)
                .map(RawValue::Value)
                .map_err(|error_type| CompileError {
                    line_num: next_token.line_num,
                    line_pos: next_token.line_pos,
                    error_type,
                }),
            Token::BracketOpen => {
                let mut items = self.parse_raw_string_list(false)?;
                match items.pop() {
                    Some(s) if items.is_empty() => Ok(s),
                    _ => Err(next_token.expected("string")),
                }
            }
            _ => Err(next_token.expected("string")),
        }
    }

    pub(crate) fn parse_raw_strings(
        &mut self,
        allow_empty: bool,
    ) -> Result<Vec<RawValue>, CompileError> {
        let token_info = self.tokens.unwrap_next()?;
        match token_info.token {
            Token::BracketOpen => self.parse_raw_string_list(allow_empty),
            Token::StringConstant(s) => Ok(vec![s.into()]),
            Token::StringVariable(s) => self
                .tokenize_string(&s, true)
                .map(|s| vec![RawValue::Value(s)])
                .map_err(|error_type| CompileError {
                    line_num: token_info.line_num,
                    line_pos: token_info.line_pos,
                    error_type,
                }),
            _ => Err(token_info.expected("'[' or string")),
        }
    }

    pub(crate) fn parse_raw_string_token(
        &mut self,
        token_info: TokenInfo,
    ) -> Result<RawValue, CompileError> {
        match token_info.token {
            Token::StringConstant(s) => Ok(s.into()),
            Token::StringVariable(s) => self
                .tokenize_string(&s, true)
                .map(RawValue::Value)
                .map_err(|error_type| CompileError {
                    line_num: token_info.line_num,
                    line_pos: token_info.line_pos,
                    error_type,
                }),
            _ => Err(token_info.expected("string")),
        }
    }

    pub(crate) fn parse_raw_strings_token(
        &mut self,
        token_info: TokenInfo,
    ) -> Result<Vec<RawValue>, CompileError> {
        match token_info.token {
            Token::StringConstant(s) => Ok(vec![s.into()]),
            Token::StringVariable(s) => self
                .tokenize_string(&s, true)
                .map(|s| vec![RawValue::Value(s)])
                .map_err(|error_type| CompileError {
                    line_num: token_info.line_num,
                    line_pos: token_info.line_pos,
                    error_type,
                }),
            Token::BracketOpen => self.parse_raw_string_list(false),
            _ => Err(token_info.expected("string")),
        }
    }

    pub(crate) fn parse_raw_string_list(
        &mut self,
        allow_empty: bool,
    ) -> Result<Vec<RawValue>, CompileError> {
        let mut strings = Vec::new();
        loop {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::StringConstant(s) => {
                    strings.push(s.into());
                }
                Token::StringVariable(s) => {
                    strings.push(RawValue::Value(self.tokenize_string(&s, true).map_err(
                        |error_type| CompileError {
                            line_num: token_info.line_num,
                            line_pos: token_info.line_pos,
                            error_type,
                        },
                    )?));
                }
                Token::Comma => (),
                Token::BracketClose if !strings.is_empty() || allow_empty => break,
                _ => return Err(token_info.expected("string or string list")),
            }
        }
        Ok(strings)
    }

    #[inline(always)]
    pub(crate) fn has_capability(&self, capability: &Capability) -> bool {
        [&self.block]
            .into_iter()
            .chain(self.block_stack.iter())
            .any(|b| b.capabilities.contains(capability))
            || (capability != &Capability::Ihave && self.compiler.no_capability_check)
    }

    #[inline(always)]
    pub(crate) fn reset_param_check(&mut self) {
        self.param_check.fill(false);
    }

    #[inline(always)]
    pub(crate) fn validate_argument(
        &mut self,
        arg_num: usize,
        capability: Option<Capability>,
        line_num: usize,
        line_pos: usize,
    ) -> Result<(), CompileError> {
        if arg_num > 0 {
            if let Some(param) = self.param_check.get_mut(arg_num - 1) {
                if !*param {
                    *param = true;
                } else {
                    return Err(CompileError {
                        line_num,
                        line_pos,
                        error_type: ErrorType::DuplicatedParameter,
                    });
                }
            } else {
                #[cfg(all(test, stalwart_tests))]
                panic!("Argument out of range {arg_num}");
            }
        }
        if let Some(capability) = capability
            && !self.has_capability(&capability)
        {
            return Err(CompileError {
                line_num,
                line_pos,
                error_type: ErrorType::UndeclaredCapability(capability),
            });
        }

        Ok(())
    }

    fn header_name(&mut self, header: RawValue) -> Result<Value, Value> {
        match header {
            RawValue::Text(text) => {
                match HeaderName::parse(text.as_str()).map(HeaderName::into_owned) {
                    Some(header_name) => Ok(Value::Header(header_name)),
                    None => Err(self.text(text)),
                }
            }
            RawValue::Value(Value::Text(id)) => {
                match HeaderName::parse(self.constant(id)).map(HeaderName::into_owned) {
                    Some(header_name) => Ok(Value::Header(header_name)),
                    None => Err(Value::Text(id)),
                }
            }
            other => Ok(self.intern_raw(other)),
        }
    }

    pub(crate) fn resolve_header_name(&mut self, header: RawValue) -> Option<Value> {
        self.header_name(header).ok()
    }

    pub(crate) fn resolve_header_names(&mut self, headers: Vec<RawValue>) -> (Vec<Value>, bool) {
        let mut all_valid = true;
        let mut values = Vec::with_capacity(headers.len());

        for header in headers {
            match self.header_name(header) {
                Ok(value) => values.push(value),
                Err(value) => {
                    all_valid = false;
                    values.push(value);
                }
            }
        }

        (values, all_valid)
    }

    pub(crate) fn validate_match(
        &mut self,
        match_type: &MatchType,
        comparator: &Comparator,
        key_list: Vec<RawValue>,
    ) -> Result<Vec<Value>, CompileError> {
        match match_type {
            MatchType::Regex(_) => {
                let mut keys = Vec::with_capacity(key_list.len());
                for key in key_list {
                    let expr = match self.match_expression(key) {
                        Ok(expr) => expr,
                        Err(key) => {
                            keys.push(key);
                            continue;
                        }
                    };
                    match crate::regex::build(&expr) {
                        Ok(_) => keys.push(Value::Regex(Regex::new(expr))),
                        Err(err) => {
                            return Err(self
                                .tokens
                                .unwrap_next()?
                                .custom(ErrorType::InvalidRegex(format!("{expr}: {err}"))));
                        }
                    }
                }
                Ok(keys)
            }
            MatchType::Matches(_) => {
                let to_lower = matches!(comparator, Comparator::AsciiCaseMap);
                let mut keys = Vec::with_capacity(key_list.len());
                for key in key_list {
                    match self.match_expression(key) {
                        Ok(expr) => keys.push(Value::Glob(Glob::new(expr, to_lower))),
                        Err(key) => keys.push(key),
                    }
                }
                Ok(keys)
            }
            _ => Ok(self.intern_raw_list(key_list)),
        }
    }

    fn match_expression(&mut self, key: RawValue) -> Result<String, Value> {
        match key {
            RawValue::Text(text) => Ok(text),
            RawValue::Value(Value::Text(id)) => Ok(self.constant(id).to_string()),
            other => Err(self.intern_raw(other)),
        }
    }
}

impl AddressPart {
    #[inline(always)]
    pub(crate) fn from_code(code: u8) -> AddressPart {
        match code {
            0 => AddressPart::LocalPart,
            1 => AddressPart::Domain,
            2 => AddressPart::All,
            3 => AddressPart::User,
            4 => AddressPart::Detail,
            _ => AddressPart::Name,
        }
    }
}

impl Capability {
    pub(crate) fn id(&self) -> u8 {
        match self {
            Capability::Envelope => 0,
            Capability::EnvelopeDsn => 1,
            Capability::EnvelopeDeliverBy => 2,
            Capability::FileInto => 3,
            Capability::EncodedCharacter => 4,
            Capability::Body => 7,
            Capability::Convert => 8,
            Capability::Copy => 9,
            Capability::Relational => 10,
            Capability::Date => 11,
            Capability::Index => 12,
            Capability::Duplicate => 13,
            Capability::Variables => 14,
            Capability::EditHeader => 15,
            Capability::ForEveryPart => 16,
            Capability::Mime => 17,
            Capability::Replace => 18,
            Capability::Enclose => 19,
            Capability::ExtractText => 20,
            Capability::Enotify => 21,
            Capability::RedirectDsn => 22,
            Capability::RedirectDeliverBy => 23,
            Capability::Environment => 24,
            Capability::Reject => 25,
            Capability::Ereject => 26,
            Capability::ExtLists => 27,
            Capability::SubAddress => 28,
            Capability::Vacation => 29,
            Capability::VacationSeconds => 30,
            Capability::Fcc => 31,
            Capability::Mailbox => 32,
            Capability::MailboxId => 33,
            Capability::MboxMetadata => 34,
            Capability::ServerMetadata => 35,
            Capability::SpecialUse => 36,
            Capability::Imap4Flags => 37,
            Capability::Ihave => 38,
            Capability::ImapSieve => 39,
            Capability::Include => 40,
            Capability::Regex => 41,
            Capability::SpamTest => 42,
            Capability::SpamTestPlus => 43,
            Capability::VirusTest => 44,
            Capability::Expressions => 45,
            Capability::While => 46,
            Capability::Comparator(_) => 5,
            Capability::Other(_) => 6,
        }
    }

    pub(crate) fn from_id(id: u8) -> Capability {
        match id {
            0 => Capability::Envelope,
            1 => Capability::EnvelopeDsn,
            2 => Capability::EnvelopeDeliverBy,
            3 => Capability::FileInto,
            4 => Capability::EncodedCharacter,
            7 => Capability::Body,
            8 => Capability::Convert,
            9 => Capability::Copy,
            10 => Capability::Relational,
            11 => Capability::Date,
            12 => Capability::Index,
            13 => Capability::Duplicate,
            14 => Capability::Variables,
            15 => Capability::EditHeader,
            16 => Capability::ForEveryPart,
            17 => Capability::Mime,
            18 => Capability::Replace,
            19 => Capability::Enclose,
            20 => Capability::ExtractText,
            21 => Capability::Enotify,
            22 => Capability::RedirectDsn,
            23 => Capability::RedirectDeliverBy,
            24 => Capability::Environment,
            25 => Capability::Reject,
            26 => Capability::Ereject,
            27 => Capability::ExtLists,
            28 => Capability::SubAddress,
            29 => Capability::Vacation,
            30 => Capability::VacationSeconds,
            31 => Capability::Fcc,
            32 => Capability::Mailbox,
            33 => Capability::MailboxId,
            34 => Capability::MboxMetadata,
            35 => Capability::ServerMetadata,
            36 => Capability::SpecialUse,
            37 => Capability::Imap4Flags,
            38 => Capability::Ihave,
            39 => Capability::ImapSieve,
            40 => Capability::Include,
            41 => Capability::Regex,
            42 => Capability::SpamTest,
            43 => Capability::SpamTestPlus,
            44 => Capability::VirusTest,
            45 => Capability::Expressions,
            46 => Capability::While,
            _ => Capability::Other(String::new()),
        }
    }

    pub fn parse(capability: &str) -> Capability {
        if let Some(capability) = lookup_capabilities(capability) {
            capability
        } else if let Some(comparator) = capability.strip_prefix("comparator-") {
            Capability::Comparator(Comparator::Other(comparator.to_string()))
        } else {
            Capability::Other(capability.to_string())
        }
    }

    pub fn all() -> &'static [Capability] {
        &[
            Capability::Envelope,
            Capability::EnvelopeDsn,
            Capability::EnvelopeDeliverBy,
            Capability::FileInto,
            Capability::EncodedCharacter,
            Capability::Comparator(Comparator::Elbonia),
            Capability::Comparator(Comparator::AsciiCaseMap),
            Capability::Comparator(Comparator::AsciiNumeric),
            Capability::Comparator(Comparator::Octet),
            Capability::Body,
            Capability::Convert,
            Capability::Copy,
            Capability::Relational,
            Capability::Date,
            Capability::Index,
            Capability::Duplicate,
            Capability::Variables,
            Capability::EditHeader,
            Capability::ForEveryPart,
            Capability::Mime,
            Capability::Replace,
            Capability::Enclose,
            Capability::ExtractText,
            Capability::Enotify,
            Capability::RedirectDsn,
            Capability::RedirectDeliverBy,
            Capability::Environment,
            Capability::Reject,
            Capability::Ereject,
            Capability::ExtLists,
            Capability::SubAddress,
            Capability::Vacation,
            Capability::VacationSeconds,
            Capability::Fcc,
            Capability::Mailbox,
            Capability::MailboxId,
            Capability::MboxMetadata,
            Capability::ServerMetadata,
            Capability::SpecialUse,
            Capability::Imap4Flags,
            Capability::Ihave,
            Capability::ImapSieve,
            Capability::Include,
            Capability::Regex,
            Capability::SpamTest,
            Capability::SpamTestPlus,
            Capability::VirusTest,
        ]
    }
}

fn lookup_relational(input: &str) -> Option<RelationalMatch> {
    hashify::map!(
        input.as_bytes(), RelationalMatch,
        "gt" => RelationalMatch::Gt,
        "ge" => RelationalMatch::Ge,
        "lt" => RelationalMatch::Lt,
        "le" => RelationalMatch::Le,
        "eq" => RelationalMatch::Eq,
        "ne" => RelationalMatch::Ne,
    )
    .copied()
}

fn lookup_comparator(input: &str) -> Option<Comparator> {
    hashify::fnc_map!(
        input.as_bytes(),
        "i;octet" => Some(Comparator::Octet),
        "i;ascii-casemap" => Some(Comparator::AsciiCaseMap),
        "i;ascii-numeric" => Some(Comparator::AsciiNumeric),
        _ => None,
    )
}

impl Invalid {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn line_num(&self) -> usize {
        self.line_num as usize
    }

    pub fn line_pos(&self) -> usize {
        self.line_pos as usize
    }
}

impl From<&str> for Capability {
    fn from(value: &str) -> Self {
        Capability::parse(value)
    }
}

impl From<String> for Capability {
    fn from(value: String) -> Self {
        Capability::parse(&value)
    }
}

impl Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Capability::Envelope => f.write_str("envelope"),
            Capability::EnvelopeDsn => f.write_str("envelope-dsn"),
            Capability::EnvelopeDeliverBy => f.write_str("envelope-deliverby"),
            Capability::FileInto => f.write_str("fileinto"),
            Capability::EncodedCharacter => f.write_str("encoded-character"),
            Capability::Comparator(Comparator::Elbonia) => f.write_str("comparator-elbonia"),
            Capability::Comparator(Comparator::Octet) => f.write_str("comparator-i;octet"),
            Capability::Comparator(Comparator::AsciiCaseMap) => {
                f.write_str("comparator-i;ascii-casemap")
            }
            Capability::Comparator(Comparator::AsciiNumeric) => {
                f.write_str("comparator-i;ascii-numeric")
            }
            Capability::Comparator(Comparator::Other(comparator)) => f.write_str(comparator),
            Capability::Body => f.write_str("body"),
            Capability::Convert => f.write_str("convert"),
            Capability::Copy => f.write_str("copy"),
            Capability::Relational => f.write_str("relational"),
            Capability::Date => f.write_str("date"),
            Capability::Index => f.write_str("index"),
            Capability::Duplicate => f.write_str("duplicate"),
            Capability::Variables => f.write_str("variables"),
            Capability::EditHeader => f.write_str("editheader"),
            Capability::ForEveryPart => f.write_str("foreverypart"),
            Capability::Mime => f.write_str("mime"),
            Capability::Replace => f.write_str("replace"),
            Capability::Enclose => f.write_str("enclose"),
            Capability::ExtractText => f.write_str("extracttext"),
            Capability::Enotify => f.write_str("enotify"),
            Capability::RedirectDsn => f.write_str("redirect-dsn"),
            Capability::RedirectDeliverBy => f.write_str("redirect-deliverby"),
            Capability::Environment => f.write_str("environment"),
            Capability::Reject => f.write_str("reject"),
            Capability::Ereject => f.write_str("ereject"),
            Capability::ExtLists => f.write_str("extlists"),
            Capability::SubAddress => f.write_str("subaddress"),
            Capability::Vacation => f.write_str("vacation"),
            Capability::VacationSeconds => f.write_str("vacation-seconds"),
            Capability::Fcc => f.write_str("fcc"),
            Capability::Mailbox => f.write_str("mailbox"),
            Capability::MailboxId => f.write_str("mailboxid"),
            Capability::MboxMetadata => f.write_str("mboxmetadata"),
            Capability::ServerMetadata => f.write_str("servermetadata"),
            Capability::SpecialUse => f.write_str("special-use"),
            Capability::Imap4Flags => f.write_str("imap4flags"),
            Capability::Ihave => f.write_str("ihave"),
            Capability::ImapSieve => f.write_str("imapsieve"),
            Capability::Include => f.write_str("include"),
            Capability::Regex => f.write_str("regex"),
            Capability::SpamTest => f.write_str("spamtest"),
            Capability::SpamTestPlus => f.write_str("spamtestplus"),
            Capability::VirusTest => f.write_str("virustest"),
            Capability::While => f.write_str("vnd.stalwart.while"),
            Capability::Expressions => f.write_str("vnd.stalwart.expressions"),
            Capability::Other(capability) => f.write_str(capability),
        }
    }
}

fn lookup_capabilities(input: &str) -> Option<Capability> {
    hashify::fnc_map!(
        input.as_bytes(),
        "envelope" => Some(Capability::Envelope),
        "envelope-dsn" => Some(Capability::EnvelopeDsn),
        "envelope-deliverby" => Some(Capability::EnvelopeDeliverBy),
        "fileinto" => Some(Capability::FileInto),
        "encoded-character" => Some(Capability::EncodedCharacter),
        "comparator-elbonia" => Some(Capability::Comparator(Comparator::Elbonia)),
        "comparator-i;octet" => Some(Capability::Comparator(Comparator::Octet)),
        "comparator-i;ascii-casemap" => Some(Capability::Comparator(Comparator::AsciiCaseMap)),
        "comparator-i;ascii-numeric" => Some(Capability::Comparator(Comparator::AsciiNumeric)),
        "body" => Some(Capability::Body),
        "convert" => Some(Capability::Convert),
        "copy" => Some(Capability::Copy),
        "relational" => Some(Capability::Relational),
        "date" => Some(Capability::Date),
        "index" => Some(Capability::Index),
        "duplicate" => Some(Capability::Duplicate),
        "variables" => Some(Capability::Variables),
        "editheader" => Some(Capability::EditHeader),
        "foreverypart" => Some(Capability::ForEveryPart),
        "mime" => Some(Capability::Mime),
        "replace" => Some(Capability::Replace),
        "enclose" => Some(Capability::Enclose),
        "extracttext" => Some(Capability::ExtractText),
        "enotify" => Some(Capability::Enotify),
        "redirect-dsn" => Some(Capability::RedirectDsn),
        "redirect-deliverby" => Some(Capability::RedirectDeliverBy),
        "environment" => Some(Capability::Environment),
        "reject" => Some(Capability::Reject),
        "ereject" => Some(Capability::Ereject),
        "extlists" => Some(Capability::ExtLists),
        "subaddress" => Some(Capability::SubAddress),
        "vacation" => Some(Capability::Vacation),
        "vacation-seconds" => Some(Capability::VacationSeconds),
        "fcc" => Some(Capability::Fcc),
        "mailbox" => Some(Capability::Mailbox),
        "mailboxid" => Some(Capability::MailboxId),
        "mboxmetadata" => Some(Capability::MboxMetadata),
        "servermetadata" => Some(Capability::ServerMetadata),
        "special-use" => Some(Capability::SpecialUse),
        "imap4flags" => Some(Capability::Imap4Flags),
        "ihave" => Some(Capability::Ihave),
        "imapsieve" => Some(Capability::ImapSieve),
        "include" => Some(Capability::Include),
        "regex" => Some(Capability::Regex),
        "spamtest" => Some(Capability::SpamTest),
        "spamtestplus" => Some(Capability::SpamTestPlus),
        "virustest" => Some(Capability::VirusTest),

        // Extensions
        "vnd.stalwart.while" => Some(Capability::While),
        "vnd.stalwart.expressions" => Some(Capability::Expressions),
        _ => None,
    )
}
