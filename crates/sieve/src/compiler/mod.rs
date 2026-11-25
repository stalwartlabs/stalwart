/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use self::{
    grammar::{AddressPart, Capability},
    lexer::{StringConstant, tokenizer::TokenInfo},
};
use crate::{
    Compiler, Envelope, FunctionMap,
    runtime::{RuntimeError, tests::glob::CompiledGlob},
};
use ahash::{AHashMap, AHashSet};
use mail_parser::HeaderName;
use std::{borrow::Cow, fmt::Display};

pub(crate) mod emit;
pub mod grammar;
pub mod lexer;

#[derive(Debug)]
pub struct CompileError {
    line_num: usize,
    line_pos: usize,
    error_type: ErrorType,
}

#[derive(Debug)]
pub enum ErrorType {
    InvalidCharacter(u8),
    InvalidNumber(String),
    InvalidMatchVariable(usize),
    InvalidUnicodeSequence(u32),
    InvalidNamespace(String),
    InvalidRegex(String),
    InvalidExpression(String),
    InvalidUtf8String,
    InvalidHeaderName,
    InvalidArguments,
    InvalidAddress,
    InvalidURI,
    InvalidEnvelope(String),
    UnterminatedString,
    UnterminatedComment,
    UnterminatedMultiline,
    UnterminatedBlock,
    ScriptTooLong,
    StringTooLong,
    VariableTooLong,
    VariableIsLocal(String),
    HeaderTooLong,
    ExpectedConstantString,
    UnexpectedToken {
        expected: Cow<'static, str>,
        found: String,
    },
    UnexpectedEOF,
    TooManyNestedBlocks,
    TooManyNestedTests,
    TooManyNestedForEveryParts,
    TooManyIncludes,
    LabelAlreadyDefined(String),
    LabelUndefined(String),
    BreakOutsideLoop,
    ContinueOutsideLoop,
    UnsupportedComparator(String),
    DuplicatedParameter,
    UndeclaredCapability(Capability),
    UnsupportedCapability(Capability),
    MissingTag(Cow<'static, str>),
}

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub(crate) enum Value {
    Text(ConstantId) = 0,
    Number(Number) = 1,
    Variable(VariableType) = 2,
    Regex(Regex) = 3,
    Glob(Glob) = 4,
    Header(HeaderName<'static>) = 5,
    List(Box<[Value]>) = 6,
}

#[derive(Debug)]
pub(crate) enum RawValue {
    Text(String),
    Number(Number),
    Value(Value),
}

impl From<StringConstant> for RawValue {
    fn from(value: StringConstant) -> Self {
        match value {
            StringConstant::String(text) => RawValue::Text(text),
            StringConstant::Number(number) => RawValue::Number(number),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(transparent)]
pub struct ConstantId(u32);

impl ConstantId {
    pub(crate) const UNRESOLVED: ConstantId = ConstantId(u32::MAX);

    #[inline(always)]
    pub(crate) fn new(index: usize) -> Self {
        ConstantId(index as u32)
    }

    #[inline(always)]
    pub(crate) fn index(&self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Regex {
    pub expr: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Glob {
    #[cfg_attr(
        any(all(test, stalwart_tests), feature = "serde"),
        serde(skip, default)
    )]
    pub(crate) glob: CompiledGlob,
    pub expr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum VariableType {
    Local(u16) = 0,
    Match(u8) = 1,
    Global(String) = 2,
    Environment(String) = 3,
    Envelope(Envelope) = 4,
    Header(HeaderVariable<'static>) = 5,
    Part(MessagePart) = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Transform {
    pub variable: Box<VariableType>,
    pub functions: Box<[u32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct HeaderVariable<'x> {
    #[cfg_attr(
        any(all(test, stalwart_tests), feature = "serde"),
        serde(deserialize_with = "deserialize_header_names")
    )]
    pub name: Box<[HeaderName<'x>]>,
    pub part: HeaderPart,
    pub index_hdr: i32,
    pub index_part: i32,
}

#[cfg(any(all(test, stalwart_tests), feature = "serde"))]
fn deserialize_header_names<'de, 'x, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Box<[HeaderName<'x>]>, D::Error> {
    <Vec<HeaderName<'static>> as serde::Deserialize>::deserialize(deserializer)
        .map(Vec::into_boxed_slice)
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum MessagePart {
    TextBody(bool) = 0,
    HtmlBody(bool) = 1,
    Contents = 2,
    Raw = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum HeaderPart {
    Text = 0,
    Date = 1,
    Id = 2,
    Address(AddressPart) = 3,
    ContentType(ContentTypePart) = 4,
    Received(ReceivedPart) = 5,
    Raw = 6,
    RawName = 7,
    Exists = 8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum ContentTypePart {
    Type = 0,
    Subtype = 1,
    Attribute(String) = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum ReceivedPart {
    From(ReceivedHostname) = 0,
    FromIp = 1,
    FromIpRev = 2,
    By(ReceivedHostname) = 3,
    For = 4,
    With = 5,
    TlsVersion = 6,
    TlsCipher = 7,
    Id = 8,
    Ident = 9,
    Via = 10,
    Date = 11,
    DateRaw = 12,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum ReceivedHostname {
    Name = 0,
    Ip = 1,
    Any = 2,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Number {
    Integer(i64) = 0,
    Float(f64) = 1,
}

impl ReceivedPart {
    pub(crate) fn code(&self) -> u16 {
        let (part, hostname): (u16, u16) = match self {
            ReceivedPart::From(host) => (0, *host as u16),
            ReceivedPart::FromIp => (1, 0),
            ReceivedPart::FromIpRev => (2, 0),
            ReceivedPart::By(host) => (3, *host as u16),
            ReceivedPart::For => (4, 0),
            ReceivedPart::With => (5, 0),
            ReceivedPart::TlsVersion => (6, 0),
            ReceivedPart::TlsCipher => (7, 0),
            ReceivedPart::Id => (8, 0),
            ReceivedPart::Ident => (9, 0),
            ReceivedPart::Via => (10, 0),
            ReceivedPart::Date => (11, 0),
            ReceivedPart::DateRaw => (12, 0),
        };
        part | (hostname << 8)
    }

    pub(crate) fn from_code(part: u8, hostname: u8) -> ReceivedPart {
        let hostname = match hostname {
            0 => ReceivedHostname::Name,
            1 => ReceivedHostname::Ip,
            _ => ReceivedHostname::Any,
        };
        match part {
            0 => ReceivedPart::From(hostname),
            1 => ReceivedPart::FromIp,
            2 => ReceivedPart::FromIpRev,
            3 => ReceivedPart::By(hostname),
            4 => ReceivedPart::For,
            5 => ReceivedPart::With,
            6 => ReceivedPart::TlsVersion,
            7 => ReceivedPart::TlsCipher,
            8 => ReceivedPart::Id,
            9 => ReceivedPart::Ident,
            10 => ReceivedPart::Via,
            11 => ReceivedPart::Date,
            _ => ReceivedPart::DateRaw,
        }
    }
}

impl Number {
    #[cfg(all(test, stalwart_tests))]
    pub fn to_float(&self) -> f64 {
        match self {
            Number::Integer(i) => *i as f64,
            Number::Float(fl) => *fl,
        }
    }
}

impl From<Number> for usize {
    fn from(value: Number) -> Self {
        match value {
            Number::Integer(i) => i as usize,
            Number::Float(fl) => fl as usize,
        }
    }
}

impl Display for Number {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Number::Integer(i) => i.fmt(f),
            Number::Float(fl) => fl.fmt(f),
        }
    }
}

impl Compiler {
    pub const VERSION: u32 = crate::bytecode::FORMAT_VERSION as u32;

    pub fn new() -> Self {
        Compiler {
            max_script_size: 1024 * 1024,
            max_string_size: 4096,
            max_variable_name_size: 32,
            max_nested_blocks: 15,
            max_nested_tests: 15,
            max_nested_foreverypart: 3,
            max_match_variables: 30,
            max_local_variables: 128,
            max_header_size: 1024,
            max_includes: 6,
            functions: AHashMap::new(),
            no_capability_check: false,
            disabled_capabilities: AHashSet::new(),
            unknown_capabilities_disabled: false,
        }
    }

    pub fn set_max_header_size(&mut self, size: usize) {
        self.max_header_size = size;
    }

    pub fn with_max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    pub fn set_max_includes(&mut self, size: usize) {
        self.max_includes = size;
    }

    pub fn with_max_includes(mut self, size: usize) -> Self {
        self.max_includes = size;
        self
    }

    pub fn set_max_nested_blocks(&mut self, size: usize) {
        self.max_nested_blocks = size;
    }

    pub fn with_max_nested_blocks(mut self, size: usize) -> Self {
        self.max_nested_blocks = size;
        self
    }

    pub fn set_max_nested_tests(&mut self, size: usize) {
        self.max_nested_tests = size;
    }

    pub fn with_max_nested_tests(mut self, size: usize) -> Self {
        self.max_nested_tests = size;
        self
    }

    pub fn set_max_nested_foreverypart(&mut self, size: usize) {
        self.max_nested_foreverypart = size;
    }

    pub fn with_max_nested_foreverypart(mut self, size: usize) -> Self {
        self.max_nested_foreverypart = size;
        self
    }

    pub fn set_max_script_size(&mut self, size: usize) {
        self.max_script_size = size;
    }

    pub fn with_max_script_size(mut self, size: usize) -> Self {
        self.max_script_size = size;
        self
    }

    pub fn set_max_string_size(&mut self, size: usize) {
        self.max_string_size = size;
    }

    pub fn with_max_string_size(mut self, size: usize) -> Self {
        self.max_string_size = size;
        self
    }

    pub fn set_max_variable_name_size(&mut self, size: usize) {
        self.max_variable_name_size = size;
    }

    pub fn with_max_variable_name_size(mut self, size: usize) -> Self {
        self.max_variable_name_size = size;
        self
    }

    pub fn set_max_match_variables(&mut self, size: usize) {
        self.max_match_variables = size;
    }

    pub fn with_max_match_variables(mut self, size: usize) -> Self {
        self.max_match_variables = size;
        self
    }

    pub fn set_max_local_variables(&mut self, size: usize) {
        self.max_local_variables = size;
    }

    pub fn with_max_local_variables(mut self, size: usize) -> Self {
        self.max_local_variables = size;
        self
    }

    pub fn register_functions(mut self, fnc_map: &mut FunctionMap) -> Self {
        self.functions = std::mem::take(&mut fnc_map.map);
        self
    }

    pub fn with_no_capability_check(mut self, value: bool) -> Self {
        self.no_capability_check = value;
        self
    }

    pub fn set_no_capability_check(&mut self, value: bool) {
        self.no_capability_check = value;
    }

    pub fn unset_capability(&mut self, capability: impl Into<Capability>) {
        self.disabled_capabilities.insert(capability.into());
    }

    pub fn without_capability(mut self, capability: impl Into<Capability>) -> Self {
        self.unset_capability(capability);
        self
    }

    pub fn without_capabilities(
        mut self,
        capabilities: impl IntoIterator<Item = impl Into<Capability>>,
    ) -> Self {
        for capability in capabilities {
            self.unset_capability(capability);
        }
        self
    }

    pub fn without_unknown_capabilities(mut self) -> Self {
        self.unknown_capabilities_disabled = true;
        self
    }
}

impl CompileError {
    pub fn line_num(&self) -> usize {
        self.line_num
    }

    pub fn line_pos(&self) -> usize {
        self.line_pos
    }

    pub fn error_type(&self) -> &ErrorType {
        &self.error_type
    }
}

impl PartialEq for Regex {
    fn eq(&self, other: &Self) -> bool {
        self.expr == other.expr
    }
}

impl Eq for Regex {}

impl TokenInfo {
    pub fn expected(self, expected: impl Into<Cow<'static, str>>) -> CompileError {
        CompileError {
            line_num: self.line_num,
            line_pos: self.line_pos,
            error_type: ErrorType::UnexpectedToken {
                expected: expected.into(),
                found: self.token.to_string(),
            },
        }
    }

    pub fn missing_tag(self, tag: impl Into<Cow<'static, str>>) -> CompileError {
        CompileError {
            line_num: self.line_num,
            line_pos: self.line_pos,
            error_type: ErrorType::MissingTag(tag.into()),
        }
    }

    pub fn custom(self, error_type: ErrorType) -> CompileError {
        CompileError {
            line_num: self.line_num,
            line_pos: self.line_pos,
            error_type,
        }
    }
}

impl Glob {
    pub fn new(expr: String, to_lower: bool) -> Self {
        let glob = CompiledGlob::compile(&expr, to_lower);
        Self { expr, glob }
    }
}

impl PartialEq for Glob {
    fn eq(&self, other: &Self) -> bool {
        self.expr == other.expr
    }
}

impl Eq for Glob {}

impl Regex {
    pub fn new(expr: String) -> Self {
        Self { expr }
    }
}

impl Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.error_type() {
            ErrorType::InvalidCharacter(value) => {
                write!(f, "Invalid character {:?}", char::from(*value))
            }
            ErrorType::InvalidNumber(value) => write!(f, "Invalid number {value:?}"),
            ErrorType::InvalidMatchVariable(value) => {
                write!(f, "Match variable {value} out of range")
            }
            ErrorType::InvalidUnicodeSequence(value) => {
                write!(f, "Invalid Unicode sequence {value:04x}")
            }
            ErrorType::InvalidNamespace(value) => write!(f, "Invalid namespace {value:?}"),
            ErrorType::InvalidRegex(value) => write!(f, "Invalid regular expression {value:?}"),
            ErrorType::InvalidExpression(value) => write!(f, "Invalid expression {value}"),
            ErrorType::InvalidUtf8String => write!(f, "Invalid UTF-8 string"),
            ErrorType::InvalidHeaderName => write!(f, "Invalid header name"),
            ErrorType::InvalidArguments => write!(f, "Invalid Arguments"),
            ErrorType::InvalidAddress => write!(f, "Invalid Address"),
            ErrorType::InvalidURI => write!(f, "Invalid URI"),
            ErrorType::InvalidEnvelope(value) => write!(f, "Invalid envelope {value:?}"),
            ErrorType::UnterminatedString => write!(f, "Unterminated string"),
            ErrorType::UnterminatedComment => write!(f, "Unterminated comment"),
            ErrorType::UnterminatedMultiline => write!(f, "Unterminated multi-line string"),
            ErrorType::UnterminatedBlock => write!(f, "Unterminated block"),
            ErrorType::ScriptTooLong => write!(f, "Sieve script is too large"),
            ErrorType::StringTooLong => write!(f, "String is too long"),
            ErrorType::VariableTooLong => write!(f, "Variable name is too long"),
            ErrorType::VariableIsLocal(value) => {
                write!(f, "Variable {value:?} was already defined as local")
            }
            ErrorType::HeaderTooLong => write!(f, "Header value is too long"),
            ErrorType::ExpectedConstantString => write!(f, "Expected a constant string"),
            ErrorType::UnexpectedToken { expected, found } => {
                write!(f, "Expected token {expected:?} but found {found:?}")
            }
            ErrorType::UnexpectedEOF => write!(f, "Unexpected end of file"),
            ErrorType::TooManyNestedBlocks => write!(f, "Too many nested blocks"),
            ErrorType::TooManyNestedTests => write!(f, "Too many nested tests"),
            ErrorType::TooManyNestedForEveryParts => {
                write!(f, "Too many nested foreverypart blocks")
            }
            ErrorType::TooManyIncludes => write!(f, "Too many includes"),
            ErrorType::LabelAlreadyDefined(value) => write!(f, "Label {value:?} already defined"),
            ErrorType::LabelUndefined(value) => write!(f, "Label {value:?} does not exist"),
            ErrorType::BreakOutsideLoop => write!(f, "Break used outside of foreverypart loop"),
            ErrorType::ContinueOutsideLoop => write!(f, "Continue used outside of while loop"),
            ErrorType::UnsupportedComparator(value) => {
                write!(f, "Comparator {value:?} is not supported")
            }
            ErrorType::DuplicatedParameter => write!(f, "Duplicated argument"),
            ErrorType::UndeclaredCapability(value) => {
                write!(f, "Undeclared capability '{value}'")
            }
            ErrorType::UnsupportedCapability(value) => {
                write!(f, "Capability '{value}' is not supported")
            }
            ErrorType::MissingTag(value) => write!(f, "Missing tag {value:?}"),
        }?;

        write!(
            f,
            " at line {}, column {}.",
            self.line_num(),
            self.line_pos()
        )
    }
}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::TooManyIncludes => f.write_str("Too many nested includes"),
            RuntimeError::ScriptNotFound(name) => write!(f, "Included script {name:?} not found."),
            RuntimeError::InvalidInstruction {
                name,
                line_num,
                line_pos,
            } => write!(
                f,
                "Script executed invalid instruction {name:?} at line {line_num}, column {line_pos}."
            ),
            RuntimeError::ScriptErrorMessage(value) => {
                write!(f, "Script reported error {value:?}.")
            }
            RuntimeError::CapabilityNotAllowed(value) => {
                write!(f, "Capability '{value}' has been disabled.")
            }
            RuntimeError::CapabilityNotSupported(value) => {
                write!(f, "Capability '{value}' not supported.")
            }
            RuntimeError::CPULimitReached => write!(
                f,
                "Script exceeded the maximum number of instructions allowed to execute."
            ),
            RuntimeError::MemoryLimitReached => {
                write!(f, "Script exceeded the maximum amount of memory allowed.")
            }
            RuntimeError::InvalidBytecode => write!(f, "Compiled script is corrupted."),
            RuntimeError::AwaitingInput => f.write_str("Script is waiting for a pending result"),
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/sieve/src/compiler/tests.rs"]
mod tests;
