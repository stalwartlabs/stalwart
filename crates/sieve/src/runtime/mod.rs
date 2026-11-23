/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod actions;
mod arena;
pub mod context;
pub mod eval;
pub mod expression;
pub mod handler;
pub(crate) mod message;
pub(crate) mod platform;
pub mod tests;
pub mod variable;
pub mod variables;

pub use arena::Arena;
pub use handler::{
    Action, Handler, Input, Mailbox, MessageSource, Recipient, Reply, Script, Status,
};
pub use variable::Variable;

use crate::{
    ExternalId, Function, FunctionMap, Metadata, Runtime, Sieve,
    bytecode::Corrupt,
    compiler::{
        Number,
        grammar::{Capability, expr::parser::ID_EXTERNAL},
    },
};
use ahash::{AHashMap, AHashSet};
use mail_parser::{HeaderName, Message, MessageParser};
use std::borrow::Cow;

use crate::Context;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    TooManyIncludes,
    ScriptNotFound(String),
    InvalidInstruction {
        name: String,
        line_num: u32,
        line_pos: u32,
    },
    ScriptErrorMessage(String),
    CapabilityNotAllowed(Capability),
    CapabilityNotSupported(String),
    CPULimitReached,
    MemoryLimitReached,
    InvalidBytecode,
    AwaitingInput,
}

impl From<Corrupt> for RuntimeError {
    fn from(_: Corrupt) -> Self {
        RuntimeError::InvalidBytecode
    }
}

impl Number {
    pub fn is_non_zero(&self) -> bool {
        match self {
            Number::Integer(n) => *n != 0,
            Number::Float(n) => *n != 0.0,
        }
    }
}

impl Default for Number {
    fn default() -> Self {
        Number::Integer(0)
    }
}

impl From<bool> for Number {
    #[inline(always)]
    fn from(b: bool) -> Self {
        Number::Integer(i64::from(b))
    }
}

impl From<i64> for Number {
    #[inline(always)]
    fn from(n: i64) -> Self {
        Number::Integer(n)
    }
}

impl From<f64> for Number {
    #[inline(always)]
    fn from(n: f64) -> Self {
        Number::Float(n)
    }
}

impl From<i32> for Number {
    #[inline(always)]
    fn from(n: i32) -> Self {
        Number::Integer(n as i64)
    }
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b,
            (Self::Integer(a), Self::Float(b)) => (*a as f64) == *b,
            (Self::Float(a), Self::Integer(b)) => *a == (*b as f64),
        }
    }
}

impl Eq for Number {}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let (a, b) = match (self, other) {
            (Number::Integer(a), Number::Integer(b)) => return a.partial_cmp(b),
            (Number::Float(a), Number::Float(b)) => (*a, *b),
            (Number::Integer(a), Number::Float(b)) => (*a as f64, *b),
            (Number::Float(a), Number::Integer(b)) => (*a, *b as f64),
        };
        a.partial_cmp(&b)
    }
}

impl Runtime {
    pub fn filter<'z: 'x, 'x>(
        &'z self,
        raw_message: &[u8],
        script: &'x Sieve<'x>,
        arena: &'x mut Arena,
    ) -> Context<'x> {
        arena.prepare(self.memory_limit);
        let message = match MessageParser::new().parse_owned(raw_message.to_vec()) {
            Some(message) => arena.keep_message(message),
            None => arena.keep_message(Message::default()),
        };
        let mut context = Context::with_message(self, message, script, arena);
        context.message_size = raw_message.len();
        context
    }

    pub fn filter_parsed<'z: 'x, 'x>(
        &'z self,
        message: &'x Message<'x>,
        script: &'x Sieve<'x>,
        arena: &'x mut Arena,
    ) -> Context<'x> {
        Context::new(self, message, script, arena)
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub fn new() -> Self {
        #[allow(unused_mut)]
        let mut allowed_capabilities = AHashSet::from_iter(Capability::all().iter().cloned());

        #[cfg(all(test, stalwart_tests))]
        allowed_capabilities.insert(Capability::Other("vnd.stalwart.testsuite".to_string()));

        Runtime {
            allowed_capabilities,
            environment: AHashMap::from_iter([
                ("name".into(), "Stalwart Sieve".into()),
                ("version".into(), env!("CARGO_PKG_VERSION").into()),
            ]),
            metadata: Vec::new(),
            include_scripts: AHashMap::new(),
            max_nested_includes: 3,
            cpu_limit: 5000,
            memory_limit: 32 * 1024 * 1024,
            max_variable_size: 4096,
            max_redirects: 1,
            max_received_headers: 10,
            protected_headers: vec![HeaderName::OriginalSubject, HeaderName::OriginalFrom],
            valid_notification_uris: AHashSet::new(),
            valid_ext_lists: AHashSet::new(),
            vacation_use_orig_rcpt: false,
            vacation_default_subject: "Automated reply".into(),
            vacation_subject_prefix: "Auto: ".into(),
            max_header_size: 1024,
            max_header_count: usize::MAX,
            max_header_block_size: usize::MAX,
            max_out_messages: 3,
            default_vacation_expiry: 30 * 86400,
            default_duplicate_expiry: 7 * 86400,
            local_hostname: "localhost".into(),
            functions: Vec::new(),
        }
    }

    pub fn cpu_limit(&self) -> usize {
        self.cpu_limit
    }

    pub fn can_edit_header(&self, name: &str) -> bool {
        self.allowed_capabilities.contains(&Capability::EditHeader)
            && HeaderName::parse(name).is_some_and(|name| !self.protected_headers.contains(&name))
    }

    pub fn max_redirects(&self) -> usize {
        self.max_redirects
    }

    pub fn max_out_messages(&self) -> usize {
        self.max_out_messages
    }

    pub fn set_cpu_limit(&mut self, size: usize) {
        self.cpu_limit = size;
    }

    pub fn with_cpu_limit(mut self, size: usize) -> Self {
        self.cpu_limit = size;
        self
    }

    pub fn set_memory_limit(&mut self, size: usize) {
        self.memory_limit = size;
    }

    pub fn with_memory_limit(mut self, size: usize) -> Self {
        self.memory_limit = size;
        self
    }

    pub fn set_max_nested_includes(&mut self, size: usize) {
        self.max_nested_includes = size;
    }

    pub fn with_max_nested_includes(mut self, size: usize) -> Self {
        self.max_nested_includes = size;
        self
    }

    pub fn set_max_redirects(&mut self, size: usize) {
        self.max_redirects = size;
    }

    pub fn with_max_redirects(mut self, size: usize) -> Self {
        self.max_redirects = size;
        self
    }

    pub fn set_max_out_messages(&mut self, size: usize) {
        self.max_out_messages = size;
    }

    pub fn with_max_out_messages(mut self, size: usize) -> Self {
        self.max_out_messages = size;
        self
    }

    pub fn set_max_received_headers(&mut self, size: usize) {
        self.max_received_headers = size;
    }

    pub fn with_max_received_headers(mut self, size: usize) -> Self {
        self.max_received_headers = size;
        self
    }

    pub fn set_max_variable_size(&mut self, size: usize) {
        self.max_variable_size = size;
    }

    pub fn with_max_variable_size(mut self, size: usize) -> Self {
        self.max_variable_size = size;
        self
    }

    pub fn set_max_header_size(&mut self, size: usize) {
        self.max_header_size = size;
    }

    pub fn with_max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    pub fn set_max_header_count(&mut self, count: usize) {
        self.max_header_count = count;
    }

    pub fn with_max_header_count(mut self, count: usize) -> Self {
        self.max_header_count = count;
        self
    }

    pub fn set_max_header_block_size(&mut self, size: usize) {
        self.max_header_block_size = size;
    }

    pub fn with_max_header_block_size(mut self, size: usize) -> Self {
        self.max_header_block_size = size;
        self
    }

    #[inline(always)]
    pub(crate) fn has_header_block_limits(&self) -> bool {
        self.max_header_count != usize::MAX || self.max_header_block_size != usize::MAX
    }

    pub fn set_default_vacation_expiry(&mut self, expiry: u64) {
        self.default_vacation_expiry = expiry;
    }

    pub fn with_default_vacation_expiry(mut self, expiry: u64) -> Self {
        self.default_vacation_expiry = expiry;
        self
    }

    pub fn set_default_duplicate_expiry(&mut self, expiry: u64) {
        self.default_duplicate_expiry = expiry;
    }

    pub fn with_default_duplicate_expiry(mut self, expiry: u64) -> Self {
        self.default_duplicate_expiry = expiry;
        self
    }

    pub fn set_capability(&mut self, capability: impl Into<Capability>) {
        self.allowed_capabilities.insert(capability.into());
    }

    pub fn with_capability(mut self, capability: impl Into<Capability>) -> Self {
        self.set_capability(capability);
        self
    }

    pub fn unset_capability(&mut self, capability: impl Into<Capability>) {
        self.allowed_capabilities.remove(&capability.into());
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
            self.allowed_capabilities.remove(&capability.into());
        }
        self
    }

    pub fn set_protected_header(&mut self, header_name: impl Into<Cow<'static, str>>) {
        if let Some(header_name) = HeaderName::parse(header_name) {
            self.protected_headers.push(header_name);
        }
    }

    pub fn with_protected_header(mut self, header_name: impl Into<Cow<'static, str>>) -> Self {
        self.set_protected_header(header_name);
        self
    }

    pub fn with_protected_headers(
        mut self,
        header_names: impl IntoIterator<Item = impl Into<Cow<'static, str>>>,
    ) -> Self {
        self.protected_headers = header_names
            .into_iter()
            .filter_map(HeaderName::parse)
            .collect();
        self
    }

    pub fn set_env_variable(
        &mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable<'static>>,
    ) {
        self.environment.insert(name.into(), value.into());
    }

    pub fn with_env_variable(
        mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable<'static>>,
    ) -> Self {
        self.set_env_variable(name, value);
        self
    }

    pub fn set_medatata(
        &mut self,
        name: impl Into<Metadata<String>>,
        value: impl Into<Cow<'static, str>>,
    ) {
        self.metadata.push((name.into(), value.into()));
    }

    pub fn with_metadata(
        mut self,
        name: impl Into<Metadata<String>>,
        value: impl Into<Cow<'static, str>>,
    ) -> Self {
        self.set_medatata(name, value);
        self
    }

    pub fn set_valid_notification_uri(&mut self, uri: impl Into<Cow<'static, str>>) {
        self.valid_notification_uris.insert(uri.into());
    }

    pub fn with_valid_notification_uri(mut self, uri: impl Into<Cow<'static, str>>) -> Self {
        self.valid_notification_uris.insert(uri.into());
        self
    }

    pub fn with_valid_notification_uris(
        mut self,
        uris: impl IntoIterator<Item = impl Into<Cow<'static, str>>>,
    ) -> Self {
        self.valid_notification_uris = uris.into_iter().map(Into::into).collect();
        self
    }

    pub fn set_valid_ext_list(&mut self, name: impl Into<Cow<'static, str>>) {
        self.valid_ext_lists.insert(name.into());
    }

    pub fn with_valid_ext_list(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.set_valid_ext_list(name);
        self
    }

    pub fn set_vacation_use_orig_rcpt(&mut self, value: bool) {
        self.vacation_use_orig_rcpt = value;
    }

    pub fn with_valid_ext_lists(
        mut self,
        lists: impl IntoIterator<Item = impl Into<Cow<'static, str>>>,
    ) -> Self {
        self.valid_ext_lists = lists.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_vacation_use_orig_rcpt(mut self, value: bool) -> Self {
        self.set_vacation_use_orig_rcpt(value);
        self
    }

    pub fn set_vacation_default_subject(&mut self, value: impl Into<Cow<'static, str>>) {
        self.vacation_default_subject = value.into();
    }

    pub fn with_vacation_default_subject(mut self, value: impl Into<Cow<'static, str>>) -> Self {
        self.set_vacation_default_subject(value);
        self
    }

    pub fn set_vacation_subject_prefix(&mut self, value: impl Into<Cow<'static, str>>) {
        self.vacation_subject_prefix = value.into();
    }

    pub fn with_vacation_subject_prefix(mut self, value: impl Into<Cow<'static, str>>) -> Self {
        self.set_vacation_subject_prefix(value);
        self
    }

    pub fn set_local_hostname(&mut self, value: impl Into<Cow<'static, str>>) {
        self.local_hostname = value.into();
    }

    pub fn with_local_hostname(mut self, value: impl Into<Cow<'static, str>>) -> Self {
        self.set_local_hostname(value);
        self
    }

    pub fn with_functions(mut self, fnc_map: &mut FunctionMap) -> Self {
        self.functions = std::mem::take(&mut fnc_map.functions);
        self
    }

    pub fn set_functions(&mut self, fnc_map: &mut FunctionMap) {
        self.functions = std::mem::take(&mut fnc_map.functions);
    }

    pub fn set_include_script(&mut self, name: impl Into<String>, script: Sieve<'static>) {
        self.include_scripts.insert(name.into(), script);
    }

    pub fn with_include_script(mut self, name: impl Into<String>, script: Sieve<'static>) -> Self {
        self.set_include_script(name, script);
        self
    }

    pub fn include_script(&self, name: &str) -> Option<&Sieve<'static>> {
        self.include_scripts.get(name)
    }
}

impl FunctionMap {
    pub fn new() -> Self {
        FunctionMap {
            map: Default::default(),
            functions: Default::default(),
        }
    }

    pub fn with_function(self, name: impl Into<String>, fnc: Function) -> Self {
        self.with_function_args(name, fnc, 1)
    }

    pub fn with_function_no_args(self, name: impl Into<String>, fnc: Function) -> Self {
        self.with_function_args(name, fnc, 0)
    }

    pub fn with_function_args(
        mut self,
        name: impl Into<String>,
        fnc: Function,
        num_args: u32,
    ) -> Self {
        self.map
            .insert(name.into(), (self.functions.len() as u32, num_args));
        self.functions.push(fnc);
        self
    }

    pub fn with_external_function(
        mut self,
        name: impl Into<String>,
        id: ExternalId,
        num_args: u32,
    ) -> Self {
        self.set_external_function(name, id, num_args);
        self
    }

    pub fn set_external_function(
        &mut self,
        name: impl Into<String>,
        id: ExternalId,
        num_args: u32,
    ) {
        self.map.insert(name.into(), (ID_EXTERNAL - id, num_args));
    }
}

impl<T> Metadata<T> {
    pub fn server(annotation: impl Into<T>) -> Self {
        Metadata::Server {
            annotation: annotation.into(),
        }
    }

    pub fn mailbox(name: impl Into<T>, annotation: impl Into<T>) -> Self {
        Metadata::Mailbox {
            name: name.into(),
            annotation: annotation.into(),
        }
    }
}

impl From<String> for Metadata<String> {
    fn from(annotation: String) -> Self {
        Metadata::Server { annotation }
    }
}

impl From<&'_ str> for Metadata<String> {
    fn from(annotation: &'_ str) -> Self {
        Metadata::Server {
            annotation: annotation.to_string(),
        }
    }
}

impl From<(String, String)> for Metadata<String> {
    fn from((name, annotation): (String, String)) -> Self {
        Metadata::Mailbox { name, annotation }
    }
}

impl From<(&'_ str, &'_ str)> for Metadata<String> {
    fn from((name, annotation): (&'_ str, &'_ str)) -> Self {
        Metadata::Mailbox {
            name: name.to_string(),
            annotation: annotation.to_string(),
        }
    }
}
