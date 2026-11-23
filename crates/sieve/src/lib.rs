/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::{AHashMap, AHashSet};
use compiler::grammar::Capability;
use mail_parser::{HeaderName, Message, PartId};
use runtime::{
    RuntimeError, Variable,
    context::{Frame, Pending},
    handler::Action,
    message::{body::BodyCache, edits::Edits, parts::PartCursor},
};
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
};

pub mod bytecode;
pub mod compiler;
mod regex;
pub mod runtime;
pub mod sieve;

pub use runtime::{
    Action as SieveAction, Arena, Handler, Input, Mailbox, MessageSource, Recipient, Reply, Script,
    Status,
};
pub use sieve::{LoadError, ScriptArena, Sieve};

pub(crate) const MAX_MATCH_VARIABLES: u32 = 63;

#[derive(Clone)]
pub struct Compiler {
    pub(crate) max_script_size: usize,
    pub(crate) max_string_size: usize,
    pub(crate) max_variable_name_size: usize,
    pub(crate) max_nested_blocks: usize,
    pub(crate) max_nested_tests: usize,
    pub(crate) max_nested_foreverypart: usize,
    pub(crate) max_match_variables: usize,
    pub(crate) max_local_variables: usize,
    pub(crate) max_header_size: usize,
    pub(crate) max_includes: usize,
    pub(crate) no_capability_check: bool,
    pub(crate) disabled_capabilities: AHashSet<Capability>,
    pub(crate) functions: AHashMap<String, (u32, u32)>,
}

pub type Function = for<'x> fn(&Context<'x>, &[Variable<'x>]) -> Variable<'x>;

#[derive(Default, Clone)]
pub struct FunctionMap {
    pub(crate) map: AHashMap<String, (u32, u32)>,
    pub(crate) functions: Vec<Function>,
}

#[derive(Debug, Clone)]
pub struct Runtime {
    pub(crate) allowed_capabilities: AHashSet<Capability>,
    pub(crate) valid_notification_uris: AHashSet<Cow<'static, str>>,
    pub(crate) valid_ext_lists: AHashSet<Cow<'static, str>>,
    pub(crate) protected_headers: Vec<HeaderName<'static>>,
    pub(crate) environment: AHashMap<Cow<'static, str>, Variable<'static>>,
    pub(crate) metadata: Vec<(Metadata<String>, Cow<'static, str>)>,
    pub(crate) include_scripts: AHashMap<String, Sieve<'static>>,
    pub(crate) local_hostname: Cow<'static, str>,
    pub(crate) functions: Vec<Function>,

    pub(crate) max_nested_includes: usize,
    pub(crate) cpu_limit: usize,
    pub(crate) memory_limit: usize,
    pub(crate) max_variable_size: usize,
    pub(crate) max_redirects: usize,
    pub(crate) max_received_headers: usize,
    pub(crate) max_header_size: usize,
    pub(crate) max_header_count: usize,
    pub(crate) max_header_block_size: usize,
    pub(crate) max_out_messages: usize,

    pub(crate) default_vacation_expiry: u64,
    pub(crate) default_duplicate_expiry: u64,

    pub(crate) vacation_use_orig_rcpt: bool,
    pub(crate) vacation_default_subject: Cow<'static, str>,
    pub(crate) vacation_subject_prefix: Cow<'static, str>,
}

pub struct Context<'x> {
    pub(crate) runtime: &'x Runtime,
    pub(crate) user_address: Cow<'x, str>,
    pub(crate) user_full_name: Cow<'x, str>,
    pub(crate) current_time: i64,

    pub(crate) message: &'x Message<'x>,
    pub(crate) message_size: usize,
    pub(crate) edits: Edits<'x>,
    pub(crate) body_cache: RefCell<BodyCache<'x>>,
    pub(crate) envelope: Vec<(Envelope, Variable<'x>)>,
    pub(crate) metadata: Vec<(Metadata<String>, Cow<'x, str>)>,

    pub(crate) part: PartId,
    pub(crate) part_iter: PartCursor,
    pub(crate) part_iter_stack: Vec<(PartId, PartCursor)>,

    pub(crate) spam_status: SpamStatus,
    pub(crate) virus_status: VirusStatus,

    pub(crate) script: &'x Sieve<'x>,
    pub(crate) frames: Vec<Frame<'x>>,
    pub(crate) local_base: usize,
    pub(crate) match_base: usize,
    pub(crate) pos: usize,
    pub(crate) test_result: bool,
    pub(crate) pending: Pending<'x>,
    pub(crate) error: Option<RuntimeError>,
    pub(crate) rejected: bool,
    pub(crate) hop_limited: bool,
    pub(crate) included: Vec<Script<'x>>,
    pub(crate) vars_global: AHashMap<Cow<'x, str>, Variable<'x>>,
    pub(crate) vars_env: AHashMap<Cow<'static, str>, Variable<'x>>,
    pub(crate) vars_local: Vec<Variable<'x>>,
    pub(crate) vars_match: Vec<Variable<'x>>,
    pub(crate) expr_stack: Vec<Variable<'x>>,
    pub(crate) expr_pos: usize,

    pub(crate) flags: Vec<&'x str>,
    pub(crate) actions: Vec<Action<'x>>,
    pub(crate) final_action: Option<Action<'x>>,
    pub(crate) last_message_id: usize,
    pub(crate) main_message_id: usize,

    pub(crate) has_changes: bool,
    pub(crate) oom: Cell<bool>,
    pub(crate) dynamic_regexes: RefCell<AHashMap<&'x str, Option<fancy_regex::Regex>>>,
    pub(crate) num_redirects: usize,
    pub(crate) num_instructions: usize,
    pub(crate) num_scanned_bytes: usize,
    pub(crate) num_out_messages: usize,
    pub(crate) has_replied: bool,

    pub(crate) arena: &'x mut Arena,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Envelope {
    From = 0,
    To = 1,
    ByTimeAbsolute = 2,
    ByTimeRelative = 3,
    ByMode = 4,
    ByTrace = 5,
    Notify = 6,
    Orcpt = 7,
    Ret = 8,
    Envid = 9,
}

impl Envelope {
    #[inline(always)]
    pub(crate) fn from_code(code: u8) -> Envelope {
        match code {
            0 => Envelope::From,
            1 => Envelope::To,
            2 => Envelope::ByTimeAbsolute,
            3 => Envelope::ByTimeRelative,
            4 => Envelope::ByMode,
            5 => Envelope::ByTrace,
            6 => Envelope::Notify,
            7 => Envelope::Orcpt,
            8 => Envelope::Ret,
            _ => Envelope::Envid,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum Metadata<T> {
    Server { annotation: T } = 0,
    Mailbox { name: T, annotation: T } = 1,
}

pub type ExternalId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct FileCarbonCopy<T> {
    pub mailbox: T,
    pub mailbox_id: Option<T>,
    pub create: bool,
    pub flags: Box<[T]>,
    pub special_use: Option<T>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Importance {
    High,
    Normal,
    Low,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MatchAs {
    Octet,
    Lowercase,
    Number,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SpamStatus {
    Unknown,
    Ham,
    MaybeSpam(f64),
    Spam,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum VirusStatus {
    Unknown,
    Clean,
    Replaced,
    Cured,
    MaybeVirus,
    Virus,
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/sieve/src/tests/mod.rs"]
mod tests;
