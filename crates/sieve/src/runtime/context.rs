/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Arena;
use super::message::{
    edits::Edits,
    parts::{PartCursor, ROOT_PART, Scope, empty_message},
};
use super::{
    RuntimeError, Variable,
    handler::{Action, Handler, Input, Reply, Script, Status},
    tests::{TestResult, test_envelope::parse_envelope_address},
    variable::Array,
};
use crate::{
    Context, Envelope, Metadata, Runtime, Sieve, SpamStatus, VirusStatus,
    bytecode::{
        cursor::Cursor,
        ops,
        rec::{Rec, tag},
    },
    compiler::grammar::Capability,
};
use ahash::AHashMap;
use mail_parser::{Message, PartId};
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
};

#[derive(Clone, Copy)]
pub(crate) struct Frame<'x> {
    pub(crate) script: &'x Sieve<'x>,
    pub(crate) prev_pos: usize,
    pub(crate) local_base: usize,
    pub(crate) match_base: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pending<'x> {
    Idle,
    Test { is_not: bool },
    Function,
    Include { name: Script<'x>, optional: bool },
    Action,
    Finished,
    Aborted,
}

impl<'x> Context<'x> {
    pub fn new(
        runtime: &'x Runtime,
        message: &'x Message<'x>,
        script: &'x Sieve<'x>,
        arena: &'x mut Arena,
    ) -> Self {
        arena.prepare(runtime.memory_limit);
        Self::with_message(runtime, message, script, arena)
    }

    pub(crate) fn with_message(
        runtime: &'x Runtime,
        message: &'x Message<'x>,
        script: &'x Sieve<'x>,
        arena: &'x mut Arena,
    ) -> Self {
        let message_size = message.raw().len();
        let message = if message.part(ROOT_PART).is_some() {
            message
        } else {
            arena.keep_message(empty_message())
        };
        Context {
            runtime,
            message,
            script,
            frames: Vec::with_capacity(2),
            local_base: 0,
            match_base: 0,
            part: ROOT_PART,
            part_iter: PartCursor::default(),
            part_iter_stack: Vec::new(),
            pos: 0,
            test_result: false,
            pending: Pending::Idle,
            error: None,
            rejected: false,
            hop_limited: false,
            included: Vec::new(),
            vars_global: AHashMap::new(),
            vars_env: AHashMap::new(),
            vars_local: Vec::with_capacity(script.num_vars()),
            vars_match: Vec::with_capacity(script.num_match_vars()),
            expr_stack: Vec::with_capacity(16),
            expr_pos: 0,
            envelope: Vec::new(),
            metadata: Vec::new(),
            message_size,
            edits: Edits::default(),
            body_cache: RefCell::new(Vec::new()),
            final_action: Some(Action::Keep {
                flags: &[],
                message_id: 0,
            }),
            flags: Vec::new(),
            actions: Vec::new(),
            has_changes: false,
            oom: Cell::new(false),
            dynamic_regexes: RefCell::new(AHashMap::new()),
            user_address: "".into(),
            user_full_name: "".into(),
            current_time: super::platform::unix_time(),
            num_redirects: 0,
            num_instructions: 0,
            num_scanned_bytes: 0,
            num_out_messages: 0,
            has_replied: false,
            last_message_id: 0,
            main_message_id: 0,
            virus_status: VirusStatus::Unknown,
            spam_status: SpamStatus::Unknown,
            arena,
        }
    }

    #[inline(always)]
    pub(crate) fn alloc_str(&self, s: &str) -> &'x str {
        if s.is_empty() {
            return "";
        }
        match self.arena.bump.try_alloc_slice_copy(s.as_bytes()) {
            Ok(bytes) => unsafe { std::str::from_utf8_unchecked(extend(bytes)) },
            Err(_) => {
                self.note_oom();
                ""
            }
        }
    }

    #[inline(always)]
    pub(crate) fn alloc_string(&self, s: String) -> &'x str {
        self.alloc_str(&s)
    }

    pub(crate) fn alloc_strs(&self, items: &[&'x str]) -> &'x [&'x str] {
        if items.is_empty() {
            return &[];
        }
        match self.arena.bump.try_alloc_slice_copy(items) {
            Ok(slice) => unsafe { extend(slice) },
            Err(_) => {
                self.note_oom();
                &[]
            }
        }
    }

    pub(crate) fn alloc_variables(&self, items: Vec<Variable<'x>>) -> &'x [Variable<'x>] {
        match self.try_alloc_variables(items) {
            Ok(slice) => slice,
            Err(_) => {
                self.note_oom();
                &[]
            }
        }
    }

    pub(crate) fn try_alloc_variables<I>(
        &self,
        items: I,
    ) -> Result<&'x [Variable<'x>], RuntimeError>
    where
        I: IntoIterator<Item = Variable<'x>>,
        I::IntoIter: ExactSizeIterator,
    {
        let items = items.into_iter();
        if items.len() == 0 {
            return Ok(&[]);
        }
        self.arena
            .bump
            .try_alloc_slice_fill_iter(items.map(|v| self.intern(v)))
            .map(|slice| unsafe { extend(slice) })
            .map_err(|_| RuntimeError::MemoryLimitReached)
    }

    #[inline(always)]
    pub(crate) fn intern(&self, value: Variable<'x>) -> Variable<'x> {
        match value {
            Variable::String(Cow::Owned(s)) => Variable::String(Cow::Borrowed(self.alloc_str(&s))),
            Variable::Array(Array::Owned(items)) => {
                Variable::Array(Array::Borrowed(self.alloc_variables(items)))
            }
            value => value,
        }
    }

    #[inline(always)]
    pub(crate) fn intern_cow(&self, value: Cow<'x, str>) -> &'x str {
        match value {
            Cow::Borrowed(s) => s,
            Cow::Owned(s) => self.alloc_str(&s),
        }
    }

    #[cold]
    pub(crate) fn note_oom(&self) {
        self.oom.set(true);
    }

    pub fn run<H: Handler<'x>>(&mut self, handler: &mut H) -> Result<Status, RuntimeError> {
        match self.pending {
            Pending::Idle => {
                self.pending = Pending::Action;
                self.push_frame(self.script);
            }
            Pending::Finished => return Ok(Status::Finished),
            Pending::Aborted => {
                return match self.error.take() {
                    Some(err) => Err(err),
                    None => self.finish(handler),
                };
            }
            Pending::Action => (),
            _ => return Err(RuntimeError::AwaitingInput),
        }

        match self.flush_actions(handler) {
            Ok(true) => (),
            Ok(false) => return Ok(Status::Pending),
            Err(err) => return Err(self.abort(err)),
        }

        if self.frames.is_empty() {
            return self.finish(handler);
        }

        let cpu_limit = self.runtime.cpu_limit;

        'outer: loop {
            if self.frames.is_empty() {
                return self.finish(handler);
            }
            let script = self.script;
            let mut cur = Cursor::new(script.code(), self.pos);

            while !cur.at_end() {
                self.num_instructions += 1;
                if self.num_instructions > cpu_limit {
                    return Err(self.abort(RuntimeError::CPULimitReached));
                }
                if self.oom.get() {
                    return Err(self.abort(RuntimeError::MemoryLimitReached));
                }
                let start = cur.pos;
                let op = cur.u8()?;

                match op {
                    ops::Jz::OP => {
                        let jump = ops::Jz::decode(&mut cur)?;
                        if !self.test_result {
                            cur.pos = jump.target.0 as usize;
                        }
                        continue;
                    }
                    ops::Jnz::OP => {
                        let jump = ops::Jnz::decode(&mut cur)?;
                        if self.test_result {
                            cur.pos = jump.target.0 as usize;
                        }
                        continue;
                    }
                    ops::Jmp::OP => {
                        let jump = ops::Jmp::decode(&mut cur)?;
                        cur.pos = jump.target.0 as usize;
                        continue;
                    }
                    ops::Clear::OP => {
                        let clear = ops::Clear::decode(&mut cur)?;
                        self.exec_clear(&clear);
                        continue;
                    }
                    ops::Discard::OP => {
                        self.final_action = Some(Action::Discard);
                        continue;
                    }
                    ops::Stop::OP => {
                        self.pos = cur.pos;
                        self.frames.clear();
                        return self.finish(handler);
                    }
                    ops::Return::OP => {
                        self.pos = cur.pos;
                        self.pop_frame();
                        continue 'outer;
                    }
                    _ => (),
                }

                match self.exec_op(op, start, &mut cur, handler) {
                    Ok(Flow::Continue) => (),
                    Ok(Flow::Jump(target)) => {
                        cur.pos = target;
                    }
                    Ok(Flow::Switch) => {
                        continue 'outer;
                    }
                    Ok(Flow::Pending) => {
                        return Ok(Status::Pending);
                    }
                    Err(err) => {
                        return Err(self.abort(err));
                    }
                }
            }

            self.pos = cur.pos;
            self.pop_frame();
        }
    }

    #[inline(always)]
    fn exec_op<H: Handler<'x>>(
        &mut self,
        op: u8,
        start: usize,
        cur: &mut Cursor<'x>,
        handler: &mut H,
    ) -> Result<Flow, RuntimeError> {
        let script = self.script;
        let flow = match op {
            ops::TestHeader::OP => {
                let test = ops::TestHeader::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_header(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestString::OP => {
                let test = ops::TestString::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_string(script, &test, false, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestEnvironment::OP => {
                let test = ops::TestEnvironment::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_environment(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestAddress::OP => {
                let test = ops::TestAddress::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_address(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestEnvelope::OP => {
                let test = ops::TestEnvelope::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_envelope(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestExists::OP => {
                let test = ops::TestExists::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_exists(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestSize::OP => {
                let test = ops::TestSize::decode(cur)?;
                self.pos = cur.pos;
                self.test_outcome(self.test_size(&test))
            }
            ops::TestBody::OP => {
                let test = ops::TestBody::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_body(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestDate::OP => {
                let test = ops::TestDate::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_date(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestCurrentDate::OP => {
                let test = ops::TestCurrentDate::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_current_date(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestDuplicate::OP => {
                let test = ops::TestDuplicate::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_duplicate(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestHasFlag::OP => {
                let test = ops::TestHasFlag::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_hasflag(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestNotifyMethodCapability::OP => {
                let test = ops::TestNotifyMethodCapability::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_notify_method_capability(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestValidNotifyMethod::OP => {
                let test = ops::TestValidNotifyMethod::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_valid_notify_method(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestValidExtList::OP => {
                let test = ops::TestValidExtList::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_valid_ext_list(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestIhave::OP => {
                let test = ops::TestIhave::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_ihave(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestMailboxExists::OP => {
                let test = ops::TestMailboxExists::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_mailbox_exists(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestMailboxIdExists::OP => {
                let test = ops::TestMailboxIdExists::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_mailbox_id_exists(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestSpecialUseExists::OP => {
                let test = ops::TestSpecialUseExists::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_special_use_exists(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestMetadata::OP => {
                let test = ops::TestMetadata::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_metadata(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestMetadataExists::OP => {
                let test = ops::TestMetadataExists::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_metadata_exists(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestSpamTest::OP => {
                let test = ops::TestSpamTest::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_spamtest(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestVirusTest::OP => {
                let test = ops::TestVirusTest::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_virustest(script, &test)?;
                    self.test_outcome(result)
                }
            }
            ops::TestVacation::OP => {
                let test = ops::TestVacation::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.test_vacation(script, &test, handler)?;
                    self.test_outcome(result)
                }
            }
            ops::TestConvert::OP => {
                let test = ops::TestConvert::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.exec_convert(script, &test.into())?;
                    self.test_outcome(result)
                }
            }
            ops::TestTrue::OP => {
                self.pos = cur.pos;
                self.test_result = true;
                Flow::Continue
            }
            ops::TestFalse::OP => {
                self.pos = cur.pos;
                self.test_result = false;
                Flow::Continue
            }
            ops::TestInvalid::OP => {
                let test = ops::TestInvalid::decode(cur)?;
                return Err(RuntimeError::InvalidInstruction {
                    name: script.str(test.name)?.to_string(),
                    line_num: test.line_num,
                    line_pos: test.line_pos,
                });
            }
            ops::Eval::OP => {
                let eval = ops::Eval::decode(cur)?;
                self.pos = cur.pos;
                match self.eval_expression(script, eval.expr, handler)? {
                    Some(result) => {
                        self.test_result = result.to_bool();
                        Flow::Continue
                    }
                    None => {
                        self.pos = start;
                        Flow::Pending
                    }
                }
            }
            ops::Let::OP => {
                let let_ = ops::Let::decode(cur)?;
                self.pos = cur.pos;
                match self.eval_expression(script, let_.expr, handler)? {
                    Some(result) => {
                        self.set_variable(script, let_.name, result)?;
                        Flow::Continue
                    }
                    None => {
                        self.pos = start;
                        Flow::Pending
                    }
                }
            }
            ops::While::OP => {
                let while_ = ops::While::decode(cur)?;
                self.pos = cur.pos;
                match self.eval_expression(script, while_.expr, handler)? {
                    Some(result) => {
                        if result.to_bool() {
                            Flow::Continue
                        } else {
                            Flow::Jump(while_.jz_pos.0 as usize)
                        }
                    }
                    None => {
                        self.pos = start;
                        Flow::Pending
                    }
                }
            }
            ops::Set::OP => {
                let set = ops::Set::decode(cur)?;
                self.pos = cur.pos;
                self.exec_set(script, &set)?;
                self.flush(handler)?
            }
            ops::Keep::OP => {
                let keep = ops::Keep::decode(cur)?;
                self.pos = cur.pos;
                self.exec_keep(script, &keep)?;
                self.flush(handler)?
            }
            ops::FileInto::OP => {
                let fileinto = ops::FileInto::decode(cur)?;
                self.pos = cur.pos;
                self.exec_fileinto(script, &fileinto)?;
                self.flush(handler)?
            }
            ops::Redirect::OP => {
                let redirect = ops::Redirect::decode(cur)?;
                self.pos = cur.pos;
                self.exec_redirect(script, &redirect)?;
                self.flush(handler)?
            }
            ops::Reject::OP => {
                let reject = ops::Reject::decode(cur)?;
                self.pos = cur.pos;
                let reason = self.eval_value(script, reject.reason)?.into_string();
                self.final_action = None;
                self.rejected = true;
                let reason = self.intern_cow(reason);
                self.actions.push(Action::Reject {
                    extended: reject.ereject,
                    reason,
                });
                self.flush(handler)?
            }
            ops::ForEveryPart::OP => {
                let fep = ops::ForEveryPart::decode(cur)?;
                self.pos = cur.pos;
                if let Some(next_part) = self.next_part() {
                    self.part = next_part;
                    Flow::Continue
                } else if let Some((prev_part, prev_iter)) = self.part_iter_stack.pop() {
                    self.part_iter = prev_iter;
                    self.part = prev_part;
                    Flow::Jump(fep.jz_pos.0 as usize)
                } else {
                    self.part = ROOT_PART;
                    Flow::Continue
                }
            }
            ops::ForEveryPartPush::OP => {
                self.pos = cur.pos;
                let part_iter = self
                    .current_part()
                    .map(|part| {
                        PartCursor::subtree(part, self.part_iter_stack.is_empty(), Scope::Message)
                    })
                    .unwrap_or_default();
                let prev_iter = std::mem::replace(&mut self.part_iter, part_iter);
                self.part_iter_stack.push((self.part, prev_iter));
                Flow::Continue
            }
            ops::ForEveryPartPop::OP => {
                let pop = ops::ForEveryPartPop::decode(cur)?;
                self.pos = cur.pos;
                debug_assert!(
                    pop.num_pops > 0 && pop.num_pops as usize <= self.part_iter_stack.len(),
                    "Pop out of range: {} with {} items.",
                    pop.num_pops,
                    self.part_iter_stack.len()
                );
                for _ in 0..pop.num_pops {
                    if let Some((prev_part, prev_iter)) = self.part_iter_stack.pop() {
                        self.part_iter = prev_iter;
                        self.part = prev_part;
                    } else {
                        break;
                    }
                }
                Flow::Continue
            }
            ops::Replace::OP => {
                let replace = ops::Replace::decode(cur)?;
                self.pos = cur.pos;
                self.exec_replace(script, &replace)?;
                Flow::Continue
            }
            ops::Enclose::OP => {
                let enclose = ops::Enclose::decode(cur)?;
                self.pos = cur.pos;
                self.exec_enclose(script, &enclose)?;
                Flow::Continue
            }
            ops::ExtractText::OP => {
                let extract = ops::ExtractText::decode(cur)?;
                self.pos = cur.pos;
                self.exec_extracttext(script, &extract)?;
                self.flush(handler)?
            }
            ops::AddHeader::OP => {
                let add = ops::AddHeader::decode(cur)?;
                self.pos = cur.pos;
                self.exec_addheader(script, &add)?;
                Flow::Continue
            }
            ops::DeleteHeader::OP => {
                let delete = ops::DeleteHeader::decode(cur)?;
                self.pos = cur.pos;
                self.exec_deleteheader(script, &delete)?;
                Flow::Continue
            }
            ops::Notify::OP => {
                let notify = ops::Notify::decode(cur)?;
                self.pos = cur.pos;
                self.exec_notify(script, &notify)?;
                self.flush(handler)?
            }
            ops::Vacation::OP => {
                let vacation = ops::Vacation::decode(cur)?;
                self.pos = cur.pos;
                self.exec_vacation(script, &vacation)?;
                self.flush(handler)?
            }
            ops::EditFlags::OP => {
                let flags = ops::EditFlags::decode(cur)?;
                self.pos = cur.pos;
                self.exec_editflags(script, &flags)?;
                Flow::Continue
            }
            ops::Convert::OP => {
                let convert = ops::Convert::decode(cur)?;
                self.pos = cur.pos;
                self.exec_convert(script, &convert)?;
                Flow::Continue
            }
            ops::Include::OP => {
                let include = ops::Include::decode(cur)?;
                self.pos = cur.pos;
                self.exec_include(script, &include, handler)?
            }
            ops::Require::OP => {
                let require = ops::Require::decode(cur)?;
                self.pos = cur.pos;
                for rec in script.recs(require.capabilities)? {
                    let capability = Capability::from_rec(script, rec)?;
                    if !self.runtime.allowed_capabilities.contains(&capability) {
                        return Err(if let Capability::Other(not_supported) = capability {
                            RuntimeError::CapabilityNotSupported(not_supported)
                        } else {
                            RuntimeError::CapabilityNotAllowed(capability)
                        });
                    }
                }
                Flow::Continue
            }
            ops::Error::OP => {
                let error = ops::Error::decode(cur)?;
                self.pos = cur.pos;
                let message = self.eval_value(script, error.message)?;
                return Err(RuntimeError::ScriptErrorMessage(
                    message.to_string().into_owned(),
                ));
            }
            ops::Invalid::OP => {
                let invalid = ops::Invalid::decode(cur)?;
                return Err(RuntimeError::InvalidInstruction {
                    name: script.str(invalid.name)?.to_string(),
                    line_num: invalid.line_num,
                    line_pos: invalid.line_pos,
                });
            }
            #[cfg(all(test, stalwart_tests))]
            ops::TestCmd::OP => {
                let cmd = ops::TestCmd::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.exec_test_cmd(script, cmd.arguments, false, handler)?;
                    self.test_outcome(result)
                }
            }
            #[cfg(all(test, stalwart_tests))]
            ops::TestCmdTest::OP => {
                let cmd = ops::TestCmdTest::decode(cur)?;
                self.pos = cur.pos;
                {
                    let result = self.exec_test_cmd(script, cmd.arguments, cmd.is_not, handler)?;
                    self.test_outcome(result)
                }
            }
            _ => return Err(RuntimeError::InvalidBytecode),
        };
        Ok(flow)
    }

    #[inline(always)]
    fn test_outcome(&mut self, result: TestResult) -> Flow {
        match result {
            TestResult::Bool(value) => {
                self.test_result = value;
                Flow::Continue
            }
            TestResult::Pending { is_not } => {
                self.pending = Pending::Test { is_not };
                Flow::Pending
            }
        }
    }

    #[inline(always)]
    fn flush<H: Handler<'x>>(&mut self, handler: &mut H) -> Result<Flow, RuntimeError> {
        if self.oom.get() {
            return Err(RuntimeError::MemoryLimitReached);
        }
        if self.actions.is_empty() || self.flush_actions(handler)? {
            Ok(Flow::Continue)
        } else {
            Ok(Flow::Pending)
        }
    }

    fn flush_actions<H: Handler<'x>>(&mut self, handler: &mut H) -> Result<bool, RuntimeError> {
        let mut actions = std::mem::take(&mut self.actions).into_iter();
        while let Some(action) = actions.next() {
            match handler.action(self, action) {
                Reply::Ready(()) => (),
                Reply::Pending => {
                    let remaining: Vec<Action<'x>> = actions.collect();
                    self.actions = remaining;
                    self.pending = Pending::Action;
                    return Ok(false);
                }
                Reply::Error(err) => return Err(err),
            }
        }
        Ok(true)
    }

    fn finish<H: Handler<'x>>(&mut self, handler: &mut H) -> Result<Status, RuntimeError> {
        self.frames.clear();
        if let Some(action) = self.final_action.take() {
            match action {
                Action::Keep { flags, message_id } => {
                    let create_message = if self.has_changes {
                        self.build_message_id()
                    } else {
                        None
                    };
                    let flags = if flags.is_empty() && !self.flags.is_empty() {
                        let flags = std::mem::take(&mut self.flags);
                        let flags = self.alloc_strs(&flags);
                        if self.oom.get() {
                            return Err(self.abort(RuntimeError::MemoryLimitReached));
                        }
                        flags
                    } else {
                        flags
                    };
                    if let Some(create_message) = create_message {
                        self.actions.push(create_message);
                        self.actions.push(Action::Keep {
                            flags,
                            message_id: self.main_message_id,
                        });
                    } else {
                        self.actions.push(Action::Keep { flags, message_id });
                    }
                }
                action => self.actions.push(action),
            }
        }
        match self.flush_actions(handler) {
            Ok(true) => {
                self.pending = Pending::Finished;
                Ok(Status::Finished)
            }
            Ok(false) => Ok(Status::Pending),
            Err(err) => Err(self.abort(err)),
        }
    }

    fn abort(&mut self, err: RuntimeError) -> RuntimeError {
        self.frames.clear();
        self.actions.clear();
        if self.pending != Pending::Aborted && !self.rejected {
            self.final_action = Some(Action::Keep {
                flags: &[],
                message_id: 0,
            });
        }
        self.pending = Pending::Aborted;
        err
    }

    pub fn resume(&mut self, input: impl Into<Input<'x>>) {
        let input = input.into();
        match std::mem::replace(&mut self.pending, Pending::Action) {
            Pending::Test { is_not } => {
                self.test_result = matches!(input, Input::Bool(true)) ^ is_not;
            }
            Pending::Function => {
                let value = match input {
                    Input::Value(value) => self.intern(value),
                    Input::Bool(value) => Variable::from(value),
                    _ => Variable::default(),
                };
                self.expr_stack.push(value);
            }
            Pending::Include { name, optional } => match input {
                Input::Script(Some(script)) => self.push_included(name, script),
                _ if optional => (),
                _ => {
                    let err = RuntimeError::ScriptNotFound(name.name().to_string());
                    self.error = Some(self.abort(err));
                }
            },
            Pending::Action => (),
            Pending::Idle => {
                self.pending = Pending::Idle;
            }
            Pending::Finished => {
                self.pending = Pending::Finished;
            }
            Pending::Aborted => {
                self.pending = Pending::Aborted;
            }
        }
    }

    fn push_included(&mut self, name: Script<'x>, script: &'x Sieve<'x>) {
        if !self.included.contains(&name) {
            self.included.push(name);
        }
        self.push_frame(script);
    }

    pub(crate) fn push_frame(&mut self, script: &'x Sieve<'x>) {
        self.frames.push(Frame {
            script: self.script,
            prev_pos: self.pos,
            local_base: self.vars_local.len(),
            match_base: self.vars_match.len(),
        });
        self.local_base = self.vars_local.len();
        self.match_base = self.vars_match.len();
        self.vars_local
            .resize_with(self.vars_local.len() + script.num_vars(), Variable::default);
        self.vars_match.resize_with(
            self.vars_match.len() + script.num_match_vars(),
            Variable::default,
        );
        self.script = script;
        self.pos = 0;
        self.test_result = false;
    }

    pub(crate) fn pop_frame(&mut self) {
        if let Some(frame) = self.frames.pop() {
            self.vars_local.truncate(frame.local_base);
            self.vars_match.truncate(frame.match_base);
            self.script = frame.script;
            self.pos = frame.prev_pos;
            self.local_base = self.frames.last().map_or(0, |f| f.local_base);
            self.match_base = self.frames.last().map_or(0, |f| f.match_base);
        }
    }

    #[inline(always)]
    pub(crate) fn local_base(&self) -> usize {
        self.local_base
    }

    #[inline(always)]
    pub(crate) fn match_base(&self) -> usize {
        self.match_base
    }

    fn exec_clear(&mut self, clear: &ops::Clear) {
        if clear.local_vars_num > 0 {
            let base = self.local_base() + clear.local_vars_idx as usize;
            if let Some(local_vars) = self
                .vars_local
                .get_mut(base..base + clear.local_vars_num as usize)
            {
                for local_var in local_vars.iter_mut() {
                    if !local_var.is_empty() {
                        *local_var = Variable::default();
                    }
                }
            } else {
                debug_assert!(false, "Failed to clear local variables: {clear:?}");
            }
        }
        if clear.match_vars != 0 {
            self.clear_match_variables(clear.match_vars);
        }
    }

    fn exec_include<H: Handler<'x>>(
        &mut self,
        script: &'x Sieve<'x>,
        include: &ops::Include,
        handler: &mut H,
    ) -> Result<Flow, RuntimeError> {
        let name = self.eval_value(script, include.value)?.into_string();
        if name.is_empty() {
            return Ok(Flow::Continue);
        }
        let name = self.intern_cow(name);
        let script_name = if include.global {
            Script::Global(name)
        } else {
            Script::Personal(name)
        };
        if include.once && self.included.contains(&script_name) {
            return Ok(Flow::Continue);
        }
        if self.frames.len() >= self.runtime.max_nested_includes {
            return Err(RuntimeError::TooManyIncludes);
        }
        if let Some(cached) = self.runtime.include_scripts.get(name) {
            self.push_included(script_name, cached);
            return Ok(Flow::Switch);
        }
        match handler.include_script(self, script_name, include.optional) {
            Reply::Ready(Some(included)) => {
                self.push_included(script_name, included);
                Ok(Flow::Switch)
            }
            Reply::Ready(None) if include.optional => Ok(Flow::Continue),
            Reply::Ready(None) => Err(RuntimeError::ScriptNotFound(name.to_string())),
            Reply::Error(err) => Err(err),
            Reply::Pending => {
                self.pending = Pending::Include {
                    name: script_name,
                    optional: include.optional,
                };
                Ok(Flow::Pending)
            }
        }
    }

    #[inline(always)]
    fn next_part(&mut self) -> Option<PartId> {
        let mut cursor = self.part_iter;
        let part = self.advance(&mut cursor);
        self.part_iter = cursor;
        part.map(|part| part.id())
    }

    pub fn set_envelope(
        &mut self,
        envelope: impl TryInto<Envelope>,
        value: impl Into<Cow<'x, str>>,
    ) {
        if let Ok(envelope) = envelope.try_into() {
            if matches!(&envelope, Envelope::From | Envelope::To) {
                let value: Cow<str> = value.into();
                if let Some(value) = parse_envelope_address(value.as_ref()) {
                    let value = self.alloc_str(value);
                    self.envelope.push((envelope, Variable::borrowed(value)));
                }
            } else {
                self.envelope.push((envelope, Variable::from(value.into())));
            }
        }
    }

    pub fn with_vars_env(mut self, vars_env: AHashMap<Cow<'static, str>, Variable<'x>>) -> Self {
        self.vars_env = vars_env;
        self
    }

    pub fn with_envelope_list(mut self, envelope: Vec<(Envelope, Variable<'x>)>) -> Self {
        self.envelope = envelope;
        self
    }

    pub fn with_envelope(
        mut self,
        envelope: impl TryInto<Envelope>,
        value: impl Into<Cow<'x, str>>,
    ) -> Self {
        self.set_envelope(envelope, value);
        self
    }

    pub fn clear_envelope(&mut self) {
        self.envelope.clear()
    }

    pub fn set_user_address(&mut self, from: impl Into<Cow<'x, str>>) {
        self.user_address = from.into();
    }

    pub fn with_user_address(mut self, from: impl Into<Cow<'x, str>>) -> Self {
        self.set_user_address(from);
        self
    }

    pub fn set_user_full_name(&mut self, name: &str) {
        let mut name_ = String::with_capacity(name.len());
        for ch in name.chars() {
            if ['\"', '\\'].contains(&ch) {
                name_.push('\\');
            }
            name_.push(ch);
        }
        self.user_full_name = name_.into();
    }

    pub fn with_user_full_name(mut self, name: &str) -> Self {
        self.set_user_full_name(name);
        self
    }

    pub fn set_env_variable(
        &mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable<'x>>,
    ) {
        self.vars_env.insert(name.into(), value.into());
    }

    pub fn with_env_variable(
        mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable<'x>>,
    ) -> Self {
        self.set_env_variable(name, value);
        self
    }

    pub fn set_global_variable(
        &mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable<'x>>,
    ) {
        self.vars_global.insert(name.into(), value.into());
    }

    pub fn with_global_variable(
        mut self,
        name: impl Into<Cow<'static, str>>,
        value: impl Into<Variable<'x>>,
    ) -> Self {
        self.set_global_variable(name, value);
        self
    }

    pub fn set_medatata(
        &mut self,
        name: impl Into<Metadata<String>>,
        value: impl Into<Cow<'x, str>>,
    ) {
        self.metadata.push((name.into(), value.into()));
    }

    pub fn with_metadata(
        mut self,
        name: impl Into<Metadata<String>>,
        value: impl Into<Cow<'x, str>>,
    ) -> Self {
        self.set_medatata(name, value);
        self
    }

    pub fn set_spam_status(&mut self, status: impl Into<SpamStatus>) {
        self.spam_status = status.into();
    }

    pub fn with_spam_status(mut self, status: impl Into<SpamStatus>) -> Self {
        self.set_spam_status(status);
        self
    }

    pub fn set_virus_status(&mut self, status: impl Into<VirusStatus>) {
        self.virus_status = status.into();
    }

    pub fn with_virus_status(mut self, status: impl Into<VirusStatus>) -> Self {
        self.set_virus_status(status);
        self
    }

    pub fn set_current_time(&mut self, time: i64) {
        self.current_time = time;
    }

    pub fn with_current_time(mut self, time: i64) -> Self {
        self.current_time = time;
        self
    }

    pub fn has_message_changed(&self) -> bool {
        self.main_message_id > 0
    }

    pub fn is_hop_limited(&self) -> bool {
        self.hop_limited
    }

    pub(crate) fn user_from_field(&self) -> String {
        if !self.user_full_name.is_empty() {
            format!("\"{}\" <{}>", self.user_full_name, self.user_address)
        } else {
            self.user_address.to_string()
        }
    }

    pub fn global_variable_names(&self) -> impl Iterator<Item = &str> {
        self.vars_global.keys().map(|k| k.as_ref())
    }

    pub fn global_variable(&self, name: &str) -> Option<&Variable<'_>> {
        self.vars_global.get(name)
    }

    pub fn message(&self) -> &'x Message<'x> {
        self.message
    }

    pub fn part(&self) -> PartId {
        self.part
    }

    pub fn runtime(&self) -> &'x Runtime {
        self.runtime
    }

    pub fn instructions_executed(&self) -> usize {
        self.num_instructions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Jump(usize),
    Switch,
    Pending,
}

#[inline(always)]
pub(crate) unsafe fn extend<'x, T: ?Sized>(value: &T) -> &'x T {
    unsafe { &*(value as *const T) }
}

impl Capability {
    pub(crate) fn from_rec(script: &Sieve<'_>, rec: Rec) -> Result<Capability, RuntimeError> {
        if rec.tag != tag::CAPABILITY {
            return Err(RuntimeError::InvalidBytecode);
        }
        Ok(match rec.b {
            5 => {
                Capability::Comparator(crate::compiler::grammar::Comparator::from_code(rec.c as u8))
            }
            6 => Capability::Other(script.str(rec.str())?.to_string()),
            id => Capability::from_id(id),
        })
    }
}

#[cfg(all(test, stalwart_tests))]
impl<'x> Context<'x> {
    pub(crate) fn with_runtime(self, runtime: &'x Runtime) -> Context<'x> {
        Context { runtime, ..self }
    }

    pub(crate) fn set_message(&mut self, message: &'x Message<'x>) {
        self.message_size = message.raw().len();
        self.message = if message.part(ROOT_PART).is_some() {
            message
        } else {
            self.arena.keep_message(empty_message())
        };
        self.edits = Edits::default();
        self.reset_body_cache();
        self.part = ROOT_PART;
    }

    pub(crate) fn exec_test_cmd<H: Handler<'x>>(
        &mut self,
        script: &'x Sieve<'x>,
        arguments: crate::bytecode::rec::Range,
        is_not: bool,
        handler: &mut H,
    ) -> Result<super::tests::TestResult, RuntimeError> {
        let arguments = self.eval_values(script, arguments)?;
        match handler.function(self, u32::MAX, &arguments) {
            Reply::Ready(value) => Ok(super::tests::TestResult::Bool(value.to_bool() ^ is_not)),
            Reply::Pending => Ok(super::tests::TestResult::Pending { is_not }),
            Reply::Error(err) => Err(err),
        }
    }
}
