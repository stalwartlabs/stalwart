/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    BinaryOperator, SystemVariable, UnaryOperator, Variable,
    capture::Captures,
    functions::{FnCtx, MAX_ASYNC_ARGS, MAX_SYNC_ARGS, ResolveVariable, SyncFn, asynch::AsyncCall},
    if_block::IfBlock,
    program::{ConstValue, Op, Program, Src},
};
use crate::Server;
use bumpalo::Bump;
use compact_str::{ToCompactString, format_compact};
use registry::{schema::enums::ExpressionVariable, types::EnumImpl};
use trc::{Collector, EvalEvent};

pub const ARENA_RETAIN_CAP: usize = 4 * 1024;
const INLINE_STACK: usize = 8;
const ASYNC_INLINE_STACK: usize = 4;

impl Server {
    pub fn eval_if<'x, R, V>(
        &'x self,
        if_block: &'x IfBlock,
        resolver: &'x V,
        arena: &'x mut Bump,
        session_id: u64,
    ) -> impl Future<Output = Option<R>> + Send + 'x
    where
        R: for<'b> TryFrom<Variable<'b>> + 'x,
        V: ResolveVariable,
    {
        self.eval_program(if_block, resolver, arena, session_id, convert::<R>)
    }

    pub fn eval_if_with<'x, T, V, F>(
        &'x self,
        if_block: &'x IfBlock,
        resolver: &'x V,
        arena: &'x mut Bump,
        session_id: u64,
        with: F,
    ) -> impl Future<Output = Option<T>> + Send + 'x
    where
        T: 'x,
        V: ResolveVariable,
        F: for<'v> FnOnce(Variable<'v>) -> T + Send + 'x,
    {
        self.eval_program(if_block, resolver, arena, session_id, |value| {
            Some(with(value))
        })
    }

    #[allow(clippy::manual_async_fn)]
    fn eval_program<'x, T, V, F>(
        &'x self,
        if_block: &'x IfBlock,
        resolver: &'x V,
        arena: &'x mut Bump,
        session_id: u64,
        finish: F,
    ) -> impl Future<Output = Option<T>> + Send + 'x
    where
        T: 'x,
        V: ResolveVariable,
        F: for<'v> FnOnce(Variable<'v>) -> Option<T> + Send + 'x,
    {
        async move {
            let program = &if_block.program;
            if program.is_empty() {
                trc::event!(
                    Eval(EvalEvent::Result),
                    SpanId = session_id,
                    Id = if_block.id.to_compact_string(),
                    Key = if_block.property.as_str(),
                    Result = ""
                );
                return None;
            }
            arena.reset();
            if let Some(value) = self.run_inline(program, resolver, &*arena) {
                let result = if_block.finish_eval(value, session_id, finish);
                recycle_arena(arena);
                return result;
            }
            Box::pin(self.eval_suspending(if_block, resolver, arena, session_id, finish)).await
        }
    }

    async fn eval_suspending<T, V, F>(
        &self,
        if_block: &IfBlock,
        resolver: &V,
        arena: &mut Bump,
        session_id: u64,
        finish: F,
    ) -> Option<T>
    where
        V: ResolveVariable,
        F: for<'v> FnOnce(Variable<'v>) -> Option<T>,
    {
        let program = &if_block.program;
        arena.reset();
        let result = {
            let mut inline = [Variable::default(); ASYNC_INLINE_STACK];
            let mut machine = Machine::new(stack(program.max_depth(), &mut inline, &*arena));
            let mut pc = 0;
            loop {
                let step = machine.run(
                    &Env {
                        server: self,
                        resolver,
                        arena: &*arena,
                        program,
                    },
                    pc,
                );
                match step {
                    Step::Done(value) => break if_block.finish_eval(value, session_id, finish),
                    Step::Suspend { call, resume } => match self.eval_fnc(call, session_id).await {
                        Ok(output) => {
                            machine.push(output.into_variable(&*arena));
                            pc = resume;
                        }
                        Err(err) => {
                            trc::event!(
                                Eval(EvalEvent::Error),
                                SpanId = session_id,
                                Id = if_block.id.to_compact_string(),
                                Key = if_block.property.as_str(),
                                CausedBy = err,
                            );
                            break None;
                        }
                    },
                }
            }
        };
        recycle_arena(arena);
        result
    }

    fn run_inline<'s, V: ResolveVariable>(
        &'s self,
        program: &'s Program,
        resolver: &'s V,
        arena: &'s Bump,
    ) -> Option<Variable<'s>> {
        let mut inline = [Variable::default(); INLINE_STACK];
        let mut machine = Machine::new(stack(program.max_depth(), &mut inline, arena));
        let env = Env {
            server: self,
            resolver,
            arena,
            program,
        };
        match machine.run(&env, 0) {
            Step::Done(value) => Some(value),
            Step::Suspend { .. } => None,
        }
    }
}

impl IfBlock {
    fn finish_eval<T, F>(&self, value: Variable<'_>, session_id: u64, finish: F) -> Option<T>
    where
        F: for<'v> FnOnce(Variable<'v>) -> Option<T>,
    {
        trc::event!(
            Eval(EvalEvent::Result),
            SpanId = session_id,
            Id = self.id.to_compact_string(),
            Key = self.property.as_str(),
            Result = format_compact!("{value:?}"),
        );
        let result = finish(value);
        if result.is_none() {
            trc::event!(
                Eval(EvalEvent::Result),
                SpanId = session_id,
                Id = self.id.to_compact_string(),
                Key = self.property.as_str(),
                Result = "",
            );
        }
        result
    }
}

fn recycle_arena(arena: &mut Bump) {
    arena.reset();
    if arena.allocated_bytes() > ARENA_RETAIN_CAP {
        *arena = Bump::new();
    }
}

fn convert<R: for<'b> TryFrom<Variable<'b>>>(value: Variable<'_>) -> Option<R> {
    R::try_from(value).ok()
}

fn stack<'b, 's: 'b, const N: usize>(
    depth: usize,
    inline: &'b mut [Variable<'s>; N],
    arena: &'s Bump,
) -> &'b mut [Variable<'s>] {
    if depth <= N {
        inline
    } else {
        arena.alloc_slice_fill_copy(depth, Variable::default())
    }
}

struct Env<'s, V> {
    server: &'s Server,
    resolver: &'s V,
    arena: &'s Bump,
    program: &'s Program,
}

enum Step<'s> {
    Done(Variable<'s>),
    Suspend { call: AsyncCall<'s>, resume: usize },
}

struct Machine<'s, 'b> {
    stack: &'b mut [Variable<'s>],
    len: usize,
    captures: Captures<'s>,
}

impl<'s, V: ResolveVariable> Env<'s, V> {
    fn load(&self, variable: ExpressionVariable) -> Variable<'s> {
        self.resolver.resolve_variable(variable, self.arena)
    }

    fn system(&self, variable: SystemVariable) -> Variable<'s> {
        let server = self.server;
        match variable {
            SystemVariable::Hostname => Variable::String(&server.core.network.server_name),
            SystemVariable::Domain => Variable::String(&server.core.email.default_domain_name),
            SystemVariable::NodeId => server.core.network.node_id.into(),
            SystemVariable::NodeHostname => Variable::String(server.registry().local_hostname()),
            SystemVariable::NodeRole => {
                Variable::String(server.registry().cluster_role().unwrap_or_default())
            }
            SystemVariable::Metric(metric) => Variable::Float(Collector::read_metric(metric)),
        }
    }

    fn constant(&self, index: u32) -> Variable<'s> {
        self.program
            .constant(index)
            .map(|value| value.to_variable(self.arena))
            .unwrap_or_default()
    }

    fn compare_constant(&self, left: Variable<'s>, op: BinaryOperator, index: u32) -> bool {
        self.program
            .constant(index)
            .and_then(ConstValue::scalar)
            .is_some_and(|right| left.compare(op, &right))
    }

    fn in_array(&self, value: Variable<'s>, index: u32) -> bool {
        match self.program.constant(index) {
            Some(ConstValue::Array { items, .. }) => items
                .iter()
                .any(|item| item.scalar().is_some_and(|item| item == value)),
            _ => false,
        }
    }
}

impl<'s, 'b> Machine<'s, 'b> {
    fn new(stack: &'b mut [Variable<'s>]) -> Self {
        Machine {
            stack,
            len: 0,
            captures: Captures::default(),
        }
    }

    fn push(&mut self, value: Variable<'s>) {
        match self.stack.get_mut(self.len) {
            Some(slot) => {
                *slot = value;
                self.len += 1;
            }
            None => debug_assert!(false, "expression stack overflow"),
        }
    }

    fn pop(&mut self) -> Variable<'s> {
        match self.len.checked_sub(1) {
            Some(top) => {
                self.len = top;
                self.stack.get(top).copied().unwrap_or_default()
            }
            None => Variable::default(),
        }
    }

    fn peek_bool(&self) -> bool {
        self.len
            .checked_sub(1)
            .and_then(|top| self.stack.get(top))
            .is_some_and(|value| value.to_bool())
    }

    fn load<V: ResolveVariable>(&mut self, src: Src, env: &Env<'s, V>) -> Variable<'s> {
        match src {
            Src::Pop => self.pop(),
            Src::Var(variable) => env.load(variable),
        }
    }

    fn call(&mut self, function: SyncFn, argc: usize, ctx: &FnCtx<'s>) {
        let result = match self.len.checked_sub(argc) {
            Some(base) => {
                let result = function(ctx, self.stack.get(base..self.len).unwrap_or_default());
                self.len = base;
                result
            }
            None => {
                let mut padded = [Variable::default(); MAX_SYNC_ARGS];
                let missing = argc - self.len;
                for (slot, value) in padded
                    .iter_mut()
                    .skip(missing)
                    .zip(self.stack.iter().take(self.len))
                {
                    *slot = *value;
                }
                self.len = 0;
                function(ctx, padded.get(..argc).unwrap_or(&padded))
            }
        };
        self.push(result);
    }

    fn build(&mut self, count: usize, arena: &'s Bump) {
        let items: &'s [Variable<'s>] = match self.len.checked_sub(count) {
            Some(base) => {
                let items =
                    arena.alloc_slice_copy(self.stack.get(base..self.len).unwrap_or_default());
                self.len = base;
                items
            }
            None => {
                let missing = count - self.len;
                let present = self.stack.get(..self.len).unwrap_or_default();
                let items = arena.alloc_slice_fill_with(count, |position| {
                    position
                        .checked_sub(missing)
                        .and_then(|position| present.get(position))
                        .copied()
                        .unwrap_or_default()
                });
                self.len = 0;
                items
            }
        };
        self.push(Variable::Array(items));
    }

    fn take_async_args(&mut self, argc: usize) -> [Variable<'s>; MAX_ASYNC_ARGS] {
        let mut args = [Variable::default(); MAX_ASYNC_ARGS];
        for position in (0..argc).rev() {
            let value = self.pop();
            if let Some(slot) = args.get_mut(position) {
                *slot = value;
            }
        }
        args
    }

    fn run<V: ResolveVariable>(&mut self, env: &Env<'s, V>, start: usize) -> Step<'s> {
        let ops = env.program.ops();
        let mut pc = start;
        while let Some(op) = ops.get(pc) {
            pc += 1;
            match *op {
                Op::Var(variable) => {
                    let value = env.load(variable);
                    self.push(value);
                }
                Op::Global(name) => {
                    let value = env
                        .resolver
                        .resolve_global(env.program.string(name), env.arena);
                    self.push(value);
                }
                Op::System(variable) => self.push(env.system(variable)),
                Op::Capture(group) => self.push(Variable::String(self.captures.get(group))),
                Op::Int(value) => self.push(Variable::Integer(value)),
                Op::Float(value) => self.push(Variable::Float(value)),
                Op::Static(value) => self.push(Variable::Constant(value)),
                Op::Str(index) => self.push(Variable::String(env.program.string(index))),
                Op::Array(index) => self.push(env.constant(index)),
                Op::Unary(op) => {
                    let value = self.pop();
                    self.push(match op {
                        UnaryOperator::Not => value.op_not(),
                        UnaryOperator::Minus => value.op_minus(),
                    });
                }
                Op::Binary(op) => {
                    let right = self.pop();
                    let left = self.pop();
                    self.push(left.op_binary(op, right, env.arena));
                }
                Op::JmpIf { val, target } => {
                    if self.peek_bool() == val {
                        pc = target as usize;
                    }
                }
                Op::Call { id, argc } => match Program::function(id) {
                    Some(function) => self.call(function, argc as usize, &FnCtx::new(env.arena)),
                    None => {
                        self.len = self.len.saturating_sub(argc as usize);
                        self.push(Variable::default());
                    }
                },
                Op::CallAsync { id, argc } => {
                    let args = self.take_async_args(argc as usize);
                    return Step::Suspend {
                        call: AsyncCall::new(id, args, env.arena),
                        resume: pc,
                    };
                }
                Op::Index => {
                    let index = self.pop().to_usize().unwrap_or_default();
                    let value = self.pop();
                    self.push(value.index(index));
                }
                Op::IndexConst { src, index } => {
                    let value = self.load(src, env);
                    self.push(value.index(index as usize));
                }
                Op::Build(count) => self.build(count as usize, env.arena),
                Op::Regex(index) => {
                    let haystack = self.pop().to_str(env.arena);
                    let matched = env.program.regex(index).is_some_and(|regex| {
                        if env.program.uses_captures() {
                            self.captures.read(index, regex, haystack, env.arena)
                        } else {
                            regex.is_match(haystack)
                        }
                    });
                    self.push(Variable::Integer(i64::from(matched)));
                }
                Op::CmpConst { src, op, konst } => {
                    let left = self.load(src, env);
                    self.push(env.compare_constant(left, op, konst).into());
                }
                Op::Text { src, op, needle } => {
                    let haystack = self.load(src, env);
                    let matched = env
                        .program
                        .needle(needle)
                        .is_some_and(|needle| needle.matches(op, haystack, env.arena));
                    self.push(matched.into());
                }
                Op::ContainsIgnoreCase { src, needle } => {
                    let haystack = self.load(src, env);
                    let matched = env
                        .program
                        .case_needle(needle)
                        .is_some_and(|needle| needle.matches(haystack, env.arena));
                    self.push(matched.into());
                }
                Op::InArray { src, array } => {
                    let value = self.load(src, env);
                    self.push(env.in_array(value, array).into());
                }
                Op::InSet { src, set } => {
                    let value = self.load(src, env);
                    let matched = env.program.set(set).is_some_and(|set| set.contains(value));
                    self.push(matched.into());
                }
                Op::Test { target } => {
                    let value = self.pop();
                    self.len = 0;
                    if !value.to_bool() {
                        pc = target as usize;
                    }
                }
                Op::Return => return Step::Done(self.pop()),
            }
        }
        Step::Done(self.pop())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::functions::EmptyResolver;
    use std::mem::size_of;

    const MAX_EVAL_FUTURE: usize = 72;

    fn eval_future<'x>(
        server: &'x Server,
        if_block: &'x IfBlock,
        arena: &'x mut Bump,
    ) -> impl Future<Output = Option<String>> + Send + 'x {
        server.eval_if::<String, _>(if_block, &EmptyResolver, arena, 0)
    }

    fn eval_with_future<'x>(
        server: &'x Server,
        if_block: &'x IfBlock,
        arena: &'x mut Bump,
    ) -> impl Future<Output = Option<usize>> + Send + 'x {
        server.eval_if_with(if_block, &EmptyResolver, arena, 0, |value| match value {
            Variable::String(text) => text.len(),
            _ => 0,
        })
    }

    fn future_size<'x, F: Future + Send>(
        _: fn(&'x Server, &'x IfBlock, &'x mut Bump) -> F,
    ) -> usize {
        size_of::<F>()
    }

    #[test]
    fn eval_futures_stay_small() {
        for size in [future_size(eval_future), future_size(eval_with_future)] {
            assert!(size <= MAX_EVAL_FUTURE, "eval future is {size} bytes");
        }
    }
}
