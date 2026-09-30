/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    BinaryOperator, Constant, ExpressionItem, SystemVariable, UnaryOperator, Variable,
    capture::CaptureRegex,
    functions::{FUNCTIONS, SyncFn, SyncFunction, text},
    kernels::{ConstNeedle, ConstSet, IgnoreCaseNeedle},
};
use ahash::AHashMap;
use bumpalo::Bump;
use registry::schema::enums::{ExpressionConstant, ExpressionVariable};
use std::{fmt, mem::size_of};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Src {
    Pop,
    Var(ExpressionVariable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextOp {
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Var(ExpressionVariable),
    Global(u32),
    System(SystemVariable),
    Capture(u32),
    Int(i64),
    Float(f64),
    Static(ExpressionConstant),
    Str(u32),
    Array(u32),
    Unary(UnaryOperator),
    Binary(BinaryOperator),
    JmpIf {
        val: bool,
        target: u32,
    },
    Call {
        id: u16,
        argc: u16,
    },
    CallAsync {
        id: u16,
        argc: u16,
    },
    Index,
    IndexConst {
        src: Src,
        index: u32,
    },
    Build(u32),
    Regex(u32),
    CmpConst {
        src: Src,
        op: BinaryOperator,
        konst: u32,
    },
    Text {
        src: Src,
        op: TextOp,
        needle: u32,
    },
    ContainsIgnoreCase {
        src: Src,
        needle: u32,
    },
    InArray {
        src: Src,
        array: u32,
    },
    InSet {
        src: Src,
        set: u32,
    },
    Test {
        target: u32,
    },
    Return,
}

const _: () = assert!(size_of::<Op>() == 16);

const JUMP_TARGET: u32 = u32::MAX;

const LINEAR_STRINGS: usize = 16;

#[derive(Debug, Clone)]
pub enum ConstValue {
    Integer(i64),
    Float(f64),
    Static(ExpressionConstant),
    String(Box<str>),
    Array {
        items: Box<[ConstValue]>,
        view: Option<Box<[Variable<'static>]>>,
    },
}

pub struct Needle {
    needle: ConstNeedle,
}

pub struct CaseNeedle {
    text: Box<str>,
    needle: IgnoreCaseNeedle,
}

pub struct StringSet {
    items: Box<[Box<str>]>,
    hashed: Option<ConstSet>,
}

#[derive(Debug, Clone, Default)]
pub struct Program {
    ops: Box<[Op]>,
    strings: Box<[Box<str>]>,
    needles: Box<[Needle]>,
    case_needles: Box<[CaseNeedle]>,
    sets: Box<[StringSet]>,
    consts: Box<[ConstValue]>,
    regexes: Box<[CaptureRegex]>,
    max_depth: usize,
    uses_captures: bool,
}

#[derive(Default)]
pub struct ProgramBuilder {
    ops: Vec<Op>,
    pools: Pools,
    scratch: Scratch,
}

#[derive(Default)]
struct Pools {
    strings: Vec<Box<str>>,
    string_ids: Option<AHashMap<u64, u32>>,
    needles: Vec<Needle>,
    case_needles: Vec<CaseNeedle>,
    sets: Vec<StringSet>,
    consts: Vec<ConstValue>,
    regexes: Vec<CaptureRegex>,
}

#[derive(Default)]
struct Scratch {
    origin: Vec<usize>,
    jumps: Vec<u32>,
}

struct Lowering<'b> {
    pools: &'b mut Pools,
    ops: &'b mut Vec<Op>,
    base: usize,
    origin: &'b mut Vec<usize>,
    jumps: &'b [u32],
    items: &'b [ExpressionItem],
}

impl ConstValue {
    pub fn to_variable<'x>(&'x self, arena: &'x Bump) -> Variable<'x> {
        match self {
            ConstValue::Integer(n) => Variable::Integer(*n),
            ConstValue::Float(n) => Variable::Float(*n),
            ConstValue::Static(c) => Variable::Constant(*c),
            ConstValue::String(s) => Variable::String(s),
            ConstValue::Array {
                view: Some(view), ..
            } => Variable::Array(view),
            ConstValue::Array { items, view: None } => Variable::Array(
                arena.alloc_slice_fill_iter(items.iter().map(|item| item.to_variable(arena))),
            ),
        }
    }

    pub fn scalar(&self) -> Option<Variable<'_>> {
        match self {
            ConstValue::Integer(n) => Some(Variable::Integer(*n)),
            ConstValue::Float(n) => Some(Variable::Float(*n)),
            ConstValue::Static(c) => Some(Variable::Constant(*c)),
            ConstValue::String(s) => Some(Variable::String(s)),
            ConstValue::Array { .. } => None,
        }
    }

    fn array(items: Box<[ConstValue]>) -> Self {
        let view = items
            .iter()
            .map(|item| match item {
                ConstValue::Integer(n) => Some(Variable::Integer(*n)),
                ConstValue::Float(n) => Some(Variable::Float(*n)),
                ConstValue::Static(c) => Some(Variable::Constant(*c)),
                ConstValue::String(_) | ConstValue::Array { .. } => None,
            })
            .collect::<Option<Box<[_]>>>();
        ConstValue::Array { items, view }
    }

    fn is_flat_array(&self) -> bool {
        matches!(self, ConstValue::Array { items, .. } if items.iter().all(|item| item.scalar().is_some()))
    }

    fn string_items(&self) -> Option<Box<[Box<str>]>> {
        match self {
            ConstValue::Array { items, .. } => items
                .iter()
                .map(|item| match item {
                    ConstValue::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }
}

impl Needle {
    pub fn new(text: &str) -> Self {
        Needle {
            needle: ConstNeedle::new(text),
        }
    }

    pub fn as_str(&self) -> &str {
        self.needle.as_str()
    }

    pub fn is_in(&self, haystack: &str) -> bool {
        self.needle.contains(haystack)
    }

    pub fn is_prefix_of(&self, haystack: &str) -> bool {
        self.needle.starts_with(haystack)
    }

    pub fn is_suffix_of(&self, haystack: &str) -> bool {
        self.needle.ends_with(haystack)
    }

    pub fn matches<'a>(&self, op: TextOp, haystack: Variable<'a>, arena: &'a Bump) -> bool {
        match op {
            TextOp::Contains => match haystack {
                Variable::String(s) => self.is_in(s),
                Variable::Array(items) => {
                    let needle = Variable::String(self.as_str());
                    items.contains(&needle)
                }
                value => self.is_in(value.to_str(arena)),
            },
            TextOp::StartsWith => self.is_prefix_of(haystack.to_str(arena)),
            TextOp::EndsWith => self.is_suffix_of(haystack.to_str(arena)),
        }
    }
}

impl Clone for Needle {
    fn clone(&self) -> Self {
        Needle::new(self.as_str())
    }
}

impl fmt::Debug for Needle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Needle").field(&self.as_str()).finish()
    }
}

impl CaseNeedle {
    pub fn new(text: &str) -> Self {
        CaseNeedle {
            text: text.into(),
            needle: IgnoreCaseNeedle::new(text),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn matches<'a>(&self, haystack: Variable<'a>, arena: &'a Bump) -> bool {
        text::contains_ignore_case(haystack, &self.text, arena, |s| self.needle.contains(s))
    }
}

impl Clone for CaseNeedle {
    fn clone(&self) -> Self {
        CaseNeedle::new(self.as_str())
    }
}

impl fmt::Debug for CaseNeedle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CaseNeedle").field(&self.as_str()).finish()
    }
}

impl StringSet {
    pub fn new(items: Box<[Box<str>]>) -> Self {
        StringSet {
            hashed: (items.len() > ConstSet::LINEAR_MAX_ITEMS).then(|| ConstSet::new(&items)),
            items,
        }
    }

    pub fn items(&self) -> &[Box<str>] {
        &self.items
    }

    pub fn contains(&self, value: Variable<'_>) -> bool {
        match (value, &self.hashed) {
            (Variable::String(s), None) => self.items.iter().any(|item| **item == *s),
            (Variable::String(s), Some(set)) => set.contains(s),
            (value, _) => self
                .items
                .iter()
                .any(|item| Variable::String(item) == value),
        }
    }
}

impl Clone for StringSet {
    fn clone(&self) -> Self {
        StringSet::new(self.items.clone())
    }
}

impl fmt::Debug for StringSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StringSet").field(&self.items).finish()
    }
}

impl Program {
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    pub fn uses_captures(&self) -> bool {
        self.uses_captures
    }

    pub fn string(&self, index: u32) -> &str {
        self.strings.get(index as usize).map_or("", |s| s)
    }

    pub fn needle(&self, index: u32) -> Option<&Needle> {
        self.needles.get(index as usize)
    }

    pub fn case_needle(&self, index: u32) -> Option<&CaseNeedle> {
        self.case_needles.get(index as usize)
    }

    pub fn set(&self, index: u32) -> Option<&StringSet> {
        self.sets.get(index as usize)
    }

    pub fn constant(&self, index: u32) -> Option<&ConstValue> {
        self.consts.get(index as usize)
    }

    pub fn regex(&self, index: u32) -> Option<&CaptureRegex> {
        self.regexes.get(index as usize)
    }

    pub fn function(id: u16) -> Option<SyncFn> {
        FUNCTIONS.get(id as usize).copied()
    }

    pub fn weight(&self) -> u64 {
        let text = |text: &str| text.len() + size_of::<Box<str>>();
        let bytes = self.ops.len() * size_of::<Op>()
            + self.strings.iter().map(|s| text(s)).sum::<usize>()
            + self
                .needles
                .iter()
                .map(|needle| size_of::<Needle>() + text(needle.as_str()))
                .sum::<usize>()
            + self
                .case_needles
                .iter()
                .map(|needle| size_of::<CaseNeedle>() + text(needle.as_str()))
                .sum::<usize>()
            + self
                .sets
                .iter()
                .map(|set| {
                    size_of::<StringSet>()
                        + set.items().iter().map(|item| text(item)).sum::<usize>()
                })
                .sum::<usize>()
            + self.consts.len() * size_of::<ConstValue>()
            + self.regexes.len() * size_of::<CaptureRegex>();
        bytes as u64
    }
}

impl ProgramBuilder {
    pub fn with_capacity(ops: usize, items: usize) -> Self {
        ProgramBuilder {
            ops: Vec::with_capacity(ops),
            pools: Pools::default(),
            scratch: Scratch {
                origin: Vec::with_capacity(items),
                jumps: Vec::with_capacity(ops.max(items) + 1),
            },
        }
    }

    pub fn push_expression(&mut self, items: &[ExpressionItem]) {
        let base = self.ops.len();
        let Scratch { origin, jumps } = &mut self.scratch;
        origin.clear();
        mark_jump_targets(items, jumps);

        let mut lowering = Lowering {
            pools: &mut self.pools,
            ops: &mut self.ops,
            base,
            origin,
            jumps,
            items,
        };
        for (index, item) in items.iter().enumerate() {
            let op = lowering.lower(item, index);
            lowering.push(op, index);
        }
        lowering.intern_strings();

        let end = self.ops.len() as u32;
        jumps.clear();
        jumps.resize(items.len() + 1, end);
        for (new, old) in origin.iter().enumerate() {
            if let Some(slot) = jumps.get_mut(*old) {
                *slot = (base + new) as u32;
            }
        }
        if let Some(slot) = jumps.last_mut() {
            *slot = end;
        }

        for op in self.ops.iter_mut().skip(base) {
            if let Op::JmpIf { target, .. } = op {
                *target = jumps.get(*target as usize).copied().unwrap_or(end);
            }
        }
    }

    pub fn push_test(&mut self) -> usize {
        self.ops.push(Op::Test { target: u32::MAX });
        self.ops.len() - 1
    }

    pub fn patch_test(&mut self, test: usize) {
        let target = self.ops.len() as u32;
        if let Some(Op::Test { target: slot }) = self.ops.get_mut(test) {
            *slot = target;
        }
    }

    pub fn push_return(&mut self) {
        self.ops.push(Op::Return);
    }

    pub fn build(mut self) -> Program {
        let pools = self.pools;
        Program {
            max_depth: max_depth(&self.ops, &mut self.scratch.jumps),
            uses_captures: self.ops.iter().any(|op| matches!(op, Op::Capture(_))),
            ops: self.ops.into_boxed_slice(),
            strings: pools.strings.into_boxed_slice(),
            needles: pools.needles.into_boxed_slice(),
            case_needles: pools.case_needles.into_boxed_slice(),
            sets: pools.sets.into_boxed_slice(),
            consts: pools.consts.into_boxed_slice(),
            regexes: pools.regexes.into_boxed_slice(),
        }
    }
}

impl Pools {
    fn add_string(&mut self, value: &str) -> u32 {
        if self.strings.len() < LINEAR_STRINGS {
            self.find_or_push_string(value)
        } else {
            self.find_or_push_hashed(value)
        }
    }

    #[cold]
    fn find_or_push_hashed(&mut self, value: &str) -> u32 {
        let strings = &self.strings;
        let string_ids = self.string_ids.get_or_insert_with(|| {
            let mut string_ids = AHashMap::with_capacity(strings.len() * 2);
            for (index, text) in strings.iter().enumerate() {
                let hash = string_ids.hasher().hash_one(&**text);
                string_ids.entry(hash).or_insert(index as u32);
            }
            string_ids
        });
        let hash = string_ids.hasher().hash_one(value);
        match string_ids.get(&hash).copied() {
            Some(index) if strings.get(index as usize).is_some_and(|s| **s == *value) => index,
            Some(_) => self.find_or_push_string(value),
            None => {
                string_ids.insert(hash, strings.len() as u32);
                self.push_string(value)
            }
        }
    }

    fn find_or_push_string(&mut self, value: &str) -> u32 {
        match self.strings.iter().position(|s| **s == *value) {
            Some(position) => position as u32,
            None => self.push_string(value),
        }
    }

    fn push_string(&mut self, value: &str) -> u32 {
        self.strings.push(value.into());
        (self.strings.len() - 1) as u32
    }

    fn add_needle(&mut self, text: &str) -> u32 {
        self.needles.push(Needle::new(text));
        (self.needles.len() - 1) as u32
    }

    fn add_case_needle(&mut self, text: &str) -> u32 {
        self.case_needles.push(CaseNeedle::new(text));
        (self.case_needles.len() - 1) as u32
    }

    fn add_set(&mut self, items: Box<[Box<str>]>) -> u32 {
        self.sets.push(StringSet::new(items));
        (self.sets.len() - 1) as u32
    }

    fn add_const(&mut self, value: ConstValue) -> u32 {
        self.consts.push(value);
        (self.consts.len() - 1) as u32
    }

    fn take_string_items(&mut self, array: u32) -> Option<Box<[Box<str>]>> {
        if array as usize + 1 == self.consts.len()
            && let Some(ConstValue::Array { items, .. }) = self.consts.last()
            && items
                .iter()
                .all(|item| matches!(item, ConstValue::String(_)))
            && let Some(ConstValue::Array { items, .. }) = self.consts.pop()
        {
            Some(
                items
                    .into_iter()
                    .filter_map(|item| match item {
                        ConstValue::String(s) => Some(s),
                        _ => None,
                    })
                    .collect(),
            )
        } else {
            self.consts.get(array as usize)?.string_items()
        }
    }
}

impl<'b> Lowering<'b> {
    fn lower(&mut self, item: &ExpressionItem, index: usize) -> Op {
        match item {
            ExpressionItem::Variable(v) => Op::Var(*v),
            ExpressionItem::Global(name) => Op::Global(self.pools.add_string(name)),
            ExpressionItem::System(system) => Op::System(*system),
            ExpressionItem::Capture(n) => Op::Capture(*n),
            ExpressionItem::Constant(Constant::Integer(n)) => Op::Int(*n),
            ExpressionItem::Constant(Constant::Float(n)) => Op::Float(*n),
            ExpressionItem::Constant(Constant::Static(c)) => Op::Static(*c),
            ExpressionItem::Constant(Constant::String(_)) => Op::Str(u32::MAX),
            ExpressionItem::BinaryOperator(op) => Op::Binary(*op),
            ExpressionItem::UnaryOperator(op) => Op::Unary(*op),
            ExpressionItem::Regex(regex) => {
                self.pools.regexes.push(regex.clone());
                Op::Regex((self.pools.regexes.len() - 1) as u32)
            }
            ExpressionItem::JmpIf { val, pos } => Op::JmpIf {
                val: *val,
                target: jump_target(index, *pos),
            },
            ExpressionItem::Function { id, num_args } => {
                let sync_len = FUNCTIONS.len() as u32;
                let argc = (*num_args).min(u16::MAX as u32) as u16;
                if *id < sync_len {
                    Op::Call {
                        id: *id as u16,
                        argc,
                    }
                } else {
                    Op::CallAsync {
                        id: (*id - sync_len).min(u16::MAX as u32) as u16,
                        argc,
                    }
                }
            }
            ExpressionItem::ArrayAccess => Op::Index,
            ExpressionItem::ArrayBuild(n) => Op::Build(*n),
        }
    }

    fn push(&mut self, op: Op, index: usize) {
        match self.fuse(op, index) {
            Some((op, origin)) => {
                self.ops.push(op);
                self.origin.push(origin);
            }
            None => {
                self.ops.push(op);
                self.origin.push(index);
            }
        }
    }

    fn intern_strings(&mut self) {
        let Lowering {
            pools,
            ops,
            base,
            origin,
            items,
            ..
        } = self;
        for (op, origin) in ops.iter_mut().skip(*base).zip(origin.iter()) {
            if let Op::Str(index) = op
                && let Some(ExpressionItem::Constant(Constant::String(text))) = items.get(*origin)
            {
                *index = pools.add_string(text);
            }
        }
    }

    fn text(&self, origin: usize) -> Option<&'b str> {
        match self.items.get(origin)? {
            ExpressionItem::Constant(Constant::String(text)) => Some(text.as_str()),
            _ => None,
        }
    }

    fn const_of(&self, op: &Op, origin: usize) -> Option<ConstValue> {
        match op {
            Op::Int(n) => Some(ConstValue::Integer(*n)),
            Op::Float(n) => Some(ConstValue::Float(*n)),
            Op::Static(c) => Some(ConstValue::Static(*c)),
            Op::Str(_) => self
                .text(origin)
                .map(|text| ConstValue::String(text.into())),
            Op::Array(index) => self.pools.consts.get(*index as usize).cloned(),
            _ => None,
        }
    }

    fn fuse(&mut self, op: Op, index: usize) -> Option<(Op, usize)> {
        match op {
            Op::Build(n) => self.fold_array(n as usize, index),
            Op::Binary(
                cmp @ (BinaryOperator::Eq
                | BinaryOperator::Ne
                | BinaryOperator::Lt
                | BinaryOperator::Le
                | BinaryOperator::Gt
                | BinaryOperator::Ge),
            ) => self.fuse_compare(cmp, index),
            Op::Call { id, argc: 2 } => self.fuse_call(id, index),
            Op::Index => self.fuse_index(index),
            _ => None,
        }
    }

    fn is_clear(&self, from: usize, to: usize) -> bool {
        self.jumps
            .get(from + 1..=to)
            .is_some_and(|window| !window.contains(&JUMP_TARGET))
    }

    fn tail(&self, back: usize) -> Option<(Op, usize)> {
        let position = self.origin.len().checked_sub(back)?;
        Some((
            *self.ops.get(self.base + position)?,
            *self.origin.get(position)?,
        ))
    }

    fn pop(&mut self, count: usize) {
        let len = self.origin.len().saturating_sub(count);
        self.ops.truncate(self.base + len);
        self.origin.truncate(len);
    }

    fn fuse_source(&mut self, consumed: usize, index: usize, start: usize) -> (Src, usize) {
        match self.tail(consumed + 1) {
            Some((Op::Var(v), origin)) if self.is_clear(origin, index) => {
                self.pop(consumed + 1);
                (Src::Var(v), origin)
            }
            _ => {
                self.pop(consumed);
                (Src::Pop, start)
            }
        }
    }

    fn fold_array(&mut self, count: usize, index: usize) -> Option<(Op, usize)> {
        let start = if count == 0 {
            index
        } else {
            let (_, origin) = self.tail(count)?;
            origin
        };
        if !self.is_clear(start, index) {
            return None;
        }
        let first = self.origin.len().checked_sub(count)?;
        let items = self
            .ops
            .get(self.base + first..)?
            .iter()
            .zip(self.origin.get(first..)?)
            .map(|(op, origin)| self.const_of(op, *origin))
            .collect::<Option<Box<[_]>>>()?;
        self.pop(count);
        let konst = self.pools.add_const(ConstValue::array(items));
        Some((Op::Array(konst), start))
    }

    fn fuse_compare(&mut self, op: BinaryOperator, index: usize) -> Option<(Op, usize)> {
        let (konst_op, start) = self.tail(1)?;
        let konst = match konst_op {
            Op::Int(_) | Op::Float(_) | Op::Static(_) | Op::Str(_) => {
                self.const_of(&konst_op, start)?
            }
            _ => return None,
        };
        if !self.is_clear(start, index) {
            return None;
        }
        let konst = self.pools.add_const(konst);
        let (src, origin) = self.fuse_source(1, index, start);
        Some((Op::CmpConst { src, op, konst }, origin))
    }

    fn fuse_call(&mut self, id: u16, index: usize) -> Option<(Op, usize)> {
        match SyncFunction::from_id(id)? {
            SyncFunction::Contains => self
                .fuse_text(TextOp::Contains, index)
                .or_else(|| self.fuse_membership(index)),
            SyncFunction::StartsWith => self.fuse_text(TextOp::StartsWith, index),
            SyncFunction::EndsWith => self.fuse_text(TextOp::EndsWith, index),
            SyncFunction::ContainsIgnoreCase => {
                let (text, src, origin) = self.needle_operand(index)?;
                let needle = self.pools.add_case_needle(text);
                Some((Op::ContainsIgnoreCase { src, needle }, origin))
            }
            _ => None,
        }
    }

    fn needle_operand(&mut self, index: usize) -> Option<(&'b str, Src, usize)> {
        let (Op::Str(_), start) = self.tail(1)? else {
            return None;
        };
        let text = self.text(start)?;
        if !self.is_clear(start, index) {
            return None;
        }
        let (src, origin) = self.fuse_source(1, index, start);
        Some((text, src, origin))
    }

    fn fuse_text(&mut self, op: TextOp, index: usize) -> Option<(Op, usize)> {
        let (text, src, origin) = self.needle_operand(index)?;
        let needle = self.pools.add_needle(text);
        Some((Op::Text { src, op, needle }, origin))
    }

    fn fuse_membership(&mut self, index: usize) -> Option<(Op, usize)> {
        let (Some((Op::Array(array), start)), Some((Op::Var(variable), _))) =
            (self.tail(2), self.tail(1))
        else {
            return None;
        };
        if !self.is_clear(start, index) {
            return None;
        }
        let src = Src::Var(variable);
        let op = match self.pools.take_string_items(array) {
            Some(items) => Op::InSet {
                src,
                set: self.pools.add_set(items),
            },
            None if self
                .pools
                .consts
                .get(array as usize)
                .is_some_and(ConstValue::is_flat_array) =>
            {
                Op::InArray { src, array }
            }
            None => return None,
        };
        self.pop(2);
        Some((op, start))
    }

    fn fuse_index(&mut self, index: usize) -> Option<(Op, usize)> {
        let (Op::Int(position), start) = self.tail(1)? else {
            return None;
        };
        let position = u32::try_from(position).ok()?;
        if !self.is_clear(start, index) {
            return None;
        }
        let (src, origin) = self.fuse_source(1, index, start);
        Some((
            Op::IndexConst {
                src,
                index: position,
            },
            origin,
        ))
    }
}

fn jump_target(index: usize, pos: u32) -> u32 {
    (index + pos as usize + 1) as u32
}

fn mark_jump_targets(items: &[ExpressionItem], jumps: &mut Vec<u32>) {
    jumps.clear();
    jumps.resize(items.len() + 1, 0);
    for (index, item) in items.iter().enumerate() {
        if let ExpressionItem::JmpIf { pos, .. } = item {
            let target = (jump_target(index, *pos) as usize).min(items.len());
            if let Some(slot) = jumps.get_mut(target) {
                *slot = JUMP_TARGET;
            }
        }
    }
}

fn stack_effect(op: &Op) -> (usize, usize) {
    match op {
        Op::Var(_)
        | Op::Global(_)
        | Op::System(_)
        | Op::Capture(_)
        | Op::Int(_)
        | Op::Float(_)
        | Op::Static(_)
        | Op::Str(_)
        | Op::Array(_) => (0, 1),
        Op::Unary(_) | Op::Regex(_) => (1, 1),
        Op::Binary(_) | Op::Index => (2, 1),
        Op::JmpIf { .. } => (0, 0),
        Op::Call { argc, .. } | Op::CallAsync { argc, .. } => (*argc as usize, 1),
        Op::Build(n) => (*n as usize, 1),
        Op::IndexConst { src, .. }
        | Op::CmpConst { src, .. }
        | Op::Text { src, .. }
        | Op::ContainsIgnoreCase { src, .. }
        | Op::InArray { src, .. }
        | Op::InSet { src, .. } => match src {
            Src::Pop => (1, 1),
            Src::Var(_) => (0, 1),
        },
        Op::Test { .. } | Op::Return => (1, 0),
    }
}

fn max_depth(ops: &[Op], incoming: &mut Vec<u32>) -> usize {
    const UNREACHED: u32 = u32::MAX;
    incoming.clear();
    incoming.resize(ops.len() + 1, UNREACHED);
    if let Some(first) = incoming.first_mut() {
        *first = 0;
    }
    let mut max = 0;
    for (index, op) in ops.iter().enumerate() {
        let Some(depth) = incoming
            .get(index)
            .filter(|depth| **depth != UNREACHED)
            .map(|depth| *depth as usize)
        else {
            continue;
        };
        let (pops, pushes) = stack_effect(op);
        let after = depth.saturating_sub(pops) + pushes;
        max = max.max(depth).max(after);
        let mut merge = |target: usize, depth: usize| {
            if let Some(slot) = incoming.get_mut(target) {
                let depth = depth as u32;
                *slot = if *slot == UNREACHED {
                    depth
                } else {
                    (*slot).max(depth)
                };
            }
        };
        match op {
            Op::JmpIf { target, .. } => {
                merge(*target as usize, depth);
                merge(index + 1, after);
            }
            Op::Test { target } => {
                merge(*target as usize, 0);
                merge(index + 1, 0);
            }
            Op::Return => {}
            _ => merge(index + 1, after),
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::if_block::IfBlock;

    fn compile(default: &str) -> IfBlock {
        IfBlock::compile_test(&[], default)
    }

    #[test]
    fn string_sets_hash_above_linear_cutover() {
        for len in [
            1,
            ConstSet::LINEAR_MAX_ITEMS - 1,
            ConstSet::LINEAR_MAX_ITEMS,
            ConstSet::LINEAR_MAX_ITEMS + 1,
            64,
        ] {
            let items = (0..len)
                .map(|index| format!("item{index}").into_boxed_str())
                .collect::<Box<[_]>>();
            let set = StringSet::new(items.clone());
            assert_eq!(
                set.hashed.is_some(),
                len > ConstSet::LINEAR_MAX_ITEMS,
                "{len} items"
            );
            for probe in items
                .iter()
                .map(|item| item.as_ref())
                .chain(["item", "", "itemx"])
            {
                assert_eq!(
                    set.contains(Variable::String(probe)),
                    items.iter().any(|item| item.as_ref() == probe),
                    "{len} items, probe {probe:?}"
                );
            }
        }
    }

    #[test]
    fn peephole_shapes() {
        let block = compile("name_lower == 'x-mailer'");
        assert!(matches!(
            block.program.ops(),
            [
                Op::CmpConst {
                    src: Src::Var(ExpressionVariable::NameLower),
                    op: BinaryOperator::Eq,
                    ..
                },
                Op::Return
            ]
        ));

        let block = compile("contains(['to', 'cc', 'bcc'], name_lower)");
        assert!(matches!(
            block.program.ops(),
            [
                Op::InSet {
                    src: Src::Var(ExpressionVariable::NameLower),
                    set: 0,
                },
                Op::Return
            ]
        ));
        assert_eq!(
            block.program.set(0).map(StringSet::items),
            Some(["to".into(), "cc".into(), "bcc".into()].as_slice())
        );

        let block = compile("contains(['to', 3, 1d], name_lower)");
        assert!(matches!(
            block.program.ops(),
            [
                Op::InArray {
                    src: Src::Var(ExpressionVariable::NameLower),
                    ..
                },
                Op::Return
            ]
        ));

        let block = compile("contains_ignore_case(subject, 'Viagra')");
        assert!(matches!(
            block.program.ops(),
            [
                Op::ContainsIgnoreCase {
                    src: Src::Var(ExpressionVariable::Subject),
                    needle: 0,
                },
                Op::Return
            ]
        ));
        assert_eq!(
            block.program.case_needle(0).map(CaseNeedle::as_str),
            Some("Viagra")
        );

        let block = compile("contains_ignore_case(trim(subject), name_lower)");
        assert!(matches!(
            block.program.ops(),
            [
                Op::Var(ExpressionVariable::Subject),
                Op::Call { .. },
                Op::Var(ExpressionVariable::NameLower),
                Op::Call { argc: 2, .. },
                Op::Return
            ]
        ));

        let block = compile("contains(value_lower, 'phpmailer')");
        assert!(matches!(
            block.program.ops(),
            [
                Op::Text {
                    src: Src::Var(ExpressionVariable::ValueLower),
                    op: TextOp::Contains,
                    ..
                },
                Op::Return
            ]
        ));

        let block = compile("ends_with(trim(subject), '!')");
        assert!(matches!(
            block.program.ops(),
            [
                Op::Var(ExpressionVariable::Subject),
                Op::Call { .. },
                Op::Text {
                    src: Src::Pop,
                    op: TextOp::EndsWith,
                    ..
                },
                Op::Return
            ]
        ));

        let block = compile("octets[3] >= 4 && octets[3] <= 7");
        assert!(matches!(
            block.program.ops(),
            [
                Op::IndexConst {
                    src: Src::Var(ExpressionVariable::Octets),
                    index: 3
                },
                Op::CmpConst {
                    src: Src::Pop,
                    op: BinaryOperator::Ge,
                    ..
                },
                Op::JmpIf {
                    val: false,
                    target: 6
                },
                Op::IndexConst { index: 3, .. },
                Op::CmpConst {
                    op: BinaryOperator::Le,
                    ..
                },
                Op::Binary(BinaryOperator::And),
                Op::Return
            ]
        ));

        let block = compile("[1, 1d]");
        assert!(matches!(block.program.ops(), [Op::Array(_), Op::Return]));
        assert!(matches!(
            block.program.constant(0),
            Some(ConstValue::Array { view: Some(_), .. })
        ));
    }

    #[test]
    fn string_sets_match_generic_membership() {
        let nested = [Variable::String("item1")];
        let probes = [
            Variable::String("item1"),
            Variable::String("item11"),
            Variable::String("item"),
            Variable::String("3"),
            Variable::String(""),
            Variable::Integer(3),
            Variable::Float(3.0),
            Variable::Integer(4),
            Variable::Array(&nested),
            Variable::Constant(ExpressionConstant::Relaxed),
        ];
        let names = (0..12)
            .map(|index| format!("item{index}"))
            .collect::<Vec<_>>();
        for len in [2, 8, 12] {
            let items = names
                .iter()
                .take(len)
                .map(String::as_str)
                .chain(["3"])
                .collect::<Vec<_>>();
            let set = StringSet::new(items.iter().map(|item| Box::<str>::from(*item)).collect());
            assert_eq!(
                set.hashed.is_some(),
                items.len() > ConstSet::LINEAR_MAX_ITEMS
            );
            let generic = items
                .iter()
                .map(|item| Variable::String(item))
                .collect::<Vec<_>>();
            for probe in probes {
                assert_eq!(
                    set.contains(probe),
                    generic.contains(&probe),
                    "{len} items, probe {probe:?}"
                );
            }
        }
    }

    #[test]
    fn large_non_foldable_array_interns_strings_in_order() {
        let distinct = 10_000;
        let items = (0..distinct * 2)
            .map(|index| format!("'dom{}.example'", index % distinct))
            .collect::<Vec<_>>()
            .join(", ");
        let block = compile(&format!("contains([rcpt, {items}, 'dom0.example'], 'x')"));
        let program = &block.program;
        let loaded = program
            .ops()
            .iter()
            .filter_map(|op| match op {
                Op::Str(index) => Some(program.string(*index)),
                _ => None,
            })
            .filter(|text| text.starts_with("dom"))
            .collect::<Vec<_>>();
        assert_eq!(loaded.len(), distinct * 2 + 1);
        for (index, text) in loaded.iter().enumerate() {
            assert_eq!(*text, format!("dom{}.example", index % distinct));
        }
        let pooled = program
            .strings
            .iter()
            .filter(|text| text.starts_with("dom"))
            .collect::<Vec<_>>();
        assert_eq!(pooled.len(), distinct);
        for (index, text) in pooled.iter().enumerate() {
            assert_eq!(&***text, format!("dom{index}.example"));
        }
    }

    #[test]
    fn block_flags() {
        let has_async = |block: &IfBlock| {
            block
                .program
                .ops()
                .iter()
                .any(|op| matches!(op, Op::CallAsync { .. }))
        };
        let block = compile("key_exists('spam-block', sender_domain)");
        assert!(has_async(&block));
        assert!(!block.program.uses_captures());

        let block = IfBlock::compile_test(
            &[("matches('^([^.]+)@(.+)$', rcpt)", "$1 + '+' + $2")],
            "false",
        );
        assert!(!has_async(&block));
        assert!(block.program.uses_captures());
        assert!(matches!(
            block.program.ops().iter().find(|op| matches!(op, Op::Test { .. })),
            Some(Op::Test { target }) if *target as usize == block.program.ops().len() - 2
        ));
        assert!(block.program.weight() > 0);
        assert!(compile("").program.is_empty());
    }
}
