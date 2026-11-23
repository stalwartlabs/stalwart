/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::variable::Array;
use super::{
    RuntimeError, Variable,
    context::Pending,
    eval::ValueRef,
    handler::{Handler, Reply},
};
use crate::{
    Context, Sieve,
    bytecode::rec::{Range, tag},
    compiler::grammar::expr::{BinaryOperator, UnaryOperator, parser::ID_EXTERNAL},
};
use std::borrow::Cow;

impl<'x> Context<'x> {
    pub(crate) fn eval_expression<H: Handler<'x>>(
        &mut self,
        script: &'x Sieve<'x>,
        range: Range,
        handler: &mut H,
    ) -> Result<Option<Variable<'x>>, RuntimeError> {
        let mut pos = self.expr_pos;
        let mut iter = script.recs(Range {
            start: range.start + pos as u32,
            len: range.len.saturating_sub(pos as u32),
        })?;

        while let Some(rec) = iter.next() {
            pos += 1;
            match rec.tag {
                tag::VAR_LOCAL => {
                    let value = self.local_variable(rec.c);
                    self.expr_stack.push(value);
                }
                tag::VAR_MATCH => {
                    let value = self.match_variable(rec.b);
                    self.expr_stack.push(value);
                }
                tag::INT => {
                    self.expr_stack.push(Variable::Integer(rec.e as i64));
                }
                tag::FLOAT => {
                    self.expr_stack.push(Variable::Float(f64::from_bits(rec.e)));
                }
                tag::TEXT => {
                    self.expr_stack
                        .push(Variable::borrowed(script.str(rec.str())?));
                }
                tag::UN_OP => {
                    let value = self.expr_stack.pop().unwrap_or_default();
                    self.expr_stack.push(match UnaryOperator::from_code(rec.b) {
                        UnaryOperator::Not => value.op_not(),
                        UnaryOperator::Minus => value.op_minus(),
                    });
                }
                tag::BIN_OP => {
                    let right = self.expr_stack.pop().unwrap_or_default();
                    let left = self.expr_stack.pop().unwrap_or_default();
                    self.expr_stack
                        .push(match BinaryOperator::from_code(rec.b) {
                            BinaryOperator::Add => {
                                left.op_add(right, self.runtime.max_variable_size)
                            }
                            BinaryOperator::Subtract => left.op_subtract(right),
                            BinaryOperator::Multiply => left.op_multiply(right),
                            BinaryOperator::Divide => left.op_divide(right),
                            BinaryOperator::And => left.op_and(right),
                            BinaryOperator::Or => left.op_or(right),
                            BinaryOperator::Xor => left.op_xor(right),
                            BinaryOperator::Eq => left.op_eq(right),
                            BinaryOperator::Ne => left.op_ne(right),
                            BinaryOperator::Lt => left.op_lt(right),
                            BinaryOperator::Le => left.op_le(right),
                            BinaryOperator::Gt => left.op_gt(right),
                            BinaryOperator::Ge => left.op_ge(right),
                        });
                }
                tag::CALL => {
                    let num_args = rec.c as usize;
                    let start = self.expr_stack.len().saturating_sub(num_args);
                    if let Some(fnc) = self.runtime.functions.get(rec.d as usize) {
                        let result = (fnc)(self, &self.expr_stack[start..]);
                        self.expr_stack.truncate(start);
                        let result = self.intern(result);
                        self.expr_stack.push(result);
                    } else {
                        let id = ID_EXTERNAL
                            .checked_sub(rec.d)
                            .ok_or(RuntimeError::InvalidBytecode)?;
                        let reply = handler.function(self, id, &self.expr_stack[start..]);
                        self.expr_stack.truncate(start);
                        match reply {
                            Reply::Ready(result) => {
                                let result = self.intern(result);
                                self.expr_stack.push(result);
                            }
                            Reply::Pending => {
                                self.expr_pos = pos;
                                self.pending = Pending::Function;
                                return Ok(None);
                            }
                            Reply::Error(err) => return Err(err),
                        }
                    }
                }
                tag::JMP_IF => {
                    if self.expr_stack.last().is_some_and(|v| v.to_bool()) == (rec.b != 0) {
                        pos += rec.d as usize;
                        if pos > range.len as usize {
                            return Err(RuntimeError::InvalidBytecode);
                        }
                        iter = script.recs(Range {
                            start: range.start + pos as u32,
                            len: range.len.saturating_sub(pos as u32),
                        })?;
                    }
                }
                tag::ARRAY_ACCESS => {
                    let index = self.expr_stack.pop().unwrap_or_default().to_usize();
                    let value = match self.expr_stack.pop() {
                        Some(Variable::Array(array)) => {
                            array.get(index).cloned().unwrap_or_default()
                        }
                        Some(value) if index == 0 && !value.is_empty() => value,
                        _ => Variable::default(),
                    };
                    self.expr_stack.push(value);
                }
                tag::ARRAY_BUILD => {
                    let start = self.expr_stack.len().saturating_sub(rec.d as usize);
                    let items = self.expr_stack.split_off(start);
                    self.expr_stack.push(Variable::Array(Array::Owned(items)));
                }
                _ => {
                    let value = ValueRef::decode(script, rec, &mut iter)?;
                    if matches!(value, ValueRef::Header(_)) {
                        pos += 1;
                    }
                    let value = self.variable_ref(script, value)?.unwrap_or_default();
                    self.expr_stack.push(value);
                }
            }
        }

        let result = self.expr_stack.pop().unwrap_or_default();
        self.expr_stack.clear();
        self.expr_pos = 0;
        Ok(Some(result))
    }
}

impl<'x> Variable<'x> {
    pub fn op_add(self, other: Variable<'x>, max_len: usize) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_add(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a + b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 + f),
            (Variable::Array(a), Variable::Array(b)) => append_items(a, b.iter().cloned(), max_len),
            (Variable::Array(a), b) => append_items(a, [b].into_iter(), max_len),
            (a, Variable::Array(b)) => {
                concat_items([a].into_iter().chain(b.iter().cloned()), max_len)
            }
            (Variable::String(a), b) => {
                if a.is_empty() {
                    b
                } else if b.is_empty() {
                    Variable::String(a)
                } else {
                    concat_strings(a, &b.to_string(), max_len)
                }
            }
            (a, Variable::String(b)) => {
                if b.is_empty() {
                    a
                } else {
                    concat_strings(a.into_string(), &b, max_len)
                }
            }
        }
    }

    pub fn op_subtract(self, other: Variable<'x>) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_sub(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a - b),
            (Variable::Integer(a), Variable::Float(b)) => Variable::Float(a as f64 - b),
            (Variable::Float(a), Variable::Integer(b)) => Variable::Float(a - b as f64),
            (Variable::Array(a), b) | (b, Variable::Array(a)) => Variable::Array(Array::Owned(
                a.iter().filter(|v| *v != &b).cloned().collect(),
            )),
            (a, b) => a.parse_number().op_subtract(b.parse_number()),
        }
    }

    pub fn op_multiply(self, other: Variable<'x>) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_mul(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a * b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 * f),
            (a, b) => a.parse_number().op_multiply(b.parse_number()),
        }
    }

    pub fn op_divide(self, other: Variable<'x>) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => {
                Variable::Float(if b != 0 { a as f64 / b as f64 } else { 0.0 })
            }
            (Variable::Float(a), Variable::Float(b)) => {
                Variable::Float(if b != 0.0 { a / b } else { 0.0 })
            }
            (Variable::Integer(a), Variable::Float(b)) => {
                Variable::Float(if b != 0.0 { a as f64 / b } else { 0.0 })
            }
            (Variable::Float(a), Variable::Integer(b)) => {
                Variable::Float(if b != 0 { a / b as f64 } else { 0.0 })
            }
            (a, b) => a.parse_number().op_divide(b.parse_number()),
        }
    }

    pub fn op_and(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self.to_bool() & other.to_bool()))
    }

    pub fn op_or(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self.to_bool() | other.to_bool()))
    }

    pub fn op_xor(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self.to_bool() ^ other.to_bool()))
    }

    pub fn op_eq(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self == other))
    }

    pub fn op_ne(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self != other))
    }

    pub fn op_lt(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self < other))
    }

    pub fn op_le(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self <= other))
    }

    pub fn op_gt(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self > other))
    }

    pub fn op_ge(self, other: Variable<'x>) -> Variable<'x> {
        Variable::Integer(i64::from(self >= other))
    }

    pub fn op_not(self) -> Variable<'x> {
        Variable::Integer(i64::from(!self.to_bool()))
    }

    pub fn op_minus(self) -> Variable<'x> {
        match self {
            Variable::Integer(n) => Variable::Integer(n.saturating_neg()),
            Variable::Float(n) => Variable::Float(-n),
            _ => self.parse_number().op_minus(),
        }
    }

    pub fn parse_number(&self) -> Variable<'x> {
        match self {
            Variable::String(s) if !s.is_empty() => {
                if let Ok(n) = s.parse::<i64>() {
                    Variable::Integer(n)
                } else if let Ok(n) = s.parse::<f64>() {
                    Variable::Float(n)
                } else {
                    Variable::Integer(0)
                }
            }
            Variable::Integer(n) => Variable::Integer(*n),
            Variable::Float(n) => Variable::Float(*n),
            Variable::Array(l) => Variable::Integer(l.is_empty() as i64),
            _ => Variable::Integer(0),
        }
    }
}

impl BinaryOperator {
    #[inline(always)]
    pub(crate) fn from_code(code: u8) -> BinaryOperator {
        match code {
            0 => BinaryOperator::Add,
            1 => BinaryOperator::Subtract,
            2 => BinaryOperator::Multiply,
            3 => BinaryOperator::Divide,
            4 => BinaryOperator::And,
            5 => BinaryOperator::Or,
            6 => BinaryOperator::Xor,
            7 => BinaryOperator::Eq,
            8 => BinaryOperator::Ne,
            9 => BinaryOperator::Lt,
            10 => BinaryOperator::Le,
            11 => BinaryOperator::Gt,
            _ => BinaryOperator::Ge,
        }
    }
}

impl UnaryOperator {
    #[inline(always)]
    pub(crate) fn from_code(code: u8) -> UnaryOperator {
        match code {
            0 => UnaryOperator::Not,
            _ => UnaryOperator::Minus,
        }
    }
}
#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/sieve/src/runtime/expression/test.rs"]
mod test;

fn concat_strings<'x>(a: Cow<'x, str>, b: &str, max_len: usize) -> Variable<'x> {
    let mut result = match a {
        Cow::Owned(mut a) => {
            a.truncate(a.floor_char_boundary(max_len));
            a
        }
        Cow::Borrowed(a) => {
            let mut result = String::with_capacity(a.len().saturating_add(b.len()).min(max_len));
            push_capped(&mut result, a, max_len);
            result
        }
    };
    push_capped(&mut result, b, max_len);
    Variable::String(Cow::Owned(result))
}

fn push_capped(result: &mut String, text: &str, max_len: usize) {
    let room = max_len.saturating_sub(result.len());
    if let Some(text) = text.get(..text.floor_char_boundary(room)) {
        result.push_str(text);
    }
}

fn append_items<'x>(
    left: Array<'x>,
    right: impl Iterator<Item = Variable<'x>>,
    max_len: usize,
) -> Variable<'x> {
    let size = left
        .as_slice()
        .iter()
        .fold(0usize, |size, item| item_size(size, item));
    if size > max_len {
        return concat_items(left.as_slice().iter().cloned().chain(right), max_len);
    }
    let mut items = match left {
        Array::Owned(items) => items,
        Array::Borrowed(items) => {
            let mut owned = Vec::with_capacity(items.len().saturating_add(right.size_hint().0));
            owned.extend_from_slice(items);
            owned
        }
    };
    push_items(&mut items, right, size, max_len);
    Variable::Array(Array::Owned(items))
}

fn concat_items<'x>(items: impl Iterator<Item = Variable<'x>>, max_len: usize) -> Variable<'x> {
    let mut result = Vec::with_capacity(items.size_hint().0);
    push_items(&mut result, items, 0, max_len);
    Variable::Array(Array::Owned(result))
}

fn push_items<'x>(
    result: &mut Vec<Variable<'x>>,
    items: impl Iterator<Item = Variable<'x>>,
    mut size: usize,
    max_len: usize,
) {
    for item in items {
        size = item_size(size, &item);
        if size > max_len {
            break;
        }
        result.push(item);
    }
}

fn item_size(size: usize, item: &Variable<'_>) -> usize {
    let len = match item {
        Variable::String(text) => text.len(),
        Variable::Integer(_) | Variable::Float(_) => 2,
        Variable::Array(_) => item.len(),
    };
    size.saturating_add(len).saturating_add(2)
}
