/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BinaryOperator, Variable};
use bumpalo::{
    Bump,
    collections::{String as BumpString, Vec as BumpVec},
};
use compact_str::CompactString;
use hyper::StatusCode;
use registry::types::EnumImpl;
use std::{
    cmp::Ordering,
    fmt::{self, Display, Write},
};

const CONCAT_NUMBER_RESERVE: usize = 24;

impl<'x> Variable<'x> {
    pub fn op_add(self, other: Variable<'x>, arena: &'x Bump) -> Variable<'x> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_add(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a + b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 + f),
            (Variable::Array(a), Variable::Array(b)) => Variable::Array(concat(arena, a, b)),
            (Variable::Array(a), b) => Variable::Array(concat(arena, a, &[b])),
            (a, Variable::Array(b)) => Variable::Array(concat(arena, &[a], b)),
            (Variable::String(a), b) => {
                if !a.is_empty() {
                    Variable::String(concat_display(arena, self, b))
                } else {
                    b
                }
            }
            (a, Variable::String(b)) => {
                if !b.is_empty() {
                    Variable::String(concat_display(arena, a, other))
                } else {
                    a
                }
            }
            (a, Variable::Constant(_)) => a,
            (Variable::Constant(_), b) => b,
        }
    }

    pub fn op_subtract(self, other: Variable<'x>, arena: &'x Bump) -> Variable<'x> {
        match (self, other) {
            (Variable::Array(a), b) | (b, Variable::Array(a)) => {
                let mut items = BumpVec::with_capacity_in(a.len(), arena);
                items.extend(a.iter().filter(|v| *v != &b).copied());
                Variable::Array(items.into_bump_slice())
            }
            (a, b) => a.op_subtract_number(b),
        }
    }

    fn op_subtract_number(self, other: Variable<'_>) -> Variable<'static> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_sub(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a - b),
            (Variable::Integer(a), Variable::Float(b)) => Variable::Float(a as f64 - b),
            (Variable::Float(a), Variable::Integer(b)) => Variable::Float(a - b as f64),
            (a, b) => a.parse_number().op_subtract_number(b.parse_number()),
        }
    }

    pub fn op_multiply(self, other: Variable<'_>) -> Variable<'static> {
        match (self, other) {
            (Variable::Integer(a), Variable::Integer(b)) => Variable::Integer(a.saturating_mul(b)),
            (Variable::Float(a), Variable::Float(b)) => Variable::Float(a * b),
            (Variable::Integer(i), Variable::Float(f))
            | (Variable::Float(f), Variable::Integer(i)) => Variable::Float(i as f64 * f),
            (a, b) => a.parse_number().op_multiply(b.parse_number()),
        }
    }

    pub fn op_divide(self, other: Variable<'_>) -> Variable<'static> {
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

    pub fn op_binary(
        self,
        op: BinaryOperator,
        other: Variable<'x>,
        arena: &'x Bump,
    ) -> Variable<'x> {
        match op {
            BinaryOperator::Add => self.op_add(other, arena),
            BinaryOperator::Subtract => self.op_subtract(other, arena),
            BinaryOperator::Multiply => self.op_multiply(other),
            BinaryOperator::Divide => self.op_divide(other),
            BinaryOperator::And => Variable::Integer(i64::from(self.to_bool() & other.to_bool())),
            BinaryOperator::Or => Variable::Integer(i64::from(self.to_bool() | other.to_bool())),
            BinaryOperator::Xor => Variable::Integer(i64::from(self.to_bool() ^ other.to_bool())),
            BinaryOperator::Eq
            | BinaryOperator::Ne
            | BinaryOperator::Lt
            | BinaryOperator::Le
            | BinaryOperator::Gt
            | BinaryOperator::Ge => Variable::Integer(i64::from(self.compare(op, &other))),
        }
    }

    pub fn compare(&self, op: BinaryOperator, other: &Variable<'_>) -> bool {
        match op {
            BinaryOperator::Eq => self == other,
            BinaryOperator::Ne => self != other,
            BinaryOperator::Lt => self < other,
            BinaryOperator::Le => self <= other,
            BinaryOperator::Gt => self > other,
            BinaryOperator::Ge => self >= other,
            _ => false,
        }
    }

    pub fn op_not(self) -> Variable<'static> {
        Variable::Integer(i64::from(!self.to_bool()))
    }

    pub fn op_minus(self) -> Variable<'static> {
        match self {
            Variable::Integer(n) => Variable::Integer(n.wrapping_neg()),
            Variable::Float(n) => Variable::Float(-n),
            _ => self.parse_number().op_minus(),
        }
    }

    pub fn parse_number(&self) -> Variable<'static> {
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

    pub fn to_bool(&self) -> bool {
        match self {
            Variable::Float(f) => *f != 0.0,
            Variable::Integer(n) => *n != 0,
            Variable::String(s) => !s.is_empty(),
            Variable::Array(a) => !a.is_empty(),
            Variable::Constant(_) => true,
        }
    }

    pub fn to_str(self, arena: &'x Bump) -> &'x str {
        match self {
            Variable::String(s) => s,
            Variable::Integer(n) => arena.alloc_str(itoa::Buffer::new().format(n)),
            Variable::Float(n) => arena.alloc_str(zmij::Buffer::new().format(n)),
            Variable::Array(items) => join_lines(items, arena),
            Variable::Constant(c) => c.as_str(),
        }
    }

    pub fn to_integer(&self) -> Option<i64> {
        match self {
            Variable::Integer(n) => Some(*n),
            Variable::Float(n) => Some(*n as i64),
            Variable::String(s) if !s.is_empty() => s.parse::<i64>().ok(),
            _ => None,
        }
    }

    pub fn to_usize(&self) -> Option<usize> {
        match self {
            Variable::Integer(n) => Some(*n as usize),
            Variable::Float(n) => Some(*n as usize),
            Variable::String(s) if !s.is_empty() => s.parse::<usize>().ok(),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Variable::String(s) => s.is_empty(),
            _ => false,
        }
    }

    pub fn as_array(&self) -> Option<&'x [Variable<'x>]> {
        match self {
            Variable::Array(l) => Some(l),
            _ => None,
        }
    }

    pub fn into_array(self, arena: &'x Bump) -> &'x [Variable<'x>] {
        match self {
            Variable::Array(l) => l,
            v if !v.is_empty() => arena.alloc_slice_copy(&[v]),
            _ => &[],
        }
    }

    pub fn index(self, index: usize) -> Variable<'x> {
        match self {
            Variable::Array(l) => l.get(index).copied().unwrap_or_default(),
            v if !v.is_empty() && index == 0 => v,
            _ => Variable::default(),
        }
    }
}

fn concat<'x>(arena: &'x Bump, a: &[Variable<'x>], b: &[Variable<'x>]) -> &'x [Variable<'x>] {
    let mut items = BumpVec::with_capacity_in(a.len() + b.len(), arena);
    items.extend_from_slice(a);
    items.extend_from_slice(b);
    items.into_bump_slice()
}

fn concat_display<'x>(arena: &'x Bump, left: Variable<'_>, right: Variable<'_>) -> &'x str {
    let capacity = left.display_hint() + right.display_hint();
    let mut out = BumpString::with_capacity_in(capacity, arena);
    left.write_display(&mut out);
    right.write_display(&mut out);
    out.into_bump_str()
}

fn join_lines<'x>(items: &[Variable<'_>], arena: &'x Bump) -> &'x str {
    let capacity = items
        .iter()
        .map(|item| match item {
            Variable::String(s) => s.len() + 2,
            _ => CONCAT_NUMBER_RESERVE,
        })
        .sum();
    let mut out = BumpString::with_capacity_in(capacity, arena);
    for item in items {
        if !out.is_empty() {
            out.push_str("\r\n");
        }
        match item {
            Variable::String(v) => out.push_str(v),
            Variable::Integer(v) => out.push_str(itoa::Buffer::new().format(*v)),
            Variable::Float(v) => out.push_str(zmij::Buffer::new().format(*v)),
            Variable::Array(_) => {}
            Variable::Constant(c) => out.push_str(c.as_str()),
        }
    }
    out.into_bump_str()
}

impl Variable<'_> {
    fn display_hint(&self) -> usize {
        match self {
            Variable::String(s) => s.len(),
            Variable::Constant(c) => c.as_str().len(),
            Variable::Array(items) => items.iter().map(|item| item.display_hint() + 1).sum(),
            Variable::Integer(_) | Variable::Float(_) => CONCAT_NUMBER_RESERVE,
        }
    }

    fn write_display(&self, out: &mut BumpString<'_>) {
        match self {
            Variable::String(s) => out.push_str(s),
            Variable::Constant(c) => out.push_str(c.as_str()),
            Variable::Integer(n) => out.push_str(itoa::Buffer::new().format(*n)),
            _ => {
                let _ = write!(out, "{self}");
            }
        }
    }
}

impl PartialEq for Variable<'_> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b,
            (Self::Integer(a), Self::Float(b)) | (Self::Float(b), Self::Integer(a)) => {
                *a as f64 == *b
            }
            (Self::String(a), Self::String(b)) => a == b,
            (Self::String(_), Self::Integer(_) | Self::Float(_)) => &self.parse_number() == other,
            (Self::Integer(_) | Self::Float(_), Self::String(_)) => self == &other.parse_number(),
            (Self::Array(a), Self::Array(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Variable<'_> {}

#[allow(clippy::non_canonical_partial_ord_impl)]
impl PartialOrd for Variable<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => a.partial_cmp(b),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b),
            (Self::Integer(a), Self::Float(b)) => (*a as f64).partial_cmp(b),
            (Self::Float(a), Self::Integer(b)) => a.partial_cmp(&(*b as f64)),
            (Self::String(a), Self::String(b)) => a.partial_cmp(b),
            (Self::String(_), Self::Integer(_) | Self::Float(_)) => {
                self.parse_number().partial_cmp(other)
            }
            (Self::Integer(_) | Self::Float(_), Self::String(_)) => {
                self.partial_cmp(&other.parse_number())
            }
            (Self::Array(a), Self::Array(b)) => a.partial_cmp(b),
            (Self::Array(_) | Self::String(_), _) => Ordering::Greater.into(),
            (Self::Constant(a), Self::Constant(b)) => a.to_id().partial_cmp(&b.to_id()),
            (_, Self::Array(_) | Self::Constant(_)) | (Self::Constant(_), _) => {
                Ordering::Less.into()
            }
        }
    }
}

impl Ord for Variable<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or(Ordering::Greater)
    }
}

impl Display for Variable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Variable::String(v) => write!(f, "{}", v),
            Variable::Integer(v) => v.fmt(f),
            Variable::Float(v) => v.fmt(f),
            Variable::Array(v) => {
                for (i, v) in v.iter().enumerate() {
                    if i > 0 {
                        f.write_str("\n")?;
                    }
                    v.fmt(f)?;
                }
                Ok(())
            }
            Variable::Constant(c) => c.as_str().fmt(f),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for CompactString {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::String(s) => Ok(s.into()),
            _ => Err(()),
        }
    }
}

impl<'x> TryFrom<Variable<'x>> for String {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::String(s) => Ok(s.to_string()),
            _ => Err(()),
        }
    }
}

impl<'x> From<Variable<'x>> for bool {
    fn from(val: Variable<'x>) -> Self {
        val.to_bool()
    }
}

impl<'x> TryFrom<Variable<'x>> for i64 {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value.to_integer().ok_or(())
    }
}

impl<'x> TryFrom<Variable<'x>> for u64 {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value.to_integer().map(|v| v as u64).ok_or(())
    }
}

impl<'x> TryFrom<Variable<'x>> for usize {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value.to_usize().ok_or(())
    }
}

impl<'x> TryFrom<Variable<'x>> for StatusCode {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        value
            .to_integer()
            .and_then(|code| StatusCode::from_u16(code as u16).ok())
            .ok_or(())
    }
}
