/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::pdf::object::{Array, Dict, Name, Object, Str};

pub(crate) const MAX_OPERANDS: usize = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Save,
    Restore,
    Concat,
    SetState,
    BeginText,
    EndText,
    CharSpacing,
    WordSpacing,
    HorizontalScale,
    Leading,
    Font,
    Rise,
    MoveText,
    MoveTextLeading,
    TextMatrix,
    NextLine,
    Show,
    ShowArray,
    NextLineShow,
    NextLineShowSpaced,
    XObject,
    BeginImage,
    BeginMarked,
    BeginMarkedProperties,
    EndMarked,
    Ignored,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum Operand<'a> {
    #[default]
    Other,
    Number(f64),
    Name(Name<'a>),
    Str(Str<'a>),
    Array(Array<'a>),
    Dict(Dict<'a>),
}

#[derive(Debug)]
pub(crate) struct Operands<'a> {
    items: [Operand<'a>; MAX_OPERANDS],
    len: usize,
}

impl Op {
    pub(crate) fn parse(keyword: &[u8]) -> Op {
        hashify::map!(keyword, Op,
            b"q" => Op::Save,
            b"Q" => Op::Restore,
            b"cm" => Op::Concat,
            b"gs" => Op::SetState,
            b"BT" => Op::BeginText,
            b"ET" => Op::EndText,
            b"Tc" => Op::CharSpacing,
            b"Tw" => Op::WordSpacing,
            b"Tz" => Op::HorizontalScale,
            b"TL" => Op::Leading,
            b"Tf" => Op::Font,
            b"Ts" => Op::Rise,
            b"Td" => Op::MoveText,
            b"TD" => Op::MoveTextLeading,
            b"Tm" => Op::TextMatrix,
            b"T*" => Op::NextLine,
            b"Tj" => Op::Show,
            b"TJ" => Op::ShowArray,
            b"'" => Op::NextLineShow,
            b"\"" => Op::NextLineShowSpaced,
            b"Do" => Op::XObject,
            b"BI" => Op::BeginImage,
            b"BMC" => Op::BeginMarked,
            b"BDC" => Op::BeginMarkedProperties,
            b"EMC" => Op::EndMarked,
            b"b" => Op::Ignored,
            b"B" => Op::Ignored,
            b"b*" => Op::Ignored,
            b"B*" => Op::Ignored,
            b"BX" => Op::Ignored,
            b"c" => Op::Ignored,
            b"CS" => Op::Ignored,
            b"cs" => Op::Ignored,
            b"d" => Op::Ignored,
            b"d0" => Op::Ignored,
            b"d1" => Op::Ignored,
            b"DP" => Op::Ignored,
            b"EX" => Op::Ignored,
            b"f" => Op::Ignored,
            b"F" => Op::Ignored,
            b"f*" => Op::Ignored,
            b"G" => Op::Ignored,
            b"g" => Op::Ignored,
            b"h" => Op::Ignored,
            b"i" => Op::Ignored,
            b"ID" => Op::Ignored,
            b"EI" => Op::Ignored,
            b"j" => Op::Ignored,
            b"J" => Op::Ignored,
            b"K" => Op::Ignored,
            b"k" => Op::Ignored,
            b"l" => Op::Ignored,
            b"m" => Op::Ignored,
            b"M" => Op::Ignored,
            b"MP" => Op::Ignored,
            b"n" => Op::Ignored,
            b"re" => Op::Ignored,
            b"RG" => Op::Ignored,
            b"rg" => Op::Ignored,
            b"ri" => Op::Ignored,
            b"s" => Op::Ignored,
            b"S" => Op::Ignored,
            b"SC" => Op::Ignored,
            b"sc" => Op::Ignored,
            b"SCN" => Op::Ignored,
            b"scn" => Op::Ignored,
            b"sh" => Op::Ignored,
            b"Tr" => Op::Ignored,
            b"v" => Op::Ignored,
            b"w" => Op::Ignored,
            b"W" => Op::Ignored,
            b"W*" => Op::Ignored,
            b"y" => Op::Ignored,
        )
        .copied()
        .unwrap_or(Op::Unknown)
    }

    pub(crate) fn is_known(keyword: &[u8]) -> bool {
        Op::parse(keyword) != Op::Unknown
    }
}

impl<'a> Operand<'a> {
    pub(crate) fn from_object(object: Object<'a>) -> Self {
        match object {
            Object::Int(value) => Operand::Number(value as f64),
            Object::Real(value) if value.is_finite() => Operand::Number(value),
            Object::Name(name) => Operand::Name(name),
            Object::Str(value) => Operand::Str(value),
            Object::Array(array) => Operand::Array(array),
            Object::Dict(dict) => Operand::Dict(dict),
            _ => Operand::Other,
        }
    }

    pub(crate) fn number(&self) -> Option<f64> {
        match self {
            Operand::Number(value) => Some(*value),
            _ => None,
        }
    }
}

impl Default for Operands<'_> {
    fn default() -> Self {
        Operands {
            items: [Operand::Other; MAX_OPERANDS],
            len: 0,
        }
    }
}

impl<'a> Operands<'a> {
    #[inline]
    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub(crate) fn push(&mut self, operand: Operand<'a>) {
        if self.len == MAX_OPERANDS {
            self.items.copy_within(1.., 0);
            self.len -= 1;
        }
        if let Some(slot) = self.items.get_mut(self.len) {
            *slot = operand;
            self.len += 1;
        }
    }

    pub(crate) fn last<const N: usize>(&self) -> Option<[Operand<'a>; N]> {
        let start = self.len.checked_sub(N)?;
        let slice = self.items.get(start..self.len)?;
        <[Operand<'a>; N]>::try_from(slice).ok()
    }

    pub(crate) fn numbers<const N: usize>(&self) -> Option<[f64; N]> {
        let operands = self.last::<N>()?;
        let mut values = [0f64; N];
        for (slot, operand) in values.iter_mut().zip(operands.iter()) {
            *slot = operand.number()?;
        }
        Some(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operand_stack_keeps_the_newest() {
        let mut operands = Operands::default();
        for index in 0..100 {
            operands.push(Operand::Number(f64::from(index)));
        }
        assert_eq!(operands.len(), MAX_OPERANDS);
        assert_eq!(operands.numbers::<2>(), Some([98.0, 99.0]));
        operands.push(Operand::Other);
        assert_eq!(operands.numbers::<2>(), None);
        assert!(operands.last::<34>().is_none());
        operands.clear();
        assert!(operands.last::<1>().is_none());
    }

    #[test]
    fn operators_are_classified() {
        assert_eq!(Op::parse(b"TJ"), Op::ShowArray);
        assert_eq!(Op::parse(b"'"), Op::NextLineShow);
        assert_eq!(Op::parse(b"re"), Op::Ignored);
        assert_eq!(Op::parse(b"Tjx"), Op::Unknown);
        assert!(Op::is_known(b"EMC"));
        assert!(!Op::is_known(b"\x80"));
    }
}
