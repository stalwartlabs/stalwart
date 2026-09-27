/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    lexer::{Lexer, Token},
    object::Object,
};
use std::cell::OnceCell;

const MAX_MEMBERS: usize = 1_000_000;
const MIN_MEMBER_BYTES: usize = 3;

#[derive(Debug, Clone, Copy)]
struct Member {
    num: u32,
    offset: u32,
}

pub(crate) struct ObjStm {
    data: Vec<u8>,
    first: usize,
    members: Vec<Member>,
    by_number: OnceCell<Vec<(u32, u32)>>,
    sequential: OnceCell<Vec<u32>>,
}

impl ObjStm {
    pub(crate) fn new(data: Vec<u8>, count: Option<i64>, first: Option<i64>) -> Self {
        let limit = count
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(MAX_MEMBERS)
            .min(MAX_MEMBERS)
            .min(data.len() / MIN_MEMBER_BYTES);
        let declared_first = first
            .and_then(|first| usize::try_from(first).ok())
            .filter(|&first| first <= data.len());
        let header = data
            .get(..declared_first.unwrap_or(data.len()))
            .unwrap_or_default();
        let mut lexer = Lexer::new(header);
        let mut members = Vec::new();
        let mut end = 0;
        while members.len() < limit {
            let mut probe = lexer;
            let (Some(Token::Int(num)), Some(Token::Int(offset))) = (probe.next(), probe.next())
            else {
                break;
            };
            lexer = probe;
            end = lexer.pos();
            if let (Ok(num), Ok(offset)) = (u32::try_from(num), u32::try_from(offset)) {
                members.push(Member { num, offset });
            }
        }
        ObjStm {
            first: declared_first.unwrap_or(end),
            data,
            members,
            by_number: OnceCell::new(),
            sequential: OnceCell::new(),
        }
    }

    pub(crate) fn members(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.members
            .iter()
            .zip(0u32..)
            .map(|(member, index)| (member.num, index))
    }

    pub(crate) fn object(&self, index: u32, num: u32) -> Option<(Object<'_>, usize)> {
        let index = match self.members.get(index as usize) {
            Some(member) if member.num == num => index,
            _ => self.index_of(num)?,
        };
        let member = self.members.get(index as usize)?;
        let start = self.first.checked_add(member.offset as usize)?;
        if let Some(found) = self.read_at(start) {
            return Some(found);
        }
        let sequential = self.sequential.get_or_init(|| self.sequential_starts());
        self.read_at(*sequential.get(index as usize)? as usize)
    }

    fn read_at(&self, start: usize) -> Option<(Object<'_>, usize)> {
        if start >= self.data.len() {
            return None;
        }
        let mut lexer = Lexer::at(&self.data, start);
        let object = Object::read(&mut lexer, None)?;
        Some((object, lexer.pos() - start))
    }

    fn index_of(&self, num: u32) -> Option<u32> {
        let sorted = self.by_number.get_or_init(|| {
            let mut sorted: Vec<(u32, u32)> = self.members().collect();
            sorted.sort_unstable();
            sorted
        });
        let position = sorted.partition_point(|&(member, _)| member < num);
        sorted
            .get(position)
            .filter(|&&(member, _)| member == num)
            .map(|&(_, index)| index)
    }

    fn sequential_starts(&self) -> Vec<u32> {
        let mut lexer = Lexer::at(&self.data, self.first);
        let mut starts = Vec::with_capacity(self.members.len());
        while starts.len() < self.members.len() {
            lexer.skip_whitespace();
            let Ok(start) = u32::try_from(lexer.pos()) else {
                break;
            };
            if Object::read(&mut lexer, None).is_some() {
                starts.push(start);
            } else if lexer.next().is_none() {
                break;
            }
        }
        starts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_resolve_by_number_and_position() {
        let body = b"10 0 11 11 12 18 << /A 1 >> (text) [1 2]";
        let first = body
            .iter()
            .position(|&byte| byte == b'<')
            .unwrap_or_default();
        let stream = ObjStm::new(body.to_vec(), Some(3), Some(first as i64));
        assert_eq!(stream.members().count(), 3);
        let dict = stream
            .object(0, 10)
            .and_then(|(object, _)| object.as_dict());
        assert!(dict.is_some());
        assert!(
            stream
                .object(5, 11)
                .and_then(|(object, _)| object.as_str())
                .is_some()
        );
        assert!(
            stream
                .object(2, 12)
                .and_then(|(object, _)| object.as_array())
                .is_some()
        );
        assert!(stream.object(0, 99).is_none());
    }

    #[test]
    fn hostile_headers_are_bounded() {
        let stream = ObjStm::new(b"1 0 2 0".to_vec(), Some(i64::MAX), None);
        assert_eq!(stream.members().count(), 2);
        let broken = ObjStm::new(b"1 500 2 900 (a) (b)".to_vec(), Some(2), Some(12));
        assert!(
            broken
                .object(1, 2)
                .and_then(|(object, _)| object.as_str())
                .is_some()
        );
        let empty = ObjStm::new(Vec::new(), Some(1_000_000_000), Some(-5));
        assert_eq!(empty.members().count(), 0);
    }
}
