/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod container;
mod string;

pub(crate) use container::{Array, ArrayIter, Dict, skip_container};
pub(crate) use string::{Name, Str};

use super::lexer::{Lexer, Token, is_regular, is_whitespace};

pub(crate) const MAX_OBJECT_NUMBER: u32 = 8_388_607;
const STREAM_KEYWORD: &[u8] = b"stream";
const OBJ_KEYWORD: &[u8] = b"obj";
const REF_KEYWORD: &[u8] = b"R";
const MAX_NUM_DIGITS: usize = 10;
const MAX_GEN_DIGITS: usize = 5;
const MAX_GEN_TOKEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ObjRef {
    pub(crate) num: u32,
    pub(crate) generation: u16,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Stream<'a> {
    pub(crate) dict: Dict<'a>,
    pub(crate) data: &'a [u8],
    pub(crate) id: ObjRef,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum Object<'a> {
    #[default]
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Name(Name<'a>),
    Str(Str<'a>),
    Array(Array<'a>),
    Dict(Dict<'a>),
    Ref(ObjRef),
    Stream(Stream<'a>),
}

pub(crate) struct Indirect<'a> {
    pub(crate) id: ObjRef,
    pub(crate) value: Object<'a>,
    pub(crate) stream_start: Option<usize>,
    pub(crate) end: usize,
}

impl ObjRef {
    pub(crate) fn new(num: i64, generation: i64) -> Option<Self> {
        let num = u32::try_from(num)
            .ok()
            .filter(|num| (1..=MAX_OBJECT_NUMBER).contains(num))?;
        Some(ObjRef {
            num,
            generation: u16::try_from(generation).ok()?,
        })
    }
}

impl<'a> Object<'a> {
    #[inline]
    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Object::Null)
    }

    pub(crate) fn as_int(&self) -> Option<i64> {
        match *self {
            Object::Int(value) => Some(value),
            Object::Real(value) if value.is_finite() => Some(value as i64),
            _ => None,
        }
    }

    pub(crate) fn as_f64(&self) -> Option<f64> {
        match *self {
            Object::Int(value) => Some(value as f64),
            Object::Real(value) if value.is_finite() => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_bool(&self) -> Option<bool> {
        match *self {
            Object::Bool(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_name(&self) -> Option<Name<'a>> {
        match *self {
            Object::Name(name) => Some(name),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<Str<'a>> {
        match *self {
            Object::Str(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<Array<'a>> {
        match *self {
            Object::Array(array) => Some(array),
            _ => None,
        }
    }

    pub(crate) fn as_dict(&self) -> Option<Dict<'a>> {
        match *self {
            Object::Dict(dict) => Some(dict),
            Object::Stream(stream) => Some(stream.dict),
            _ => None,
        }
    }

    pub(crate) fn as_stream(&self) -> Option<Stream<'a>> {
        match *self {
            Object::Stream(stream) => Some(stream),
            _ => None,
        }
    }

    pub(crate) fn as_ref(&self) -> Option<ObjRef> {
        match *self {
            Object::Ref(id) => Some(id),
            _ => None,
        }
    }

    pub(crate) fn is_name(&self, name: &[u8]) -> bool {
        self.as_name().is_some_and(|value| value.is(name))
    }

    pub(crate) fn read(lexer: &mut Lexer<'a>, owner: Option<ObjRef>) -> Option<Self> {
        let saved = *lexer;
        let object = match lexer.next()? {
            Token::Int(value) => return Some(Object::integer_or_ref(value, lexer)),
            Token::Real(value) => Object::Real(value),
            Token::Name(raw) => Object::Name(Name::new(raw)),
            Token::Literal(raw) => Object::Str(Str::literal(raw, owner)),
            Token::Hex(raw) => Object::Str(Str::hex(raw, owner)),
            Token::ArrayOpen => Object::Array(Array::new(container::skip(lexer), owner)),
            Token::DictOpen => Object::Dict(Dict::new(container::skip(lexer), owner)),
            Token::Keyword(b"true") => Object::Bool(true),
            Token::Keyword(b"false") => Object::Bool(false),
            Token::Keyword(b"null") => Object::Null,
            Token::Keyword(_)
            | Token::ArrayClose
            | Token::DictClose
            | Token::BraceOpen
            | Token::BraceClose
            | Token::Error => {
                *lexer = saved;
                return None;
            }
        };
        Some(object)
    }

    fn integer_or_ref(value: i64, lexer: &mut Lexer<'a>) -> Self {
        let mut probe = *lexer;
        probe.skip_whitespace();
        let rest = probe.rest();
        if rest
            .first()
            .is_some_and(|&byte| byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.'))
            && rest
                .iter()
                .take(MAX_GEN_TOKEN + 1)
                .take_while(|&&byte| is_regular(byte))
                .count()
                <= MAX_GEN_TOKEN
            && let Some(Token::Int(generation)) = probe.next()
            && let Some(end) = keyword_after(probe, REF_KEYWORD)
        {
            lexer.set_pos(end);
            return ObjRef::new(value, generation).map_or(Object::Null, Object::Ref);
        }
        Object::Int(value)
    }
}

impl<'a> Indirect<'a> {
    pub(crate) fn header(data: &'a [u8], pos: usize) -> Option<(ObjRef, Lexer<'a>)> {
        let mut lexer = Lexer::at(data, pos);
        lexer.skip_whitespace();
        let (num, after_num) = digits(data, lexer.pos(), MAX_NUM_DIGITS)?;
        let gap = spaces(data, after_num);
        if gap == 0 {
            return None;
        }
        let (generation, after_gen) = match digits(data, after_num + gap, MAX_GEN_DIGITS) {
            Some((generation, end)) => (generation, end + spaces(data, end)),
            None => (0, after_num + gap),
        };
        if !keyword_at(data, after_gen, OBJ_KEYWORD) {
            return None;
        }
        let id = ObjRef::new(num, generation)?;
        Some((id, Lexer::at(data, after_gen + OBJ_KEYWORD.len())))
    }

    pub(crate) fn header_before(data: &[u8], keyword: usize) -> Option<usize> {
        if !keyword_at(data, keyword, OBJ_KEYWORD) {
            return None;
        }
        let digits_end = run_start(data, keyword, is_whitespace);
        let last = run_start(data, digits_end, |byte| byte.is_ascii_digit());
        if last == digits_end {
            return None;
        }
        let gap = run_start(data, last, is_whitespace);
        let first = run_start(data, gap, |byte| byte.is_ascii_digit());
        let full = (gap < last && first < gap).then_some(first);
        full.into_iter().chain([last]).find(|&start| {
            start
                .checked_sub(1)
                .and_then(|before| data.get(before))
                .is_none_or(|&before| !is_regular(before))
                && Indirect::header(data, start)
                    .is_some_and(|(_, lexer)| lexer.pos() == keyword + OBJ_KEYWORD.len())
        })
    }

    pub(crate) fn parse(data: &'a [u8], pos: usize, streams: bool) -> Option<Self> {
        let (id, mut lexer) = Indirect::header(data, pos)?;
        let value = Object::read(&mut lexer, Some(id)).unwrap_or_default();
        lexer.skip_whitespace();
        let mut end = lexer.pos();
        let stream_start = match value {
            Object::Dict(_) if streams => keyword_after(lexer, STREAM_KEYWORD).map(|after| {
                end = after;
                stream_data_start(data, after)
            }),
            _ => None,
        };
        Some(Indirect {
            id,
            value,
            stream_start,
            end,
        })
    }
}

pub(crate) fn keyword_after(mut lexer: Lexer<'_>, keyword: &[u8]) -> Option<usize> {
    lexer.skip_whitespace();
    let pos = lexer.pos();
    keyword_at(lexer.data(), pos, keyword).then_some(pos + keyword.len())
}

pub(crate) fn stream_data_start(data: &[u8], after_keyword: usize) -> usize {
    let mut pos = after_keyword;
    while let Some(b' ' | b'\t') = data.get(pos) {
        pos += 1;
    }
    match (data.get(pos), data.get(pos + 1)) {
        (Some(b'\r'), Some(b'\n')) => pos + 2,
        (Some(b'\r' | b'\n'), _) => pos + 1,
        _ => pos,
    }
    .min(data.len())
}

fn digits(data: &[u8], pos: usize, max: usize) -> Option<(i64, usize)> {
    let run = data
        .get(pos..)?
        .iter()
        .take(max + 1)
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if run == 0 || run > max {
        return None;
    }
    let value = data
        .get(pos..pos + run)?
        .iter()
        .fold(0i64, |value, &digit| value * 10 + i64::from(digit - b'0'));
    Some((value, pos + run))
}

fn run_start(data: &[u8], end: usize, class: impl Fn(u8) -> bool) -> usize {
    let run = data
        .get(..end)
        .unwrap_or_default()
        .iter()
        .rev()
        .take_while(|&&byte| class(byte))
        .count();
    end - run
}

fn spaces(data: &[u8], pos: usize) -> usize {
    data.get(pos..)
        .unwrap_or_default()
        .iter()
        .take_while(|&&byte| is_whitespace(byte))
        .count()
}

pub(crate) fn keyword_at(data: &[u8], pos: usize, keyword: &[u8]) -> bool {
    data.get(pos..)
        .and_then(|rest| rest.strip_prefix(keyword))
        .is_some_and(|rest| rest.first().is_none_or(|&byte| !is_regular(byte)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(data: &[u8]) -> Object<'_> {
        Object::read(&mut Lexer::new(data), None).unwrap_or_default()
    }

    #[test]
    fn references_and_scalars() {
        assert_eq!(
            read(b"12 0 R").as_ref(),
            Some(ObjRef {
                num: 12,
                generation: 0
            })
        );
        assert!(read(b"0 0 R").is_null());
        assert!(read(b"9000000 0 R").is_null());
        assert!(read(b"1 70000 R").is_null());
        assert_eq!(read(b"12 0 obj").as_int(), Some(12));
        assert_eq!(read(b"12 0").as_int(), Some(12));
        assert_eq!(read(b"true").as_bool(), Some(true));
        assert!(read(b"null").is_null());
        assert!(Object::read(&mut Lexer::new(b">>"), None).is_none());
        let mut lexer = Lexer::new(b"endobj");
        assert!(Object::read(&mut lexer, None).is_none());
        assert_eq!(lexer.pos(), 0);
    }

    #[test]
    fn indirect_objects_and_streams() {
        let data = b"junk 7 0 obj\r\n<< /Length 4 >>stream\r\nabcd\nendstream endobj";
        let object = Indirect::parse(data, 5, true).unwrap_or_else(|| panic!("object"));
        assert_eq!(
            object.id,
            ObjRef {
                num: 7,
                generation: 0
            }
        );
        let start = object.stream_start.unwrap_or_default();
        assert_eq!(data.get(start..start + 4), Some(&b"abcd"[..]));
        assert!(Indirect::parse(data, 0, true).is_none());
        let bare = Indirect::parse(b"3 obj 42", 0, false).map(|object| object.value.as_int());
        assert_eq!(bare, Some(Some(42)));
        let glued = Indirect::parse(b" 3 0obj<</A 1>>", 0, false).map(|object| object.id);
        assert_eq!(
            glued,
            Some(ObjRef {
                num: 3,
                generation: 0
            })
        );
        assert!(Indirect::parse(b"3 0 (x) obj", 0, false).is_none());
        assert!(Indirect::parse(b"12345678901 0 obj", 0, false).is_none());
        let headers = b"x 1 0 obj 12 obj 3 4 5 obj endobj 9 0obj 1 0 objx";
        let found: Vec<Option<usize>> = memchr::memmem::find_iter(headers, b"obj")
            .map(|keyword| Indirect::header_before(headers, keyword))
            .collect();
        assert_eq!(
            found,
            vec![Some(2), Some(10), Some(19), None, Some(34), None]
        );
        assert_eq!(stream_data_start(b"stream \t\rX", 6), 9);
        assert_eq!(stream_data_start(b"streamX", 6), 6);
        assert_eq!(stream_data_start(b"stream\n\nX", 6), 7);
        assert!(keyword_at(b"xref\n", 0, b"xref"));
        assert!(!keyword_at(b"xrefs", 0, b"xref"));
    }
}
