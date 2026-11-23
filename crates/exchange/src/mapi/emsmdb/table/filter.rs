/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mapi::{emsmdb::props::PropOut, text::decode_text};
use exchange_proto::mapi::{
    prop::{CodePage, PropTag, PropValue, tags},
    restriction::{RelOp, Restriction, RestrictionNode},
};
use memchr::memmem::{self, Finder};
use std::{borrow::Cow, cmp::Ordering};
use store::roaring::RoaringBitmap;

pub const MAX_RESTRICTION_NODES: usize = 256;
const FL_LEVEL_MASK: u32 = 0x0000_FFFF;
const FL_SUBSTRING: u32 = 0x0001;
const FL_PREFIX: u32 = 0x0002;
const FL_IGNORE_CASE: u32 = 0x0001_0000;
const FL_LOOSE: u32 = 0x0004_0000;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RowValue<'v> {
    Int(i64),
    Float(f64),
    Text(&'v str),
    Bytes(&'v [u8]),
}

#[derive(Debug, Clone, PartialEq)]
pub enum SortKey {
    Missing,
    Int(i64),
    Float(f64),
    Text(Box<str>),
    Bytes(Box<[u8]>),
}

enum Target<'r> {
    Int(i64),
    Float(f64),
    Text {
        folded: String,
        exact: String,
        finder: Option<Finder<'static>>,
    },
    Bytes {
        bytes: &'r [u8],
        finder: Option<Finder<'r>>,
    },
}

pub struct RowFilter<'r> {
    restriction: &'r Restriction<'r>,
    targets: Vec<Option<Target<'r>>>,
    documents: Vec<(u16, RoaringBitmap)>,
}

impl<'v> RowValue<'v> {
    pub fn of(value: &PropOut<'v>) -> Option<Self> {
        match *value {
            PropOut::Text(text) => Some(RowValue::Text(text)),
            PropOut::Value(value) => match value {
                PropValue::I16(v) => Some(RowValue::Int(i64::from(v))),
                PropValue::I32(v) => Some(RowValue::Int(i64::from(v))),
                PropValue::I64(v) | PropValue::Currency(v) => Some(RowValue::Int(v)),
                PropValue::Bool(v) => Some(RowValue::Int(i64::from(v))),
                PropValue::Time(v) => Some(RowValue::Int(i64::try_from(v.0).unwrap_or(i64::MAX))),
                PropValue::F32(v) => Some(RowValue::Float(f64::from(v))),
                PropValue::F64(v) | PropValue::AppTime(v) => Some(RowValue::Float(v)),
                PropValue::Binary(v) | PropValue::ServerId(v) => Some(RowValue::Bytes(v)),
                PropValue::Guid(v) => Some(RowValue::Bytes(v)),
                _ => None,
            },
        }
    }

    fn byte_size(&self) -> usize {
        match self {
            RowValue::Int(_) | RowValue::Float(_) => size_of::<i64>(),
            RowValue::Text(text) => text
                .encode_utf16()
                .count()
                .saturating_add(1)
                .saturating_mul(2),
            RowValue::Bytes(bytes) => bytes.len(),
        }
    }
}

impl SortKey {
    pub fn of(value: Option<PropOut<'_>>) -> Self {
        match value.as_ref().and_then(RowValue::of) {
            None => SortKey::Missing,
            Some(RowValue::Int(v)) => SortKey::Int(v),
            Some(RowValue::Float(v)) => SortKey::Float(v),
            Some(RowValue::Text(text)) => SortKey::Text(fold(text).into_owned().into_boxed_str()),
            Some(RowValue::Bytes(bytes)) => SortKey::Bytes(bytes.into()),
        }
    }

    pub fn compare(&self, other: &Self) -> Ordering {
        match (self, other) {
            (SortKey::Missing, SortKey::Missing) => Ordering::Equal,
            (SortKey::Missing, _) => Ordering::Less,
            (_, SortKey::Missing) => Ordering::Greater,
            (SortKey::Int(a), SortKey::Int(b)) => a.cmp(b),
            (SortKey::Float(a), SortKey::Float(b)) => a.total_cmp(b),
            (SortKey::Text(a), SortKey::Text(b)) => a.cmp(b),
            (SortKey::Bytes(a), SortKey::Bytes(b)) => a.cmp(b),
            (a, b) => a.rank().cmp(&b.rank()),
        }
    }

    fn rank(&self) -> u8 {
        match self {
            SortKey::Missing => 0,
            SortKey::Int(_) => 1,
            SortKey::Float(_) => 2,
            SortKey::Text(_) => 3,
            SortKey::Bytes(_) => 4,
        }
    }
}

impl<'r> RowFilter<'r> {
    pub fn new(restriction: &'r Restriction<'r>, code_page: CodePage) -> Option<Self> {
        if restriction.nodes.len() > MAX_RESTRICTION_NODES {
            return None;
        }
        let mut scratch = String::new();
        let targets = restriction
            .nodes
            .iter()
            .map(|node| match node {
                RestrictionNode::Content { value, fuzzy, .. } => {
                    Target::of(value, code_page, &mut scratch)
                        .map(|target| target.with_finder(*fuzzy))
                }
                RestrictionNode::Property { value, .. } => {
                    Target::of(value, code_page, &mut scratch)
                }
                _ => None,
            })
            .collect();
        Some(RowFilter {
            restriction,
            targets,
            documents: Vec::new(),
        })
    }

    pub fn body_terms(&self) -> impl Iterator<Item = (u16, &str)> {
        self.restriction
            .nodes
            .iter()
            .zip(&self.targets)
            .zip(0u16..)
            .filter_map(|((node, target), index)| match (node, target) {
                (RestrictionNode::Content { tag, .. }, Some(Target::Text { exact, .. }))
                    if tag.id() == tags::BODY.id() && !exact.trim().is_empty() =>
                {
                    Some((index, exact.as_str()))
                }
                _ => None,
            })
    }

    pub fn uses_body(&self) -> bool {
        self.restriction.nodes.iter().any(|node| {
            matches!(
                node,
                RestrictionNode::Content { tag, .. } | RestrictionNode::Exist(tag)
                    if tag.id() == tags::BODY.id()
            )
        })
    }

    pub fn resolve_documents(&mut self, index: u16, documents: RoaringBitmap) {
        self.documents.push((index, documents));
    }

    pub fn matches<'v>(&self, row: &impl Fn(PropTag) -> Option<PropOut<'v>>) -> bool {
        self.node(row, None, self.restriction.root)
    }

    pub fn matches_document<'v>(
        &self,
        row: &impl Fn(PropTag) -> Option<PropOut<'v>>,
        document: Option<u32>,
    ) -> bool {
        self.node(row, document, self.restriction.root)
    }

    fn node<'v>(
        &self,
        row: &impl Fn(PropTag) -> Option<PropOut<'v>>,
        document: Option<u32>,
        index: u16,
    ) -> bool {
        let Some(node) = self.restriction.nodes.get(usize::from(index)) else {
            return false;
        };
        if let (RestrictionNode::Content { .. }, Some(document)) = (node, document)
            && let Some((_, documents)) = self.documents.iter().find(|(node, _)| *node == index)
        {
            return documents.contains(document);
        }
        let target = self
            .targets
            .get(usize::from(index))
            .and_then(Option::as_ref);
        match node {
            RestrictionNode::And(range) => self
                .children(range.start, range.end)
                .iter()
                .all(|child| self.node(row, document, *child)),
            RestrictionNode::Or(range) => self
                .children(range.start, range.end)
                .iter()
                .any(|child| self.node(row, document, *child)),
            RestrictionNode::Not(child) => !self.node(row, document, *child),
            RestrictionNode::Content { fuzzy, tag, .. } => match (row(*tag), target) {
                (Some(value), Some(target)) => {
                    RowValue::of(&value).is_some_and(|value| target.contains(value, *fuzzy))
                }
                _ => false,
            },
            RestrictionNode::Property { op, tag, .. } => match (row(*tag), target) {
                (Some(value), Some(target)) => RowValue::of(&value)
                    .and_then(|value| target.compare(value))
                    .is_some_and(|order| holds(*op, order)),
                _ => false,
            },
            RestrictionNode::CompareProps { op, a, b } => {
                match (
                    row(*a).as_ref().and_then(RowValue::of),
                    row(*b).as_ref().and_then(RowValue::of),
                ) {
                    (Some(a), Some(b)) => {
                        compare_values(a, b).is_some_and(|order| holds(*op, order))
                    }
                    _ => false,
                }
            }
            RestrictionNode::Bitmask { all_set, tag, mask } => {
                match row(*tag).as_ref().and_then(RowValue::of) {
                    Some(RowValue::Int(value)) => (value & i64::from(*mask) != 0) == *all_set,
                    _ => false,
                }
            }
            RestrictionNode::Size { op, tag, size } => row(*tag)
                .as_ref()
                .and_then(RowValue::of)
                .is_some_and(|value| {
                    holds(
                        *op,
                        value
                            .byte_size()
                            .cmp(&usize::try_from(*size).unwrap_or(usize::MAX)),
                    )
                }),
            RestrictionNode::Exist(tag) => {
                (document.is_some() && tag.id() == tags::BODY.id()) || row(*tag).is_some()
            }
            RestrictionNode::Sub { .. } => false,
            RestrictionNode::Comment { child, .. } => {
                child.is_none_or(|child| self.node(row, document, child))
            }
            RestrictionNode::Count { child, .. } => self.node(row, document, *child),
        }
    }

    fn children(&self, start: u16, end: u16) -> &[u16] {
        self.restriction
            .children
            .get(usize::from(start)..usize::from(end))
            .unwrap_or_default()
    }
}

impl<'r> Target<'r> {
    fn of(value: &PropValue<'r>, code_page: CodePage, scratch: &mut String) -> Option<Self> {
        match value {
            PropValue::Unicode(_) | PropValue::String8(_) => decode_text(value, code_page, scratch)
                .then(|| Target::Text {
                    folded: scratch.to_lowercase(),
                    exact: scratch.clone(),
                    finder: None,
                }),
            other => match RowValue::of(&PropOut::Value(*other))? {
                RowValue::Int(v) => Some(Target::Int(v)),
                RowValue::Float(v) => Some(Target::Float(v)),
                RowValue::Bytes(bytes) => Some(Target::Bytes {
                    bytes,
                    finder: None,
                }),
                RowValue::Text(_) => None,
            },
        }
    }

    fn with_finder(mut self, fuzzy: u32) -> Self {
        if fuzzy & FL_LEVEL_MASK != FL_SUBSTRING {
            return self;
        }
        match &mut self {
            Target::Text {
                folded,
                exact,
                finder,
            } => {
                let needle = if ignores_case(fuzzy) { folded } else { exact };
                *finder = Some(Finder::new(needle.as_bytes()).into_owned());
            }
            Target::Bytes { bytes, finder } => *finder = Some(Finder::new(*bytes)),
            Target::Int(_) | Target::Float(_) => {}
        }
        self
    }

    fn compare(&self, value: RowValue<'_>) -> Option<Ordering> {
        match (value, self) {
            (RowValue::Int(a), Target::Int(b)) => Some(a.cmp(b)),
            (RowValue::Float(a), Target::Float(b)) => a.partial_cmp(b),
            (RowValue::Bytes(a), Target::Bytes { bytes: b, .. }) => Some(a.cmp(b)),
            (RowValue::Text(a), Target::Text { folded, .. }) => {
                Some(fold(a).as_ref().cmp(folded.as_str()))
            }
            _ => None,
        }
    }

    fn contains(&self, value: RowValue<'_>, fuzzy: u32) -> bool {
        let level = fuzzy & FL_LEVEL_MASK;
        let test = |text: &[u8], target: &[u8], finder: Option<&Finder<'_>>| match level {
            FL_SUBSTRING => finder.map_or_else(
                || memmem::find(text, target).is_some(),
                |finder| finder.find(text).is_some(),
            ),
            FL_PREFIX => text.starts_with(target),
            _ => text == target,
        };
        match (value, self) {
            (
                RowValue::Text(text),
                Target::Text {
                    folded,
                    exact,
                    finder,
                },
            ) => {
                if ignores_case(fuzzy) {
                    test(fold(text).as_bytes(), folded.as_bytes(), finder.as_ref())
                } else {
                    test(text.as_bytes(), exact.as_bytes(), finder.as_ref())
                }
            }
            (
                RowValue::Bytes(bytes),
                Target::Bytes {
                    bytes: target,
                    finder,
                },
            ) => test(bytes, target, finder.as_ref()),
            _ => false,
        }
    }
}

fn ignores_case(fuzzy: u32) -> bool {
    fuzzy & (FL_IGNORE_CASE | FL_LOOSE) != 0
}

fn fold(text: &str) -> Cow<'_, str> {
    if text
        .bytes()
        .any(|byte| byte.is_ascii_uppercase() || !byte.is_ascii())
    {
        text.to_lowercase().into()
    } else {
        text.into()
    }
}

fn compare_values(a: RowValue<'_>, b: RowValue<'_>) -> Option<Ordering> {
    match (a, b) {
        (RowValue::Int(a), RowValue::Int(b)) => Some(a.cmp(&b)),
        (RowValue::Float(a), RowValue::Float(b)) => a.partial_cmp(&b),
        (RowValue::Text(a), RowValue::Text(b)) => Some(fold(a).cmp(&fold(b))),
        (RowValue::Bytes(a), RowValue::Bytes(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

fn holds(op: RelOp, order: Ordering) -> bool {
    match op {
        RelOp::Lt => order == Ordering::Less,
        RelOp::Le => order != Ordering::Greater,
        RelOp::Gt => order == Ordering::Greater,
        RelOp::Ge => order != Ordering::Less,
        RelOp::Eq => order == Ordering::Equal,
        RelOp::Ne => order != Ordering::Equal,
        RelOp::Re | RelOp::MemberOfDl => false,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/table/filter/tests.rs"]
mod tests;
