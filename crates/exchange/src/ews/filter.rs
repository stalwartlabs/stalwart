/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::ews::{
    Status,
    schema::{
        ContainmentComparison, ContainmentMode, Importance, LegacyFreeBusy, ResponseCode,
        TaskStatus,
    },
    types::{
        path::Path,
        restriction::{CompareOp, CompareRhs, NodeIdx, Restriction, SearchNode},
    },
};
use jiff::Timestamp;
use std::{borrow::Cow, cmp::Ordering, marker::PhantomData};

const NEAR_UNSUPPORTED: &str = "Near is not supported in restrictions.";
const PATH_UNSUPPORTED: &str = "The property cannot be used in a restriction.";
const TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

const _: () = assert!(Importance::Low as i64 == 0 && Importance::High as i64 == 2);
const _: () =
    assert!(LegacyFreeBusy::Free as i64 == 0 && LegacyFreeBusy::WorkingElsewhere as i64 == 4);
const _: () = assert!(TaskStatus::NotStarted as i64 == 0 && TaskStatus::Deferred as i64 == 4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsupportedFilter {
    Near,
    Path,
}

impl UnsupportedFilter {
    pub fn status(self) -> Status<'static> {
        match self {
            UnsupportedFilter::Near => {
                Status::error(ResponseCode::ErrorUnsupportedQueryFilter, NEAR_UNSUPPORTED)
            }
            UnsupportedFilter::Path => {
                Status::error(ResponseCode::ErrorUnsupportedPathForQuery, PATH_UNSUPPORTED)
            }
        }
    }
}

pub(crate) trait FilterProp: Copy {
    fn of_path(path: &Path<'_>) -> Option<Self>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PropValue<'t> {
    Text(&'t str),
    Int(i64),
    Name(NameValue),
    Bool(bool),
    Time(Timestamp),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameValue {
    Importance(Importance),
    FreeBusy(LegacyFreeBusy),
    TaskStatus(TaskStatus),
}

impl NameValue {
    pub fn as_str(self) -> &'static str {
        match self {
            NameValue::Importance(value) => value.as_str(),
            NameValue::FreeBusy(value) => value.as_str(),
            NameValue::TaskStatus(value) => value.as_str(),
        }
    }

    pub fn ordinal(self) -> i64 {
        match self {
            NameValue::Importance(value) => value as i64,
            NameValue::FreeBusy(value) => value as i64,
            NameValue::TaskStatus(value) => value as i64,
        }
    }

    fn parse_as(self, constant: &str) -> Option<Self> {
        let constant = constant.as_bytes();
        match self {
            NameValue::Importance(_) => Importance::parse(constant).map(NameValue::Importance),
            NameValue::FreeBusy(_) => LegacyFreeBusy::parse(constant).map(NameValue::FreeBusy),
            NameValue::TaskStatus(_) => TaskStatus::parse(constant).map(NameValue::TaskStatus),
        }
    }
}

impl<'t> PropValue<'t> {
    pub fn to_text(self) -> Cow<'t, str> {
        match self {
            PropValue::Text(text) => Cow::Borrowed(text),
            PropValue::Int(value) => Cow::Owned(value.to_string()),
            PropValue::Name(value) => Cow::Borrowed(value.as_str()),
            PropValue::Bool(true) => Cow::Borrowed("true"),
            PropValue::Bool(false) => Cow::Borrowed("false"),
            PropValue::Time(time) => Cow::Owned(time.strftime(TIME_FORMAT).to_string()),
        }
    }
}

pub(crate) struct Filter<'r, 'a, P> {
    restriction: &'r Restriction<'a>,
    props: PhantomData<P>,
}

impl<'r, 'a, P: FilterProp> Filter<'r, 'a, P> {
    pub fn new(restriction: &'r Restriction<'a>) -> Result<Self, UnsupportedFilter> {
        for node in &restriction.nodes {
            if matches!(node, SearchNode::Near { .. }) {
                return Err(UnsupportedFilter::Near);
            }
            for path in node_paths(node).into_iter().flatten() {
                P::of_path(path).ok_or(UnsupportedFilter::Path)?;
            }
        }
        Ok(Filter {
            restriction,
            props: PhantomData,
        })
    }

    pub fn props(&self) -> impl Iterator<Item = P> + '_ {
        self.restriction
            .nodes
            .iter()
            .flat_map(node_paths)
            .flatten()
            .filter_map(P::of_path)
    }

    pub fn matches<'t>(&self, value: &impl Fn(P) -> Option<PropValue<'t>>) -> bool {
        self.eval(value, self.restriction.root)
    }

    fn eval<'t>(&self, values: &impl Fn(P) -> Option<PropValue<'t>>, idx: NodeIdx) -> bool {
        let value = |path: &Path<'_>| P::of_path(path).and_then(values);
        match self.restriction.node(idx) {
            Some(SearchNode::Exists(path)) => value(path).is_some(),
            Some(SearchNode::Compare { op, path, rhs }) => {
                let Some(lhs) = value(path) else {
                    return false;
                };
                let ordering = match rhs {
                    CompareRhs::Constant(constant) => compare_constant(lhs, constant),
                    CompareRhs::Path(rhs) => value(rhs).and_then(|rhs| compare_values(lhs, rhs)),
                };
                ordering.is_some_and(|ordering| op_matches(*op, ordering))
            }
            Some(SearchNode::Contains {
                path,
                value: needle,
                mode,
                comparison,
            }) => match value(path) {
                Some(PropValue::Text(haystack)) => {
                    contains(haystack, needle, *mode, ignores_case(*comparison))
                }
                _ => false,
            },
            Some(SearchNode::Excludes { path, mask }) => match value(path) {
                Some(PropValue::Int(value)) => value.cast_unsigned() & mask == 0,
                _ => false,
            },
            Some(SearchNode::Not(child)) => !self.eval(values, *child),
            Some(SearchNode::And(range)) => self
                .restriction
                .range(range)
                .iter()
                .all(|child| self.eval(values, *child)),
            Some(SearchNode::Or(range)) => self
                .restriction
                .range(range)
                .iter()
                .any(|child| self.eval(values, *child)),
            Some(SearchNode::Near { .. }) | None => false,
        }
    }
}

fn node_paths<'n, 'a>(node: &'n SearchNode<'a>) -> [Option<&'n Path<'a>>; 2] {
    match node {
        SearchNode::Exists(path)
        | SearchNode::Contains { path, .. }
        | SearchNode::Excludes { path, .. } => [Some(path), None],
        SearchNode::Compare { path, rhs, .. } => [
            Some(path),
            match rhs {
                CompareRhs::Path(rhs) => Some(rhs),
                CompareRhs::Constant(_) => None,
            },
        ],
        SearchNode::Near { .. } | SearchNode::Not(_) | SearchNode::And(_) | SearchNode::Or(_) => {
            [None, None]
        }
    }
}

fn op_matches(op: CompareOp, ordering: Ordering) -> bool {
    match op {
        CompareOp::IsEqualTo => ordering.is_eq(),
        CompareOp::IsNotEqualTo => ordering.is_ne(),
        CompareOp::IsGreaterThan => ordering.is_gt(),
        CompareOp::IsGreaterThanOrEqualTo => ordering.is_ge(),
        CompareOp::IsLessThan => ordering.is_lt(),
        CompareOp::IsLessThanOrEqualTo => ordering.is_le(),
    }
}

fn compare_constant(lhs: PropValue<'_>, constant: &str) -> Option<Ordering> {
    let rhs = match lhs {
        PropValue::Text(_) => PropValue::Text(constant),
        PropValue::Int(_) => PropValue::Int(constant.trim().parse().ok()?),
        PropValue::Name(value) => PropValue::Name(value.parse_as(constant.trim())?),
        PropValue::Bool(_) => PropValue::Bool(parse_bool(constant.trim())?),
        PropValue::Time(_) => PropValue::Time(constant.trim().parse::<Timestamp>().ok()?),
    };
    compare_values(lhs, rhs)
}

fn parse_bool(value: &str) -> Option<bool> {
    hashify::map_ignore_case!(value.as_bytes(), bool,
        "true" => true,
        "1" => true,
        "false" => false,
        "0" => false,
    )
    .copied()
}

fn compare_values(lhs: PropValue<'_>, rhs: PropValue<'_>) -> Option<Ordering> {
    Some(match (lhs, rhs) {
        (PropValue::Text(lhs), PropValue::Text(rhs)) => folded(lhs).cmp(folded(rhs)),
        (PropValue::Int(lhs), PropValue::Int(rhs)) => lhs.cmp(&rhs),
        (PropValue::Name(lhs), PropValue::Name(rhs)) => lhs.ordinal().cmp(&rhs.ordinal()),
        (PropValue::Bool(lhs), PropValue::Bool(rhs)) => lhs.cmp(&rhs),
        (PropValue::Time(lhs), PropValue::Time(rhs)) => lhs.cmp(&rhs),
        _ => return None,
    })
}

fn ignores_case(comparison: ContainmentComparison) -> bool {
    matches!(
        comparison,
        ContainmentComparison::IgnoreCase
            | ContainmentComparison::IgnoreCaseAndNonSpacingCharacters
            | ContainmentComparison::LooseAndIgnoreCase
            | ContainmentComparison::LooseAndIgnoreCaseAndIgnoreNonSpace
    )
}

fn folded(text: &str) -> impl Iterator<Item = char> + '_ {
    text.chars().flat_map(char::to_lowercase)
}

fn contains(haystack: &str, needle: &str, mode: ContainmentMode, ignore_case: bool) -> bool {
    match mode {
        ContainmentMode::FullString => text_eq(haystack, needle, ignore_case),
        ContainmentMode::Prefixed => starts_with(haystack, needle, ignore_case),
        ContainmentMode::Substring | ContainmentMode::ExactPhrase => {
            let mut chars = haystack.chars();
            loop {
                if starts_with(chars.as_str(), needle, ignore_case) {
                    return true;
                }
                if chars.next().is_none() {
                    return false;
                }
            }
        }
        ContainmentMode::PrefixOnWords => haystack
            .split_whitespace()
            .any(|word| starts_with(word, needle, ignore_case)),
    }
}

fn text_eq(lhs: &str, rhs: &str, ignore_case: bool) -> bool {
    if ignore_case {
        folded(lhs).eq(folded(rhs))
    } else {
        lhs == rhs
    }
}

fn starts_with(haystack: &str, needle: &str, ignore_case: bool) -> bool {
    if !ignore_case {
        return haystack.starts_with(needle);
    }
    let mut haystack = folded(haystack);
    folded(needle).all(|expected| haystack.next() == Some(expected))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/ews/filter/tests.rs"]
mod tests;
