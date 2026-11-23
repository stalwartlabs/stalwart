/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    page::{Page, RowKey, fold, fold_cmp_folded},
    props::has_property,
    scan::{AbView, ScanScope},
};
use crate::{
    identity::{DirectoryRef, directory_ref_from_dn},
    mapi::text::decode_text,
};
use exchange_proto::mapi::{
    nspi::{NspiStatus, Stat, tags::ANR},
    prop::{CodePage, PropTag},
    restriction::{RelOp, Restriction, RestrictionNode},
};
use std::{borrow::Cow, cmp::Ordering};

const GAL_CONTAINER: u32 = 0;
pub const ROOMS_CONTAINER: u32 = 0xFFFF_FFE8;
pub const ROOMS_CONTAINER_DN: &str = "/guid=5354414C5741525452524F4F4D533031";
const FL_SUBSTRING: u32 = 0x0001;
const FL_PREFIX: u32 = 0x0002;
const MAX_RESTRICTION_NODES: usize = 256;

pub fn container_scope(stat: &Stat) -> Result<ScanScope, NspiStatus> {
    match stat.container_id {
        GAL_CONTAINER => Ok(ScanScope::All),
        ROOMS_CONTAINER => Ok(ScanScope::Rooms),
        _ => Err(NspiStatus::INVALID_BOOKMARK),
    }
}

pub fn set_position(stat: &mut Stat, page: &Page, position: usize) {
    stat.current_rec = page.mid_at(position).0;
    stat.num_pos = u32::try_from(position).unwrap_or(u32::MAX);
    stat.total_recs = u32::try_from(page.total).unwrap_or(u32::MAX);
    stat.delta = 0;
}

pub enum NameKind<'n> {
    Empty,
    Principal(DirectoryRef),
    Smtp(&'n str),
    Text(&'n str),
}

impl<'n> NameKind<'n> {
    pub fn of(name: &'n str) -> Self {
        let name = name.trim();
        if name.is_empty() {
            NameKind::Empty
        } else if let Some(principal) = directory_ref_from_dn(name.as_bytes()) {
            NameKind::Principal(principal)
        } else if let Some(address) = strip_prefix_ignore_case(name, "=SMTP:") {
            NameKind::Smtp(address)
        } else {
            NameKind::Text(name)
        }
    }
}

#[derive(Debug, Default)]
enum Hit {
    #[default]
    None,
    One(RowKey),
    Many,
}

impl Hit {
    fn add(&mut self, key: &RowKey) {
        *self = match std::mem::take(self) {
            Hit::None => Hit::One(key.clone()),
            Hit::One(found) if found.mid() == key.mid() => Hit::One(found),
            _ => Hit::Many,
        };
    }
}

pub enum Resolution {
    Unresolved,
    Ambiguous,
    Resolved(RowKey),
}

impl From<Option<RowKey>> for Resolution {
    fn from(key: Option<RowKey>) -> Self {
        key.map_or(Resolution::Unresolved, Resolution::Resolved)
    }
}

pub struct PendingName {
    name: Box<str>,
    folded: String,
    exact: Hit,
    anr: Hit,
}

impl PendingName {
    pub fn new(name: &str) -> Self {
        PendingName {
            name: name.into(),
            folded: fold(name),
            exact: Hit::None,
            anr: Hit::None,
        }
    }

    pub fn test(&mut self, view: &AbView<'_>, key: &RowKey) {
        if exact(view, &self.name, &self.folded) {
            self.exact.add(key);
        }
        if matches!(self.exact, Hit::None) && anr(view, &self.folded) {
            self.anr.add(key);
        }
    }

    pub fn finish(self) -> Resolution {
        match (self.exact, self.anr) {
            (Hit::One(key), _) | (Hit::None, Hit::One(key)) => Resolution::Resolved(key),
            (Hit::Many, _) | (Hit::None, Hit::Many) => Resolution::Ambiguous,
            (Hit::None, Hit::None) => Resolution::Unresolved,
        }
    }
}

fn strip_prefix_ignore_case<'s>(text: &'s str, prefix: &str) -> Option<&'s str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| text.get(prefix.len()..))
        .flatten()
}

fn exact(view: &AbView<'_>, name: &str, folded: &str) -> bool {
    fold_cmp_folded(view.display_name, folded).is_eq()
        || view.account.eq_ignore_ascii_case(name)
        || view.smtp.eq_ignore_ascii_case(name)
}

pub fn anr(view: &AbView<'_>, lower: &str) -> bool {
    name_anr(view.display_name, lower)
        || starts_with_ignore_case(view.account, lower)
        || view
            .addresses()
            .any(|address| starts_with_ignore_case(address, lower))
}

pub(crate) fn name_anr(name: &str, lower: &str) -> bool {
    if name.is_ascii() {
        starts_with_ignore_case(name, lower)
            || name
                .split_whitespace()
                .any(|word| starts_with_ignore_case(word, lower))
    } else {
        folded_starts_with(name, lower)
            || name
                .split_whitespace()
                .any(|word| folded_starts_with(word, lower))
    }
}

fn folded_starts_with(text: &str, lower: &str) -> bool {
    let mut chars = text.chars().flat_map(char::to_lowercase);
    lower.chars().all(|c| chars.next() == Some(c))
}

fn starts_with_ignore_case(text: &str, lower: &str) -> bool {
    text.get(..lower.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(lower))
}

pub struct Matcher<'r> {
    restriction: &'r Restriction<'r>,
    targets: Vec<Option<Target>>,
}

struct Target {
    op: TextOp,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Prefix,
    Substring,
    Never,
}

impl TextOp {
    fn of(node: &RestrictionNode<'_>) -> Self {
        match node {
            RestrictionNode::Content { fuzzy, .. } => match fuzzy & (FL_SUBSTRING | FL_PREFIX) {
                FL_SUBSTRING => TextOp::Substring,
                FL_PREFIX => TextOp::Prefix,
                _ => TextOp::Eq,
            },
            RestrictionNode::Property { op, .. } => match op {
                RelOp::Eq => TextOp::Eq,
                RelOp::Ne => TextOp::Ne,
                RelOp::Lt => TextOp::Lt,
                RelOp::Le => TextOp::Le,
                RelOp::Gt => TextOp::Gt,
                RelOp::Ge => TextOp::Ge,
                RelOp::Re | RelOp::MemberOfDl => TextOp::Never,
            },
            _ => TextOp::Never,
        }
    }

    fn test(self, text: &str, target: &str) -> bool {
        if text.is_ascii() {
            self.test_folded(text.as_bytes(), target.as_bytes())
        } else {
            self.test_folded(fold(text).as_bytes(), target.as_bytes())
        }
    }

    fn test_folded(self, text: &[u8], target: &[u8]) -> bool {
        let order = || {
            text.iter()
                .map(u8::to_ascii_lowercase)
                .cmp(target.iter().copied())
        };
        match self {
            TextOp::Eq => text.eq_ignore_ascii_case(target),
            TextOp::Ne => !text.eq_ignore_ascii_case(target),
            TextOp::Lt => order() == Ordering::Less,
            TextOp::Le => order() != Ordering::Greater,
            TextOp::Gt => order() == Ordering::Greater,
            TextOp::Ge => order() != Ordering::Less,
            TextOp::Prefix => text
                .get(..target.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(target)),
            TextOp::Substring => {
                target.is_empty()
                    || text
                        .windows(target.len())
                        .any(|window| window.eq_ignore_ascii_case(target))
            }
            TextOp::Never => false,
        }
    }
}

impl<'r> Matcher<'r> {
    pub fn new(restriction: &'r Restriction<'r>, code_page: CodePage) -> Result<Self, NspiStatus> {
        if restriction.nodes.len() > MAX_RESTRICTION_NODES
            || !restriction.nodes.iter().all(supported)
        {
            return Err(NspiStatus::TOO_COMPLEX);
        }
        let mut scratch = String::new();
        let targets = restriction
            .nodes
            .iter()
            .map(|node| match node {
                RestrictionNode::Content { value, .. }
                | RestrictionNode::Property { value, .. } => {
                    decode_text(value, code_page, &mut scratch).then(|| Target {
                        op: TextOp::of(node),
                        text: fold(&scratch),
                    })
                }
                _ => None,
            })
            .collect();
        Ok(Matcher {
            restriction,
            targets,
        })
    }

    pub fn matches(&self, entry: &AbView<'_>) -> bool {
        self.node(entry, self.restriction.root)
    }

    fn node(&self, entry: &AbView<'_>, index: u16) -> bool {
        let index = usize::from(index);
        let (Some(node), Some(target)) =
            (self.restriction.nodes.get(index), self.targets.get(index))
        else {
            return false;
        };
        match node {
            RestrictionNode::And(range) => self
                .children(range.start, range.end)
                .iter()
                .all(|child| self.node(entry, *child)),
            RestrictionNode::Or(range) => self
                .children(range.start, range.end)
                .iter()
                .any(|child| self.node(entry, *child)),
            RestrictionNode::Not(child) => !self.node(entry, *child),
            RestrictionNode::Exist(tag) => has_property(*tag),
            RestrictionNode::Content { tag, .. } | RestrictionNode::Property { tag, .. } => target
                .as_ref()
                .is_some_and(|target| text_test(entry, *tag, target)),
            _ => false,
        }
    }

    fn children(&self, start: u16, end: u16) -> &[u16] {
        self.restriction
            .children
            .get(usize::from(start)..usize::from(end))
            .unwrap_or(&[])
    }
}

fn text_test(entry: &AbView<'_>, tag: PropTag, target: &Target) -> bool {
    if tag.id() == ANR.id() {
        anr(entry, &target.text)
    } else {
        text_of(entry, tag).is_some_and(|text| target.op.test(&text, &target.text))
    }
}

fn supported(node: &RestrictionNode<'_>) -> bool {
    matches!(
        node,
        RestrictionNode::And(_)
            | RestrictionNode::Or(_)
            | RestrictionNode::Not(_)
            | RestrictionNode::Exist(_)
            | RestrictionNode::Content { .. }
            | RestrictionNode::Property { .. }
    )
}

fn text_of<'a>(entry: &AbView<'a>, tag: PropTag) -> Option<Cow<'a, str>> {
    match tag.id().0 {
        0x3001 | 0x3A20 => Some(Cow::Borrowed(entry.display_name)),
        0x3003 | 0x803C => entry.dn(),
        0x39FE => Some(Cow::Borrowed(entry.smtp)),
        0x3A00 => Some(Cow::Borrowed(entry.account)),
        0x3002 => Some(Cow::Borrowed("EX")),
        _ => None,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/nspi/table/tests.rs"]
pub mod tests;
