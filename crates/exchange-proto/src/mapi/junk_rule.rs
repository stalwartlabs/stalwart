/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    prop::{CountWidth, OwnedPropValue, PropKeyRef, PropValue, tags},
    restriction::{Restriction, RestrictionBytes, RestrictionNode},
    rop::RopDecodeError,
};
use crate::{common::LeReader, convert::model::PropBag};
use std::str::from_utf8;

pub const JUNK_RULE_PROVIDER: &str = "JunkEmailRule";
pub const EXTENDED_RULE_CLASS: &str = "IPM.ExtendedRule.Message";
pub const MAX_JUNK_ENTRIES: usize = 1024;
const ST_ENABLED: i32 = 0x01;
const MAX_DEPTH: u8 = 12;
const FUZZY_LEVEL_MASK: u32 = 0xFFFF;
const FL_FULLSTRING: u32 = 0;
const FL_SUBSTRING: u32 = 1;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JunkLists {
    pub blocked_senders: Vec<String>,
    pub safe_senders: Vec<String>,
    pub safe_recipients: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JunkRule {
    pub is_enabled: bool,
    pub lists: JunkLists,
}

#[derive(Clone, Copy)]
struct Scope {
    trusted: bool,
    recipients: bool,
}

impl JunkRule {
    pub fn from_props(props: &PropBag) -> Option<Result<Self, RopDecodeError>> {
        let is_class = matches!(
            props.get_any(PropKeyRef::Tag(tags::MESSAGE_CLASS.id())),
            Some(OwnedPropValue::Unicode(class)) if class.eq_ignore_ascii_case(EXTENDED_RULE_CLASS)
        );
        let is_provider = matches!(
            props.get_any(PropKeyRef::Tag(tags::RULE_MESSAGE_PROVIDER.id())),
            Some(OwnedPropValue::Unicode(provider)) if &**provider == JUNK_RULE_PROVIDER
        );
        if !is_class || !is_provider {
            return None;
        }
        let is_enabled = matches!(
            props.get_any(PropKeyRef::Tag(tags::RULE_MESSAGE_STATE.id())),
            Some(OwnedPropValue::I32(state)) if state & ST_ENABLED != 0
        );
        let lists = match props.get_any(PropKeyRef::Tag(tags::EXTENDED_RULE_MESSAGE_CONDITION.id()))
        {
            Some(OwnedPropValue::Binary(condition)) => JunkLists::decode(condition),
            _ => Ok(JunkLists::default()),
        };
        Some(lists.map(|lists| JunkRule { is_enabled, lists }))
    }
}

impl JunkLists {
    pub fn decode(condition: &[u8]) -> Result<Self, RopDecodeError> {
        let mut lists = JunkLists::default();
        if let Some(tree) = RestrictionBytes(skip_named_properties(condition)?).decode(
            CountWidth::Wide,
            false,
            MAX_DEPTH,
        )? {
            lists.collect(
                &tree,
                tree.root,
                Scope {
                    trusted: false,
                    recipients: false,
                },
            );
        }
        Ok(lists)
    }

    fn collect(&mut self, tree: &Restriction<'_>, index: u16, scope: Scope) {
        let Some(node) = tree.nodes.get(usize::from(index)) else {
            return;
        };
        match node {
            RestrictionNode::And(range) | RestrictionNode::Or(range) => {
                if let Some(children) = tree
                    .children
                    .get(usize::from(range.start)..usize::from(range.end))
                {
                    for child in children {
                        self.collect(tree, *child, scope);
                    }
                }
            }
            RestrictionNode::Not(child) => self.collect(
                tree,
                *child,
                Scope {
                    trusted: !scope.trusted,
                    ..scope
                },
            ),
            RestrictionNode::Sub { tag, child } if tag.id() == tags::MESSAGE_RECIPIENTS.id() => {
                self.collect(
                    tree,
                    *child,
                    Scope {
                        recipients: true,
                        ..scope
                    },
                )
            }
            RestrictionNode::Content { fuzzy, tag, value } => {
                let expected = if scope.recipients {
                    tags::EMAIL_ADDRESS
                } else {
                    tags::SENDER_EMAIL_ADDRESS
                };
                if tag.id() == expected.id() {
                    self.push_entry(scope, *fuzzy & FUZZY_LEVEL_MASK, value);
                }
            }
            _ => {}
        }
    }

    fn push_entry(&mut self, scope: Scope, level: u32, value: &PropValue<'_>) {
        let list = match (scope.trusted, scope.recipients) {
            (false, false) => &mut self.blocked_senders,
            (true, false) => &mut self.safe_senders,
            (true, true) => &mut self.safe_recipients,
            (false, true) => return,
        };
        if list.len() >= MAX_JUNK_ENTRIES {
            return;
        }
        let mut decoded = String::new();
        let value = match value {
            PropValue::Unicode(value) => {
                value.to_string_lossy(&mut decoded);
                decoded.as_str()
            }
            PropValue::String8(value) => match from_utf8(value) {
                Ok(value) => value,
                Err(_) => return,
            },
            _ => return,
        };
        let value = value.trim();
        match level {
            FL_FULLSTRING if is_address(value) => {
                let trimmed = (value.len() != decoded.len()).then(|| value.to_string());
                list.push(trimmed.unwrap_or(decoded));
            }
            FL_SUBSTRING => {
                let domain = value.strip_prefix('@').unwrap_or(value);
                if is_domain(domain) {
                    let mut entry = String::with_capacity(domain.len().saturating_add(1));
                    entry.push('@');
                    entry.push_str(domain);
                    list.push(entry);
                }
            }
            _ => {}
        }
    }
}

fn is_address(value: &str) -> bool {
    value.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && !local.contains(is_forbidden) && is_domain(domain)
    })
}

fn is_domain(domain: &str) -> bool {
    !domain.is_empty() && !domain.contains(|ch| ch == '@' || is_forbidden(ch))
}

fn is_forbidden(ch: char) -> bool {
    ch.is_whitespace() || ch.is_control() || matches!(ch, '*' | '?' | '\\' | '"')
}

fn skip_named_properties(condition: &[u8]) -> Result<&[u8], RopDecodeError> {
    let mut reader = LeReader::new(condition);
    let count = reader.u16()?;
    if count > 0 {
        reader.skip(usize::from(count) * 2)?;
        let size = reader.u32()?;
        reader.skip(usize::try_from(size).unwrap_or(usize::MAX))?;
    }
    Ok(reader.remaining())
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/mapi/junk_rule/tests.rs"]
mod tests;
