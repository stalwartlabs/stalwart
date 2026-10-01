/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    error::set::SetError,
    object::metadata::{MetadataProperty, MetadataRoot},
};
use jmap_tools::{JsonPointer, Key, Null};
use std::borrow::Cow;
use types::metadata::LimitViolation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Rule {
    Syntax,
    Forbidden,
    Private,
    Namespace,
    Parent,
    Depth,
    ControlCharacter,
    EntrySize,
    Entries,
    ContainerSize,
}

#[derive(Debug)]
pub(super) struct Violation {
    pub rule: Rule,
    pub root: MetadataRoot,
    pub path: Option<String>,
    pub description: Cow<'static, str>,
}

#[derive(Debug, Default)]
pub(super) struct Violations(Option<Violation>);

impl Violations {
    pub fn report(&mut self, rule: Rule, violation: impl FnOnce() -> Violation) {
        if self.0.as_ref().is_none_or(|first| rule < first.rule) {
            self.0 = Some(violation());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn into_set_error<P: MetadataProperty>(self) -> SetError<P> {
        let Some(violation) = self.0 else {
            return SetError::invalid_properties();
        };
        let error = match violation.rule {
            Rule::Syntax | Rule::Parent => SetError::invalid_patch(),
            Rule::Forbidden => SetError::forbidden(),
            _ => SetError::invalid_properties(),
        };
        match violation.path {
            Some(path) => error.with_property(Key::Owned(path)),
            None => error.with_property(P::from_metadata_root(violation.root)),
        }
        .with_description(violation.description)
    }
}

pub(super) fn namespace_path(root: MetadataRoot, name: &str) -> String {
    JsonPointer::<Null>::encode([root.as_str(), name])
}

pub(super) fn limit_description(violation: LimitViolation) -> String {
    match violation {
        LimitViolation::Depth { depth, max } => {
            format!("Metadata value depth {depth} exceeds the maximum of {max}.")
        }
        LimitViolation::EntrySize { size, max } => {
            format!("Metadata value size {size} exceeds the maximum of {max} bytes.")
        }
        LimitViolation::ContainerSize { size, max } => {
            format!("Metadata size {size} exceeds the maximum of {max} bytes.")
        }
        LimitViolation::Entries { count, max } => {
            format!("Metadata entry count {count} exceeds the maximum of {max}.")
        }
    }
}
