/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MetadataSupport, metadata_scope,
    patch::{InvalidValue, Patch, PatchKey, PatchValue, value_depth},
    validate::ValidatedPatches,
    violation::{Rule, Violation, Violations, limit_description, namespace_path},
    write::MetadataUpdate,
};
use common::storage::metadata::ContainerChange;
use jmap_proto::{
    error::set::SetError,
    object::metadata::{MetadataProperty, MetadataRoot},
};
use jmap_tools::{JsonPointer, JsonPointerHandler, Null, Value};
use std::mem;
use store::write::metadata::MetadataBuf;
use types::metadata::{
    EncodedJson, JsonError, JsonKind, JsonView, LimitViolation, MetadataBuilder, MetadataEdit,
    MetadataView, Namespace,
};

struct RootContext<'x> {
    support: &'x MetadataSupport,
    root: MetadataRoot,
}

impl ValidatedPatches {
    pub fn apply<P: MetadataProperty>(
        self,
        shared: Option<&MetadataBuf>,
        private: Option<&MetadataBuf>,
    ) -> Result<MetadataUpdate, SetError<P>> {
        let mut violations = Violations::default();
        let shared = RootContext {
            support: &self.support,
            root: MetadataRoot::Shared,
        }
        .apply(self.shared, shared, &mut violations);
        let private = RootContext {
            support: &self.support,
            root: MetadataRoot::Private,
        }
        .apply(self.private, private, &mut violations);

        if violations.is_empty() {
            Ok(MetadataUpdate::new(shared, private))
        } else {
            Err(violations.into_set_error())
        }
    }
}

impl RootContext<'_> {
    fn apply(
        &self,
        patches: Vec<Patch>,
        current: Option<&MetadataBuf>,
        violations: &mut Violations,
    ) -> Option<ContainerChange> {
        if patches.is_empty() {
            return None;
        }

        let mut patches = expand(patches);
        let edit = if patches.iter().all(|patch| patch.value.is_removal()) {
            MetadataEdit::RemovalOnly
        } else {
            MetadataEdit::Write
        };
        let view = current.map(MetadataBuf::view);
        let mut builder = view
            .as_ref()
            .map(MetadataBuilder::from_view)
            .unwrap_or_default();
        let entry_bound = self
            .support
            .limits
            .entry_bound(view.as_ref().map_or(0, MetadataView::len));
        let mut removals = patches
            .iter()
            .filter(|patch| !patch.key.is_deep() && matches!(patch.value, PatchValue::Remove))
            .count();
        let mut is_over_limit = false;

        let mut items = patches
            .iter_mut()
            .map(|patch| {
                let value = mem::replace(&mut patch.value, PatchValue::Clear);
                (&patch.key, value)
            })
            .peekable();
        while let Some((key, value)) = items.next() {
            match (key.namespace.as_deref(), value) {
                (None, PatchValue::Clear) => builder.clear_jmap(),
                (Some(name), value) if key.is_deep() => {
                    let mut group = vec![(key, value)];
                    while let Some(item) = items.next_if(|(next, _)| {
                        next.is_deep() && next.namespace.as_deref() == Some(name)
                    }) {
                        group.push(item);
                    }
                    self.patch_namespace(&mut builder, name, &group, violations);
                }
                (Some(name), PatchValue::Remove) => {
                    removals = removals.saturating_sub(1);
                    if let Ok(namespace) = Namespace::parse(name) {
                        builder.remove_jmap(&namespace);
                    }
                }
                (Some(name), PatchValue::Set(value)) => {
                    if let Some((namespace, value)) =
                        self.namespace_value(name, value, view.as_ref(), violations)
                        && !is_over_limit
                    {
                        builder.set_jmap(namespace, value);
                        if let Err(violation) = entry_bound.check(builder.len(), removals) {
                            is_over_limit = true;
                            self.report_container(Rule::Entries, violation, violations);
                        }
                    }
                }
                (_, _) => {}
            }
        }

        if is_over_limit {
            None
        } else {
            self.finish(builder, view, current, edit, violations)
        }
    }

    fn namespace_value<'x>(
        &self,
        name: &'x str,
        value: Result<EncodedJson, InvalidValue>,
        stored: Option<&MetadataView<'_>>,
        violations: &mut Violations,
    ) -> Option<(Namespace<'x>, EncodedJson)> {
        let namespace = self.namespace(name, violations)?;
        if self.support.is_supported(&namespace, self.root) {
            return self
                .check_value(name, value, violations)
                .map(|value| (namespace, value));
        }

        match (
            value,
            stored.and_then(|stored| stored.jmap_namespace(&namespace)),
        ) {
            (Ok(value), Some(stored)) if same_json(value.view(), stored) => {
                let kept = if value.as_bytes() == stored.as_bytes() {
                    value
                } else {
                    stored
                        .to_value::<Null, Null>()
                        .and_then(|stored| EncodedJson::encode(&stored).ok())
                        .unwrap_or(value)
                };
                Some((namespace, kept))
            }
            (_, Some(_)) => {
                self.report_namespace(
                    name,
                    "Withdrawn namespaces can only be removed or kept unchanged.",
                    violations,
                );
                None
            }
            (_, None) => {
                self.report_namespace(name, "Unsupported namespace.", violations);
                None
            }
        }
    }

    fn patch_namespace<'x>(
        &self,
        builder: &mut MetadataBuilder<'x>,
        name: &'x str,
        group: &[(&PatchKey, PatchValue)],
        violations: &mut Violations,
    ) {
        let Some(namespace) = self.namespace(name, violations) else {
            return;
        };
        let patched = {
            let Some(mut value) = builder
                .jmap(&namespace)
                .and_then(|view| view.to_value::<Null, Null>())
            else {
                if let Some((key, _)) = group.first() {
                    self.report_parent(key, "The namespace does not exist.", violations);
                }
                return;
            };

            for (key, patch) in group {
                let patch = match patch {
                    PatchValue::Set(Ok(encoded)) => encoded.view().to_value().unwrap_or_default(),
                    PatchValue::Set(Err(invalid)) => {
                        let depth = u32::try_from(key.pointer.len())
                            .unwrap_or(u32::MAX)
                            .saturating_add(invalid.depth);
                        self.report_invalid(name, InvalidValue { depth, ..*invalid }, violations);
                        Value::Null
                    }
                    PatchValue::Remove | PatchValue::Replace(_) | PatchValue::Clear => Value::Null,
                };
                if !value.patch_jptr(key.pointer.iter(), patch) {
                    self.report_parent(
                        key,
                        "A parent of the patched value does not exist or is not an object.",
                        violations,
                    );
                }
            }

            EncodedJson::encode_namespace(&value).map_err(|error| InvalidValue {
                error,
                depth: value_depth(&value, 0),
            })
        };

        if let Some(value) = self.check_value(name, patched, violations) {
            builder.set_jmap(namespace, value);
        }
    }

    fn namespace<'x>(&self, name: &'x str, violations: &mut Violations) -> Option<Namespace<'x>> {
        let namespace = Namespace::parse(name).ok();
        if namespace.is_none() {
            self.report_namespace(name, "Unsupported namespace.", violations);
        }
        namespace
    }

    fn check_value(
        &self,
        name: &str,
        value: Result<EncodedJson, InvalidValue>,
        violations: &mut Violations,
    ) -> Option<EncodedJson> {
        match value {
            Ok(value) => {
                let limits = &self.support.limits;
                if let Err(violation) = limits.check_depth(value.depth()) {
                    self.report_limit(Rule::Depth, name, violation, violations);
                }
                if let Err(violation) = limits.check_entry_size(value.len()) {
                    self.report_limit(Rule::EntrySize, name, violation, violations);
                }
                Some(value)
            }
            Err(invalid) => {
                self.report_invalid(name, invalid, violations);
                None
            }
        }
    }

    fn finish(
        &self,
        builder: MetadataBuilder<'_>,
        view: Option<MetadataView<'_>>,
        current: Option<&MetadataBuf>,
        edit: MetadataEdit,
        violations: &mut Violations,
    ) -> Option<ContainerChange> {
        let change = ContainerChange::new(current, builder.encode(), edit)?;
        if let Some(next) = change.next() {
            let (previous_len, previous_entries) = view
                .as_ref()
                .map_or((0, 0), |view| (view.as_bytes().len(), view.len()));
            if let Err(violation) = self.support.limits.check_edit(
                metadata_scope(self.root),
                previous_len,
                previous_entries,
                next,
            ) {
                let rule = match violation {
                    LimitViolation::Entries { .. } => Rule::Entries,
                    _ => Rule::ContainerSize,
                };
                self.report_container(rule, violation, violations);
            }
        }
        Some(change)
    }

    fn report_namespace(&self, name: &str, description: &'static str, violations: &mut Violations) {
        violations.report(Rule::Namespace, || Violation {
            rule: Rule::Namespace,
            root: self.root,
            path: Some(namespace_path(self.root, name)),
            description: description.into(),
        });
    }

    fn report_parent(
        &self,
        key: &PatchKey,
        description: &'static str,
        violations: &mut Violations,
    ) {
        violations.report(Rule::Parent, || Violation {
            rule: Rule::Parent,
            root: self.root,
            path: Some(key.to_path()),
            description: description.into(),
        });
    }

    fn report_limit(
        &self,
        rule: Rule,
        name: &str,
        violation: LimitViolation,
        violations: &mut Violations,
    ) {
        violations.report(rule, || Violation {
            rule,
            root: self.root,
            path: Some(namespace_path(self.root, name)),
            description: limit_description(violation).into(),
        });
    }

    fn report_container(&self, rule: Rule, violation: LimitViolation, violations: &mut Violations) {
        violations.report(rule, || Violation {
            rule,
            root: self.root,
            path: None,
            description: limit_description(violation).into(),
        });
    }

    fn report_invalid(&self, name: &str, invalid: InvalidValue, violations: &mut Violations) {
        if let Err(violation) = self.support.limits.check_depth(invalid.depth) {
            self.report_limit(Rule::Depth, name, violation, violations);
        }
        let (rule, description) = match invalid.error {
            JsonError::ControlCharacter => (
                Rule::ControlCharacter,
                "Metadata keys and values cannot contain control characters.",
            ),
            JsonError::NestingTooDeep => (Rule::Depth, "Metadata value is nested too deeply."),
            JsonError::NotAnObject => (Rule::Namespace, "Namespace values must be objects."),
        };
        violations.report(rule, || Violation {
            rule,
            root: self.root,
            path: Some(namespace_path(self.root, name)),
            description: description.into(),
        });
    }
}

fn same_json(left: JsonView<'_>, right: JsonView<'_>) -> bool {
    if left.as_bytes() == right.as_bytes() {
        return true;
    }
    match (left.kind(), right.kind()) {
        (JsonKind::Object, JsonKind::Object) => {
            let mut left = left.members().collect::<Vec<_>>();
            let mut right = right.members().collect::<Vec<_>>();
            left.len() == right.len() && {
                left.sort_by_key(|(key, _)| *key);
                right.sort_by_key(|(key, _)| *key);
                left.into_iter()
                    .zip(right)
                    .all(|((left_key, left), (right_key, right))| {
                        left_key == right_key && same_json(left, right)
                    })
            }
        }
        (JsonKind::Array, JsonKind::Array) => {
            left.len() == right.len()
                && left
                    .items()
                    .zip(right.items())
                    .all(|(left, right)| same_json(left, right))
        }
        (JsonKind::Number, JsonKind::Number) => match (left.as_i64(), right.as_i64()) {
            (Some(left), Some(right)) => left == right,
            _ => match (left.as_u64(), right.as_u64()) {
                (Some(left), Some(right)) => left == right,
                _ => left.as_f64() == right.as_f64(),
            },
        },
        (JsonKind::String, JsonKind::String) => left.as_str() == right.as_str(),
        _ => false,
    }
}

fn expand(patches: Vec<Patch>) -> Vec<Patch> {
    if !patches
        .iter()
        .any(|patch| matches!(patch.value, PatchValue::Replace(_)))
    {
        return patches;
    }
    let mut expanded = Vec::with_capacity(patches.len());
    for patch in patches {
        match patch.value {
            PatchValue::Replace(members) => {
                let root = patch.key.root;
                expanded.reserve(members.len() + 1);
                expanded.push(Patch {
                    key: patch.key,
                    value: PatchValue::Clear,
                });
                expanded.extend(members.into_iter().map(|member| Patch {
                    key: PatchKey {
                        root,
                        namespace: Some(member.namespace),
                        pointer: JsonPointer::new(Vec::new()),
                    },
                    value: PatchValue::Set(member.value),
                }));
            }
            value => expanded.push(Patch {
                key: patch.key,
                value,
            }),
        }
    }
    expanded
}
