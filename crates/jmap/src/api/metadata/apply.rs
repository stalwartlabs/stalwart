/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MetadataSupport, metadata_scope,
    patch::{InvalidValue, Patch, PatchKey, PatchValue},
    validate::ValidatedPatches,
    violation::{Rule, Violation, Violations, limit_description, namespace_path},
    write::{ContainerChange, MetadataUpdate},
};
use common::storage::metadata::StoredContainer;
use jmap_proto::{
    error::set::SetError,
    object::metadata::{MetadataProperty, MetadataRoot},
};
use jmap_tools::{JsonPointer, JsonPointerHandler, Null, Value};
use store::write::metadata::MetadataBuf;
use types::metadata::{
    EncodedJson, JsonError, LimitViolation, MetadataBuilder, MetadataEdit, MetadataView, Namespace,
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

        let (keys, values): (Vec<PatchKey>, Vec<PatchValue>) = expand(patches)
            .into_iter()
            .map(|patch| (patch.key, patch.value))
            .unzip();
        let edit = if values.iter().all(PatchValue::is_removal) {
            MetadataEdit::RemovalOnly
        } else {
            MetadataEdit::Write
        };
        let view = current.map(MetadataBuf::view);
        let mut builder = view
            .as_ref()
            .map(MetadataBuilder::from_view)
            .unwrap_or_default();

        let mut items = keys.iter().zip(values).peekable();
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
                    if let Ok(namespace) = Namespace::parse(name) {
                        builder.remove_jmap(&namespace);
                    }
                }
                (Some(name), PatchValue::Set(value)) => {
                    self.set_namespace(&mut builder, name, value, view.as_ref(), violations)
                }
                (_, _) => {}
            }
        }

        self.finish(builder, view, current, edit, violations)
    }

    fn set_namespace<'x>(
        &self,
        builder: &mut MetadataBuilder<'x>,
        name: &'x str,
        value: Result<EncodedJson, InvalidValue>,
        stored: Option<&MetadataView<'_>>,
        violations: &mut Violations,
    ) {
        let Some(namespace) = self.namespace(name, violations) else {
            return;
        };
        if self.support.is_supported(&namespace, self.root) {
            if let Some(value) = self.check_value(name, value, violations) {
                builder.set_jmap(namespace, value);
            }
            return;
        }

        match (
            value,
            stored.and_then(|stored| stored.jmap_namespace(&namespace)),
        ) {
            (Ok(value), Some(stored)) if value.as_bytes() == stored.as_bytes() => {
                builder.set_jmap(namespace, value);
            }
            (_, Some(_)) => self.report_namespace(
                name,
                "Withdrawn namespaces can only be removed or kept unchanged.",
                violations,
            ),
            (_, None) => self.report_namespace(name, "Unsupported namespace.", violations),
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

            EncodedJson::encode_namespace(&value)
        };

        let patched = patched.map_err(|error| InvalidValue {
            error,
            depth: self
                .support
                .limits
                .max_depth
                .map_or(0, |max| max.saturating_add(1)),
        });
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
        let next = builder.encode();
        let (previous_len, previous_entries) = view
            .as_ref()
            .map_or((0, 0), |view| (view.as_bytes().len(), view.len()));
        match (&next, &view) {
            (Some(next), Some(view)) if next.as_bytes() == view.as_bytes() => return None,
            (None, None) => return None,
            _ => {}
        }

        if let Some(next) = &next {
            let limits = &self.support.limits;
            let max_size = limits.max_container_size(metadata_scope(self.root));
            if next.len() > max_size && next.len() > previous_len {
                self.report_container(
                    Rule::ContainerSize,
                    LimitViolation::ContainerSize {
                        size: next.len(),
                        max: max_size,
                    },
                    violations,
                );
            }
            if next.entries() > limits.max_entries && next.entries() > previous_entries {
                self.report_container(
                    Rule::Entries,
                    LimitViolation::Entries {
                        count: next.entries(),
                        max: limits.max_entries,
                    },
                    violations,
                );
            }
        }

        Some(ContainerChange::new(
            current.map(StoredContainer::from),
            next,
            edit,
        ))
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

fn expand(patches: Vec<Patch>) -> Vec<Patch> {
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
