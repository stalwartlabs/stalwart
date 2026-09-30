/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    MetadataSupport,
    patch::{MetadataPatches, Patch, PatchValue},
    violation::{Rule, Violation, Violations, namespace_path},
    write::MetadataUpdate,
};
use jmap_proto::{
    error::set::SetError,
    object::metadata::{MetadataProperty, MetadataRoot},
};
use store::write::metadata::MetadataBuf;
use types::metadata::{Namespace, NamespaceError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataAccess {
    pub may_write_shared: bool,
    pub may_read: bool,
}

impl MetadataAccess {
    pub const FULL: Self = MetadataAccess {
        may_write_shared: true,
        may_read: true,
    };
}

#[derive(Debug)]
pub struct ValidatedPatches {
    pub(super) support: MetadataSupport,
    pub(super) shared: Vec<Patch>,
    pub(super) private: Vec<Patch>,
}

impl MetadataPatches {
    pub fn validate<P: MetadataProperty>(
        self,
        support: &MetadataSupport,
        access: MetadataAccess,
    ) -> Result<ValidatedPatches, SetError<P>> {
        let mut patches = self.patches;
        patches.sort_unstable_by(|a, b| a.key.cmp_path(&b.key));

        let mut violations = Violations::default();
        if let Some([first, second]) = patches
            .windows(2)
            .find(|pair| matches!(pair, [first, second] if first.key.is_prefix_of(&second.key)))
        {
            violations.report(Rule::Syntax, || Violation {
                rule: Rule::Syntax,
                root: second.key.root,
                path: Some(second.key.to_path()),
                description: format!(
                    "Patch {} overlaps with patch {}.",
                    second.key.to_path(),
                    first.key.to_path()
                )
                .into(),
            });
            return Err(violations.into_set_error());
        }

        let private = patches
            .split_off(patches.partition_point(|patch| patch.key.root == MetadataRoot::Shared));
        let shared = patches;

        for (root, patches, is_allowed) in [
            (
                MetadataRoot::Shared,
                &shared,
                support.writable && access.may_write_shared,
            ),
            (MetadataRoot::Private, &private, access.may_read),
        ] {
            if !patches.is_empty() && !is_allowed {
                violations.report(Rule::Forbidden, || Violation {
                    rule: Rule::Forbidden,
                    root,
                    path: None,
                    description: format!("Not allowed to modify {}.", root.as_str()).into(),
                });
            }
        }
        if !private.is_empty() && !support.private {
            violations.report(Rule::Private, || Violation {
                rule: Rule::Private,
                root: MetadataRoot::Private,
                path: None,
                description: "Private metadata is not supported on this object.".into(),
            });
        }
        for patch in shared.iter().chain(&private) {
            check_namespaces(support, patch, &mut violations);
        }

        if violations.is_empty() {
            Ok(ValidatedPatches {
                support: *support,
                shared,
                private,
            })
        } else {
            Err(violations.into_set_error())
        }
    }

    pub fn apply<P: MetadataProperty>(
        self,
        support: &MetadataSupport,
        access: MetadataAccess,
        shared: Option<&MetadataBuf>,
        private: Option<&MetadataBuf>,
    ) -> Result<MetadataUpdate, SetError<P>> {
        self.validate(support, access)?.apply(shared, private)
    }
}

impl ValidatedPatches {
    pub fn has_shared(&self) -> bool {
        !self.shared.is_empty()
    }

    pub fn has_private(&self) -> bool {
        !self.private.is_empty()
    }
}

fn check_namespaces(support: &MetadataSupport, patch: &Patch, violations: &mut Violations) {
    let root = patch.key.root;
    let mut report = |name: &str, description: &'static str| {
        violations.report(Rule::Namespace, || Violation {
            rule: Rule::Namespace,
            root,
            path: Some(namespace_path(root, name)),
            description: description.into(),
        })
    };

    match (patch.key.namespace.as_deref(), &patch.value) {
        (None, PatchValue::Replace(members)) => {
            for member in members {
                match Namespace::parse(&member.namespace) {
                    Ok(_) => {}
                    Err(NamespaceError::Unregistered) => {
                        report(&member.namespace, "Unsupported namespace.")
                    }
                    Err(NamespaceError::Invalid) => {
                        report(&member.namespace, "Invalid namespace name.")
                    }
                }
            }
        }
        (Some(name), PatchValue::Remove) if !patch.key.is_deep() => {
            if let Err(NamespaceError::Invalid) = Namespace::parse(name) {
                report(name, "Invalid namespace name.");
            }
        }
        (Some(name), _) => match Namespace::parse(name) {
            Ok(namespace) if support.is_supported(&namespace, root) => {}
            Ok(_) | Err(NamespaceError::Unregistered) => report(name, "Unsupported namespace."),
            Err(NamespaceError::Invalid) => report(name, "Invalid namespace name."),
        },
        (None, _) => {}
    }
}
