/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::DeadTarget;
use crate::PropStatBuilder;
use common::{
    Server,
    storage::{
        dav::{DISPLAY_NAME_PROPERTY, FilePresence},
        metadata::{MetadataWrite, StoredContainer},
    },
};
use dav_proto::schema::{
    property::{DavProperty, DavValue, WebDavProperty},
    request::{DavPropertyValue, PropertyUpdate},
    response::BaseCondition,
};
use hyper::StatusCode;
use std::{borrow::Cow, mem};
use store::write::PendingId;
use types::metadata::{
    MetadataBuilder, MetadataKinds, MetadataScope, XmlError, XmlName, XmlNode, XmlValue,
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DisplayName {
    Live,
    Stored,
}

#[derive(Debug)]
enum DeadOp {
    Set {
        property: DavProperty,
        name: XmlName<'static>,
        value: XmlValue<'static>,
    },
    Remove {
        property: DavProperty,
        name: XmlName<'static>,
    },
}

#[derive(Debug, Default)]
pub(crate) struct DeadPatch {
    ops: Vec<DeadOp>,
}

#[derive(Debug)]
pub(crate) struct DeadWrite {
    pub write: Option<MetadataWrite>,
    pub kinds: MetadataKinds,
    pub file_presence: FilePresence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Set,
    Removed,
    TooLarge,
    Invalid(XmlError),
    StorageFull,
    OverQuota,
}

impl DeadPatch {
    pub fn take(update: &mut PropertyUpdate, display_name: DisplayName) -> Self {
        let mut sets = take_sets(&mut update.set, display_name);
        let mut removes = take_removes(&mut update.remove, display_name);
        let ops = if update.set_first {
            sets.append(&mut removes);
            sets
        } else {
            removes.append(&mut sets);
            removes
        };
        DeadPatch { ops }
    }

    pub fn take_values(values: &mut Vec<DavPropertyValue>, display_name: DisplayName) -> Self {
        DeadPatch {
            ops: take_sets(values, display_name),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    fn fail(self, items: &mut PropStatBuilder) {
        for op in self.ops {
            items.insert_with_status(op.into_property(), StatusCode::FAILED_DEPENDENCY);
        }
    }

    pub async fn apply(
        self,
        server: &Server,
        target: DeadTarget,
        items: &mut PropStatBuilder,
    ) -> trc::Result<Option<DeadWrite>> {
        if self.is_empty() {
            Ok(None)
        } else if items.has_errors() {
            self.fail(items);
            Ok(None)
        } else {
            self.prepare(server, target, items).await
        }
    }

    async fn prepare(
        self,
        server: &Server,
        target: DeadTarget,
        items: &mut PropStatBuilder,
    ) -> trc::Result<Option<DeadWrite>> {
        let owner = server.account(target.account_id).await?;
        let current = match target.document_id {
            PendingId::Assigned(document_id) if !target.kinds.is_empty() => {
                server
                    .metadata_container(target.account_id, target.collection, document_id)
                    .await?
            }
            _ => None,
        };
        let current_view = current.as_ref().map(|current| current.view());
        let mut builder = current_view
            .as_ref()
            .map_or_else(MetadataBuilder::new, MetadataBuilder::from_view);
        let limits = server.core.metadata.limits();
        let live_property_size = server.core.groupware.live_property_size;

        let mut results = Vec::with_capacity(self.ops.len());
        let mut has_sets = false;
        for op in self.ops {
            match op {
                DeadOp::Set {
                    property,
                    name,
                    value,
                } => {
                    has_sets = true;
                    let outcome = if is_live_display_name(&property)
                        && text_len(&value) > live_property_size
                    {
                        Outcome::TooLarge
                    } else {
                        match builder.set_dav(name, &value) {
                            Ok(size) if limits.check_entry_size(size).is_ok() => Outcome::Set,
                            Ok(_) => Outcome::TooLarge,
                            Err(err) => Outcome::Invalid(err),
                        }
                    };
                    results.push((property, outcome));
                }
                DeadOp::Remove { property, name } => {
                    builder.remove_dav(&name);
                    results.push((property, Outcome::Removed));
                }
            }
        }

        let previous = current.as_ref().map(StoredContainer::from);
        let mut next = None;
        if results.iter().all(|(_, outcome)| outcome.is_success()) {
            let edit = builder.edit();
            next = builder.encode();
            let failure = match &next {
                Some(encoded)
                    if has_sets
                        && limits
                            .check_container(MetadataScope::Shared, encoded)
                            .is_err() =>
                {
                    Some(Outcome::StorageFull)
                }
                Some(encoded)
                    if !server
                        .has_metadata_quota(&owner, edit, previous.as_ref(), encoded)
                        .await? =>
                {
                    Some(Outcome::OverQuota)
                }
                _ => None,
            };
            if let Some(failure) = failure {
                for (_, outcome) in &mut results {
                    if *outcome == Outcome::Set {
                        *outcome = failure;
                    }
                }
            }
        }

        let is_success = results.iter().all(|(_, outcome)| outcome.is_success());
        for (property, outcome) in results {
            outcome.report(property, items);
        }
        if !is_success {
            return Ok(None);
        }

        let is_unchanged = match (&current_view, &next) {
            (Some(current), Some(next)) => current.as_bytes() == next.as_bytes(),
            (None, None) => true,
            _ => false,
        };
        let kinds = next
            .as_ref()
            .map_or(MetadataKinds::NONE, |next| next.kinds());
        let file_presence = next.as_ref().map_or(FilePresence::NONE, |next| {
            FilePresence::from_view(&next.view())
        });
        Ok(Some(DeadWrite {
            write: (!is_unchanged).then(|| MetadataWrite {
                account_id: target.account_id,
                tenant_id: owner.id_tenant,
                collection: target.collection,
                document_id: target.document_id,
                previous,
                next,
                log: target.log,
            }),
            kinds,
            file_presence,
        }))
    }
}

impl DeadOp {
    fn into_property(self) -> DavProperty {
        match self {
            DeadOp::Set { property, .. } | DeadOp::Remove { property, .. } => property,
        }
    }
}

impl Outcome {
    fn is_success(self) -> bool {
        matches!(self, Outcome::Set | Outcome::Removed)
    }

    fn report(self, property: DavProperty, items: &mut PropStatBuilder) {
        match self {
            Outcome::Set => {
                items.insert_ok(property);
            }
            Outcome::Removed => {
                items.insert_with_status(property, StatusCode::NO_CONTENT);
            }
            Outcome::TooLarge => {
                items.insert_error_with_description(
                    property,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Property value is too long",
                );
            }
            Outcome::Invalid(err) => {
                items.insert_error_with_description(
                    property,
                    StatusCode::CONFLICT,
                    err.to_string(),
                );
            }
            Outcome::StorageFull => {
                items.insert_error_with_description(
                    property,
                    StatusCode::INSUFFICIENT_STORAGE,
                    "Property storage limit exceeded",
                );
            }
            Outcome::OverQuota => {
                items.insert_precondition_failed(
                    property,
                    StatusCode::INSUFFICIENT_STORAGE,
                    BaseCondition::QuotaNotExceeded,
                );
            }
        }
    }
}

fn take_sets(values: &mut Vec<DavPropertyValue>, display_name: DisplayName) -> Vec<DeadOp> {
    let mut ops = Vec::new();
    values.retain_mut(|value| {
        match (&value.property, &mut value.value, display_name) {
            (DavProperty::Dead(name), DavValue::Dead(dead), _) => {
                ops.push(DeadOp::Set {
                    property: value.property.clone(),
                    name: name.clone(),
                    value: mem::take(dead.as_mut()),
                });
            }
            (
                DavProperty::WebDav(WebDavProperty::DisplayName),
                DavValue::String(text),
                DisplayName::Stored,
            ) => {
                ops.push(DeadOp::Set {
                    property: value.property.clone(),
                    name: DISPLAY_NAME_PROPERTY,
                    value: text_value(mem::take(text)),
                });
            }
            (
                DavProperty::WebDav(WebDavProperty::DisplayName),
                DavValue::Null,
                DisplayName::Stored,
            ) => {
                ops.push(DeadOp::Set {
                    property: value.property.clone(),
                    name: DISPLAY_NAME_PROPERTY,
                    value: XmlValue::default(),
                });
            }
            _ => return true,
        }
        false
    });
    ops
}

fn take_removes(properties: &mut Vec<DavProperty>, display_name: DisplayName) -> Vec<DeadOp> {
    let mut ops = Vec::new();
    properties.retain(|property| {
        let name = match (property, display_name) {
            (DavProperty::Dead(name), _) => name.clone(),
            (DavProperty::WebDav(WebDavProperty::DisplayName), DisplayName::Stored) => {
                DISPLAY_NAME_PROPERTY
            }
            _ => return true,
        };
        ops.push(DeadOp::Remove {
            property: property.clone(),
            name,
        });
        false
    });
    ops
}

fn text_value(text: String) -> XmlValue<'static> {
    XmlValue {
        children: if text.is_empty() {
            Vec::new()
        } else {
            vec![XmlNode::Text(Cow::Owned(text))]
        },
        ..Default::default()
    }
}

fn is_live_display_name(property: &DavProperty) -> bool {
    matches!(property, DavProperty::WebDav(WebDavProperty::DisplayName))
}

fn text_len(value: &XmlValue<'_>) -> usize {
    value
        .children
        .iter()
        .map(|child| match child {
            XmlNode::Text(text) => text.len(),
            XmlNode::Element(_) => 0,
        })
        .sum()
}
