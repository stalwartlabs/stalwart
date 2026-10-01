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
        metadata::{ContainerChange, MetadataWrite},
    },
};
use dav_proto::schema::{
    property::{DavProperty, DavValue, WebDavProperty},
    request::{DavPropertyValue, PropertyUpdateOp},
    response::BaseCondition,
};
use hyper::StatusCode;
use std::{borrow::Cow, mem};
use store::write::PendingId;
use types::metadata::{
    EncodedMetadata, MetadataBuilder, MetadataKinds, MetadataScope, MetadataView, XmlError,
    XmlName, XmlNode, XmlValue,
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
        value: XmlValue<'static>,
    },
    Remove {
        property: DavProperty,
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
    pub fn take(ops: &mut Vec<PropertyUpdateOp>, display_name: DisplayName) -> Self {
        let mut dead = Vec::new();
        ops.retain_mut(|op| {
            let taken = match op {
                PropertyUpdateOp::Set(value) => take_set(value, display_name),
                PropertyUpdateOp::Remove(property) => take_remove(property, display_name),
            };
            taken.map(|op| dead.push(op)).is_none()
        });
        DeadPatch { ops: dead }
    }

    pub fn take_values(values: &mut Vec<DavPropertyValue>, display_name: DisplayName) -> Self {
        let mut dead = Vec::new();
        values.retain_mut(|value| {
            take_set(value, display_name)
                .map(|op| dead.push(op))
                .is_none()
        });
        DeadPatch { ops: dead }
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
        let previous_entries = builder.len();
        let previous_len = current_view
            .as_ref()
            .map_or(0, |current| current.as_bytes().len());
        let entry_bound = limits.entry_bound(previous_entries);

        let ops = self.ops;
        let mut outcomes = Vec::with_capacity(ops.len());
        let mut is_full = false;
        let mut pending_removes = ops
            .iter()
            .filter(|op| matches!(op, DeadOp::Remove { .. }))
            .count();
        for op in &ops {
            outcomes.push(match op {
                DeadOp::Set { .. } if is_full => Outcome::StorageFull,
                DeadOp::Set { property, value } => {
                    if is_live_display_name(property) && text_len(value) > live_property_size {
                        Outcome::TooLarge
                    } else {
                        match builder.set_dav(dead_name(property), value) {
                            Ok(_) if entry_bound.check(builder.len(), pending_removes).is_err() => {
                                builder.remove_dav(&dead_name(property));
                                is_full = true;
                                Outcome::StorageFull
                            }
                            Ok(size) if limits.check_entry_size(size).is_ok() => Outcome::Set,
                            Ok(_) => Outcome::TooLarge,
                            Err(err) => Outcome::Invalid(err),
                        }
                    }
                }
                DeadOp::Remove { property } => {
                    pending_removes = pending_removes.saturating_sub(1);
                    builder.remove_dav(&dead_name(property));
                    Outcome::Removed
                }
            });
        }

        let mut change = None;
        if outcomes.iter().all(|outcome| outcome.is_success()) {
            change = ContainerChange::new(current.as_ref(), builder.encode(), builder.edit());
            let failure = match &change {
                Some(change)
                    if change.next().is_some_and(|next| {
                        limits
                            .check_edit(MetadataScope::Shared, previous_len, previous_entries, next)
                            .is_err()
                    }) =>
                {
                    Some(Outcome::StorageFull)
                }
                Some(change) if !server.has_metadata_quota(&owner, change).await? => {
                    Some(Outcome::OverQuota)
                }
                _ => None,
            };
            if let Some(failure) = failure {
                for outcome in &mut outcomes {
                    if *outcome == Outcome::Set {
                        *outcome = failure;
                    }
                }
            }
        }
        drop(builder);

        let is_success = outcomes.iter().all(|outcome| outcome.is_success());
        for (op, outcome) in ops.into_iter().zip(outcomes) {
            outcome.report(op.into_property(), items);
        }
        if !is_success {
            return Ok(None);
        }

        let view = match &change {
            Some(change) => change.next().map(EncodedMetadata::view),
            None => current_view,
        };
        let kinds = view
            .as_ref()
            .map_or(MetadataKinds::NONE, MetadataView::kinds);
        let file_presence = view
            .as_ref()
            .map_or(FilePresence::NONE, FilePresence::from_view);
        Ok(Some(DeadWrite {
            write: change.map(|change| change.into_write(&owner, target.collection, target.log)),
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
                items.insert_ok(property);
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

fn take_set(value: &mut DavPropertyValue, display_name: DisplayName) -> Option<DeadOp> {
    let dead = match (&value.property, &mut value.value, display_name) {
        (DavProperty::Dead(_), DavValue::Dead(dead), _) => mem::take(dead.as_mut()),
        (
            DavProperty::WebDav(WebDavProperty::DisplayName),
            DavValue::String(text),
            DisplayName::Stored,
        ) => text_value(mem::take(text)),
        (DavProperty::WebDav(WebDavProperty::DisplayName), DavValue::Null, DisplayName::Stored) => {
            XmlValue::default()
        }
        _ => return None,
    };
    Some(DeadOp::Set {
        property: take_property(&mut value.property),
        value: dead,
    })
}

fn take_remove(property: &mut DavProperty, display_name: DisplayName) -> Option<DeadOp> {
    match (&*property, display_name) {
        (DavProperty::Dead(_), _)
        | (DavProperty::WebDav(WebDavProperty::DisplayName), DisplayName::Stored) => {
            Some(DeadOp::Remove {
                property: take_property(property),
            })
        }
        _ => None,
    }
}

fn take_property(property: &mut DavProperty) -> DavProperty {
    mem::replace(property, DavProperty::WebDav(WebDavProperty::GetETag))
}

fn dead_name(property: &DavProperty) -> XmlName<'_> {
    match property {
        DavProperty::Dead(name) => XmlName::borrowed(name.namespace(), name.name()),
        _ => DISPLAY_NAME_PROPERTY,
    }
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
