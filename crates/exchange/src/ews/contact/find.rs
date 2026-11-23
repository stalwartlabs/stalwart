/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::ews::filter::{FilterProp, PropValue};
use exchange_proto::ews::{
    contact::{ContactProps, ContactText},
    schema::UnindexedField,
    types::path::Path,
};
use jiff::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContactProp {
    Text(ContactText),
    LastModified,
}

impl FilterProp for ContactProp {
    fn of_path(path: &Path<'_>) -> Option<Self> {
        match path {
            Path::Field(UnindexedField::ItemLastModifiedTime) => Some(ContactProp::LastModified),
            path => ContactText::of_path(path).map(ContactProp::Text),
        }
    }
}

impl ContactProp {
    pub(super) fn value<'p>(
        self,
        props: ContactProps<'p>,
        modified_at: impl FnOnce() -> Option<i64>,
    ) -> Option<PropValue<'p>> {
        match self {
            ContactProp::Text(field) => props.field_text(field).map(PropValue::Text),
            ContactProp::LastModified => props
                .last_modified()
                .map(|time| time.to_utc().0.0)
                .or_else(modified_at)
                .and_then(|seconds| Timestamp::from_second(seconds).ok())
                .map(PropValue::Time),
        }
    }
}
