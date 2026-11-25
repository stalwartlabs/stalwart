/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use email::message::ingest::IngestedEmail;
use jmap_proto::{
    error::set::SetError,
    object::email::{EmailProperty, EmailValue},
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map, Value};
use types::{id::Id, keyword::Keyword};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/jmap/src/email/contention.rs"]
mod contention;
#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/jmap/src/email/patch.rs"]
mod patch;
pub mod copy;
pub mod get;
mod grouped;
pub mod import;
pub mod parse;
pub mod query;
pub mod set;
pub mod snippet;

fn ingested_into_object(email: IngestedEmail) -> Map<'static, EmailProperty, EmailValue> {
    Map::with_capacity(3)
        .with_key_value(
            EmailProperty::Id,
            Id::from_parts(email.thread_id, email.document_id),
        )
        .with_key_value(EmailProperty::ThreadId, Id::from(email.thread_id))
        .with_key_value(EmailProperty::BlobId, email.blob_id)
        .with_key_value(EmailProperty::Size, email.size)
}

pub(crate) enum PatchResult<'x> {
    SetKeyword(&'x Keyword),
    RemoveKeyword(&'x Keyword),
    AddMailbox(u32),
    RemoveMailbox(u32),
    Invalid,
    InvalidValue,
}

pub(crate) fn parse_keywords<'x>(
    keywords: Value<'x, EmailProperty, EmailValue>,
) -> Result<Vec<Keyword>, SetError<EmailProperty>> {
    keywords
        .into_expanded_boolean_set()
        .map(|keyword| keyword.try_into_property()?.try_into_keyword())
        .collect::<Option<Vec<_>>>()
        .ok_or_else(invalid_keywords)
}

pub(crate) fn invalid_keywords() -> SetError<EmailProperty> {
    SetError::invalid_properties()
        .with_property(EmailProperty::Keywords)
        .with_description("Invalid keyword.")
}

pub(crate) fn handle_email_patch<'x>(
    pointer: &'x JsonPointer<EmailProperty>,
    value: Value<'_, EmailProperty, EmailValue>,
) -> PatchResult<'x> {
    let mut pointer_iter = pointer.iter();

    match (
        pointer_iter.next(),
        pointer_iter.next(),
        pointer_iter.next(),
    ) {
        (Some(JsonPointerItem::Key(Key::Property(EmailProperty::Keywords))), Some(item), None) => {
            match (item, value) {
                (JsonPointerItem::Invalid(_), _) => PatchResult::Invalid,
                (
                    JsonPointerItem::Key(Key::Property(EmailProperty::Keyword(keyword))),
                    Value::Bool(true),
                ) => PatchResult::SetKeyword(keyword),
                (
                    JsonPointerItem::Key(Key::Property(EmailProperty::Keyword(keyword))),
                    Value::Bool(false) | Value::Null,
                ) => PatchResult::RemoveKeyword(keyword),
                _ => PatchResult::InvalidValue,
            }
        }
        (
            Some(JsonPointerItem::Key(Key::Property(EmailProperty::MailboxIds))),
            Some(item),
            None,
        ) => match (item, value) {
            (JsonPointerItem::Invalid(_), _) => PatchResult::Invalid,
            (
                JsonPointerItem::Key(Key::Property(EmailProperty::IdValue(id))),
                Value::Bool(true),
            ) => PatchResult::AddMailbox(id.document_id()),
            (
                JsonPointerItem::Key(Key::Property(EmailProperty::IdValue(id))),
                Value::Bool(false) | Value::Null,
            ) => PatchResult::RemoveMailbox(id.document_id()),
            _ => PatchResult::InvalidValue,
        },
        _ => PatchResult::Invalid,
    }
}

#[cold]
pub(crate) fn invalid_pointer(
    error: SetError<EmailProperty>,
    pointer: JsonPointer<EmailProperty>,
) -> SetError<EmailProperty> {
    error
        .with_property(EmailProperty::Pointer(pointer))
        .with_description("Invalid patch value")
}

#[cold]
pub(crate) fn conflicting_patch(property: EmailProperty) -> SetError<EmailProperty> {
    SetError::invalid_patch()
        .with_property(property)
        .with_description("A property cannot be replaced and patched in the same update.")
}
