/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Key, Property};
use std::borrow::Cow;
use types::id::Id;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(bound(serialize = "InvalidProperty<P>: serde::Serialize"))]
pub struct SetError<P: Property> {
    #[serde(rename = "type")]
    pub type_: SetErrorType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Cow<'static, str>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Vec<InvalidProperty<P>>>,

    #[serde(rename = "existingId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    existing_id: Option<Id>,
}

#[derive(Debug, Clone)]
pub enum InvalidProperty<T: Property> {
    Property(Key<'static, T>),
    Path(Vec<Key<'static, T>>),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SetErrorType {
    #[serde(rename = "forbidden")]
    Forbidden,
    #[serde(rename = "overQuota")]
    OverQuota,
    #[serde(rename = "tooLarge")]
    TooLarge,
    #[serde(rename = "rateLimit")]
    RateLimit,
    #[serde(rename = "notFound")]
    NotFound,
    #[serde(rename = "invalidPatch")]
    InvalidPatch,
    #[serde(rename = "willDestroy")]
    WillDestroy,
    #[serde(rename = "invalidProperties")]
    InvalidProperties,
    #[serde(rename = "singleton")]
    Singleton,
    #[serde(rename = "mailboxHasChild")]
    MailboxHasChild,
    #[serde(rename = "mailboxHasEmail")]
    MailboxHasEmail,
    #[serde(rename = "blobNotFound")]
    BlobNotFound,
    #[serde(rename = "tooManyKeywords")]
    TooManyKeywords,
    #[serde(rename = "tooManyMailboxes")]
    TooManyMailboxes,
    #[serde(rename = "forbiddenFrom")]
    ForbiddenFrom,
    #[serde(rename = "invalidEmail")]
    InvalidEmail,
    #[serde(rename = "tooManyRecipients")]
    TooManyRecipients,
    #[serde(rename = "noRecipients")]
    NoRecipients,
    #[serde(rename = "invalidRecipients")]
    InvalidRecipients,
    #[serde(rename = "forbiddenMailFrom")]
    ForbiddenMailFrom,
    #[serde(rename = "forbiddenToSend")]
    ForbiddenToSend,
    #[serde(rename = "cannotUnsend")]
    CannotUnsend,
    #[serde(rename = "alreadyExists")]
    AlreadyExists,
    #[serde(rename = "invalidScript")]
    InvalidScript,
    #[serde(rename = "scriptIsActive")]
    ScriptIsActive,
    #[serde(rename = "addressBookHasContents")]
    AddressBookHasContents,
    #[serde(rename = "nodeHasChildren")]
    NodeHasChildren,
    #[serde(rename = "calendarHasEvent")]
    CalendarHasEvent,
}

impl SetErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SetErrorType::Forbidden => "forbidden",
            SetErrorType::OverQuota => "overQuota",
            SetErrorType::TooLarge => "tooLarge",
            SetErrorType::RateLimit => "rateLimit",
            SetErrorType::NotFound => "notFound",
            SetErrorType::InvalidPatch => "invalidPatch",
            SetErrorType::WillDestroy => "willDestroy",
            SetErrorType::InvalidProperties => "invalidProperties",
            SetErrorType::Singleton => "singleton",
            SetErrorType::BlobNotFound => "blobNotFound",
            SetErrorType::MailboxHasChild => "mailboxHasChild",
            SetErrorType::MailboxHasEmail => "mailboxHasEmail",
            SetErrorType::TooManyKeywords => "tooManyKeywords",
            SetErrorType::TooManyMailboxes => "tooManyMailboxes",
            SetErrorType::ForbiddenFrom => "forbiddenFrom",
            SetErrorType::InvalidEmail => "invalidEmail",
            SetErrorType::TooManyRecipients => "tooManyRecipients",
            SetErrorType::NoRecipients => "noRecipients",
            SetErrorType::InvalidRecipients => "invalidRecipients",
            SetErrorType::ForbiddenMailFrom => "forbiddenMailFrom",
            SetErrorType::ForbiddenToSend => "forbiddenToSend",
            SetErrorType::CannotUnsend => "cannotUnsend",
            SetErrorType::AlreadyExists => "alreadyExists",
            SetErrorType::InvalidScript => "invalidScript",
            SetErrorType::ScriptIsActive => "scriptIsActive",
            SetErrorType::AddressBookHasContents => "addressBookHasContents",
            SetErrorType::NodeHasChildren => "nodeHasChildren",
            SetErrorType::CalendarHasEvent => "calendarHasEvent",
        }
    }
}

impl<T: Property> SetError<T> {
    pub fn new(type_: SetErrorType) -> Self {
        SetError {
            type_,
            description: None,
            properties: None,
            existing_id: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.description = description.into().into();
        self
    }

    pub fn with_property(mut self, property: impl Into<InvalidProperty<T>>) -> Self {
        self.properties = vec![property.into()].into();
        self
    }

    pub fn with_properties(
        mut self,
        properties: impl IntoIterator<Item = impl Into<InvalidProperty<T>>>,
    ) -> Self {
        self.properties = properties
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>()
            .into();
        self
    }

    pub fn with_existing_id(mut self, id: Id) -> Self {
        self.existing_id = id.into();
        self
    }

    pub fn invalid_properties() -> Self {
        Self::new(SetErrorType::InvalidProperties)
    }

    pub fn forbidden() -> Self {
        Self::new(SetErrorType::Forbidden)
    }

    pub fn not_found() -> Self {
        Self::new(SetErrorType::NotFound)
    }

    pub fn blob_not_found() -> Self {
        Self::new(SetErrorType::BlobNotFound)
    }

    pub fn over_quota() -> Self {
        Self::new(SetErrorType::OverQuota).with_description("Account quota exceeded.")
    }

    pub fn already_exists() -> Self {
        Self::new(SetErrorType::AlreadyExists)
    }

    pub fn too_large() -> Self {
        Self::new(SetErrorType::TooLarge)
    }

    pub fn will_destroy() -> Self {
        Self::new(SetErrorType::WillDestroy).with_description("ID will be destroyed.")
    }

    pub fn address_book_has_contents() -> Self {
        Self::new(SetErrorType::AddressBookHasContents)
            .with_description("Address book is not empty.")
    }

    pub fn node_has_children() -> Self {
        Self::new(SetErrorType::NodeHasChildren).with_description("Cannot delete non-empty folder.")
    }

    pub fn calendar_has_event() -> Self {
        Self::new(SetErrorType::CalendarHasEvent).with_description("Calendar is not empty.")
    }
}

impl<T: Property> From<T> for InvalidProperty<T> {
    fn from(property: T) -> Self {
        InvalidProperty::Property(Key::Property(property))
    }
}

impl<T: Property> From<(T, T)> for InvalidProperty<T> {
    fn from((a, b): (T, T)) -> Self {
        InvalidProperty::Path(vec![Key::Property(a), Key::Property(b)])
    }
}

impl<T: Property> From<Key<'static, T>> for InvalidProperty<T> {
    fn from(property: Key<'static, T>) -> Self {
        InvalidProperty::Property(property)
    }
}

impl<T: Property> serde::Serialize for InvalidProperty<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            InvalidProperty::Property(p) => p.serialize(serializer),
            InvalidProperty::Path(p) => {
                use std::fmt::Write;
                let mut path = String::with_capacity(64);
                for (i, p) in p.iter().enumerate() {
                    if i > 0 {
                        path.push('/');
                    }
                    let _ = write!(path, "{}", p.to_string());
                }
                path.serialize(serializer)
            }
        }
    }
}
