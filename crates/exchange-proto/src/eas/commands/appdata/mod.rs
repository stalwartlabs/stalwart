/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::io::Write;

use bytes::Bytes;

use crate::common::base64::Base64Text;
use crate::common::time::EasDateForm;
use crate::eas::commands::Children;
use crate::eas::status::SyncStatus;
use crate::eas::tokens::{ProtocolVersion, Tag};
use crate::eas::types::{Class, EasDateTime};
use crate::eas::wbxml::decoder::parse_u32;
use crate::eas::wbxml::{DecodeError, Decoder, Encoder, NulPolicy, WbxmlLimits};

pub mod base;
pub mod calendar;
pub mod contact;
pub mod email;
pub mod note;
pub mod rights;
pub mod sms;
pub mod task;

pub use base::{
    Attachment, AttachmentAdd, AttachmentDelete, AttachmentEntry, Attachments, Body, BodyPart,
    Location,
};
pub use calendar::{Attendee, Calendar, CalendarException, Recurrence};
pub use contact::Contact;
pub use email::{Email, EmailFlag, MeetingRecurrence, MeetingRequest};
pub use note::Note;
pub use rights::RightsManagementLicense;
pub use sms::Sms;
pub use task::{Task, TaskRecurrence};

pub const MAX_LIST_ITEMS: usize = 1000;

pub(crate) trait Value<'a>: Sized {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError>;
    fn encode(&self, enc: &mut Encoder, tag: Tag);
}

#[cold]
fn invalid(dec: &Decoder<'_>) -> DecodeError {
    DecodeError::InvalidValue {
        offset: dec.offset(),
    }
}

impl<'a> Value<'a> for Cow<'a, str> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        dec.str()
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_str(tag, self);
    }
}

impl Value<'_> for u32 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        dec.u32()
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_u64(tag, u64::from(*self));
    }
}

impl Value<'_> for u64 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        dec.u64()
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_u64(tag, *self);
    }
}

impl Value<'_> for u16 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let value = dec.u32()?;
        u16::try_from(value).map_err(|_| invalid(dec))
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_u64(tag, u64::from(*self));
    }
}

impl Value<'_> for u8 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        dec.u8()
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_u64(tag, u64::from(*self));
    }
}

impl Value<'_> for i32 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        dec.i32()
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_i64(tag, i64::from(*self));
    }
}

impl Value<'_> for bool {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        dec.bool()
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_bool(tag, *self);
    }
}

impl Value<'_> for f64 {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let text = dec.str()?;
        text.trim()
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
            .ok_or_else(|| invalid(dec))
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        let value = *self;
        enc.text_with(tag, |out| {
            let _ = write!(out, "{value}");
        });
    }
}

impl Value<'_> for EasDateTime {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let text = dec.text()?;
        EasDateTime::parse(&text).ok_or_else(|| invalid(dec))
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_with(tag, |out| self.write(out, EasDateForm::Punctuated));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Compact(pub EasDateTime);

impl Value<'_> for Compact {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        EasDateTime::decode(dec).map(Compact)
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text_with(tag, |out| self.0.write(out, EasDateForm::Compact));
    }
}

impl<'a> Value<'a> for Base64Text<'a> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        dec.bytes().map(Base64Text)
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.text(tag, &self.0);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Empty;

impl Value<'_> for Empty {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        dec.skip_element().map(|()| Empty)
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.empty(tag);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OrEmpty<T>(pub Option<T>);

macro_rules! or_empty {
    ($($ty:ty),*) => {
        $(
            impl Value<'_> for OrEmpty<$ty> {
                fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                    let text = dec.text()?;
                    let text = text.trim_ascii();
                    if text.is_empty() {
                        return Ok(OrEmpty(None));
                    }
                    parse_u32(text)
                        .and_then(|value| <$ty>::try_from(value).ok())
                        .map(|value| OrEmpty(Some(value)))
                        .ok_or_else(|| invalid(dec))
                }

                fn encode(&self, enc: &mut Encoder, tag: Tag) {
                    match self.0 {
                        Some(value) => enc.text_u64(tag, u64::from(value)),
                        None => enc.empty(tag),
                    };
                }
            }
        )*
    };
}

or_empty!(u8, u32);

impl Value<'_> for OrEmpty<EasDateTime> {
    fn decode(dec: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let text = dec.text()?;
        let text = text.trim_ascii();
        if text.is_empty() {
            return Ok(OrEmpty(None));
        }
        EasDateTime::parse(text)
            .map(|value| OrEmpty(Some(value)))
            .ok_or_else(|| invalid(dec))
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        match &self.0 {
            Some(value) => value.encode(enc, tag),
            None => {
                enc.empty(tag);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Opaque<'a>(pub Cow<'a, [u8]>);

impl<'a> Value<'a> for Opaque<'a> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        dec.bytes().map(Opaque)
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.opaque(tag, &self.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blob<'a> {
    Slice(Cow<'a, [u8]>),
    Shared(Bytes),
}

impl Blob<'_> {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Blob::Slice(slice) => slice,
            Blob::Shared(bytes) => bytes,
        }
    }
}

impl<'a> Value<'a> for Blob<'a> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        dec.bytes().map(Blob::Slice)
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        match self {
            Blob::Slice(slice) => enc.text(tag, slice),
            Blob::Shared(bytes) => enc.text_shared(tag, bytes.clone(), NulPolicy::Strip),
        };
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct List<T, const ITEM: u16>(pub Vec<T>);

impl<T, const ITEM: u16> Default for List<T, ITEM> {
    fn default() -> Self {
        List(Vec::new())
    }
}

impl<T, const ITEM: u16> List<T, ITEM> {
    pub const ITEM_TAG: Tag = Tag::from_raw(ITEM);
}

impl<'a, T: Value<'a>, const ITEM: u16> Value<'a> for List<T, ITEM> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        let mut items = Vec::new();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            if tag == Self::ITEM_TAG {
                if items.len() >= MAX_LIST_ITEMS {
                    return Err(invalid(dec));
                }
                items.push(T::decode(dec)?);
            }
        }
        Ok(List(items))
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.start(tag);
        if enc.allows(Self::ITEM_TAG) {
            for item in &self.0 {
                item.encode(enc, Self::ITEM_TAG);
            }
        }
        enc.end();
    }
}

macro_rules! eas_struct {
    (@impl $name:ident [$($lt:lifetime)?] { $( $field:ident : $ty:ty = $tag:path ),* $(,)? }) => {
        impl<'a> $crate::eas::commands::appdata::Value<'a> for $name$(<$lt>)? {
            fn decode(
                dec: &mut $crate::eas::wbxml::Decoder<'a>,
            ) -> Result<Self, $crate::eas::wbxml::DecodeError> {
                let mut item = Self::default();
                let mut children = $crate::eas::commands::Children::of(dec);
                while let Some(tag) = children.next(dec)? {
                    item.decode_field(tag, dec)?;
                }
                Ok(item)
            }

            fn encode(&self, enc: &mut $crate::eas::wbxml::Encoder, tag: $crate::eas::tokens::Tag) {
                enc.start(tag);
                self.encode_fields(enc);
                enc.end();
            }
        }

        impl<'a> $name$(<$lt>)? {
            #[allow(clippy::match_single_binding)]
            pub(crate) fn decode_field(
                &mut self,
                tag: $crate::eas::tokens::Tag,
                dec: &mut $crate::eas::wbxml::Decoder<'a>,
            ) -> Result<(), $crate::eas::wbxml::DecodeError> {
                match tag {
                    $( $tag => {
                        self.$field = Some(<$ty as $crate::eas::commands::appdata::Value<'a>>::decode(dec)?);
                    } )*
                    _ => {}
                }
                Ok(())
            }

            pub fn encode_fields(&self, enc: &mut $crate::eas::wbxml::Encoder) {
                $(
                    if let Some(value) = &self.$field
                        && enc.allows($tag)
                    {
                        <$ty as $crate::eas::commands::appdata::Value<'a>>::encode(value, enc, $tag);
                    }
                )*
            }

            pub fn retain_fields(&mut self, schema: &[$crate::eas::tokens::Tag]) {
                $(
                    if !schema.contains(&$tag) {
                        self.$field = None;
                    }
                )*
            }
        }
    };
    ($(#[$meta:meta])* $name:ident<'a> { $( $field:ident : $ty:ty = $tag:path ),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq)]
        pub struct $name<'a> {
            $( pub $field: Option<$ty>, )*
        }
        $crate::eas::commands::appdata::eas_struct!(@impl $name ['a] { $( $field : $ty = $tag ),* });
    };
    ($(#[$meta:meta])* $name:ident { $( $field:ident : $ty:ty = $tag:path ),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq)]
        pub struct $name {
            $( pub $field: Option<$ty>, )*
        }
        $crate::eas::commands::appdata::eas_struct!(@impl $name [] { $( $field : $ty = $tag ),* });
    };
}

pub(crate) use eas_struct;

#[derive(Debug, Clone, PartialEq)]
pub enum ApplicationData<'a> {
    Email(Box<Email<'a>>),
    Calendar(Box<Calendar<'a>>),
    Contact(Box<Contact<'a>>),
    Task(Box<Task<'a>>),
    Note(Box<Note<'a>>),
    Sms(Box<Sms<'a>>),
}

impl ApplicationData<'_> {
    pub fn class(&self) -> Class {
        match self {
            ApplicationData::Email(_) => Class::Email,
            ApplicationData::Calendar(_) => Class::Calendar,
            ApplicationData::Contact(_) => Class::Contacts,
            ApplicationData::Task(_) => Class::Tasks,
            ApplicationData::Note(_) => Class::Notes,
            ApplicationData::Sms(_) => Class::Sms,
        }
    }

    pub fn encode_fields(&self, enc: &mut Encoder) {
        match self {
            ApplicationData::Email(item) => item.encode_fields(enc),
            ApplicationData::Calendar(item) => item.encode_fields(enc),
            ApplicationData::Contact(item) => item.encode_fields(enc),
            ApplicationData::Task(item) => item.encode_fields(enc),
            ApplicationData::Note(item) => item.encode_fields(enc),
            ApplicationData::Sms(item) => item.encode_fields(enc),
        }
    }

    pub fn retain_fields(&mut self, schema: &[Tag]) {
        match self {
            ApplicationData::Email(item) => item.retain_fields(schema),
            ApplicationData::Calendar(item) => item.retain_fields(schema),
            ApplicationData::Contact(item) => item.retain_fields(schema),
            ApplicationData::Task(item) => item.retain_fields(schema),
            ApplicationData::Note(item) => item.retain_fields(schema),
            ApplicationData::Sms(item) => item.retain_fields(schema),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidItem {
    pub offset: usize,
}

impl InvalidItem {
    pub const fn status(&self) -> SyncStatus {
        SyncStatus::CONVERSION_ERROR
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawApplicationData<'a> {
    page: u8,
    content: &'a [u8],
}

impl<'a> RawApplicationData<'a> {
    pub(crate) fn new(page: u8, content: &'a [u8]) -> Self {
        RawApplicationData { page, content }
    }

    pub fn content(&self) -> &'a [u8] {
        self.content
    }

    pub fn len(&self) -> usize {
        self.content.len()
    }

    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    pub fn parse(
        &self,
        class: Class,
        _version: ProtocolVersion,
        limits: &WbxmlLimits,
    ) -> Result<ApplicationData<'a>, InvalidItem> {
        let mut dec = Decoder::fragment(self.content, self.page, limits);
        let result =
            match class {
                Class::Email => parse_fields::<Email<'a>>(&mut dec)
                    .map(|item| ApplicationData::Email(Box::new(item))),
                Class::Calendar => parse_fields::<Calendar<'a>>(&mut dec)
                    .map(|item| ApplicationData::Calendar(Box::new(item))),
                Class::Contacts => parse_fields::<Contact<'a>>(&mut dec)
                    .map(|item| ApplicationData::Contact(Box::new(item))),
                Class::Tasks => parse_fields::<Task<'a>>(&mut dec)
                    .map(|item| ApplicationData::Task(Box::new(item))),
                Class::Notes => parse_fields::<Note<'a>>(&mut dec)
                    .map(|item| ApplicationData::Note(Box::new(item))),
                Class::Sms => parse_fields::<Sms<'a>>(&mut dec)
                    .map(|item| ApplicationData::Sms(Box::new(item))),
            };
        result.map_err(|err| InvalidItem {
            offset: err.offset().unwrap_or(dec.offset()),
        })
    }
}

fn parse_fields<'a, T: Value<'a>>(dec: &mut Decoder<'a>) -> Result<T, DecodeError> {
    T::decode(dec)
}
