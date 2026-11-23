/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Blob, MAX_LIST_ITEMS, Opaque, Value, eas_struct};
use crate::eas::commands::Children;
use crate::eas::tokens::Tag;
use crate::eas::tokens::tag::{airsyncbase as asb, email2, item_operations};
use crate::eas::types::BodyType;
use crate::eas::wbxml::{DecodeError, Decoder, Encoder};

eas_struct!(Body<'a> {
    body_type: u8 = asb::TYPE,
    estimated_data_size: u32 = asb::ESTIMATED_DATA_SIZE,
    truncated: bool = asb::TRUNCATED,
    data: Blob<'a> = asb::DATA,
    part: u32 = item_operations::PART,
    preview: Cow<'a, str> = asb::PREVIEW,
});

impl Body<'_> {
    pub fn text(&self) -> Option<(BodyType, &str)> {
        let text = std::str::from_utf8(self.data.as_ref()?.as_bytes()).ok()?;
        match self
            .body_type
            .map(|code| BodyType::from_code(u32::from(code)))
        {
            None | Some(Some(BodyType::Plain)) => Some((BodyType::Plain, text)),
            Some(Some(BodyType::Html)) => Some((BodyType::Html, text)),
            Some(_) => None,
        }
    }

    #[cfg(feature = "convert")]
    pub fn description(&self) -> Option<Cow<'_, str>> {
        self.text().map(|(kind, text)| match kind {
            BodyType::Html => Cow::Owned(mail_parser::html_to_text(text)),
            _ => Cow::Borrowed(text),
        })
    }
}

eas_struct!(BodyPart<'a> {
    status: u16 = asb::STATUS,
    body_type: u8 = asb::TYPE,
    estimated_data_size: u32 = asb::ESTIMATED_DATA_SIZE,
    truncated: bool = asb::TRUNCATED,
    data: Blob<'a> = asb::DATA,
    preview: Cow<'a, str> = asb::PREVIEW,
});

eas_struct!(Attachment<'a> {
    display_name: Cow<'a, str> = asb::DISPLAY_NAME,
    file_reference: Cow<'a, str> = asb::FILE_REFERENCE,
    client_id: Cow<'a, str> = asb::CLIENT_ID,
    method: u8 = asb::METHOD,
    estimated_data_size: u32 = asb::ESTIMATED_DATA_SIZE,
    content_id: Cow<'a, str> = asb::CONTENT_ID,
    content_location: Cow<'a, str> = asb::CONTENT_LOCATION,
    is_inline: bool = asb::IS_INLINE,
    um_att_duration: i32 = email2::UM_ATT_DURATION,
    um_att_order: i32 = email2::UM_ATT_ORDER,
});

eas_struct!(AttachmentAdd<'a> {
    client_id: Cow<'a, str> = asb::CLIENT_ID,
    method: u8 = asb::METHOD,
    content_type: Cow<'a, str> = asb::CONTENT_TYPE,
    content: Opaque<'a> = asb::CONTENT,
    display_name: Cow<'a, str> = asb::DISPLAY_NAME,
    content_id: Cow<'a, str> = asb::CONTENT_ID,
    content_location: Cow<'a, str> = asb::CONTENT_LOCATION,
    is_inline: bool = asb::IS_INLINE,
});

eas_struct!(AttachmentDelete<'a> {
    file_reference: Cow<'a, str> = asb::FILE_REFERENCE,
});

eas_struct!(Location<'a> {
    display_name: Cow<'a, str> = asb::DISPLAY_NAME,
    annotation: Cow<'a, str> = asb::ANNOTATION,
    street: Cow<'a, str> = asb::STREET,
    city: Cow<'a, str> = asb::CITY,
    state: Cow<'a, str> = asb::STATE,
    country: Cow<'a, str> = asb::COUNTRY,
    postal_code: Cow<'a, str> = asb::POSTAL_CODE,
    latitude: f64 = asb::LATITUDE,
    longitude: f64 = asb::LONGITUDE,
    accuracy: f64 = asb::ACCURACY,
    altitude: f64 = asb::ALTITUDE,
    altitude_accuracy: f64 = asb::ALTITUDE_ACCURACY,
    location_uri: Cow<'a, str> = asb::LOCATION_URI,
});

#[derive(Debug, Clone, PartialEq)]
pub enum AttachmentEntry<'a> {
    Attachment(Attachment<'a>),
    Add(AttachmentAdd<'a>),
    Delete(AttachmentDelete<'a>),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attachments<'a>(pub Vec<AttachmentEntry<'a>>);

impl<'a> Value<'a> for Attachments<'a> {
    fn decode(dec: &mut Decoder<'a>) -> Result<Self, DecodeError> {
        let mut entries = Vec::new();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            let entry = match tag {
                asb::ATTACHMENT => AttachmentEntry::Attachment(Attachment::decode(dec)?),
                asb::ADD => AttachmentEntry::Add(AttachmentAdd::decode(dec)?),
                asb::DELETE => AttachmentEntry::Delete(AttachmentDelete::decode(dec)?),
                _ => continue,
            };
            if entries.len() >= MAX_LIST_ITEMS {
                return Err(DecodeError::InvalidValue {
                    offset: dec.offset(),
                });
            }
            entries.push(entry);
        }
        Ok(Attachments(entries))
    }

    fn encode(&self, enc: &mut Encoder, tag: Tag) {
        enc.start(tag);
        for entry in &self.0 {
            match entry {
                AttachmentEntry::Attachment(item) => item.encode(enc, asb::ATTACHMENT),
                AttachmentEntry::Add(item) if enc.allows(asb::ADD) => item.encode(enc, asb::ADD),
                AttachmentEntry::Delete(item) if enc.allows(asb::DELETE) => {
                    item.encode(enc, asb::DELETE)
                }
                _ => {}
            }
        }
        enc.end();
    }
}
