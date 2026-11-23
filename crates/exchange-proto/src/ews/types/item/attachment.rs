/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Item;
use crate::{
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        types::{
            ids::AttachmentId,
            value::{DateTime, EwsValue, T, XBinary, ews_fields},
        },
    },
    xml::{Attrs, XmlWriter},
};
use std::borrow::Cow;

ews_fields! {
    pub struct AttachmentFields<'x> {
        attachment_id: "AttachmentId" => AttachmentId<'x>,
        name: "Name" => Cow<'x, str>,
        content_type: "ContentType" => Cow<'x, str>,
        content_id: "ContentId" => Cow<'x, str>,
        content_location: "ContentLocation" => Cow<'x, str>,
        attachment_original_url: "AttachmentOriginalUrl" => Cow<'x, str>,
        size: "Size" => i32,
        last_modified_time: "LastModifiedTime" => DateTime,
        is_inline: "IsInline" => bool,
    }
}

ews_fields! {
    pub struct FileAttachmentFields<'x> {
        is_contact_photo: "IsContactPhoto" => bool,
        content: "Content" => XBinary<'x>,
    }
}

ews_fields! {
    pub struct ReferenceAttachmentFields<'x> {
        attach_long_path_name: "AttachLongPathName" => Cow<'x, str>,
        provider_type: "ProviderType" => Cow<'x, str>,
        provider_endpoint_url: "ProviderEndpointUrl" => Cow<'x, str>,
        attachment_thumbnail_url: "AttachmentThumbnailUrl" => Cow<'x, str>,
        attachment_preview_url: "AttachmentPreviewUrl" => Cow<'x, str>,
        permission_type: "PermissionType" => i32,
        original_permission_type: "OriginalPermissionType" => i32,
        attachment_is_folder: "AttachmentIsFolder" => bool,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Attachment<'x> {
    File(AttachmentFields<'x>, FileAttachmentFields<'x>),
    Item(AttachmentFields<'x>, Option<Box<Item<'x>>>),
    Reference(AttachmentFields<'x>, Box<ReferenceAttachmentFields<'x>>),
}

#[derive(Clone, Copy)]
enum AttachmentKind {
    File,
    Item,
    Reference,
}

impl<'x> Attachment<'x> {
    pub fn parse_child(p: &mut Parser<'x>, child: &Child<'x>) -> Result<Option<Self>> {
        let Some(kind) = hashify::map!(child.local.as_bytes(), AttachmentKind,
            "FileAttachment" => AttachmentKind::File,
            "ItemAttachment" => AttachmentKind::Item,
            "ReferenceAttachment" => AttachmentKind::Reference,
        )
        .copied() else {
            return Ok(None);
        };
        p.expect_types(child)?;
        let mut fields = AttachmentFields::default();
        Ok(Some(match kind {
            AttachmentKind::File => {
                let mut file = FileAttachmentFields::default();
                while let Some(child) = p.child()? {
                    if !(fields.parse_child(p, &child)? || file.parse_child(p, &child)?) {
                        p.skip()?;
                    }
                }
                Attachment::File(fields, file)
            }
            AttachmentKind::Reference => {
                let mut reference = Box::<ReferenceAttachmentFields>::default();
                while let Some(child) = p.child()? {
                    if !(fields.parse_child(p, &child)? || reference.parse_child(p, &child)?) {
                        p.skip()?;
                    }
                }
                Attachment::Reference(fields, reference)
            }
            AttachmentKind::Item => {
                let mut item = None;
                while let Some(child) = p.child()? {
                    if fields.parse_child(p, &child)? {
                        continue;
                    }
                    p.enter_attached_item()?;
                    let parsed = Item::parse_attached(p, &child);
                    p.leave_attached_item();
                    match parsed? {
                        Some(_) if item.is_some() => {
                            return Err(p.error(ParseErrorKind::InvalidValue("ItemAttachment")));
                        }
                        Some(parsed) => item = Some(Box::new(parsed)),
                        None => p.skip()?,
                    }
                }
                Attachment::Item(fields, item)
            }
        }))
    }

    pub const fn element(&self) -> &'static str {
        match self {
            Attachment::File(..) => "FileAttachment",
            Attachment::Item(..) => "ItemAttachment",
            Attachment::Reference(..) => "ReferenceAttachment",
        }
    }

    pub fn fields(&self) -> &AttachmentFields<'x> {
        match self {
            Attachment::File(fields, _)
            | Attachment::Item(fields, _)
            | Attachment::Reference(fields, _) => fields,
        }
    }

    pub fn write(&self, w: &mut XmlWriter<'_>) {
        let name = self.element();
        w.start(T, name);
        self.fields().write_fields(w);
        match self {
            Attachment::File(_, file) => file.write_fields(w),
            Attachment::Item(_, item) => {
                if let Some(item) = item {
                    item.write(w);
                }
            }
            Attachment::Reference(_, reference) => reference.write_fields(w),
        }
        w.end(T, name);
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Attachments<'x>(pub Vec<Attachment<'x>>);

impl<'x> EwsValue<'x> for Attachments<'x> {
    fn parse(p: &mut Parser<'x>, _: &Attrs<'x>) -> Result<Self> {
        let mut list = Vec::new();
        while let Some(child) = p.child()? {
            match Attachment::parse_child(p, &child)? {
                Some(attachment) => {
                    p.count_id()?;
                    list.push(attachment);
                }
                None => p.skip()?,
            }
        }
        Ok(Attachments(list))
    }

    fn write(&self, w: &mut XmlWriter<'_>, local: &str) {
        if !self.0.is_empty() {
            w.start(T, local);
            for attachment in &self.0 {
                attachment.write(w);
            }
            w.end(T, local);
        }
    }
}
