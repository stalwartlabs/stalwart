/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use bytes::Bytes;

use super::props::{
    ATTACH_EXTENSION, ATTACH_FILENAME, ATTACH_LONG_FILENAME, ATTACH_METHOD,
    ATTACHMENT_CONTACT_PHOTO, DISPLAY_NAME, LID_CATEGORIES, PHOTO_FILE_STEM,
};
use crate::{
    convert::{
        model::{AttachData, Attachment, MessageContent, PropBag},
        tags::{KEYWORDS_NAME, attach_method},
    },
    mapi::prop::{OwnedPropValue, PropKey, PropKeyRef, sets::PS_PUBLIC_STRINGS},
};

pub(super) const KEYWORDS: PropKeyRef<'static> = PropKeyRef::Name {
    set: PS_PUBLIC_STRINGS,
    name: KEYWORDS_NAME,
};
pub(super) const CATEGORIES: PropKeyRef<'static> = PropKeyRef::Lid {
    set: PS_PUBLIC_STRINGS,
    lid: LID_CATEGORIES,
};

pub(super) trait ContactSink<'c> {
    const FULL_MESSAGE: bool;
    const BINARY: bool;

    fn has(&self, key: PropKeyRef<'_>) -> bool;

    fn text(&mut self, key: PropKeyRef<'static>, value: Cow<'c, str>, origin: usize);

    fn value(&mut self, key: PropKeyRef<'static>, value: OwnedPropValue, origin: usize);

    fn list(&mut self, key: PropKeyRef<'static>, values: Vec<Cow<'c, str>>, origin: usize);

    fn categories(&mut self, values: Vec<Cow<'c, str>>, origin: usize);

    fn photo(&mut self, extension: &'static str, data: &'c [u8]);
}

#[derive(Default)]
pub(super) struct MessageSink {
    pub content: MessageContent,
}

impl<'c> ContactSink<'c> for MessageSink {
    const FULL_MESSAGE: bool = true;
    const BINARY: bool = true;

    fn has(&self, key: PropKeyRef<'_>) -> bool {
        self.content.props.get_any(key).is_some()
    }

    fn text(&mut self, key: PropKeyRef<'static>, value: Cow<'c, str>, _: usize) {
        self.content
            .props
            .set(key.to_key(), OwnedPropValue::Unicode(value.into()));
    }

    fn value(&mut self, key: PropKeyRef<'static>, value: OwnedPropValue, _: usize) {
        self.content.props.set(key.to_key(), value);
    }

    fn list(&mut self, key: PropKeyRef<'static>, values: Vec<Cow<'c, str>>, _: usize) {
        if !values.is_empty() {
            let values: Box<[Box<str>]> = values.into_iter().map(Box::from).collect();
            self.content
                .props
                .set(key.to_key(), OwnedPropValue::MvUnicode(values));
        }
    }

    fn categories(&mut self, values: Vec<Cow<'c, str>>, _: usize) {
        let values: Box<[Box<str>]> = values.into_iter().map(Box::from).collect();
        self.content
            .props
            .set(KEYWORDS.to_key(), OwnedPropValue::MvUnicode(values.clone()));
        self.content
            .props
            .set(CATEGORIES.to_key(), OwnedPropValue::MvUnicode(values));
    }

    fn photo(&mut self, extension: &'static str, data: &'c [u8]) {
        let mut props = PropBag::new();
        props.set(
            PropKey::tag(ATTACH_METHOD),
            OwnedPropValue::I32(attach_method::BY_VALUE),
        );
        props.set(
            PropKey::tag(ATTACHMENT_CONTACT_PHOTO),
            OwnedPropValue::Bool(true),
        );
        props.set(
            PropKey::tag(ATTACH_EXTENSION),
            OwnedPropValue::Unicode(format!(".{extension}").into()),
        );
        let name: Box<str> = format!("{PHOTO_FILE_STEM}.{extension}").into();
        for id in [ATTACH_FILENAME, DISPLAY_NAME] {
            props.set(PropKey::tag(id), OwnedPropValue::Unicode(name.clone()));
        }
        props.set(
            PropKey::tag(ATTACH_LONG_FILENAME),
            OwnedPropValue::Unicode(name),
        );
        self.content.attachments.push(Attachment {
            props,
            data: AttachData::Bytes(Bytes::copy_from_slice(data)),
        });
    }
}

#[derive(Default)]
pub(super) struct OriginSink {
    message: MessageSink,
    pub origins: Vec<(PropKey, usize)>,
}

impl<'c> ContactSink<'c> for OriginSink {
    const FULL_MESSAGE: bool = true;
    const BINARY: bool = false;

    fn has(&self, key: PropKeyRef<'_>) -> bool {
        ContactSink::<'c>::has(&self.message, key)
    }

    fn text(&mut self, key: PropKeyRef<'static>, value: Cow<'c, str>, origin: usize) {
        self.origins.push((key.to_key(), origin));
        self.message.text(key, value, origin);
    }

    fn value(&mut self, key: PropKeyRef<'static>, value: OwnedPropValue, origin: usize) {
        self.origins.push((key.to_key(), origin));
        ContactSink::<'c>::value(&mut self.message, key, value, origin);
    }

    fn list(&mut self, key: PropKeyRef<'static>, values: Vec<Cow<'c, str>>, origin: usize) {
        if !values.is_empty() {
            self.origins.push((key.to_key(), origin));
            self.message.list(key, values, origin);
        }
    }

    fn categories(&mut self, values: Vec<Cow<'c, str>>, origin: usize) {
        self.origins.push((KEYWORDS.to_key(), origin));
        self.origins.push((CATEGORIES.to_key(), origin));
        self.message.categories(values, origin);
    }

    fn photo(&mut self, extension: &'static str, data: &'c [u8]) {
        self.message.photo(extension, data);
    }
}
