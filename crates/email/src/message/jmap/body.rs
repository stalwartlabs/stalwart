/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{EmailRender, JmapMap, JmapValue, str_value};
use crate::message::{
    body::{truncate_html, truncate_plain},
    metadata::{BodyList, MAX_NESTING, PartFlags, PartKind, PartSource, PartView},
};
use jmap_proto::object::email::{EmailProperty, EmailValue};
use jmap_tools::{Key, Map, Value};
use std::borrow::Cow;
use types::blob::{BlobId, EncodedRange};

struct Level<'a> {
    parent: Option<PartView<'a>>,
    next: usize,
    values: Vec<JmapValue<'a>>,
}

impl<'a> EmailRender<'a, '_> {
    pub(super) fn body_list_values(&self, list: BodyList) -> JmapValue<'a> {
        Value::Array(
            self.root
                .body_list(list)
                .map(|part| self.body_part(part))
                .collect(),
        )
    }

    pub(super) fn body_part(&self, root: PartView<'a>) -> JmapValue<'a> {
        let mut levels = vec![Level {
            parent: None,
            next: 0,
            values: Vec::with_capacity(1),
        }];
        loop {
            let Some(level) = levels.last_mut() else {
                return Value::Null;
            };
            let next = match level.parent {
                None => (level.next == 0).then_some(root),
                Some(parent) => parent.child(level.next),
            };
            if let Some(part) = next {
                level.next += 1;
                level.values.push(Value::Object(self.part_values(part)));
                if part.is_multipart() && levels.len() < MAX_NESTING {
                    levels.push(Level {
                        parent: Some(part),
                        next: 0,
                        values: Vec::with_capacity(part.children().len()),
                    });
                }
            } else if levels.len() > 1 {
                let Some(finished) = levels.pop() else {
                    return Value::Null;
                };
                if let Some(Value::Object(object)) =
                    levels.last_mut().and_then(|level| level.values.last_mut())
                {
                    object.insert_unchecked(EmailProperty::SubParts, Value::Array(finished.values));
                }
            } else {
                return levels
                    .pop()
                    .and_then(|level| level.values.into_iter().next())
                    .unwrap_or_default();
            }
        }
    }

    fn part_values(&self, part: PartView<'a>) -> JmapMap<'a> {
        let multipart = part.is_multipart();
        let mut values = Map::with_capacity(self.body_properties.len());
        for property in self.body_properties {
            let value = match property {
                EmailProperty::PartId if !multipart => {
                    Value::Str(Cow::Owned(part.id().to_string()))
                }
                EmailProperty::BlobId if !multipart => self.part_blob_id(part),
                EmailProperty::Size if !multipart => Value::Number(part.decoded_size().into()),
                EmailProperty::Name => str_value(part.attachment_name()),
                EmailProperty::Type => match part.content_type() {
                    Some(content_type) => Value::Str(content_type.mime_type()),
                    None => match part.kind() {
                        PartKind::Text => Value::Str(Cow::Borrowed("text/plain")),
                        PartKind::Html => Value::Str(Cow::Borrowed("text/html")),
                        PartKind::Message => Value::Str(Cow::Borrowed("message/rfc822")),
                        _ => Value::Null,
                    },
                },
                EmailProperty::Charset => str_value(
                    part.charset()
                        .or_else(|| part.is_text().then_some("us-ascii")),
                ),
                EmailProperty::Disposition => {
                    str_value(part.content_disposition().map(|cd| cd.ctype()))
                }
                EmailProperty::Cid => str_value(part.content_id()),
                EmailProperty::Language => {
                    let languages = part.content_language();
                    if languages.is_present() {
                        Value::Array(
                            languages
                                .iter()
                                .map(|language| Value::Str(Cow::Borrowed(language)))
                                .collect(),
                        )
                    } else {
                        Value::Null
                    }
                }
                EmailProperty::Location => str_value(part.content_location()),
                EmailProperty::Header(_) | EmailProperty::Headers => {
                    self.part_header(part, property)
                }
                EmailProperty::SubParts => continue,
                _ => Value::Null,
            };
            values.insert_unchecked(property.clone(), value);
        }
        values
    }

    fn part_blob_id(&self, part: PartView<'a>) -> JmapValue<'a> {
        self.inner_blob_id(part).map_or(Value::Null, |blob_id| {
            Value::Element(EmailValue::BlobId(blob_id))
        })
    }

    pub(super) fn inner_blob_id(&self, part: PartView<'a>) -> Option<BlobId> {
        let encoded = |part: PartView<'a>, start: usize| {
            EncodedRange::new(start, part.body_range().len(), part.encoding().as_u8())
        };
        let chain = self.meta.source_chain(part.message())?;
        let mut ids = chain.ids();
        let outermost = match ids.next() {
            Some(id) => self.meta.part(id)?,
            None => part,
        };
        let start = self
            .meta
            .blob_range(outermost.body_range())?
            .start
            .checked_sub(self.blob_prefix)?;
        let outermost = encoded(outermost, start);
        if chain.is_empty() {
            return self.blob_id.inner_part(&[], outermost);
        }
        let mut containers = Vec::with_capacity(chain.len());
        containers.push(outermost);
        for id in ids {
            let container = self.meta.part(id)?;
            containers.push(encoded(container, container.offset_body()));
        }
        self.blob_id
            .inner_part(&containers, encoded(part, part.offset_body()))
    }

    fn part_header(&self, part: PartView<'a>, property: &EmailProperty) -> JmapValue<'a> {
        let Some(raw) = self.raw else {
            return Value::Null;
        };
        let Some(source) = self.meta.source(part.message(), raw) else {
            return Value::Null;
        };
        let headers = part.headers();
        match &source {
            PartSource::Raw(raw) => headers.jmap_value(property, *raw),
            PartSource::Decoded(bytes) => {
                headers.jmap_value(property, bytes.as_slice()).into_owned()
            }
        }
    }

    pub(super) fn body_values(&self) -> JmapValue<'a> {
        if !self.options.fetches_any() {
            return Value::Object(Map::new());
        }
        let Some(raw) = self.raw else {
            return Value::Null;
        };
        let source = PartSource::Raw(raw);
        let mut body_values = Map::with_capacity(self.root.parts().len());
        for part in self.root.parts() {
            if !part.is_text()
                || !part
                    .content_type()
                    .is_none_or(|ct| ct.ctype().eq_ignore_ascii_case("text"))
            {
                continue;
            }
            let flags = part.flags();
            if !(self.options.fetch_all
                || (self.options.fetch_html && flags.contains(PartFlags::IN_HTML_BODY))
                || (self.options.fetch_text && flags.contains(PartFlags::IN_TEXT_BODY)))
            {
                continue;
            }
            let Some(decoded) = part.text(&source) else {
                continue;
            };
            let (is_truncated, value) = match part.kind() {
                PartKind::Html => truncate_html(&decoded.text, self.options.max_bytes),
                _ => truncate_plain(&decoded.text, self.options.max_bytes),
            };
            body_values.insert_unchecked(
                Key::Owned(part.id().to_string()),
                Map::with_capacity(3)
                    .with_key_value(EmailProperty::IsEncodingProblem, decoded.has_problems)
                    .with_key_value(EmailProperty::IsTruncated, is_truncated)
                    .with_key_value(EmailProperty::Value, value),
            );
        }
        Value::Object(body_values)
    }
}
