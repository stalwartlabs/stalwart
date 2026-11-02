/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::{Header, HeaderName, Headers, Message};

use super::{
    CRLF, Canonical, Counter, Sink, has_bare_lf,
    legacy::{LEGACY_PARAM, LegacyParts},
    protection::Protection,
};
use crate::{error::EncryptError, types::HeaderProtection};

const MIME_VERSION: &[u8] = b"MIME-Version: 1.0\r\n";
const OBSCURED_SUBJECT: &[u8] = b"Subject: [...]\r\n";
const HP_OUTER: &[u8] = b"HP-Outer: ";
const HP_OUTER_SUBJECT: &[u8] = b"HP-Outer: Subject: [...]\r\n";
const HP_CIPHER: &[u8] = b"; hp=\"cipher\"";
const DEFAULT_CONTENT_TYPE: &[u8] = b"Content-Type: text/plain; charset=us-ascii";
const NAME_SEPARATOR: &[u8] = b": ";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outer {
    Keep,
    Obscure,
    Remove,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    ContentType,
    Mime,
    Protected(Outer),
    Unprotected,
}

impl Field {
    fn classify(name: &HeaderName<'_>, protection: HeaderProtection) -> Self {
        let baseline = |outer| {
            if protection == HeaderProtection::Baseline {
                outer
            } else {
                Outer::Keep
            }
        };
        match name {
            HeaderName::ContentType => Field::ContentType,
            name if name.is_mime_header() => Field::Mime,
            _ if protection == HeaderProtection::None => Field::Unprotected,
            HeaderName::Subject => Field::Protected(baseline(Outer::Obscure)),
            HeaderName::Comments | HeaderName::Keywords => {
                Field::Protected(baseline(Outer::Remove))
            }
            HeaderName::From
            | HeaderName::Sender
            | HeaderName::ReplyTo
            | HeaderName::To
            | HeaderName::Cc
            | HeaderName::Date
            | HeaderName::MessageId
            | HeaderName::InReplyTo
            | HeaderName::References => Field::Protected(Outer::Keep),
            _ => Field::Unprotected,
        }
    }
}

pub(crate) struct Entity<'x> {
    raw: &'x [u8],
    headers: Headers<'x>,
    body_offset: usize,
    body_canonical: bool,
    has_mime_version: bool,
    has_content_type: bool,
    protection: HeaderProtection,
    legacy: LegacyParts<'x>,
}

fn write_field<S: Sink>(out: &mut S, bytes: &[u8]) {
    out.put(bytes);
    if !bytes.ends_with(b"\n") {
        out.put(CRLF);
    }
}

fn write_with_params<S: Sink>(out: &mut S, field: &[u8], params: &[&[u8]]) {
    let value = field.trim_ascii_end();
    out.put(value.strip_suffix(b";").unwrap_or(value).trim_ascii_end());
    for param in params {
        out.put(param);
    }
    out.put(CRLF);
}

impl<'x> Entity<'x> {
    pub(crate) fn new(
        message: &'x Message<'x>,
        protection: HeaderProtection,
    ) -> Result<Self, EncryptError> {
        let raw = message.raw();
        let root = message.root_part();
        let headers = root.headers();
        let mut has_mime_version = false;
        let mut has_content_type = false;
        for header in headers.iter() {
            if raw
                .get(header.offset_field() as usize..header.offset_end() as usize)
                .is_none()
                || header.offset_start() < header.offset_field()
            {
                return Err(EncryptError::MalformedMessage);
            }
            match header.name() {
                HeaderName::MimeVersion => has_mime_version = true,
                HeaderName::ContentType => has_content_type = true,
                _ => {}
            }
        }
        let body_offset = root.offset_body() as usize;
        if body_offset > raw.len() {
            return Err(EncryptError::MalformedMessage);
        }
        let body_canonical = !raw
            .get(body_offset..)
            .is_some_and(|body| has_bare_lf(body, false));
        let protection = if protection != HeaderProtection::None
            && crate::mime::protection::protection(message) == Protection::Signed
        {
            HeaderProtection::None
        } else {
            protection
        };
        let legacy = if protection == HeaderProtection::Baseline {
            LegacyParts::collect(message)
        } else {
            LegacyParts::none()
        };
        Ok(Entity {
            raw,
            headers,
            body_offset,
            body_canonical,
            has_mime_version,
            has_content_type,
            protection,
            legacy,
        })
    }

    fn field_bytes(&self, header: &Header<'x>) -> &'x [u8] {
        self.raw
            .get(header.offset_field() as usize..header.offset_end() as usize)
            .unwrap_or_default()
    }

    fn fields(&self) -> impl Iterator<Item = (Field, Header<'x>)> + '_ {
        self.headers
            .iter()
            .map(|header| (Field::classify(&header.name(), self.protection), header))
    }

    pub(crate) fn outer_len(&self) -> usize {
        let mut counter = Counter::default();
        self.write_outer(&mut counter);
        counter.0
    }

    pub(crate) fn write_outer<S: Sink>(&self, out: &mut S) {
        for (field, header) in self.fields() {
            match field {
                Field::ContentType | Field::Mime | Field::Protected(Outer::Remove) => {}
                Field::Protected(Outer::Obscure) => out.put(OBSCURED_SUBJECT),
                Field::Protected(Outer::Keep) | Field::Unprotected => {
                    write_field(out, self.field_bytes(&header))
                }
            }
        }
        if !self.has_mime_version {
            out.put(MIME_VERSION);
        }
    }

    pub(crate) fn inner_len(&self) -> usize {
        let mut counter = Counter::default();
        self.write_inner(&mut counter);
        counter.0
    }

    pub(crate) fn write_inner<S: Sink>(&self, sink: &mut S) {
        let mut out = Canonical::new(sink);
        let protected = self.protection != HeaderProtection::None;
        if protected {
            for (field, header) in self.fields() {
                if matches!(field, Field::Protected(_)) {
                    write_field(&mut out, self.field_bytes(&header));
                }
            }
            for (field, header) in self.fields() {
                match field {
                    Field::Protected(Outer::Keep) => {
                        out.put(HP_OUTER);
                        out.put(header.raw_name().as_bytes());
                        out.put(NAME_SEPARATOR);
                        write_field(&mut out, header.raw_value().trim_ascii_start());
                    }
                    Field::Protected(Outer::Obscure) => out.put(HP_OUTER_SUBJECT),
                    _ => {}
                }
            }
        }
        let root_params: &[&[u8]] = if self.legacy.root {
            &[HP_CIPHER, LEGACY_PARAM]
        } else {
            &[HP_CIPHER]
        };
        for (field, header) in self.fields() {
            match field {
                Field::ContentType if protected => {
                    write_with_params(&mut out, self.field_bytes(&header), root_params)
                }
                Field::ContentType | Field::Mime => {
                    write_field(&mut out, self.field_bytes(&header))
                }
                _ => {}
            }
        }
        if protected && !self.has_content_type {
            write_with_params(&mut out, DEFAULT_CONTENT_TYPE, root_params);
        }
        out.put(CRLF);
        self.write_body(&mut out);
    }

    fn write_body<S: Sink>(&self, out: &mut Canonical<'_, S>) {
        let raw = self.raw;
        let mut pos = self.body_offset;
        let put = |out: &mut Canonical<'_, S>, data: &[u8]| {
            if self.body_canonical {
                out.put_canonical(data);
            } else {
                out.put(data);
            }
        };
        for part in self.legacy.iter() {
            if let Some((start, end)) = part.content_type {
                put(out, raw.get(pos..start).unwrap_or_default());
                write_with_params(
                    out,
                    raw.get(start..end).unwrap_or_default(),
                    &[LEGACY_PARAM],
                );
                pos = end;
            }
            let (body_start, body_end) = part.body;
            put(out, raw.get(pos..body_start).unwrap_or_default());
            if part.is_base64() {
                out.put_reencoded(part);
                pos = body_end;
            } else {
                let insert = body_start + part.insert_at;
                put(out, raw.get(body_start..insert).unwrap_or_default());
                part.write_inline(out);
                pos = insert;
            }
        }
        put(out, raw.get(pos..).unwrap_or_default());
    }
}
