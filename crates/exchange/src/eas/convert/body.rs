/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;
use email::message::metadata::{
    ArchivedMessageMetadata, BodyList, MessageView, PartKind, PartSource, RawMessage,
};
use exchange_proto::eas::{
    commands::{
        appdata::{
            Blob,
            base::{Body, BodyPart},
        },
        sync::SyncOptions,
    },
    status::BodyPartStatus,
    types::{BodyPreference, BodyType},
};
use std::{borrow::Cow, ops::Range};

const MIME_SUPPORT_SMIME: u8 = 1;
const MIME_SUPPORT_ALWAYS: u8 = 2;
const MIME_TRUNCATION_NONE: u8 = 8;
const MIME_TRUNCATION_SIZES: [u32; 8] = [0, 4096, 5120, 7168, 10240, 20480, 51200, 102400];
const SHARED_MIN_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    Plain,
    Html,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFormat {
    Text(TextKind),
    Mime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyChoice {
    pub format: BodyFormat,
    pub truncation: Option<u32>,
    pub all_or_none: bool,
    pub preview: Option<u8>,
    fallback: Option<Fallback>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fallback {
    kind: TextKind,
    truncation: Option<u32>,
    all_or_none: bool,
    preview: Option<u8>,
}

impl Fallback {
    fn choice(self) -> BodyChoice {
        BodyChoice {
            format: BodyFormat::Text(self.kind),
            truncation: self.truncation,
            all_or_none: self.all_or_none,
            preview: self.preview,
            fallback: None,
        }
    }
}

impl BodyChoice {
    pub fn select(options: Option<&SyncOptions>, is_smime: bool) -> Self {
        let Some(options) = options else {
            return BodyChoice::plain();
        };
        let mime_allowed = match options.mime_support {
            Some(MIME_SUPPORT_ALWAYS) => true,
            Some(MIME_SUPPORT_SMIME) => is_smime,
            _ => false,
        };
        if mime_allowed {
            let preference = options
                .body_preferences
                .iter()
                .find(|preference| preference.body_type == BodyType::Mime);
            let truncation = match options.mime_truncation {
                Some(code) if code < MIME_TRUNCATION_NONE => {
                    MIME_TRUNCATION_SIZES.get(usize::from(code)).copied()
                }
                _ => preference.and_then(|preference| preference.truncation_size),
            };
            return BodyChoice {
                format: BodyFormat::Mime,
                truncation,
                all_or_none: preference.is_some_and(|preference| preference.all_or_none),
                preview: preference.and_then(|preference| preference.preview),
                fallback: None,
            };
        }
        BodyChoice::text(&options.body_preferences).unwrap_or_else(BodyChoice::plain)
    }

    pub fn select_part(options: Option<&SyncOptions>) -> Option<Self> {
        options.and_then(|options| BodyChoice::text(&options.body_part_preferences))
    }

    pub fn shows_body(options: Option<&SyncOptions>) -> bool {
        options.is_none_or(|options| {
            !options.body_preferences.is_empty()
                || options.body_part_preferences.is_empty()
                || options.mime_support == Some(MIME_SUPPORT_ALWAYS)
        })
    }

    fn text(preferences: &[BodyPreference]) -> Option<Self> {
        let mut texts = preferences.iter().filter_map(|preference| {
            let kind = match preference.body_type {
                BodyType::Plain => TextKind::Plain,
                BodyType::Html => TextKind::Html,
                BodyType::Rtf | BodyType::Mime => return None,
            };
            Some((kind, preference))
        });
        let (kind, preference) = texts.next()?;
        let mut choice = BodyChoice::from_preference(BodyFormat::Text(kind), preference);
        if choice.all_or_none && choice.truncation.is_some() {
            choice.fallback = texts.next().map(|(kind, preference)| Fallback {
                kind,
                truncation: preference.truncation_size,
                all_or_none: preference.all_or_none,
                preview: preference.preview,
            });
        }
        Some(choice)
    }

    fn plain() -> Self {
        BodyChoice {
            format: BodyFormat::Text(TextKind::Plain),
            truncation: None,
            all_or_none: false,
            preview: None,
            fallback: None,
        }
    }

    fn from_preference(format: BodyFormat, preference: &BodyPreference) -> Self {
        BodyChoice {
            format,
            truncation: preference.truncation_size,
            all_or_none: preference.all_or_none,
            preview: preference.preview,
            fallback: None,
        }
    }

    pub fn is_smime(meta: &ArchivedMessageMetadata) -> bool {
        meta.root()
            .root_part()
            .content_type()
            .is_some_and(|content_type| {
                let mime_type = content_type.mime_type();
                hashify::set_ignore_case!(
                    mime_type.as_bytes(),
                    "multipart/signed",
                    "application/pkcs7-mime",
                    "application/x-pkcs7-mime",
                )
            })
    }

    pub fn blob_range(&self, meta: &ArchivedMessageMetadata) -> Option<Range<usize>> {
        match (self.format, self.truncation) {
            (_, Some(0)) if self.fallback.is_none() => None,
            (BodyFormat::Mime, Some(limit)) => Some(
                0..meta.blob_body_offset().saturating_add(
                    usize::try_from(limit)
                        .unwrap_or(usize::MAX)
                        .saturating_sub(meta.headers_len()),
                ),
            ),
            _ => Some(0..usize::MAX),
        }
    }

    pub fn render<'a>(
        &self,
        meta: &'a ArchivedMessageMetadata,
        raw: Option<&RawMessage<'_>>,
    ) -> Option<Body<'a>> {
        let (choice, content) = self.resolve(meta, raw);
        Some(choice.finish(meta, raw.is_some(), content))
    }

    pub fn render_with_part<'a>(
        body: Option<&BodyChoice>,
        part: Option<&BodyChoice>,
        meta: &'a ArchivedMessageMetadata,
        raw: Option<&RawMessage<'_>>,
    ) -> (Option<Body<'a>>, Option<BodyPart<'a>>) {
        let Some(body) = body else {
            return (
                None,
                part.map(|part| part.render_part(meta, raw, part.content(meta, raw))),
            );
        };
        let (choice, content) = body.resolve(meta, raw);
        let part = part.map(|part| {
            let part_content = if part.format == choice.format {
                content.clone()
            } else {
                part.content(meta, raw)
            };
            part.render_part(meta, raw, part_content)
        });
        (Some(choice.finish(meta, raw.is_some(), content)), part)
    }

    fn render_part<'a>(
        &self,
        meta: &'a ArchivedMessageMetadata,
        raw: Option<&RawMessage<'_>>,
        content: Content,
    ) -> BodyPart<'a> {
        let body = self.finish(meta, raw.is_some(), content);
        BodyPart {
            status: Some(BodyPartStatus::SUCCESS.code()),
            body_type: body.body_type,
            estimated_data_size: body.estimated_data_size,
            truncated: body.truncated,
            data: body.data,
            preview: body.preview,
        }
    }

    fn resolve(
        &self,
        meta: &ArchivedMessageMetadata,
        raw: Option<&RawMessage<'_>>,
    ) -> (BodyChoice, Content) {
        let content = self.content(meta, raw);
        match (self.fallback, self.limit()) {
            (Some(fallback), Some(limit))
                if self.all_or_none && raw.is_some() && content.full_len > limit =>
            {
                let choice = fallback.choice();
                let content = choice.content(meta, raw);
                (choice, content)
            }
            _ => (*self, content),
        }
    }

    fn content(&self, meta: &ArchivedMessageMetadata, raw: Option<&RawMessage<'_>>) -> Content {
        let limit = self.limit();
        match self.format {
            BodyFormat::Mime => {
                let whole = raw.and_then(RawMessage::whole);
                let len = whole.map_or(0, |whole| whole.len());
                let keep = limit.map_or(len, |limit| limit.min(len));
                Content {
                    body_type: BodyType::Mime,
                    data: whole
                        .and_then(|whole| whole.view(0..keep))
                        .map(|prefix| prefix.to_vec())
                        .unwrap_or_default(),
                    full_len: meta.size().max(len),
                }
            }
            BodyFormat::Text(kind) => {
                let data = raw
                    .map(|raw| text_body(meta, raw, kind).into_bytes())
                    .unwrap_or_default();
                Content {
                    body_type: match kind {
                        TextKind::Plain => BodyType::Plain,
                        TextKind::Html => BodyType::Html,
                    },
                    full_len: data.len(),
                    data,
                }
            }
        }
    }

    fn finish<'a>(
        &self,
        meta: &'a ArchivedMessageMetadata,
        loaded: bool,
        content: Content,
    ) -> Body<'a> {
        let Content {
            body_type,
            data,
            full_len,
        } = content;
        let estimated = if loaded {
            u32::try_from(full_len).unwrap_or(u32::MAX)
        } else {
            u32::try_from(meta.size()).unwrap_or(u32::MAX)
        };
        let mut body = Body {
            body_type: Some(body_type.code()),
            estimated_data_size: Some(estimated),
            preview: self.preview.filter(|preview| *preview > 0).map(|preview| {
                Cow::Borrowed(char_prefix(
                    meta.preview().trim_start(),
                    usize::from(preview),
                ))
            }),
            ..Default::default()
        };
        match self.limit() {
            Some(limit) if full_len > limit || !loaded => {
                body.truncated = Some(true);
                if !self.all_or_none && limit > 0 {
                    let mut data = data;
                    data.truncate(cut_point(&data, limit, self.format));
                    body.data = Some(blob(data));
                }
            }
            _ if !loaded => {
                body.truncated = Some(true);
            }
            _ => {
                body.data = Some(blob(data));
            }
        }
        if body_type == BodyType::Plain && body.data.is_some() {
            body.preview = None;
        }
        body
    }

    fn limit(&self) -> Option<usize> {
        self.truncation
            .map(|limit| usize::try_from(limit).unwrap_or(usize::MAX))
    }
}

#[derive(Clone)]
struct Content {
    body_type: BodyType,
    data: Vec<u8>,
    full_len: usize,
}

impl BodyChoice {
    pub fn render_text<'a>(&self, text: &'a str) -> Body<'a> {
        let (body_type, data) = match self.format {
            BodyFormat::Text(TextKind::Html) => (BodyType::Html, Cow::Owned(html_text(text))),
            BodyFormat::Text(TextKind::Plain) | BodyFormat::Mime => {
                (BodyType::Plain, Cow::Borrowed(text))
            }
        };
        let full_len = data.len();
        let mut body = Body {
            body_type: Some(body_type.code()),
            estimated_data_size: Some(u32::try_from(full_len).unwrap_or(u32::MAX)),
            preview: self
                .preview
                .filter(|preview| *preview > 0)
                .map(|preview| Cow::Borrowed(char_prefix(text.trim_start(), usize::from(preview)))),
            ..Default::default()
        };
        let limit = self
            .truncation
            .map(|limit| usize::try_from(limit).unwrap_or(usize::MAX));
        match limit {
            Some(limit) if full_len > limit => {
                body.truncated = Some(true);
                if !self.all_or_none && limit > 0 {
                    let cut = cut_point(data.as_bytes(), limit, self.format);
                    body.data = Some(Blob::Slice(match data {
                        Cow::Borrowed(text) => {
                            Cow::Borrowed(text.as_bytes().get(..cut).unwrap_or_default())
                        }
                        Cow::Owned(text) => {
                            let mut bytes = text.into_bytes();
                            bytes.truncate(cut);
                            Cow::Owned(bytes)
                        }
                    }));
                }
            }
            _ => {
                body.data = Some(Blob::Slice(match data {
                    Cow::Borrowed(text) => Cow::Borrowed(text.as_bytes()),
                    Cow::Owned(text) => Cow::Owned(text.into_bytes()),
                }));
            }
        }
        if body_type == BodyType::Plain && body.data.is_some() {
            body.preview = None;
        }
        body
    }
}

impl BodyChoice {
    pub fn render_owned(&self, text: &str) -> Body<'static> {
        let body = self.render_text(text);
        Body {
            body_type: body.body_type,
            estimated_data_size: body.estimated_data_size,
            truncated: body.truncated,
            data: body.data.map(|data| blob(data.as_bytes().to_vec())),
            part: body.part,
            preview: body.preview.map(|preview| Cow::Owned(preview.into_owned())),
        }
    }
}

fn html_text(text: &str) -> String {
    let mut html = String::with_capacity(text.len() + 32);
    html.push_str("<html><body>");
    for ch in text.chars() {
        match ch {
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '&' => html.push_str("&amp;"),
            '"' => html.push_str("&quot;"),
            '\n' => html.push_str("<br>"),
            '\r' => {}
            _ => html.push(ch),
        }
    }
    html.push_str("</body></html>");
    html
}

fn blob<'a>(data: Vec<u8>) -> Blob<'a> {
    if data.len() >= SHARED_MIN_LEN {
        Blob::Shared(Bytes::from(data))
    } else {
        Blob::Slice(Cow::Owned(data))
    }
}

fn cut_point(data: &[u8], limit: usize, format: BodyFormat) -> usize {
    match format {
        BodyFormat::Mime => limit,
        BodyFormat::Text(_) => {
            let mut cut = limit.min(data.len());
            while cut > 0 && data.get(cut).is_some_and(|byte| byte & 0xC0 == 0x80) {
                cut -= 1;
            }
            cut
        }
    }
}

pub fn incoming_body<'a>(body: &'a Body<'_>) -> Option<(TextKind, &'a str)> {
    body.text().map(|(kind, text)| {
        (
            match kind {
                BodyType::Html => TextKind::Html,
                _ => TextKind::Plain,
            },
            text,
        )
    })
}

pub fn incoming_text<'a>(body: &'a Body<'_>) -> Option<Cow<'a, str>> {
    body.description()
}

pub fn char_prefix(text: &str, chars: usize) -> &str {
    match text.char_indices().nth(chars) {
        Some((end, _)) => text.get(..end).unwrap_or(text),
        None => text,
    }
}

pub(crate) fn text_body(
    meta: &ArchivedMessageMetadata,
    raw: &RawMessage<'_>,
    kind: TextKind,
) -> String {
    message_text_body(meta.root(), &PartSource::Raw(*raw), kind)
}

pub(crate) fn message_text_body(
    message: MessageView<'_>,
    source: &PartSource<'_>,
    kind: TextKind,
) -> String {
    let mut out = String::new();
    let parts = message.body_list(match kind {
        TextKind::Plain => BodyList::Text,
        TextKind::Html => BodyList::Html,
    });
    for part in parts {
        let Some(decoded) = part.text(source) else {
            continue;
        };
        let text = match (kind, part.kind()) {
            (TextKind::Plain, PartKind::Html) => {
                Cow::Owned(mail_parser::html_to_text(&decoded.text))
            }
            (TextKind::Html, PartKind::Text) => {
                Cow::Owned(mail_parser::text_to_html(&decoded.text))
            }
            _ => decoded.text,
        };
        if out.is_empty() {
            out = text.into_owned();
        } else {
            if kind == TextKind::Plain {
                out.push('\n');
            }
            out.push_str(&text);
        }
    }
    out
}
