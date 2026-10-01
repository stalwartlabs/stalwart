/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    source::{DecodedSources, SourceView},
    structure::Binary,
};
use email::message::metadata::{
    HeaderList, HeaderMatcher, HeaderView, MessageView, PartFlags, PartKind, PartView, RawMessage,
};
use imap_proto::protocol::{
    fetch::{BodyContents, Section},
    push_int,
};
use std::ops::Range;
use utils::chained_bytes::ChainedBytes;

const CONTENT_PREFIX: &[u8] = b"content-";
const MAX_FIELDS_CAPACITY: usize = 16 * 1024;

pub(super) trait MessageSections {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    );
    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>>;
    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>>;
    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>>;
    fn binary_size(&self, sections: &[u32]) -> Binary<usize>;
}

impl MessageSections for MessageView<'_> {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
    ) {
        let part = self.root_part();
        let fields = part.headers();
        let gap = part.header_gap(&SourceView::Bytes(headers));
        if gap.is_empty() {
            fields.write_header_fields(buf, headers, section, matcher, |_| true);
        } else {
            fields.write_header_fields(buf, headers, section, matcher, |header| {
                !gap.contains(&header.field_range().start)
            });
        }
    }

    fn header<'x>(&self, raw: RawMessage<'x>) -> Option<ChainedBytes<'x>> {
        let part = self.root_part();
        let source = SourceView::Raw(raw);
        source.view_without(part.header_range(), part.header_gap(&source))
    }

    fn body_section<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[Section],
        partial: Option<(u32, u32)>,
        matcher: Option<&HeaderMatcher>,
    ) -> Option<BodyContents<'x>> {
        let mut part = self.root_part();
        if sections.is_empty() {
            return raw
                .view(part.raw_range())
                .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
        }

        let mut sections_iter = sections.iter().enumerate().peekable();
        while let Some((section_num, section)) = sections_iter.next() {
            match section {
                Section::Part { num } => {
                    part = if part.is_multipart() {
                        part.child((*num).saturating_sub(1) as usize)?
                    } else if *num == 1
                        && (section_num == sections.len() - 1
                            || part.is_message()
                            || (part.is_message_root()
                                && matches!(sections_iter.peek(), Some((_, Section::Mime)))))
                    {
                        part
                    } else {
                        return None;
                    };

                    if part.is_message()
                        && let Some((
                            _,
                            Section::Part { .. }
                            | Section::Header
                            | Section::HeaderFields { .. }
                            | Section::Text,
                        )) = sections_iter.peek()
                    {
                        part = part.nested()?.root_part();
                    }
                }
                Section::Header => {
                    let source = sources.source(part.message(), raw)?;
                    return source
                        .view_without(part.header_range(), part.header_gap(&source))
                        .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
                }
                Section::HeaderFields { not, fields } => {
                    let built;
                    let matcher = match matcher {
                        Some(matcher) => matcher,
                        None => {
                            built = HeaderMatcher::new(fields.iter().map(String::as_str));
                            &built
                        }
                    };
                    return part.fields_section(sources, raw, partial, |source| {
                        part.collect_fields(source, |header, field| {
                            matcher.matches_field(header, field) != *not
                        })
                    });
                }
                Section::Text => {
                    let message = part.message();
                    let source = sources.source(message, raw)?;
                    let mut range = part.body_range();
                    if part.is_message_root()
                        && let Some(container) = message.container()
                    {
                        let end = if message
                            .source_part()
                            .is_some_and(|source_part| source_part.id() == container.id())
                        {
                            source.len()
                        } else {
                            container.offset_end()
                        };
                        if end > range.end {
                            range.end = end;
                        }
                    }
                    return source
                        .view(range)
                        .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
                }
                Section::Mime => {
                    if !part.is_message_root() {
                        return sources
                            .source(part.message(), raw)?
                            .view(part.header_range())
                            .map(|bytes| BodyContents::Bytes(bytes).partial(partial));
                    }
                    return part.fields_section(sources, raw, partial, |source| {
                        part.collect_fields(source, |header, field| header.is_mime_field(field))
                    });
                }
            }
        }

        sources
            .source(part.message(), raw)?
            .view(part.body_range())
            .map(|bytes| BodyContents::Bytes(bytes).partial(partial))
    }

    fn binary<'x>(
        &self,
        raw: RawMessage<'x>,
        sources: &'x mut DecodedSources,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Binary<BodyContents<'x>> {
        let Some(part) = self.root_part().descend(sections) else {
            return Binary::Missing;
        };
        if part.flags().contains(PartFlags::UNKNOWN_TRANSFER_ENCODING) {
            return Binary::UnknownCte;
        }
        let contents = match part.kind() {
            PartKind::Text | PartKind::Html | PartKind::Binary | PartKind::InlineBinary => {
                match sources.leaf(part, raw) {
                    Some(bytes) => BodyContents::Bytes(bytes),
                    None => return Binary::Missing,
                }
            }
            PartKind::Message => {
                let Some(nested) = part.nested() else {
                    return Binary::Missing;
                };
                match sources.source(nested, raw) {
                    Some(source) => source
                        .view(nested.root_part().raw_range())
                        .map_or(BodyContents::Owned(Vec::new()), BodyContents::Bytes),
                    None => return Binary::Missing,
                }
            }
            PartKind::Multipart => match sources.source(part.message(), raw) {
                Some(source) => source
                    .view(part.raw_range())
                    .map_or(BodyContents::Owned(Vec::new()), BodyContents::Bytes),
                None => return Binary::Missing,
            },
        };
        Binary::Found(contents.partial(partial))
    }

    fn binary_size(&self, sections: &[u32]) -> Binary<usize> {
        let Some(part) = self.root_part().descend(sections) else {
            return Binary::Missing;
        };
        if part.flags().contains(PartFlags::UNKNOWN_TRANSFER_ENCODING) {
            return Binary::UnknownCte;
        }
        Binary::Found(match part.kind() {
            PartKind::Multipart => part.raw_range().len(),
            _ => part.decoded_size() as usize,
        })
    }
}

trait PartSections<'a>: Sized {
    fn descend(self, sections: &[u32]) -> Option<Self>;
    fn fields_section<'x>(
        &self,
        sources: &'x mut DecodedSources,
        raw: RawMessage<'x>,
        partial: Option<(u32, u32)>,
        collect: impl FnOnce(&SourceView<'_>) -> Vec<u8>,
    ) -> Option<BodyContents<'x>>;
    fn header_gap(&self, source: &SourceView<'_>) -> Range<usize>;
    fn collect_fields(
        &self,
        source: &SourceView<'_>,
        select: impl Fn(HeaderView<'_>, &[u8]) -> bool,
    ) -> Vec<u8>;
}

impl<'a> PartSections<'a> for PartView<'a> {
    fn descend(self, sections: &[u32]) -> Option<Self> {
        let mut part = self;
        let mut sections_iter = sections.iter().enumerate().peekable();
        while let Some((section_num, num)) = sections_iter.next() {
            part = if part.is_multipart() {
                part.child((*num).saturating_sub(1) as usize)?
            } else if *num == 1 && (section_num == sections.len() - 1 || part.is_message()) {
                part
            } else {
                return None;
            };
            if part.is_message() && sections_iter.peek().is_some() {
                part = part.nested()?.root_part();
            }
        }
        Some(part)
    }

    fn fields_section<'x>(
        &self,
        sources: &'x mut DecodedSources,
        raw: RawMessage<'x>,
        partial: Option<(u32, u32)>,
        collect: impl FnOnce(&SourceView<'_>) -> Vec<u8>,
    ) -> Option<BodyContents<'x>> {
        let source = sources.source(self.message(), raw)?;
        Some(BodyContents::Owned(collect(&source)).partial(partial))
    }

    fn header_gap(&self, source: &SourceView<'_>) -> Range<usize> {
        if !self.is_message_root() {
            return 0..0;
        }
        let message = self.message();
        let prefix = if message.id() == 0 {
            message.metadata().extra_headers_len()
        } else {
            0
        };
        let start = self.offset_header().saturating_add(prefix);
        let first_field = |header: HeaderView<'_>| {
            let range = header.field_range();
            (range.start >= start
                && (header.id().is_known()
                    || source
                        .get(range.clone())
                        .is_some_and(|field| header.raw_name_in(&field).is_field_name())))
            .then_some(range.start)
        };
        let end = self.headers().iter().find_map(first_field);
        start..end.unwrap_or(start)
    }

    fn collect_fields(
        &self,
        source: &SourceView<'_>,
        select: impl Fn(HeaderView<'_>, &[u8]) -> bool,
    ) -> Vec<u8> {
        let gap = self.header_gap(source);
        let mut headers = Vec::with_capacity(self.header_range().len().min(MAX_FIELDS_CAPACITY));
        for header in self.headers().iter() {
            let range = header.field_range();
            if !gap.contains(&range.start)
                && let Some(field) = source.get(range)
                && select(header, &field)
            {
                headers.extend_from_slice(&field);
            }
        }
        headers.extend_from_slice(b"\r\n");
        headers
    }
}

trait HeaderFieldsWriter {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
        keep: impl Fn(&HeaderView<'_>) -> bool,
    );
}

impl HeaderFieldsWriter for HeaderList<'_> {
    fn write_header_fields(
        &self,
        buf: &mut Vec<u8>,
        headers: &[u8],
        section: &Section,
        matcher: &HeaderMatcher,
        keep: impl Fn(&HeaderView<'_>) -> bool,
    ) {
        let not = matches!(section, Section::HeaderFields { not: true, .. });
        let selected = || {
            self.iter().filter(|header| {
                keep(header)
                    && matcher.matches(*header, headers) != not
                    && headers.get(header.field_range()).is_some()
            })
        };
        let len = selected()
            .map(|header| header.field_range().len())
            .sum::<usize>()
            + 2;
        buf.extend_from_slice(b"BODY[");
        section.serialize(buf);
        buf.extend_from_slice(b"] {");
        push_int(buf, len);
        buf.extend_from_slice(b"}\r\n");
        for header in selected() {
            if let Some(field) = headers.get(header.field_range()) {
                buf.extend_from_slice(field);
            }
        }
        buf.extend_from_slice(b"\r\n");
    }
}

trait FieldName {
    fn is_field_name(&self) -> bool;
}

impl FieldName for [u8] {
    fn is_field_name(&self) -> bool {
        !self.is_empty() && self.iter().all(|byte| matches!(byte, 33..=57 | 59..=126))
    }
}

trait MimeField {
    fn is_mime_field(&self, field: &[u8]) -> bool;
}

impl MimeField for HeaderView<'_> {
    fn is_mime_field(&self, field: &[u8]) -> bool {
        self.id().is_mime()
            || self
                .raw_name_in(field)
                .get(..CONTENT_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CONTENT_PREFIX))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        source::DecodedSources,
        structure::{Binary, ImapMetadata, tests::Stored},
    };
    use email::message::metadata::{ExtraHeaders, HeaderId, HeaderMatcher};
    use imap_proto::protocol::fetch::{BodyContents, DataItem, Section};
    use std::borrow::Cow;

    const SIMPLE: &str = concat!(
        "subject: lower case\r\n",
        "X-custom-HEADER: custom\r\n",
        "FROM: a@example.com\r\n",
        "content-type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Hello there\r\n",
        "second line\r\n"
    );

    #[test]
    fn body_section_views_the_whole_message_without_copying() {
        let mut extra = ExtraHeaders::default();
        extra
            .push(HeaderId::DELIVERED_TO, "jdoe@example.org")
            .push(HeaderId::X_SPAM_STATUS, "No");
        let stored = Stored::with_extra(SIMPLE, &extra);
        let row = stored.row();
        let meta = row.unarchive().expect("unarchives");
        let headers = row.raw_headers().expect("headers");
        let raw = meta.raw_message(Some(&headers), &stored.blob);
        let expected = [extra.as_bytes(), SIMPLE.as_bytes()].concat();

        let mut sources = DecodedSources::default();
        let whole = meta
            .body_section(raw, &mut sources, &[], None, None)
            .expect("whole message");
        assert!(matches!(whole, BodyContents::Bytes(_)));
        assert_eq!(whole.as_chained().to_vec(), expected);
        assert_eq!(whole.len(), meta.size());

        let text = meta
            .body_section(raw, &mut sources, &[Section::Text], None, None)
            .expect("text");
        assert!(matches!(text, BodyContents::Bytes(_)));
        assert_eq!(
            text.as_chained().to_vec(),
            b"Hello there\r\nsecond line\r\n".to_vec()
        );
        assert_eq!(
            stored.section(&[Section::Header], None),
            Some(headers.to_vec())
        );
        assert_eq!(
            stored.body_only_section(&[Section::Text], None),
            Some(b"Hello there\r\nsecond line\r\n".to_vec())
        );
        assert_eq!(stored.body_only_section(&[], None), None);
    }

    #[test]
    fn partial_past_u32_max() {
        let stored = Stored::new(SIMPLE);
        assert_eq!(
            stored.section(&[], Some((1, u32::MAX))),
            Some(SIMPLE.as_bytes().get(1..).unwrap_or_default().to_vec())
        );
        assert_eq!(
            stored.section(&[Section::Text], Some((u32::MAX, u32::MAX))),
            Some(Vec::new())
        );
        assert_eq!(
            stored.binary(&[1], Some((6, u32::MAX))),
            Binary::Found(b"there\r\nsecond line\r\n".to_vec())
        );

        let row = stored.row();
        let meta = row.unarchive().expect("unarchives");
        let headers = row.raw_headers().expect("headers");
        let raw = meta.raw_message(Some(&headers), &stored.blob);
        let mut buf = Vec::new();
        DataItem::BodySection {
            sections: Cow::Borrowed(&[]),
            origin_octet: Some(1),
            contents: meta
                .body_section(
                    raw,
                    &mut DecodedSources::default(),
                    &[],
                    Some((1, u32::MAX)),
                    None,
                )
                .expect("partial"),
        }
        .serialize(&mut buf);
        assert!(buf.starts_with(format!("BODY[]<1> {{{}}}\r\n", SIMPLE.len() - 1).as_bytes()));
    }

    #[test]
    fn header_fields_keep_names_as_written() {
        let stored = Stored::new(SIMPLE);
        let row = stored.row();
        let meta = row.unarchive().expect("unarchives");
        let headers = row.raw_headers().expect("headers");
        let raw = meta.raw_message(Some(&headers), &stored.blob);

        for (not, fields, expected) in [
            (
                false,
                vec!["Subject".to_string(), "x-custom-header".to_string()],
                "subject: lower case\r\nX-custom-HEADER: custom\r\n\r\n",
            ),
            (
                true,
                vec!["SUBJECT".to_string(), "Content-Type".to_string()],
                "X-custom-HEADER: custom\r\nFROM: a@example.com\r\n\r\n",
            ),
            (false, vec!["X-Missing".to_string()], "\r\n"),
        ] {
            let matcher = HeaderMatcher::new(fields.iter().map(String::as_str));
            let sections = [Section::HeaderFields { not, fields }];
            let [section] = &sections;
            assert_eq!(
                stored.section(&sections, None),
                Some(expected.as_bytes().to_vec())
            );

            let mut direct = Vec::new();
            meta.write_header_fields(&mut direct, &headers, section, &matcher);
            let mut through_item = Vec::new();
            DataItem::BodySection {
                sections: Cow::Borrowed(&sections),
                origin_octet: None,
                contents: meta
                    .body_section(
                        raw,
                        &mut DecodedSources::default(),
                        &sections,
                        None,
                        Some(&matcher),
                    )
                    .expect("fields"),
            }
            .serialize(&mut through_item);
            assert_eq!(
                String::from_utf8(direct),
                String::from_utf8(through_item),
                "not {not}"
            );
        }
    }

    #[test]
    fn mime_of_root_and_nested_parts() {
        let stored = Stored::new(concat!(
            "From: a@example.com\r\n",
            "content-TYPE: multipart/mixed; boundary=\"b\"\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-X-Other: kept\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "X-Part: 1\r\n",
            "\r\n",
            "part one\r\n",
            "--b--\r\n"
        ));
        assert_eq!(
            stored.body_only_section(&[Section::Part { num: 1 }, Section::Mime], None),
            Some(b"Content-Type: text/plain\r\nX-Part: 1\r\n\r\n".to_vec())
        );
        assert_eq!(
            stored.body_only_section(&[Section::Part { num: 1 }], None),
            Some(b"part one".to_vec())
        );
    }

    #[test]
    fn binary_of_encoded_message_rfc822() {
        let inner = concat!(
            "From: inner@example.com\r\n",
            "Subject: inner\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "caf=C3=A9 au lait\r\n"
        );
        let encoded = encodify::base64::STANDARD.encode(inner.as_bytes());
        let stored = Stored::new(&format!(
            concat!(
                "From: a@example.com\r\n",
                "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                "\r\n",
                "--b\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "cover\r\n",
                "--b\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--b--\r\n"
            ),
            encoded
        ));

        assert_eq!(
            stored.binary(&[2], None),
            Binary::Found(inner.as_bytes().to_vec())
        );
        assert_eq!(stored.binary_size(&[2]), Binary::Found(inner.len()));
        let text = "caf\u{e9} au lait\r\n";
        assert_eq!(
            stored.binary(&[2, 1], None),
            Binary::Found(text.as_bytes().to_vec())
        );
        assert_eq!(stored.binary_size(&[2, 1]), Binary::Found(text.len()));
        assert_eq!(
            stored.body_only_section(&[Section::Part { num: 2 }, Section::Text], None),
            Some(b"caf=C3=A9 au lait\r\n".to_vec())
        );
        assert_eq!(
            stored.body_only_section(
                &[
                    Section::Part { num: 2 },
                    Section::HeaderFields {
                        not: false,
                        fields: vec!["subject".to_string()],
                    },
                ],
                None
            ),
            Some(b"Subject: inner\r\n\r\n".to_vec())
        );
        assert_eq!(stored.binary(&[3], None), Binary::Missing);
    }

    #[test]
    fn malformed_base64_binary_matches_size() {
        let stored = Stored::new(concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "SGVs!bG8=\r\n",
            "--b\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Transfer-Encoding: x-unknown\r\n",
            "\r\n",
            "opaque\r\n",
            "--b--\r\n"
        ));
        assert_eq!(stored.binary(&[1], None), Binary::Found(b"Hello".to_vec()));
        assert_eq!(stored.binary_size(&[1]), Binary::Found(b"Hello".len()));
        assert_eq!(stored.binary(&[2], None), Binary::UnknownCte);
        assert_eq!(stored.binary_size(&[2]), Binary::UnknownCte);
    }

    #[test]
    fn text_of_message_inside_decoded_container_stops_at_its_container() {
        let inner = concat!(
            "From: b@example.com\r\n",
            "Subject: B\r\n",
            "Content-Type: multipart/mixed; boundary=\"bb\"\r\n",
            "\r\n",
            "--bb\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: c@example.com\r\n",
            "Subject: C\r\n",
            "\r\n",
            "C body\r\n",
            "--bb\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "B trailing part that must not leak into C\r\n",
            "--bb--\r\n",
        );
        let outer = |encoding: &str, body: &str| {
            Stored::new(&format!(
                concat!(
                    "From: a@example.com\r\n",
                    "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                    "\r\n",
                    "--b\r\n",
                    "Content-Type: text/plain\r\n",
                    "\r\n",
                    "cover\r\n",
                    "--b\r\n",
                    "Content-Type: message/rfc822\r\n",
                    "Content-Transfer-Encoding: {}\r\n",
                    "\r\n",
                    "{}\r\n",
                    "--b--\r\n"
                ),
                encoding, body
            ))
        };
        let nested_text = [
            Section::Part { num: 2 },
            Section::Part { num: 1 },
            Section::Text,
        ];
        let encoded = outer(
            "base64",
            &encodify::base64::STANDARD.encode(inner.as_bytes()),
        );
        let plain = outer("7bit", inner);
        assert_eq!(
            encoded.body_only_section(&nested_text, None),
            Some(b"C body".to_vec())
        );
        assert_eq!(
            plain.body_only_section(&nested_text, None),
            encoded.body_only_section(&nested_text, None)
        );
        assert_eq!(
            encoded.body_only_section(&[Section::Part { num: 2 }, Section::Text], None),
            Some(
                inner
                    .split_once("\r\n\r\n")
                    .map(|(_, text)| text.as_bytes().to_vec())
                    .unwrap_or_default()
            )
        );
    }

    #[test]
    fn header_sections_skip_leading_non_header_lines() {
        const MBOX: &str = concat!(
            "From user@domain  Fri Feb 22 17:06:23 2008\r\n",
            "From: user@domain.org\r\n",
            "Subject: s\r\n",
            "X-A: b\r\n",
            "\r\n",
            "body\r\n"
        );
        let mut delivery = ExtraHeaders::default();
        delivery.push(HeaderId::DELIVERED_TO, "jdoe@example.org");
        for extra in [ExtraHeaders::default(), delivery] {
            let stored = Stored::with_extra(MBOX, &extra);
            let header = [
                extra.as_bytes(),
                b"From: user@domain.org\r\nSubject: s\r\nX-A: b\r\n\r\n",
            ]
            .concat();
            let not_subject =
                [extra.as_bytes(), b"From: user@domain.org\r\nX-A: b\r\n\r\n"].concat();
            assert_eq!(
                stored.section(&[Section::Header], None),
                Some(header.clone())
            );
            assert_eq!(
                stored.section(&[], None),
                Some([extra.as_bytes(), MBOX.as_bytes()].concat())
            );

            let row = stored.row();
            let meta = row.unarchive().expect("unarchives");
            let headers = row.raw_headers().expect("headers");
            let raw = meta.raw_message(Some(&headers), &stored.blob);
            assert_eq!(meta.header(raw).map(|bytes| bytes.to_vec()), Some(header));

            let fields = vec!["Subject".to_string()];
            let matcher = HeaderMatcher::new(fields.iter().map(String::as_str));
            let sections = [Section::HeaderFields { not: true, fields }];
            let [section] = &sections;
            assert_eq!(stored.section(&sections, None), Some(not_subject.clone()));
            let mut direct = Vec::new();
            meta.write_header_fields(&mut direct, &headers, section, &matcher);
            let mut expected = format!(
                "BODY[HEADER.FIELDS.NOT (SUBJECT)] {{{}}}\r\n",
                not_subject.len()
            )
            .into_bytes();
            expected.extend_from_slice(&not_subject);
            assert_eq!(String::from_utf8(direct), String::from_utf8(expected));
        }

        let stored = Stored::new(concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "cover\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From inner@example.com Sat Mar 24 23:00:00 2007\r\n",
            "a line without a colon\r\n",
            "From: inner@example.com\r\n",
            "Subject: inner\r\n",
            "\r\n",
            "inner body\r\n",
            "--b--\r\n"
        ));
        assert_eq!(
            stored.body_only_section(&[Section::Part { num: 2 }, Section::Header], None),
            Some(b"From: inner@example.com\r\nSubject: inner\r\n\r\n".to_vec())
        );
        assert_eq!(
            stored.body_only_section(
                &[
                    Section::Part { num: 2 },
                    Section::HeaderFields {
                        not: true,
                        fields: vec!["Subject".to_string()],
                    },
                ],
                None
            ),
            Some(b"From: inner@example.com\r\n\r\n".to_vec())
        );
    }

    #[test]
    fn decoded_sources_are_decoded_once_per_message() {
        let inner = format!(
            concat!(
                "From: inner@example.com\r\n",
                "Subject: inner\r\n",
                "Content-Type: multipart/mixed; boundary=\"i\"\r\n",
                "\r\n",
                "--i\r\n",
                "Content-Type: text/plain\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--i--\r\n"
            ),
            encodify::base64::STANDARD.encode("0123456789\r\n".repeat(512).as_bytes())
        );
        let stored = Stored::new(&format!(
            concat!(
                "From: a@example.com\r\n",
                "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                "\r\n",
                "--b\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "cover\r\n",
                "--b\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--b--\r\n"
            ),
            encodify::base64::STANDARD.encode(inner.as_bytes())
        ));
        let row = stored.row();
        let meta = row.unarchive().expect("unarchives");
        let headers = row.raw_headers().expect("headers");
        let raw = meta.raw_message(Some(&headers), &stored.blob);
        let text = [Section::Part { num: 2 }, Section::Text];
        let fields = [
            Section::Part { num: 2 },
            Section::HeaderFields {
                not: false,
                fields: vec!["Subject".to_string()],
            },
        ];

        let mut sources = DecodedSources::default();
        for offset in 0..64u32 {
            let partial = Some((offset * 7, 5));
            for sections in [&text[..], &fields[..]] {
                assert_eq!(
                    meta.body_section(raw, &mut sources, sections, partial, None)
                        .map(|contents| contents.as_chained().to_vec()),
                    meta.body_section(raw, &mut DecodedSources::default(), sections, partial, None)
                        .map(|contents| contents.as_chained().to_vec()),
                    "{sections:?} {partial:?}"
                );
            }
            for sections in [&[2u32][..], &[2, 1][..]] {
                assert_eq!(
                    meta.binary(raw, &mut sources, sections, partial)
                        .map(|contents| contents.as_chained().to_vec()),
                    meta.binary(raw, &mut DecodedSources::default(), sections, partial)
                        .map(|contents| contents.as_chained().to_vec()),
                    "{sections:?} {partial:?}"
                );
            }
        }
        assert_eq!(sources.len(), 2);
        assert_eq!(
            meta.binary(raw, &mut sources, &[2, 1], None)
                .map(|contents| contents.len()),
            Binary::Found(512 * 12)
        );
        assert_eq!(sources.len(), 2);
    }

    const QP_LINE: &str =
        "=3D3D3D41bcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\r\n";

    fn quoted_printable_chain(levels: usize, lines: usize) -> String {
        let mut message = format!(
            concat!(
                "From: z@example.com\r\n",
                "Content-Type: text/plain\r\n",
                "Content-Transfer-Encoding: quoted-printable\r\n",
                "\r\n",
                "{}"
            ),
            QP_LINE.repeat(lines)
        );
        for level in 0..levels {
            message = format!(
                concat!(
                    "From: l{}@example.com\r\n",
                    "Content-Type: message/rfc822\r\n",
                    "Content-Transfer-Encoding: quoted-printable\r\n",
                    "\r\n",
                    "{}"
                ),
                level, message
            );
        }
        message
    }

    #[test]
    fn decoded_sources_hold_one_level_and_one_leaf() {
        let stored = Stored::new(&quoted_printable_chain(3, 8 * 1024));
        let structure = stored.structure();
        let meta = structure.unarchive().expect("unarchives");
        let raw = meta.raw_message(None, &stored.blob);
        let Binary::Found(leaf_size) = meta.binary_size(&[1, 1, 1, 1]) else {
            panic!("leaf");
        };
        let bound = stored.blob.len() + leaf_size;

        let mut sources = DecodedSources::default();
        let first = meta
            .binary(raw, &mut sources, &[1, 1, 1, 1], Some((0, 1)))
            .map(|contents| contents.as_chained().to_vec());
        assert_eq!(first, Binary::Found(b"A".to_vec()));
        assert!(
            sources.bytes_held() <= bound,
            "{} held, blob {}, bound {bound}",
            sources.bytes_held(),
            stored.blob.len()
        );

        let mut items = Vec::new();
        for depth in 1..=4usize {
            let path = vec![1u32; depth];
            let mut text = path
                .iter()
                .map(|num| Section::Part { num: *num })
                .collect::<Vec<_>>();
            text.push(Section::Text);
            items.push((path, text));
        }
        for order in [false, true] {
            let mut sources = DecodedSources::default();
            let sequence = if order {
                items.iter().rev().collect::<Vec<_>>()
            } else {
                items.iter().collect()
            };
            for (path, text) in sequence {
                assert_eq!(
                    meta.binary(raw, &mut sources, path, Some((5, 7)))
                        .map(|contents| contents.as_chained().to_vec()),
                    meta.binary(raw, &mut DecodedSources::default(), path, Some((5, 7)))
                        .map(|contents| contents.as_chained().to_vec()),
                    "{path:?}"
                );
                assert!(
                    sources.bytes_held() <= bound,
                    "{path:?}: {} held, blob {}, bound {bound}",
                    sources.bytes_held(),
                    stored.blob.len()
                );
                assert_eq!(
                    meta.body_section(raw, &mut sources, text, Some((5, 7)), None)
                        .map(|contents| contents.as_chained().to_vec()),
                    meta.body_section(
                        raw,
                        &mut DecodedSources::default(),
                        text,
                        Some((5, 7)),
                        None
                    )
                    .map(|contents| contents.as_chained().to_vec()),
                    "{text:?}"
                );
                assert!(
                    sources.bytes_held() <= bound,
                    "{text:?}: {} held, blob {}, bound {bound}",
                    sources.bytes_held(),
                    stored.blob.len()
                );
                assert!(sources.len() <= 2);
            }
        }
    }

    #[test]
    fn decoded_sources_keep_one_leaf_among_many() {
        const LEAVES: u32 = 1_000;
        let mut message = String::from(concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"m\"\r\n",
            "\r\n"
        ));
        for index in 0..LEAVES {
            message.push_str(&format!(
                concat!(
                    "--m\r\n",
                    "Content-Type: application/octet-stream\r\n",
                    "Content-Transfer-Encoding: base64\r\n",
                    "\r\n",
                    "{}\r\n"
                ),
                encodify::base64::STANDARD.encode(format!("leaf number {index}").as_bytes())
            ));
        }
        message.push_str("--m--\r\n");
        let stored = Stored::new(&message);
        let structure = stored.structure();
        let meta = structure.unarchive().expect("unarchives");
        let raw = meta.raw_message(None, &stored.blob);

        let mut sources = DecodedSources::default();
        for offset in 0..2u32 {
            for part in 1..=LEAVES {
                let expected = format!("leaf number {}", part - 1);
                assert_eq!(
                    meta.binary(raw, &mut sources, &[part], Some((offset, 64)))
                        .map(|contents| contents.as_chained().to_vec()),
                    Binary::Found(
                        expected
                            .as_bytes()
                            .get(offset as usize..)
                            .unwrap_or_default()
                            .to_vec()
                    )
                );
                assert!(sources.len() <= 1, "{}", sources.len());
            }
        }
        assert!(sources.bytes_held() < 64, "{}", sources.bytes_held());
    }

    #[test]
    fn shared_sources_match_fresh_sources_in_any_order() {
        let encode = |text: &str| encodify::base64::STANDARD.encode(text.as_bytes());
        let deepest = concat!(
            "From: i3@example.com\r\n",
            "Subject: inner three\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "SW5uZXIgdGhyZWUgYm9keSB0ZXh0Cg==\r\n"
        );
        let plain = concat!(
            "From: i2@example.com\r\n",
            "Subject: inner two\r\n",
            "Content-Type: multipart/mixed; boundary=\"j\"\r\n",
            "\r\n",
            "--j\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "ZGVlcCBiaW5hcnkgZGF0YQ==\r\n",
            "--j\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "caf=C3=A9 two\r\n",
            "--j--\r\n"
        );
        let inner = format!(
            concat!(
                "From: i1@example.com\r\n",
                "Subject: inner one\r\n",
                "Content-Type: multipart/mixed; boundary=\"i\"\r\n",
                "\r\n",
                "--i\r\n",
                "Content-Type: text/plain\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "bGVhZiBvbmUgdGV4dA==\r\n",
                "--i\r\n",
                "Content-Type: message/rfc822\r\n",
                "\r\n",
                "{}\r\n",
                "--i\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--i--\r\n"
            ),
            plain,
            encode(deepest)
        );
        let stored = Stored::new(&format!(
            concat!(
                "From: a@example.com\r\n",
                "Subject: outer\r\n",
                "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                "\r\n",
                "--b\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "cover\r\n",
                "--b\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--b\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: quoted-printable\r\n",
                "\r\n",
                "From: i4@example.com\r\n",
                "Subject: inner four\r\n",
                "\r\n",
                "four=20body\r\n",
                "--b--\r\n"
            ),
            encode(&inner)
        ));
        let row = stored.row();
        let meta = row.unarchive().expect("unarchives");
        let headers = row.raw_headers().expect("headers");
        let raw = meta.raw_message(Some(&headers), &stored.blob);

        let suffixes = [
            None,
            Some(Section::Header),
            Some(Section::Text),
            Some(Section::Mime),
            Some(Section::HeaderFields {
                not: false,
                fields: vec!["Subject".to_string(), "Content-Type".to_string()],
            }),
            Some(Section::HeaderFields {
                not: true,
                fields: vec!["Subject".to_string()],
            }),
        ];
        let mut paths = vec![vec![]];
        for first in 1..4u32 {
            paths.push(vec![first]);
            for second in 1..4u32 {
                paths.push(vec![first, second]);
                for third in 1..3u32 {
                    paths.push(vec![first, second, third]);
                }
            }
        }
        let mut items = Vec::new();
        for path in &paths {
            for suffix in &suffixes {
                if path.is_empty() && matches!(suffix, Some(Section::Mime)) {
                    continue;
                }
                let mut sections = path
                    .iter()
                    .map(|num| Section::Part { num: *num })
                    .collect::<Vec<_>>();
                sections.extend(suffix.clone());
                items.push((sections, Vec::new()));
            }
            items.push((Vec::new(), path.clone()));
        }
        let run = |sources: &mut DecodedSources, (sections, binary): &(Vec<Section>, Vec<u32>)| {
            if binary.is_empty() {
                format!(
                    "{:?}",
                    meta.body_section(raw, sources, sections, Some((3, 9)), None)
                        .map(|contents| contents.as_chained().to_vec())
                )
            } else {
                format!(
                    "{:?}",
                    meta.binary(raw, sources, binary, Some((2, 11)))
                        .map(|contents| contents.as_chained().to_vec())
                )
            }
        };
        let fresh = items
            .iter()
            .map(|item| run(&mut DecodedSources::default(), item))
            .collect::<Vec<_>>();
        let found = fresh
            .iter()
            .filter(|result| !matches!(result.as_str(), "None" | "Missing"))
            .count();
        assert!(found > 60, "{found} of {} items found", items.len());

        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for round in 0..6 {
            let mut order = (0..items.len()).collect::<Vec<_>>();
            if round == 1 {
                order.reverse();
            } else if round > 1 {
                for index in (1..order.len()).rev() {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    order.swap(index, (seed % (index as u64 + 1)) as usize);
                }
            }
            let mut sources = DecodedSources::default();
            for index in order {
                let (Some(item), Some(expected)) = (items.get(index), fresh.get(index)) else {
                    panic!("item {index}");
                };
                assert_eq!(&run(&mut sources, item), expected, "{item:?}");
                assert!(sources.len() <= 2);
            }
        }
    }

    #[test]
    fn header_fields_of_large_header_blocks() {
        let mut raw = String::from("From: a@example.com\r\n");
        for index in 0..16_400 {
            raw.push_str(&format!("X-Junk: {index}\r\n"));
        }
        raw.push_str("Subject: hidden\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n");
        let stored = Stored::new(&raw);
        let row = stored.row();
        let meta = row.unarchive().expect("unarchives");
        let headers = row.raw_headers().expect("headers");

        for (not, fields, expected) in [
            (
                false,
                vec!["Subject".to_string()],
                "Subject: hidden\r\n\r\n".to_string(),
            ),
            (
                true,
                vec!["X-Junk".to_string()],
                concat!(
                    "From: a@example.com\r\n",
                    "Subject: hidden\r\n",
                    "Content-Type: text/plain; charset=utf-8\r\n\r\n"
                )
                .to_string(),
            ),
        ] {
            let matcher = HeaderMatcher::new(fields.iter().map(String::as_str));
            let sections = [Section::HeaderFields { not, fields }];
            let [section] = &sections;
            assert_eq!(
                stored.section(&sections, None),
                Some(expected.as_bytes().to_vec())
            );
            let mut direct = Vec::new();
            meta.write_header_fields(&mut direct, &headers, section, &matcher);
            assert!(
                direct.ends_with(format!("}}\r\n{expected}").as_bytes()),
                "not {not}"
            );
        }

        let mut forward = String::from("From: a@example.com\r\n");
        for index in 0..16_400 {
            forward.push_str(&format!("X-Junk: {index}\r\n"));
        }
        forward.push_str(concat!(
            "Content-Type: message/rfc822\r\n",
            "Content-Description: forwarded\r\n",
            "\r\n",
            "From: inner@example.com\r\n",
            "\r\n",
            "inner body\r\n"
        ));
        assert_eq!(
            Stored::new(&forward).section(&[Section::Part { num: 1 }, Section::Mime], None),
            Some(
                b"Content-Type: message/rfc822\r\nContent-Description: forwarded\r\n\r\n".to_vec()
            )
        );

        let mut nested = String::from(concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
        ));
        for index in 0..16_400 {
            nested.push_str(&format!("X-Junk: {index}\r\n"));
        }
        nested.push_str(concat!(
            "\r\n",
            "cover\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: inner@example.com\r\n",
            "X-Target: found\r\n",
            "\r\n",
            "inner body\r\n",
            "--b--\r\n"
        ));
        let stored = Stored::new(&nested);
        assert_eq!(
            stored.body_only_section(
                &[
                    Section::Part { num: 2 },
                    Section::HeaderFields {
                        not: false,
                        fields: vec!["x-target".to_string()],
                    },
                ],
                None
            ),
            Some(b"X-Target: found\r\n\r\n".to_vec())
        );
    }

    #[test]
    fn mime_of_a_single_part_message_is_its_mime_header() {
        let single = Stored::new(concat!(
            "From: a@example.com\r\n",
            "Subject: single\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "X-Other: kept out\r\n",
            "Content-Language: en\r\n",
            "\r\n",
            "caf=C3=A9\r\n"
        ));
        let mime = [Section::Part { num: 1 }, Section::Mime];
        assert_eq!(
            single.section(&mime, None),
            Some(
                concat!(
                    "Content-Type: text/plain; charset=utf-8\r\n",
                    "Content-Transfer-Encoding: quoted-printable\r\n",
                    "Content-Language: en\r\n",
                    "\r\n"
                )
                .as_bytes()
                .to_vec()
            )
        );
        assert_eq!(
            single.section(&[Section::Part { num: 1 }, Section::Header], None),
            None
        );

        let nested = Stored::new(concat!(
            "From: a@example.com\r\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
            "\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "cover\r\n",
            "--b\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "From: inner@example.com\r\n",
            "Content-Type: text/html\r\n",
            "Subject: inner\r\n",
            "\r\n",
            "<p>inner</p>\r\n",
            "--b--\r\n"
        ));
        assert_eq!(
            nested.body_only_section(
                &[
                    Section::Part { num: 2 },
                    Section::Part { num: 1 },
                    Section::Mime
                ],
                None
            ),
            Some(b"Content-Type: text/html\r\n\r\n".to_vec())
        );
        assert_eq!(
            nested.body_only_section(
                &[
                    Section::Part { num: 1 },
                    Section::Part { num: 1 },
                    Section::Mime
                ],
                None
            ),
            None
        );
    }
}
