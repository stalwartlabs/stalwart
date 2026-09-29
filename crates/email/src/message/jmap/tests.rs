/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BodyValueOptions, EmailNeeds, EmailRender, HeaderNeeds, JmapValue};
use crate::message::{
    metadata::{
        AddressHeader, Completeness, ExtraHeaders, HeaderId, HeaderSelection, MAX_FIELD_ADDRESSES,
        MAX_HEADER_ENTRIES, MAX_VALUE_LEN, Mailbox, MessageMetadata, MetadataRow, Occurrence,
    },
    sortkeys::MessageSortKeys,
};
use common::storage::blob::SectionDecode;
use encodify::base64::MIME;
use jmap_proto::object::email::{EmailProperty, EmailValue, HeaderForm, HeaderProperty};
use jmap_tools::{Key, Value};
use mail_parser::MessageParser;
use std::borrow::Cow;
use store::Deserialize;
use types::{
    blob::{BlobClass, BlobId, BlobSection},
    blob_hash::BlobHash,
    collection::Collection,
};

const DEFAULT_BODY_PROPERTIES: [EmailProperty; 10] = [
    EmailProperty::PartId,
    EmailProperty::BlobId,
    EmailProperty::Size,
    EmailProperty::Name,
    EmailProperty::Type,
    EmailProperty::Charset,
    EmailProperty::Disposition,
    EmailProperty::Cid,
    EmailProperty::Language,
    EmailProperty::Location,
];

struct Fixture {
    blob: Vec<u8>,
    row: MetadataRow,
    headers: Vec<u8>,
    blob_id: BlobId,
    header_needs: HeaderNeeds,
}

impl Fixture {
    fn new(raw: &str) -> Self {
        Fixture::with_extra(raw, &ExtraHeaders::default())
    }

    fn with_extra(raw: &str, extra: &ExtraHeaders) -> Self {
        let blob = raw.as_bytes().to_vec();
        let message = MessageParser::new().parse(&blob).expect("message parses");
        let hash = BlobHash::generate(&blob);
        let built = MessageMetadata::build(&message, extra, hash.clone());
        let row = MetadataRow::deserialize(&built.encode().expect("row encodes")).expect("row");
        let headers = row.raw_headers().expect("headers").into_owned();
        Fixture {
            blob,
            row,
            headers,
            header_needs: HeaderNeeds::new(&[EmailProperty::Headers], &[EmailProperty::Headers]),
            blob_id: BlobId::new(
                hash,
                BlobClass::Linked {
                    account_id: 1,
                    collection: Collection::Email.into(),
                    document_id: 2,
                },
            ),
        }
    }

    fn render<'x>(
        &'x self,
        headers: bool,
        blob: bool,
        body_properties: &'x [EmailProperty],
        options: &'x BodyValueOptions,
    ) -> EmailRender<'x, 'x> {
        self.render_with(&self.header_needs, headers, blob, body_properties, options)
    }

    fn render_with<'x>(
        &'x self,
        header_needs: &'x HeaderNeeds,
        headers: bool,
        blob: bool,
        body_properties: &'x [EmailProperty],
        options: &'x BodyValueOptions,
    ) -> EmailRender<'x, 'x> {
        EmailRender::new(
            self.row.unarchive().expect("archive"),
            headers.then_some(self.headers.as_slice()),
            blob.then_some(self.blob.as_slice()),
            &self.blob_id,
            header_needs,
            body_properties,
            options,
        )
    }
}

fn header(name: &str, form: HeaderForm, all: bool) -> EmailProperty {
    EmailProperty::Header(HeaderProperty {
        form,
        header: name.to_string(),
        all,
    })
}

fn get<'x>(value: &'x JmapValue<'_>, property: EmailProperty) -> &'x JmapValue<'x> {
    value
        .as_object_and_get(&Key::Property(property))
        .expect("property present")
}

fn is_borrowed(value: &JmapValue<'_>) -> bool {
    matches!(value, Value::Str(Cow::Borrowed(_)))
}

fn text(value: &JmapValue<'_>) -> String {
    value.as_str().map(Cow::into_owned).unwrap_or_default()
}

const LIST_MESSAGE: &str = concat!(
    "From: \"John Doe\" <jdoe@example.com>\r\n",
    "To: Jane <jane@example.com>, Team: ann@example.com;\r\n",
    "Subject: Hello there\r\n",
    "Date: Mon, 1 Jan 2024 10:00:00 +0100\r\n",
    "Message-ID: <id1@example.com>\r\n",
    "In-Reply-To: <a@example.com> <b@example.com>\r\n",
    "References: <r1@example.com>\r\n",
    " <r2@example.com>\r\n",
    "\r\n",
    "Preview text of the body\r\n",
);

#[test]
fn list_properties_borrow_from_the_archive() {
    let fixture = Fixture::new(LIST_MESSAGE);
    let options = BodyValueOptions::default();
    let properties = [
        EmailProperty::From,
        EmailProperty::To,
        EmailProperty::Subject,
        EmailProperty::SentAt,
        EmailProperty::MessageId,
        EmailProperty::InReplyTo,
        EmailProperty::Preview,
    ];
    let needs = EmailNeeds::new(&properties, &DEFAULT_BODY_PROPERTIES, &options);
    assert_eq!(
        needs,
        EmailNeeds {
            headers: false,
            blob: false,
            envelope: true,
            fallback: true
        }
    );
    assert!(!needs.headers_for(fixture.row.unarchive().expect("archive")));
    let render = fixture.render(false, false, &DEFAULT_BODY_PROPERTIES, &options);

    let subject = render.value(&EmailProperty::Subject).expect("subject");
    assert!(is_borrowed(&subject));
    assert_eq!(text(&subject), "Hello there");

    let preview = render.value(&EmailProperty::Preview).expect("preview");
    assert!(is_borrowed(&preview));
    assert_eq!(text(&preview).trim_end(), "Preview text of the body");

    let from = render.value(&EmailProperty::From).expect("from");
    let mailbox = from
        .as_array()
        .and_then(|list| list.first())
        .expect("mailbox");
    assert!(is_borrowed(get(mailbox, EmailProperty::Name)));
    assert!(is_borrowed(get(mailbox, EmailProperty::Email)));
    assert_eq!(text(get(mailbox, EmailProperty::Name)), "John Doe");
    assert_eq!(text(get(mailbox, EmailProperty::Email)), "jdoe@example.com");

    let to = render.value(&EmailProperty::To).expect("to");
    let emails = to
        .as_array()
        .expect("array")
        .iter()
        .map(|mailbox| text(get(mailbox, EmailProperty::Email)))
        .collect::<Vec<_>>();
    assert_eq!(emails, ["jane@example.com", "ann@example.com"]);

    let message_id = render.value(&EmailProperty::MessageId).expect("message id");
    let ids = message_id.as_array().expect("array");
    assert!(ids.iter().all(is_borrowed));
    assert_eq!(
        ids.iter().map(text).collect::<Vec<_>>(),
        ["id1@example.com"]
    );
    let in_reply_to = render
        .value(&EmailProperty::InReplyTo)
        .expect("in reply to");
    assert_eq!(
        in_reply_to
            .as_array()
            .expect("array")
            .iter()
            .map(text)
            .collect::<Vec<_>>(),
        ["a@example.com", "b@example.com"]
    );

    let sent_at = render.value(&EmailProperty::SentAt).expect("sent at");
    let Some(EmailValue::Date(date)) = sent_at.as_element() else {
        panic!("sentAt is not a date");
    };
    assert_eq!(
        (date.year, date.month, date.day, date.hour),
        (2024, 1, 1, 10)
    );
    assert_eq!((date.tz_before_gmt, date.tz_hour), (false, 1));

    for property in [EmailProperty::Cc, EmailProperty::Bcc, EmailProperty::Sender] {
        assert_eq!(render.value(&property), Some(Value::Null));
    }
    assert_eq!(render.value(&EmailProperty::Id), None);
    assert!(!EmailRender::renders(&EmailProperty::Id));
    assert!(EmailRender::renders(&EmailProperty::Preview));

    let empty = Fixture::new("Message-ID:\r\nIn-Reply-To: \r\nSubject:\r\n\r\n");
    let render = empty.render(false, false, &DEFAULT_BODY_PROPERTIES, &options);
    assert_eq!(
        render.value(&EmailProperty::Preview),
        Some(Value::Str(Cow::Borrowed("")))
    );
    assert_eq!(render.value(&EmailProperty::MessageId), Some(Value::Null));
    assert_eq!(render.value(&EmailProperty::InReplyTo), Some(Value::Null));
    assert_eq!(
        render
            .value(&EmailProperty::Subject)
            .map(|value| text(&value)),
        Some(String::new())
    );
}

#[test]
fn references_and_headers_read_section_b() {
    let mut extra = ExtraHeaders::default();
    extra.push(HeaderId::DELIVERED_TO, "jdoe@example.org");
    let fixture = Fixture::with_extra(LIST_MESSAGE, &extra);
    let options = BodyValueOptions::default();
    let properties = [EmailProperty::References, EmailProperty::Headers];
    assert_eq!(
        EmailNeeds::new(&properties, &DEFAULT_BODY_PROPERTIES, &options),
        EmailNeeds {
            headers: true,
            blob: false,
            envelope: false,
            fallback: false
        }
    );
    let render = fixture.render(true, false, &DEFAULT_BODY_PROPERTIES, &options);
    let references = render
        .value(&EmailProperty::References)
        .expect("references");
    let ids = references.as_array().expect("array");
    assert!(ids.iter().all(is_borrowed));
    assert_eq!(
        ids.iter().map(text).collect::<Vec<_>>(),
        ["r1@example.com", "r2@example.com"]
    );

    let headers = render.value(&EmailProperty::Headers).expect("headers");
    let headers = headers.as_array().expect("array");
    assert_eq!(headers.len(), 8);
    assert_eq!(text(get(&headers[0], EmailProperty::Name)), "Delivered-To");
    assert_eq!(
        text(get(&headers[0], EmailProperty::Value)),
        " jdoe@example.org"
    );
    assert_eq!(text(get(&headers[7], EmailProperty::Name)), "References");
    assert_eq!(
        text(get(&headers[7], EmailProperty::Value)),
        " <r1@example.com>\r\n <r2@example.com>"
    );

    let render = fixture.render(false, false, &DEFAULT_BODY_PROPERTIES, &options);
    assert_eq!(render.value(&EmailProperty::References), Some(Value::Null));
    assert_eq!(render.value(&EmailProperty::Headers), Some(Value::Null));
}

#[test]
fn header_names_as_written() {
    let fixture = Fixture::new(concat!(
        "SUBJECT: shouting\r\n",
        "x-custom-header: first\r\n",
        "X-CUSTOM-HEADER: second\r\n",
        "from: lower@example.com\r\n",
        "Content-type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "content-TYPE: text/plain\r\n",
        "X-Part: one\r\n",
        "\r\n",
        "part\r\n",
        "--b--\r\n",
    ));
    let options = BodyValueOptions::default();
    let body_properties = [EmailProperty::PartId, EmailProperty::Headers];
    let render = fixture.render(true, true, &body_properties, &options);

    let headers = render.value(&EmailProperty::Headers).expect("headers");
    let names = headers
        .as_array()
        .expect("array")
        .iter()
        .map(|header| text(get(header, EmailProperty::Name)))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "SUBJECT",
            "x-custom-header",
            "X-CUSTOM-HEADER",
            "from",
            "Content-type"
        ]
    );

    let custom = render
        .value(&header("X-Custom-Header", HeaderForm::Raw, true))
        .expect("custom");
    assert_eq!(
        custom
            .as_array()
            .expect("array")
            .iter()
            .map(text)
            .collect::<Vec<_>>(),
        [" first", " second"]
    );
    let last = render
        .value(&header("x-CUSTOM-header", HeaderForm::Text, false))
        .expect("custom");
    assert_eq!(text(&last), "second");

    let text_body = render.value(&EmailProperty::TextBody).expect("text body");
    let part = text_body
        .as_array()
        .and_then(|parts| parts.first())
        .expect("part");
    assert_eq!(text(get(part, EmailProperty::PartId)), "1");
    let names = get(part, EmailProperty::Headers)
        .as_array()
        .expect("array")
        .iter()
        .map(|header| text(get(header, EmailProperty::Name)))
        .collect::<Vec<_>>();
    assert_eq!(names, ["content-TYPE", "X-Part"]);
}

#[test]
fn content_type_as_text() {
    let fixture = Fixture::new(concat!(
        "From: Sender <sender@example.com>\r\n",
        "Subject: =?utf-8?q?caf=C3=A9?=\r\n",
        "List-Unsubscribe: <mailto:unsub@example.com>, <https://example.com/u>\r\n",
        "X-Addresses: A <a@example.com>, b@example.com\r\n",
        "Content-Type: multipart/mixed;\r\n boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "part\r\n",
        "--b--\r\n",
    ));
    let options = BodyValueOptions::default();
    let body_properties = [
        EmailProperty::PartId,
        header("Content-Type", HeaderForm::Text, false),
    ];
    assert_eq!(
        EmailNeeds::new(&[EmailProperty::TextBody], &body_properties, &options),
        EmailNeeds {
            headers: true,
            blob: true,
            envelope: false,
            fallback: false
        }
    );
    let render = fixture.render(true, true, &body_properties, &options);

    let content_type = render
        .value(&header("Content-Type", HeaderForm::Text, false))
        .expect("content type");
    assert_eq!(text(&content_type), "multipart/mixed; boundary=\"b\"");
    let subject = render
        .value(&header("Subject", HeaderForm::Text, false))
        .expect("subject");
    assert_eq!(text(&subject), "café");
    let urls = render
        .value(&header("List-Unsubscribe", HeaderForm::URLs, false))
        .expect("urls");
    assert_eq!(
        urls.as_array()
            .expect("array")
            .iter()
            .map(text)
            .collect::<Vec<_>>(),
        ["mailto:unsub@example.com", "https://example.com/u"]
    );
    let addresses = render
        .value(&header("X-Addresses", HeaderForm::Addresses, false))
        .expect("addresses");
    assert_eq!(addresses.as_array().map(<[_]>::len), Some(2));
    let grouped = render
        .value(&header("From", HeaderForm::GroupedAddresses, false))
        .expect("grouped");
    let group = grouped
        .as_array()
        .and_then(|groups| groups.first())
        .expect("group");
    assert!(get(group, EmailProperty::Name).is_null());
    assert_eq!(
        get(group, EmailProperty::Addresses)
            .as_array()
            .map(<[_]>::len),
        Some(1)
    );

    let text_body = render.value(&EmailProperty::TextBody).expect("text body");
    let part = text_body
        .as_array()
        .and_then(|parts| parts.first())
        .expect("part");
    assert_eq!(
        text(get(part, header("Content-Type", HeaderForm::Text, false))),
        "text/plain; charset=utf-8"
    );
}

#[test]
fn part_size_is_transfer_decoded() {
    let fixture = Fixture::new(concat!(
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain; charset=iso-8859-1\r\n",
        "Content-Transfer-Encoding: quoted-printable\r\n",
        "\r\n",
        "caf=E9\r\n",
        "--b\r\n",
        "Content-Type: application/octet-stream; name=\"hello.bin\"\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "SGVsbG8=\r\n",
        "--b--\r\n",
    ));
    let options = BodyValueOptions {
        fetch_all: true,
        ..Default::default()
    };
    let render = fixture.render(false, true, &DEFAULT_BODY_PROPERTIES, &options);
    let text_body = render.value(&EmailProperty::TextBody).expect("text body");
    let part = text_body
        .as_array()
        .and_then(|parts| parts.first())
        .expect("text part");
    assert_eq!(get(part, EmailProperty::Size).as_u64(), Some(4));
    assert_eq!(text(get(part, EmailProperty::Charset)), "iso-8859-1");
    let attachments = render
        .value(&EmailProperty::Attachments)
        .expect("attachments");
    let attachment = attachments
        .as_array()
        .and_then(|parts| parts.first())
        .expect("attachment");
    assert_eq!(get(attachment, EmailProperty::Size).as_u64(), Some(5));
    assert_eq!(text(get(attachment, EmailProperty::Name)), "hello.bin");
    assert!(get(attachment, EmailProperty::Charset).is_null());

    let body_values = render.value(&EmailProperty::BodyValues).expect("values");
    let value = body_values
        .as_object_and_get(&Key::Borrowed("1"))
        .expect("value of part 1");
    assert_eq!(text(get(value, EmailProperty::Value)), "café");
    assert_eq!(
        get(value, EmailProperty::IsEncodingProblem).as_bool(),
        Some(false)
    );
}

#[test]
fn body_values_report_encoding_problems() {
    let fixture = Fixture::new(concat!(
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "clean text that is long enough to truncate\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "SGVs*bG8\r\n",
        "--b\r\n",
        "Content-Type: text/plain; charset=x-unknown-charset\r\n",
        "\r\n",
        "unknown charset\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Transfer-Encoding: x-uuencode\r\n",
        "\r\n",
        "unknown cte\r\n",
        "--b--\r\n",
    ));
    let options = BodyValueOptions {
        fetch_text: true,
        max_bytes: 20,
        ..Default::default()
    };
    assert_eq!(
        EmailNeeds::new(
            &[EmailProperty::BodyValues],
            &DEFAULT_BODY_PROPERTIES,
            &options
        ),
        EmailNeeds {
            headers: false,
            blob: true,
            envelope: false,
            fallback: false
        }
    );
    let render = fixture.render(false, true, &DEFAULT_BODY_PROPERTIES, &options);
    let body_values = render.value(&EmailProperty::BodyValues).expect("values");
    let problems = ["1", "2", "3", "4"]
        .into_iter()
        .map(|id| {
            let value = body_values
                .as_object_and_get(&Key::Borrowed(id))
                .expect("body value");
            get(value, EmailProperty::IsEncodingProblem).as_bool()
        })
        .collect::<Vec<_>>();
    assert_eq!(problems, [Some(false), Some(true), Some(true), Some(true)]);
    let first = body_values
        .as_object_and_get(&Key::Borrowed("1"))
        .expect("body value");
    assert_eq!(get(first, EmailProperty::IsTruncated).as_bool(), Some(true));
    assert!(text(get(first, EmailProperty::Value)).len() <= 20);

    let no_flags = BodyValueOptions::default();
    assert_eq!(
        EmailNeeds::new(
            &[EmailProperty::BodyValues],
            &DEFAULT_BODY_PROPERTIES,
            &no_flags
        ),
        EmailNeeds::default()
    );
    let render = fixture.render(false, false, &DEFAULT_BODY_PROPERTIES, &no_flags);
    let empty = render.value(&EmailProperty::BodyValues).expect("values");
    assert!(empty.as_object().is_some_and(|object| object.is_empty()));
}

#[test]
fn part_blob_ids_map_to_the_blob() {
    let raw = concat!(
        "Subject: blobs\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "text part\r\n",
        "--b\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "SGVsbG8=\r\n",
        "--b--\r\n",
    );
    let mut extra = ExtraHeaders::default();
    extra
        .push(HeaderId::DELIVERED_TO, "jdoe@example.org")
        .push(HeaderId::X_SPAM_STATUS, "No");
    let options = BodyValueOptions::default();
    for fixture in [Fixture::new(raw), Fixture::with_extra(raw, &extra)] {
        let render = fixture.render(false, false, &DEFAULT_BODY_PROPERTIES, &options);
        let structure = render
            .value(&EmailProperty::BodyStructure)
            .expect("structure");
        assert!(
            structure
                .as_object_and_get(&Key::Property(EmailProperty::BlobId))
                .is_some_and(|value| value.is_null())
        );
        let parts = get(&structure, EmailProperty::SubParts)
            .as_array()
            .expect("sub parts");
        let bodies = parts
            .iter()
            .map(|part| {
                let Some(EmailValue::BlobId(blob_id)) =
                    get(part, EmailProperty::BlobId).as_element()
                else {
                    panic!("part without blobId");
                };
                let Some(BlobSection::Single(section)) = &blob_id.section else {
                    panic!("single section");
                };
                assert_eq!(blob_id.hash, fixture.blob_id.hash);
                (
                    fixture
                        .blob
                        .get(section.offset_start..section.offset_start + section.size)
                        .map(<[u8]>::to_vec),
                    section.encoding,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            bodies,
            [
                (Some(b"text part".to_vec()), 0),
                (Some(b"SGVsbG8=".to_vec()), 2)
            ]
        );
    }

    let mut fixture = Fixture::new(raw);
    fixture.blob_id = BlobId::new_section(
        fixture.blob_id.hash.clone(),
        fixture.blob_id.class.clone(),
        100,
        100 + raw.len(),
        0u8,
    );
    let render = fixture.render(false, false, &DEFAULT_BODY_PROPERTIES, &options);
    let attachments = render
        .value(&EmailProperty::Attachments)
        .expect("attachments");
    let attachment = attachments
        .as_array()
        .and_then(|parts| parts.first())
        .expect("attachment");
    let Some(EmailValue::BlobId(blob_id)) = get(attachment, EmailProperty::BlobId).as_element()
    else {
        panic!("part without blobId");
    };
    let Some(BlobSection::Single(section)) = &blob_id.section else {
        panic!("single section");
    };
    let start = raw.find("SGVsbG8=").expect("body");
    assert_eq!(section.offset_start, 100 + start);
    assert_eq!(section.size, 8);
}

#[test]
fn part_headers_without_sources_are_null() {
    let fixture = Fixture::new(concat!(
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "text\r\n",
        "--b--\r\n",
    ));
    let options = BodyValueOptions::default();
    let body_properties = [
        EmailProperty::PartId,
        header("Content-Type", HeaderForm::Raw, false),
    ];
    let render = fixture.render(false, true, &body_properties, &options);
    let structure = render
        .value(&EmailProperty::BodyStructure)
        .expect("structure");
    assert!(get(&structure, header("Content-Type", HeaderForm::Raw, false)).is_null());
    let part = get(&structure, EmailProperty::SubParts)
        .as_array()
        .and_then(|parts| parts.first())
        .expect("part");
    assert_eq!(
        text(get(part, header("Content-Type", HeaderForm::Raw, false))),
        " text/plain"
    );

    let render = fixture.render(false, false, &body_properties, &options);
    let structure = render
        .value(&EmailProperty::BodyStructure)
        .expect("structure");
    let part = get(&structure, EmailProperty::SubParts)
        .as_array()
        .and_then(|parts| parts.first())
        .expect("part");
    assert!(get(part, header("Content-Type", HeaderForm::Raw, false)).is_null());
}

#[test]
fn truncated_envelopes_are_read_from_section_b() {
    const RECIPIENTS: usize = MAX_FIELD_ADDRESSES + 476;
    let mut raw = String::from("To: ");
    for index in 0..RECIPIENTS {
        if index > 0 {
            raw.push_str(",\r\n ");
        }
        raw.push_str(&format!("\"Name {index}\" <r{index}@example.com>"));
    }
    let subject = "s".repeat(MAX_VALUE_LEN + 100);
    raw.push_str(&format!(
        "\r\nSubject: {subject}\r\nFrom: a@example.com\r\nMessage-ID: <m@example.com>\r\n\r\nbody\r\n"
    ));
    let fixture = Fixture::with_extra(&raw, &ExtraHeaders::default());
    let meta = fixture.row.unarchive().expect("archive");
    assert_eq!(meta.completeness(), Completeness::Truncated);
    let options = BodyValueOptions::default();
    let needs = EmailNeeds::new(&[EmailProperty::To], &DEFAULT_BODY_PROPERTIES, &options);
    assert_eq!(
        needs,
        EmailNeeds {
            headers: false,
            blob: false,
            envelope: true,
            fallback: false
        }
    );
    assert!(needs.headers_for(meta));

    let render = fixture.render(true, false, &DEFAULT_BODY_PROPERTIES, &options);
    let to = render.value(&EmailProperty::To).expect("to");
    let to = to.as_array().expect("array");
    assert_eq!(to.len(), RECIPIENTS);
    assert_eq!(
        text(get(to.last().expect("last"), EmailProperty::Email)),
        format!("r{}@example.com", RECIPIENTS - 1)
    );
    assert_eq!(
        render
            .value(&EmailProperty::Subject)
            .map(|value| text(&value)),
        Some(subject)
    );
    let from = render.value(&EmailProperty::From).expect("from");
    assert_eq!(
        text(get(
            &from.as_array().expect("array")[0],
            EmailProperty::Email
        )),
        "a@example.com"
    );
    let ids = render.value(&EmailProperty::MessageId).expect("ids");
    assert_eq!(text(&ids.as_array().expect("array")[0]), "m@example.com");
    for property in [
        EmailProperty::Cc,
        EmailProperty::InReplyTo,
        EmailProperty::SentAt,
    ] {
        assert_eq!(render.value(&property), Some(Value::Null));
    }

    let complete = Fixture::new(LIST_MESSAGE);
    let meta = complete.row.unarchive().expect("archive");
    assert_eq!(meta.completeness(), Completeness::Complete);
    assert!(!needs.headers_for(meta));
}

#[test]
fn truncated_root_headers_are_read_from_section_b() {
    let mut raw = String::new();
    for index in 0..MAX_HEADER_ENTRIES + 8 {
        raw.push_str(&format!("X-Junk-{}: value\r\n", index % 97));
    }
    raw.push_str("Subject: hidden\r\nReferences: <a@example.com> <b@example.com>\r\n\r\nbody\r\n");
    let mut extra = ExtraHeaders::default();
    extra.push(HeaderId::DELIVERED_TO, "jdoe@example.org");
    let fixture = Fixture::with_extra(&raw, &extra);
    let options = BodyValueOptions::default();
    let render = fixture.render(true, false, &DEFAULT_BODY_PROPERTIES, &options);
    let subject = render
        .value(&header("Subject", HeaderForm::Text, false))
        .expect("subject");
    assert_eq!(text(&subject), "hidden");
    let references = render
        .value(&EmailProperty::References)
        .expect("references");
    assert_eq!(references.as_array().map(<[_]>::len), Some(2));
    let headers = render.value(&EmailProperty::Headers).expect("headers");
    let headers = headers.as_array().expect("array");
    assert_eq!(headers.len(), MAX_HEADER_ENTRIES + 8 + 3);
    assert_eq!(text(get(&headers[0], EmailProperty::Name)), "Delivered-To");
    assert_eq!(
        text(get(headers.last().expect("last"), EmailProperty::Name)),
        "References"
    );
}

#[test]
fn raw_form_drops_nul_octets() {
    let fixture = Fixture::new("X-Nul: a\0b\0\r\nSubject: clean\r\n\r\nbody\r\n");
    let options = BodyValueOptions::default();
    let render = fixture.render(true, false, &DEFAULT_BODY_PROPERTIES, &options);
    let raw = render
        .value(&header("X-Nul", HeaderForm::Raw, false))
        .expect("raw");
    assert_eq!(text(&raw), " ab");
    let clean = render
        .value(&header("Subject", HeaderForm::Raw, false))
        .expect("raw");
    assert!(is_borrowed(&clean));
    assert_eq!(text(&clean), " clean");
    let headers = render.value(&EmailProperty::Headers).expect("headers");
    let first = &headers.as_array().expect("array")[0];
    assert_eq!(text(get(first, EmailProperty::Name)), "X-Nul");
    assert_eq!(text(get(first, EmailProperty::Value)), " ab");
}

fn download(blob: &[u8], blob_id: &BlobId) -> Option<Vec<u8>> {
    let section = blob_id.section.as_ref()?;
    section.decode_fetched(blob.get(section.fetch_range())?.to_vec())
}

fn listed_blob_ids(fixture: &Fixture, property: EmailProperty) -> Vec<BlobId> {
    let options = BodyValueOptions::default();
    let render = fixture.render(false, false, &DEFAULT_BODY_PROPERTIES, &options);
    render
        .value(&property)
        .expect("list")
        .as_array()
        .expect("parts")
        .iter()
        .map(|part| match get(part, EmailProperty::BlobId).as_element() {
            Some(EmailValue::BlobId(blob_id)) => blob_id.clone(),
            _ => panic!("part without blobId"),
        })
        .collect()
}

fn parsed(bytes: &[u8], blob_id: &BlobId) -> Fixture {
    let mut fixture = Fixture::new(std::str::from_utf8(bytes).expect("utf-8"));
    fixture.blob_id = blob_id.clone();
    fixture
}

struct NestedMessages {
    level_two: &'static str,
    level_one: String,
    root: String,
}

impl NestedMessages {
    fn new() -> Self {
        let level_two = concat!(
            "Subject: level two\r\n",
            "Content-Type: multipart/alternative; boundary=\"c\"\r\n",
            "\r\n",
            "--c\r\n",
            "Content-Type: text/plain\r\n",
            "\r\n",
            "level two text\r\n",
            "--c\r\n",
            "Content-Type: text/html\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "<p>level two =3D html</p>\r\n",
            "--c--\r\n",
        );
        let level_one = format!(
            concat!(
                "Subject: level one\r\n",
                "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
                "\r\n",
                "--b\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "level one text\r\n",
                "--b\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--b--\r\n",
            ),
            MIME.encode(level_two.as_bytes())
        );
        let root = format!(
            concat!(
                "Subject: root\r\n",
                "Content-Type: multipart/mixed; boundary=\"a\"\r\n",
                "\r\n",
                "--a\r\n",
                "Content-Type: text/plain\r\n",
                "\r\n",
                "root text\r\n",
                "--a\r\n",
                "Content-Type: message/rfc822\r\n",
                "Content-Transfer-Encoding: base64\r\n",
                "\r\n",
                "{}\r\n",
                "--a--\r\n",
            ),
            MIME.encode(level_one.as_bytes())
        );
        NestedMessages {
            level_two,
            level_one,
            root,
        }
    }
}

#[test]
fn parts_of_encoded_nested_messages_resolve_to_their_bytes() {
    let NestedMessages {
        level_two,
        level_one,
        root,
    } = NestedMessages::new();
    let stored = Fixture::new(&root);
    let resolve = |blob_id: &BlobId| {
        let serialized = blob_id.to_string();
        assert_eq!(serialized.parse::<BlobId>().as_ref(), Ok(blob_id));
        download(&stored.blob, blob_id)
    };

    let [first] = listed_blob_ids(&stored, EmailProperty::Attachments)
        .try_into()
        .expect("one attachment");
    assert!(matches!(first.section, Some(BlobSection::Single(_))));
    let first_bytes = resolve(&first).expect("level one");
    assert_eq!(first_bytes, level_one.as_bytes());

    let one = parsed(&first_bytes, &first);
    let [text] = listed_blob_ids(&one, EmailProperty::TextBody)
        .try_into()
        .expect("one text part");
    assert_eq!(text.section.as_ref().map(|s| s.containers().len()), Some(1));
    assert_eq!(resolve(&text).as_deref(), Some(&b"level one text"[..]));
    let [second] = listed_blob_ids(&one, EmailProperty::Attachments)
        .try_into()
        .expect("one nested attachment");
    assert_eq!(
        second.section.as_ref().map(|s| s.containers().len()),
        Some(1)
    );
    let second_bytes = resolve(&second).expect("level two");
    assert_eq!(second_bytes, level_two.as_bytes());

    let two = parsed(&second_bytes, &second);
    let [text] = listed_blob_ids(&two, EmailProperty::TextBody)
        .try_into()
        .expect("one text part");
    let [html] = listed_blob_ids(&two, EmailProperty::HtmlBody)
        .try_into()
        .expect("one html part");
    for (blob_id, expected) in [
        (&text, &b"level two text"[..]),
        (&html, &b"<p>level two = html</p>"[..]),
    ] {
        assert_eq!(blob_id.hash, stored.blob_id.hash);
        assert_eq!(blob_id.class, stored.blob_id.class);
        assert_eq!(
            blob_id.section.as_ref().map(|s| s.containers().len()),
            Some(2)
        );
        assert_eq!(resolve(blob_id).as_deref(), Some(expected));
    }
}

#[test]
fn parts_inside_encoded_sources_name_their_decode_chain() {
    let mut delivery = ExtraHeaders::default();
    delivery
        .push(HeaderId::DELIVERED_TO, "jdoe@example.org")
        .push(HeaderId::X_SPAM_STATUS, "No");
    for extra in [ExtraHeaders::default(), delivery] {
        let fixture = Fixture::with_extra(&NestedMessages::new().root, &extra);
        let meta = fixture.row.unarchive().expect("archive");
        assert_eq!(meta.extra_headers_len(), extra.len());
        let options = BodyValueOptions::default();
        let render = fixture.render(false, false, &DEFAULT_BODY_PROPERTIES, &options);
        let raw = meta.raw_message(Some(&fixture.headers), &fixture.blob);
        let mut depths = Vec::new();
        for part in meta.parts().filter(|part| part.is_text()) {
            let blob_id = render.inner_blob_id(part).expect("blob id");
            let source = meta.source(part.message(), raw).expect("source");
            let depth = meta.source_chain(part.message()).expect("chain").len();
            let section = blob_id.section.as_ref().expect("section");
            assert_eq!(section.containers().len(), depth);
            let expected = part.decoded(&source).into_owned();
            assert_eq!(download(&fixture.blob, &blob_id), Some(expected));
            if let Some(outermost) = section.containers().first() {
                let chain_start = meta
                    .source_chain(part.message())
                    .and_then(|chain| chain.ids().next())
                    .and_then(|id| meta.part(id))
                    .map(|container| container.offset_body());
                assert_eq!(
                    chain_start.map(|start| start - extra.len()),
                    Some(outermost.offset_start)
                );
                for (level, container) in section.containers().iter().enumerate().skip(1) {
                    assert!(
                        container.offset_start < outermost.size,
                        "level {level} is in decoded coordinates"
                    );
                }
            }
            depths.push(depth);
        }
        assert_eq!(depths, [0, 1, 2, 2]);
    }
}

#[test]
fn parsed_blob_ids_skip_extra_headers() {
    let raw = concat!(
        "Subject: parse me\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "\r\n",
        "text part\r\n",
        "--b\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "SGVsbG8=\r\n",
        "--b--\r\n",
    );
    let mut extra = ExtraHeaders::default();
    extra
        .push(HeaderId::DELIVERED_TO, "jdoe@example.org")
        .push(HeaderId::X_SPAM_STATUS, "No");
    let stored = Fixture::with_extra(raw, &extra);
    let meta = stored.row.unarchive().expect("archive");
    assert!(meta.extra_headers_len() > 0);
    let mut download = stored.headers.clone();
    download.extend_from_slice(
        stored
            .blob
            .get(meta.blob_body_offset()..)
            .expect("stored body"),
    );
    let mut parsed = Fixture::new(std::str::from_utf8(&download).expect("utf-8"));
    parsed.blob_id = stored.blob_id.clone();
    let options = BodyValueOptions::default();
    let render = parsed
        .render(false, false, &DEFAULT_BODY_PROPERTIES, &options)
        .with_blob_prefix(meta.extra_headers_len());
    let structure = render
        .value(&EmailProperty::BodyStructure)
        .expect("structure");
    let bodies = get(&structure, EmailProperty::SubParts)
        .as_array()
        .expect("sub parts")
        .iter()
        .map(|part| {
            let Some(EmailValue::BlobId(blob_id)) = get(part, EmailProperty::BlobId).as_element()
            else {
                panic!("part without blobId");
            };
            let Some(BlobSection::Single(section)) = &blob_id.section else {
                panic!("single section");
            };
            stored
                .blob
                .get(section.offset_start..section.offset_start + section.size)
                .map(<[u8]>::to_vec)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        bodies,
        [Some(b"text part".to_vec()), Some(b"SGVsbG8=".to_vec())]
    );
}

#[test]
fn truncated_part_headers_are_scanned_once_per_render() {
    let junk: String = (0..MAX_HEADER_ENTRIES + 8)
        .map(|index| format!("X-Junk: {index}\r\n"))
        .collect();
    let body = concat!(
        "Subject: parts\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain\r\n",
        "X-Target: found\r\n",
        "X-Other: skipped\r\n",
        "X-Target: again\r\n",
        "\r\n",
        "text\r\n",
        "--b--\r\n",
    );
    let truncated = Fixture::new(&format!("{junk}{body}"));
    let twin = Fixture::new(body);
    let options = BodyValueOptions::default();
    let body_properties = [
        EmailProperty::PartId,
        header("X-Target", HeaderForm::Text, false),
        header("X-Target", HeaderForm::Raw, true),
    ];
    let properties = [EmailProperty::TextBody, EmailProperty::BodyStructure];
    let needs = HeaderNeeds::new(&properties, &body_properties);
    let values = |fixture: &Fixture| {
        let render = fixture.render_with(&needs, true, true, &body_properties, &options);
        properties
            .iter()
            .map(|property| format!("{:?}", render.value(property)))
            .collect::<Vec<_>>()
    };
    assert_eq!(values(&truncated), values(&twin));
    assert!(values(&truncated).concat().contains("again"));

    let meta = truncated.row.unarchive().expect("archive");
    assert!(meta.part(1).expect("text part").is_headers_truncated());
    let render = truncated.render_with(&needs, true, true, &body_properties, &options);
    for property in properties {
        render.value(&property);
    }
    let memo = render.part_headers.borrow();
    let memo = memo.as_ref().expect("memo");
    assert_eq!(memo.len(), 2);
    assert_eq!(memo.get(&0).map(|parsed| parsed.list().len()), Some(0));
    assert_eq!(memo.get(&1).map(|parsed| parsed.list().len()), Some(2));
}

fn pool_exhausting_message(flood: bool) -> String {
    let mut raw = String::new();
    if flood {
        raw.push_str("From: ");
        for index in 0..300 {
            if index > 0 {
                raw.push_str(", ");
            }
            raw.push_str(&format!(
                "\"{}\" <u{index}@example.com>",
                "x".repeat(MAX_VALUE_LEN)
            ));
        }
        raw.push_str("\r\n");
    }
    raw.push_str(concat!(
        "From: Real Sender <real@example.com>\r\n",
        "To: Rcpt <rcpt@example.com>\r\n",
        "Subject: pool\r\n",
        "Message-ID: <mid@example.com>\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/html\r\n",
        "Content-ID: <logo@example.com>\r\n",
        "Content-Location: http://example.com/x\r\n",
        "Content-Language: en, fr\r\n",
        "\r\n",
        "<p>preview text here</p>\r\n",
        "--b--\r\n",
    ));
    raw
}

#[test]
fn exhausted_pools_store_absent_values_and_read_them_from_the_source() {
    let truncated = Fixture::new(&pool_exhausting_message(true));
    let twin = Fixture::new(&pool_exhausting_message(false));
    let meta = truncated.row.unarchive().expect("archive");
    assert_eq!(meta.completeness(), Completeness::Truncated);
    assert_eq!(
        twin.row.unarchive().expect("archive").completeness(),
        Completeness::Complete
    );
    let part = meta.part(1).expect("html part");
    assert_eq!(part.content_id(), None);
    assert_eq!(part.content_location(), None);
    assert!(!part.content_language().is_present());
    assert_eq!(meta.stored_preview(), None);
    let last_from = meta
        .root()
        .envelope()
        .addresses(AddressHeader::From, Occurrence::Last);
    assert!(
        last_from
            .mailboxes()
            .all(|mailbox| mailbox.address.is_none() && mailbox.name.is_none())
    );

    let options = BodyValueOptions::default();
    let properties = [
        EmailProperty::Preview,
        EmailProperty::From,
        EmailProperty::To,
        EmailProperty::Subject,
        EmailProperty::MessageId,
        EmailProperty::BodyStructure,
        EmailProperty::HtmlBody,
    ];
    let needs = EmailNeeds::new(&properties, &DEFAULT_BODY_PROPERTIES, &options);
    assert!(needs.fallback);
    assert!(needs.headers_for(meta) && needs.blob_for(meta));
    let body_properties = DEFAULT_BODY_PROPERTIES
        .iter()
        .filter(|property| **property != EmailProperty::BlobId)
        .cloned()
        .collect::<Vec<_>>();
    let values = |fixture: &Fixture| {
        let render = fixture.render(true, true, &body_properties, &options);
        properties
            .iter()
            .map(|property| format!("{property:?}: {:?}", render.value(property)))
            .collect::<Vec<_>>()
    };
    let rendered = values(&truncated);
    assert_eq!(rendered, values(&twin));
    let rendered = rendered.concat();
    for expected in [
        "preview text here",
        "real@example.com",
        "logo@example.com",
        "http://example.com/x",
        "\"fr\"",
    ] {
        assert!(rendered.contains(expected), "{expected} in {rendered}");
    }

    let headers = truncated.headers.as_slice();
    let parsed = meta.root_field_in(headers, HeaderId::FROM, mail_parser::HeaderForm::Addresses);
    let sender = parsed.as_ref().and_then(Mailbox::first_of);
    assert_eq!(
        sender,
        Some(Mailbox {
            name: Some("Real Sender"),
            address: Some("real@example.com")
        })
    );
    let root = meta
        .root()
        .root_part()
        .selected_headers(headers, HeaderSelection::ENVELOPE);
    let twin_meta = twin.row.unarchive().expect("archive");
    assert_eq!(
        MessageSortKeys::from_headers(root.list(), headers).serialize(),
        MessageSortKeys::from_envelope(twin_meta.root().envelope()).serialize()
    );
    assert_ne!(
        MessageSortKeys::from_envelope(meta.root().envelope()).serialize(),
        MessageSortKeys::from_envelope(twin_meta.root().envelope()).serialize()
    );
}
