/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::set::{SetError, SetErrorType},
    method::{
        PropertyWrapper,
        availability::{BusyPeriod, BusyStatus, GetAvailabilityResponse},
        changes::ChangesResponse,
        copy::{CopyBlobResponse, CopyResponse},
        get::GetResponse,
        import::ImportEmailResponse,
        lookup::{BlobInfo, BlobLookupResponse},
        parse::ParseResponse,
        query::QueryResponse,
        query_changes::{AddedItem, QueryChangesResponse},
        search_snippet::{GetSearchSnippetResponse, SearchSnippet},
        set::SetResponse,
        upload::{BlobUploadResponse, BlobUploadResponseObject},
        validate::ValidateSieveScriptResponse,
    },
    object::{
        AnyId,
        calendar_event::CalendarEvent,
        contact::ContactCard,
        email::{Email, EmailProperty, EmailValue, HeaderForm, HeaderProperty},
        mailbox::{Mailbox, MailboxProperty, MailboxRight, MailboxValue},
        registry::Registry,
        sieve::SieveProperty,
    },
    request::{MaybeInvalid, method::MethodName, websocket::WebSocketResponse},
    response::{Response, ResponseMethod},
    types::{date::UTCDate, state::State},
};
use calcard::jscalendar::{JSCalendar, JSCalendarProperty, JSCalendarValue};
use jmap_tools::{JsonPointer, Key, Map, Null, Value};
use registry::types::EnumImpl;
use registry::{jmap::RegistryValue, schema::properties::Property as RegistryProperty};
use serde::{
    Serialize, Serializer,
    ser::{
        SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant,
    },
};
use std::collections::HashMap;
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    id::Id,
    keyword::Keyword,
    special_use::SpecialUse,
    type_state::DataType,
};
use utils::map::vec_map::VecMap;

const FIELDS: &[&str] = &["a", "é", "quote\"", "back\\slash", "ctl\u{1}", "", "🎉"];

const EVENT: &str = r##"{"@type":"Event","uid":"a8df6573-0474-496d-8496-033ad45d7fea","title":"Team sync","description":"Agenda:\n1. Roadmap\n2. Café","start":"2025-02-03T09:00:00","timeZone":"Europe/Berlin","duration":"PT1H","status":"confirmed","sequence":3,"priority":5,"showWithoutTime":false,"locations":{"l1":{"@type":"Location","name":"Room 42"}},"participants":{"p1":{"@type":"Participant","name":"Jane Doe","calendarAddress":"mailto:jane@example.com","roles":{"owner":true,"attendee":true},"participationStatus":"accepted"}},"alerts":{"k1":{"@type":"Alert","trigger":{"@type":"OffsetTrigger","offset":"-PT10M"},"action":"display"}},"recurrenceRule":{"@type":"RecurrenceRule","frequency":"weekly","byDay":[{"@type":"NDay","day":"mo"}]},"recurrenceOverrides":{"2025-02-10T09:00:00":{"title":"Moved sync"},"2025-02-17T09:00:00":{"excluded":true}},"keywords":{"work":true},"color":"#ff0000"}"##;

const CARD: &str = r#"{"@type":"Card","version":"1.0","uid":"urn:uuid:4fbe8971-0bc3-424c-9c26-36c3e1eff6b1","kind":"individual","name":{"@type":"Name","components":[{"@type":"NameComponent","kind":"given","value":"Jane"},{"@type":"NameComponent","kind":"surname","value":"Doe"}]},"emails":{"e1":{"@type":"EmailAddress","address":"jane@example.com","contexts":{"work":true},"pref":1}},"phones":{"p1":{"@type":"Phone","number":"+1-555-0100","features":{"voice":true}}},"notes":{"n1":{"@type":"Note","note":"Met at the conference; likes café"}}}"#;

type CardValue = Value<
    'static,
    <ContactCard as crate::object::JmapObject>::Property,
    <ContactCard as crate::object::JmapObject>::Element,
>;

struct Rng(u64);

struct Templates {
    event: Value<'static, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>,
    card: CardValue,
}

impl Templates {
    fn new() -> Self {
        Templates {
            event: JSCalendar::<Id, BlobId>::parse(EVENT)
                .expect("event parses")
                .0
                .into_owned(),
            card: serde_json::from_str::<CardValue>(CARD)
                .expect("card parses")
                .into_owned(),
        }
    }
}

#[derive(Debug)]
enum Probe {
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    F32(f32),
    F64(f64),
    Char(char),
    Str(String),
    Bytes(Vec<u8>),
    None,
    Some(Box<Probe>),
    Unit,
    UnitStruct,
    UnitVariant,
    NewtypeStruct(Box<Probe>),
    NewtypeVariant(Box<Probe>),
    Seq(Vec<Probe>),
    Tuple(Vec<Probe>),
    TupleStruct(Vec<Probe>),
    TupleVariant(Vec<Probe>),
    Map(Vec<(Probe, Probe)>),
    Struct(Vec<Probe>),
    StructVariant(Vec<Probe>),
    CollectStr(String),
}

impl Serialize for Probe {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Probe::Bool(value) => serializer.serialize_bool(*value),
            Probe::I8(value) => serializer.serialize_i8(*value),
            Probe::I16(value) => serializer.serialize_i16(*value),
            Probe::I32(value) => serializer.serialize_i32(*value),
            Probe::I64(value) => serializer.serialize_i64(*value),
            Probe::I128(value) => serializer.serialize_i128(*value),
            Probe::U8(value) => serializer.serialize_u8(*value),
            Probe::U16(value) => serializer.serialize_u16(*value),
            Probe::U32(value) => serializer.serialize_u32(*value),
            Probe::U64(value) => serializer.serialize_u64(*value),
            Probe::U128(value) => serializer.serialize_u128(*value),
            Probe::F32(value) => serializer.serialize_f32(*value),
            Probe::F64(value) => serializer.serialize_f64(*value),
            Probe::Char(value) => serializer.serialize_char(*value),
            Probe::Str(value) => serializer.serialize_str(value),
            Probe::Bytes(value) => serializer.serialize_bytes(value),
            Probe::None => serializer.serialize_none(),
            Probe::Some(value) => serializer.serialize_some(value),
            Probe::Unit => serializer.serialize_unit(),
            Probe::UnitStruct => serializer.serialize_unit_struct("Probe"),
            Probe::UnitVariant => serializer.serialize_unit_variant("Probe", 2, "unit"),
            Probe::NewtypeStruct(value) => serializer.serialize_newtype_struct("Probe", value),
            Probe::NewtypeVariant(value) => {
                serializer.serialize_newtype_variant("Probe", 4, "newtype", value)
            }
            Probe::Seq(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Probe::Tuple(items) => {
                let mut tuple = serializer.serialize_tuple(items.len())?;
                for item in items {
                    tuple.serialize_element(item)?;
                }
                tuple.end()
            }
            Probe::TupleStruct(items) => {
                let mut tuple = serializer.serialize_tuple_struct("Probe", items.len())?;
                for item in items {
                    tuple.serialize_field(item)?;
                }
                tuple.end()
            }
            Probe::TupleVariant(items) => {
                let mut tuple =
                    serializer.serialize_tuple_variant("Probe", 7, "tuple", items.len())?;
                for item in items {
                    tuple.serialize_field(item)?;
                }
                tuple.end()
            }
            Probe::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
            Probe::Struct(fields) => {
                let mut object = serializer.serialize_struct("Probe", fields.len())?;
                for (name, value) in FIELDS.iter().zip(fields) {
                    object.serialize_field(name, value)?;
                }
                object.end()
            }
            Probe::StructVariant(fields) => {
                let mut object =
                    serializer.serialize_struct_variant("Probe", 9, "object", fields.len())?;
                for (name, value) in FIELDS.iter().zip(fields) {
                    object.serialize_field(name, value)?;
                }
                object.end()
            }
            Probe::CollectStr(value) => serializer.collect_str(value),
        }
    }
}

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }

    fn float(&mut self) -> f64 {
        match self.below(4) {
            0 => f64::from_bits(self.next()),
            1 => (self.next() as i64) as f64 / (1u64 << self.below(64)) as f64,
            2 => FLOATS
                .get(self.below(FLOATS.len()))
                .copied()
                .unwrap_or_default(),
            _ => (self.next() % 1_000_000) as f64 / 1000.0,
        }
    }

    fn text(&mut self) -> String {
        const PIECES: &[&str] = &[
            "\"",
            "\\",
            "/",
            "\u{7f}",
            "\u{2028}",
            "\u{2029}",
            "\u{feff}",
            "é€🎉",
            "\r\n",
            "\t",
        ];
        let mut text = String::new();
        for _ in 0..self.below(12) {
            match self.below(8) {
                0 => text.push(char::from(self.below(0x80) as u8)),
                1 => {
                    text.push(char::from_u32(self.next() as u32 % 0x11_0000).unwrap_or('\u{fffd}'))
                }
                2 | 3 => text.push_str(
                    PIECES
                        .get(self.below(PIECES.len()))
                        .copied()
                        .unwrap_or_default(),
                ),
                _ => text.push(char::from(b'a' + self.below(26) as u8)),
            }
        }
        text
    }

    fn id(&mut self) -> Id {
        let bits = self.next();
        Id::from(bits >> self.below(64))
    }

    fn blob_id(&mut self) -> BlobId {
        BlobId::new(
            BlobHash::generate(self.next().to_le_bytes()),
            BlobClass::Linked {
                account_id: self.next() as u32,
                collection: self.next() as u8,
                document_id: self.next() as u32,
            },
        )
    }

    fn date(&mut self) -> UTCDate {
        UTCDate::from_timestamp((self.next() % 4_102_444_800) as i64 - 1_000_000_000)
    }

    fn state(&mut self) -> State {
        let from = self.next() >> self.below(64);
        match self.below(3) {
            0 => State::Initial,
            1 => State::new_exact(self.next() >> self.below(64)),
            _ => State::new_intermediate(
                from,
                from.saturating_add(self.next() >> self.below(64)),
                self.below(1000),
            ),
        }
    }

    fn probe(&mut self, depth: usize) -> Probe {
        match self.below(if depth > 3 { 17 } else { 31 }) {
            0 => Probe::Bool(self.chance(2)),
            1 => Probe::I8(self.next() as i8),
            2 => Probe::I16(self.next() as i16),
            3 => Probe::I32(self.next() as i32),
            4 => Probe::I64(self.next() as i64),
            5 => Probe::I128(((self.next() as i128) << 64) | self.next() as i128),
            6 => Probe::U8(self.next() as u8),
            7 => Probe::U16(self.next() as u16),
            8 => Probe::U32(self.next() as u32),
            9 => Probe::U64(self.next() >> self.below(64)),
            10 => Probe::U128(((self.next() as u128) << 64) | self.next() as u128),
            11 => Probe::F32(self.float() as f32),
            12 => Probe::F64(self.float()),
            13 => Probe::Char(char::from_u32(self.next() as u32 % 0x11_0000).unwrap_or('a')),
            14 => Probe::Str(self.text()),
            15 => Probe::None,
            16 => Probe::CollectStr(self.text()),
            17 => Probe::Bytes((0..self.below(6)).map(|_| self.next() as u8).collect()),
            18 => Probe::Some(Box::new(self.probe(depth + 1))),
            19 => Probe::Unit,
            20 => Probe::UnitStruct,
            21 => Probe::UnitVariant,
            22 => Probe::NewtypeStruct(Box::new(self.probe(depth + 1))),
            23 => Probe::NewtypeVariant(Box::new(self.probe(depth + 1))),
            24 => Probe::Seq(self.probes(depth)),
            25 => Probe::Tuple(self.probes(depth)),
            26 => Probe::TupleStruct(self.probes(depth)),
            27 => Probe::TupleVariant(self.probes(depth)),
            28 => Probe::Struct(self.probes(depth)),
            29 => Probe::StructVariant(self.probes(depth)),
            _ => Probe::Map(
                (0..self.below(4))
                    .map(|_| (self.key_probe(), self.probe(depth + 1)))
                    .collect(),
            ),
        }
    }

    fn probes(&mut self, depth: usize) -> Vec<Probe> {
        (0..self.below(FIELDS.len() + 1))
            .map(|_| self.probe(depth + 1))
            .collect()
    }

    fn key_probe(&mut self) -> Probe {
        match self.below(8) {
            0 => Probe::U64(self.next() >> self.below(64)),
            1 => Probe::I64(self.next() as i64),
            2 => Probe::Char(char::from_u32(self.next() as u32 % 0x11_0000).unwrap_or('a')),
            3 => Probe::CollectStr(self.text()),
            4 => Probe::UnitVariant,
            5 => Probe::NewtypeStruct(Box::new(Probe::Str(self.text()))),
            _ => Probe::Str(self.text()),
        }
    }

    fn value(&mut self, depth: usize) -> Value<'static, Null, Null> {
        match self.below(if depth > 3 { 5 } else { 7 }) {
            0 => Value::Null,
            1 => Value::Bool(self.chance(2)),
            2 => {
                let float = self.float();
                if float.is_finite() {
                    Value::Number(float.into())
                } else {
                    Value::Null
                }
            }
            3 => match self.below(3) {
                0 => Value::Number(self.next().into()),
                1 => Value::Number((self.next() as i64).into()),
                _ => Value::Number((self.below(1000) as u64).into()),
            },
            4 => Value::Str(self.text().into()),
            5 => Value::Array((0..self.below(5)).map(|_| self.value(depth + 1)).collect()),
            _ => Value::Object(
                (0..self.below(5))
                    .map(|_| (Key::Owned(self.text()), self.value(depth + 1)))
                    .collect::<Vec<_>>()
                    .into(),
            ),
        }
    }

    fn email(&mut self) -> Value<'static, EmailProperty, EmailValue> {
        let mut email = Map::with_capacity(12);
        email.insert_unchecked(EmailProperty::Id, Value::Element(EmailValue::Id(self.id())));
        email.insert_unchecked(
            EmailProperty::ThreadId,
            Value::Element(EmailValue::Id(self.id())),
        );
        email.insert_unchecked(
            EmailProperty::BlobId,
            Value::Element(EmailValue::BlobId(self.blob_id())),
        );
        email.insert_unchecked(EmailProperty::Subject, Value::Str(self.text().into()));
        email.insert_unchecked(
            EmailProperty::Size,
            Value::Number((self.next() >> self.below(64)).into()),
        );
        email.insert_unchecked(
            EmailProperty::ReceivedAt,
            Value::Element(EmailValue::Date(self.date())),
        );
        email.insert_unchecked(
            EmailProperty::Keywords,
            Value::Object(
                (0..self.below(4))
                    .map(|_| {
                        (
                            Key::Property(EmailProperty::Keyword(Keyword::parse(&self.text()))),
                            Value::Bool(true),
                        )
                    })
                    .collect::<Vec<_>>()
                    .into(),
            ),
        );
        email.insert_unchecked(
            EmailProperty::MailboxIds,
            Value::Object(
                (0..self.below(3))
                    .map(|_| {
                        (
                            Key::Property(EmailProperty::IdValue(self.id())),
                            Value::Bool(true),
                        )
                    })
                    .collect::<Vec<_>>()
                    .into(),
            ),
        );
        email.insert_unchecked(
            EmailProperty::From,
            Value::Array(vec![Value::Object(
                vec![
                    (
                        Key::Property(EmailProperty::Name),
                        Value::Str(self.text().into()),
                    ),
                    (
                        Key::Property(EmailProperty::Email),
                        Value::Str(self.text().into()),
                    ),
                ]
                .into(),
            )]),
        );
        email.insert_unchecked(
            EmailProperty::Header(HeaderProperty {
                form: HeaderForm::Text,
                header: self.text(),
                all: self.chance(2),
            }),
            Value::Str(self.text().into()),
        );
        email.insert_unchecked(
            EmailProperty::Pointer(JsonPointer::parse(&format!("keywords/{}", self.text()))),
            Value::Null,
        );
        Value::Object(email)
    }

    fn mailbox(&mut self) -> Value<'static, MailboxProperty, MailboxValue> {
        Value::Object(
            vec![
                (
                    Key::Property(MailboxProperty::Id),
                    Value::Element(MailboxValue::Id(self.id())),
                ),
                (
                    Key::Property(MailboxProperty::Name),
                    Value::Str(self.text().into()),
                ),
                (
                    Key::Property(MailboxProperty::Role),
                    Value::Element(MailboxValue::Role(SpecialUse::Inbox)),
                ),
                (
                    Key::Property(MailboxProperty::SortOrder),
                    Value::Number((self.below(100) as u64).into()),
                ),
                (
                    Key::Property(MailboxProperty::MyRights),
                    Value::Object(
                        vec![
                            (
                                Key::Property(MailboxProperty::Rights(MailboxRight::MayReadItems)),
                                Value::Bool(true),
                            ),
                            (
                                Key::Property(MailboxProperty::Rights(MailboxRight::MayDelete)),
                                Value::Bool(false),
                            ),
                        ]
                        .into(),
                    ),
                ),
                (
                    Key::Property(MailboxProperty::ShareWith),
                    Value::Object(
                        vec![(
                            Key::Property(MailboxProperty::IdValue(self.id())),
                            Value::Null,
                        )]
                        .into(),
                    ),
                ),
            ]
            .into(),
        )
    }

    fn set_error<P: jmap_tools::Property>(&mut self, a: P, b: P) -> SetError<P> {
        match self.below(3) {
            0 => SetError::invalid_properties()
                .with_property(a)
                .with_description(self.text()),
            1 => SetError::invalid_properties().with_property((a, b)),
            _ => SetError::new(SetErrorType::NotFound).with_description(self.text()),
        }
    }

    fn event(&mut self, templates: &Templates) -> JSCalendar<'static, Id, BlobId> {
        let mut event = templates.event.clone();
        if let Some(object) = event.as_object_mut() {
            object.insert_unchecked(Key::Borrowed("x-vendor"), Value::Str(self.text().into()));
        }
        JSCalendar(event)
    }

    fn response(&mut self, templates: &Templates) -> Response<'static> {
        let mut response = Response::new(self.next() as u32, HashMap::new(), 20);
        let method = |name| MethodName::parse(name).expect("method");

        response.push_response(
            self.text(),
            method("Core/echo"),
            ResponseMethod::Echo(self.value(0)),
        );
        response.push_response(
            self.text(),
            method("Email/get"),
            GetResponse::<Email> {
                account_id: Some(self.id()),
                state: Some(self.state()),
                list: (0..self.below(3)).map(|_| self.email()).collect(),
                not_found: vec![
                    MaybeInvalid::Value(self.id()),
                    MaybeInvalid::Invalid(self.text()),
                ],
            },
        );
        response.push_response(
            self.text(),
            method("Mailbox/get"),
            GetResponse::<Mailbox> {
                account_id: Some(self.id()),
                state: Some(self.state()),
                list: (0..self.below(3)).map(|_| self.mailbox()).collect(),
                not_found: Vec::new(),
            },
        );
        let mut set = SetResponse::<Email>::from_request(&Default::default(), 1000).expect("set");
        set.account_id = Some(self.id());
        set.old_state = Some(self.state());
        set.new_state = Some(self.state());
        set.created.insert(self.text(), self.email());
        set.updated.append(self.id(), None);
        set.updated.append(self.id(), Some(self.email()));
        set.destroyed.push(self.id());
        let error = self.set_error(EmailProperty::Subject, EmailProperty::Keywords);
        set.not_created.append(self.text(), error);
        let header = EmailProperty::Header(HeaderProperty {
            form: HeaderForm::Raw,
            header: self.text(),
            all: false,
        });
        let error = self.set_error(EmailProperty::MailboxIds, header);
        set.not_updated
            .append(MaybeInvalid::Value(self.id()), error);
        set.not_destroyed
            .append(MaybeInvalid::Invalid(self.text()), SetError::forbidden());
        response.push_response(self.text(), method("Email/set"), set);
        response.push_response(
            self.text(),
            method("Email/changes"),
            ChangesResponse::<Email> {
                account_id: self.id(),
                old_state: self.state(),
                new_state: self.state(),
                has_more_changes: self.chance(2),
                created: vec![self.id()],
                updated: vec![self.id(), self.id()],
                destroyed: Vec::new(),
                updated_properties: self.chance(2).then(|| {
                    vec![
                        PropertyWrapper(EmailProperty::Keywords),
                        PropertyWrapper(EmailProperty::Keyword(Keyword::parse(&self.text()))),
                    ]
                }),
            },
        );
        response.push_response(
            self.text(),
            method("Email/query"),
            QueryResponse {
                account_id: self.id(),
                query_state: self.state(),
                can_calculate_changes: self.chance(2),
                position: self.next() as i32,
                ids: (0..self.below(5)).map(|_| self.id()).collect(),
                total: self.chance(2).then(|| self.below(10_000)),
                limit: self.chance(2).then(|| self.below(100)),
            },
        );
        response.push_response(
            self.text(),
            method("Email/queryChanges"),
            QueryChangesResponse {
                account_id: self.id(),
                old_query_state: self.state(),
                new_query_state: self.state(),
                total: self.chance(2).then(|| self.below(100)),
                removed: vec![self.id()],
                added: vec![AddedItem {
                    id: self.id(),
                    index: self.below(100),
                }],
            },
        );
        response.push_response(
            self.text(),
            method("SearchSnippet/get"),
            GetSearchSnippetResponse {
                account_id: self.id(),
                list: vec![SearchSnippet {
                    email_id: self.id(),
                    subject: self.chance(2).then(|| self.text()),
                    preview: Some(format!("<mark>{}</mark>", self.text())),
                }],
                not_found: self
                    .chance(2)
                    .then(|| vec![MaybeInvalid::Invalid(self.text())]),
            },
        );
        response.push_response(
            self.text(),
            method("SieveScript/validate"),
            ValidateSieveScriptResponse {
                account_id: self.id(),
                error: self
                    .chance(2)
                    .then(|| SetError::invalid_properties().with_property(SieveProperty::BlobId)),
            },
        );
        let mut matched_ids = VecMap::new();
        matched_ids.append(DataType::Email, vec![self.id()]);
        matched_ids.append(DataType::Mailbox, Vec::new());
        response.push_response(
            self.text(),
            method("Blob/lookup"),
            BlobLookupResponse {
                account_id: self.id(),
                list: vec![BlobInfo {
                    id: self.blob_id(),
                    matched_ids,
                }],
                not_found: vec![self.blob_id()],
            },
        );
        let mut upload = BlobUploadResponse {
            account_id: self.id(),
            created: Default::default(),
            not_created: VecMap::new(),
        };
        upload.created.insert(
            self.text(),
            BlobUploadResponseObject {
                id: self.blob_id(),
                type_: self.chance(2).then(|| self.text()),
                size: self.below(1 << 20),
            },
        );
        response.push_response(self.text(), method("Blob/upload"), upload);
        let mut created = VecMap::new();
        created.append(self.text(), self.email());
        response.push_response(
            self.text(),
            method("Email/import"),
            ImportEmailResponse {
                account_id: self.id(),
                old_state: self.chance(2).then(|| self.state()),
                new_state: self.state(),
                created,
                not_created: VecMap::new(),
            },
        );
        let mut parsed = VecMap::new();
        parsed.append(self.blob_id(), self.email());
        response.push_response(
            self.text(),
            method("Email/parse"),
            ParseResponse::<Email> {
                account_id: self.id(),
                parsed,
                not_parsable: vec![self.blob_id()],
                not_found: vec![MaybeInvalid::Invalid(self.text())],
            },
        );
        let mut copied = VecMap::new();
        copied.append(self.blob_id(), self.blob_id());
        response.push_response(
            self.text(),
            method("Blob/copy"),
            CopyBlobResponse {
                from_account_id: self.id(),
                account_id: self.id(),
                copied,
                not_copied: VecMap::new(),
            },
        );
        let mut created = VecMap::new();
        created.append(self.text(), self.email());
        response.push_response(
            self.text(),
            method("Email/copy"),
            CopyResponse::<Email> {
                from_account_id: self.id(),
                account_id: self.id(),
                old_state: self.state(),
                new_state: self.state(),
                created,
                not_created: VecMap::new(),
            },
        );
        response.push_response(
            self.text(),
            method("Principal/getAvailability"),
            GetAvailabilityResponse {
                list: vec![BusyPeriod {
                    utc_start: self.date(),
                    utc_end: self.date(),
                    busy_status: match self.below(4) {
                        0 => Some(BusyStatus::Tentative),
                        1 => Some(BusyStatus::Unavailable),
                        2 => Some(BusyStatus::Confirmed),
                        _ => None,
                    },
                    event: self.chance(2).then(|| self.event(templates)),
                    account_id: self.chance(2).then(|| self.id()),
                }],
            },
        );
        response.push_response(
            self.text(),
            method("CalendarEvent/get"),
            GetResponse::<CalendarEvent> {
                account_id: Some(self.id()),
                state: Some(self.state()),
                list: vec![self.event(templates).0],
                not_found: Vec::new(),
            },
        );
        let mut card = templates.card.clone();
        if let Some(object) = card.as_object_mut() {
            object.insert_unchecked(Key::Borrowed("id"), Value::Str(self.text().into()));
        }
        response.push_response(
            self.text(),
            method("ContactCard/get"),
            GetResponse::<ContactCard> {
                account_id: Some(self.id()),
                state: Some(self.state()),
                list: vec![card],
                not_found: Vec::new(),
            },
        );
        let registry_object = (0..self.below(6))
            .filter_map(|_| {
                let property = RegistryProperty::from_id(self.next() as u16 % 1024)?;
                let value = match self.below(4) {
                    0 => Value::Element(RegistryValue::Id(self.id())),
                    1 => Value::Element(RegistryValue::BlobId(self.blob_id())),
                    2 => Value::Element(RegistryValue::IdReference(self.text())),
                    _ => Value::Str(self.text().into()),
                };
                Some((Key::Property(property), value))
            })
            .collect::<Vec<_>>();
        response.push_response(
            self.text(),
            method("x:Account/get"),
            GetResponse::<Registry> {
                account_id: Some(self.id()),
                state: Some(self.state()),
                list: vec![Value::Object(registry_object.into())],
                not_found: Vec::new(),
            },
        );
        response.push_error(
            self.text(),
            trc::JmapEvent::InvalidArguments
                .into_err()
                .details(self.text()),
        );
        response.push_error(self.text(), trc::JmapEvent::UnknownMethod.into_err());
        response
            .created_ids
            .insert(self.text(), AnyId::Id(self.id()));
        response
            .created_ids
            .insert(self.text(), AnyId::BlobId(self.blob_id()));
        response
    }
}

fn same<T: Serialize + ?Sized>(value: &T) -> bool {
    match (serde_json::to_string(value), sonic_rs::to_string(value)) {
        (Ok(serde), Ok(sonic)) => serde == sonic,
        (Err(_), Err(_)) => true,
        _ => false,
    }
}

const FLOATS: &[f64] = &[
    0.0,
    -0.0,
    0.1,
    -1.5,
    1e15,
    1e16,
    1e17,
    1e21,
    1e22,
    1e-7,
    5e-324,
    f64::MIN_POSITIVE,
    f64::from_bits(0x000F_FFFF_FFFF_FFFF),
    f64::EPSILON,
    f64::MAX,
    f64::MIN,
    f64::NAN,
    f64::INFINITY,
    f64::NEG_INFINITY,
    9_007_199_254_740_991.0,
    9_007_199_254_740_992.0,
    9_007_199_254_740_994.0,
    18_014_398_509_481_988.0,
    123456789012345678.0,
    16_777_217.0,
    f32::MAX as f64,
    f32::MIN_POSITIVE as f64,
];

const ESCAPED: &str = "\"\\/\u{7f}\u{80}é\u{2028}\u{2029}\u{feff}\u{ffff}\u{10000}🎉\u{10ffff}";

const POSITIONS: &[usize] = &[0, 1, 7, 8, 15, 16, 17, 31, 32, 33];

#[test]
fn serializer_methods_match_serde_json() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..2_000 {
        let probe = rng.probe(0);
        assert!(same(&probe), "{probe:?}");
    }
}

#[test]
fn scalars_match_serde_json() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let random = (0..3_000).map(|_| rng.float());
    for float in FLOATS.iter().copied().chain(random) {
        assert!(same(&float), "{float:?}");
        assert!(same(&(float as f32)), "{float:?}");
        assert!(same(&(float as i64)), "{float:?}");
        assert!(same(&(float as u64)), "{float:?}");
    }
    let controls = (0..0x20u8).map(char::from);
    for special in controls.chain(ESCAPED.chars()) {
        for len in 0..=40 {
            for &at in POSITIONS.iter().filter(|&&at| at <= len) {
                let text = (0..=len)
                    .map(|index| if index == at { special } else { 'a' })
                    .collect::<String>();
                assert!(same(&text), "{text:?}");
            }
        }
    }
    let mixed = (0..0x20u8)
        .map(char::from)
        .chain(ESCAPED.chars())
        .cycle()
        .take(500)
        .collect::<String>();
    assert!(same(&mixed));
}

#[test]
fn responses_match_serde_json() {
    let templates = Templates::new();
    let mut rng = Rng(0x5EED_CAFE_F00D);
    for round in 0..200 {
        let response = rng.response(&templates);
        assert_eq!(
            response.to_json(),
            serde_json::to_string(&response).unwrap_or_default(),
            "round {round}"
        );
        let websocket =
            WebSocketResponse::from_response(response, rng.chance(2).then(|| rng.text()));
        assert_eq!(
            websocket.to_json().ok(),
            serde_json::to_string(&websocket).ok(),
            "round {round}"
        );
    }
}
