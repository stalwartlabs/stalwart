/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::store::{
    QuotaOwner,
    object::{
        ArchivedExchangeObject, ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite,
        ObjectVersion, OwnerStamp,
    },
};
use common::{Server, cache::exchange::ExchangeAccountCache};
use exchange_proto::{
    common::FileTime,
    convert::tags::RESPONSE_REQUESTED,
    eas::{commands::appdata::email::EmailFlag, types::EasDateTime},
    mapi::prop::{
        OwnedPropValue, PropKeyRef, PropValue, read_canonical_borrowed,
        sets::{PSETID_COMMON, PSETID_MEETING, PSETID_TASK},
        tags,
    },
};
use std::{borrow::Cow, mem};
use store::{
    roaring::RoaringBitmap,
    write::{Archive, ArchiveBytes, PendingId},
};
use trc::AddContext;
use types::collection::Collection;

pub(crate) const FLAG_STATUS_COMPLETE: u8 = 1;
pub(crate) const FLAG_STATUS_ACTIVE: u8 = 2;
pub(crate) const FLAG_FOLLOW_UP: &str = "Flag for follow up";
const MAPI_FLAG_COMPLETE: i32 = 1;
const NANOS_PER_MILLI: u32 = 1_000_000;
const MAX_MILLIS: u16 = 999;
const STATUS_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::FLAG_STATUS.id());
const VERB_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::LAST_VERB_EXECUTED.id());
const VERB_TIME_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::LAST_VERB_EXECUTION_TIME.id());
pub(crate) const MEETING_TYPE_KEY: PropKeyRef<'static> = PropKeyRef::Lid {
    set: PSETID_MEETING,
    lid: 0x0026,
};
const RESPONSE_REQUESTED_KEY: PropKeyRef<'static> = PropKeyRef::Tag(RESPONSE_REQUESTED);
const MESSAGE_CLASS_KEY: PropKeyRef<'static> = PropKeyRef::Tag(tags::MESSAGE_CLASS.id());
const MAX_MESSAGE_CLASS: usize = 255;
const MAPI_VERB_REPLY_TO_SENDER: i32 = 102;
const MAPI_VERB_REPLY_TO_ALL: i32 = 103;
const MAPI_VERB_FORWARD: i32 = 104;
const EAS_VERB_REPLY_TO_SENDER: i32 = 1;
const EAS_VERB_REPLY_TO_ALL: i32 = 2;
const EAS_VERB_FORWARD: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastVerb {
    ReplyToSender,
    ReplyToAll,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerbState {
    pub verb: LastVerb,
    pub time: Option<EasDateTime>,
}

#[derive(Debug, Default, PartialEq)]
pub struct StoredMail {
    pub flag: Option<EmailFlag<'static>>,
    pub verb: Option<VerbState>,
    pub meeting_type: Option<i32>,
    pub response_requested: Option<bool>,
    pub message_class: Option<Box<str>>,
}

impl LastVerb {
    pub const fn mapi(self) -> i32 {
        match self {
            LastVerb::ReplyToSender => MAPI_VERB_REPLY_TO_SENDER,
            LastVerb::ReplyToAll => MAPI_VERB_REPLY_TO_ALL,
            LastVerb::Forward => MAPI_VERB_FORWARD,
        }
    }

    pub const fn from_mapi(verb: i32) -> Option<Self> {
        match verb {
            MAPI_VERB_REPLY_TO_SENDER => Some(LastVerb::ReplyToSender),
            MAPI_VERB_REPLY_TO_ALL => Some(LastVerb::ReplyToAll),
            MAPI_VERB_FORWARD => Some(LastVerb::Forward),
            _ => None,
        }
    }

    pub const fn eas(self) -> i32 {
        match self {
            LastVerb::ReplyToSender => EAS_VERB_REPLY_TO_SENDER,
            LastVerb::ReplyToAll => EAS_VERB_REPLY_TO_ALL,
            LastVerb::Forward => EAS_VERB_FORWARD,
        }
    }
}

impl VerbState {
    pub fn write(self, object: &mut ExchangeObject) -> bool {
        let verb = set_or_remove(
            object,
            &encode_key(VERB_KEY),
            Some(OwnedPropValue::I32(self.verb.mapi())),
        );
        let time = set_or_remove(
            object,
            &encode_key(VERB_TIME_KEY),
            self.time.as_ref().map(FlagValue::to_prop),
        );
        verb || time
    }
}

const fn common(lid: u32) -> PropKeyRef<'static> {
    PropKeyRef::Lid {
        set: PSETID_COMMON,
        lid,
    }
}

const fn task(lid: u32) -> PropKeyRef<'static> {
    PropKeyRef::Lid {
        set: PSETID_TASK,
        lid,
    }
}

trait FlagValue: Sized {
    fn to_prop(&self) -> OwnedPropValue;
    fn from_prop(value: PropValue<'_>) -> Option<Self>;
}

impl FlagValue for EasDateTime {
    fn to_prop(&self) -> OwnedPropValue {
        OwnedPropValue::Time(FileTime::from_utc(
            self.0,
            u32::from(self.1.min(MAX_MILLIS)) * NANOS_PER_MILLI,
        ))
    }

    fn from_prop(value: PropValue<'_>) -> Option<Self> {
        match value {
            PropValue::Time(time) => {
                let (seconds, nanos) = time.to_utc();
                Some(EasDateTime(
                    seconds,
                    u16::try_from(nanos / NANOS_PER_MILLI).unwrap_or(MAX_MILLIS),
                ))
            }
            _ => None,
        }
    }
}

impl FlagValue for bool {
    fn to_prop(&self) -> OwnedPropValue {
        OwnedPropValue::Bool(*self)
    }

    fn from_prop(value: PropValue<'_>) -> Option<Self> {
        match value {
            PropValue::Bool(value) => Some(value),
            _ => None,
        }
    }
}

impl FlagValue for Cow<'_, str> {
    fn to_prop(&self) -> OwnedPropValue {
        OwnedPropValue::Unicode(self.as_ref().into())
    }

    fn from_prop(value: PropValue<'_>) -> Option<Self> {
        match value {
            PropValue::Unicode(text) => {
                let mut out = String::new();
                text.to_string_lossy(&mut out);
                Some(Cow::Owned(out))
            }
            _ => None,
        }
    }
}

pub(crate) fn encode_key(key: PropKeyRef<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    key.write_canonical(&mut out);
    out
}

pub(crate) fn decode(bytes: &[u8]) -> Option<PropValue<'_>> {
    read_canonical_borrowed(bytes)
        .filter(|(_, rest)| rest.is_empty())
        .map(|(value, _)| value)
}

fn decode_class(value: PropValue<'_>) -> Option<Box<str>> {
    let PropValue::Unicode(text) = value else {
        return None;
    };
    if text.is_empty() || text.len_units() > MAX_MESSAGE_CLASS {
        return None;
    }
    let mut class = String::new();
    text.to_string_lossy(&mut class);
    Some(class.into_boxed_str())
}

pub(crate) fn decode_i32(bytes: &[u8]) -> Option<i32> {
    match decode(bytes)? {
        PropValue::I32(value) => Some(value),
        _ => None,
    }
}

pub(crate) fn set_or_remove(
    object: &mut ExchangeObject,
    key: &[u8],
    value: Option<OwnedPropValue>,
) -> bool {
    match value {
        Some(value) => {
            let mut encoded = Vec::new();
            value.write_canonical(&mut encoded);
            if object.property(key) == Some(encoded.as_slice()) {
                false
            } else {
                object.set_property(key.to_vec(), encoded);
                true
            }
        }
        None => object.remove_property(key).is_some(),
    }
}

macro_rules! flag_fields {
    (
        ews: [$($ews:ident => $ews_key:expr),+ $(,)?],
        other: [$($other:ident => $other_key:expr),+ $(,)?] $(,)?
    ) => {
        pub struct FlagKeys {
            status: Vec<u8>,
            verb: Vec<u8>,
            verb_time: Vec<u8>,
            meeting_type: Vec<u8>,
            response_requested: Vec<u8>,
            message_class: Vec<u8>,
            $($ews: Vec<u8>,)+
            $($other: Vec<u8>,)+
        }

        impl FlagKeys {
            pub fn new() -> Self {
                FlagKeys {
                    status: encode_key(STATUS_KEY),
                    verb: encode_key(VERB_KEY),
                    verb_time: encode_key(VERB_TIME_KEY),
                    meeting_type: encode_key(MEETING_TYPE_KEY),
                    response_requested: encode_key(RESPONSE_REQUESTED_KEY),
                    message_class: encode_key(MESSAGE_CLASS_KEY),
                    $($ews: encode_key($ews_key),)+
                    $($other: encode_key($other_key),)+
                }
            }

            pub fn read(&self, object: &ArchivedExchangeObject) -> Option<EmailFlag<'static>> {
                let flag = EmailFlag {
                    status: matches!(
                        object.property(&self.status).and_then(decode),
                        Some(PropValue::I32(MAPI_FLAG_COMPLETE))
                    )
                    .then_some(FLAG_STATUS_COMPLETE),
                    $($ews: object
                        .property(&self.$ews)
                        .and_then(decode)
                        .and_then(FlagValue::from_prop),)+
                    $($other: object
                        .property(&self.$other)
                        .and_then(decode)
                        .and_then(FlagValue::from_prop),)+
                };
                (flag != EmailFlag::default()).then_some(flag)
            }

            pub fn write(&self, object: &mut ExchangeObject, flag: &EmailFlag<'_>) -> bool {
                let mut changed = false;
                self.edits(flag, |key, value| changed |= set_or_remove(object, key, value));
                changed
            }

            pub fn edits(
                &self,
                flag: &EmailFlag<'_>,
                mut edit: impl FnMut(&[u8], Option<OwnedPropValue>),
            ) {
                let kept = self.owned_edits(flag, &mut edit);
                $(edit(
                    &self.$other,
                    flag.$other.as_ref().filter(|_| kept).map(FlagValue::to_prop),
                );)+
            }

            pub fn ews_edits(
                &self,
                flag: &EmailFlag<'_>,
                mut edit: impl FnMut(&[u8], Option<OwnedPropValue>),
            ) {
                if !self.owned_edits(flag, &mut edit) {
                    $(edit(&self.$other, None);)+
                }
            }

            fn owned_edits(
                &self,
                flag: &EmailFlag<'_>,
                mut edit: impl FnMut(&[u8], Option<OwnedPropValue>),
            ) -> bool {
                let kept = matches!(
                    flag.status,
                    Some(FLAG_STATUS_COMPLETE | FLAG_STATUS_ACTIVE)
                );
                self.status_edit(flag.status == Some(FLAG_STATUS_COMPLETE), &mut edit);
                $(edit(
                    &self.$ews,
                    flag.$ews.as_ref().filter(|_| kept).map(FlagValue::to_prop),
                );)+
                kept
            }
        }
    };
}

flag_fields!(
    ews: [
        flag_type => common(0x8530),
        date_completed => task(0x810F),
        complete_time => PropKeyRef::Tag(tags::FLAG_COMPLETE_TIME.id()),
        start_date => task(0x8104),
        due_date => task(0x8105),
        utc_start_date => common(0x8516),
        utc_due_date => common(0x8517),
    ],
    other: [
        subject => common(0x85A4),
        reminder_set => common(0x8503),
        reminder_time => common(0x8502),
        ordinal_date => common(0x85A0),
        sub_ordinal_date => common(0x85A1),
    ],
);

impl FlagKeys {
    pub fn status_edit(&self, complete: bool, mut edit: impl FnMut(&[u8], Option<OwnedPropValue>)) {
        edit(
            &self.status,
            complete.then_some(OwnedPropValue::I32(MAPI_FLAG_COMPLETE)),
        );
    }

    pub fn verb_edit(
        &self,
        verb: Option<LastVerb>,
        mut edit: impl FnMut(&[u8], Option<OwnedPropValue>),
    ) {
        if verb.is_none() {
            edit(&self.verb_time, None);
        }
        edit(
            &self.verb,
            verb.map(|verb| OwnedPropValue::I32(verb.mapi())),
        );
    }

    pub fn response_requested_edit(
        &self,
        requested: Option<bool>,
        mut edit: impl FnMut(&[u8], Option<OwnedPropValue>),
    ) {
        edit(
            &self.response_requested,
            requested.map(OwnedPropValue::Bool),
        );
    }

    pub fn read_mail(&self, object: &ArchivedExchangeObject) -> Option<StoredMail> {
        let mail = StoredMail {
            flag: self.read(object),
            verb: self.read_verb(object),
            meeting_type: object.property(&self.meeting_type).and_then(decode_i32),
            response_requested: object
                .property(&self.response_requested)
                .and_then(decode)
                .and_then(FlagValue::from_prop),
            message_class: object
                .property(&self.message_class)
                .and_then(decode)
                .and_then(decode_class),
        };
        (mail != StoredMail::default()).then_some(mail)
    }

    fn read_verb(&self, object: &ArchivedExchangeObject) -> Option<VerbState> {
        let verb = LastVerb::from_mapi(object.property(&self.verb).and_then(decode_i32)?)?;
        Some(VerbState {
            verb,
            time: object
                .property(&self.verb_time)
                .and_then(decode)
                .and_then(FlagValue::from_prop),
        })
    }
}

impl Default for FlagKeys {
    fn default() -> Self {
        FlagKeys::new()
    }
}

pub struct MailRow {
    pub previous: Option<Archive<ArchiveBytes>>,
    pub next: ExchangeObject,
    collection: Collection,
}

impl MailRow {
    pub async fn load(
        server: &Server,
        exchange: &ExchangeAccountCache,
        account_id: u32,
        document_id: u32,
    ) -> trc::Result<Self> {
        let previous = if exchange.has_object(Collection::Email, document_id) {
            server
                .exchange_object(account_id, Collection::Email, document_id)
                .await?
        } else {
            None
        };
        MailRow::from_previous(previous, Collection::Email)
    }

    pub fn from_previous(
        previous: Option<Archive<ArchiveBytes>>,
        collection: Collection,
    ) -> trc::Result<Self> {
        let next = match &previous {
            Some(previous) => previous
                .deserialize::<ExchangeObject>()
                .caused_by(trc::location!())?,
            None => ExchangeObject::default(),
        };
        Ok(MailRow {
            previous,
            next,
            collection,
        })
    }

    pub fn write(
        &mut self,
        owner: QuotaOwner,
        document_id: u32,
        stamp: OwnerStamp,
        max_size: usize,
    ) -> ExchangeObjectWrite<'_> {
        self.write_as(owner, document_id, stamp, ObjectVersion::Server, max_size)
    }

    pub fn write_as(
        &mut self,
        owner: QuotaOwner,
        document_id: u32,
        stamp: OwnerStamp,
        version: ObjectVersion,
        max_size: usize,
    ) -> ExchangeObjectWrite<'_> {
        ExchangeObjectWrite {
            owner,
            collection: self.collection,
            document_id: PendingId::Assigned(document_id),
            stamp,
            version,
            previous: self.previous.as_ref(),
            next: Some(mem::take(&mut self.next)),
            max_size,
        }
    }
}

#[derive(Default)]
pub struct StoredFlags(Vec<(u32, StoredMail)>);

impl StoredFlags {
    pub async fn load(
        server: &Server,
        exchange: &ExchangeAccountCache,
        account_id: u32,
        documents: &RoaringBitmap,
    ) -> trc::Result<Self> {
        let mut flags = Vec::new();
        if exchange
            .objects(Collection::Email)
            .is_none_or(|stored| stored.is_disjoint(documents))
        {
            return Ok(StoredFlags(flags));
        }
        let keys = FlagKeys::new();
        server
            .exchange_objects(
                exchange,
                account_id,
                Collection::Email,
                documents,
                |document_id, object| {
                    if let Some(mail) = keys.read_mail(object) {
                        flags.push((document_id, mail));
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        flags.sort_unstable_by_key(|(document_id, _)| *document_id);
        Ok(StoredFlags(flags))
    }

    pub fn take(&mut self, document_id: u32) -> Option<StoredMail> {
        self.0
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .ok()
            .and_then(|idx| self.0.get_mut(idx))
            .map(|(_, mail)| mem::take(mail))
    }

    pub fn get(&self, document_id: u32) -> Option<&StoredMail> {
        self.0
            .binary_search_by_key(&document_id, |(id, _)| *id)
            .ok()
            .and_then(|idx| self.0.get(idx))
            .map(|(_, mail)| mail)
    }
}

pub fn rendered_flag<'a>(flagged: bool, stored: Option<&'a EmailFlag<'static>>) -> EmailFlag<'a> {
    match stored {
        Some(stored) if flagged => EmailFlag {
            status: Some(FLAG_STATUS_ACTIVE),
            flag_type: Some(Cow::Borrowed(
                stored.flag_type.as_deref().unwrap_or(FLAG_FOLLOW_UP),
            )),
            date_completed: None,
            complete_time: None,
            ..borrowed(stored)
        },
        Some(stored) if stored.status == Some(FLAG_STATUS_COMPLETE) => borrowed(stored),
        _ if flagged => EmailFlag {
            status: Some(FLAG_STATUS_ACTIVE),
            flag_type: Some(Cow::Borrowed(FLAG_FOLLOW_UP)),
            ..Default::default()
        },
        _ => EmailFlag::default(),
    }
}

fn borrowed<'a>(flag: &'a EmailFlag<'static>) -> EmailFlag<'a> {
    EmailFlag {
        subject: flag.subject.as_deref().map(Cow::Borrowed),
        status: flag.status,
        flag_type: flag.flag_type.as_deref().map(Cow::Borrowed),
        date_completed: flag.date_completed,
        complete_time: flag.complete_time,
        start_date: flag.start_date,
        due_date: flag.due_date,
        utc_start_date: flag.utc_start_date,
        utc_due_date: flag.utc_due_date,
        reminder_set: flag.reminder_set,
        reminder_time: flag.reminder_time,
        ordinal_date: flag.ordinal_date,
        sub_ordinal_date: flag.sub_ordinal_date.as_deref().map(Cow::Borrowed),
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/eas/convert/flag/tests.rs"]
mod tests;
