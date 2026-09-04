/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Command, ResponseCode, ResponseType, StatusResponse};
use base64::{Engine, engine::general_purpose::STANDARD};
use compact_str::CompactString;
use std::fmt::Display;
use types::id::Id;
use types::keyword::Keyword;
use utils::chained_bytes::SliceRange;

pub mod acl;
pub mod append;
pub mod authenticate;
pub mod capability;
pub mod copy_move;
pub mod create;
pub mod delete;
pub mod enable;
pub mod expunge;
pub mod fetch;
pub mod list;
pub mod login;
pub mod namespace;
pub mod quota;
pub mod rename;
pub mod search;
pub mod select;
pub mod status;
pub mod store;
pub mod subscribe;
pub mod thread;
pub mod uidbatches;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    Rev1,
    Rev2,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectId {
    pub mailbox_id: Option<Id>,
    pub account_id: Option<Id>,
    pub email_id: Option<Id>,
    pub thread_id: Option<Id>,
}

impl ObjectId {
    pub fn is_empty(&self) -> bool {
        self.mailbox_id.is_none()
            && self.account_id.is_none()
            && self.email_id.is_none()
            && self.thread_id.is_none()
    }

    pub fn serialize_kvpairs(&self, buf: &mut Vec<u8>) {
        buf.push(b'(');
        let mut first = true;
        for (key, value) in [
            (&b"ACCOUNTID "[..], &self.account_id),
            (&b"MAILBOXID "[..], &self.mailbox_id),
            (&b"EMAILID "[..], &self.email_id),
            (&b"THREADID "[..], &self.thread_id),
        ] {
            if let Some(value) = value {
                if !first {
                    buf.push(b' ');
                }
                first = false;
                buf.extend_from_slice(key);
                buf.extend_from_slice(value.to_string().as_bytes());
            }
        }
        buf.push(b')');
    }

    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(b"OBJECTID ");
        self.serialize_kvpairs(buf);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sequence {
    Number {
        value: u32,
    },
    Range {
        start: Option<u32>,
        end: Option<u32>,
    },
    SavedSearch,
    List {
        items: Vec<Sequence>,
    },
}

impl Sequence {
    pub fn number(value: u32) -> Sequence {
        Sequence::Number { value }
    }

    pub fn range(start: Option<u32>, end: Option<u32>) -> Sequence {
        Sequence::Range { start, end }
    }

    pub fn contains(&self, value: u32, max_value: u32) -> bool {
        match self {
            Sequence::Number { value: number } => *number == value,
            Sequence::Range { start, end } => match (start, end) {
                (Some(start), Some(end)) => {
                    value >= *start && value <= *end || value >= *end && value <= *start
                }
                (Some(range), None) | (None, Some(range)) => {
                    value >= *range && value <= max_value || value >= max_value && value <= *range
                }
                (None, None) => value == max_value,
            },
            Sequence::List { items } => {
                for item in items {
                    if item.contains(value, max_value) {
                        return true;
                    }
                }
                false
            }
            Sequence::SavedSearch => false,
        }
    }

    pub fn is_saved_search(&self) -> bool {
        match self {
            Sequence::SavedSearch => true,
            Sequence::List { items } => items.iter().any(|s| s.is_saved_search()),
            _ => false,
        }
    }
}

pub trait ImapResponse {
    fn serialize_into(&self, buf: &mut Vec<u8>);

    fn serialize(self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut buf = Vec::with_capacity(128);
        self.serialize_into(&mut buf);
        buf
    }
}

pub fn quoted_string(buf: &mut Vec<u8>, text: &str) {
    let text = text.as_bytes();
    buf.push(b'"');
    let mut copied = 0;
    for (pos, &ch) in text.iter().enumerate() {
        if ch == b'\\' || ch == b'"' {
            buf.extend_from_slice(&text[copied..pos]);
            buf.push(b'\\');
            copied = pos;
        }
    }
    buf.extend_from_slice(&text[copied..]);
    buf.push(b'"');
}

pub fn quoted_or_literal_string(buf: &mut Vec<u8>, text: &str) {
    if text.as_bytes().iter().any(|ch| b"\\\"\r\n".contains(ch)) {
        literal_string(buf, text.as_bytes())
    } else {
        buf.push(b'"');
        buf.extend_from_slice(text.as_bytes());
        buf.push(b'"');
    }
}
pub fn quoted_or_literal_string_or_nil(buf: &mut Vec<u8>, text: Option<&str>) {
    if let Some(text) = text {
        quoted_or_literal_string(buf, text);
    } else {
        buf.extend_from_slice(b"NIL");
    }
}

pub fn quoted_or_literal_encoded_string(buf: &mut Vec<u8>, text: &str, is_utf8: bool) {
    if is_utf8 || text.is_ascii() {
        quoted_or_literal_string(buf, text);
    } else {
        buf.extend_from_slice(b"\"=?utf-8?B?");
        buf.extend_from_slice(STANDARD.encode(text.as_bytes()).as_bytes());
        buf.extend_from_slice(b"?=\"");
    }
}

pub fn quoted_or_literal_encoded_string_or_nil(
    buf: &mut Vec<u8>,
    text: Option<&str>,
    is_utf8: bool,
) {
    if let Some(text) = text {
        quoted_or_literal_encoded_string(buf, text, is_utf8);
    } else {
        buf.extend_from_slice(b"NIL");
    }
}

pub fn quoted_string_or_nil(buf: &mut Vec<u8>, text: Option<&str>) {
    if let Some(text) = text {
        quoted_string(buf, text);
    } else {
        buf.extend_from_slice(b"NIL");
    }
}

pub fn literal_string(buf: &mut Vec<u8>, text: &[u8]) {
    buf.push(b'{');
    push_int(buf, text.len());
    buf.extend_from_slice(b"}\r\n");
    buf.extend_from_slice(text);
}

pub fn literal_string_slice(buf: &mut Vec<u8>, text: &SliceRange<'_>) {
    buf.push(b'{');
    push_int(buf, text.len());
    buf.extend_from_slice(b"}\r\n");
    buf.extend(*text);
}

pub fn push_int(buf: &mut Vec<u8>, value: impl itoa::Integer) {
    let mut int_buf = itoa::Buffer::new();
    buf.extend_from_slice(int_buf.format(value).as_bytes());
}

const MONTHS_ABBREVIATED: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

fn push_zero_padded(buf: &mut Vec<u8>, value: u32) {
    buf.push(b'0' + (value / 10) as u8);
    buf.push(b'0' + (value % 10) as u8);
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    let year = year_of_era + era * 400;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

pub fn quoted_timestamp(buf: &mut Vec<u8>, timestamp: i64) {
    let (year, month, day) = civil_from_days(timestamp.div_euclid(86_400));
    let seconds_of_day = timestamp.rem_euclid(86_400) as u32;
    let year = year.clamp(0, 9999) as u32;

    buf.push(b'"');
    push_zero_padded(buf, day);
    buf.push(b'-');
    buf.extend_from_slice(MONTHS_ABBREVIATED[(month - 1) as usize]);
    buf.push(b'-');
    push_zero_padded(buf, year / 100);
    push_zero_padded(buf, year % 100);
    buf.push(b' ');
    push_zero_padded(buf, seconds_of_day / 3600);
    buf.push(b':');
    push_zero_padded(buf, (seconds_of_day / 60) % 60);
    buf.push(b':');
    push_zero_padded(buf, seconds_of_day % 60);
    buf.extend_from_slice(b" +0000\"");
}

pub fn quoted_rfc2822(buf: &mut Vec<u8>, timestamp: &mail_parser::DateTime) {
    buf.push(b'"');
    buf.extend_from_slice(timestamp.to_rfc822().as_bytes());
    buf.push(b'"');
}

pub fn quoted_rfc2822_or_nil(buf: &mut Vec<u8>, timestamp: &Option<mail_parser::DateTime>) {
    if let Some(timestamp) = timestamp {
        quoted_rfc2822(buf, timestamp);
    } else {
        buf.extend_from_slice(b"NIL");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    Seen,
    Draft,
    Flagged,
    Answered,
    Recent,
    Important,
    Phishing,
    Junk,
    NotJunk,
    Deleted,
    Forwarded,
    MDNSent,
    Autosent,
    CanUnsubscribe,
    Followed,
    HasAttachment,
    HasMemo,
    HasNoAttachment,
    Imported,
    IsTrusted,
    MailFlagBit0,
    MailFlagBit1,
    MailFlagBit2,
    MaskedEmail,
    Memo,
    Muted,
    New,
    Notify,
    Unsubscribed,
    Keyword(CompactString),
}

impl Flag {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            Flag::Seen => b"\\Seen",
            Flag::Draft => b"\\Draft",
            Flag::Flagged => b"\\Flagged",
            Flag::Answered => b"\\Answered",
            Flag::Recent => b"\\Recent",
            Flag::Important => b"\\Important",
            Flag::Phishing => b"$Phishing",
            Flag::Junk => b"$Junk",
            Flag::NotJunk => b"$NotJunk",
            Flag::Deleted => b"\\Deleted",
            Flag::Forwarded => b"$Forwarded",
            Flag::MDNSent => b"$MDNSent",
            Flag::Autosent => b"$autosent",
            Flag::CanUnsubscribe => b"$canunsubscribe",
            Flag::Followed => b"$followed",
            Flag::HasAttachment => b"$hasattachment",
            Flag::HasMemo => b"$hasmemo",
            Flag::HasNoAttachment => b"$hasnoattachment",
            Flag::Imported => b"$imported",
            Flag::IsTrusted => b"$istrusted",
            Flag::MailFlagBit0 => b"$MailFlagBit0",
            Flag::MailFlagBit1 => b"$MailFlagBit1",
            Flag::MailFlagBit2 => b"$MailFlagBit2",
            Flag::MaskedEmail => b"$maskedemail",
            Flag::Memo => b"$memo",
            Flag::Muted => b"$muted",
            Flag::New => b"$new",
            Flag::Notify => b"$notify",
            Flag::Unsubscribed => b"$unsubscribed",
            Flag::Keyword(keyword) => keyword.as_bytes(),
        });
    }
}

impl From<Keyword> for Flag {
    fn from(value: Keyword) -> Self {
        match value {
            Keyword::Seen => Flag::Seen,
            Keyword::Draft => Flag::Draft,
            Keyword::Flagged => Flag::Flagged,
            Keyword::Answered => Flag::Answered,
            Keyword::Recent => Flag::Recent,
            Keyword::Important => Flag::Important,
            Keyword::Phishing => Flag::Phishing,
            Keyword::Junk => Flag::Junk,
            Keyword::NotJunk => Flag::NotJunk,
            Keyword::Deleted => Flag::Deleted,
            Keyword::Forwarded => Flag::Forwarded,
            Keyword::MdnSent => Flag::MDNSent,
            Keyword::Autosent => Flag::Autosent,
            Keyword::CanUnsubscribe => Flag::CanUnsubscribe,
            Keyword::Followed => Flag::Followed,
            Keyword::HasAttachment => Flag::HasAttachment,
            Keyword::HasMemo => Flag::HasMemo,
            Keyword::HasNoAttachment => Flag::HasNoAttachment,
            Keyword::Imported => Flag::Imported,
            Keyword::IsTrusted => Flag::IsTrusted,
            Keyword::MailFlagBit0 => Flag::MailFlagBit0,
            Keyword::MailFlagBit1 => Flag::MailFlagBit1,
            Keyword::MailFlagBit2 => Flag::MailFlagBit2,
            Keyword::MaskedEmail => Flag::MaskedEmail,
            Keyword::Memo => Flag::Memo,
            Keyword::Muted => Flag::Muted,
            Keyword::New => Flag::New,
            Keyword::Notify => Flag::Notify,
            Keyword::Unsubscribed => Flag::Unsubscribed,
            Keyword::Other(value) => Flag::Keyword(value),
        }
    }
}

impl From<Flag> for Keyword {
    fn from(value: Flag) -> Self {
        match value {
            Flag::Seen => Keyword::Seen,
            Flag::Draft => Keyword::Draft,
            Flag::Flagged => Keyword::Flagged,
            Flag::Answered => Keyword::Answered,
            Flag::Recent => Keyword::Recent,
            Flag::Important => Keyword::Important,
            Flag::Phishing => Keyword::Phishing,
            Flag::Junk => Keyword::Junk,
            Flag::NotJunk => Keyword::NotJunk,
            Flag::Deleted => Keyword::Deleted,
            Flag::Forwarded => Keyword::Forwarded,
            Flag::MDNSent => Keyword::MdnSent,
            Flag::Autosent => Keyword::Autosent,
            Flag::CanUnsubscribe => Keyword::CanUnsubscribe,
            Flag::Followed => Keyword::Followed,
            Flag::HasAttachment => Keyword::HasAttachment,
            Flag::HasMemo => Keyword::HasMemo,
            Flag::HasNoAttachment => Keyword::HasNoAttachment,
            Flag::Imported => Keyword::Imported,
            Flag::IsTrusted => Keyword::IsTrusted,
            Flag::MailFlagBit0 => Keyword::MailFlagBit0,
            Flag::MailFlagBit1 => Keyword::MailFlagBit1,
            Flag::MailFlagBit2 => Keyword::MailFlagBit2,
            Flag::MaskedEmail => Keyword::MaskedEmail,
            Flag::Memo => Keyword::Memo,
            Flag::Muted => Keyword::Muted,
            Flag::New => Keyword::New,
            Flag::Notify => Keyword::Notify,
            Flag::Unsubscribed => Keyword::Unsubscribed,
            Flag::Keyword(value) => Keyword::from_compact_string(value),
        }
    }
}

impl ResponseCode {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            ResponseCode::Alert => b"ALERT",
            ResponseCode::AlreadyExists => b"ALREADYEXISTS",
            ResponseCode::AppendUid { uid_validity, uids } => {
                buf.extend_from_slice(b"APPENDUID ");
                push_int(buf, *uid_validity);
                buf.push(b' ');
                serialize_sequence(buf, uids);
                return;
            }
            ResponseCode::AuthenticationFailed => b"AUTHENTICATIONFAILED",
            ResponseCode::AuthorizationFailed => b"AUTHORIZATIONFAILED",
            ResponseCode::BadCharset => b"BADCHARSET",
            ResponseCode::Cannot => b"CANNOT",
            ResponseCode::Capability { capabilities } => {
                buf.extend_from_slice(b"CAPABILITY");
                for capability in capabilities {
                    buf.push(b' ');
                    capability.serialize(buf);
                }
                return;
            }
            ResponseCode::ClientBug => b"CLIENTBUG",
            ResponseCode::Closed => b"CLOSED",
            ResponseCode::ContactAdmin => b"CONTACTADMIN",
            ResponseCode::CopyUid {
                uid_validity,
                src_uids,
                dest_uids,
            } => {
                buf.extend_from_slice(b"COPYUID ");
                push_int(buf, *uid_validity);
                buf.push(b' ');
                serialize_sequence(buf, src_uids);
                buf.push(b' ');
                serialize_sequence(buf, dest_uids);
                return;
            }
            ResponseCode::Corruption => b"CORRUPTION",
            ResponseCode::Expired => b"EXPIRED",
            ResponseCode::ExpungeIssued => b"EXPUNGEISSUED",
            ResponseCode::HasChildren => b"HASCHILDREN",
            ResponseCode::InUse => b"INUSE",
            ResponseCode::Limit => b"LIMIT",
            ResponseCode::NonExistent => b"NONEXISTENT",
            ResponseCode::NoPerm => b"NOPERM",
            ResponseCode::OverQuota => b"OVERQUOTA",
            ResponseCode::Parse => b"PARSE",
            ResponseCode::PermanentFlags => b"PERMANENTFLAGS",
            ResponseCode::PrivacyRequired => b"PRIVACYREQUIRED",
            ResponseCode::ReadOnly => b"READ-ONLY",
            ResponseCode::ReadWrite => b"READ-WRITE",
            ResponseCode::ServerBug => b"SERVERBUG",
            ResponseCode::TryCreate => b"TRYCREATE",
            ResponseCode::UidNext => b"UIDNEXT",
            ResponseCode::UidNotSticky => b"UIDNOTSTICKY",
            ResponseCode::UidValidity => b"UIDVALIDITY",
            ResponseCode::Unavailable => b"UNAVAILABLE",
            ResponseCode::UnknownCte => b"UNKNOWN-CTE",
            ResponseCode::Modified { ranges } => {
                buf.extend_from_slice(b"MODIFIED ");
                serialize_sequence_ranges(buf, ranges);
                return;
            }
            ResponseCode::ObjectId(object_id) => {
                object_id.serialize(buf);
                return;
            }
            ResponseCode::HighestModseq { modseq } => {
                buf.extend_from_slice(b"HIGHESTMODSEQ ");
                push_int(buf, *modseq);
                return;
            }
            ResponseCode::UseAttr => b"USEATTR",
            ResponseCode::UidRequired => b"UIDREQUIRED",
            ResponseCode::TooFew => b"TOOFEW",
            ResponseCode::TooMany => b"TOOMANY",
            ResponseCode::MessageLimit { limit, uid } => {
                buf.extend_from_slice(b"MESSAGELIMIT ");
                push_int(buf, *limit);
                if let Some(uid) = uid {
                    buf.push(b' ');
                    push_int(buf, *uid);
                }
                return;
            }
        });
    }

    pub fn as_str(&self) -> &'static str {
        // Only returns the name without arguments
        match self {
            ResponseCode::Alert => "ALERT",
            ResponseCode::AlreadyExists => "ALREADYEXISTS",
            ResponseCode::AppendUid { .. } => "APPENDUID",
            ResponseCode::AuthenticationFailed => "AUTHENTICATIONFAILED",
            ResponseCode::AuthorizationFailed => "AUTHORIZATIONFAILED",
            ResponseCode::BadCharset => "BADCHARSET",
            ResponseCode::Cannot => "CANNOT",
            ResponseCode::Capability { .. } => "CAPABILITY",
            ResponseCode::ClientBug => "CLIENTBUG",
            ResponseCode::Closed => "CLOSED",
            ResponseCode::ContactAdmin => "CONTACTADMIN",
            ResponseCode::CopyUid { .. } => "COPYUID",
            ResponseCode::Corruption => "CORRUPTION",
            ResponseCode::Expired => "EXPIRED",
            ResponseCode::ExpungeIssued => "EXPUNGEISSUED",
            ResponseCode::HasChildren => "HASCHILDREN",
            ResponseCode::InUse => "INUSE",
            ResponseCode::Limit => "LIMIT",
            ResponseCode::NonExistent => "NONEXISTENT",
            ResponseCode::NoPerm => "NOPERM",
            ResponseCode::OverQuota => "OVERQUOTA",
            ResponseCode::Parse => "PARSE",
            ResponseCode::PermanentFlags => "PERMANENTFLAGS",
            ResponseCode::PrivacyRequired => "PRIVACYREQUIRED",
            ResponseCode::ReadOnly => "READ-ONLY",
            ResponseCode::ReadWrite => "READ-WRITE",
            ResponseCode::ServerBug => "SERVERBUG",
            ResponseCode::TryCreate => "TRYCREATE",
            ResponseCode::UidNext => "UIDNEXT",
            ResponseCode::UidNotSticky => "UIDNOTSTICKY",
            ResponseCode::UidValidity => "UIDVALIDITY",
            ResponseCode::Unavailable => "UNAVAILABLE",
            ResponseCode::UnknownCte => "UNKNOWN-CTE",
            ResponseCode::Modified { .. } => "MODIFIED",
            ResponseCode::ObjectId { .. } => "OBJECTID",
            ResponseCode::HighestModseq { .. } => "HIGHESTMODSEQ",
            ResponseCode::UseAttr => "USEATTR",
            ResponseCode::UidRequired => "UIDREQUIRED",
            ResponseCode::TooFew => "TOOFEW",
            ResponseCode::TooMany => "TOOMANY",
            ResponseCode::MessageLimit { .. } => "MESSAGELIMIT",
        }
    }
}

impl ResponseType {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_str().as_bytes());
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseType::Ok => "OK",
            ResponseType::No => "NO",
            ResponseType::Bad => "BAD",
            ResponseType::PreAuth => "PREAUTH",
            ResponseType::Bye => "BYE",
        }
    }
}

impl From<ResponseCode> for trc::Value {
    fn from(value: ResponseCode) -> Self {
        trc::Value::String(CompactString::const_new(value.as_str()))
    }
}

impl From<ResponseType> for trc::Value {
    fn from(value: ResponseType) -> Self {
        trc::Value::String(CompactString::const_new(value.as_str()))
    }
}

impl StatusResponse {
    pub fn serialize_into(&self, buf: &mut Vec<u8>) {
        if let Some(tag) = &self.tag {
            buf.extend_from_slice(tag.as_bytes());
        } else {
            buf.push(b'*');
        }
        buf.push(b' ');
        self.rtype.serialize(buf);
        buf.push(b' ');
        if let Some(code) = &self.code {
            buf.push(b'[');
            code.serialize(buf);
            buf.extend_from_slice(b"] ");
        }
        buf.extend_from_slice(self.message.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }

    pub fn serialize(self, mut buf: Vec<u8>) -> Vec<u8> {
        self.serialize_into(&mut buf);
        buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.serialize(Vec::with_capacity(16))
    }
}

pub trait SerializeResponse {
    fn serialize(&self) -> Vec<u8>;
}

impl SerializeResponse for trc::Error {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        if let Some(tag) = self.value_as_str(trc::Key::Id) {
            buf.extend_from_slice(tag.as_bytes());
        } else {
            buf.push(b'*');
        }
        buf.push(b' ');
        buf.extend_from_slice(self.value_as_str(trc::Key::Type).unwrap_or("NO").as_bytes());
        buf.push(b' ');
        if let Some(code) = self
            .value_as_str(trc::Key::Code)
            .or_else(|| match self.as_ref() {
                trc::EventType::Store(trc::StoreEvent::NotFound) => {
                    Some(ResponseCode::NonExistent.as_str())
                }
                trc::EventType::Store(_) => Some(ResponseCode::ContactAdmin.as_str()),
                trc::EventType::Limit(trc::LimitEvent::Quota) => {
                    Some(ResponseCode::OverQuota.as_str())
                }
                trc::EventType::Limit(_) => Some(ResponseCode::Limit.as_str()),
                trc::EventType::Auth(_) => Some(ResponseCode::AuthenticationFailed.as_str()),
                trc::EventType::Security(_) => Some(ResponseCode::AuthorizationFailed.as_str()),
                _ => None,
            })
        {
            buf.push(b'[');
            buf.extend_from_slice(code.as_bytes());
            buf.extend_from_slice(b"] ");
        }
        buf.extend_from_slice(
            self.value_as_str(trc::Key::Details)
                .unwrap_or_else(|| self.as_ref().message())
                .as_bytes(),
        );
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

impl ProtocolVersion {
    #[inline(always)]
    pub fn is_rev2(&self) -> bool {
        matches!(self, ProtocolVersion::Rev2)
    }

    #[inline(always)]
    pub fn is_rev1(&self) -> bool {
        matches!(self, ProtocolVersion::Rev1)
    }
}

pub fn serialize_sequence(buf: &mut Vec<u8>, list: &[u32]) {
    let mut ids = list.iter().peekable();
    while let Some(&id) = ids.next() {
        push_int(buf, id);
        let mut range_id = id;
        loop {
            match ids.peek() {
                Some(&&next_id) if next_id == range_id + 1 => {
                    range_id += 1;
                    ids.next();
                }
                next => {
                    if range_id != id {
                        buf.push(b':');
                        push_int(buf, range_id);
                    }
                    if next.is_some() {
                        buf.push(b',');
                    }
                    break;
                }
            }
        }
    }
}

pub fn serialize_sequence_ranges(buf: &mut Vec<u8>, ranges: &[(u32, u32)]) {
    for (pos, (from, to)) in ranges.iter().enumerate() {
        if pos > 0 {
            buf.push(b',');
        }
        push_int(buf, *from);
        if to != from {
            buf.push(b':');
            push_int(buf, *to);
        }
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Command::UidBatches => write!(f, "UIDBATCHES"),
            Command::Capability => write!(f, "CAPABILITY"),
            Command::Noop => write!(f, "NOOP"),
            Command::Logout => write!(f, "LOGOUT"),
            Command::StartTls => write!(f, "STARTTLS"),
            Command::Authenticate => write!(f, "AUTHENTICATE"),
            Command::Login => write!(f, "LOGIN"),
            Command::Enable => write!(f, "ENABLE"),
            Command::Select => write!(f, "SELECT"),
            Command::Examine => write!(f, "EXAMINE"),
            Command::Create => write!(f, "CREATE"),
            Command::Delete => write!(f, "DELETE"),
            Command::Rename => write!(f, "RENAME"),
            Command::Subscribe => write!(f, "SUBSCRIBE"),
            Command::Unsubscribe => write!(f, "UNSUBSCRIBE"),
            Command::List => write!(f, "LIST"),
            Command::Namespace => write!(f, "NAMESPACE"),
            Command::Status => write!(f, "STATUS"),
            Command::Append => write!(f, "APPEND"),
            Command::Idle => write!(f, "IDLE"),
            Command::Close => write!(f, "CLOSE"),
            Command::Unselect => write!(f, "UNSELECT"),
            Command::Expunge(false) => write!(f, "EXPUNGE"),
            Command::Search(false) => write!(f, "SEARCH"),
            Command::Fetch(false) => write!(f, "FETCH"),
            Command::Store(false) => write!(f, "STORE"),
            Command::Copy(false) => write!(f, "COPY"),
            Command::Move(false) => write!(f, "MOVE"),
            Command::Sort(false) => write!(f, "SORT"),
            Command::Thread(false) => write!(f, "THREAD"),
            Command::Expunge(true) => write!(f, "UID EXPUNGE"),
            Command::Search(true) => write!(f, "UID SEARCH"),
            Command::Fetch(true) => write!(f, "UID FETCH"),
            Command::Store(true) => write!(f, "UID STORE"),
            Command::Copy(true) => write!(f, "UID COPY"),
            Command::Move(true) => write!(f, "UID MOVE"),
            Command::Sort(true) => write!(f, "UID SORT"),
            Command::Thread(true) => write!(f, "UID THREAD"),
            Command::Lsub => write!(f, "LSUB"),
            Command::Check => write!(f, "CHECK"),
            Command::SetAcl => write!(f, "SETACL"),
            Command::DeleteAcl => write!(f, "DELETEACL"),
            Command::GetAcl => write!(f, "GETACL"),
            Command::ListRights => write!(f, "LISTRIGHTS"),
            Command::MyRights => write!(f, "MYRIGHTS"),
            Command::Unauthenticate => write!(f, "UNAUTHENTICATE"),
            Command::Id => write!(f, "ID"),
            Command::GetQuota => write!(f, "GETQUOTA"),
            Command::GetQuotaRoot => write!(f, "GETQUOTAROOT"),
            Command::GetJmapAccess => write!(f, "GETJMAPACCESS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::parse_sequence_set;
    use crate::protocol::ObjectId;
    use types::id::Id;

    #[test]
    fn quoted_timestamp_matches_chrono() {
        use chrono::{DateTime, Utc};

        let mut timestamp = -2_208_988_800i64;
        while timestamp < 4_102_444_800 {
            let mut buf = Vec::new();
            super::quoted_timestamp(&mut buf, timestamp);

            let expected = format!(
                "\"{}\"",
                DateTime::<Utc>::from_timestamp(timestamp, 0)
                    .unwrap_or_default()
                    .format("%d-%b-%Y %H:%M:%S %z")
            );
            assert_eq!(
                String::from_utf8(buf).unwrap(),
                expected,
                "mismatch at timestamp {timestamp}"
            );

            timestamp += 86_400 * 13 + 3_607;
        }
    }

    #[test]
    fn serialize_objectid_compound() {
        // Empty compound
        let mut buf = Vec::new();
        ObjectId::default().serialize(&mut buf);
        assert_eq!(String::from_utf8(buf).unwrap(), "OBJECTID ()");

        // Mailbox context: MAILBOXID + ACCOUNTID
        let mut buf = Vec::new();
        ObjectId {
            mailbox_id: Some(Id::from(1u32)),
            account_id: Some(Id::from(2u32)),
            ..Default::default()
        }
        .serialize(&mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!(
                "OBJECTID (ACCOUNTID {} MAILBOXID {})",
                Id::from(2u32),
                Id::from(1u32)
            )
        );

        // Message context: EMAILID + THREADID only
        let mut buf = Vec::new();
        ObjectId {
            email_id: Some(Id::from_parts(3, 4)),
            thread_id: Some(Id::from(3u32)),
            ..Default::default()
        }
        .serialize(&mut buf);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!(
                "OBJECTID (EMAILID {} THREADID {})",
                Id::from_parts(3, 4),
                Id::from(3u32)
            )
        );
    }

    #[test]
    fn sequence_set_contains() {
        for (sequence, expected_result, max_value) in [
            ("1,5:10", vec![1, 5, 6, 7, 8, 9, 10], 10),
            ("2,4:7,9,12:*", vec![2, 4, 5, 6, 7, 9, 12, 13, 14, 15], 15),
            ("*:4,5:7", vec![4, 5, 6, 7], 7),
            ("2,4,5", vec![2, 4, 5], 5),
        ] {
            let sequence = parse_sequence_set(sequence.as_bytes()).unwrap();

            assert_eq!(
                (1..=15)
                    .filter(|num| sequence.contains(*num, max_value))
                    .collect::<Vec<_>>(),
                expected_result
            );
        }
    }
}
