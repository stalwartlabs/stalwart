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
use utils::codec::base32_custom::BASE32_ALPHABET;

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
                push_id(buf, *value);
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

const DEFAULT_RESPONSE_CAPACITY: usize = 128;

pub trait ImapResponse {
    fn serialize_into(&self, buf: &mut Vec<u8>);

    fn size_hint(&self) -> usize {
        DEFAULT_RESPONSE_CAPACITY
    }

    fn serialize(self) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut buf = Vec::with_capacity(self.size_hint());
        self.serialize_into(&mut buf);
        buf
    }
}

const fn byte_class_table(needles: &[u8]) -> [bool; 256] {
    let mut table = [false; 256];
    let mut pos = 0;
    while pos < needles.len() {
        table[needles[pos] as usize] = true;
        pos += 1;
    }
    table
}

static NEEDS_ESCAPE: [bool; 256] = byte_class_table(b"\\\"");
static NEEDS_LITERAL: [bool; 256] = byte_class_table(b"\\\"\r\n");

#[inline(always)]
fn find_escape(text: &[u8]) -> Option<usize> {
    text.iter().position(|&ch| NEEDS_ESCAPE[ch as usize])
}

pub fn quoted_string(buf: &mut Vec<u8>, text: &str) {
    let mut rest = text.as_bytes();
    buf.push(b'"');
    while let Some(pos) = find_escape(rest) {
        let (head, tail) = rest.split_at(pos);
        buf.extend_from_slice(head);
        buf.push(b'\\');
        let mut tail = tail.iter();
        if let Some(&ch) = tail.next() {
            buf.push(ch);
        }
        rest = tail.as_slice();
    }
    buf.extend_from_slice(rest);
    buf.push(b'"');
}

pub fn quoted_or_literal_string(buf: &mut Vec<u8>, text: &str) {
    let text = text.as_bytes();
    if text.iter().any(|&ch| NEEDS_LITERAL[ch as usize]) {
        literal_string(buf, text)
    } else {
        buf.push(b'"');
        buf.extend_from_slice(text);
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

const CLASS_LITERAL: u8 = 1;
const CLASS_NON_ASCII: u8 = 2;

const fn text_class_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    table[b'\\' as usize] = CLASS_LITERAL;
    table[b'"' as usize] = CLASS_LITERAL;
    table[b'\r' as usize] = CLASS_LITERAL;
    table[b'\n' as usize] = CLASS_LITERAL;
    let mut ch = 0x80;
    while ch < 256 {
        table[ch] |= CLASS_NON_ASCII;
        ch += 1;
    }
    table
}

static TEXT_CLASS: [u8; 256] = text_class_table();

#[inline(always)]
fn base64_encoded_len(len: usize) -> usize {
    len.div_ceil(3) * 4
}

fn push_base64_encoded(buf: &mut Vec<u8>, text: &[u8]) {
    buf.extend_from_slice(b"\"=?utf-8?B?");
    let start = buf.len();
    buf.resize(start + base64_encoded_len(text.len()), 0);
    match buf
        .get_mut(start..)
        .ok_or(())
        .and_then(|target| STANDARD.encode_slice(text, target).map_err(|_| ()))
    {
        Ok(written) => buf.truncate(start + written),
        Err(()) => {
            buf.truncate(start);
            buf.extend_from_slice(STANDARD.encode(text).as_bytes());
        }
    }
    buf.extend_from_slice(b"?=\"");
}

pub fn quoted_or_literal_encoded_string(buf: &mut Vec<u8>, text: &str, is_utf8: bool) {
    if is_utf8 {
        quoted_or_literal_string(buf, text);
        return;
    }
    let text = text.as_bytes();
    let class = text
        .iter()
        .fold(0u8, |class, &ch| class | TEXT_CLASS[ch as usize]);
    if class & CLASS_NON_ASCII != 0 {
        push_base64_encoded(buf, text);
    } else if class & CLASS_LITERAL != 0 {
        literal_string(buf, text);
    } else {
        buf.push(b'"');
        buf.extend_from_slice(text);
        buf.push(b'"');
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
    match text {
        SliceRange::Single(bytes) => buf.extend_from_slice(bytes),
        SliceRange::Split(first, last) => {
            buf.extend_from_slice(first);
            buf.extend_from_slice(last);
        }
        SliceRange::None => (),
    }
}

pub fn push_int(buf: &mut Vec<u8>, value: impl itoa::Integer) {
    let mut int_buf = itoa::Buffer::new();
    buf.extend_from_slice(int_buf.format(value).as_bytes());
}

const ID_MAX_LEN: usize = 13;

fn push_id(buf: &mut Vec<u8>, id: Id) {
    const QUAD_SHIFT: usize = 60;
    const QUAD_RESET: usize = 4;
    const FIVE_SHIFT: usize = 59;
    const FIVE_RESET: usize = 5;
    const STOP_BIT: u64 = 1 << QUAD_SHIFT;

    let mut n = id.id();
    if n == 0 {
        buf.push(b'a');
        return;
    }

    buf.reserve(ID_MAX_LEN);
    match (n >> QUAD_SHIFT) as usize {
        0 => {
            n <<= QUAD_RESET;
            n |= 1;
            n <<= n.leading_zeros() / 5 * 5;
        }
        i => {
            n <<= QUAD_RESET;
            n |= 1;
            buf.push(BASE32_ALPHABET[i]);
        }
    }

    while n != STOP_BIT {
        buf.push(BASE32_ALPHABET[(n >> FIVE_SHIFT) as usize]);
        n <<= FIVE_RESET;
    }
}

const MONTHS_ABBREVIATED: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

const DAYS_ABBREVIATED: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];

#[inline(always)]
fn two_digits(value: u32) -> [u8; 2] {
    [b'0' + (value / 10) as u8, b'0' + (value % 10) as u8]
}

#[inline(always)]
fn push_padded_u8(buf: &mut Vec<u8>, value: u8) {
    if value >= 100 {
        buf.push(b'0' + value / 100);
    }
    buf.push(b'0' + (value / 10) % 10);
    buf.push(b'0' + value % 10);
}

#[inline(always)]
fn push_plain_u8(buf: &mut Vec<u8>, value: u8) {
    if value >= 100 {
        buf.push(b'0' + value / 100);
    }
    if value >= 10 {
        buf.push(b'0' + (value / 10) % 10);
    }
    buf.push(b'0' + value % 10);
}

#[inline(always)]
fn push_padded_u16(buf: &mut Vec<u8>, value: u16) {
    if value >= 10_000 {
        buf.push(b'0' + (value / 10_000) as u8);
    }
    buf.push(b'0' + ((value / 1_000) % 10) as u8);
    buf.push(b'0' + ((value / 100) % 10) as u8);
    buf.push(b'0' + ((value / 10) % 10) as u8);
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
    let month = MONTHS_ABBREVIATED[(month - 1) as usize];
    let [day_hi, day_lo] = two_digits(day);
    let [year_a, year_b] = two_digits(year / 100);
    let [year_c, year_d] = two_digits(year % 100);
    let [hour_hi, hour_lo] = two_digits(seconds_of_day / 3600);
    let [minute_hi, minute_lo] = two_digits((seconds_of_day / 60) % 60);
    let [second_hi, second_lo] = two_digits(seconds_of_day % 60);

    buf.extend_from_slice(&[
        b'"', day_hi, day_lo, b'-', month[0], month[1], month[2], b'-', year_a, year_b, year_c,
        year_d, b' ', hour_hi, hour_lo, b':', minute_hi, minute_lo, b':', second_hi, second_lo,
        b' ', b'+', b'0', b'0', b'0', b'0', b'"',
    ]);
}

pub fn quoted_rfc2822(buf: &mut Vec<u8>, timestamp: &mail_parser::DateTime) {
    const MAX_LEN: usize = 40;
    buf.reserve(MAX_LEN);
    buf.push(b'"');
    buf.extend_from_slice(DAYS_ABBREVIATED[usize::from(timestamp.day_of_week()) % 7]);
    buf.extend_from_slice(b", ");
    push_plain_u8(buf, timestamp.day);
    buf.push(b' ');
    if let Some(month) = MONTHS_ABBREVIATED.get(usize::from(timestamp.month.saturating_sub(1))) {
        buf.extend_from_slice(*month);
    }
    buf.push(b' ');
    push_padded_u16(buf, timestamp.year);
    buf.push(b' ');
    push_padded_u8(buf, timestamp.hour);
    buf.push(b':');
    push_padded_u8(buf, timestamp.minute);
    buf.push(b':');
    push_padded_u8(buf, timestamp.second);
    buf.push(b' ');
    buf.push(
        if timestamp.tz_before_gmt && (timestamp.tz_hour > 0 || timestamp.tz_minute > 0) {
            b'-'
        } else {
            b'+'
        },
    );
    push_padded_u8(buf, timestamp.tz_hour);
    push_padded_u8(buf, timestamp.tz_minute);
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

    fn size_hint(&self) -> usize {
        const BRACKETS_LEN: usize = 3;
        const INT_LEN: usize = 11;
        const CAPABILITY_LEN: usize = 20;
        const OBJECT_ID_LEN: usize = 92;

        self.as_str().len()
            + BRACKETS_LEN
            + match self {
                ResponseCode::AppendUid { uids, .. } => INT_LEN * (uids.len() + 1),
                ResponseCode::Capability { capabilities } => capabilities.len() * CAPABILITY_LEN,
                ResponseCode::CopyUid {
                    src_uids,
                    dest_uids,
                    ..
                } => INT_LEN * (src_uids.len() + dest_uids.len() + 1) + 2,
                ResponseCode::Modified { ranges } => ranges.len() * (INT_LEN * 2 + 1) + 1,
                ResponseCode::ObjectId(_) => OBJECT_ID_LEN,
                ResponseCode::HighestModseq { .. } => 21,
                ResponseCode::MessageLimit { .. } => INT_LEN * 2 + 1,
                _ => 0,
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
        let capacity = self.size_hint();
        self.serialize(Vec::with_capacity(capacity))
    }

    pub fn serialize_after(self, response: &impl ImapResponse) -> Vec<u8> {
        let mut buf = Vec::with_capacity(response.size_hint() + self.size_hint());
        response.serialize_into(&mut buf);
        self.serialize_into(&mut buf);
        buf
    }

    fn size_hint(&self) -> usize {
        const FRAMING_LEN: usize = 4;

        self.tag.as_ref().map_or(1, |tag| tag.len())
            + self.rtype.as_str().len()
            + self.message.len()
            + self.code.as_ref().map_or(0, ResponseCode::size_hint)
            + FRAMING_LEN
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
    let mut rest = list;
    while let Some((&id, mut tail)) = rest.split_first() {
        push_int(buf, id);

        let mut range_id = id;
        while let Some((&next_id, next_tail)) = tail.split_first() {
            if next_id != range_id + 1 {
                break;
            }
            range_id += 1;
            tail = next_tail;
        }

        if range_id != id {
            buf.push(b':');
            push_int(buf, range_id);
        }
        if !tail.is_empty() {
            buf.push(b',');
        }
        rest = tail;
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
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::parse_sequence_set;
    use crate::protocol::ObjectId;
    use crate::{Command, StatusResponse};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use mail_parser::DateTime;
    use types::id::Id;
    use utils::chained_bytes::SliceRange;

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

    const ALL_COMMANDS: [Command; 50] = [
        Command::Capability,
        Command::Noop,
        Command::Logout,
        Command::StartTls,
        Command::Authenticate,
        Command::Login,
        Command::Enable,
        Command::Select,
        Command::Examine,
        Command::Create,
        Command::Delete,
        Command::Rename,
        Command::Subscribe,
        Command::Unsubscribe,
        Command::List,
        Command::Namespace,
        Command::Status,
        Command::Append,
        Command::Idle,
        Command::Close,
        Command::Unselect,
        Command::Expunge(false),
        Command::Expunge(true),
        Command::Search(false),
        Command::Search(true),
        Command::Fetch(false),
        Command::Fetch(true),
        Command::Store(false),
        Command::Store(true),
        Command::Copy(false),
        Command::Copy(true),
        Command::Move(false),
        Command::Move(true),
        Command::Lsub,
        Command::Check,
        Command::Sort(false),
        Command::Sort(true),
        Command::Thread(false),
        Command::Thread(true),
        Command::SetAcl,
        Command::DeleteAcl,
        Command::GetAcl,
        Command::ListRights,
        Command::MyRights,
        Command::Unauthenticate,
        Command::Id,
        Command::GetQuota,
        Command::GetQuotaRoot,
        Command::GetJmapAccess,
        Command::UidBatches,
    ];
    #[test]
    fn command_names_and_completed_messages() {
        let expected: [(Command, &str); 50] = [
            (Command::Capability, "CAPABILITY"),
            (Command::Noop, "NOOP"),
            (Command::Logout, "LOGOUT"),
            (Command::StartTls, "STARTTLS"),
            (Command::Authenticate, "AUTHENTICATE"),
            (Command::Login, "LOGIN"),
            (Command::Enable, "ENABLE"),
            (Command::Select, "SELECT"),
            (Command::Examine, "EXAMINE"),
            (Command::Create, "CREATE"),
            (Command::Delete, "DELETE"),
            (Command::Rename, "RENAME"),
            (Command::Subscribe, "SUBSCRIBE"),
            (Command::Unsubscribe, "UNSUBSCRIBE"),
            (Command::List, "LIST"),
            (Command::Namespace, "NAMESPACE"),
            (Command::Status, "STATUS"),
            (Command::Append, "APPEND"),
            (Command::Idle, "IDLE"),
            (Command::Close, "CLOSE"),
            (Command::Unselect, "UNSELECT"),
            (Command::Expunge(false), "EXPUNGE"),
            (Command::Expunge(true), "UID EXPUNGE"),
            (Command::Search(false), "SEARCH"),
            (Command::Search(true), "UID SEARCH"),
            (Command::Fetch(false), "FETCH"),
            (Command::Fetch(true), "UID FETCH"),
            (Command::Store(false), "STORE"),
            (Command::Store(true), "UID STORE"),
            (Command::Copy(false), "COPY"),
            (Command::Copy(true), "UID COPY"),
            (Command::Move(false), "MOVE"),
            (Command::Move(true), "UID MOVE"),
            (Command::Lsub, "LSUB"),
            (Command::Check, "CHECK"),
            (Command::Sort(false), "SORT"),
            (Command::Sort(true), "UID SORT"),
            (Command::Thread(false), "THREAD"),
            (Command::Thread(true), "UID THREAD"),
            (Command::SetAcl, "SETACL"),
            (Command::DeleteAcl, "DELETEACL"),
            (Command::GetAcl, "GETACL"),
            (Command::ListRights, "LISTRIGHTS"),
            (Command::MyRights, "MYRIGHTS"),
            (Command::Unauthenticate, "UNAUTHENTICATE"),
            (Command::Id, "ID"),
            (Command::GetQuota, "GETQUOTA"),
            (Command::GetQuotaRoot, "GETQUOTAROOT"),
            (Command::GetJmapAccess, "GETJMAPACCESS"),
            (Command::UidBatches, "UIDBATCHES"),
        ];
        assert_eq!(expected.len(), ALL_COMMANDS.len());
        for (command, name) in expected {
            assert!(ALL_COMMANDS.contains(&command));
            assert_eq!(command.as_str(), name);
            assert_eq!(format!("{command}"), name);
            assert_eq!(command.completed_message(), format!("{name} completed"));
            assert_eq!(
                StatusResponse::completed(command).message,
                format!("{name} completed")
            );
        }
    }

    #[test]
    fn quoted_rfc2822_matches_mail_parser() {
        let mut buf = Vec::new();
        for year in [0u16, 1, 99, 999, 1000, 1970, 2024, 9999, 10000, 65535] {
            for month in [0u8, 1, 2, 6, 11, 12, 13, 255] {
                for day in [0u8, 1, 9, 10, 28, 31, 32, 99, 100, 255] {
                    for (hour, minute, second) in [
                        (0u8, 0u8, 0u8),
                        (9, 5, 7),
                        (23, 59, 59),
                        (24, 60, 60),
                        (99, 100, 255),
                    ] {
                        for (tz_before_gmt, tz_hour, tz_minute) in [
                            (false, 0u8, 0u8),
                            (true, 0, 0),
                            (true, 0, 30),
                            (true, 8, 0),
                            (false, 14, 45),
                            (true, 99, 99),
                        ] {
                            let timestamp = DateTime {
                                year,
                                month,
                                day,
                                hour,
                                minute,
                                second,
                                tz_before_gmt,
                                tz_hour,
                                tz_minute,
                            };
                            buf.clear();
                            super::quoted_rfc2822(&mut buf, &timestamp);
                            assert_eq!(
                                buf,
                                format!("\"{}\"", timestamp.to_rfc822()).as_bytes(),
                                "{timestamp:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn object_id_matches_id_display() {
        let ids = [
            0u64,
            1,
            31,
            32,
            33,
            1023,
            1024,
            u32::MAX as u64,
            1 << 59,
            (1 << 60) - 1,
            1 << 60,
            (1 << 60) + 1,
            u64::MAX - 1,
            u64::MAX,
        ];
        for &raw in &ids {
            for &other in &ids {
                let object_id = ObjectId {
                    mailbox_id: Some(Id::new(raw)),
                    account_id: None,
                    email_id: Some(Id::new(other)),
                    thread_id: Some(Id::from_parts(raw as u32, other as u32)),
                };
                let mut buf = Vec::new();
                object_id.serialize(&mut buf);
                assert_eq!(
                    String::from_utf8(buf).unwrap(),
                    format!(
                        "OBJECTID (MAILBOXID {} EMAILID {} THREADID {})",
                        Id::new(raw),
                        Id::new(other),
                        Id::from_parts(raw as u32, other as u32)
                    )
                );
            }
        }
    }

    fn naive_quoted(text: &str) -> Vec<u8> {
        let mut out = vec![b'"'];
        for &ch in text.as_bytes() {
            if ch == b'\\' || ch == b'"' {
                out.push(b'\\');
            }
            out.push(ch);
        }
        out.push(b'"');
        out
    }

    fn naive_literal(text: &[u8]) -> Vec<u8> {
        let mut out = format!("{{{}}}\r\n", text.len()).into_bytes();
        out.extend_from_slice(text);
        out
    }

    const STRING_SAMPLES: &[&str] = &[
        "",
        "a",
        "INBOX",
        "Sent Items",
        "\\",
        "\"",
        "\\\"",
        "a\\b\"c",
        "ends with backslash\\",
        "\"starts with quote",
        "line\r\nbreak",
        "carriage\rreturn",
        "line\nfeed",
        "tab\tinside",
        "\u{7f}",
        "J\u{fc}rgen M\u{fc}ller",
        "\u{53f0}\u{5317}",
        "\u{1f604}",
        "mixed \u{fc} and \"quotes\"",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];

    #[test]
    fn quoted_strings_match_naive_encoders() {
        for repeat in [1usize, 5, 40] {
            for sample in STRING_SAMPLES {
                let text = sample.repeat(repeat);
                let bytes = text.as_bytes();
                let needs_literal = bytes
                    .iter()
                    .any(|ch| matches!(ch, b'\\' | b'"' | b'\r' | b'\n'));

                let mut buf = b"prefix ".to_vec();
                super::quoted_string(&mut buf, &text);
                let mut expected = b"prefix ".to_vec();
                expected.extend(naive_quoted(&text));
                assert_eq!(buf, expected, "quoted_string {text:?}");

                let mut buf = Vec::new();
                super::quoted_or_literal_string(&mut buf, &text);
                let expected = if needs_literal {
                    naive_literal(bytes)
                } else {
                    naive_quoted(&text)
                };
                assert_eq!(buf, expected, "quoted_or_literal_string {text:?}");

                for is_utf8 in [false, true] {
                    let mut buf = Vec::new();
                    super::quoted_or_literal_encoded_string(&mut buf, &text, is_utf8);
                    let expected = if is_utf8 || text.is_ascii() {
                        if needs_literal {
                            naive_literal(bytes)
                        } else {
                            naive_quoted(&text)
                        }
                    } else {
                        format!("\"=?utf-8?B?{}?=\"", STANDARD.encode(bytes)).into_bytes()
                    };
                    assert_eq!(
                        buf, expected,
                        "quoted_or_literal_encoded_string {text:?} is_utf8={is_utf8}"
                    );
                }
            }
        }
    }

    fn naive_sequence(list: &[u32]) -> String {
        let mut out = String::new();
        let mut index = 0;
        while index < list.len() {
            let start = list[index];
            let mut end = start;
            while index + 1 < list.len() && list[index + 1] == end + 1 {
                end += 1;
                index += 1;
            }
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(&start.to_string());
            if end != start {
                out.push(':');
                out.push_str(&end.to_string());
            }
            index += 1;
        }
        out
    }

    #[test]
    fn serialize_sequence_matches_naive_ranges() {
        let cases: &[&[u32]] = &[
            &[],
            &[1],
            &[1, 2],
            &[1, 3],
            &[
                1, 2, 3, 5, 10, 11, 12, 13, 90, 92, 93, 94, 95, 96, 97, 98, 99,
            ],
            &[5, 5, 5],
            &[3, 2, 1],
            &[u32::MAX - 1, u32::MAX],
            &[0, 1, 2],
            &[7, 9, 11, 13],
        ];
        for case in cases {
            let mut buf = Vec::new();
            super::serialize_sequence(&mut buf, case);
            assert_eq!(
                String::from_utf8(buf).unwrap(),
                naive_sequence(case),
                "{case:?}"
            );
        }
        let long: Vec<u32> = (1..=5000)
            .filter(|id| id % 7 != 0 && id % 11 != 3)
            .collect();
        let mut buf = Vec::new();
        super::serialize_sequence(&mut buf, &long);
        assert_eq!(String::from_utf8(buf).unwrap(), naive_sequence(&long));
    }

    #[test]
    fn literal_string_slice_matches_concatenation() {
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        for split in [0usize, 1, 7, 150, 299, 300] {
            let (first, last) = payload.split_at(split);
            for range in [
                SliceRange::Single(first),
                SliceRange::Split(first, last),
                SliceRange::None,
            ] {
                let mut buf = Vec::new();
                super::literal_string_slice(&mut buf, &range);
                let expected_payload: Vec<u8> = match range {
                    SliceRange::Single(bytes) => bytes.to_vec(),
                    SliceRange::Split(first, last) => [first, last].concat(),
                    SliceRange::None => Vec::new(),
                };
                assert_eq!(buf, naive_literal(&expected_payload));
            }
        }
    }
}
