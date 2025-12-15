/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_tools::{Element, Property, Value};
use std::{fmt::Display, str::FromStr};

pub const SEEN: usize = 0;
pub const DRAFT: usize = 1;
pub const FLAGGED: usize = 2;
pub const ANSWERED: usize = 3;
pub const RECENT: usize = 4;
pub const IMPORTANT: usize = 5;
pub const PHISHING: usize = 6;
pub const JUNK: usize = 7;
pub const NOTJUNK: usize = 8;
pub const DELETED: usize = 9;
pub const FORWARDED: usize = 10;
pub const MDN_SENT: usize = 11;
pub const AUTOSENT: usize = 12;
pub const CANUNSUBSCRIBE: usize = 13;
pub const FOLLOWED: usize = 14;
pub const HASATTACHMENT: usize = 15;
pub const HASMEMO: usize = 16;
pub const HASNOATTACHMENT: usize = 17;
pub const IMPORTED: usize = 18;
pub const ISTRUSTED: usize = 19;
pub const MAILFLAGBIT0: usize = 20;
pub const MAILFLAGBIT1: usize = 21;
pub const MAILFLAGBIT2: usize = 22;
pub const MASKEDEMAIL: usize = 23;
pub const MEMO: usize = 24;
pub const MUTED: usize = 25;
pub const NEW: usize = 26;
pub const NOTIFY: usize = 27;
pub const UNSUBSCRIBED: usize = 28;
pub const OTHER: usize = 29;

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    PartialOrd,
    Ord,
    serde::Serialize,
)]
#[serde(untagged)]
#[rkyv(derive(PartialEq), compare(PartialEq))]
pub enum Keyword {
    Other(Box<str>),
    #[serde(rename(serialize = "$seen"))]
    Seen,
    #[serde(rename(serialize = "$draft"))]
    Draft,
    #[serde(rename(serialize = "$flagged"))]
    Flagged,
    #[serde(rename(serialize = "$answered"))]
    Answered,
    #[default]
    #[serde(rename(serialize = "$recent"))]
    Recent,
    #[serde(rename(serialize = "$important"))]
    Important,
    #[serde(rename(serialize = "$phishing"))]
    Phishing,
    #[serde(rename(serialize = "$junk"))]
    Junk,
    #[serde(rename(serialize = "$notjunk"))]
    NotJunk,
    #[serde(rename(serialize = "$deleted"))]
    Deleted,
    #[serde(rename(serialize = "$forwarded"))]
    Forwarded,
    #[serde(rename(serialize = "$mdnsent"))]
    MdnSent,
    #[serde(rename(serialize = "$autosent"))]
    Autosent,
    #[serde(rename(serialize = "$canunsubscribe"))]
    CanUnsubscribe,
    #[serde(rename(serialize = "$followed"))]
    Followed,
    #[serde(rename(serialize = "$hasattachment"))]
    HasAttachment,
    #[serde(rename(serialize = "$hasmemo"))]
    HasMemo,
    #[serde(rename(serialize = "$hasnoattachment"))]
    HasNoAttachment,
    #[serde(rename(serialize = "$imported"))]
    Imported,
    #[serde(rename(serialize = "$istrusted"))]
    IsTrusted,
    #[serde(rename(serialize = "$MailFlagBit0"))]
    MailFlagBit0,
    #[serde(rename(serialize = "$MailFlagBit1"))]
    MailFlagBit1,
    #[serde(rename(serialize = "$MailFlagBit2"))]
    MailFlagBit2,
    #[serde(rename(serialize = "$maskedemail"))]
    MaskedEmail,
    #[serde(rename(serialize = "$memo"))]
    Memo,
    #[serde(rename(serialize = "$muted"))]
    Muted,
    #[serde(rename(serialize = "$new"))]
    New,
    #[serde(rename(serialize = "$notify"))]
    Notify,
    #[serde(rename(serialize = "$unsubscribed"))]
    Unsubscribed,
}

impl Keyword {
    pub const MAX_LENGTH: usize = 128;

    pub fn parse(value: &str) -> Self {
        Self::try_parse(value)
            .unwrap_or_else(|| Keyword::Other(value.chars().take(Keyword::MAX_LENGTH).collect()))
    }

    pub fn from_other(value: String) -> Self {
        if value.len() <= Keyword::MAX_LENGTH {
            Keyword::Other(value.into_boxed_str())
        } else {
            Keyword::Other(value.chars().take(Keyword::MAX_LENGTH).collect())
        }
    }

    pub fn from_boxed_other(value: Box<str>) -> Self {
        if value.len() <= Keyword::MAX_LENGTH {
            Keyword::Other(value)
        } else {
            Keyword::Other(value.chars().take(Keyword::MAX_LENGTH).collect())
        }
    }

    pub fn try_parse(value: &str) -> Option<Self> {
        value
            .split_at_checked(1)
            .filter(|(prefix, _)| matches!(*prefix, "$" | "\\"))
            .and_then(|(_, rest)| {
                hashify::tiny_map_ignore_case!(rest.as_bytes(),
                    "seen" => Keyword::Seen,
                    "draft" => Keyword::Draft,
                    "flagged" => Keyword::Flagged,
                    "answered" => Keyword::Answered,
                    "recent" => Keyword::Recent,
                    "important" => Keyword::Important,
                    "phishing" => Keyword::Phishing,
                    "junk" => Keyword::Junk,
                    "notjunk" => Keyword::NotJunk,
                    "deleted" => Keyword::Deleted,
                    "forwarded" => Keyword::Forwarded,
                    "mdnsent" => Keyword::MdnSent,
                    "autosent" => Keyword::Autosent,
                    "canunsubscribe" => Keyword::CanUnsubscribe,
                    "followed" => Keyword::Followed,
                    "hasattachment" => Keyword::HasAttachment,
                    "hasmemo" => Keyword::HasMemo,
                    "hasnoattachment" => Keyword::HasNoAttachment,
                    "imported" => Keyword::Imported,
                    "istrusted" => Keyword::IsTrusted,
                    "mailflagbit0" => Keyword::MailFlagBit0,
                    "mailflagbit1" => Keyword::MailFlagBit1,
                    "mailflagbit2" => Keyword::MailFlagBit2,
                    "maskedemail" => Keyword::MaskedEmail,
                    "memo" => Keyword::Memo,
                    "muted" => Keyword::Muted,
                    "new" => Keyword::New,
                    "notify" => Keyword::Notify,
                    "unsubscribed" => Keyword::Unsubscribed,
                )
            })
    }

    pub fn id(&self) -> Result<u32, &str> {
        match self {
            Keyword::Seen => Ok(SEEN as u32),
            Keyword::Draft => Ok(DRAFT as u32),
            Keyword::Flagged => Ok(FLAGGED as u32),
            Keyword::Answered => Ok(ANSWERED as u32),
            Keyword::Recent => Ok(RECENT as u32),
            Keyword::Important => Ok(IMPORTANT as u32),
            Keyword::Phishing => Ok(PHISHING as u32),
            Keyword::Junk => Ok(JUNK as u32),
            Keyword::NotJunk => Ok(NOTJUNK as u32),
            Keyword::Deleted => Ok(DELETED as u32),
            Keyword::Forwarded => Ok(FORWARDED as u32),
            Keyword::MdnSent => Ok(MDN_SENT as u32),
            Keyword::Autosent => Ok(AUTOSENT as u32),
            Keyword::CanUnsubscribe => Ok(CANUNSUBSCRIBE as u32),
            Keyword::Followed => Ok(FOLLOWED as u32),
            Keyword::HasAttachment => Ok(HASATTACHMENT as u32),
            Keyword::HasMemo => Ok(HASMEMO as u32),
            Keyword::HasNoAttachment => Ok(HASNOATTACHMENT as u32),
            Keyword::Imported => Ok(IMPORTED as u32),
            Keyword::IsTrusted => Ok(ISTRUSTED as u32),
            Keyword::MailFlagBit0 => Ok(MAILFLAGBIT0 as u32),
            Keyword::MailFlagBit1 => Ok(MAILFLAGBIT1 as u32),
            Keyword::MailFlagBit2 => Ok(MAILFLAGBIT2 as u32),
            Keyword::MaskedEmail => Ok(MASKEDEMAIL as u32),
            Keyword::Memo => Ok(MEMO as u32),
            Keyword::Muted => Ok(MUTED as u32),
            Keyword::New => Ok(NEW as u32),
            Keyword::Notify => Ok(NOTIFY as u32),
            Keyword::Unsubscribed => Ok(UNSUBSCRIBED as u32),
            Keyword::Other(string) => Err(string.as_ref()),
        }
    }

    pub fn into_id(self) -> Result<u32, Box<str>> {
        match self {
            Keyword::Seen => Ok(SEEN as u32),
            Keyword::Draft => Ok(DRAFT as u32),
            Keyword::Flagged => Ok(FLAGGED as u32),
            Keyword::Answered => Ok(ANSWERED as u32),
            Keyword::Recent => Ok(RECENT as u32),
            Keyword::Important => Ok(IMPORTANT as u32),
            Keyword::Phishing => Ok(PHISHING as u32),
            Keyword::Junk => Ok(JUNK as u32),
            Keyword::NotJunk => Ok(NOTJUNK as u32),
            Keyword::Deleted => Ok(DELETED as u32),
            Keyword::Forwarded => Ok(FORWARDED as u32),
            Keyword::MdnSent => Ok(MDN_SENT as u32),
            Keyword::Autosent => Ok(AUTOSENT as u32),
            Keyword::CanUnsubscribe => Ok(CANUNSUBSCRIBE as u32),
            Keyword::Followed => Ok(FOLLOWED as u32),
            Keyword::HasAttachment => Ok(HASATTACHMENT as u32),
            Keyword::HasMemo => Ok(HASMEMO as u32),
            Keyword::HasNoAttachment => Ok(HASNOATTACHMENT as u32),
            Keyword::Imported => Ok(IMPORTED as u32),
            Keyword::IsTrusted => Ok(ISTRUSTED as u32),
            Keyword::MailFlagBit0 => Ok(MAILFLAGBIT0 as u32),
            Keyword::MailFlagBit1 => Ok(MAILFLAGBIT1 as u32),
            Keyword::MailFlagBit2 => Ok(MAILFLAGBIT2 as u32),
            Keyword::MaskedEmail => Ok(MASKEDEMAIL as u32),
            Keyword::Memo => Ok(MEMO as u32),
            Keyword::Muted => Ok(MUTED as u32),
            Keyword::New => Ok(NEW as u32),
            Keyword::Notify => Ok(NOTIFY as u32),
            Keyword::Unsubscribed => Ok(UNSUBSCRIBED as u32),
            Keyword::Other(string) => Err(string),
        }
    }

    pub fn try_from_id(id: usize) -> Result<Self, usize> {
        match id {
            SEEN => Ok(Keyword::Seen),
            DRAFT => Ok(Keyword::Draft),
            FLAGGED => Ok(Keyword::Flagged),
            ANSWERED => Ok(Keyword::Answered),
            RECENT => Ok(Keyword::Recent),
            IMPORTANT => Ok(Keyword::Important),
            PHISHING => Ok(Keyword::Phishing),
            JUNK => Ok(Keyword::Junk),
            NOTJUNK => Ok(Keyword::NotJunk),
            DELETED => Ok(Keyword::Deleted),
            FORWARDED => Ok(Keyword::Forwarded),
            MDN_SENT => Ok(Keyword::MdnSent),
            AUTOSENT => Ok(Keyword::Autosent),
            CANUNSUBSCRIBE => Ok(Keyword::CanUnsubscribe),
            FOLLOWED => Ok(Keyword::Followed),
            HASATTACHMENT => Ok(Keyword::HasAttachment),
            HASMEMO => Ok(Keyword::HasMemo),
            HASNOATTACHMENT => Ok(Keyword::HasNoAttachment),
            IMPORTED => Ok(Keyword::Imported),
            ISTRUSTED => Ok(Keyword::IsTrusted),
            MAILFLAGBIT0 => Ok(Keyword::MailFlagBit0),
            MAILFLAGBIT1 => Ok(Keyword::MailFlagBit1),
            MAILFLAGBIT2 => Ok(Keyword::MailFlagBit2),
            MASKEDEMAIL => Ok(Keyword::MaskedEmail),
            MEMO => Ok(Keyword::Memo),
            MUTED => Ok(Keyword::Muted),
            NEW => Ok(Keyword::New),
            NOTIFY => Ok(Keyword::Notify),
            UNSUBSCRIBED => Ok(Keyword::Unsubscribed),
            _ => Err(id),
        }
    }
}

impl From<String> for Keyword {
    fn from(value: String) -> Self {
        Keyword::try_parse(&value).unwrap_or_else(|| Keyword::from_other(value))
    }
}

impl Display for Keyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keyword::Seen => write!(f, "$seen"),
            Keyword::Draft => write!(f, "$draft"),
            Keyword::Flagged => write!(f, "$flagged"),
            Keyword::Answered => write!(f, "$answered"),
            Keyword::Recent => write!(f, "$recent"),
            Keyword::Important => write!(f, "$important"),
            Keyword::Phishing => write!(f, "$phishing"),
            Keyword::Junk => write!(f, "$junk"),
            Keyword::NotJunk => write!(f, "$notjunk"),
            Keyword::Deleted => write!(f, "$deleted"),
            Keyword::Forwarded => write!(f, "$forwarded"),
            Keyword::MdnSent => write!(f, "$mdnsent"),
            Keyword::Autosent => write!(f, "$autosent"),
            Keyword::CanUnsubscribe => write!(f, "$canunsubscribe"),
            Keyword::Followed => write!(f, "$followed"),
            Keyword::HasAttachment => write!(f, "$hasattachment"),
            Keyword::HasMemo => write!(f, "$hasmemo"),
            Keyword::HasNoAttachment => write!(f, "$hasnoattachment"),
            Keyword::Imported => write!(f, "$imported"),
            Keyword::IsTrusted => write!(f, "$istrusted"),
            Keyword::MailFlagBit0 => write!(f, "$MailFlagBit0"),
            Keyword::MailFlagBit1 => write!(f, "$MailFlagBit1"),
            Keyword::MailFlagBit2 => write!(f, "$MailFlagBit2"),
            Keyword::MaskedEmail => write!(f, "$maskedemail"),
            Keyword::Memo => write!(f, "$memo"),
            Keyword::Muted => write!(f, "$muted"),
            Keyword::New => write!(f, "$new"),
            Keyword::Notify => write!(f, "$notify"),
            Keyword::Unsubscribed => write!(f, "$unsubscribed"),
            Keyword::Other(s) => write!(f, "{}", s),
        }
    }
}

impl Display for ArchivedKeyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchivedKeyword::Seen => write!(f, "$seen"),
            ArchivedKeyword::Draft => write!(f, "$draft"),
            ArchivedKeyword::Flagged => write!(f, "$flagged"),
            ArchivedKeyword::Answered => write!(f, "$answered"),
            ArchivedKeyword::Recent => write!(f, "$recent"),
            ArchivedKeyword::Important => write!(f, "$important"),
            ArchivedKeyword::Phishing => write!(f, "$phishing"),
            ArchivedKeyword::Junk => write!(f, "$junk"),
            ArchivedKeyword::NotJunk => write!(f, "$notjunk"),
            ArchivedKeyword::Deleted => write!(f, "$deleted"),
            ArchivedKeyword::Forwarded => write!(f, "$forwarded"),
            ArchivedKeyword::MdnSent => write!(f, "$mdnsent"),
            ArchivedKeyword::Autosent => write!(f, "$autosent"),
            ArchivedKeyword::CanUnsubscribe => write!(f, "$canunsubscribe"),
            ArchivedKeyword::Followed => write!(f, "$followed"),
            ArchivedKeyword::HasAttachment => write!(f, "$hasattachment"),
            ArchivedKeyword::HasMemo => write!(f, "$hasmemo"),
            ArchivedKeyword::HasNoAttachment => write!(f, "$hasnoattachment"),
            ArchivedKeyword::Imported => write!(f, "$imported"),
            ArchivedKeyword::IsTrusted => write!(f, "$istrusted"),
            ArchivedKeyword::MailFlagBit0 => write!(f, "$MailFlagBit0"),
            ArchivedKeyword::MailFlagBit1 => write!(f, "$MailFlagBit1"),
            ArchivedKeyword::MailFlagBit2 => write!(f, "$MailFlagBit2"),
            ArchivedKeyword::MaskedEmail => write!(f, "$maskedemail"),
            ArchivedKeyword::Memo => write!(f, "$memo"),
            ArchivedKeyword::Muted => write!(f, "$muted"),
            ArchivedKeyword::New => write!(f, "$new"),
            ArchivedKeyword::Notify => write!(f, "$notify"),
            ArchivedKeyword::Unsubscribed => write!(f, "$unsubscribed"),
            ArchivedKeyword::Other(s) => write!(f, "{}", s),
        }
    }
}

impl From<Keyword> for Vec<u8> {
    fn from(keyword: Keyword) -> Self {
        match keyword {
            Keyword::Seen => vec![SEEN as u8],
            Keyword::Draft => vec![DRAFT as u8],
            Keyword::Flagged => vec![FLAGGED as u8],
            Keyword::Answered => vec![ANSWERED as u8],
            Keyword::Recent => vec![RECENT as u8],
            Keyword::Important => vec![IMPORTANT as u8],
            Keyword::Phishing => vec![PHISHING as u8],
            Keyword::Junk => vec![JUNK as u8],
            Keyword::NotJunk => vec![NOTJUNK as u8],
            Keyword::Deleted => vec![DELETED as u8],
            Keyword::Forwarded => vec![FORWARDED as u8],
            Keyword::MdnSent => vec![MDN_SENT as u8],
            Keyword::Autosent => vec![AUTOSENT as u8],
            Keyword::CanUnsubscribe => vec![CANUNSUBSCRIBE as u8],
            Keyword::Followed => vec![FOLLOWED as u8],
            Keyword::HasAttachment => vec![HASATTACHMENT as u8],
            Keyword::HasMemo => vec![HASMEMO as u8],
            Keyword::HasNoAttachment => vec![HASNOATTACHMENT as u8],
            Keyword::Imported => vec![IMPORTED as u8],
            Keyword::IsTrusted => vec![ISTRUSTED as u8],
            Keyword::MailFlagBit0 => vec![MAILFLAGBIT0 as u8],
            Keyword::MailFlagBit1 => vec![MAILFLAGBIT1 as u8],
            Keyword::MailFlagBit2 => vec![MAILFLAGBIT2 as u8],
            Keyword::MaskedEmail => vec![MASKEDEMAIL as u8],
            Keyword::Memo => vec![MEMO as u8],
            Keyword::Muted => vec![MUTED as u8],
            Keyword::New => vec![NEW as u8],
            Keyword::Notify => vec![NOTIFY as u8],
            Keyword::Unsubscribed => vec![UNSUBSCRIBED as u8],
            Keyword::Other(string) => string.as_bytes().to_vec(),
        }
    }
}

impl FromStr for Keyword {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Keyword::parse(s))
    }
}

impl ArchivedKeyword {
    pub fn id(&self) -> Result<u32, &str> {
        match self {
            ArchivedKeyword::Seen => Ok(SEEN as u32),
            ArchivedKeyword::Draft => Ok(DRAFT as u32),
            ArchivedKeyword::Flagged => Ok(FLAGGED as u32),
            ArchivedKeyword::Answered => Ok(ANSWERED as u32),
            ArchivedKeyword::Recent => Ok(RECENT as u32),
            ArchivedKeyword::Important => Ok(IMPORTANT as u32),
            ArchivedKeyword::Phishing => Ok(PHISHING as u32),
            ArchivedKeyword::Junk => Ok(JUNK as u32),
            ArchivedKeyword::NotJunk => Ok(NOTJUNK as u32),
            ArchivedKeyword::Deleted => Ok(DELETED as u32),
            ArchivedKeyword::Forwarded => Ok(FORWARDED as u32),
            ArchivedKeyword::MdnSent => Ok(MDN_SENT as u32),
            ArchivedKeyword::Autosent => Ok(AUTOSENT as u32),
            ArchivedKeyword::CanUnsubscribe => Ok(CANUNSUBSCRIBE as u32),
            ArchivedKeyword::Followed => Ok(FOLLOWED as u32),
            ArchivedKeyword::HasAttachment => Ok(HASATTACHMENT as u32),
            ArchivedKeyword::HasMemo => Ok(HASMEMO as u32),
            ArchivedKeyword::HasNoAttachment => Ok(HASNOATTACHMENT as u32),
            ArchivedKeyword::Imported => Ok(IMPORTED as u32),
            ArchivedKeyword::IsTrusted => Ok(ISTRUSTED as u32),
            ArchivedKeyword::MailFlagBit0 => Ok(MAILFLAGBIT0 as u32),
            ArchivedKeyword::MailFlagBit1 => Ok(MAILFLAGBIT1 as u32),
            ArchivedKeyword::MailFlagBit2 => Ok(MAILFLAGBIT2 as u32),
            ArchivedKeyword::MaskedEmail => Ok(MASKEDEMAIL as u32),
            ArchivedKeyword::Memo => Ok(MEMO as u32),
            ArchivedKeyword::Muted => Ok(MUTED as u32),
            ArchivedKeyword::New => Ok(NEW as u32),
            ArchivedKeyword::Notify => Ok(NOTIFY as u32),
            ArchivedKeyword::Unsubscribed => Ok(UNSUBSCRIBED as u32),
            ArchivedKeyword::Other(string) => Err(string.as_ref()),
        }
    }

    pub fn to_native(&self) -> Keyword {
        match self {
            ArchivedKeyword::Seen => Keyword::Seen,
            ArchivedKeyword::Draft => Keyword::Draft,
            ArchivedKeyword::Flagged => Keyword::Flagged,
            ArchivedKeyword::Answered => Keyword::Answered,
            ArchivedKeyword::Recent => Keyword::Recent,
            ArchivedKeyword::Important => Keyword::Important,
            ArchivedKeyword::Phishing => Keyword::Phishing,
            ArchivedKeyword::Junk => Keyword::Junk,
            ArchivedKeyword::NotJunk => Keyword::NotJunk,
            ArchivedKeyword::Deleted => Keyword::Deleted,
            ArchivedKeyword::Forwarded => Keyword::Forwarded,
            ArchivedKeyword::MdnSent => Keyword::MdnSent,
            ArchivedKeyword::Autosent => Keyword::Autosent,
            ArchivedKeyword::CanUnsubscribe => Keyword::CanUnsubscribe,
            ArchivedKeyword::Followed => Keyword::Followed,
            ArchivedKeyword::HasAttachment => Keyword::HasAttachment,
            ArchivedKeyword::HasMemo => Keyword::HasMemo,
            ArchivedKeyword::HasNoAttachment => Keyword::HasNoAttachment,
            ArchivedKeyword::Imported => Keyword::Imported,
            ArchivedKeyword::IsTrusted => Keyword::IsTrusted,
            ArchivedKeyword::MailFlagBit0 => Keyword::MailFlagBit0,
            ArchivedKeyword::MailFlagBit1 => Keyword::MailFlagBit1,
            ArchivedKeyword::MailFlagBit2 => Keyword::MailFlagBit2,
            ArchivedKeyword::MaskedEmail => Keyword::MaskedEmail,
            ArchivedKeyword::Memo => Keyword::Memo,
            ArchivedKeyword::Muted => Keyword::Muted,
            ArchivedKeyword::New => Keyword::New,
            ArchivedKeyword::Notify => Keyword::Notify,
            ArchivedKeyword::Unsubscribed => Keyword::Unsubscribed,
            ArchivedKeyword::Other(other) => Keyword::Other(other.as_ref().into()),
        }
    }
}

impl From<&ArchivedKeyword> for Keyword {
    fn from(value: &ArchivedKeyword) -> Self {
        match value {
            ArchivedKeyword::Seen => Keyword::Seen,
            ArchivedKeyword::Draft => Keyword::Draft,
            ArchivedKeyword::Flagged => Keyword::Flagged,
            ArchivedKeyword::Answered => Keyword::Answered,
            ArchivedKeyword::Recent => Keyword::Recent,
            ArchivedKeyword::Important => Keyword::Important,
            ArchivedKeyword::Phishing => Keyword::Phishing,
            ArchivedKeyword::Junk => Keyword::Junk,
            ArchivedKeyword::NotJunk => Keyword::NotJunk,
            ArchivedKeyword::Deleted => Keyword::Deleted,
            ArchivedKeyword::Forwarded => Keyword::Forwarded,
            ArchivedKeyword::MdnSent => Keyword::MdnSent,
            ArchivedKeyword::Autosent => Keyword::Autosent,
            ArchivedKeyword::CanUnsubscribe => Keyword::CanUnsubscribe,
            ArchivedKeyword::Followed => Keyword::Followed,
            ArchivedKeyword::HasAttachment => Keyword::HasAttachment,
            ArchivedKeyword::HasMemo => Keyword::HasMemo,
            ArchivedKeyword::HasNoAttachment => Keyword::HasNoAttachment,
            ArchivedKeyword::Imported => Keyword::Imported,
            ArchivedKeyword::IsTrusted => Keyword::IsTrusted,
            ArchivedKeyword::MailFlagBit0 => Keyword::MailFlagBit0,
            ArchivedKeyword::MailFlagBit1 => Keyword::MailFlagBit1,
            ArchivedKeyword::MailFlagBit2 => Keyword::MailFlagBit2,
            ArchivedKeyword::MaskedEmail => Keyword::MaskedEmail,
            ArchivedKeyword::Memo => Keyword::Memo,
            ArchivedKeyword::Muted => Keyword::Muted,
            ArchivedKeyword::New => Keyword::New,
            ArchivedKeyword::Notify => Keyword::Notify,
            ArchivedKeyword::Unsubscribed => Keyword::Unsubscribed,
            ArchivedKeyword::Other(string) => Keyword::Other(string.as_ref().into()),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Keyword {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Keyword::parse(<&str>::deserialize(deserializer)?))
    }
}

impl<'x, P: Property, E: Element + From<Keyword>> From<Keyword> for Value<'x, P, E> {
    fn from(id: Keyword) -> Self {
        Value::Element(E::from(id))
    }
}
