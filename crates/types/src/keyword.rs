/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{fmt::Display, str::FromStr};

use jmap_tools::{Element, Property, Value};

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
pub const OTHER: usize = 12;

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
    Other(String),
}

impl Keyword {
    pub const MAX_LENGTH: usize = 128;

    pub fn parse(value: &str) -> Self {
        Self::try_parse(value)
            .unwrap_or_else(|| Keyword::Other(value.chars().take(Keyword::MAX_LENGTH).collect()))
    }

    pub fn from_other(value: String) -> Self {
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
                    "mdnsent" => Keyword::MdnSent
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
            Keyword::Other(string) => Err(string.as_str()),
        }
    }

    pub fn into_id(self) -> Result<u32, String> {
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
            ArchivedKeyword::Other(string) => Err(string.as_str()),
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
            ArchivedKeyword::Other(string) => Keyword::Other(string.as_str().into()),
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
