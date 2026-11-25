/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::eas::http::Command;
use crate::eas::status::{
    CommonStatus, FindStatus, FolderStatus, ItemOperationsStatus, MeetingResponseStatus,
    PingStatus, ProvisionStatus, ResolveRecipientsStatus, SearchStatus, SettingsStatus, Status,
    SyncStatus, ValidateCertStatus,
};
use crate::eas::tokens::Tag;
use crate::eas::tokens::tag::airsyncbase as asb;
use crate::eas::types::{BodyPreference, BodyType, EasDateTime, SplitOnceByte};
use crate::eas::wbxml::decoder::parse_u32;
use crate::eas::wbxml::encoder::format_u64;
use crate::eas::wbxml::{DecodeError, Decoder, Encoder, Event};

pub mod appdata;
pub mod find;
pub mod folder;
pub mod get_item_estimate;
pub mod item_operations;
pub mod meeting_response;
pub mod move_items;
pub mod ping;
pub mod provision;
pub mod resolve_recipients;
pub mod search;
pub mod send_mail;
pub mod settings;
pub mod sync;
pub mod validate_cert;

pub const MAX_SYNC_COMMANDS: u32 = 200;
pub const MAX_GET_ITEM_ESTIMATE_COLLECTIONS: u32 = 1000;
pub const MAX_ITEM_OPERATIONS: u32 = 100;
pub const MAX_MEETING_RESPONSES: u32 = 100;
pub const MAX_MOVE_ITEMS: u32 = 1000;
pub const MAX_RESOLVE_RECIPIENTS: u32 = 100;
pub const MAX_VALIDATE_CERTIFICATES: u32 = 100;
pub const MAX_ID_LEN: usize = 64;
pub const MAX_LONG_ID_LEN: usize = 256;
pub const MAX_LIST_LEN: u32 = 1000;
pub const MAX_PING_FOLDERS: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    Decode(DecodeError),
    UnexpectedRoot { tag: Option<Tag> },
    Missing { tag: Tag },
    InvalidValue { tag: Tag },
    InvalidDate { tag: Tag },
    TooManyCommands,
    TooMany { tag: Tag, limit: u32 },
    NotSupported { tag: Tag },
}

const _: () = assert!(size_of::<CommandError>() <= 32);

impl From<DecodeError> for CommandError {
    fn from(err: DecodeError) -> Self {
        CommandError::Decode(err)
    }
}

impl CommandError {
    pub fn status(&self, command: Command) -> Status {
        match self {
            CommandError::Decode(_) => CommonStatus::INVALID_WBXML.into(),
            CommandError::InvalidDate { .. } if command != Command::ResolveRecipients => {
                CommonStatus::INVALID_DATE_TIME.into()
            }
            CommandError::TooManyCommands | CommandError::TooMany { .. } => limit_status(command),
            CommandError::InvalidValue { .. } if command == Command::MeetingResponse => {
                MeetingResponseStatus::INVALID_REQUEST.into()
            }
            _ => grammar_status(command),
        }
    }

    #[cold]
    fn value(err: DecodeError, tag: Tag) -> Self {
        match err {
            DecodeError::InvalidValue { .. }
            | DecodeError::Utf8 { .. }
            | DecodeError::UnexpectedEvent { .. } => CommandError::InvalidValue { tag },
            err => CommandError::Decode(err),
        }
    }
}

fn limit_status(command: Command) -> Status {
    match command {
        Command::Sync => SyncStatus::PROTOCOL_ERROR.into(),
        Command::Ping => PingStatus::TOO_MANY_FOLDERS.into(),
        Command::ItemOperations => ItemOperationsStatus::TOO_LARGE.into(),
        Command::ResolveRecipients => ResolveRecipientsStatus::PROTOCOL_ERROR.into(),
        Command::ValidateCert => ValidateCertStatus::PROTOCOL_ERROR.into(),
        _ => grammar_status(command),
    }
}

fn grammar_status(command: Command) -> Status {
    match command {
        Command::Sync => SyncStatus::PROTOCOL_ERROR.into(),
        Command::FolderSync
        | Command::FolderCreate
        | Command::FolderDelete
        | Command::FolderUpdate => FolderStatus::MALFORMED_REQUEST.into(),
        Command::Ping => PingStatus::SYNTAX_ERROR.into(),
        Command::Provision => ProvisionStatus::PROTOCOL_ERROR.into(),
        Command::ItemOperations => ItemOperationsStatus::PROTOCOL_ERROR.into(),
        Command::Settings => SettingsStatus::PROTOCOL_ERROR.into(),
        Command::Search => SearchStatus::INVALID_REQUEST.into(),
        Command::Find => FindStatus::INVALID_REQUEST.into(),
        Command::ResolveRecipients => ResolveRecipientsStatus::PROTOCOL_ERROR.into(),
        Command::ValidateCert => ValidateCertStatus::PROTOCOL_ERROR.into(),
        _ => CommonStatus::INVALID_XML.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SyncKeyStr<'a>(pub Cow<'a, str>);

impl SyncKeyStr<'_> {
    pub const INITIAL: &'static str = "0";

    pub fn is_initial(&self) -> bool {
        self.0 == Self::INITIAL
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ItemRange {
    pub start: u32,
    pub end: u32,
}

impl ItemRange {
    pub fn parse(text: &[u8]) -> Option<Self> {
        let (start, end) = text.trim_ascii().split_once_byte(b'-')?;
        let start = parse_u32(start)?;
        let end = parse_u32(end)?;
        (start <= end).then_some(ItemRange { start, end })
    }

    pub fn encode(&self, enc: &mut Encoder, tag: Tag) {
        let mut digits = [0u8; 10];
        enc.text_with(tag, |out| {
            let len = format_u64(u64::from(self.start), &mut digits);
            out.extend_from_slice(digits.get(..len).unwrap_or_default());
            out.push(b'-');
            let len = format_u64(u64::from(self.end), &mut digits);
            out.extend_from_slice(digits.get(..len).unwrap_or_default());
        });
    }
}

pub(crate) fn read_range(dec: &mut Decoder<'_>, tag: Tag) -> Result<ItemRange, CommandError> {
    let text = dec.text().map_err(|err| CommandError::value(err, tag))?;
    ItemRange::parse(&text).ok_or(CommandError::InvalidValue { tag })
}

pub(crate) struct Children {
    depth: u8,
}

impl Children {
    pub(crate) fn root(dec: &mut Decoder<'_>, expected: Tag) -> Result<Self, CommandError> {
        match dec.next()? {
            Event::Start { tag, .. } if tag == expected => Ok(Children { depth: dec.depth() }),
            Event::Start { tag, .. } => Err(CommandError::UnexpectedRoot { tag: Some(tag) }),
            _ => Err(CommandError::UnexpectedRoot { tag: None }),
        }
    }

    pub(crate) fn of(dec: &Decoder<'_>) -> Self {
        Children { depth: dec.depth() }
    }

    pub(crate) fn next(&mut self, dec: &mut Decoder<'_>) -> Result<Option<Tag>, DecodeError> {
        while dec.depth() > self.depth {
            dec.skip_element()?;
        }
        loop {
            if dec.depth() < self.depth {
                return Ok(None);
            }
            let offset = dec.offset();
            match dec.next()? {
                Event::Start { tag, .. } => return Ok(Some(tag)),
                Event::End => return Ok(None),
                Event::Text(text) if text.trim_ascii().is_empty() => {}
                Event::Opaque([]) => {}
                Event::Text(_) | Event::Opaque(_) => {
                    return Err(DecodeError::UnexpectedEvent { offset });
                }
                Event::Eof if self.depth == 0 => return Ok(None),
                Event::Eof => return Err(DecodeError::Truncated { offset }),
            }
        }
    }
}

pub(crate) fn read_str<'a>(dec: &mut Decoder<'a>, tag: Tag) -> Result<Cow<'a, str>, CommandError> {
    dec.str().map_err(|err| CommandError::value(err, tag))
}

pub(crate) fn read_id<'a>(
    dec: &mut Decoder<'a>,
    tag: Tag,
    max: usize,
) -> Result<Cow<'a, str>, CommandError> {
    read_str(dec, tag).and_then(|value| bounded(value, tag, max))
}

pub(crate) fn bounded<T: AsRef<str>>(value: T, tag: Tag, max: usize) -> Result<T, CommandError> {
    if value.as_ref().len() <= max {
        Ok(value)
    } else {
        Err(CommandError::InvalidValue { tag })
    }
}

pub(crate) fn read_u32(dec: &mut Decoder<'_>, tag: Tag) -> Result<u32, CommandError> {
    dec.u32().map_err(|err| CommandError::value(err, tag))
}

pub(crate) fn read_u8(dec: &mut Decoder<'_>, tag: Tag) -> Result<u8, CommandError> {
    dec.u8().map_err(|err| CommandError::value(err, tag))
}

pub(crate) fn read_bool(dec: &mut Decoder<'_>, tag: Tag) -> Result<bool, CommandError> {
    dec.bool().map_err(|err| CommandError::value(err, tag))
}

pub(crate) fn read_bytes<'a>(
    dec: &mut Decoder<'a>,
    tag: Tag,
) -> Result<Cow<'a, [u8]>, CommandError> {
    dec.bytes().map_err(|err| CommandError::value(err, tag))
}

pub(crate) fn read_date(dec: &mut Decoder<'_>, tag: Tag) -> Result<EasDateTime, CommandError> {
    let text = dec.text().map_err(|err| CommandError::value(err, tag))?;
    EasDateTime::parse(&text).ok_or(CommandError::InvalidDate { tag })
}

pub(crate) fn read_body_preference(dec: &mut Decoder<'_>) -> Result<BodyPreference, CommandError> {
    let mut body_type = None;
    let mut truncation_size = None;
    let mut all_or_none = false;
    let mut preview = None;
    let mut position = 0u8;
    let mut children = Children::of(dec);
    while let Some(tag) = children.next(dec)? {
        let next = match tag {
            asb::TYPE => 1,
            asb::TRUNCATION_SIZE => 2,
            asb::ALL_OR_NONE => 3,
            asb::PREVIEW => 4,
            _ => 0,
        };
        if next <= position {
            return Err(CommandError::NotSupported { tag });
        }
        position = next;
        match tag {
            asb::TYPE => {
                body_type = Some(
                    BodyType::from_code(read_u32(dec, tag)?)
                        .ok_or(CommandError::InvalidValue { tag })?,
                )
            }
            asb::TRUNCATION_SIZE => truncation_size = Some(read_u32(dec, tag)?),
            asb::ALL_OR_NONE => all_or_none = read_bool(dec, tag)?,
            _ => preview = Some(read_u8(dec, tag)?),
        }
    }
    Ok(BodyPreference {
        body_type: required(body_type, asb::TYPE)?,
        truncation_size,
        all_or_none,
        preview,
    })
}

pub(crate) fn required<T>(value: Option<T>, tag: Tag) -> Result<T, CommandError> {
    value.ok_or(CommandError::Missing { tag })
}

pub(crate) struct Counter {
    count: u32,
    limit: u32,
}

impl Counter {
    pub(crate) const fn new(limit: u32) -> Self {
        Counter { count: 0, limit }
    }

    pub(crate) fn bump(&mut self, tag: Tag) -> Result<(), CommandError> {
        if self.count < self.limit {
            self.count = self.count.wrapping_add(1);
            Ok(())
        } else {
            Err(CommandError::TooMany {
                tag,
                limit: self.limit,
            })
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/eas/commands/tests.rs"]
mod tests;
