/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use smallvec::SmallVec;

use crate::common::reader::LeReader;
use crate::eas::commands::{
    Children, CommandError, read_body_preference, read_bool, read_str, read_u8, read_u32,
};
use crate::eas::tokens::Tag;
use crate::eas::tokens::tag::{airsync as sync, airsyncbase as asb, rights_management as rm};
use crate::eas::types::{BodyPreference, BodyType, Class};
use crate::eas::wbxml::Decoder;

pub const MAX_BODY_PREFERENCES: u8 = 8;
pub const MAX_FILTER_TYPE: u8 = 8;
pub const FILTER_INCOMPLETE_TASKS: u8 = 8;

const MAIL_FILTERS: u16 = 0b0_0011_1111;
const CALENDAR_FILTERS: u16 = 0b0_1111_0001;
const TASK_FILTERS: u16 = 0b1_0000_0001;
const ANY_FILTER: u16 = 0b1_1111_1111;
const STATE_VERSION: u8 = 1;
const HAS_FILTER: u8 = 0x01;
const HAS_CONFLICT: u8 = 0x02;
const HAS_MIME_SUPPORT: u8 = 0x04;
const HAS_MIME_TRUNCATION: u8 = 0x08;
const HAS_MAX_ITEMS: u8 = 0x10;
const HAS_RIGHTS_MANAGEMENT: u8 = 0x20;
const RIGHTS_MANAGEMENT_ON: u8 = 0x40;
const PREF_TRUNCATION: u8 = 0x01;
const PREF_ALL_OR_NONE: u8 = 0x02;
const PREF_PREVIEW: u8 = 0x04;
const CLASS_CODES: [Option<Class>; 7] = [
    None,
    Some(Class::Email),
    Some(Class::Calendar),
    Some(Class::Contacts),
    Some(Class::Tasks),
    Some(Class::Notes),
    Some(Class::Sms),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterFit {
    Fits,
    OutOfClass,
    Invalid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncOptions {
    pub class: Option<Class>,
    pub filter_type: Option<u8>,
    pub body_preferences: SmallVec<[BodyPreference; 2]>,
    pub body_part_preferences: SmallVec<[BodyPreference; 1]>,
    pub conflict: Option<u8>,
    pub mime_support: Option<u8>,
    pub mime_truncation: Option<u8>,
    pub max_items: Option<u32>,
    pub rights_management_support: Option<bool>,
}

impl SyncOptions {
    pub(crate) fn parse(dec: &mut Decoder<'_>) -> Result<Self, CommandError> {
        let mut options = SyncOptions::default();
        let mut children = Children::of(dec);
        while let Some(tag) = children.next(dec)? {
            match tag {
                sync::CLASS => {
                    let class = read_str(dec, tag)?;
                    options.class = Some(
                        Class::parse(class.as_bytes()).ok_or(CommandError::InvalidValue { tag })?,
                    );
                }
                sync::FILTER_TYPE => options.filter_type = Some(read_u8(dec, tag)?),
                sync::CONFLICT => options.conflict = Some(read_u8(dec, tag)?),
                sync::MIME_SUPPORT => options.mime_support = Some(read_u8(dec, tag)?),
                sync::MIME_TRUNCATION => options.mime_truncation = Some(read_u8(dec, tag)?),
                sync::MAX_ITEMS => options.max_items = Some(read_u32(dec, tag)?),
                asb::BODY_PREFERENCE => push_preference(&mut options.body_preferences, dec, tag)?,
                asb::BODY_PART_PREFERENCE => {
                    push_preference(&mut options.body_part_preferences, dec, tag)?
                }
                rm::RIGHTS_MANAGEMENT_SUPPORT => {
                    options.rights_management_support = Some(read_bool(dec, tag)?)
                }
                _ => {}
            }
        }
        Ok(options)
    }

    pub fn filter_fit(&self, class: Class) -> FilterFit {
        let allowed = match class {
            Class::Email | Class::Sms => MAIL_FILTERS,
            Class::Calendar => CALENDAR_FILTERS,
            Class::Tasks => TASK_FILTERS,
            Class::Contacts | Class::Notes => ANY_FILTER,
        };
        match self.filter_type {
            None => FilterFit::Fits,
            Some(filter) if filter > MAX_FILTER_TYPE => FilterFit::Invalid,
            Some(filter) if (allowed >> filter) & 1 == 1 => FilterFit::Fits,
            Some(_) => FilterFit::OutOfClass,
        }
    }

    pub fn has_bad_filter(&self) -> bool {
        match self.class {
            Some(class @ (Class::Email | Class::Sms)) => self.filter_fit(class) != FilterFit::Fits,
            _ => self
                .filter_type
                .is_some_and(|filter| filter > MAX_FILTER_TYPE),
        }
    }

    pub fn has_unsupported_body_part(&self) -> bool {
        self.body_part_preferences
            .iter()
            .any(|preference| matches!(preference.body_type, BodyType::Rtf | BodyType::Mime))
    }

    pub fn encode_state(&self, out: &mut Vec<u8>) {
        let mut flags = 0u8;
        let mut scalars = SmallVec::<[u8; 4]>::new();
        for (value, flag) in [
            (self.filter_type, HAS_FILTER),
            (self.conflict, HAS_CONFLICT),
            (self.mime_support, HAS_MIME_SUPPORT),
            (self.mime_truncation, HAS_MIME_TRUNCATION),
        ] {
            if let Some(value) = value {
                flags |= flag;
                scalars.push(value);
            }
        }
        if self.max_items.is_some() {
            flags |= HAS_MAX_ITEMS;
        }
        match self.rights_management_support {
            Some(true) => flags |= HAS_RIGHTS_MANAGEMENT | RIGHTS_MANAGEMENT_ON,
            Some(false) => flags |= HAS_RIGHTS_MANAGEMENT,
            None => {}
        }
        let class = CLASS_CODES
            .iter()
            .position(|code| *code == self.class)
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or_default();
        out.extend_from_slice(&[STATE_VERSION, class, flags]);
        out.extend_from_slice(&scalars);
        if let Some(max_items) = self.max_items {
            out.extend_from_slice(&max_items.to_le_bytes());
        }
        encode_preferences(&self.body_preferences, out);
        encode_preferences(&self.body_part_preferences, out);
    }

    pub fn decode_state(state: &[u8]) -> Option<Self> {
        let mut reader = LeReader::new(state);
        if reader.u8().ok()? != STATE_VERSION {
            return None;
        }
        let class = *CLASS_CODES.get(usize::from(reader.u8().ok()?))?;
        let flags = reader.u8().ok()?;
        let mut scalar = |flag: u8| -> Option<Option<u8>> {
            if flags & flag != 0 {
                reader.u8().ok().map(Some)
            } else {
                Some(None)
            }
        };
        let filter_type = scalar(HAS_FILTER)?;
        let conflict = scalar(HAS_CONFLICT)?;
        let mime_support = scalar(HAS_MIME_SUPPORT)?;
        let mime_truncation = scalar(HAS_MIME_TRUNCATION)?;
        let max_items = if flags & HAS_MAX_ITEMS != 0 {
            Some(reader.u32().ok()?)
        } else {
            None
        };
        let rights_management_support =
            (flags & HAS_RIGHTS_MANAGEMENT != 0).then_some(flags & RIGHTS_MANAGEMENT_ON != 0);
        let body_preferences = decode_preferences(&mut reader)?;
        let body_part_preferences = decode_preferences(&mut reader)?;
        reader.is_empty().then_some(SyncOptions {
            class,
            filter_type,
            body_preferences,
            body_part_preferences,
            conflict,
            mime_support,
            mime_truncation,
            max_items,
            rights_management_support,
        })
    }
}

fn push_preference<const N: usize>(
    list: &mut SmallVec<[BodyPreference; N]>,
    dec: &mut Decoder<'_>,
    tag: Tag,
) -> Result<(), CommandError>
where
    [BodyPreference; N]: smallvec::Array<Item = BodyPreference>,
{
    let preference = read_body_preference(dec)?;
    if list
        .iter()
        .any(|existing| existing.body_type == preference.body_type)
    {
        return Err(CommandError::NotSupported { tag });
    }
    if list.len() >= usize::from(MAX_BODY_PREFERENCES) {
        return Err(CommandError::TooMany {
            tag,
            limit: u32::from(MAX_BODY_PREFERENCES),
        });
    }
    list.push(preference);
    Ok(())
}

fn encode_preferences(list: &[BodyPreference], out: &mut Vec<u8>) {
    let count = u8::try_from(list.len())
        .unwrap_or(u8::MAX)
        .min(MAX_BODY_PREFERENCES);
    out.push(count);
    for preference in list.iter().take(usize::from(count)) {
        let mut flags = 0u8;
        if preference.truncation_size.is_some() {
            flags |= PREF_TRUNCATION;
        }
        if preference.all_or_none {
            flags |= PREF_ALL_OR_NONE;
        }
        if preference.preview.is_some() {
            flags |= PREF_PREVIEW;
        }
        out.extend_from_slice(&[preference.body_type.code(), flags]);
        if let Some(truncation_size) = preference.truncation_size {
            out.extend_from_slice(&truncation_size.to_le_bytes());
        }
        if let Some(preview) = preference.preview {
            out.push(preview);
        }
    }
}

fn decode_preferences<const N: usize>(
    reader: &mut LeReader<'_>,
) -> Option<SmallVec<[BodyPreference; N]>>
where
    [BodyPreference; N]: smallvec::Array<Item = BodyPreference>,
{
    let count = reader.u8().ok()?;
    if count > MAX_BODY_PREFERENCES {
        return None;
    }
    let mut list = SmallVec::new();
    for _ in 0..count {
        let body_type = BodyType::from_code(u32::from(reader.u8().ok()?))?;
        let flags = reader.u8().ok()?;
        let truncation_size = if flags & PREF_TRUNCATION != 0 {
            Some(reader.u32().ok()?)
        } else {
            None
        };
        let preview = if flags & PREF_PREVIEW != 0 {
            Some(reader.u8().ok()?)
        } else {
            None
        };
        list.push(BodyPreference {
            body_type,
            truncation_size,
            all_or_none: flags & PREF_ALL_OR_NONE != 0,
            preview,
        });
    }
    Some(list)
}

pub fn encode_tag_state(tags: &[Tag], out: &mut Vec<u8>) {
    let count = u16::try_from(tags.len()).unwrap_or(u16::MAX);
    out.push(STATE_VERSION);
    out.extend_from_slice(&count.to_le_bytes());
    for tag in tags.iter().take(usize::from(count)) {
        out.extend_from_slice(&tag.raw().to_le_bytes());
    }
}

pub fn decode_tag_state(state: &[u8]) -> Option<SmallVec<[Tag; 16]>> {
    let mut reader = LeReader::new(state);
    if reader.u8().ok()? != STATE_VERSION {
        return None;
    }
    let count = usize::from(reader.u16().ok()?);
    if reader.remaining().len() != count.checked_mul(2)? {
        return None;
    }
    let mut tags = SmallVec::with_capacity(count);
    for _ in 0..count {
        let [token, page] = reader.u16().ok()?.to_le_bytes();
        let tag = Tag::new(page, token);
        if tag.token() != token {
            return None;
        }
        tags.push(tag);
    }
    Some(tags)
}
