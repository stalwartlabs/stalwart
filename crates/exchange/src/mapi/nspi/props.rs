/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    book::{AbEntry, AbResource, ResourceDetail},
    page::AbKind,
};
use exchange_proto::{
    ids::entryid::provider,
    mapi::{
        ErrorCode,
        nspi::{
            AbkCell, AbkListWriter,
            tags::{
                AB_RECIPIENTS, ACCOUNT, CONTAINER_CONTENTS, CONTAINER_FLAGS, CONTAINER_ID,
                DISPLAY_NAME_PRINTABLE, DISPLAY_TYPE_EX, DT_DISTLIST, DT_EQUIPMENT, DT_MAILUSER,
                DT_ROOM, DTE_FLAG_ACL_CAPABLE, INITIAL_DETAILS_PANE, MAPPING_SIGNATURE,
                OBJECT_DISTINGUISHED_NAME, OFFICE_LOCATION, PROXY_ADDRESSES, ROOM_CAPACITY,
                SEND_INTERNET_ENCODING, SEND_RICH_INFO, TEMPLATE_ID,
            },
        },
        prop::{CodePage, PropTag, PropType, PropValue, tags},
    },
    oab::OabValue,
};
use registry::schema::enums::ResourceKind;

pub const DEFAULT_COLUMNS: [PropTag; 7] = [
    CONTAINER_ID,
    tags::OBJECT_TYPE,
    tags::DISPLAY_TYPE,
    PropTag(0x3001_001E),
    PropTag(0x3A1A_001E),
    PropTag(0x3A18_001E),
    PropTag(0x3A19_001E),
];

const USER_PROPS: &[PropTag] = &[
    tags::ENTRY_ID,
    tags::RECORD_KEY,
    tags::SEARCH_KEY,
    tags::INSTANCE_KEY,
    MAPPING_SIGNATURE,
    TEMPLATE_ID,
    tags::OBJECT_TYPE,
    tags::DISPLAY_TYPE,
    DISPLAY_TYPE_EX,
    INITIAL_DETAILS_PANE,
    CONTAINER_ID,
    tags::DISPLAY_NAME,
    tags::TRANSMITTABLE_DISPLAY_NAME,
    DISPLAY_NAME_PRINTABLE,
    tags::ADDRESS_TYPE,
    tags::EMAIL_ADDRESS,
    tags::SMTP_ADDRESS,
    ACCOUNT,
    OBJECT_DISTINGUISHED_NAME,
    PROXY_ADDRESSES,
    SEND_RICH_INFO,
    SEND_INTERNET_ENCODING,
];

const LIST_PROPS: &[PropTag] = &[CONTAINER_FLAGS, CONTAINER_CONTENTS];

const RESOURCE_PROPS: &[PropTag] = &[ROOM_CAPACITY, OFFICE_LOCATION];

const NOT_FOUND: AbkCell<'static> = AbkCell::Error(ErrorCode::NOT_FOUND);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryIdForm {
    Permanent,
    Ephemeral,
}

#[derive(Debug, Clone, Copy)]
pub enum AbValue<'e> {
    Bool(bool),
    I32(i32),
    Binary(&'e [u8]),
    Text(&'e str),
    Texts(&'e [Box<str>]),
    EmbeddedTable,
}

impl<'e> AbValue<'e> {
    pub fn of(entry: &'e AbEntry, tag: PropTag, form: EntryIdForm) -> Option<Self> {
        let value = match tag.id().0 {
            0x0FFF => AbValue::Binary(match form {
                EntryIdForm::Permanent => &entry.permanent_id,
                EntryIdForm::Ephemeral => &entry.ephemeral_id,
            }),
            0x0FF9 | 0x3902 => AbValue::Binary(&entry.permanent_id),
            0x300B => AbValue::Binary(&entry.search_key),
            0x0FF6 => AbValue::Binary(&entry.instance_key),
            0x0FF8 => AbValue::Binary(provider::ADDRESS_BOOK.as_bytes()),
            0x0FFE => AbValue::I32(i32_of(entry.kind.object_type())),
            0x3900 => AbValue::I32(i32_of(entry.kind.display_type())),
            0x3905 => AbValue::I32(i32_of(match (entry.kind, &entry.resource) {
                (AbKind::User, None) => DTE_FLAG_ACL_CAPABLE | DT_MAILUSER,
                (AbKind::User, Some(resource)) => resource.display_type(),
                (AbKind::List, _) => DT_DISTLIST,
            })),
            0x0807 => AbValue::I32(entry.resource.as_ref()?.details()?.capacity?),
            0x3A19 => AbValue::Text(entry.resource.as_ref()?.details()?.location.as_deref()?),
            0x3600 if entry.kind == AbKind::List => AbValue::I32(i32_of(AB_RECIPIENTS)),
            0x360F if entry.kind == AbKind::List => AbValue::EmbeddedTable,
            0x3F08 | 0x3A71 => AbValue::I32(0),
            0x3A40 => AbValue::Bool(true),
            0xFFFD => AbValue::I32(i32_of(entry.mid.0)),
            0x3001 | 0x3A20 => AbValue::Text(&entry.display_name),
            0x39FF => AbValue::Text(if entry.display_name.is_ascii() {
                &entry.display_name
            } else {
                &entry.account
            }),
            0x3002 => AbValue::Text("EX"),
            0x3003 | 0x803C => AbValue::Text(&entry.dn),
            0x39FE => AbValue::Text(&entry.smtp),
            0x3A00 => AbValue::Text(&entry.account),
            0x800F => AbValue::Texts(&entry.proxies),
            _ => return None,
        };
        value.fits(tag.ptype()).then_some(value)
    }

    fn fits(&self, requested: PropType) -> bool {
        matches!(
            (self, requested),
            (_, PropType::Unspecified)
                | (AbValue::Bool(_), PropType::Bool)
                | (AbValue::I32(_), PropType::I32)
                | (AbValue::Binary(_), PropType::Binary)
                | (AbValue::Text(_), PropType::String8 | PropType::Unicode)
                | (AbValue::Texts(_), PropType::MvString8 | PropType::MvUnicode)
                | (AbValue::EmbeddedTable, PropType::Object)
        )
    }

    pub fn oab(self) -> Option<OabValue<'e>> {
        Some(match self {
            AbValue::Bool(value) => OabValue::Bool(value),
            AbValue::I32(value) => OabValue::Int(value.cast_unsigned()),
            AbValue::Binary(value) => OabValue::Binary(value),
            AbValue::Text(value) => OabValue::Text(value),
            AbValue::Texts(value) => OabValue::Texts(value),
            AbValue::EmbeddedTable => return None,
        })
    }

    pub fn cell(self) -> AbkCell<'e> {
        match self {
            AbValue::Bool(value) => AbkCell::Value(PropValue::Bool(value)),
            AbValue::I32(value) => AbkCell::Value(PropValue::I32(value)),
            AbValue::Binary(value) => AbkCell::Value(PropValue::Binary(value)),
            AbValue::Text(value) => AbkCell::Text(value),
            AbValue::Texts(value) => AbkCell::Texts(value),
            AbValue::EmbeddedTable => AbkCell::Value(PropValue::Object),
        }
    }

    pub fn write(self, list: &mut AbkListWriter<'_>, tag: PropTag, code_page: CodePage) {
        match self {
            AbValue::Bool(value) => {
                list.value(tag.with_type(PropType::Bool), &PropValue::Bool(value));
            }
            AbValue::I32(value) => {
                list.value(tag.with_type(PropType::I32), &PropValue::I32(value));
            }
            AbValue::Binary(value) => {
                list.value(tag.with_type(PropType::Binary), &PropValue::Binary(value));
            }
            AbValue::Text(value) => list.text(tag, value, code_page),
            AbValue::Texts(value) => list.texts(tag, value, code_page),
            AbValue::EmbeddedTable => {
                list.value(tag.with_type(PropType::Object), &PropValue::Object);
            }
        }
    }
}

fn i32_of(value: u32) -> i32 {
    i32::from_le_bytes(value.to_le_bytes())
}

pub fn cell<'e>(entry: Option<&'e AbEntry>, tag: PropTag, form: EntryIdForm) -> AbkCell<'e> {
    entry
        .and_then(|entry| AbValue::of(entry, tag, form))
        .map_or(NOT_FOUND, AbValue::cell)
}

pub fn write_missing(list: &mut AbkListWriter<'_>, tag: PropTag) {
    list.value(
        tag.with_type(PropType::Error),
        &PropValue::Error(ErrorCode::NOT_FOUND),
    );
}

pub fn has_property(tag: PropTag) -> bool {
    USER_PROPS.iter().any(|served| served.id() == tag.id())
}

pub fn resource_detail(columns: Option<&[PropTag]>) -> ResourceDetail {
    match columns {
        Some(columns)
            if !columns.iter().any(|tag| {
                RESOURCE_PROPS
                    .iter()
                    .any(|resource| resource.id() == tag.id())
            }) =>
        {
            ResourceDetail::Kind
        }
        _ => ResourceDetail::Full,
    }
}

pub fn all_tags() -> impl Iterator<Item = PropTag> {
    USER_PROPS.iter().chain(RESOURCE_PROPS).copied()
}

pub fn entry_tags(entry: &AbEntry) -> impl Iterator<Item = PropTag> {
    let extra = match entry.kind {
        AbKind::User => &[][..],
        AbKind::List => LIST_PROPS,
    };
    let resource = entry
        .resource
        .as_ref()
        .and_then(AbResource::details)
        .into_iter()
        .flat_map(|details| {
            [
                details.capacity.map(|_| ROOM_CAPACITY),
                details.location.as_ref().map(|_| OFFICE_LOCATION),
            ]
            .into_iter()
            .flatten()
        });
    USER_PROPS.iter().chain(extra).copied().chain(resource)
}

impl AbResource {
    fn display_type(&self) -> u32 {
        match self.kind {
            ResourceKind::Room => DT_ROOM,
            ResourceKind::Equipment => DT_EQUIPMENT,
        }
    }
}

pub fn as_string8(tag: PropTag) -> PropTag {
    match tag.ptype() {
        PropType::Unicode => tag.with_type(PropType::String8),
        PropType::MvUnicode => tag.with_type(PropType::MvString8),
        _ => tag,
    }
}
