/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::{
    convert::model::PropBag as ContentBag,
    mapi::{
        prop::{CodePage, OwnedPropValue, PropKeyRef, PropTag, row::RowWriter, tags},
        rop::responses::property_row_options,
    },
};
use smallvec::SmallVec;

const MAPI_MAILUSER: i32 = 6;
const DT_MAILUSER: i32 = 0;
const RECIP_SENDABLE: i32 = 1;
const SMTP: &str = "SMTP";
const NO_CELL_LIMIT: u16 = 0;

#[derive(Debug, Clone, Copy)]
enum Fallback {
    Int(i32),
    Order,
    DisplayName,
    Address,
    EntryId,
}

const COLUMNS: [(PropTag, Fallback); 12] = [
    (tags::OBJECT_TYPE, Fallback::Int(MAPI_MAILUSER)),
    (tags::DISPLAY_TYPE, Fallback::Int(DT_MAILUSER)),
    (
        tags::ADDRESS_BOOK_DISPLAY_NAME_PRINTABLE,
        Fallback::DisplayName,
    ),
    (tags::SMTP_ADDRESS, Fallback::Address),
    (tags::SEND_INTERNET_ENCODING, Fallback::Int(0)),
    (tags::DISPLAY_TYPE_EX, Fallback::Int(0)),
    (tags::RECIPIENT_DISPLAY_NAME, Fallback::DisplayName),
    (tags::RECIPIENT_FLAGS, Fallback::Int(RECIP_SENDABLE)),
    (tags::RECIPIENT_TRACK_STATUS, Fallback::Int(0)),
    (tags::RECIPIENT_RESOURCE_STATE, Fallback::Int(0)),
    (tags::RECIPIENT_ORDER, Fallback::Order),
    (tags::RECIPIENT_ENTRY_ID, Fallback::EntryId),
];

pub const RECIPIENT_COLUMNS: [PropTag; COLUMNS.len()] = {
    let mut out = [PropTag(0); COLUMNS.len()];
    let mut at = 0;
    while at < COLUMNS.len() {
        out[at] = COLUMNS[at].0;
        at += 1;
    }
    out
};

pub struct RecipientColumnWriter<'a> {
    columns: &'a [PropTag],
    fallbacks: SmallVec<[Option<Fallback>; 32]>,
}

impl<'a> RecipientColumnWriter<'a> {
    pub fn new(columns: &'a [PropTag]) -> Self {
        RecipientColumnWriter {
            columns,
            fallbacks: columns
                .iter()
                .map(|tag| {
                    COLUMNS
                        .iter()
                        .find(|(fixed, _)| fixed.id() == tag.id())
                        .map(|(_, fallback)| *fallback)
                })
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    pub fn write(&self, out: &mut Vec<u8>, bag: &ContentBag, order: i32, code_page: CodePage) {
        let mut row = RowWriter::standalone(
            out,
            self.columns,
            true,
            property_row_options(true, NO_CELL_LIMIT, code_page),
        );
        for (tag, fallback) in self.columns.iter().zip(&self.fallbacks) {
            let value = bag_value(bag, *tag).or_else(|| match (*fallback)? {
                Fallback::Int(_) | Fallback::Order => None,
                Fallback::DisplayName => bag_value(bag, tags::DISPLAY_NAME),
                Fallback::Address => bag_value(bag, tags::EMAIL_ADDRESS).filter(|_| {
                    !matches!(
                        bag_value(bag, tags::ADDRESS_TYPE),
                        Some(OwnedPropValue::Unicode(kind)) if !kind.eq_ignore_ascii_case(SMTP)
                    )
                }),
                Fallback::EntryId => bag_value(bag, tags::ENTRY_ID),
            });
            match (value, fallback) {
                (Some(value), _) => write_value(&mut row, value),
                (None, Some(Fallback::Int(value))) => row.i32(*value),
                (None, Some(Fallback::Order)) => row.i32(order),
                (None, _) => row.missing(),
            }
        }
    }
}

fn write_value(row: &mut RowWriter<'_>, value: &OwnedPropValue) {
    match value {
        OwnedPropValue::I16(value) => row.i16(*value),
        OwnedPropValue::I32(value) => row.i32(*value),
        OwnedPropValue::I64(value) => row.i64(*value),
        OwnedPropValue::Bool(value) => row.bool(*value),
        OwnedPropValue::F64(value) => row.f64(*value),
        OwnedPropValue::Time(value) => row.time(*value),
        OwnedPropValue::Guid(value) => row.guid(value),
        OwnedPropValue::Unicode(text) => row.unicode(text),
        OwnedPropValue::String8(text) => row.string8(text),
        OwnedPropValue::Binary(bytes) => row.binary(bytes),
        OwnedPropValue::Error(code) => row.error(*code),
        _ => row.missing(),
    }
}

fn bag_value(bag: &ContentBag, tag: PropTag) -> Option<&OwnedPropValue> {
    bag.get(PropKeyRef::Tag(tag.id()), tag.ptype())
}
