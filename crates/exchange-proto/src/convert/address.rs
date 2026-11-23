/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bytes::Bytes;

use crate::{
    convert::{model::PropBag, tags},
    mapi::{
        prop::{OwnedPropValue, PropId, PropKey, PropKeyRef},
        recipient::{one_off, smtp_search_key, write_one_off},
    },
};

const SMTP: &str = "SMTP";
const FLAT_SIZE_LEN: usize = 4;
const FLAT_LIST_HEADER: usize = 2 * FLAT_SIZE_LEN;
const FLAT_ENTRY_ALIGN: usize = 4;
pub const RECEIVED_REPRESENTING_IDS: [PropId; 6] = [
    tags::RECEIVED_REPRESENTING_ENTRY_ID,
    tags::RECEIVED_REPRESENTING_NAME,
    tags::RECEIVED_REPRESENTING_ADDRESS_TYPE,
    tags::RECEIVED_REPRESENTING_EMAIL_ADDRESS,
    tags::RECEIVED_REPRESENTING_SEARCH_KEY,
    tags::RECEIVED_REPRESENTING_SMTP_ADDRESS,
];

pub(crate) struct Address {
    pub name: Box<str>,
    pub address_type: Box<str>,
    pub email: Box<str>,
}

pub(crate) struct AddressTags {
    entry_id: PropId,
    name: PropId,
    address_type: PropId,
    email: PropId,
}

pub(crate) const SENDER: AddressTags = AddressTags {
    entry_id: tags::SENDER_ENTRY_ID,
    name: tags::SENDER_NAME,
    address_type: tags::SENDER_ADDRESS_TYPE,
    email: tags::SENDER_EMAIL_ADDRESS,
};
pub(crate) const SENT_REPRESENTING: AddressTags = AddressTags {
    entry_id: tags::SENT_REPRESENTING_ENTRY_ID,
    name: tags::SENT_REPRESENTING_NAME,
    address_type: tags::SENT_REPRESENTING_ADDRESS_TYPE,
    email: tags::SENT_REPRESENTING_EMAIL_ADDRESS,
};
pub(crate) const RECEIVED_REPRESENTING: AddressTags = AddressTags {
    entry_id: tags::RECEIVED_REPRESENTING_ENTRY_ID,
    name: tags::RECEIVED_REPRESENTING_NAME,
    address_type: tags::RECEIVED_REPRESENTING_ADDRESS_TYPE,
    email: tags::RECEIVED_REPRESENTING_EMAIL_ADDRESS,
};

pub(crate) struct FlatEntryListWriter {
    buf: Vec<u8>,
    count: u32,
}

impl FlatEntryListWriter {
    pub fn new() -> Self {
        FlatEntryListWriter {
            buf: vec![0; FLAT_LIST_HEADER],
            count: 0,
        }
    }

    pub fn push_one_off(&mut self, name: &str, address_type: &str, email: &str) -> bool {
        let start = self.buf.len();
        let padding = (start - FLAT_LIST_HEADER).wrapping_neg() % FLAT_ENTRY_ALIGN;
        self.buf.resize(start + padding + FLAT_SIZE_LEN, 0);
        let entry_start = self.buf.len();
        let size = write_one_off(&mut self.buf, name, address_type, email)
            .and_then(|()| u32::try_from(self.buf.len() - entry_start).ok());
        let (Some(size), Some(count)) = (size, self.count.checked_add(1)) else {
            self.buf.truncate(start);
            return false;
        };
        if let Some(slot) = self.buf.get_mut(entry_start - FLAT_SIZE_LEN..entry_start) {
            slot.copy_from_slice(&size.to_le_bytes());
        }
        self.count = count;
        true
    }

    pub fn finish(mut self) -> Option<Bytes> {
        let size = u32::try_from(self.buf.len() - FLAT_LIST_HEADER).ok()?;
        if self.count == 0 {
            return None;
        }
        let (header, _) = self.buf.split_first_chunk_mut::<FLAT_LIST_HEADER>()?;
        let (count, size_slot) = header.split_at_mut(FLAT_SIZE_LEN);
        count.copy_from_slice(&self.count.to_le_bytes());
        size_slot.copy_from_slice(&size.to_le_bytes());
        Some(self.buf.into())
    }
}

pub(crate) struct FlatEntries<'a> {
    rest: &'a [u8],
    remaining: u32,
}

impl<'a> FlatEntries<'a> {
    pub fn new(b: &'a [u8]) -> Option<Self> {
        let (count, rest) = b.split_first_chunk::<FLAT_SIZE_LEN>()?;
        let (size, rest) = rest.split_first_chunk::<FLAT_SIZE_LEN>()?;
        let size = usize::try_from(u32::from_le_bytes(*size)).ok()?;
        Some(FlatEntries {
            rest: rest.get(..size)?,
            remaining: u32::from_le_bytes(*count),
        })
    }

    pub fn claimed_len(&self) -> u32 {
        self.remaining
    }
}

impl<'a> Iterator for FlatEntries<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.remaining = self.remaining.checked_sub(1)?;
        let parsed = self
            .rest
            .split_first_chunk::<FLAT_SIZE_LEN>()
            .and_then(|(size, rest)| {
                let size = usize::try_from(u32::from_le_bytes(*size)).ok()?;
                let (entry, rest) = rest.split_at_checked(size)?;
                let padding = size.wrapping_neg() % FLAT_ENTRY_ALIGN;
                Some((entry, rest.get(padding..).unwrap_or_default()))
            });
        let Some((entry, rest)) = parsed else {
            self.remaining = 0;
            return None;
        };
        self.rest = rest;
        Some(entry)
    }
}

pub(crate) fn set_address(bag: &mut PropBag, target: &AddressTags, address: Address) {
    if let Some(entry_id) = one_off(&address.name, &address.address_type, &address.email) {
        bag.set(
            PropKey::tag(target.entry_id),
            OwnedPropValue::Binary(entry_id),
        );
    }
    bag.set(
        PropKey::tag(target.name),
        OwnedPropValue::Unicode(address.name),
    );
    bag.set(
        PropKey::tag(target.address_type),
        OwnedPropValue::Unicode(address.address_type),
    );
    bag.set(
        PropKey::tag(target.email),
        OwnedPropValue::Unicode(address.email),
    );
}

pub fn clear_received_representing(bag: &mut PropBag) {
    for id in RECEIVED_REPRESENTING_IDS {
        bag.remove_any(PropKeyRef::Tag(id));
    }
}

pub fn set_received_representing(bag: &mut PropBag, name: &str, email: &str) {
    bag.set(
        PropKey::tag(tags::RECEIVED_REPRESENTING_SEARCH_KEY),
        OwnedPropValue::Binary(smtp_search_key(email)),
    );
    bag.set(
        PropKey::tag(tags::RECEIVED_REPRESENTING_SMTP_ADDRESS),
        OwnedPropValue::Unicode(email.into()),
    );
    set_address(
        bag,
        &RECEIVED_REPRESENTING,
        Address {
            name: name.into(),
            address_type: SMTP.into(),
            email: email.into(),
        },
    );
}

pub(crate) struct SmtpRecipient<'a> {
    pub kind: i32,
    pub name: &'a str,
    pub smtp: &'a str,
    pub display_type: i32,
    pub flags: i32,
}

pub(crate) fn smtp_recipient(recipient: SmtpRecipient<'_>) -> PropBag {
    let SmtpRecipient {
        kind,
        name,
        smtp,
        display_type,
        flags,
    } = recipient;
    let mut row = PropBag::new();
    let mut set = |id: PropId, value: OwnedPropValue| row.set(PropKey::tag(id), value);
    set(tags::RECIPIENT_TYPE, OwnedPropValue::I32(kind));
    set(tags::DISPLAY_NAME, OwnedPropValue::Unicode(name.into()));
    set(tags::ADDRESS_TYPE, OwnedPropValue::Unicode(SMTP.into()));
    set(tags::EMAIL_ADDRESS, OwnedPropValue::Unicode(smtp.into()));
    set(tags::SMTP_ADDRESS, OwnedPropValue::Unicode(smtp.into()));
    if let Some(entry_id) = one_off(name, SMTP, smtp) {
        set(tags::ENTRY_ID, OwnedPropValue::Binary(entry_id));
    }
    set(
        tags::SEARCH_KEY,
        OwnedPropValue::Binary(smtp_search_key(smtp)),
    );
    set(
        tags::OBJECT_TYPE,
        OwnedPropValue::I32(tags::OBJECT_TYPE_MAIL_USER),
    );
    set(tags::DISPLAY_TYPE, OwnedPropValue::I32(display_type));
    set(tags::RECIPIENT_FLAGS, OwnedPropValue::I32(flags));
    row
}
