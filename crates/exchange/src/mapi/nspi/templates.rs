/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::props::as_string8;
use exchange_proto::{
    ids::entryid::{AddressBookEntryId, EntryId, EntryIdError},
    mapi::{
        nspi::{
            AbkListWriter,
            tags::{
                DT_ADDRESS_TEMPLATE, DT_DISTLIST, DT_MAILUSER, EMAIL_TYPE, SCRIPT_DATA, SELECTABLE,
                TEMPLATE_DATA,
            },
            verbs::{TI_EMT, TI_SCRIPT, TI_TEMPLATE},
        },
        prop::{CodePage, PropValue, tags},
    },
};
use std::borrow::Cow;

pub const NO_LOCALE: u32 = 0;

const TEMPLATE_TYPE: u32 = 1;
const ROW_LEN: usize = 36;
const ANY_CHARACTER: &str = "*";

const LABEL: u32 = 0x00;
const EDIT: u32 = 0x01;
const LIST_BOX: u32 = 0x02;
const MULTI_VALUE_LIST: u32 = 0x0B;
const PAGE: u32 = 0x08;
const GROUP: u32 = 0x06;

const EDITABLE: u32 = 0x02;
const REQUIRED: u32 = 0x04;

const SCRIPT_HALT: u32 = 0x0000_0000;
const SCRIPT_ERROR: u32 = 0x0000_0001;
const SCRIPT_EMIT_PROPERTY: u32 = 0x0000_0002;
const SCRIPT_JUMP_IF_NOT_EXISTS: u32 = 0x0000_0004;

const DISPLAY_NAME: u32 = 0x3001_001E;
const EMAIL_ADDRESS: u32 = 0x3003_001E;
const ACCOUNT: u32 = 0x3A00_001E;
const SMTP_ADDRESS: u32 = 0x39FE_001E;
const PROXY_ADDRESSES: u32 = 0x800F_101E;
const MEMBERS: u32 = 0x8009_000D;

#[derive(Debug, Clone, Copy)]
enum Control {
    Page(&'static str),
    Group(&'static str),
    Label(&'static str),
    Edit { tag: u32, max: u32, flags: u32 },
    MultiValueList(u32),
    ListBox(u32),
}

impl Control {
    fn wire(self) -> [u32; 4] {
        match self {
            Control::Page(_) => [PAGE, 0, 0, 0],
            Control::Group(_) => [GROUP, 0, 0, 0],
            Control::Label(_) => [LABEL, 0, 0, 0],
            Control::Edit { tag, max, flags } => [EDIT, flags, tag, max],
            Control::MultiValueList(tag) => [MULTI_VALUE_LIST, 0, tag, 0],
            Control::ListBox(tag) => [LIST_BOX, 0, tag, 0],
        }
    }

    fn text(self) -> &'static str {
        match self {
            Control::Page(text) | Control::Group(text) | Control::Label(text) => text,
            Control::Edit { .. } | Control::MultiValueList(_) | Control::ListBox(_) => {
                ANY_CHARACTER
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Placed {
    x: u32,
    width: u32,
    y: u32,
    height: u32,
    control: Control,
}

const fn at(x: u32, width: u32, y: u32, height: u32, control: Control) -> Placed {
    Placed {
        x,
        width,
        y,
        height,
        control,
    }
}

const fn page(text: &'static str) -> Placed {
    at(0, 0, 0, 0, Control::Page(text))
}

const fn read_only(tag: u32, max: u32) -> Control {
    Control::Edit { tag, max, flags: 0 }
}

const DISPLAY_CONTROLS: &[Placed] = &[
    page("General"),
    at(6, 359, 3, 60, Control::Group("Name")),
    at(12, 70, 15, 8, Control::Label("&Display name:")),
    at(83, 270, 13, 12, read_only(DISPLAY_NAME, 256)),
    at(12, 70, 30, 8, Control::Label("Al&ias:")),
    at(83, 270, 28, 12, read_only(ACCOUNT, 64)),
    at(12, 70, 45, 8, Control::Label("E-&mail:")),
    at(83, 270, 43, 12, read_only(SMTP_ADDRESS, 256)),
    page("E-mail Addresses"),
    at(6, 359, 4, 8, Control::Label("&E-mail addresses:")),
    at(6, 359, 14, 132, Control::MultiValueList(PROXY_ADDRESSES)),
];

const DISTLIST_CONTROLS: &[Placed] = &[
    page("General"),
    at(6, 359, 3, 60, Control::Group("Name")),
    at(12, 70, 15, 8, Control::Label("&Display name:")),
    at(83, 270, 13, 12, read_only(DISPLAY_NAME, 256)),
    at(12, 70, 30, 8, Control::Label("Al&ias:")),
    at(83, 270, 28, 12, read_only(ACCOUNT, 64)),
    at(12, 70, 45, 8, Control::Label("E-&mail:")),
    at(83, 270, 43, 12, read_only(SMTP_ADDRESS, 256)),
    page("Members"),
    at(6, 359, 4, 8, Control::Label("&Members:")),
    at(6, 359, 14, 132, Control::ListBox(MEMBERS)),
    page("E-mail Addresses"),
    at(6, 359, 4, 8, Control::Label("&E-mail addresses:")),
    at(6, 359, 14, 132, Control::MultiValueList(PROXY_ADDRESSES)),
];

const SMTP_CONTROLS: &[Placed] = &[
    page("General"),
    at(12, 70, 15, 8, Control::Label("&Display name:")),
    at(
        83,
        270,
        13,
        12,
        Control::Edit {
            tag: DISPLAY_NAME,
            max: 256,
            flags: EDITABLE,
        },
    ),
    at(12, 70, 30, 8, Control::Label("&E-mail address:")),
    at(
        83,
        270,
        28,
        12,
        Control::Edit {
            tag: EMAIL_ADDRESS,
            max: 256,
            flags: EDITABLE | REQUIRED,
        },
    ),
];

const DISPLAY_SCRIPT: &[u32] = &[1, SCRIPT_HALT];

const SMTP_SCRIPT: &[u32] = &[
    7,
    SCRIPT_JUMP_IF_NOT_EXISTS,
    EMAIL_ADDRESS,
    24,
    SCRIPT_EMIT_PROPERTY,
    EMAIL_ADDRESS,
    SCRIPT_HALT,
    SCRIPT_ERROR,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    Display,
    DistList,
    Smtp,
}

impl Template {
    pub const CREATION: [Template; 1] = [Template::Smtp];

    pub fn for_display_type(display_type: u32) -> Option<Self> {
        match display_type {
            DT_MAILUSER => Some(Template::Display),
            DT_DISTLIST => Some(Template::DistList),
            _ => None,
        }
    }

    pub fn from_dn(dn: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(dn, Template,
            "/o=Stalwart/ou=Address Templates/cn=SMTP" => Template::Smtp,
        )
        .copied()
    }

    pub fn dn(self) -> &'static str {
        match self {
            Template::Display => "/o=Stalwart/ou=Display Templates/cn=Default",
            Template::DistList => "/o=Stalwart/ou=Display Templates/cn=Distribution List",
            Template::Smtp => "/o=Stalwart/ou=Address Templates/cn=SMTP",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Template::Display => "Default",
            Template::DistList => "Distribution List",
            Template::Smtp => "Internet Address",
        }
    }

    fn address_type(self) -> &'static str {
        match self {
            Template::Display | Template::DistList => "EX",
            Template::Smtp => "SMTP",
        }
    }

    fn controls(self) -> &'static [Placed] {
        match self {
            Template::Display => DISPLAY_CONTROLS,
            Template::DistList => DISTLIST_CONTROLS,
            Template::Smtp => SMTP_CONTROLS,
        }
    }

    fn script(self) -> &'static [u32] {
        match self {
            Template::Display | Template::DistList => DISPLAY_SCRIPT,
            Template::Smtp => SMTP_SCRIPT,
        }
    }

    pub fn encode_controls(self, out: &mut Vec<u8>) {
        let controls = self.controls();
        let mut string_at = 8 + controls.len() * ROW_LEN;
        out.reserve(
            string_at
                + controls
                    .iter()
                    .map(|placed| placed.control.text().len() + 1)
                    .sum::<usize>(),
        );
        out.extend_from_slice(&TEMPLATE_TYPE.to_le_bytes());
        out.extend_from_slice(&u32_of(controls.len()).to_le_bytes());
        for placed in controls {
            let [control_type, flags, dw_type, size] = placed.control.wire();
            for value in [
                placed.x,
                placed.width,
                placed.y,
                placed.height,
                control_type,
                flags,
                dw_type,
                size,
                u32_of(string_at),
            ] {
                out.extend_from_slice(&value.to_le_bytes());
            }
            string_at += placed.control.text().len() + 1;
        }
        for placed in controls {
            out.extend_from_slice(placed.control.text().as_bytes());
            out.push(0);
        }
    }

    pub fn encode_script(self, out: &mut Vec<u8>) {
        let script = self.script();
        out.reserve(script.len() * 4);
        for value in script {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }

    pub fn write_info(self, flags: u32, list: &mut AbkListWriter<'_>) {
        let mut data = Vec::new();
        if flags & TI_TEMPLATE != 0 {
            self.encode_controls(&mut data);
            list.value(TEMPLATE_DATA, &PropValue::Binary(&data));
        }
        if flags & TI_SCRIPT != 0 {
            data.clear();
            self.encode_script(&mut data);
            list.value(SCRIPT_DATA, &PropValue::Binary(&data));
        }
        if flags & TI_EMT != 0 {
            list.text(EMAIL_TYPE, self.address_type(), CodePage::WINDOWS_1252);
        }
    }

    pub fn write_creation_table(locale: u32, out: &mut Vec<u8>) -> Result<(), EntryIdError> {
        let templates: &[Template] = if locale == NO_LOCALE {
            &[]
        } else {
            &Template::CREATION
        };
        out.extend_from_slice(&u32_of(templates.len()).to_le_bytes());
        let mut entry_id = Vec::with_capacity(64);
        for (index, template) in (0u32..).zip(templates) {
            entry_id.clear();
            EntryId::AddressBook(AddressBookEntryId {
                flags: 0,
                display_type: DT_ADDRESS_TEMPLATE,
                dn: Cow::Borrowed(template.dn().as_bytes()),
            })
            .encode(&mut entry_id)?;
            let mut row = AbkListWriter::begin(out);
            row.text(
                as_string8(tags::DISPLAY_NAME),
                template.display_name(),
                CodePage::WINDOWS_1252,
            );
            row.text(
                as_string8(tags::ADDRESS_TYPE),
                template.address_type(),
                CodePage::WINDOWS_1252,
            );
            row.value(tags::DISPLAY_TYPE, &PropValue::I32(0));
            row.value(tags::DEPTH, &PropValue::I32(0));
            row.value(SELECTABLE, &PropValue::Bool(true));
            row.value(tags::INSTANCE_KEY, &PropValue::Binary(&index.to_le_bytes()));
            row.value(tags::ENTRY_ID, &PropValue::Binary(&entry_id));
            row.finish();
        }
        Ok(())
    }
}

fn u32_of(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
