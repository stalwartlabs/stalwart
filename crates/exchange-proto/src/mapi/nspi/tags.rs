/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mapi::prop::PropTag;

pub const CONTAINER_FLAGS: PropTag = PropTag(0x3600_0003);
pub const ANR: PropTag = PropTag(0x360C_001F);
pub const CONTAINER_CONTENTS: PropTag = PropTag(0x360F_000D);
pub const TEMPLATE_ID: PropTag = PropTag(0x3902_0102);
pub const SELECTABLE: PropTag = PropTag(0x3609_000B);
pub const TEMPLATE_DATA: PropTag = PropTag(0x0001_0102);
pub const SCRIPT_DATA: PropTag = PropTag(0x0004_0102);
pub const EMAIL_TYPE: PropTag = PropTag(0x0001_001E);
pub const DISPLAY_NAME_PRINTABLE: PropTag = PropTag(0x39FF_001E);
pub const ACCOUNT: PropTag = PropTag(0x3A00_001F);
pub const DEPARTMENT_NAME: PropTag = PropTag(0x3A18_001F);
pub const OFFICE_LOCATION: PropTag = PropTag(0x3A19_001F);
pub const ROOM_CAPACITY: PropTag = PropTag(0x0807_0003);
pub const PRIMARY_TELEPHONE_NUMBER: PropTag = PropTag(0x3A1A_001F);
pub const INITIAL_DETAILS_PANE: PropTag = PropTag(0x3F08_0003);
pub const DISPLAY_TYPE_EX: PropTag = PropTag(0x3905_0003);
pub const SEND_RICH_INFO: PropTag = PropTag(0x3A40_000B);
pub const SEND_INTERNET_ENCODING: PropTag = PropTag(0x3A71_0003);
pub const MAPPING_SIGNATURE: PropTag = PropTag(0x0FF8_0102);
pub const PROXY_ADDRESSES: PropTag = PropTag(0x800F_101F);
pub const OBJECT_DISTINGUISHED_NAME: PropTag = PropTag(0x803C_001F);
pub const IS_MASTER: PropTag = PropTag(0xFFFB_000B);
pub const PARENT_ENTRY_ID: PropTag = PropTag(0xFFFC_0102);
pub const CONTAINER_ID: PropTag = PropTag(0xFFFD_0003);

pub const DT_MAILUSER: u32 = 0x0000_0000;
pub const DT_DISTLIST: u32 = 0x0000_0001;
pub const DT_ROOM: u32 = 0x0000_0007;
pub const DT_EQUIPMENT: u32 = 0x0000_0008;
pub const DTE_FLAG_ACL_CAPABLE: u32 = 0x4000_0000;
pub const DT_CONTAINER: u32 = 0x0000_0100;
pub const DT_ADDRESS_TEMPLATE: u32 = 0x0000_0102;

pub const MAPI_ABCONT: u32 = 0x0000_0004;
pub const MAPI_MAILUSER: u32 = 0x0000_0006;
pub const MAPI_DISTLIST: u32 = 0x0000_0008;

pub const AB_RECIPIENTS: u32 = 0x0000_0001;
pub const AB_SUBCONTAINERS: u32 = 0x0000_0002;
pub const AB_UNMODIFIABLE: u32 = 0x0000_0008;
pub const AB_ROOMS: u32 = 0x0000_0200;
