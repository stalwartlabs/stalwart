/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::mapi::prop::PropId;

pub const MESSAGE_CLASS: PropId = PropId(0x001A);
pub const IMPORTANCE: PropId = PropId(0x0017);
pub const SUBJECT: PropId = PropId(0x0037);
pub const CLIENT_SUBMIT_TIME: PropId = PropId(0x0039);
pub const SENT_REPRESENTING_ENTRY_ID: PropId = PropId(0x0041);
pub const SENT_REPRESENTING_NAME: PropId = PropId(0x0042);
pub const RECEIVED_REPRESENTING_ENTRY_ID: PropId = PropId(0x0043);
pub const RECEIVED_REPRESENTING_NAME: PropId = PropId(0x0044);
pub const ORIGINAL_MESSAGE_CLASS: PropId = PropId(0x004B);
pub const REPLY_RECIPIENT_ENTRIES: PropId = PropId(0x004F);
pub const REPLY_RECIPIENT_NAMES: PropId = PropId(0x0050);
pub const START_DATE: PropId = PropId(0x0060);
pub const END_DATE: PropId = PropId(0x0061);
pub const OWNER_APPOINTMENT_ID: PropId = PropId(0x0062);
pub const RESPONSE_REQUESTED: PropId = PropId(0x0063);
pub const SENT_REPRESENTING_ADDRESS_TYPE: PropId = PropId(0x0064);
pub const SENT_REPRESENTING_EMAIL_ADDRESS: PropId = PropId(0x0065);
pub const RECEIVED_REPRESENTING_ADDRESS_TYPE: PropId = PropId(0x0077);
pub const RECEIVED_REPRESENTING_EMAIL_ADDRESS: PropId = PropId(0x0078);
pub const RECEIVED_REPRESENTING_SEARCH_KEY: PropId = PropId(0x0052);
pub const TNEF_CORRELATION_KEY: PropId = PropId(0x007F);
pub const SENDER_ENTRY_ID: PropId = PropId(0x0C19);
pub const SENDER_NAME: PropId = PropId(0x0C1A);
pub const SENDER_ADDRESS_TYPE: PropId = PropId(0x0C1E);
pub const SENDER_EMAIL_ADDRESS: PropId = PropId(0x0C1F);
pub const MESSAGE_DELIVERY_TIME: PropId = PropId(0x0E06);
pub const MESSAGE_FLAGS: PropId = PropId(0x0E07);
pub const BODY: PropId = PropId(0x1000);
pub const CREATION_TIME: PropId = PropId(0x3007);
pub const LAST_MODIFICATION_TIME: PropId = PropId(0x3008);
pub const SEARCH_KEY: PropId = PropId(0x300B);
pub const ATTACH_DATA: PropId = PropId(0x3701);
pub const ATTACH_ENCODING: PropId = PropId(0x3702);
pub const ATTACH_FILENAME: PropId = PropId(0x3704);
pub const ATTACH_METHOD: PropId = PropId(0x3705);
pub const ATTACH_LONG_FILENAME: PropId = PropId(0x3707);
pub const ATTACH_RENDERING: PropId = PropId(0x3709);
pub const ATTACH_TAG: PropId = PropId(0x370A);
pub const RENDERING_POSITION: PropId = PropId(0x370B);
pub const ATTACH_TRANSPORT_NAME: PropId = PropId(0x370C);
pub const INTERNET_CODEPAGE: PropId = PropId(0x3FDE);

pub const ORIGINATOR_DELIVERY_REPORT_REQUESTED: PropId = PropId(0x0023);
pub const PARENT_KEY: PropId = PropId(0x0025);
pub const RECEIPT_TIME: PropId = PropId(0x002A);
pub const REPORT_TIME: PropId = PropId(0x0032);
pub const ORIGINAL_DELIVERY_TIME: PropId = PropId(0x0055);
pub const ORIGINAL_DISPLAY_TO: PropId = PropId(0x0074);
pub const REPORT_TEXT: PropId = PropId(0x1001);
pub const ORIGINAL_MESSAGE_ID: PropId = PropId(0x1046);
pub const READ_RECEIPT_REQUESTED: PropId = PropId(0x0029);
pub const SENSITIVITY: PropId = PropId(0x0036);
pub const SENT_REPRESENTING_SEARCH_KEY: PropId = PropId(0x003B);
pub const SUBJECT_PREFIX: PropId = PropId(0x003D);
pub const CONVERSATION_TOPIC: PropId = PropId(0x0070);
pub const CONVERSATION_INDEX: PropId = PropId(0x0071);
pub const CHANGE_KEY: PropId = PropId(0x65E2);
pub const PREDECESSOR_CHANGE_LIST: PropId = PropId(0x65E3);
pub const TRANSPORT_MESSAGE_HEADERS: PropId = PropId(0x007D);
pub const RECIPIENT_TYPE: PropId = PropId(0x0C15);
pub const SENDER_SEARCH_KEY: PropId = PropId(0x0C1D);
pub const DISPLAY_BCC: PropId = PropId(0x0E02);
pub const DISPLAY_CC: PropId = PropId(0x0E03);
pub const DISPLAY_TO: PropId = PropId(0x0E04);
pub const HAS_ATTACHMENTS: PropId = PropId(0x0E1B);
pub const NORMALIZED_SUBJECT: PropId = PropId(0x0E1D);
pub const RTF_IN_SYNC: PropId = PropId(0x0E1F);
pub const ATTACH_SIZE: PropId = PropId(0x0E20);
pub const OBJECT_TYPE: PropId = PropId(0x0FFE);
pub const ENTRY_ID: PropId = PropId(0x0FFF);
pub const RTF_COMPRESSED: PropId = PropId(0x1009);
pub const HTML: PropId = PropId(0x1013);
pub const NATIVE_BODY: PropId = PropId(0x1016);
pub const INTERNET_MESSAGE_ID: PropId = PropId(0x1035);
pub const INTERNET_REFERENCES: PropId = PropId(0x1039);
pub const IN_REPLY_TO_ID: PropId = PropId(0x1042);
pub const DISPLAY_NAME: PropId = PropId(0x3001);
pub const ADDRESS_TYPE: PropId = PropId(0x3002);
pub const EMAIL_ADDRESS: PropId = PropId(0x3003);
pub const ATTACH_EXTENSION: PropId = PropId(0x3703);
pub const ATTACH_MIME_TAG: PropId = PropId(0x370E);
pub const ATTACH_CONTENT_ID: PropId = PropId(0x3712);
pub const ATTACH_CONTENT_LOCATION: PropId = PropId(0x3713);
pub const ATTACH_FLAGS: PropId = PropId(0x3714);
pub const TEXT_ATTACHMENT_CHARSET: PropId = PropId(0x371B);
pub const DISPLAY_TYPE: PropId = PropId(0x3900);
pub const SMTP_ADDRESS: PropId = PropId(0x39FE);
pub const SENDER_SMTP_ADDRESS: PropId = PropId(0x5D01);
pub const SENT_REPRESENTING_SMTP_ADDRESS: PropId = PropId(0x5D02);
pub const RECEIVED_REPRESENTING_SMTP_ADDRESS: PropId = PropId(0x5D08);
pub const RECIPIENT_FLAGS: PropId = PropId(0x5FFD);
pub const ATTACHMENT_HIDDEN: PropId = PropId(0x7FFE);

pub mod attach_method {
    pub const BY_VALUE: i32 = 1;
    pub const EMBEDDED_MESSAGE: i32 = 5;
    pub const OLE: i32 = 6;
}

pub mod message_flags {
    pub const READ: i32 = 0x01;
    pub const UNMODIFIED: i32 = 0x02;
    pub const SUBMIT: i32 = 0x04;
    pub const UNSENT: i32 = 0x08;
    pub const HAS_ATTACH: i32 = 0x10;
    pub const RESEND: i32 = 0x80;
    pub const NOTIFY_READ: i32 = 0x100;
    pub const EVER_READ: i32 = 0x400;
}

pub mod attach_flags {
    pub const RENDERED_IN_BODY: i32 = 0x4;
}

pub mod native_body {
    pub const PLAIN: i32 = 1;
    pub const RTF: i32 = 2;
    pub const HTML: i32 = 3;
}

pub mod recipient_type {
    pub const TO: i32 = 1;
    pub const CC: i32 = 2;
    pub const BCC: i32 = 3;
    pub const MASK: i32 = 0x0F;
    pub const P1: i32 = 0x1000_0000;
    pub const SUBMITTED: i32 = i32::MIN;
    pub const FLAGS: i32 = P1 | SUBMITTED;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WireType(pub u8);

    impl WireType {
        const KIND_MASK: u8 = 0x0F;
        const FLAGS_SHIFT: u32 = 24;
        const FLAGS_MASK: u32 = 0xF0;

        pub fn from_stored(value: i32) -> Self {
            let value = value.cast_unsigned();
            WireType(
                ((value & MASK.cast_unsigned()) | ((value >> Self::FLAGS_SHIFT) & Self::FLAGS_MASK))
                    as u8,
            )
        }

        pub fn kind(self) -> Option<i32> {
            match self.0 & Self::KIND_MASK {
                0 => None,
                kind => Some(i32::from(kind)),
            }
        }
    }
}

pub const OBJECT_TYPE_MAIL_USER: i32 = 6;
pub const RECIPIENT_FLAG_SENDABLE: i32 = 0x1;
pub const KEYWORDS_NAME: &str = "Keywords";
pub const CONTENT_CLASS_NAME: &str = "Content-Class";
pub const LID_INFO_PATH_FORM_NAME: u32 = 0x85B1;
