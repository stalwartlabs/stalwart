/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    name::{PropKeyRef, sets},
    tag::{PropTag, PropType},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedProp {
    pub key: PropKeyRef<'static>,
    pub ptype: PropType,
}

pub const MID: PropTag = PropTag(0x674A_0014);
pub const FOLDER_ID: PropTag = PropTag(0x6748_0014);
pub const PARENT_FOLDER_ID: PropTag = PropTag(0x6749_0014);
pub const ENTRY_ID: PropTag = PropTag(0x0FFF_0102);
pub const PARENT_ENTRY_ID: PropTag = PropTag(0x0E09_0102);
pub const ORIGINAL_ENTRY_ID: PropTag = PropTag(0x3A12_0102);
pub const RECORD_KEY: PropTag = PropTag(0x0FF9_0102);
pub const SEARCH_KEY: PropTag = PropTag(0x300B_0102);
pub const INSTANCE_KEY: PropTag = PropTag(0x0FF6_0102);
pub const SOURCE_KEY: PropTag = PropTag(0x65E0_0102);
pub const PARENT_SOURCE_KEY: PropTag = PropTag(0x65E1_0102);
pub const CHANGE_KEY: PropTag = PropTag(0x65E2_0102);
pub const PREDECESSOR_CHANGE_LIST: PropTag = PropTag(0x65E3_0102);
pub const CHANGE_NUMBER: PropTag = PropTag(0x67A4_0014);
pub const ASSOCIATED: PropTag = PropTag(0x67AA_000B);
pub const OBJECT_TYPE: PropTag = PropTag(0x0FFE_0003);
pub const ACCESS: PropTag = PropTag(0x0FF4_0003);
pub const ACCESS_LEVEL: PropTag = PropTag(0x0FF7_0003);
pub const CREATION_TIME: PropTag = PropTag(0x3007_0040);
pub const LAST_MODIFICATION_TIME: PropTag = PropTag(0x3008_0040);
pub const LOCAL_COMMIT_TIME: PropTag = PropTag(0x6709_0040);
pub const LOCAL_COMMIT_TIME_MAX: PropTag = PropTag(0x670A_0040);
pub const LAST_MODIFIER_NAME: PropTag = PropTag(0x3FFA_001F);
pub const LAST_MODIFIER_ENTRY_ID: PropTag = PropTag(0x3FFB_0102);
pub const CREATOR_NAME: PropTag = PropTag(0x3FF8_001F);
pub const CREATOR_ENTRY_ID: PropTag = PropTag(0x3FF9_0102);
pub const MESSAGE_SIZE: PropTag = PropTag(0x0E08_0003);
pub const MESSAGE_SIZE_EXTENDED: PropTag = PropTag(0x0E08_0014);
pub const DELETED_ON: PropTag = PropTag(0x668F_0040);
pub const MESSAGE_CLASS: PropTag = PropTag(0x001A_001F);
pub const SUBJECT: PropTag = PropTag(0x0037_001F);
pub const SUBJECT_PREFIX: PropTag = PropTag(0x003D_001F);
pub const NORMALIZED_SUBJECT: PropTag = PropTag(0x0E1D_001F);
pub const CONVERSATION_TOPIC: PropTag = PropTag(0x0070_001F);
pub const CONVERSATION_INDEX: PropTag = PropTag(0x0071_0102);
pub const CONVERSATION_ID: PropTag = PropTag(0x3013_0102);
pub const MESSAGE_FLAGS: PropTag = PropTag(0x0E07_0003);
pub const MESSAGE_STATUS: PropTag = PropTag(0x0E17_0003);
pub const MESSAGE_DELIVERY_TIME: PropTag = PropTag(0x0E06_0040);
pub const CLIENT_SUBMIT_TIME: PropTag = PropTag(0x0039_0040);
pub const IMPORTANCE: PropTag = PropTag(0x0017_0003);
pub const SENSITIVITY: PropTag = PropTag(0x0036_0003);
pub const PRIORITY: PropTag = PropTag(0x0026_0003);
pub const HAS_ATTACHMENTS: PropTag = PropTag(0x0E1B_000B);
pub const HAS_NAMED_PROPERTIES: PropTag = PropTag(0x664A_000B);
pub const MESSAGE_CODEPAGE: PropTag = PropTag(0x3FFD_0003);
pub const MESSAGE_LOCALE_ID: PropTag = PropTag(0x3FF1_0003);
pub const INTERNET_CODEPAGE: PropTag = PropTag(0x3FDE_0003);
pub const NATIVE_BODY: PropTag = PropTag(0x1016_0003);
pub const ICON_INDEX: PropTag = PropTag(0x1080_0003);
pub const LAST_VERB_EXECUTED: PropTag = PropTag(0x1081_0003);
pub const LAST_VERB_EXECUTION_TIME: PropTag = PropTag(0x1082_0040);
pub const DISPLAY_TO: PropTag = PropTag(0x0E04_001F);
pub const DISPLAY_CC: PropTag = PropTag(0x0E03_001F);
pub const DISPLAY_BCC: PropTag = PropTag(0x0E02_001F);
pub const READ: PropTag = PropTag(0x0E69_000B);
pub const READ_RECEIPT_REQUESTED: PropTag = PropTag(0x0029_000B);
pub const DELETE_AFTER_SUBMIT: PropTag = PropTag(0x0E01_000B);
pub const SENT_MAIL_ENTRY_ID: PropTag = PropTag(0x0E0A_0102);
pub const TARGET_ENTRY_ID: PropTag = PropTag(0x3010_0102);
pub const SENT_MAIL_SVR_EID: PropTag = PropTag(0x6740_00FB);
pub const DEFERRED_SEND_TIME: PropTag = PropTag(0x3FEF_0040);
pub const ORIGINATOR_DELIVERY_REPORT_REQUESTED: PropTag = PropTag(0x0023_000B);
pub const TRUST_SENDER: PropTag = PropTag(0x0E79_0003);
pub const MESSAGE_TO_ME: PropTag = PropTag(0x0057_000B);
pub const MESSAGE_CC_ME: PropTag = PropTag(0x0058_000B);
pub const MESSAGE_RECIP_ME: PropTag = PropTag(0x0059_000B);
pub const BODY: PropTag = PropTag(0x1000_001F);
pub const HTML: PropTag = PropTag(0x1013_0102);
pub const BODY_HTML: PropTag = PropTag(0x1013_001F);
pub const RTF_COMPRESSED: PropTag = PropTag(0x1009_0102);
pub const RTF_IN_SYNC: PropTag = PropTag(0x0E1F_000B);
pub const INTERNET_MESSAGE_ID: PropTag = PropTag(0x1035_001F);
pub const IN_REPLY_TO_ID: PropTag = PropTag(0x1042_001F);
pub const INTERNET_REFERENCES: PropTag = PropTag(0x1039_001F);
pub const TRANSPORT_MESSAGE_HEADERS: PropTag = PropTag(0x007D_001F);
pub const REPORT_DISPOSITION_MODE: PropTag = PropTag(0x0081_001F);
pub const INTERNET_MAIL_OVERRIDE_FORMAT: PropTag = PropTag(0x5902_0003);
pub const MESSAGE_EDITOR_FORMAT: PropTag = PropTag(0x5909_0003);
pub const SENDER_NAME: PropTag = PropTag(0x0C1A_001F);
pub const SENDER_ENTRY_ID: PropTag = PropTag(0x0C19_0102);
pub const SENDER_ADDRESS_TYPE: PropTag = PropTag(0x0C1E_001F);
pub const SENDER_EMAIL_ADDRESS: PropTag = PropTag(0x0C1F_001F);
pub const SENDER_SMTP_ADDRESS: PropTag = PropTag(0x5D01_001F);
pub const SENDER_SEARCH_KEY: PropTag = PropTag(0x0C1D_0102);
pub const SENT_REPRESENTING_NAME: PropTag = PropTag(0x0042_001F);
pub const SENT_REPRESENTING_ENTRY_ID: PropTag = PropTag(0x0041_0102);
pub const SENT_REPRESENTING_ADDRESS_TYPE: PropTag = PropTag(0x0064_001F);
pub const SENT_REPRESENTING_EMAIL_ADDRESS: PropTag = PropTag(0x0065_001F);
pub const SENT_REPRESENTING_SMTP_ADDRESS: PropTag = PropTag(0x5D02_001F);
pub const SENT_REPRESENTING_SEARCH_KEY: PropTag = PropTag(0x003B_0102);
pub const RECEIVED_BY_NAME: PropTag = PropTag(0x0040_001F);
pub const RECEIVED_BY_ENTRY_ID: PropTag = PropTag(0x003F_0102);
pub const RECEIVED_BY_ADDRESS_TYPE: PropTag = PropTag(0x0075_001F);
pub const RECEIVED_BY_EMAIL_ADDRESS: PropTag = PropTag(0x0076_001F);
pub const RECEIVED_REPRESENTING_NAME: PropTag = PropTag(0x0044_001F);
pub const RECEIVED_REPRESENTING_ENTRY_ID: PropTag = PropTag(0x0043_0102);
pub const RECEIVED_REPRESENTING_EMAIL_ADDRESS: PropTag = PropTag(0x0078_001F);
pub const ROWID: PropTag = PropTag(0x3000_0003);
pub const RECIPIENT_TYPE: PropTag = PropTag(0x0C15_0003);
pub const DISPLAY_NAME: PropTag = PropTag(0x3001_001F);
pub const ADDRESS_TYPE: PropTag = PropTag(0x3002_001F);
pub const EMAIL_ADDRESS: PropTag = PropTag(0x3003_001F);
pub const SMTP_ADDRESS: PropTag = PropTag(0x39FE_001F);
pub const DISPLAY_TYPE: PropTag = PropTag(0x3900_0003);
pub const DISPLAY_TYPE_EX: PropTag = PropTag(0x3905_0003);
pub const RECIPIENT_FLAGS: PropTag = PropTag(0x5FFD_0003);
pub const RECIPIENT_TRACK_STATUS: PropTag = PropTag(0x5FFF_0003);
pub const RECIPIENT_DISPLAY_NAME: PropTag = PropTag(0x5FF6_001F);
pub const RECIPIENT_ENTRY_ID: PropTag = PropTag(0x5FF7_0102);
pub const RESPONSIBILITY: PropTag = PropTag(0x0E0F_000B);
pub const SEND_RICH_INFO: PropTag = PropTag(0x3A40_000B);
pub const SEND_INTERNET_ENCODING: PropTag = PropTag(0x3A71_0003);
pub const TRANSMITTABLE_DISPLAY_NAME: PropTag = PropTag(0x3A20_001F);
pub const RECIPIENT_ORDER: PropTag = PropTag(0x5FDF_0003);
pub const RECIPIENT_RESOURCE_STATE: PropTag = PropTag(0x5FDE_0003);
pub const ADDRESS_BOOK_DISPLAY_NAME_PRINTABLE: PropTag = PropTag(0x39FF_001F);
pub const ATTACH_NUMBER: PropTag = PropTag(0x0E21_0003);
pub const ATTACH_METHOD: PropTag = PropTag(0x3705_0003);
pub const ATTACH_DATA_BINARY: PropTag = PropTag(0x3701_0102);
pub const ATTACH_DATA_OBJECT: PropTag = PropTag(0x3701_000D);
pub const ATTACH_FILENAME: PropTag = PropTag(0x3704_001F);
pub const ATTACH_LONG_FILENAME: PropTag = PropTag(0x3707_001F);
pub const ATTACH_EXTENSION: PropTag = PropTag(0x3703_001F);
pub const ATTACHMENT_CONTACT_PHOTO: PropTag = PropTag(0x7FFF_000B);
pub const ATTACH_MIME_TAG: PropTag = PropTag(0x370E_001F);
pub const ATTACH_SIZE: PropTag = PropTag(0x0E20_0003);
pub const ATTACH_CONTENT_ID: PropTag = PropTag(0x3712_001F);
pub const ATTACH_CONTENT_LOCATION: PropTag = PropTag(0x3713_001F);
pub const ATTACH_FLAGS: PropTag = PropTag(0x3714_0003);
pub const ATTACHMENT_HIDDEN: PropTag = PropTag(0x7FFE_000B);
pub const ATTACHMENT_FLAGS: PropTag = PropTag(0x7FFD_0003);
pub const ATTACH_ENCODING: PropTag = PropTag(0x3702_0102);
pub const RENDERING_POSITION: PropTag = PropTag(0x370B_0003);
pub const ATTACH_TAG: PropTag = PropTag(0x370A_0102);
pub const CONTAINER_CLASS: PropTag = PropTag(0x3613_001F);
pub const CONTENT_COUNT: PropTag = PropTag(0x3602_0003);
pub const CONTENT_UNREAD_COUNT: PropTag = PropTag(0x3603_0003);
pub const SUBFOLDERS: PropTag = PropTag(0x360A_000B);
pub const FOLDER_TYPE: PropTag = PropTag(0x3601_0003);
pub const COMMENT: PropTag = PropTag(0x3004_001F);
pub const FOLDER_FLAGS: PropTag = PropTag(0x66A8_0003);
pub const RIGHTS: PropTag = PropTag(0x6639_0003);
pub const HIER_REV: PropTag = PropTag(0x4082_0040);
pub const HIERARCHY_CHANGE_NUMBER: PropTag = PropTag(0x663E_0003);
pub const ATTRIBUTE_HIDDEN: PropTag = PropTag(0x10F4_000B);
pub const DELETED_COUNT_TOTAL: PropTag = PropTag(0x670B_0003);
pub const EXTENDED_FOLDER_FLAGS: PropTag = PropTag(0x36DA_0102);
pub const DEFAULT_POST_MESSAGE_CLASS: PropTag = PropTag(0x36E5_001F);
pub const HAS_RULES: PropTag = PropTag(0x663A_000B);
pub const HAS_DEFERRED_ACTION_MESSAGES: PropTag = PropTag(0x3FEA_000B);
pub const IPM_APPOINTMENT_ENTRY_ID: PropTag = PropTag(0x36D0_0102);
pub const IPM_CONTACT_ENTRY_ID: PropTag = PropTag(0x36D1_0102);
pub const IPM_JOURNAL_ENTRY_ID: PropTag = PropTag(0x36D2_0102);
pub const IPM_NOTE_ENTRY_ID: PropTag = PropTag(0x36D3_0102);
pub const IPM_TASK_ENTRY_ID: PropTag = PropTag(0x36D4_0102);
pub const IPM_DRAFTS_ENTRY_ID: PropTag = PropTag(0x36D7_0102);
pub const REMINDERS_ONLINE_ENTRY_ID: PropTag = PropTag(0x36D5_0102);
pub const ADDITIONAL_REN_ENTRY_IDS: PropTag = PropTag(0x36D8_1102);
pub const ADDITIONAL_REN_ENTRY_IDS_EX: PropTag = PropTag(0x36D9_0102);
pub const FREE_BUSY_ENTRY_IDS: PropTag = PropTag(0x36E4_1102);
pub const SEARCH_FOLDER_ID: PropTag = PropTag(0x6842_0102);
pub const STORE_ENTRY_ID: PropTag = PropTag(0x0FFB_0102);
pub const STORE_SUPPORT_MASK: PropTag = PropTag(0x340D_0003);
pub const STORE_STATE: PropTag = PropTag(0x340E_0003);
pub const MAILBOX_OWNER_ENTRY_ID: PropTag = PropTag(0x661B_0102);
pub const MAILBOX_OWNER_NAME: PropTag = PropTag(0x661C_001F);
pub const USER_ENTRY_ID: PropTag = PropTag(0x6619_0102);
pub const SORT_LOCALE_ID: PropTag = PropTag(0x6705_0003);
pub const LOCALE_ID: PropTag = PropTag(0x66A1_0003);
pub const CODE_PAGE_ID: PropTag = PropTag(0x66C3_0003);
pub const OUT_OF_OFFICE_STATE: PropTag = PropTag(0x661D_000B);
pub const PROHIBIT_RECEIVE_QUOTA: PropTag = PropTag(0x666A_0003);
pub const PROHIBIT_SEND_QUOTA: PropTag = PropTag(0x666E_0003);
pub const MAXIMUM_SUBMIT_MESSAGE_SIZE: PropTag = PropTag(0x666D_0003);
pub const EXTENDED_RULE_SIZE_LIMIT: PropTag = PropTag(0x0E9B_0003);
pub const ROW_TYPE: PropTag = PropTag(0x0FF5_0003);
pub const DEPTH: PropTag = PropTag(0x3005_0003);
pub const INST_ID: PropTag = PropTag(0x674D_0014);
pub const INSTANCE_NUM: PropTag = PropTag(0x674E_0003);
pub const MEMBER_ID: PropTag = PropTag(0x6671_0014);
pub const MEMBER_NAME: PropTag = PropTag(0x6672_001F);
pub const MEMBER_RIGHTS: PropTag = PropTag(0x6673_0003);
pub const RULE_ID: PropTag = PropTag(0x6674_0014);
pub const RULE_SEQUENCE: PropTag = PropTag(0x6676_0003);
pub const RULE_STATE: PropTag = PropTag(0x6677_0003);
pub const RULE_CONDITION: PropTag = PropTag(0x6679_00FD);
pub const RULE_ACTIONS: PropTag = PropTag(0x6680_00FE);
pub const RULE_PROVIDER: PropTag = PropTag(0x6681_001F);
pub const RULE_NAME: PropTag = PropTag(0x6682_001F);
pub const RULE_LEVEL: PropTag = PropTag(0x6683_0003);
pub const RULE_USER_FLAGS: PropTag = PropTag(0x6678_0003);
pub const RULE_PROVIDER_DATA: PropTag = PropTag(0x6684_0102);
pub const EXTENDED_RULE_MESSAGE_ACTIONS: PropTag = PropTag(0x0E99_0102);
pub const EXTENDED_RULE_MESSAGE_CONDITION: PropTag = PropTag(0x0E9A_0102);
pub const RULE_MESSAGE_STATE: PropTag = PropTag(0x65E9_0003);
pub const RULE_MESSAGE_PROVIDER: PropTag = PropTag(0x65EB_001F);
pub const MESSAGE_RECIPIENTS: PropTag = PropTag(0x0E12_000D);
pub const DAM_ORIGINAL_ENTRY_ID: PropTag = PropTag(0x6646_0102);
pub const DAM_BACK_PATCHED: PropTag = PropTag(0x6647_000B);
pub const FLAG_STATUS: PropTag = PropTag(0x1090_0003);
pub const AUTO_FORWARDED: PropTag = PropTag(0x0005_000B);
pub const FLAG_COMPLETE_TIME: PropTag = PropTag(0x1091_0040);
pub const FOLLOWUP_ICON: PropTag = PropTag(0x1095_0003);
pub const TO_DO_ITEM_FLAGS: PropTag = PropTag(0x0E2B_0003);
pub const ROOT_ENTRY_ID: PropTag = PropTag(0x35D8_0102);
pub const IPM_SUBTREE_ENTRY_ID: PropTag = PropTag(0x35E0_0102);
pub const IPM_INBOX_ENTRY_ID: PropTag = PropTag(0x35E1_0102);
pub const IPM_OUTBOX_ENTRY_ID: PropTag = PropTag(0x35E2_0102);
pub const IPM_WASTEBASKET_ENTRY_ID: PropTag = PropTag(0x35E3_0102);
pub const IPM_SENT_MAIL_ENTRY_ID: PropTag = PropTag(0x35E4_0102);
pub const VIEWS_ENTRY_ID: PropTag = PropTag(0x35E5_0102);
pub const COMMON_VIEWS_ENTRY_ID: PropTag = PropTag(0x35E6_0102);
pub const FINDER_ENTRY_ID: PropTag = PropTag(0x35E7_0102);
pub const SCHEDULE_FOLDER_ENTRY_ID: PropTag = PropTag(0x661E_0102);
pub const NON_IPM_SUBTREE_ENTRY_ID: PropTag = PropTag(0x6620_0102);
pub const STORE_RECORD_KEY: PropTag = PropTag(0x0FFA_0102);
pub const SERIALIZED_REPLID_GUID_MAP: PropTag = PropTag(0x6638_0102);
pub const FOLDER_CHILD_COUNT: PropTag = PropTag(0x6638_0003);
pub const ASSOC_CONTENT_COUNT: PropTag = PropTag(0x3617_0003);
pub const ROAMING_DATATYPES: PropTag = PropTag(0x7C06_0003);
pub const ROAMING_DICTIONARY: PropTag = PropTag(0x7C07_0102);
pub const ROAMING_XML_STREAM: PropTag = PropTag(0x7C08_0102);
pub const ROAMING_BINARY_STREAM: PropTag = PropTag(0x7C09_0102);

pub mod named {
    use super::*;

    pub const FLAG_REQUEST: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8530,
        },
        ptype: PropType::Unicode,
    };
    pub const REMINDER_SET: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8503,
        },
        ptype: PropType::Bool,
    };
    pub const REMINDER_TIME: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8502,
        },
        ptype: PropType::Time,
    };
    pub const REMINDER_SIGNAL_TIME: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8560,
        },
        ptype: PropType::Time,
    };
    pub const REMINDER_DELTA: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8501,
        },
        ptype: PropType::I32,
    };
    pub const COMMON_START: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8516,
        },
        ptype: PropType::Time,
    };
    pub const COMMON_END: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8517,
        },
        ptype: PropType::Time,
    };
    pub const PRIVATE: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8506,
        },
        ptype: PropType::Bool,
    };
    pub const SIDE_EFFECTS: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_COMMON,
            lid: 0x8510,
        },
        ptype: PropType::I32,
    };
    pub const IS_READ_RECEIPT: NamedProp = NamedProp {
        key: PropKeyRef::Name {
            set: sets::PSETID_MESSAGING,
            name: "IsReadReceipt",
        },
        ptype: PropType::Bool,
    };
    pub const IS_SIGNED: NamedProp = NamedProp {
        key: PropKeyRef::Name {
            set: sets::PSETID_MESSAGING,
            name: "IsSigned",
        },
        ptype: PropType::Bool,
    };
    pub const KEYWORDS: NamedProp = NamedProp {
        key: PropKeyRef::Name {
            set: sets::PS_PUBLIC_STRINGS,
            name: "Keywords",
        },
        ptype: PropType::MvUnicode,
    };
    pub const CONTENT_CLASS: NamedProp = NamedProp {
        key: PropKeyRef::Name {
            set: sets::PS_INTERNET_HEADERS,
            name: "content-class",
        },
        ptype: PropType::Unicode,
    };
    pub const GLOBAL_OBJECT_ID: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_MEETING,
            lid: 0x0003,
        },
        ptype: PropType::Binary,
    };
    pub const CLEAN_GLOBAL_OBJECT_ID: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_MEETING,
            lid: 0x0023,
        },
        ptype: PropType::Binary,
    };
    pub const APPOINTMENT_START_WHOLE: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_APPOINTMENT,
            lid: 0x820D,
        },
        ptype: PropType::Time,
    };
    pub const APPOINTMENT_END_WHOLE: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_APPOINTMENT,
            lid: 0x820E,
        },
        ptype: PropType::Time,
    };
    pub const APPOINTMENT_RECUR: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_APPOINTMENT,
            lid: 0x8216,
        },
        ptype: PropType::Binary,
    };
    pub const BUSY_STATUS: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_APPOINTMENT,
            lid: 0x8205,
        },
        ptype: PropType::I32,
    };
    pub const LOCATION: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_APPOINTMENT,
            lid: 0x8208,
        },
        ptype: PropType::Unicode,
    };
    pub const EMAIL1_EMAIL_ADDRESS: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_ADDRESS,
            lid: 0x8083,
        },
        ptype: PropType::Unicode,
    };
    pub const FILE_UNDER: NamedProp = NamedProp {
        key: PropKeyRef::Lid {
            set: sets::PSETID_ADDRESS,
            lid: 0x8005,
        },
        ptype: PropType::Unicode,
    };
}
