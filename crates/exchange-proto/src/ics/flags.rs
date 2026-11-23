/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

macro_rules! flag_set {
    ($name:ident($repr:ty) { $($flag:ident = $value:expr),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name(pub $repr);

        impl $name {
            $(pub const $flag: $repr = $value;)*
            pub const KNOWN: $repr = 0 $(| $value)*;

            pub const fn contains(self, flag: $repr) -> bool {
                self.0 & flag == flag
            }

            pub const fn has_unknown(self) -> bool {
                self.0 & !Self::KNOWN != 0
            }
        }
    };
}

flag_set!(SendOptions(u8) {
    UNICODE = 0x01,
    USE_CPID = 0x02,
    FOR_UPLOAD = 0x03,
    RECOVER_MODE = 0x04,
    FORCE_UNICODE = 0x08,
    PARTIAL_ITEM = 0x10,
    RESERVED1 = 0x20,
    RESERVED2 = 0x40,
});

flag_set!(SynchronizationFlags(u16) {
    UNICODE = 0x0001,
    NO_DELETIONS = 0x0002,
    IGNORE_NO_LONGER_IN_SCOPE = 0x0004,
    READ_STATE = 0x0008,
    FAI = 0x0010,
    NORMAL = 0x0020,
    ONLY_SPECIFIED_PROPERTIES = 0x0080,
    NO_FOREIGN_IDENTIFIERS = 0x0100,
    RESERVED = 0x1000,
    BEST_BODY = 0x2000,
    IGNORE_SPECIFIED_ON_FAI = 0x4000,
    PROGRESS = 0x8000,
});

flag_set!(SynchronizationExtraFlags(u32) {
    EID = 0x0000_0001,
    MESSAGE_SIZE = 0x0000_0002,
    CN = 0x0000_0004,
    ORDER_BY_DELIVERY_TIME = 0x0000_0008,
});

flag_set!(FastTransferCopyFlags(u8) {
    MOVE = 0x01,
    UNUSED1 = 0x02,
    UNUSED2 = 0x04,
    UNUSED3 = 0x08,
    BEST_BODY = 0x10,
    COPY_SUBFOLDERS = 0x10,
    SEND_ENTRY_ID = 0x20,
});

flag_set!(FastTransferCopyToFlags(u32) {
    MOVE = 0x0000_0001,
    UNUSED1 = 0x0000_0002,
    UNUSED2 = 0x0000_0004,
    UNUSED3 = 0x0000_0008,
    UNUSED4 = 0x0000_0200,
    UNUSED5 = 0x0000_0400,
    BEST_BODY = 0x0000_2000,
});

flag_set!(DestinationCopyFlags(u8) {
    MOVE = 0x01,
});

flag_set!(ImportFlags(u8) {
    ASSOCIATED = 0x10,
    FAIL_ON_CONFLICT = 0x40,
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SynchronizationType {
    Contents,
    Hierarchy,
}

impl SynchronizationType {
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(SynchronizationType::Contents),
            0x02 => Some(SynchronizationType::Hierarchy),
            _ => None,
        }
    }

    pub const fn to_wire(self) -> u8 {
        match self {
            SynchronizationType::Contents => 0x01,
            SynchronizationType::Hierarchy => 0x02,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceOperation {
    CopyTo,
    CopyProperties,
    CopyMessages,
    CopyFolder,
}

impl SourceOperation {
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(SourceOperation::CopyTo),
            0x02 => Some(SourceOperation::CopyProperties),
            0x03 => Some(SourceOperation::CopyMessages),
            0x04 => Some(SourceOperation::CopyFolder),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum TransferStatus {
    Error = 0x0000,
    Partial = 0x0001,
    NoRoom = 0x0002,
    Done = 0x0003,
}
