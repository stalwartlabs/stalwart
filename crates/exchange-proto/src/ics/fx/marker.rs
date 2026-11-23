/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

macro_rules! markers {
    ($($name:ident = $value:expr),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u32)]
        pub enum Marker {
            $($name = $value,)*
        }

        impl TryFrom<u32> for Marker {
            type Error = u32;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                match value {
                    $($value => Ok(Marker::$name),)*
                    other => Err(other),
                }
            }
        }

        impl Marker {
            pub const ALL: &[Marker] = &[$(Marker::$name,)*];
        }
    };
}

markers! {
    StartTopFld = 0x4009_0003,
    StartSubFld = 0x400A_0003,
    EndFolder = 0x400B_0003,
    StartMessage = 0x400C_0003,
    StartFaiMsg = 0x4010_0003,
    EndMessage = 0x400D_0003,
    StartEmbed = 0x4001_0003,
    EndEmbed = 0x4002_0003,
    StartRecip = 0x4003_0003,
    EndToRecip = 0x4004_0003,
    NewAttach = 0x4000_0003,
    EndAttach = 0x400E_0003,
    IncrSyncChg = 0x4012_0003,
    IncrSyncChgPartial = 0x407D_0003,
    IncrSyncDel = 0x4013_0003,
    IncrSyncEnd = 0x4014_0003,
    IncrSyncRead = 0x402F_0003,
    IncrSyncStateBegin = 0x403A_0003,
    IncrSyncStateEnd = 0x403B_0003,
    IncrSyncProgressMode = 0x4074_000B,
    IncrSyncProgressPerMsg = 0x4075_000B,
    IncrSyncMessage = 0x4015_0003,
    IncrSyncGroupInfo = 0x407B_0102,
    FxErrorInfo = 0x4018_0003,
}

impl Marker {
    pub const fn to_wire(self) -> u32 {
        self as u32
    }

    pub const fn closes(self) -> Option<Marker> {
        match self {
            Marker::StartTopFld | Marker::StartSubFld => Some(Marker::EndFolder),
            Marker::StartMessage | Marker::StartFaiMsg => Some(Marker::EndMessage),
            Marker::StartEmbed => Some(Marker::EndEmbed),
            Marker::StartRecip => Some(Marker::EndToRecip),
            Marker::NewAttach => Some(Marker::EndAttach),
            Marker::IncrSyncStateBegin => Some(Marker::IncrSyncStateEnd),
            _ => None,
        }
    }
}

pub mod meta {
    use crate::mapi::prop::PropTag;

    pub const FX_DEL_PROP: PropTag = PropTag(0x4016_0003);
    pub const EC_WARNING: PropTag = PropTag(0x400F_0003);
    pub const DN_PREFIX: PropTag = PropTag(0x4008_001E);
    pub const NEW_FX_FOLDER: PropTag = PropTag(0x4011_0102);
    pub const INCR_SYNC_GROUP_ID: PropTag = PropTag(0x407C_0003);
    pub const INCREMENTAL_SYNC_MESSAGE_PARTIAL: PropTag = PropTag(0x407A_0003);
    pub const IDSET_GIVEN: PropTag = PropTag(0x4017_0003);
    pub const IDSET_GIVEN_BINARY: PropTag = PropTag(0x4017_0102);
    pub const CNSET_SEEN: PropTag = PropTag(0x6796_0102);
    pub const CNSET_SEEN_FAI: PropTag = PropTag(0x67DA_0102);
    pub const CNSET_READ: PropTag = PropTag(0x67D2_0102);
    pub const IDSET_DELETED: PropTag = PropTag(0x67E5_0102);
    pub const IDSET_NO_LONGER_IN_SCOPE: PropTag = PropTag(0x4021_0102);
    pub const IDSET_EXPIRED: PropTag = PropTag(0x6793_0102);
    pub const IDSET_READ: PropTag = PropTag(0x402D_0102);
    pub const IDSET_UNREAD: PropTag = PropTag(0x402E_0102);
    pub const PROGRESS_INFORMATION: PropTag = PropTag(0x0000_0102);
    pub const PROGRESS_MESSAGE_SIZE: PropTag = PropTag(0x0000_0003);
    pub const PROGRESS_MESSAGE_FAI: PropTag = PropTag(0x0000_000B);

    pub const fn is_ics_meta(tag: PropTag) -> bool {
        matches!(
            tag.id().0,
            0x4017 | 0x6796 | 0x67DA | 0x67D2 | 0x67E5 | 0x4021 | 0x6793 | 0x402D | 0x402E
        )
    }
}

pub mod tags {
    use crate::mapi::prop::PropTag;

    pub const SOURCE_KEY: PropTag = PropTag(0x65E0_0102);
    pub const PARENT_SOURCE_KEY: PropTag = PropTag(0x65E1_0102);
    pub const CHANGE_KEY: PropTag = PropTag(0x65E2_0102);
    pub const PREDECESSOR_CHANGE_LIST: PropTag = PropTag(0x65E3_0102);
    pub const LAST_MODIFICATION_TIME: PropTag = PropTag(0x3008_0040);
    pub const ASSOCIATED: PropTag = PropTag(0x67AA_000B);
    pub const MID: PropTag = PropTag(0x674A_0014);
    pub const FOLDER_ID: PropTag = PropTag(0x6748_0014);
    pub const PARENT_FOLDER_ID: PropTag = PropTag(0x6749_0014);
    pub const MESSAGE_SIZE: PropTag = PropTag(0x0E08_0003);
    pub const CHANGE_NUMBER: PropTag = PropTag(0x67A4_0014);
    pub const DISPLAY_NAME: PropTag = PropTag(0x3001_001F);
    pub const ATTACH_NUMBER: PropTag = PropTag(0x0E21_0003);
    pub const MESSAGE_RECIPIENTS: PropTag = PropTag(0x0E12_000D);
    pub const MESSAGE_ATTACHMENTS: PropTag = PropTag(0x0E13_000D);
    pub const CONTAINER_HIERARCHY: PropTag = PropTag(0x360E_000D);
    pub const CONTAINER_CONTENTS: PropTag = PropTag(0x360F_000D);
    pub const FOLDER_ASSOCIATED_CONTENTS: PropTag = PropTag(0x3610_000D);
}
