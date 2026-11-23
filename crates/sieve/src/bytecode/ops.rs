/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Corrupt, Decoded,
    cursor::{Code, Cursor},
    rec::{Range, Rec, Str},
};

pub(crate) trait Field: Sized {
    fn read(c: &mut Cursor<'_>) -> Decoded<Self>;
    fn write(&self, w: &mut Code);
}

macro_rules! primitive_field {
    ($($ty:ty => $read:ident),* $(,)?) => {
        $(
            impl Field for $ty {
                #[inline(always)]
                fn read(c: &mut Cursor<'_>) -> Decoded<Self> {
                    c.$read()
                }

                fn write(&self, w: &mut Code) {
                    w.$read(*self);
                }
            }
        )*
    };
}

primitive_field!(
    u8 => u8,
    bool => bool,
    u16 => u16,
    u32 => u32,
    i32 => i32,
    u64 => u64,
    i64 => i64,
    Rec => rec,
    Range => range,
    Str => str,
    Option<i32> => opt_i32,
    Option<u32> => opt_u32,
    Option<u64> => opt_u64,
    Option<i64> => opt_i64,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Jump(pub u32);

impl Field for Jump {
    #[inline(always)]
    fn read(c: &mut Cursor<'_>) -> Decoded<Self> {
        c.jump().map(Jump)
    }

    fn write(&self, w: &mut Code) {
        w.u32(self.0);
    }
}

macro_rules! composite_field {
    ($( $name:ident { $( $field:ident : $ty:ty ),* $(,)? } )*) => {
        $(
            #[derive(Debug, Clone, Copy, PartialEq, Default)]
            pub(crate) struct $name {
                $( pub $field: $ty, )*
            }

            impl Field for $name {
                #[inline(always)]
                fn read(c: &mut Cursor<'_>) -> Decoded<Self> {
                    Ok(Self {
                        $( $field: <$ty as Field>::read(c)?, )*
                    })
                }

                fn write(&self, w: &mut Code) {
                    $( <$ty as Field>::write(&self.$field, w); )*
                }
            }
        )*
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct Match {
    pub kind: u8,
    pub arg: u64,
}

impl Field for Match {
    #[inline(always)]
    fn read(c: &mut Cursor<'_>) -> Decoded<Self> {
        let kind = c.u8()?;
        let arg = if matches!(kind, match_kind::MATCHES | match_kind::REGEX) {
            c.mask()?
        } else {
            c.u64()?
        };
        Ok(Match { kind, arg })
    }

    fn write(&self, w: &mut Code) {
        w.u8(self.kind);
        w.u64(self.arg);
    }
}

composite_field! {
    MimeOpts { kind: u8, params: Range }
    Fcc { present: bool, mailbox: Rec, mailbox_id: Rec, create: bool, flags: Range, special_use: Rec }
    ByTime { kind: u8, mode: u8, trace: bool, rlimit: u64, alimit: Rec }
    Zone { kind: u8, time: i64 }
    Period { kind: u8, value: u64 }
    DupMatch { kind: u8, value: Rec }
    MetadataRef { kind: u8, name: Rec, annotation: Rec }
    NotifySpec { kind: u8, items: Range }
    BodyTransform { kind: u8, content_types: Range }
}

pub(crate) mod match_kind {
    pub const IS: u8 = 0;
    pub const CONTAINS: u8 = 1;
    pub const MATCHES: u8 = 2;
    pub const REGEX: u8 = 3;
    pub const VALUE: u8 = 4;
    pub const COUNT: u8 = 5;
    pub const LIST: u8 = 6;
}

macro_rules! ops {
    ($( $name:ident = $code:expr => { $( $field:ident : $ty:ty ),* $(,)? } )*) => {
        $(
            #[derive(Debug, Clone, Copy, PartialEq, Default)]
            pub(crate) struct $name {
                $( pub $field: $ty, )*
            }

            impl $name {
                pub(crate) const OP: u8 = $code;

                #[inline(always)]
                pub(crate) fn decode(c: &mut Cursor<'_>) -> Decoded<Self> {
                    let _ = &c;
                    Ok(Self {
                        $( $field: <$ty as Field>::read(c)?, )*
                    })
                }

                pub(crate) fn emit(&self, w: &mut Code) {
                    w.u8(Self::OP);
                    $( <$ty as Field>::write(&self.$field, w); )*
                }
            }
        )*

        pub(crate) fn skip_op(op: u8, c: &mut Cursor<'_>) -> Decoded<()> {
            match op {
                $( $code => $name::decode(c).map(|_| ()), )*
                _ => Err(Corrupt),
            }
        }
    };
}

ops! {
    Require = 0 => { capabilities: Range }
    Keep = 1 => { flags: Range }
    FileInto = 2 => { copy: bool, create: bool, folder: Rec, flags: Range, mailbox_id: Rec, special_use: Rec }
    Redirect = 3 => { copy: bool, list: bool, address: Rec, notify: NotifySpec, ret: u8, by_time: ByTime }
    Discard = 4 => {}
    Stop = 5 => {}
    Invalid = 6 => { name: Str, line_num: u32, line_pos: u32 }
    TestTrue = 7 => {}
    TestFalse = 8 => {}
    TestAddress = 9 => { header_list: Range, key_list: Range, address_part: u8, match_type: Match, comparator: u8, index: Option<i32>, mime_anychild: bool, is_not: bool }
    TestEnvelope = 10 => { envelope_list: Range, key_list: Range, address_part: u8, match_type: Match, comparator: u8, zone: Option<i64>, is_not: bool }
    TestExists = 11 => { header_names: Range, mime_anychild: bool, is_not: bool }
    TestHeader = 12 => { header_list: Range, key_list: Range, match_type: Match, comparator: u8, index: Option<i32>, mime_opts: MimeOpts, mime_anychild: bool, is_not: bool }
    TestSize = 13 => { over: bool, limit: u64, is_not: bool }
    TestInvalid = 14 => { name: Str, line_num: u32, line_pos: u32 }
    TestBody = 15 => { key_list: Range, body_transform: BodyTransform, match_type: Match, comparator: u8, include_subject: bool, is_not: bool }
    TestConvert = 16 => { from_media_type: Rec, to_media_type: Rec, transcoding_params: Range, is_not: bool }
    Convert = 17 => { from_media_type: Rec, to_media_type: Rec, transcoding_params: Range, is_not: bool }
    TestDate = 18 => { header_name: Rec, key_list: Range, match_type: Match, comparator: u8, index: Option<i32>, zone: Zone, date_part: u8, mime_anychild: bool, is_not: bool }
    TestCurrentDate = 19 => { zone: Zone, match_type: Match, comparator: u8, date_part: u8, key_list: Range, is_not: bool }
    TestDuplicate = 20 => { handle: Rec, dup_match: DupMatch, seconds: Option<u64>, last: bool, is_not: bool }
    TestString = 21 => { match_type: Match, comparator: u8, source: Range, key_list: Range, is_not: bool }
    TestEnvironment = 22 => { match_type: Match, comparator: u8, source: Range, key_list: Range, is_not: bool }
    TestNotifyMethodCapability = 23 => { comparator: u8, match_type: Match, notification_uri: Rec, notification_capability: Rec, key_list: Range, is_not: bool }
    TestValidNotifyMethod = 24 => { notification_uris: Range, is_not: bool }
    TestValidExtList = 25 => { list_names: Range, is_not: bool }
    TestIhave = 26 => { capabilities: Range, is_not: bool }
    TestHasFlag = 27 => { comparator: u8, match_type: Match, variable_list: Range, flags: Range, is_not: bool }
    TestMailboxExists = 28 => { mailbox_names: Range, is_not: bool }
    TestMetadata = 29 => { match_type: Match, comparator: u8, metadata: MetadataRef, key_list: Range, is_not: bool }
    TestMetadataExists = 30 => { mailbox: Rec, annotation_names: Range, is_not: bool }
    TestMailboxIdExists = 31 => { mailbox_ids: Range, is_not: bool }
    TestSpamTest = 32 => { value: Rec, match_type: Match, comparator: u8, percent: bool, is_not: bool }
    TestVirusTest = 33 => { value: Rec, match_type: Match, comparator: u8, is_not: bool }
    TestSpecialUseExists = 34 => { mailbox: Rec, attributes: Range, is_not: bool }
    TestVacation = 35 => { addresses: Range, period: Period, handle: Rec, reason: Rec }
    Jmp = 36 => { target: Jump }
    Jz = 37 => { target: Jump }
    Jnz = 38 => { target: Jump }
    ForEveryPartPush = 39 => {}
    ForEveryPart = 40 => { jz_pos: Jump }
    ForEveryPartPop = 41 => { num_pops: u32 }
    Replace = 42 => { subject: Rec, from: Rec, replacement: Rec, mime: bool }
    Enclose = 43 => { subject: Rec, headers: Range, value: Rec }
    ExtractText = 44 => { modifiers: Range, first: Option<u32>, name: Rec }
    AddHeader = 45 => { last: bool, field_name: Rec, value: Rec }
    DeleteHeader = 46 => { index: Option<i32>, comparator: u8, match_type: Match, field_name: Rec, value_patterns: Range, mime_anychild: bool }
    Set = 47 => { modifiers: Range, name: Rec, value: Rec }
    Clear = 48 => { local_vars_idx: u32, local_vars_num: u32, match_vars: u64 }
    Notify = 49 => { from: Rec, importance: Rec, options: Range, message: Rec, fcc: Fcc, method: Rec }
    Reject = 50 => { ereject: bool, reason: Rec }
    Vacation = 51 => { subject: Rec, from: Rec, mime: bool, fcc: Fcc, reason: Rec }
    Error = 52 => { message: Rec }
    EditFlags = 53 => { action: u8, name: Rec, flags: Range }
    Include = 54 => { global: bool, once: bool, optional: bool, value: Rec }
    Return = 55 => {}
    While = 56 => { expr: Range, jz_pos: Jump }
    Eval = 57 => { expr: Range }
    Let = 58 => { name: Rec, expr: Range }
    TestCmd = 59 => { arguments: Range }
    TestCmdTest = 60 => { arguments: Range, is_not: bool }
}

impl From<TestConvert> for Convert {
    fn from(test: TestConvert) -> Self {
        Convert {
            from_media_type: test.from_media_type,
            to_media_type: test.to_media_type,
            transcoding_params: test.transcoding_params,
            is_not: test.is_not,
        }
    }
}
