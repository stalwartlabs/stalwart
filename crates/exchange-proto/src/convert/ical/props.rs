/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::Guid,
    mapi::prop::{
        PropId, PropKey, PropKeyRef,
        sets::{PSETID_APPOINTMENT, PSETID_COMMON, PSETID_MEETING},
    },
};

pub(crate) const CLASS_APPOINTMENT: &str = "IPM.Appointment";
pub(super) const CLASS_REQUEST: &str = "IPM.Schedule.Meeting.Request";
pub(super) const CLASS_CANCELED: &str = "IPM.Schedule.Meeting.Canceled";
pub(super) const CLASS_RESP_POS: &str = "IPM.Schedule.Meeting.Resp.Pos";
pub(super) const CLASS_RESP_TENT: &str = "IPM.Schedule.Meeting.Resp.Tent";
pub(super) const CLASS_RESP_NEG: &str = "IPM.Schedule.Meeting.Resp.Neg";
pub(super) const CLASS_EXCEPTION: &str = "IPM.OLE.CLASS.{00061055-0000-0000-C000-000000000046}";

pub(super) const CUSTOM_KEY_NAME: &str = "Customized Time Zone";
pub(super) const UTC_KEY_NAME: &str = "UTC";
pub(super) const REMINDER_DESCRIPTION: &str = "Reminder";
pub(super) const BUSY_STATUS_NAME: &str = "X-MICROSOFT-CDO-BUSYSTATUS";
pub(super) const INTENDED_STATUS_NAME: &str = "X-MICROSOFT-CDO-INTENDEDSTATUS";
pub(super) const CDO_IMPORTANCE_NAME: &str = "X-MICROSOFT-CDO-IMPORTANCE";
pub(super) const CDO_SEQUENCE_NAME: &str = "X-MICROSOFT-CDO-APPT-SEQUENCE";
pub(super) const DISALLOW_COUNTER_NAME: &str = "X-MICROSOFT-DISALLOW-COUNTER";
pub(super) const DISALLOW_COUNTER_TRUE: &str = "TRUE";
pub(super) const DRAFT_NAME: &str = "X-MICROSOFT-ISDRAFT";
pub(super) const DRAFT_TRUE: &str = "TRUE";
pub(super) const LAST_SEQUENCE_NAME: &str = "X-MS-OLK-APPTLASTSEQUENCE";
pub(super) const SEQUENCE_TIME_NAME: &str = "X-MS-OLK-APPTSEQTIME";
pub(super) const CONFERENCING_TYPE_NAME: &str = "X-MS-OLK-CONFTYPE";
pub(super) const SEQUENCE_TIME_FORMAT: &str = "%Y%m%dT%H%M%SZ";
pub(super) const PERSONAL_CLASS: &str = "X-PERSONAL";
pub(super) const MAX_SUBJECT_CHARS: usize = 255;
pub(super) const MAX_KEYWORD_CHARS: usize = 255;

pub(super) const REPLY_REQUESTED: PropId = PropId(0x0C17);
pub(super) const RENDERING_POSITION_HIDDEN: i32 = -1;
pub(crate) const RECIPIENT_TRACK_STATUS: PropId = PropId(0x5FFF);
pub(super) const EXCEPTION_REPLACE_TIME: PropId = PropId(0x7FF9);
pub(super) const EXCEPTION_START_TIME: PropId = PropId(0x7FFB);
pub(super) const EXCEPTION_END_TIME: PropId = PropId(0x7FFC);
pub(super) const ATTACHMENT_FLAGS: PropId = PropId(0x7FFD);
pub(super) const ATTACHMENT_FLAG_EXCEPTION: i32 = 0x2;
pub(crate) const RECIPIENT_FLAG_ORGANIZER: i32 = 0x2;

pub(crate) mod state_flags {
    pub const MEETING: i32 = 0x1;
    pub const RECEIVED: i32 = 0x2;
    pub const CANCELED: i32 = 0x4;
}

pub(crate) mod meeting_type {
    pub const EMPTY: i32 = 0;
    pub const REQUEST: i32 = 0x0000_0001;
    pub const FULL: i32 = 0x0001_0000;
}

pub(crate) mod busy {
    pub const FREE: i32 = 0;
    pub const TENTATIVE: i32 = 1;
    pub const BUSY: i32 = 2;
    pub const OOF: i32 = 3;
    pub const WORKING_ELSEWHERE: i32 = 4;
    pub const NO_DATA: i32 = -1;
}

pub(crate) mod track_status {
    pub const NONE: i32 = 0;
    pub const ORGANIZED: i32 = 1;
    pub const TENTATIVE: i32 = 2;
    pub const ACCEPTED: i32 = 3;
    pub const DECLINED: i32 = 4;
    pub const NOT_RESPONDED: i32 = 5;
}

pub(super) mod importance {
    pub const LOW: i32 = 0;
    pub const NORMAL: i32 = 1;
    pub const HIGH: i32 = 2;
}

pub(super) mod sensitivity {
    pub const NORMAL: i32 = 0;
    pub const PERSONAL: i32 = 1;
    pub const PRIVATE: i32 = 2;
    pub const CONFIDENTIAL: i32 = 3;
}

#[derive(Clone, Copy)]
pub(crate) struct Lid {
    pub set: Guid,
    pub lid: u32,
}

impl Lid {
    pub const fn appointment(lid: u32) -> Self {
        Lid {
            set: PSETID_APPOINTMENT,
            lid,
        }
    }

    pub const fn common(lid: u32) -> Self {
        Lid {
            set: PSETID_COMMON,
            lid,
        }
    }

    pub const fn meeting(lid: u32) -> Self {
        Lid {
            set: PSETID_MEETING,
            lid,
        }
    }

    pub const fn key(self) -> PropKey {
        PropKey::lid(self.set, self.lid)
    }

    pub const fn prop(self) -> PropKeyRef<'static> {
        PropKeyRef::Lid {
            set: self.set,
            lid: self.lid,
        }
    }
}

pub(crate) const SEQUENCE: Lid = Lid::appointment(0x8201);
pub(super) const SEQUENCE_TIME: Lid = Lid::appointment(0x8202);
pub(super) const LAST_SEQUENCE: Lid = Lid::appointment(0x8203);
pub(crate) const BUSY_STATUS: Lid = Lid::appointment(0x8205);
pub(super) const F_EXCEPTIONAL_BODY: Lid = Lid::appointment(0x8206);
pub(crate) const LOCATION: Lid = Lid::appointment(0x8208);
pub(crate) const START_WHOLE: Lid = Lid::appointment(0x820D);
pub(crate) const END_WHOLE: Lid = Lid::appointment(0x820E);
pub(crate) const DURATION: Lid = Lid::appointment(0x8213);
pub(crate) const SUB_TYPE: Lid = Lid::appointment(0x8215);
pub(crate) const RECUR: Lid = Lid::appointment(0x8216);
pub(crate) const STATE_FLAGS: Lid = Lid::appointment(0x8217);
pub(super) const RESPONSE_STATUS: Lid = Lid::appointment(0x8218);
pub(crate) const RECURRING: Lid = Lid::appointment(0x8223);
pub(super) const INTENDED_BUSY_STATUS: Lid = Lid::appointment(0x8224);
pub(super) const EXCEPTION_REPLACE: Lid = Lid::appointment(0x8228);
pub(crate) const F_INVITED: Lid = Lid::appointment(0x8229);
pub(super) const RECURRENCE_TYPE: Lid = Lid::appointment(0x8231);
pub(super) const TZ_STRUCT: Lid = Lid::appointment(0x8233);
pub(super) const TZ_DESCRIPTION: Lid = Lid::appointment(0x8234);
pub(super) const CLIP_START: Lid = Lid::appointment(0x8235);
pub(super) const CLIP_END: Lid = Lid::appointment(0x8236);
pub(crate) const CONFERENCING_TYPE: Lid = Lid::appointment(0x8241);
pub(super) const COUNTER_PROPOSAL: Lid = Lid::appointment(0x8257);
pub(crate) const TZDEF_START: Lid = Lid::appointment(0x825E);
pub(crate) const TZDEF_END: Lid = Lid::appointment(0x825F);
pub(super) const TZDEF_RECUR: Lid = Lid::appointment(0x8260);
pub(super) const ATTENDEE_CRITICAL_CHANGE: Lid = Lid::meeting(0x0001);
pub(super) const WHERE: Lid = Lid::meeting(0x0002);
pub(super) const GLOBAL_OBJECT_ID: Lid = Lid::meeting(0x0003);
pub(super) const IS_RECURRING: Lid = Lid::meeting(0x0005);
pub(crate) const IS_EXCEPTION: Lid = Lid::meeting(0x000A);
pub(crate) const OWNER_CRITICAL_CHANGE: Lid = Lid::meeting(0x001A);
pub(crate) const CLEAN_GLOBAL_OBJECT_ID: Lid = Lid::meeting(0x0023);
pub(super) const APPOINTMENT_MESSAGE_CLASS: Lid = Lid::meeting(0x0024);
pub(super) const MEETING_TYPE: Lid = Lid::meeting(0x0026);
pub(crate) const REMINDER_DELTA: Lid = Lid::common(0x8501);
pub(crate) const REMINDER_TIME: Lid = Lid::common(0x8502);
pub(crate) const REMINDER_SET: Lid = Lid::common(0x8503);
pub(super) const COMMON_START: Lid = Lid::common(0x8516);
pub(super) const COMMON_END: Lid = Lid::common(0x8517);
pub(crate) const REMINDER_SIGNAL_TIME: Lid = Lid::common(0x8560);
