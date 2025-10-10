/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use groupware::calendar::{
    CALENDAR_AVAILABILITY_ALL, CALENDAR_AVAILABILITY_ATTENDING, CALENDAR_AVAILABILITY_NONE,
};
use jmap_proto::object::calendar::IncludeInAvailability;

pub mod get;
pub mod set;

pub(crate) trait Availability: Sized {
    fn from_flags(flags: u16) -> Option<Self>;
}

impl Availability for IncludeInAvailability {
    fn from_flags(flags: u16) -> Option<Self> {
        if flags & CALENDAR_AVAILABILITY_ALL != 0 {
            Some(IncludeInAvailability::All)
        } else if flags & CALENDAR_AVAILABILITY_ATTENDING != 0 {
            Some(IncludeInAvailability::Attending)
        } else if flags & CALENDAR_AVAILABILITY_NONE != 0 {
            Some(IncludeInAvailability::None)
        } else {
            None
        }
    }
}
