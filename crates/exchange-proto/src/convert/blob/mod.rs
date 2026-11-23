/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

pub mod goid;
pub mod recur;
pub mod tz;

pub use goid::GlobalObjectId;
pub use recur::{
    AppointmentRecur, ExceptionInfo, PatternType, RecurAnchor, RecurEnd, RecurFrequency,
    RecurrencePattern, TaskAnchor, TaskRecur, TaskRecurError, Unmappable,
};
pub(crate) use recur::{RuleCount, local_from_minutes, local_minutes, with_seconds_of};
pub use tz::{TERRITORY_ZONES, TzDefinition, TzRule, TzStruct, iana_to_windows};
