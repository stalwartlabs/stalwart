/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::config::cron::SimpleCron;

#[allow(clippy::derivable_impls)]
pub mod enums;
pub mod enums_impl;
pub mod prelude;
pub mod properties;
pub mod properties_impl;
#[allow(clippy::large_enum_variant)]
pub mod structs;
#[allow(clippy::derivable_impls)]
pub mod structs_impl;

impl From<prelude::Cron> for SimpleCron {
    fn from(value: prelude::Cron) -> Self {
        match value {
            prelude::Cron::Daily(cron) => SimpleCron::Day {
                hour: cron.hour as u32,
                minute: cron.minute as u32,
            },
            prelude::Cron::Weekly(cron) => SimpleCron::Week {
                day: cron.day as u32,
                hour: cron.hour as u32,
                minute: cron.minute as u32,
            },
            prelude::Cron::Hourly(cron) => SimpleCron::Hour {
                minute: cron.minute as u32,
            },
        }
    }
}
