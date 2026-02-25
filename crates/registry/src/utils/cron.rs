/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::schema::prelude::Cron;
use utils::cron::SimpleCron;

impl From<Cron> for SimpleCron {
    fn from(value: Cron) -> Self {
        match value {
            Cron::Daily(cron) => SimpleCron::Day {
                hour: cron.hour as u32,
                minute: cron.minute as u32,
            },
            Cron::Weekly(cron) => SimpleCron::Week {
                day: cron.day as u32,
                hour: cron.hour as u32,
                minute: cron.minute as u32,
            },
            Cron::Hourly(cron) => SimpleCron::Hour {
                minute: cron.minute as u32,
            },
        }
    }
}
