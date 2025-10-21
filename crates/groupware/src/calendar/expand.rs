/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ArchivedCalendarEventData;
use crate::calendar::CalendarEventData;
use ahash::AHashSet;
use calcard::common::timezone::Tz;
use chrono::{DateTime, TimeZone};
use store::write::bitpack::BitpackIterator;
use types::TimeRange;
use utils::codec::leb128::Leb128Reader;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarEventExpansion {
    pub comp_id: u32,
    pub expansion_id: u32,
    pub start: i64,
    pub end: i64,
}

impl ArchivedCalendarEventData {
    pub fn expand(&self, default_tz: Tz, limit: TimeRange) -> Option<Vec<CalendarEventExpansion>> {
        let mut expansion = Vec::with_capacity(self.time_ranges.len());
        let base_offset = self.base_offset.to_native();
        let mut base_expansion_id = 0;

        'outer: for range in self.time_ranges.iter() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;

            let comp_id = range.id.to_native() as u32;
            let duration = range.duration.to_native() as i64;
            let mut start_tz = Tz::from_id(range.start_tz.to_native())?;
            let mut end_tz = Tz::from_id(range.end_tz.to_native())?;
            let is_todo = self.event.components[comp_id as usize]
                .component_type
                .is_todo();

            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            if instances.len() > bytes_read {
                // Recurring event
                let unpacker =
                    BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count);
                let mut expansion_id = base_expansion_id;
                base_expansion_id += offset_or_count;
                for start_offset in unpacker {
                    let start_date_naive = start_offset as i64 + base_offset;
                    let end_date_naive = start_date_naive + duration;
                    let start = start_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();
                    let end = end_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();

                    if limit.is_in_range(is_todo, start, end) {
                        expansion.push(CalendarEventExpansion {
                            comp_id,
                            expansion_id,
                            start,
                            end,
                        });
                    } else if start > limit.end {
                        continue 'outer;
                    }

                    expansion_id += 1;
                }
            } else {
                // Single event
                let start_date_naive = offset_or_count as i64 + base_offset;
                let end_date_naive = start_date_naive + duration;
                let start = start_tz
                    .from_local_datetime(
                        &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                    )
                    .single()?
                    .timestamp();
                let end = end_tz
                    .from_local_datetime(
                        &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                    )
                    .single()?
                    .timestamp();

                if limit.is_in_range(is_todo, start, end) {
                    expansion.push(CalendarEventExpansion {
                        comp_id,
                        expansion_id: base_expansion_id,
                        start,
                        end,
                    });
                }

                base_expansion_id += 1;
            }
        }

        Some(expansion)
    }
}

impl CalendarEventData {
    pub fn expand_from_ids(
        &self,
        expansion_ids: &mut AHashSet<u32>,
        default_tz: Tz,
    ) -> Option<Vec<CalendarEventExpansion>> {
        let mut expansion = Vec::with_capacity(expansion_ids.len());
        let base_offset = self.base_offset;
        let mut base_expansion_id = 0;

        'outer: for range in self.time_ranges.iter() {
            let instances = range.instances.as_ref();
            let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;
            let mut start_tz = Tz::from_id(range.start_tz)?;
            let mut end_tz = Tz::from_id(range.end_tz)?;

            if start_tz.is_floating() && !default_tz.is_floating() {
                start_tz = default_tz;
            }
            if end_tz.is_floating() && !default_tz.is_floating() {
                end_tz = default_tz;
            }

            if instances.len() > bytes_read {
                let match_range = base_expansion_id..base_expansion_id + offset_or_count;
                let mut match_count = expansion_ids
                    .iter()
                    .filter(|id| match_range.contains(id))
                    .count();
                let mut expansion_id = base_expansion_id;
                base_expansion_id += offset_or_count;

                if match_count > 0 {
                    let unpacker = BitpackIterator::from_bytes_and_offset(
                        instances,
                        bytes_read,
                        offset_or_count,
                    );
                    for start_offset in unpacker {
                        if expansion_ids.remove(&expansion_id) {
                            let start_date_naive = start_offset as i64 + base_offset;
                            let end_date_naive = start_date_naive + range.duration as i64;
                            let start = start_tz
                                .from_local_datetime(
                                    &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                                )
                                .single()?
                                .timestamp();
                            let end = end_tz
                                .from_local_datetime(
                                    &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                                )
                                .single()?
                                .timestamp();

                            expansion.push(CalendarEventExpansion {
                                comp_id: range.id as u32,
                                expansion_id,
                                start,
                                end,
                            });

                            match_count -= 1;
                            if match_count == 0 {
                                if expansion_ids.is_empty() {
                                    break 'outer;
                                } else {
                                    continue 'outer;
                                }
                            }
                        }
                        expansion_id += 1;
                    }
                }
            } else {
                if expansion_ids.remove(&base_expansion_id) {
                    // Single event
                    let start_date_naive = offset_or_count as i64 + base_offset;
                    let end_date_naive = start_date_naive + range.duration as i64;
                    let start = start_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(start_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();
                    let end = end_tz
                        .from_local_datetime(
                            &DateTime::from_timestamp(end_date_naive, 0)?.naive_local(),
                        )
                        .single()?
                        .timestamp();

                    expansion.push(CalendarEventExpansion {
                        comp_id: range.id as u32,
                        expansion_id: base_expansion_id,
                        start,
                        end,
                    });

                    if expansion_ids.is_empty() {
                        break 'outer;
                    }
                }

                base_expansion_id += 1;
            }
        }

        if !expansion_ids.is_empty() {
            expansion.extend(
                expansion_ids
                    .drain()
                    .map(|expansion_id| CalendarEventExpansion {
                        comp_id: u32::MAX,
                        expansion_id,
                        start: i64::MAX,
                        end: i64::MAX,
                    }),
            );
        }

        Some(expansion)
    }

    pub fn expand_single(&self, comp_id: u32, default_tz: Tz) -> Option<CalendarEventExpansion> {
        let range = self.time_ranges.iter().find(|r| r.id as u32 == comp_id)?;
        let instances = range.instances.as_ref();
        let (offset_or_count, bytes_read) = instances.read_leb128::<u32>()?;
        let mut start_tz = Tz::from_id(range.start_tz)?;
        let mut end_tz = Tz::from_id(range.end_tz)?;

        if start_tz.is_floating() && !default_tz.is_floating() {
            start_tz = default_tz;
        }
        if end_tz.is_floating() && !default_tz.is_floating() {
            end_tz = default_tz;
        }
        let start_offset = if instances.len() > bytes_read {
            // Recurring event
            let mut unpacker =
                BitpackIterator::from_bytes_and_offset(instances, bytes_read, offset_or_count);
            unpacker.next()?
        } else {
            // Single event
            offset_or_count
        };
        let start_date_naive = start_offset as i64 + self.base_offset;
        let end_date_naive = start_date_naive + range.duration as i64;
        let start = start_tz
            .from_local_datetime(&DateTime::from_timestamp(start_date_naive, 0)?.naive_local())
            .single()?
            .timestamp();
        let end = end_tz
            .from_local_datetime(&DateTime::from_timestamp(end_date_naive, 0)?.naive_local())
            .single()?
            .timestamp();

        Some(CalendarEventExpansion {
            comp_id,
            expansion_id: u32::MAX,
            start,
            end,
        })
    }
}

impl Default for CalendarEventExpansion {
    fn default() -> Self {
        Self {
            comp_id: u32::MAX,
            expansion_id: u32::MAX,
            start: i64::MAX,
            end: i64::MAX,
        }
    }
}

impl CalendarEventExpansion {
    pub fn is_valid(&self) -> bool {
        self.comp_id != u32::MAX && self.start != i64::MAX && self.end != i64::MAX
    }
}
