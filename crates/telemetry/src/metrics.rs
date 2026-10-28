/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use trc::atomics::histogram::AtomicHistogram;

pub const HISTOGRAM_BUCKETS: usize = 12;
pub const HISTOGRAM_BOUNDS: usize = HISTOGRAM_BUCKETS - 1;
const SECONDS_UNIT: &str = "s";
const MILLIS_PER_SECOND: f64 = 1000.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricScale {
    Identity,
    MillisToSeconds,
}

pub struct HistogramSnapshot {
    pub buckets: [u64; HISTOGRAM_BUCKETS],
    pub bounds: [u64; HISTOGRAM_BOUNDS],
    pub count: u64,
    pub sum: u64,
    pub min: Option<u64>,
    pub max: Option<u64>,
}

impl MetricScale {
    #[inline(always)]
    pub fn from_otel_unit(unit: &str) -> Self {
        if unit == SECONDS_UNIT {
            MetricScale::MillisToSeconds
        } else {
            MetricScale::Identity
        }
    }

    #[inline(always)]
    pub fn apply(self, value: u64) -> f64 {
        match self {
            MetricScale::Identity => value as f64,
            MetricScale::MillisToSeconds => value as f64 / MILLIS_PER_SECOND,
        }
    }
}

impl HistogramSnapshot {
    pub fn new(histogram: &AtomicHistogram<HISTOGRAM_BUCKETS>) -> Self {
        let mut buckets = [0u64; HISTOGRAM_BUCKETS];
        for (slot, value) in buckets.iter_mut().zip(histogram.buckets_iter()) {
            *slot = value;
        }
        let mut bounds = [0u64; HISTOGRAM_BOUNDS];
        for (slot, value) in bounds.iter_mut().zip(histogram.upper_bounds_iter()) {
            *slot = value;
        }
        Self {
            count: buckets.iter().sum(),
            buckets,
            bounds,
            sum: histogram.sum(),
            min: histogram.min(),
            max: histogram.max(),
        }
    }
}
