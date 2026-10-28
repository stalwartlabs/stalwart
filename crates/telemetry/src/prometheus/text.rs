/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    PromFormat,
    number::{write_canonical_f64, write_f64, write_u64},
};
use crate::metrics::{HistogramSnapshot, MetricScale};
use trc::Collector;

const COUNTER_SUFFIX: &str = "_total";
const EOF_MARKER: &[u8] = b"# EOF\n";

#[derive(Clone, Copy)]
enum FamilyType {
    Counter,
    Gauge,
    Histogram,
}

impl FamilyType {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            FamilyType::Counter => b"counter",
            FamilyType::Gauge => b"gauge",
            FamilyType::Histogram => b"histogram",
        }
    }
}

pub fn write_prometheus(out: &mut Vec<u8>, format: PromFormat, is_enterprise: bool) {
    let om = format.is_open_metrics();

    for counter in Collector::collect_counters(is_enterprise) {
        let event = counter.id();
        let name = event.prom_metric_name();
        if name.is_empty() {
            continue;
        }
        let family = if om {
            name.strip_suffix(COUNTER_SUFFIX).unwrap_or(name)
        } else {
            name
        };
        write_metadata(
            out,
            om,
            family,
            FamilyType::Counter,
            "",
            event.description(),
        );
        out.extend_from_slice(name.as_bytes());
        out.push(b' ');
        write_u64(out, counter.value());
        out.push(b'\n');
    }

    for gauge in Collector::collect_gauges(is_enterprise) {
        let metric_type = gauge.id();
        let name = metric_type.prom_name();
        if name.is_empty() {
            continue;
        }
        write_metadata(
            out,
            om,
            name,
            FamilyType::Gauge,
            metric_type.prom_unit(),
            metric_type.description(),
        );
        out.extend_from_slice(name.as_bytes());
        out.push(b' ');
        match MetricScale::from_otel_unit(metric_type.otel_unit()) {
            MetricScale::Identity => write_u64(out, gauge.get()),
            scale => write_f64(out, scale.apply(gauge.get())),
        }
        out.push(b'\n');
    }

    for histogram in Collector::collect_histograms(is_enterprise) {
        let metric_type = histogram.id();
        let name = metric_type.prom_name();
        if name.is_empty() {
            continue;
        }
        let scale = MetricScale::from_otel_unit(metric_type.otel_unit());
        let snapshot = HistogramSnapshot::new(histogram);
        write_metadata(
            out,
            om,
            name,
            FamilyType::Histogram,
            metric_type.prom_unit(),
            metric_type.description(),
        );

        let mut cumulative = 0u64;
        for (bound, bucket) in snapshot.bounds.iter().zip(snapshot.buckets.iter()) {
            cumulative += bucket;
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"_bucket{le=\"");
            match (scale, om) {
                (MetricScale::Identity, false) => write_u64(out, *bound),
                (_, false) => write_f64(out, scale.apply(*bound)),
                (_, true) => write_canonical_f64(out, scale.apply(*bound)),
            }
            out.extend_from_slice(b"\"} ");
            write_u64(out, cumulative);
            out.push(b'\n');
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"_bucket{le=\"+Inf\"} ");
        write_u64(out, snapshot.count);
        out.push(b'\n');

        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"_sum ");
        match scale {
            MetricScale::Identity => write_u64(out, snapshot.sum),
            scale => write_f64(out, scale.apply(snapshot.sum)),
        }
        out.push(b'\n');

        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b"_count ");
        write_u64(out, snapshot.count);
        out.push(b'\n');
    }

    if om {
        out.extend_from_slice(EOF_MARKER);
    }
}

fn write_metadata(
    out: &mut Vec<u8>,
    om: bool,
    family: &str,
    family_type: FamilyType,
    unit: &str,
    help: &str,
) {
    if om {
        write_type(out, family, family_type);
        if !unit.is_empty() {
            out.extend_from_slice(b"# UNIT ");
            out.extend_from_slice(family.as_bytes());
            out.push(b' ');
            out.extend_from_slice(unit.as_bytes());
            out.push(b'\n');
        }
        write_help(out, family, help, om);
    } else {
        write_help(out, family, help, om);
        write_type(out, family, family_type);
    }
}

#[inline(always)]
fn write_type(out: &mut Vec<u8>, family: &str, family_type: FamilyType) {
    out.extend_from_slice(b"# TYPE ");
    out.extend_from_slice(family.as_bytes());
    out.push(b' ');
    out.extend_from_slice(family_type.as_bytes());
    out.push(b'\n');
}

#[inline(always)]
fn write_help(out: &mut Vec<u8>, family: &str, help: &str, escape_quotes: bool) {
    out.extend_from_slice(b"# HELP ");
    out.extend_from_slice(family.as_bytes());
    out.push(b' ');
    write_escaped(out, help.as_bytes(), escape_quotes);
    out.push(b'\n');
}

pub fn write_escaped(out: &mut Vec<u8>, mut text: &[u8], escape_quotes: bool) {
    loop {
        let found = if escape_quotes {
            memchr::memchr3(b'\\', b'\n', b'"', text)
        } else {
            memchr::memchr2(b'\\', b'\n', text)
        };
        let Some((head, special, tail)) = found.and_then(|pos| {
            let (head, rest) = text.split_at_checked(pos)?;
            let (special, tail) = rest.split_first()?;
            Some((head, *special, tail))
        }) else {
            out.extend_from_slice(text);
            return;
        };
        out.extend_from_slice(head);
        out.extend_from_slice(match special {
            b'\n' => b"\\n",
            b'"' => b"\\\"",
            _ => b"\\\\",
        });
        text = tail;
    }
}
