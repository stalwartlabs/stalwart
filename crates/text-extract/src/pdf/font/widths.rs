/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ranges::RangeMap;
use crate::pdf::{
    document::Document,
    object::{Array, Dict, Object},
};

pub(crate) const MAX_WIDTH_ENTRIES: usize = 100_000;
pub(crate) const MAX_WIDTH: f64 = 10_000.0;
pub(crate) const DEFAULT_CID_WIDTH: f32 = 1000.0;
const DEFAULT_VERTICAL_ADVANCE: f32 = -1000.0;
const HORIZONTAL_GROUP: usize = 1;
const VERTICAL_GROUP: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
struct Span {
    lo: u32,
    hi: u32,
    start: u32,
    per_code: bool,
}

#[derive(Debug, Clone, Default)]
struct Runs {
    spans: Box<[Span]>,
    values: Box<[f32]>,
}

#[derive(Debug, Clone)]
pub(crate) struct CidWidths {
    runs: Runs,
    default: f32,
}

#[derive(Debug, Clone)]
pub(crate) struct VerticalAdvances {
    runs: Runs,
    default: f32,
}

impl Runs {
    fn read(doc: &Document<'_>, array: Option<Array<'_>>, group: usize) -> Self {
        let Some(array) = array else {
            return Runs::default();
        };
        let mut map = RangeMap::default();
        read_groups(doc, array, group, &mut map);
        let mut spans: Vec<Span> = Vec::new();
        let mut values: Vec<f32> = Vec::new();
        for (lo, hi, value) in map.entries() {
            let (Ok(lo), Ok(hi), Ok(start)) = (
                u32::try_from(lo),
                u32::try_from(hi),
                u32::try_from(values.len()),
            ) else {
                continue;
            };
            let adjacent = |span: &Span| span.hi.checked_add(1) == Some(lo);
            match spans.last_mut() {
                Some(last)
                    if !last.per_code
                        && adjacent(last)
                        && values.get(last.start as usize) == Some(&value) =>
                {
                    last.hi = hi;
                }
                Some(last) if last.per_code && lo == hi && adjacent(last) => {
                    last.hi = hi;
                    values.push(value);
                }
                _ => {
                    spans.push(Span {
                        lo,
                        hi,
                        start,
                        per_code: lo == hi,
                    });
                    values.push(value);
                }
            }
        }
        Runs {
            spans: spans.into_boxed_slice(),
            values: values.into_boxed_slice(),
        }
    }

    fn find(&self, cid: u32) -> Option<f32> {
        let index = self.spans.partition_point(|span| span.lo <= cid);
        let span = self.spans.get(index.checked_sub(1)?)?;
        if cid > span.hi {
            return None;
        }
        let offset = if span.per_code { cid - span.lo } else { 0 };
        self.values
            .get(span.start as usize + offset as usize)
            .copied()
    }

    fn heap_size(&self) -> usize {
        self.spans.len() * std::mem::size_of::<Span>()
            + self.values.len() * std::mem::size_of::<f32>()
    }
}

pub(crate) fn sanitize(value: f64) -> Option<f32> {
    value
        .is_finite()
        .then(|| value.clamp(-MAX_WIDTH, MAX_WIDTH) as f32)
}

impl CidWidths {
    pub(crate) fn empty() -> Self {
        CidWidths {
            runs: Runs::default(),
            default: DEFAULT_CID_WIDTH,
        }
    }

    pub(crate) fn load(doc: &Document<'_>, dict: Dict<'_>) -> Self {
        let default = doc
            .get_f64(dict, b"DW")
            .and_then(sanitize)
            .unwrap_or(DEFAULT_CID_WIDTH);
        CidWidths {
            runs: Runs::read(doc, doc.get_array(dict, b"W"), HORIZONTAL_GROUP),
            default,
        }
    }

    pub(crate) fn width(&self, cid: u32) -> f32 {
        self.runs.find(cid).unwrap_or(self.default)
    }

    pub(crate) fn default_width(&self) -> f32 {
        self.default
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.runs.heap_size()
    }
}

impl VerticalAdvances {
    pub(crate) fn empty() -> Self {
        VerticalAdvances {
            runs: Runs::default(),
            default: DEFAULT_VERTICAL_ADVANCE,
        }
    }

    pub(crate) fn default_advance(&self) -> f32 {
        self.default
    }

    pub(crate) fn load(doc: &Document<'_>, dict: Dict<'_>) -> Self {
        let default = doc
            .get_array(dict, b"DW2")
            .and_then(|array| doc.array_iter(array).nth(1))
            .and_then(|value| value.as_f64())
            .and_then(sanitize)
            .unwrap_or(DEFAULT_VERTICAL_ADVANCE);
        VerticalAdvances {
            runs: Runs::read(doc, doc.get_array(dict, b"W2"), VERTICAL_GROUP),
            default,
        }
    }

    pub(crate) fn advance(&self, cid: u32) -> f32 {
        self.runs.find(cid).unwrap_or(self.default)
    }

    pub(crate) fn heap_size(&self) -> usize {
        self.runs.heap_size()
    }
}

fn read_groups(doc: &Document<'_>, array: Array<'_>, group: usize, map: &mut RangeMap<f32>) {
    let mut pending = [0f64; 2 + VERTICAL_GROUP];
    let mut count = 0usize;
    for item in doc.array_iter(array) {
        if map.len() >= MAX_WIDTH_ENTRIES {
            break;
        }
        match item {
            Object::Array(inner) => {
                if count == 1
                    && let [start, ..] = pending
                    && let Some(first) = code(start)
                {
                    read_list(doc, inner, first, group, map);
                }
                count = 0;
            }
            other => match other.as_f64() {
                Some(value) => {
                    if let Some(slot) = pending.get_mut(count) {
                        *slot = value;
                    }
                    count += 1;
                    if count == 2 + group {
                        let [lo, hi, width, ..] = pending;
                        if let (Some(lo), Some(hi), Some(width)) =
                            (code(lo), code(hi), sanitize(width))
                        {
                            map.push(lo, hi, width);
                        }
                        count = 0;
                    }
                }
                None => count = 0,
            },
        }
    }
    map.finish();
}

fn read_list(
    doc: &Document<'_>,
    list: Array<'_>,
    first: u64,
    group: usize,
    map: &mut RangeMap<f32>,
) {
    let mut cid = first;
    for (index, value) in doc.array_iter(list).enumerate() {
        if map.len() >= MAX_WIDTH_ENTRIES {
            return;
        }
        if index % group != 0 {
            continue;
        }
        if let Some(width) = value.as_f64().and_then(sanitize) {
            map.push(cid, cid, width);
        }
        cid = cid.saturating_add(1);
    }
}

fn code(value: f64) -> Option<u64> {
    (value.is_finite() && (0.0..=f64::from(u32::MAX)).contains(&value)).then_some(value as u64)
}
