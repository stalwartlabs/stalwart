/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{CODE_COUNT, SimpleKind, WIDTH_SCALE};
use crate::pdf::{document::Document, font::widths::sanitize, object::Dict, tables::StandardFont};

const DEFAULT_TYPE3_SCALE: f64 = 0.001;
const MATRIX_LEN: usize = 6;
const SERIF_HINTS: &[&[u8]] = &[
    b"Times",
    b"Serif",
    b"Roman",
    b"Georgia",
    b"Garamond",
    b"Book",
    b"Cambria",
    b"Palatino",
    b"Minion",
];
const SANS_HINT: &[u8] = b"Sans";
const BOLD_HINTS: &[&[u8]] = &[b"Bold", b"Black", b"Heavy"];
const WIDTH_ALIASES: &[(&[u8], &[u8])] = &[
    (b"nbspace", b"space"),
    (b"nonbreakingspace", b"space"),
    (b"sfthyphen", b"hyphen"),
    (b"softhyphen", b"hyphen"),
];

pub(super) struct Widths {
    pub(super) explicit: Box<[Option<f32>; CODE_COUNT]>,
    pub(super) missing: Option<f32>,
    pub(super) type3_scale: f32,
    pub(super) type3_em: f64,
}

impl Widths {
    pub(super) fn load(
        doc: &Document<'_>,
        dict: Dict<'_>,
        descriptor: Option<Dict<'_>>,
        kind: SimpleKind,
    ) -> Self {
        let (type3_scale, type3_em) = match kind {
            SimpleKind::Type3 => type3_scales(doc, dict),
            _ => (1.0 / WIDTH_SCALE, 1.0),
        };
        let mut widths = Widths {
            explicit: Box::new([None; CODE_COUNT]),
            missing: descriptor
                .and_then(|descriptor| doc.get_f64(descriptor, b"MissingWidth"))
                .and_then(sanitize)
                .filter(|width| *width > 0.0),
            type3_scale,
            type3_em,
        };
        let first = doc
            .get_int(dict, b"FirstChar")
            .and_then(|first| usize::try_from(first).ok())
            .unwrap_or(0);
        if let Some(array) = doc.get_array(dict, b"Widths")
            && let Some(slots) = widths.explicit.get_mut(first..)
        {
            for (slot, value) in slots.iter_mut().zip(doc.array_iter(array)) {
                *slot = value
                    .as_f64()
                    .and_then(sanitize)
                    .map(|width| width * type3_scale);
            }
        }
        widths
    }

    pub(super) fn explicit(&self, code: u8) -> Option<f32> {
        self.explicit.get(usize::from(code)).copied().flatten()
    }
}

fn type3_scales(doc: &Document<'_>, dict: Dict<'_>) -> (f32, f64) {
    let mut matrix = [DEFAULT_TYPE3_SCALE, 0.0, 0.0, DEFAULT_TYPE3_SCALE, 0.0, 0.0];
    if let Some(array) = doc.get_array(dict, b"FontMatrix") {
        let mut values = [0f64; MATRIX_LEN];
        let mut count = 0;
        for (slot, value) in values.iter_mut().zip(doc.array_iter(array)) {
            if let Some(value) = value.as_f64() {
                *slot = value;
                count += 1;
            }
        }
        if count == MATRIX_LEN {
            matrix = values;
        }
    }
    let [a, _, _, d, _, _] = matrix;
    let horizontal = if a != 0.0 { a } else { DEFAULT_TYPE3_SCALE };
    let vertical = if d != 0.0 { d.abs() } else { horizontal.abs() };
    (horizontal as f32, vertical * f64::from(WIDTH_SCALE))
}

pub(super) fn metric_width(font: StandardFont, name: &[u8]) -> Option<f32> {
    font.width(name)
        .or_else(|| {
            WIDTH_ALIASES
                .iter()
                .find(|(alias, _)| *alias == name)
                .and_then(|(_, target)| font.width(target))
        })
        .map(f32::from)
}

pub(super) fn substitute(base_font: &[u8]) -> StandardFont {
    let contains = |needle: &[u8]| {
        base_font
            .windows(needle.len())
            .any(|window| window == needle)
    };
    let bold = BOLD_HINTS.iter().any(|hint| contains(hint));
    let serif = !contains(SANS_HINT) && SERIF_HINTS.iter().any(|hint| contains(hint));
    match (serif, bold) {
        (true, true) => StandardFont::TimesBold,
        (true, false) => StandardFont::TimesRoman,
        (false, true) => StandardFont::HelveticaBold,
        (false, false) => StandardFont::Helvetica,
    }
}
