/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Interpreter, state::finite};
use crate::{
    output::Output,
    pdf::{
        layout::{Placement, space_threshold},
        object::{Array, Object, Str},
    },
};

const THOUSANDTHS: f64 = 1000.0;
const MIN_LENGTH: f64 = 1e-9;
const FALLBACK_DIRECTION: (f64, f64) = (1.0, 0.0);
const DEGENERATE_SIZE: f64 = 1.0;

fn normalize(vector: (f64, f64)) -> Option<(f64, f64)> {
    let length = vector.0.hypot(vector.1);
    (length > MIN_LENGTH && length.is_finite()).then(|| (vector.0 / length, vector.1 / length))
}

impl Interpreter {
    pub(super) fn show(&mut self, bytes: &[u8], out: &mut Output<'_>) {
        let Interpreter {
            fonts,
            state,
            text_matrix,
            glyph_text,
            layout,
            continued,
            ..
        } = self;
        let text = state.text;
        let font = fonts.font(text.font);
        let metrics = font.metrics();
        let vertical = font.is_vertical();
        let size = if text.size.abs() > MIN_LENGTH {
            text.size
        } else {
            DEGENERATE_SIZE
        };
        let scale = text.scale;
        let mut matrix = text_matrix.then(&state.ctm);
        let x_axis = (matrix.a * size * scale, matrix.b * size * scale);
        let y_axis = (matrix.c * size, matrix.d * size);
        let em_scale = f64::from(metrics.em_scale);
        let (dir, em) = if vertical {
            (
                normalize((-y_axis.0, -y_axis.1)),
                (matrix.a * size).hypot(matrix.b * size) * em_scale,
            )
        } else {
            (normalize(x_axis), y_axis.0.hypot(y_axis.1) * em_scale)
        };
        let dir = dir.unwrap_or(FALLBACK_DIRECTION);
        let em = if em.is_finite() && em > MIN_LENGTH {
            em
        } else {
            1.0
        };
        let threshold = space_threshold(metrics.space_width);
        let spacing_em = finite(text.char_spacing * scale / size.abs());
        let mut rest = bytes;
        while !rest.is_empty() {
            let Some((glyph, glyph_str)) = font.glyph(rest, glyph_text) else {
                break;
            };
            let width = f64::from(glyph.width);
            let spacing = text.char_spacing
                + if glyph.space_code {
                    text.word_spacing
                } else {
                    0.0
                };
            let origin = (
                matrix.e + text.rise * matrix.c,
                matrix.f + text.rise * matrix.d,
            );
            let end = if vertical {
                (origin.0 + width * y_axis.0, origin.1 + width * y_axis.1)
            } else {
                (origin.0 + width * x_axis.0, origin.1 + width * x_axis.1)
            };
            layout.glyph(
                out,
                glyph_str,
                &Placement {
                    origin,
                    end,
                    dir,
                    em,
                    space_threshold: threshold,
                    spacing: spacing_em,
                    continued: *continued,
                    vertical,
                    font: text.font,
                },
            );
            *continued = true;
            if vertical {
                let advance = finite(width * size + spacing);
                matrix.translate(0.0, advance);
                text_matrix.translate(0.0, advance);
            } else {
                let advance = finite((width * size + spacing) * scale);
                matrix.translate(advance, 0.0);
                text_matrix.translate(advance, 0.0);
            }
            rest = rest.get(glyph.len.max(1)..).unwrap_or_default();
        }
    }

    pub(super) fn show_str(&mut self, value: Str<'_>, out: &mut Output<'_>) {
        if let Some(raw) = value.plain() {
            self.show(raw, out);
            return;
        }
        let mut buf = std::mem::take(&mut self.string_buf);
        buf.clear();
        value.decode_into(&mut buf);
        self.show(&buf, out);
        self.string_buf = buf;
    }

    pub(super) fn show_array(&mut self, array: Array<'_>, out: &mut Output<'_>) {
        for item in array.iter() {
            if out.is_full() {
                return;
            }
            match item {
                Object::Str(value) => self.show_str(value, out),
                other => {
                    let Some(adjust) = other.as_f64() else {
                        continue;
                    };
                    let text = self.state.text;
                    let shift = finite(-adjust / THOUSANDTHS * text.size);
                    if self.fonts.font(text.font).is_vertical() {
                        self.text_matrix.translate(0.0, shift);
                    } else {
                        self.text_matrix.translate(finite(shift * text.scale), 0.0);
                    }
                }
            }
        }
    }
}
