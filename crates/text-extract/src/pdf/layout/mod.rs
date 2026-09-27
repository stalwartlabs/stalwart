/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod dedupe;
mod line;
mod script;
mod shift;

#[cfg(test)]
mod tests;

use self::{
    dedupe::Dedupe,
    line::{Extent, Line, SpaceMark},
    script::{is_combining, is_dropped, is_rtl, is_space, is_unspaced},
    shift::Run,
};
use crate::{
    output::{Output, Separator},
    pdf::{font::FontId, tables::combining_accent},
};

const SAME_DIRECTION: f64 = 0.99;
const NEWLINE_ACROSS: f64 = 0.7;
const BACKWARD_JUMP: f64 = -0.5;
const BACKWARD_ACROSS: f64 = 0.3;
const FORWARD_NEWLINE: f64 = 2.0;
const PEN_MOVED: f64 = 0.03;
const MIN_SPACE: f64 = 0.08;
const BASE_SPACE: f64 = 0.15;
const SPACE_WIDTH_FACTOR: f64 = 0.5;
const PAGE_MARGIN_EM: f64 = 1.0;
const MIN_EM: f64 = 1e-6;
const MIN_ADVANCE: f64 = 1e-9;
const SOFT_HYPHEN: char = '\u{AD}';
const ACCENT_OVERLAP: f64 = 0.3;
const ACCENT_ACROSS: f64 = 1.5;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Placement {
    pub(crate) origin: (f64, f64),
    pub(crate) end: (f64, f64),
    pub(crate) dir: (f64, f64),
    pub(crate) em: f64,
    pub(crate) space_threshold: f64,
    pub(crate) spacing: f64,
    pub(crate) continued: bool,
    pub(crate) vertical: bool,
    pub(crate) font: FontId,
}

#[derive(Debug, Clone, Copy)]
struct Previous {
    origin: (f64, f64),
    end: (f64, f64),
    dir: (f64, f64),
    em: f64,
    spacing: f64,
    vertical: bool,
    font: FontId,
    last: char,
    rtl: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct PendingAccent {
    spacing: char,
    mark: char,
    placement: Placement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gap {
    separator: Separator,
    provisional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Class {
    Empty,
    Space,
    SoftHyphen,
    Visible { first: char, last: char, rtl: bool },
}

#[derive(Debug, Default)]
pub(crate) struct Layout {
    previous: Option<Previous>,
    pending_space: bool,
    spaced_line: bool,
    soft_hyphen: bool,
    media_box: Option<[f64; 4]>,
    dedupe: Dedupe,
    line: Line,
    actual: Option<bool>,
    actual_text: String,
    accent: Option<PendingAccent>,
    run: Run,
    tentative: Option<SpaceMark>,
    glyphs: u64,
    candidates: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GlyphCounts {
    pub(crate) candidates: u64,
    pub(crate) placed: u64,
    pub(crate) in_actual_text: bool,
}

pub(crate) fn fingerprint(text: &str) -> u64 {
    dedupe::fnv(text.as_bytes())
}

pub(crate) fn space_threshold(space_width: Option<f32>) -> f64 {
    space_width
        .map_or(BASE_SPACE, |width| {
            BASE_SPACE.min(SPACE_WIDTH_FACTOR * f64::from(width))
        })
        .max(MIN_SPACE)
}

impl Class {
    fn of(text: &str) -> Class {
        if let &[byte] = text.as_bytes()
            && byte.is_ascii_graphic()
        {
            let ch = char::from(byte);
            return Class::Visible {
                first: ch,
                last: ch,
                rtl: false,
            };
        }
        let mut chars = text
            .chars()
            .filter(|&ch| !is_dropped(ch) || ch == SOFT_HYPHEN);
        let Some(first) = chars.next() else {
            return Class::Empty;
        };
        if text.chars().all(|ch| ch == SOFT_HYPHEN) {
            return Class::SoftHyphen;
        }
        let mut visible = text.chars().filter(|&ch| !is_dropped(ch) && !is_space(ch));
        let Some(first_visible) = visible.next() else {
            return if is_space(first) {
                Class::Space
            } else {
                Class::Empty
            };
        };
        let last = visible.next_back().unwrap_or(first_visible);
        Class::Visible {
            first: first_visible,
            last,
            rtl: is_rtl(first_visible),
        }
    }
}

impl From<Separator> for Gap {
    fn from(separator: Separator) -> Self {
        Gap {
            separator,
            provisional: false,
        }
    }
}

impl Extent {
    fn of(placement: &Placement) -> Self {
        let (from, to) = (
            dot(placement.origin, placement.dir),
            dot(placement.end, placement.dir),
        );
        Extent {
            start: from.min(to),
            end: from.max(to),
            em: placement.em.max(MIN_EM),
            threshold: placement.space_threshold,
        }
    }
}

fn dot(a: (f64, f64), b: (f64, f64)) -> f64 {
    a.0 * b.0 + a.1 * b.1
}

fn cross(a: (f64, f64), b: (f64, f64)) -> f64 {
    a.0 * b.1 - a.1 * b.0
}

fn sub(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    (a.0 - b.0, a.1 - b.1)
}

fn single_accent(text: &str) -> Option<(char, char)> {
    let mut chars = text.chars();
    let spacing = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    if is_combining(spacing) {
        return Some((spacing, spacing));
    }
    combining_accent(spacing).map(|mark| (spacing, mark))
}

fn overlaps(
    accent: &Placement,
    origin: (f64, f64),
    end: (f64, f64),
    dir: (f64, f64),
    em: f64,
) -> bool {
    let span = |from: (f64, f64), to: (f64, f64)| {
        let (a, b) = (dot(from, dir), dot(to, dir));
        (a.min(b), a.max(b))
    };
    let (accent_start, accent_end) = span(accent.origin, accent.end);
    let (base_start, base_end) = span(origin, end);
    let width = (accent_end - accent_start).max(MIN_ADVANCE);
    let shared = accent_end.min(base_end) - accent_start.max(base_start);
    let across = cross(dir, sub(accent.origin, origin)).abs();
    shared / width > ACCENT_OVERLAP && across < ACCENT_ACROSS * em.max(MIN_EM)
}

impl Layout {
    pub(crate) fn begin_page(&mut self, media_box: Option<[f64; 4]>) {
        self.previous = None;
        self.pending_space = false;
        self.spaced_line = false;
        self.soft_hyphen = false;
        self.accent = None;
        self.media_box = media_box;
        self.dedupe.clear();
        self.actual = None;
        self.run = Run::default();
        self.tentative = None;
    }

    pub(crate) fn shrink(&mut self) {
        self.line.shrink();
        self.actual_text = String::new();
    }

    pub(crate) fn counts(&self) -> GlyphCounts {
        GlyphCounts {
            candidates: self.candidates,
            placed: self.glyphs,
            in_actual_text: self.actual.is_some(),
        }
    }

    pub(crate) fn end_page(&mut self, out: &mut Output<'_>) {
        self.flush_accent(out);
        self.end_actual_text(out);
        self.line.flush(out);
        out.separator(Separator::Newline);
    }

    pub(crate) fn block(&mut self, out: &mut Output<'_>, text: &str) {
        self.line.separate(out, Separator::Newline);
        self.line.push(out, text, Extent::default());
        self.line.separate(out, Separator::Newline);
    }

    pub(crate) fn begin_actual_text(&mut self, text: &str) -> bool {
        if self.actual.is_some() {
            return false;
        }
        self.actual_text.clear();
        self.actual_text.push_str(text);
        self.actual = Some(false);
        true
    }

    pub(crate) fn end_actual_text(&mut self, out: &mut Output<'_>) {
        if let Some(emitted) = self.actual.take()
            && !emitted
        {
            let extent = self.last_extent();
            self.line.separate(out, Separator::Space);
            let text = std::mem::take(&mut self.actual_text);
            self.line.push(out, &text, extent);
            self.actual_text = text;
            self.glyphs = self.glyphs.saturating_add(1);
            self.candidates = self.candidates.saturating_add(1);
        }
    }

    fn outside_page(&self, placement: &Placement) -> bool {
        let Some([left, bottom, right, top]) = self.media_box else {
            return false;
        };
        let margin = placement.em * PAGE_MARGIN_EM;
        let (x, y) = placement.origin;
        x < left - margin || x > right + margin || y < bottom - margin || y > top + margin
    }

    pub(crate) fn glyph(&mut self, out: &mut Output<'_>, text: &str, placement: &Placement) {
        self.candidates = self.candidates.saturating_add(1);
        if self.outside_page(placement) {
            return;
        }
        if let Some((spacing, mark)) = single_accent(text) {
            if !self.attach_accent(mark, placement) {
                self.flush_accent(out);
                self.accent = Some(PendingAccent {
                    spacing,
                    mark,
                    placement: *placement,
                });
            }
            return;
        }
        if let Some(accent) = self.accent.take() {
            if matches!(Class::of(text), Class::Visible { .. })
                && overlaps(
                    &accent.placement,
                    placement.origin,
                    placement.end,
                    placement.dir,
                    placement.em,
                )
            {
                let before = self.glyphs;
                self.place(out, text, placement);
                if self.glyphs > before && self.actual.is_none() {
                    self.line.append_mark(accent.mark);
                }
                return;
            }
            self.place(
                out,
                accent.spacing.encode_utf8(&mut [0u8; 4]),
                &accent.placement,
            );
        }
        self.place(out, text, placement);
    }

    fn flush_accent(&mut self, out: &mut Output<'_>) {
        if let Some(accent) = self.accent.take() {
            self.place(
                out,
                accent.spacing.encode_utf8(&mut [0u8; 4]),
                &accent.placement,
            );
        }
    }

    fn attach_accent(&mut self, mark: char, placement: &Placement) -> bool {
        let Some(previous) = self.previous.filter(|previous| {
            previous.last != SOFT_HYPHEN && dot(previous.dir, placement.dir) >= SAME_DIRECTION
        }) else {
            return false;
        };
        if !overlaps(
            placement,
            previous.origin,
            previous.end,
            previous.dir,
            previous.em,
        ) {
            return false;
        }
        if self.actual.is_none() {
            self.line.append_mark(mark);
        }
        true
    }

    fn place(&mut self, out: &mut Output<'_>, text: &str, placement: &Placement) {
        let (first, last, rtl) = match Class::of(text) {
            Class::Empty => return,
            Class::Space => {
                if !self.spaced_line {
                    self.line.retract_provisional();
                }
                self.pending_space = true;
                self.spaced_line = true;
                return;
            }
            Class::SoftHyphen => {
                self.soft_hyphen = true;
                self.remember(placement, SOFT_HYPHEN, false);
                return;
            }
            Class::Visible { first, last, rtl } => (first, last, rtl),
        };
        let advance = dot(sub(placement.end, placement.origin), placement.dir);
        if self.actual.is_none()
            && self
                .dedupe
                .is_duplicate(text, placement.origin, advance, placement.em)
        {
            return;
        }
        self.glyphs = self.glyphs.saturating_add(1);
        let gap = self.separator(placement, first, rtl);
        let mut separator = gap.separator;
        let shifted = self.shift(placement, separator, first, last);
        if self.soft_hyphen && separator == Separator::Newline {
            separator = Separator::None;
        }
        if separator == Separator::Newline {
            self.spaced_line = false;
        }
        self.soft_hyphen = false;
        let tentative = self.apply_shift(shifted, &mut separator);
        let extent = Extent::of(placement);
        match self.actual {
            Some(true) => {}
            Some(false) => {
                self.line.separate(out, separator);
                let actual = std::mem::take(&mut self.actual_text);
                self.line.push(out, &actual, extent);
                self.actual_text = actual;
                self.actual = Some(true);
            }
            None => {
                if gap.provisional && separator == Separator::Space {
                    self.line.separate_provisionally(out);
                } else {
                    self.line.separate(out, separator);
                }
                if tentative {
                    self.tentative = self.line.separate_tentatively();
                }
                self.line.push(out, text, extent);
            }
        }
        if self.actual.is_some()
            && self
                .actual_text
                .chars()
                .all(|ch| is_space(ch) || is_dropped(ch))
        {
            self.soft_hyphen = true;
        }
        self.remember(placement, last, rtl);
        self.pending_space = false;
    }

    fn last_extent(&self) -> Extent {
        self.previous.map_or_else(Extent::default, |previous| {
            let end = dot(previous.end, previous.dir);
            Extent {
                start: end,
                end,
                em: previous.em,
                threshold: BASE_SPACE,
            }
        })
    }

    fn remember(&mut self, placement: &Placement, last: char, rtl: bool) {
        let advance = dot(sub(placement.end, placement.origin), placement.dir).abs();
        let end = match self.previous {
            Some(previous) if advance < MIN_ADVANCE => previous.end,
            _ => placement.end,
        };
        self.previous = Some(Previous {
            origin: placement.origin,
            end,
            dir: placement.dir,
            em: placement.em,
            spacing: placement.spacing,
            vertical: placement.vertical,
            font: placement.font,
            last,
            rtl,
        });
    }

    fn separator(&self, placement: &Placement, first: char, rtl: bool) -> Gap {
        let Some(previous) = self.previous else {
            return if self.pending_space {
                Separator::Space
            } else {
                Separator::None
            }
            .into();
        };
        if previous.vertical != placement.vertical
            || dot(previous.dir, placement.dir) < SAME_DIRECTION
        {
            return Separator::Newline.into();
        }
        let em = previous.em.max(placement.em).max(MIN_EM);
        let delta = sub(placement.origin, previous.end);
        let mut along = dot(delta, previous.dir) / em;
        let across = (cross(previous.dir, delta) / em).abs();
        if rtl && previous.rtl && dot(sub(placement.origin, previous.origin), previous.dir) < 0.0 {
            along = dot(sub(previous.origin, placement.end), previous.dir) / em;
        }
        if across >= NEWLINE_ACROSS {
            return Separator::Newline.into();
        }
        if along < BACKWARD_JUMP {
            return if across > BACKWARD_ACROSS {
                Separator::Newline
            } else {
                Separator::Space
            }
            .into();
        }
        if along > FORWARD_NEWLINE {
            return Separator::Newline.into();
        }
        let pending = self.pending_space && along > PEN_MOVED;
        let relaxed = if placement.continued {
            previous.spacing.max(0.0)
        } else {
            0.0
        };
        let spaced_threshold = placement.space_threshold.max(BASE_SPACE) + relaxed;
        let threshold = if self.spaced_line {
            spaced_threshold
        } else {
            placement.space_threshold + relaxed
        };
        let synthetic = along > threshold;
        if pending || synthetic && !is_unspaced(previous.last) && !is_unspaced(first) {
            Gap {
                separator: Separator::Space,
                provisional: !pending
                    && along <= spaced_threshold
                    && previous.font == placement.font
                    && previous.last.is_alphanumeric()
                    && first.is_alphanumeric(),
            }
        } else {
            Separator::None.into()
        }
    }
}
