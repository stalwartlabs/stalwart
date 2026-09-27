/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::script::{is_combining, is_dropped, is_neutral, is_rtl, is_space, mirror};
use crate::{
    output::{Output, Separator},
    pdf::tables::presentation_form,
};

pub(crate) const MAX_LINE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct Extent {
    pub(crate) start: f64,
    pub(crate) end: f64,
    pub(crate) em: f64,
    pub(crate) threshold: f64,
}

#[derive(Debug, Clone, Copy)]
struct Unit {
    extent: Extent,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpaceMark {
    at: usize,
    generation: u32,
}

#[derive(Debug, Default)]
pub(crate) struct Line {
    text: String,
    units: Vec<Unit>,
    ordered: String,
    scratch: String,
    provisional: Vec<usize>,
    rtl: bool,
    generation: u32,
}

impl Line {
    pub(crate) fn clear(&mut self) {
        self.text.clear();
        self.units.clear();
        self.provisional.clear();
        self.rtl = false;
        self.generation = self.generation.wrapping_add(1);
    }

    pub(crate) fn shrink(&mut self) {
        self.clear();
        self.text.shrink_to(MAX_LINE_BYTES);
        self.units.shrink_to(MAX_LINE_BYTES);
        self.provisional.shrink_to(MAX_LINE_BYTES);
        self.ordered = String::new();
        self.scratch = String::new();
    }

    pub(crate) fn separate(&mut self, out: &mut Output<'_>, separator: Separator) {
        match separator {
            Separator::None => {}
            Separator::Space => {
                if self.text.is_empty() {
                    out.separator(Separator::Space);
                } else if !self.text.ends_with(' ') {
                    self.text.push(' ');
                }
            }
            Separator::Newline => {
                self.flush(out);
                out.separator(Separator::Newline);
            }
        }
    }

    pub(crate) fn separate_tentatively(&mut self) -> Option<SpaceMark> {
        if self.text.is_empty() || self.text.ends_with(' ') {
            return None;
        }
        let at = self.text.len();
        self.text.push(' ');
        Some(SpaceMark {
            at,
            generation: self.generation,
        })
    }

    pub(crate) fn separate_provisionally(&mut self, out: &mut Output<'_>) {
        let at = self.text.len();
        self.separate(out, Separator::Space);
        if self.text.len() > at {
            self.provisional.push(at);
        }
    }

    pub(crate) fn retract(&mut self, mark: SpaceMark) {
        if mark.generation != self.generation || self.text.as_bytes().get(mark.at) != Some(&b' ') {
            return;
        }
        self.text.remove(mark.at);
        for unit in self.units.iter_mut().filter(|unit| unit.start > mark.at) {
            unit.start -= 1;
            unit.end -= 1;
        }
        self.provisional.retain(|&at| at != mark.at);
        for at in self.provisional.iter_mut().filter(|at| **at > mark.at) {
            *at -= 1;
        }
    }

    pub(crate) fn retract_provisional(&mut self) {
        let text = &self.text;
        self.provisional
            .retain(|&at| text.as_bytes().get(at) == Some(&b' '));
        if self.provisional.is_empty() {
            return;
        }
        self.scratch.clear();
        let mut kept_from = 0;
        for &at in &self.provisional {
            self.scratch
                .push_str(self.text.get(kept_from..at).unwrap_or_default());
            kept_from = at + 1;
        }
        self.scratch
            .push_str(self.text.get(kept_from..).unwrap_or_default());
        std::mem::swap(&mut self.text, &mut self.scratch);
        let mut removed = self.provisional.iter().peekable();
        let mut shift = 0;
        for unit in &mut self.units {
            while removed.next_if(|&&at| at < unit.start).is_some() {
                shift += 1;
            }
            unit.start -= shift;
            unit.end -= shift;
        }
        self.provisional.clear();
    }

    pub(crate) fn push(&mut self, out: &mut Output<'_>, text: &str, extent: Extent) {
        let start = self.text.len();
        if text.bytes().all(|byte| (0x21..0x7F).contains(&byte)) {
            self.text.push_str(text);
        } else {
            for ch in text.chars() {
                if is_space(ch) {
                    if !self.text.is_empty() && !self.text.ends_with(' ') {
                        self.text.push(' ');
                    }
                } else if !is_dropped(ch) {
                    self.rtl |= is_rtl(ch);
                    match presentation_form(ch) {
                        Some(form) => self.text.push_str(form),
                        None => self.text.push(ch),
                    }
                }
            }
        }
        if self.text.len() > start {
            self.units.push(Unit {
                extent,
                start,
                end: self.text.len(),
            });
        }
        if self.text.len() >= MAX_LINE_BYTES {
            self.flush(out);
        }
    }

    pub(crate) fn append_mark(&mut self, mark: char) {
        self.text.push(mark);
        if let Some(unit) = self.units.last_mut() {
            unit.end = self.text.len();
        }
    }

    pub(crate) fn flush(&mut self, out: &mut Output<'_>) {
        if self.text.is_empty() {
            return;
        }
        let text = if self.rtl {
            self.reorder();
            self.ordered.as_str()
        } else {
            self.text.as_str()
        };
        let trimmed = text.trim_matches(' ');
        if text.starts_with(' ') {
            out.separator(Separator::Space);
        }
        out.push_str(trimmed);
        if trimmed.len() < text.len() && text.ends_with(' ') {
            out.separator(Separator::Space);
        }
        self.clear();
    }

    fn reorder(&mut self) {
        self.units
            .sort_by(|left, right| left.extent.start.total_cmp(&right.extent.start));
        self.scratch.clear();
        let mut previous: Option<&Unit> = None;
        for unit in &self.units {
            if let Some(before) = previous {
                let em = before.extent.em.max(unit.extent.em);
                let gap = (unit.extent.start - before.extent.end) / em;
                if gap > unit.extent.threshold
                    && !self.scratch.is_empty()
                    && !self.scratch.ends_with(' ')
                {
                    self.scratch.push(' ');
                }
            }
            push_visual(
                self.text.get(unit.start..unit.end).unwrap_or_default(),
                &mut self.scratch,
            );
            previous = Some(unit);
        }
        let (rtl, ltr) = self
            .scratch
            .chars()
            .fold((0usize, 0usize), |(rtl, ltr), ch| {
                if is_rtl(ch) && !is_combining(ch) {
                    (rtl + 1, ltr)
                } else if !is_neutral(ch) {
                    (rtl, ltr + 1)
                } else {
                    (rtl, ltr)
                }
            });
        self.ordered.clear();
        if rtl >= ltr {
            reverse_line(&self.scratch, &mut self.ordered);
        } else {
            reverse_runs(&self.scratch, &mut self.ordered);
        }
    }
}

fn push_visual(logical: &str, out: &mut String) {
    let mut chars = logical.chars();
    let first = chars.next();
    if chars.next().is_none() || !first.is_some_and(is_rtl) {
        out.push_str(logical);
        return;
    }
    let mut end = logical.len();
    for (index, ch) in logical.char_indices().rev() {
        if !is_combining(ch) {
            out.push_str(logical.get(index..end).unwrap_or_default());
            end = index;
        }
    }
    out.push_str(logical.get(..end).unwrap_or_default());
}

fn is_strong_ltr(ch: char) -> bool {
    (!is_neutral(ch) && !is_rtl(ch)) || ch.is_numeric()
}

fn reverse_line(visual: &str, out: &mut String) {
    let chars: Vec<(usize, char)> = visual.char_indices().collect();
    let mut end = visual.len();
    let mut cursor = chars.len();
    while let Some(index) = cursor.checked_sub(1) {
        cursor = index;
        let Some(&(offset, ch)) = chars.get(index) else {
            break;
        };
        if is_combining(ch) {
            continue;
        }
        if is_strong_ltr(ch) {
            let mut start = offset;
            let mut probe = index;
            while let Some(previous) = probe.checked_sub(1) {
                let Some(&(at, before)) = chars.get(previous) else {
                    break;
                };
                if is_rtl(before) && !is_combining(before) {
                    break;
                }
                probe = previous;
                if is_strong_ltr(before) {
                    start = at;
                    cursor = previous;
                }
            }
            out.push_str(visual.get(start..end).unwrap_or_default());
            end = start;
        } else {
            out.push(mirror(ch));
            out.push_str(visual.get(offset + ch.len_utf8()..end).unwrap_or_default());
            end = offset;
        }
    }
}

fn reverse_runs(visual: &str, out: &mut String) {
    let mut segment: Option<(usize, usize)> = None;
    let mut copied = 0usize;
    for (index, ch) in visual.char_indices() {
        if is_rtl(ch) && !is_combining(ch) {
            let end = index + ch.len_utf8();
            segment = Some(segment.map_or((index, end), |(start, _)| (start, end)));
        } else if !is_neutral(ch)
            && let Some((start, end)) = segment.take()
        {
            out.push_str(visual.get(copied..start).unwrap_or_default());
            reverse_line(visual.get(start..end).unwrap_or_default(), out);
            copied = end;
        }
    }
    if let Some((start, end)) = segment {
        out.push_str(visual.get(copied..start).unwrap_or_default());
        reverse_line(visual.get(start..end).unwrap_or_default(), out);
        copied = end;
    }
    out.push_str(visual.get(copied..).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extent(start: f64) -> Extent {
        Extent {
            start,
            end: start + 1.0,
            em: 1.0,
            threshold: 0.15,
        }
    }

    fn logical(visual: &str) -> String {
        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 1024);
        let mut line = Line::default();
        for (position, ch) in visual.chars().enumerate() {
            if ch != ' ' {
                line.push(
                    &mut out,
                    ch.encode_utf8(&mut [0u8; 4]),
                    extent(position as f64),
                );
            }
        }
        line.flush(&mut out);
        buf
    }

    #[test]
    fn visual_rtl_lines_become_logical() {
        assert_eq!(
            logical("\u{5dd}\u{5d5}\u{5dc}\u{5e9}"),
            "\u{5e9}\u{5dc}\u{5d5}\u{5dd}"
        );
        assert_eq!(
            logical("abc \u{5d1}\u{5d0} 123 \u{5d2} def"),
            "abc \u{5d2} 123 \u{5d0}\u{5d1} def"
        );
        assert_eq!(logical("12.5 \u{5d1}\u{5d0}"), "\u{5d0}\u{5d1} 12.5");
        assert_eq!(
            logical("ISSN 0252 \u{5d1}\u{5d0} \u{5d3}\u{5d2}"),
            "\u{5d2}\u{5d3} \u{5d0}\u{5d1} ISSN 0252"
        );
        assert_eq!(logical("(\u{5d1}\u{5d0})"), "(\u{5d0}\u{5d1})");
        assert_eq!(logical("\u{627}\u{64e}\u{628}"), "\u{628}\u{627}\u{64e}");
        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 1024);
        let mut line = Line::default();
        line.push(&mut out, "\u{644}\u{625}", extent(0.0));
        line.push(&mut out, "\u{627}", extent(1.0));
        line.flush(&mut out);
        assert_eq!(buf, "\u{627}\u{644}\u{625}");
    }

    #[test]
    fn logical_painting_is_sorted_first() {
        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 1024);
        let mut line = Line::default();
        for (text, position) in ["\u{5e9}", "\u{5dc}", "\u{5d5}", "\u{5dd}"]
            .iter()
            .zip([4.0, 3.0, 2.0, 1.0])
        {
            line.push(&mut out, text, extent(position));
        }
        line.separate(&mut out, Separator::Space);
        line.push(&mut out, "\u{5d0}", extent(-1.0));
        line.flush(&mut out);
        assert_eq!(buf, "\u{5e9}\u{5dc}\u{5d5}\u{5dd} \u{5d0}");
    }

    #[test]
    fn normalization_and_flushing() {
        let mut buf = String::new();
        let mut out = Output::new(&mut buf, 1024);
        let mut line = Line::default();
        line.push(&mut out, "\u{fb01}ne\u{ad}\u{0}\u{e000}", extent(0.0));
        line.separate(&mut out, Separator::Space);
        line.push(&mut out, "caf\u{e9}\u{a0}", extent(1.0));
        line.separate(&mut out, Separator::Newline);
        line.push(&mut out, "u", extent(2.0));
        line.append_mark('\u{308}');
        line.flush(&mut out);
        assert_eq!(buf, "fine caf\u{e9}\nu\u{308}");
    }
}
