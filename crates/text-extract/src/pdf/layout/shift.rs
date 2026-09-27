/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Layout, MIN_EM, Placement, cross, script::is_unspaced, sub};
use crate::output::Separator;

const MIN_SHIFT: f64 = 0.2;
const SMALLER_FONT: f64 = 1.15;
const WORD_LETTERS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Level {
    #[default]
    Base,
    Raised,
    Lowered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shifted {
    Joined,
    Space,
    Tentative,
    Retract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Glyph {
    first: char,
    last: char,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Run {
    level: Level,
    recent: [Glyph; WORD_LETTERS],
    count: usize,
    marker: bool,
    detached: bool,
}

fn is_marker(ch: char) -> bool {
    is_marker_start(ch) || matches!(ch, ',' | '-' | '\u{2013}')
}

fn is_marker_start(ch: char) -> bool {
    if ch.is_ascii() {
        ch.is_ascii_digit() || matches!(ch, '*' | '#')
    } else {
        matches!(
            ch,
            '\u{A7}' | '\u{B6}' | '\u{2016}' | '\u{2020}' | '\u{2021}' | '\u{2217}' | '\u{22C6}'
        ) || ch.is_numeric()
    }
}

fn is_word(ch: char) -> bool {
    if ch.is_ascii() {
        ch.is_ascii_alphabetic()
    } else {
        ch.is_alphabetic() && !is_unspaced(ch)
    }
}

impl Glyph {
    fn is_marker(&self) -> bool {
        is_marker(self.first) && is_marker(self.last)
    }

    fn is_word(&self) -> bool {
        is_word(self.first) && is_word(self.last)
    }
}

impl Run {
    fn restart(&mut self, glyph: Glyph) {
        self.level = Level::Base;
        self.next_word(glyph);
    }

    fn next_word(&mut self, glyph: Glyph) {
        self.count = 0;
        self.push(glyph);
        self.marker = self.level != Level::Base && glyph.is_marker();
    }

    fn is_raised(&self) -> bool {
        self.level == Level::Raised
    }

    fn advance(&mut self, shift: f64, growth: f64, glyph: Glyph) -> Shifted {
        let direction = if shift >= MIN_SHIFT {
            Direction::Up
        } else if shift <= -MIN_SHIFT {
            Direction::Down
        } else {
            return self.extend(glyph);
        };
        let grew = growth > SMALLER_FONT;
        let (level, shifted) = match (self.level, direction) {
            (Level::Raised, Direction::Up) | (Level::Lowered, Direction::Down) => {
                return self.extend(glyph);
            }
            (Level::Lowered, Direction::Up) => (Level::Base, Shifted::Joined),
            (Level::Base, Direction::Up) if grew => (Level::Base, Shifted::Joined),
            (Level::Base, Direction::Up) => (Level::Raised, self.opening(glyph)),
            (Level::Base, Direction::Down) if !grew => (Level::Lowered, Shifted::Joined),
            (Level::Base, Direction::Down) => {
                let marker = self.count <= WORD_LETTERS && self.word().iter().all(Glyph::is_marker);
                (Level::Base, Self::closing(marker, glyph))
            }
            (Level::Raised, Direction::Down) => (
                Level::Base,
                Self::closing(self.detached && self.marker, glyph),
            ),
        };
        self.level = level;
        self.next_word(glyph);
        shifted
    }

    fn opening(&mut self, glyph: Glyph) -> Shifted {
        let word = self.word();
        let long_word = word.len() >= WORD_LETTERS && word.iter().all(Glyph::is_word);
        self.detached = long_word || !word.last().is_some_and(Glyph::is_word);
        if long_word && is_marker_start(glyph.first) {
            Shifted::Tentative
        } else {
            Shifted::Joined
        }
    }

    fn closing(marker: bool, glyph: Glyph) -> Shifted {
        if marker && is_word(glyph.first) {
            Shifted::Space
        } else {
            Shifted::Joined
        }
    }

    fn word(&self) -> &[Glyph] {
        self.recent
            .get(WORD_LETTERS - self.count.min(WORD_LETTERS)..)
            .unwrap_or_default()
    }

    fn push(&mut self, glyph: Glyph) {
        let [_, middle, last] = self.recent;
        self.recent = [middle, last, glyph];
        self.count = self.count.saturating_add(1);
    }

    fn extend(&mut self, glyph: Glyph) -> Shifted {
        self.push(glyph);
        if self.level == Level::Base || !self.marker {
            return Shifted::Joined;
        }
        self.marker = glyph.is_marker();
        if self.level == Level::Raised && !self.marker {
            Shifted::Retract
        } else {
            Shifted::Joined
        }
    }
}

impl Layout {
    pub(super) fn shift(
        &mut self,
        placement: &Placement,
        separator: Separator,
        first: char,
        last: char,
    ) -> Shifted {
        let glyph = Glyph { first, last };
        let Some(previous) = self.previous.filter(|previous| {
            separator != Separator::Newline && !previous.vertical && !placement.vertical
        }) else {
            self.run.restart(glyph);
            return Shifted::Joined;
        };
        let em = previous.em.max(placement.em).max(MIN_EM);
        let shift = cross(previous.dir, sub(placement.origin, previous.end)) / em;
        let growth = placement.em / previous.em.max(MIN_EM);
        let shifted = self.run.advance(shift, growth, glyph);
        if separator == Separator::Space {
            self.run.next_word(glyph);
        }
        shifted
    }

    pub(super) fn apply_shift(&mut self, shifted: Shifted, separator: &mut Separator) -> bool {
        if *separator != Separator::None || !self.run.is_raised() {
            self.tentative = None;
        }
        if *separator != Separator::None || self.actual.is_some() {
            return false;
        }
        match shifted {
            Shifted::Joined => false,
            Shifted::Space => {
                *separator = Separator::Space;
                false
            }
            Shifted::Tentative => true,
            Shifted::Retract => {
                if let Some(mark) = self.tentative.take() {
                    self.line.retract(mark);
                }
                false
            }
        }
    }
}
