/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Outcome;
use super::predictor::{Layout, Png};

pub(super) enum Step {
    More,
    Done { corrupt: bool },
}

pub(super) trait Source {
    fn produce(&mut self, out: &mut Vec<u8>, cap: usize) -> Step;
    fn size_hint(&self) -> usize;
}

pub(super) fn run(
    source: &mut impl Source,
    layout: Layout,
    out: &mut Vec<u8>,
    limit: usize,
    probe: &mut Vec<u8>,
) -> Outcome {
    let start = out.len();
    let end = start.saturating_add(limit);
    match layout {
        Layout::None => settle(fill(source, out, start, end), source, probe),
        Layout::Tiff(tiff) => {
            let step = fill(source, out, start, end.saturating_add(1));
            tiff.apply(out.get_mut(start..).unwrap_or_default());
            let truncated = out.len() > end;
            out.truncate(end);
            Outcome {
                truncated,
                corrupt: matches!(step, Step::Done { corrupt: true }),
            }
        }
        Layout::Png(png) => run_png(source, png, out, start, end, probe),
    }
}

fn run_png(
    source: &mut impl Source,
    png: Png,
    out: &mut Vec<u8>,
    start: usize,
    end: usize,
    probe: &mut Vec<u8>,
) -> Outcome {
    let mut decoded = start;
    let mut unknown = false;
    loop {
        let step = fill(source, out, start, end.saturating_add(1));
        unknown |= png.rows(out, start, &mut decoded);
        match step {
            Step::Done { corrupt } => {
                unknown |= png.partial(out, start, decoded, end);
                return Outcome {
                    truncated: false,
                    corrupt: corrupt | unknown,
                };
            }
            Step::More if out.len() <= end => {}
            Step::More => {
                unknown |= png.partial(out, start, decoded, end);
                return Outcome {
                    truncated: has_more(source, probe),
                    corrupt: unknown,
                };
            }
        }
    }
}

fn fill(source: &mut impl Source, out: &mut Vec<u8>, start: usize, cap: usize) -> Step {
    let hint = source.size_hint();
    loop {
        let len = out.len();
        if len >= cap {
            return Step::More;
        }
        let step = (cap - len).min(len.saturating_sub(start).max(hint));
        out.reserve_exact(step);
        if let done @ Step::Done { .. } = source.produce(out, len + step) {
            return done;
        }
    }
}

fn settle(step: Step, source: &mut impl Source, probe: &mut Vec<u8>) -> Outcome {
    match step {
        Step::Done { corrupt } => Outcome {
            truncated: false,
            corrupt,
        },
        Step::More => Outcome {
            truncated: has_more(source, probe),
            corrupt: false,
        },
    }
}

fn has_more(source: &mut impl Source, probe: &mut Vec<u8>) -> bool {
    probe.clear();
    let _ = source.produce(probe, 1);
    let more = !probe.is_empty();
    probe.clear();
    more
}
