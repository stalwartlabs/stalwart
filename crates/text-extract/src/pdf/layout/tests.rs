/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;

const EM: f64 = 10.0;
const WIDTH: f64 = 5.0;

fn at(x: f64, y: f64) -> Placement {
    Placement {
        origin: (x, y),
        end: (x + WIDTH, y),
        dir: (1.0, 0.0),
        em: EM,
        space_threshold: space_threshold(Some(0.278)),
        spacing: 0.0,
        continued: false,
        vertical: false,
        font: FontId::STANDARD,
    }
}

fn run(glyphs: &[(&str, Placement)]) -> String {
    let mut buf = String::new();
    let mut out = Output::new(&mut buf, 1 << 16);
    let mut layout = Layout::default();
    layout.begin_page(Some([0.0, 0.0, 612.0, 792.0]));
    for (text, placement) in glyphs {
        layout.glyph(&mut out, text, placement);
    }
    layout.end_page(&mut out);
    buf
}

#[test]
fn gaps_become_spaces_and_newlines() {
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            ("b", at(105.5, 700.0)),
            ("c", at(112.0, 700.0))
        ]),
        "ab c"
    );
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            ("b", at(100.0, 690.0)),
            ("c", at(140.0, 690.0))
        ]),
        "a\nb\nc"
    );
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            ("b", at(90.0, 700.0)),
            ("c", at(80.0, 695.0))
        ]),
        "a b\nc"
    );
}

#[test]
fn space_glyphs_only_count_when_the_pen_moves() {
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            (" ", at(105.0, 700.0)),
            ("b", at(107.0, 700.0))
        ]),
        "a b"
    );
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            (" ", at(105.0, 700.0)),
            ("b", at(105.1, 700.0))
        ]),
        "ab"
    );
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            ("\u{a0}\u{2009}", at(105.0, 700.0)),
            ("b", at(108.0, 700.0))
        ]),
        "a b"
    );
}

#[test]
fn duplicates_do_not_disturb_geometry() {
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            ("b", at(105.0, 700.0)),
            ("a", at(100.2, 700.1)),
            ("c", at(110.0, 700.0)),
        ]),
        "abc"
    );
}

#[test]
fn actual_text_spans() {
    let mut buf = String::new();
    let mut out = Output::new(&mut buf, 1 << 16);
    let mut layout = Layout::default();
    layout.begin_page(None);
    layout.glyph(&mut out, "x", &at(100.0, 700.0));
    assert!(layout.begin_actual_text("replacement"));
    assert!(!layout.begin_actual_text("nested"));
    layout.glyph(&mut out, "y", &at(105.0, 700.0));
    layout.glyph(&mut out, "z", &at(110.0, 700.0));
    layout.end_actual_text(&mut out);
    layout.glyph(&mut out, "w", &at(115.0, 700.0));
    assert!(layout.begin_actual_text("empty span"));
    layout.end_actual_text(&mut out);
    layout.end_page(&mut out);
    assert_eq!(buf, "xreplacementw empty span");
}

#[test]
fn cjk_neighbours_never_get_synthetic_spaces() {
    assert_eq!(
        run(&[
            ("\u{65e5}", at(100.0, 700.0)),
            ("\u{672c}", at(108.0, 700.0)),
            ("a", at(116.0, 700.0))
        ]),
        "\u{65e5}\u{672c}a"
    );
    assert_eq!(
        run(&[
            ("\u{65e5}", at(100.0, 700.0)),
            (" ", at(105.0, 700.0)),
            ("\u{672c}", at(108.0, 700.0))
        ]),
        "\u{65e5} \u{672c}"
    );
}

#[test]
fn letter_spacing_relaxes_only_continued_runs() {
    let spaced = |x: f64, continued: bool| Placement {
        spacing: 0.3,
        continued,
        ..at(x, 700.0)
    };
    assert_eq!(
        run(&[
            ("a", spaced(100.0, false)),
            ("b", spaced(108.0, true)),
            ("c", spaced(116.0, true))
        ]),
        "abc"
    );
    assert_eq!(
        run(&[("a", spaced(100.0, false)), ("b", spaced(108.0, false))]),
        "a b"
    );
}

fn tracked(glyphs: &[(&str, f64)], font_at: usize) -> String {
    let placed: Vec<(&str, Placement)> = glyphs
        .iter()
        .enumerate()
        .map(|(index, &(text, x))| {
            let font = if index >= font_at {
                FontId::STANDARD
            } else {
                FontId::FIRST
            };
            (
                text,
                Placement {
                    font,
                    ..at(x, 700.0)
                },
            )
        })
        .collect();
    run(&placed)
}

#[test]
fn tracked_gaps_before_the_first_space_follow_the_line() {
    let line = [
        ("a", 100.0),
        ("b", 106.45),
        ("c", 112.9),
        (" ", 118.35),
        ("d", 121.2),
    ];
    assert_eq!(tracked(&line, 0), "abc d");
    assert_eq!(tracked(&line, 1), "a bc d");
    assert_eq!(
        tracked(&[("a", 100.0), ("b", 106.45), ("c", 112.9)], 0),
        "a b c"
    );
    assert_eq!(
        tracked(
            &[
                ("a", 100.0),
                (",", 106.45),
                ("c", 112.9),
                (" ", 118.35),
                ("d", 121.2)
            ],
            0
        ),
        "a , c d"
    );
    assert_eq!(
        run(&[
            ("a", at(100.0, 700.0)),
            ("b", at(106.45, 700.0)),
            (" ", at(111.9, 700.0)),
            ("e", at(100.0, 690.0)),
            ("f", at(106.45, 690.0)),
        ]),
        "ab\ne f"
    );
}

#[test]
fn thresholds_respect_condensed_spaces() {
    assert_eq!(space_threshold(None), BASE_SPACE);
    assert!((space_threshold(Some(0.2)) - 0.1).abs() < 1e-6);
    assert_eq!(space_threshold(Some(0.05)), MIN_SPACE);
    assert_eq!(space_threshold(Some(0.6)), BASE_SPACE);
}

fn sized(x: f64, y: f64, em: f64) -> Placement {
    Placement {
        end: (x + em / 2.0, y),
        em,
        ..at(x, y)
    }
}

fn word(text: &str, x: f64, y: f64, em: f64) -> Vec<(String, Placement)> {
    text.chars()
        .zip(0u32..)
        .map(|(ch, index)| {
            (
                ch.to_string(),
                sized(x + f64::from(index) * em / 2.0, y, em),
            )
        })
        .collect()
}

fn words(parts: &[(&str, f64)]) -> String {
    let mut x = 100.0;
    let mut glyphs = Vec::new();
    for &(text, rise) in parts {
        let em = if rise == 0.0 { EM } else { EM * 0.7 };
        glyphs.extend(word(text, x, 700.0 + rise * EM, em));
        x += text.chars().count() as f64 * em / 2.0;
    }
    let borrowed: Vec<(&str, Placement)> = glyphs
        .iter()
        .map(|(text, placement)| (text.as_str(), *placement))
        .collect();
    run(&borrowed)
}

#[test]
fn raised_markers_are_detached_from_words() {
    assert_eq!(words(&[("result", 0.0), ("1", 0.4)]), "result 1");
    assert_eq!(
        words(&[("Smith", 0.0), ("1,2", 0.4), (", Jones", 0.0)]),
        "Smith 1,2, Jones"
    );
    assert_eq!(
        words(&[("word", 0.0), ("\u{2020}", 0.4), ("next", 0.0)]),
        "word \u{2020} next"
    );
    assert_eq!(words(&[("1", 0.4), ("Department", 0.0)]), "1 Department");
    assert_eq!(
        words(&[("*", 0.4), ("Corresponding", 0.0)]),
        "* Corresponding"
    );
}

#[test]
fn other_baseline_shifts_stay_joined() {
    assert_eq!(words(&[("H", 0.0), ("2", -0.3), ("O", 0.0)]), "H2O");
    assert_eq!(
        words(&[("1", 0.0), ("st", 0.4), (" place", 0.0)]),
        "1st place"
    );
    assert_eq!(
        words(&[
            ("L", 0.0),
            ("A", 0.25),
            ("T", 0.0),
            ("E", -0.25),
            ("X", 0.0)
        ]),
        "LATEX"
    );
    assert_eq!(words(&[("x", 0.0), ("2", 0.4), ("+y", 0.0)]), "x2+y");
    assert_eq!(words(&[("I", 0.0), ("2", 0.4), ("C bus", 0.0)]), "I2C bus");
    assert_eq!(
        words(&[("10", 0.0), ("6", 0.4), (" cells", 0.0)]),
        "106 cells"
    );
    assert_eq!(words(&[("power", 0.0), ("2n", 0.4)]), "power2n");
    assert_eq!(
        words(&[("CO", 0.0), ("2", -0.3), (" levels", 0.0)]),
        "CO2 levels"
    );
}
