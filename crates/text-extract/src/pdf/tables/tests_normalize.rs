/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{combining_accent, presentation_form};

#[test]
fn presentation_forms() {
    let cases = [
        ('\u{FB00}', Some("ff")),
        ('\u{FB01}', Some("fi")),
        ('\u{FB03}', Some("ffi")),
        ('\u{FB05}', Some("st")),
        ('\u{FB06}', Some("st")),
        ('\u{FB13}', Some("\u{574}\u{576}")),
        ('\u{FB1D}', Some("\u{5D9}\u{5B4}")),
        ('\u{FB2A}', Some("\u{5E9}\u{5C1}")),
        ('\u{FB4F}', Some("\u{5D0}\u{5DC}")),
        ('\u{FB50}', Some("\u{671}")),
        ('\u{FDF2}', Some("\u{627}\u{644}\u{644}\u{647}")),
        ('\u{FE70}', Some(" \u{64B}")),
        ('\u{FE8D}', Some("\u{627}")),
        ('\u{FE8E}', Some("\u{627}")),
        ('\u{FEF5}', Some("\u{644}\u{622}")),
        ('\u{FEFC}', Some("\u{644}\u{627}")),
        ('\u{FEFF}', None),
        ('\u{FDD0}', None),
        ('\u{FB07}', None),
        ('a', None),
        ('\u{1F600}', None),
    ];
    for (c, expected) in cases {
        assert_eq!(presentation_form(c), expected, "{:X}", u32::from(c));
    }
}

#[test]
fn spacing_accents() {
    let cases = [
        ('\u{B4}', Some('\u{301}')),
        ('`', Some('\u{300}')),
        ('\u{2C7}', Some('\u{30C}')),
        ('\u{2DD}', Some('\u{30B}')),
        ('a', None),
        ('^', None),
    ];
    for (c, expected) in cases {
        assert_eq!(combining_accent(c), expected, "{c}");
    }
}
