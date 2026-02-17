/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

include!(concat!(env!("OUT_DIR"), "/locales.rs"));

pub fn locale_or_default(name: &str) -> &'static Locale {
    locale(name)
        .or_else(|| name.split_once('_').and_then(|(lang, _)| locale(lang)))
        .unwrap_or(&EN_LOCALES)
}

#[cfg(test)]
mod tests {
    use super::locale;

    #[test]
    fn calendar_templates_include_minutes() {
        for lang in ["en", "es", "fr", "de", "it", "pt", "nl", "da", "ca", "el", "sv", "pl"] {
            let locale = locale(lang).expect("locale must exist");
            assert!(
                locale.calendar_date_template.contains("%M"),
                "{lang} calendar.date_template must include minutes"
            );
            assert!(
                locale.calendar_date_template_long.contains("%M"),
                "{lang} calendar.date_template_long must include minutes"
            );
        }
    }
}
