/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

include!(concat!(env!("OUT_DIR"), "/locales.rs"));

pub fn locale_or_default(name: &str) -> &'static Locale {
    if let Some(locale) = locale(name) {
        return locale;
    }

    locale_by_language(name.split(['_', '-']).next().unwrap_or(name)).unwrap_or(&EN_US_LOCALES)
}

#[cfg(test)]
mod tests {
    use super::{locale, locale_or_default};

    const LOCALES: [&str; 12] = [
        "en_US", "es_ES", "fr_FR", "de_DE", "it_IT", "pt_PT", "nl_NL", "da_DK", "ca_ES", "el_GR",
        "sv_SE", "pl_PL",
    ];

    #[test]
    fn calendar_templates_include_minutes() {
        for lang in LOCALES {
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

    #[test]
    fn locales_are_named_after_themselves() {
        for lang in LOCALES {
            assert_eq!(locale(lang).expect("locale must exist").name, lang);
        }
    }

    #[test]
    fn bare_and_hyphenated_language_tags_resolve() {
        for (input, expected) in [
            ("es_ES", "es_ES"),
            ("es", "es_ES"),
            ("es-ES", "es_ES"),
            ("es_MX", "es_ES"),
            ("pt-BR", "pt_PT"),
            ("zz", "en_US"),
            ("", "en_US"),
            // BCP 47 tags are case-insensitive
            ("ES", "es_ES"),
            ("es_es", "es_ES"),
            ("PT-br", "pt_PT"),
            ("EL_GR", "el_GR"),
        ] {
            assert_eq!(
                locale_or_default(input).name,
                expected,
                "failed for {input}"
            );
        }
    }
}
