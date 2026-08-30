/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::scheduling::ItipValue;
use calcard::{
    common::timezone::Tz,
    icalendar::{ICalendarDay, ICalendarFrequency, ICalendarRecurrenceRule, ICalendarWeekday},
};
use chrono::{DateTime, NaiveDate, TimeZone, Weekday};
use common::i18n::{self, Locale, PluralForms};
use icu_datetime::{DateTimeFormatter, fieldsets};
use icu_locale_core::{Locale as IcuLocale, locale};
use icu_plurals::{PluralCategory, PluralRuleType, PluralRules, PluralRulesOptions};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DateStyle {
    Short,
    Long,
}

pub struct TextFormatter {
    pub locale: &'static Locale,
    date_short: DateTimeFormatter<fieldsets::YMDT>,
    date_long: DateTimeFormatter<fieldsets::YMDT>,
    weekday_short: DateTimeFormatter<fieldsets::E>,
    weekday: DateTimeFormatter<fieldsets::E>,
    month: DateTimeFormatter<fieldsets::M>,
    cardinal: PluralRules,
    ordinal: PluralRules,
}

impl TextFormatter {
    pub fn new(language: &str) -> trc::Result<Self> {
        let locale = i18n::locale_or_default(language);
        let icu_locale = IcuLocale::try_from_str(locale.name).unwrap_or(locale!("en-US"));
        let failed = |detail: &'static str| {
            move |err: icu_datetime::DateTimeFormatterLoadError| {
                trc::EventType::Calendar(trc::CalendarEvent::ItipMessageError)
                    .into_err()
                    .caused_by(trc::location!())
                    .details(detail)
                    .ctx(trc::Key::Reason, err.to_string())
            }
        };
        let plural_prefs = (&icu_locale).into();
        let datetime_prefs = (&icu_locale).into();
        let plural_rules = |options| {
            PluralRules::try_new(plural_prefs, options).map_err(|err| {
                trc::EventType::Calendar(trc::CalendarEvent::ItipMessageError)
                    .into_err()
                    .caused_by(trc::location!())
                    .details("Failed to load plural rules")
                    .ctx(trc::Key::Reason, err.to_string())
            })
        };

        Ok(Self {
            locale,
            date_short: DateTimeFormatter::try_new(
                datetime_prefs,
                fieldsets::YMD::medium().with_time_hm(),
            )
            .map_err(failed("Failed to load short date formatter"))?,
            date_long: DateTimeFormatter::try_new(
                datetime_prefs,
                fieldsets::YMD::long().with_time_hm(),
            )
            .map_err(failed("Failed to load long date formatter"))?,
            weekday_short: DateTimeFormatter::try_new(datetime_prefs, fieldsets::E::short())
                .map_err(failed("Failed to load short weekday formatter"))?,
            weekday: DateTimeFormatter::try_new(datetime_prefs, fieldsets::E::long())
                .map_err(failed("Failed to load weekday formatter"))?,
            month: DateTimeFormatter::try_new(datetime_prefs, fieldsets::M::long())
                .map_err(failed("Failed to load month formatter"))?,
            cardinal: plural_rules(PluralRulesOptions::default())?,
            ordinal: plural_rules(
                PluralRulesOptions::default().with_type(PluralRuleType::Ordinal),
            )?,
        })
    }

    pub fn field(&self, out: &mut String, value: &ItipValue, style: DateStyle) {
        match value {
            ItipValue::Text(text) => out.push_str(text),
            ItipValue::Time(time) => {
                let tz = Tz::from_id(time.tz_id).unwrap_or(Tz::UTC);
                let (weekday, date) = match style {
                    DateStyle::Short => (&self.weekday_short, &self.date_short),
                    DateStyle::Long => (&self.weekday, &self.date_long),
                };
                let local = tz
                    .from_utc_datetime(
                        &DateTime::from_timestamp(time.start, 0)
                            .unwrap_or_default()
                            .naive_local(),
                    )
                    .naive_local();
                let _ = write!(
                    out,
                    "{}, {}",
                    weekday.format(&local.date()),
                    date.format(&local)
                );

                if let Some(name) = tz.name().filter(|name| !name.is_empty()) {
                    let _ = write!(out, " ({name})");
                }
            }
            ItipValue::Rrule(rrule) => self.recurrence(out, rrule),
            ItipValue::Participants(_) => {}
        }
    }

    pub fn field_to_string(&self, value: &ItipValue, style: DateStyle) -> String {
        let mut out = String::with_capacity(32);
        self.field(&mut out, value, style);
        out
    }

    pub fn recurrence(&self, out: &mut String, rule: &ICalendarRecurrenceRule) {
        let start = out.len();
        self.write_frequency(out, &rule.freq, rule.interval.unwrap_or(1));

        if !rule.byday.is_empty() {
            self.write_clause(out, start, self.locale.calendar_rrule_on, |out| {
                self.write_list(out, rule.byday.len(), |out, index| {
                    self.write_day(out, &rule.byday[index])
                })
            });
        }

        if !rule.byhour.is_empty() || !rule.byminute.is_empty() {
            let hours = rule.byhour.len().max(1);
            let minutes = rule.byminute.len().max(1);
            self.write_clause(out, start, self.locale.calendar_rrule_at, |out| {
                self.write_list(out, hours * minutes, |out, index| {
                    let hour = rule.byhour.get(index / minutes).copied().unwrap_or(0);
                    let minute = rule.byminute.get(index % minutes).copied().unwrap_or(0);
                    let _ = write!(out, "{hour:02}:{minute:02}");
                })
            });
        }

        if !rule.bymonthday.is_empty() {
            self.write_clause(out, start, self.locale.calendar_rrule_on_the, |out| {
                self.write_list(out, rule.bymonthday.len(), |out, index| {
                    self.write_signed_ordinal(out, rule.bymonthday[index] as i32)
                })
            });
        }

        if !rule.bymonth.is_empty() {
            self.write_clause(out, start, self.locale.calendar_rrule_in, |out| {
                self.write_list(out, rule.bymonth.len(), |out, index| {
                    self.write_month(out, rule.bymonth[index].month())
                })
            });
        }

        if !rule.byyearday.is_empty() {
            self.write_clause(out, start, self.locale.calendar_rrule_on, |out| {
                self.write_list(out, rule.byyearday.len(), |out, index| {
                    self.write_counted(
                        out,
                        rule.byyearday[index] as i32,
                        self.locale.calendar_rrule_year_day,
                    )
                })
            });
        }

        if !rule.byweekno.is_empty() {
            self.write_clause(out, start, self.locale.calendar_rrule_in, |out| {
                self.write_list(out, rule.byweekno.len(), |out, index| {
                    self.write_counted(
                        out,
                        rule.byweekno[index] as i32,
                        self.locale.calendar_rrule_week_no,
                    )
                })
            });
        }

        if !rule.bysetpos.is_empty() {
            self.write_clause(out, start, self.locale.calendar_rrule_setpos, |out| {
                self.write_list(out, rule.bysetpos.len(), |out, index| {
                    self.write_signed_ordinal(out, rule.bysetpos[index])
                })
            });
        }

        if let Some(count) = rule.count.as_ref() {
            if out.len() > start {
                out.push_str(", ");
            }
            let form = self
                .cardinal
                .category_for(*count)
                .plural_form(&self.locale.calendar_rrule_count);
            write_number(out, form, "$n", *count as u64);
        }
    }

    fn write_clause(
        &self,
        out: &mut String,
        start: usize,
        template: &str,
        write_items: impl FnOnce(&mut String),
    ) {
        let restore = out.len();
        if out.len() > start {
            out.push(' ');
        }

        let (before, after) = template.split_once("$list").unwrap_or((template, ""));
        out.push_str(before);
        let items_start = out.len();
        write_items(out);

        if out.len() == items_start {
            out.truncate(restore);
        } else {
            out.push_str(after);
        }
    }

    fn write_list(
        &self,
        out: &mut String,
        len: usize,
        mut write_item: impl FnMut(&mut String, usize),
    ) {
        match len {
            0 => {}
            1 => write_item(out, 0),
            _ => {
                let conjunction = self.locale.calendar_rrule_and;
                let (prefix, rest) = conjunction.split_once("$a").unwrap_or(("", conjunction));
                let (separator, suffix) = rest.split_once("$b").unwrap_or((rest, ""));

                out.push_str(prefix);
                for index in 0..len - 1 {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    write_item(out, index);
                }
                out.push_str(separator);
                write_item(out, len - 1);
                out.push_str(suffix);
            }
        }
    }

    fn write_frequency(&self, out: &mut String, freq: &ICalendarFrequency, interval: u16) {
        let entry = match freq {
            ICalendarFrequency::Secondly => self.locale.calendar_rrule_secondly,
            ICalendarFrequency::Minutely => self.locale.calendar_rrule_minutely,
            ICalendarFrequency::Hourly => self.locale.calendar_rrule_hourly,
            ICalendarFrequency::Daily => self.locale.calendar_rrule_daily,
            ICalendarFrequency::Weekly => self.locale.calendar_rrule_weekly,
            ICalendarFrequency::Monthly => self.locale.calendar_rrule_monthly,
            ICalendarFrequency::Yearly => self.locale.calendar_rrule_yearly,
        };
        let form = self
            .cardinal
            .category_for(interval as u32)
            .plural_form(&entry);
        write_number(out, form, "$n", interval as u64);
    }

    fn write_ordinal(&self, out: &mut String, n: u32) {
        let form = self
            .ordinal
            .category_for(n)
            .plural_form(&self.locale.calendar_rrule_ordinal);
        write_number(out, form, "$n", n as u64);
    }

    fn write_signed_ordinal(&self, out: &mut String, value: i32) {
        if value < 0 {
            let (before, after) = self
                .locale
                .calendar_rrule_from_end
                .split_once("$ordinal")
                .unwrap_or((self.locale.calendar_rrule_from_end, ""));
            out.push_str(before);
            self.write_ordinal(out, value.unsigned_abs());
            out.push_str(after);
        } else {
            self.write_ordinal(out, value.unsigned_abs());
        }
    }

    fn write_counted(&self, out: &mut String, value: i32, template: &str) {
        let count = value.unsigned_abs() as u64;

        if value < 0 {
            let (before, after) = self
                .locale
                .calendar_rrule_from_end
                .split_once("$ordinal")
                .unwrap_or((self.locale.calendar_rrule_from_end, ""));
            out.push_str(before);
            write_number(out, template, "$n", count);
            out.push_str(after);
        } else {
            write_number(out, template, "$n", count);
        }
    }

    fn write_weekday(&self, out: &mut String, weekday: ICalendarWeekday) {
        let weekday = match weekday {
            ICalendarWeekday::Monday => Weekday::Mon,
            ICalendarWeekday::Tuesday => Weekday::Tue,
            ICalendarWeekday::Wednesday => Weekday::Wed,
            ICalendarWeekday::Thursday => Weekday::Thu,
            ICalendarWeekday::Friday => Weekday::Fri,
            ICalendarWeekday::Saturday => Weekday::Sat,
            ICalendarWeekday::Sunday => Weekday::Sun,
        };

        if let Some(date) = NaiveDate::from_isoywd_opt(2024, 1, weekday) {
            let _ = write!(out, "{}", self.weekday.format(&date));
        }
    }

    fn write_month(&self, out: &mut String, month: u8) {
        if let Some(date) = NaiveDate::from_ymd_opt(2024, month.clamp(1, 12) as u32, 1) {
            let _ = write!(out, "{}", self.month.format(&date));
        }
    }

    fn write_day(&self, out: &mut String, day: &ICalendarDay) {
        let Some(occurrence) = day.ordwk.filter(|occurrence| *occurrence != 0) else {
            self.write_weekday(out, day.weekday);
            return;
        };

        let (wrap_before, wrap_after) = if occurrence < 0 {
            let from_end = self.locale.calendar_rrule_from_end;
            from_end.split_once("$ordinal").unwrap_or((from_end, ""))
        } else {
            ("", "")
        };

        out.push_str(wrap_before);

        let mut rest = self.locale.calendar_rrule_nth_weekday;
        loop {
            let Some((at, placeholder)) = ["$ordinal", "$weekday"]
                .into_iter()
                .filter_map(|placeholder| rest.find(placeholder).map(|at| (at, placeholder)))
                .min()
            else {
                out.push_str(rest);
                break;
            };

            out.push_str(&rest[..at]);
            if placeholder == "$ordinal" {
                self.write_ordinal(out, occurrence.unsigned_abs() as u32);
            } else {
                self.write_weekday(out, day.weekday);
            }
            rest = &rest[at + placeholder.len()..];
        }

        out.push_str(wrap_after);
    }
}

trait PluralCategoryExt {
    fn plural_form(&self, forms: &PluralForms) -> &'static str;
}

impl PluralCategoryExt for PluralCategory {
    fn plural_form(&self, forms: &PluralForms) -> &'static str {
        match self {
            PluralCategory::Zero => forms.zero,
            PluralCategory::One => forms.one,
            PluralCategory::Two => forms.two,
            PluralCategory::Few => forms.few,
            PluralCategory::Many => forms.many,
            PluralCategory::Other => forms.other,
        }
    }
}

fn write_number(out: &mut String, template: &str, placeholder: &str, value: u64) {
    let mut rest = template;

    while let Some((before, after)) = rest.split_once(placeholder) {
        out.push_str(before);
        let _ = write!(out, "{value}");
        rest = after;
    }

    out.push_str(rest);
}

pub fn hyperlink(value: &str) -> Option<&str> {
    let (scheme, _) = value.split_once(':')?;

    ["https", "http", "tel", "sip", "sips", "xmpp"]
        .iter()
        .any(|candidate| scheme.eq_ignore_ascii_case(candidate))
        .then_some(value)
}

#[cfg(test)]
mod tests {
    use super::{PluralCategoryExt, PluralForms, TextFormatter, i18n};
    use calcard::icalendar::{
        ICalendarDay, ICalendarFrequency, ICalendarRecurrenceRule, ICalendarWeekday,
    };
    use icu_plurals::PluralCategory;

    fn rule(freq: ICalendarFrequency, interval: Option<u16>) -> ICalendarRecurrenceRule {
        ICalendarRecurrenceRule {
            freq,
            interval,
            ..Default::default()
        }
    }

    fn format(language: &str, rule: &ICalendarRecurrenceRule) -> String {
        let mut out = String::new();
        TextFormatter::new(language)
            .expect("formatter")
            .recurrence(&mut out, rule);
        out
    }

    #[test]
    fn every_shipped_locale_loads_icu_data() {
        for locale in i18n::ALL_LOCALES {
            let formatter = TextFormatter::new(locale.name)
                .unwrap_or_else(|err| panic!("{}: {err:?}", locale.name));
            assert_eq!(formatter.locale.name, locale.name);

            let mut out = String::new();
            formatter.recurrence(
                &mut out,
                &ICalendarRecurrenceRule {
                    freq: ICalendarFrequency::Monthly,
                    interval: Some(2),
                    count: Some(5),
                    bymonthday: vec![3, -1],
                    byday: vec![ICalendarDay {
                        ordwk: Some(2),
                        weekday: ICalendarWeekday::Monday,
                    }],
                    ..Default::default()
                },
            );
            assert!(!out.is_empty(), "{} produced no text", locale.name);
        }
    }

    #[test]
    fn plural_form_selects_category_and_falls_back_to_other() {
        let forms = PluralForms {
            zero: "many",
            one: "single",
            two: "many",
            few: "a few",
            many: "many",
            other: "many",
        };
        assert_eq!(PluralCategory::One.plural_form(&forms), "single");
        assert_eq!(PluralCategory::Few.plural_form(&forms), "a few");
        assert_eq!(PluralCategory::Many.plural_form(&forms), "many");
        assert_eq!(PluralCategory::Other.plural_form(&forms), "many");

        // Categories a locale omits are filled from "other" at build time
        let polish = i18n::locale("pl-PL").expect("locale must exist");
        assert_eq!(polish.calendar_rrule_secondly.many, "Co $n sekund");
        assert_eq!(
            polish.calendar_rrule_secondly.zero,
            polish.calendar_rrule_secondly.other
        );
    }

    #[test]
    fn frequency_uses_cardinal_plural_rules() {
        assert_eq!(
            format("en", &rule(ICalendarFrequency::Weekly, None)),
            "Every week"
        );
        assert_eq!(
            format("en", &rule(ICalendarFrequency::Weekly, Some(2))),
            "Every 2 weeks"
        );

        // Polish distinguishes one / few / many, unlike English
        assert_eq!(
            format("pl", &rule(ICalendarFrequency::Weekly, Some(1))),
            "Co tydzień"
        );
        assert_eq!(
            format("pl", &rule(ICalendarFrequency::Weekly, Some(2))),
            "Co 2 tygodnie"
        );
        assert_eq!(
            format("pl", &rule(ICalendarFrequency::Weekly, Some(5))),
            "Co 5 tygodni"
        );
    }

    #[test]
    fn weekday_names_are_localized_without_translation_keys() {
        let mut byday = rule(ICalendarFrequency::Weekly, None);
        byday.byday = vec![ICalendarDay {
            weekday: ICalendarWeekday::Monday,
            ordwk: None,
        }];

        assert_eq!(format("en", &byday), "Every week on Monday");
        assert_eq!(format("es", &byday), "Cada semana los lunes");
    }

    #[test]
    fn ordinal_weekday_uses_ordinal_plural_rules() {
        let mut byday = rule(ICalendarFrequency::Monthly, None);
        byday.byday = vec![ICalendarDay {
            weekday: ICalendarWeekday::Tuesday,
            ordwk: Some(2),
        }];
        assert_eq!(format("en", &byday), "Every month on the 2nd Tuesday");

        byday.byday = vec![ICalendarDay {
            weekday: ICalendarWeekday::Tuesday,
            ordwk: Some(3),
        }];
        assert_eq!(format("en", &byday), "Every month on the 3rd Tuesday");

        byday.byday = vec![ICalendarDay {
            weekday: ICalendarWeekday::Tuesday,
            ordwk: Some(-1),
        }];
        assert_eq!(
            format("en", &byday),
            "Every month on the 1st Tuesday from the end"
        );
    }

    #[test]
    fn count_is_pluralized_and_appended() {
        let mut counted = rule(ICalendarFrequency::Daily, None);
        counted.count = Some(1);
        assert_eq!(format("en", &counted), "Every day, 1 time");

        counted.count = Some(5);
        assert_eq!(format("en", &counted), "Every day, 5 times");
    }

    #[test]
    fn multiple_days_are_joined_with_the_localized_conjunction() {
        let mut byday = rule(ICalendarFrequency::Weekly, None);
        byday.byday = vec![
            ICalendarDay {
                weekday: ICalendarWeekday::Monday,
                ordwk: None,
            },
            ICalendarDay {
                weekday: ICalendarWeekday::Wednesday,
                ordwk: None,
            },
            ICalendarDay {
                weekday: ICalendarWeekday::Friday,
                ordwk: None,
            },
        ];

        assert_eq!(
            format("en", &byday),
            "Every week on Monday, Wednesday and Friday"
        );
    }

    #[test]
    fn unknown_language_falls_back_to_english_rules() {
        assert_eq!(
            format("zz", &rule(ICalendarFrequency::Weekly, Some(3))),
            "Every 3 weeks"
        );
    }
}
