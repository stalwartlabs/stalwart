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
use chrono::{DateTime, Locale as ChronoLocale, NaiveDate, TimeZone, Weekday};
use common::i18n::{self, Locale};
use icu_locale_core::{Locale as IcuLocale, locale};
use icu_plurals::{PluralCategory, PluralRuleType, PluralRules, PluralRulesOptions};
use std::{fmt::Write, str::FromStr};

pub struct TextFormatter {
    pub locale: &'static Locale,
    pub chrono_locale: ChronoLocale,
    cardinal: PluralRules,
    ordinal: PluralRules,
}

impl TextFormatter {
    pub fn new(language: &str) -> trc::Result<Self> {
        let locale = i18n::locale_or_default(language);
        let icu_locale =
            IcuLocale::try_from_str(&locale.name.replace('_', "-")).unwrap_or(locale!("en-US"));
        let prefs = (&icu_locale).into();
        let plural_rules = |options| {
            PluralRules::try_new(prefs, options).map_err(|err| {
                trc::EventType::Calendar(trc::CalendarEvent::ItipMessageError)
                    .into_err()
                    .caused_by(trc::location!())
                    .details("Failed to load plural rules")
                    .ctx(trc::Key::Reason, err.to_string())
            })
        };

        Ok(Self {
            locale,
            chrono_locale: ChronoLocale::from_str(locale.name).unwrap_or(ChronoLocale::en_US),
            cardinal: plural_rules(PluralRulesOptions::default())?,
            ordinal: plural_rules(
                PluralRulesOptions::default().with_type(PluralRuleType::Ordinal),
            )?,
        })
    }

    pub fn field(&self, out: &mut String, value: &ItipValue, template: &str) {
        match value {
            ItipValue::Text(text) => out.push_str(text),
            ItipValue::Time(time) => {
                let tz = Tz::from_id(time.tz_id).unwrap_or(Tz::UTC);
                let _ = write!(
                    out,
                    "{}",
                    tz.from_utc_datetime(
                        &DateTime::from_timestamp(time.start, 0)
                            .unwrap_or_default()
                            .naive_local()
                    )
                    .format_localized(template, self.chrono_locale)
                );

                if let Some(name) = tz.name().filter(|name| !name.is_empty()) {
                    let _ = write!(out, " ({name})");
                }
            }
            ItipValue::Rrule(rrule) => self.recurrence(out, rrule),
            ItipValue::Participants(_) => {}
        }
    }

    pub fn field_to_string(&self, value: &ItipValue, template: &str) -> String {
        let mut out = String::with_capacity(32);
        self.field(&mut out, value, template);
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
            let form = plural_form(
                self.locale.calendar_rrule_count,
                self.cardinal.category_for(*count),
            );
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
        let form = plural_form(entry, self.cardinal.category_for(interval as u32));
        write_number(out, form, "$n", interval as u64);
    }

    fn write_ordinal(&self, out: &mut String, n: u32) {
        let form = plural_form(
            self.locale.calendar_rrule_ordinal,
            self.ordinal.category_for(n),
        );
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
        let count = value.unsigned_abs();
        let form = plural_form(template, self.cardinal.category_for(count));

        if value < 0 {
            let (before, after) = self
                .locale
                .calendar_rrule_from_end
                .split_once("$ordinal")
                .unwrap_or((self.locale.calendar_rrule_from_end, ""));
            out.push_str(before);
            write_number(out, form, "$n", count as u64);
            out.push_str(after);
        } else {
            write_number(out, form, "$n", count as u64);
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
            let _ = write!(out, "{}", date.format_localized("%A", self.chrono_locale));
        }
    }

    fn write_month(&self, out: &mut String, month: u8) {
        if let Some(date) = NaiveDate::from_ymd_opt(2024, month.clamp(1, 12) as u32, 1) {
            let _ = write!(out, "{}", date.format_localized("%B", self.chrono_locale));
        }
    }

    fn write_day(&self, out: &mut String, day: &ICalendarDay) {
        let Some(occurrence) = day.ordwk.filter(|occurrence| *occurrence != 0) else {
            self.write_weekday(out, day.weekday);
            return;
        };

        let nth = self.locale.calendar_rrule_nth_weekday;
        let (before, rest) = nth.split_once("$ordinal").unwrap_or((nth, ""));
        let (middle, after) = rest.split_once("$weekday").unwrap_or((rest, ""));

        if occurrence < 0 {
            let from_end = self.locale.calendar_rrule_from_end;
            let (wrap_before, wrap_after) =
                from_end.split_once("$ordinal").unwrap_or((from_end, ""));
            out.push_str(wrap_before);
            out.push_str(before);
            self.write_ordinal(out, occurrence.unsigned_abs() as u32);
            out.push_str(middle);
            self.write_weekday(out, day.weekday);
            out.push_str(after);
            out.push_str(wrap_after);
        } else {
            out.push_str(before);
            self.write_ordinal(out, occurrence as u32);
            out.push_str(middle);
            self.write_weekday(out, day.weekday);
            out.push_str(after);
        }
    }
}

fn plural_form(entry: &str, category: PluralCategory) -> &str {
    let wanted = match category {
        PluralCategory::Zero => "zero",
        PluralCategory::One => "one",
        PluralCategory::Two => "two",
        PluralCategory::Few => "few",
        PluralCategory::Many => "many",
        PluralCategory::Other => "other",
    };
    let mut fallback = None;

    for form in entry.split(';') {
        let Some((name, text)) = form.split_once('=') else {
            return entry;
        };
        if name == wanted {
            return text;
        } else if name == "other" {
            fallback = Some(text);
        }
    }

    fallback.unwrap_or(entry)
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
    use super::{TextFormatter, plural_form};
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
    fn plural_form_selects_category_and_falls_back_to_other() {
        let entry = "one=single;few=a few;other=many";
        assert_eq!(plural_form(entry, PluralCategory::One), "single");
        assert_eq!(plural_form(entry, PluralCategory::Few), "a few");
        assert_eq!(plural_form(entry, PluralCategory::Many), "many");
        assert_eq!(
            plural_form("no categories", PluralCategory::One),
            "no categories"
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
