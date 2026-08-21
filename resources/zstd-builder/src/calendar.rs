use std::path::Path;

use calcard::{
    Entry, Parser,
    common::timezone::Tz,
    icalendar::{
        ICalendar, ICalendarParameterName, ICalendarParameterValue, ICalendarProperty,
        ICalendarValue, Uri,
    },
};
use common::DavName;
use groupware::calendar::{
    CalendarEvent, CalendarEventData, EVENT_DRAFT, EVENT_INVITE_OTHERS, EventPreferences,
};

use crate::corpus::{Corpus, Rng, Stats, archive, collect_files, scrub};

const MAX_EXPANSIONS: usize = 3000;
const SCRUB_SEED: u64 = 0x5eed_5c2b;

const KEEP: &[&str] = &[
    "http",
    "https",
    "mailto",
    "data",
    "urn",
    "uuid",
    "www",
    "com",
    "net",
    "org",
    "true",
    "false",
    "base64",
    "image",
    "png",
    "jpeg",
    "gif",
    "text",
    "plain",
    "html",
    "calendar",
    "ics",
    "vcf",
    "charset",
    "utf",
    "8",
];

pub fn build(dir: &Path, keep_text: bool, stats: &mut Stats) -> std::io::Result<Corpus> {
    let files = collect_files(dir, &["ics"])?;
    let mut corpus = Corpus::new();
    let mut seed = 0u64;

    for path in files.iter() {
        let Ok(raw) = std::fs::read_to_string(path) else {
            stats.skipped += 1;
            continue;
        };
        let mut parser = Parser::new(&raw);
        let mut found = 0;
        loop {
            match parser.entry() {
                Entry::ICalendar(real) if !real.components.is_empty() => {
                    seed += 1;
                    let size = real.to_string().len();
                    if keep_text {
                        corpus.push_both(sample(&mut Rng::new(seed), real, size));
                    } else {
                        let mut scrubbed = real.clone();
                        scrub_ical(&mut Rng::new(seed ^ SCRUB_SEED), &mut scrubbed);
                        corpus.push(
                            sample(&mut Rng::new(seed), scrubbed, size),
                            sample(&mut Rng::new(seed), real, size),
                        );
                    }
                    stats.read += 1;
                    found += 1;
                }
                Entry::Eof => break,
                _ => {}
            }
        }

        if found == 0 {
            stats.skipped += 1;
        }
    }

    Ok(corpus)
}

fn sample(rng: &mut Rng, ical: ICalendar, size: usize) -> Vec<u8> {
    archive(&event(rng, ical, size))
}

fn event(rng: &mut Rng, ical: ICalendar, size: usize) -> CalendarEvent {
    let name = ical
        .uids()
        .next()
        .map(|uid| uid.to_string())
        .unwrap_or_else(|| rng.token(36));
    let mut next_email_alarm = None;
    let mut data =
        CalendarEventData::new(ical, Tz::Floating, MAX_EXPANSIONS, &mut next_email_alarm);
    stabilise(&mut data);
    let created = timestamp(rng);
    let display_name_len = rng.range(6, 24);

    CalendarEvent {
        names: vec![DavName {
            name: format!("{name}.ics"),
            parent_id: rng.below(4) as u32,
        }],
        display_name: rng.chance(20).then(|| rng.token(display_name_len)),
        data,
        preferences: if rng.chance(15) {
            vec![EventPreferences {
                account_id: rng.below(4096) as u32,
                flags: 0,
                properties: Vec::new(),
                alerts: Vec::new(),
            }]
        } else {
            Vec::new()
        },
        flags: if rng.chance(10) {
            EVENT_DRAFT
        } else if rng.chance(30) {
            EVENT_INVITE_OTHERS
        } else {
            0
        },
        dead_properties: Default::default(),
        size: size as u32,
        created,
        modified: created + rng.below(86400 * 30) as i64,
        schedule_tag: rng.chance(20).then(|| rng.below(64) as u32),
    }
}

fn stabilise(data: &mut CalendarEventData) {
    let mut ranges = std::mem::take(&mut data.time_ranges).into_vec();
    ranges.sort_unstable_by_key(|range| (range.id, range.start_tz, range.end_tz, range.duration));
    data.time_ranges = ranges.into_boxed_slice();

    let mut alarms = std::mem::take(&mut data.alarms).into_vec();
    alarms.sort_unstable_by_key(|alarm| (alarm.parent_id, alarm.id));
    data.alarms = alarms.into_boxed_slice();
}

fn timestamp(rng: &mut Rng) -> i64 {
    1_750_000_000 + rng.below(86400 * 365) as i64
}

fn scrub_ical(rng: &mut Rng, ical: &mut ICalendar) {
    for component in ical.components.iter_mut() {
        for entry in component.entries.iter_mut() {
            if keep_property(&entry.name) {
                continue;
            }

            for value in entry.values.iter_mut() {
                match value {
                    ICalendarValue::Text(text) => *text = scrub(rng, text, KEEP),
                    ICalendarValue::Uri(Uri::Location(uri)) => *uri = scrub(rng, uri, KEEP),
                    ICalendarValue::Uri(Uri::Data(data)) => {
                        data.data = rng.bytes(data.data.len());
                    }
                    ICalendarValue::Binary(bytes) => {
                        *bytes = rng.bytes(bytes.len());
                    }
                    _ => {}
                }
            }

            for param in entry.params.iter_mut() {
                if matches!(
                    param.name,
                    ICalendarParameterName::Tzid
                        | ICalendarParameterName::Language
                        | ICalendarParameterName::Value
                        | ICalendarParameterName::Fmttype
                ) {
                    continue;
                }
                match &mut param.value {
                    ICalendarParameterValue::Text(text) => *text = scrub(rng, text, KEEP),
                    ICalendarParameterValue::Uri(Uri::Location(uri)) => {
                        *uri = scrub(rng, uri, KEEP)
                    }
                    _ => {}
                }
            }
        }
    }
}

fn keep_property(property: &ICalendarProperty) -> bool {
    matches!(
        property,
        ICalendarProperty::Prodid
            | ICalendarProperty::Version
            | ICalendarProperty::Calscale
            | ICalendarProperty::Method
            | ICalendarProperty::Tzid
            | ICalendarProperty::Tzname
            | ICalendarProperty::Tzurl
            | ICalendarProperty::Categories
            | ICalendarProperty::Class
            | ICalendarProperty::Status
            | ICalendarProperty::Transp
            | ICalendarProperty::Action
    )
}
