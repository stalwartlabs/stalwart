/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DateTimeResult, PartialDateTime, tzdb};
use hashify::map;
use jiff::{
    SignedDuration, Timestamp,
    civil::{Date, DateTime, Time},
    tz::{AmbiguousOffset, Offset, TimeZone, TimeZoneDatabase},
};
use std::{borrow::Cow, hash::Hash, str::FromStr, sync::OnceLock};

/// The value type of the proprietary time zone name tables.
type TzName = &'static str;

pub(crate) const SECONDS_PER_DAY: i64 = 86_400;

/// A reference to the time zone a calendar value is interpreted in.
///
/// The three forms map onto the three date-time forms of RFC 5545 section
/// 3.3.5: a floating value carries no zone at all, a fixed value carries a UTC
/// offset, and a named value references the IANA time zone database.
///
/// `Tz` is a small `Copy` value. Named zones are stored as an identifier into
/// a committed table (see [`Tz::as_id`]) and resolved to a `jiff` time zone
/// once per process, so passing a `Tz` around never touches a reference count.
#[derive(Clone, Copy, Default, Eq)]
pub enum Tz {
    /// No time zone: the value means the same wall clock reading everywhere.
    #[default]
    Floating,
    /// A fixed offset from UTC.
    Fixed(Offset),
    /// A named IANA zone, held as an identifier into the time zone table.
    Iana(u16),
}

/// Resolved time zones, kept for the lifetime of the process.
static RESOLVED: [OnceLock<Option<TimeZone>>; tzdb::len()] =
    [const { OnceLock::new() }; tzdb::len()];

impl Tz {
    /// The UTC time zone.
    pub const UTC: Self = Self::Iana(tzdb::UTC_ID);

    /// Returns the time zone for an IANA name, if the database knows it and
    /// the name has an identifier assigned.
    pub fn iana(name: &str) -> Option<Self> {
        let tz = Self::Iana(tzdb::name_to_id(name)?);
        tz.time_zone().is_some().then_some(tz)
    }

    pub fn from_iana_id(id: u16) -> Option<Self> {
        tzdb::id_to_name(id).map(|_| Self::Iana(id))
    }

    pub fn iana_name(&self) -> Option<&'static str> {
        match self {
            Self::Iana(id) => tzdb::id_to_name(*id),
            Self::Fixed(_) | Self::Floating => None,
        }
    }

    pub fn offset_at_unix(&self, seconds: i64) -> i32 {
        Timestamp::from_second(seconds).map_or(0, |timestamp| self.offset_at(timestamp).seconds())
    }

    /// Resolves a named zone, caching it for the lifetime of the process.
    ///
    /// Returns `None` for floating and fixed zones, and for a name the time
    /// zone database does not know.
    pub fn time_zone(&self) -> Option<&'static TimeZone> {
        let Self::Iana(id) = *self else {
            return None;
        };
        RESOLVED
            .get(usize::from(id))?
            .get_or_init(|| {
                let name = tzdb::id_to_name(id)?;
                TimeZone::get(name)
                    .or_else(|_| TimeZoneDatabase::bundled().get(name))
                    .ok()
                    .or_else(|| Self::builtin_time_zone(name))
            })
            .as_ref()
    }

    fn builtin_time_zone(name: &str) -> Option<TimeZone> {
        let name = name.strip_prefix("Etc/").unwrap_or(name);
        if matches!(
            name,
            "UTC" | "UCT" | "Universal" | "Zulu" | "GMT" | "GMT0" | "GMT+0" | "GMT-0" | "Greenwich"
        ) {
            return Some(TimeZone::UTC);
        }
        let hours = name.strip_prefix("GMT")?.parse::<i8>().ok()?;
        Offset::from_hours(-hours).ok().map(TimeZone::fixed)
    }

    /// Returns the UTC offset in effect at an instant.
    fn offset_at(&self, timestamp: Timestamp) -> Offset {
        match self {
            Self::Floating => Offset::UTC,
            Self::Fixed(offset) => *offset,
            Self::Iana(_) => self
                .time_zone()
                .map_or(Offset::UTC, |tz| tz.to_offset(timestamp)),
        }
    }

    /// Interprets a wall clock reading in this time zone.
    pub fn from_local(&self, local: DateTime) -> Option<ZonedDateTime> {
        self.interpret_local(local).map(|(zoned, _)| zoned)
    }

    pub fn from_local_later(&self, local: DateTime) -> Option<ZonedDateTime> {
        match self
            .time_zone()
            .map(|tz| tz.to_ambiguous_timestamp(local).offset())
        {
            Some(AmbiguousOffset::Fold { after, .. }) => Some(ZonedDateTime {
                local,
                offset: after,
                tz: *self,
            }),
            _ => self.from_local(local),
        }
    }

    pub(crate) fn interpret_local(&self, local: DateTime) -> Option<(ZonedDateTime, bool)> {
        let (offset, in_gap) = match self {
            Self::Floating => (Offset::UTC, false),
            Self::Fixed(offset) => (*offset, false),
            Self::Iana(_) => match self.time_zone()?.to_ambiguous_timestamp(local).offset() {
                AmbiguousOffset::Unambiguous { offset } => (offset, false),
                AmbiguousOffset::Fold { before, .. } => (before, false),
                AmbiguousOffset::Gap { before, .. } => (before, true),
            },
        };
        Some((
            ZonedDateTime {
                local,
                offset,
                tz: *self,
            },
            in_gap,
        ))
    }

    /// Interprets an instant in this time zone.
    pub fn from_timestamp(&self, timestamp: Timestamp) -> ZonedDateTime {
        let offset = self.offset_at(timestamp);
        ZonedDateTime {
            local: offset.to_datetime(timestamp),
            offset,
            tz: *self,
        }
    }

    /// Interprets a wall clock reading, kept for call sites that predate
    /// [`Tz::from_local`] handling gaps itself.
    #[inline]
    pub fn resolve_local_datetime(&self, local: DateTime) -> Option<ZonedDateTime> {
        self.from_local(local)
    }

    /// Returns the identifier for this time zone.
    pub fn as_id(&self) -> u16 {
        match self {
            Self::Iana(id) => *id,
            Self::Fixed(offset) => {
                let minutes = offset.seconds() / 60;
                debug_assert!((-1440..=1440).contains(&minutes));
                0x8000 | ((minutes + 1440) as u16)
            }
            Self::Floating => 0x8000,
        }
    }

    /// Returns the time zone an identifier refers to.
    pub fn from_id(id: u16) -> Option<Self> {
        if id & 0x8000 == 0 {
            tzdb::id_to_name(id).map(|_| Self::Iana(id))
        } else if id == 0x8000 {
            Some(Self::Floating)
        } else {
            let minutes = i32::from(id & 0x7FFF) - 1440;
            (-1440..=1440)
                .contains(&minutes)
                .then(|| Offset::from_seconds(minutes * 60).ok())
                .flatten()
                .map(Self::Fixed)
        }
    }

    /// Returns the IANA name of this time zone, if it has one.
    pub fn name(&self) -> Option<Cow<'static, str>> {
        match self {
            Self::Iana(id) if *id == tzdb::UTC_ID => Some(Cow::Borrowed("Etc/UTC")),
            Self::Iana(id) => tzdb::id_to_name(*id).map(Cow::Borrowed),
            Self::Fixed(offset) => {
                let hour = offset.seconds() / 3600;
                Some(if hour != 0 {
                    // `Etc/GMT` names invert the sign of the offset.
                    Cow::Owned(format!(
                        "Etc/GMT{}{}",
                        if hour < 0 { "+" } else { "-" },
                        hour.abs()
                    ))
                } else {
                    Cow::Borrowed("Etc/UTC")
                })
            }
            Self::Floating => None,
        }
    }

    #[inline]
    pub fn to_resolved(&self) -> Option<Tz> {
        match self {
            Self::Floating => None,
            _ => Some(*self),
        }
    }

    #[inline]
    pub fn is_floating(&self) -> bool {
        matches!(self, Self::Floating)
    }

    /// Returns whether this zone is UTC, under any of its names.
    pub fn is_utc(&self) -> bool {
        match self {
            Self::Iana(_) => self
                .name()
                .is_some_and(|name| matches!(name.as_ref(), "Etc/UTC" | "Etc/GMT" | "UTC" | "GMT")),
            Self::Fixed(offset) => offset.seconds() == 0,
            Self::Floating => false,
        }
    }

    /// Returns whether this zone has the same offset all year round.
    pub fn has_fixed_offset(&self) -> bool {
        match self {
            Self::Floating | Self::Fixed(_) => true,
            Self::Iana(_) => self
                .time_zone()
                .is_some_and(|tz| tz.following(Timestamp::MIN).next().is_none()),
        }
    }

    /// Returns the offset from UTC, in seconds, in effect on a date.
    pub fn offset_from_utc_date(&self, utc: Date) -> i32 {
        match self {
            Self::Floating => 0,
            Self::Fixed(offset) => offset.seconds(),
            Self::Iana(_) => Offset::UTC
                .to_timestamp(utc.to_datetime(Time::midnight()))
                .map_or(0, |timestamp| self.offset_at(timestamp).seconds()),
        }
    }

    /// Returns the current offset from UTC, split into the parts a serialized
    /// value is written from.
    pub fn offset_parts(&self) -> PartialDateTime {
        let mut seconds = self.offset_at(Timestamp::now()).seconds();

        let tz_minus = if seconds < 0 {
            seconds = -seconds;
            true
        } else {
            false
        };

        PartialDateTime {
            tz_hour: Some((seconds / 3600) as u8),
            tz_minute: Some(((seconds % 3600) / 60) as u8),
            tz_minus,
            ..Default::default()
        }
    }
}

impl PartialEq for Tz {
    fn eq(&self, other: &Self) -> bool {
        self.as_id() == other.as_id()
    }
}

impl PartialOrd for Tz {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tz {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_id().cmp(&other.as_id())
    }
}

impl Hash for Tz {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_id().hash(state);
    }
}

impl std::fmt::Debug for Tz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for Tz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Floating => f.write_str("Floating"),
            Self::Fixed(offset) => write!(f, "{offset}"),
            Self::Iana(id) => match tzdb::id_to_name(*id) {
                Some(name) => f.write_str(name),
                None => write!(f, "Unknown({id})"),
            },
        }
    }
}

/// A wall clock reading together with the time zone it belongs to.
#[derive(Clone, Copy)]
pub struct ZonedDateTime {
    local: DateTime,
    offset: Offset,
    tz: Tz,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NominalDuration {
    civil: SignedDuration,
    exact: SignedDuration,
}

impl NominalDuration {
    pub const DAY: Self = Self::new(1, 0);

    pub const fn new(days: i32, exact_seconds: i64) -> Self {
        Self {
            civil: SignedDuration::from_secs(days as i64 * SECONDS_PER_DAY),
            exact: SignedDuration::from_secs(exact_seconds),
        }
    }

    pub fn between(from: ZonedDateTime, to: ZonedDateTime) -> Self {
        Self {
            civil: SignedDuration::from_secs(to.naive_timestamp() - from.naive_timestamp()),
            exact: SignedDuration::ZERO,
        }
    }
}

impl ZonedDateTime {
    /// Returns the wall clock reading in this value's own time zone.
    #[inline]
    pub fn naive_local(&self) -> DateTime {
        self.local
    }

    /// Returns the time zone this value is interpreted in.
    #[inline]
    pub fn timezone(&self) -> Tz {
        self.tz
    }

    /// Returns the offset from UTC in effect at this value's instant.
    #[inline]
    pub fn offset(&self) -> Offset {
        self.offset
    }

    /// Returns the instant this value refers to.
    #[inline]
    pub fn to_timestamp(&self) -> Timestamp {
        self.offset
            .to_timestamp(self.local)
            .unwrap_or(if self.local < DateTime::default() {
                Timestamp::MIN
            } else {
                Timestamp::MAX
            })
    }

    /// Returns the instant this value refers to, in whole seconds since the
    /// Unix epoch.
    #[inline]
    pub fn timestamp(&self) -> i64 {
        self.to_timestamp().as_second()
    }

    /// Returns the wall clock reading as seconds since the Unix epoch, as
    /// though it were UTC.
    #[inline]
    pub fn naive_timestamp(&self) -> i64 {
        Offset::UTC
            .to_timestamp(self.local)
            .map_or(0, |timestamp| timestamp.as_second())
    }

    /// Returns the calendar date this value falls on in its own zone.
    #[inline]
    pub fn date(&self) -> Date {
        self.local.date()
    }

    /// Returns how long has elapsed between another value and this one.
    pub fn signed_duration_since(&self, earlier: Self) -> SignedDuration {
        SignedDuration::from_secs(self.timestamp() - earlier.timestamp())
    }

    /// Returns the number of whole days between another value's date and this
    /// one's, counted in each value's own zone.
    pub fn days_since(&self, earlier: Self) -> i32 {
        earlier
            .local
            .date()
            .until(self.local.date())
            .map_or(0, |span| span.get_days())
    }

    /// Returns this same instant, read in another time zone.
    pub fn with_timezone(&self, tz: Tz) -> Self {
        if tz == self.tz {
            return *self;
        }
        match tz {
            // A floating value keeps the wall clock reading and drops the
            // instant, which is the only way to move into a floating zone.
            Tz::Floating => Self {
                local: self.local,
                offset: Offset::UTC,
                tz,
            },
            _ => tz.from_timestamp(self.to_timestamp()),
        }
    }

    /// Returns this value moved by an exact duration.
    pub fn checked_add(&self, duration: SignedDuration) -> Option<Self> {
        let timestamp = self.to_timestamp().checked_add(duration).ok()?;
        Some(self.tz.from_timestamp(timestamp))
    }

    /// Returns this value moved by a calendar span.
    pub fn checked_add_nominal(&self, duration: NominalDuration) -> Option<Self> {
        let moved = if duration.civil.is_zero() {
            *self
        } else {
            self.tz
                .from_local(self.local.checked_add(duration.civil).ok()?)?
        };
        if duration.exact.is_zero() {
            Some(moved)
        } else {
            moved.checked_add(duration.exact)
        }
    }
}

impl PartialEq for ZonedDateTime {
    /// Compares the instant, so the same moment read in two zones is equal.
    fn eq(&self, other: &Self) -> bool {
        self.to_timestamp() == other.to_timestamp()
    }
}

impl Eq for ZonedDateTime {}

impl PartialOrd for ZonedDateTime {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ZonedDateTime {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_timestamp().cmp(&other.to_timestamp())
    }
}

impl Hash for ZonedDateTime {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_timestamp().hash(state);
    }
}

impl std::fmt::Display for ZonedDateTime {
    /// Writes the value in the form RFC 3339 defines, always spelling out the
    /// offset.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.write_rfc3339(f, false)
    }
}

impl std::fmt::Debug for ZonedDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self} [{}]", self.tz)
    }
}

impl ZonedDateTime {
    /// Writes the value in the form RFC 3339 defines, abbreviating a zero
    /// offset as `Z`.
    fn write_rfc3339(&self, f: &mut std::fmt::Formatter<'_>, zulu: bool) -> std::fmt::Result {
        let seconds = self.offset.seconds();
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.local.year(),
            self.local.month(),
            self.local.day(),
            self.local.hour(),
            self.local.minute(),
            self.local.second(),
        )?;
        if zulu && seconds == 0 {
            return f.write_str("Z");
        }
        let (sign, seconds) = if seconds < 0 {
            ('-', -seconds)
        } else {
            ('+', seconds)
        };
        write!(
            f,
            "{sign}{:02}:{:02}",
            seconds / 3600,
            (seconds % 3600) / 60
        )
    }
}

#[cfg(any(all(test, stalwart_tests), feature = "serde"))]
impl serde::Serialize for ZonedDateTime {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        /// Serializes with `Z` for a zero offset, the form RFC 3339 prefers
        /// and the one a serialized expansion is read back from.
        struct Zulu<'x>(&'x ZonedDateTime);

        impl std::fmt::Display for Zulu<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.write_rfc3339(f, true)
            }
        }

        serializer.collect_str(&Zulu(self))
    }
}

impl PartialDateTime {
    pub fn to_date_time_with_tz(&self, tz: Tz) -> Option<ZonedDateTime> {
        self.to_date_time()
            .and_then(|dt| dt.to_date_time_with_tz(tz))
    }
}

impl DateTimeResult {
    /// Returns the time zone the value carried itself, if it carried one.
    pub fn tz(&self) -> Option<Tz> {
        self.offset.map(|offset| {
            if offset.seconds() == 0 {
                Tz::UTC
            } else {
                Tz::Fixed(offset)
            }
        })
    }

    /// Interprets the value, preferring the offset it carries itself over the
    /// zone supplied by the caller.
    pub fn to_date_time_with_tz(&self, tz: Tz) -> Option<ZonedDateTime> {
        match self.offset {
            Some(offset) if offset.seconds() == 0 => Tz::UTC.from_local(self.date_time),
            Some(offset) => Tz::Fixed(offset).from_local(self.date_time),
            None => tz.from_local(self.date_time),
        }
    }

    /// Interprets the value the same way as [`Self::to_date_time_with_tz`].
    #[inline]
    pub fn resolve_with_tz(&self, tz: Tz) -> Option<ZonedDateTime> {
        self.to_date_time_with_tz(tz)
    }
}

impl Tz {
    pub fn from_ms_cdo_zone_id(id: &str) -> Option<Self> {
        // Source https://learn.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2007/aa563018(v=exchg.80)
        map!(id.as_bytes(), &'static str,
            "0" => "UTC",
            "1" => "Europe/London",
            "10" => "America/New_York",
            "11" => "America/Chicago",
            "12" => "America/Denver",
            "13" => "America/Los_Angeles",
            "14" => "America/Anchorage",
            "15" => "Pacific/Honolulu",
            "16" => "Pacific/Midway",
            "17" => "Pacific/Auckland",
            "18" => "Australia/Brisbane",
            "19" => "Australia/Adelaide",
            "2" => "Europe/Lisbon",
            "20" => "Asia/Tokyo",
            "21" => "Asia/Singapore",
            "22" => "Asia/Bangkok",
            "23" => "Asia/Calcutta",
            "24" => "Asia/Muscat",
            "25" => "Asia/Tehran",
            "26" => "Asia/Baghdad",
            "27" => "Asia/Jerusalem",
            "28" => "America/St_Johns",
            "29" => "Atlantic/Azores",
            "3" => "Europe/Paris",
            "30" => "America/Noronha",
            "31" => "Africa/Casablanca",
            "32" => "America/Argentina/Buenos_Aires",
            "33" => "America/Caracas",
            "34" => "America/Indiana/Indianapolis",
            "35" => "America/Bogota",
            "36" => "America/Edmonton",
            "37" => "America/Mexico_City",
            "38" => "America/Phoenix",
            "39" => "Pacific/Kwajalein",
            "4" => "Europe/Berlin",
            "40" => "Pacific/Fiji",
            "41" => "Asia/Magadan",
            "42" => "Australia/Hobart",
            "43" => "Pacific/Guam",
            "44" => "Australia/Darwin",
            "45" => "Asia/Shanghai",
            "46" => "Asia/Almaty",
            "47" => "Asia/Karachi",
            "48" => "Asia/Kabul",
            "49" => "Africa/Cairo",
            "5" => "Europe/Bucharest",
            "50" => "Africa/Harare",
            "51" => "Europe/Moscow",
            "53" => "Atlantic/Cape_Verde",
            "54" => "Asia/Baku",
            "55" => "America/Guatemala",
            "56" => "Africa/Nairobi",
            "58" => "Asia/Yekaterinburg",
            "59" => "Europe/Helsinki",
            "6" => "Europe/Prague",
            "60" => "America/Godthab",
            "61" => "Asia/Rangoon",
            "62" => "Asia/Kathmandu",
            "63" => "Asia/Irkutsk",
            "64" => "Asia/Krasnoyarsk",
            "65" => "America/Santiago",
            "66" => "Asia/Colombo",
            "67" => "Pacific/Tongatapu",
            "68" => "Asia/Vladivostok",
            "69" => "Africa/Luanda",
            "7" => "Europe/Athens",
            "70" => "Asia/Yakutsk",
            "71" => "Asia/Dhaka",
            "72" => "Asia/Seoul",
            "73" => "Australia/Perth",
            "74" => "Asia/Kuwait",
            "75" => "Asia/Taipei",
            "76" => "Australia/Sydney",
            "8" => "America/Sao_Paulo",
            "9" => "America/Halifax",
        )
        .copied()
        .and_then(Tz::iana)
    }
}

impl FromStr for Tz {
    type Err = ();

    /*
      Calconnect recommends ignoring VTIMEZONE and just "guess" the timezone

      See: https://standards.calconnect.org/cc/cc-r0602-2006.html

    */

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // First try the name as given
        if let Some(tz) = Tz::iana(s) {
            return Ok(tz);
        }

        // Strip common prefixes
        let mut s = s.trim();
        let mut zone_offset = None;
        let mut retry_iana = false;
        if let Some(part) = s.strip_prefix('(') {
            if let Some((zone, name)) = part.split_once(')') {
                s = name.trim_start();
                zone_offset = Some(zone.trim());
            }
        } else if let Some(mut name) = s.strip_prefix('/') {
            /*
               The presence of the SOLIDUS character as a prefix, indicates that
               this "TZID" represents a unique ID in a globally defined time zone
               registry (when such registry is defined).
            */
            if name.as_bytes().iter().filter(|&&c| c == b'/').count() > 2 {
                // Extract zones such as '/softwarestudio.org/Olson_20011030_5/America/Chicago'
                if let Some(new_name) = name.splitn(3, '/').nth(2) {
                    name = new_name.strip_prefix("SystemV/").unwrap_or(new_name);
                }
            }
            retry_iana = true;
            s = name;
        }

        // Try again with the stripped name
        if retry_iana && let Some(tz) = Tz::iana(s) {
            return Ok(tz);
        }

        // Map proprietary timezones to IANA names
        let result = hashify::map!(s.as_bytes(), TzName,
        "AUS Central Standard Time" => "Australia/Darwin",
        "AUS Central" => "Australia/Darwin",
        "AUS Eastern Standard Time" => "Australia/Sydney",
        "AUS Eastern" => "Australia/Sydney",
        "Abu Dhabi, Muscat" => "Asia/Muscat",
        "Adelaide, Central Australia" => "Australia/Adelaide",
        "Afghanistan Standard Time" => "Asia/Kabul",
        "Afghanistan" => "Asia/Kabul",
        "Alaska" => "America/Anchorage",
        "Alaskan Standard Time" => "America/Anchorage",
        "Alaskan" => "America/Anchorage",
        "Aleutian Standard Time" => "America/Adak",
        "Almaty, Novosibirsk, North Central Asia" => "Asia/Almaty",
        "Altai Standard Time" => "Asia/Barnaul",
        "Amsterdam, Berlin, Bern, Rom, Stockholm, Wien" => "Europe/Berlin",
        "Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna" => "Europe/Berlin",
        "Arab Standard Time" => "Asia/Riyadh",
        "Arab" => "Asia/Kuwait",
        "Arab, Kuwait, Riyadh" => "Asia/Kuwait",
        "Arabian Standard Time" => "Asia/Dubai",
        "Arabian" => "Asia/Muscat",
        "Arabic Standard Time" => "Asia/Baghdad",
        "Arabic" => "Asia/Baghdad",
        "Argentina Standard Time" => "America/Buenos_Aires",
        "Argentina" => "America/Argentina/Buenos_Aires",
        "Arizona" => "America/Phoenix",
        "Armenian" => "Asia/Yerevan",
        "Astana, Dhaka" => "Asia/Dhaka",
        "Astrakhan Standard Time" => "Europe/Astrakhan",
        "Athens, Istanbul, Minsk" => "Europe/Athens",
        "Atlantic Standard Time" => "America/Halifax",
        "Atlantic Time (Canada)" => "America/Halifax",
        "Atlantic" => "America/Halifax",
        "Auckland, Wellington" => "Pacific/Auckland",
        "Aus Central W. Standard Time" => "Australia/Eucla",
        "Azerbaijan Standard Time" => "Asia/Baku",
        "Azerbijan" => "Asia/Baku",
        "Azores Standard Time" => "Atlantic/Azores",
        "Azores" => "Atlantic/Azores",
        "Baghdad" => "Asia/Baghdad",
        "Bahia Standard Time" => "America/Bahia",
        "Baku, Tbilisi, Yerevan" => "Asia/Baku",
        "Bangkok, Hanoi, Jakarta" => "Asia/Bangkok",
        "Bangladesh Standard Time" => "Asia/Dhaka",
        "Beijing, Chongqing, Hong Kong SAR, Urumqi" => "Asia/Shanghai",
        "Belarus Standard Time" => "Europe/Minsk",
        "Belgrade, Pozsony, Budapest, Ljubljana, Prague" => "Europe/Prague",
        "Bogota, Lima, Quito" => "America/Bogota",
        "Bougainville Standard Time" => "Pacific/Bougainville",
        "Brasilia" => "America/Sao_Paulo",
        "Brisbane, East Australia" => "Australia/Brisbane",
        "Brussels, Copenhagen, Madrid, Paris" => "Europe/Paris",
        "Bucharest" => "Europe/Bucharest",
        "Buenos Aires" => "America/Argentina/Buenos_Aires",
        "Cairo" => "Africa/Cairo",
        "Canada Central Standard Time" => "America/Regina",
        "Canada Central" => "America/Edmonton",
        "Canberra, Melbourne, Sydney, Hobart" => "Australia/Sydney",
        "Canberra, Melbourne, Sydney" => "Australia/Sydney",
        "Cape Verde Is." => "Atlantic/Cape_Verde",
        "Cape Verde Standard Time" => "Atlantic/Cape_Verde",
        "Cape Verde" => "Atlantic/Cape_Verde",
        "Caracas, La Paz" => "America/Caracas",
        "Casablanca, Monrovia" => "Africa/Casablanca",
        "Caucasus Standard Time" => "Asia/Yerevan",
        "Caucasus" => "Asia/Yerevan",
        "Cen. Australia Standard Time" => "Australia/Adelaide",
        "Cen. Australia" => "Australia/Adelaide",
        "Central America Standard Time" => "America/Guatemala",
        "Central America" => "America/Guatemala",
        "Central Asia Standard Time" => "Asia/Almaty",
        "Central Asia" => "Asia/Dhaka",
        "Central Brazilian Standard Time" => "America/Cuiaba",
        "Central Brazilian" => "America/Manaus",
        "Central Europe Standard Time" => "Europe/Budapest",
        "Central Europe" => "Europe/Prague",
        "Central European Standard Time" => "Europe/Warsaw",
        "Central European" => "Europe/Sarajevo",
        "Central Pacific Standard Time" => "Pacific/Guadalcanal",
        "Central Pacific" => "Asia/Magadan",
        "Central Standard Time (Mexico)" => "America/Mexico_City",
        "Central Standard Time" => "America/Chicago",
        "Central Time (US & Canada)" => "America/Chicago",
        "Central Time (US and Canada)" => "America/Chicago",
        "Central" => "America/Chicago",
        "Chatham Islands Standard Time" => "Pacific/Chatham",
        "China Standard Time" => "Asia/Shanghai",
        "China" => "Asia/Shanghai",
        "Cuba Standard Time" => "America/Havana",
        "Darwin" => "Australia/Darwin",
        "Dateline Standard Time" => "Etc/GMT+12",
        "Dateline" => "Etc/GMT-12",
        "E. Africa Standard Time" => "Africa/Nairobi",
        "E. Africa" => "Africa/Nairobi",
        "E. Australia Standard Time" => "Australia/Brisbane",
        "E. Australia" => "Australia/Brisbane",
        "E. Europe Standard Time" => "Europe/Chisinau",
        "E. Europe" => "Europe/Minsk",
        "E. South America Standard Time" => "America/Sao_Paulo",
        "E. South America" => "America/Belem",
        "East Africa, Nairobi" => "Africa/Nairobi",
        "Easter Island Standard Time" => "Pacific/Easter",
        "Eastern Standard Time (Mexico)" => "America/Cancun",
        "Eastern Standard Time" => "America/New_York",
        "Eastern Time (US & Canada)" => "America/New_York",
        "Eastern Time (US and Canada)" => "America/New_York",
        "Eastern" => "America/New_York",
        "Egypt Standard Time" => "Africa/Cairo",
        "Egypt" => "Africa/Cairo",
        "Ekaterinburg Standard Time" => "Asia/Yekaterinburg",
        "Ekaterinburg" => "Asia/Yekaterinburg",
        "Eniwetok, Kwajalein, Dateline Time" => "Pacific/Kwajalein",
        "FLE Standard Time" => "Europe/Kiev",
        "FLE" => "Europe/Helsinki",
        "Fiji Islands, Kamchatka, Marshall Is." => "Pacific/Fiji",
        "Fiji Standard Time" => "Pacific/Fiji",
        "Fiji" => "Pacific/Fiji",
        "GMT Standard Time" => "Europe/London",
        "GTB Standard Time" => "Europe/Bucharest",
        "GTB" => "Europe/Athens",
        "Georgian Standard Time" => "Asia/Tbilisi",
        "Georgian" => "Asia/Tbilisi",
        "Greenland Standard Time" => "America/Godthab",
        "Greenland" => "America/Godthab",
        "Greenwich Mean Time: Dublin, Edinburgh, Lisbon, London" => "Europe/Lisbon",
        "Greenwich Mean Time; Dublin, Edinburgh, London" => "Europe/London",
        "Greenwich Standard Time" => "Atlantic/Reykjavik",
        "Greenwich" => "Atlantic/Reykjavik",
        "Guam, Port Moresby" => "Pacific/Guam",
        "Haiti Standard Time" => "America/Port-au-Prince",
        "Harare, Pretoria" => "Africa/Harare",
        "Hawaii" => "Pacific/Honolulu",
        "Hawaiian Standard Time" => "Pacific/Honolulu",
        "Hawaiian" => "Pacific/Honolulu",
        "Helsinki, Riga, Tallinn" => "Europe/Helsinki",
        "Hobart, Tasmania" => "Australia/Hobart",
        "India Standard Time" => "Asia/Calcutta",
        "India" => "Asia/Calcutta",
        "Indiana (East)" => "America/Indiana/Indianapolis",
        "Iran Standard Time" => "Asia/Tehran",
        "Iran" => "Asia/Tehran",
        "Irkutsk, Ulaan Bataar" => "Asia/Irkutsk",
        "Islamabad, Karachi, Tashkent" => "Asia/Karachi",
        "Israel Standard Time" => "Asia/Jerusalem",
        "Israel" => "Asia/Jerusalem",
        "Israel, Jerusalem Standard Time" => "Asia/Jerusalem",
        "Jordan Standard Time" => "Asia/Amman",
        "Jordan" => "Asia/Amman",
        "Kabul" => "Asia/Kabul",
        "Kaliningrad Standard Time" => "Europe/Kaliningrad",
        "Kathmandu, Nepal" => "Asia/Kathmandu",
        "Kolkata, Chennai, Mumbai, New Delhi, India Standard Time" => "Asia/Calcutta",
        "Korea Standard Time" => "Asia/Seoul",
        "Korea" => "Asia/Seoul",
        "Krasnoyarsk" => "Asia/Krasnoyarsk",
        "Kuala Lumpur, Singapore" => "Asia/Singapore",
        "Libya Standard Time" => "Africa/Tripoli",
        "Line Islands Standard Time" => "Pacific/Kiritimati",
        "Lord Howe Standard Time" => "Australia/Lord_Howe",
        "Magadan Standard Time" => "Asia/Magadan",
        "Magadan, Solomon Is., New Caledonia" => "Asia/Magadan",
        "Magallanes Standard Time" => "America/Punta_Arenas",
        "Marquesas Standard Time" => "Pacific/Marquesas",
        "Mauritius Standard Time" => "Indian/Mauritius",
        "Mauritius" => "Indian/Mauritius",
        "Mexico City, Tegucigalpa" => "America/Mexico_City",
        "Mexico Standard Time 2" => "America/Chihuahua",
        "Mexico" => "America/Mexico_City",
        "Mid-Atlantic" => "America/Noronha",
        "Middle East Standard Time" => "Asia/Beirut",
        "Middle East" => "Asia/Beirut",
        "Midway Island, Samoa" => "Pacific/Midway",
        "Montevideo Standard Time" => "America/Montevideo",
        "Montevideo" => "America/Montevideo",
        "Morocco Standard Time" => "Africa/Casablanca",
        "Morocco" => "Africa/Casablanca",
        "Moscow, St. Petersburg, Volgograd" => "Europe/Moscow",
        "Mountain Standard Time (Mexico)" => "America/Chihuahua",
        "Mountain Standard Time" => "America/Denver",
        "Mountain Time (US & Canada)" => "America/Denver",
        "Mountain Time (US and Canada)" => "America/Denver",
        "Mountain" => "America/Denver",
        "Myanmar Standard Time" => "Asia/Rangoon",
        "Myanmar" => "Asia/Rangoon",
        "N. Central Asia Standard Time" => "Asia/Novosibirsk",
        "N. Central Asia" => "Asia/Almaty",
        "Namibia Standard Time" => "Africa/Windhoek",
        "Namibia" => "Africa/Windhoek",
        "Nepal Standard Time" => "Asia/Katmandu",
        "Nepal" => "Asia/Kathmandu",
        "New Zealand Standard Time" => "Pacific/Auckland",
        "New Zealand" => "Pacific/Auckland",
        "Newfoundland Standard Time" => "America/St_Johns",
        "Newfoundland" => "America/St_Johns",
        "Norfolk Standard Time" => "Pacific/Norfolk",
        "North Asia East Standard Time" => "Asia/Irkutsk",
        "North Asia East" => "Asia/Irkutsk",
        "North Asia Standard Time" => "Asia/Krasnoyarsk",
        "North Asia" => "Asia/Krasnoyarsk",
        "North Korea Standard Time" => "Asia/Pyongyang",
        "Omsk Standard Time" => "Asia/Omsk",
        "Osaka, Sapporo, Tokyo" => "Asia/Tokyo",
        "Japan" => "Asia/Tokyo",
        "Pacific SA Standard Time" => "America/Santiago",
        "Pacific SA" => "America/Santiago",
        "Pacific Standard Time (Mexico)" => "America/Tijuana",
        "Pacific Standard Time" => "America/Los_Angeles",
        "Pacific Time (US & Canada)" => "America/Los_Angeles",
        "Pacific Time (US & Canada); Tijuana" => "America/Los_Angeles",
        "Pacific Time (US and Canada)" => "America/Los_Angeles",
        "Pacific Time (US and Canada); Tijuana" => "America/Los_Angeles",
        "Pacific" => "America/Los_Angeles",
        "Pakistan Standard Time" => "Asia/Karachi",
        "Pakistan" => "Asia/Karachi",
        "Paraguay Standard Time" => "America/Asuncion",
        "Paris, Madrid, Brussels, Copenhagen" => "Europe/Paris",
        "Perth, Western Australia" => "Australia/Perth",
        "Prague, Central Europe" => "Europe/Prague",
        "Qyzylorda Standard Time" => "Asia/Qyzylorda",
        "Rangoon" => "Asia/Rangoon",
        "Romance Standard Time" => "Europe/Paris",
        "Romance" => "Europe/Paris",
        "Russia Time Zone 10" => "Asia/Srednekolymsk",
        "Russia Time Zone 11" => "Asia/Kamchatka",
        "Russia Time Zone 3" => "Europe/Samara",
        "Russian Standard Time" => "Europe/Moscow",
        "Russian" => "Europe/Moscow",
        "SA Eastern Standard Time" => "America/Cayenne",
        "SA Eastern" => "America/Belem",
        "SA Pacific Standard Time" => "America/Bogota",
        "SA Pacific" => "America/Bogota",
        "SA Western Standard Time" => "America/La_Paz",
        "SA Western" => "America/La_Paz",
        "SE Asia Standard Time" => "Asia/Bangkok",
        "SE Asia" => "Asia/Bangkok",
        "Saint Pierre Standard Time" => "America/Miquelon",
        "Sakhalin Standard Time" => "Asia/Sakhalin",
        "Samoa Standard Time" => "Pacific/Apia",
        "Samoa" => "Pacific/Apia",
        "Santiago" => "America/Santiago",
        "Sao Tome Standard Time" => "Africa/Sao_Tome",
        "Sarajevo, Skopje, Sofija, Vilnius, Warsaw, Zagreb" => "Europe/Sarajevo",
        "Saratov Standard Time" => "Europe/Saratov",
        "Saskatchewan" => "America/Edmonton",
        "Seoul, Korea Standard time" => "Asia/Seoul",
        "Singapore Standard Time" => "Asia/Singapore",
        "Singapore" => "Asia/Singapore",
        "South Africa Standard Time" => "Africa/Johannesburg",
        "South Africa" => "Africa/Harare",
        "Sri Jayawardenepura, Sri Lanka" => "Asia/Colombo",
        "Sri Lanka Standard Time" => "Asia/Colombo",
        "Sri Lanka" => "Asia/Colombo",
        "Sudan Standard Time" => "Africa/Khartoum",
        "Syria Standard Time" => "Asia/Damascus",
        "Taipei Standard Time" => "Asia/Taipei",
        "Taipei" => "Asia/Taipei",
        "Tasmania Standard Time" => "Australia/Hobart",
        "Tasmania" => "Australia/Hobart",
        "Tehran" => "Asia/Tehran",
        "Tocantins Standard Time" => "America/Araguaina",
        "Tokyo Standard Time" => "Asia/Tokyo",
        "Tokyo" => "Asia/Tokyo",
        "Tomsk Standard Time" => "Asia/Tomsk",
        "Tonga Standard Time" => "Pacific/Tongatapu",
        "Tonga" => "Pacific/Tongatapu",
        "Transbaikal Standard Time" => "Asia/Chita",
        "Turkey Standard Time" => "Europe/Istanbul",
        "Turks And Caicos Standard Time" => "America/Grand_Turk",
        "US Eastern Standard Time" => "America/Indianapolis",
        "US Eastern" => "America/Indiana/Indianapolis",
        "US Mountain Standard Time" => "America/Phoenix",
        "US Mountain" => "America/Phoenix",
        "UTC" => "Etc/GMT",
        "UTC+12" => "Etc/GMT-12",
        "UTC+13" => "Etc/GMT-13",
        "UTC-02" => "Etc/GMT+2",
        "UTC-08" => "Etc/GMT+8",
        "UTC-09" => "Etc/GMT+9",
        "UTC-11" => "Etc/GMT+11",
        "Ulaanbaatar Standard Time" => "Asia/Ulaanbaatar",
        "Universal Coordinated Time" => "UTC",
        "Venezuela Standard Time" => "America/Caracas",
        "Venezuela" => "America/Caracas",
        "Vladivostok Standard Time" => "Asia/Vladivostok",
        "Vladivostok" => "Asia/Vladivostok",
        "Volgograd Standard Time" => "Europe/Volgograd",
        "W. Australia Standard Time" => "Australia/Perth",
        "W. Australia" => "Australia/Perth",
        "W. Central Africa Standard Time" => "Africa/Lagos",
        "W. Central Africa" => "Africa/Lagos",
        "W. Europe Standard Time" => "Europe/Berlin",
        "W. Europe" => "Europe/Amsterdam",
        "W. Mongolia Standard Time" => "Asia/Hovd",
        "West Asia Standard Time" => "Asia/Tashkent",
        "West Asia" => "Asia/Tashkent",
        "West Bank Standard Time" => "Asia/Hebron",
        "West Central Africa" => "Africa/Luanda",
        "West Pacific Standard Time" => "Pacific/Port_Moresby",
        "West Pacific" => "Pacific/Guam",
        "Yakutsk Standard Time" => "Asia/Yakutsk",
        "Yakutsk" => "Asia/Yakutsk",
        "Yukon Standard Time" => "America/Whitehorse",
        "Nuku'alofa, Tonga" => "Pacific/Tongatapu",
        );

        if let Some(name) = result {
            if let Some(tz) = Tz::iana(name) {
                return Ok(tz);
            }
        } else if let Some(zone_offset) = zone_offset {
            let (zone, sign, time) = if let Some((zone, part)) = zone_offset.split_once('+') {
                (zone.trim(), '-', part.trim())
            } else if let Some((zone, part)) = zone_offset.split_once('-') {
                (zone.trim(), '+', part.trim())
            } else {
                return Err(());
            };
            if !zone.eq_ignore_ascii_case("UTC") && !zone.eq_ignore_ascii_case("GMT") {
                return Err(());
            }
            let mut zone = String::with_capacity(10);
            zone.push_str("Etc/GMT");
            zone.push(sign);

            for (pos, ch) in time.chars().enumerate() {
                if !ch.is_ascii_digit() {
                    break;
                } else if ch != '0' || pos > 0 {
                    zone.push(ch);
                }
            }

            if let Some(tz) = Tz::iana(&zone) {
                return Ok(tz);
            }
        }
        Err(())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/calcard/src/common/timezone/tests.rs"]
mod tests;
