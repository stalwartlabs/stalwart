/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod append;
pub mod authenticate;
pub mod copy_move;
pub mod create;
pub mod delete;
pub mod enable;
pub mod fetch;
pub mod list;
pub mod login;
pub mod lsub;
pub mod quota;
pub mod rename;
pub mod search;
pub mod select;
pub mod sort;
pub mod status;
pub mod store;
pub mod subscribe;
pub mod thread;
pub mod uidbatches;

use crate::{
    Command,
    protocol::{Flag, Sequence},
    receiver::{ArgumentBytes, CommandParser},
};
use chrono::{DateTime, NaiveDate};
use compact_str::CompactString;
use std::{borrow::Cow, str::FromStr};

pub type Result<T> = std::result::Result<T, Cow<'static, str>>;

impl CommandParser for Command {
    fn parse(value: &[u8], uid: bool) -> Option<Self> {
        hashify::tiny_map!(value,
            "CAPABILITY" => Command::Capability,
            "NOOP" => Command::Noop,
            "LOGOUT" => Command::Logout,
            "STARTTLS" => Command::StartTls,
            "AUTHENTICATE" => Command::Authenticate,
            "LOGIN" => Command::Login,
            "ENABLE" => Command::Enable,
            "SELECT" => Command::Select,
            "EXAMINE" => Command::Examine,
            "CREATE" => Command::Create,
            "DELETE" => Command::Delete,
            "RENAME" => Command::Rename,
            "SUBSCRIBE" => Command::Subscribe,
            "UNSUBSCRIBE" => Command::Unsubscribe,
            "LIST" => Command::List,
            "NAMESPACE" => Command::Namespace,
            "STATUS" => Command::Status,
            "APPEND" => Command::Append,
            "IDLE" => Command::Idle,
            "CLOSE" => Command::Close,
            "UNSELECT" => Command::Unselect,
            "EXPUNGE" => Command::Expunge(uid),
            "SEARCH" => Command::Search(uid),
            "FETCH" => Command::Fetch(uid),
            "STORE" => Command::Store(uid),
            "COPY" => Command::Copy(uid),
            "MOVE" => Command::Move(uid),
            "SORT" => Command::Sort(uid),
            "THREAD" => Command::Thread(uid),
            "LSUB" => Command::Lsub,
            "CHECK" => Command::Check,
            "SETACL" => Command::SetAcl,
            "DELETEACL" => Command::DeleteAcl,
            "GETACL" => Command::GetAcl,
            "LISTRIGHTS" => Command::ListRights,
            "MYRIGHTS" => Command::MyRights,
            "UNAUTHENTICATE" => Command::Unauthenticate,
            "ID" => Command::Id,
            "GETQUOTA" => Command::GetQuota,
            "GETQUOTAROOT" => Command::GetQuotaRoot,
            "GETJMAPACCESS" => Command::GetJmapAccess,
            "UIDBATCHES" => Command::UidBatches,
        )
    }

    #[inline(always)]
    fn tokenize_brackets(&self) -> bool {
        matches!(self, Command::Fetch(_))
    }
}

impl Flag {
    pub fn parse_imap(value: ArgumentBytes) -> Result<Self> {
        if !value.is_empty() {
            let flag = hashify::tiny_map_ignore_case!(value.as_slice(),
                "\\Seen" => Flag::Seen,
                "\\Answered" => Flag::Answered,
                "\\Flagged" => Flag::Flagged,
                "\\Deleted" => Flag::Deleted,
                "\\Draft" => Flag::Draft,
                "\\Recent" => Flag::Recent,
                "\\Important" => Flag::Important,
                "$Forwarded" => Flag::Forwarded,
                "$MDNSent" => Flag::MDNSent,
                "$Junk" => Flag::Junk,
                "$NotJunk" => Flag::NotJunk,
                "$Phishing" => Flag::Phishing,
                "$Important" => Flag::Important,
                "$autosent" => Flag::Autosent,
                "$canunsubscribe" => Flag::CanUnsubscribe,
                "$followed" => Flag::Followed,
                "$hasattachment" => Flag::HasAttachment,
                "$hasmemo" => Flag::HasMemo,
                "$hasnoattachment" => Flag::HasNoAttachment,
                "$imported" => Flag::Imported,
                "$istrusted" => Flag::IsTrusted,
                "$MailFlagBit0" => Flag::MailFlagBit0,
                "$MailFlagBit1" => Flag::MailFlagBit1,
                "$MailFlagBit2" => Flag::MailFlagBit2,
                "$maskedemail" => Flag::MaskedEmail,
                "$memo" => Flag::Memo,
                "$muted" => Flag::Muted,
                "$new" => Flag::New,
                "$notify" => Flag::Notify,
                "$unsubscribed" => Flag::Unsubscribed,
            );

            if let Some(flag) = flag {
                Ok(flag)
            } else if value.spilled() {
                String::from_utf8(value.into_vec())
                    .map_err(|_| Cow::from("Invalid UTF-8."))
                    .map(|keyword| Flag::Keyword(CompactString::from_string_buffer(keyword)))
            } else {
                CompactString::from_utf8(value.as_slice())
                    .map_err(|_| Cow::from("Invalid UTF-8."))
                    .map(Flag::Keyword)
            }
        } else {
            Err(Cow::from("Null flags are not allowed."))
        }
    }

    pub fn parse_jmap(value: String) -> Self {
        if value.starts_with('$') {
            hashify::tiny_map_ignore_case!(value.as_bytes(),
                "$seen" => Flag::Seen,
                "$draft" => Flag::Draft,
                "$flagged" => Flag::Flagged,
                "$answered" => Flag::Answered,
                "$recent" => Flag::Recent,
                "$important" => Flag::Important,
                "$phishing" => Flag::Phishing,
                "$junk" => Flag::Junk,
                "$notjunk" => Flag::NotJunk,
                "$deleted" => Flag::Deleted,
                "$forwarded" => Flag::Forwarded,
                "$mdnsent" => Flag::MDNSent,
                "$autosent" => Flag::Autosent,
                "$canunsubscribe" => Flag::CanUnsubscribe,
                "$followed" => Flag::Followed,
                "$hasattachment" => Flag::HasAttachment,
                "$hasmemo" => Flag::HasMemo,
                "$hasnoattachment" => Flag::HasNoAttachment,
                "$imported" => Flag::Imported,
                "$istrusted" => Flag::IsTrusted,
                "$MailFlagBit0" => Flag::MailFlagBit0,
                "$MailFlagBit1" => Flag::MailFlagBit1,
                "$MailFlagBit2" => Flag::MailFlagBit2,
                "$maskedemail" => Flag::MaskedEmail,
                "$memo" => Flag::Memo,
                "$muted" => Flag::Muted,
                "$new" => Flag::New,
                "$notify" => Flag::Notify,
                "$unsubscribed" => Flag::Unsubscribed,
            )
            .unwrap_or_else(|| Flag::Keyword(value.into()))
        } else {
            let mut keyword = String::with_capacity(value.len());
            for c in value.chars() {
                if c.is_ascii_alphanumeric() {
                    keyword.push(c);
                } else {
                    keyword.push('_');
                }
            }
            Flag::Keyword(keyword.into())
        }
    }
}

const SECONDS_PER_DAY: i64 = 86_400;

#[inline(always)]
fn short_month(m0: u8, m1: u8, m2: u8) -> Option<u32> {
    Some(match (m0 | 32, m1 | 32, m2 | 32) {
        (b'j', b'a', b'n') => 1,
        (b'f', b'e', b'b') => 2,
        (b'm', b'a', b'r') => 3,
        (b'a', b'p', b'r') => 4,
        (b'm', b'a', b'y') => 5,
        (b'j', b'u', b'n') => 6,
        (b'j', b'u', b'l') => 7,
        (b'a', b'u', b'g') => 8,
        (b's', b'e', b'p') => 9,
        (b'o', b'c', b't') => 10,
        (b'n', b'o', b'v') => 11,
        (b'd', b'e', b'c') => 12,
        _ => return None,
    })
}

#[inline(always)]
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        _ => 28,
    }
}

#[inline(always)]
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - (month <= 2) as i32;
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as i64;
    let month_of_year = (if month > 2 { month - 3 } else { month + 9 }) as i64;
    let day_of_year = (153 * month_of_year + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era as i64 * 146_097 + day_of_era - 719_468
}

#[inline(always)]
fn two_digits(d0: u8, d1: u8) -> Option<u32> {
    (d0.is_ascii_digit() && d1.is_ascii_digit()).then(|| ((d0 - b'0') * 10 + (d1 - b'0')) as u32)
}

#[inline(always)]
fn parse_civil_date(value: &[u8]) -> Option<(i64, &[u8])> {
    let (day, rest) = match value {
        [d0, d1, b'-', rest @ ..] if d0.is_ascii_digit() && d1.is_ascii_digit() => {
            (two_digits(*d0, *d1)?, rest)
        }
        [d0, b'-', rest @ ..] if d0.is_ascii_digit() => ((*d0 - b'0') as u32, rest),
        _ => return None,
    };
    let [m0, m1, m2, b'-', rest @ ..] = rest else {
        return None;
    };
    let month = short_month(*m0, *m1, *m2)?;
    let [y0, y1, y2, y3, rest @ ..] = rest else {
        return None;
    };
    let year = (two_digits(*y0, *y1)? * 100 + two_digits(*y2, *y3)?) as i32;

    if day == 0 || day > days_in_month(year, month) {
        return None;
    }

    Some((days_from_civil(year, month, day), rest))
}

fn parse_datetime_fast(value: &[u8]) -> Option<i64> {
    let (days, rest) = parse_civil_date(value)?;
    let [
        b' ',
        h0,
        h1,
        b':',
        m0,
        m1,
        b':',
        s0,
        s1,
        b' ',
        sign,
        z0,
        z1,
        z2,
        z3,
    ] = rest
    else {
        return None;
    };
    let hour = two_digits(*h0, *h1)?;
    let minute = two_digits(*m0, *m1)?;
    let second = two_digits(*s0, *s1)?;
    let zone_hour = two_digits(*z0, *z1)?;
    let zone_minute = two_digits(*z2, *z3)?;

    if hour > 23 || minute > 59 || second > 59 || zone_hour > 23 || zone_minute > 59 {
        return None;
    }

    let zone = (zone_hour * 3600 + zone_minute * 60) as i64;
    let zone = match sign {
        b'+' => -zone,
        b'-' => zone,
        _ => return None,
    };

    Some(days * SECONDS_PER_DAY + (hour * 3600 + minute * 60 + second) as i64 + zone)
}

fn parse_date_fast(value: &[u8]) -> Option<i64> {
    let (days, rest) = parse_civil_date(value)?;
    rest.is_empty().then(|| days * SECONDS_PER_DAY)
}

pub fn parse_datetime(value: &[u8]) -> Result<i64> {
    if let Some(timestamp) = parse_datetime_fast(value.trim_ascii()) {
        return Ok(timestamp);
    }

    parse_datetime_chrono(value)
}

#[inline(never)]
fn parse_datetime_chrono(value: &[u8]) -> Result<i64> {
    std::str::from_utf8(value)
        .map_err(|_| Cow::from("Expected date/time, found an invalid UTF-8 string."))
        .and_then(|datetime| {
            DateTime::parse_from_str(datetime.trim(), "%d-%b-%Y %H:%M:%S %z")
                .map_err(|_| Cow::from(format!("Failed to parse date/time '{}'.", datetime)))
                .map(|dt| dt.timestamp())
        })
}

pub fn parse_date(value: &[u8]) -> Result<i64> {
    if let Some(timestamp) = parse_date_fast(value.trim_ascii()) {
        return Ok(timestamp);
    }

    parse_date_chrono(value)
}

#[inline(never)]
fn parse_date_chrono(value: &[u8]) -> Result<i64> {
    std::str::from_utf8(value)
        .map_err(|_| Cow::from("Expected date, found an invalid UTF-8 string."))
        .and_then(|date| {
            NaiveDate::parse_from_str(date.trim(), "%d-%b-%Y")
                .map_err(|_| Cow::from(format!("Failed to parse date '{}'.", date)))
                .map(|dt| {
                    dt.and_hms_opt(0, 0, 0)
                        .unwrap_or_default()
                        .and_utc()
                        .timestamp()
                })
        })
}

pub fn parse_number<T: FromStr>(value: &[u8]) -> Result<T> {
    std::str::from_utf8(value)
        .map_err(|_| Cow::from("Expected a number, found an invalid UTF-8 string."))
        .and_then(|string| {
            string
                .parse::<T>()
                .map_err(|_| Cow::from(format!("Expected a number, found {:?}.", string)))
        })
}

#[inline(always)]
fn sequence_number(value: &[u8]) -> Option<(u32, &[u8])> {
    let digits = value
        .iter()
        .position(|ch| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, tail) = value.split_at(digits);
    if number.is_empty() || number.len() > 10 {
        return None;
    }
    let number = number
        .iter()
        .fold(0u64, |acc, ch| acc * 10 + (ch - b'0') as u64);
    (number <= u32::MAX as u64).then_some((number as u32, tail))
}

#[inline(always)]
fn sequence_item(value: &[u8]) -> Option<(Sequence, &[u8])> {
    match value {
        [b'$', tail @ ..] => Some((Sequence::SavedSearch, tail)),
        [b'*', b':', b'*', tail @ ..] => Some((
            Sequence::Range {
                start: None,
                end: None,
            },
            tail,
        )),
        [b'*', b':', tail @ ..] => {
            let (end, tail) = sequence_number(tail)?;
            Some((
                Sequence::Range {
                    start: None,
                    end: Some(end),
                },
                tail,
            ))
        }
        [b'*', tail @ ..] => Some((
            Sequence::Range {
                start: None,
                end: None,
            },
            tail,
        )),
        _ => {
            let (start, tail) = sequence_number(value)?;
            match tail {
                [b':', b'*', tail @ ..] => Some((
                    Sequence::Range {
                        start: Some(start),
                        end: None,
                    },
                    tail,
                )),
                [b':', tail @ ..] => {
                    let (end, tail) = sequence_number(tail)?;
                    Some((
                        Sequence::Range {
                            start: Some(start),
                            end: Some(end),
                        },
                        tail,
                    ))
                }
                _ => Some((Sequence::Number { value: start }, tail)),
            }
        }
    }
}

fn parse_sequence_set_fast(value: &[u8]) -> Option<Sequence> {
    let (first, tail) = sequence_item(value)?;
    let mut rest = match tail {
        [] => return Some(first),
        [b',', rest @ ..] => rest,
        _ => return None,
    };

    let commas = rest.iter().filter(|&&ch| ch == b',').count();
    let mut items = Vec::with_capacity(commas + 2);
    items.push(first);
    loop {
        let (item, tail) = sequence_item(rest)?;
        items.push(item);
        match tail {
            [b',', tail @ ..] => rest = tail,
            [] => return Some(Sequence::List { items }),
            _ => return None,
        }
    }
}

pub fn parse_sequence_set(value: &[u8]) -> Result<Sequence> {
    if let Some(sequence_set) = parse_sequence_set_fast(value) {
        return Ok(sequence_set);
    }

    parse_sequence_set_slow(value)
}

#[inline(never)]
fn parse_sequence_set_slow(value: &[u8]) -> Result<Sequence> {
    let mut sequence_set = Vec::with_capacity(value.iter().filter(|&&ch| ch == b',').count() + 1);

    let mut range_start = None;
    let mut token_start = None;

    let mut is_wildcard = false;
    let mut is_range = false;
    let mut is_saved_search = false;

    for (mut pos, ch) in value.iter().enumerate() {
        let mut add_token = false;
        match ch {
            b',' => {
                add_token = true;
            }
            b':' => {
                if !is_range {
                    if let Some(from_pos) = token_start {
                        range_start =
                            parse_number::<u32>(value.get(from_pos..pos).ok_or_else(|| {
                                Cow::from(format!(
                                    "Invalid sequence set {:?}, parse error.",
                                    String::from_utf8_lossy(value)
                                ))
                            })?)?
                            .into();
                        token_start = None;
                    } else if is_wildcard {
                        is_wildcard = false;
                    } else {
                        return Err(Cow::from(format!(
                            "Invalid sequence set {:?}, number expected before ':'.",
                            String::from_utf8_lossy(value)
                        )));
                    }
                    is_range = true;
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, ':' appears multiple times.",
                        String::from_utf8_lossy(value)
                    )));
                }
            }
            b'*' => {
                if !is_wildcard {
                    if value.len() == 1 {
                        return Ok(Sequence::Range {
                            start: None,
                            end: None,
                        });
                    } else if token_start.is_none() {
                        is_wildcard = true;
                    } else {
                        return Err(Cow::from(format!(
                            "Invalid sequence set {:?}, invalid use of '*'.",
                            String::from_utf8_lossy(value)
                        )));
                    }
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, '*' appears multiple times.",
                        String::from_utf8_lossy(value)
                    )));
                }
            }
            b'$' => {
                if value.get(pos + 1).is_none_or(|&ch| ch == b',') {
                    is_saved_search = true;
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, unexpected token after '$'.",
                        String::from_utf8_lossy(value)
                    )));
                }
            }
            _ => {
                if ch.is_ascii_digit() {
                    if is_wildcard {
                        return Err(Cow::from(format!(
                            "Invalid sequence set {:?}, invalid use of '*'.",
                            String::from_utf8_lossy(value)
                        )));
                    }
                    if token_start.is_none() {
                        token_start = pos.into();
                    }
                } else {
                    return Err(Cow::from(format!(
                        "Invalid sequence set {:?}, found invalid character '{}' at position {}.",
                        String::from_utf8_lossy(value),
                        ch,
                        pos
                    )));
                }
            }
        }

        if add_token || pos == value.len() - 1 {
            if is_range {
                sequence_set.push(Sequence::Range {
                    start: range_start,
                    end: if !is_wildcard {
                        if !add_token {
                            pos += 1;
                        }
                        parse_number::<u32>(
                            value
                                .get(
                                    token_start.ok_or_else(|| {
                                        Cow::from(format!(
                                            "Invalid sequence set {:?}, expected number.",
                                            String::from_utf8_lossy(value)
                                        ))
                                    })?..pos,
                                )
                                .ok_or_else(|| {
                                    Cow::from(format!(
                                        "Invalid sequence set {:?}, parse error.",
                                        String::from_utf8_lossy(value)
                                    ))
                                })?,
                        )?
                        .into()
                    } else {
                        is_wildcard = false;
                        None
                    },
                });
                is_range = false;
                range_start = None;
            } else {
                if !add_token {
                    pos += 1;
                }
                if is_wildcard {
                    sequence_set.push(Sequence::Range {
                        start: None,
                        end: None,
                    });
                    is_wildcard = false;
                } else if is_saved_search {
                    sequence_set.push(Sequence::SavedSearch);
                    is_saved_search = false;
                } else {
                    sequence_set.push(Sequence::Number {
                        value: parse_number(
                            value
                                .get(
                                    token_start.ok_or_else(|| {
                                        Cow::from(format!(
                                            "Invalid sequence set {:?}, expected number.",
                                            String::from_utf8_lossy(value)
                                        ))
                                    })?..pos,
                                )
                                .ok_or_else(|| {
                                    Cow::from(format!(
                                        "Invalid sequence set {:?}, parse error.",
                                        String::from_utf8_lossy(value)
                                    ))
                                })?,
                        )?,
                    });
                }
            }
            token_start = None;
        }
    }

    match sequence_set.len() {
        1 => Ok(sequence_set.pop().unwrap()),
        0 => Err(Cow::from("Invalid empty sequence set.")),
        _ => Ok(Sequence::List {
            items: sequence_set,
        }),
    }
}

pub trait PushUnique<T> {
    fn push_unique(&mut self, value: T);
}

impl<T: PartialEq> PushUnique<T> for Vec<T> {
    fn push_unique(&mut self, value: T) {
        if !self.contains(&value) {
            self.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Command, protocol::Sequence, receiver::CommandParser};

    #[test]
    fn parse_command() {
        assert_eq!(
            Command::parse(b"GETJMAPACCESS", false),
            Some(Command::GetJmapAccess)
        );
        assert_eq!(Command::parse(b"NOTACOMMAND", false), None);
    }

    #[test]
    fn parse_sequence_set() {
        for (sequence, expected_result) in [
            ("$", Sequence::SavedSearch),
            (
                "*",
                Sequence::Range {
                    start: None,
                    end: None,
                },
            ),
            (
                "1,3000:3021",
                Sequence::List {
                    items: vec![
                        Sequence::Number { value: 1 },
                        Sequence::Range {
                            start: 3000.into(),
                            end: 3021.into(),
                        },
                    ],
                },
            ),
            (
                "2,4:7,9,12:*",
                Sequence::List {
                    items: vec![
                        Sequence::Number { value: 2 },
                        Sequence::Range {
                            start: 4.into(),
                            end: 7.into(),
                        },
                        Sequence::Number { value: 9 },
                        Sequence::Range {
                            start: 12.into(),
                            end: None,
                        },
                    ],
                },
            ),
            (
                "*:4,5:7",
                Sequence::List {
                    items: vec![
                        Sequence::Range {
                            start: None,
                            end: 4.into(),
                        },
                        Sequence::Range {
                            start: 5.into(),
                            end: 7.into(),
                        },
                    ],
                },
            ),
            (
                "2,4,5",
                Sequence::List {
                    items: vec![
                        Sequence::Number { value: 2 },
                        Sequence::Number { value: 4 },
                        Sequence::Number { value: 5 },
                    ],
                },
            ),
        ] {
            assert_eq!(
                super::parse_sequence_set(sequence.as_bytes()).unwrap(),
                expected_result
            );
        }
    }

    #[test]
    fn sequence_set_fast_path_matches_slow_path() {
        let cases = [
            "",
            "1",
            "*",
            "$",
            "1:*",
            "*:1",
            "*:*",
            "1:2",
            "2:1",
            "1,2",
            "1,2,3",
            "1:3,5,7:9",
            "$,1",
            "1,$",
            "*,1",
            "1,*",
            "1:2:3",
            "1::2",
            "1,",
            ",1",
            ",",
            ":",
            "1:",
            ":1",
            "1*",
            "*1",
            "**",
            "$$",
            "$:",
            "1,,2",
            "0",
            "0:0",
            "00000000001",
            "4294967295",
            "4294967296",
            "99999999999",
            "1:4294967295",
            "1:4294967296",
            "12:*,*:13",
            "a",
            "1a",
            "1:a",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1: 2",
            "1;2",
            "1.2",
            "18446744073709551616",
        ];
        for case in cases {
            assert_eq!(
                format!("{:?}", super::parse_sequence_set(case.as_bytes())),
                format!("{:?}", super::parse_sequence_set_slow(case.as_bytes())),
                "{case:?}"
            );
        }
        let mut long = String::new();
        for i in 0..2000u32 {
            if i > 0 {
                long.push(',');
            }
            long.push_str(&(i * 3 + 1).to_string());
            if i % 5 == 0 {
                long.push(':');
                long.push_str(&(i * 3 + 2).to_string());
            }
        }
        assert_eq!(
            format!("{:?}", super::parse_sequence_set(long.as_bytes())),
            format!("{:?}", super::parse_sequence_set_slow(long.as_bytes()))
        );
    }

    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    #[test]
    fn date_fast_path_matches_chrono() {
        for year in (0..=9999)
            .step_by(7)
            .chain([1, 4, 100, 400, 1900, 2000, 2024, 9999])
        {
            for (index, month) in MONTHS.iter().enumerate() {
                for day in [0u32, 1, 9, 10, 28, 29, 30, 31, 32] {
                    for text in [
                        format!("{day}-{month}-{year:04}"),
                        format!("{day:02}-{month}-{year:04}"),
                        format!(" {day}-{}-{year:04} ", month.to_ascii_uppercase()),
                        format!("{day}-{}-{year}", month.to_ascii_lowercase()),
                        format!("{day}-{month}-{year:05}"),
                    ] {
                        assert_eq!(
                            format!("{:?}", super::parse_date(text.as_bytes())),
                            format!("{:?}", super::parse_date_chrono(text.as_bytes())),
                            "{text:?} month index {index}"
                        );
                    }
                }
            }
        }
        for text in [
            "",
            "1-Feb",
            "1-Feb-",
            "1-Feb-1994 ",
            "1-Feb-1994x",
            "1-Foo-1994",
            "32-Jan-2000",
            "1-Jan-+2000",
            "1-Jan--200",
            "1-Jan-200",
            "01-01-2000",
            "1 Feb 1994",
            "1-Feb-1994\t",
            "\x0b1-Feb-1994",
            "1-Feb-1994\x0b",
            "\u{a0}1-Feb-1994",
            "1-Feb-1994\u{2000}",
            "1-Fe\u{fc}-1994",
            "\u{ff}",
        ] {
            assert_eq!(
                format!("{:?}", super::parse_date(text.as_bytes())),
                format!("{:?}", super::parse_date_chrono(text.as_bytes())),
                "{text:?}"
            );
        }
    }

    #[test]
    fn datetime_fast_path_matches_chrono() {
        for (day, month, year) in [
            (7u32, "Feb", 1994u32),
            (17, "Jul", 1996),
            (29, "Feb", 2000),
            (29, "Feb", 1900),
            (31, "Dec", 9999),
            (1, "Jan", 0),
        ] {
            for hour in [0u32, 1, 9, 12, 23, 24, 99] {
                for minute in [0u32, 1, 59, 60] {
                    for second in [0u32, 1, 59, 60, 61] {
                        for (sign, tz_hour, tz_minute) in [
                            ('+', 0u32, 0u32),
                            ('-', 0, 0),
                            ('+', 8, 0),
                            ('-', 8, 0),
                            ('+', 23, 59),
                            ('-', 23, 59),
                            ('+', 24, 0),
                            ('+', 12, 60),
                        ] {
                            let text = format!(
                                "{day}-{month}-{year:04} {hour:02}:{minute:02}:{second:02} {sign}{tz_hour:02}{tz_minute:02}"
                            );
                            assert_eq!(
                                format!("{:?}", super::parse_datetime(text.as_bytes())),
                                format!("{:?}", super::parse_datetime_chrono(text.as_bytes())),
                                "{text:?}"
                            );
                        }
                    }
                }
            }
        }
        for text in [
            "7-Feb-1994 22:43:04 -0800",
            "07-Feb-1994 22:43:04 -0800",
            " 7-Feb-1994 22:43:04 -0800 ",
            "7-Feb-1994  22:43:04 -0800",
            "7-Feb-1994 22:43:04  -0800",
            "7-Feb-1994 22:43:04 -08:00",
            "7-Feb-1994 22:43:04 -08",
            "7-Feb-1994 22:43:04 Z",
            "7-Feb-1994 22:43:04",
            "7-Feb-1994 2:43:04 -0800",
            "7-Feb-1994 22:3:04 -0800",
            "7-Feb-1994 22:43:4 -0800",
            "7-Feb-1994T22:43:04 -0800",
            "7-Feb-199422:43:04-0800",
            "7-Feb-1994 22:43:04 -0800x",
            "",
            "\u{ff}",
        ] {
            assert_eq!(
                format!("{:?}", super::parse_datetime(text.as_bytes())),
                format!("{:?}", super::parse_datetime_chrono(text.as_bytes())),
                "{text:?}"
            );
        }
    }
}
