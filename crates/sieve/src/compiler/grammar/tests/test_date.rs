/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::compiler::{
    CompileError, Number, Value,
    grammar::{Capability, Comparator, instruction::CompilerState},
    lexer::{StringConstant, Token, tokenizer::TokenInfo, word::Word},
};
use calcard::common::timezone::Tz;

use crate::compiler::grammar::{MatchType, test::Test};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TestDate {
    pub header_name: Value,
    pub key_list: Box<[Value]>,
    pub match_type: MatchType,
    pub comparator: Comparator,
    pub index: Option<i32>,
    pub zone: Zone,
    pub date_part: DatePart,
    pub mime_anychild: bool,
    pub is_not: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub(crate) struct TestCurrentDate {
    pub zone: Zone,
    pub match_type: MatchType,
    pub comparator: Comparator,
    pub date_part: DatePart,
    pub key_list: Box<[Value]>,
    pub is_not: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub(crate) enum Zone {
    Time(i64) = 0,
    Original = 1,
    Local = 2,
    Named(u16) = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    any(all(test, stalwart_tests), feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(u8)]
pub enum DatePart {
    Year = 0,
    Month = 1,
    Day = 2,
    Date = 3,
    Julian = 4,
    Hour = 5,
    Minute = 6,
    Second = 7,
    Time = 8,
    Iso8601 = 9,
    Std11 = 10,
    Zone = 11,
    Weekday = 12,
}

impl CompilerState<'_> {
    pub(crate) fn parse_test_date(&mut self) -> Result<Test, CompileError> {
        let mut match_type = MatchType::Is;
        let mut comparator = Comparator::AsciiCaseMap;
        let mut header_name = None;
        let key_list;
        let mut index = None;
        let mut index_last = false;
        let mut zone = Zone::Local;
        let mut date_part = None;

        let mut mime = false;
        let mut mime_anychild = false;

        loop {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Tag(
                    word @ (Word::Is
                    | Word::Contains
                    | Word::Matches
                    | Word::Value
                    | Word::Count
                    | Word::Regex
                    | Word::List),
                ) => {
                    self.validate_argument(
                        1,
                        match word {
                            Word::Value | Word::Count => Capability::Relational.into(),
                            Word::Regex => Capability::Regex.into(),
                            Word::List => Capability::ExtLists.into(),
                            _ => None,
                        },
                        token_info.line_num,
                        token_info.line_pos,
                    )?;

                    match_type = self.parse_match_type(word)?;
                }
                Token::Tag(Word::Comparator) => {
                    self.validate_argument(2, None, token_info.line_num, token_info.line_pos)?;
                    comparator = self.parse_comparator()?;
                }
                Token::Tag(Word::Index) => {
                    self.validate_argument(
                        3,
                        Capability::Index.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    index = (self.tokens.expect_number(u16::MAX as usize)? as i32).into();
                }
                Token::Tag(Word::Last) => {
                    self.validate_argument(
                        4,
                        Capability::Index.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    index_last = true;
                }
                Token::Tag(Word::Mime) => {
                    self.validate_argument(
                        5,
                        Capability::Mime.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    mime = true;
                }
                Token::Tag(Word::AnyChild) => {
                    self.validate_argument(
                        6,
                        Capability::Mime.into(),
                        token_info.line_num,
                        token_info.line_pos,
                    )?;
                    mime_anychild = true;
                }
                Token::Tag(Word::OriginalZone) => {
                    self.validate_argument(7, None, token_info.line_num, token_info.line_pos)?;
                    zone = Zone::Original;
                }
                Token::Tag(Word::Zone) => {
                    self.validate_argument(7, None, token_info.line_num, token_info.line_pos)?;
                    zone = self.parse_timezone()?;
                }
                _ => {
                    if header_name.is_none() {
                        let header = self.parse_raw_string_token(token_info)?;
                        header_name = self.resolve_test_header_name(header).into();
                    } else if date_part.is_none() {
                        if let Token::StringConstant(string) = &token_info.token
                            && let Some(date_part_) =
                                lookup_date_part(&string.to_string().to_ascii_lowercase())
                        {
                            date_part = date_part_.into();
                            continue;
                        }
                        return Err(token_info.expected("valid date part"));
                    } else {
                        key_list = self.parse_raw_strings_token(token_info)?;
                        break;
                    }
                }
            }
        }

        if !mime && mime_anychild {
            return Err(self.tokens.unwrap_next()?.missing_tag(":mime"));
        }
        let key_list = self.validate_match(&match_type, &comparator, key_list)?;

        Ok(Test::Date(Box::new(TestDate {
            header_name: header_name.unwrap(),
            key_list: key_list.into(),
            date_part: date_part.unwrap(),
            match_type,
            comparator,
            index: if index_last { index.map(|i| -i) } else { index },
            zone,
            mime_anychild,
            is_not: false,
        })))
    }

    pub(crate) fn parse_test_currentdate(&mut self) -> Result<Test, CompileError> {
        let mut match_type = MatchType::Is;
        let mut comparator = Comparator::AsciiCaseMap;
        let key_list;
        let mut zone = Zone::Local;
        let mut date_part = None;

        loop {
            let token_info = self.tokens.unwrap_next()?;
            match token_info.token {
                Token::Tag(
                    word @ (Word::Is
                    | Word::Contains
                    | Word::Matches
                    | Word::Value
                    | Word::Count
                    | Word::Regex
                    | Word::List),
                ) => {
                    self.validate_argument(
                        1,
                        match word {
                            Word::Value | Word::Count => Capability::Relational.into(),
                            Word::Regex => Capability::Regex.into(),
                            Word::List => Capability::ExtLists.into(),
                            _ => None,
                        },
                        token_info.line_num,
                        token_info.line_pos,
                    )?;

                    match_type = self.parse_match_type(word)?;
                }
                Token::Tag(Word::Comparator) => {
                    self.validate_argument(2, None, token_info.line_num, token_info.line_pos)?;
                    comparator = self.parse_comparator()?;
                }
                Token::Tag(Word::Zone) => {
                    self.validate_argument(3, None, token_info.line_num, token_info.line_pos)?;
                    zone = self.parse_timezone()?;
                }
                _ => {
                    if date_part.is_none() {
                        if let Token::StringConstant(string) = &token_info.token
                            && let Some(date_part_) =
                                lookup_date_part(&string.to_string().to_ascii_lowercase())
                        {
                            date_part = date_part_.into();
                            continue;
                        }
                        return Err(token_info.expected("valid date part"));
                    } else {
                        key_list = self.parse_raw_strings_token(token_info)?;
                        break;
                    }
                }
            }
        }
        let key_list = self.validate_match(&match_type, &comparator, key_list)?;

        Ok(Test::CurrentDate(Box::new(TestCurrentDate {
            key_list: key_list.into(),
            date_part: date_part.unwrap(),
            match_type,
            comparator,
            zone,
            is_not: false,
        })))
    }

    pub(crate) fn parse_timezone(&mut self) -> Result<Zone, CompileError> {
        let token_info = self.tokens.unwrap_next()?;
        if let Token::StringConstant(StringConstant::String(name)) = &token_info.token
            && name.parse::<i64>().is_err()
        {
            return Tz::iana(name)
                .map(|tz| Zone::Named(tz.as_id()))
                .ok_or_else(|| token_info.expected("invalid timezone"));
        }
        zone_offset(token_info).map(Zone::Time)
    }

    pub(crate) fn parse_timezone_offset(&mut self) -> Result<i64, CompileError> {
        let token_info = self.tokens.unwrap_next()?;
        zone_offset(token_info)
    }
}

fn zone_offset(token_info: TokenInfo) -> Result<i64, CompileError> {
    let Token::StringConstant(value) = &token_info.token else {
        return Err(token_info.expected("string containing time zone"));
    };
    let timezone = match value {
        StringConstant::String(value) => value.parse::<i64>().unwrap_or(i64::MAX),
        StringConstant::Number(Number::Integer(n)) => *n,
        StringConstant::Number(Number::Float(n)) => *n as i64,
    };
    match timezone {
        0..=1400 => Ok((timezone / 100 * 3600) + (timezone % 100 * 60)),
        -1200..=-1 => Ok((timezone / 100 * 3600) - (-timezone % 100 * 60)),
        _ => Err(token_info.expected("invalid timezone")),
    }
}

/*
     "year"      => the year, "0000" .. "9999".
     "month"     => the month, "01" .. "12".
     "day"       => the day, "01" .. "31".
     "date"      => the date in "yyyy-mm-dd" format.
     "julian"    => the Modified Julian Day, that is, the date
                    expressed as an integer number of days since
                    00:00 UTC on November 17, 1858 (using the Gregorian
                    calendar).  This corresponds to the regular
                    Julian Day minus 2400000.5.  Sample routines to
                    convert to and from modified Julian dates are
                    given in Appendix A.
     "hour"      => the hour, "00" .. "23".
     "minute"    => the minute, "00" .. "59".
     "second"    => the second, "00" .. "60".
     "time"      => the time in "hh:mm:ss" format.
     "iso8601"   => the date and time in restricted ISO 8601 format.
     "std11"     => the date and time in a format appropriate
                    for use in a Date: header field [RFC2822].
     "zone"      => the time zone in use.  If the user specified a
                    time zone with ":zone", "zone" will
                    contain that value.  If :originalzone is specified
                    this value will be the original zone specified
                    in the date-time value.  If neither argument is
                    specified the value will be the server's default
                    time zone in offset format "+hhmm" or "-hhmm".  An
                    offset of 0 (Zulu) always has a positive sign.
     "weekday"   => the day of the week expressed as an integer between
                    "0" and "6". "0" is Sunday, "1" is Monday, etc.
*/

fn lookup_date_part(input: &str) -> Option<DatePart> {
    hashify::map!(
        input.as_bytes(), DatePart,
        "year" => DatePart::Year,
        "month" => DatePart::Month,
        "day" => DatePart::Day,
        "date" => DatePart::Date,
        "julian" => DatePart::Julian,
        "hour" => DatePart::Hour,
        "minute" => DatePart::Minute,
        "second" => DatePart::Second,
        "time" => DatePart::Time,
        "iso8601" => DatePart::Iso8601,
        "std11" => DatePart::Std11,
        "zone" => DatePart::Zone,
        "weekday" => DatePart::Weekday,
    )
    .copied()
}

impl DatePart {
    pub(crate) fn from_code(code: u8) -> DatePart {
        match code {
            0 => DatePart::Year,
            1 => DatePart::Month,
            2 => DatePart::Day,
            3 => DatePart::Date,
            4 => DatePart::Julian,
            5 => DatePart::Hour,
            6 => DatePart::Minute,
            7 => DatePart::Second,
            8 => DatePart::Time,
            9 => DatePart::Iso8601,
            10 => DatePart::Std11,
            11 => DatePart::Zone,
            _ => DatePart::Weekday,
        }
    }
}
