/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::der::{DerError, reader::Tlv, tag};

fn digits(bytes: &[u8]) -> Result<u32, DerError> {
    bytes.iter().try_fold(0u32, |acc, b| {
        if b.is_ascii_digit() {
            Ok(acc * 10 + u32::from(b - b'0'))
        } else {
            Err(DerError::InvalidValue)
        }
    })
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub(crate) fn parse_time(tlv: Tlv<'_>) -> Result<u64, DerError> {
    let (year, rest) = match (tlv.tag, tlv.content) {
        (tag::UTC_TIME, [y0, y1, rest @ ..]) => {
            let yy = digits(&[*y0, *y1])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, rest)
        }
        (tag::GENERALIZED_TIME, [y0, y1, y2, y3, rest @ ..]) => {
            (digits(&[*y0, *y1, *y2, *y3])?, rest)
        }
        _ => return Err(DerError::UnexpectedTag),
    };
    let [m0, m1, d0, d1, h0, h1, mi0, mi1, s0, s1, b'Z'] = rest else {
        return Err(DerError::InvalidValue);
    };
    let month = digits(&[*m0, *m1])?;
    let day = digits(&[*d0, *d1])?;
    let hour = digits(&[*h0, *h1])?;
    let minute = digits(&[*mi0, *mi1])?;
    let second = digits(&[*s0, *s1])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(DerError::InvalidValue);
    }
    let days = days_from_civil(i64::from(year), month, day);
    let secs = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    u64::try_from(secs).map_err(|_| DerError::InvalidValue)
}
