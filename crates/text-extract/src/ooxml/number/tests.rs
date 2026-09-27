/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;
use crate::output::Output;

fn rendered(raw: &str, format: NumberFormat, dates: DateSystem) -> String {
    let mut buf = String::new();
    let mut out = Output::new(&mut buf, usize::MAX);
    push_number(raw.as_bytes(), format, dates, &mut out);
    buf
}

#[test]
fn classifies_format_codes() {
    let cases: &[(&str, NumberFormat)] = &[
        ("General", NumberFormat::General),
        ("0.00", NumberFormat::Fixed(2)),
        ("#,##0.00_);[Red](#,##0.00)", NumberFormat::Fixed(2)),
        ("\"$\"#,##0", NumberFormat::Fixed(0)),
        ("# ?/?", NumberFormat::General),
        ("0%", NumberFormat::Percent(0)),
        ("0.000%", NumberFormat::Percent(3)),
        ("yyyy\\-mm\\-dd", NumberFormat::Date),
        ("mmm\\ yyyy", NumberFormat::Date),
        ("mmmm", NumberFormat::Date),
        ("[$-409]d\\-mmm\\-yy;@", NumberFormat::Date),
        ("m/d/yy h:mm", NumberFormat::DateTime),
        ("h:mm AM/PM", NumberFormat::Time),
        ("mm:ss", NumberFormat::Time),
        ("[h]:mm:ss", NumberFormat::ElapsedTime),
        ("@", NumberFormat::Text),
        ("\"days: \"0", NumberFormat::Fixed(0)),
        ("&quot;days&quot;0.0", NumberFormat::Fixed(1)),
        ("0.0%", NumberFormat::Percent(1)),
        ("[Red]0.00", NumberFormat::Fixed(2)),
        ("[Magenta]0.000", NumberFormat::Fixed(3)),
        ("[mm]:ss", NumberFormat::ElapsedTime),
        ("0.00E+00", NumberFormat::General),
    ];
    for (code, expected) in cases {
        assert_eq!(NumberFormat::classify(code.as_bytes()), *expected, "{code}");
    }
}

#[test]
fn renders_numbers_dates_and_times() {
    let e1900 = DateSystem::Epoch1900;
    let cases: &[(&str, NumberFormat, &str)] = &[
        ("42", NumberFormat::General, "42"),
        ("0.30000000000000004", NumberFormat::General, "0.3"),
        ("1.0000000000000002", NumberFormat::General, "1"),
        ("-2.5E-3", NumberFormat::General, "-0.0025"),
        ("1.5E+20", NumberFormat::General, "1.5e20"),
        (
            "123456789012345678",
            NumberFormat::General,
            "1.23456789012346e17",
        ),
        ("-0", NumberFormat::General, "0"),
        ("-0.001", NumberFormat::Fixed(2), "0.00"),
        ("0.125", NumberFormat::Percent(0), "13%"),
        ("0.005", NumberFormat::Percent(0), "1%"),
        ("0.045", NumberFormat::Percent(0), "5%"),
        ("0.00125", NumberFormat::Percent(2), "0.13%"),
        ("-0.125", NumberFormat::Percent(0), "-13%"),
        ("12.5", NumberFormat::Percent(1), "1250.0%"),
        ("1.5E-3", NumberFormat::Percent(1), "0.2%"),
        ("2.5", NumberFormat::Fixed(0), "3"),
        ("1.25E-1", NumberFormat::Fixed(2), "0.13"),
        ("1e15", NumberFormat::Percent(0), "1e15"),
        ("1E+300", NumberFormat::Fixed(2), "1E+300"),
        ("inf", NumberFormat::Percent(0), "inf"),
        ("0.0", NumberFormat::General, "0"),
        ("0.1234", NumberFormat::Percent(2), "12.34%"),
        ("1169823.7", NumberFormat::Fixed(0), "1169824"),
        ("5", NumberFormat::Fixed(2), "5.00"),
        ("86.4449999", NumberFormat::Fixed(2), "86.44"),
        ("7", NumberFormat::Fixed(0), "7"),
        ("123.25", NumberFormat::General, "123.25"),
        ("5.0", NumberFormat::General, "5"),
        ("007", NumberFormat::General, "7"),
        ("0.000123", NumberFormat::General, "0.000123"),
        ("1234.5", NumberFormat::Fixed(3), "1234.500"),
        ("-3", NumberFormat::Fixed(1), "-3.0"),
        ("1.235", NumberFormat::Fixed(2), "1.24"),
        (
            "12345678901234567",
            NumberFormat::Fixed(0),
            "12345678901234567",
        ),
        (
            "5239.327720170785",
            NumberFormat::General,
            "5239.32772017079",
        ),
        (
            "0.79626390103711074",
            NumberFormat::General,
            "0.796263901037111",
        ),
        ("9.9999999999999999", NumberFormat::General, "10"),
        (
            "-0.0000000000000000001",
            NumberFormat::General,
            "-0.0000000000000000001",
        ),
        (
            "-0.00000000000000000000000001234567890123456789",
            NumberFormat::General,
            "-1.23456789012346e-26",
        ),
        (
            "0.000012345678901234567",
            NumberFormat::General,
            "0.0000123456789012346",
        ),
        ("1.005", NumberFormat::Fixed(2), "1.01"),
        ("-2.5", NumberFormat::Fixed(0), "-3"),
        ("99.996", NumberFormat::Fixed(2), "100.00"),
        ("0.125", NumberFormat::Fixed(5), "0.12500"),
        (
            "12.3456789012345678",
            NumberFormat::Fixed(20),
            "12.34567890123460000000",
        ),
        ("0.07", NumberFormat::Percent(0), "7%"),
        ("45123", NumberFormat::Date, "2023-07-16"),
        ("45123.5", NumberFormat::DateTime, "2023-07-16 12:00:00"),
        ("0.75", NumberFormat::Time, "18:00:00"),
        ("0.99999999", NumberFormat::Time, "00:00:00"),
        ("1", NumberFormat::Date, "1900-01-01"),
        ("59", NumberFormat::Date, "1900-02-28"),
        ("60", NumberFormat::Date, "1900-02-29"),
        ("61", NumberFormat::Date, "1900-03-01"),
        ("2958465", NumberFormat::Date, "9999-12-31"),
        ("2958466", NumberFormat::Date, "2958466"),
        ("-1", NumberFormat::Date, "-1"),
        ("1.5", NumberFormat::ElapsedTime, "36:00:00"),
        ("text", NumberFormat::Date, "text"),
        ("NaN", NumberFormat::General, "NaN"),
    ];
    for (raw, format, expected) in cases {
        assert_eq!(rendered(raw, *format, e1900), *expected, "{raw} {format:?}");
    }
    assert_eq!(
        rendered("0", NumberFormat::Date, DateSystem::Epoch1904),
        "1904-01-01"
    );
    assert_eq!(
        rendered("43661", NumberFormat::Date, DateSystem::Epoch1904),
        "2023-07-16"
    );
    assert_eq!(
        rendered("2957003", NumberFormat::Date, DateSystem::Epoch1904),
        "9999-12-31"
    );
    assert_eq!(
        rendered("2957004", NumberFormat::Date, DateSystem::Epoch1904),
        "2957004"
    );
    assert_eq!(
        rendered("2958465.5", NumberFormat::DateTime, DateSystem::Epoch1904),
        "2958465.5"
    );
}
