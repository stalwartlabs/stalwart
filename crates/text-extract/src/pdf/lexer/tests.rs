/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::*;

fn tokens(data: &[u8]) -> Vec<Token<'_>> {
    let mut lexer = Lexer::new(data);
    std::iter::from_fn(|| lexer.next()).collect()
}

#[test]
fn fast_numbers_match_the_reference_parser() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut samples: Vec<Vec<u8>> = [
        &b"0"[..],
        b"-0.5",
        b"123456789012345",
        b"1234567890123456",
        b"99999999999999999999.5",
        b"3.14159265358979323846264",
        b"-\n12.5",
        b"1.2.3",
        b"..5",
        b"+-+",
        b"0.00-5684",
    ]
    .iter()
    .map(|sample| sample.to_vec())
    .collect();
    const ALPHABET: &[u8] = b"0123456789012345678901234567890123456789.-+";
    for _ in 0..5_000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let len = 1 + (seed % 24) as usize;
        samples.push(
            (0..len)
                .map(|shift| {
                    let index =
                        (seed.rotate_left(shift as u32 * 5) % ALPHABET.len() as u64) as usize;
                    ALPHABET.get(index).copied().unwrap_or(b'0')
                })
                .collect(),
        );
    }
    for sample in &samples {
        let (mut fast, mut reference) = (Lexer::new(sample), Lexer::new(sample));
        let fast_token = fast.number(0);
        let reference_token = reference.wide_number(0);
        assert_eq!(
            (fast_token, fast.pos()),
            (reference_token, reference.pos()),
            "{:?}",
            String::from_utf8_lossy(sample)
        );
    }
}

#[test]
fn numbers_follow_reader_conventions() {
    assert_eq!(
        tokens(b"12 -3 +4 --5 5. .5 -.5 - + . 1.2.3 0.00-5684 007"),
        vec![
            Token::Int(12),
            Token::Int(-3),
            Token::Int(4),
            Token::Int(-5),
            Token::Real(5.0),
            Token::Real(0.5),
            Token::Real(-0.5),
            Token::Int(0),
            Token::Int(0),
            Token::Int(0),
            Token::Real(1.2),
            Token::Real(0.005684),
            Token::Int(7),
        ]
    );
    assert_eq!(
        tokens(b"1e5 0obj -\n5"),
        vec![
            Token::Int(1),
            Token::Keyword(b"e5"),
            Token::Int(0),
            Token::Keyword(b"obj"),
            Token::Int(-5),
        ]
    );
    let Some(Token::Real(big)) = tokens(b"123456789012345678901234567890").first().copied() else {
        panic!("overflowing integer should become a real");
    };
    assert!(big > 1e29);
    let Some(Token::Real(huge)) = tokens(&[b'9'; 400]).first().copied() else {
        panic!("huge integer should become a real");
    };
    assert_eq!(huge, f64::from(f32::MAX));
}

#[test]
fn strings_names_and_delimiters() {
    assert_eq!(
        tokens(b"/Name/A#20B (a(b)c\\)d) <41 42> <<>> [ ] { } ) > true"),
        vec![
            Token::Name(b"Name"),
            Token::Name(b"A#20B"),
            Token::Literal(b"a(b)c\\)d"),
            Token::Hex(b"41 42"),
            Token::DictOpen,
            Token::DictClose,
            Token::ArrayOpen,
            Token::ArrayClose,
            Token::BraceOpen,
            Token::BraceClose,
            Token::Error,
            Token::Error,
            Token::Keyword(b"true"),
        ]
    );
    assert_eq!(
        tokens(b"(unterminated"),
        vec![Token::Literal(b"unterminated")]
    );
    assert_eq!(tokens(b"<4142"), vec![Token::Hex(b"4142")]);
    assert_eq!(tokens(b"/"), vec![Token::Name(b"")]);
    assert_eq!(
        tokens(b"% comment\r\n/A%x\n/B"),
        vec![Token::Name(b"A"), Token::Name(b"B")]
    );
    assert_eq!(
        tokens(b"\x80Tj BT"),
        vec![
            Token::Keyword(b"\x80"),
            Token::Keyword(b"Tj"),
            Token::Keyword(b"BT")
        ]
    );
}

#[test]
fn every_call_makes_progress() {
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let mut lexer = Lexer::new(&data);
    let mut last = 0;
    while lexer.next().is_some() {
        assert!(lexer.pos() > last);
        last = lexer.pos();
    }
    assert!(lexer.at_end());
}
