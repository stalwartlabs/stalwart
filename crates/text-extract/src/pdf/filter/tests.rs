/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Write;

use flate2::Compression;
use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};

use super::{Decoder, Filter, Outcome, Params};

const UNLIMITED: usize = usize::MAX;

const CONTENT: &[u8] = include_bytes!("testdata/flate_content.bin");
const CONTENT_ZLIB: &[u8] = include_bytes!("testdata/flate_content.zlib");
const LZW_CORPUS: &[u8] = include_bytes!("testdata/lzw_corpus.bin");
const LZW_EARLY1: &[u8] = include_bytes!("testdata/lzw_early1.bin");
const LZW_EARLY0: &[u8] = include_bytes!("testdata/lzw_early0.bin");
const LZW_FROZEN: &[u8] = include_bytes!("testdata/lzw_frozen.bin");
const LZW_PNG8: &[u8] = include_bytes!("testdata/lzw_png8.bin");

const CLEAN: Outcome = Outcome {
    truncated: false,
    corrupt: false,
};
const CORRUPT: Outcome = Outcome {
    truncated: false,
    corrupt: true,
};
const TRUNCATED: Outcome = Outcome {
    truncated: true,
    corrupt: false,
};

struct Vector {
    encoded: &'static [u8],
    image: &'static [u8],
    params: Params,
}

fn predicted(predictor: i64, colors: i64, bits_per_component: i64, columns: i64) -> Params {
    Params {
        predictor,
        colors,
        bits_per_component,
        columns,
        ..Params::default()
    }
}

fn vectors() -> [(&'static str, Vector); 8] {
    [
        (
            "png8",
            Vector {
                encoded: include_bytes!("testdata/png8_encoded.bin"),
                image: include_bytes!("testdata/png8_image.bin"),
                params: predicted(12, 3, 8, 7),
            },
        ),
        (
            "png16",
            Vector {
                encoded: include_bytes!("testdata/png16_encoded.bin"),
                image: include_bytes!("testdata/png16_image.bin"),
                params: predicted(15, 2, 16, 3),
            },
        ),
        (
            "png2",
            Vector {
                encoded: include_bytes!("testdata/png2_encoded.bin"),
                image: include_bytes!("testdata/png2_image.bin"),
                params: predicted(10, 1, 2, 11),
            },
        ),
        (
            "tiff8",
            Vector {
                encoded: include_bytes!("testdata/tiff8_encoded.bin"),
                image: include_bytes!("testdata/tiff8_image.bin"),
                params: predicted(2, 3, 8, 5),
            },
        ),
        (
            "tiff16",
            Vector {
                encoded: include_bytes!("testdata/tiff16_encoded.bin"),
                image: include_bytes!("testdata/tiff16_image.bin"),
                params: predicted(2, 2, 16, 4),
            },
        ),
        (
            "tiff1",
            Vector {
                encoded: include_bytes!("testdata/tiff1_encoded.bin"),
                image: include_bytes!("testdata/tiff1_image.bin"),
                params: predicted(2, 1, 1, 13),
            },
        ),
        (
            "tiff2",
            Vector {
                encoded: include_bytes!("testdata/tiff2_encoded.bin"),
                image: include_bytes!("testdata/tiff2_image.bin"),
                params: predicted(2, 3, 2, 5),
            },
        ),
        (
            "tiff4",
            Vector {
                encoded: include_bytes!("testdata/tiff4_encoded.bin"),
                image: include_bytes!("testdata/tiff4_image.bin"),
                params: predicted(2, 3, 4, 3),
            },
        ),
    ]
}

fn decode(filter: Filter, params: &Params, input: &[u8], limit: usize) -> (Vec<u8>, Outcome) {
    let mut out = Vec::new();
    let outcome = Decoder::new().decode(filter, params, input, &mut out, limit);
    (out, outcome)
}

fn flate(input: &[u8]) -> (Vec<u8>, Outcome) {
    decode(Filter::Flate, &Params::default(), input, UNLIMITED)
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("in-memory write");
    encoder.finish().expect("in-memory finish")
}

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).expect("in-memory write");
    encoder.finish().expect("in-memory finish")
}

fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u8
        })
        .collect()
}

fn text(len: usize) -> Vec<u8> {
    let words: [&[u8]; 6] = [
        b"BT ",
        b"/F1 12 Tf ",
        b"(Hello world) Tj ",
        b"ET\n",
        b"72 712 Td ",
        b"q 1 0 0 1 0 0 cm Q\n",
    ];
    noise(99, len)
        .iter()
        .flat_map(|byte| {
            words
                .get(usize::from(*byte) % words.len())
                .copied()
                .unwrap_or_default()
        })
        .copied()
        .take(len)
        .collect()
}

#[test]
fn filter_names() {
    for (name, filter) in [
        (&b"FlateDecode"[..], Filter::Flate),
        (b"Fl", Filter::Flate),
        (b"LZWDecode", Filter::Lzw),
        (b"LZW", Filter::Lzw),
        (b"ASCII85Decode", Filter::Ascii85),
        (b"A85", Filter::Ascii85),
        (b"ASCIIHexDecode", Filter::AsciiHex),
        (b"AHx", Filter::AsciiHex),
        (b"RunLengthDecode", Filter::RunLength),
        (b"RL", Filter::RunLength),
    ] {
        assert_eq!(Filter::from_name(name), Some(filter));
    }
    for name in [
        &b"DCTDecode"[..],
        b"DCT",
        b"JPXDecode",
        b"JBIG2Decode",
        b"CCITTFaxDecode",
        b"CCF",
        b"Crypt",
        b"flatedecode",
        b"",
    ] {
        assert_eq!(Filter::from_name(name), None);
    }
}

#[test]
fn params_default() {
    assert_eq!(
        Params::default(),
        Params {
            predictor: 1,
            colors: 1,
            bits_per_component: 8,
            columns: 1,
            early_change: 1,
        }
    );
}

#[test]
fn flate_python_vector() {
    assert_eq!(flate(CONTENT_ZLIB), (CONTENT.to_vec(), CLEAN));
}

#[test]
fn flate_round_trips() {
    for len in [0, 1, 100, 4096, 70_000, 1_500_000] {
        let data = text(len);
        assert_eq!(flate(&zlib(&data)), (data.clone(), CLEAN), "len {len}");
        let random = noise(len as u32, len);
        assert_eq!(flate(&zlib(&random)), (random, CLEAN), "random len {len}");
    }
}

#[test]
fn flate_bad_adler() {
    let mut compressed = zlib(CONTENT);
    if let Some(last) = compressed.last_mut() {
        *last ^= 0xff;
    }
    assert_eq!(flate(&compressed), (CONTENT.to_vec(), CLEAN));
    let without_adler = compressed.get(..compressed.len() - 4).unwrap_or_default();
    assert_eq!(flate(without_adler), (CONTENT.to_vec(), CLEAN));
}

#[test]
fn flate_truncated() {
    let data = text(200_000);
    let compressed = zlib(&data);
    for cut in [3, 100, compressed.len() / 2, compressed.len() - 10] {
        let (out, outcome) = flate(compressed.get(..cut).unwrap_or_default());
        assert_eq!(outcome, CORRUPT, "cut {cut}");
        assert!(data.starts_with(&out), "cut {cut}");
        if cut > 1000 {
            assert!(out.len() > cut, "cut {cut} gave {}", out.len());
        }
    }
}

#[test]
fn flate_corrupt_middle_keeps_prefix() {
    let data = text(300_000);
    let mut compressed = raw_deflate(&data);
    let middle = compressed.len() / 2;
    if let Some(chunk) = compressed.get_mut(middle..middle + 64) {
        chunk.fill(0xff);
    }
    let (out, _) = flate(&compressed);
    assert!(out.len() > data.len() / 4);
    let prefix = out.len().min(data.len() / 3);
    assert_eq!(out.get(..prefix), data.get(..prefix));
}

#[test]
fn flate_raw_deflate() {
    assert_eq!(flate(&raw_deflate(CONTENT)), (CONTENT.to_vec(), CLEAN));
    let data = text(100_000);
    assert_eq!(flate(&raw_deflate(&data)), (data, CLEAN));
}

#[test]
fn flate_raw_after_bogus_header() {
    let mut input = vec![0x00, 0x00];
    input.extend(raw_deflate(CONTENT));
    assert_eq!(flate(&input), (CONTENT.to_vec(), CLEAN));
}

#[test]
fn flate_trailing_garbage() {
    let mut compressed = zlib(CONTENT);
    compressed.extend_from_slice(b"\r\nendstream\nendobj\n\x00\xff\x13garbage");
    assert_eq!(flate(&compressed), (CONTENT.to_vec(), CLEAN));
}

#[test]
fn flate_leading_whitespace() {
    let mut input = b"\r\n".to_vec();
    input.extend(zlib(CONTENT));
    assert_eq!(flate(&input), (CONTENT.to_vec(), CLEAN));
}

#[test]
fn flate_gzip() {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(CONTENT).expect("in-memory write");
    let compressed = encoder.finish().expect("in-memory finish");
    assert_eq!(flate(&compressed), (CONTENT.to_vec(), CLEAN));
}

#[test]
fn flate_empty_and_garbage() {
    assert_eq!(flate(b""), (Vec::new(), CORRUPT));
    let (out, outcome) = flate(&noise(5, 10_000));
    assert!(outcome.corrupt || out.len() <= 10_000 * 1032);
}

#[test]
fn flate_limit() {
    let compressed = zlib(CONTENT);
    let params = Params::default();
    for limit in [0, 1, 999, 2048, CONTENT.len() - 1] {
        let (out, outcome) = decode(Filter::Flate, &params, &compressed, limit);
        assert_eq!(outcome, TRUNCATED, "limit {limit}");
        assert_eq!(out.as_slice(), CONTENT.get(..limit).unwrap_or_default());
        assert!(
            out.capacity() <= limit.max(1),
            "limit {limit} capacity {}",
            out.capacity()
        );
    }
    for limit in [CONTENT.len(), CONTENT.len() + 1] {
        assert_eq!(
            decode(Filter::Flate, &params, &compressed, limit),
            (CONTENT.to_vec(), CLEAN)
        );
    }
}

#[test]
fn flate_bomb_is_capped() {
    let zeros = vec![0u8; 50_000_000];
    let compressed = zlib(&zeros);
    let (out, outcome) = decode(Filter::Flate, &Params::default(), &compressed, 1_000_000);
    assert_eq!(outcome, TRUNCATED);
    assert_eq!(out.len(), 1_000_000);
    assert!(out.capacity() <= 1_000_000);
}

#[test]
fn appends_to_existing_output() {
    let mut out = b"prefix".to_vec();
    let mut decoder = Decoder::new();
    let outcome = decoder.decode(
        Filter::Flate,
        &Params::default(),
        &zlib(CONTENT),
        &mut out,
        10,
    );
    assert_eq!(outcome, TRUNCATED);
    assert_eq!(out.len(), 16);
    assert!(out.starts_with(b"prefix"));
    let outcome = decoder.decode(
        Filter::AsciiHex,
        &Params::default(),
        b"4142>",
        &mut out,
        UNLIMITED,
    );
    assert_eq!(outcome, CLEAN);
    assert!(out.ends_with(b"AB"));
}

#[test]
fn decoder_reuse() {
    let mut decoder = Decoder::new();
    let compressed = zlib(CONTENT);
    for _ in 0..3 {
        for (name, vector) in vectors() {
            let mut out = Vec::new();
            let outcome = decoder.decode(
                Filter::Flate,
                &vector.params,
                &zlib(vector.encoded),
                &mut out,
                UNLIMITED,
            );
            assert_eq!((out.as_slice(), outcome), (vector.image, CLEAN), "{name}");
        }
        let mut out = Vec::new();
        let _ = decoder.decode(
            Filter::Flate,
            &Params::default(),
            compressed.get(..100).unwrap_or_default(),
            &mut out,
            UNLIMITED,
        );
        let mut out = Vec::new();
        assert_eq!(
            decoder.decode(
                Filter::Flate,
                &Params::default(),
                &compressed,
                &mut out,
                UNLIMITED
            ),
            CLEAN
        );
        assert_eq!(out, CONTENT);
        let mut out = Vec::new();
        assert_eq!(
            decoder.decode(
                Filter::Lzw,
                &Params::default(),
                LZW_EARLY1,
                &mut out,
                UNLIMITED
            ),
            CLEAN
        );
        assert_eq!(out, LZW_CORPUS);
    }
}

#[test]
fn predictor_vectors() {
    for (name, vector) in vectors() {
        let compressed = zlib(vector.encoded);
        assert_eq!(
            decode(Filter::Flate, &vector.params, &compressed, UNLIMITED),
            (vector.image.to_vec(), CLEAN),
            "{name}"
        );
    }
}

#[test]
fn predictor_limits() {
    for (name, vector) in vectors() {
        let compressed = zlib(vector.encoded);
        for limit in 0..vector.image.len() {
            let (out, outcome) = decode(Filter::Flate, &vector.params, &compressed, limit);
            assert_eq!(outcome, TRUNCATED, "{name} limit {limit}");
            assert_eq!(
                out.as_slice(),
                vector.image.get(..limit).unwrap_or_default(),
                "{name} limit {limit}"
            );
            assert!(out.capacity() <= limit + 1, "{name} limit {limit}");
        }
        assert_eq!(
            decode(
                Filter::Flate,
                &vector.params,
                &compressed,
                vector.image.len()
            ),
            (vector.image.to_vec(), CLEAN),
            "{name}"
        );
    }
}

#[test]
fn predictor_partial_last_row() {
    for (name, vector) in vectors() {
        for cut in 1..vector.encoded.len() {
            let encoded = vector.encoded.get(..cut).unwrap_or_default();
            let (out, outcome) = decode(Filter::Flate, &vector.params, &zlib(encoded), UNLIMITED);
            assert_eq!(outcome, CLEAN, "{name} cut {cut}");
            assert!(out.len() <= cut, "{name} cut {cut}");
            let exact = match (vector.params.predictor, vector.params.bits_per_component) {
                (2, 16) => out.len() & !1,
                (2, 1..8) => 0,
                _ => out.len(),
            };
            assert_eq!(
                out.get(..exact),
                vector.image.get(..exact),
                "{name} cut {cut}"
            );
        }
    }
}

#[test]
fn predictor_through_lzw() {
    let (_, vector) = vectors().into_iter().next().expect("png8 vector");
    assert_eq!(
        decode(Filter::Lzw, &vector.params, LZW_PNG8, UNLIMITED),
        (vector.image.to_vec(), CLEAN)
    );
    let (out, outcome) = decode(Filter::Lzw, &vector.params, LZW_PNG8, 100);
    assert_eq!(outcome, TRUNCATED);
    assert_eq!(out.as_slice(), vector.image.get(..100).unwrap_or_default());
}

#[test]
fn png_unknown_row_type_is_none() {
    let encoded = [0u8, 1, 2, 3, 9, 4, 5, 6, 2, 1, 1, 1];
    let (out, outcome) = decode(
        Filter::Flate,
        &predicted(12, 1, 8, 3),
        &zlib(&encoded),
        UNLIMITED,
    );
    assert_eq!(out, [1, 2, 3, 4, 5, 6, 5, 6, 7]);
    assert_eq!(outcome, CORRUPT);
}

#[test]
fn png_xref_rows() {
    let rows: [[u8; 5]; 3] = [[1, 0, 0, 0x10, 0], [1, 0, 0, 0x90, 0], [2, 0, 0, 0, 1]];
    let mut encoded = Vec::new();
    let mut previous = [0u8; 5];
    for row in rows {
        encoded.push(2);
        encoded.extend(
            row.iter()
                .zip(previous)
                .map(|(current, above)| current.wrapping_sub(above)),
        );
        previous = row;
    }
    let (out, outcome) = decode(
        Filter::Flate,
        &predicted(12, 1, 8, 5),
        &zlib(&encoded),
        UNLIMITED,
    );
    assert_eq!(outcome, CLEAN);
    assert_eq!(out, rows.as_flattened());
}

#[test]
fn absurd_params() {
    let data = text(5000);
    let compressed = zlib(&data);
    for params in [
        predicted(12, 1, 8, 0),
        predicted(12, 1, 8, -5),
        predicted(12, 1, 8, i64::MAX),
        predicted(2, i64::MAX, 16, i64::MAX),
        predicted(12, 1, 3, 4),
        predicted(12, 1, 32, 4),
        predicted(7, 1, 8, 4),
        predicted(16, 1, 8, 4),
        predicted(i64::MAX, 1, 8, 4),
    ] {
        assert_eq!(
            decode(Filter::Flate, &params, &compressed, UNLIMITED),
            (data.clone(), CORRUPT),
            "{params:?}"
        );
    }
    for params in [
        predicted(1, 1, 8, 4),
        predicted(0, 99, 99, -1),
        predicted(i64::MIN, 1, 8, 4),
    ] {
        assert_eq!(
            decode(Filter::Flate, &params, &compressed, UNLIMITED),
            (data.clone(), CLEAN),
            "{params:?}"
        );
    }
    let huge = predicted(12, 1, 8, 1 << 40);
    let (out, outcome) = decode(Filter::Flate, &huge, &compressed, UNLIMITED);
    assert!(!outcome.truncated);
    assert_eq!(out.len(), data.len() - 1);
    let clamped = predicted(12, 1000, 8, 1);
    let (out, outcome) = decode(Filter::Flate, &clamped, &compressed, UNLIMITED);
    assert!(!outcome.truncated);
    assert_eq!(out.len(), data.len() - data.len().div_ceil(33));
    let huge_tiff = predicted(2, 32, 16, 1 << 40);
    let (out, outcome) = decode(Filter::Flate, &huge_tiff, &compressed, 100);
    assert_eq!(outcome, TRUNCATED);
    assert_eq!(out.len(), 100);
}

#[test]
fn lzw_vectors() {
    let early0 = Params {
        early_change: 0,
        ..Params::default()
    };
    let early_other = Params {
        early_change: 7,
        ..Params::default()
    };
    assert_eq!(
        decode(Filter::Lzw, &Params::default(), LZW_EARLY1, UNLIMITED),
        (LZW_CORPUS.to_vec(), CLEAN)
    );
    assert_eq!(
        decode(Filter::Lzw, &early_other, LZW_EARLY1, UNLIMITED),
        (LZW_CORPUS.to_vec(), CLEAN)
    );
    assert_eq!(
        decode(Filter::Lzw, &early0, LZW_EARLY0, UNLIMITED),
        (LZW_CORPUS.to_vec(), CLEAN)
    );
    assert_eq!(
        decode(Filter::Lzw, &Params::default(), LZW_FROZEN, UNLIMITED),
        (LZW_CORPUS.to_vec(), CLEAN)
    );
    let (out, _) = decode(Filter::Lzw, &early0, LZW_EARLY1, UNLIMITED);
    assert_ne!(out, LZW_CORPUS);
}

#[test]
fn lzw_specification_example() {
    let input = [0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01];
    assert_eq!(
        decode(Filter::Lzw, &Params::default(), &input, UNLIMITED),
        (b"-----A---B".to_vec(), CLEAN)
    );
}

#[test]
fn lzw_truncated_and_limit() {
    for cut in [0, 1, 2, 100, LZW_EARLY1.len() / 2, LZW_EARLY1.len() - 1] {
        let (out, outcome) = decode(
            Filter::Lzw,
            &Params::default(),
            LZW_EARLY1.get(..cut).unwrap_or_default(),
            UNLIMITED,
        );
        assert_eq!(outcome, CLEAN, "cut {cut}");
        assert!(LZW_CORPUS.starts_with(&out), "cut {cut}");
    }
    for limit in [0, 1, 7, 5000, LZW_CORPUS.len() - 1] {
        let (out, outcome) = decode(Filter::Lzw, &Params::default(), LZW_EARLY1, limit);
        assert_eq!(outcome, TRUNCATED, "limit {limit}");
        assert_eq!(out.as_slice(), LZW_CORPUS.get(..limit).unwrap_or_default());
    }
    assert_eq!(
        decode(
            Filter::Lzw,
            &Params::default(),
            LZW_EARLY1,
            LZW_CORPUS.len()
        ),
        (LZW_CORPUS.to_vec(), CLEAN)
    );
}

#[test]
fn lzw_invalid_codes() {
    let mut writer = BitWriter::default();
    for code in [256, 65, 66, 400] {
        writer.write(code, 9);
    }
    let (out, outcome) = decode(Filter::Lzw, &Params::default(), &writer.finish(), UNLIMITED);
    assert_eq!((out.as_slice(), outcome), (&b"AB"[..], CORRUPT));

    let mut writer = BitWriter::default();
    for code in [256, 300, 65] {
        writer.write(code, 9);
    }
    let (out, outcome) = decode(Filter::Lzw, &Params::default(), &writer.finish(), UNLIMITED);
    assert_eq!((out.as_slice(), outcome), (&b""[..], CORRUPT));

    let mut writer = BitWriter::default();
    for code in [65, 258, 256, 66, 257, 67] {
        writer.write(code, 9);
    }
    let (out, outcome) = decode(Filter::Lzw, &Params::default(), &writer.finish(), UNLIMITED);
    assert_eq!((out.as_slice(), outcome), (&b"AAAB"[..], CLEAN));

    let mut writer = BitWriter::default();
    for code in [65, 66, 256, 258, 67] {
        writer.write(code, 9);
    }
    let (out, outcome) = decode(Filter::Lzw, &Params::default(), &writer.finish(), UNLIMITED);
    assert_eq!((out.as_slice(), outcome), (&b"AB"[..], CORRUPT));

    let mut writer = BitWriter::default();
    for code in [65, 66, 258, 256, 67, 257, 68] {
        writer.write(code, 9);
    }
    let (out, outcome) = decode(Filter::Lzw, &Params::default(), &writer.finish(), UNLIMITED);
    assert_eq!((out.as_slice(), outcome), (&b"ABABC"[..], CLEAN));
}

#[test]
fn lzw_bomb_is_capped() {
    let mut writer = BitWriter::default();
    writer.write(256, 9);
    writer.write(65, 9);
    let mut next = 258u32;
    let mut code = 65u32;
    while next < 4096 {
        let width = match next + 1 {
            2048.. => 12,
            1024.. => 11,
            512.. => 10,
            _ => 9,
        };
        code = if code == 65 { 258 } else { next };
        writer.write(code, width);
        next += 1;
    }
    for _ in 0..20_000 {
        writer.write(code, 12);
    }
    let input = writer.finish();
    let (out, outcome) = decode(Filter::Lzw, &Params::default(), &input, 10_000_000);
    assert_eq!(outcome, TRUNCATED);
    assert_eq!(out.len(), 10_000_000);
    assert!(out.iter().all(|byte| *byte == b'A'));
}

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    buffer: u64,
    bits: u32,
}

impl BitWriter {
    fn write(&mut self, code: u32, width: u32) {
        self.buffer = (self.buffer << width) | u64::from(code);
        self.bits += width;
        while self.bits >= 8 {
            self.bits -= 8;
            self.out.push((self.buffer >> self.bits) as u8);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.out.push((self.buffer << (8 - self.bits)) as u8);
        }
        self.out
    }
}

fn a85(input: &[u8]) -> (Vec<u8>, Outcome) {
    decode(Filter::Ascii85, &Params::default(), input, UNLIMITED)
}

#[test]
fn ascii85_python_vectors() {
    let hello = b"Hello, PDF world! \x00\x00\x00\x00 end.".to_vec();
    assert_eq!(
        a85(b"<~87cURD_*#-6q/;CDfTZ)+Wpab!!\"-QDIb@~>"),
        (hello.clone(), CLEAN)
    );
    assert_eq!(
        a85(b"87cURD_*#-6q/;CDfTZ)+Wpab!!\"-QDIb@~>"),
        (hello.clone(), CLEAN)
    );
    assert_eq!(
        a85(b"87cU RD_*#\r\n-6q/;\tCDfTZ)+W\x0cpab!!\"-QDIb@\x00~"),
        (hello.clone(), CLEAN)
    );
    assert_eq!(a85(b"87cURD_*#-6q/;CDfTZ)+Wpab!!\"-QDIb@"), (hello, CLEAN));
    assert_eq!(a85(b"@:E_WAS,Q~>"), (b"abcdefg".to_vec(), CLEAN));
    assert_eq!(a85(b"s8W-!~>"), (vec![0xff; 4], CLEAN));
}

#[test]
fn ascii85_edge_cases() {
    assert_eq!(a85(b"z~>"), (vec![0; 4], CLEAN));
    assert_eq!(
        a85(b"zz@:E_Wz~>"),
        ([&[0u8; 8][..], b"abcd", &[0; 4]].concat(), CLEAN)
    );
    assert_eq!(a85(b"@:zE_W~>"), (b"abcd".to_vec(), CORRUPT));
    assert_eq!(a85(b"@:E{_W~>"), (b"abcd".to_vec(), CORRUPT));
    assert_eq!(a85(b"@:E_WA~>"), (b"abcd".to_vec(), CORRUPT));
    assert_eq!(a85(b"~>"), (Vec::new(), CLEAN));
    assert_eq!(a85(b""), (Vec::new(), CLEAN));
    assert_eq!(a85(b"@:E_W~>@:E_W"), (b"abcd".to_vec(), CLEAN));
    let (out, outcome) = a85(b"uuuuu~>");
    assert_eq!((out.len(), outcome), (4, CLEAN));
    let (out, outcome) = decode(Filter::Ascii85, &Params::default(), b"zzz", 6);
    assert_eq!((out, outcome), (vec![0; 6], TRUNCATED));
    let (out, outcome) = decode(Filter::Ascii85, &Params::default(), b"@:E_WAS,Q~>", 7);
    assert_eq!((out, outcome), (b"abcdefg".to_vec(), CLEAN));
    let (out, outcome) = decode(Filter::Ascii85, &Params::default(), b"@:E_WAS,Q~>", 6);
    assert_eq!((out, outcome), (b"abcdef".to_vec(), TRUNCATED));
}

fn hex(input: &[u8]) -> (Vec<u8>, Outcome) {
    decode(Filter::AsciiHex, &Params::default(), input, UNLIMITED)
}

#[test]
fn ascii_hex_edge_cases() {
    assert_eq!(hex(b"48656c6C6F>"), (b"Hello".to_vec(), CLEAN));
    assert_eq!(hex(b" 4 8\r\n65\t6c 6c6f >"), (b"Hello".to_vec(), CLEAN));
    assert_eq!(hex(b"48656c6c6f"), (b"Hello".to_vec(), CLEAN));
    assert_eq!(hex(b"4865 7>"), (vec![0x48, 0x65, 0x70], CLEAN));
    assert_eq!(hex(b"48657"), (vec![0x48, 0x65, 0x70], CLEAN));
    assert_eq!(hex(b"48>6565"), (vec![0x48], CLEAN));
    assert_eq!(hex(b"4x8g65>"), (vec![0x48, 0x65], CORRUPT));
    assert_eq!(hex(b">"), (Vec::new(), CLEAN));
    let (out, outcome) = decode(Filter::AsciiHex, &Params::default(), b"414243>", 2);
    assert_eq!((out, outcome), (b"AB".to_vec(), TRUNCATED));
    let (out, outcome) = decode(Filter::AsciiHex, &Params::default(), b"414243>", 3);
    assert_eq!((out, outcome), (b"ABC".to_vec(), CLEAN));
}

fn rle(input: &[u8]) -> (Vec<u8>, Outcome) {
    decode(Filter::RunLength, &Params::default(), input, UNLIMITED)
}

#[test]
fn run_length_edge_cases() {
    assert_eq!(
        rle(b"\x02abc\xfex\x00y\x80zzz"),
        (b"abcxxxy".to_vec(), CLEAN)
    );
    assert_eq!(rle(b"\x02abc\xfex"), (b"abcxxx".to_vec(), CLEAN));
    assert_eq!(rle(b"\x81q\x80"), (vec![b'q'; 128], CLEAN));
    assert_eq!(rle(b"\x05ab"), (b"ab".to_vec(), CORRUPT));
    assert_eq!(rle(b"\x01a\xfe"), (b"a\xfe".to_vec(), CLEAN));
    assert_eq!(rle(b"\x00a\xfe"), (b"a".to_vec(), CORRUPT));
    assert_eq!(rle(b"\x80"), (Vec::new(), CLEAN));
    assert_eq!(rle(b""), (Vec::new(), CLEAN));
    let (out, outcome) = decode(
        Filter::RunLength,
        &Params::default(),
        b"\x81q\x81r\x80",
        200,
    );
    assert_eq!((out.len(), outcome), (200, TRUNCATED));
    assert!(out.capacity() <= 200);
    let bomb = b"\x81z".repeat(10_000);
    let (out, outcome) = decode(Filter::RunLength, &Params::default(), &bomb, 100_000);
    assert_eq!((out.len(), outcome), (100_000, TRUNCATED));
    assert!(out.capacity() <= 100_000);
    let (out, outcome) = decode(Filter::RunLength, &Params::default(), b"\x04abcde\x80", 3);
    assert_eq!((out, outcome), (b"abc".to_vec(), TRUNCATED));
    let (out, outcome) = decode(Filter::RunLength, &Params::default(), b"\x04abcde\x80", 5);
    assert_eq!((out, outcome), (b"abcde".to_vec(), CLEAN));
}

#[test]
fn hostile_inputs_never_panic() {
    let mut decoder = Decoder::new();
    let mut out = Vec::new();
    let filters = [
        Filter::Flate,
        Filter::Lzw,
        Filter::Ascii85,
        Filter::AsciiHex,
        Filter::RunLength,
    ];
    let params = [
        Params::default(),
        predicted(12, 1, 8, 5),
        predicted(2, 3, 2, 7),
        predicted(2, 2, 16, 3),
        predicted(15, 4, 1, 1),
        Params {
            early_change: 0,
            ..Params::default()
        },
    ];
    let compressed = zlib(&text(20_000));
    for seed in 0..60u32 {
        let mut input = noise(seed, 1 + (seed as usize * 97) % 5000);
        if seed % 3 == 0 {
            input = compressed.clone();
            if let Some(byte) = input.get_mut(seed as usize * 13 % compressed.len()) {
                *byte ^= 0x5a;
            }
        }
        for filter in filters {
            for params in &params {
                for limit in [0, 1, 17, 4096, UNLIMITED] {
                    out.clear();
                    let _ = decoder.decode(filter, params, &input, &mut out, limit);
                    assert!(out.len() <= limit);
                }
            }
        }
    }
}
