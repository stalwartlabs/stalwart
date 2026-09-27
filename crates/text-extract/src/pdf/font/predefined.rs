/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::code::{Code, MAX_CODE_LEN};
use crate::pdf::tables::{CmapDecoder, PredefinedCmap};
use encoding_rs::{BIG5, EUC_JP, EUC_KR, Encoding, GB18030, GBK, SHIFT_JIS};

const JIS_HIGH_BIT: u8 = 0x80;

impl PredefinedCmap {
    pub(crate) fn is_text_encoding(self) -> bool {
        !matches!(self.decoder(), CmapDecoder::Identity | CmapDecoder::EucTw)
    }

    pub(crate) fn decode(self, code: Code, out: &mut String) -> bool {
        let mut bytes = [0u8; MAX_CODE_LEN];
        let mut len = 0;
        for (slot, byte) in bytes.iter_mut().zip(code.bytes()) {
            *slot = byte;
            len += 1;
        }
        let bytes = bytes.get(..len).unwrap_or_default();
        let mark = out.len();
        match self.decoder() {
            CmapDecoder::Identity | CmapDecoder::EucTw => return false,
            CmapDecoder::Utf16Be => {
                let (units, _) = bytes.as_chunks::<2>();
                for ch in char::decode_utf16(units.iter().map(|pair| u16::from_be_bytes(*pair))) {
                    match ch {
                        Ok(ch) => out.push(ch),
                        Err(_) => {
                            out.truncate(mark);
                            return false;
                        }
                    }
                }
            }
            CmapDecoder::Utf8 => match std::str::from_utf8(bytes) {
                Ok(text) => out.push_str(text),
                Err(_) => return false,
            },
            CmapDecoder::Utf32Be => match char::from_u32(code.value) {
                Some(ch) => out.push(ch),
                None => return false,
            },
            CmapDecoder::JisRowCell => {
                let mut shifted = [0u8; MAX_CODE_LEN];
                for (slot, byte) in shifted.iter_mut().zip(bytes) {
                    *slot = byte | JIS_HIGH_BIT;
                }
                return legacy(EUC_JP, shifted.get(..bytes.len()).unwrap_or_default(), out);
            }
            decoder => {
                if let [byte] = bytes
                    && let Some(ch) = self.single_byte(*byte)
                {
                    out.push(ch);
                    return true;
                }
                let encoding = match decoder {
                    CmapDecoder::Gbk => GBK,
                    CmapDecoder::Gb18030 => GB18030,
                    CmapDecoder::Big5 => BIG5,
                    CmapDecoder::ShiftJis => SHIFT_JIS,
                    CmapDecoder::EucJp => EUC_JP,
                    _ => EUC_KR,
                };
                return legacy(encoding, bytes, out);
            }
        }
        out.len() > mark
    }
}

fn legacy(encoding: &'static Encoding, bytes: &[u8], out: &mut String) -> bool {
    match encoding.decode_without_bom_handling_and_without_replacement(bytes) {
        Some(text) if !text.is_empty() => {
            out.push_str(&text);
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(name: &str, value: u32, len: u8) -> Option<String> {
        let cmap = PredefinedCmap::from_name(name.as_bytes())?;
        let mut out = String::new();
        cmap.decode(
            Code {
                value,
                len,
                valid: true,
            },
            &mut out,
        )
        .then_some(out)
    }

    #[test]
    fn unicode_cmaps_decode_the_code_bytes() {
        assert_eq!(
            decode("UniJIS-UCS2-H", 0x65E5, 2).as_deref(),
            Some("\u{65e5}")
        );
        assert_eq!(
            decode("UniGB-UTF16-H", 0xD840_DC00, 4).as_deref(),
            Some("\u{20000}")
        );
        assert_eq!(
            decode("UniKS-UTF8-H", 0xED959C, 3).as_deref(),
            Some("\u{d55c}")
        );
        assert_eq!(
            decode("UniCNS-UTF32-H", 0x4E2D, 4).as_deref(),
            Some("\u{4e2d}")
        );
        assert_eq!(decode("UniJIS-UCS2-H", 0xD800, 2), None);
        assert_eq!(decode("Identity-H", 0x41, 2), None);
    }

    #[test]
    fn legacy_cmaps_use_encoding_rs() {
        assert_eq!(
            decode("90ms-RKSJ-H", 0x93FA, 2).as_deref(),
            Some("\u{65e5}")
        );
        assert_eq!(decode("90ms-RKSJ-H", 0x41, 1).as_deref(), Some("A"));
        assert_eq!(decode("GBK-EUC-H", 0xD6D0, 2).as_deref(), Some("\u{4e2d}"));
        assert_eq!(decode("ETen-B5-H", 0xA4A4, 2).as_deref(), Some("\u{4e2d}"));
        assert_eq!(
            decode("KSCms-UHC-H", 0xC7D1, 2).as_deref(),
            Some("\u{d55c}")
        );
        assert_eq!(decode("EUC-H", 0xC6FC, 2).as_deref(), Some("\u{65e5}"));
        assert_eq!(decode("H", 0x467C, 2).as_deref(), Some("\u{65e5}"));
        assert_eq!(decode("CNS-EUC-H", 0xA4A1, 2), None);
    }
}
