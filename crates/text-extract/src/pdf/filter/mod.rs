/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod ascii85;
mod ascii_hex;
mod flate;
mod lzw;
mod output;
mod predictor;
mod run_length;
mod stage;

#[cfg(test)]
mod tests;

use flate2::Decompress;

use self::flate::FlateSource;
use self::lzw::{LzwSource, LzwTable};
use self::output::Output;
use self::predictor::Layout;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filter {
    Flate,
    Lzw,
    Ascii85,
    AsciiHex,
    RunLength,
}

impl Filter {
    pub(crate) fn from_name(name: &[u8]) -> Option<Self> {
        hashify::map!(name, Filter,
            b"FlateDecode" => Filter::Flate,
            b"Fl" => Filter::Flate,
            b"LZWDecode" => Filter::Lzw,
            b"LZW" => Filter::Lzw,
            b"ASCII85Decode" => Filter::Ascii85,
            b"A85" => Filter::Ascii85,
            b"ASCIIHexDecode" => Filter::AsciiHex,
            b"AHx" => Filter::AsciiHex,
            b"RunLengthDecode" => Filter::RunLength,
            b"RL" => Filter::RunLength,
        )
        .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Params {
    pub(crate) predictor: i64,
    pub(crate) colors: i64,
    pub(crate) bits_per_component: i64,
    pub(crate) columns: i64,
    pub(crate) early_change: i64,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            predictor: 1,
            colors: 1,
            bits_per_component: 8,
            columns: 1,
            early_change: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[must_use]
pub(crate) struct Outcome {
    pub(crate) truncated: bool,
    pub(crate) corrupt: bool,
}

pub(crate) struct Decoder {
    inflate: Decompress,
    lzw: Option<Box<LzwTable>>,
    probe: Vec<u8>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub(crate) fn new() -> Self {
        Self {
            inflate: Decompress::new(false),
            lzw: None,
            probe: Vec::with_capacity(1),
        }
    }

    pub(crate) fn decode(
        &mut self,
        filter: Filter,
        params: &Params,
        input: &[u8],
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Outcome {
        match filter {
            Filter::Flate => {
                let (layout, invalid) = Layout::from_params(params);
                let mut source = FlateSource::new(&mut self.inflate, input);
                stage::run(&mut source, layout, out, limit, &mut self.probe).or_corrupt(invalid)
            }
            Filter::Lzw => {
                let (layout, invalid) = Layout::from_params(params);
                let table = self.lzw.get_or_insert_with(LzwTable::boxed);
                let mut source = LzwSource::new(table, input, params.early_change != 0);
                stage::run(&mut source, layout, out, limit, &mut self.probe).or_corrupt(invalid)
            }
            Filter::Ascii85 => Output::run(out, limit, |output| ascii85::decode(input, output)),
            Filter::AsciiHex => Output::run(out, limit, |output| ascii_hex::decode(input, output)),
            Filter::RunLength => {
                Output::run(out, limit, |output| run_length::decode(input, output))
            }
        }
    }
}

impl Outcome {
    fn or_corrupt(self, corrupt: bool) -> Self {
        Self {
            truncated: self.truncated,
            corrupt: self.corrupt | corrupt,
        }
    }
}
