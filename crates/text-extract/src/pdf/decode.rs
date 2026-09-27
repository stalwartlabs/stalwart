/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    filter::{Filter, Params},
    object::{Dict, Name, Object},
};

pub(crate) const MAX_STAGES: usize = 8;

const IMAGE_FILTERS: &[&[u8]] = &[
    b"DCTDecode",
    b"DCT",
    b"JPXDecode",
    b"JBIG2Decode",
    b"CCITTFaxDecode",
    b"CCF",
];
const FULL_NAMES: &[(&[u8], Filter)] = &[
    (b"FlateDecode", Filter::Flate),
    (b"LZWDecode", Filter::Lzw),
    (b"ASCII85Decode", Filter::Ascii85),
    (b"ASCIIHexDecode", Filter::AsciiHex),
    (b"RunLengthDecode", Filter::RunLength),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeOutcome {
    Complete,
    Truncated,
    Corrupt,
    Image,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    Codec(Filter, Params),
    Crypt { identity: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Decodable,
    Image,
    Unsupported,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Chain {
    stages: [Option<Stage>; MAX_STAGES],
    len: usize,
    status: Status,
}

impl DecodeOutcome {
    pub(crate) fn is_failure(self) -> bool {
        matches!(self, DecodeOutcome::Corrupt | DecodeOutcome::Unsupported)
    }
}

impl Chain {
    pub(crate) fn parse<'d>(dict: Dict<'d>, resolve: &impl Fn(Object<'d>) -> Object<'d>) -> Self {
        let mut chain = Chain {
            stages: [None; MAX_STAGES],
            len: 0,
            status: Status::Decodable,
        };
        let (mut filter, mut params, mut abbreviated) = (None, None, None);
        for (key, value) in dict.iter() {
            hashify::fnc_map!(key.decoded(),
                b"Filter" => filter = Some(value),
                b"DecodeParms" => params = Some(value),
                b"DP" => abbreviated = Some(value),
                _ => {}
            );
        }
        let params = params.or(abbreviated).map(resolve).unwrap_or_default();
        match filter.map(resolve).unwrap_or_default() {
            Object::Null => {}
            Object::Name(name) => {
                let params = match params {
                    Object::Array(array) => array.get(0).map(resolve).unwrap_or_default(),
                    other => other,
                };
                chain.push(name, params.as_dict(), resolve);
            }
            Object::Array(filters) => {
                let mut params = params.as_array().map(|params| params.iter());
                for filter in filters.iter() {
                    let entry = params
                        .as_mut()
                        .and_then(Iterator::next)
                        .map(resolve)
                        .and_then(|entry| entry.as_dict());
                    let Some(name) = resolve(filter).as_name() else {
                        chain.status = Status::Unsupported;
                        break;
                    };
                    chain.push(name, entry, resolve);
                    if chain.status != Status::Decodable {
                        break;
                    }
                }
            }
            _ => chain.status = Status::Unsupported,
        }
        chain
    }

    pub(crate) fn early_outcome(&self) -> Option<DecodeOutcome> {
        match self.status {
            Status::Decodable => None,
            Status::Image => Some(DecodeOutcome::Image),
            Status::Unsupported => Some(DecodeOutcome::Unsupported),
        }
    }

    pub(crate) fn stages(&self) -> impl Iterator<Item = Stage> + '_ {
        self.stages.iter().take(self.len).flatten().copied()
    }

    pub(crate) fn codecs(&self) -> impl Iterator<Item = (Filter, Params)> + '_ {
        self.stages().filter_map(|stage| match stage {
            Stage::Codec(filter, params) => Some((filter, params)),
            Stage::Crypt { .. } => None,
        })
    }

    pub(crate) fn is_passthrough(&self) -> bool {
        self.status == Status::Decodable && self.codecs().next().is_none()
    }

    pub(crate) fn crypt_stage(&self) -> Option<bool> {
        self.stages().find_map(|stage| match stage {
            Stage::Crypt { identity } => Some(identity),
            Stage::Codec(..) => None,
        })
    }

    fn push<'d>(
        &mut self,
        name: Name<'d>,
        params: Option<Dict<'d>>,
        resolve: &impl Fn(Object<'d>) -> Object<'d>,
    ) {
        let decoded = name.decoded();
        let stage = if let Some(filter) = Filter::from_name(&decoded).or_else(|| {
            FULL_NAMES
                .iter()
                .find(|(full, _)| full.eq_ignore_ascii_case(&decoded))
                .map(|&(_, filter)| filter)
        }) {
            Stage::Codec(
                filter,
                params.map_or_else(Params::default, |dict| read_params(dict, resolve)),
            )
        } else if name.is(b"Crypt") {
            Stage::Crypt {
                identity: params
                    .and_then(|dict| dict.get(b"Name"))
                    .map(resolve)
                    .is_none_or(|name| name.is_null() || name.is_name(b"Identity")),
            }
        } else {
            self.status = if IMAGE_FILTERS.iter().any(|image| name.is(image)) {
                Status::Image
            } else {
                Status::Unsupported
            };
            return;
        };
        match self.stages.get_mut(self.len) {
            Some(slot) => {
                *slot = Some(stage);
                self.len += 1;
            }
            None => self.status = Status::Unsupported,
        }
    }
}

fn read_params<'d>(dict: Dict<'d>, resolve: &impl Fn(Object<'d>) -> Object<'d>) -> Params {
    let mut params = Params::default();
    for (key, value) in dict.iter() {
        let Some(value) = resolve(value).as_int() else {
            continue;
        };
        hashify::fnc_map!(key.raw(),
            b"Predictor" => { params.predictor = value; },
            b"Colors" => { params.colors = value; },
            b"BitsPerComponent" => { params.bits_per_component = value; },
            b"Columns" => { params.columns = value; },
            b"EarlyChange" => { params.early_change = value; },
            _ => {}
        );
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::lexer::Lexer;

    fn chain(source: &[u8]) -> Chain {
        let dict = Object::read(&mut Lexer::new(source), None)
            .and_then(|object| object.as_dict())
            .unwrap_or_else(|| panic!("dict"));
        Chain::parse(dict, &|object| object)
    }

    #[test]
    fn filter_chains_follow_reader_rules() {
        let single = chain(b"<< /Filter /Fl /DecodeParms [<< /Predictor 12 /Columns 5 >>] >>");
        assert_eq!(
            single.stages().collect::<Vec<_>>(),
            vec![Stage::Codec(
                Filter::Flate,
                Params {
                    predictor: 12,
                    columns: 5,
                    ..Params::default()
                }
            )]
        );
        let array =
            chain(b"<< /Filter [/ASCIIHexDecode /flatedecode] /DecodeParms << /Predictor 12 >> >>");
        assert_eq!(
            array.stages().collect::<Vec<_>>(),
            vec![
                Stage::Codec(Filter::AsciiHex, Params::default()),
                Stage::Codec(Filter::Flate, Params::default())
            ]
        );
        let nulls = chain(b"<< /Filter [/A85 /Fl] /DecodeParms [null << /Columns 3 >>] >>");
        assert_eq!(
            nulls.stages().nth(1),
            Some(Stage::Codec(
                Filter::Flate,
                Params {
                    columns: 3,
                    ..Params::default()
                }
            ))
        );
        assert_eq!(
            chain(b"<< /Filter [/Fl /DCTDecode] >>").early_outcome(),
            Some(DecodeOutcome::Image)
        );
        assert_eq!(
            chain(b"<< /Filter /Bogus >>").early_outcome(),
            Some(DecodeOutcome::Unsupported)
        );
        assert_eq!(
            chain(b"<< /Filter [/Fl 3] >>").early_outcome(),
            Some(DecodeOutcome::Unsupported)
        );
        assert_eq!(
            chain(b"<< /Filter [/Fl /Fl /Fl /Fl /Fl /Fl /Fl /Fl /Fl] >>").early_outcome(),
            Some(DecodeOutcome::Unsupported)
        );
        assert_eq!(chain(b"<< /F /Fl >>").stages().count(), 0);
        assert_eq!(chain(b"<< /Filter [/Crypt] >>").crypt_stage(), Some(true));
        assert_eq!(
            chain(b"<< /Filter [/Crypt] /DecodeParms [<< /Name /StdCF >>] >>").crypt_stage(),
            Some(false)
        );
    }
}
