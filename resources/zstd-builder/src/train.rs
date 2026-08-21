use std::ffi::CStr;

use store::write::compress::{
    COMPRESS_WATERMARK, COMPRESS_WATERMARK_DICTIONARY, COMPRESSION_LEVEL,
};
use zstd::{
    bulk::{Compressor, Decompressor},
    dict::{DecoderDictionary, EncoderDictionary},
    zstd_safe::{CParameter, compress_bound, get_dict_id_from_dict, get_dict_id_from_frame},
};

use crate::corpus::Corpus;

pub const CANDIDATE_SIZES: [usize; 7] = [2048, 4096, 8192, 16384, 32768, 65536, 114688];
pub const MIN_DICTIONARY_SIZE: usize = 256;

const DICT_MAGIC: u32 = 0xEC30A437;
const DICT_ID_FLOOR: u32 = 32768;
const DICT_ID_CEILING: u32 = 65536;
const KNEE_TOLERANCE: f64 = 0.5;
const ARCHIVE_HASH_LEN: usize = 4;

pub struct Split {
    pub train: Vec<Vec<u8>>,
    pub dev: Vec<Vec<u8>>,
}

pub fn split(corpus: Corpus, core_only: bool) -> Split {
    let mut train = Vec::with_capacity(corpus.len() - corpus.len() / 4);
    let mut dev = Vec::with_capacity(corpus.len() / 4);
    for (index, (scrubbed, real)) in corpus.scrubbed.into_iter().zip(corpus.real).enumerate() {
        if index % 4 == 3 {
            dev.push(real);
        } else {
            train.push(scrubbed);
        }
    }
    if !core_only {
        train.extend(corpus.train_only);
    }
    Split { train, dev }
}

pub struct Samples {
    flat: Vec<u8>,
    sizes: Vec<usize>,
}

impl Samples {
    pub fn new(samples: &[Vec<u8>]) -> Self {
        let mut flat = Vec::with_capacity(samples.iter().map(Vec::len).sum());
        let mut sizes = Vec::with_capacity(samples.len());
        for sample in samples {
            flat.extend_from_slice(sample);
            sizes.push(sample.len());
        }
        Samples { flat, sizes }
    }
}

pub fn train(samples: &Samples, capacity: usize) -> Result<Vec<u8>, String> {
    use zstd::zstd_safe::zstd_sys;

    let mut params = zstd_sys::ZDICT_cover_params_t {
        k: 0,
        d: 0,
        steps: 32,
        nbThreads: 1,
        splitPoint: 1.0,
        shrinkDict: 0,
        shrinkDictMaxRegression: 0,
        zParams: zstd_sys::ZDICT_params_t {
            compressionLevel: COMPRESSION_LEVEL,
            notificationLevel: 0,
            dictID: 0,
        },
    };

    let mut out = vec![0u8; capacity];
    let written = unsafe {
        zstd_sys::ZDICT_optimizeTrainFromBuffer_cover(
            out.as_mut_ptr() as *mut _,
            out.len(),
            samples.flat.as_ptr() as *const _,
            samples.sizes.as_ptr(),
            samples.sizes.len() as u32,
            &mut params,
        )
    };
    if unsafe { zstd_sys::ZDICT_isError(written) } != 0 {
        let name = unsafe { CStr::from_ptr(zstd_sys::ZDICT_getErrorName(written)) };
        return Err(name.to_string_lossy().into_owned());
    }
    out.truncate(written);

    stamp_dict_id(&mut out);
    Ok(out)
}

fn stamp_dict_id(dict: &mut [u8]) -> u32 {
    assert_eq!(
        u32::from_le_bytes(dict[0..4].try_into().unwrap()),
        DICT_MAGIC,
        "trainer did not produce a zstd dictionary"
    );

    let mut probe = dict.to_vec();
    probe[4..8].fill(0);
    let id = DICT_ID_FLOOR
        + (xxhash_rust::xxh3::xxh3_64(&probe) as u32 % (DICT_ID_CEILING - DICT_ID_FLOOR));
    dict[4..8].copy_from_slice(&id.to_le_bytes());

    assert_eq!(
        get_dict_id_from_dict(dict).map(|id| id.get()),
        Some(id),
        "dictionary identifier did not survive stamping"
    );
    id
}

pub struct Score {
    pub raw: usize,
    pub stored: usize,
    pub typical_raw: usize,
    pub typical_stored: usize,
    pub compressed_values: usize,
    pub samples: usize,
}

impl Score {
    pub fn ratio(&self) -> f64 {
        100.0 * self.stored as f64 / self.raw.max(1) as f64
    }

    pub fn typical_ratio(&self) -> f64 {
        100.0 * self.typical_stored as f64 / self.typical_raw.max(1) as f64
    }

    pub fn mean_stored(&self) -> usize {
        self.stored / self.samples.max(1)
    }
}

fn new_compressor<'a>(dictionary: Option<&'a EncoderDictionary<'a>>) -> Compressor<'a> {
    let mut compressor = match dictionary {
        Some(dictionary) => Compressor::with_prepared_dictionary(dictionary).unwrap(),
        None => Compressor::new(COMPRESSION_LEVEL).unwrap(),
    };
    compressor
        .set_parameter(CParameter::ChecksumFlag(true))
        .unwrap();
    compressor
        .set_parameter(CParameter::ContentSizeFlag(true))
        .unwrap();
    compressor
}

pub fn evaluate(dict: Option<&[u8]>, dev: &[Vec<u8>], typical: usize) -> Score {
    let prepared = dict.map(|dict| EncoderDictionary::copy(dict, COMPRESSION_LEVEL));
    let mut compressor = new_compressor(prepared.as_ref());
    let watermark = if dict.is_some() {
        COMPRESS_WATERMARK_DICTIONARY
    } else {
        COMPRESS_WATERMARK
    };

    let mut score = Score {
        raw: 0,
        stored: 0,
        typical_raw: 0,
        typical_stored: 0,
        compressed_values: 0,
        samples: dev.len(),
    };
    let mut output = Vec::new();
    for sample in dev {
        score.raw += sample.len();
        let stored = if sample.len() < watermark {
            sample.len() + ARCHIVE_HASH_LEN
        } else {
            output.clear();
            output.reserve(compress_bound(sample.len()));
            let len = compressor.compress_to_buffer(sample, &mut output).unwrap();
            if len < sample.len() {
                score.compressed_values += 1;
                len
            } else {
                sample.len() + ARCHIVE_HASH_LEN
            }
        };
        score.stored += stored;
        if sample.len() <= typical {
            score.typical_raw += sample.len();
            score.typical_stored += stored;
        }
    }
    score
}

pub fn verify(dict: &[u8], dev: &[Vec<u8>]) -> Result<u32, String> {
    let id = get_dict_id_from_dict(dict)
        .ok_or_else(|| "dictionary carries no identifier".to_string())?
        .get();
    let encoder = EncoderDictionary::copy(dict, COMPRESSION_LEVEL);
    let decoder = DecoderDictionary::copy(dict);
    let mut compressor = new_compressor(Some(&encoder));
    let mut decompressor = Decompressor::with_prepared_dictionary(&decoder)
        .map_err(|err| format!("decompressor: {err}"))?;

    let mut output = Vec::new();
    for (index, sample) in dev.iter().enumerate() {
        if sample.is_empty() {
            continue;
        }
        output.clear();
        output.reserve(compress_bound(sample.len()));
        compressor
            .compress_to_buffer(sample, &mut output)
            .map_err(|err| format!("sample {index}: {err}"))?;
        match get_dict_id_from_frame(&output).map(|id| id.get()) {
            Some(frame_id) if frame_id == id => {}
            other => return Err(format!("sample {index}: frame names dictionary {other:?}")),
        }
        let back = decompressor
            .decompress(&output, sample.len())
            .map_err(|err| format!("sample {index}: {err}"))?;
        if back != *sample {
            return Err(format!("sample {index}: round trip mismatch"));
        }
    }
    Ok(id)
}

pub struct Candidate {
    pub size: usize,
    pub dict: Vec<u8>,
    pub score: Score,
}

pub fn sweep(
    split: &Split,
    sizes: &[usize],
    typical: usize,
    fraction: usize,
) -> (Vec<Candidate>, usize) {
    let keep = (split.train.len() * fraction / 100).max(1);
    let samples = Samples::new(&split.train[..keep.min(split.train.len())]);
    let mut candidates = Vec::new();
    for &size in sizes {
        match train(&samples, size) {
            Ok(dict) => {
                let score = evaluate(Some(&dict), &split.dev, typical);
                candidates.push(Candidate { size, dict, score });
            }
            Err(err) => {
                eprintln!("  {size:>7} bytes: training failed ({err})");
            }
        }
    }

    let best = candidates
        .iter()
        .map(|candidate| candidate.score.typical_ratio())
        .fold(f64::INFINITY, f64::min);
    let knee = candidates
        .iter()
        .position(|candidate| candidate.score.typical_ratio() <= best + KNEE_TOLERANCE)
        .unwrap_or(0);
    (candidates, knee)
}
