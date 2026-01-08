/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;
use xxhash_rust::xxh3::xxh3_64_with_seed;

#[derive(Debug)]
pub struct Sample<T> {
    pub features: Vec<T>,
    pub class: f32,
}

pub struct FhFeatureBuilder {
    pub(super) weight_mask: u64,
}

#[derive(Debug)]
pub struct FhFeature {
    pub idx: usize,
    pub weight: f32,
}

#[derive(Debug)]
pub struct CcfhFeature {
    pub idx_w1: usize,
    pub idx_w2: usize,
    pub idx_i: usize,
    pub weight: f32,
}

pub struct CcfhFeatureBuilder {
    pub(super) weight_mask: u64,
    pub(super) indicator_mask: u64,
}

pub trait FeatureWeight {
    fn idx(&self) -> usize;
    fn weight(&self) -> f32;
    fn weight_mut(&mut self) -> &mut f32;
}

pub trait UnprocessedFeature {
    fn prefix(&self) -> u16;
    fn value(&self) -> &[u8];
}

impl FeatureWeight for FhFeature {
    fn weight(&self) -> f32 {
        self.weight
    }

    fn weight_mut(&mut self) -> &mut f32 {
        &mut self.weight
    }

    fn idx(&self) -> usize {
        self.idx
    }
}

impl FeatureWeight for CcfhFeature {
    fn weight(&self) -> f32 {
        self.weight
    }

    fn weight_mut(&mut self) -> &mut f32 {
        &mut self.weight
    }

    fn idx(&self) -> usize {
        self.idx_w1
    }
}

impl FeatureBuilder for FhFeatureBuilder {
    type Feature = FhFeature;

    fn build_feature(&self, bytes: &[u8], weight: f32) -> FhFeature {
        let hash1 = xxh3_64_with_seed(bytes, 0);
        let sign = if hash1 & (1 << 63) == 0 { 1.0 } else { -1.0 };

        FhFeature {
            idx: (hash1 & self.weight_mask) as usize,
            weight: sign * weight,
        }
    }
}

impl FeatureBuilder for CcfhFeatureBuilder {
    type Feature = CcfhFeature;

    fn build_feature(&self, bytes: &[u8], weight: f32) -> CcfhFeature {
        let hash1 = xxh3_64_with_seed(bytes, 0);
        let hash2 = xxh3_64_with_seed(bytes, 0x9E3779B97F4A7C15);
        let hash3 = xxh3_64_with_seed(bytes, 0x517CC1B727220A95);
        let sign = if hash3 & (1 << 63) == 0 { 1.0 } else { -1.0 };

        CcfhFeature {
            idx_w1: (hash1 & self.weight_mask) as usize,
            idx_w2: (hash2 & self.weight_mask) as usize,
            idx_i: (hash3 & self.indicator_mask) as usize,
            weight: sign * weight,
        }
    }
}

pub trait FeatureBuilder {
    // Feature type associated type
    type Feature: FeatureWeight;

    fn build_feature(&self, bytes: &[u8], weight: f32) -> Self::Feature;

    fn scale<I: UnprocessedFeature>(&self, features: &mut HashMap<I, f32>) {
        // Log frequency scaling
        for x in features.values_mut() {
            *x = x.ln_1p();
        }
    }

    fn build<I: UnprocessedFeature>(
        &self,
        features_in: &HashMap<I, f32>,
        account_id: Option<u32>,
        l2_normalize: bool,
    ) -> Vec<Self::Feature> {
        let mut features_out = Vec::with_capacity(features_in.len());
        let mut buf = Vec::with_capacity(2 + 4 + 63);
        for (feature, count) in features_in {
            buf.extend_from_slice(&feature.prefix().to_be_bytes());
            buf.extend_from_slice(feature.value());
            features_out.push(self.build_feature(&buf, *count));

            if let Some(account_id) = account_id {
                buf.extend_from_slice(&account_id.to_be_bytes());
                features_out.push(self.build_feature(&buf, *count));
            }

            buf.clear();
        }

        // L2 normalization
        if l2_normalize {
            let sum_of_squares = features_out
                .iter()
                .map(|f| f.weight() as f64 * f.weight() as f64)
                .sum::<f64>();
            if sum_of_squares > 0.0 {
                let norm = sum_of_squares.sqrt() as f32;
                for feature in &mut features_out {
                    *feature.weight_mut() /= norm;
                }
            }
        }

        features_out
    }
}

impl<T> Sample<T> {
    pub fn new(features: Vec<T>, class: bool) -> Self {
        Self {
            features,
            class: if class { 1.0 } else { 0.0 },
        }
    }
}

impl<T> AsRef<Sample<T>> for Sample<T> {
    fn as_ref(&self) -> &Sample<T> {
        self
    }
}
