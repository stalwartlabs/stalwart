/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::{
    feature::{CcfhFeature, CcfhFeatureBuilder, FhFeature, FhFeatureBuilder},
    sigmoid,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct Score {
    z: f32,
    squares: f64,
}

impl Score {
    pub fn combine(self, other: Score) -> Score {
        Score {
            z: self.z + other.z,
            squares: self.squares + other.squares,
        }
    }

    fn scaled(self, l2_normalize: bool) -> f32 {
        if l2_normalize && self.squares > 0.0 {
            self.z / self.squares.sqrt() as f32
        } else {
            self.z
        }
    }
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default)]
pub struct FhClassifier {
    pub(crate) parameters: Vec<f32>,
    pub(crate) bias: f32,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default)]
pub struct CcfhClassifier {
    pub(crate) parameters: Vec<f32>,
    pub(crate) indicators: Vec<f32>,
    pub(crate) bias: f32,
}

impl FhClassifier {
    pub fn predict_proba_sample(&self, features: &[FhFeature]) -> f32 {
        let mut z: f32 = 0.0;

        for f in features {
            z += self.parameters[f.idx] * f.weight;
        }

        sigmoid(z + self.bias)
    }

    pub fn score(&self, features: &[FhFeature]) -> Score {
        let mut score = Score::default();
        for f in features {
            score.z += self.parameters[f.idx] * f.weight;
            score.squares += f64::from(f.weight) * f64::from(f.weight);
        }
        score
    }

    pub fn predict_proba_score(&self, score: Score, l2_normalize: bool) -> f32 {
        sigmoid(score.scaled(l2_normalize) + self.bias)
    }

    pub fn predict(&self, features: &[FhFeature]) -> f32 {
        if self.predict_proba_sample(features) > 0.7 {
            1.0
        } else {
            0.0
        }
    }

    pub fn predict_batch<I>(&self, test: I) -> Vec<f32>
    where
        I: IntoIterator,
        I::Item: AsRef<Vec<FhFeature>>,
    {
        test.into_iter()
            .map(|features| self.predict(features.as_ref()))
            .collect()
    }

    pub fn feature_builder(&self) -> FhFeatureBuilder {
        FhFeatureBuilder {
            weight_mask: (self.parameters.len() - 1) as u64,
        }
    }

    pub fn parameters(&self) -> &[f32] {
        &self.parameters
    }

    pub fn bias(&self) -> f32 {
        self.bias
    }
}

impl CcfhClassifier {
    pub fn predict_proba_sample(&self, features: &[CcfhFeature]) -> f32 {
        let mut z: f32 = 0.0;
        for f in features {
            let q = self.indicators[f.idx_i];
            let v1 = self.parameters[f.idx_w1];
            let v2 = self.parameters[f.idx_w2];
            z += (q * v1 + (1.0 - q) * v2) * f.weight;
        }
        sigmoid(z + self.bias)
    }

    pub fn score(&self, features: &[CcfhFeature]) -> Score {
        let mut score = Score::default();
        for f in features {
            let q = self.indicators[f.idx_i];
            let v1 = self.parameters[f.idx_w1];
            let v2 = self.parameters[f.idx_w2];
            score.z += (q * v1 + (1.0 - q) * v2) * f.weight;
            score.squares += f64::from(f.weight) * f64::from(f.weight);
        }
        score
    }

    pub fn predict_proba_score(&self, score: Score, l2_normalize: bool) -> f32 {
        sigmoid(score.scaled(l2_normalize) + self.bias)
    }

    pub fn predict(&self, features: &[CcfhFeature]) -> f32 {
        if self.predict_proba_sample(features) >= 0.5 {
            1.0
        } else {
            0.0
        }
    }

    pub fn predict_batch<I>(&self, test: I) -> Vec<f32>
    where
        I: IntoIterator,
        I::Item: AsRef<Vec<CcfhFeature>>,
    {
        test.into_iter()
            .map(|features| self.predict(features.as_ref()))
            .collect()
    }

    pub fn feature_builder(&self) -> CcfhFeatureBuilder {
        CcfhFeatureBuilder {
            weight_mask: (self.parameters.len() - 1) as u64,
            indicator_mask: (self.indicators.len() - 1) as u64,
        }
    }

    pub fn is_active(&self) -> bool {
        !self.parameters.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{CcfhClassifier, FhClassifier};
    use crate::classifier::feature::{FeatureBuilder, UnprocessedFeature};
    use std::collections::HashMap;

    #[derive(PartialEq, Eq, Hash)]
    struct Word(String);

    impl UnprocessedFeature for Word {
        fn prefix(&self) -> u16 {
            7
        }

        fn value(&self) -> &[u8] {
            self.0.as_bytes()
        }
    }

    #[test]
    fn split_scores_match_full_build() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let fh = FhClassifier {
            parameters: (0..1 << 12)
                .map(|_| (next() % 2000) as f32 / 1000.0 - 1.0)
                .collect(),
            bias: 0.25,
        };
        let ccfh = CcfhClassifier {
            parameters: (0..1 << 12)
                .map(|_| (next() % 2000) as f32 / 1000.0 - 1.0)
                .collect(),
            indicators: (0..1 << 10)
                .map(|_| (next() % 1000) as f32 / 1000.0)
                .collect(),
            bias: -0.5,
        };
        let fh_builder = fh.feature_builder();
        let ccfh_builder = ccfh.feature_builder();
        let mut base = Vec::new();
        let mut account = Vec::new();
        let mut ccfh_base = Vec::new();
        let mut ccfh_account = Vec::new();

        for round in 0..200 {
            let features: HashMap<Word, f32> = (0..(next() % 300))
                .map(|_| (Word(format!("w{}", next() % 500)), (next() % 7 + 1) as f32))
                .collect();
            let account_id = (round % 3 != 0).then_some(round as u32 * 7919);
            for l2_normalize in [false, true] {
                let score = if let Some(account_id) = account_id {
                    fh_builder.build_part(&features, Some(account_id), &mut account);
                    let split = fh.score(&account);
                    fh_builder.build_base_and_account(
                        &features,
                        account_id,
                        &mut base,
                        &mut account,
                    );
                    assert_eq!(split.z, fh.score(&account).z);
                    fh.score(&base).combine(split)
                } else {
                    fh_builder.build_part(&features, None, &mut base);
                    fh.score(&base)
                };
                let expected =
                    fh.predict_proba_sample(&fh_builder.build(&features, account_id, l2_normalize));
                let actual = fh.predict_proba_score(score, l2_normalize);
                assert!((expected - actual).abs() < 1e-5, "{expected} {actual}");

                ccfh_builder.build_part(&features, None, &mut ccfh_base);
                let mut score = ccfh.score(&ccfh_base);
                if let Some(account_id) = account_id {
                    ccfh_builder.build_part(&features, Some(account_id), &mut ccfh_account);
                    score = score.combine(ccfh.score(&ccfh_account));
                }
                let expected = ccfh.predict_proba_sample(&ccfh_builder.build(
                    &features,
                    account_id,
                    l2_normalize,
                ));
                let actual = ccfh.predict_proba_score(score, l2_normalize);
                assert!((expected - actual).abs() < 1e-5, "{expected} {actual}");
            }
        }
    }
}
