/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::{
    MAX_DLOSS, Optimizer,
    feature::{CcfhFeature, CcfhFeatureBuilder, FhFeature, FhFeatureBuilder, Sample},
    gradient,
    model::{CcfhClassifier, FhClassifier},
};
use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default)]
pub struct FhTrainer<T: Optimizer> {
    pub optimizer: T,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default)]
pub struct CcfhTrainer<W: Optimizer, I: Optimizer> {
    pub w_optimizer: W,
    pub i_optimizer: I,
}

impl<T: Optimizer> FhTrainer<T> {
    pub fn new(optimizer: T) -> Self {
        FhTrainer { optimizer }
    }

    pub fn fit(&mut self, samples: &mut [impl AsRef<Sample<FhFeature>>], num_epochs: usize) {
        for _ in 0..num_epochs {
            samples.shuffle(&mut StdRng::seed_from_u64(42));

            for sample in samples.iter() {
                let sample = sample.as_ref();
                let mut dot: f32 = 0.0;
                for f in &sample.features {
                    dot += self.optimizer.get_param(f.idx) * f.weight;
                }
                let p = dot + self.optimizer.get_bias();
                let dloss = gradient(sample.class, p).clamp(-MAX_DLOSS, MAX_DLOSS);

                self.optimizer.step();

                for f in &sample.features {
                    self.optimizer.update_param(f.idx, dloss * f.weight);
                }

                self.optimizer.update_bias(dloss);
            }
        }
    }

    pub fn feature_builder(&self) -> FhFeatureBuilder {
        FhFeatureBuilder {
            weight_mask: (self.optimizer.num_parameters() - 1) as u64,
        }
    }

    pub fn build_classifier(&self) -> FhClassifier {
        self.optimizer.build_classifier()
    }

    pub fn optimizer(&self) -> &T {
        &self.optimizer
    }

    pub fn optimizer_mut(&mut self) -> &mut T {
        &mut self.optimizer
    }
}

impl<W: Optimizer, I: Optimizer> CcfhTrainer<W, I> {
    pub fn new(w_optimizer: W, i_optimizer: I) -> Self {
        CcfhTrainer {
            w_optimizer,
            i_optimizer,
        }
    }

    pub fn fit(&mut self, samples: &mut [impl AsRef<Sample<CcfhFeature>>], num_epochs: usize) {
        for _ in 0..num_epochs {
            samples.shuffle(&mut StdRng::seed_from_u64(42));

            for sample in samples.iter() {
                let sample = sample.as_ref();
                let mut dot: f32 = 0.0;
                for f in &sample.features {
                    let q = self.i_optimizer.get_param(f.idx_i);
                    let v1 = self.w_optimizer.get_param(f.idx_w1);
                    let v2 = self.w_optimizer.get_param(f.idx_w2);
                    dot += (q * v1 + (1.0 - q) * v2) * f.weight;
                }
                let p = dot + self.w_optimizer.get_bias();
                let dloss = gradient(sample.class, p).clamp(-MAX_DLOSS, MAX_DLOSS);

                self.w_optimizer.step();
                self.i_optimizer.step();

                for f in &sample.features {
                    let q = self.i_optimizer.get_param(f.idx_i);
                    let v1 = self.w_optimizer.get_param(f.idx_w1);
                    let v2 = self.w_optimizer.get_param(f.idx_w2);

                    // Update weights
                    let d_v1 = f.weight * q;
                    let d_v2 = f.weight * (1.0 - q);
                    self.w_optimizer.update_param(f.idx_w1, dloss * d_v1);
                    self.w_optimizer.update_param(f.idx_w2, dloss * d_v2);

                    // Update indicator
                    let d_q = (v1 - v2) * f.weight;
                    self.i_optimizer.update_param(f.idx_i, dloss * d_q);
                    let fi = self.i_optimizer.get_param_mut(f.idx_i);
                    *fi = fi.clamp(0.0, 1.0);
                }

                self.w_optimizer.update_bias(dloss);
            }
        }
    }

    pub fn feature_builder(&self) -> CcfhFeatureBuilder {
        CcfhFeatureBuilder {
            weight_mask: (self.w_optimizer.num_parameters() - 1) as u64,
            indicator_mask: (self.i_optimizer.num_parameters() - 1) as u64,
        }
    }

    pub fn build_classifier(&self) -> CcfhClassifier {
        let w_classifier = self.w_optimizer.build_classifier();
        let i_classifier = self.i_optimizer.build_classifier();

        CcfhClassifier {
            parameters: w_classifier.parameters,
            indicators: i_classifier.parameters,
            bias: w_classifier.bias,
        }
    }

    pub fn w_optimizer(&self) -> &W {
        &self.w_optimizer
    }

    pub fn w_optimizer_mut(&mut self) -> &mut W {
        &mut self.w_optimizer
    }

    pub fn i_optimizer(&self) -> &I {
        &self.i_optimizer
    }

    pub fn i_optimizer_mut(&mut self) -> &mut I {
        &mut self.i_optimizer
    }
}
