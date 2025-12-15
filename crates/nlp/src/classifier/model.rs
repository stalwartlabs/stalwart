/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::{
    feature::{CcfhFeature, CcfhFeatureBuilder, FhFeature, FhFeatureBuilder},
    sigmoid,
};

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
