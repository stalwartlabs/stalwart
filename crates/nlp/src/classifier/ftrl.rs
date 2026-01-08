/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::{Optimizer, model::FhClassifier};

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug)]
pub struct Ftrl {
    alpha: f64,
    beta: f64,
    l1_ratio: f64,
    l2_ratio: f64,
    zn: Vec<Zn>,
    zn_bias: Zn,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Clone, Copy, Debug, Default)]
pub struct Zn {
    z: f32,
    n: f64,
}

impl Ftrl {
    pub fn new(n_features: usize) -> Self {
        Ftrl {
            alpha: 2.0,
            beta: 1.0,
            l1_ratio: 0.001,
            l2_ratio: 0.0001,
            zn: vec![Zn::default(); n_features],
            zn_bias: Zn::default(),
        }
    }

    pub fn with_hyperparams(mut self, alpha: f64, beta: f64, l1_ratio: f64, l2_ratio: f64) -> Self {
        self.alpha = alpha;
        self.beta = beta;
        self.l1_ratio = l1_ratio;
        self.l2_ratio = l2_ratio;
        self
    }

    pub fn set_hyperparams(&mut self, alpha: f64, beta: f64, l1_ratio: f64, l2_ratio: f64) {
        self.alpha = alpha;
        self.beta = beta;
        self.l1_ratio = l1_ratio;
        self.l2_ratio = l2_ratio;
    }

    pub fn with_initial_weights(self, value: f32) -> Self {
        Ftrl {
            zn: vec![Zn { z: value, n: 0.0 }; self.zn.len()],
            ..self
        }
    }
}

impl Optimizer for Ftrl {
    #[inline(always)]
    fn update_param(&mut self, idx: usize, grad: f32) {
        let zn = &mut self.zn[idx];
        let current_w = if zn.z.abs() as f64 <= self.l1_ratio {
            0.0
        } else {
            -(zn.z - zn.z.signum() * self.l1_ratio as f32)
                / (self.l2_ratio + (self.beta + zn.n.sqrt()) / self.alpha) as f32
        };
        let grad = grad as f64;
        let grad_sq = grad * grad;
        let sigma = ((zn.n + grad_sq).sqrt() - zn.n.sqrt()) / self.alpha;
        zn.z += (grad - sigma * current_w as f64) as f32;
        zn.n += grad_sq;
    }

    #[inline(always)]
    fn update_bias(&mut self, grad: f32) {
        let current_bias = -self.zn_bias.z
            / ((self.zn_bias.n.sqrt() + self.beta) / self.alpha + self.l2_ratio) as f32;
        let grad = grad as f64;
        let grad_sq = grad * grad;
        let sigma = ((self.zn_bias.n + grad_sq).sqrt() - self.zn_bias.n.sqrt()) / self.alpha;
        self.zn_bias.z += (grad - sigma * current_bias as f64) as f32;
        self.zn_bias.n += grad_sq;
    }

    #[inline(always)]
    fn get_param(&self, idx: usize) -> f32 {
        let zn = self.zn[idx];
        if zn.z.abs() as f64 <= self.l1_ratio {
            0.0
        } else {
            -(zn.z - zn.z.signum() * self.l1_ratio as f32)
                / (self.l2_ratio + (self.beta + zn.n.sqrt()) / self.alpha) as f32
        }
    }

    #[inline(always)]
    fn get_bias(&self) -> f32 {
        -self.zn_bias.z / ((self.zn_bias.n.sqrt() + self.beta) / self.alpha + self.l2_ratio) as f32
    }

    fn step(&mut self) {}

    #[inline(always)]
    fn get_param_mut(&mut self, idx: usize) -> &mut f32 {
        &mut self.zn[idx].z
    }

    fn build_classifier(&self) -> FhClassifier {
        FhClassifier {
            parameters: self
                .zn
                .iter()
                .map(|zn| {
                    if zn.z.abs() as f64 <= self.l1_ratio {
                        0.0
                    } else {
                        -(zn.z - zn.z.signum() * self.l1_ratio as f32)
                            / (self.l2_ratio + (self.beta + zn.n.sqrt()) / self.alpha) as f32
                    }
                })
                .collect(),
            bias: self.get_bias(),
        }
    }

    fn num_parameters(&self) -> usize {
        self.zn.len()
    }
}
