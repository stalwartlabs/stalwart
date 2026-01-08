/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::{Optimizer, model::FhClassifier};

pub struct Adam {
    parameters: Vec<f32>,
    bias: f32,
    learning_rate: f32,
    beta1: f32,
    beta2: f32,
    epsilon: f32,
    t: f32,
    m0: Vec<f32>,
    v0: Vec<f32>,
    m_bias: f32,
    v_bias: f32,

    // Step info
    bias2_sqrt: f32,
    alpha_t: f32,
}

impl Adam {
    pub fn new(n_parameters: usize, learning_rate: f32) -> Self {
        Adam {
            parameters: vec![0.0; n_parameters],
            learning_rate,
            beta1: 0.9,
            beta2: 0.999,
            epsilon: 1e-8,
            t: 0.0,
            m0: vec![0.0; n_parameters],
            v0: vec![0.0; n_parameters],
            m_bias: 0.0,
            v_bias: 0.0,
            bias: 0.0,
            bias2_sqrt: 0.0,
            alpha_t: 0.0,
        }
    }

    pub fn with_hyperparams(mut self, beta1: f32, beta2: f32, epsilon: f32) -> Self {
        self.beta1 = beta1;
        self.beta2 = beta2;
        self.epsilon = epsilon;
        self
    }

    pub fn with_initial_weights(self, value: f32) -> Self {
        Adam {
            parameters: vec![value; self.parameters.len()],
            ..self
        }
    }
}

impl Optimizer for Adam {
    #[inline(always)]
    fn step(&mut self) {
        self.t += 1.0;
        let bias1 = 1.0 - self.beta1.powf(self.t);
        self.bias2_sqrt = (1.0 - self.beta2.powf(self.t)).sqrt();
        self.alpha_t = self.learning_rate / bias1;
    }

    #[inline(always)]
    fn update_param(&mut self, i: usize, g: f32) {
        self.m0[i] = self.beta1 * self.m0[i] + (1.0 - self.beta1) * g;
        self.v0[i] = self.beta2 * self.v0[i] + (1.0 - self.beta2) * g * g;
        self.parameters[i] -=
            self.alpha_t * self.m0[i] / (self.v0[i].sqrt() / self.bias2_sqrt + self.epsilon);
    }

    #[inline(always)]
    fn update_bias(&mut self, g: f32) {
        self.m_bias = self.beta1 * self.m_bias + (1.0 - self.beta1) * g;
        self.v_bias = self.beta2 * self.v_bias + (1.0 - self.beta2) * g * g;
        self.bias -=
            self.alpha_t * self.m_bias / (self.v_bias.sqrt() / self.bias2_sqrt + self.epsilon);
    }

    #[inline(always)]
    fn get_param(&self, idx: usize) -> f32 {
        self.parameters[idx]
    }

    #[inline(always)]
    fn get_bias(&self) -> f32 {
        self.bias
    }

    #[inline(always)]
    fn get_param_mut(&mut self, idx: usize) -> &mut f32 {
        &mut self.parameters[idx]
    }

    fn build_classifier(&self) -> FhClassifier {
        FhClassifier {
            parameters: self.parameters.clone(),
            bias: self.bias,
        }
    }

    fn num_parameters(&self) -> usize {
        self.parameters.len()
    }
}
