/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::model::FhClassifier;

pub mod adam;
pub mod feature;
pub mod ftrl;
pub mod model;
pub mod reservoir;
pub mod sgd;
pub mod train;

const MAX_DLOSS: f32 = 1e4;

pub trait Optimizer {
    fn step(&mut self);
    fn update_param(&mut self, i: usize, g: f32);
    fn update_bias(&mut self, g: f32);
    fn get_param(&self, idx: usize) -> f32;
    fn get_param_mut(&mut self, idx: usize) -> &mut f32;
    fn get_bias(&self) -> f32;
    fn build_classifier(&self) -> FhClassifier;
    fn num_parameters(&self) -> usize;
}

#[inline(always)]
fn sigmoid(z: f32) -> f32 {
    let z = z.clamp(-35.0, 35.0);
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let exp_z = z.exp();
        exp_z / (1.0 + exp_z)
    }
}

#[inline(always)]
fn gradient(y: f32, p: f32) -> f32 {
    if p > -16.0 {
        let exp_tmp = (-p).exp();
        ((1.0 - y) - y * exp_tmp) / (1.0 + exp_tmp)
    } else {
        p.exp() - y
    }
}
