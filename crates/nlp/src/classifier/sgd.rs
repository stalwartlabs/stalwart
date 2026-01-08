/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::classifier::{Optimizer, gradient, model::FhClassifier};

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default)]
pub struct Sgd {
    parameters: Vec<f32>,
    bias: f32,
    alpha: f64,
    l1_ratio: f64,
    l2_ratio: f64,
    t: f64,
    w_scale: f32,
    optimal_init: f64,
    eta: f32,
    u: f32,
    q: Vec<f32>,
}

impl Sgd {
    pub fn new(n_features: usize, alpha: f64, l1_ratio: f64, l2_ratio: f64) -> Self {
        let typw = (1.0 / alpha.sqrt()).sqrt();
        let initial_eta0 = typw / 1.0_f64.max(gradient(1.0, -typw as f32) as f64);
        let optimal_init = 1.0 / (initial_eta0 * alpha);

        Sgd {
            parameters: vec![0.0; n_features],
            bias: 0.0,
            alpha,
            l1_ratio,
            l2_ratio,
            t: 0.0,
            w_scale: 1.0,
            optimal_init,
            eta: initial_eta0 as f32,
            u: 0.0,
            q: vec![0.0; n_features],
        }
    }

    pub fn with_initial_parameters(self, value: f32) -> Self {
        Sgd {
            parameters: vec![value; self.parameters.len()],
            ..self
        }
    }

    fn maybe_rescale(&mut self) {
        if !(1e-6..=1e6).contains(&self.w_scale) {
            for w in &mut self.parameters {
                *w *= self.w_scale;
            }
            self.w_scale = 1.0;
        }
    }

    #[inline(always)]
    fn apply_l1_penalty(&mut self) {
        if self.l1_ratio > 0.0 {
            for (z, q) in self.parameters.iter_mut().zip(self.q.iter_mut()) {
                let z_orig = *z;
                let scaled_z = *z * self.w_scale;
                if scaled_z > 0.0 {
                    *z = (*z - (self.u + *q) / self.w_scale).max(0.0);
                } else if scaled_z < 0.0 {
                    *z = (*z + (self.u - *q) / self.w_scale).min(0.0);
                }
                *q += self.w_scale * (z_orig - *z);
            }
        }
    }
}

impl Optimizer for Sgd {
    fn step(&mut self) {
        self.t += 1.0;
        self.eta = (1.0 / ((self.alpha) * (self.optimal_init + self.t - 1.0))) as f32;
        self.w_scale *= 1.0 - ((1.0 - self.l1_ratio) as f32 * self.eta * self.l2_ratio as f32);
        self.u += self.eta * self.l1_ratio as f32 * self.alpha as f32;
    }

    fn update_param(&mut self, i: usize, g: f32) {
        self.parameters[i] += (-self.eta * g) / self.w_scale;
    }

    fn update_bias(&mut self, g: f32) {
        self.bias += -self.eta * g;
        self.maybe_rescale();
        self.apply_l1_penalty();
    }

    #[inline(always)]
    fn get_param(&self, idx: usize) -> f32 {
        self.parameters[idx] * self.w_scale
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
            parameters: self.parameters.iter().map(|w| w * self.w_scale).collect(),
            bias: self.bias,
        }
    }

    fn num_parameters(&self) -> usize {
        self.parameters.len()
    }
}

#[cfg(test)]
pub mod tests {
    use rand::{SeedableRng, rngs::StdRng, seq::SliceRandom};
    use std::{
        collections::HashMap,
        fs::File,
        io::{BufRead, BufReader},
        time::Instant,
    };

    use crate::classifier::{
        Optimizer,
        adam::Adam,
        feature::{
            CcfhFeature, CcfhFeatureBuilder, FeatureBuilder, FhFeature, FhFeatureBuilder, Sample,
            UnprocessedFeature,
        },
        ftrl::Ftrl,
        train::{CcfhTrainer, FhTrainer},
    };

    #[test]
    fn text_classifier() {
        let reader = BufReader::new(
            File::open("/Users/me/code/playground/phishing_email.csv")
                .expect("Could not open file"),
        );
        let mut samples = Vec::with_capacity(1024);

        let time = Instant::now();

        for line in reader.lines().skip(1) {
            let line = line.unwrap();
            let (text, class) = line.trim().rsplit_once(',').unwrap();
            //let (class, text) = line.trim().split_once(',').unwrap();
            let text = text.trim_start_matches('"').trim_end_matches('"');

            samples.push((text.to_string(), class == "1"));
        }

        println!("Loaded {} samples in {:?}", samples.len(), time.elapsed());

        samples.shuffle(&mut StdRng::seed_from_u64(42));

        let (train_samples, test_samples) = train_test_split(&samples, 0.2);

        println!(
            "Training samples: {}, Testing samples: {}",
            train_samples.len(),
            test_samples.len()
        );

        const FH_SIZE: usize = 16;
        const CCFH_SIZE: usize = FH_SIZE - 2;
        let mut rng = StdRng::seed_from_u64(42);

        let fh_builder = FhFeatureBuilder {
            weight_mask: (1 << FH_SIZE) - 1,
        };
        let mut fh_train_samples = build_fh_samples(train_samples.as_slice(), &fh_builder);
        fh_train_samples.shuffle(&mut rng);
        let fh_test_samples = build_fh_samples(test_samples.as_slice(), &fh_builder);
        let ccfh_builder = CcfhFeatureBuilder {
            weight_mask: (1 << FH_SIZE) - 1,
            indicator_mask: (1 << CCFH_SIZE) - 1,
        };
        let mut ccfh_train_samples = build_ccfh_samples(train_samples.as_slice(), &ccfh_builder);
        ccfh_train_samples.shuffle(&mut rng);
        let ccfh_test_samples = build_ccfh_samples(test_samples.as_slice(), &ccfh_builder);

        fh_model_stats(
            "FTRL",
            FhTrainer::new(Ftrl::new(1 << FH_SIZE)),
            &fh_train_samples,
            &fh_test_samples,
        );

        ccfh_model_stats(
            "FTRL + FTRL",
            CcfhTrainer::new(
                Ftrl::new(1 << FH_SIZE),
                Ftrl::new(1 << CCFH_SIZE).with_initial_weights(0.5),
            ),
            &ccfh_train_samples,
            &ccfh_test_samples,
        );

        fh_model_stats(
            "Adam",
            FhTrainer::new(Adam::new(1 << FH_SIZE, 0.01)),
            &fh_train_samples,
            &fh_test_samples,
        );

        ccfh_model_stats(
            "Adam + Adam",
            CcfhTrainer::new(
                Adam::new(1 << FH_SIZE, 0.01),
                Adam::new(1 << CCFH_SIZE, 0.01).with_initial_weights(0.5),
            ),
            &ccfh_train_samples,
            &ccfh_test_samples,
        );

        /*fh_model_stats(
            "SGD",
            FhTrainer::new(Sgd::new(1 << FH_SIZE, 0.0001, 0.0, 0.0001)),
            &fh_train_samples,
            &fh_test_samples,
        );

        ccfh_model_stats(
            "FTRL + SGD",
            CcfhTrainer::new(
                Ftrl::new(1 << FH_SIZE),
                Sgd::new(1 << CCFH_SIZE, 0.0001, 0.0, 0.0001).with_initial_parameters(0.5),
            ),
            &ccfh_train_samples,
            &ccfh_test_samples,
        );*/
    }

    fn fh_model_stats(
        name: &str,
        mut model: FhTrainer<impl Optimizer>,
        train_samples: &[Sample<FhFeature>],
        test_samples: &[Sample<FhFeature>],
    ) {
        print!("⏳ Training {}... ", name);
        let time = Instant::now();
        let mut batch = Vec::new();
        for sample in train_samples {
            batch.push(sample);
            if batch.len() == 128 {
                model.fit(&mut batch, 5);
                batch.clear();
            }
        }
        if !batch.is_empty() {
            model.fit(&mut batch, 5);
        }
        println!(" trained in {:?}", time.elapsed());
        let y_pred = model
            .build_classifier()
            .predict_batch(test_samples.iter().map(|s| &s.features));
        let y_train: Vec<f32> = test_samples.iter().map(|s| s.class).collect();
        println!("Accuracy: {:.4}", accuracy_score(&y_train, &y_pred));
        println!("Precision: {:.4}", precision_score(&y_train, &y_pred, 1.0));
        println!("Recall: {:.4}", recall_score(&y_train, &y_pred, 1.0));
        println!("F1 Score: {:.4}", f1_score(&y_train, &y_pred, 1.0));
    }

    fn ccfh_model_stats(
        name: &str,
        mut model: CcfhTrainer<impl Optimizer, impl Optimizer>,
        train_samples: &[Sample<CcfhFeature>],
        test_samples: &[Sample<CcfhFeature>],
    ) {
        print!("⏳ Training {}... ", name);
        let time = Instant::now();
        let mut batch = Vec::new();
        for sample in train_samples {
            batch.push(sample);
            if batch.len() == 128 {
                model.fit(&mut batch, 5);
                batch.clear();
            }
        }
        if !batch.is_empty() {
            model.fit(&mut batch, 5);
        }
        println!(" trained in {:?}", time.elapsed());
        let y_pred = model
            .build_classifier()
            .predict_batch(test_samples.iter().map(|s| &s.features));
        let y_train: Vec<f32> = test_samples.iter().map(|s| s.class).collect();
        println!("Accuracy: {:.4}", accuracy_score(&y_train, &y_pred));
        println!("Precision: {:.4}", precision_score(&y_train, &y_pred, 1.0));
        println!("Recall: {:.4}", recall_score(&y_train, &y_pred, 1.0));
        println!("F1 Score: {:.4}", f1_score(&y_train, &y_pred, 1.0));
    }

    fn accuracy_score(y_true: &[f32], y_pred: &[f32]) -> f32 {
        y_true
            .iter()
            .zip(y_pred.iter())
            .filter(|(true_val, pred_val)| **true_val == **pred_val)
            .count() as f32
            / y_true.len() as f32
    }

    fn precision_score(y_true: &[f32], y_pred: &[f32], positive_class: f32) -> f32 {
        let true_positives = y_true
            .iter()
            .zip(y_pred.iter())
            .filter(|(true_val, pred_val)| {
                **pred_val == positive_class && **true_val == positive_class
            })
            .count() as f32;

        let predicted_positives = y_pred
            .iter()
            .filter(|pred_val| **pred_val == positive_class)
            .count() as f32;

        if predicted_positives == 0.0 {
            0.0
        } else {
            true_positives / predicted_positives
        }
    }

    fn recall_score(y_true: &[f32], y_pred: &[f32], positive_class: f32) -> f32 {
        let true_positives = y_true
            .iter()
            .zip(y_pred.iter())
            .filter(|(true_val, pred_val)| {
                **pred_val == positive_class && **true_val == positive_class
            })
            .count() as f32;

        let actual_positives = y_true
            .iter()
            .filter(|true_val| **true_val == positive_class)
            .count() as f32;

        if actual_positives == 0.0 {
            0.0
        } else {
            true_positives / actual_positives
        }
    }

    fn f1_score(y_true: &[f32], y_pred: &[f32], positive_class: f32) -> f32 {
        let precision = precision_score(y_true, y_pred, positive_class);
        let recall = recall_score(y_true, y_pred, positive_class);

        if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * (precision * recall) / (precision + recall)
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn train_test_split(
        data: &[(String, bool)],
        test_size: f32,
    ) -> (Vec<(&String, bool)>, Vec<(&String, bool)>) {
        let mut class_0: Vec<(&String, bool)> = Vec::new();
        let mut class_1: Vec<(&String, bool)> = Vec::new();

        for (sample, class) in data {
            if !*class {
                class_0.push((sample, *class));
            } else {
                class_1.push((sample, *class));
            }
        }

        let test_count_0 = (class_0.len() as f32 * test_size).round() as usize;
        let test_count_1 = (class_1.len() as f32 * test_size).round() as usize;

        let (test_0, train_0) = class_0.split_at(test_count_0);
        let (test_1, train_1) = class_1.split_at(test_count_1);

        let mut train = Vec::new();
        let mut test = Vec::new();

        train.extend_from_slice(train_0);
        train.extend_from_slice(train_1);
        test.extend_from_slice(test_0);
        test.extend_from_slice(test_1);

        (train, test)
    }

    pub fn build_fh_samples(
        data: &[(&String, bool)],
        builder: &FhFeatureBuilder,
    ) -> Vec<Sample<FhFeature>> {
        let mut samples = Vec::with_capacity(data.len());

        for (text, class) in data {
            let mut sample: HashMap<String, f32> = HashMap::new();
            for word in text.split_whitespace() {
                *sample.entry(word.to_string()).or_default() += 1.0;
            }
            builder.scale(&mut sample);
            samples.push(Sample {
                features: builder.build(&sample, 12345.into(), true),
                class: if *class { 1.0 } else { 0.0 },
            });
        }

        samples
    }

    pub fn build_ccfh_samples(
        data: &[(&String, bool)],
        builder: &CcfhFeatureBuilder,
    ) -> Vec<Sample<CcfhFeature>> {
        let mut samples = Vec::with_capacity(data.len());

        for (text, class) in data {
            let mut sample: HashMap<String, f32> = HashMap::new();
            for word in text.split_whitespace() {
                *sample.entry(word.to_string()).or_default() += 1.0;
            }
            builder.scale(&mut sample);
            samples.push(Sample {
                features: builder.build(&sample, 12345.into(), true),
                class: if *class { 1.0 } else { 0.0 },
            });
        }

        samples
    }

    impl UnprocessedFeature for String {
        fn prefix(&self) -> u16 {
            0
        }

        fn value(&self) -> &[u8] {
            self.as_bytes()
        }
    }
}
