/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use rand::{Rng, seq::IndexedRandom};

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug)]
pub struct SampleReservoir<T> {
    pub spam: SampleReservoirClass<T>,
    pub ham: SampleReservoirClass<T>,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug)]
pub struct SampleReservoirClass<T> {
    pub buffer: Vec<T>,
    pub total_seen: u64,
}

impl<T: Clone + Eq> SampleReservoir<T> {
    pub fn update_reservoir(&mut self, item: &T, is_spam: bool, capacity: usize) {
        let class = if is_spam {
            &mut self.spam
        } else {
            &mut self.ham
        };

        class.total_seen += 1;

        if class.buffer.len() < capacity {
            class.buffer.push(item.clone());
        } else if let Some(buf) = class
            .buffer
            .get_mut(rand::rng().random_range(0..class.total_seen as usize))
        {
            *buf = item.clone();
        }
    }

    pub fn update_counts(&mut self, is_spam: bool) {
        let class = if is_spam {
            &mut self.spam
        } else {
            &mut self.ham
        };

        class.total_seen += 1;
    }

    pub fn replay_samples(
        &mut self,
        count_needed: usize,
        is_spam: bool,
    ) -> impl Iterator<Item = &T> {
        (if is_spam {
            &mut self.spam
        } else {
            &mut self.ham
        })
        .buffer
        .choose_multiple(&mut rand::rng(), count_needed)
    }

    pub fn remove_sample(&mut self, item: &T, is_spam: bool) {
        let class = if is_spam {
            &mut self.spam
        } else {
            &mut self.ham
        };

        if let Some(pos) = class.buffer.iter().position(|x| x == item) {
            class.buffer.swap_remove(pos);
        }
    }
}

impl<T> Default for SampleReservoir<T> {
    fn default() -> Self {
        SampleReservoir {
            spam: SampleReservoirClass {
                buffer: Vec::new(),
                total_seen: 0,
            },
            ham: SampleReservoirClass {
                buffer: Vec::new(),
                total_seen: 0,
            },
        }
    }
}
