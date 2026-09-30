/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashSet;

pub struct ConstSet {
    items: AHashSet<Box<str>>,
}

impl ConstSet {
    pub const LINEAR_MAX_ITEMS: usize = 15;

    pub fn new<I>(items: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        Self {
            items: items.into_iter().map(|item| item.as_ref().into()).collect(),
        }
    }

    pub fn contains(&self, value: &str) -> bool {
        self.items.contains(value)
    }
}
