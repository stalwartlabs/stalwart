/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acl;
pub mod log;

use crate::{IterateParams, Key};

impl<T: Key> IterateParams<T> {
    pub fn new(begin: T, end: T) -> Self {
        IterateParams {
            begin,
            end,
            first: false,
            ascending: true,
            values: true,
        }
    }

    pub fn set_ascending(mut self, ascending: bool) -> Self {
        self.ascending = ascending;
        self
    }

    pub fn set_values(mut self, values: bool) -> Self {
        self.values = values;
        self
    }

    pub fn ascending(mut self) -> Self {
        self.ascending = true;
        self
    }

    pub fn descending(mut self) -> Self {
        self.ascending = false;
        self
    }

    pub fn only_first(mut self) -> Self {
        self.first = true;
        self
    }

    pub fn no_values(mut self) -> Self {
        self.values = false;
        self
    }
}
