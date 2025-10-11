/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod enterprise;
pub mod purge;
pub mod webhooks;

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
pub(crate) struct List<T> {
    pub items: Vec<T>,
    pub total: usize,
}
