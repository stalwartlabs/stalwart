/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

pub mod api;
pub mod auth;
pub mod form;
pub mod request;
mod stream;

use common::{Core, Inner};
use std::sync::Arc;

#[derive(Clone)]
pub struct HttpSessionManager {
    pub inner: Arc<Inner>,
}

impl HttpSessionManager {
    pub fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "exchange")]
pub(crate) fn is_exchange_enabled(core: &Core) -> bool {
    core.exchange.enabled
}

#[cfg(not(feature = "exchange"))]
pub(crate) fn is_exchange_enabled(_core: &Core) -> bool {
    false
}
