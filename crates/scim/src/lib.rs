/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

#[cfg(feature = "enterprise")]
pub mod auth;
#[cfg(feature = "enterprise")]
pub mod bulk;
#[cfg(feature = "enterprise")]
pub mod context;
#[cfg(feature = "enterprise")]
pub mod discovery;
#[cfg(feature = "enterprise")]
pub mod error;
#[cfg(feature = "enterprise")]
pub mod groups;
#[cfg(feature = "enterprise")]
pub mod query;
#[cfg(feature = "enterprise")]
pub mod request;
#[cfg(feature = "enterprise")]
pub mod users;
