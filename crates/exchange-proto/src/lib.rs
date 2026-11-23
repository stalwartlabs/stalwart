/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![forbid(unsafe_code)]

pub mod autodiscover;
pub mod common;
#[cfg(feature = "convert")]
pub mod convert;
pub mod eas;
pub mod ews;
pub mod ics;
pub mod ids;
pub mod mapi;
pub mod oab;
pub mod rules;
pub mod xml;
