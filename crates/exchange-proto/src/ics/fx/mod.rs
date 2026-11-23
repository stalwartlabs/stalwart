/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(feature = "convert")]
pub mod copy;
pub mod decoder;
pub mod encoder;
pub mod marker;

#[cfg(feature = "convert")]
pub use copy::{Children, CopyBuilder, CopyError, CopyItem, CopyRoot};
pub use decoder::{FxDecoder, FxEvent, FxEvents};
pub use encoder::{
    FxCheckpoint, FxEncoder, FxValueSink, MessageChangeHeader, ProgressInformation, PropOutcome,
    StringMode,
};
pub use marker::{Marker, meta, tags};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange-proto/src/ics/fx/tests.rs"]
mod tests;
