/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod buffer;
pub mod error;
pub mod header;
pub mod ids;
pub mod requests;
pub mod responses;
pub mod views;
pub mod writer;

pub use buffer::{DecodedRop, HandleTableIn, LogonKind, LogonKinds, RopBuffer, RopIter};
pub use header::{ResponseHeader, RopHeader, RopId};
pub use requests::RopRequest;
pub use writer::{
    BUFFER_TOO_SMALL_LEN, FailureBody, Mark, Overflow, PENDING_LEN, RopResponse, RopWriter,
};

pub use error::RopDecodeError;
