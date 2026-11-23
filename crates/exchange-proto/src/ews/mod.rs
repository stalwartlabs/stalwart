/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod bulk;
#[cfg(feature = "convert")]
pub mod calendar;
#[cfg(feature = "convert")]
pub mod contact;
pub mod envelope;
pub mod fault;
pub mod header;
pub mod html;
#[cfg(feature = "convert")]
mod item_edit;
pub mod operation;
pub mod parser;
pub mod persona;
pub mod requests;
pub mod responses;
pub mod schema;
#[cfg(feature = "convert")]
pub mod task;
pub mod types;
pub mod version;

pub use envelope::{
    BodyWriter, Envelope, EnvelopeWriter, MessageBodyWriter, MessagesWriter, XmlDecl,
    parse_request, write_envelope,
};
pub use fault::{Fault, write_fault};
pub use header::{ConnectingSid, SoapHeader};
pub use operation::{Operation, ResponseShape};
pub use parser::{EwsLimits, ParseError, ParseErrorKind, ParseOutcome};
pub use requests::EwsRequest;
pub use responses::{MessageResult, MessageXml, Paging, ResponseMessage, Status};
pub use version::{ExchangeVersion, RequestedVersion, ServerVersionInfo};

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/ews/tests/mod.rs"]
mod tests;
