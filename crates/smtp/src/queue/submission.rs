/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ArchivedError, ArchivedErrorDetails, ArchivedRecipient, ArchivedStatus, Error, ErrorDetails,
    MessageWrapper, Recipient, Status,
};
use email::submission::{Delivered, DeliveryResult, DeliveryResults, DeliveryStatus, QUEUED_REPLY};
use store::{
    Serialize,
    write::{Archiver, BatchBuilder},
};

const REMOVED_REPLY: &str = "Removed from queue";

impl MessageWrapper {
    pub(crate) fn write_delivery_results(&self, batch: &mut BatchBuilder) {
        let Some(account_id) = self.message.submission_account_id() else {
            return;
        };
        let results = DeliveryResults(
            self.message
                .recipients
                .iter()
                .map(Recipient::delivery_result)
                .collect(),
        );
        match Archiver::new(results).serialize() {
            Ok(value) => {
                DeliveryResults::write(batch, account_id, self.queue_id, value);
            }
            Err(err) => {
                trc::error!(
                    err.details("Failed to serialize delivery results.")
                        .span_id(self.span_id)
                        .account_id(account_id)
                        .caused_by(trc::location!())
                );
            }
        }
    }
}

impl Recipient {
    fn delivery_result(&self) -> DeliveryResult {
        let (delivered, smtp_reply) = match &self.status {
            Status::Scheduled => (Delivered::No, REMOVED_REPLY.into()),
            Status::Completed(reply) => (
                Delivered::Yes,
                format_response(
                    reply.response.code,
                    reply.response.esc,
                    &reply.response.message,
                ),
            ),
            Status::TemporaryFailure(err) | Status::PermanentFailure(err) => {
                (Delivered::No, format_error(err))
            }
        };
        DeliveryResult {
            address: self.address.clone(),
            delivered,
            smtp_reply: smtp_reply.into_boxed_str(),
        }
    }
}

impl ArchivedRecipient {
    pub fn delivery_status(&self) -> DeliveryStatus {
        let (delivered, smtp_reply) = match &self.status {
            ArchivedStatus::Scheduled => (Delivered::Queued, QUEUED_REPLY.into()),
            ArchivedStatus::Completed(reply) => (
                Delivered::Yes,
                format_response(
                    reply.response.code.into(),
                    reply.response.esc,
                    &reply.response.message,
                ),
            ),
            ArchivedStatus::TemporaryFailure(err) => {
                (Delivered::Queued, format_archived_error(err))
            }
            ArchivedStatus::PermanentFailure(err) => (Delivered::No, format_archived_error(err)),
        };
        DeliveryStatus {
            smtp_reply,
            delivered,
            displayed: false,
        }
    }
}

fn format_error(err: &ErrorDetails) -> String {
    match &err.details {
        Error::UnexpectedResponse(response) => format_response(
            response.response.code,
            response.response.esc,
            &response.response.message,
        ),
        Error::DnsError(details)
        | Error::Io(details)
        | Error::ConnectionError(details)
        | Error::TlsError(details)
        | Error::DaneError(details)
        | Error::EncryptionError(details)
        | Error::MtaStsError(details) => details.to_string(),
        Error::RateLimited => "Rate limited".into(),
        Error::ConcurrencyLimited => "Concurrency limited".into(),
    }
}

fn format_archived_error(err: &ArchivedErrorDetails) -> String {
    match &err.details {
        ArchivedError::UnexpectedResponse(response) => format_response(
            response.response.code.into(),
            response.response.esc,
            &response.response.message,
        ),
        ArchivedError::DnsError(details)
        | ArchivedError::Io(details)
        | ArchivedError::ConnectionError(details)
        | ArchivedError::TlsError(details)
        | ArchivedError::DaneError(details)
        | ArchivedError::EncryptionError(details)
        | ArchivedError::MtaStsError(details) => details.to_string(),
        ArchivedError::RateLimited => "Rate limited".into(),
        ArchivedError::ConcurrencyLimited => "Concurrency limited".into(),
    }
}

fn format_response(code: u16, [a, b, c]: [u8; 3], message: &str) -> String {
    let mut reply = format!("Code: {code}, Enhanced code: {a}.{b}.{c}, Message: ");
    reply.extend(message.chars().map(|ch| if ch == '\n' { ' ' } else { ch }));
    reply
}
