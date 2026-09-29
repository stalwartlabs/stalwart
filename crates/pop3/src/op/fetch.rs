/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{Session, protocol::response::Response};
use common::network::SessionStream;
use email::message::metadata::MetadataRow;
use registry::schema::enums::Permission;
use std::time::Instant;
use store::ValueKey;
use trc::AddContext;
use types::{collection::Collection, field::EmailField};
use utils::chained_bytes::ChainedBytes;

impl<T: SessionStream> Session<T> {
    pub async fn handle_fetch(&mut self, msg: u32, lines: Option<u32>) -> trc::Result<()> {
        // Validate access
        self.state
            .access_token()
            .enforce_permission(Permission::Pop3Retr)?;

        let op_start = Instant::now();
        let mailbox = self.state.mailbox();
        if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
            if let Some(row) = self
                .server
                .store()
                .get_value::<MetadataRow>(ValueKey::immutable(
                    mailbox.account_id,
                    Collection::Email,
                    message.id,
                    EmailField::Metadata,
                ))
                .await
                .caused_by(trc::location!())?
            {
                let metadata = row.unarchive().caused_by(trc::location!())?;
                let headers = row.raw_headers().caused_by(trc::location!())?;
                if let Some(bytes) = self
                    .server
                    .blob_store()
                    .get_blob(metadata.blob_hash.0.as_slice(), 0..usize::MAX)
                    .await
                    .caused_by(trc::location!())?
                {
                    trc::event!(
                        Pop3(trc::Pop3Event::Fetch),
                        SpanId = self.session_id,
                        DocumentId = message.id,
                        Elapsed = op_start.elapsed()
                    );

                    self.write_bytes(
                        Response::<u32>::message(
                            ChainedBytes::from_blob(&headers, &bytes, metadata.blob_body_offset()),
                            metadata.headers_len(),
                            lines,
                        )
                        .serialize(),
                    )
                    .await
                } else {
                    Err(trc::Pop3Event::Error
                        .into_err()
                        .details("Failed to fetch message. Perhaps another session deleted it?")
                        .caused_by(trc::location!()))
                }
            } else {
                Err(trc::Pop3Event::Error
                    .into_err()
                    .details("Failed to fetch message. Perhaps another session deleted it?")
                    .caused_by(trc::location!()))
            }
        } else {
            Err(trc::Pop3Event::Error.into_err().details("No such message."))
        }
    }
}
