/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ImapContext;
use crate::core::Session;
use common::network::SessionStream;
use email::cache::MessageCacheFetch;
use imap_proto::{
    Command, ResponseCode, ResponseType, StatusResponse, protocol::uidbatches, receiver::Request,
};
use registry::schema::enums::Permission;
use std::time::Instant;

impl<T: SessionStream> Session<T> {
    pub async fn handle_uidbatches(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapSearch)?;

        let op_start = Instant::now();
        let arguments = request.parse_uidbatches()?;
        let (data, mailbox) = self.state.select_data();

        let min_batch_size = self.server.core.imap.min_uid_batch_size;
        if arguments.batch_size < min_batch_size {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(format!("Minimum batch size is {min_batch_size}."))
                .code(ResponseCode::TooFew)
                .id(arguments.tag));
        }

        if let Some((from, to)) = arguments.batch_range
            && from > to
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("Batch ranges must be ordered from lowest to highest.")
                .code(ResponseCode::ClientBug)
                .ctx(trc::Key::Type, ResponseType::Bad)
                .id(arguments.tag));
        }

        // Reject oversized requests before doing any work on their behalf
        let max_uid_batches = self.server.core.imap.max_uid_batches;
        if arguments
            .batch_range
            .is_some_and(|(from, to)| to - from + 1 > max_uid_batches)
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(format!(
                    "A single UIDBATCHES response is limited to {max_uid_batches} ranges."
                ))
                .code(ResponseCode::TooMany)
                .id(arguments.tag));
        }

        // Resynchronize so that batches reflect the current mailbox contents
        let cache = data
            .server
            .get_cached_messages(mailbox.id.account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        data.sync_view(&mailbox, &cache, None)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        let batch_size = arguments.batch_size as usize;
        let ranges = {
            let view = mailbox.view.lock();
            let live_rows;
            let rows = if view.has_pending_changes() {
                live_rows = view.live_rows_by_uid();
                live_rows.as_slice()
            } else {
                view.rows()
            };
            let total_batches = rows.len().div_ceil(batch_size);

            if arguments.batch_range.is_none() && total_batches > max_uid_batches as usize {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details(format!(
                        "A single UIDBATCHES response is limited to {max_uid_batches} ranges."
                    ))
                    .code(ResponseCode::TooMany)
                    .id(arguments.tag));
            }

            // Batch ranges tile the whole UID space, so each range starts right below
            // the previous one and the oldest batch always reaches down to UID 1.
            let (first, last) = match arguments.batch_range {
                Some((from, to)) => (
                    (from as usize - 1).min(total_batches),
                    (to as usize).min(total_batches),
                ),
                None => (0, total_batches),
            };
            let mut ranges = Vec::with_capacity(last.saturating_sub(first));
            let mut high = rows.last().map_or(0, |row| row.uid);
            for batch in 0..last {
                let end = ((batch + 1) * batch_size).min(rows.len());
                let low = if end == rows.len() {
                    1
                } else {
                    rows.get(rows.len() - end).map_or(1, |row| row.uid)
                };
                if batch >= first {
                    ranges.push((high, low));
                }
                high = low.saturating_sub(1);
            }
            ranges
        };

        trc::event!(
            Imap(trc::ImapEvent::UidBatches),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            Limit = arguments.batch_size,
            Total = ranges.len(),
            Elapsed = op_start.elapsed()
        );

        let response = uidbatches::Response { ranges }.serialize(&arguments.tag);
        self.write_bytes(
            StatusResponse::completed(Command::UidBatches)
                .with_tag(arguments.tag)
                .serialize(response),
        )
        .await
    }
}
