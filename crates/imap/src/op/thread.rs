/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::{SelectedMailbox, Session, SessionData},
    spawn_op,
};
use ahash::AHashMap;
use common::network::SessionStream;
use email::cache::{MessageCacheFetch, email::MessageCacheAccess};
use imap_proto::{
    Command, StatusResponse,
    protocol::{
        ImapResponse,
        thread::{Arguments, Response},
    },
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use trc::AddContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_thread(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapThread)?;

        let op_start = Instant::now();
        let command = request.command;
        let mut arguments = request.parse_thread()?;
        let (data, mailbox) = self.state.mailbox_state();

        spawn_op!(data, {
            let tag = std::mem::take(&mut arguments.tag);

            match data.thread(arguments, mailbox, is_uid, op_start).await {
                Ok(response) => {
                    data.write_bytes(
                        StatusResponse::completed(command)
                            .with_tag(tag)
                            .serialize(response.serialize()),
                    )
                    .await
                }
                Err(err) => Err(err.id(tag)),
            }
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn thread(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        is_uid: bool,
        op_start: Instant,
    ) -> trc::Result<Response> {
        let cache = self
            .server
            .get_cached_messages(mailbox.id.account_id)
            .await
            .caused_by(trc::location!())?;
        self.sync_view(&mailbox, &cache, None)
            .await
            .caused_by(trc::location!())?;

        // Run query
        let (result_set, _) = self
            .query(arguments.filter, vec![], &mailbox, &cache, &None)
            .await?;

        if result_set.is_empty() {
            return Ok(Response {
                is_uid,
                threads: vec![],
            });
        }

        // Group messages by thread
        let mut threads: AHashMap<u32, Vec<u32>> = AHashMap::new();
        {
            let view = mailbox.view.lock();
            for document_id in result_set {
                if let Some(item) = cache.email_by_id(&document_id)
                    && let Some(resolved) = view.map_result(document_id)
                {
                    threads
                        .entry(item.thread_id())
                        .or_default()
                        .push(resolved.imap_id(is_uid));
                }
            }
        }

        let mut threads = threads
            .into_values()
            .map(|mut messages| {
                messages.sort_unstable();
                messages
            })
            .collect::<Vec<_>>();
        threads.sort_unstable();

        trc::event!(
            Imap(trc::ImapEvent::Thread),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            Total = threads.len(),
            Elapsed = op_start.elapsed()
        );

        // Build response
        Ok(Response { is_uid, threads })
    }
}
