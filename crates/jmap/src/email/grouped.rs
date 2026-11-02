/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use email::message::ingest::{
    EmailIngest, IngestEmail, IngestSource, IngestedEmail,
    group::{IngestGroup, ThreadKey},
};
use mail_parser::{Message, MessageParser};
use types::{blob_hash::BlobHash, keyword::Keyword};

pub(super) struct QueuedEmail {
    pub id: String,
    pub blob_hash: Option<BlobHash>,
    pub mailbox_ids: Vec<u32>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<u64>,
    pub train_classifier: bool,
}

pub(super) struct GroupedIngest<'a, R> {
    access_token: &'a AccessToken,
    session_id: u64,
    group: IngestGroup,
    queued: Vec<(QueuedEmail, R)>,
    pub results: Vec<(String, trc::Result<IngestedEmail>)>,
}

impl QueuedEmail {
    pub fn params<'x>(
        &'x self,
        raw_message: &'x [u8],
        message: Option<&'x Message<'x>>,
        access_token: &'x AccessToken,
        session_id: u64,
    ) -> IngestEmail<'x> {
        IngestEmail {
            raw_message,
            message,
            blob_hash: self.blob_hash.as_ref(),
            access_token,
            source: IngestSource::Jmap {
                train_classifier: self.train_classifier,
            },
            mailbox_ids: self.mailbox_ids.clone(),
            keywords: self.keywords.clone(),
            received_at: self.received_at,
            metadata: None,
            session_id,
        }
    }
}

impl<'a, R: AsRef<[u8]>> GroupedIngest<'a, R> {
    pub fn new(access_token: &'a AccessToken, session_id: u64) -> Self {
        GroupedIngest {
            access_token,
            session_id,
            group: IngestGroup::default(),
            queued: Vec::new(),
            results: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }

    pub fn must_flush_before(&self, size: usize) -> bool {
        self.group.must_flush_before(size)
    }

    pub fn ingest<'x>(
        &'x mut self,
        server: &'x Server,
        email: &'x QueuedEmail,
        raw_message: &'x [u8],
        message: Option<&'x Message<'x>>,
        key: ThreadKey,
    ) -> impl Future<Output = trc::Result<()>> + 'x {
        self.group.ingest(
            server,
            email.params(raw_message, message, self.access_token, self.session_id),
            key,
        )
    }

    pub fn queue(&mut self, email: QueuedEmail, raw_message: R, result: trc::Result<()>) {
        match result {
            Ok(()) => self.queued.push((email, raw_message)),
            Err(err) => self.results.push((email.id, Err(err))),
        }
    }

    pub async fn flush(&mut self, server: &Server) -> trc::Result<()> {
        match self.group.flush(server).await {
            Ok(emails) => {
                self.results.extend(
                    self.queued
                        .drain(..)
                        .map(|(email, _)| email.id)
                        .zip(emails.into_iter().map(Ok)),
                );
                Ok(())
            }
            Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::Quota)) => {
                if self.queued.len() == 1 {
                    if let Some((email, _)) = self.queued.pop() {
                        self.results.push((email.id, Err(err)));
                    }
                } else {
                    for (email, raw_message) in self.queued.drain(..) {
                        let raw_message = raw_message.as_ref();
                        let message = MessageParser::new().parse(raw_message);
                        let result = Box::pin(server.email_ingest(email.params(
                            raw_message,
                            message.as_ref(),
                            self.access_token,
                            self.session_id,
                        )))
                        .await;
                        self.results.push((email.id, result));
                    }
                }
                Ok(())
            }
            Err(err) => {
                self.queued.clear();
                Err(err)
            }
        }
    }
}
