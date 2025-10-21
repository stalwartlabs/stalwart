/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::message::bayes::EmailBayesTrain;
use mail_parser::MessageParser;
use std::time::Instant;
use trc::{SpamEvent, TaskQueueEvent};
use types::{blob_hash::BlobHash, collection::Collection};

pub trait BayesTrainTask: Sync + Send {
    fn bayes_train(
        &self,
        account_id: u32,
        document_id: u32,
        hash: &BlobHash,
        learn_spam: bool,
    ) -> impl Future<Output = bool> + Send;
}

impl BayesTrainTask for Server {
    async fn bayes_train(
        &self,
        account_id: u32,
        document_id: u32,
        hash: &BlobHash,
        learn_spam: bool,
    ) -> bool {
        let op_start = Instant::now();
        // Obtain raw message
        if let Ok(Some(raw_message)) = self
            .blob_store()
            .get_blob(hash.as_slice(), 0..usize::MAX)
            .await
        {
            // Train bayes classifier for account
            self.email_bayes_train(
                account_id,
                0,
                MessageParser::new().parse(&raw_message).unwrap_or_default(),
                learn_spam,
            )
            .await;

            trc::event!(
                Spam(SpamEvent::TrainAccount),
                AccountId = account_id,
                Collection = Collection::Email,
                DocumentId = document_id,
                Details = if learn_spam { "spam" } else { "ham" },
                Elapsed = op_start.elapsed(),
            );
            true
        } else {
            trc::event!(
                TaskQueue(TaskQueueEvent::BlobNotFound),
                AccountId = account_id,
                DocumentId = document_id,
                BlobId = hash.as_slice(),
            );
            false
        }
    }
}
