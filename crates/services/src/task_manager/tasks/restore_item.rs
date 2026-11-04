/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::BuildAccessToken};
use email::{
    mailbox::INBOX_ID,
    message::ingest::{EmailIngest, IngestEmail, IngestSource},
};
use mail_parser::MessageParser;
use registry::schema::{enums::ArchivedItemType, structs::TaskRestoreArchivedItem};
use store::write::{BatchBuilder, BlobLink, BlobOp};
use trc::AddContext;

use crate::task_manager::outcome::Outcome;

pub(crate) trait RestoreItemTask: Sync + Send {
    fn restore_item(&self, task: &TaskRestoreArchivedItem) -> impl Future<Output = Outcome> + Send;
}

impl RestoreItemTask for Server {
    async fn restore_item(&self, task: &TaskRestoreArchivedItem) -> Outcome {
        match restore_item(self, task).await {
            Ok(outcome) => outcome,
            Err(err) => {
                let result = Outcome::error(&err);
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to restore item")
                );
                result
            }
        }
    }
}

async fn restore_item(server: &Server, task: &TaskRestoreArchivedItem) -> trc::Result<Outcome> {
    match task.archived_item_type {
        ArchivedItemType::Email => {
            let account_id = task.account_id.document_id();
            let access_token = server
                .access_token(account_id)
                .await
                .caused_by(trc::location!())?;

            let Some(bytes) = server
                .get_blob(task.blob_id.hash.as_slice(), 0..usize::MAX)
                .await?
            else {
                return Ok(Outcome::Obsolete("Archived blob no longer exists"));
            };

            match server
                .email_ingest(IngestEmail {
                    raw_message: &bytes,
                    message: MessageParser::new().parse(&bytes).as_ref(),
                    blob_hash: Some(&task.blob_id.hash),
                    access_token: &access_token.build(),
                    mailbox_ids: vec![INBOX_ID],
                    keywords: vec![],
                    received_at: (task.created_at.timestamp() as u64).into(),
                    source: IngestSource::Restore,
                    metadata: None,
                    session_id: 0,
                })
                .await
            {
                Ok(_) => {
                    let mut batch = BatchBuilder::new();
                    batch.with_account_id(account_id).clear(BlobOp::Link {
                        hash: task.blob_id.hash.clone(),
                        to: BlobLink::Temporary {
                            until: task.archived_until.timestamp() as u64,
                        },
                    });
                    server.store().write_batch(&mut batch).await?;

                    Ok(Outcome::done())
                }
                Err(mut err)
                    if err.matches(trc::EventType::MessageIngest(
                        trc::MessageIngestEvent::Error,
                    )) =>
                {
                    Ok(Outcome::fatal(
                        err.take_value(trc::Key::Reason)
                            .and_then(|v| v.into_string())
                            .map_or_else(|| "Message ingestion failed".to_string(), Into::into),
                    ))
                }
                Err(err) => Err(err.caused_by(trc::location!())),
            }
        }
        ArchivedItemType::FileNode
        | ArchivedItemType::CalendarEvent
        | ArchivedItemType::ContactCard
        | ArchivedItemType::SieveScript => Ok(Outcome::fatal("Not implemented")),
    }
}
