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

use crate::task_manager::TaskResult;

pub(crate) trait RestoreItemTask: Sync + Send {
    fn restore_item(
        &self,
        task: &TaskRestoreArchivedItem,
    ) -> impl Future<Output = TaskResult> + Send;
}

impl RestoreItemTask for Server {
    async fn restore_item(&self, task: &TaskRestoreArchivedItem) -> TaskResult {
        match restore_item(self, task).await {
            Ok(result) => result,
            Err(err) => {
                let result = TaskResult::temporary(err.to_string());
                trc::error!(
                    err.account_id(task.account_id.document_id())
                        .details("Failed to restore item")
                );
                result
            }
        }
    }
}

async fn restore_item(server: &Server, task: &TaskRestoreArchivedItem) -> trc::Result<TaskResult> {
    match task.archived_item_type {
        ArchivedItemType::Email => {
            let account_id = task.account_id.document_id();
            let access_token = server
                .access_token(account_id)
                .await
                .caused_by(trc::location!())?;

            let Some(bytes) = server
                .blob_store()
                .get_blob(task.blob_id.hash.as_slice(), 0..usize::MAX)
                .await?
            else {
                return Ok(TaskResult::permanent("Blob not found"));
            };

            match server
                .email_ingest(IngestEmail {
                    raw_message: &bytes,
                    message: MessageParser::new().parse(&bytes),
                    blob_hash: Some(&task.blob_id.hash),
                    access_token: &access_token.build(),
                    mailbox_ids: vec![INBOX_ID],
                    keywords: vec![],
                    received_at: (task.created_at.timestamp() as u64).into(),
                    source: IngestSource::Restore,
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
                    server.store().write(batch.build_all()).await?;

                    Ok(TaskResult::Success(vec![]))
                }
                Err(mut err)
                    if err.matches(trc::EventType::MessageIngest(
                        trc::MessageIngestEvent::Error,
                    )) =>
                {
                    Ok(TaskResult::permanent(
                        err.take_value(trc::Key::Reason)
                            .and_then(|v| v.into_string())
                            .unwrap()
                            .to_string(),
                    ))
                }
                Err(err) => Err(err.caused_by(trc::location!())),
            }
        }
        ArchivedItemType::FileNode
        | ArchivedItemType::CalendarEvent
        | ArchivedItemType::ContactCard
        | ArchivedItemType::SieveScript => Ok(TaskResult::permanent("Not implemented")),
    }
}
