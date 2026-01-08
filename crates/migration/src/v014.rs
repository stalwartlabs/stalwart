/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    blob::migrate_blobs_v014, email_v2::migrate_emails_v014,
    encryption_v2::migrate_encryption_params_v014, queue_v2::migrate_queue_v014,
    tasks_v2::migrate_tasks_v014,
};
use common::Server;
use directory::backend::internal::manage::ManageDirectory;
use email::submission::EmailSubmission;
use groupware::{calendar::CalendarEventNotification, contact::ContactCard};
use std::sync::Arc;
use store::{
    SUBSPACE_INDEXES, SerializeInfallible, U32_LEN, U64_LEN,
    rand::{self, seq::SliceRandom},
    write::{
        AnyKey, BatchBuilder, IndexPropertyClass, Operation, ValueClass, ValueOp,
        key::KeySerializer,
    },
};
use tokio::sync::Semaphore;
use trc::AddContext;
use types::{
    collection::Collection,
    field::{CalendarNotificationField, ContactField, EmailSubmissionField, IdentityField},
};

pub const SUBSPACE_BITMAP_ID: u8 = b'b';
pub const SUBSPACE_BITMAP_TAG: u8 = b'c';
pub const SUBSPACE_BITMAP_TEXT: u8 = b'v';
pub const SUBSPACE_FTS_INDEX: u8 = b'g';
pub const SUBSPACE_TELEMETRY_INDEX: u8 = b'w';

pub async fn migrate_v0_14(server: &Server) -> trc::Result<()> {
    // Migrate global data
    let mut tasks = Vec::new();
    let _server = server.clone();
    tasks.push(tokio::spawn(
        async move { migrate_queue_v014(&_server).await },
    ));
    let _server = server.clone();
    tasks.push(tokio::spawn(
        async move { migrate_blobs_v014(&_server).await },
    ));
    let _server = server.clone();
    tasks.push(tokio::spawn(
        async move { migrate_tasks_v014(&_server).await },
    ));
    futures::future::join_all(tasks)
        .await
        .into_iter()
        .collect::<Result<trc::Result<()>, _>>()
        .map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .caused_by(trc::location!())
                .details("Join Error")
        })??;

    // Migrate account data
    let mut principal_ids = server
        .store()
        .principal_ids(None, None)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect::<Vec<_>>();
    principal_ids.shuffle(&mut rand::rng());
    let semaphore = Arc::new(Semaphore::new(
        std::env::var("NUM_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| num_cpus::get().min(2) * 2),
    ));
    let mut tasks = Vec::with_capacity(principal_ids.len());
    let num_principals = principal_ids.len();
    for principal_id in principal_ids {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let _server = server.clone();
        tasks.push(tokio::spawn(async move {
            let result = migrate_principal_v0_14(&_server, principal_id).await;
            drop(permit);
            result
        }));
    }
    futures::future::join_all(tasks)
        .await
        .into_iter()
        .collect::<Result<trc::Result<()>, _>>()
        .map_err(|err| {
            trc::EventType::Server(trc::ServerEvent::ThreadError)
                .reason(err)
                .caused_by(trc::location!())
                .details("Join Error")
        })??;

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!("Migrated {num_principals} accounts")
    );

    // Delete old subspaces
    for subspace in [
        SUBSPACE_BITMAP_ID,
        SUBSPACE_BITMAP_TAG,
        SUBSPACE_BITMAP_TEXT,
        SUBSPACE_FTS_INDEX,
        SUBSPACE_TELEMETRY_INDEX,
    ] {
        server
            .store()
            .delete_range(
                AnyKey {
                    subspace,
                    key: vec![0u8],
                },
                AnyKey {
                    subspace,
                    key: vec![u8::MAX; 32],
                },
            )
            .await
            .caused_by(trc::location!())?;
    }

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!("Migration to v0.15 completed")
    );

    Ok(())
}

pub(crate) async fn migrate_principal_v0_14(server: &Server, account_id: u32) -> trc::Result<()> {
    let emails = migrate_emails_v014(server, account_id).await?;
    let params = migrate_encryption_params_v014(server, account_id).await?;
    let (num_contacts, num_calendars, num_email_submissions, num_identities) =
        migrate_indexes(server, account_id).await?;

    trc::event!(
        Server(trc::ServerEvent::Startup),
        Details = format!(
            "Migrated account {account_id}: {emails} emails, {params} encryption params, {num_contacts} contacts, {num_calendars} calendars, {num_email_submissions} submissions, and {num_identities} identities"
        )
    );

    Ok(())
}

pub(crate) async fn migrate_indexes(
    server: &Server,
    account_id: u32,
) -> trc::Result<(usize, usize, usize, usize)> {
    /*

           EmailSubmissionField::UndoStatus => 41,
           EmailSubmissionField::EmailId => 83,
           EmailSubmissionField::ThreadId => 33,
           EmailSubmissionField::IdentityId => 95,
           EmailSubmissionField::SendAt => 24,

    */

    /*

           ContactField::Created => 2,
           ContactField::Updated => 3,
           ContactField::Text => 4,
    */

    /*

           CalendarField::Text => 1,
           CalendarField::Created => 2,
           CalendarField::Updated => 3,
           CalendarField::Start => 4,
           CalendarField::EventId => 5,
    */

    /*

            EmailField::From => 87,
            EmailField::To => 35,
            EmailField::Cc => 74,
            EmailField::Bcc => 69,
            EmailField::Subject => 29,
            EmailField::Size => 27,
            EmailField::References => 20,
            EmailField::MailboxIds => 7,
            EmailField::ReceivedAt => 19,
            EmailField::SentAt => 26,
            EmailField::HasAttachment => 89,

    */

    for (collection, fields) in [
        (
            Collection::Email,
            &[87u8, 35, 74, 69, 29, 27, 20, 7, 19, 26, 89][..],
        ),
        (Collection::EmailSubmission, &[41, 83, 33, 95, 24][..]),
        (Collection::ContactCard, &[1, 2, 3, 4][..]),
        (Collection::CalendarEvent, &[1, 2, 3, 4][..]),
        (Collection::CalendarEventNotification, &[2, 5][..]),
    ] {
        for index in fields {
            server
                .store()
                .delete_range(
                    AnyKey {
                        subspace: SUBSPACE_INDEXES,
                        key: KeySerializer::new(U64_LEN * 3)
                            .write(account_id)
                            .write(u8::from(collection))
                            .write(*index)
                            .finalize(),
                    },
                    AnyKey {
                        subspace: SUBSPACE_INDEXES,
                        key: KeySerializer::new(U64_LEN * 4)
                            .write(account_id)
                            .write(u8::from(collection))
                            .write(*index)
                            .write(&[u8::MAX; 8][..])
                            .finalize(),
                    },
                )
                .await
                .caused_by(trc::location!())?;
        }
    }

    let mut indexes = Vec::new();
    let mut num_contacts = 0;
    let mut num_calendars = 0;
    let mut num_email_submissions = 0;
    let mut num_identities = 0;
    for collection in [
        Collection::ContactCard,
        Collection::CalendarEventNotification,
        Collection::EmailSubmission,
        Collection::Identity,
    ] {
        server
            .archives(account_id, collection, &(), |document_id, archive| {
                match collection {
                    Collection::ContactCard => {
                        let data = archive
                            .unarchive_untrusted::<ContactCard>()
                            .caused_by(trc::location!())?;

                        if let Some(email) = data.emails().next() {
                            indexes.push((
                                collection,
                                document_id,
                                Operation::Index {
                                    field: ContactField::Email.into(),
                                    key: email.into_bytes(),
                                    set: true,
                                },
                            ));
                        }
                        num_contacts += 1;
                        indexes.push((
                            collection,
                            document_id,
                            Operation::Value {
                                class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                                    property: ContactField::CreatedToUpdated.into(),
                                    value: data.created.to_native() as u64,
                                }),
                                op: ValueOp::Set((data.modified.to_native() as u64).serialize()),
                            },
                        ));
                    }
                    Collection::CalendarEventNotification => {
                        let data = archive
                            .unarchive_untrusted::<CalendarEventNotification>()
                            .caused_by(trc::location!())?;
                        num_calendars += 1;
                        indexes.push((
                            collection,
                            document_id,
                            Operation::Value {
                                class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                                    property: CalendarNotificationField::CreatedToId.into(),
                                    value: data.created.to_native() as u64,
                                }),
                                op: ValueOp::Set(
                                    data.event_id
                                        .as_ref()
                                        .map(|v| v.to_native())
                                        .unwrap_or(u32::MAX)
                                        .serialize(),
                                ),
                            },
                        ));
                    }
                    Collection::EmailSubmission => {
                        let data = archive
                            .unarchive_untrusted::<EmailSubmission>()
                            .caused_by(trc::location!())?;
                        num_email_submissions += 1;
                        indexes.push((
                            collection,
                            document_id,
                            Operation::Value {
                                class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                                    property: EmailSubmissionField::Metadata.into(),
                                    value: data.send_at.to_native(),
                                }),
                                op: ValueOp::Set(
                                    KeySerializer::new(U32_LEN * 3 + 1)
                                        .write(data.email_id.to_native())
                                        .write(data.thread_id.to_native())
                                        .write(data.identity_id.to_native())
                                        .write(data.undo_status.as_index())
                                        .finalize(),
                                ),
                            },
                        ));
                    }
                    Collection::Identity => {
                        num_identities += 1;
                        indexes.push((
                            collection,
                            document_id,
                            Operation::Index {
                                field: IdentityField::DocumentId.into(),
                                key: vec![],
                                set: true,
                            },
                        ));
                    }
                    _ => unreachable!(),
                }

                Ok(true)
            })
            .await
            .caused_by(trc::location!())?;
    }

    let mut batch = BatchBuilder::new();
    for (collection, document_id, op) in indexes {
        batch
            .with_account_id(account_id)
            .with_collection(collection)
            .with_document(document_id)
            .any_op(op);
        if batch.is_large_batch() || batch.len() == 255 {
            server
                .store()
                .write(batch.build_all())
                .await
                .caused_by(trc::location!())?;
            batch = BatchBuilder::new();
        }
    }

    if !batch.is_empty() {
        server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok((
        num_contacts,
        num_calendars,
        num_email_submissions,
        num_identities,
    ))
}
