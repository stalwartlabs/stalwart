/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::index_queue::REINDEX_CHUNK_SIZE;
use common::Server;
use email::cache::MessageCacheFetch;
use groupware::cache::GroupwareCache;
use store::{
    IterateParams, U32_LEN, ValueKey,
    write::{
        BatchBuilder, QueueDocumentId, SearchIndex, SearchIndexClass, TelemetryClass, ValueClass,
        key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use types::collection::SyncCollection;

pub(crate) async fn reindex_telemetry(server: &Server) -> trc::Result<()> {
    clear_tracing_queue(server).await?;

    let mut from_span_id = 0;

    loop {
        // The spans are collected in chunks, a telemetry store can hold millions of them
        let mut spans = Vec::with_capacity(REINDEX_CHUNK_SIZE);
        server
            .tracing_store()
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(from_span_id))),
                    ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(u64::MAX))),
                )
                .ascending()
                .no_values(),
                |key, _| {
                    spans.push(key.deserialize_be_u64(0)?);
                    Ok(spans.len() < REINDEX_CHUNK_SIZE)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let Some(last_span_id) = spans.last().copied() else {
            return Ok(());
        };

        let mut batch = BatchBuilder::new();
        for span_id in spans {
            batch.queue_trace_index(span_id);
            if batch.is_large_batch() {
                server.commit_batch(batch).await?;
                batch = BatchBuilder::new();
            }
        }

        if !batch.is_empty() {
            server.commit_batch(batch).await?;
        }

        if let Some(next_span_id) = last_span_id.checked_add(1) {
            from_span_id = next_span_id;
        } else {
            return Ok(());
        }
    }
}

pub(crate) async fn reindex_account(server: &Server, account_id: u32) -> trc::Result<()> {
    for index in [
        SearchIndex::Email,
        SearchIndex::Calendar,
        SearchIndex::Contacts,
    ] {
        clear_queued_updates(server, index, account_id).await?;
    }

    let mut batch = BatchBuilder::new();

    for document_id in server
        .get_cached_messages(account_id)
        .await
        .caused_by(trc::location!())?
        .emails
        .items
        .iter()
        .map(|v| v.document_id)
    {
        batch.queue_document_index(SearchIndex::Email, account_id, document_id);

        if batch.is_large_batch() {
            server.commit_batch(batch).await?;
            batch = BatchBuilder::new();
        }
    }

    for document_type in [SearchIndex::Calendar, SearchIndex::Contacts] {
        let cache = server
            .fetch_dav_resources(
                account_id,
                account_id,
                if document_type == SearchIndex::Calendar {
                    SyncCollection::Calendar
                } else {
                    SyncCollection::AddressBook
                },
            )
            .await
            .caused_by(trc::location!())?;

        for document_id in cache.document_ids(false) {
            batch.queue_document_index(document_type, account_id, document_id);

            if batch.is_large_batch() {
                server.commit_batch(batch).await?;
                batch = BatchBuilder::new();
            }
        }
    }

    if !batch.is_empty() {
        server.commit_batch(batch).await?;
    }

    Ok(())
}

async fn clear_queued_updates(
    server: &Server,
    index: SearchIndex,
    partition: u32,
) -> trc::Result<()> {
    let (from_class, to_class) = SearchIndexClass::queue_range(index, partition);
    let mut batch = BatchBuilder::new();
    batch.clear(SearchIndexClass::QueueStatus { index, partition });

    server
        .store()
        .iterate(
            IterateParams::new(
                ValueKey::from(ValueClass::SearchIndex(from_class)),
                ValueKey::from(ValueClass::SearchIndex(to_class)),
            )
            .ascending(),
            |key, value| {
                if value.first().is_some_and(|action| *action != 0) {
                    batch
                        .clear(SearchIndexClass::Queue {
                            index,
                            id_prefix: key.deserialize_be_u32(1)?,
                            id_suffix: QueueDocumentId::Assigned(
                                key.deserialize_be_u32(1 + U32_LEN)?,
                            ),
                            created_at: key.deserialize_be_u64(1 + (U32_LEN * 2))?,
                        })
                        .commit_point();
                }

                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;

    server
        .store()
        .write_batch(&mut batch)
        .await
        .caused_by(trc::location!())?;

    Ok(())
}

async fn clear_tracing_queue(server: &Server) -> trc::Result<()> {
    server
        .store()
        .delete_range(
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
                index: SearchIndex::Tracing,
                id_prefix: 0,
                id_suffix: QueueDocumentId::Assigned(0),
                created_at: 0,
            })),
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::Queue {
                index: SearchIndex::Tracing,
                id_prefix: u32::MAX,
                id_suffix: QueueDocumentId::Assigned(u32::MAX),
                created_at: u64::MAX,
            })),
        )
        .await
        .caused_by(trc::location!())?;

    server
        .store()
        .delete_range(
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::QueueIndex {
                index: SearchIndex::Tracing,
                partition: 0,
            })),
            ValueKey::from(ValueClass::SearchIndex(SearchIndexClass::QueueStatus {
                index: SearchIndex::Tracing,
                partition: u32::MAX,
            })),
        )
        .await
        .caused_by(trc::location!())
}
