/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use email::message::metadata::MessageMetadata;
use groupware::{calendar::CalendarEvent, contact::ContactCard};
use store::{
    ValueKey,
    search::IndexDocument,
    write::{Archive, ArchiveBytes, SearchIndex},
};
use trc::AddContext;
use types::{collection::Collection, field::EmailField};

pub(crate) async fn build_email_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Email) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::immutable(
            account_id,
            Collection::Email,
            document_id,
            EmailField::Metadata,
        ))
        .await?
    {
        Some(metadata_) => {
            let metadata = metadata_
                .unarchive::<MessageMetadata>()
                .caused_by(trc::location!())?;

            let raw_message = server
                .blob_store()
                .get_blob(metadata.blob_hash.0.as_slice(), 0..usize::MAX)
                .await
                .caused_by(trc::location!())?
                .ok_or_else(|| {
                    trc::StoreEvent::NotFound
                        .into_err()
                        .details("Blob not found")
                })?;

            Ok(Some(metadata.index_document(
                account_id,
                document_id,
                &raw_message,
                index_fields,
                server.core.email.default_language,
            )))
        }
        None => Ok(None),
    }
}

pub(crate) async fn build_calendar_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Calendar) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::CalendarEvent,
            document_id,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<CalendarEvent>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(None),
    }
}

pub(crate) async fn build_contact_document(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<IndexDocument>> {
    let Some(index_fields) = server.core.email.index_fields.get(&SearchIndex::Contacts) else {
        return Ok(None);
    };

    match server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
            account_id,
            Collection::ContactCard,
            document_id,
        ))
        .await?
    {
        Some(metadata_) => Ok(Some(
            metadata_
                .unarchive::<ContactCard>()
                .caused_by(trc::location!())?
                .index_document(
                    account_id,
                    document_id,
                    index_fields,
                    server.core.email.default_language,
                ),
        )),
        None => Ok(None),
    }
}

// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL

#[cfg(feature = "enterprise")]
pub(crate) async fn build_tracing_span_document(
    server: &Server,
    span_id: u64,
) -> trc::Result<Option<IndexDocument>> {
    use common::telemetry::tracers::store::build_span_document;
    use registry::schema::structs::Trace;
    use store::write::{TelemetryClass, ValueClass};

    server
        .tracing_store()
        .get_value::<Trace>(ValueKey::from(ValueClass::Telemetry(TelemetryClass::Span(
            span_id,
        ))))
        .await
        .map(|trace| trace.map(|trace| build_span_document(span_id, trace)))
}

// SPDX-SnippetEnd

#[cfg(not(feature = "enterprise"))]
pub(crate) async fn build_tracing_span_document(
    _: &Server,
    _: u64,
) -> trc::Result<Option<IndexDocument>> {
    Ok(None)
}
