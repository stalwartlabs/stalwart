/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::download::BlobDownload;
use calcard::{
    common::{
        blob::{BlobIdGenerator, BlobIdOutcome},
        export::{ExportError, ImportError},
    },
    icalendar::ICalendar,
    jscalendar::{
        JSCalendar, JSCalendarProperty, JSCalendarValue,
        export::ExportOptions as CalendarExportOptions, ext::JSCalendarPatch,
    },
    jscontact::{JSContact, JSContactProperty, export::ExportOptions as ContactExportOptions},
    vcard::VCard,
};
use common::{Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::{CalendarEventContent, privacy::EventPrivacy},
    contact::ContactCardContent,
};
use jmap_proto::error::set::{InvalidProperty, SetError};
use jmap_tools::{Key, Map, Property, Value};
use std::future::Future;
use store::{
    ValueKey,
    ahash::AHashMap,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{
    acl::Acl,
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    collection::{Collection, SyncCollection},
    field::{CalendarEventField, ContactField},
    id::Id,
};

#[derive(Debug, Clone, Copy)]
pub struct EmbeddedBlobIds {
    account_id: u32,
    collection: Collection,
    document_id: u32,
}

pub struct ResolvedBlobs(AHashMap<BlobId, Vec<u8>>);

pub enum EmbeddingError {
    NotFound(Vec<BlobId>),
    TooLarge { max_size: usize },
}

type EventMap<'x> = Map<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;
type EventValue<'x> = Value<'x, JSCalendarProperty<Id>, JSCalendarValue<Id, BlobId>>;

struct InstanceCopies<'a, 'x> {
    event: &'a EventMap<'x>,
    instances: usize,
}

pub trait EmbeddedBlobs: Sync + Send {
    fn embedded_blob(
        &self,
        blob_id: &BlobId,
    ) -> impl Future<Output = trc::Result<Option<Vec<u8>>>> + Send;

    fn resolve_blobs<'x>(
        &self,
        access_token: &AccessToken,
        blob_ids: impl Iterator<Item = &'x BlobId> + Send,
        max_size: usize,
    ) -> impl Future<Output = trc::Result<Result<ResolvedBlobs, EmbeddingError>>> + Send;

    fn has_access_embedded_blob(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: u8,
        document_id: u32,
    ) -> impl Future<Output = trc::Result<bool>> + Send;
}

pub trait EmbeddedExport: Sync + Send {
    fn export_icalendar(
        &self,
        access_token: &AccessToken,
        js_calendar: JSCalendar<'_, Id, BlobId>,
    ) -> impl Future<Output = trc::Result<Result<ICalendar, SetError<JSCalendarProperty<Id>>>>> + Send;

    fn export_vcard(
        &self,
        access_token: &AccessToken,
        js_contact: JSContact<'_, Id, BlobId>,
    ) -> impl Future<Output = trc::Result<Result<VCard, SetError<JSContactProperty<Id>>>>> + Send;
}

impl EmbeddedBlobIds {
    pub fn new(account_id: u32, collection: Collection, document_id: u32) -> Self {
        EmbeddedBlobIds {
            account_id,
            collection,
            document_id,
        }
    }

    fn blob_id(&self, data: &[u8]) -> BlobId {
        BlobId::new(
            BlobHash::generate(data),
            BlobClass::Embedded {
                account_id: self.account_id,
                collection: self.collection.into(),
                document_id: self.document_id,
            },
        )
    }
}

impl BlobIdGenerator<BlobId> for EmbeddedBlobIds {
    fn blob_id(&mut self, data: Vec<u8>, _: Option<&str>) -> BlobIdOutcome<BlobId> {
        BlobIdOutcome::Generated(EmbeddedBlobIds::blob_id(self, &data))
    }
}

impl ResolvedBlobs {
    pub fn take(&mut self, blob_id: &BlobId) -> Option<Vec<u8>> {
        self.0.remove(blob_id)
    }

    fn size<'x>(&self, blob_ids: impl Iterator<Item = &'x BlobId>) -> usize {
        blob_ids
            .filter_map(|blob_id| self.0.get(blob_id))
            .map(Vec::len)
            .fold(0, usize::saturating_add)
    }

    fn value_size(&self, value: &EventValue<'_>) -> usize {
        match value {
            Value::Element(JSCalendarValue::BlobId(blob_id)) => {
                self.0.get(blob_id).map_or(0, Vec::len)
            }
            Value::Str(text) => data_uri_size(text),
            Value::Array(values) => values
                .iter()
                .map(|value| self.value_size(value))
                .fold(0, usize::saturating_add),
            Value::Object(object) => object
                .values()
                .map(|value| self.value_size(value))
                .fold(0, usize::saturating_add),
            _ => 0,
        }
    }
}

impl<'a, 'x> InstanceCopies<'a, 'x> {
    fn of(js_calendar: &'a JSCalendar<'x, Id, BlobId>) -> Vec<Self> {
        js_calendar
            .0
            .as_object_and_get(&Key::Property(JSCalendarProperty::Entries))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
            .filter_map(|event| {
                let instances = event
                    .get(&Key::Property(JSCalendarProperty::RecurrenceOverrides))
                    .and_then(Value::as_object)?
                    .values()
                    .filter(|patch| patch.is_instance_patch())
                    .count();
                (instances > 0).then_some(InstanceCopies { event, instances })
            })
            .collect()
    }

    fn size(&self, resolved: &ResolvedBlobs) -> usize {
        self.event
            .iter()
            .filter(|(key, _)| {
                !matches!(key, Key::Property(JSCalendarProperty::RecurrenceOverrides))
            })
            .map(|(_, value)| resolved.value_size(value))
            .fold(0, usize::saturating_add)
            .saturating_mul(self.instances)
    }
}

impl EmbeddedBlobs for Server {
    async fn embedded_blob(&self, blob_id: &BlobId) -> trc::Result<Option<Vec<u8>>> {
        let BlobClass::Embedded {
            account_id,
            collection,
            document_id,
        } = blob_id.class
        else {
            return Ok(None);
        };

        match Collection::from(collection) {
            Collection::CalendarEvent => {
                let Some(archive) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::CalendarEvent,
                        document_id,
                        CalendarEventField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(None);
                };
                let content = archive
                    .unarchive::<CalendarEventContent>()
                    .caused_by(trc::location!())?;

                Ok(matching_binary(
                    content.data.event.blob_binaries(),
                    &blob_id.hash,
                ))
            }
            Collection::ContactCard => {
                let Some(archive) = self
                    .store()
                    .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                        account_id,
                        Collection::ContactCard,
                        document_id,
                        ContactField::Content,
                    ))
                    .await
                    .caused_by(trc::location!())?
                else {
                    return Ok(None);
                };
                let content = archive
                    .unarchive::<ContactCardContent>()
                    .caused_by(trc::location!())?;

                Ok(matching_binary(content.card.blob_binaries(), &blob_id.hash))
            }
            _ => Ok(None),
        }
    }

    async fn resolve_blobs<'x>(
        &self,
        access_token: &AccessToken,
        blob_ids: impl Iterator<Item = &'x BlobId> + Send,
        max_size: usize,
    ) -> trc::Result<Result<ResolvedBlobs, EmbeddingError>> {
        let mut resolved = AHashMap::new();
        let mut resolved_size = 0usize;
        let mut not_found = Vec::new();
        for blob_id in blob_ids {
            if resolved.contains_key(blob_id) || not_found.contains(blob_id) {
                continue;
            }
            match self.blob_download(blob_id, access_token).await? {
                Some(data) if !data.is_empty() => {
                    resolved_size = resolved_size.saturating_add(data.len());
                    if resolved_size > max_size {
                        return Ok(Err(EmbeddingError::TooLarge { max_size }));
                    }
                    resolved.insert(blob_id.clone(), data);
                }
                _ => not_found.push(blob_id.clone()),
            }
        }

        Ok(if not_found.is_empty() {
            Ok(ResolvedBlobs(resolved))
        } else {
            Err(EmbeddingError::NotFound(not_found))
        })
    }

    async fn has_access_embedded_blob(
        &self,
        access_token: &AccessToken,
        account_id: u32,
        collection: u8,
        document_id: u32,
    ) -> trc::Result<bool> {
        let collection @ (Collection::CalendarEvent | Collection::ContactCard) =
            Collection::from(collection)
        else {
            return Ok(false);
        };
        let resources = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::from(collection),
            )
            .await
            .caused_by(trc::location!())?;
        let Some(resource) = resources.item_by_id(document_id) else {
            return Ok(false);
        };

        Ok(if access_token.is_member(account_id) {
            true
        } else {
            resources
                .shared_items(access_token, [Acl::ReadItems], true)
                .contains(document_id)
                && resource
                    .event_flags()
                    .is_none_or(|flags| EventPrivacy::from_flags(flags).is_public())
        })
    }
}

impl EmbeddedExport for Server {
    async fn export_icalendar(
        &self,
        access_token: &AccessToken,
        js_calendar: JSCalendar<'_, Id, BlobId>,
    ) -> trc::Result<Result<ICalendar, SetError<JSCalendarProperty<Id>>>> {
        let max_instances = self.core.groupware.max_ical_instances;
        let instance_copies = InstanceCopies::of(&js_calendar);
        if instance_copies
            .iter()
            .map(|copies| copies.instances)
            .sum::<usize>()
            > max_instances
        {
            return Ok(Err(SetError::invalid_properties()
                .with_property(JSCalendarProperty::RecurrenceOverrides)
                .with_description(format!(
                    "An event cannot have more than {max_instances} recurrence overrides."
                ))));
        }

        let max_size = self.core.groupware.max_ical_size;
        let mut resolved = match self
            .resolve_blobs(access_token, js_calendar.blob_ids(), max_size)
            .await?
        {
            Ok(resolved) => resolved,
            Err(err) => return Ok(Err(err.into())),
        };
        if instance_copies
            .iter()
            .map(|copies| copies.size(&resolved))
            .fold(resolved.size(js_calendar.blob_ids()), usize::saturating_add)
            > max_size
        {
            return Ok(Err(EmbeddingError::TooLarge { max_size }.into()));
        }

        let ical = match js_calendar.into_icalendar_with_report(
            CalendarExportOptions::new()
                .max_expansions(max_instances)
                .max_embedded_size(max_size)
                .with_blob_resolver(|blob_id: &BlobId| resolved.take(blob_id)),
        ) {
            Ok((ical, rejected_patches)) => match rejected_patches.into_iter().next() {
                Some(rejected) => {
                    return Ok(Err(export_error(
                        ExportError::InvalidPatch {
                            recurrence_id: rejected.recurrence_id,
                            pointer: rejected.pointer,
                        },
                        "calendar event",
                        "iCalendar",
                    )));
                }
                None => ical,
            },
            Err(err) => return Ok(Err(export_error(err, "calendar event", "iCalendar"))),
        };

        Ok(assert_embedded_size(
            ical.embedded_size(),
            ical,
            self.core.groupware.max_attachments_size,
            "attachments",
        ))
    }

    async fn export_vcard(
        &self,
        access_token: &AccessToken,
        js_contact: JSContact<'_, Id, BlobId>,
    ) -> trc::Result<Result<VCard, SetError<JSContactProperty<Id>>>> {
        let max_size = self.core.groupware.max_vcard_size;
        let mut resolved = match self
            .resolve_blobs(access_token, js_contact.blob_ids(), max_size)
            .await?
        {
            Ok(resolved) => resolved,
            Err(err) => return Ok(Err(err.into())),
        };
        if resolved.size(js_contact.blob_ids()) > max_size {
            return Ok(Err(EmbeddingError::TooLarge { max_size }.into()));
        }

        let card = match js_contact.into_vcard_with(
            ContactExportOptions::new()
                .max_embedded_size(max_size)
                .with_blob_resolver(|blob_id: &BlobId| resolved.take(blob_id)),
        ) {
            Ok(card) => card,
            Err(err) => return Ok(Err(export_error(err, "contact", "vCard"))),
        };

        Ok(assert_embedded_size(
            card.embedded_size(),
            card,
            self.core.groupware.max_media_size,
            "media",
        ))
    }
}

impl<P: Property> From<EmbeddingError> for SetError<P> {
    fn from(err: EmbeddingError) -> Self {
        match err {
            EmbeddingError::NotFound(not_found) => SetError::invalid_properties().with_description(
                unresolved_description(not_found.iter().map(BlobId::to_string)),
            ),
            EmbeddingError::TooLarge { max_size } => {
                SetError::too_large().with_description(format!(
                    "The embedded binaries exceed the maximum object size of {max_size} bytes."
                ))
            }
        }
    }
}

fn export_error<P: Property>(err: ExportError, object: &str, format: &str) -> SetError<P> {
    match err {
        ExportError::EmbeddedSizeExceeded { max } => SetError::too_large().with_description(
            format!("The embedded binaries exceed the maximum object size of {max} bytes."),
        ),
        ExportError::UnresolvedBlob { blob_id } => {
            SetError::invalid_properties().with_description(unresolved_description([blob_id]))
        }
        ExportError::InvalidPatch {
            recurrence_id,
            pointer,
        } => SetError::invalid_properties()
            .with_property(InvalidProperty::Path(vec![
                Key::Owned("recurrenceOverrides".to_string()),
                Key::Owned(escape_pointer_token(recurrence_id)),
                Key::Owned(escape_pointer_token(pointer)),
            ]))
            .with_description("The patch object could not be applied to the recurrence override."),
        err => SetError::invalid_properties()
            .with_description(format!("Failed to convert {object} to {format}: {err}.")),
    }
}

fn unresolved_description(blob_ids: impl IntoIterator<Item = String>) -> String {
    let mut description =
        String::from("The following blobIds do not exist or are not accessible: ");
    for (pos, blob_id) in blob_ids.into_iter().enumerate() {
        if pos > 0 {
            description.push_str(", ");
        }
        description.push_str(&blob_id);
    }
    description.push('.');
    description
}

fn matching_binary<'x>(
    mut binaries: impl Iterator<Item = &'x [u8]>,
    hash: &BlobHash,
) -> Option<Vec<u8>> {
    binaries
        .find(|data| &BlobHash::generate(data) == hash)
        .map(<[u8]>::to_vec)
}

pub fn import_error(err: ImportError) -> trc::Error {
    trc::StoreEvent::UnexpectedError
        .caused_by(trc::location!())
        .reason(err)
        .details("Failed to generate a blob id for an embedded binary.")
}

fn escape_pointer_token(token: String) -> String {
    if !token.contains(['~', '/']) {
        return token;
    }
    let mut escaped = String::with_capacity(token.len() + 8);
    for ch in token.chars() {
        match ch {
            '~' => escaped.push_str("~0"),
            '/' => escaped.push_str("~1"),
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn data_uri_size(text: &str) -> usize {
    let Some((header, data)) = text.split_once(',').filter(|(header, _)| {
        header
            .as_bytes()
            .get(..5)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"data:"))
    }) else {
        return 0;
    };

    if header
        .rsplit_once(';')
        .is_some_and(|(_, encoding)| encoding.eq_ignore_ascii_case("base64"))
    {
        data.trim_end_matches('=').len().saturating_mul(3) / 4
    } else {
        data.len()
    }
}

fn assert_embedded_size<T, P: Property>(
    size: usize,
    object: T,
    max_size: usize,
    kind: &str,
) -> Result<T, SetError<P>> {
    if max_size == 0 || size <= max_size {
        Ok(object)
    } else {
        Err(SetError::too_large().with_description(format!(
            "The size of the embedded {kind} ({size} bytes) exceeds the maximum of {max_size} bytes."
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn instance_copies_multiply_series_binaries() {
        let series = BlobId::new(BlobHash::generate(b"series"), BlobClass::default());
        let instance = BlobId::new(BlobHash::generate(b"instance"), BlobClass::default());
        let resolved = ResolvedBlobs(AHashMap::from_iter([
            (series.clone(), vec![0; 100]),
            (instance.clone(), vec![0; 10]),
        ]));
        let json = json!({
            "@type": "Group",
            "entries": [{
                "@type": "Event",
                "uid": "copies",
                "start": "2030-01-01T09:00:00",
                "timeZone": "Etc/UTC",
                "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily"},
                "links": {
                    "series": {"@type": "Link", "blobId": series.to_string()}
                },
                "recurrenceOverrides": {
                    "2030-01-02T09:00:00": {"title": "Moved"},
                    "2030-01-03T09:00:00": {"excluded": true},
                    "2030-01-04T09:00:00": {},
                    "2030-01-05T09:00:00": {
                        "links/instance": {"@type": "Link", "blobId": instance.to_string()}
                    }
                }
            }]
        })
        .to_string();
        let js_calendar = JSCalendar::<Id, BlobId>::parse(&json).expect("valid JSCalendar");
        let copies = InstanceCopies::of(&js_calendar);

        assert_eq!(
            copies.iter().map(|copies| copies.instances).sum::<usize>(),
            2
        );
        assert_eq!(
            copies
                .iter()
                .map(|copies| copies.size(&resolved))
                .sum::<usize>(),
            200
        );
        assert_eq!(resolved.size(js_calendar.blob_ids()), 110);
    }

    #[test]
    fn instance_copies_count_data_hrefs() {
        let resolved = ResolvedBlobs(AHashMap::new());
        let json = json!({
            "@type": "Group",
            "entries": [{
                "@type": "Event",
                "uid": "copies",
                "start": "2030-01-01T09:00:00",
                "timeZone": "Etc/UTC",
                "recurrenceRule": {"@type": "RecurrenceRule", "frequency": "daily"},
                "links": {
                    "series": {
                        "@type": "Link",
                        "href": "data:text/plain;base64,AAECAwQFBgcICQoLDA0ODw==",
                        "rel": "enclosure"
                    },
                    "remote": {"@type": "Link", "href": "https://example.com/a.pdf"}
                },
                "recurrenceOverrides": {
                    "2030-01-02T09:00:00": {"title": "Moved"},
                    "2030-01-03T09:00:00": {"title": "Moved again"}
                }
            }]
        })
        .to_string();
        let js_calendar = JSCalendar::<Id, BlobId>::parse(&json).expect("valid JSCalendar");

        assert_eq!(
            InstanceCopies::of(&js_calendar)
                .iter()
                .map(|copies| copies.size(&resolved))
                .sum::<usize>(),
            32
        );
    }

    #[test]
    fn data_uri_sizes_are_estimated_from_base64() {
        assert_eq!(data_uri_size("data:text/plain;base64,AAECAwQ="), 5);
        assert_eq!(data_uri_size("data:text/plain;BASE64,AAECAwQFBgc="), 8);
        assert_eq!(data_uri_size("data:;base64,AAEC"), 3);
        assert_eq!(data_uri_size("DATA:,hello"), 5);
        assert_eq!(data_uri_size("data:text/plain,hello"), 5);
        assert_eq!(data_uri_size("https://example.com/a.pdf"), 0);
        assert_eq!(data_uri_size("data:"), 0);
    }

    #[test]
    fn invalid_patch_property_path_is_escaped() {
        let error: SetError<JSCalendarProperty<Id>> = export_error(
            ExportError::InvalidPatch {
                recurrence_id: "2030-01-02T09:00:00".to_string(),
                pointer: "participants/zoe/participationStatus".to_string(),
            },
            "calendar event",
            "iCalendar",
        );

        assert_eq!(
            serde_json::to_value(&error).expect("serializable")["properties"],
            json!([
                "recurrenceOverrides/2030-01-02T09:00:00/participants~1zoe~1participationStatus"
            ])
        );
    }
}
