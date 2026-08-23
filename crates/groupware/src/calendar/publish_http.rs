/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::icalendar::{
    ICalendar, ICalendarComponentType, ICalendarEntry, ICalendarProperty, ICalendarValue,
};
use common::{DavResource, Server};
use directory::core::secret::{hash_secret, verify_secret_hash};
use crate::cache::GroupwareCache;
use registry::schema::enums::PasswordHashAlgorithm;
use store::{
    Deserialize, IterateParams, Serialize, SerializeInfallible, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, ValueClass, now},
};
use trc::AddContext;
use types::{TimeRange, collection::Collection, collection::SyncCollection};

use super::publish_link::{
    CalendarPublishLink, FEED_FUTURE_SECONDS, FEED_PAST_SECONDS, LAST_USED_DEBOUNCE_SECONDS,
    PublishAccess, PublishLinkSecret, PublishVisibility, format_uuid, parse_uuid,
};

pub trait CalendarPublishStore: Sync + Send {
    fn get_publish_link(
        &self,
        account_id: u32,
        link_id: [u8; 16],
    ) -> impl Future<Output = trc::Result<Option<CalendarPublishLink>>> + Send;

    fn lookup_publish_link_account(
        &self,
        link_id: [u8; 16],
    ) -> impl Future<Output = trc::Result<Option<u32>>> + Send;

    fn verify_publish_link_access(
        &self,
        link_id: [u8; 16],
        secret: Option<&str>,
        is_public: bool,
    ) -> impl Future<Output = trc::Result<(u32, CalendarPublishLink)>> + Send;

    fn export_calendar_publish_feed(
        &self,
        account_id: u32,
        link: &CalendarPublishLink,
    ) -> impl Future<Output = trc::Result<String>> + Send;

    fn store_publish_link(
        &self,
        batch: &mut BatchBuilder,
        account_id: u32,
        link: &CalendarPublishLink,
    ) -> trc::Result<()>;

    fn list_publish_links(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<Vec<CalendarPublishLink>>> + Send;

    fn build_publish_url(&self, link: &CalendarPublishLink, secret: Option<&str>) -> String;

    fn touch_publish_link_if_stale(
        &self,
        account_id: u32,
        link: &CalendarPublishLink,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

pub fn clear_publish_link(batch: &mut BatchBuilder, account_id: u32, link_id: [u8; 16]) {
    batch.clear(ValueClass::CalendarPublishLink {
        link_id,
        account_id,
    });
    batch.clear(ValueClass::CalendarPublishLinkLookup { link_id });
}

fn not_found() -> trc::Error {
    trc::ResourceEvent::NotFound.into_err()
}

impl CalendarPublishStore for Server {
    async fn get_publish_link(
        &self,
        account_id: u32,
        link_id: [u8; 16],
    ) -> trc::Result<Option<CalendarPublishLink>> {
        let value = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::from(ValueClass::CalendarPublishLink {
                link_id,
                account_id,
            }))
            .await
            .caused_by(trc::location!())?;
        value
            .map(|archive| archive.deserialize::<CalendarPublishLink>())
            .transpose()
    }

    async fn lookup_publish_link_account(&self, link_id: [u8; 16]) -> trc::Result<Option<u32>> {
        self.store()
            .get_value::<u32>(ValueKey::from(ValueClass::CalendarPublishLinkLookup { link_id }))
            .await
            .caused_by(trc::location!())
    }

    async fn verify_publish_link_access(
        &self,
        link_id: [u8; 16],
        secret: Option<&str>,
        is_public: bool,
    ) -> trc::Result<(u32, CalendarPublishLink)> {
        let account_id = self
            .lookup_publish_link_account(link_id)
            .await?
            .ok_or_else(not_found)?;
        let link = self
            .get_publish_link(account_id, link_id)
            .await?
            .ok_or_else(not_found)?;

        if is_public && link.access != PublishAccess::Public {
            return Err(not_found());
        }
        if !is_public {
            if link.access != PublishAccess::Private {
                return Err(not_found());
            }
            let Some(secret_hash) = &link.secret_hash else {
                return Err(not_found());
            };
            let provided = secret.ok_or_else(not_found)?;
            if !verify_secret_hash(secret_hash, provided.as_bytes()).await? {
                return Err(not_found());
            }
        }

        let now_ts = now() as i64;
        if let Some(expires) = link.expires_at
            && expires <= now_ts
        {
            return Err(not_found());
        }

        Ok((account_id, link))
    }

    async fn export_calendar_publish_feed(
        &self,
        account_id: u32,
        link: &CalendarPublishLink,
    ) -> trc::Result<String> {
        let resources = self
            .fetch_dav_resources(account_id, account_id, SyncCollection::Calendar)
            .await
            .caused_by(trc::location!())?;
        let calendar_id = link.calendar_id;
        if !resources.has_container_id(&calendar_id) {
            return Err(not_found());
        }

        let now_ts = now() as i64;
        let range = TimeRange {
            start: now_ts - FEED_PAST_SECONDS,
            end: now_ts + FEED_FUTURE_SECONDS,
        };

        let mut ical = ICalendar {
            components: vec![calcard::icalendar::ICalendarComponent {
                component_type: ICalendarComponentType::VCalendar,
                entries: vec![
                    ICalendarEntry {
                        name: ICalendarProperty::Version,
                        params: vec![],
                        values: vec![ICalendarValue::Text("2.0".to_string())],
                    },
                    ICalendarEntry {
                        name: ICalendarProperty::Prodid,
                        params: vec![],
                        values: vec![ICalendarValue::Text(
                            "-//Stalwart Labs LLC//Stalwart//EN".to_string(),
                        )],
                    },
                ],
                component_ids: vec![],
            }],
        };

        for resource in resources.children(calendar_id) {
            if !is_resource_in_time_range(resource.resource, &range) {
                continue;
            }
            let event_ = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::CalendarEvent,
                    resource.document_id(),
                ))
                .await
                .caused_by(trc::location!())?;
            if let Some(event_) = event_ {
                let event = event_
                    .deserialize::<super::CalendarEvent>()
                    .caused_by(trc::location!())?;
                let mut event_ical = event.data.event;
                apply_publish_visibility(&mut event_ical, link.visibility);
                merge_events_into_calendar(&mut ical, &event_ical);
            }
        }

        Ok(ical.to_string())
    }

    fn store_publish_link(
        &self,
        batch: &mut BatchBuilder,
        account_id: u32,
        link: &CalendarPublishLink,
    ) -> trc::Result<()> {
        let archive = Archiver::new(link.clone());
        batch.set(
            ValueClass::CalendarPublishLink {
                link_id: link.link_id,
                account_id,
            },
            archive.serialize()?,
        );
        batch.set(
            ValueClass::CalendarPublishLinkLookup {
                link_id: link.link_id,
            },
            account_id.serialize(),
        );
        Ok(())
    }

    async fn list_publish_links(
        &self,
        account_id: u32,
    ) -> trc::Result<Vec<CalendarPublishLink>> {
        let begin = ValueKey::from(ValueClass::CalendarPublishLink {
            link_id: [0u8; 16],
            account_id,
        });
        let end = ValueKey::from(ValueClass::CalendarPublishLink {
            link_id: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            account_id,
        });
        let mut links = Vec::new();
        self.store()
            .iterate(
                IterateParams::new(begin, end).ascending(),
                |_, value| {
                    let archive =
                        <Archive<AlignedBytes> as Deserialize>::deserialize(value)
                            .caused_by(trc::location!())?;
                    links.push(
                        archive
                            .deserialize::<CalendarPublishLink>()
                            .caused_by(trc::location!())?,
                    );
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;
        Ok(links)
    }

    fn build_publish_url(&self, link: &CalendarPublishLink, secret: Option<&str>) -> String {
        let base = if let Some(url) = &self.core.groupware.itip_http_rsvp_url {
            url.replace("/calendar/rsvp", "")
                .trim_end_matches('/')
                .to_string()
        } else {
            format!("https://{}", self.core.email.default_domain_name.as_str())
        };
        let id = format_uuid(&link.link_id);
        match link.access {
            PublishAccess::Public => format!("{base}/ics/public/{id}.ics"),
            PublishAccess::Private => {
                if let Some(secret) = secret {
                    format!("{base}/ics/{id}/{secret}.ics")
                } else {
                    format!("{base}/ics/{id}/")
                }
            }
        }
    }

    async fn touch_publish_link_if_stale(
        &self,
        account_id: u32,
        link: &CalendarPublishLink,
    ) -> trc::Result<()> {
        let now_ts = now() as i64;
        if link
            .last_used_at
            .is_none_or(|t| now_ts - t >= LAST_USED_DEBOUNCE_SECONDS)
        {
            let mut updated = link.clone();
            updated.last_used_at = Some(now_ts);
            let mut batch = BatchBuilder::new();
            self.store_publish_link(&mut batch, account_id, &updated)?;
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }
        Ok(())
    }
}

pub fn parse_ics_http_path(path: &str) -> trc::Result<([u8; 16], Option<String>, bool)> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() == 2 && parts[0] == "public" {
        let link_id = parse_uuid(parts[1]).ok_or_else(not_found)?;
        return Ok((link_id, None, true));
    }
    if parts.len() == 2 {
        let link_id = parse_uuid(parts[0]).ok_or_else(not_found)?;
        let secret = parts[1]
            .strip_suffix(".ics")
            .unwrap_or(parts[1])
            .to_string();
        return Ok((link_id, Some(secret), false));
    }
    Err(not_found())
}

fn is_resource_in_time_range(resource: &DavResource, filter: &TimeRange) -> bool {
    if let Some((start, end)) = resource.event_time_range() {
        ((filter.start < end) || (filter.start <= start)) && (filter.end > start || filter.end >= end)
    } else {
        false
    }
}

fn merge_events_into_calendar(target: &mut ICalendar, source: &ICalendar) {
    let mut push_vevent = |component: &calcard::icalendar::ICalendarComponent| {
        if component.component_type != ICalendarComponentType::VEvent {
            return;
        }
        let new_id = target.components.len() as u32;
        target.components.push(component.clone());
        if let Some(vcal) = target
            .components
            .first_mut()
            .filter(|c| c.component_type == ICalendarComponentType::VCalendar)
        {
            vcal.component_ids.push(new_id);
        }
    };

    for component in &source.components {
        if component.component_type == ICalendarComponentType::VCalendar {
            for child_id in &component.component_ids {
                if let Some(child) = source.components.get(*child_id as usize) {
                    push_vevent(child);
                }
            }
        } else {
            push_vevent(component);
        }
    }
}

fn apply_publish_visibility(ical: &mut ICalendar, visibility: PublishVisibility) {
    for component in &mut ical.components {
        if component.component_type != ICalendarComponentType::VEvent {
            continue;
        }
        let is_private = component.entries.iter().any(|entry| {
            entry.name == ICalendarProperty::Class
                && entry
                    .values
                    .first()
                    .is_some_and(|v| matches!(v, ICalendarValue::Text(t) if t.eq_ignore_ascii_case("PRIVATE")))
        });
        if visibility == PublishVisibility::Busy || is_private {
            redact_event_to_busy(component);
        }
    }
}

fn redact_event_to_busy(component: &mut calcard::icalendar::ICalendarComponent) {
    component.entries.retain(|entry| {
        !matches!(
            entry.name,
            ICalendarProperty::Location
                | ICalendarProperty::Description
                | ICalendarProperty::Attendee
                | ICalendarProperty::Organizer
                | ICalendarProperty::Url
        )
    });
    component.component_ids.clear();
    if let Some(summary) = component
        .entries
        .iter_mut()
        .find(|e| e.name == ICalendarProperty::Summary)
    {
        summary.values = vec![ICalendarValue::Text("Busy".to_string())];
    } else {
        component.entries.push(ICalendarEntry {
            name: ICalendarProperty::Summary,
            params: vec![],
            values: vec![ICalendarValue::Text("Busy".to_string())],
        });
    }
}

pub async fn create_publish_link_secret() -> (PublishLinkSecret, String) {
    let secret = PublishLinkSecret::new();
    let token = secret.build();
    let hash = hash_secret(PasswordHashAlgorithm::Argon2id, token.as_bytes().to_vec())
        .await
        .expect("hash failed");
    (secret, hash)
}
