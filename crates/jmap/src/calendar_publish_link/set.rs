/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use groupware::{
    cache::GroupwareCache,
    calendar::publish_link::{
        CalendarPublishLink, MAX_PRIVATE_LINKS_PER_CALENDAR, MAX_PUBLIC_LINKS_PER_CALENDAR,
        PublishAccess, PublishVisibility,
    },
    calendar::publish_http::{CalendarPublishStore, clear_publish_link, create_publish_link_secret},
};
use jmap_proto::{
    error::set::SetError,
    method::set::{SetRequest, SetResponse},
    object::{
        JmapObjectId,
        calendar_publish_link::{
            self, CalendarPublishLinkProperty, CalendarPublishLinkValue, PublishAccess as JmapAccess,
            PublishVisibility as JmapVisibility,
        },
    },
    request::MaybeInvalid,
};
use jmap_tools::{Key, Map, Value};
use store::write::{BatchBuilder, now};
use trc::AddContext;
use types::{acl::Acl, collection::SyncCollection, id::Id};
use utils::map::bitmap::Bitmap;

pub trait CalendarPublishLinkSet: Sync + Send {
    fn calendar_publish_link_set(
        &self,
        request: SetRequest<'_, calendar_publish_link::CalendarPublishLink>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<calendar_publish_link::CalendarPublishLink>>> + Send;
}

impl CalendarPublishLinkSet for Server {
    async fn calendar_publish_link_set(
        &self,
        mut request: SetRequest<'_, calendar_publish_link::CalendarPublishLink>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<calendar_publish_link::CalendarPublishLink>> {
        let account_id = request.account_id.document_id();
        let mut response =
            SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;
        let will_destroy = response.collect_will_destroy(request.unwrap_destroy());
        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let existing_links = self.list_publish_links(account_id).await?;
        let mut next_document_id = existing_links
            .iter()
            .map(|l| l.document_id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let mut batch = BatchBuilder::new();

        'create: for (id, object) in request.unwrap_create() {
            let mut calendar_id = None;
            let mut access = PublishAccess::Private;
            let mut visibility = PublishVisibility::Full;
            let mut label = None;
            let mut expires_at = None;

            for (property, value) in object.into_expanded_object() {
                match property {
                    Key::Property(CalendarPublishLinkProperty::CalendarId) => {
                        calendar_id = value
                            .into_element()
                            .and_then(|e| e.as_id())
                            .map(|id| id.document_id());
                    }
                    Key::Property(CalendarPublishLinkProperty::Access) => {
                        access = match value.into_element() {
                            Some(CalendarPublishLinkValue::Access(JmapAccess::Public)) => {
                                PublishAccess::Public
                            }
                            _ => PublishAccess::Private,
                        };
                    }
                    Key::Property(CalendarPublishLinkProperty::Visibility) => {
                        visibility = match value.into_element() {
                            Some(CalendarPublishLinkValue::Visibility(JmapVisibility::Busy)) => {
                                PublishVisibility::Busy
                            }
                            _ => PublishVisibility::Full,
                        };
                    }
                    Key::Property(CalendarPublishLinkProperty::Label) => {
                        label = value.into_string().map(|s| s.into_owned());
                    }
                    Key::Property(CalendarPublishLinkProperty::ExpiresAt) => {
                        expires_at = value.into_element().and_then(|e| match e {
                            CalendarPublishLinkValue::Date(d) => Some(d.timestamp()),
                            _ => None,
                        });
                    }
                    Key::Property(CalendarPublishLinkProperty::Secret) => {
                        response.not_created.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(CalendarPublishLinkProperty::Secret)
                                .with_description("Secret cannot be set on create."),
                        );
                        continue 'create;
                    }
                    _ => {}
                }
            }

            let Some(calendar_id) = calendar_id else {
                response.not_created.append(
                    id,
                    SetError::invalid_properties()
                        .with_property(CalendarPublishLinkProperty::CalendarId),
                );
                continue 'create;
            };

            if let Err(err) =
                assert_calendar_publish_acl(access_token, account_id, calendar_id, &cache)
            {
                response.not_created.append(id, err);
                continue 'create;
            }

            let calendar_links: Vec<_> = existing_links
                .iter()
                .filter(|l| l.calendar_id == calendar_id)
                .collect();
            let private_count = calendar_links
                .iter()
                .filter(|l| l.access == PublishAccess::Private)
                .count();
            let public_count = calendar_links
                .iter()
                .filter(|l| l.access == PublishAccess::Public)
                .count();

            if access == PublishAccess::Private && private_count >= MAX_PRIVATE_LINKS_PER_CALENDAR
            {
                response.not_created.append(
                    id,
                    SetError::forbidden()
                        .with_description("Maximum private publish links reached for calendar."),
                );
                continue 'create;
            }
            if access == PublishAccess::Public {
                if public_count >= MAX_PUBLIC_LINKS_PER_CALENDAR {
                    response.not_created.append(
                        id,
                        SetError::forbidden()
                            .with_description("Maximum public publish links reached for calendar."),
                    );
                    continue 'create;
                }
                if calendar_links
                    .iter()
                    .any(|l| l.access == PublishAccess::Public && l.visibility == visibility)
                {
                    response.not_created.append(
                        id,
                        SetError::forbidden()
                            .with_description("A public link with this visibility already exists."),
                    );
                    continue 'create;
                }
            }

            let (secret_token, secret_hash) = if access == PublishAccess::Private {
                let (secret, hash) = create_publish_link_secret().await;
                (Some(secret.build()), Some(hash))
            } else {
                (None, None)
            };

            let document_id = next_document_id;
            next_document_id = next_document_id.saturating_add(1);

            let link = CalendarPublishLink::new(
                document_id,
                calendar_id,
                access,
                visibility,
                label,
                secret_hash,
                now() as i64,
                expires_at,
            );
            self.store_publish_link(&mut batch, account_id, &link)?;
            let url = self.build_publish_url(&link, secret_token.as_deref());
            let mut created = Map::with_capacity(4);
            created.insert_unchecked(
                CalendarPublishLinkProperty::Id,
                Value::Element(CalendarPublishLinkValue::Id(Id::from(document_id))),
            );
            created.insert_unchecked(CalendarPublishLinkProperty::Url, Value::Str(url.into()));
            if let Some(secret) = secret_token {
                created.insert_unchecked(
                    CalendarPublishLinkProperty::Secret,
                    Value::Str(secret.into()),
                );
            }
            response.created.insert(id, Value::Object(created));
        }

        'update: for (id, object) in request.unwrap_update() {
            let id = match id {
                MaybeInvalid::Value(id) => id,
                invalid => {
                    response.not_updated.append(invalid, SetError::not_found());
                    continue 'update;
                }
            };
            if will_destroy.contains(&id) {
                response.not_updated.append(id, SetError::will_destroy());
                continue 'update;
            }

            let document_id = id.document_id();
            let mut link = match existing_links
                .iter()
                .find(|l| l.document_id == document_id)
                .cloned()
            {
                Some(link) => link,
                None => {
                    response.not_updated.append(id, SetError::not_found());
                    continue 'update;
                }
            };

            if let Err(err) =
                assert_calendar_publish_acl(access_token, account_id, link.calendar_id, &cache)
            {
                response.not_updated.append(id, err);
                continue 'update;
            }

            for (property, value) in object.into_expanded_object() {
                match property {
                    Key::Property(CalendarPublishLinkProperty::Secret) => {
                        response.not_updated.append(
                            id,
                            SetError::invalid_properties()
                                .with_property(CalendarPublishLinkProperty::Secret)
                                .with_description("Secret cannot be updated."),
                        );
                        continue 'update;
                    }
                    Key::Property(CalendarPublishLinkProperty::Label) => {
                        link.label = value.into_string().map(|s| s.into_owned());
                    }
                    Key::Property(CalendarPublishLinkProperty::Visibility) => {
                        link.visibility = match value.into_element() {
                            Some(CalendarPublishLinkValue::Visibility(JmapVisibility::Busy)) => {
                                PublishVisibility::Busy
                            }
                            _ => PublishVisibility::Full,
                        };
                    }
                    Key::Property(CalendarPublishLinkProperty::ExpiresAt) => {
                        link.expires_at = value.into_element().and_then(|e| match e {
                            CalendarPublishLinkValue::Date(d) => Some(d.timestamp()),
                            _ => None,
                        });
                    }
                    _ => {}
                }
            }
            self.store_publish_link(&mut batch, account_id, &link)?;
            response.updated.append(id, None);
        }

        for id in will_destroy {
            let document_id = id.document_id();
            if let Some(link) = existing_links
                .iter()
                .find(|l| l.document_id == document_id)
            {
                if let Err(err) = assert_calendar_publish_acl(
                    access_token,
                    account_id,
                    link.calendar_id,
                    &cache,
                ) {
                    response.not_destroyed.append(id, err);
                    continue;
                }
                clear_publish_link(&mut batch, account_id, link.link_id);
                response.destroyed.push(id);
            } else {
                response.not_destroyed.append(id, SetError::not_found());
            }
        }

        if !batch.is_empty() {
            self.commit_batch(batch).await.caused_by(trc::location!())?;
        }

        Ok(response)
    }
}

fn assert_calendar_publish_acl(
    access_token: &AccessToken,
    account_id: u32,
    calendar_id: u32,
    cache: &common::DavResources,
) -> Result<(), SetError<CalendarPublishLinkProperty>> {
    if !cache.has_container_id(&calendar_id) {
        return Err(SetError::not_found());
    }
    if access_token.is_member(account_id) {
        return Ok(());
    }
    let required = Bitmap::from_iter([Acl::ModifyItems, Acl::Modify]);
    if cache.has_access_to_container(access_token, calendar_id, required) {
        Ok(())
    } else {
        Err(SetError::forbidden().with_description(
            "Write or admin access to the calendar is required.",
        ))
    }
}
