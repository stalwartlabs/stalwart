/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use groupware::{cache::GroupwareCache, calendar::publish_http::CalendarPublishStore};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::calendar_publish_link::{
        self, CalendarPublishLinkProperty, CalendarPublishLinkValue, PublishAccess,
        PublishVisibility,
    },
    request::MaybeInvalid,
};
use jmap_tools::{Map, Value};
use types::{collection::SyncCollection, id::Id};

use super::set::assert_calendar_publish_acl;

pub trait CalendarPublishLinkGet: Sync + Send {
    fn calendar_publish_link_get(
        &self,
        request: GetRequest<calendar_publish_link::CalendarPublishLink>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<calendar_publish_link::CalendarPublishLink>>> + Send;
}

impl CalendarPublishLinkGet for Server {
    async fn calendar_publish_link_get(
        &self,
        mut request: GetRequest<calendar_publish_link::CalendarPublishLink>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<calendar_publish_link::CalendarPublishLink>> {
        let properties = request.unwrap_properties(&[
            CalendarPublishLinkProperty::Id,
            CalendarPublishLinkProperty::CalendarId,
            CalendarPublishLinkProperty::Access,
            CalendarPublishLinkProperty::Visibility,
            CalendarPublishLinkProperty::Label,
            CalendarPublishLinkProperty::Url,
            CalendarPublishLinkProperty::CreatedAt,
            CalendarPublishLinkProperty::LastUsedAt,
            CalendarPublishLinkProperty::ExpiresAt,
        ]);

        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let account_id = request.account_id.document_id();

        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::Calendar,
            )
            .await?;
        let links: Vec<_> = self
            .list_publish_links(account_id)
            .await?
            .into_iter()
            .filter(|link| {
                assert_calendar_publish_acl(access_token, account_id, link.calendar_id, &cache)
                    .is_ok()
            })
            .collect();

        let ids = if let Some(ids) = ids {
            ids
        } else {
            links
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(|link| Id::from(link.document_id))
                .collect::<Vec<_>>()
        };

        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        for id in ids {
            let document_id = id.document_id();
            if let Some(link) = links.iter().find(|l| l.document_id == document_id) {
                response.list.push(build_publish_link_object(
                    link,
                    &properties,
                    self.build_publish_url(link, None),
                ));
            } else {
                response.not_found.push(MaybeInvalid::Value(id));
            }
        }

        Ok(response)
    }
}

fn build_publish_link_object(
    link: &groupware::calendar::publish_link::CalendarPublishLink,
    properties: &[CalendarPublishLinkProperty],
    url: String,
) -> Value<'static, CalendarPublishLinkProperty, CalendarPublishLinkValue> {
    let mut result = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            CalendarPublishLinkProperty::Id => {
                Value::Element(CalendarPublishLinkValue::Id(Id::from(link.document_id)))
            }
            CalendarPublishLinkProperty::CalendarId => Value::Element(
                CalendarPublishLinkValue::CalendarId(Id::from(link.calendar_id)),
            ),
            CalendarPublishLinkProperty::Access => Value::Element(
                CalendarPublishLinkValue::Access(match link.access {
                    groupware::calendar::publish_link::PublishAccess::Public => PublishAccess::Public,
                    groupware::calendar::publish_link::PublishAccess::Private => {
                        PublishAccess::Private
                    }
                }),
            ),
            CalendarPublishLinkProperty::Visibility => Value::Element(
                CalendarPublishLinkValue::Visibility(match link.visibility {
                    groupware::calendar::publish_link::PublishVisibility::Full => {
                        PublishVisibility::Full
                    }
                    groupware::calendar::publish_link::PublishVisibility::Busy => {
                        PublishVisibility::Busy
                    }
                }),
            ),
            CalendarPublishLinkProperty::Label => {
                Value::Str(link.label.clone().unwrap_or_default().into())
            }
            CalendarPublishLinkProperty::Url => Value::Str(url.clone().into()),
            CalendarPublishLinkProperty::CreatedAt => Value::Element(
                CalendarPublishLinkValue::Date(jmap_proto::types::date::UTCDate::from_timestamp(
                    link.created_at,
                )),
            ),
            CalendarPublishLinkProperty::LastUsedAt => link
                .last_used_at
                .map(|ts| {
                    Value::Element(CalendarPublishLinkValue::Date(
                        jmap_proto::types::date::UTCDate::from_timestamp(ts),
                    ))
                })
                .unwrap_or(Value::Null),
            CalendarPublishLinkProperty::ExpiresAt => link
                .expires_at
                .map(|ts| {
                    Value::Element(CalendarPublishLinkValue::Date(
                        jmap_proto::types::date::UTCDate::from_timestamp(ts),
                    ))
                })
                .unwrap_or(Value::Null),
            CalendarPublishLinkProperty::Secret => Value::Null,
        };
        result.insert_unchecked(property.clone(), value);
    }
    Value::Object(result)
}
