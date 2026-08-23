/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use groupware::calendar::publish_http::CalendarPublishStore;
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::calendar_publish_link::{
        self, CalendarPublishLinkProperty, CalendarPublishLinkValue, PublishAccess,
        PublishVisibility,
    },
    request::{IntoValid, MaybeInvalid},
};
use jmap_tools::{Map, Value};
use types::id::Id;

pub trait CalendarPublishLinkGet: Sync + Send {
    fn calendar_publish_link_get(
        &self,
        request: GetRequest<calendar_publish_link::CalendarPublishLink>,
    ) -> impl Future<Output = trc::Result<GetResponse<calendar_publish_link::CalendarPublishLink>>> + Send;
}

impl CalendarPublishLinkGet for Server {
    async fn calendar_publish_link_get(
        &self,
        mut request: GetRequest<calendar_publish_link::CalendarPublishLink>,
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

        let account_id = request.account_id.document_id();
        let filter_ids = request.ids.take().map(|ids| {
            ids.unwrap()
                .into_valid()
                .map(|id| id.document_id())
                .collect::<std::collections::HashSet<_>>()
        });

        let links = self.list_publish_links(account_id).await?;
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::new(),
            not_found: vec![],
        };

        for link in &links {
            if filter_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&link.document_id))
            {
                continue;
            }
            if response.list.len() >= self.core.jmap.get_max_objects {
                break;
            }
            response.list.push(build_publish_link_object(
                link,
                &properties,
                self.build_publish_url(link, None),
            ));
        }

        if let Some(ids) = filter_ids {
            for document_id in ids {
                if !links.iter().any(|l| l.document_id == document_id) {
                    response.not_found.push(MaybeInvalid::Value(Id::from(document_id)));
                }
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
