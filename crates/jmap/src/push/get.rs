/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken, ipc::PushEvent};
use email::push::{PushSubscriptions, Urgency};
use jmap_proto::{
    method::{
        get::{GetRequest, GetResponse},
        query::ArchivedFilter,
    },
    object::{
        email::{ArchivedEmailFilter, EmailFilter, EmailProperty},
        push_subscription::{self, PushSubscriptionProperty, PushSubscriptionValue},
    },
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Property, Value};
use std::future::Future;
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, now},
};
use trc::{AddContext, ServerEvent};
use types::{collection::Collection, field::PrincipalField, id::Id};
use utils::map::bitmap::Bitmap;

pub trait PushSubscriptionFetch: Sync + Send {
    fn push_subscription_get(
        &self,
        request: GetRequest<push_subscription::PushSubscription>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<push_subscription::PushSubscription>>> + Send;
}

impl PushSubscriptionFetch for Server {
    async fn push_subscription_get(
        &self,
        mut request: GetRequest<push_subscription::PushSubscription>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<push_subscription::PushSubscription>> {
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            PushSubscriptionProperty::Id,
            PushSubscriptionProperty::DeviceClientId,
            PushSubscriptionProperty::VerificationCode,
            PushSubscriptionProperty::Expires,
            PushSubscriptionProperty::Types,
        ]);

        let account_id = access_token.account_id();

        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::new(),
            not_found: not_found_ids,
        };

        let Some(subscriptions_) = self
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::property(
                account_id,
                Collection::Principal,
                0,
                PrincipalField::PushSubscriptions,
            ))
            .await?
        else {
            for id in ids.unwrap_or_default() {
                response.push_not_found(id);
            }
            return Ok(response);
        };
        let subscriptions = subscriptions_
            .to_unarchived::<PushSubscriptions>()
            .caused_by(trc::location!())?;

        let ids = if let Some(ids) = ids {
            ids
        } else {
            subscriptions
                .inner
                .subscriptions
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(|s| Id::from(s.id.to_native()))
                .collect::<Vec<_>>()
        };

        for id in ids {
            // Obtain the push subscription object
            let document_id = id.document_id();
            let Some(push) = subscriptions
                .inner
                .subscriptions
                .iter()
                .find(|p| p.id.to_native() == document_id)
            else {
                response.push_not_found(id);
                continue;
            };

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    PushSubscriptionProperty::Id => {
                        result.insert_unchecked(PushSubscriptionProperty::Id, id);
                    }
                    PushSubscriptionProperty::Url | PushSubscriptionProperty::Keys => {
                        return Err(trc::JmapEvent::Forbidden.into_err().details(
                            "The 'url' and 'keys' properties are not readable".to_string(),
                        ));
                    }
                    PushSubscriptionProperty::DeviceClientId => {
                        result.insert_unchecked(
                            PushSubscriptionProperty::DeviceClientId,
                            &push.device_client_id,
                        );
                    }
                    PushSubscriptionProperty::Types => {
                        let mut types = Vec::new();
                        for typ in Bitmap::from(&push.types).into_iter() {
                            types.push(Value::Element(PushSubscriptionValue::Types(typ)));
                        }
                        result
                            .insert_unchecked(PushSubscriptionProperty::Types, Value::Array(types));
                    }
                    PushSubscriptionProperty::Expires => {
                        if push.expires > 0 {
                            result.insert_unchecked(
                                PushSubscriptionProperty::Expires,
                                Value::Element(PushSubscriptionValue::Date(
                                    UTCDate::from_timestamp(u64::from(push.expires) as i64),
                                )),
                            );
                        } else {
                            result.insert_unchecked(PushSubscriptionProperty::Expires, Value::Null);
                        }
                    }
                    PushSubscriptionProperty::EmailPush => {
                        if push.email_push.is_empty() {
                            result
                                .insert_unchecked(PushSubscriptionProperty::EmailPush, Value::Null);
                        } else {
                            let mut configs = Map::with_capacity(push.email_push.len());
                            for config in push.email_push.iter() {
                                let properties = config
                                    .properties
                                    .iter()
                                    .map(|property| {
                                        Value::Str(EmailProperty::from(property).to_cow())
                                    })
                                    .collect();
                                let obj = Map::with_capacity(3)
                                    .with_key_value(
                                        Key::Borrowed("filter"),
                                        archived_filter_node(&mut config.filter.iter().peekable())
                                            .unwrap_or(Value::Null),
                                    )
                                    .with_key_value(
                                        Key::Borrowed("properties"),
                                        Value::Array(properties),
                                    )
                                    .with_key_value(
                                        Key::Borrowed("urgency"),
                                        Value::Str(Urgency::from(&config.urgency).as_str().into()),
                                    );
                                configs.insert_unchecked(
                                    Key::Owned(Id::from(config.account_id.to_native()).as_string()),
                                    Value::Object(obj),
                                );
                            }
                            result.insert_unchecked(
                                PushSubscriptionProperty::EmailPush,
                                Value::Object(configs),
                            );
                        }
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        // Purge old subscriptions
        let current_time = now();
        if subscriptions
            .inner
            .subscriptions
            .iter()
            .any(|s| s.expires.to_native() < current_time)
        {
            let mut updated_subscriptions = subscriptions.deserialize::<PushSubscriptions>()?;
            updated_subscriptions
                .subscriptions
                .retain(|s| s.expires >= current_time);
            let mut batch = BatchBuilder::new();

            if updated_subscriptions.subscriptions.is_empty() {
                batch
                    .with_account_id(u32::MAX)
                    .with_collection(Collection::Principal)
                    .with_account_id(account_id)
                    .tag(PrincipalField::PushSubscriptions);
            }

            batch
                .with_account_id(account_id)
                .with_collection(Collection::Principal)
                .with_document(0)
                .assert_value(PrincipalField::PushSubscriptions, subscriptions);

            if !updated_subscriptions.subscriptions.is_empty() {
                batch.set(
                    PrincipalField::PushSubscriptions,
                    Archiver::new(updated_subscriptions)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
            } else {
                batch.clear(PrincipalField::PushSubscriptions);
            }

            self.commit_batch(batch).await.caused_by(trc::location!())?;

            // Update push servers
            if self
                .inner
                .ipc
                .push_tx
                .clone()
                .send(PushEvent::PushServerUpdate {
                    account_id,
                    broadcast: true,
                })
                .await
                .is_err()
            {
                trc::event!(
                    Server(ServerEvent::ThreadError),
                    Details = "Error sending push updates.",
                    CausedBy = trc::location!()
                );
            }
        }

        Ok(response)
    }
}

fn archived_filter_node<'a, I>(
    tokens: &mut std::iter::Peekable<I>,
) -> Option<Value<'static, PushSubscriptionProperty, PushSubscriptionValue>>
where
    I: Iterator<Item = &'a ArchivedFilter<EmailFilter>>,
{
    match tokens.next()? {
        operator @ (ArchivedFilter::And | ArchivedFilter::Or | ArchivedFilter::Not) => {
            let operator = match operator {
                ArchivedFilter::And => "AND",
                ArchivedFilter::Or => "OR",
                ArchivedFilter::Not => "NOT",
                _ => unreachable!(),
            };
            let mut conditions = Vec::new();
            while let Some(token) = tokens.peek() {
                if matches!(token, ArchivedFilter::Close) {
                    tokens.next();
                    break;
                }
                if let Some(condition) = archived_filter_node(tokens) {
                    conditions.push(condition);
                }
            }
            Some(Value::Object(
                Map::with_capacity(2)
                    .with_key_value(Key::Borrowed("operator"), Value::Str(operator.into()))
                    .with_key_value(Key::Borrowed("conditions"), Value::Array(conditions)),
            ))
        }
        ArchivedFilter::Property(filter) => Some(archived_condition_to_value(filter)),
        ArchivedFilter::Close => None,
    }
}

fn archived_condition_to_value(
    filter: &ArchivedEmailFilter,
) -> Value<'static, PushSubscriptionProperty, PushSubscriptionValue> {
    let (key, value): (
        &'static str,
        Value<'static, PushSubscriptionProperty, PushSubscriptionValue>,
    ) = match filter {
        ArchivedEmailFilter::InMailbox(id) => ("inMailbox", Id::from(id).as_string().into()),
        ArchivedEmailFilter::InMailboxOtherThan(ids) => (
            "inMailboxOtherThan",
            Value::Array(
                ids.iter()
                    .map(|id| Id::from(id).as_string().into())
                    .collect(),
            ),
        ),
        ArchivedEmailFilter::Before(date) => ("before", UTCDate::from(date).to_string().into()),
        ArchivedEmailFilter::After(date) => ("after", UTCDate::from(date).to_string().into()),
        ArchivedEmailFilter::MinSize(size) => ("minSize", (size.to_native() as u64).into()),
        ArchivedEmailFilter::MaxSize(size) => ("maxSize", (size.to_native() as u64).into()),
        ArchivedEmailFilter::AllInThreadHaveKeyword(keyword) => {
            ("allInThreadHaveKeyword", keyword.to_string().into())
        }
        ArchivedEmailFilter::SomeInThreadHaveKeyword(keyword) => {
            ("someInThreadHaveKeyword", keyword.to_string().into())
        }
        ArchivedEmailFilter::NoneInThreadHaveKeyword(keyword) => {
            ("noneInThreadHaveKeyword", keyword.to_string().into())
        }
        ArchivedEmailFilter::HasKeyword(keyword) => ("hasKeyword", keyword.to_string().into()),
        ArchivedEmailFilter::NotKeyword(keyword) => ("notKeyword", keyword.to_string().into()),
        ArchivedEmailFilter::HasAttachment(value) => ("hasAttachment", (*value).into()),
        ArchivedEmailFilter::From(value) => ("from", value.as_str().to_string().into()),
        ArchivedEmailFilter::To(value) => ("to", value.as_str().to_string().into()),
        ArchivedEmailFilter::Cc(value) => ("cc", value.as_str().to_string().into()),
        ArchivedEmailFilter::Bcc(value) => ("bcc", value.as_str().to_string().into()),
        ArchivedEmailFilter::Subject(value) => ("subject", value.as_str().to_string().into()),
        ArchivedEmailFilter::Body(value) => ("body", value.as_str().to_string().into()),
        ArchivedEmailFilter::Header(values) => (
            "header",
            Value::Array(
                values
                    .iter()
                    .map(|value| value.as_str().to_string().into())
                    .collect(),
            ),
        ),
        ArchivedEmailFilter::Text(value) => ("text", value.as_str().to_string().into()),
        ArchivedEmailFilter::SentBefore(date) => {
            ("sentBefore", UTCDate::from(date).to_string().into())
        }
        ArchivedEmailFilter::SentAfter(date) => {
            ("sentAfter", UTCDate::from(date).to_string().into())
        }
        ArchivedEmailFilter::InThread(id) => ("inThread", Id::from(id).as_string().into()),
        ArchivedEmailFilter::Id(ids) => (
            "id",
            Value::Array(
                ids.iter()
                    .map(|id| Id::from(id).as_string().into())
                    .collect(),
            ),
        ),
        ArchivedEmailFilter::_T(_) => return Value::Object(Map::with_capacity(0)),
    };
    Value::Object(Map::with_capacity(1).with_key_value(Key::Borrowed(key), value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmap_proto::method::query::{Filter, FilterWrapper};
    use serde::Deserialize;

    fn parse_filter(json: &str) -> Vec<Filter<EmailFilter>> {
        let value: Value<PushSubscriptionProperty, PushSubscriptionValue> =
            serde_json::from_str(json).expect("valid filter json");
        FilterWrapper::<EmailFilter>::deserialize(&value)
            .expect("parseable filter")
            .0
    }

    fn store_and_serialize(
        filter: &[Filter<EmailFilter>],
    ) -> Value<'static, PushSubscriptionProperty, PushSubscriptionValue> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&filter.to_vec()).expect("serialize");
        let archived = rkyv::access::<
            <Vec<Filter<EmailFilter>> as rkyv::Archive>::Archived,
            rkyv::rancor::Error,
        >(&bytes)
        .expect("access archived");
        archived_filter_node(&mut archived.iter().peekable()).unwrap_or(Value::Null)
    }

    #[test]
    fn email_push_filter_round_trips() {
        let mailbox_a = Id::from_parts(0, 10).to_string();
        let mailbox_b = Id::from_parts(0, 20).to_string();

        for json in [
            format!(r#"{{"inMailbox":"{mailbox_a}"}}"#),
            format!(r#"{{"inMailbox":"{mailbox_a}","hasKeyword":"$seen"}}"#),
            format!(
                r#"{{"operator":"OR","conditions":[{{"inMailbox":"{mailbox_a}"}},{{"hasKeyword":"$notify"}}]}}"#
            ),
            format!(
                r#"{{"operator":"AND","conditions":[{{"inMailbox":"{mailbox_a}"}},{{"operator":"NOT","conditions":[{{"hasKeyword":"$junk"}}]}}]}}"#
            ),
            format!(
                r#"{{"operator":"OR","conditions":[{{"subject":"hello"}},{{"operator":"AND","conditions":[{{"from":"alice@example.com"}},{{"inMailboxOtherThan":["{mailbox_a}","{mailbox_b}"]}},{{"minSize":1024}},{{"hasAttachment":true}}]}}]}}"#
            ),
        ] {
            let parsed = parse_filter(&json);
            let serialized = store_and_serialize(&parsed);
            let round_tripped = FilterWrapper::<EmailFilter>::deserialize(&serialized)
                .expect("reparseable filter")
                .0;

            assert_eq!(parsed, round_tripped, "filter did not round-trip: {json}");
        }
    }

    #[test]
    fn empty_filter_serializes_to_null() {
        assert!(matches!(store_and_serialize(&[]), Value::Null));
    }
}
