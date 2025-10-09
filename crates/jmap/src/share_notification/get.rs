/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, sharing::notification::ShareNotification};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::{
        JmapRight,
        addressbook::AddressBookRight,
        calendar::CalendarRight,
        file_node::FileNodeRight,
        mailbox::MailboxRight,
        share_notification::{self, ShareNotificationProperty, ShareNotificationValue},
    },
    request::IntoValid,
    types::{date::UTCDate, state::State},
};
use jmap_tools::{Key, Map, Value};
use std::time::Duration;
use store::{
    Deserialize, IterateParams, LogKey, U64_LEN, ahash::AHashSet, write::key::DeserializeBigEndian,
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    id::Id,
    type_state::DataType,
};
use utils::{map::bitmap::Bitmap, snowflake::SnowflakeIdGenerator};

pub trait ShareNotificationGet: Sync + Send {
    fn share_notification_get(
        &self,
        request: GetRequest<share_notification::ShareNotification>,
    ) -> impl Future<Output = trc::Result<GetResponse<share_notification::ShareNotification>>> + Send;
}

impl ShareNotificationGet for Server {
    async fn share_notification_get(
        &self,
        mut request: GetRequest<share_notification::ShareNotification>,
    ) -> trc::Result<GetResponse<share_notification::ShareNotification>> {
        let properties = request.unwrap_properties(&[
            ShareNotificationProperty::Id,
            ShareNotificationProperty::Name,
            ShareNotificationProperty::ChangedBy,
            ShareNotificationProperty::Created,
            ShareNotificationProperty::ObjectAccountId,
            ShareNotificationProperty::ObjectId,
            ShareNotificationProperty::ObjectType,
            ShareNotificationProperty::OldRights,
            ShareNotificationProperty::NewRights,
            ShareNotificationProperty::Name,
        ]);

        let account_id = request.account_id.document_id();
        let mut min_id = u64::MAX;
        let mut max_id = 0u64;

        let mut ids = if let Some(ids) = request.ids.take() {
            let ids = ids.unwrap();
            if ids.len() <= self.core.jmap.get_max_objects {
                ids.into_valid()
                    .map(|id| {
                        let id_num = *id.as_ref();
                        if id_num < min_id {
                            min_id = id_num;
                        }
                        if id_num > max_id {
                            max_id = id_num;
                        }
                        id_num
                    })
                    .collect::<AHashSet<_>>()
            } else {
                return Err(trc::JmapEvent::RequestTooLarge.into_err());
            }
        } else {
            AHashSet::new()
        };
        let has_ids = !ids.is_empty();

        if min_id == u64::MAX {
            min_id = SnowflakeIdGenerator::from_duration(
                self.core
                    .jmap
                    .share_notification_max_history
                    .unwrap_or(Duration::from_secs(30 * 86400)),
            )
            .unwrap_or_default();
        }

        if max_id == 0 {
            max_id = u64::MAX;
        }

        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: None,
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        self.store()
            .iterate(
                IterateParams::new(
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: min_id,
                    },
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: max_id + 1,
                    },
                )
                .descending(),
                |key, value| {
                    let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;
                    if response.state.is_none() {
                        response.state = Some(State::Exact(change_id));
                    }

                    if !has_ids || ids.remove(&change_id) {
                        let notification =
                            ShareNotification::deserialize(value).caused_by(trc::location!())?;
                        response.list.push(build_share_notification(
                            change_id,
                            notification,
                            &properties,
                        ));
                    }

                    Ok((!has_ids || !ids.is_empty())
                        && response.list.len() < self.core.jmap.get_max_objects)
                },
            )
            .await
            .caused_by(trc::location!())?;

        response
            .not_found
            .extend(ids.into_iter().map(Id::from).collect::<Vec<_>>());

        Ok(response)
    }
}

fn build_share_notification(
    id: u64,
    mut notification: ShareNotification,
    properties: &[ShareNotificationProperty],
) -> Value<'static, ShareNotificationProperty, ShareNotificationValue> {
    let mut result = Map::with_capacity(properties.len());
    for property in properties {
        let value = match property {
            ShareNotificationProperty::Id => Value::Element(ShareNotificationValue::Id(id.into())),
            ShareNotificationProperty::Created => Value::Element(ShareNotificationValue::Date(
                UTCDate::from_timestamp(SnowflakeIdGenerator::to_timestamp(id) as i64),
            )),
            ShareNotificationProperty::ChangedBy => Value::Object(Map::from(vec![
                (
                    Key::Property(ShareNotificationProperty::ChangedByPrincipalId),
                    Value::Element(ShareNotificationValue::Id(notification.changed_by.into())),
                ),
                (
                    Key::Property(ShareNotificationProperty::ChangedByName),
                    Value::Str("".into()),
                ),
            ])),
            ShareNotificationProperty::ObjectType => DataType::try_from(notification.object_type)
                .ok()
                .map(|typ| Value::Element(ShareNotificationValue::ObjectType(typ)))
                .unwrap_or(Value::Null),
            ShareNotificationProperty::ObjectAccountId => Value::Element(
                ShareNotificationValue::Id(notification.object_account_id.into()),
            ),
            ShareNotificationProperty::ObjectId => {
                Value::Element(ShareNotificationValue::Id(notification.object_id.into()))
            }
            ShareNotificationProperty::OldRights => {
                map_rights(notification.object_type, notification.old_rights)
            }
            ShareNotificationProperty::NewRights => {
                map_rights(notification.object_type, notification.new_rights)
            }
            ShareNotificationProperty::Name => {
                Value::Str(std::mem::take(&mut notification.name).into())
            }
            _ => Value::Null,
        };

        result.insert_unchecked(property.clone(), value);
    }

    Value::Object(result)
}

fn map_rights(
    object_type: Collection,
    rights: Bitmap<Acl>,
) -> Value<'static, ShareNotificationProperty, ShareNotificationValue> {
    let mut obj = Map::with_capacity(3);

    match object_type {
        Collection::Calendar | Collection::CalendarEvent => {
            for acl in rights.into_iter() {
                for right in CalendarRight::from_acl(acl) {
                    obj.insert_unchecked(Key::Borrowed(right.as_str()), Value::Bool(true));
                }
            }
        }
        Collection::AddressBook | Collection::ContactCard => {
            for acl in rights.into_iter() {
                for right in AddressBookRight::from_acl(acl) {
                    obj.insert_unchecked(Key::Borrowed(right.as_str()), Value::Bool(true));
                }
            }
        }
        Collection::FileNode => {
            for acl in rights.into_iter() {
                for right in FileNodeRight::from_acl(acl) {
                    obj.insert_unchecked(Key::Borrowed(right.as_str()), Value::Bool(true));
                }
            }
        }
        Collection::Mailbox | Collection::Email => {
            for acl in rights.into_iter() {
                for right in MailboxRight::from_acl(acl) {
                    obj.insert_unchecked(Key::Borrowed(right.as_str()), Value::Bool(true));
                }
            }
        }
        _ => {}
    }

    Value::Object(obj)
}
