/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::query::QueryResponseBuilder;
use common::{Server, sharing::notification::ShareNotification};
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::share_notification::{self, ShareNotificationFilter},
    types::state::State,
};
use std::time::Duration;
use store::{Deserialize, IterateParams, LogKey, U64_LEN, write::key::DeserializeBigEndian};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    id::Id,
};
use utils::snowflake::SnowflakeIdGenerator;

pub trait ShareNotificationQuery: Sync + Send {
    fn share_notification_query(
        &self,
        request: QueryRequest<share_notification::ShareNotification>,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl ShareNotificationQuery for Server {
    async fn share_notification_query(
        &self,
        mut request: QueryRequest<share_notification::ShareNotification>,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut from_change_id = SnowflakeIdGenerator::from_duration(
            self.core
                .jmap
                .share_notification_max_history
                .unwrap_or(Duration::from_secs(30 * 86400)),
        )
        .unwrap_or_default();
        let mut to_change_id = u64::MAX;
        let mut collection = None;
        let mut object_type = None;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    ShareNotificationFilter::After(utcdate) => {
                        from_change_id =
                            SnowflakeIdGenerator::from_timestamp(utcdate.timestamp() as u64)
                                .unwrap_or(0);
                    }
                    ShareNotificationFilter::Before(utcdate) => {
                        to_change_id =
                            SnowflakeIdGenerator::from_timestamp(utcdate.timestamp() as u64)
                                .unwrap_or(u64::MAX);
                    }
                    ShareNotificationFilter::ObjectType(typ) => {
                        collection = Collection::try_from(typ).ok();
                    }
                    ShareNotificationFilter::ObjectAccountId(id) => {
                        object_type = Some(id.document_id());
                    }
                    ShareNotificationFilter::_T(other) => {
                        return Err(trc::JmapEvent::UnsupportedFilter.into_err().details(other));
                    }
                },
                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    return Err(trc::JmapEvent::UnsupportedFilter
                        .into_err()
                        .details("Logical operators are not supported"));
                }
            }
        }

        let mut results = Vec::new();
        self.store()
            .iterate(
                IterateParams::new(
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: from_change_id,
                    },
                    LogKey {
                        account_id,
                        collection: SyncCollection::ShareNotification.into(),
                        change_id: to_change_id,
                    },
                )
                .descending(),
                |key, value| {
                    let change_id = key.deserialize_be_u64(key.len() - U64_LEN)?;

                    if collection.is_some() || object_type.is_some() {
                        let notification =
                            ShareNotification::deserialize(value).caused_by(trc::location!())?;
                        if collection.is_some_and(|c| c != notification.object_type)
                            || object_type.is_some_and(|o| o != notification.object_account_id)
                        {
                            return Ok(true);
                        }
                    }

                    results.push(Id::from(change_id));

                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        let mut response = QueryResponseBuilder::new(
            results.len(),
            self.core.jmap.query_max_results,
            State::Initial,
            &request,
        );

        for id in results {
            if !response.add_id(id) {
                break;
            }
        }

        response.build()
    }
}
