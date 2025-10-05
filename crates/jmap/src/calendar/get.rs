/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::acl::JmapRights, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken, sharing::EffectiveAcl};
use groupware::{cache::GroupwareCache, calendar::Calendar};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::calendar::{self, CalendarProperty, CalendarValue},
};
use jmap_tools::{Map, Value};
use store::roaring::RoaringBitmap;
use trc::AddContext;
use types::{
    acl::{Acl, AclGrant},
    collection::{Collection, SyncCollection},
};

pub trait CalendarGet: Sync + Send {
    fn calendar_get(
        &self,
        request: GetRequest<calendar::Calendar>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<calendar::Calendar>>> + Send;
}

impl CalendarGet for Server {
    async fn calendar_get(
        &self,
        mut request: GetRequest<calendar::Calendar>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<calendar::Calendar>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            CalendarProperty::Id,
            CalendarProperty::Name,
            CalendarProperty::Description,
            CalendarProperty::SortOrder,
            CalendarProperty::IsDefault,
            CalendarProperty::IsSubscribed,
            CalendarProperty::MyRights,
        ]);
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_dav_resources(access_token, account_id, SyncCollection::Calendar)
            .await?;
        let calendar_ids = if access_token.is_member(account_id) {
            cache.document_ids(true).collect::<RoaringBitmap>()
        } else {
            cache.shared_containers(access_token, [Acl::Read, Acl::ReadItems], true)
        };

        let ids = if let Some(ids) = ids {
            ids
        } else {
            calendar_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: cache.get_state(true).into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the calendar object
            let document_id = id.document_id();
            if !calendar_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            }
            let _calendar = if let Some(calendar) = self
                .get_archive(account_id, Collection::Calendar, document_id)
                .await?
            {
                calendar
            } else {
                response.not_found.push(id);
                continue;
            };
            let calendar = _calendar
                .unarchive::<Calendar>()
                .caused_by(trc::location!())?;
            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                match property {
                    CalendarProperty::Id => {
                        result.insert_unchecked(CalendarProperty::Id, CalendarValue::Id(id));
                    }
                    CalendarProperty::Name => {
                        result.insert_unchecked(
                            CalendarProperty::Name,
                            calendar.preferences(access_token).name.to_string(),
                        );
                    }
                    CalendarProperty::Description => {
                        result.insert_unchecked(
                            CalendarProperty::Description,
                            calendar
                                .preferences(access_token)
                                .description
                                .as_ref()
                                .map(|v| v.to_string()),
                        );
                    }
                    CalendarProperty::SortOrder => {
                        result.insert_unchecked(
                            CalendarProperty::SortOrder,
                            calendar.preferences(access_token).sort_order.to_native(),
                        );
                    }
                    /*CalendarProperty::IsDefault => {
                        result.insert_unchecked(CalendarProperty::IsDefault, calendar.is_default);
                    }
                    CalendarProperty::IsSubscribed => {
                        result.insert_unchecked(
                            CalendarProperty::IsSubscribed,
                            calendar
                                .subscribers
                                .iter()
                                .any(|account_id| *account_id == access_token.primary_id()),
                        );
                    }*/
                    CalendarProperty::ShareWith => {
                        result.insert_unchecked(
                            CalendarProperty::ShareWith,
                            JmapRights::share_with::<calendar::Calendar>(
                                account_id,
                                access_token,
                                &calendar.acls.iter().map(AclGrant::from).collect::<Vec<_>>(),
                            ),
                        );
                    }
                    CalendarProperty::MyRights => {
                        result.insert_unchecked(
                            CalendarProperty::MyRights,
                            if access_token.is_shared(account_id) {
                                JmapRights::rights::<calendar::Calendar>(
                                    calendar.acls.effective_acl(access_token),
                                )
                            } else {
                                JmapRights::all_rights::<calendar::Calendar>()
                            },
                        );
                    }
                    property => {
                        result.insert_unchecked(property.clone(), Value::Null);
                    }
                }
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
