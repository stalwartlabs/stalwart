/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::quota::{Quota, QuotaProperty, QuotaValue},
    types::state::State,
};
use jmap_tools::{Map, Value};
use std::future::Future;
use types::{id::Id, type_state::DataType};

pub trait QuotaGet: Sync + Send {
    fn quota_get(
        &self,
        request: GetRequest<Quota>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Quota>>> + Send;
}

impl QuotaGet for Server {
    async fn quota_get(
        &self,
        mut request: GetRequest<Quota>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Quota>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            QuotaProperty::Id,
            QuotaProperty::ResourceType,
            QuotaProperty::Used,
            QuotaProperty::WarnLimit,
            QuotaProperty::SoftLimit,
            QuotaProperty::HardLimit,
            QuotaProperty::Scope,
            QuotaProperty::Name,
            QuotaProperty::Description,
            QuotaProperty::Types,
        ]);
        let account_id = request.account_id.document_id();
        let quota_ids = if access_token.quota > 0 {
            vec![0u32]
        } else {
            vec![]
        };
        let ids = if let Some(ids) = ids {
            ids
        } else {
            quota_ids.iter().map(|id| Id::from(*id)).collect()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: State::Initial.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the sieve script object
            let document_id = id.document_id();
            if !quota_ids.contains(&document_id) {
                response.not_found.push(id);
                continue;
            }

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    QuotaProperty::Id => Value::Element(id.into()),
                    QuotaProperty::ResourceType => "octets".to_string().into(),
                    QuotaProperty::Used => (self.get_used_quota(account_id).await? as u64).into(),
                    QuotaProperty::HardLimit => access_token.quota.into(),
                    QuotaProperty::Scope => "account".to_string().into(),
                    QuotaProperty::Name => access_token.name.to_string().into(),
                    QuotaProperty::Description => access_token
                        .description
                        .as_ref()
                        .map(|s| s.to_string())
                        .into(),
                    QuotaProperty::Types => vec![
                        Value::Element(QuotaValue::Types(DataType::Email)),
                        Value::Element(QuotaValue::Types(DataType::SieveScript)),
                    ]
                    .into(),

                    _ => Value::Null,
                };
                result.insert_unchecked(property.clone(), value);
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
