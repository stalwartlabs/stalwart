/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use directory::QueryParams;
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::principal::{Principal, PrincipalProperty, PrincipalValue},
    types::state::State,
};
use jmap_tools::{Map, Value};
use std::future::Future;
use types::collection::Collection;

pub trait PrincipalGet: Sync + Send {
    fn principal_get(
        &self,
        request: GetRequest<Principal>,
    ) -> impl Future<Output = trc::Result<GetResponse<Principal>>> + Send;
}

impl PrincipalGet for Server {
    async fn principal_get(
        &self,
        mut request: GetRequest<Principal>,
    ) -> trc::Result<GetResponse<Principal>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            PrincipalProperty::Id,
            PrincipalProperty::Type,
            PrincipalProperty::Name,
            PrincipalProperty::Description,
            PrincipalProperty::Email,
            //PrincipalProperty::Timezone,
            //PrincipalProperty::Capabilities,
        ]);
        let principal_ids = self
            .get_document_ids(u32::MAX, Collection::Principal)
            .await?
            .unwrap_or_default();
        let ids = if let Some(ids) = ids {
            ids
        } else {
            principal_ids
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>()
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: State::Initial.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the principal
            let principal = if let Some(principal) = self
                .core
                .storage
                .directory
                .query(QueryParams::id(id.document_id()).with_return_member_of(false))
                .await?
            {
                principal
            } else {
                response.not_found.push(id);
                continue;
            };

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    PrincipalProperty::Id => Value::Element(PrincipalValue::Id(id)),
                    PrincipalProperty::Type => {
                        Value::Str(principal.typ().to_jmap().to_string().into())
                    }
                    PrincipalProperty::Name => Value::Str(principal.name().to_string().into()),
                    PrincipalProperty::Description => principal
                        .description()
                        .map(|v| Value::Str(v.to_string().into()))
                        .unwrap_or(Value::Null),
                    PrincipalProperty::Email => principal
                        .emails
                        .first()
                        .map(|email| Value::Str(email.to_string().into()))
                        .unwrap_or(Value::Null),
                    _ => Value::Null,
                };

                result.insert_unchecked(property.clone(), value);
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
