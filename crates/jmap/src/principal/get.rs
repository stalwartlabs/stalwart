/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::principal::{Principal, PrincipalProperty, PrincipalType, PrincipalValue},
    request::capability::Capability,
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use registry::schema::prelude::{Object, Permission, Property};
use std::future::Future;
use store::{registry::RegistryQuery, roaring::RoaringBitmap};
use trc::AddContext;

pub trait PrincipalGet: Sync + Send {
    fn principal_get(
        &self,
        request: GetRequest<Principal>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Principal>>> + Send;
}

impl PrincipalGet for Server {
    async fn principal_get(
        &self,
        mut request: GetRequest<Principal>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Principal>> {
        if !self.core.groupware.allow_directory_query
            && !access_token.has_permission(Permission::IndividualList)
        {
            return Err(trc::JmapEvent::Forbidden
                .into_err()
                .details("The administrator has disabled directory queries.".to_string()));
        }

        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            PrincipalProperty::Id,
            PrincipalProperty::Type,
            PrincipalProperty::Name,
            PrincipalProperty::Description,
            PrincipalProperty::Email,
        ]);

        // Return all principals
        let principal_ids = self
            .registry()
            .query::<RoaringBitmap>(
                RegistryQuery::new(Object::Account)
                    .equal_opt(Property::MemberTenantId, access_token.tenant_id()),
            )
            .await
            .caused_by(trc::location!())?;

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
            let document_id = id.document_id();
            if !principal_ids.contains(document_id) {
                response.not_found.push(id);
                continue;
            };
            let principal = self
                .account_info(document_id)
                .await
                .caused_by(trc::location!())?;

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    PrincipalProperty::Id => Value::Element(PrincipalValue::Id(id)),
                    PrincipalProperty::Type => {
                        Value::Element(PrincipalValue::Type(if principal.is_user_account() {
                            PrincipalType::Individual
                        } else {
                            PrincipalType::Group
                        }))
                    }
                    PrincipalProperty::Name => Value::Str(principal.name().to_string().into()),
                    PrincipalProperty::Description => principal
                        .description()
                        .map(|v| Value::Str(v.to_string().into()))
                        .unwrap_or(Value::Null),
                    PrincipalProperty::Email => Value::Str(principal.name().to_string().into()),
                    PrincipalProperty::Accounts => Value::Object(Map::from(vec![(
                        Key::Property(PrincipalProperty::IdValue(id)),
                        Value::Object(Map::from_iter(
                            [
                                Capability::Mail,
                                Capability::Contacts,
                                Capability::Calendars,
                                Capability::FileNode,
                                Capability::Principals,
                            ]
                            .iter()
                            .map(|cap| {
                                (
                                    Key::Property(PrincipalProperty::Capability(*cap)),
                                    Value::Object(Map::new()),
                                )
                            })
                            .chain([
                                (
                                    Key::Property(PrincipalProperty::Capability(
                                        Capability::PrincipalsOwner,
                                    )),
                                    Value::Object(Map::from(vec![
                                        (
                                            Key::Borrowed("accountIdForPrincipal"),
                                            Value::Element(PrincipalValue::Id(id)),
                                        ),
                                        (
                                            Key::Borrowed("principalId"),
                                            Value::Element(PrincipalValue::Id(id)),
                                        ),
                                    ])),
                                ),
                                (
                                    Key::Property(PrincipalProperty::Capability(
                                        Capability::Calendars,
                                    )),
                                    Value::Object(Map::from(vec![
                                        (
                                            Key::Borrowed("accountId"),
                                            Value::Element(PrincipalValue::Id(id)),
                                        ),
                                        (Key::Borrowed("mayGetAvailability"), Value::Bool(true)),
                                        (Key::Borrowed("mayShareWith"), Value::Bool(true)),
                                        (
                                            Key::Borrowed("calendarAddress"),
                                            Value::Str(
                                                format!("mailto:{}", principal.name()).into(),
                                            ),
                                        ),
                                    ])),
                                ),
                            ]),
                        )),
                    )])),
                    PrincipalProperty::Capabilities => Value::Object(Map::from_iter(
                        [
                            Capability::Mail,
                            Capability::Contacts,
                            Capability::Calendars,
                            Capability::FileNode,
                            Capability::Principals,
                        ]
                        .iter()
                        .map(|cap| {
                            (
                                Key::Property(PrincipalProperty::Capability(*cap)),
                                Value::Object(Map::new()),
                            )
                        }),
                    )),
                    _ => Value::Null,
                };

                result.insert_unchecked(property.clone(), value);
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}
