/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use directory::{Permission, QueryParams, Type, backend::internal::manage::ManageDirectory};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::principal::{Principal, PrincipalProperty, PrincipalType, PrincipalValue},
    request::capability::Capability,
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use std::future::Future;
use store::roaring::RoaringBitmap;
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
            .store()
            .list_principals(
                None,
                access_token.tenant_id(),
                &[
                    Type::Individual,
                    Type::Group,
                    Type::Resource,
                    Type::Location,
                ],
                false,
                0,
                0,
            )
            .await
            .caused_by(trc::location!())?
            .items
            .into_iter()
            .map(|p| p.id())
            .collect::<RoaringBitmap>();

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
            let principal = if principal_ids.contains(document_id)
                && let Some(principal) = self
                    .core
                    .storage
                    .directory
                    .query(QueryParams::id(document_id).with_return_member_of(false))
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
                        Value::Element(PrincipalValue::Type(match principal.typ() {
                            Type::Individual => PrincipalType::Individual,
                            Type::Group => PrincipalType::Group,
                            Type::Resource => PrincipalType::Resource,
                            Type::Location => PrincipalType::Location,
                            _ => PrincipalType::Other,
                        }))
                    }
                    PrincipalProperty::Name => Value::Str(principal.name().to_string().into()),
                    PrincipalProperty::Description => principal
                        .description()
                        .map(|v| Value::Str(v.to_string().into()))
                        .unwrap_or(Value::Null),
                    PrincipalProperty::Email => principal
                        .primary_email()
                        .map(|email| Value::Str(email.to_string().into()))
                        .unwrap_or(Value::Null),
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
                                                principal
                                                    .primary_email()
                                                    .map(|email| format!("mailto:{}", email))
                                                    .unwrap_or_default()
                                                    .into(),
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
