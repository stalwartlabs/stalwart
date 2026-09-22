/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::session::JmapAccount;
use common::{
    Server,
    auth::{AccessToken, AccountCache},
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::principal::{Principal, PrincipalProperty, PrincipalType, PrincipalValue},
    request::capability::Capability,
    types::state::State,
};
use jmap_tools::{Key, Map, Value};
use registry::schema::prelude::{ObjectType, Permission};
use std::{future::Future, sync::Arc};
use store::{registry::RegistryQuery, roaring::RoaringBitmap};
use trc::AddContext;
use types::id::Id;

type PrincipalObject = Value<'static, PrincipalProperty, PrincipalValue>;
type PrincipalMap = Map<'static, PrincipalProperty, PrincipalValue>;

pub trait PrincipalGet: Sync + Send {
    fn principal_get(
        &self,
        request: GetRequest<Principal>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Principal>>> + Send;

    fn visible_principal(
        &self,
        access_token: &AccessToken,
        principal_id: u32,
    ) -> impl Future<Output = trc::Result<Option<Arc<AccountCache>>>> + Send;
}

impl PrincipalGet for Server {
    async fn principal_get(
        &self,
        mut request: GetRequest<Principal>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Principal>> {
        let allow_directory_query = self.core.groupware.allow_directory_query;
        let (ids, not_found_ids) = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            PrincipalProperty::Id,
            PrincipalProperty::Type,
            PrincipalProperty::Name,
            PrincipalProperty::Description,
            PrincipalProperty::Email,
            PrincipalProperty::Timezone,
            PrincipalProperty::Capabilities,
            PrincipalProperty::Accounts,
        ]);

        // Return all principals
        let ids = match ids {
            Some(ids) => ids,
            None if allow_directory_query => self
                .registry()
                .query::<RoaringBitmap>(
                    RegistryQuery::new(ObjectType::Account).with_tenant(access_token.tenant_id()),
                )
                .await
                .caused_by(trc::location!())?
                .iter()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>(),
            None => access_token
                .all_ids()
                .take(self.core.jmap.get_max_objects)
                .map(Into::into)
                .collect::<Vec<_>>(),
        };
        let may_get_availability = allow_directory_query
            && access_token.has_permission(Permission::JmapPrincipalGetAvailability);
        let mut accounts = AccountObjects::default();
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: State::Initial.into(),
            list: Vec::with_capacity(ids.len()),
            not_found: not_found_ids,
        };

        for id in ids {
            // Obtain the principal
            let document_id = id.document_id();
            if !allow_directory_query && !access_token.has_account_access(document_id) {
                response.push_not_found(id);
                continue;
            }
            let Some(principal) = self.visible_principal(access_token, document_id).await? else {
                response.push_not_found(id);
                continue;
            };

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
                    PrincipalProperty::Accounts => {
                        if access_token.is_member(document_id)
                            || access_token.is_shared(document_id)
                        {
                            Value::Object(Map::from(vec![(
                                Key::Property(PrincipalProperty::IdValue(id)),
                                accounts.account(self, access_token, id, principal.name())?,
                            )]))
                        } else {
                            Value::Null
                        }
                    }
                    PrincipalProperty::Capabilities => Value::Object(Map::from_iter(
                        [
                            Capability::Mail,
                            Capability::Contacts,
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
                        .chain([(
                            Key::Property(PrincipalProperty::Capability(Capability::Calendars)),
                            Value::Object(Map::from(vec![
                                (
                                    Key::Borrowed("accountId"),
                                    if access_token.is_member(document_id)
                                        || access_token.is_shared(document_id)
                                    {
                                        Value::Element(PrincipalValue::Id(id))
                                    } else {
                                        Value::Null
                                    },
                                ),
                                (
                                    Key::Borrowed("mayGetAvailability"),
                                    Value::Bool(may_get_availability),
                                ),
                                (
                                    Key::Borrowed("mayShareWith"),
                                    Value::Bool(document_id != access_token.account_id()),
                                ),
                                (
                                    Key::Borrowed("calendarAddress"),
                                    Value::Str(format!("mailto:{}", principal.name()).into()),
                                ),
                            ])),
                        )]),
                    )),
                    _ => Value::Null,
                };

                result.insert_unchecked(property.clone(), value);
            }
            response.list.push(result.into());
        }

        Ok(response)
    }

    async fn visible_principal(
        &self,
        access_token: &AccessToken,
        principal_id: u32,
    ) -> trc::Result<Option<Arc<AccountCache>>> {
        self.try_account(principal_id)
            .await
            .caused_by(trc::location!())
            .map(|account| {
                account.filter(|account| {
                    access_token
                        .tenant_id()
                        .is_none_or(|tenant_id| account.tenant_id() == Some(tenant_id))
                })
            })
    }
}

#[derive(Default)]
struct AccountObjects {
    member_capabilities: Option<PrincipalMap>,
    shared_capabilities: Option<PrincipalMap>,
}

impl AccountObjects {
    fn account(
        &mut self,
        server: &Server,
        access_token: &AccessToken,
        id: Id,
        name: &str,
    ) -> trc::Result<PrincipalObject> {
        let account_id = id.document_id();
        let template = if access_token.is_member(account_id) {
            &mut self.member_capabilities
        } else {
            &mut self.shared_capabilities
        };
        let template = match template {
            Some(template) => template,
            None => template.insert(Self::capabilities(server, access_token, account_id)?),
        };
        let mut capabilities = PrincipalMap::with_capacity(template.len() + 1);
        capabilities.extend(
            template
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        capabilities.insert_unchecked(
            Key::Property(PrincipalProperty::Capability(Capability::PrincipalsOwner)),
            Value::Object(Map::from(vec![
                (
                    Key::Borrowed("accountIdForPrincipal"),
                    Value::Element(PrincipalValue::Id(Id::from(access_token.account_id()))),
                ),
                (
                    Key::Borrowed("principalId"),
                    Value::Element(PrincipalValue::Id(id)),
                ),
            ])),
        );

        Ok(Value::Object(Map::from(vec![
            (Key::Borrowed("name"), Value::Str(name.to_string().into())),
            (
                Key::Borrowed("isPersonal"),
                Value::Bool(account_id == access_token.account_id()),
            ),
            (
                Key::Borrowed("isReadOnly"),
                Value::Bool(access_token.is_read_only(account_id)),
            ),
            (
                Key::Borrowed("accountCapabilities"),
                Value::Object(capabilities),
            ),
        ])))
    }

    fn capabilities(
        server: &Server,
        access_token: &AccessToken,
        account_id: u32,
    ) -> trc::Result<PrincipalMap> {
        server
            .jmap_account_capabilities(access_token, account_id)
            .map(|(capability, capabilities)| {
                serde_json::to_value(capabilities).map(|value| {
                    (
                        Key::Property(PrincipalProperty::Capability(capability)),
                        value.into_principal_value(),
                    )
                })
            })
            .collect::<Result<PrincipalMap, _>>()
            .map_err(|err| {
                trc::StoreEvent::UnexpectedError
                    .caused_by(trc::location!())
                    .reason(err)
            })
    }
}

trait IntoPrincipalValue {
    fn into_principal_value(self) -> PrincipalObject;
}

impl IntoPrincipalValue for serde_json::Value {
    fn into_principal_value(self) -> PrincipalObject {
        match self {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(value) => Value::Bool(value),
            serde_json::Value::Number(number) => {
                if let Some(number) = number.as_u64() {
                    number.into()
                } else if let Some(number) = number.as_i64() {
                    number.into()
                } else if let Some(number) = number.as_f64() {
                    number.into()
                } else {
                    Value::Null
                }
            }
            serde_json::Value::String(value) => Value::Str(value.into()),
            serde_json::Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(IntoPrincipalValue::into_principal_value)
                    .collect(),
            ),
            serde_json::Value::Object(values) => Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (Key::Owned(key), value.into_principal_value()))
                    .collect(),
            ),
        }
    }
}
