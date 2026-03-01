/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::{
    ObjectResponse, RegistrySetResponse,
    masked_email::validate_masked_email,
    principal::{validate_account, validate_role, validate_tenant_quota},
    public_key::validate_public_key,
};
use common::{Server, auth::AccessToken, cache::invalidate::CacheInvalidationBuilder};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::registry::Registry,
    request::IntoValid,
};
use jmap_tools::{JsonPointer, JsonPointerItem, Key, Map};
use registry::{
    jmap::{JmapValue, JsonPointerPatch, MaybeUnpatched, RegistryValue},
    schema::{
        enums::{Permission, TenantStorageQuota},
        prelude::{
            OBJ_FILTER_ACCOUNT, OBJ_FILTER_TENANT, OBJ_SINGLETON, Object, ObjectInner, ObjectType,
            Property,
        },
        structs::{Account, PublicKey, Role},
    },
    types::id::ObjectId,
};
use store::registry::write::{RegistryWrite, RegistryWriteResult};
use trc::AddContext;
use types::id::Id;
use utils::map::vec_map::VecMap;

pub trait RegistrySet: Sync + Send {
    fn registry_set(
        &self,
        object_type: ObjectType,
        request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<Registry>>> + Send;
}

#[allow(clippy::large_enum_variant)]
enum Modification {
    Create(String),
    Update { id: Id, object: Object },
}

impl RegistrySet for Server {
    async fn registry_set(
        &self,
        object_type: ObjectType,
        mut request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<Registry>> {
        let object_flags = object_type.flags();
        let is_singleton = (object_flags & OBJ_SINGLETON) != 0;
        let has_account_id = (object_flags & OBJ_FILTER_ACCOUNT) != 0;
        let is_tenant_filtered =
            (object_flags & OBJ_FILTER_TENANT) != 0 && access_token.tenant_id().is_some();
        let is_account_filtered =
            has_account_id && !access_token.has_permission(Permission::Impersonate);

        // Build response
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?;

        // Initial create validation for singletons
        let mut create = request.unwrap_create();
        if is_singleton && !create.is_empty() {
            response
                .not_created
                .extend(create.drain().map(|(id, _)| (id, SetError::singleton())));
        }

        // Initial destroy validation for singletons
        let mut destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();
        if is_singleton && !destroy.is_empty() {
            response
                .not_destroyed
                .extend(destroy.drain(..).map(|id| (id, SetError::singleton())));
        }

        // Update validation for willDestroy
        let update = request
            .unwrap_update()
            .into_valid()
            .filter_map(|(id, value)| {
                if is_singleton {
                    if id.is_singleton() {
                        Some((id, value))
                    } else {
                        response.not_updated.append(id, SetError::not_found());
                        None
                    }
                } else if !destroy.contains(&id) {
                    Some((id, value))
                } else {
                    response.not_updated.append(id, SetError::will_destroy());
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut set = RegistrySetResponse {
            access_token,
            server: self,
            account_id: request.account_id.document_id(),
            object_type,
            response,
            object_flags,
            is_tenant_filtered,
            is_account_filtered,
            create,
            update,
            destroy,
        };
        match object_type {
            ObjectType::AddressBook
            | ObjectType::Asn
            | ObjectType::Authentication
            | ObjectType::BlobStore
            | ObjectType::Cache
            | ObjectType::Calendar
            | ObjectType::CalendarAlarm
            | ObjectType::CalendarScheduling
            | ObjectType::Coordinator
            | ObjectType::DataRetention
            | ObjectType::DataStore
            | ObjectType::DkimReportSettings
            | ObjectType::DmarcReportSettings
            | ObjectType::DnsResolver
            | ObjectType::Email
            | ObjectType::Enterprise
            | ObjectType::FileStorage
            | ObjectType::Http
            | ObjectType::HttpForm
            | ObjectType::Imap
            | ObjectType::InMemoryStore
            | ObjectType::Jmap
            | ObjectType::LocalSettings
            | ObjectType::Metrics
            | ObjectType::MetricsStore
            | ObjectType::MtaConnectionStrategy
            | ObjectType::MtaExtensions
            | ObjectType::MtaInboundSession
            | ObjectType::MtaOutboundStrategy
            | ObjectType::MtaOutboundThrottle
            | ObjectType::MtaStageAuth
            | ObjectType::MtaStageConnect
            | ObjectType::MtaStageData
            | ObjectType::MtaStageEhlo
            | ObjectType::MtaStageMail
            | ObjectType::MtaStageRcpt
            | ObjectType::MtaSts
            | ObjectType::OidcProvider
            | ObjectType::ReportSettings
            | ObjectType::Search
            | ObjectType::SearchStore
            | ObjectType::Security
            | ObjectType::SenderAuth
            | ObjectType::Sharing
            | ObjectType::SieveSystemInterpreter
            | ObjectType::SieveUserInterpreter
            | ObjectType::SpamClassifier
            | ObjectType::SpamDnsblSettings
            | ObjectType::SpamLlm
            | ObjectType::SpamPyzor
            | ObjectType::SpamSettings
            | ObjectType::SpfReportSettings
            | ObjectType::TaskManager
            | ObjectType::TlsReportSettings
            | ObjectType::TracingStore
            | ObjectType::WebDav
            | ObjectType::DsnReportSettings
            | ObjectType::AcmeProvider
            | ObjectType::AiModel
            | ObjectType::Alert
            | ObjectType::AllowedIp
            | ObjectType::Application
            | ObjectType::BlockedIp
            | ObjectType::Certificate
            | ObjectType::Directory
            | ObjectType::DnsServer
            | ObjectType::EventTracingLevel
            | ObjectType::HttpLookup
            | ObjectType::MemoryLookupKey
            | ObjectType::MemoryLookupKeyValue
            | ObjectType::MtaVirtualQueue
            | ObjectType::MtaQueueQuota
            | ObjectType::MtaRoute
            | ObjectType::MtaDeliverySchedule
            | ObjectType::MtaInboundThrottle
            | ObjectType::MtaTlsStrategy
            | ObjectType::MtaMilter
            | ObjectType::MtaHook
            | ObjectType::NetworkListener
            | ObjectType::Node
            | ObjectType::NodeRole
            | ObjectType::NodeShard
            | ObjectType::RegistryBundle
            | ObjectType::SieveSystemScript
            | ObjectType::SieveUserScript
            | ObjectType::SpamDnsblServer
            | ObjectType::SpamFileExtension
            | ObjectType::SpamRule
            | ObjectType::SpamTag
            | ObjectType::StoreLookup
            | ObjectType::Tracer
            | ObjectType::WebHook
            | ObjectType::PublicKey
            | ObjectType::DkimSignature
            | ObjectType::MaskedEmail
            | ObjectType::Account
            | ObjectType::MailingList
            | ObjectType::OAuthClient
            | ObjectType::Role
            | ObjectType::Tenant
            | ObjectType::Domain => {
                // Bundle modifications together
                let mut modifications = Vec::with_capacity(set.create.len() + set.update.len());
                for (id, value) in set.create.drain() {
                    modifications.push((
                        Modification::Create(id),
                        value,
                        Object::from(set.object_type),
                    ));
                }
                for (id, value) in set.update.drain(..) {
                    if let Some(object) = self
                        .registry()
                        .get(ObjectId::new(object_type, id))
                        .await
                        .caused_by(trc::location!())?
                    {
                        if (is_tenant_filtered
                            && access_token.tenant_id().map(Id::from)
                                != object.inner.member_tenant_id())
                            || (is_account_filtered
                                && object.inner.account_id() != Some(Id::from(set.account_id)))
                        {
                            set.response.not_updated.append(id, SetError::not_found());
                            continue;
                        }

                        modifications.push((
                            Modification::Update {
                                id,
                                object: object.clone(),
                            },
                            value,
                            object,
                        ));
                    } else if is_singleton {
                        modifications.push((
                            Modification::Update {
                                id,
                                object: Object::from(set.object_type),
                            },
                            value,
                            Object::from(set.object_type),
                        ));
                    } else {
                        set.response.not_updated.append(id, SetError::not_found());
                    }
                }

                // Process modifications
                let mut cache_invalidator = CacheInvalidationBuilder::default();
                'outer: for (modification, value, mut new_object) in modifications {
                    // Initial validations
                    let is_create = matches!(modification, Modification::Create(_));
                    let mut unpatched_properties = VecMap::new();

                    for (key, value) in value.into_expanded_object() {
                        let ptr = match (key, &modification) {
                            (Key::Property(prop), _) => {
                                JsonPointer::new(vec![JsonPointerItem::Key(Key::Property(prop))])
                            }
                            (Key::Borrowed(other), Modification::Update { .. }) => {
                                JsonPointer::parse(other)
                            }
                            (Key::Owned(other), Modification::Update { .. }) => {
                                JsonPointer::parse(&other)
                            }
                            (key, Modification::Create(_)) => {
                                set.failed(
                                    modification,
                                    SetError::invalid_properties().with_property(key.into_owned()),
                                );
                                continue 'outer;
                            }
                        };

                        if is_tenant_filtered || is_account_filtered {
                            match ptr.last().and_then(|p| p.as_property_key()) {
                                Some(Property::MemberTenantId) => {
                                    // SPDX-SnippetBegin
                                    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
                                    // SPDX-License-Identifier: LicenseRef-SEL
                                    #[cfg(feature = "enterprise")]
                                    if access_token.tenant_id().is_some() {
                                        continue;
                                    }
                                    // SPDX-SnippetEnd

                                    #[cfg(not(feature = "enterprise"))]
                                    continue;
                                }
                                Some(Property::AccountId) => {
                                    set.failed(
                                        modification,
                                        SetError::forbidden()
                                            .with_property(Property::AccountId)
                                            .with_description("Cannot change server-set property"),
                                    );
                                    continue 'outer;
                                }
                                _ => {}
                            }
                        }

                        // Patch object
                        match new_object
                            .patch(JsonPointerPatch::new(&ptr).with_create(is_create), value)
                        {
                            Ok(MaybeUnpatched::Patched) => {}
                            Ok(MaybeUnpatched::Unpatched { property, value }) => {
                                unpatched_properties.append(property, value);
                            }
                            Ok(MaybeUnpatched::UnpatchedMany { properties }) => {
                                if unpatched_properties.is_empty() {
                                    unpatched_properties = properties;
                                } else {
                                    unpatched_properties.extend(properties);
                                }
                            }
                            Err(err) => {
                                set.failed(modification, err.into());
                                continue 'outer;
                            }
                        }
                    }

                    if is_create {
                        // Add tenantId for tenant filtered objects
                        if is_tenant_filtered && let Some(tenant_id) = set.access_token.tenant_id()
                        {
                            new_object.inner.set_member_tenant_id(tenant_id.into());
                        }

                        // Add accountId
                        if has_account_id {
                            new_object.inner.set_account_id(set.account_id.into());
                        }
                    }

                    // Validate objects
                    let result = match &mut new_object.inner {
                        ObjectInner::Account(account) => {
                            validate_account(&set, account, modification.as_account()).await?
                        }
                        ObjectInner::Role(role) => {
                            validate_role(&set, role, modification.as_role()).await?
                        }
                        ObjectInner::MaskedEmail(masked_email) => {
                            validate_masked_email(
                                &set,
                                masked_email,
                                is_create,
                                unpatched_properties,
                            )
                            .await?
                        }
                        ObjectInner::PublicKey(key) => {
                            validate_public_key(
                                &set,
                                key,
                                modification.as_public_key(),
                                unpatched_properties,
                            )
                            .await?
                        }
                        ObjectInner::Domain(_) if is_create => {
                            validate_tenant_quota(&set, TenantStorageQuota::MaxDomains).await?
                        }
                        ObjectInner::MailingList(_) if is_create => {
                            validate_tenant_quota(&set, TenantStorageQuota::MaxMailingLists).await?
                        }
                        ObjectInner::OAuthClient(_) if is_create => {
                            validate_tenant_quota(&set, TenantStorageQuota::MaxOauthClients).await?
                        }
                        _ => Ok(ObjectResponse::default()),
                    };

                    let mut response = match result {
                        Ok(response) => response,
                        Err(err) => {
                            set.failed(modification, err);
                            continue 'outer;
                        }
                    };

                    // Save object
                    let result = match &modification {
                        Modification::Create(_) => {
                            self.registry()
                                .write(RegistryWrite::Insert {
                                    object: &new_object,
                                    id: response.id,
                                })
                                .await?
                        }
                        Modification::Update { id, object } => {
                            if object.inner != new_object.inner {
                                self.registry()
                                    .write(RegistryWrite::update(*id, &new_object, object))
                                    .await?
                            } else {
                                set.response.updated.append(*id, None);
                                continue;
                            }
                        }
                    };

                    match (modification, result) {
                        (Modification::Update { id, object }, RegistryWriteResult::Success(_)) => {
                            cache_invalidator.process_update(id, &object, &new_object);
                            set.response.updated.append(
                                id,
                                if !response.object.is_empty() {
                                    Some(JmapValue::Object(response.object))
                                } else {
                                    None
                                },
                            );
                        }
                        (Modification::Create(client_id), RegistryWriteResult::Success(id)) => {
                            response.object.insert(Property::Id, RegistryValue::Id(id));
                            set.response
                                .created
                                .insert(client_id, JmapValue::Object(response.object));
                        }
                        (Modification::Update { id, .. }, err) => {
                            set.response.not_updated.append(id, map_write_error(err));
                        }
                        (Modification::Create(client_id), err) => {
                            set.response
                                .not_created
                                .append(client_id, map_write_error(err));
                        }
                    }
                }

                // Process destroy
                for id in set.destroy.drain(..) {
                    let object_id = ObjectId::new(object_type, id);
                    if let Some(object) = self
                        .registry()
                        .get(object_id)
                        .await
                        .caused_by(trc::location!())?
                        .filter(|object| {
                            !(is_tenant_filtered
                                && access_token.tenant_id().map(Id::from)
                                    != object.inner.member_tenant_id())
                                || (is_account_filtered
                                    && object.inner.account_id() != Some(Id::from(set.account_id)))
                        })
                    {
                        match self
                            .registry()
                            .write(RegistryWrite::Delete {
                                object_id,
                                object: Some(&object),
                            })
                            .await?
                        {
                            RegistryWriteResult::Success(_) => {
                                cache_invalidator.process_delete(id, &object);
                                set.response.destroyed.push(id);
                            }
                            err => {
                                set.response.not_destroyed.append(id, map_write_error(err));
                            }
                        }
                    } else {
                        set.response.not_destroyed.append(id, SetError::not_found());
                    }
                }

                // Finalize cache invalidation
                self.invalidate_caches(cache_invalidator).await?;
            }
            ObjectType::QueuedMessage => {}
            ObjectType::Task => {}
            ObjectType::ArfExternalReport => {}
            ObjectType::DmarcExternalReport => {}
            ObjectType::TlsExternalReport => {}
            ObjectType::DeletedItem => {}
            ObjectType::Metric => {}
            ObjectType::Trace => {}
            ObjectType::SpamTrainingSample => {}
            ObjectType::DmarcInternalReport => {}
            ObjectType::TlsInternalReport => {}
            ObjectType::Log => {}
            ObjectType::AccountSettings => {}
            ObjectType::Credential => {}
        }

        // Schedule account and tenant deletions

        // management objects for actions (reload, etc)";
        // DkimSignature = Generate keys + Enforce count?
        // PublicKey = Validate PK? Store decoded? Enforce count? Update ingest
        // Domain = trigger DNIM stuff
        // Validate expressions
        // Fallback admin password from env or files

        Ok(set.into_response())
    }
}

impl RegistrySetResponse<'_> {
    fn failed(&mut self, modification: Modification, error: SetError<Property>) {
        match modification {
            Modification::Create(id) => self.response.not_created.append(id, error),
            Modification::Update { id, .. } => self.response.not_updated.append(id, error),
        }
    }

    fn create(
        &mut self,
        client_id: String,
        result: RegistryWriteResult,
        mut object: Map<'static, Property, RegistryValue>,
    ) {
        match result {
            RegistryWriteResult::Success(id) => {
                object.insert(Key::Property(Property::Id), RegistryValue::Id(id));
                self.response
                    .created
                    .insert(client_id, JmapValue::Object(object));
            }
            RegistryWriteResult::NotFound { .. } => {
                self.response
                    .not_created
                    .append(client_id, SetError::not_found());
            }
            err => {
                self.response
                    .not_created
                    .append(client_id, map_write_error(err));
            }
        }
    }

    fn update(&mut self, id: Id, result: RegistryWriteResult) {
        match result {
            RegistryWriteResult::Success(_) => self.response.updated.append(id, None),
            RegistryWriteResult::NotFound { .. } => {
                self.response.not_updated.append(id, SetError::not_found());
            }
            err => {
                self.response.not_updated.append(id, map_write_error(err));
            }
        }
    }

    fn into_response(self) -> SetResponse<Registry> {
        self.response
    }
}

impl Modification {
    fn as_account(&self) -> Option<&Account> {
        match self {
            Modification::Create(_) => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::Account(account) => Some(account),
                _ => None,
            },
        }
    }

    fn as_role(&self) -> Option<&Role> {
        match self {
            Modification::Create(_) => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::Role(role) => Some(role),
                _ => None,
            },
        }
    }

    fn as_public_key(&self) -> Option<&PublicKey> {
        match self {
            Modification::Create(_) => None,
            Modification::Update { object, .. } => match &object.inner {
                ObjectInner::PublicKey(key) => Some(key),
                _ => None,
            },
        }
    }
}

fn map_write_error(err: RegistryWriteResult) -> SetError<Property> {
    match err {
        RegistryWriteResult::CannotDeleteLinked {
            object_id,
            linked_objects,
        } => SetError::new(SetErrorType::ObjectIsLinked)
            .with_object_id(object_id)
            .with_linked_objects(linked_objects),
        RegistryWriteResult::InvalidSingletonId => SetError::invalid_properties()
            .with_property(Property::Id)
            .with_description("Invalid singleton id"),
        RegistryWriteResult::CannotDeleteSingleton => {
            SetError::forbidden().with_description("Singleton objects cannot be deleted")
        }
        RegistryWriteResult::InvalidForeignKey { object_id } => {
            SetError::new(SetErrorType::InvalidForeignKey).with_object_id(object_id)
        }
        RegistryWriteResult::PrimaryKeyConflict {
            property,
            existing_id,
        } => SetError::new(SetErrorType::PrimaryKeyViolation)
            .with_property(property)
            .with_object_id(existing_id),
        RegistryWriteResult::ValidationError { errors } => {
            SetError::new(SetErrorType::ValidationFailed).with_validation_errors(errors)
        }
        RegistryWriteResult::NotSupported => SetError::forbidden()
            .with_description("The requested action is not supported by the registry store"),
        RegistryWriteResult::NotFound { .. } => SetError::not_found(),
        RegistryWriteResult::Success(_) => unreachable!(),
    }
}
